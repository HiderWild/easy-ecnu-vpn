// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// P1-b: the engine-side gRPC transport over a mutually-authenticated Tokio Windows
// Named Pipe (spec §9.4; TG-WIN "Named Pipe mutual auth"). This module is the
// transport-layer interception gate for the HelperControl product channel:
//
//   * [`serve_named_pipe`] creates the pipe with the WSP1 §4 DACL (SYSTEM + the
//     core user SID, via `pipe_security::PipeSecurity`), accepts one core
//     connection, authenticates the core peer (client pid + user SID) BEFORE any
//     gRPC frame is dispatched, and only then serves the HelperControl service.
//     Any identity query failure fails closed and the connection is refused.
//   * [`require_verified_peer`] is the dispatch-time interceptor: every request
//     must carry the transport-verified peer extension ([`NamedPipeConnectInfo`],
//     attached via the tonic `Connected` hook); without it the call is rejected
//     with `UNAUTHENTICATED`. Handlers additionally fail closed when the
//     extension is absent — dispatch only ever happens for verified connections.
//
// The client side (core) mirrors this in `exv_core::grpc_transport`
// (P1-c): tokio `NamedPipeClient` + `GetNamedPipeServerProcessId`+SID verification.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use exv_vpn_domain::identity::{ConnectionBindingDigest, PrincipalDigest};
use exv_vpn_win32_ipc::peer_auth::{
    current_process_identity, current_user_sid, process_sid, encode_identity_frame, ProcessIdentity,
};
use exv_vpn_win32_ipc::pipe_security::PipeSecurity;
use exv_vpn_win32_ipc::service_key::{ct_eq, hmac_sha256, random_32};
use exv_vpn_wire::generated;
use generated::helper_control_server::HelperControlServer;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tonic::codegen::tokio_stream;
use tonic::transport::Server;
use tonic::Status;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;

use crate::grpc_server::HelperControlService;

/// The verified transport identity of the connected core peer.
///
/// Derived ONLY from verified transport metadata (`GetNamedPipeClientProcessId`
/// + token SID read-back); a client-supplied field can never fabricate identity
/// (spec §9.4: "PeerContext 只由已验证 connection metadata 构造").
#[derive(Clone)]
pub struct TransportPeerInfo {
    /// Whether the peer passed transport-level authentication (always true when
    /// built by this transport; false guards non-verified construction paths).
    pub verified: bool,
    /// The authenticated core process id (transport-derived).
    pub process_id: u32,
    /// The authenticated core user SID (transport-derived).
    pub user_sid: String,
    /// The account name resolved from the user SID, when available.
    pub account_name: String,
    /// The authenticated principal digest (SHA-256 of the user SID).
    pub principal: PrincipalDigest,
    /// The per-connection binding digest (SHA-256 of pid + per-accept nonce).
    pub connection_digest: ConnectionBindingDigest,
}

/// The `Connected::ConnectInfo` attached to every request by the named-pipe transport.
///
/// Handlers and the [`require_verified_peer`] interceptor read it from request
/// extensions; it is the ONLY source of peer identity on the engine.
#[derive(Clone)]
pub struct NamedPipeConnectInfo(pub TransportPeerInfo);

/// A transport-verified named-pipe server connection: the async pipe plus the
/// authenticated peer, surfaced to tonic via the `Connected` hook.
pub struct VerifiedNamedPipeServer {
    /// The async named-pipe server connection (tokio overlapped I/O).
    io: NamedPipeServer,
    /// The transport-verified peer attached to every request on this connection.
    info: TransportPeerInfo,
}

impl VerifiedNamedPipeServer {
    /// Wrap an accepted, authenticated pipe with its verified peer info.
    #[must_use]
    pub fn new(io: NamedPipeServer, info: TransportPeerInfo) -> Self {
        Self { io, info }
    }
}

impl tonic::transport::server::Connected for VerifiedNamedPipeServer {
    type ConnectInfo = NamedPipeConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        NamedPipeConnectInfo(self.info.clone())
    }
}

impl AsyncRead for VerifiedNamedPipeServer {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl AsyncWrite for VerifiedNamedPipeServer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// A 32-byte SHA-256 digest of `bytes`.
fn digest32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

/// Create a first-instance, remote-client-rejecting named-pipe server whose DACL grants
/// `SYSTEM` plus exactly `core_sid`, both `GA` (WSP1 §4 frozen shape via
/// `pipe_security::PipeSecurity`). A broad principal is refused by `PipeSecurity`.
///
/// # Errors
/// Returns an `io::Error` when the pipe cannot be created (e.g. another engine already
/// owns the name — first-instance anti-squatting).
/// 创建控制面 Named Pipe server 实例。
///
/// `first_instance`：`true` = 管道名的首个实例（`FILE_FLAG_FIRST_PIPE_INSTANCE`）；
/// `false` = 后续实例（多实例服务：每个连接一个实例，旧实例被占用时不影响新实例创建）。
/// `max_instances`：管道最大实例数（oneshot 用 1；service 用 N 支持连接/重连并存）。
///
/// 修复（2026-08-23）：service 此前单实例（max=1 + first=true），`serve_with_incoming`
/// 对每个连接 `tokio::spawn` 不 await，连接存活时管道名被占 → 下轮重建恒
/// `ERROR_PIPE_BUSY(231)` → 服务退出（连接后即死）。多实例让每次 accept 用独立实例。
pub fn create_control_pipe_server(
    name: &str,
    core_sid: &str,
    first_instance: bool,
    max_instances: usize,
) -> std::io::Result<NamedPipeServer> {
    let security = PipeSecurity::new(core_sid, true)
        .map_err(|code| std::io::Error::from_raw_os_error(code as i32))?;
    // `CreateNamedPipeW`'s `lpSecurityAttributes` parameter is a `SECURITY_ATTRIBUTES*`, NOT a
    // `PSECURITY_DESCRIPTOR`. Passing the inner descriptor (the previous behavior) made the OS
    // read a `SECURITY_DESCRIPTOR` as a `SECURITY_ATTRIBUTES` — indeterminate DACL that happened
    // to work same-process but denied cross-process (`ERROR_ACCESS_DENIED`/`ERROR_INVALID_NAME`).
    // Pass the `SECURITY_ATTRIBUTES` struct itself (its `lpSecurityDescriptor` points at the
    // live `security`-owned descriptor), mirroring the trusted `named_pipe_io::create_server_inner`
    // pattern.
    let mut attributes = security.as_attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true)
        .max_instances(max_instances);
    // SAFETY: `attributes` is a live `SECURITY_ATTRIBUTES` whose `lpSecurityDescriptor` points at
    // the live descriptor owned by `security`; both stay alive for the duration of this call
    // (same scope). tokio forwards the pointer verbatim as `CreateNamedPipeW`'s
    // `lpSecurityAttributes`, which copies the DACL at creation.
    unsafe { options.create_with_security_attributes_raw(name, &raw mut attributes as *mut core::ffi::c_void) }
}

/// Verify the connected core (client) peer: its pid must equal `expected_host_pid` and its
/// user SID must equal `expected_core_sid`. Any identity query failure fails closed.
///
/// # Errors
/// Returns a typed failure when the pid/SID mismatch or the identity cannot be resolved.
pub fn verify_core_peer(
    server: &NamedPipeServer,
    expected_host_pid: u32,
    expected_core_sid: &str,
) -> Result<TransportPeerInfo, String> {
    use std::os::windows::io::AsRawHandle;

    let mut pid = 0u32;
    // SAFETY: `server.as_raw_handle()` is the connected server pipe handle and `pid` is a
    // live out-param for the call.
    if let Err(e) = unsafe {
        GetNamedPipeClientProcessId(
            HANDLE(server.as_raw_handle() as *mut core::ffi::c_void),
            &raw mut pid,
        )
    } {
        return Err(format!("core process query failed: {e}"));
    }
    if pid != expected_host_pid {
        return Err(format!(
            "core pid mismatch: expected {expected_host_pid}, observed {pid}"
        ));
    }
    let sid = process_sid(pid).ok_or_else(|| format!("cannot resolve user SID of core pid {pid}"))?;
    if sid != expected_core_sid {
        return Err(format!(
            "core SID mismatch: expected {expected_core_sid}, observed {sid}"
        ));
    }

    // Per-accept nonce so each connection gets a distinct, non-forwardable binding.
    let nonce = uuid::Uuid::new_v4();
    let principal = PrincipalDigest::try_from(digest32(format!("sid:{sid}").as_bytes()))
        .expect("principal digest mints");
    let connection_digest = ConnectionBindingDigest::try_from(digest32(
        format!("conn:{pid}:{nonce}").as_bytes(),
    ))
    .expect("connection digest mints");

    Ok(TransportPeerInfo {
        verified: true,
        process_id: pid,
        user_sid: sid,
        account_name: String::new(),
        principal,
        connection_digest,
    })
}

/// Verify a **service-mode** core (client) peer: its user SID must equal `expected_core_sid`
/// (the installing user). Unlike oneshot ([`verify_core_peer`]), the pid is NOT pinned to a
/// fixed core — the service engine outlives individual cores and each accepted connection is a
/// different process. The pid is still read for the per-accept connection binding digest
/// (non-forwardable); the SID is the trust anchor for S2 (D2 PSK-HMAC strengthens it in S3).
///
/// # Errors
/// Returns a typed failure when the SID mismatches or the identity cannot be resolved.
pub fn verify_service_peer(
    server: &NamedPipeServer,
    expected_core_sid: &str,
) -> Result<TransportPeerInfo, String> {
    use std::os::windows::io::AsRawHandle;

    let mut pid = 0u32;
    // SAFETY: `server.as_raw_handle()` is the connected server pipe handle and `pid` is a
    // live out-param for the call.
    if let Err(e) = unsafe {
        GetNamedPipeClientProcessId(HANDLE(server.as_raw_handle()), &raw mut pid)
    } {
        return Err(format!("core process query failed: {e}"));
    }
    let sid = process_sid(pid).ok_or_else(|| format!("cannot resolve user SID of core pid {pid}"))?;
    if sid != expected_core_sid {
        return Err(format!(
            "core SID mismatch: expected {expected_core_sid}, observed {sid}"
        ));
    }

    // Per-accept nonce so each service connection gets a distinct, non-forwardable binding.
    let nonce = uuid::Uuid::new_v4();
    let principal = PrincipalDigest::try_from(digest32(format!("sid:{sid}").as_bytes()))
        .expect("principal digest mints");
    let connection_digest = ConnectionBindingDigest::try_from(digest32(
        format!("conn:{pid}:{nonce}").as_bytes(),
    ))
    .expect("connection digest mints");

    Ok(TransportPeerInfo {
        verified: true,
        process_id: pid,
        user_sid: sid,
        account_name: String::new(),
        principal,
        connection_digest,
    })
}

/// 服务模式 pre-gRPC 握手（server 侧，D2 + S6 自报身份）：在 SID 验证（`verify_service_peer`）
/// 之后、任何 gRPC 帧派发之前，经裸帧先自报身份、再证明客户端持有共享 PSK。
///
/// 协议：
/// 0. server → client：**自报身份帧**（PID u32 LE + sid_len u16 LE + SID UTF-8）——
///    engine 自报自身进程 PID + user SID（S6 方案；标准用户 core 无法 `OpenProcess`
///    SYSTEM 会话 0 服务进程读 SID，S5 真机实测 err=5，改由 engine 免特权自报）；
/// 1. server → client：`nonce_e`（32 字节随机）；
/// 2. client → server：`HMAC(psk, nonce_e || "c2e")`（32 字节）+ `nonce_s`（32 字节）；
/// 3. server 恒时验证应答 → server → client：`HMAC(psk, nonce_s || "e2c")`（32 字节）。
///
/// 双向：server 验证 client 的应答（client 证明持有 PSK），client 验证 server 的应答
/// （server 证明持有 PSK，防伪 server / 中间人）+ 自报身份（PID 交叉核验 + SID 比对）。
/// 任何失败 → `Err`（调用方 fail closed 拒绝该连接）。落点选 pre-gRPC 裸帧挑战——免
/// helper_control.proto 第三次解冻（理由见
/// `docs/superpowers/evidence/2026-08-20-engine-service-psk-hmac.md`；身份帧决策见
/// `docs/superpowers/evidence/2026-08-20-engine-self-identity.md`）。
///
/// # Errors
/// 随机数 / 读 / 写 / 应答不匹配 → 携带原因的字符串（连接拒绝）。
pub async fn psk_challenge_server(
    pipe: &mut NamedPipeServer,
    psk: &[u8],
    identity: &ProcessIdentity,
) -> Result<(), String> {
    // 0. 自报身份帧（client 侧先读身份再进入 PSK 挑战——帧序对称由双侧实现保证）。
    let frame = encode_identity_frame(identity);
    pipe.write_all(&frame)
        .await
        .map_err(|e| format!("psk challenge: send identity: {e}"))?;
    // 1. server nonce。
    let nonce_e = random_32()?;
    pipe.write_all(&nonce_e)
        .await
        .map_err(|e| format!("psk challenge: send nonce: {e}"))?;
    // 2. client 应答 + client nonce（64 字节）。
    let mut buf = [0u8; 64];
    pipe.read_exact(&mut buf)
        .await
        .map_err(|e| format!("psk challenge: read response: {e}"))?;
    let (response, nonce_s) = buf.split_at(32);
    let expected = hmac_sha256(psk, &tagged(&nonce_e, b"c2e"));
    if !ct_eq(response, &expected) {
        return Err("psk challenge: response mismatch".to_string());
    }
    // 3. server 应答（client 验证）。
    let reply = hmac_sha256(psk, &tagged(nonce_s, b"e2c"));
    pipe.write_all(&reply)
        .await
        .map_err(|e| format!("psk challenge: send reply: {e}"))?;
    Ok(())
}

/// `base || suffix`（challenge 域标签：防止应答反射/跨域误用）。
fn tagged(base: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(base.len() + suffix.len());
    out.extend_from_slice(base);
    out.extend_from_slice(suffix);
    out
}

/// Dispatch-time gate: a request may only be handled when the transport has verified the
/// peer ([`NamedPipeConnectInfo`] present and `verified`). This runs for EVERY RPC before
/// the handler, so an unauthenticated connection can never reach mutation dispatch.
pub fn require_verified_peer(request: tonic::Request<()>) -> Result<tonic::Request<()>, Status> {
    let info = request
        .extensions()
        .get::<NamedPipeConnectInfo>()
        .ok_or_else(|| Status::unauthenticated("transport peer not verified"))?;
    if !info.0.verified {
        return Err(Status::unauthenticated("transport peer not verified"));
    }
    Ok(request)
}

/// Serve the HelperControl service over one mutually-authenticated named-pipe connection.
///
/// 1. Creates the control pipe with the WSP1 §4 DACL (`SYSTEM` + `core_sid`);
/// 2. accepts one core connection;
/// 3. verifies the core pid (`expected_host_pid`) + user SID (`core_sid`) — any failure
///    fails closed BEFORE the first gRPC frame is decoded or dispatched;
/// 4. serves `service` behind the [`require_verified_peer`] interceptor, with the
///    verified peer attached to every request via the `Connected` hook.
///
/// The future resolves when the single connection closes (client disconnect), matching the
/// legacy engine's one-core-connection control-plane shape.
///
/// # Errors
/// Pipe create/accept/authenticate failures return a typed string; tonic transport errors
/// also propagate.
pub async fn serve_named_pipe(
    name: &str,
    core_sid: &str,
    expected_host_pid: u32,
    service: HelperControlServer<HelperControlService>,
) -> Result<(), String> {
    let server = create_control_pipe_server(name, core_sid, true, 1)
        .map_err(|e| format!("create control pipe: {e}"))?;
    server
        .connect()
        .await
        .map_err(|e| format!("accept core connection: {e}"))?;

    let info = verify_core_peer(&server, expected_host_pid, core_sid)?;

    let io = VerifiedNamedPipeServer::new(server, info);
    let incoming = tokio_stream::iter(vec![Ok::<_, std::io::Error>(io)]);

    let router = Server::builder()
        .layer(tonic::service::InterceptorLayer::new(require_verified_peer))
        .add_service(service);
    router
        .serve_with_incoming(incoming)
        .await
        .map_err(|e| format!("gRPC serve: {e}"))
}

// ---------------------------------------------------------------------------
// 服务模式 accept-loop（D1 / S2）：engine 以 SCM 服务常驻时**连续 accept**——每次独立
// verify、独立 owner 流；oneshot 保持单 accept（[`serve_named_pipe`]）。accept-loop 本体
// 泛化到可注入的 [`AcceptServe`]，ServiceMain 只做薄壳（真实 = [`ServiceAcceptor`]）。
// ---------------------------------------------------------------------------

/// 连续 accept-loop 的结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptLoopOutcome {
    /// 收到停止信号（SCM stop / 显式停机）→ 调用方走退出清理路径。
    Stopped,
    /// 服务端已关闭（不再接受新连接）。
    ServerClosed,
    /// accept/verify/serve 失败（携带原因）。
    Failed(String),
}

/// ServiceMain 与控制面 accept-loop 之间的一次性启动就绪通知。
pub struct ControlPlaneReady {
    sender: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

impl ControlPlaneReady {
    #[must_use]
    pub fn new(sender: tokio::sync::oneshot::Sender<Result<(), String>>) -> Self {
        Self { sender: Some(sender) }
    }

    /// 报告控制管道已经创建；重复报告或接收端已关闭均失败。
    pub fn report_ready(&mut self) -> Result<(), String> {
        let sender = self
            .sender
            .take()
            .ok_or_else(|| "control-plane readiness already reported".to_string())?;
        sender
            .send(Ok(()))
            .map_err(|_| "control-plane readiness receiver dropped".to_string())
    }

    /// 将初始化错误传递给 ServiceMain；发送端只消费一次。
    pub fn report_error(&mut self, error: String) -> Result<(), String> {
        let sender = self
            .sender
            .take()
            .ok_or_else(|| "control-plane readiness already reported".to_string())?;
        sender.send(Err(error.clone())).map_err(|_| error)
    }
}

/// 单次 accept-and-serve 的可注入原语（测试注入 fake；生产 = [`ServiceAcceptor`]）。
///
/// 注：`async fn` 在 public trait 的 auto-trait 边界警告（rustc `async_fn_in_trait`）——
/// 本 trait 只被泛型 [`accept_loop`]（monomorphized）使用，不做 `dyn` 分派；各实现
/// （fake / [`ServiceAcceptor`]）的具体 future 均为 `Send`（编译期已证）。
#[allow(async_fn_in_trait)]
pub trait AcceptServe {
    /// 接受并服务一个连接。返回 `Ok(true)` = 继续接受下一个；`Ok(false)` = 服务端关闭
    /// （不再接受）；`Err` = 失败（携带原因）。
    async fn serve_one(&mut self) -> Result<bool, String>;
}

/// 服务模式连续 accept-loop：循环 select「停止信号 vs 单次 accept-and-serve」。收到停止
/// 信号（SCM stop）→ [`AcceptLoopOutcome::Stopped`]；服务端关闭 → `ServerClosed`；任一
/// 失败 → `Failed`。
///
/// 与 oneshot 的差异：oneshot 只 accept 一个 core 连接（`serve_named_pipe` 返回即走
/// 进程句柄/心跳生命周期）；服务模式由本循环持续 accept，直到 SCM stop。
pub async fn accept_loop<S: AcceptServe>(
    mut acceptor: S,
    mut stop_rx: tokio::sync::watch::Receiver<bool>,
) -> AcceptLoopOutcome {
    loop {
        tokio::select! {
            stop_result = stop_rx.changed() => {
                if stop_result.is_err() {
                    // 停止信号发送端已 drop：停止信号通道终结，视同停止（防 busy-loop）。
                    return AcceptLoopOutcome::Stopped;
                }
                if *stop_rx.borrow_and_update() {
                    return AcceptLoopOutcome::Stopped;
                }
            }
            result = acceptor.serve_one() => {
                match result {
                    Ok(true) => continue,
                    Ok(false) => return AcceptLoopOutcome::ServerClosed,
                    Err(e) => return AcceptLoopOutcome::Failed(e),
                }
            }
        }
    }
}

/// 服务模式的单次 accept-and-serve（生产 [`AcceptServe`]）：创建控制面管道（DACL =
/// SYSTEM + core 用户 SID，reject_remote_clients 继承）→ accept → [`verify_service_peer`]
/// （SID-only，pid 不固定）→ **pre-gRPC 握手**（D2 + S6：engine 自报身份帧 + PSK-HMAC
/// 双向挑战；持有共享 PSK 且身份可验才放行）→ serve gRPC 直至该连接关闭 → 返回
/// `Ok(true)` 继续 accept。
///
/// 独立 verify 语义：未授权 peer（SID 不匹配 / PSK 挑战失败 / 身份帧失败）连接被拒——
/// 记录并继续 accept（单次连接失败不拖垮常驻服务）；管道创建/accept/serve 硬失败才
/// 上报 `Err`（循环终止）。exe 路径 + SYSTEM 的既有 SID 验证保留为 fail-closed 兜底；
/// PSK 是 service 模式的主认证机制（D2），自报身份是其上的 server 身份确认（S6）。
pub struct ServiceAcceptor {
    /// 控制面 Named Pipe 名（服务模式为稳定名，非按 core PID 唯一）。
    name: String,
    /// 授权 core 用户 SID（安装用户；管道 DACL + 每次 accept 的 peer 验证）。
    core_sid: String,
    /// service 模式 PSK（安装时生成；engine 启动读入）。缺文件 → 启动失败（fail closed）。
    psk: [u8; 32],
    /// engine 自身身份（PID + SID，自进程 token 读取免特权）——pre-gRPC 握手时自报。
    identity: ProcessIdentity,
    /// tonic HelperControl server（`HelperControlServer` 经 Arc 封装，Clone 共享同一服务）。
    service: HelperControlServer<HelperControlService>,
    ready: Option<ControlPlaneReady>,
    /// S3/Tier 2：控制面就绪的**可查询持久布尔**（`ServiceSelfState.control_plane_ready` 的
    /// 同一载体）——`serve_one` 建管 + `report_ready` 成功后置 true；`ServiceManage.query`
    /// 经 `HelperControlService.service_self` 读同一 `Arc`。与一次性 oneshot
    /// [`ControlPlaneReady`] 是同一事实的不同载体，不得互相替代。
    control_plane_ready: Arc<AtomicBool>,
    /// 是否已创建管道名的首实例（`FILE_FLAG_FIRST_PIPE_INSTANCE`）。首个连接用
    /// first=true；其后用 first=false 创建多实例——连接存活时旧实例被占不影响新 accept。
    first_instance_created: bool,
}

impl ServiceAcceptor {
    /// 用稳定管道名 + 授权 SID + PSK + 自报身份 + tonic server 构造。
    ///
    /// `identity` 是 engine 自身身份（`serve_named_pipe_loop` 经 `current_process_identity`
    /// 解析；SYSTEM 服务进程自报 `S-1-5-18`，标准用户 core 据此免特权验证）。
    #[must_use]
    pub fn new(
        name: String,
        core_sid: String,
        psk: [u8; 32],
        identity: ProcessIdentity,
        service: HelperControlServer<HelperControlService>,
        ready: Option<ControlPlaneReady>,
        control_plane_ready: Arc<AtomicBool>,
    ) -> Self {
        Self {
            name,
            core_sid,
            psk,
            identity,
            service,
            ready,
            control_plane_ready,
            first_instance_created: false,
        }
    }
}

impl AcceptServe for ServiceAcceptor {
    async fn serve_one(&mut self) -> Result<bool, String> {
        // 多实例管道：首个连接 first=true 建首实例；其后 first=false 建后续实例（每次
        // accept 独立实例，旧实例被连接占用时不影响新实例创建——根治单实例下重建
        // ERROR_PIPE_BUSY 导致的「连接后服务退出」）。瞬时建管失败仍有界重试兜底。
        const SERVICE_PIPE_MAX_INSTANCES: usize = 4;
        let first_instance = !self.first_instance_created;
        let mut server = None;
        for attempt in 0..5u32 {
            match create_control_pipe_server(
                &self.name,
                &self.core_sid,
                first_instance,
                SERVICE_PIPE_MAX_INSTANCES,
            ) {
                Ok(s) => {
                    server = Some(s);
                    self.first_instance_created = true;
                    if let Some(mut ready) = self.ready.take() {
                        ready.report_ready()?;
                        // S3/Tier 2：建管 + report_ready 成功 → 控制面就绪（query 读同一
                        // 事实）。ready oneshot 是一次性通知；AtomicBool 是可查询持久布尔。
                        self.control_plane_ready.store(true, Ordering::SeqCst);
                    }
                    break;
                }
                Err(e) if attempt < 4 => {
                    tracing::warn!(
                        attempt,
                        error = %e,
                        "create control pipe transient failure, retrying"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(e) => {
                    let error = format!("create control pipe: {e}");
                    if let Some(mut ready) = self.ready.take() {
                        let _ = ready.report_error(error.clone());
                    }
                    return Err(error);
                }
            }
        }
        let server = server.expect("bounded retry yields a pipe or returns");
        server
            .connect()
            .await
            .map_err(|e| format!("accept core connection: {e}"))?;

        let info = match verify_service_peer(&server, &self.core_sid) {
            Ok(info) => info,
            Err(e) => {
                tracing::warn!(error = %e, "service accept rejected unverified peer");
                return Ok(true); // 独立 verify：拒绝该连接，继续 accept。
            }
        };

        // D2 + S6：PSK-HMAC 双向挑战（service 模式主认证；SID 之上的第二层），握手首帧
        // 携带 engine 自报身份（PID + SID）。挑战/身份失败 → fail closed 拒绝该连接
        // （单次连接失败不拖垮常驻服务）。
        let mut server = server;
        if let Err(e) = psk_challenge_server(&mut server, &self.psk, &self.identity).await {
            tracing::warn!(error = %e, "service accept rejected psk challenge");
            return Ok(true);
        }

        let io = VerifiedNamedPipeServer::new(server, info);
        let incoming = tokio_stream::iter(vec![Ok::<_, std::io::Error>(io)]);
        let router = Server::builder()
            .layer(tonic::service::InterceptorLayer::new(require_verified_peer))
            .add_service(self.service.clone());
        // tonic `serve_with_incoming` 对每个连接 `tokio::spawn` 且不 await（单元素流
        // 接受后立即返回），连接在其 spawned task 中存活。配合**多实例管道**（每个
        // accept 一个独立实例，`first_pipe_instance(false)`），连接存活时旧实例被占也
        // 不影响下一次 accept 创建新实例——服务可连续接受/重连，不再 ERROR_PIPE_BUSY。
        router
            .serve_with_incoming(incoming)
            .await
            .map_err(|e| format!("gRPC serve: {e}"))?;
        Ok(true)
    }
}

/// 服务模式便捷入口：连续 accept + 独立 verify + PSK 挑战 + 独立 owner 流，直至 SCM
/// stop 或服务端关闭。ServiceMain 仅做薄壳——把 SCM 停止信号接进 `stop_rx` 后调用。
///
/// `psk` 是服务模式共享秘密（安装时生成，engine 启动读入）；PSK 缺失 → 服务启动失败
/// （fail closed，D2——服务无 PSK 即拒绝一切连接）。
///
/// `control_plane_ready` 是与 [`HelperControlService`] 共享的 `Arc<AtomicBool>`
/// （S3/Tier 2）：`ServiceAcceptor` 建管 + `report_ready` 成功后置 true，`query` 读同一事实。
pub async fn serve_named_pipe_loop(
    name: &str,
    core_sid: &str,
    psk: [u8; 32],
    service: HelperControlServer<HelperControlService>,
    stop_rx: tokio::sync::watch::Receiver<bool>,
    mut ready: Option<ControlPlaneReady>,
    control_plane_ready: Arc<AtomicBool>,
) -> AcceptLoopOutcome {
    // S6：engine 自报身份（PID + SID）——自进程 token 读取免特权；解析失败 → 启动失败
    // fail closed（服务无自报身份即拒绝一切连接）。
    let identity = match current_process_identity() {
        Some(identity) => {
            tracing::info!(
                pid = identity.process_id,
                sid = %identity.user_sid,
                "engine self identity resolved (service accept loop)"
            );
            identity
        }
        None => {
            let error = "cannot resolve engine self identity".to_string();
            tracing::error!("{error}");
            if let Some(ref mut ready) = ready {
                let _ = ready.report_error(error.clone());
            }
            return AcceptLoopOutcome::Failed(error);
        }
    };
    let acceptor = ServiceAcceptor::new(
        name.to_string(),
        core_sid.to_string(),
        psk,
        identity,
        service,
        ready,
        control_plane_ready,
    );
    accept_loop(acceptor, stop_rx).await
}

/// The current user's SID, or a typed failure (mirrors the legacy fallback when no core SID
/// is supplied: the engine trusts the same user as itself).
///
/// # Errors
/// Returns a failure when the current process's user SID cannot be resolved.
pub fn engine_default_core_sid() -> Result<String, String> {
    current_user_sid().ok_or_else(|| "cannot resolve current user SID".to_string())
}

// ---------------------------------------------------------------------------
// 单元测试：`create_control_pipe_server` 的 DACL 真实生效（Bug C 回归护栏）。
//
// 旧实现把 `PSECURITY_DESCRIPTOR` 当 `SECURITY_ATTRIBUTES*` 传给 tokio → OS 读 garbage
// DACL，同进程碰巧可用、跨进程被拒。下面两个测试钉死：DACL 确实交到了 CreateNamedPipeW
// （未授权用户连接必须被拒 = 5，授权用户可连）——对旧实现失败（garbage DACL 会让本机
// 用户连上或创建失败），对修复后实现通过。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use exv_vpn_win32_ipc::named_pipe_io::{NamedPipeByteStream, PipeIoError};
    use exv_vpn_win32_ipc::peer_auth::current_user_sid;
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    use super::*;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_pipe(tag: &str) -> String {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\exv-ctrl-dacl-{tag}-{}-{n}", std::process::id())
    }

    /// DACL 授权 core 用户 SID 时，当前用户（非提权 token 亦可）能连上控制面管道。
    #[tokio::test]
    async fn control_pipe_dacl_allows_current_user_connect() {
        let sid = current_user_sid().expect("current user sid");
        let name = unique_pipe("allow");
        let server = create_control_pipe_server(&name, &sid, true, 1).expect("create control pipe");
        let client =
            NamedPipeByteStream::connect_client(&name).expect("current user must connect");
        server.connect().await.expect("server accept");
        drop(client);
    }

    /// DACL 未授权当前用户（只授 SYSTEM + 伪造域 SID）时，客户端连接必须被拒
    /// （ERROR_ACCESS_DENIED = 5）——证明 `create_control_pipe_server` 确实把
    /// `SECURITY_ATTRIBUTES`（含 DACL）交到了 `CreateNamedPipeW`。旧实现（传
    /// `PSECURITY_DESCRIPTOR`，DACL garbage）下本测试会失败。
    #[tokio::test]
    async fn control_pipe_dacl_denies_unlisted_user() {
        // 当前用户不可能持有的伪造域 SID；DACL = SYSTEM + 该 SID，普通客户端在
        // CreateFileW 阶段即被 ACL 拒绝。
        let bogus = "S-1-5-21-1000000000-1000000000-1000000000-1001";
        let name = unique_pipe("deny");
        let server = create_control_pipe_server(&name, bogus, true, 1).expect("create control pipe");
        let err = NamedPipeByteStream::connect_client(&name)
            .expect_err("unlisted user must be denied by the DACL");
        assert_eq!(
            err,
            PipeIoError::Io(ERROR_ACCESS_DENIED.0),
            "unlisted user connect must fail with ERROR_ACCESS_DENIED (5)"
        );
        drop(server);
    }

    // -------------------------------------------------------------------------
    // 服务 accept-loop（S2）：注入 fake [`AcceptServe`] 验证循环控制流——
    // 连续 accept / SCM stop / 服务端关闭 / 失败传播。真实管道 accept+verify+serve
    // 由真机集成覆盖（tests/service_lifecycle.rs，env 门控）。
    // -------------------------------------------------------------------------

    /// 记录型 fake acceptor：可配置连续 N 次后服务端关闭、或第 1 次即失败。
    ///
    /// 注：每次 serve 前 `sleep(1ms)` 模拟真实 [`ServiceAcceptor`] 阻塞于 accept 的
    /// 行为——当前线程 tokio runtime 下，完全立即返回的 busy-loop 会饿死计时器驱动
    /// （SCM stop 信号测试将永不触发）。
    struct FakeAcceptor {
        served: u32,
        stop_after: Option<u32>,
        fail_with: Option<String>,
    }

    impl AcceptServe for FakeAcceptor {
        async fn serve_one(&mut self) -> Result<bool, String> {
            if let Some(fail) = &self.fail_with {
                return Err(fail.clone());
            }
            // 模拟真实 accept 阻塞（真实 acceptor await pipe connect，让出驱动）。
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            self.served += 1;
            if let Some(n) = self.stop_after
                && self.served >= n
            {
                return Ok(false);
            }
            Ok(true)
        }
    }

    /// 连续 accept：服务端每次 serve_one 返回继续 → 循环持续推进，直到服务端关闭。
    #[tokio::test]
    async fn accept_loop_continues_until_server_closed() {
        let acceptor = FakeAcceptor {
            served: 0,
            stop_after: Some(3),
            fail_with: None,
        };
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let outcome = accept_loop(acceptor, rx).await;
        assert_eq!(
            outcome,
            AcceptLoopOutcome::ServerClosed,
            "服务端关闭（Ok(false)）必须结束循环"
        );
    }

    /// SCM stop：循环运行中 stop 信号置位 → [`AcceptLoopOutcome::Stopped`]（SCM stop →
    /// 退出清理路径的入口触发）。
    #[tokio::test]
    async fn accept_loop_stops_on_scm_stop_signal() {
        let acceptor = FakeAcceptor {
            served: 0,
            stop_after: None,
            fail_with: None,
        };
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(accept_loop(acceptor, rx));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        tx.send(true).expect("stop signal send");
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handle,
        )
        .await
        .expect("loop within timeout")
        .expect("task ok");
        assert_eq!(
            outcome,
            AcceptLoopOutcome::Stopped,
            "SCM stop 信号必须结束 accept-loop（退出清理入口）"
        );
    }

    /// 停止信号发送端 drop → 视同停止（防 busy-loop：无停止信号可再等）。
    #[tokio::test]
    async fn accept_loop_treats_sender_drop_as_stop() {
        let acceptor = FakeAcceptor {
            served: 0,
            stop_after: None,
            fail_with: None,
        };
        let (tx, rx) = tokio::sync::watch::channel(false);
        drop(tx); // 发送端终结：无后续信号，循环必须退出而非空转。
        let outcome = accept_loop(acceptor, rx).await;
        assert_eq!(
            outcome,
            AcceptLoopOutcome::Stopped,
            "停止信号发送端 drop 必须视同停止（防 busy-loop）"
        );
    }

    /// 失败传播：serve_one 返回 Err → [`AcceptLoopOutcome::Failed`]（携带原因）。
    #[tokio::test]
    async fn accept_loop_propagates_serve_failure() {
        let acceptor = FakeAcceptor {
            served: 0,
            stop_after: None,
            fail_with: Some("boom".to_string()),
        };
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let outcome = accept_loop(acceptor, rx).await;
        assert_eq!(
            outcome,
            AcceptLoopOutcome::Failed("boom".to_string()),
            "serve_one 失败必须传播"
        );
    }
}
