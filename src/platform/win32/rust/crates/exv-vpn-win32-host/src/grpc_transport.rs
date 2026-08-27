// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core→engine 的 tonic gRPC 传输层：Tokio Windows Named Pipe（spec §9.4）。
//!
//! 产品 wire 是 tonic gRPC（P1 决策），承载在双向认证的 Named Pipe 上（TG-WIN 的
//! "Named Pipe mutual auth"）。本模块提供 client 侧拨号：
//!
//! - [`dial_control_pipe_with_retry`]：带界重试的 async Named Pipe 拨号（engine
//!   可能仍在启动建管道的竞窗，复用 legacy `control_client` 的重试语义）；
//! - [`verify_engine_server_pipe`]：client 侧验证 engine（server）进程身份——实测
//!   server pid 必须等于期望 pid，其 user SID 必须等于期望 SID（spec §9.4 "core 也
//!   验证 engine/server identity"），任何查询失败 fail closed；
//! - [`NamedPipeConnector`]：tower `Service<Uri>`，把已拨号且已验证的 pipe 包装为
//!   tonic transport stream（`TokioIo<NamedPipeClient>`），与 tonic 自带 UDS
//!   connector 同构；
//! - [`connect_engine_channel`]：一次拨号 + 验证后构造 HTTP/2 `Channel`。
//!
//! 对端（engine）侧验证 core 的 pid+SID 是 server 的职责（P1-b/§9.4），不在本模块。
//! peer 认证只来自已验证的连接元数据，endpoint 名/路径不是 capability（§9.4）。

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tonic::transport::{Channel, Endpoint};
use tower::Service;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;

use exv_vpn_win32_ipc::peer_auth::{
    decode_identity_frame, process_sid, ProcessIdentity, VerifiedPipePeer,
    IDENTITY_FRAME_HEADER_LEN, IDENTITY_FRAME_MAX_SID_LEN,
};
use exv_vpn_win32_ipc::service_key::{ct_eq, hmac_sha256, random_32};

/// 拨号重试次数（engine 启动竞窗；与 legacy `connect_pipe_with_retry` 同量级）。
const DIAL_ATTEMPTS: u32 = 30;
/// 重试间隔。
const DIAL_RETRY_DELAY: Duration = Duration::from_millis(100);
/// 渠道构建 connect 超时（包裹 connector 的整次拨号+验证）。
const CHANNEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// client 侧传输层错误。所有失败 fail closed。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrpcPipeError {
    /// Named Pipe 拨号失败（含重试耗尽）；携带最后 Win32 错误码。
    Dial(u32),
    /// engine server 身份与期望 pid/SID 不匹配，或身份查询失败。
    Auth(String),
    /// tonic channel 构建失败。
    Transport(String),
}

impl fmt::Display for GrpcPipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dial(code) => write!(f, "control pipe dial failed (win32 error {code})"),
            Self::Auth(reason) => write!(f, "engine peer authentication failed: {reason}"),
            Self::Transport(reason) => write!(f, "gRPC channel build failed: {reason}"),
        }
    }
}

impl std::error::Error for GrpcPipeError {}

/// 拨号 engine 控制面 Named Pipe：`ERROR_FILE_NOT_FOUND`/`ERROR_PIPE_BUSY` 有界
/// 重试（engine 可能仍在启动建管道的竞窗）。
///
/// # Errors
/// 重试耗尽或遇到非重试错误 → `GrpcPipeError::Dial`。
pub async fn dial_control_pipe_with_retry(name: &str) -> Result<NamedPipeClient, GrpcPipeError> {
    let mut last = GrpcPipeError::Dial(2);
    for _ in 0..DIAL_ATTEMPTS {
        match ClientOptions::new().open(name) {
            Ok(pipe) => return Ok(pipe),
            Err(e) => {
                // 2 = ERROR_FILE_NOT_FOUND（server 尚未创建）；231 = ERROR_PIPE_BUSY。
                let code = e.raw_os_error().unwrap_or(0) as u32;
                last = GrpcPipeError::Dial(code);
                if code == 2 || code == 231 {
                    tokio::time::sleep(DIAL_RETRY_DELAY).await;
                    continue;
                }
                return Err(last);
            }
        }
    }
    Err(last)
}

/// client 侧验证 engine（server）进程身份：实测 server pid 必须等于 `expected_pid`，
/// 实测 server user SID 必须等于 `expected_sid`（spec §9.4）。任何查询失败 fail
/// closed。这是 legacy `verify_engine_server` 在 async Named Pipe 句柄上的对应。
///
/// # Errors
/// pid/SID 不匹配或身份无法解析 → `GrpcPipeError::Auth`。
pub fn verify_engine_server_pipe(
    pipe: &NamedPipeClient,
    expected_pid: u32,
    expected_sid: &str,
) -> Result<VerifiedPipePeer, GrpcPipeError> {
    use std::os::windows::io::AsRawHandle;

    let mut pid = 0u32;
    // SAFETY: `pipe.as_raw_handle()` 是已连接的 client pipe 句柄，`pid` 是有效输出参数。
    if let Err(e) = unsafe {
        // `as_raw_handle()` 已返回 `*mut c_void`，无需再 cast（clippy::unnecessary_cast）。
        GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &raw mut pid)
    } {
        return Err(GrpcPipeError::Auth(format!(
            "server process query failed: {e}"
        )));
    }
    if pid != expected_pid {
        return Err(GrpcPipeError::Auth(format!(
            "engine pid mismatch: expected {expected_pid}, observed {pid}"
        )));
    }
    let sid = process_sid(pid).ok_or_else(|| {
        GrpcPipeError::Auth(format!("cannot resolve user SID of engine pid {pid}"))
    })?;
    if sid != expected_sid {
        return Err(GrpcPipeError::Auth(format!(
            "engine SID mismatch: expected {expected_sid}, observed {sid}"
        )));
    }
    Ok(VerifiedPipePeer {
        process_id: pid,
        user_sid: sid,
        logon_sid: None,
        account_name: String::new(),
    })
}

/// tower `Service<Uri>`：把一次拨号并验证过的 engine 控制面 pipe 交给 tonic channel。
///
/// 与 tonic 自带 UDS connector 同构（`Response = TokioIo<NamedPipeClient>`）。首个
/// `call` 消费预拨号且已验证的连接（`warm`），后续 `call`（channel 重连）现场
/// 拨号并重新验证 engine 身份。`Uri` 只作占位——真实传输是 Named Pipe，endpoint
/// 名不携带路由/授权语义（§9.4）。
pub struct NamedPipeConnector {
    pipe_name: String,
    expected_pid: u32,
    expected_sid: String,
    /// 预拨号且已验证的连接，交给 channel 的首个 dial（`None` 之后每次现场拨号）。
    warm: Option<NamedPipeClient>,
    /// 已验证的 engine peer（供调用方读取）。
    verified_peer: Arc<Mutex<Option<VerifiedPipePeer>>>,
}

impl NamedPipeConnector {
    /// 用预拨号且已验证的 `warm` 连接构造 connector。
    #[must_use]
    pub fn with_warm(
        pipe_name: String,
        expected_pid: u32,
        expected_sid: String,
        warm: NamedPipeClient,
    ) -> Self {
        Self {
            pipe_name,
            expected_pid,
            expected_sid,
            warm: Some(warm),
            verified_peer: Arc::new(Mutex::new(None)),
        }
    }
}

impl Service<Uri> for NamedPipeConnector {
    type Response = TokioIo<NamedPipeClient>;
    type Error = GrpcPipeError;
    type Future = NamedPipeConnecting;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let pipe_name = self.pipe_name.clone();
        let expected_pid = self.expected_pid;
        let expected_sid = self.expected_sid.clone();
        let verified_peer = Arc::clone(&self.verified_peer);
        let warm = self.warm.take();
        let fut = async move {
            let pipe = match warm {
                Some(pipe) => pipe,
                None => dial_control_pipe_with_retry(&pipe_name).await?,
            };
            let peer = verify_engine_server_pipe(&pipe, expected_pid, &expected_sid)?;
            *verified_peer.lock().expect("verified peer lock") = Some(peer);
            Ok(TokioIo::new(pipe))
        };
        NamedPipeConnecting {
            inner: Box::pin(fut),
        }
    }
}

type ConnectorResult = Result<TokioIo<NamedPipeClient>, GrpcPipeError>;

/// `NamedPipeConnector` 的拨号 future。
pub struct NamedPipeConnecting {
    inner: Pin<Box<dyn Future<Output = ConnectorResult> + Send>>,
}

impl Future for NamedPipeConnecting {
    type Output = ConnectorResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

/// 拨号并验证 engine 控制面 pipe，随后构建 tonic gRPC `Channel`。
///
/// 单次拨号：先 `dial_control_pipe_with_retry` + `verify_engine_server_pipe`
/// （fail closed，typed 错误直接暴露给调用方），再把该已验证连接作为 connector
/// 的 `warm` 交给 channel——不会重复拨号。返回 (channel, 已验证的 engine peer)。
///
/// # Errors
/// 拨号失败 → `GrpcPipeError::Dial`；身份不匹配 → `GrpcPipeError::Auth`；channel
/// 构建失败 → `GrpcPipeError::Transport`。
pub async fn connect_engine_channel(
    pipe_name: &str,
    expected_engine_pid: u32,
    expected_user_sid: &str,
) -> Result<(Channel, VerifiedPipePeer), GrpcPipeError> {
    let warm = dial_control_pipe_with_retry(pipe_name).await?;
    let peer = verify_engine_server_pipe(&warm, expected_engine_pid, expected_user_sid)?;

    let connector = NamedPipeConnector::with_warm(
        pipe_name.to_string(),
        expected_engine_pid,
        expected_user_sid.to_string(),
        warm,
    );
    let endpoint = Endpoint::from_static("http://engine.local")
        .connect_timeout(CHANNEL_CONNECT_TIMEOUT);
    let channel = endpoint
        .connect_with_connector(connector)
        .await
        .map_err(|e| GrpcPipeError::Transport(e.to_string()))?;
    Ok((channel, peer))
}

/// client 侧验证 **service-mode** engine（server）进程身份（S6 自报身份方案）：从 pipe 读取
/// engine **自报身份帧**（PID + SID），再交叉核验/比对：
///
/// 1. **PID 交叉核验**：自报 PID 必须等于 `GetNamedPipeServerProcessId`（管道对端进程，
///    OS 权威，无需 `OpenProcess` 特权——标准用户对 SYSTEM 会话 0 服务进程 `OpenProcess`
///    必失败，S5 真机实测 err=5）；
/// 2. **SID 比对**：自报 SID 必须等于 `expected_sid`（服务 engine 由 SCM 以 LocalSystem
///    运行 → [`SYSTEM_SID`]）。
///
/// 取代旧 `verify_engine_server_sid_only` 的 `process_sid`（`OpenProcess` 读 SYSTEM 进程
/// token）路径——该路径在标准用户 core 下必失败，engine 自报是免特权替代。与 oneshot 不同，
/// PID **不固定**——SCM 常驻 engine 跨 core 生命周期，每次 accept 是不同进程（同 SID）。
/// 任何查询 / 帧解析 / 比对失败 → fail closed。
///
/// # Errors
/// 身份帧缺失 / 畸形 / PID 或 SID 不匹配 → `GrpcPipeError::Auth`。
pub async fn verify_engine_self_identity(
    pipe: &mut NamedPipeClient,
    expected_sid: &str,
) -> Result<VerifiedPipePeer, GrpcPipeError> {
    let identity = read_identity_frame(pipe).await?;
    let server_pid = pipe_server_process_id(pipe)?;
    if identity.process_id != server_pid {
        return Err(GrpcPipeError::Auth(format!(
            "service engine pid mismatch: self-reported {}, pipe server {server_pid}",
            identity.process_id
        )));
    }
    if identity.user_sid != expected_sid {
        return Err(GrpcPipeError::Auth(format!(
            "service engine SID mismatch: expected {expected_sid}, self-reported {}",
            identity.user_sid
        )));
    }
    Ok(VerifiedPipePeer {
        process_id: identity.process_id,
        user_sid: identity.user_sid,
        logon_sid: None,
        account_name: String::new(),
    })
}

/// 读取 pre-gRPC 自报身份帧（6 字节头 + 变长 UTF-8 SID）。帧畸形 / SID 长度超限 /
/// 非 UTF-8 → fail closed（编解码统一在 ipc `peer_auth`，避免两侧线格式漂移）。
///
/// # Errors
/// 读失败 / 畸形帧 → `GrpcPipeError::Auth`。
async fn read_identity_frame(pipe: &mut NamedPipeClient) -> Result<ProcessIdentity, GrpcPipeError> {
    let mut header = [0u8; IDENTITY_FRAME_HEADER_LEN];
    pipe.read_exact(&mut header)
        .await
        .map_err(|e| GrpcPipeError::Auth(format!("self-identity frame: read header: {e}")))?;
    let len = u16::from_le_bytes([header[4], header[5]]) as usize;
    if len > IDENTITY_FRAME_MAX_SID_LEN {
        return Err(GrpcPipeError::Auth(format!(
            "self-identity frame: SID length {len} exceeds cap {IDENTITY_FRAME_MAX_SID_LEN}"
        )));
    }
    let mut body = vec![0u8; len];
    pipe.read_exact(&mut body)
        .await
        .map_err(|e| GrpcPipeError::Auth(format!("self-identity frame: read sid: {e}")))?;
    let mut frame = Vec::with_capacity(IDENTITY_FRAME_HEADER_LEN + len);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&body);
    decode_identity_frame(&frame)
        .ok_or_else(|| GrpcPipeError::Auth("self-identity frame: malformed".to_string()))
}

/// 管道对端（server）进程 PID——`GetNamedPipeServerProcessId`，无需 `OpenProcess` 特权。
///
/// # Errors
/// 查询失败 → `GrpcPipeError::Auth`。
fn pipe_server_process_id(pipe: &NamedPipeClient) -> Result<u32, GrpcPipeError> {
    use std::os::windows::io::AsRawHandle;

    let mut pid = 0u32;
    // SAFETY: `pipe.as_raw_handle()` 是已连接的 client pipe 句柄，`pid` 是有效输出参数。
    if let Err(e) = unsafe {
        GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &raw mut pid)
    } {
        return Err(GrpcPipeError::Auth(format!(
            "service engine process query failed: {e}"
        )));
    }
    Ok(pid)
}

/// 服务模式 pre-gRPC 完整握手（client 侧）：engine 自报身份验证（PID 交叉核验 + SID 比对）
/// → PSK-HMAC 双向挑战。取代旧 `verify_engine_server_sid_only` + `psk_challenge_client`
/// 的两步。
///
/// 双向 fail-closed：身份帧缺失/畸形/不匹配，或 PSK 应答不匹配 → `Err(GrpcPipeError::Auth)`
/// （不进入 gRPC 派发）。PSK 仍为主认证，自报 SID 是 server 身份确认（S6）。
///
/// # Errors
/// 身份 / PSK 任一不通过 → `GrpcPipeError::Auth`。
pub async fn service_peer_handshake(
    pipe: &mut NamedPipeClient,
    expected_sid: &str,
    psk: &[u8],
) -> Result<VerifiedPipePeer, GrpcPipeError> {
    let peer = verify_engine_self_identity(pipe, expected_sid).await?;
    psk_challenge_client(pipe, psk).await?;
    Ok(peer)
}

/// 服务模式 pre-gRPC PSK-HMAC 挑战（client 侧，D2，握手第 1–3 步）：读取 server nonce →
/// 应答 `HMAC(psk, nonce_e || "c2e")` + 自己的 nonce_s → 恒时验证 server 应答
/// `HMAC(psk, nonce_s || "e2c")`。与 engine `psk_challenge_server` 逐帧对称。
///
/// 注：完整握手（身份帧 + 本挑战）由 [`service_peer_handshake`] 编排——调用方应优先使用
/// 它，而非单独调用本函数（身份帧先于本挑战读取，单独调用会错序）。
///
/// 双向 fail-closed：server 应答不匹配 → `Err(GrpcPipeError::Auth)`（不进入 gRPC 派发）。
///
/// # Errors
/// 读 / 写 / 应答不匹配 → `GrpcPipeError::Auth`。
pub async fn psk_challenge_client(pipe: &mut NamedPipeClient, psk: &[u8]) -> Result<(), GrpcPipeError> {
    // 1. 读 server nonce。
    let mut nonce_e = [0u8; 32];
    pipe.read_exact(&mut nonce_e)
        .await
        .map_err(|e| GrpcPipeError::Auth(format!("psk challenge: read nonce: {e}")))?;
    // 2. 应答 + 自己的 nonce（64 字节）。
    let nonce_s = random_32().map_err(GrpcPipeError::Auth)?;
    let response = hmac_sha256(psk, &tagged(&nonce_e, b"c2e"));
    pipe.write_all(&response)
        .await
        .map_err(|e| GrpcPipeError::Auth(format!("psk challenge: send response: {e}")))?;
    pipe.write_all(&nonce_s)
        .await
        .map_err(|e| GrpcPipeError::Auth(format!("psk challenge: send nonce: {e}")))?;
    // 3. 恒时验证 server 应答。
    let mut reply = [0u8; 32];
    pipe.read_exact(&mut reply)
        .await
        .map_err(|e| GrpcPipeError::Auth(format!("psk challenge: read reply: {e}")))?;
    let expected = hmac_sha256(psk, &tagged(&nonce_s, b"e2c"));
    if !ct_eq(&reply, &expected) {
        return Err(GrpcPipeError::Auth("psk challenge: reply mismatch".to_string()));
    }
    Ok(())
}

/// `base || suffix`（challenge 域标签；与 engine 侧同构）。
fn tagged(base: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(base.len() + suffix.len());
    out.extend_from_slice(base);
    out.extend_from_slice(suffix);
    out
}

/// 服务模式 tower `Service<Uri>`：每次拨号（含 channel 重连）都做完整握手（engine 自报
/// 身份验证 + PSK-HMAC 挑战）后才把 pipe 交给 tonic——重连不会绕过认证（D2 主认证 +
/// S6 身份确认必须逐连接施加）。
pub struct ServicePipeConnector {
    pipe_name: String,
    expected_sid: String,
    psk: [u8; 32],
    /// 预拨号且**已完整握手**的 warm 连接 + 其已验证 peer（`connect_engine_service_channel`
    /// 传入；首次 `call` 消费，其后每次现场拨号 + 现场握手）。
    warm: Option<(NamedPipeClient, VerifiedPipePeer)>,
    /// 已验证的 engine peer（供调用方读取）。
    verified_peer: Arc<Mutex<Option<VerifiedPipePeer>>>,
}

impl ServicePipeConnector {
    /// 用预拨号且已完整握手的 `warm` 连接 + `warm_peer` 构造 connector。
    ///
    /// 注：warm 连接**已消费过**握手帧（身份 + PSK），首次 `call` 不再重复握手；重连
    /// （`None`）现场拨号并现场握手。
    #[must_use]
    pub fn with_warm(
        pipe_name: String,
        expected_sid: String,
        psk: [u8; 32],
        warm: NamedPipeClient,
        warm_peer: VerifiedPipePeer,
    ) -> Self {
        Self {
            pipe_name,
            expected_sid,
            psk,
            warm: Some((warm, warm_peer)),
            verified_peer: Arc::new(Mutex::new(None)),
        }
    }
}

impl Service<Uri> for ServicePipeConnector {
    type Response = TokioIo<NamedPipeClient>;
    type Error = GrpcPipeError;
    type Future = ServicePipeConnecting;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let pipe_name = self.pipe_name.clone();
        let expected_sid = self.expected_sid.clone();
        let psk = self.psk;
        let verified_peer = Arc::clone(&self.verified_peer);
        let warm = self.warm.take();
        let fut = async move {
            // warm 连接已完整握手（身份 + PSK）；重连现场拨号 + 现场握手（不绕过认证）。
            let (pipe, peer) = match warm {
                Some((pipe, peer)) => (pipe, peer),
                None => {
                    let mut pipe = dial_control_pipe_with_retry(&pipe_name).await?;
                    let peer = service_peer_handshake(&mut pipe, &expected_sid, &psk).await?;
                    (pipe, peer)
                }
            };
            *verified_peer.lock().expect("verified peer lock") = Some(peer);
            Ok(TokioIo::new(pipe))
        };
        ServicePipeConnecting {
            inner: Box::pin(fut),
        }
    }
}

/// `ServicePipeConnector` 的拨号+挑战 future。
pub struct ServicePipeConnecting {
    inner: Pin<Box<dyn Future<Output = ConnectorResult> + Send>>,
}

impl Future for ServicePipeConnecting {
    type Output = ConnectorResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().inner.as_mut().poll(cx)
    }
}

/// 拨号 + 完整握手（engine 自报身份验证 + PSK-HMAC 挑战）后构建 service-mode tonic `Channel`。
///
/// 首次连接（warm）与 channel 重连（现场拨号）都由 [`ServicePipeConnector`] 施加完整
/// 认证；`psk` 是共享秘密（core 从 `%ProgramData%\exv\service.key` 读入）。`warm` 在
/// 拨号后立即完成握手（身份 + PSK），以其构造 connector 的 warm（首次 `call` 不再重复）。
///
/// # Errors
/// 拨号失败 → `GrpcPipeError::Dial`；身份/PSK 不通过 → `GrpcPipeError::Auth`；channel
/// 构建失败 → `GrpcPipeError::Transport`。
pub async fn connect_engine_service_channel(
    pipe_name: &str,
    expected_user_sid: &str,
    psk: &[u8],
) -> Result<(Channel, VerifiedPipePeer), GrpcPipeError> {
    let mut warm = dial_control_pipe_with_retry(pipe_name).await?;
    let peer = service_peer_handshake(&mut warm, expected_user_sid, psk).await?;
    let psk_arr: [u8; 32] = psk
        .try_into()
        .map_err(|_| GrpcPipeError::Auth("service PSK must be 32 bytes".to_string()))?;
    let connector = ServicePipeConnector::with_warm(
        pipe_name.to_string(),
        expected_user_sid.to_string(),
        psk_arr,
        warm,
        peer.clone(),
    );
    let endpoint = Endpoint::from_static("http://engine.local")
        .connect_timeout(CHANNEL_CONNECT_TIMEOUT);
    let channel = endpoint
        .connect_with_connector(connector)
        .await
        .map_err(|e| GrpcPipeError::Transport(e.to_string()))?;
    Ok((channel, peer))
}

// ---------------------------------------------------------------------------
// 单元测试：真实 local Named Pipe（同进程）验证 client 侧 peer 认证 fail closed。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tokio::net::windows::named_pipe::ServerOptions;

    use exv_vpn_win32_ipc::peer_auth::current_user_sid;

    use super::*;

    fn unique_pipe_name(tag: &str) -> String {
        format!(r"\\.\pipe\exv-grpc-transport-{tag}-{}", std::process::id())
    }

    /// client 侧验证同进程 server：pid/SID 必须通过；错误 pid/SID 必须 fail closed。
    ///
    /// server 的 accept 在独立任务中等待 client 连接，避免 accept 与拨号互等死锁。
    #[tokio::test]
    async fn verify_engine_server_pipe_accepts_local_server() {
        let name = unique_pipe_name("verify");
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(name.as_str())
            .expect("create server");
        let accept_task = tokio::spawn(async move {
            server.connect().await.expect("accept client");
        });

        let client = dial_control_pipe_with_retry(&name).await.expect("dial");
        let pid = std::process::id();
        let sid = current_user_sid().expect("current user sid");

        let peer = verify_engine_server_pipe(&client, pid, &sid).expect("verify local server");
        assert_eq!(peer.process_id, pid);
        assert_eq!(peer.user_sid, sid);

        // 错误 PID / SID 必须 fail closed。
        assert!(
            verify_engine_server_pipe(&client, pid + 1, &sid).is_err(),
            "错误 PID 必须拒绝"
        );
        assert!(
            verify_engine_server_pipe(&client, pid, "S-1-0-0").is_err(),
            "错误 SID 必须拒绝"
        );

        drop(client);
        accept_task.await.expect("accept task joins");
    }

    /// 拨号重试：server 尚未存在时（无 server），拨号到重试耗尽必须返回 Dial 错误。
    #[tokio::test]
    async fn dial_fails_closed_when_no_server() {
        let name = unique_pipe_name("absent");
        let err = dial_control_pipe_with_retry(&name).await.expect_err("must fail");
        assert!(matches!(err, GrpcPipeError::Dial(_)), "got {err:?}");
    }
}
