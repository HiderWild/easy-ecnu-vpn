// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core 侧 UI-facing `KernelControl` Named Pipe 传输层（P3-c2：UI↔core 强绑定）。
//!
//! 镜像 helper `grpc_transport::serve_named_pipe`（P1-b，engine 侧），方向相反：**core**
//! 建 UI 连接管道（DACL = SYSTEM + UI 用户 SID），accept 一个 UI 连接，验证 UI peer
//! （client pid + user SID + account name），经 [`KernelControlService::authorize_transport_peer`]
//! 授权 gate（controller transport peer auth 先于一切 secret 转换，spec §5.2/§9.1），随后
//! serve `KernelControlServer`。
//!
//! **UI 生命周期（O3 强绑定）**：`serve_kernel_control_pipe` 在授权后立即拉起状态转发器
//! （R1 `spawn_status_forwarder`）并把 tonic serve 作为内部任务 spawn，返回
//! [`UiKernelControlHandles`]。**UI 退出检测**：tonic `serve_with_incoming` 对单元素
//! 传入流在 accept 后立即返回（流耗尽即 break，连接任务被 detached 继续服务）——
//! serve 任务句柄**不能**当"UI 连接断开"信号（会假 resolve 触发假停机）。真实信号是
//! [`spawn_ui_exit_watcher`]：监视已验证的 UI **进程**（OpenProcess + WaitForSingleObject）
//! 退出 → `UiLifetime::on_ui_exited` → `CoreRuntime` 感知停机；serve 任务以 pending 流
//! 保持存活到 core 停机（abort）释放服务引用。UI 最小化到托盘进程仍存活，信号保持
//! `true`，core 存活。
//!
//! 复用 helper 的传输类型（[`VerifiedNamedPipeServer`]/[`require_verified_peer`]/
//! [`NamedPipeConnectInfo`]）——每个请求经 `require_verified_peer` 拦截，未验证连接
//! 永远到不了 mutation 派发。

use std::ffi::c_void;

use exv_vpn_domain::identity::{ConnectionBindingDigest, PrincipalDigest};
use exv_engine::grpc_transport::{
    require_verified_peer, TransportPeerInfo, VerifiedNamedPipeServer,
};
use exv_vpn_win32_ipc::peer_auth::{process_sid, VerifiedPipePeer};
use exv_vpn_win32_ipc::pipe_security::PipeSecurity;
use exv_vpn_wire::generated::kernel_control_server::KernelControlServer;
use sha2::{Digest, Sha256};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio_stream::StreamExt;
use tonic::transport::Server;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{LookupAccountSidW, SidTypeUser, PSID};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, PROCESS_ACCESS_RIGHTS,
};

use crate::grpc_control::KEEPALIVE_PERIOD;
use crate::kernel_control_service::KernelControlService;
use crate::shutdown::UiLifetime;

/// SYNCHRONIZE（0x00100000）：等待进程句柄退出所需的最小访问权（OpenProcess）。
/// windows crate 0.62 将其挂在 FileSystem 的 FILE_ACCESS_RIGHTS 下；此处直接构造
/// PROCESS_ACCESS_RIGHTS 避免依赖位置（数值 = 标准 access right，稳定）。
const SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);

/// windows `HANDLE`（`*mut c_void`）非 `Send` 的等待封装：进程句柄是线程安全的句柄值，
/// 可跨线程 `WaitForSingleObject`——`unsafe impl Send` 仅用于把句柄移入 `spawn_blocking`
/// 等待线程（等待与关闭在同一线程串行完成，无并发关闭）。
///
/// 注意：必须经 [`WaitHandle::wait_exit_blocking`]（`self` 按值）完成等待——闭包若直接
/// 访问 `handle.0` 字段，Rust 2021 disjoint capture 会捕获裸 `HANDLE`（非 Send），绕过
/// 本 `Send` impl；方法调用强制捕获整个 `WaitHandle`。
struct WaitHandle(HANDLE);
// SAFETY: 进程句柄是独立句柄值；`WaitForSingleObject` 可在任意线程安全调用；句柄释放
// （`CloseHandle`）与等待由同一线程串行完成，无并发关闭。
unsafe impl Send for WaitHandle {}

impl WaitHandle {
    /// 阻塞等待进程句柄 signaled（INFINITE）后关闭句柄（本封装生命周期终结）。
    ///
    /// 调用方应将其置于 `spawn_blocking`/独立线程（阻塞调用，不占异步 worker）。
    fn wait_exit_blocking(self) {
        // SAFETY: self.0 是有效进程句柄；INFINITE（u32::MAX）等待其 signaled。
        unsafe {
            let _ = WaitForSingleObject(self.0, u32::MAX);
        }
        // SAFETY: self.0 使用后关闭。
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// 32 字节 SHA-256 digest（principal/connection 派生；与 helper 同源）。
fn digest32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

/// 经 `LookupAccountSidW` 解析 SID 的 account name（gate 授权需要；任何失败返回空串——
/// 调用方据此 fail closed）。`pub` 供 core 入口（bin crate）构造 composition 绑定的
/// engine peer 身份时复用。
pub fn lookup_account_name(sid: &str) -> String {
    let sid_str = windows::core::HSTRING::from(sid);
    let mut sid_ptr = PSID(std::ptr::null_mut());
    // SAFETY: sid_str 是活宽字符串；sid_ptr 是活输出参数（API 分配，用后 LocalFree）。
    let ok = unsafe {
        ConvertStringSidToSidW(
            windows::core::PCWSTR::from_raw(sid_str.as_ptr()),
            &raw mut sid_ptr,
        )
    };
    if ok.is_err() {
        return String::new();
    }
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let mut name_len = u32::try_from(name.len()).unwrap_or_default();
    let mut domain_len = u32::try_from(domain.len()).unwrap_or_default();
    let mut use_enum = SidTypeUser;
    // SAFETY: name/domain 是活缓冲（长度参数匹配），use_enum 是活输出参数，sid_ptr 是
    // 有效的二进制 SID 结构（ConvertStringSidToSidW 分配）。
    let result = unsafe {
        LookupAccountSidW(
            None,
            sid_ptr,
            Some(windows::core::PWSTR(name.as_mut_ptr())),
            &raw mut name_len,
            Some(windows::core::PWSTR(domain.as_mut_ptr())),
            &raw mut domain_len,
            &raw mut use_enum,
        )
    };
    // SAFETY: sid_ptr 由 ConvertStringSidToSidW 分配，使用后释放。
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            sid_ptr.0,
        )));
    }
    if result.is_err() {
        return String::new();
    }
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    String::from_utf16_lossy(&name[..end])
}

/// 验证连接的 UI（client）peer：client 用户 SID 必须等于 `expected_sid`（同用户拓扑），
/// 并解析 account name（gate 授权需要）。任何身份查询失败 fail closed。
///
/// # Errors
/// SID 不匹配 / 身份无法解析 → 携带原因的字符串。
pub fn verify_ui_peer(server: &NamedPipeServer, expected_sid: &str) -> Result<TransportPeerInfo, String> {
    use std::os::windows::io::AsRawHandle;

    let mut pid = 0u32;
    // SAFETY: `server.as_raw_handle()` 是已连接的 server pipe 句柄，`pid` 是活输出参数。
    if let Err(e) = unsafe {
        GetNamedPipeClientProcessId(
            HANDLE(server.as_raw_handle() as *mut c_void),
            &raw mut pid,
        )
    } {
        return Err(format!("ui process query failed: {e}"));
    }
    let sid = process_sid(pid).ok_or_else(|| format!("cannot resolve user SID of ui pid {pid}"))?;
    if sid != expected_sid {
        return Err(format!(
            "ui SID mismatch: expected {expected_sid}, observed {sid}"
        ));
    }
    let account_name = lookup_account_name(&sid);
    if account_name.is_empty() {
        return Err(format!("cannot resolve account name of ui sid {sid}"));
    }

    // 每连接非 forwardable 的 binding（与 helper `verify_core_peer` 同构）。
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
        account_name,
        principal,
        connection_digest,
    })
}

/// 创建 UI-facing 控制面管道（FIRST_INSTANCE + REJECT_REMOTE_CLIENTS；DACL = SYSTEM +
/// `ui_sid`，经 `PipeSecurity` 冻结形状）。
///
/// # Errors
/// 管道创建失败（另一 core 已持名——first-instance 反 squatting）。
pub fn create_kernel_control_pipe_server(name: &str, ui_sid: &str) -> std::io::Result<NamedPipeServer> {
    let security = PipeSecurity::new(ui_sid, true)
        .map_err(|code| std::io::Error::from_raw_os_error(code as i32))?;
    // `CreateNamedPipeW` 的 `lpSecurityAttributes` 参数是 `SECURITY_ATTRIBUTES*`，**不是**
    // `PSECURITY_DESCRIPTOR`。旧代码传内层 descriptor（tokio 原样转发），OS 会把
    // `SECURITY_DESCRIPTOR` 当 `SECURITY_ATTRIBUTES` 读——DACL 不确定，同进程碰巧可用、
    // 跨进程被拒（ERROR_ACCESS_DENIED/ERROR_INVALID_NAME）。改传 `SECURITY_ATTRIBUTES`
    // 结构本身（其 `lpSecurityDescriptor` 指向 `security` 拥有的活 descriptor），对齐
    // 旧 acceptance `named_pipe_io::create_server_inner` 的可信模式。
    let mut attributes = security.as_attributes();
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1);
    // SAFETY: `attributes` 是活的 `SECURITY_ATTRIBUTES`，其 `lpSecurityDescriptor` 指向
    // `security` 拥有的活 descriptor；两者同一作用域内本调用期间存活。tokio 把指针原样
    // 作为 `CreateNamedPipeW` 的 `lpSecurityAttributes` 转发，创建时复制 DACL。
    unsafe { options.create_with_security_attributes_raw(name, &raw mut attributes as *mut c_void) }
}

/// `serve_kernel_control_pipe` 返回的句柄组（P4 经 `CoreRuntime::set_serve_task` /
/// `set_forwarder_task` 接线）。
#[derive(Debug)]
pub struct UiKernelControlHandles {
    /// 已验证的 UI peer（controller transport peer 身份）。
    pub ui_peer: VerifiedPipePeer,
    /// 运行 `KernelControl` tonic serve 的任务。**不是"UI 断开"信号**——tonic
    /// `serve_with_incoming` 对单元素流在 accept 后立即返回（见模块文档），若把它的
    /// JoinHandle 当 UI 退出判据会假停机；serve 任务以 pending 流保持存活，由
    /// [`spawn_ui_exit_watcher`] 在 UI 进程退出时发真实信号。停机时 abort 本任务以释放
    /// router 持有的服务引用（停止接收 UI 请求）。
    pub serve_task: tokio::task::JoinHandle<()>,
    /// engine 事件转发器任务（持 engine 控制面 Arc；停机先中止以释放引用）。
    pub forwarder: tokio::task::JoinHandle<()>,
    /// P5-b 统计转发器任务（持 engine 控制面 Arc；停机先中止以释放引用）。
    pub stats_forwarder: tokio::task::JoinHandle<()>,
    /// R3 日志转发器任务（持 engine 控制面 Arc + 日志聚合器 Arc；停机先中止以释放
    /// 引用——日志纯单向输出，无状态副作用）。
    pub logs_forwarder: tokio::task::JoinHandle<()>,
    /// C3a 自动重连 worker 任务（持服务克隆；停机先中止以释放引用——否则 worker 永久
    /// 引用服务克隆）。
    pub reconnect_worker: tokio::task::JoinHandle<()>,
    /// P2 KeepAlive 心跳 tick 任务（持 engine 控制面 Arc；停机先中止以释放引用——
    /// engine 侧据此刷新 `last_heartbeat`，15s 未收到即自清理+自退出）。
    pub keepalive_ticker: tokio::task::JoinHandle<()>,
}

/// 监视 UI **进程**退出（O3 强绑定）：进程退出 → `on_ui_exited` → core 停机。
///
/// 用已验证的 UI pid 打开进程句柄并等待其 signaled。选择进程句柄而非管道 EOF 的原因：
/// hyper 独占连接读，core 无法在不与其竞争的情况下自测管道断开；而 UI 进程退出必然
/// 同时关闭其管道端（进程退出 → OS 回收句柄 → hyper 读到 EOF），进程句柄是独立、可靠、
/// 与断线同时发生的信号。UI 最小化到托盘进程仍存活 → 信号保持 `true`。
///
/// fail-safe：`OpenProcess` 失败（进程已退出 / 无法打开）→ 立即判定退出。
fn spawn_ui_exit_watcher(ui_pid: u32, ui: UiLifetime) {
    tokio::spawn(async move {
        // SAFETY: OpenProcess 打开同用户 UI 进程句柄（SYNCHRONIZE 足以等待退出）；
        // 失败即认为 UI 已退出（fail-safe）。
        let handle = match unsafe { OpenProcess(SYNCHRONIZE, false, ui_pid) } {
            Ok(handle) => handle,
            Err(_) => {
                ui.on_ui_exited();
                return;
            }
        };
        // WaitForSingleObject 是阻塞调用 → spawn_blocking 隔离（不占异步 worker）。
        // WaitHandle 提供 Send（windows HANDLE 非 Send，见上）；必须经方法调用触发
        // whole-struct 捕获（disjoint capture 会绕过 Send impl）。
        let handle = WaitHandle(handle);
        let _ = tokio::task::spawn_blocking(move || handle.wait_exit_blocking()).await;
        ui.on_ui_exited();
    });
}

/// serve `KernelControl` 服务给一个 UI 连接（双向认证 + gate 授权 + 传输拦截）。
///
/// 1. 建 UI 控制面管道（DACL = SYSTEM + `ui_sid`）；
/// 2. accept 一个 UI 连接；
/// 3. 验证 UI peer（client pid + user SID + account name）——任何失败 fail closed，
///    在第一个 gRPC frame 解码/派发前拒绝；
/// 4. 经 `KernelControlService::authorize_transport_peer` 授权 gate；
/// 5. 拉起 UI 进程退出监视（[`spawn_ui_exit_watcher`]——O3 强绑定：UI 进程退出 →
///    `on_ui_exited` → core 停机）；
/// 6. 拉起 engine 状态转发器（`spawn_status_forwarder`，R1 seam——engine 已就绪，
///    `WatchEvents` 总线由此开始发布 engine 状态流事件）并把 tonic serve 作为内部任务
///    spawn（pending 流：serve 任务保持存活到 core 停机 abort，**不**当 UI 断开信号）；
/// 7. **立即返回** [`UiKernelControlHandles`]（serve 任务供停机 abort；转发器句柄供
///    停机先中止）——句柄必须在 UI 断开前可用，P4 才能把两者都接进 `CoreRuntime`。
///
/// `ui` 与 `CoreRuntime::new` 共享同一 [`UiLifetime`]——UI 退出信号由本函数持有的一份
/// 触发，`CoreRuntime::run` 的 select 等待同一事实。
///
/// # Errors
/// 管道创建/accept/验证/授权失败 → 携带原因的字符串（tonic serve 错误经 serve 任务内
/// 吞掉——UI 断开本就由进程监视感知，serve 错误不携带停机语义）。
pub async fn serve_kernel_control_pipe(
    name: &str,
    ui_sid: &str,
    service: KernelControlService,
    ui: UiLifetime,
) -> Result<UiKernelControlHandles, String> {
    let server = create_kernel_control_pipe_server(name, ui_sid)
        .map_err(|e| format!("create kernel control pipe: {e}"))?;
    server
        .connect()
        .await
        .map_err(|e| format!("accept ui connection: {e}"))?;

    let info = verify_ui_peer(&server, ui_sid)?;
    let ui_peer = VerifiedPipePeer {
        process_id: info.process_id,
        user_sid: info.user_sid.clone(),
        logon_sid: None,
        account_name: info.account_name.clone(),
    };

    // gate 授权（controller transport peer auth 先于一切 secret 转换；P3-c1 seam）。
    service
        .authorize_transport_peer(&ui_peer)
        .await
        .map_err(|e| format!("authorize ui peer: {e:?}"))?;

    // UI 进程退出监视（O3 强绑定）：进程句柄等待 → on_ui_exited → core 停机。
    // 放在授权后（gate 已通过、UI 身份已核实），UI 退出即触发真实停机。
    spawn_ui_exit_watcher(info.process_id, ui);

    // engine 已就绪：拉起状态转发器（订阅 engine 独立 StreamConnectStatus → 驱动
    // 状态机 + EventBus；断线退避重连；attach-before-apply 硬约束——写路径依赖其
    // 已挂接）、统计转发器（P5-b：StreamStats → 归一化 → EventBus 统计 lane；同一
    // 总线共存）与日志转发器（R3：StreamLogs → 聚合落盘，纯单向输出——绝不驱动状态）。
    let forwarder = service.spawn_status_forwarder();
    let stats_forwarder = service.spawn_stats_forwarder();
    let logs_forwarder = service.spawn_log_forwarder();
    // C3a 自动重连 worker：消费状态转发器对「可重试数据面掉线」的信号，自动重跑
    // connect（凭据从磁盘重新组装）。停机须 abort（worker 持服务克隆）。
    let reconnect_worker = service.spawn_reconnect_worker();
    // P2 有界存留：core 侧心跳 tick（默认 10s 周期）——engine 侧刷新 last_heartbeat，
    // 15s 未收到即自清理+自退出（hung-core / 进程句柄路径故障兜底）。
    let keepalive_ticker = service.spawn_keepalive_ticker(KEEPALIVE_PERIOD);

    let io = VerifiedNamedPipeServer::new(server, info);
    // 关键：chain pending 使传入流**永不耗尽**。tonic `serve_internal` 在流返回 `None`
    // 时 break（`serve_with_incoming` 立即返回、连接任务 detached 继续服务）——若用
    // 单元素流，serve 任务会在 accept 后 ~1ms 假 resolve，被当作"UI 断开"触发假停机。
    // pending 链让 serve 任务保持 pending 到 core 停机（abort），detached 连接任务
    // 继续服务 UI。
    let incoming = tokio_stream::iter(vec![Ok::<_, std::io::Error>(io)])
        .chain(tokio_stream::pending());

    let router = Server::builder()
        .layer(tonic::service::InterceptorLayer::new(require_verified_peer))
        .add_service(KernelControlServer::new(service));
    let serve_task = tokio::spawn(async move {
        let _ = router.serve_with_incoming(incoming).await;
    });

    Ok(UiKernelControlHandles {
        ui_peer,
        serve_task,
        forwarder,
        stats_forwarder,
        logs_forwarder,
        reconnect_worker,
        keepalive_ticker,
    })
}

// ---------------------------------------------------------------------------
// 单元测试：digest 派生（纯）+ account name 解析（真实 SID 查询；当前用户恒可解析）。
// `verify_ui_peer` / `serve_kernel_control_pipe` 需真实 Named Pipe 连接，属集成覆盖。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `digest32` 输出 32 字节且确定性（同一输入 → 同一 digest；不同输入 → 不同 digest）。
    #[test]
    fn digest32_is_deterministic_32_byte_sha256() {
        let a = digest32(b"peer");
        let b = digest32(b"peer");
        let c = digest32(b"peep");
        assert_eq!(a.len(), 32);
        assert_eq!(a, b, "同一输入必须产生同一 digest");
        assert_ne!(a, c, "不同输入必须产生不同 digest");
    }

    /// `lookup_account_name` 对当前进程的 user SID 必须解析出非空 account name——
    /// 这是 gate 授权的必需事实（fail closed：解析不出 → 空串 → 授权拒绝）。
    /// 非交互/系统级 token（不可解析 SID）时短路：本机用户 token 恒有可解析的 SID。
    #[test]
    fn lookup_account_name_resolves_current_user() {
        let Some(sid) = exv_vpn_win32_ipc::peer_auth::current_user_sid() else {
            return; // 无法解析当前用户 SID（极罕见）——诚实短路。
        };
        let name = lookup_account_name(&sid);
        assert!(!name.is_empty(), "当前用户 SID {sid} 必须解析出 account name");
    }

    /// `lookup_account_name` 对无效 SID fail closed（返回空串，不 panic）。
    #[test]
    fn lookup_account_name_fails_closed_on_invalid_sid() {
        assert_eq!(lookup_account_name("S-1-not-a-real-sid"), "");
    }

    /// `spawn_ui_exit_watcher`：真实子进程退出 → `on_ui_exited` 触发（O3 强绑定信号）。
    ///
    /// 子进程退出后 OS 回收其句柄、管道断开——进程句柄等待随即 signaled，信号翻转。
    /// 用真实的 `cmd /c exit 0` 子进程；其 pid 即监视目标。
    #[tokio::test]
    async fn ui_exit_watcher_flips_signal_on_process_exit() {
        let child = std::process::Command::new("cmd")
            .args(["/c", "exit 0"])
            .spawn()
            .expect("spawn child");
        let pid = child.id();
        // 等子进程退出（进程句柄 signaled 的前提）。`cmd /c exit 0` 立即退出，阻塞短暂。
        let mut child = child;
        let status = child.wait().expect("wait child");
        assert!(status.success());

        let ui = crate::shutdown::UiLifetime::new();
        spawn_ui_exit_watcher(pid, ui.clone());
        // 已退出的进程：OpenProcess 成功（句柄仍可打开）→ WaitForSingleObject 立即
        // signaled → on_ui_exited。有界等待翻转。
        let flipped = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if !ui.is_ui_alive() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(flipped.is_ok(), "UI 进程退出必须翻转存活信号");
    }

    /// `spawn_ui_exit_watcher`：已不可打开的 pid（进程已完全消失）→ fail-safe 立即翻转。
    /// 0xFFFFFFFF 是保留 pid，OpenProcess 恒失败 → 立即判定 UI 退出。
    #[tokio::test]
    async fn ui_exit_watcher_fails_closed_for_unknown_pid() {
        let ui = crate::shutdown::UiLifetime::new();
        spawn_ui_exit_watcher(u32::MAX, ui.clone());
        let flipped = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if !ui.is_ui_alive() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(flipped.is_ok(), "未知 pid 必须 fail-safe 判定 UI 退出");
    }

    // -----------------------------------------------------------------------
    // Bug C 回归护栏：`create_kernel_control_pipe_server` 的 DACL 真实生效。
    // 旧实现把 `PSECURITY_DESCRIPTOR` 当 `SECURITY_ATTRIBUTES*` 传给 tokio → OS 读
    // garbage DACL，同进程碰巧可用、跨进程被拒。下面两个测试钉死：DACL 确实交到了
    // CreateNamedPipeW（未授权用户连接必须被拒 = 5，授权用户可连）——对旧实现失败。
    // -----------------------------------------------------------------------

    /// DACL 授权 UI 用户 SID 时，当前用户能连上 KernelControl 管道。
    #[tokio::test]
    async fn kernel_control_pipe_dacl_allows_current_user_connect() {
        let sid = exv_vpn_win32_ipc::peer_auth::current_user_sid().expect("current user sid");
        let name = format!(r"\\.\pipe\exv-kc-dacl-allow-{}", std::process::id());
        let server = create_kernel_control_pipe_server(&name, &sid).expect("create kernel pipe");
        let client =
            exv_vpn_win32_ipc::named_pipe_io::NamedPipeByteStream::connect_client(&name)
                .expect("current user must connect");
        server.connect().await.expect("server accept");
        drop(client);
    }

    /// DACL 未授权当前用户（只授 SYSTEM + 伪造域 SID）时，客户端连接必须被拒
    /// （ERROR_ACCESS_DENIED = 5）——证明 `create_kernel_control_pipe_server` 确实把
    /// `SECURITY_ATTRIBUTES`（含 DACL）交到了 `CreateNamedPipeW`。旧实现（传
    /// `PSECURITY_DESCRIPTOR`，DACL garbage）下本测试会失败。
    #[tokio::test]
    async fn kernel_control_pipe_dacl_denies_unlisted_user() {
        // 当前用户不可能持有的伪造域 SID；DACL = SYSTEM + 该 SID，普通客户端在
        // CreateFileW 阶段即被 ACL 拒绝。
        let bogus = "S-1-5-21-1000000000-1000000000-1000000000-1001";
        let name = format!(r"\\.\pipe\exv-kc-dacl-deny-{}", std::process::id());
        let server = create_kernel_control_pipe_server(&name, bogus).expect("create kernel pipe");
        let err = exv_vpn_win32_ipc::named_pipe_io::NamedPipeByteStream::connect_client(&name)
            .expect_err("unlisted user must be denied by the DACL");
        assert_eq!(
            err,
            exv_vpn_win32_ipc::named_pipe_io::PipeIoError::Io(
                windows::Win32::Foundation::ERROR_ACCESS_DENIED.0
            ),
            "unlisted user connect must fail with ERROR_ACCESS_DENIED (5)"
        );
        drop(server);
    }
}
