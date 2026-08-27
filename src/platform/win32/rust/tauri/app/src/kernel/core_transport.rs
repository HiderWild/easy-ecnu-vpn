//! UI → core 的 tonic gRPC 传输层：Tokio Windows Named Pipe（P4-b）。
//!
//! 镜像 host crate `grpc_transport.rs` 的 client 侧拨号模式（core→engine 同构，
//! spec §9.4 "Named Pipe mutual auth"），方向为 **Tauri host → core**：
//!
//! - [`dial_core_pipe_with_retry`]：带界重试的 async Named Pipe 拨号（core 可能仍
//!   在启动建管道的竞窗）；
//! - [`verify_core_server_pipe`]：client 侧验证 core（server）进程身份——实测
//!   server pid 必须等于期望 pid、user SID 必须等于期望 SID（spec §9.4），任何查询
//!   失败 fail closed；
//! - [`NamedPipeConnector`]：tower `Service<Uri>`，把已拨号且已验证的 pipe 包装为
//!   tonic transport stream（`TokioIo<NamedPipeClient>`）；
//! - [`connect_core_channel`]：一次拨号 + 验证后构造 HTTP/2 `Channel`。
//!
//! 对端（core）侧验证 UI 的 pid+SID 是 server 的职责
//! （host `kernel_control_transport::verify_ui_peer`），不在本模块。peer 认证只来自
//! 已验证的连接元数据，endpoint 名/路径不是 capability（§9.4）。
//!
//! SID 查询路径复用 ipc crate `peer_auth` 的冻结 WSP1 事实（`GetTokenInformation
//! (TokenUser)` + `ConvertSidToStringSidW`）——本模块内联小实现，避免把 Tauri
//! workspace 并入 win32 ipc 的依赖树。

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use http::Uri;
use hyper_util::rt::TokioIo;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tonic::transport::{Channel, Endpoint};
use tower::Service;
use windows::Win32::Foundation::{CloseHandle, HLOCAL, LocalFree, HANDLE};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER, PSID};
use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::PWSTR;

/// 拨号重试次数（core 启动竞窗；与 host `DIAL_ATTEMPTS` 同量级）。
const DIAL_ATTEMPTS: u32 = 30;
/// 重试间隔。
const DIAL_RETRY_DELAY: Duration = Duration::from_millis(100);
/// 渠道构建 connect 超时（包裹 connector 的整次拨号+验证）。
const CHANNEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// 已验证的 core（server）身份（client 侧 transport 派生的最小事实集）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorePeer {
    /// 已验证的 core 进程 pid（transport 派生）。
    pub process_id: u32,
    /// 已验证的 core 用户 SID（transport 派生）。
    pub user_sid: String,
}

/// client 侧传输层错误。所有失败 fail closed。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrpcPipeError {
    /// Named Pipe 拨号失败（含重试耗尽）；携带最后 Win32 错误码。
    Dial(u32),
    /// core server 身份与期望 pid/SID 不匹配，或身份查询失败。
    Auth(String),
    /// tonic channel 构建失败。
    Transport(String),
}

impl fmt::Display for GrpcPipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dial(code) => write!(f, "core control pipe dial failed (win32 error {code})"),
            Self::Auth(reason) => write!(f, "core peer authentication failed: {reason}"),
            Self::Transport(reason) => write!(f, "gRPC channel build failed: {reason}"),
        }
    }
}

impl std::error::Error for GrpcPipeError {}

// ---------------------------------------------------------------------------
// SID 查询（冻结 WSP1 事实；镜像 ipc peer_auth 的小实现）
// ---------------------------------------------------------------------------

/// 读取 token 的 user SID 字符串（`GetTokenInformation(TokenUser)` →
/// `ConvertSidToStringSidW`）。任何查询失败 → `None`（fail closed）。
fn read_user_sid(token: HANDLE) -> Option<String> {
    let mut len: u32 = 0;
    // SAFETY: 只查尺寸（null 缓冲）不可能写入任何位置；`len` 是有效输出参数。
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, None, 0, &raw mut len);
    }
    if len == 0 {
        return None;
    }
    // 对齐对齐：`Vec<u64>` 与 `TOKEN_USER` 均 8 字节对齐，cast 安全。
    let mut buf = vec![0u64; usize::try_from(len).unwrap_or_default().div_ceil(8)];
    // SAFETY: `buf` 是至少 `len` 字节的活缓冲；API 写入结构 + SID 数据并回报同长度。
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            len,
            &raw mut len,
        )
    }
    .is_err()
    {
        return None;
    }
    // SAFETY: `buf` 以合法 `TOKEN_USER` 开头（User.Sid 指向缓冲内）。
    let user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
    sid_to_string(user.User.Sid)
}

/// `ConvertSidToStringSidW` 的封装（结果 LocalFree 释放）。
fn sid_to_string(sid: PSID) -> Option<String> {
    let mut ptr = PWSTR::null();
    // SAFETY: `sid` 是调用方 token 缓冲内的合法 PSID；`ptr` 是 API 分配的活输出参数。
    if unsafe { ConvertSidToStringSidW(sid, &raw mut ptr) }.is_err() {
        return None;
    }
    let s = unsafe { ptr.to_string() }.ok();
    // SAFETY: 字符串由 `ConvertSidToStringSidW` 分配，使用后必须释放。
    unsafe {
        let _ = LocalFree(Some(HLOCAL(ptr.0.cast())));
    }
    s
}

/// 当前进程的用户 SID（本进程 token 呈现的 SID；UI 与 core 同用户拓扑）。
#[must_use]
pub fn current_user_sid() -> Option<String> {
    // SAFETY: GetCurrentProcess 返回进程伪句柄，由 OS 持有，无需关闭。
    let process = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: `token` 是活输出参数；成功打开的句柄在下方关闭。
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        return None;
    }
    let sid = read_user_sid(token);
    // SAFETY: `token` 是本进程新打开句柄，使用后关闭。
    unsafe {
        let _ = CloseHandle(token);
    }
    sid
}

/// 进程 `pid` 的用户 SID（打开进程 token 读取）。任何查询失败 → `None`（fail closed）。
#[must_use]
pub fn process_sid(pid: u32) -> Option<String> {
    // SAFETY: `pid` 由调用方解析；返回值（或错误）在此检查。
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut token = HANDLE::default();
    // SAFETY: `token` 是活输出参数；成功打开的句柄在下方关闭。
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        // SAFETY: `process` 是上方打开的句柄，使用后关闭。
        unsafe {
            let _ = CloseHandle(process);
        }
        return None;
    }
    let sid = read_user_sid(token);
    // SAFETY: `token`/`process` 均为上方打开句柄，使用后关闭。
    unsafe {
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
    }
    sid
}

// ---------------------------------------------------------------------------
// 拨号 + 验证 + connector
// ---------------------------------------------------------------------------

/// 拨号 core 控制面 Named Pipe：`ERROR_FILE_NOT_FOUND`/`ERROR_PIPE_BUSY` 有界
/// 重试（core 可能仍在启动建管道的竞窗）。
///
/// # Errors
/// 重试耗尽或遇到非重试错误 → `GrpcPipeError::Dial`。
pub async fn dial_core_pipe_with_retry(name: &str) -> Result<NamedPipeClient, GrpcPipeError> {
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

/// client 侧验证 core（server）进程身份：实测 server pid 必须等于 `expected_pid`、
/// 实测 server user SID 必须等于 `expected_sid`（spec §9.4）。任何查询失败 fail
/// closed。
///
/// # Errors
/// pid/SID 不匹配或身份无法解析 → `GrpcPipeError::Auth`。
pub fn verify_core_server_pipe(
    pipe: &NamedPipeClient,
    expected_pid: u32,
    expected_sid: &str,
) -> Result<CorePeer, GrpcPipeError> {
    use std::os::windows::io::AsRawHandle;

    let mut pid = 0u32;
    // SAFETY: `pipe.as_raw_handle()` 是已连接的 client pipe 句柄，`pid` 是有效输出参数。
    if let Err(e) = unsafe {
        GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &raw mut pid)
    } {
        return Err(GrpcPipeError::Auth(format!(
            "server process query failed: {e}"
        )));
    }
    if pid != expected_pid {
        return Err(GrpcPipeError::Auth(format!(
            "core pid mismatch: expected {expected_pid}, observed {pid}"
        )));
    }
    let sid = process_sid(pid)
        .ok_or_else(|| GrpcPipeError::Auth(format!("cannot resolve user SID of core pid {pid}")))?;
    if sid != expected_sid {
        return Err(GrpcPipeError::Auth(format!(
            "core SID mismatch: expected {expected_sid}, observed {sid}"
        )));
    }
    Ok(CorePeer {
        process_id: pid,
        user_sid: sid,
    })
}

/// tower `Service<Uri>`：把一次拨号并验证过的 core 控制面 pipe 交给 tonic channel。
///
/// 与 tonic 自带 UDS connector 同构（`Response = TokioIo<NamedPipeClient>`）。首个
/// `call` 消费预拨号且已验证的连接（`warm`），后续 `call`（channel 重连）现场拨号并
/// 重新验证 core 身份。`Uri` 只作占位——真实传输是 Named Pipe，endpoint 名不携带
/// 路由/授权语义（§9.4）。
pub struct NamedPipeConnector {
    pipe_name: String,
    expected_pid: u32,
    expected_sid: String,
    /// 预拨号且已验证的连接，交给 channel 的首个 dial（`None` 之后每次现场拨号）。
    warm: Option<NamedPipeClient>,
    /// 已验证的 core peer（供调用方读取）。
    verified_peer: Arc<Mutex<Option<CorePeer>>>,
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
                None => dial_core_pipe_with_retry(&pipe_name).await?,
            };
            let peer = verify_core_server_pipe(&pipe, expected_pid, &expected_sid)?;
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

/// 拨号并验证 core 控制面 pipe，随后构建 tonic gRPC `Channel`。
///
/// 单次拨号：先 `dial_core_pipe_with_retry` + `verify_core_server_pipe`（fail
/// closed，typed 错误直接暴露给调用方），再把该已验证连接作为 connector 的 `warm`
/// 交给 channel——不会重复拨号。返回 (channel, 已验证的 core peer)。
///
/// # Errors
/// 拨号失败 → `GrpcPipeError::Dial`；身份不匹配 → `GrpcPipeError::Auth`；channel
/// 构建失败 → `GrpcPipeError::Transport`。
pub async fn connect_core_channel(
    pipe_name: &str,
    expected_core_pid: u32,
    expected_user_sid: &str,
) -> Result<(Channel, CorePeer), GrpcPipeError> {
    let warm = dial_core_pipe_with_retry(pipe_name).await?;
    let peer = verify_core_server_pipe(&warm, expected_core_pid, expected_user_sid)?;

    let connector = NamedPipeConnector::with_warm(
        pipe_name.to_string(),
        expected_core_pid,
        expected_user_sid.to_string(),
        warm,
    );
    let endpoint = Endpoint::from_static("http://core.local")
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

    use super::*;

    fn unique_pipe_name(tag: &str) -> String {
        format!(r"\\.\pipe\exv-tauri-transport-{tag}-{}", std::process::id())
    }

    /// client 侧验证同进程 server：pid/SID 必须通过；错误 pid/SID 必须 fail closed。
    ///
    /// server 的 accept 在独立任务中等待 client 连接，避免 accept 与拨号互等死锁。
    #[tokio::test]
    async fn verify_core_server_pipe_accepts_local_server() {
        let name = unique_pipe_name("verify");
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(name.as_str())
            .expect("create server");
        let accept_task = tokio::spawn(async move {
            server.connect().await.expect("accept client");
        });

        let client = dial_core_pipe_with_retry(&name).await.expect("dial");
        let pid = std::process::id();
        let sid = current_user_sid().expect("current user sid");

        let peer = verify_core_server_pipe(&client, pid, &sid).expect("verify local server");
        assert_eq!(peer.process_id, pid);
        assert_eq!(peer.user_sid, sid);

        // 错误 PID / SID 必须 fail closed。
        assert!(
            verify_core_server_pipe(&client, pid + 1, &sid).is_err(),
            "错误 PID 必须拒绝"
        );
        assert!(
            verify_core_server_pipe(&client, pid, "S-1-0-0").is_err(),
            "错误 SID 必须拒绝"
        );

        drop(client);
        accept_task.await.expect("accept task joins");
    }

    /// 拨号重试：server 尚未存在时（无 server），拨号到重试耗尽必须返回 Dial 错误。
    #[tokio::test]
    async fn dial_fails_closed_when_no_server() {
        let name = unique_pipe_name("absent");
        let err = dial_core_pipe_with_retry(&name).await.expect_err("must fail");
        assert!(matches!(err, GrpcPipeError::Dial(_)), "got {err:?}");
    }

    /// SID 查询：当前进程 SID 恒可解析；未知 PID 必须 fail closed（不 panic）。
    #[test]
    fn sid_queries_resolve_self_and_fail_closed_on_unknown() {
        let sid = current_user_sid();
        assert!(sid.is_some(), "当前进程 SID 必须可解析");
        let self_pid_sid = process_sid(std::process::id());
        assert_eq!(self_pid_sid, sid, "process_sid(当前 pid) 必须等于 current_user_sid");
        assert!(process_sid(u32::MAX).is_none(), "未知 PID 必须 fail closed");
    }
}
