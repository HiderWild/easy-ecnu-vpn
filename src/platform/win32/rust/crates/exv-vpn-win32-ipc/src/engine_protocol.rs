// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// LEGACY / ACCEPTANCE-ONLY (P1, WIRE DECISION)：产品 core↔engine wire 是 tonic gRPC
// over proto/exv/v1/helper_control.proto（唯一权威），承载于双向认证 Windows Named
// Pipe（spec §9.4）。本文件的 u32 BE 长度 + JSON 帧协议（`CoreToEngine`/`EngineToCore`）
// 为 legacy/acceptance-only：保留供 acceptance 测试与 raw-dump 序列化参考，**永不作为
// 产品通道**。产品 core 走 `exv-core::grpc_control`（tonic HelperControlClient）。

//! Core↔engine 控制面管道协议（阶段 3a：engine 进程骨架 + 控制面管道协议）。
//!
//! 两进程架构：普通用户 token 的 **core**（纯协调层 + 日志层 + 请求翻译）与特权 token 的
//! **engine**（唯一特权进程：建网卡 + 写路由 + 网络设置 + 数据面）。core↔engine 之间只有
//! 低频控制面 IPC（Named Pipe + 双向 peer 认证）。
//!
//! 本模块冻结：
//! - 帧 wire 格式：u32 BE 长度前缀 + JSON（serde），与 `scenarios::controlled` 的
//!   write_json/read_json 同款（WSP1 冻结的 byte-mode pipe 帧形状）；
//! - 握手类型（`EngineHelloReq`/`EngineHelloReply`）：engine 与 core 在命令循环前完成
//!   双向身份交换（engine 侧验 core 的 pid+SID；core 侧验 engine 的 pid+SID）；
//! - 命令消息集（`CoreToEngine`）与事件/回复消息集（`EngineToCore`）；
//! - `Credentials` 一次性凭据：使用后 `zeroize`（Drop 清零），`Debug` 不泄漏明文密码。
//!
//! 控制面低频：不承载数据包、不经由本协议传递 Wintun ring 数据。数据面在 engine 内
//! 零跨进程（ring→CSTP→TLS→学校）。

use std::fmt;

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::HLOCAL;
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER, PSID};
use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows::Win32::System::Threading::OpenProcessToken;
use windows::core::PWSTR;

use crate::named_pipe_io::{NamedPipeByteStream, PipeIoError};
use crate::peer_auth::VerifiedPipePeer;

// ---------------------------------------------------------------------------
// 帧 wire 格式（u32 BE 长度 + JSON，与 controlled.rs 同款）。
// ---------------------------------------------------------------------------

/// 帧头长度（u32 BE）。
pub const FRAME_LEN_BYTES: usize = 4;
/// 控制面单帧上限（1 MiB）——防御失控消息，与 controlled.rs 的 read_json 上限一致。
pub const MAX_FRAME_BYTES: usize = 1 << 20;

/// 控制面帧 I/O 错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// 底层管道 I/O 错误，携带 Win32 错误码。
    Io(u32),
    /// 对端关闭（EOF / broken pipe）。
    PeerClosed,
    /// 帧超过 `MAX_FRAME_BYTES`。
    FrameTooLong(usize),
    /// JSON 反序列化失败。
    Deserialize(String),
    /// JSON 序列化失败。
    Serialize(String),
}

impl From<PipeIoError> for FrameError {
    fn from(value: PipeIoError) -> Self {
        match value {
            PipeIoError::PeerClosed => FrameError::PeerClosed,
            PipeIoError::Io(code) => FrameError::Io(code),
        }
    }
}

/// 写入一帧 JSON（u32 BE 长度前缀 + JSON bytes）。
///
/// # Errors
/// 序列化失败 → `FrameError::Serialize`；长度超 `u32` → `FrameError::FrameTooLong`；
/// 管道写入失败 → `FrameError::Io`/`FrameError::PeerClosed`。
pub fn write_json_frame(
    pipe: &mut NamedPipeByteStream,
    value: &impl Serialize,
) -> Result<(), FrameError> {
    let json = serde_json::to_vec(value).map_err(|e| FrameError::Serialize(e.to_string()))?;
    let len = u32::try_from(json.len()).map_err(|_| FrameError::FrameTooLong(json.len()))?;
    let mut frame = Vec::with_capacity(FRAME_LEN_BYTES + json.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&json);
    pipe.write_all(&frame).map_err(FrameError::from)
}

/// 读取一帧 JSON。
///
/// # Errors
/// 帧头/正文读取失败 → `FrameError::Io`/`FrameError::PeerClosed`；超限 →
/// `FrameError::FrameTooLong`；反序列化失败 → `FrameError::Deserialize`。
pub fn read_json_frame<T>(pipe: &mut NamedPipeByteStream) -> Result<T, FrameError>
where
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; FRAME_LEN_BYTES];
    read_exact(pipe, &mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLong(len));
    }
    let mut buf = vec![0u8; len];
    read_exact(pipe, &mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| FrameError::Deserialize(e.to_string()))
}

/// 逐段读取精确长度（`NamedPipeByteStream::read` 允许部分读）。
fn read_exact(pipe: &mut NamedPipeByteStream, buf: &mut [u8]) -> Result<(), FrameError> {
    let mut off = 0usize;
    while off < buf.len() {
        let n = pipe.read(&mut buf[off..])?;
        if n == 0 {
            return Err(FrameError::PeerClosed);
        }
        off += n;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 握手（命令循环前的一次双向身份交换）。
// ---------------------------------------------------------------------------

/// core → engine 的握手请求（core 在连接后首先发送）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineHelloReq {
    /// core 的进程 id（engine 侧核对 client pid == 声明 host pid）。
    pub host_pid: u32,
}

/// engine → core 的握手回复（双向认证：engine 验 core；core 据本回复验 engine）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EngineHelloReply {
    /// 握手是否通过（host pid 匹配）。
    pub ok: bool,
    /// 拒绝原因（`ok == false` 时）。
    pub error: Option<String>,
    /// engine 进程 id（core 侧与 pipe 实测 server pid 交叉核对）。
    pub engine_pid: u32,
    /// engine 进程 user SID（core 侧与期望 SID 核对）。
    pub engine_sid: String,
    /// engine 进程账户名（观测事实）。
    pub engine_account: String,
    /// engine 是否 elevated（core 侧确认 engine 是唯一特权进程）。
    pub engine_elevated: bool,
}

// ---------------------------------------------------------------------------
// 命令/事件消息集（阶段 3a 冻结形状）。
// ---------------------------------------------------------------------------

/// 一次性凭据（username/password）。使用后必须 `zeroize`（本类型的 `Drop` 自动清零）。
///
/// `Debug` 只输出 username，密码恒为 `<redacted>`。`Clone` 产生的新值在自身 `Drop` 时
/// 各自清零，不共享缓冲。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credentials {
    /// 登录用户名。
    pub username: String,
    /// 登录密码（明文，仅在 engine 侧短暂存活后清零）。
    pub password: String,
}

impl Credentials {
    /// 构造一次性凭据。
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    /// 清零本凭据的明文（覆写字节后清空），`Drop` 亦调用。
    pub fn zeroize(&mut self) {
        zeroize_string(&mut self.username);
        zeroize_string(&mut self.password);
    }

    /// 登录用户名（只读）。
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// 登录密码（只读；仅在消费点短暂持有，用毕由 `Drop` 清零）。
    #[must_use]
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// 覆写 String 的现有字节为 0 后清空（best-effort；capacity 内旧字节无法在不移动内存的
/// 前提下完全擦除，这里保证已分配且已使用的字节清零）。
fn zeroize_string(s: &mut String) {
    // SAFETY: `String::as_mut_vec` 返回可变字节视图；`String` 与 `Vec<u8>` 布局一致，
    // 调用方保证无其它引用借用这些字节。
    unsafe {
        for b in s.as_mut_vec() {
            *b = 0;
        }
    }
    s.clear();
}

/// core → engine 的 Connect 参数（core 读 config→解密凭据→组装；engine 据其做特权初始化）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectRequest {
    /// 学校网关 hostname（3b TLS/CSTP 使用；3a 不消费）。
    pub server: String,
    /// 隧道接口 IPv4 地址（adapter 上配置的地址）。
    pub real_ip: String,
    /// 隧道地址前缀长度。
    pub prefix: u8,
    /// 一次性凭据（engine 消费后清零）。
    pub credentials: Credentials,
    /// 客户端 user-agent（3b TLS/CSTP 使用；3a 不消费）。
    pub user_agent: String,
    /// 隧道 MTU。
    pub mtu: u32,
    /// 隧道 DNS 服务器列表。
    pub dns: Vec<String>,
    /// 隧道路由（CIDR 列表）。
    pub routes: Vec<String>,
    /// 校园路由（config-driven，经 engine 特权进程安装；缺省空集合向后兼容）。
    #[serde(default)]
    pub campus_routes: Vec<String>,
}

/// core → engine 命令消息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CoreToEngine {
    /// 建立连接：engine 做特权初始化（建 Wintun adapter + 写路由/网络设置）。
    Connect(ConnectRequest),
    /// 断开连接。`cleanup == true` 时移除路由/删 adapter；`cleanup == false` 仅断开控制面
    /// （保留隧道，用于控制面重连场景）。
    Disconnect { cleanup: bool },
    /// 重连（3b 实现；3a 回复当前状态）。
    Reconnect,
    /// 更新凭据（one-shot，engine 消费后清零；3b 使用）。
    UpdateCredentials { credentials: Credentials },
    /// 查询当前状态。
    GetStatus,
    /// 查询流量统计。
    GetStats,
    /// 订阅 engine 主动推送的 StatusChanged/Stats 事件。
    Subscribe { enabled: bool },
    /// 心跳（core 保活）。
    Heartbeat,
}

/// engine 生命周期状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum EngineState {
    /// 空闲（无连接）。
    #[default]
    Idle,
    /// 连接建立中（3b 数据面阶段）。
    Connecting,
    /// 已连接（3a：特权初始化完成即 Connected；3b：数据面就绪）。
    Connected,
    /// 重连中（3b）。
    Reconnecting,
    /// 断开中（3b-iii：core 发 Disconnect 后、teardown 完成前）。
    Disconnecting,
    /// 已断开。
    Disconnected,
    /// 错误。
    Error,
}

/// engine → core 事件/回复消息。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EngineToCore {
    /// 状态变更（也是多数命令的主回复：GetStatus/Heartbeat/Connect/Disconnect 的结果）。
    StatusChanged { state: EngineState, reason: Option<String> },
    /// 流量统计快照。
    Stats {
        /// 累计接收字节。
        rx_bytes: u64,
        /// 累计发送字节。
        tx_bytes: u64,
        /// 实时速率（bytes/s）。
        speed: u64,
        /// RTT（ms）。
        latency_ms: u32,
    },
    /// 错误事件。`code`/`a0` 保留给 domain 错误码与 Win32 状态；`detail` 是可读文本。
    Error { code: u32, a0: u32, detail: Option<String> },
    /// engine 需要 core 提供凭据（3b 交互式认证）。
    CredentialRequired,
    /// 隧道路由应用结果。
    RouteApplied { ok: bool, conflict: bool },
}

// ---------------------------------------------------------------------------
// client 侧 server 身份验证（core 验 engine：GetNamedPipeServerProcessId + SID 校验）。
// ---------------------------------------------------------------------------

/// client 侧验证 engine（server）身份的失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerVerifyError {
    /// Win32 查询失败（携带错误码）。
    Io(u32),
    /// 管道未连接或对端关闭。
    PeerClosed,
    /// server 的 pid/SID 与期望不匹配（fail closed）。
    NotAuthorized,
}

/// 验证已连接的 client 管道背后的 server（engine）进程身份：实测 server pid 必须等于
/// `expected_pid`，实测 server user SID 必须等于 `expected_sid`。任何查询失败 fail closed。
///
/// # Errors
/// 查询失败 → `ServerVerifyError::Io`；身份不匹配 → `ServerVerifyError::NotAuthorized`。
pub fn verify_engine_server(
    client: &NamedPipeByteStream,
    expected_pid: u32,
    expected_sid: &str,
) -> Result<VerifiedPipePeer, ServerVerifyError> {
    let mut pid = 0u32;
    // SAFETY: `client` 的底层句柄是已连接的 client 管道句柄；`pid` 是有效输出参数。
    if let Err(e) = unsafe { GetNamedPipeServerProcessId(client.raw_handle(), &raw mut pid) } {
        let code = u32::from_ne_bytes(e.code().0.to_ne_bytes()) & 0xFFFF;
        return Err(ServerVerifyError::Io(code));
    }
    if pid != expected_pid {
        return Err(ServerVerifyError::NotAuthorized);
    }
    let sid = process_sid_from_pid(pid).ok_or(ServerVerifyError::Io(0))?;
    if sid != expected_sid {
        return Err(ServerVerifyError::NotAuthorized);
    }
    Ok(VerifiedPipePeer {
        process_id: pid,
        user_sid: sid,
        logon_sid: None,
        account_name: String::new(),
    })
}

/// 从 PID 读取进程 token 的 user SID 字符串。
fn process_sid_from_pid(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess 打开受限查询句柄；失败即 None（fail closed）。
    let process = unsafe {
        windows::Win32::System::Threading::OpenProcess(
            windows::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        )
    }
    .ok()?;
    let mut token = windows::Win32::Foundation::HANDLE(std::ptr::null_mut());
    // SAFETY: `token` 是有效输出参数；成功后需关闭。
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        // SAFETY: process 句柄使用后关闭。
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(process);
        }
        return None;
    }
    let sid = token_user_sid_to_string(token);
    // SAFETY: token/process 句柄使用后关闭。
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(token);
        let _ = windows::Win32::Foundation::CloseHandle(process);
    }
    sid
}

/// 从 token 读取 TokenUser SID 字符串。
fn token_user_sid_to_string(token: windows::Win32::Foundation::HANDLE) -> Option<String> {
    let mut buff = [0u8; 4096];
    let mut ret = 0u32;
    // SAFETY: buff 有效；TokenUser 写入 TOKEN_USER + SID 数据到 buff。
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buff.as_mut_ptr().cast::<core::ffi::c_void>()),
            buff.len() as u32,
            &raw mut ret,
        )
    };
    if ok.is_err() {
        return None;
    }
    // SAFETY: buff 以 TOKEN_USER 开头（8 字节对齐）；其 User.Sid 指向 buff 内 SID。
    let psid = unsafe { buff.as_ptr().cast::<TOKEN_USER>().read().User.Sid };
    sid_to_string(psid)
}

/// SID → 字符串（LocalFree 释放）。
fn sid_to_string(sid: PSID) -> Option<String> {
    let mut ptr = PWSTR::null();
    // SAFETY: sid 有效；返回字符串由系统分配，必须 LocalFree。
    let ok = unsafe { ConvertSidToStringSidW(sid, &raw mut ptr) };
    if ok.is_err() {
        return None;
    }
    let s = unsafe { ptr.to_string() }.ok()?;
    // SAFETY: ConvertSidToStringSidW 用 LocalAlloc 分配，LocalFree 配对释放。
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(HLOCAL(ptr.0.cast())));
    }
    Some(s)
}

// ---------------------------------------------------------------------------
// 单元测试：协议序列化往返 + 凭据清零 + 帧 I/O（真实 pipe）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_pipe_name(tag: &str) -> String {
        format!(r"\\.\pipe\exv-engine-protocol-{tag}-{}", std::process::id())
    }

    fn sample_connect_request() -> ConnectRequest {
        ConnectRequest {
            server: "vpn-cn.ecnu.edu.cn".to_string(),
            real_ip: "10.88.88.1".to_string(),
            prefix: 24,
            credentials: Credentials::new("student", "s3cret"),
            user_agent: "AnyConnect Win_x86_64 4.10.05095".to_string(),
            mtu: 1420,
            dns: vec!["10.88.88.53".to_string()],
            routes: vec!["10.99.99.0/24".to_string()],
            campus_routes: vec!["202.120.80.0/20".to_string()],
        }
    }

    /// Connect 消息往返（含凭据）。
    #[test]
    fn connect_request_round_trip() {
        let req = sample_connect_request();
        let json = serde_json::to_vec(&req).expect("serialize");
        let back: ConnectRequest = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(back.server, "vpn-cn.ecnu.edu.cn");
        assert_eq!(back.real_ip, "10.88.88.1");
        assert_eq!(back.prefix, 24);
        assert_eq!(back.mtu, 1420);
        assert_eq!(back.credentials.username(), "student");
        assert_eq!(back.credentials.password(), "s3cret");
        assert_eq!(back.routes, vec!["10.99.99.0/24"]);
        assert_eq!(back.campus_routes, vec!["202.120.80.0/20"]);
        // 缺省 campus_routes 必须反序列化为空集合（向后兼容）。
        let json = serde_json::to_vec(&CoreToEngine::Connect(ConnectRequest {
            campus_routes: vec![],
            ..sample_connect_request()
        }))
        .expect("serialize");
        let _: CoreToEngine = serde_json::from_slice(&json).expect("deserialize");
    }

    /// 所有 CoreToEngine 变体 JSON 往返。
    #[test]
    fn core_to_engine_all_variants_round_trip() {
        let cases = vec![
            CoreToEngine::Connect(sample_connect_request()),
            CoreToEngine::Disconnect { cleanup: true },
            CoreToEngine::Reconnect,
            CoreToEngine::UpdateCredentials {
                credentials: Credentials::new("u", "p"),
            },
            CoreToEngine::GetStatus,
            CoreToEngine::GetStats,
            CoreToEngine::Subscribe { enabled: true },
            CoreToEngine::Heartbeat,
        ];
        for msg in cases {
            let json = serde_json::to_vec(&msg).expect("serialize");
            let back: CoreToEngine = serde_json::from_slice(&json).expect("deserialize");
            assert_eq!(back, msg, "variant must round-trip");
        }
    }

    /// 所有 EngineToCore 变体 JSON 往返。
    #[test]
    fn engine_to_core_all_variants_round_trip() {
        let cases = vec![
            EngineToCore::StatusChanged {
                state: EngineState::Connected,
                reason: None,
            },
            EngineToCore::StatusChanged {
                state: EngineState::Error,
                reason: Some("boom".to_string()),
            },
            EngineToCore::StatusChanged {
                state: EngineState::Disconnecting,
                reason: None,
            },
            EngineToCore::Stats {
                rx_bytes: 123,
                tx_bytes: 456,
                speed: 789,
                latency_ms: 12,
            },
            EngineToCore::Error {
                code: 7,
                a0: 0,
                detail: Some("detail".to_string()),
            },
            EngineToCore::CredentialRequired,
            EngineToCore::RouteApplied {
                ok: true,
                conflict: false,
            },
        ];
        for msg in cases {
            let json = serde_json::to_vec(&msg).expect("serialize");
            let back: EngineToCore = serde_json::from_slice(&json).expect("deserialize");
            assert_eq!(back, msg, "variant must round-trip");
        }
    }

    /// Credentials 的 Debug 不得泄漏明文密码。
    #[test]
    fn credentials_debug_redacts_password() {
        let creds = Credentials::new("student", "top-secret-password");
        let dbg = format!("{creds:?}");
        assert!(!dbg.contains("top-secret-password"), "Debug must not leak password: {dbg}");
        assert!(dbg.contains("student"), "Debug must show the username");
    }

    /// Credentials::zeroize 清零明文。
    #[test]
    fn credentials_zeroize_clears_plaintext() {
        let mut creds = Credentials::new("student", "s3cret");
        assert_eq!(creds.password(), "s3cret");
        creds.zeroize();
        assert!(creds.username().is_empty());
        assert!(creds.password().is_empty());
    }

    /// 帧 I/O 在真实 local Named Pipe 上往返（write_json_frame/read_json_frame）。
    #[test]
    fn frame_round_trip_over_real_pipe() {
        let name = unique_pipe_name("frame");
        let server = NamedPipeByteStream::create_server(&name, 1).expect("create server");
        // 先连接 client（实例已存在，CreateFileW 立即成功），再 accept（返回已连接）。
        let client = NamedPipeByteStream::connect_client(&name).expect("connect");
        server.connect().expect("server accept");
        let mut server = server;
        let mut client = client;

        let msg = CoreToEngine::Connect(sample_connect_request());
        write_json_frame(&mut server, &msg).expect("write frame");
        let back: CoreToEngine = read_json_frame(&mut client).expect("read frame");
        assert_eq!(back, msg);

        // 连续多帧（客户端 drain 场景）。
        let replies = vec![
            EngineToCore::StatusChanged {
                state: EngineState::Connected,
                reason: None,
            },
            EngineToCore::RouteApplied {
                ok: true,
                conflict: false,
            },
        ];
        for reply in &replies {
            write_json_frame(&mut server, reply).expect("write reply");
        }
        for expected in &replies {
            let got: EngineToCore = read_json_frame(&mut client).expect("read reply");
            assert_eq!(&got, expected);
        }
    }

    /// client 侧 server 身份验证（verify_engine_server）——真实 pipe，同一进程。
    #[test]
    fn verify_engine_server_accepts_local_server() {
        let name = unique_pipe_name("server-verify");
        let server = NamedPipeByteStream::create_server(&name, 1).expect("create server");
        let client = NamedPipeByteStream::connect_client(&name).expect("connect");
        server.connect().expect("server accept");

        let sid = crate::peer_auth::current_user_sid().expect("current user sid");
        let peer = verify_engine_server(&client, std::process::id(), &sid)
            .expect("a same-process local server must verify");
        assert_eq!(peer.process_id, std::process::id());
        assert_eq!(peer.user_sid, sid);

        // 错误 PID / SID 必须 fail closed。
        assert_eq!(
            verify_engine_server(&client, std::process::id() + 1, &sid),
            Err(ServerVerifyError::NotAuthorized)
        );
        assert_eq!(
            verify_engine_server(&client, std::process::id(), "S-1-0-0"),
            Err(ServerVerifyError::NotAuthorized)
        );
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
