// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core 侧控制面客户端（阶段 3a 骨架 + 阶段 4-i：完整命令集 + 事件分发 + 凭据安全 + 掉线感知）。
//!
//! core（普通用户 token）经本模块连接特权 engine 的控制面 Named Pipe，完成双向 peer
//! 认证（server 侧 engine 验 core 的 pid+SID；client 侧本模块验 engine 的 pid+SID），
//! 然后发送 `CoreToEngine` 命令并接收 `EngineToCore` 回复。控制面低频，不承载数据包。
//!
//! ## 命令
//! 类型化命令方法：`connect_tunnel`/`disconnect`/`reconnect`/`update_credentials`/
//! `get_status`/`get_stats`/`subscribe`/`heartbeat`，外加底层 `send`（`&CoreToEngine`，
//! 兼容 3a）与 `send_owned`（`&mut CoreToEngine`，发送后零化一次性凭据）。对不期待回复
//! 的命令（`Subscribe`/`UpdateCredentials`，engine 命令循环回空批）`send` 立即返回空批，
//! 不阻塞。
//!
//! ## 事件
//! 所有 `EngineToCore`（`StatusChanged`/`Stats`/`Error`/`CredentialRequired`/`RouteApplied`）
//! 经 `enable_event_channel` 得到的 `mpsc::Receiver` 分发给调用者：命令回复批在 `send` 内
//! 转发，engine 主动推送的异步事件（订阅后）由 `poll_events` 读取并转发。命令方法同时把
//! 回复批原样返回给调用方（同步等待完成）。
//!
//! ## 凭据安全
//! `Credentials` 一次性：`connect`/`update_credentials` 消费的凭据在发送后**立即**
//! `zeroize` 本地副本（`send_owned` 的实现保证，不等待 `Drop`）；`Credentials::Drop`
//! 兜底清零。明文只短暂存在于序列化帧缓冲，随帧写入管道后释放，绝不落地。
//!
//! ## 掉线感知
//! engine 关闭控制面连接（`PeerClosed`/broken pipe）→ `ControlClientError::ConnectionLost`；
//! 可选 `set_reply_timeout` 让主回复等待有界（超时 → `ControlClientError::Timeout`）。

use std::sync::mpsc;
use std::time::{Duration, Instant};

use exv_vpn_win32_ipc::engine_protocol::{
    read_json_frame, verify_engine_server, write_json_frame, ConnectRequest, CoreToEngine,
    Credentials, EngineHelloReply, EngineHelloReq, EngineToCore, FrameError,
};
use exv_vpn_win32_ipc::named_pipe_io::{NamedPipeByteStream, PipeIoError};
use exv_vpn_win32_ipc::peer_auth::VerifiedPipePeer;

/// 控制面客户端错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlClientError {
    /// 管道连接失败（含重试耗尽）。
    Pipe(PipeIoError),
    /// 握手拒绝（engine 侧 ok=false）。
    Handshake(String),
    /// 双向 peer 身份验证失败（fail closed）。
    Auth(String),
    /// 帧读写失败（非对端关闭）。
    Frame(String),
    /// engine 已关闭控制面连接（PeerClosed / broken pipe）——调用方应重连。
    ConnectionLost,
    /// 等待 engine 回复超时。
    Timeout(Duration),
}

/// 将协议层帧错误映射为客户端错误。`PeerClosed` 单独映射为 `ConnectionLost`（掉线感知），
/// 其余帧错误归入 `Frame`。
fn map_frame_error(e: FrameError) -> ControlClientError {
    match e {
        FrameError::PeerClosed => ControlClientError::ConnectionLost,
        FrameError::Io(code) => ControlClientError::Frame(format!("pipe io {code}")),
        FrameError::FrameTooLong(n) => ControlClientError::Frame(format!("frame too long {n}")),
        FrameError::Deserialize(s) => ControlClientError::Frame(format!("deserialize {s}")),
        FrameError::Serialize(s) => ControlClientError::Frame(format!("serialize {s}")),
    }
}

/// core → engine 控制面客户端。
pub struct EngineControlClient {
    pipe: NamedPipeByteStream,
    /// 已认证的 engine（server）身份。
    pub engine_peer: VerifiedPipePeer,
    /// 可选事件分发：所有 `EngineToCore` 消息（命令回复 + `poll_events` 异步事件）转发。
    event_tx: Option<mpsc::Sender<EngineToCore>>,
    /// 主回复等待超时（`None` = 无限等待，与 3a 行为一致）。
    reply_timeout: Option<Duration>,
}

impl EngineControlClient {
    /// 连接 engine 控制面管道并完成双向认证。
    ///
    /// `host_pid` 是本 core 进程 pid（engine 侧核对）；`expected_engine_pid` 是 engine
    /// 进程 pid（core 侧核对）；`expected_user_sid` 是当前用户 SID（engine 与 core 同用户）。
    ///
    /// # Errors
    /// 管道不可达 → `ControlClientError::Pipe`；握手/身份不匹配 →
    /// `ControlClientError::Auth`/`Handshake`；帧 I/O 失败 → `ControlClientError::Frame`。
    pub fn connect(
        pipe_name: &str,
        host_pid: u32,
        expected_engine_pid: u32,
        expected_user_sid: &str,
    ) -> Result<Self, ControlClientError> {
        let mut pipe = connect_pipe_with_retry(pipe_name)?;

        // 握手：先发 HelloReq（声明本 core pid），再读 HelloReply。
        write_json_frame(&mut pipe, &EngineHelloReq { host_pid })
            .map_err(map_frame_error)?;
        let hello: EngineHelloReply = read_json_frame(&mut pipe).map_err(map_frame_error)?;
        if !hello.ok {
            return Err(ControlClientError::Handshake(
                hello.error.unwrap_or_else(|| "engine refused hello".to_string()),
            ));
        }

        // client 侧验 engine：pipe 实测 server pid/SID 必须匹配期望，且与 HelloReply 自报一致。
        let verified = verify_engine_server(&pipe, expected_engine_pid, expected_user_sid)
            .map_err(|e| ControlClientError::Auth(format!("{e:?}")))?;
        if hello.engine_pid != expected_engine_pid || hello.engine_sid != expected_user_sid {
            return Err(ControlClientError::Auth(
                "engine HelloReply identity does not match expected pid/SID".to_string(),
            ));
        }
        if hello.engine_pid != verified.process_id || hello.engine_sid != verified.user_sid {
            return Err(ControlClientError::Auth(
                "engine HelloReply identity does not match pipe-observed server identity".to_string(),
            ));
        }
        if !hello.engine_elevated {
            return Err(ControlClientError::Auth(
                "engine is not elevated (control plane requires the privileged engine)".to_string(),
            ));
        }

        Ok(Self {
            pipe,
            engine_peer: verified,
            event_tx: None,
            reply_timeout: None,
        })
    }

    /// 启用事件分发并返回调用者的事件接收端。启用后所有 `EngineToCore` 消息（命令回复批
    /// 以及 `poll_events` 读取的异步推送）都会发送到该 channel；调用方可据此统一处理
    /// `StatusChanged`/`Stats`/`Error`/`CredentialRequired`/`RouteApplied`。
    ///
    /// 命令方法仍同时把回复批原样返回给调用方（同步完成 + 事件流两者都可得）。
    pub fn enable_event_channel(&mut self) -> mpsc::Receiver<EngineToCore> {
        let (tx, rx) = mpsc::channel();
        self.event_tx = Some(tx);
        rx
    }

    /// 设置主回复等待超时。engine 在该时长内未写出主回复 → `ControlClientError::Timeout`。
    /// `None`（默认）表示无限等待（与 3a 行为一致）。
    pub fn set_reply_timeout(&mut self, timeout: Duration) {
        self.reply_timeout = Some(timeout);
    }

    // -----------------------------------------------------------------------
    // 类型化命令
    // -----------------------------------------------------------------------

    /// 建立连接（向 engine 发 `Connect` 命令）。`req` 携带一次性凭据
    /// （`ConnectRequest.credentials`），发送后本地副本**立即零化**（`send_owned` 契约），
    /// 不等待 `Drop`。
    ///
    /// 命名为 `connect_tunnel` 以区别于构造函数 `connect`（后者连接控制面管道本身）。
    ///
    /// engine 的回复批通常为 `StatusChanged(Connecting)` + `StatusChanged(Connected)` +
    /// `RouteApplied`（成功）或 `Error` + `StatusChanged(Error)`（失败，含网关 `a0` 结果码）。
    ///
    /// # Errors
    /// engine 掉线 → `ControlClientError::ConnectionLost`；等待超时（已配置）→
    /// `ControlClientError::Timeout`；帧读写失败 → `ControlClientError::Frame`。
    pub fn connect_tunnel(
        &mut self,
        req: ConnectRequest,
    ) -> Result<Vec<EngineToCore>, ControlClientError> {
        let mut cmd = CoreToEngine::Connect(req);
        self.send_owned(&mut cmd)
    }

    /// 断开连接。`cleanup == true` 时 engine 做完整 teardown（停数据面 + 逆序 restore +
    /// 删 adapter）；`false` 时仅断开控制面（保留隧道，用于控制面重连场景）。
    ///
    /// # Errors
    /// engine 掉线 → `ControlClientError::ConnectionLost`；等待超时（已配置）→
    /// `ControlClientError::Timeout`；帧读写失败 → `ControlClientError::Frame`。
    pub fn disconnect(&mut self, cleanup: bool) -> Result<Vec<EngineToCore>, ControlClientError> {
        self.send(&CoreToEngine::Disconnect { cleanup })
    }

    /// 重连（3b 语义；当前 engine 仅回复当前状态）。
    ///
    /// # Errors
    /// engine 掉线 → `ControlClientError::ConnectionLost`；等待超时（已配置）→
    /// `ControlClientError::Timeout`；帧读写失败 → `ControlClientError::Frame`。
    pub fn reconnect(&mut self) -> Result<Vec<EngineToCore>, ControlClientError> {
        self.send(&CoreToEngine::Reconnect)
    }

    /// 更新凭据（一次性：`credentials` 发送后本地副本零化）。engine 当前不回复
    /// （fire-and-forget），方法返回空批。
    ///
    /// # Errors
    /// engine 掉线 → `ControlClientError::ConnectionLost`；帧写入失败 →
    /// `ControlClientError::Frame`。
    pub fn update_credentials(
        &mut self,
        credentials: Credentials,
    ) -> Result<Vec<EngineToCore>, ControlClientError> {
        let mut cmd = CoreToEngine::UpdateCredentials { credentials };
        self.send_owned(&mut cmd)
    }

    /// 查询当前状态（回复 `StatusChanged`）。
    ///
    /// # Errors
    /// engine 掉线 → `ControlClientError::ConnectionLost`；等待超时（已配置）→
    /// `ControlClientError::Timeout`；帧读写失败 → `ControlClientError::Frame`。
    pub fn get_status(&mut self) -> Result<Vec<EngineToCore>, ControlClientError> {
        self.send(&CoreToEngine::GetStatus)
    }

    /// 查询流量统计（回复 `Stats`）。
    ///
    /// # Errors
    /// engine 掉线 → `ControlClientError::ConnectionLost`；等待超时（已配置）→
    /// `ControlClientError::Timeout`；帧读写失败 → `ControlClientError::Frame`。
    pub fn get_stats(&mut self) -> Result<Vec<EngineToCore>, ControlClientError> {
        self.send(&CoreToEngine::GetStats)
    }

    /// 订阅/取消订阅 engine 主动推送的 `StatusChanged`/`Stats` 事件（fire-and-forget）。
    ///
    /// # Errors
    /// engine 掉线 → `ControlClientError::ConnectionLost`；帧写入失败 →
    /// `ControlClientError::Frame`。
    pub fn subscribe(&mut self, enabled: bool) -> Result<Vec<EngineToCore>, ControlClientError> {
        self.send(&CoreToEngine::Subscribe { enabled })
    }

    /// 心跳（core 保活；回复当前状态）。
    ///
    /// # Errors
    /// engine 掉线 → `ControlClientError::ConnectionLost`；等待超时（已配置）→
    /// `ControlClientError::Timeout`；帧读写失败 → `ControlClientError::Frame`。
    pub fn heartbeat(&mut self) -> Result<Vec<EngineToCore>, ControlClientError> {
        self.send(&CoreToEngine::Heartbeat)
    }

    // -----------------------------------------------------------------------
    // 底层发送
    // -----------------------------------------------------------------------

    /// 发送一条命令并读取完整回复批（对不期待回复的命令——`Subscribe`/`UpdateCredentials`，
    /// engine 命令循环回空批——立即返回空批，不阻塞）。
    ///
    /// 先读主回复，再短暂沉降后 drain 已到达的额外帧（engine 可能对一条命令回复多帧，
    /// 如 `Connect` → `StatusChanged` + `RouteApplied`）。所有回复批同时转发给已启用的事件
    /// channel。
    ///
    /// # Errors
    /// engine 掉线 → `ControlClientError::ConnectionLost`；等待超时（已配置）→
    /// `ControlClientError::Timeout`；帧读写失败 → `ControlClientError::Frame`。
    pub fn send(&mut self, cmd: &CoreToEngine) -> Result<Vec<EngineToCore>, ControlClientError> {
        write_json_frame(&mut self.pipe, cmd).map_err(map_frame_error)?;
        if !Self::expects_reply(cmd) {
            return Ok(Vec::new());
        }
        let mut replies = vec![self.read_reply()?];
        // 沉降：给 engine 写出同批后续帧的时间（控制面低频，短等待可接受）。
        std::thread::sleep(Duration::from_millis(20));
        while self.pipe.has_pending_data() {
            replies.push(self.read_reply()?);
        }
        self.dispatch_events(&replies);
        Ok(replies)
    }

    /// 发送一条命令并读取回复批；若命令携带一次性凭据（`Connect`/`UpdateCredentials`），
    /// 发送后**立即零化**本地凭据副本（不等待 `Drop`）。
    ///
    /// `cmd` 以 `&mut` 传入：调用方可据 `req.credentials.password().is_empty()` 验证零化。
    ///
    /// # Errors
    /// 与 `send` 相同：engine 掉线 → `ControlClientError::ConnectionLost`；等待超时（已配置）
    /// → `ControlClientError::Timeout`；帧读写失败 → `ControlClientError::Frame`。
    pub fn send_owned(
        &mut self,
        cmd: &mut CoreToEngine,
    ) -> Result<Vec<EngineToCore>, ControlClientError> {
        let result = self.send(cmd);
        match cmd {
            CoreToEngine::Connect(req) => req.credentials.zeroize(),
            CoreToEngine::UpdateCredentials { credentials } => credentials.zeroize(),
            _ => {}
        }
        result
    }

    /// 读取 engine 主动推送的异步事件（订阅后；在命令间隙调用）。已到达的帧作为事件返回，
    /// 并（若已启用事件 channel）转发给调用者。不阻塞：无待读数据时立即返回空批。
    ///
    /// # Errors
    /// engine 掉线 → `ControlClientError::ConnectionLost`；帧读写失败 →
    /// `ControlClientError::Frame`。
    pub fn poll_events(&mut self) -> Result<Vec<EngineToCore>, ControlClientError> {
        let mut events = Vec::new();
        while self.pipe.has_pending_data() {
            let msg: EngineToCore = read_json_frame(&mut self.pipe).map_err(map_frame_error)?;
            events.push(msg);
        }
        if !events.is_empty() {
            self.dispatch_events(&events);
        }
        Ok(events)
    }

    /// 关闭控制面连接（engine 命令循环收到 `PeerClosed` 后清理并退出）。
    pub fn close(self) {
        drop(self);
    }

    // -----------------------------------------------------------------------
    // 内部
    // -----------------------------------------------------------------------

    /// 该命令是否期待 engine 回复。engine 命令循环对 `Subscribe`/`UpdateCredentials`
    /// 回空批（fire-and-forget），对其它命令至少回一帧。
    fn expects_reply(cmd: &CoreToEngine) -> bool {
        !matches!(
            cmd,
            CoreToEngine::Subscribe { .. } | CoreToEngine::UpdateCredentials { .. }
        )
    }

    /// 读取一帧回复。若配置了回复超时，先有界轮询 `has_pending_data` 等待数据到达；
    /// 超时返回 `Timeout`。engine 掉线（PeerClosed）映射为 `ConnectionLost`。
    fn read_reply(&mut self) -> Result<EngineToCore, ControlClientError> {
        if let Some(timeout) = self.reply_timeout {
            let deadline = Instant::now() + timeout;
            while !self.pipe.has_pending_data() {
                if Instant::now() >= deadline {
                    return Err(ControlClientError::Timeout(timeout));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        read_json_frame(&mut self.pipe).map_err(map_frame_error)
    }

    /// 将一批 `EngineToCore` 消息转发给已启用的事件 channel（best-effort：调用方可能已
    /// 丢弃接收端，此时忽略 send 失败）。
    fn dispatch_events(&self, messages: &[EngineToCore]) {
        if let Some(tx) = &self.event_tx {
            for msg in messages {
                let _ = tx.send(msg.clone());
            }
        }
    }
}

/// 连接 engine 控制面管道：`ERROR_FILE_NOT_FOUND`/`ERROR_PIPE_BUSY` 有界重试（engine
/// 可能仍在启动建管道的竞窗）。
fn connect_pipe_with_retry(name: &str) -> Result<NamedPipeByteStream, ControlClientError> {
    const ATTEMPTS: usize = 30;
    let mut last = PipeIoError::Io(2);
    for _ in 0..ATTEMPTS {
        match NamedPipeByteStream::connect_client(name) {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                last = e;
                // 2 = ERROR_FILE_NOT_FOUND（server 尚未创建）；231 = ERROR_PIPE_BUSY。
                if matches!(&last, PipeIoError::Io(code) if *code == 2 || *code == 231) {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                return Err(ControlClientError::Pipe(last));
            }
        }
    }
    Err(ControlClientError::Pipe(last))
}

// ---------------------------------------------------------------------------
// 单元测试：假 engine 管道服务（同进程线程）测命令往返 / 凭据零化 / 事件分发 /
// 掉线感知 / 超时。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use exv_vpn_win32_ipc::engine_protocol::{
        read_json_frame, write_json_frame, ConnectRequest, CoreToEngine, Credentials,
        EngineHelloReply, EngineHelloReq, EngineState, EngineToCore, FrameError,
    };
    use exv_vpn_win32_ipc::named_pipe_io::NamedPipeByteStream;
    use exv_vpn_win32_ipc::peer_auth::current_user_sid;

    use super::*;

    fn unique_pipe_name(tag: &str) -> String {
        format!(r"\\.\pipe\exv-control-client-{tag}-{}", std::process::id())
    }

    fn test_connect_request() -> ConnectRequest {
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

    /// 客户端连接（同进程：假 engine 的 server pid == 本进程 pid，SID == 当前用户 SID）。
    fn connect_client(name: &str) -> EngineControlClient {
        let pid = std::process::id();
        let sid = current_user_sid().expect("current user sid");
        EngineControlClient::connect(name, pid, pid, &sid).expect("client connect")
    }

    /// 假 engine 服务端：建管道 → accept → 握手 → 命令循环（handler 决定回复）。
    /// 返回管道名与线程句柄。`handler` 对 `Subscribe`/`UpdateCredentials` 应回空批
    /// （与真实 engine 命令循环一致）。
    fn spawn_fake_engine(
        tag: &str,
        handler: impl Fn(CoreToEngine) -> Vec<EngineToCore> + Send + 'static,
    ) -> (String, std::thread::JoinHandle<()>) {
        let name = unique_pipe_name(tag);
        let name_for_engine = name.clone();
        let sid = current_user_sid().expect("current user sid");
        let pid = std::process::id();
        let handle = std::thread::spawn(move || {
            let server =
                NamedPipeByteStream::create_server(&name_for_engine, 1).expect("create server");
            server.connect().expect("accept client");
            let mut server = server;

            let hello: EngineHelloReq = read_json_frame(&mut server).expect("read hello");
            assert_eq!(hello.host_pid, pid, "fake engine must see the declared host pid");
            let reply = EngineHelloReply {
                ok: true,
                error: None,
                engine_pid: pid,
                engine_sid: sid.clone(),
                engine_account: String::new(),
                engine_elevated: true,
            };
            write_json_frame(&mut server, &reply).expect("write hello");

            loop {
                let cmd: CoreToEngine = match read_json_frame(&mut server) {
                    Ok(cmd) => cmd,
                    Err(FrameError::PeerClosed) => break,
                    Err(e) => panic!("fake engine read: {e:?}"),
                };
                let replies = handler(cmd);
                for reply in &replies {
                    write_json_frame(&mut server, reply).expect("write reply");
                }
            }
        });
        (name, handle)
    }

    /// 所有类型化命令经假 engine 往返；fire-and-forget 命令立即返回空批。
    #[test]
    #[allow(clippy::too_many_lines)] // 覆盖全部命令的单一往返测试，保可读性优先
    fn all_commands_round_trip() {
        let (name, handle) = spawn_fake_engine("all-commands", |cmd| match cmd {
            CoreToEngine::Connect(req) => {
                assert_eq!(req.credentials.password(), "s3cret", "wire 必须携带明文凭据");
                vec![
                    EngineToCore::StatusChanged {
                        state: EngineState::Connecting,
                        reason: None,
                    },
                    EngineToCore::StatusChanged {
                        state: EngineState::Connected,
                        reason: None,
                    },
                    EngineToCore::RouteApplied {
                        ok: true,
                        conflict: false,
                    },
                ]
            }
            CoreToEngine::Disconnect { .. } => vec![EngineToCore::StatusChanged {
                state: EngineState::Disconnected,
                reason: None,
            }],
            CoreToEngine::Reconnect
            | CoreToEngine::GetStatus
            | CoreToEngine::Heartbeat => vec![EngineToCore::StatusChanged {
                state: EngineState::Connected,
                reason: None,
            }],
            CoreToEngine::GetStats => vec![EngineToCore::Stats {
                rx_bytes: 111,
                tx_bytes: 222,
                speed: 333,
                latency_ms: 4,
            }],
            // Subscribe / UpdateCredentials：fire-and-forget（engine 命令循环回空批）。
            CoreToEngine::Subscribe { .. } | CoreToEngine::UpdateCredentials { .. } => vec![],
        });

        let mut client = connect_client(&name);

        let replies = client.connect_tunnel(test_connect_request()).expect("connect");
        assert!(
            replies.iter().any(|r| matches!(
                r,
                EngineToCore::StatusChanged {
                    state: EngineState::Connected,
                    ..
                }
            )),
            "Connect 回复必须含 Connected，got {replies:?}"
        );
        assert!(
            replies
                .iter()
                .any(|r| matches!(r, EngineToCore::RouteApplied { ok: true, .. })),
            "Connect 回复必须含 RouteApplied，got {replies:?}"
        );

        let replies = client.disconnect(true).expect("disconnect");
        assert!(
            replies.iter().any(|r| matches!(
                r,
                EngineToCore::StatusChanged {
                    state: EngineState::Disconnected,
                    ..
                }
            )),
            "Disconnect 回复必须含 Disconnected，got {replies:?}"
        );

        let replies = client.reconnect().expect("reconnect");
        assert!(
            replies.iter().any(|r| matches!(
                r,
                EngineToCore::StatusChanged {
                    state: EngineState::Connected,
                    ..
                }
            )),
            "Reconnect 回复必须含 Connected，got {replies:?}"
        );

        let replies = client.get_status().expect("get_status");
        assert!(
            replies.iter().any(|r| matches!(
                r,
                EngineToCore::StatusChanged {
                    state: EngineState::Connected,
                    ..
                }
            )),
            "GetStatus 回复必须含 Connected，got {replies:?}"
        );

        let replies = client.get_stats().expect("get_stats");
        assert!(
            replies.iter().any(|r| matches!(r, EngineToCore::Stats { rx_bytes: 111, .. })),
            "GetStats 回复必须含 Stats，got {replies:?}"
        );

        let replies = client.heartbeat().expect("heartbeat");
        assert!(
            replies.iter().any(|r| matches!(r, EngineToCore::StatusChanged { .. })),
            "Heartbeat 回复必须含 StatusChanged，got {replies:?}"
        );

        // fire-and-forget：必须立即返回空批，不阻塞等待 engine 回复。
        let replies = client.subscribe(true).expect("subscribe");
        assert!(replies.is_empty(), "Subscribe 不期待回复");
        let replies = client
            .update_credentials(Credentials::new("u", "p"))
            .expect("update_credentials");
        assert!(replies.is_empty(), "UpdateCredentials 不期待回复");

        drop(client);
        handle.join().expect("fake engine thread joins");
    }

    /// 凭据零化：`send_owned` 发送后，`Connect`/`UpdateCredentials` 内的凭据本地副本
    /// 必须立即清零（一次性凭据契约，不等待 Drop）。
    #[test]
    fn send_owned_zeroizes_credentials() {
        let (name, handle) = spawn_fake_engine("zeroize", |cmd| match cmd {
            CoreToEngine::Connect(_) => vec![EngineToCore::StatusChanged {
                state: EngineState::Connected,
                reason: None,
            }],
            _ => vec![],
        });
        let mut client = connect_client(&name);

        let mut cmd = CoreToEngine::Connect(test_connect_request());
        client.send_owned(&mut cmd).expect("send connect");
        match &cmd {
            CoreToEngine::Connect(req) => {
                assert!(
                    req.credentials.password().is_empty(),
                    "password 必须已零化，got {:?}",
                    req.credentials.password()
                );
                assert!(
                    req.credentials.username().is_empty(),
                    "username 必须已零化，got {:?}",
                    req.credentials.username()
                );
            }
            _ => panic!("expected Connect"),
        }

        let mut cmd = CoreToEngine::UpdateCredentials {
            credentials: Credentials::new("u", "p"),
        };
        client.send_owned(&mut cmd).expect("send update credentials");
        match &cmd {
            CoreToEngine::UpdateCredentials { credentials } => {
                assert!(
                    credentials.password().is_empty(),
                    "password 必须已零化，got {:?}",
                    credentials.password()
                );
            }
            _ => panic!("expected UpdateCredentials"),
        }

        drop(client);
        handle.join().expect("fake engine thread joins");
    }

    /// 事件分发：启用事件 channel 后，命令回复批也必须送达调用者的 Receiver。
    #[test]
    fn event_channel_receives_replies() {
        let (name, handle) = spawn_fake_engine("events", |cmd| match cmd {
            CoreToEngine::GetStatus => vec![EngineToCore::StatusChanged {
                state: EngineState::Connected,
                reason: Some("via-event".to_string()),
            }],
            CoreToEngine::GetStats => vec![EngineToCore::Stats {
                rx_bytes: 9,
                tx_bytes: 9,
                speed: 9,
                latency_ms: 9,
            }],
            _ => vec![],
        });
        let mut client = connect_client(&name);
        let rx = client.enable_event_channel();

        client.get_status().expect("get_status");
        let ev = rx.recv_timeout(Duration::from_secs(5)).expect("event received");
        assert!(
            matches!(ev, EngineToCore::StatusChanged { reason: Some(ref r), .. } if r == "via-event"),
            "事件 channel 必须收到 StatusChanged，got {ev:?}"
        );

        client.get_stats().expect("get_stats");
        let ev = rx.recv_timeout(Duration::from_secs(5)).expect("event received");
        assert!(
            matches!(ev, EngineToCore::Stats { rx_bytes: 9, .. }),
            "事件 channel 必须收到 Stats，got {ev:?}"
        );

        drop(client);
        handle.join().expect("fake engine thread joins");
    }

    /// 掉线感知：engine 关闭控制面管道后，client 的下一条命令必须报 `ConnectionLost`。
    #[test]
    fn connection_lost_on_engine_close() {
        let name = unique_pipe_name("lost");
        let name_for_engine = name.clone();
        let sid = current_user_sid().expect("current user sid");
        let pid = std::process::id();
        let handle = std::thread::spawn(move || {
            let server =
                NamedPipeByteStream::create_server(&name_for_engine, 1).expect("create server");
            server.connect().expect("accept client");
            let mut server = server;

            let _hello: EngineHelloReq = read_json_frame(&mut server).expect("read hello");
            write_json_frame(
                &mut server,
                &EngineHelloReply {
                    ok: true,
                    error: None,
                    engine_pid: pid,
                    engine_sid: sid,
                    engine_account: String::new(),
                    engine_elevated: true,
                },
            )
            .expect("write hello");

            // 回一条 GetStatus 回复后立即关闭控制面（drop server → 管道断开）。
            let _cmd: CoreToEngine = read_json_frame(&mut server).expect("read get-status");
            write_json_frame(
                &mut server,
                &EngineToCore::StatusChanged {
                    state: EngineState::Disconnected,
                    reason: None,
                },
            )
            .expect("write status");
        });

        let mut client = connect_client(&name);
        client.get_status().expect("first get_status ok");

        // engine 已关闭：写可能成功（pipe 缓冲）但读必须报 PeerClosed → ConnectionLost；
        // 若写已失败（broken pipe）同样映射为 ConnectionLost。
        let err = client.get_status().expect_err("engine closed -> error");
        assert!(
            matches!(err, ControlClientError::ConnectionLost),
            "必须报 ConnectionLost，got {err:?}"
        );

        handle.join().expect("fake engine thread joins");
    }

    /// 超时：engine 不回复且配置了 `reply_timeout` 时，client 必须报 `Timeout`。
    #[test]
    fn reply_timeout_when_engine_hangs() {
        let (name, handle) = spawn_fake_engine("hang", |_cmd| {
            // 收到命令但永不回复（engine 命令循环侧挂起）。
            Vec::new()
        });
        let mut client = connect_client(&name);
        client.set_reply_timeout(Duration::from_millis(300));

        let err = client.get_status().expect_err("hang -> timeout");
        assert!(
            matches!(err, ControlClientError::Timeout(_)),
            "必须报 Timeout，got {err:?}"
        );

        drop(client); // 关闭 client → fake engine 读到 PeerClosed → 线程退出
        handle.join().expect("fake engine thread joins");
    }

    /// 凭据在 wire 上完整（序列化先于零化）：假 engine 收到 Connect 帧时必须看到明文
    /// 密码，而 client 本地副本随后已被零化（另一测试验证）。
    #[test]
    fn connect_sends_credentials_before_zeroize() {
        let seen = Arc::new(Mutex::new(None::<String>));
        let seen_clone = Arc::clone(&seen);
        let (name, handle) = spawn_fake_engine("wire-creds", move |cmd| {
            if let CoreToEngine::Connect(req) = cmd {
                *seen_clone.lock().expect("seen 锁") = Some(req.credentials.password().to_string());
                vec![EngineToCore::StatusChanged {
                    state: EngineState::Connected,
                    reason: None,
                }]
            } else {
                vec![]
            }
        });

        let mut client = connect_client(&name);
        client.connect_tunnel(test_connect_request()).expect("connect");
        assert_eq!(
            seen.lock().expect("seen 锁").as_deref(),
            Some("s3cret"),
            "假 engine 必须收到明文凭据（序列化先于零化）"
        );

        drop(client);
        handle.join().expect("fake engine thread joins");
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
