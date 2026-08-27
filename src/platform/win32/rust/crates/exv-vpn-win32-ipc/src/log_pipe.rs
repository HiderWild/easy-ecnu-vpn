// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core 暴露的 **Log API**：固定名 + 多实例的日志命名管道。
//!
//! 两进程架构中 engine（特权 token，`ShellExecuteExW(runas)` 拉起，stdout 落在 runas
//! 新窗口不回流）需要把日志送回 core 统一落盘。本模块实现 core 侧多实例 log 管道 server
//! 与调用方（engine / 未来 UI）的 log 管道 client：
//!
//! - **固定管道名** `\\.\pipe\exv-log`（对齐 C++ `\\.\pipe\exv-helper` 固定名模式）——
//!   任意调用者连同一名字即可发日志，与 UI 访问方式一致；
//! - **多实例**：core 预创建 `LOG_PIPE_MAX_INSTANCES` 个实例，每实例一条 accept 线程
//!   （参考 C++ helper_daemon 固定名多实例 accept 循环），多客户端可同时连入；
//!   client 断开后 accept 循环重建额外实例（支持重连）；
//! - **帧 wire 格式**：`LogEvent` JSON 帧（u32 BE 长度前缀 + JSON，与控制面同款）；
//!   `message` 不含时间戳——core 侧统一加 `[+NNN.NN s]` 落盘（core 是唯一日志层）。
//!
//! DACL：server 授 core 用户 SID（engine 同用户提权 token 可连；未来 UI 同用户也可连）。

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::engine_protocol::{read_json_frame, write_json_frame};
use crate::named_pipe_io::{NamedPipeByteStream, PipeIoError};

/// 固定 log 管道名（core server + engine/UI client 共用的 well-known 名字）。
pub const LOG_PIPE_NAME: &str = r"\\.\pipe\exv-log";

/// log 管道最大并发实例（core 预创建；engine + 未来 UI 各占一个实例）。
pub const LOG_PIPE_MAX_INSTANCES: u32 = 8;

/// 日志事件帧（u32 BE 长度前缀 + JSON，与控制面同款 wire 格式）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEvent {
    /// 来源/级别（`info`/`warn`/`error`；MVP 仅记录，core 不据此过滤）。
    pub level: String,
    /// 日志行文本（**不含时间戳**——core 侧统一加 `[+NNN.NN s]` 落盘）。
    pub message: String,
}

/// 多实例 log 管道 server（core 侧）。
pub struct LogPipeServer {
    /// 各实例的 accept 线程句柄（`join_all` 可选等待；进程退出时线程随之结束）。
    joiners: Vec<std::thread::JoinHandle<()>>,
}

impl LogPipeServer {
    /// 启动多实例 log 管道 server。
    ///
    /// 先建第一实例（`FILE_FLAG_FIRST_PIPE_INSTANCE` 反 squat——若另一 core 已持名则
    /// 失败返回），再 best-effort 建 `max_instances - 1` 个额外实例。每个实例一条 accept
    /// 线程：阻塞 accept → 逐帧读 `LogEvent` → 交给 `on_event`（core 用它统一 `log_line`
    /// 落盘）；client 断开后重建额外实例继续 accept（支持重连）。
    ///
    /// `dacl_user_sid` 为 `Some` 时授 `SYSTEM + 该 SID`（core 用户 SID），engine（同用户
    /// 提权 token）与未来 UI 才能连入。
    ///
    /// # Errors
    /// 第一实例创建失败（另一 core 已持有 `name`，或 DACL 构造失败）→
    /// `PipeIoError`。调用方可据此优雅降级（不建 log server，日志只走调用方 stdout）。
    pub fn start(
        name: &str,
        dacl_user_sid: Option<&str>,
        max_instances: u32,
        on_event: impl Fn(LogEvent) + Send + Sync + 'static,
    ) -> Result<Self, PipeIoError> {
        // 1. 第一实例（反 squat：失败 = 另一 server 已持名）。
        let first =
            NamedPipeByteStream::create_server_with_dacl(name, max_instances, dacl_user_sid)?;
        // 2. 额外实例（不带 FIRST_PIPE_INSTANCE；best-effort——达 max 或失败即停）。
        let mut instances = vec![first];
        for _ in 1..max_instances {
            match NamedPipeByteStream::create_server_additional_with_dacl(
                name,
                max_instances,
                dacl_user_sid,
            ) {
                Ok(h) => instances.push(h),
                Err(_) => break,
            }
        }
        // 3. 每实例一条 accept 线程。
        let handler = Arc::new(on_event);
        let mut joiners = Vec::with_capacity(instances.len());
        for instance in instances {
            let name = name.to_string();
            let sid = dacl_user_sid.map(str::to_string);
            let handler = Arc::clone(&handler);
            joiners.push(std::thread::spawn(move || {
                accept_loop(instance, &name, sid.as_deref(), max_instances, handler);
            }));
        }
        Ok(Self { joiners })
    }

    /// 等待全部 accept 线程退出（所有 client 断开后各线程自然结束；core 退出时可选调用）。
    pub fn join_all(self) {
        for j in self.joiners {
            let _ = j.join();
        }
    }
}

/// 单实例 accept 循环：阻塞 accept → 逐帧读 `LogEvent` → 回调；client 断开后重建
/// 额外实例继续 accept（重连支持）。
fn accept_loop(
    mut server: NamedPipeByteStream,
    name: &str,
    sid: Option<&str>,
    max_instances: u32,
    handler: Arc<dyn Fn(LogEvent) + Send + Sync>,
) {
    loop {
        if server.connect().is_err() {
            return;
        }
        // 逐帧读 `LogEvent` 直到 client 断开 / 帧错误（重建实例 accept 下一个）。
        while let Ok(ev) = read_json_frame::<LogEvent>(&mut server) {
            handler(ev);
        }
        // 断开实例被丢弃，创建新实例（additional，不带 FIRST_PIPE_INSTANCE）再 accept。
        match NamedPipeByteStream::create_server_additional_with_dacl(name, max_instances, sid) {
            Ok(next) => server = next,
            Err(_) => return,
        }
    }
}

/// log 管道 client（engine / 未来 UI 侧）。连接到 core 的 log 管道并发送 `LogEvent`。
pub struct LogPipeClient {
    pipe: Option<NamedPipeByteStream>,
}

impl LogPipeClient {
    /// 连接 core 的 log 管道。
    ///
    /// # Errors
    /// 管道不可达 / 连接失败 → `PipeIoError`（调用方 best-effort：失败时日志只走本地
    /// stdout）。
    pub fn connect(name: &str) -> Result<Self, PipeIoError> {
        Ok(Self {
            pipe: Some(NamedPipeByteStream::connect_client(name)?),
        })
    }

    /// 发送一条日志事件（best-effort：管道断开时静默丢弃连接——后续日志只走调用方
    /// stdout，不阻塞主流程）。
    pub fn send_event(&mut self, ev: &LogEvent) {
        let ok = self
            .pipe
            .as_mut()
            .is_some_and(|p| write_json_frame(p, ev).is_ok());
        if !ok {
            self.pipe = None;
        }
    }

    /// 是否仍连接着 log 管道（调用方可据以决定是否降级 stdout-only）。
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.pipe.is_some()
    }
}

// ---------------------------------------------------------------------------
// 单元测试：帧格式 + server/client 往返 + 多客户端并发。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::*;

    fn unique_pipe(tag: &str) -> String {
        format!(r"\\.\pipe\exv-log-test-{tag}-{}", std::process::id())
    }

    /// `LogEvent` JSON 帧序列化往返（wire 契约稳定）。
    #[test]
    fn log_event_serde_round_trip() {
        let ev = LogEvent {
            level: "info".to_string(),
            message: "hello world".to_string(),
        };
        let json = serde_json::to_string(&ev).expect("serialize");
        let back: LogEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, ev);
    }

    /// server + client 往返：client 发送的日志事件必须到达 server 的回调（异步 accept
    /// 线程转发）。
    #[test]
    fn log_pipe_delivers_client_events() {
        let name = unique_pipe("deliver");
        let received = Arc::new(Mutex::new(Vec::new()));
        let recv = Arc::clone(&received);
        let _server = LogPipeServer::start(&name, None, 4, move |ev| {
            recv.lock().expect("recv 锁").push(format!("{}:{}", ev.level, ev.message));
        })
        .expect("start log server");

        let mut client = LogPipeClient::connect(&name).expect("connect");
        assert!(client.is_connected());
        client.send_event(&LogEvent {
            level: "info".into(),
            message: "one".into(),
        });
        client.send_event(&LogEvent {
            level: "error".into(),
            message: "two".into(),
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        while received.lock().expect("recv 锁").len() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let got = received.lock().expect("recv 锁").clone();
        assert_eq!(got, vec!["info:one".to_string(), "error:two".to_string()]);
        drop(client);
    }

    /// 多客户端并发：两个 client 同时连入同一固定名 log 管道，各自日志都能送达回调。
    #[test]
    fn log_pipe_two_clients_both_deliver() {
        let name = unique_pipe("two-clients");
        let received = Arc::new(Mutex::new(Vec::new()));
        let recv = Arc::clone(&received);
        let _server = LogPipeServer::start(&name, None, 4, move |ev| {
            recv.lock().expect("recv 锁").push(ev.message);
        })
        .expect("start log server");

        let mut c1 = LogPipeClient::connect(&name).expect("client 1");
        let mut c2 = LogPipeClient::connect(&name).expect("client 2");
        c1.send_event(&LogEvent {
            level: "info".into(),
            message: "from-1".into(),
        });
        c2.send_event(&LogEvent {
            level: "info".into(),
            message: "from-2".into(),
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        while received.lock().expect("recv 锁").len() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut got = received.lock().expect("recv 锁").clone();
        got.sort();
        assert_eq!(got, vec!["from-1".to_string(), "from-2".to_string()]);
        drop(c1);
        drop(c2);
    }

    /// `LogEvent` 通过真实 pipe 以 JSON 帧往返（端到端 wire 校验）。
    #[test]
    fn log_event_wire_frame_round_trip() {
        let name = unique_pipe("wire");
        let received = Arc::new(Mutex::new(None::<LogEvent>));
        let recv = Arc::clone(&received);
        let _server = LogPipeServer::start(&name, None, 2, move |ev| {
            *recv.lock().expect("recv 锁") = Some(ev);
        })
        .expect("start log server");

        let mut client = LogPipeClient::connect(&name).expect("connect");
        client.send_event(&LogEvent {
            level: "warn".into(),
            message: "wire-check".into(),
        });

        let deadline = Instant::now() + Duration::from_secs(5);
        while received.lock().expect("recv 锁").is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let got = received.lock().expect("recv 锁").clone().expect("event received");
        assert_eq!(got.level, "warn");
        assert_eq!(got.message, "wire-check");
        drop(client);
    }
}
