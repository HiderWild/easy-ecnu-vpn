// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// R1w: engine 连接状态事件发布器 —— 独立 status 通道（HelperControl.StreamConnectStatus）。
//
// 通道设计镜像 `stats::StatsPublisher`（P5-a）与 `log_sink::LogSink`（P2-b）：
//   * [`StatusPublisher::open_stream`] 建立一条 mpsc 推送通道（last-writer-wins：
//     core 是唯一状态消费方），返回接收端给 gRPC server 转成 `ReceiverStream`；
//   * [`StatusPublisher::publish`] 推送一个 [`StatusEvent`] 到当前挂接通道；无挂接流
//     则 no-op（状态事件不是持久化的——core 在挂接时重新获取 snapshot，R2 接线）；
//   * 客户端断线（接收端 drop）→ 发送失败 → 静默丢弃；重连走 `open_stream` 重新挂接。
//
// 事件携带 operation_id + 8 级 ConnectPhase + 粗粒度 StatsPhase + 可选 err（R1w
// 契约）。真实数据面状态由 R1b 落地：登录/CSTP/apply/数据面组装在
// `tunnel_runtime` 后台逐段 publish（ConnectPhase 推进），终态 Connected/Failed
// 由组装线程 publish（见 `RealTunnelRuntime::assemble`）；StopTunnel teardown 完
// 后由 `grpc_server::stop_tunnel` publish Idle（业务停机收敛信号——D1 解耦后 engine
// 回 Idle 常驻，不再随 StopTunnel 自退）。
//
// 除推送通道外，本模块还支持一个**内部终态观察者**（R2/P2-1）：`grpc_server`
// 在构造时注册一个回调，`publish` 每次都会调用它——engine 侧用它把异步 apply 的
// 运行时终态（Connected/Failed）写回 `HelperControlCore::terminals`，使
// `GetOperation(apply)` 能回答真实终态而非恒 Pending。观察者与推送通道互不影响
// （推送是 last-writer-wins 的外部流；观察者是 engine 内部记账）。
//
// 与 StreamStats 的关系：**不并入 StreamStats**（统计通道保持纯计数）。本模块是
// 独立的 status 通道；`StatsPublisher` 保持纯字节计数 + 阶段采样，status 语义不流入。

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use exv_vpn_wire::generated;
use generated::ConnectPhase;
use generated::StatsPhase;
use tokio::sync::mpsc;
use tonic::Status;

/// status 推送 mpsc 通道容量（低频事件，32 足够；满则不阻塞业务路径）。
const STREAM_CAPACITY: usize = 32;

/// 一次连接状态事件（独立 status 通道的领域形态；R1b 由真实数据面驱动）。
#[derive(Debug, Clone)]
pub struct StatusEvent {
    /// 16 字节 operation_id（= `OperationLookupKey.operation_id`；与 ApplyAccepted 关联）。
    pub operation_id: Vec<u8>,
    /// 细粒度 8 级连接阶段（common.proto `ConnectPhase`）。
    pub connect_phase: ConnectPhase,
    /// 粗粒度生命周期阶段（common.proto `StatsPhase`）。
    pub coarse_phase: StatsPhase,
    /// 失败时携带（coarse_phase = Failed）；成功时 `None`。
    pub error: Option<generated::VpnError>,
    /// engine 首次确认数据面可用的 wall-clock epoch 毫秒；只在 `Connected` 终态
    /// 非零。它是展示用真实会话起点，不参与授权、路由或资源所有权决策。
    pub session_established_at_ms: i64,
}

impl StatusEvent {
    /// 一个「连接进行中」事件（coarse = Connecting）。
    #[must_use]
    pub fn connecting(operation_id: Vec<u8>, connect_phase: ConnectPhase) -> Self {
        Self {
            operation_id,
            connect_phase,
            coarse_phase: StatsPhase::Connecting,
            error: None,
            session_established_at_ms: 0,
        }
    }

    /// 一个「已连接」终态事件（coarse = Connected，无错误）。
    #[must_use]
    pub fn connected(operation_id: Vec<u8>) -> Self {
        Self {
            operation_id,
            connect_phase: ConnectPhase::StartingDataPlane,
            coarse_phase: StatsPhase::Connected,
            error: None,
            session_established_at_ms: wall_clock_ms(),
        }
    }

    /// 一个「失败」终态事件（coarse = Failed，携带结构化错误）。
    #[must_use]
    pub fn failed(operation_id: Vec<u8>, connect_phase: ConnectPhase, error: generated::VpnError) -> Self {
        Self {
            operation_id,
            connect_phase,
            coarse_phase: StatsPhase::Failed,
            error: Some(error),
            session_established_at_ms: 0,
        }
    }

    /// 一个「已停止 / 回 idle」终态事件（coarse = Idle，无连接阶段语义）。
    #[must_use]
    pub fn idle(operation_id: Vec<u8>) -> Self {
        Self {
            operation_id,
            connect_phase: ConnectPhase::Unspecified,
            coarse_phase: StatsPhase::Idle,
            error: None,
            session_established_at_ms: 0,
        }
    }

    /// 转 wire `ConnectStatusEvent`。
    #[must_use]
    pub fn to_wire(&self) -> generated::ConnectStatusEvent {
        generated::ConnectStatusEvent {
            operation_id: self.operation_id.clone(),
            connect_phase: self.connect_phase as i32,
            coarse_phase: self.coarse_phase as i32,
            error: self.error.clone(),
            session_established_at_ms: self.session_established_at_ms,
        }
    }
}

/// 当前 UTC epoch 毫秒。系统时钟不可用或溢出时返回 0，保持 wire 中的“未知”约定。
fn wall_clock_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
}

/// `StreamConnectStatus` 推送端内部可变态。
///
/// 注：不 derive `Debug`——内部终态观察者（`dyn Fn`）非 `Debug`。
struct StatusPublisherInner {
    /// 当前挂接的 `StreamConnectStatus` 推送通道（`last-writer-wins`：core 是唯一消费方）。
    push: Option<mpsc::Sender<Result<generated::ConnectStatusEvent, Status>>>,
    /// engine 内部终态观察者（R2/P2-1）：`publish` 每次调用它；`grpc_server` 用它把
    /// 异步 apply 的运行时终态写回 `core.terminals`（`GetOperation(apply)` 可答真实
    /// 终态）。独立于推送通道（观察者是内部记账，不挂接外部流）。`None` = 未注册。
    observer: Option<Arc<dyn Fn(&StatusEvent) + Send + Sync>>,
}

/// engine 状态事件推送端点：持有推送通道（对齐 `StatsPublisher` 的 last-writer-wins）。
///
/// 注：不 derive `Debug`——内部终态观察者（`dyn Fn`）非 `Debug`。
pub struct StatusPublisher {
    inner: Mutex<StatusPublisherInner>,
}

impl StatusPublisher {
    /// 建一个空推送端点（未挂接流；发布为 no-op；无内部观察者）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(StatusPublisherInner {
                push: None,
                observer: None,
            }),
        }
    }

    /// 挂接一条 `StreamConnectStatus` 推送流，返回接收端（由 gRPC server 转成
    /// `ReceiverStream`）。注册为当前唯一推送通道（替换任何残留旧通道）。
    ///
    /// # Panics
    /// 内部互斥锁中毒（另一线程持锁时 panic）→ panic。
    #[must_use]
    pub fn open_stream(&self) -> mpsc::Receiver<Result<generated::ConnectStatusEvent, Status>> {
        let (tx, rx) = mpsc::channel(STREAM_CAPACITY);
        {
            let mut inner = self.inner.lock().expect("status publisher lock");
            inner.push = Some(tx);
        }
        rx
    }

    /// 发布一个连接状态事件（无挂接流则 no-op；接收端 drop 则静默丢弃）。
    ///
    /// R2/P2-1：无论是否挂接外部流，都先调用内部终态观察者（`grpc_server` 用它把
    /// 异步 apply 的运行时终态写回 `core.terminals`）。观察者在锁外调用（避免重入
    /// 持锁；观察者回调里只取 `core` 锁，与发布器锁无环）。
    ///
    /// # Panics
    /// 内部互斥锁中毒（另一线程持锁时 panic）→ panic。
    pub fn publish(&self, event: StatusEvent) {
        let (sender, observer) = {
            let inner = self.inner.lock().expect("status publisher lock");
            (inner.push.clone(), inner.observer.clone())
        };
        if let Some(observer) = observer {
            observer(&event);
        }
        if let Some(tx) = sender {
            let wire = event.to_wire();
            let _ = tx.try_send(Ok(wire));
        }
    }

    /// 注册内部终态观察者（R2/P2-1）：每次 `publish` 调用一次（替换任何先前的观察者）。
    /// `grpc_server` 在构造时调用；观察者只做 engine 内部记账（写 `core.terminals`），
    /// 不得触碰推送通道（外部流仍由 core 唯一消费）。
    ///
    /// # Panics
    /// 内部互斥锁中毒（另一线程持锁时 panic）→ panic。
    pub fn set_terminal_observer(&self, observer: Arc<dyn Fn(&StatusEvent) + Send + Sync>) {
        let mut inner = self.inner.lock().expect("status publisher lock");
        inner.observer = Some(observer);
    }

    /// 是否挂接着推送通道（测试/观测）。
    ///
    /// # Panics
    /// 内部互斥锁中毒（另一线程持锁时 panic）→ panic。
    #[must_use]
    pub fn is_push_attached(&self) -> bool {
        self.inner.lock().expect("status publisher lock").push.is_some()
    }
}

impl Default for StatusPublisher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// 单元测试：事件形态 / 挂接 / 发布。
// 集成契约测试（StreamConnectStatus RPC over named pipe）在 tests/grpc_server.rs。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 事件形态：connecting / connected / failed / idle 各自携带正确的 phase + coarse + err。
    #[test]
    fn event_shapes_carry_phase_coarse_and_error() {
        let connecting = StatusEvent::connecting(uuid16(3), ConnectPhase::ApplyingPlatformTunnel);
        assert_eq!(connecting.coarse_phase, StatsPhase::Connecting);
        assert_eq!(connecting.connect_phase, ConnectPhase::ApplyingPlatformTunnel);
        assert!(connecting.error.is_none());
        assert_eq!(connecting.session_established_at_ms, 0);

        let connected = StatusEvent::connected(uuid16(3));
        assert_eq!(connected.coarse_phase, StatsPhase::Connected);
        assert_eq!(connected.connect_phase, ConnectPhase::StartingDataPlane);
        assert!(connected.error.is_none());
        assert!(
            connected.session_established_at_ms > 0,
            "engine 确认数据面可用时必须铸造真实会话起点"
        );

        let error = generated::VpnError {
            code: 1,
            stage: 8,
            certainty: 0,
            retry: 1,
            subject: None,
            resource: None,
            native: None,
        };
        let failed = StatusEvent::failed(uuid16(3), ConnectPhase::ApplyingPlatformTunnel, error.clone());
        assert_eq!(failed.coarse_phase, StatsPhase::Failed);
        assert_eq!(failed.error.as_ref(), Some(&error));
        assert_eq!(failed.session_established_at_ms, 0);

        let idle = StatusEvent::idle(uuid16(7));
        assert_eq!(idle.coarse_phase, StatsPhase::Idle);
        assert_eq!(idle.connect_phase, ConnectPhase::Unspecified);
        assert!(idle.error.is_none());
        assert_eq!(idle.session_established_at_ms, 0);
    }

    /// wire 形态：to_wire 保留 operation_id + phase + coarse + err。
    #[test]
    fn to_wire_preserves_correlation_fields() {
        let operation_id = uuid16(3);
        let event = StatusEvent::connecting(operation_id.clone(), ConnectPhase::AcquiringPlatformLease);
        let wire = event.to_wire();
        assert_eq!(wire.operation_id, operation_id);
        assert_eq!(wire.connect_phase, ConnectPhase::AcquiringPlatformLease as i32);
        assert_eq!(wire.coarse_phase, StatsPhase::Connecting as i32);
        assert!(wire.error.is_none());
        assert_eq!(wire.session_established_at_ms, 0);
    }

    /// 挂接 + 发布：open_stream 后 publish 的事件到达接收端；未挂接时 no-op。
    #[tokio::test]
    async fn publish_delivers_to_attached_stream() {
        let publisher = StatusPublisher::new();
        assert!(!publisher.is_push_attached(), "no stream attached initially");

        let mut rx = publisher.open_stream();
        assert!(publisher.is_push_attached(), "stream attached after open_stream");

        publisher.publish(StatusEvent::connecting(uuid16(3), ConnectPhase::ApplyingPlatformTunnel));
        let item = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("event within timeout")
            .expect("stream alive")
            .expect("event ok");
        assert_eq!(item.operation_id, uuid16(3));
        assert_eq!(item.connect_phase, ConnectPhase::ApplyingPlatformTunnel as i32);

        // 未挂接流时发布 no-op（不 panic、不泄漏）。
        drop(rx);
        publisher.publish(StatusEvent::connected(uuid16(3)));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    /// R2/P2-1：注册内部终态观察者后，`publish` 每次调用它（与挂接流无关）；
    /// 未注册时不调用（no-op 保持）。
    #[tokio::test]
    async fn publish_invokes_terminal_observer() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let publisher = StatusPublisher::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(std::sync::Mutex::new(Vec::<StatusEvent>::new()));
        let calls_c = Arc::clone(&calls);
        let seen_c = Arc::clone(&seen);
        publisher.set_terminal_observer(Arc::new(move |event: &StatusEvent| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            seen_c.lock().unwrap().push(event.clone());
        }));

        // 未挂接外部流也调用观察者（内部记账与推送解耦）。
        publisher.publish(StatusEvent::connected(uuid16(3)));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "publish 必须调用观察者");
        let got = seen.lock().unwrap();
        assert_eq!(got[0].coarse_phase, StatsPhase::Connected);
        assert_eq!(got[0].operation_id, uuid16(3));
        drop(got);

        // 挂接外部流后仍调用观察者（推送与观察并存）。
        let mut rx = publisher.open_stream();
        publisher.publish(StatusEvent::idle(uuid16(7)));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let item = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("idle within timeout")
            .expect("stream alive")
            .expect("event ok");
        assert_eq!(item.coarse_phase, StatsPhase::Idle as i32);

        // 新观察者替换旧观察者。
        let calls2 = Arc::new(AtomicUsize::new(0));
        let calls2_c = Arc::clone(&calls2);
        publisher.set_terminal_observer(Arc::new(move |_: &StatusEvent| {
            calls2_c.fetch_add(1, Ordering::SeqCst);
        }));
        publisher.publish(StatusEvent::idle(uuid16(7)));
        assert_eq!(calls2.load(Ordering::SeqCst), 1, "替换后仅新观察者被调用");
    }

    /// 16-byte 测试 id（对齐 tests/grpc_server.rs 的 uuid16）。
    fn uuid16(n: u8) -> Vec<u8> {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        bytes[1] = 0x42;
        bytes.to_vec()
    }
}
