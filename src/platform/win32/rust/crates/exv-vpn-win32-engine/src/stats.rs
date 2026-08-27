// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// P5-a: engine 统计注册表 + StreamStats 推送。
//
// 数据面（Wintun ring → CSTP/TLS）尚未在本阶段接死；本模块是统计点的产品化接缝：
// 未来数据面在每个 packet 边界调用 [`StatsRegistry::record_rx`]/[`record_tx`]，
// 本模块聚合为 wire `StatsEvent` 并经 `HelperControl.StreamStats` 推给 core。
//
// 通道设计镜像 `log_sink::LogSink`（P2-b）：
//   * [`StatsPublisher::open_stream`] 建立一条 mpsc 推送通道（last-writer-wins：
//     core 是唯一统计消费方），并 spawn 一个采样 task；
//   * 采样 task 按 interval 读 [`StatsRegistry`] 快照，计算自上次样本的字节速率
//     （bytes/sec），组 wire `StatsEvent` 推送；无挂接流则不采样（无空转）；
//   * 客户端断线（接收端 drop）→ 发送失败 → task 自行退出；重连走 `open_stream`
//     重新挂接（累计计数器即天然断点，无需 resume tick）。
//
// 数据面安全：`record_rx`/`record_tx` 是 lock-free 的 saturating 原子累加，永不
// 阻塞 packet 路径（relaxed 序对单调累计计数器足够）。
//
// wire 形态：`rx_bytes`/`tx_bytes` 为累计权威字节数；`rx_rate`/`tx_rate` 为 engine
// 采样速率（0 = 尚无前一样本），core 侧 P5-2 仍按字节增量自行归一化速度。

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use exv_vpn_wire::generated;
use generated::StatsPhase;
use tokio::sync::mpsc;
use tonic::Status;

/// engine 默认 `StreamStats` 推送间隔（ms；`StreamStatsRequest.sample_interval_ms == 0` 时）。
pub const DEFAULT_SAMPLE_INTERVAL_MS: u32 = 1000;

/// 采样 mpsc 通道容量（低频推送，16 足够；满则不阻塞业务路径）。
const STREAM_CAPACITY: usize = 16;

/// 一次统计快照（`StatsRegistry` 聚合读出的不可变态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsSample {
    /// 累计接收字节（隧道方向）。
    pub rx_bytes: u64,
    /// 累计发送字节（隧道方向）。
    pub tx_bytes: u64,
    /// 最近一次往返延迟（ms；0 = 未知/不可得）。
    pub latency_ms: u64,
    /// 采样时刻的连接阶段。
    pub phase: StatsPhase,
    /// 采样时刻 wall-clock epoch 毫秒（UTC；0 = 未知）。
    pub timestamp_ms: i64,
}

/// 数据面可写的统计注册表（lock-free 累计 + 阶段）。
///
/// 数据面线程只在 packet 边界调用 `record_rx`/`record_tx`（以及可选的
/// `record_latency`/`set_phase`）；采样 task 以 relaxed 序读取，永不加锁。
#[derive(Debug)]
pub struct StatsRegistry {
    rx_bytes: AtomicU64,
    tx_bytes: AtomicU64,
    latency_ms: AtomicU64,
    phase: AtomicU8,
}

impl StatsRegistry {
    /// 建一个清零注册表（默认阶段 `Idle`）。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            latency_ms: AtomicU64::new(0),
            phase: AtomicU8::new(StatsPhase::Idle as u8),
        }
    }

    /// 记录 `bytes` 接收字节（saturating 原子累加，不阻塞数据面路径）。
    pub fn record_rx(&self, bytes: u64) {
        saturating_add(&self.rx_bytes, bytes);
    }

    /// 记录 `bytes` 发送字节（saturating 原子累加，不阻塞数据面路径）。
    pub fn record_tx(&self, bytes: u64) {
        saturating_add(&self.tx_bytes, bytes);
    }

    /// 记录一次往返延迟（ms；0 = 清除为未知）。
    pub fn record_latency(&self, ms: u64) {
        self.latency_ms.store(ms, Ordering::Relaxed);
    }

    /// 设置当前连接阶段（`StatsPhase`）。
    pub fn set_phase(&self, phase: StatsPhase) {
        self.phase.store(phase as u8, Ordering::Relaxed);
    }

    /// 读取一次聚合快照（relaxed；累计计数器 + 阶段 + wall-clock）。
    #[must_use]
    pub fn snapshot(&self) -> StatsSample {
        StatsSample {
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            latency_ms: self.latency_ms.load(Ordering::Relaxed),
            phase: phase_from_u8(self.phase.load(Ordering::Relaxed)),
            timestamp_ms: wall_clock_ms(),
        }
    }
}

impl Default for StatsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// saturating 原子累加：`fetch_add` 回绕是累计计数器的 bug，这里用 CAS 循环保证
/// `u64::MAX` 封顶（数据面只多一两次原子操作，仍无锁）。
fn saturating_add(counter: &AtomicU64, delta: u64) {
    if delta == 0 {
        return;
    }
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(delta);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(actual) => {
                debug_assert!(actual >= current);
                break;
            }
            Err(actual) => current = actual,
        }
    }
}

/// u8 阶段判别 → `StatsPhase`（未知判别 → `Unspecified`）。
fn phase_from_u8(value: u8) -> StatsPhase {
    match value {
        1 => StatsPhase::Idle,
        2 => StatsPhase::Connecting,
        3 => StatsPhase::Connected,
        4 => StatsPhase::Stopping,
        5 => StatsPhase::Failed,
        _ => StatsPhase::Unspecified,
    }
}

/// 字节速率（bytes/sec）：`delta_bytes` 在 `elapsed_ms` 内的速率，饱和不溢出。
#[must_use]
fn rate_bytes_per_sec(delta_bytes: u64, elapsed_ms: u64) -> u64 {
    if elapsed_ms == 0 {
        return 0;
    }
    u64::try_from(u128::from(delta_bytes) * 1000 / u128::from(elapsed_ms)).unwrap_or(u64::MAX)
}

/// 当前 wall-clock epoch 毫秒（UTC；proto 约定 0 = unknown，本实现恒填真实值）。
fn wall_clock_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// `StreamStats` 推送端内部可变态。
#[derive(Debug)]
struct StatsPublisherInner {
    /// 当前挂接的 `StreamStats` 推送通道（`last-writer-wins`：core 是唯一消费方）。
    push: Option<mpsc::Sender<Result<generated::StatsEvent, Status>>>,
}

/// engine 统计推送端点：持有注册表 + 采样推送通道（对齐 `LogSink` 的 `last-writer-wins`）。
#[derive(Debug)]
pub struct StatsPublisher {
    /// 数据面写入/服务读取共享的统计注册表。
    registry: Arc<StatsRegistry>,
    /// 全局单调样本序列（per engine boot；`StatsEvent.sequence` 的序列基础）。
    next_sequence: Arc<AtomicU64>,
    /// 推送通道插槽。
    inner: Mutex<StatsPublisherInner>,
}

impl StatsPublisher {
    /// 建一个空推送端点（未挂接流；注册表可供数据面立即写入）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: Arc::new(StatsRegistry::new()),
            next_sequence: Arc::new(AtomicU64::new(0)),
            inner: Mutex::new(StatsPublisherInner { push: None }),
        }
    }

    /// 共享的统计注册表（数据面通过它写入计数器）。
    #[must_use]
    pub fn registry(&self) -> &Arc<StatsRegistry> {
        &self.registry
    }

    /// 挂接一条 `StreamStats` 推送流，返回接收端（由 gRPC server 转成 `ReceiverStream`）。
    ///
    /// `sample_interval_ms == 0` 使用 engine 默认间隔（1000 ms）。注册为当前唯一
    /// 推送通道（替换任何残留旧通道），并 spawn 采样 task：按间隔读注册表快照、
    /// 计算速率、推 `StatsEvent`。无挂接流时无采样 task（无空转）。
    ///
    /// # Panics
    /// 内部互斥锁中毒（另一线程持锁时 panic）→ panic。
    #[must_use]
    pub fn open_stream(
        &self,
        sample_interval_ms: u32,
    ) -> mpsc::Receiver<Result<generated::StatsEvent, Status>> {
        let interval_ms = if sample_interval_ms == 0 {
            DEFAULT_SAMPLE_INTERVAL_MS
        } else {
            sample_interval_ms
        };
        let (tx, rx) = mpsc::channel(STREAM_CAPACITY);
        let sampler = sample_loop(
            self.registry.clone(),
            tx.clone(),
            self.next_sequence.clone(),
            interval_ms,
        );
        {
            let mut inner = self.inner.lock().expect("stats publisher lock");
            inner.push = Some(tx);
        }
        tokio::spawn(sampler);
        rx
    }

    /// 是否挂接着推送通道（测试/观测）。
    ///
    /// # Panics
    /// 内部互斥锁中毒（另一线程持锁时 panic）→ panic。
    #[must_use]
    pub fn is_push_attached(&self) -> bool {
        self.inner.lock().expect("stats publisher lock").push.is_some()
    }
}

impl Default for StatsPublisher {
    fn default() -> Self {
        Self::new()
    }
}

/// 采样循环：按 interval 读注册表快照 → 计算速率 → 推 wire `StatsEvent`。
///
/// 发送失败（接收端 drop = 客户端断线）即退出；无外部取消信号——断线是唯一终止源。
async fn sample_loop(
    registry: Arc<StatsRegistry>,
    tx: mpsc::Sender<Result<generated::StatsEvent, Status>>,
    next_sequence: Arc<AtomicU64>,
    interval_ms: u32,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(u64::from(interval_ms)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_rx = 0u64;
    let mut last_tx = 0u64;
    let mut last_time: Option<Instant> = None;
    loop {
        interval.tick().await;
        let sample = registry.snapshot();
        let now = Instant::now();
        let (rx_rate, tx_rate) = match last_time {
            Some(prev) => {
                let elapsed_ms = u64::try_from(now.duration_since(prev).as_millis()).unwrap_or(0);
                let delta_rx = sample.rx_bytes.saturating_sub(last_rx);
                let delta_tx = sample.tx_bytes.saturating_sub(last_tx);
                (
                    rate_bytes_per_sec(delta_rx, elapsed_ms),
                    rate_bytes_per_sec(delta_tx, elapsed_ms),
                )
            }
            None => (0, 0),
        };
        last_rx = sample.rx_bytes;
        last_tx = sample.tx_bytes;
        last_time = Some(now);

        let sequence = next_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let event = generated::StatsEvent {
            sequence,
            timestamp_ms: sample.timestamp_ms,
            phase: sample.phase as i32,
            rx_bytes: sample.rx_bytes,
            tx_bytes: sample.tx_bytes,
            rx_rate,
            tx_rate,
            latency_ms: sample.latency_ms,
        };
        if tx.send(Ok(event)).await.is_err() {
            // 客户端断线：采样 task 自行退出；重连由 open_stream 重新挂接。
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// 单元测试：累计正确性（含饱和）、阶段/延迟反映、速率计算、事件形状。
// 集成契约测试（StreamStats RPC over named pipe）在 tests/stats.rs。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 累计正确性：`record_rx`/`record_tx` 聚合为快照的累计值。
    #[test]
    fn cumulative_counters_accumulate() {
        let registry = StatsRegistry::new();
        registry.record_rx(100);
        registry.record_rx(250);
        registry.record_tx(40);
        let sample = registry.snapshot();
        assert_eq!(sample.rx_bytes, 350);
        assert_eq!(sample.tx_bytes, 40);
    }

    /// 饱和：在 `u64::MAX` 处继续累加不回绕（累计计数器 bug 的回归门）。
    #[test]
    fn cumulative_counters_saturate_at_max() {
        let registry = StatsRegistry::new();
        registry.record_rx(u64::MAX);
        registry.record_rx(1000);
        assert_eq!(registry.snapshot().rx_bytes, u64::MAX, "saturating add");
    }

    /// 阶段/延迟：`set_phase` 与 `record_latency` 反映到快照；默认阶段为 `Idle`。
    #[test]
    fn phase_and_latency_reflect_in_snapshot() {
        let registry = StatsRegistry::new();
        assert_eq!(registry.snapshot().phase, StatsPhase::Idle);
        registry.set_phase(StatsPhase::Connected);
        registry.record_latency(42);
        let sample = registry.snapshot();
        assert_eq!(sample.phase, StatsPhase::Connected);
        assert_eq!(sample.latency_ms, 42);
        registry.record_latency(0);
        assert_eq!(registry.snapshot().latency_ms, 0, "0 = unknown");
    }

    /// 速率：纯函数按 delta/elapsed 计算 bytes/sec，elapsed 0 与 delta 0 均安全。
    #[test]
    fn rate_bytes_per_sec_computes_deltas() {
        assert_eq!(rate_bytes_per_sec(1000, 1000), 1000);
        assert_eq!(rate_bytes_per_sec(2000, 500), 4000);
        assert_eq!(rate_bytes_per_sec(0, 1000), 0);
        assert_eq!(rate_bytes_per_sec(1000, 0), 0, "zero elapsed is safe");
        assert_eq!(rate_bytes_per_sec(u64::MAX, 1), u64::MAX, "saturating rate");
    }

    /// 阶段判别往返：u8 判别 → `StatsPhase` → 事件 `i32`。
    #[test]
    fn phase_discriminant_round_trips() {
        for phase in [
            StatsPhase::Idle,
            StatsPhase::Connecting,
            StatsPhase::Connected,
            StatsPhase::Stopping,
            StatsPhase::Failed,
        ] {
            let as_u8 = phase as u8;
            assert_eq!(phase_from_u8(as_u8), phase, "{phase:?} round-trips");
        }
        assert_eq!(phase_from_u8(99), StatsPhase::Unspecified, "unknown -> unspecified");
    }

    /// 采样事件形状：注册表写入 → `open_stream` 后首个事件携带累计计数与阶段，
    /// 且首个样本速率 = 0（尚无前一样本）；后续样本速率 > 0。
    #[tokio::test]
    async fn sample_loop_pushes_events_with_accumulated_shape() {
        let registry = Arc::new(StatsRegistry::new());
        registry.record_rx(1000);
        registry.record_tx(500);
        registry.set_phase(StatsPhase::Connected);
        registry.record_latency(7);

        let publisher = StatsPublisher {
            registry: registry.clone(),
            next_sequence: Arc::new(AtomicU64::new(0)),
            inner: Mutex::new(StatsPublisherInner { push: None }),
        };
        let mut rx = publisher.open_stream(10); // 10 ms 采样
        assert!(publisher.is_push_attached(), "push attached after open_stream");

        // 首个事件：累计计数 + 阶段 + 延迟；速率为 0。
        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("first sample within timeout")
            .expect("stream alive")
            .expect("event ok");
        assert_eq!(first.sequence, 1);
        assert_eq!(first.rx_bytes, 1000);
        assert_eq!(first.tx_bytes, 500);
        assert_eq!(first.latency_ms, 7);
        assert_eq!(first.phase, StatsPhase::Connected as i32);
        assert_eq!(first.rx_rate, 0, "first sample has no prior rate");
        assert_eq!(first.tx_rate, 0);

        // 继续累加 → 下一个样本反映累计增长，且速率 > 0。
        registry.record_rx(9000);
        registry.record_tx(4000);
        let second = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("second sample within timeout")
            .expect("stream alive")
            .expect("event ok");
        assert_eq!(second.sequence, 2);
        assert_eq!(second.rx_bytes, 10_000);
        assert_eq!(second.tx_bytes, 4_500);
        assert!(second.rx_rate > 0, "rate computed from delta: {}", second.rx_rate);
        assert!(second.tx_rate > 0, "rate computed from delta: {}", second.tx_rate);

        // 断线（drop 接收端）→ 采样 task 自行退出（channel closed）。
        drop(rx);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
}
