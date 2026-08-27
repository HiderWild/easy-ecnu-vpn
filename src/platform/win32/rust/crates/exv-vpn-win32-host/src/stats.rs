// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core 侧统计归一化（P5-b：消费 engine `StreamStats`，做权威速度归一化）。
//!
//! P5-a 契约：engine 经 `HelperControl.StreamStats` 推送 `StatsEvent`，其中
//! `rx_bytes`/`tx_bytes` 为**累计权威字节数**；`rx_rate`/`tx_rate` 是 engine 侧采样
//! 速率 convenience。按 P5-2 计划，core 不信任 engine 采样速率，改为以累计字节的
//! **增量采样**自行归一化速度（`delta_bytes / elapsed_seconds`）——累计计数为唯一
//! 权威，任何 engine 侧采样口径差异都在 core 归一化层抹平。
//!
//! [`TrafficSample`] 维护跨样本的增量状态（上次累计计数 + 时间戳）；[`normalize_stats`]
//! 把一条 `StatsEvent` 归一化为 host 侧 [`RuntimeStats`]（归一化速率 + 累计流量 +
//! phase + latency 透传），并维护采样状态。速率计算镜像 engine 侧
//! `rate_bytes_per_sec`（`delta * 1000 / elapsed_ms`，饱和不溢出）——同口径、core
//! 为权威。
//!
//! `RuntimeStats.sample_tick` 由 [`crate::kernel_control_service::EventBus::publish_stats`]
//! 铸造（与 wire 事件同一 monotonic tick 对齐），供 P5-c 在 UI wire（proto 冻结）扩展
//! 统计字段时与状态事件关联。

use exv_vpn_wire::generated::{StatsEvent, StatsPhase};

/// 字节速率（bytes/sec）：`delta_bytes` 在 `elapsed_ms` 内的速率，饱和不溢出。
///
/// 镜像 engine `stats.rs::rate_bytes_per_sec` 同口径；`elapsed_ms == 0` 安全返回 0。
#[must_use]
fn rate_bytes_per_sec(delta_bytes: u64, elapsed_ms: u64) -> u64 {
    if elapsed_ms == 0 {
        return 0;
    }
    u64::try_from(u128::from(delta_bytes) * 1000 / u128::from(elapsed_ms)).unwrap_or(u64::MAX)
}

/// wire `StatsEvent.phase`（i32）→ `StatsPhase`（未知判别 → `Unspecified`）。
///
/// 生成的 wire 未提供 `TryFrom<i32>`（prost 0.14 本生成配置未产出），故手动判别；
/// 与 engine 侧 `phase_from_u8` 同构。
#[must_use]
fn stats_phase_from_i32(value: i32) -> StatsPhase {
    match value {
        1 => StatsPhase::Idle,
        2 => StatsPhase::Connecting,
        3 => StatsPhase::Connected,
        4 => StatsPhase::Stopping,
        5 => StatsPhase::Failed,
        _ => StatsPhase::Unspecified,
    }
}

/// core 侧跨样本的流量增量采样状态（P5-2：以累计字节增量做权威速度归一化）。
///
/// 每次 `feed` 一条 `StatsEvent`：以本次累计计数与上次的**差值**除以两次样本的
/// 时间戳间隔得到归一化速率（bytes/sec）；首条样本无上次参照 → 速率 0 并初始化状态。
/// 时间戳未知（0）/回退（engine 时钟调整）→ elapsed 0 → 速率 0（安全不误报）。
/// 累计计数回退（engine 重启/重置）→ `saturating_sub` 差值 0 → 速率 0（不虚构负流量）。
#[derive(Debug, Clone, Copy, Default)]
pub struct TrafficSample {
    /// 上次样本的累计接收字节。
    last_rx_bytes: u64,
    /// 上次样本的累计发送字节。
    last_tx_bytes: u64,
    /// 上次样本的 wall-clock epoch 毫秒（0 = 未知）。
    last_timestamp_ms: i64,
    /// 是否已有上次样本（首条样本无参照）。
    has_prior: bool,
}

impl TrafficSample {
    /// 建一个空采样状态（首条 `feed` 初始化）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 归一化本条样本：返回 `(rx_bps, tx_bps)`（累计增量 / 时间间隔），并推进状态。
    ///
    /// 首条样本 → `(0, 0)`（无上次参照）；此后以累计字节差值与时间戳间隔计算权威速率。
    #[must_use]
    pub fn feed(&mut self, ev: &StatsEvent) -> (u64, u64) {
        if !self.has_prior {
            self.last_rx_bytes = ev.rx_bytes;
            self.last_tx_bytes = ev.tx_bytes;
            self.last_timestamp_ms = ev.timestamp_ms;
            self.has_prior = true;
            return (0, 0);
        }
        let delta_rx = ev.rx_bytes.saturating_sub(self.last_rx_bytes);
        let delta_tx = ev.tx_bytes.saturating_sub(self.last_tx_bytes);
        let elapsed_ms = if ev.timestamp_ms > 0 && self.last_timestamp_ms > 0 {
            // 时钟回退 → try_from 失败 → 0（安全不误报）。
            u64::try_from(ev.timestamp_ms - self.last_timestamp_ms).unwrap_or(0)
        } else {
            0
        };
        self.last_rx_bytes = ev.rx_bytes;
        self.last_tx_bytes = ev.tx_bytes;
        self.last_timestamp_ms = ev.timestamp_ms;
        (
            rate_bytes_per_sec(delta_rx, elapsed_ms),
            rate_bytes_per_sec(delta_tx, elapsed_ms),
        )
    }
}

/// host 侧归一化后的运行期统计（P5-b；wire proto 冻结，UI 侧 P5-c 消费）。
///
/// `rx_bytes`/`tx_bytes` 为 engine 累计权威字节（透传）；`rx_rate_bps`/`tx_rate_bps`
/// 为 core 归一化速度（累计增量 / 时间间隔，engine 的 `rx_rate`/`tx_rate` convenience
/// 不使用）；`latency_ms`/`phase` 透传；`engine_sequence` 为 engine 样本序号（关联用）；
/// `sample_tick` 由 `EventBus::publish_stats` 铸造（与 wire 事件同一 monotonic tick 对齐）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeStats {
    /// 累计接收字节（engine 权威）。
    pub rx_bytes: u64,
    /// 累计发送字节（engine 权威）。
    pub tx_bytes: u64,
    /// 归一化接收速率（bytes/sec；累计增量 / 时间间隔）。
    pub rx_rate_bps: u64,
    /// 归一化发送速率（bytes/sec；累计增量 / 时间间隔）。
    pub tx_rate_bps: u64,
    /// 往返延迟（ms；0 = 未知/不可得）。
    pub latency_ms: u64,
    /// engine 采样时刻的连接阶段。
    pub phase: StatsPhase,
    /// engine 样本序号（per engine boot）。
    pub engine_sequence: u64,
    /// 发布时的事件总线 tick（`publish_stats` 铸造；0 = 尚未发布）。
    pub sample_tick: u64,
}

/// 把一条 engine `StatsEvent` 归一化为 host 侧 [`RuntimeStats`]（P5-2 权威速度）。
///
/// 速率由 `sample`（[`TrafficSample`]）的累计增量归一化；累计字节/latency/phase/
/// sequence 透传。`sample_tick` 初始 0，由 `EventBus::publish_stats` 铸造后覆盖。
#[must_use]
pub fn normalize_stats(ev: &StatsEvent, sample: &mut TrafficSample) -> RuntimeStats {
    let (rx_rate_bps, tx_rate_bps) = sample.feed(ev);
    RuntimeStats {
        rx_bytes: ev.rx_bytes,
        tx_bytes: ev.tx_bytes,
        rx_rate_bps,
        tx_rate_bps,
        latency_ms: ev.latency_ms,
        phase: stats_phase_from_i32(ev.phase),
        engine_sequence: ev.sequence,
        sample_tick: 0,
    }
}

// ---------------------------------------------------------------------------
// 单元测试：增量/速度归一化正确性（权威口径）、边界（首条/时钟未知/时钟回退/
// 计数回退/饱和）、字段透传。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一条 `StatsEvent`（测试便捷；累计字节/time/phase/latency 可注入）。
    fn event(
        sequence: u64,
        timestamp_ms: i64,
        rx_bytes: u64,
        tx_bytes: u64,
        phase: StatsPhase,
        latency_ms: u64,
    ) -> StatsEvent {
        StatsEvent {
            sequence,
            timestamp_ms,
            phase: phase as i32,
            rx_bytes,
            tx_bytes,
            rx_rate: 0,
            tx_rate: 0,
            latency_ms,
        }
    }

    /// 首条样本：无上次参照 → 速率 (0, 0)，状态初始化。
    #[test]
    fn first_sample_has_zero_rates_and_initializes_state() {
        let mut sample = TrafficSample::new();
        let ev = event(1, 1000, 1000, 500, StatsPhase::Connected, 7);
        assert_eq!(sample.feed(&ev), (0, 0), "首条样本无参照");
        // 状态已初始化：下一条以本样本为参照。
        let ev2 = event(2, 2000, 2000, 1000, StatsPhase::Connected, 7);
        assert_eq!(sample.feed(&ev2), (1000, 500), "delta/elapsed 归一化");
    }

    /// 权威速度归一化：累计增量 / 时间间隔（engine `rx_rate` convenience 不使用）。
    #[test]
    fn second_sample_normalizes_rate_from_cumulative_delta() {
        let mut sample = TrafficSample::new();
        // 样本 1：累计 rx=1000，t=1000ms。
        sample.feed(&event(1, 1000, 1000, 0, StatsPhase::Connected, 0));
        // 样本 2：累计 rx=3000（增量 2000），t=2000ms（间隔 1000ms）→ 2000 B/s。
        // engine convenience 报 999 也必须被 core 归一化覆盖（权威口径）。
        let mut ev = event(2, 2000, 3000, 0, StatsPhase::Connected, 0);
        ev.rx_rate = 999; // 故意喂一个"错误"的 engine 采样速率
        let (rx_bps, tx_bps) = sample.feed(&ev);
        assert_eq!(rx_bps, 2000, "core 以累计增量归一化，不信 engine 采样速率");
        assert_eq!(tx_bps, 0);
    }

    /// 时间戳间隔换算：delta 2000 字节在 500ms → 4000 B/s。
    #[test]
    fn rate_scales_with_elapsed_interval() {
        let mut sample = TrafficSample::new();
        sample.feed(&event(1, 1000, 0, 0, StatsPhase::Connected, 0));
        let (rx_bps, tx_bps) = sample.feed(&event(2, 1500, 2000, 1000, StatsPhase::Connected, 0));
        assert_eq!(rx_bps, 4000, "2000 bytes / 0.5s = 4000 B/s");
        assert_eq!(tx_bps, 2000, "1000 bytes / 0.5s = 2000 B/s");
    }

    /// 时间戳未知（0）：无可靠间隔 → 速率 0（不误报）；两侧锚点都已知后速率恢复。
    #[test]
    fn unknown_timestamp_yields_zero_rate_and_recovers_once_anchored() {
        let mut sample = TrafficSample::new();
        // 样本 1：时间戳未知（0）→ 初始化，速率 0。
        assert_eq!(
            sample.feed(&event(1, 0, 1000, 0, StatsPhase::Connected, 0)),
            (0, 0)
        );
        // 样本 2：时间戳已知，但上次锚点未知 → elapsed 0 → 速率 0（不误报）。
        assert_eq!(
            sample.feed(&event(2, 1000, 3000, 0, StatsPhase::Connected, 0)),
            (0, 0)
        );
        // 样本 3：两侧锚点都已知（1000 → 2000ms，delta 2000）→ 速率恢复。
        assert_eq!(
            sample.feed(&event(3, 2000, 5000, 0, StatsPhase::Connected, 0)),
            (2000, 0),
            "两侧锚点已知后速率恢复"
        );
    }

    /// 时间戳回退（engine 时钟调整）：`try_from` 失败 → elapsed 0 → 速率 0（安全）。
    #[test]
    fn timestamp_regression_yields_zero_rate() {
        let mut sample = TrafficSample::new();
        sample.feed(&event(1, 5000, 1000, 0, StatsPhase::Connected, 0));
        // 下一样本时间戳回退到 3000（负间隔）。
        assert_eq!(
            sample.feed(&event(2, 3000, 3000, 0, StatsPhase::Connected, 0)),
            (0, 0),
            "时钟回退不误报速率"
        );
        // 状态已推进到样本 2：再下一条以样本 2 为参照（delta 2000 / 2000ms = 1000）。
        assert_eq!(
            sample.feed(&event(3, 5000, 5000, 0, StatsPhase::Connected, 0)),
            (1000, 0),
            "回退后状态仍正确推进"
        );
    }

    /// 累计计数回退（engine 重启/重置）：`saturating_sub` 差值 0 → 速率 0（不虚构负流量）。
    #[test]
    fn counter_regression_yields_zero_rate() {
        let mut sample = TrafficSample::new();
        sample.feed(&event(1, 1000, 1_000_000, 500_000, StatsPhase::Connected, 0));
        // 下一样本计数回退到较小值（engine 重启，计数器清零重来）。
        let (rx_bps, tx_bps) = sample.feed(&event(2, 2000, 10_000, 5_000, StatsPhase::Connected, 0));
        assert_eq!(rx_bps, 0, "计数回退差值 0");
        assert_eq!(tx_bps, 0);
    }

    /// 饱和：速率计算在大 delta / 小 elapsed 下不溢出。
    #[test]
    fn rate_saturates_without_overflow() {
        assert_eq!(rate_bytes_per_sec(u64::MAX, 1), u64::MAX, "饱和不溢出");
        assert_eq!(rate_bytes_per_sec(1000, 0), 0, "zero elapsed 安全");
    }

    /// `normalize_stats` 字段透传：累计字节/latency/phase/sequence 正确；
    /// 速率来自增量归一化；`sample_tick` 初始 0（由 `publish_stats` 铸造）。
    #[test]
    fn normalize_stats_passes_through_fields_and_normalizes_rate() {
        let mut sample = TrafficSample::new();
        let first = normalize_stats(
            &event(7, 1000, 1234, 5678, StatsPhase::Connected, 42),
            &mut sample,
        );
        assert_eq!(first.rx_bytes, 1234);
        assert_eq!(first.tx_bytes, 5678);
        assert_eq!(first.latency_ms, 42);
        assert_eq!(first.phase, StatsPhase::Connected);
        assert_eq!(first.engine_sequence, 7);
        assert_eq!(first.rx_rate_bps, 0, "首条样本速率 0");
        assert_eq!(first.sample_tick, 0, "由 publish_stats 铸造");

        let second = normalize_stats(
            &event(8, 2000, 3234, 6678, StatsPhase::Connected, 43),
            &mut sample,
        );
        assert_eq!(second.rx_rate_bps, 2000, "delta 2000 / 1000ms");
        assert_eq!(second.tx_rate_bps, 1000, "delta 1000 / 1000ms");
        assert_eq!(second.latency_ms, 43);
        assert_eq!(second.engine_sequence, 8);
        assert_eq!(second.phase, StatsPhase::Connected);
    }

    /// `stats_phase_from_i32`：已知判别往返，未知 → `Unspecified`。
    #[test]
    fn phase_from_i32_round_trips_and_falls_back() {
        for phase in [
            StatsPhase::Idle,
            StatsPhase::Connecting,
            StatsPhase::Connected,
            StatsPhase::Stopping,
            StatsPhase::Failed,
        ] {
            assert_eq!(stats_phase_from_i32(phase as i32), phase, "{phase:?}");
        }
        assert_eq!(stats_phase_from_i32(0), StatsPhase::Unspecified);
        assert_eq!(stats_phase_from_i32(99), StatsPhase::Unspecified);
    }
}
