//! 运行期统计镜像（P5-c：UI 展示 rx/tx 速度、累计流量、延迟与阶段）。
//!
//! 数据契约源：host `exv-core/src/stats.rs::RuntimeStats`（P5-b core 侧
//! 归一化后的权威统计：累计字节增量 / 时间间隔的速度归一化 + 累计流量透传）。
//! 本模块是它的 UI 侧 serde 镜像——字段名与 host 一致，snake_case，供 Command 返回
//! 与 Event payload 复用。
//!
//! **stats-wire 方案 A（已落地）**：`common.proto` `RuntimeSnapshot` 增非 oneof 字段
//! `RuntimeStats stats = 9`，`GetSnapshot` 与 `WatchEvents` 一并携带 host `EventBus`
//! 统计 lane（`publish_stats`/`subscribe_stats`/`current_stats`，host
//! `kernel_control_service.rs`）的最新样本——UI 复用现有 snapshot 命令与 `exv://status`
//! 事件，无新 RPC。
//!
//! 展示管道（已接好）：
//!   * 连接状态：来自 `WatchEvents` RuntimeSnapshot（P4-b 已真实接线）；
//!   * 统计数值：`snapshot` 命令/`WatchEvents` 事件随 `RuntimeSnapshot.stats` 携带；
//!     `stats` 命令从 snapshot 写入的缓存读取（unary 拉当前）；前端从 `exv://status`
//!     的 `ev.snapshot.stats` 直接渲染，`exv://stats` 事件 seam 保留。

use serde::{Deserialize, Serialize};

/// 统计采样时刻的粗粒度连接阶段（proto `helper_control.proto: StatsPhase`，
/// host `stats_phase_from_i32` 同源）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatsPhase {
    Unspecified,
    Idle,
    Connecting,
    Connected,
    Stopping,
    Failed,
}

/// 运行期统计的 UI 视图（mirror host `crate::stats::RuntimeStats`，P5-b 归一化后）。
///
/// `rx_bytes`/`tx_bytes` 为累计权威字节（透传）；`rx_rate_bps`/`tx_rate_bps` 为
/// core 归一化速度（累计增量 / 时间间隔，UI 不做任何再归一化——core 是唯一语义
/// 网关）；`latency_ms` 往返延迟（0 = 未知）；`phase` 粗粒度阶段；`engine_sequence`
/// 为 engine 样本序号；`sample_tick` 与 wire 事件同一 monotonic tick 轴（P5-b
/// `EventBus::publish_stats` 铸造）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// 采样时刻的连接阶段。
    pub phase: StatsPhase,
    /// engine 样本序号（per engine boot）。
    pub engine_sequence: u64,
    /// 发布时的事件总线 tick（与 wire 事件同一 tick 轴；0 = 尚未发布）。
    pub sample_tick: u64,
}

impl StatsPhase {
    /// 前端展示名（中文；前端默认语言为中文）。
    #[allow(dead_code)]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Unspecified => "未知",
            Self::Idle => "空闲",
            Self::Connecting => "连接中",
            Self::Connected => "已连接",
            Self::Stopping => "停止中",
            Self::Failed => "失败",
        }
    }
}

// ---------------------------------------------------------------------------
// stats-wire 方案 A（已落地）记录：`RuntimeSnapshot.stats` 携带统计。
//
// 落地方式（协调者拍板方案 A，2026-08-17）：
//   * `common.proto`：`RuntimeSnapshot` 增非 oneof 字段 `RuntimeStats stats = 9`；
//     `StatsPhase` 从 helper_control.proto 迁至 common.proto（同 package，生成符号
//     不变），供 `RuntimeStats.phase` 使用，避免循环 import。
//   * host：`GetSnapshot` 与 `EventBus::publish`（WatchEvents 事件）从统计 lane
//     `current_stats` 附加最新样本。
//   * tauri：`snapshot_from_wire` 映射 `stats`；`snapshot` 命令更新 `last_stats`
//     缓存；`stats` 命令从缓存读取；前端从 `exv://status` 的 `snapshot.stats` 渲染。
//
// 未采用的 B 案（独立 `rpc GetStats`）与 `exv://stats` 独立推送保留为 seam：统计是
// 状态事件的伴生数据，随快照下发 wire 面最小；若后续需独立高频推送再评估 B。
// ---------------------------------------------------------------------------
