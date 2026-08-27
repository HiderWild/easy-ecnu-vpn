//! kernel — UI<->core 语义层（P4-b 真实接线）。
//!
//! 镜像 core KernelControl / common proto 的 wire 契约
//! （proto/exv/v1/kernel_control.proto, common.proto, helper_control.proto），
//! 作为 Tauri Command 返回值与 Event payload 的类型源。P4-b 已把 Command 与
//! WatchEvents 事件订阅接到 core 的 gRPC KernelControl 端点（复用 Root workspace
//! `exv-vpn-wire` 的生成 client，见 [`super::core_transport`] 与 [`super::wire`]）。
//!
//! 政策（docs/superpowers/plans/2026-08-17-vpn-rust-native-runtime-productization-plan.md）：
//!   * Command ↔ unary；Event ↔ server-streaming（范式同构、栈分离）。
//!   * core 是唯一语义网关，UI 不直连 engine。
//!   * snapshots/events 永不携带口令、cookie、原始证书或自由文本诊断栈。
//!
//! 2026-08-18：`logs_list`/`config_get`/`config_set` 已真实接线（KernelControl
//! 新增 LogsList/LogsClear/ConfigGet/ConfigSet RPC，host 聚合日志与 ExvConfig 直接
//! 服务；proto/common.proto 的 LogEvent 自 helper_control 迁入共享）。stats 经
//! `RuntimeSnapshot.stats` 携带（GetSnapshot + WatchEvents），`stats` 命令从 snapshot
//! 写入的缓存读取（详见 [`super::stats`]）。

pub mod bootstrap;
pub mod client;
pub mod commands;
pub mod core_process;
pub mod core_transport;
pub mod error;
pub mod events;
pub mod latency;
pub mod logs;
pub mod state;
pub mod stats;
pub mod wire;

#[cfg(test)]
mod tests;
