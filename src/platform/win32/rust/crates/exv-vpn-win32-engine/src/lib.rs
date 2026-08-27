// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Win32 特权 helper 平台 crate（构建接缝，空模块占位）。
//!
//! 本 crate 当前仅为 `vpn-rust-native-runtime-mvp` acceptance 提供空构建接缝，
//! 不含任何产品行为。实际实现由各叶 worker 在对应模块中填充。

pub mod composition;
pub mod data_plane;
pub mod grpc_server;
pub mod grpc_transport;
pub mod heartbeat;
pub mod log_sink;
pub mod mutation_ingress;
pub mod owner_lease;
pub mod packet_relay;
pub mod platform_tunnel;
pub mod secret_payload;
pub mod service;
pub mod service_batch;
pub mod shutdown;
pub mod stats;
pub mod status;
pub mod token_slot;
pub mod tunnel_runtime;
pub mod vgdc_connect;

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。