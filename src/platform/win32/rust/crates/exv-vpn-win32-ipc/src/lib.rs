// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Win32 IPC 平台 crate（构建接缝，空模块占位）。
//!
//! 本 crate 当前仅为 `vpn-rust-native-runtime-mvp` acceptance 提供空构建接缝，
//! 不含任何产品行为。实际实现由各叶 worker 在对应模块中填充。

pub mod connection_binding;
pub mod engine_protocol;
pub mod grpc_planes;
pub mod limits;
pub mod log_pipe;
pub mod named_pipe_io;
pub mod packet_channel;
pub mod packet_limits;
pub mod peer_auth;
pub mod pipe_security;
pub mod service_key;
pub mod verified_incoming;

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。