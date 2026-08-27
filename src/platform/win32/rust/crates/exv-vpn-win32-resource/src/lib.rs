// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Win32 资源平台 crate（构建接缝，空模块占位）。
//!
//! 本 crate 当前仅为 `vpn-rust-native-runtime-mvp` acceptance 提供空构建接缝，
//! 不含任何产品行为。实际实现由各叶 worker 在对应模块中填充。

pub mod aggregate;
pub mod adapter_address;
pub mod apply_tunnel;
pub mod authority;
pub mod bypass_route;
pub mod cleanup_proof;
pub mod dns;
pub mod dns_types;
pub mod inventory;
pub mod ip_address;
pub mod ip_helper_types;
pub mod journal_path;
pub mod journal_projection;
pub mod journal_store;
pub mod mtu;
pub mod native_error;
pub mod native_observation;
pub mod packet_attachment;
pub mod packet_buffer;
pub mod packet_capability;
pub mod packet_worker;
pub mod plan_wiring;
pub mod proxy_tun;
pub mod recovery;
pub mod routes;
pub mod storage_security;
pub mod system_proxy;
pub mod system_proxy_family;
pub mod system_proxy_family_exec;
pub mod system_proxy_override;
pub mod system_proxy_pac;
pub mod teardown;
pub mod timing;
pub mod vgdc_dns;
pub mod wintun_adapter;
pub mod wintun_api;
pub mod wintun_session;

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
