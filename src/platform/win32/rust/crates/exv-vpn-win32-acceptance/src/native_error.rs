// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W28 纵切的类型化 native 错误（W28-I）。
//!
//! 复用资源 crate 的 W13 类型化错误（category + raw code + message），本模块只是
//! 平台 crate 的组成接缝：纵切内所有 native 失败都以 [`NativeError`] 返回，绝不
//! 吞成裸错误码或 panic 字符串。

pub use exv_vpn_win32_resource::native_error::{NativeError, NativeErrorKind};

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
