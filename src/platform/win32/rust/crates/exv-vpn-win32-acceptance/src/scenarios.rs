// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! 真实纵切 scenario 模块注册（计划 §9：controlled / crash_matrix / school）。
//! 每个 scenario 是 host 侧 seam（`run_<name>_vertical`），由 Terra oracle 测试
//! 与 scenario 二进制共同调用；helper 角色经同一模块的 helper 函数 + 专用 bin 运行。

pub mod controlled;
pub mod crash_matrix;
pub mod stop_pressure;
pub mod school;

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
