// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! 特权 engine 进程二进制（阶段 3a：engine 进程骨架 + 控制面管道协议）。
//!
//! 被 core（普通权限）经 ShellExecuteExW(runas) 提权拉起，运行
//! `exv_vpn_win32_acceptance::engine::run_engine_role`：建控制面 Named Pipe server →
//! 接受 core 连接 → 双向认证 → 命令循环。`Connect` 做特权初始化（建 Wintun adapter +
//! 写路由/网络设置，复用 `helper_apply`），`Disconnect` 清理（复用 `helper_stop`）。
//! 数据面（session + ring→CSTP→TLS→学校）由阶段 3b 在 engine 内实现。
//! 进程退出码：0 = 干净退出，1 = engine 侧致命错误，2 = 身份/初始化失败。

fn main() {
    let code = match exv_vpn_win32_acceptance::engine::parse_engine_args() {
        Ok(args) => exv_vpn_win32_acceptance::engine::run_engine_role(&args),
        Err(e) => {
            eprintln!("[engine] bad args: {e}");
            1
        }
    };
    std::process::exit(code);
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
