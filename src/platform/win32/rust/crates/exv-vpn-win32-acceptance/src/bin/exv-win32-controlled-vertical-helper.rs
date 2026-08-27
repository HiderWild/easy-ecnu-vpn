// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W28-A helper 进程二进制：被 host（普通权限）经 ShellExecuteExW(runas) 提权拉起，
//! 运行 `scenarios::controlled::run_helper_role`（W26 组合 + W16/W22 create-then-idle
//! apply + W24/W14 teardown）。DP-01：helper 只做特权初始化（adapter 创建 + 四族网络
//! 设置），不建 Wintun session、不起 ring worker——数据面由引擎/host 接管（DP-02/03/04）。
//! 进程退出码：0 = 干净 Stop，2 = helper 侧失败。

fn main() {
    let code = match exv_vpn_win32_acceptance::scenarios::controlled::parse_helper_args() {
        Ok(args) => exv_vpn_win32_acceptance::scenarios::controlled::run_helper_role(&args),
        Err(e) => {
            eprintln!("[helper] bad args: {e}");
            1
        }
    };
    std::process::exit(code);
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
