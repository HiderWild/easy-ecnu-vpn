// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Bypass route capture via `GetBestRoute2` (W20-I).
//!
//! Frozen facts (`docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md`
//! §3): the bypass route must be captured BEFORE the tunnel route exists —
//! `GetBestRoute2(10.99.99.2)` then returns the host's own best route (the default
//! route on the frozen host). Once the tunnel route is in the table, a source-less
//! lookup still returns the bypass (a Wintun interface that is not connected does
//! not participate in source-less lookups) — route selection must never rely on a
//! source-less `GetBestRoute2` picking the tunnel route.

use std::net::Ipv4Addr;

use windows::Win32::NetworkManagement::IpHelper::{GetBestRoute2, MIB_IPFORWARD_ROW2};
use windows::Win32::Networking::WinSock::SOCKADDR_INET;

use crate::native_error::NativeError;
use crate::routes::{from_api_row, to_sockaddr, RouteRow};

/// `ERROR_NOT_FOUND`：`GetBestRoute2` 无路由（facts §3：None = 1168）。
const ERROR_NOT_FOUND: u32 = 1168;

/// 在隧道路由安装**之前**捕获 `control_destination` 的最优路由（宿主自身的最优
/// 路由 = bypass）。无路由时返回 `Ok(None)`（1168 `ERROR_NOT_FOUND`）。
///
/// # Errors
///
/// 查找失败（1168 之外的其他错误码）或最优路由不是 IPv4 路由时返回 [`NativeError`]。
pub fn capture(control_destination: Ipv4Addr) -> Result<Option<RouteRow>, NativeError> {
    let dest = to_sockaddr(control_destination);
    let mut best = MIB_IPFORWARD_ROW2::default();
    let mut best_src = SOCKADDR_INET::default();
    // SAFETY: dest 是合法 SOCKADDR_INET；best/best_src 由系统填充（WSP4 spike 同款
    // 无源限制调用：GetBestRoute2(None, 0, None, ...)）。
    let rc = unsafe {
        GetBestRoute2(None, 0, None, &raw const dest, 0, &raw mut best, &raw mut best_src)
    }
    .0;
    if rc == ERROR_NOT_FOUND {
        return Ok(None);
    }
    if rc != 0 {
        return Err(NativeError::from_win32(rc, "GetBestRoute2 失败"));
    }
    match from_api_row(&best) {
        Some(row) => Ok(Some(row)),
        None => Err(NativeError::from_win32(
            ERROR_NOT_FOUND,
            "GetBestRoute2 返回了非 IPv4 路由",
        )),
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
