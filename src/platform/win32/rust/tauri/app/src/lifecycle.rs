//! 生命周期（O3 强绑定，P4-b 真实接线；2026-08-23 托盘迁自管 + close_preference 驱动关闭）。
//!
//!   * 关闭按钮行为由 ui_prefs 的 `close_preference` 驱动（[`close_decision`] 纯函数）：
//!     `quit` → O3 停机；`tray` → 隐藏到托盘；`smart` → 先隐藏，宽限期内未再唤出则自动退出
//!     （对齐 C++ 壳 `begin_smart_close_resolution` 的误关保护意图）。
//!   * 彻底退出 → [`notify_core_shutdown`] → O3：core 经管道关闭感知 UI 退出 → 有序停机。
//!   * 启动可见性：`--silent` 参数（单次）∨ prefs `silent_startup` → 不弹窗仅托盘；
//!     否则显示主窗口（[`resolve_startup_visibility`] 纯函数）。
//!
//! ## O3 停机机制（P4-b 确认）
//!
//! core `KernelControl` 无 shutdown RPC——「通知 core 退出」即**断开控制面管道**
//! （host `kernel_control_transport` 注释：serve 任务句柄在 UI 连接断开时 resolve →
//! `CoreRuntime` 感知停机 → `shutdown_core` 有序停机）。UI 侧不 kill core：core 由
//! pipe-close 感知自行退出（[`super::kernel::core_process::CoreChild`] 有意不做 Drop
//! 自动 terminate——kill 会打断有序停机）。

use tauri::{App, AppHandle, Manager};

use crate::kernel::client::CoreSession;
use crate::ui_prefs::{UiPrefsStore, CLOSE_PREFERENCE_VALUES, DEFAULT_CLOSE_PREFERENCE};

/// smart 关闭的宽限窗口（毫秒）：隐藏后在此时间内未再显示主窗则自动退出。
pub const SMART_CLOSE_GRACE_MS: u64 = 15_000;

// ---- 纯函数决策（单测覆盖）----

/// 关闭请求的处置动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseDecision {
    /// 直接退出（quit pref / smart 宽限超时）。
    Quit,
    /// 仅隐藏（tray pref / smart 宽限期内再次关闭）。
    Hide,
    /// 隐藏并启动宽限计时（smart pref 首次关闭）。
    SmartHide,
}

/// 由 close_preference 字符串决定关闭处置。未知值视为默认 `smart`（与存储层回落一致）。
///
/// `grace_active`：smart 宽限计时已在进行（隐藏期间用户未唤出又触发关闭）→ 直接退出。
#[must_use]
pub fn close_decision(preference: &str, grace_active: bool) -> CloseDecision {
    let pref = if CLOSE_PREFERENCE_VALUES.contains(&preference) {
        preference
    } else {
        DEFAULT_CLOSE_PREFERENCE
    };
    match pref {
        "quit" => CloseDecision::Quit,
        "tray" => CloseDecision::Hide,
        // smart：宽限期内再次关闭 = 用户确认退出；否则先隐藏观察。
        _ if grace_active => CloseDecision::Quit,
        _ => CloseDecision::SmartHide,
    }
}

/// 启动时是否静默（不弹窗）。`silent_arg` 来自命令行 `--silent`（单次语义）；
/// `silent_pref` 来自 ui_prefs 的持久偏好。任一为真即静默。
#[must_use]
pub fn should_start_silent(silent_arg: bool, silent_pref: bool) -> bool {
    silent_arg || silent_pref
}

// ---- 纯函数测试 ----

#[cfg(test)]
mod tests {
    use super::{close_decision, should_start_silent, CloseDecision};

    #[test]
    fn close_decision_maps_all_preference_values() {
        assert_eq!(close_decision("quit", false), CloseDecision::Quit);
        assert_eq!(close_decision("tray", false), CloseDecision::Hide);
        assert_eq!(close_decision("smart", false), CloseDecision::SmartHide);
        // 未知值回落 smart。
        assert_eq!(close_decision("minimize", false), CloseDecision::SmartHide);
    }

    #[test]
    fn close_decision_smart_grace_active_quits() {
        // smart 宽限期内再次关闭 = 确认退出；其他 pref 不受宽限影响。
        assert_eq!(close_decision("smart", true), CloseDecision::Quit);
        assert_eq!(close_decision("quit", true), CloseDecision::Quit);
        assert_eq!(close_decision("tray", true), CloseDecision::Hide);
    }

    #[test]
    fn startup_visibility_or_semantics() {
        assert!(should_start_silent(true, false));
        assert!(should_start_silent(false, true));
        assert!(should_start_silent(true, true));
        assert!(!should_start_silent(false, false));
    }
}

// ---- O3 停机 ----

/// 通知 core 进程退出（O3：窗口彻底关闭 → core+engine 一并终止）。
///
/// 1. 卸载托盘图标（避免残留幽灵图标）；
/// 2. 中止事件订阅 task（停止 emit）；
/// 3. `app.exit(0)`——进程 teardown drop `CoreState`（channel）→ 控制面管道关闭 →
///    core `serve_task` resolve → core 有序停机（engine StopTunnel → engine 终止）。
///    订阅 task 已中止，其 channel 克隆随之释放，管道在进程退出前已无引用。
pub fn notify_core_shutdown(app: &AppHandle) {
    tracing::info!(target: "exv.lifecycle", "core shutdown requested (O3: UI exit → core+engine terminate)");

    // 0. 移除托盘图标。
    crate::tray::remove_tray();

    // 1. 中止事件订阅（停止 emit + 释放 channel 克隆，加速管道断开）。
    if let Some(session) = app.try_state::<CoreSession>() {
        let subs = session
            .subscriptions
            .lock()
            .expect("subscriptions lock");
        for handle in subs.iter() {
            handle.abort();
        }
        tracing::info!(target: "exv.lifecycle", count = subs.len(), "event subscriptions aborted");
    }

    // 2. 应用退出。core 由 pipe-close 感知自行有序停机（见模块文档）。
    app.exit(0);
}

// ---- setup ----

/// 注册托盘回调 + 决定启动可见性（托盘本体在 lib.rs 的 Builder 之后经 [`install`] 安装）。
///
/// # Errors
/// 仅 propagate tauri 错误；托盘/可见性失败降级不阻断应用。
pub fn setup(app: &mut App) -> tauri::Result<()> {
    let handle = app.handle().clone();

    // 托盘回调注入：show = 显示主窗口；quit = O3 停机。
    crate::tray::set_show_handler(move || show_main_window(&handle));
    let quit_handle = app.handle().clone();
    crate::tray::set_quit_handler(move || notify_core_shutdown(&quit_handle));

    // 自管托盘安装（best effort：失败降级无托盘，CloseRequested→hide 仍可用）。
    if let Err(error) = crate::tray::install_tray() {
        tracing::warn!(target: "exv.lifecycle", "tray install failed (degraded): {error}");
    }

    Ok(())
}

/// 安装完成后的启动可见性决策（lib.rs 在 bootstrap 后调用一次）。
///
/// `--silent` 单次参数 ∨ prefs `silent_startup` → 保持隐藏（tauri.conf visible:false），
/// 仅托盘驻留；否则显示主窗口。
pub fn apply_startup_visibility(app: &AppHandle) {
    let silent_arg = std::env::args().any(|arg| arg == "--silent");

    let silent_pref = match app.try_state::<UiPrefsStore>() {
        Some(store) => store
            .get()
            .ok()
            .and_then(|prefs| prefs.silent_startup)
            .unwrap_or(false),
        None => false,
    };

    if should_start_silent(silent_arg, silent_pref) {
        tracing::info!(target: "exv.lifecycle",
            silent_arg, silent_pref, "starting hidden to tray (silent)");
        return;
    }
    show_main_window(app);
}

/// 显示并聚焦主窗口（托盘单击 / 菜单「显示 EXV」/ 非静默启动共用）。
fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}
