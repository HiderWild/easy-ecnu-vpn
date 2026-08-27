//! EXV VPN Tauri 桌面 UI（P4-b：core 真实接线）。
//!
//! 独立 requirement: vpn-rust-tauri-desktop-ui。
//! 架构：UI 进程（Tauri 前端）↔ core 进程 = Tauri Command/Event；
//!      core ↔ engine = tonic gRPC；core 是唯一语义网关。
//! P4-b：setup 时 spawn core → 拨号 KernelControl 端点 → 管理状态 → 挂事件订阅；
//!      CoreClient 真实 tonic 调用（unary + WatchEvents streaming）；托盘「退出」→
//!      O3 停机（core 经 pipe-close 感知退出，engine 一并终止）。
//! 2026-08-23：前端自有设置（ui_prefs）+ 自管托盘 + close_preference 驱动关闭 +
//! 静默启动（`--silent` 单次 / prefs 常态）。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// kernel 对外暴露：供集成测试/诊断驱动（`tests/drive_service_flow.rs`）在进程级
// spawn 真实 core 并驱动 ServiceControl/Connect/Snapshot/LogsList，无需 GUI。
pub mod kernel;
mod autostart;
mod lifecycle;
mod toast;
mod toast_identity;
mod tray;
mod ui_prefs;
mod window_chrome;

use std::sync::Mutex;
use std::time::Instant;

use tauri::Manager;

use kernel::commands;

/// smart 关闭宽限状态：隐藏时刻（None = 未在宽限期内）。
static SMART_CLOSE_HIDDEN_AT: Mutex<Option<Instant>> = Mutex::new(None);

/// 主窗口被显式显示/聚焦时重置 smart 宽限计时（宽限期内唤出 = 用户还在用）。
pub fn notify_main_window_shown() {
    if let Ok(mut guard) = SMART_CLOSE_HIDDEN_AT.lock() {
        *guard = None;
    }
}

/// 处理主窗口关闭请求：按 `close_preference` 决定 hide / smart-hide / 退出。
fn handle_close_request(window: &tauri::WebviewWindow) {
    use lifecycle::CloseDecision;

    let app = window.app_handle();
    let preference = app
        .try_state::<ui_prefs::UiPrefsStore>()
        .and_then(|store| store.get().ok())
        .and_then(|prefs| prefs.close_preference)
        .unwrap_or_else(|| ui_prefs::DEFAULT_CLOSE_PREFERENCE.to_string());

    let grace_active = SMART_CLOSE_HIDDEN_AT
        .lock()
        .map(|guard| guard.is_some())
        .unwrap_or(false);

    match lifecycle::close_decision(&preference, grace_active) {
        CloseDecision::Quit => {
            lifecycle::notify_core_shutdown(app);
        }
        CloseDecision::Hide => {
            let _ = window.hide();
        }
        CloseDecision::SmartHide => {
            // 隐藏并启动宽限计时；超时后自动退出（误关保护到期）。
            let _ = window.hide();
            if let Ok(mut guard) = SMART_CLOSE_HIDDEN_AT.lock() {
                *guard = Some(Instant::now());
            }
            let app_handle = app.clone();
            let _ = tauri::async_runtime::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(
                    lifecycle::SMART_CLOSE_GRACE_MS,
                ))
                .await;
                let expired = SMART_CLOSE_HIDDEN_AT
                    .lock()
                    .map(|guard| {
                        guard
                            .map(|at| {
                                at.elapsed().as_millis() as u64 >= lifecycle::SMART_CLOSE_GRACE_MS
                            })
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if expired {
                    if let Ok(mut guard) = SMART_CLOSE_HIDDEN_AT.lock() {
                        *guard = None;
                    }
                    tracing::info!(target: "exv.lifecycle",
                        "smart-close grace expired; quitting (O3)");
                    lifecycle::notify_core_shutdown(&app_handle);
                }
            });
        }
    }
}

/// 应用入口（main.rs 调用）。
pub fn run() {
    tauri::Builder::default()
        .manage(window_chrome::WindowChromeState::new())
        .plugin(tauri_plugin_log::Builder::new().build())
        .setup(|app| {
            // 前端自有设置存储（产品状态目录；解析失败时不 manage → Command 返回错误）。
            if let Some(store) = ui_prefs::UiPrefsStore::from_product_dir() {
                app.manage(store);
            } else {
                tracing::warn!(target: "exv.bootstrap",
                    "ui state dir unavailable; ui prefs commands will error");
            }

            lifecycle::setup(app)?;
            window_chrome::install(&app.handle())?;
            // R8：toast AUMID 注册（幂等）。让系统 toast 以 EXV 身份发出。
            toast_identity::ensure_toast_identity_registered();
            // core 进程归属（O3）：UI 宿主 spawn core → 拨号 → 管理 CoreState/
            // CoreSession → 挂事件订阅。core 缺失/拨号失败走降级路径（NotWired）。
            kernel::bootstrap::bootstrap(app)?;

            // 启动可见性（静默启动 ∨ prefs）：默认窗口 visible:false，此处决定是否亮出。
            lifecycle::apply_startup_visibility(app.handle());
            Ok(())
        })
        .on_window_event(|window, event| {
            match event {
                tauri::WindowEvent::CloseRequested { api, .. } => {
                    // 关闭行为由 close_preference 驱动（quit/tray/smart 宽限）；
                    // prevent_close 统一接管，真正退出走 notify_core_shutdown。
                    api.prevent_close();
                    if window.label() == "main" {
                        if let Some(webview) = window.app_handle().get_webview_window("main") {
                            handle_close_request(&webview);
                        }
                    }
                }
                tauri::WindowEvent::Focused(true) => {
                    if window.label() == "main" && window.is_visible().unwrap_or(false) {
                        notify_main_window_shown();
                    }
                }
                _ => {}
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::connect,
            commands::core_status,
            commands::stop,
            commands::snapshot,
            commands::stats,
            commands::logs_list,
            commands::logs_clear,
            commands::config_get,
            commands::config_set,
            commands::tunnel_address,
            commands::respond_interaction,
            commands::trigger_latency_refresh,
            commands::service_control,
            commands::open_external,
            ui_prefs::ui_prefs_get,
            ui_prefs::ui_prefs_set,
            autostart::autostart_set,
            tray::tray_notify,
            window_chrome::window_chrome_set_mode,
            window_chrome::window_chrome_control,
            window_chrome::window_set_visible,
        ])
        .run(tauri::generate_context!())
        .expect("error while running EXV Tauri app");
}
