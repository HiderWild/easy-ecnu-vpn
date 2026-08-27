//! core 启动接线（P4-b）：Tauri setup 时 spawn core → 拨号 → 管理状态 → 挂订阅。
//!
//! 流程（O3 强绑定：UI 宿主管理 core 生命周期）：
//!   1. 定位 core 二进制（[`super::core_process::core_bin_path`]）并 spawn
//!      （[`super::core_process::spawn_core`]）——core 是普通用户 token 的纯协调层，
//!      非特权直接拉起；
//!   2. 拨号 core 控制面 Named Pipe（[`super::client::dial_core`]，按 UI 侧已知的
//!      core pid + 当前用户 SID 验证 server）；
//!   3. 组装 [`CoreState`]（Dialed/NotWired handle + 快照缓存）与 [`CoreSession`]
//!      （core 子进程句柄 + 订阅 task 句柄）并 `app.manage`；
//!   4. 拨号成功 → 拉起事件订阅（[`super::events::spawn_subscriptions`]）。
//!
//! **诚实降级**：core 二进制尚不存在（P5 落 host main 前）或拨号失败 → 记录 warning，
//! 保留 `NotWired` handle，UI 照常打开（命令返回 `CoreUnreachable`，前端展示
//! "core 未连接"）——不把启动失败升级为进程崩溃。

use tauri::{AppHandle, Manager};

use super::client::{dial_core, CoreHandle, CoreSession, CoreState};
use super::core_process::{core_bin_path, spawn_core};
use super::core_transport::current_user_sid;
use super::error::AppError;
use super::events::spawn_subscriptions;

/// 执行 core 启动接线（幂等性由调用方保证——setup 只调一次）。
///
/// # Errors
/// 仅 propagate tauri 管理错误（不可恢复）；core 缺失/拨号失败走降级路径不报错。
pub fn bootstrap(app: &mut tauri::App) -> tauri::Result<()> {
    // 1. spawn core（best effort）。
    let (child, core_pid) = match core_bin_path().and_then(|p| spawn_core(&p).ok()) {
        Some(child) => {
            let pid = child.pid();
            tracing::info!(
                target: "exv.bootstrap",
                pid,
                "core process spawned"
            );
            (Some(child), pid)
        }
        None => {
            tracing::warn!(
                target: "exv.bootstrap",
                "core binary not available (P5 lands host main); running degraded with NotWired handle"
            );
            (None, 0)
        }
    };

    // 2. 拨号 core 控制面管道（best effort；身份验证 fail closed）。
    let handle = match core_pid {
        0 => CoreHandle::NotWired,
        pid => {
            // setup 阶段 tauri 的 tokio runtime 已就绪：阻塞等待拨号完成。
            match tauri::async_runtime::block_on(dial_spawned_core(pid)) {
                Ok((channel, core_peer)) => {
                    tracing::info!(
                        target: "exv.bootstrap",
                        core_pid = core_peer.process_id,
                        "dialed core KernelControl endpoint"
                    );
                    CoreHandle::Dialed { channel, core_peer }
                }
                Err(e) => {
                    tracing::warn!(target: "exv.bootstrap", "dial core failed (degraded): {e}");
                    CoreHandle::NotWired
                }
            }
        }
    };

    // 3. 管理状态（setup 阶段 manage 合法；命令在 setup 完成后才可 invoke）。
    // `Manager` trait 在 `AppHandle` 上实现（`&mut App` 无 manage/state）。
    let channel = handle.channel().cloned();
    let handle_ref = app.handle();
    handle_ref.manage(CoreState {
        handle: std::sync::RwLock::new(handle),
        last_snapshot: Default::default(),
        last_stats: Default::default(),
    });
    handle_ref.manage(CoreSession {
        child: std::sync::Mutex::new(child),
        subscriptions: std::sync::Mutex::new(Vec::new()),
        recovery: tokio::sync::Mutex::new(()),
    });

    // 4. 拨号成功 → 挂事件订阅（emit 到前端；快照缓存由 snapshot 命令维护）。
    if let Some(channel) = channel {
        let app_handle = handle_ref.clone();
        let handles = spawn_subscriptions(app_handle, channel);
        handle_ref
            .state::<CoreSession>()
            .subscriptions
            .lock()
            .expect("subscriptions lock")
            .extend(handles);
        tracing::info!(target: "exv.bootstrap", "event subscriptions started");
    }

    Ok(())
}

/// 用户点“连接”时的唯一 Core 恢复入口。
///
/// 日常 UI 只经 [`CoreState::probe_status`] 观察控制管道；**不会**枚举进程，也不会尝试
/// 拉起 Core。只有当前次 Connect 已返回 `CoreUnreachable` 才调用本函数：先确认 UI
/// 托管的子进程是否退出，确认后才静默重拉、等待并认证新管道、替换会话、重试原请求。
pub async fn recover_stopped_core_for_connect(
    app: &AppHandle,
    state: &CoreState,
    session: &CoreSession,
) -> Result<(), AppError> {
    let _gate = session.recovery.lock().await;

    // 并发 Connect 的第一个调用可能已经完成恢复；此处只用管道 RPC 复核，不观察进程。
    if state.probe_status().await == super::client::CoreStatus::Normal {
        return Ok(());
    }

    // 这是唯一允许的“进程是否已退出”检查。依赖 UI 自己 spawn 后保存的 Child 句柄，
    // 不扫描系统进程表，也不会误把同名外部进程视为本 Core。
    let exited = session
        .child
        .lock()
        .map(|mut child| child.as_mut().is_none_or(super::core_process::CoreChild::has_exited))
        .unwrap_or(false);
    if !exited {
        return Err(AppError::CoreUnreachable(
            "connect: core control pipe is unavailable while the managed core process is still running"
                .to_string(),
        ));
    }

    let executable = core_bin_path().ok_or_else(|| {
        AppError::CoreUnreachable("connect: core executable is unavailable for recovery".to_string())
    })?;
    let mut replacement = spawn_core(&executable)
        .map_err(|error| AppError::CoreUnreachable(format!("connect: restart core failed: {error}")))?;
    let pid = replacement.pid();
    // core 刚 spawn 时命名管道尚在创建。有限重试只等待本次受控重拉的就绪，不做后台轮询。
    match dial_spawned_core(pid).await {
        Ok((channel, core_peer)) => {
            state.replace_handle(CoreHandle::Dialed {
                channel: channel.clone(),
                core_peer,
            });
            replace_subscriptions(app, session, channel);
            if let Ok(mut child) = session.child.lock() {
                *child = Some(replacement);
            }
            tracing::info!(target: "exv.bootstrap", core_pid = pid, "core recovered for user connect");
            Ok(())
        }
        Err(error) => {
            replacement.terminate();
            state.mark_stopped();
            Err(error)
        }
    }
}

/// 受 UI 管理的新 Core 的有限就绪等待。只在 UI 初启和已确认退出后的连接恢复中调用；
/// 不属于日常健康检查，也不构成后台重启循环。
async fn dial_spawned_core(pid: u32) -> Result<(tonic::transport::Channel, super::core_transport::CorePeer), AppError> {
    let pipe = super::core_process::core_control_pipe_name();
    let sid = current_user_sid().unwrap_or_default();
    let mut last_error = None;
    for _ in 0..25 {
        match dial_core(&pipe, pid, &sid).await {
            Ok(dialed) => return Ok(dialed),
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        AppError::CoreUnreachable("core did not expose its control pipe before readiness timeout".to_string())
    }))
}

/// 新 Core 认证成功后更换 status 订阅，避免旧管道的退避任务继续占用 UI。
fn replace_subscriptions(app: &AppHandle, session: &CoreSession, channel: tonic::transport::Channel) {
    if let Ok(mut subscriptions) = session.subscriptions.lock() {
        for subscription in subscriptions.drain(..) {
            subscription.abort();
        }
        subscriptions.extend(spawn_subscriptions(app.clone(), channel));
    }
}
