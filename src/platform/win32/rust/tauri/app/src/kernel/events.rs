//! Event 名称与 emit 辅助 + 真实订阅 task（P4-b）。
//!
//! 范式同构（计划 §1）：Event ↔ server-streaming。
//!   * `exv://status`  ← core WatchEvents（RuntimeEvent，实时快照/过渡）
//!   * `exv://logs`    ← core StreamLogs（LogEvent 增量）——**wire 缺口**：core 的
//!     `KernelControl` 服务未向 UI 暴露 StreamLogs（host `log_control.rs` 为进程内
//!     方法，proto 变更须协调者评估），P4-b 保留 emit seam，无真实推送源。
//!   * `exv://interaction` ← 需要用户在 UI 中应答的交互提示（RespondInteraction）
//!
//! [`spawn_subscriptions`] 在 core 拨号成功后由 [`super::bootstrap`] 调用：为每个
//! 订阅源拉起 tokio task，`stream.next()` → `app.emit`。返回句柄供停机时中止。
//! 快照缓存由 `snapshot` 命令维护（事件本身携带快照，前端可即时渲染）。

use tauri::{AppHandle, Emitter};
use tokio_stream::StreamExt;
use tonic::transport::Channel;

use super::client::CoreClient;
use super::logs::LogEvent;
use super::state::RuntimeEvent;
use super::stats::RuntimeStats;
use super::wire;

/// WatchEvents 订阅的 Event 名。
pub const EVENT_STATUS: &str = "exv://status";
/// StreamLogs 订阅的 Event 名（P4-b wire 缺口：core 未向 UI 暴露 StreamLogs，
/// 前端 `ipc.ts` 仍监听此名，接线后生效）。
#[allow(dead_code)]
pub const EVENT_LOGS: &str = "exv://logs";
/// 交互提示 Event 名（登录二次确认等；P5 交互流接线后生效）。
#[allow(dead_code)]
pub const EVENT_INTERACTION: &str = "exv://interaction";
/// 归一化统计推送 Event 名（stats-wire 方案 A 后为 seam：统计随 `exv://status` 的
/// `snapshot.stats` 到达，前端直接读 `ev.snapshot.stats`，本事件无发射源；若后续需
/// 独立高频统计推送再经 `emit_stats` 启用）。
#[allow(dead_code)]
pub const EVENT_STATS: &str = "exv://stats";

/// 向主窗口广播一次运行时事件。
pub fn emit_status(app: &AppHandle, event: &RuntimeEvent) -> tauri::Result<()> {
    app.emit(EVENT_STATUS, event)
}

/// 向主窗口广播一条日志（P4-b wire 缺口 seam：无真实推送源，StreamLogs 接线后启用）。
#[allow(dead_code)]
pub fn emit_log(app: &AppHandle, log: &LogEvent) -> tauri::Result<()> {
    app.emit(EVENT_LOGS, log)
}

/// 向主窗口广播一条归一化统计（stats-wire 方案 A 后为 seam：统计随快照到达，前端
/// 经 `exv://status` 读 `snapshot.stats`；独立高频推送需先立 requirement 再启用）。
#[allow(dead_code)]
pub fn emit_stats(app: &AppHandle, stats: &RuntimeStats) -> tauri::Result<()> {
    app.emit(EVENT_STATS, stats)
}

/// 启动 core 事件订阅（P4-b）：WatchEvents 实时订阅 task。
///
/// 订阅循环：`watch_events(resume=0)` → 逐事件 `wire::event_from_wire` 映射 →
/// `emit_status` → 流 EOF（core 断开）→ 以本地已见最大 tick 恢复订阅（core
/// `EventBus::subscribe` 按 resume_tick 重放当前快照，断线重放语义）→ 退避重连。
///
/// StreamLogs（`exv://logs`）为 wire 缺口（见模块文档），当前不拉起——emit_log
/// seam 保留。
pub fn spawn_subscriptions(app: AppHandle, channel: Channel) -> Vec<tauri::async_runtime::JoinHandle<()>> {
    let mut handles = Vec::new();

    // WatchEvents 订阅（经 CoreClient.open_watch_stream 打开流，语义与命令层一致）。
    let app_status = app.clone();
    let channel_status = channel.clone();
    // Tauri setup 闭包运行在主线程（非 tokio runtime 上下文），`tokio::spawn` 会 panic
    // （"no reactor running"）。改用 `tauri::async_runtime::spawn`（tauri 自带 runtime）。
    handles.push(tauri::async_runtime::spawn(async move {
        let mut resume_tick = 0u64;
        let mut backoff = WATCH_RECONNECT_BASE;
        loop {
            let stream = match CoreClient.open_watch_stream(&channel_status, resume_tick).await {
                Ok(stream) => stream,
                Err(e) => {
                    tracing::warn!(target: "exv.events", "watch_events subscribe failed: {e}; reconnecting");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(WATCH_RECONNECT_MAX);
                    continue;
                }
            };
            backoff = WATCH_RECONNECT_BASE;
            let mut stream = stream;
            while let Some(ev) = stream.next().await {
                match ev {
                    Ok(wire_ev) => {
                        // 记录本地已见最大 tick，供断线后 resume（core 断线重放语义）。
                        resume_tick = resume_tick.max(wire_ev.monotonic_tick);
                        let ui = wire::event_from_wire(&wire_ev);
                        if let Err(e) = emit_status(&app_status, &ui) {
                            tracing::debug!(target: "exv.events", "emit_status failed: {e}");
                        }
                    }
                    Err(status) => {
                        tracing::warn!(target: "exv.events", "watch_events stream error: {status}");
                        break;
                    }
                }
            }
            // 流 EOF = core 断开（或 stream 错误）→ 退避重连。
            tracing::warn!(target: "exv.events", "watch_events stream ended; reconnecting from tick {resume_tick}");
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(WATCH_RECONNECT_MAX);
        }
    }));

    handles
}

/// WatchEvents 重连初始退避。
const WATCH_RECONNECT_BASE: std::time::Duration = std::time::Duration::from_millis(200);
/// WatchEvents 重连退避上限。
const WATCH_RECONNECT_MAX: std::time::Duration = std::time::Duration::from_secs(5);
