//! Tauri Command 定义（P4-b：真实接线，经 CoreClient 接缝）。
//!
//! 映射（计划 §1）：Command ↔ unary。
//!   connect / stop / snapshot / config.get / config.set / logs.list / logs.clear /
//!   respond_interaction
//!
//! P4-b：CoreClient 方法体已替换为真实 gRPC 调用（命令签名不变，仅 async 化）；
//! `logs_list`/`logs_clear`/`config_get`/`config_set` 已真实接线（KernelControl RPC），
//! `stats` 从 snapshot 维护的缓存读取（尚无样本时返回 typed NotWired 占位）。

use tauri::State;

use super::client::{ConfigItem, ConnectIntent, CoreClient, CoreSession, CoreState, CoreStatus};
use super::error::AppError;
use super::logs::{LogChunk, LogsClearReply};
use super::state::{OperationReply, RuntimeSnapshot};
use super::stats::RuntimeStats;

/// 发起连接（core KernelControl.Connect）。
///
/// R4：connect 是异步受理（R1w pending）——终态/阶段经 `exv://status` 事件驱动，
/// 不再用 stderr 诊断直出（失败走事件链/命令错误，D3 铁律：日志纯输出、状态走事件）。
#[tauri::command]
pub async fn connect(
    app: tauri::AppHandle,
    state: State<'_, CoreState>,
    session: State<'_, CoreSession>,
    intent: ConnectIntent,
) -> Result<OperationReply, AppError> {
    match CoreClient.connect(&state, intent.clone()).await {
        Ok(reply) => Ok(reply),
        Err(AppError::CoreUnreachable(_)) => {
            super::bootstrap::recover_stopped_core_for_connect(&app, &state, &session).await?;
            CoreClient.connect(&state, intent).await
        }
        Err(error) => Err(error),
    }
}

/// UI 的 Core 两态健康检查。仅由控制管道实际可通与否得出，绝不扫描进程或拉起 Core。
#[tauri::command]
pub async fn core_status(state: State<'_, CoreState>) -> Result<CoreStatus, AppError> {
    Ok(state.probe_status().await)
}

/// 停止连接（core KernelControl.Stop）。
#[tauri::command]
pub async fn stop(
    app: tauri::AppHandle,
    state: State<'_, CoreState>,
) -> Result<OperationReply, AppError> {
    let _ = app; // O3/P4-b：停止成功后通知 core 退出在 lifecycle::notify_core_shutdown。
    CoreClient.stop(&state).await
}

/// 拉取当前运行时快照（core KernelControl.GetSnapshot）。
#[tauri::command]
pub async fn snapshot(state: State<'_, CoreState>) -> Result<RuntimeSnapshot, AppError> {
    CoreClient.snapshot(&state).await
}

/// 拉取日志历史分片（KernelControl.LogsList 真实接线；host 聚合 core/engine 日志）。
#[tauri::command]
pub async fn logs_list(
    state: State<'_, CoreState>,
    after_seq: u64,
    limit: u32,
) -> Result<LogChunk, AppError> {
    CoreClient.logs_list(&state, after_seq, limit).await
}

/// 清空 core 持久化日志（KernelControl.LogsClear；不是只清当前 Vue 视图）。
#[tauri::command]
pub async fn logs_clear(state: State<'_, CoreState>) -> Result<LogsClearReply, AppError> {
    CoreClient.logs_clear(&state).await
}

/// 读取配置（KernelControl.ConfigGet 真实接线；设置页核心配置数据源）。
#[tauri::command]
pub async fn config_get(
    state: State<'_, CoreState>,
) -> Result<super::client::ConfigPayload, AppError> {
    CoreClient.config_get(&state).await
}

/// 拉取当前归一化统计（stats-wire 方案 A：从 `snapshot` 命令维护的缓存读取；
/// 尚无样本返回 typed NotWired 占位，前端保持「暂无统计」不视为失败）。
#[tauri::command]
pub async fn stats(state: State<'_, CoreState>) -> Result<RuntimeStats, AppError> {
    CoreClient.stats(&state).await
}

/// 写入配置（KernelControl.ConfigSet 真实接线；返回 ok 标志）。
#[tauri::command]
pub async fn config_set(
    state: State<'_, CoreState>,
    items: Vec<ConfigItem>,
) -> Result<bool, AppError> {
    CoreClient.config_set(&state, items).await
}

/// 读取 EXV Wintun 适配器当前的 IPv4 单播地址。
///
/// 这是只读系统观测：未连接/地址尚未分配时返回 `None`，不把配置中的地址或
/// 路由目标伪装成校内地址。
#[tauri::command]
pub fn tunnel_address() -> Result<Option<String>, String> {
    exv_vpn_win32_resource::adapter_address::first_ipv4_for_adapter("ExvEngine")
        .map(|address| address.map(|value| value.to_string()))
}

/// 应答交互提示（core KernelControl.RespondInteraction）。
#[tauri::command]
pub async fn respond_interaction(
    state: State<'_, CoreState>,
    interaction_id: Vec<u8>,
    response_payload: Vec<u8>,
) -> Result<OperationReply, AppError> {
    CoreClient
        .respond_interaction(&state, interaction_id, response_payload)
        .await
}

/// 触发一次延迟刷新（T1 latency design v2）：写本地标记文件，engine 数据面探测
/// 循环轮询到新值即立即执行一次隧道 ping。无 wire 变更（延迟仍经
/// `RuntimeSnapshot.stats.latency_ms` 到达；host/engine RPC 面在 T1 边界之外）。
#[tauri::command]
pub async fn trigger_latency_refresh() -> Result<(), AppError> {
    super::latency::write_refresh_marker().map_err(AppError::Internal)
}

/// 服务控制（S3/D5：`KernelControl.ServiceControl`）：query 非提权读；install/
/// uninstall/start 变更 action 由 host 经 engine 子命令 runas 提权 seam 执行。
/// 返回 post-action 服务状态 + `ok` + 人类可读信息（无秘密/栈）。
#[tauri::command]
pub async fn service_control(
    state: State<'_, CoreState>,
    action: super::state::ServiceControlAction,
) -> Result<super::state::ServiceControlReply, AppError> {
    CoreClient.service_control(&state, action).await
}

/// 用系统默认浏览器打开外部 URL（Windows 经 cmd /C start）。关于页仓库链接等使用；
/// WebView2 会拦截 `window.open`，必须走本命令。
#[tauri::command]
pub fn open_external(url: String) -> Result<(), String> {
    let _ = std::process::Command::new("cmd")
        .args(["/C", "start", "", &url])
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}
