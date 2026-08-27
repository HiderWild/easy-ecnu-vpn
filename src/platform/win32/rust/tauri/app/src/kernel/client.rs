//! CoreClient —— UI 侧访问 core 的唯一接缝（P4-b：真实 tonic 调用）。
//!
//! 架构（计划 §1）：core 是独立进程，唯一语义网关；UI 不直连 engine。
//! P4-b 接线方式（见 README「P4-b IPC 接线说明」）：
//!   * Tauri host 进程 spawn/attach core 进程（[`super::core_process`]），
//!     经 [`super::core_transport::connect_core_channel`] 拨号 core 的
//!     `KernelControl` Named Pipe gRPC 端点；
//!   * [`CoreHandle::Dialed`] 持有 tonic `Channel`；[`CoreClient`] 方法经
//!     `KernelControlClient` 做真实 unary / server-streaming 调用；
//!   * wire 消息 → UI 镜像类型的机械映射在 [`super::wire`]。
//!
//! 2026-08-18：`logs_list`/`config_get`/`config_set` 已真实接线（KernelControl
//! 新增 LogsList/LogsClear/ConfigGet/ConfigSet RPC；host 聚合日志 + ExvConfig
//! 服务，LogEvent 迁至 common.proto 共享）。stats 经 RuntimeSnapshot.stats 携带，
//! `stats` 命令从 snapshot 缓存读取。`stats` 缓存无样本时返回 NotWired 占位。

use std::sync::RwLock;

use exv_vpn_wire::generated::kernel_control_client::KernelControlClient;
use exv_vpn_wire::generated::{self as wire};
use serde::{Deserialize, Serialize};
use tonic::transport::Channel;
use tonic::{Code, Status};

use super::core_transport::{connect_core_channel, CorePeer, GrpcPipeError};
use super::error::AppError;
use super::logs::{LogChunk, LogsClearReply};
use super::state::{OperationReply, RuntimeSnapshot, ServiceControlAction, ServiceControlReply};
use super::stats::RuntimeStats;
use super::wire::{self as wire_map};

/// 连接/身份意图（P4-b 已对齐 core ConnectIntent 的 UI 侧字段；`secret_payload`
/// 是 UI 提交的一次性 secret，core 侧走一次性通道并零化 wire 副本）。
///
/// R1：安装/连接拆分为独立路由——`auto_install_service` 已从 wire 移除，connect 只携带
/// `profile_ref` + `secret_payload`；安装服务由 UI 独立发 ServiceControl install 请求。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectIntent {
    pub profile_ref: String,
    pub secret_payload: Option<String>,
}

/// 配置项（设置页骨架；core config 契约不在冻结 wire 上，P4-b 保留 seam）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigPayload {
    pub items: Vec<ConfigItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigItem {
    pub key: String,
    pub value: String,
}

/// 与 core 的通道形态。P4-a 恒为 `NotWired`；P4-b 增加 `Dialed`。
#[derive(Debug, Clone)]
pub enum CoreHandle {
    /// 尚未建立到 core 的通道（core 未启动 / 拨号失败）。
    NotWired,
    /// 已拨号并验证 core server 的通道（含已验证的 core peer 身份）。
    Dialed {
        channel: Channel,
        /// 已验证的 core server 身份（transport 派生；生命周期/诊断在后续阶段读取）。
        #[allow(dead_code)]
        core_peer: CorePeer,
    },
}

/// UI 对 Core 控制面的两态结论。日常探测只依据已验证管道上的 RPC 是否可通，
/// 不把 Windows 进程表当作健康来源；进程句柄只允许在用户点击连接后的恢复分支读取。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreStatus {
    Normal,
    Stopped,
}

impl Default for CoreHandle {
    fn default() -> Self {
        Self::NotWired
    }
}

impl CoreHandle {
    /// 已拨号通道的引用（`NotWired` → `None`）。
    #[must_use]
    pub fn channel(&self) -> Option<&Channel> {
        match self {
            Self::Dialed { channel, .. } => Some(channel),
            Self::NotWired => None,
        }
    }

    /// 是否已拨号（UI 可否访问 core）。
    #[must_use]
    #[allow(dead_code)]
    pub fn is_dialed(&self) -> bool {
        matches!(self, Self::Dialed { .. })
    }

    /// 已验证的 core peer 身份（未拨号 → `None`）。P4-b 接入点：bootstrap 已存入，
    /// 生命周期/诊断在后续阶段读取。
    #[must_use]
    #[allow(dead_code)]
    pub fn core_peer(&self) -> Option<&CorePeer> {
        match self {
            Self::Dialed { core_peer, .. } => Some(core_peer),
            Self::NotWired => None,
        }
    }
}

/// Tauri managed state：UI 侧 core 会话状态 + 快照缓存。
#[derive(Debug, Default)]
pub struct CoreState {
    /// 当前经过身份验证的 Core 控制通道。Core 意外退出后，只有连接恢复分支可以替换它；
    /// 其余命令仅克隆读取，不会触发进程探测或拉起。
    pub handle: RwLock<CoreHandle>,
    /// 最近一次 RuntimeSnapshot 缓存（前端可即时渲染，无需等下一事件）。
    /// `RwLock`：命令层读，事件订阅 task 写。
    pub last_snapshot: RwLock<Option<RuntimeSnapshot>>,
    /// 最近一次归一化统计缓存（stats-wire 方案 A：由 `snapshot` 命令从快照携带的
    /// `stats` 写入；`stats` 命令读取）。`RwLock`：命令层读/写。
    pub last_stats: RwLock<Option<RuntimeStats>>,
}

impl CoreState {
    /// 取得当前已验证通道的副本。`None` 即 UI 所见「Core 已停止」。
    #[must_use]
    pub fn channel(&self) -> Option<Channel> {
        self.handle
            .read()
            .ok()
            .and_then(|handle| handle.channel().cloned())
    }

    /// 原子替换为恢复后重新认证的通道。
    pub fn replace_handle(&self, handle: CoreHandle) {
        if let Ok(mut current) = self.handle.write() {
            *current = handle;
        }
    }

    /// 将 UI 的 Core 两态结论置为已停止（管道不可用）。
    pub fn mark_stopped(&self) {
        self.replace_handle(CoreHandle::NotWired);
    }

    /// 日常管道健康结论。这里不观察进程，仅执行既有轻量 snapshot RPC。
    pub async fn probe_status(&self) -> CoreStatus {
        match CoreClient.snapshot(self).await {
            Ok(_) => CoreStatus::Normal,
            Err(_) => CoreStatus::Stopped,
        }
    }

    /// 最近一次缓存快照（P4-b 接入点：snapshot 命令写入；P5-c UI 展示统计/即时渲染读取）。
    #[must_use]
    #[allow(dead_code)]
    pub fn cached_snapshot(&self) -> Option<RuntimeSnapshot> {
        self.last_snapshot.read().map(|g| g.clone()).unwrap_or(None)
    }

    /// 更新缓存快照。
    pub fn update_snapshot(&self, snapshot: RuntimeSnapshot) {
        if let Ok(mut g) = self.last_snapshot.write() {
            *g = Some(snapshot);
        }
    }

    /// 最近一次缓存统计（stats-wire 方案 A：`snapshot` 命令写入，`stats` 命令读取）。
    #[must_use]
    pub fn cached_stats(&self) -> Option<RuntimeStats> {
        self.last_stats.read().map(|g| g.clone()).unwrap_or(None)
    }

    /// 更新缓存统计（`snapshot` 命令从快照携带的 `stats` 写入）。
    pub fn update_stats(&self, stats: RuntimeStats) {
        if let Ok(mut g) = self.last_stats.write() {
            *g = Some(stats);
        }
    }
}

/// Tauri managed state：core 进程生命周期句柄（O3 强绑定）。
///
/// - `child`：core 子进程句柄（UI 宿主 spawn；Drop → 强制终止，core 不得遗留）。
/// - `subscriptions`：事件订阅 task 句柄（停机先中止，停止 emit）。
///
/// 由 [`super::bootstrap::bootstrap`] 在 setup 时管理；lifecycle 停机路径
/// （[`crate::lifecycle::notify_core_shutdown`]）读取。
#[derive(Default)]
pub struct CoreSession {
    /// core 子进程（`None` = 未拉起 / 已退出）。O3 生命周期句柄：core 由 pipe-close
    /// 感知自行退出（不做 Drop 强杀）；本句柄供挂死兜底（`terminate`）与观测。
    #[allow(dead_code)]
    pub child: std::sync::Mutex<Option<super::core_process::CoreChild>>,
    /// 事件订阅 task 句柄（WatchEvents 等；停机先中止）。用 tauri 自带 runtime 的
    /// JoinHandle（setup 主线程非 tokio 上下文，`tokio::spawn` 会 panic）。
    pub subscriptions: std::sync::Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>,
    /// 连接恢复的串行闸门。并发点击连接只允许一个调用检查子进程/重拉 Core，避免
    /// 同一 UI PID 下竞争同一个控制管道。
    pub recovery: tokio::sync::Mutex<()>,
}

/// UI 侧对 core 的命令客户端（无状态 facade；真实会话状态在 CoreState）。
#[derive(Debug, Default)]
pub struct CoreClient;

/// 拨号并连接 core 控制面管道（P4-b：UI 宿主 spawn core 后调用）。
///
/// `expected_core_pid` 是 core 进程 pid（UI 侧 spawn 时获得）；`expected_user_sid`
/// 是当前用户 SID（core 与 UI 同用户）。core 侧验证 UI 的 pid+SID 由 server 完成
/// （host `verify_ui_peer`）。
///
/// # Errors
/// 拨号失败 → `AppError::CoreUnreachable`；身份不匹配 → `AppError::CoreUnreachable`；
/// channel 构建失败 → `AppError::CoreUnreachable`。
pub async fn dial_core(
    pipe_name: &str,
    expected_core_pid: u32,
    expected_user_sid: &str,
) -> Result<(Channel, CorePeer), AppError> {
    connect_core_channel(pipe_name, expected_core_pid, expected_user_sid)
        .await
        .map_err(pipe_error_to_app)
}

/// 把传输层错误映射为 UI 错误（全部归 `CoreUnreachable`——core 不可达）。
fn pipe_error_to_app(e: GrpcPipeError) -> AppError {
    AppError::CoreUnreachable(e.to_string())
}

/// R5 服务连接失败消息的稳定前缀（host `kernel_control_service` 路由失败时置于
/// `failed_precondition` 消息开头；前缀后为可读信息）。
const SERVICE_NOT_RUNNING_PREFIX: &str = "service_not_running|";
const SERVICE_START_FAILED_PREFIX: &str = "service_start_failed|";
const SERVICE_CONNECT_FAILED_PREFIX: &str = "service_connect_failed|";

/// 把 tonic `Status` 映射为 UI 错误：transport 类 → `CoreUnreachable`；
/// 服务路由失败前缀 → typed `ServiceNotRunning` / `ServiceConnectFailed`（R5 modal
/// 触发）；其余 → `Internal`（携带稳定 code + 精简 message）。
fn map_status(s: Status) -> AppError {
    match s.code() {
        Code::Unavailable | Code::Cancelled | Code::Unknown | Code::DeadlineExceeded => {
            AppError::CoreUnreachable(format!("{}: {}", s.code(), s.message()))
        }
        _ => {
            let message = s.message();
            if let Some(rest) = message.strip_prefix(SERVICE_NOT_RUNNING_PREFIX) {
                AppError::ServiceNotRunning(rest.trim().to_string())
            } else if let Some(rest) = message.strip_prefix(SERVICE_START_FAILED_PREFIX) {
                AppError::ServiceNotRunning(rest.trim().to_string())
            } else if let Some(rest) = message.strip_prefix(SERVICE_CONNECT_FAILED_PREFIX) {
                AppError::ServiceConnectFailed(rest.trim().to_string())
            } else {
                AppError::Internal(format!("{}: {}", s.code(), s.message()))
            }
        }
    }
}

impl CoreClient {
    /// 发起连接（P4-b: KernelControl.Connect）。
    ///
    /// R4 事件关联：调用方在组装 intent 时生成 operation_id（16 字节 UUID），
    /// host 以 lookup_key.operation_id 关联状态事件；同一 id 随 `OperationReply`
    /// 回传前端，前端据此只让「当前用户操作」的事件驱动连接 UI。
    pub async fn connect(
        &self,
        state: &CoreState,
        intent: ConnectIntent,
    ) -> Result<OperationReply, AppError> {
        let channel = state
            .channel()
            .ok_or_else(|| AppError::CoreUnreachable("connect: core not dialed".to_string()))?;
        let operation_id = uuid::Uuid::new_v4().as_bytes().to_vec();
        let request = wire_map::connect_request(&intent, operation_id.clone())?;
        let mut client = KernelControlClient::new(channel);
        let reply = match client.connect(request).await.map_err(map_status) {
            Ok(reply) => reply,
            Err(error) => {
                if matches!(error, AppError::CoreUnreachable(_)) {
                    state.mark_stopped();
                }
                return Err(error);
            }
        };
        let mut ui = wire_map::operation_reply_from_wire(&reply.into_inner());
        ui.operation_id = Some(wire_map::hex(&operation_id));
        Ok(ui)
    }

    /// 停止连接（P4-b: KernelControl.Stop）。operation_id 关联契约同 connect。
    pub async fn stop(&self, state: &CoreState) -> Result<OperationReply, AppError> {
        let channel = state
            .channel()
            .ok_or_else(|| AppError::CoreUnreachable("stop: core not dialed".to_string()))?;
        let operation_id = uuid::Uuid::new_v4().as_bytes().to_vec();
        let request = wire_map::stop_request(operation_id.clone())?;
        let mut client = KernelControlClient::new(channel);
        let reply = client.stop(request).await.map_err(map_status)?;
        let mut ui = wire_map::operation_reply_from_wire(&reply.into_inner());
        ui.operation_id = Some(wire_map::hex(&operation_id));
        Ok(ui)
    }

    /// 拉取当前运行时快照（P4-b: KernelControl.GetSnapshot），并更新缓存。
    ///
    /// stats-wire 方案 A：快照携带最新统计（`GetSnapshot` 从 EventBus 统计 lane
    /// 附加）——`snapshot` 同时更新 `last_snapshot` 与 `last_stats` 缓存。
    pub async fn snapshot(&self, state: &CoreState) -> Result<RuntimeSnapshot, AppError> {
        let channel = state
            .channel()
            .ok_or_else(|| AppError::CoreUnreachable("snapshot: core not dialed".to_string()))?;
        let mut client = KernelControlClient::new(channel);
        let reply = match client
            .get_snapshot(wire::SnapshotRequest::default())
            .await
            .map_err(map_status)
        {
            Ok(reply) => reply,
            Err(error) => {
                if matches!(error, AppError::CoreUnreachable(_)) {
                    state.mark_stopped();
                }
                return Err(error);
            }
        };
        let ui = wire_map::snapshot_from_wire(&reply.into_inner(), 0);
        state.update_snapshot(ui.clone());
        if let Some(stats) = ui.stats {
            state.update_stats(stats);
        }
        Ok(ui)
    }

    /// 查询先前操作 disposition（P4-b: KernelControl.GetOperation）。
    /// P4-3 重试 UI（Reconcile）接入后启用——当前命令层未暴露。
    #[allow(dead_code)]
    pub async fn get_operation(
        &self,
        state: &CoreState,
        key: wire::OperationLookupKey,
    ) -> Result<Option<wire::OperationState>, AppError> {
        let channel = state.channel().ok_or_else(|| {
            AppError::CoreUnreachable("get_operation: core not dialed".to_string())
        })?;
        let mut client = KernelControlClient::new(channel);
        let reply = client
            .get_operation(wire::GetKernelOperationRequest { key: Some(key) })
            .await
            .map_err(map_status)?;
        Ok(reply.into_inner().state)
    }

    /// 拉取日志历史分片（KernelControl.LogsList 真实接线）。
    pub async fn logs_list(
        &self,
        state: &CoreState,
        after_seq: u64,
        limit: u32,
    ) -> Result<LogChunk, AppError> {
        let channel = state
            .channel()
            .ok_or_else(|| AppError::CoreUnreachable("logs_list: core not dialed".to_string()))?;
        let request = wire::LogsListRequest {
            after_seq,
            limit,
            filter: String::new(),
        };
        let mut client = KernelControlClient::new(channel);
        let reply = client.logs_list(request).await.map_err(map_status)?;
        let inner = reply.into_inner();
        let effective_limit = if limit == 0 { 100 } else { limit as usize };
        let events = inner
            .entries
            .iter()
            .map(wire_map::log_event_from_wire)
            .collect::<Vec<_>>();
        let has_more = !inner.entries.is_empty() && inner.entries.len() >= effective_limit;
        Ok(LogChunk {
            events,
            next_after_seq: inner.next_seq,
            has_more,
        })
    }

    /// 清空 core 的持久化日志（KernelControl.LogsClear）。
    pub async fn logs_clear(&self, state: &CoreState) -> Result<LogsClearReply, AppError> {
        let channel = state
            .channel()
            .ok_or_else(|| AppError::CoreUnreachable("logs_clear: core not dialed".to_string()))?;
        let mut client = KernelControlClient::new(channel);
        let reply = client
            .logs_clear(wire::LogsClearRequest {})
            .await
            .map_err(map_status)?
            .into_inner();
        Ok(LogsClearReply {
            cleared: reply.cleared,
            removed_entries: reply.removed_entries,
        })
    }

    /// 读取配置（KernelControl.ConfigGet 真实接线）。
    pub async fn config_get(&self, state: &CoreState) -> Result<ConfigPayload, AppError> {
        let channel = state
            .channel()
            .ok_or_else(|| AppError::CoreUnreachable("config_get: core not dialed".to_string()))?;
        let mut client = KernelControlClient::new(channel);
        let reply = client
            .config_get(wire::ConfigGetRequest {})
            .await
            .map_err(map_status)?;
        let inner = reply.into_inner();
        Ok(ConfigPayload {
            items: inner
                .items
                .into_iter()
                .map(|i| ConfigItem {
                    key: i.key,
                    value: i.value,
                })
                .collect(),
        })
    }

    /// 写入配置（KernelControl.ConfigSet 真实接线）。
    pub async fn config_set(
        &self,
        state: &CoreState,
        items: Vec<ConfigItem>,
    ) -> Result<bool, AppError> {
        let channel = state
            .channel()
            .ok_or_else(|| AppError::CoreUnreachable("config_set: core not dialed".to_string()))?;
        let request = wire::ConfigSetRequest {
            items: items
                .into_iter()
                .map(|i| wire::ConfigItem {
                    key: i.key,
                    value: i.value,
                })
                .collect(),
        };
        let mut client = KernelControlClient::new(channel);
        let reply = client.config_set(request).await.map_err(map_status)?;
        Ok(reply.into_inner().ok)
    }

    /// 拉取当前归一化统计（stats-wire 方案 A）。
    ///
    /// 统计不再走独立 RPC：`RuntimeSnapshot` 携带统计（`GetSnapshot`/`WatchEvents`
    /// 一并下发），本命令从 `snapshot` 命令维护的 `last_stats` 缓存读取——最小改动的
    /// unary 拉取路径。尚无样本（未连接/无快照）→ `NotWired` 占位错误（前端
    /// 保持「暂无统计」占位，不视为失败）。
    pub async fn stats(&self, state: &CoreState) -> Result<RuntimeStats, AppError> {
        state.cached_stats().ok_or_else(|| {
            AppError::NotWired(
                "stats: no statistics yet (snapshot carries none; connect to start the data plane)"
                    .into(),
            )
        })
    }

    /// 应答交互提示（P4-b: KernelControl.RespondInteraction）。
    pub async fn respond_interaction(
        &self,
        state: &CoreState,
        interaction_id: Vec<u8>,
        response_payload: Vec<u8>,
    ) -> Result<OperationReply, AppError> {
        let channel = state.channel().ok_or_else(|| {
            AppError::CoreUnreachable("respond_interaction: core not dialed".to_string())
        })?;
        let request = wire_map::interaction_response(interaction_id, response_payload);
        let mut client = KernelControlClient::new(channel);
        let reply = client
            .respond_interaction(request)
            .await
            .map_err(map_status)?;
        Ok(wire_map::operation_reply_from_wire(&reply.into_inner()))
    }

    /// 执行服务控制（S3/D5: `KernelControl.ServiceControl`）。query 非提权读；
    /// install/uninstall/start 变更 action 由 host 经 engine 子命令 runas 提权 seam
    /// 执行（D4——host 非提权，SCM 操作在 engine 内）。
    pub async fn service_control(
        &self,
        state: &CoreState,
        action: ServiceControlAction,
    ) -> Result<ServiceControlReply, AppError> {
        let channel = state.channel().ok_or_else(|| {
            AppError::CoreUnreachable("service_control: core not dialed".to_string())
        })?;
        let mut client = KernelControlClient::new(channel);
        let reply = client
            .service_control(wire_map::service_control_request(action))
            .await
            .map_err(map_status)?;
        Ok(wire_map::service_control_reply_from_wire(
            &reply.into_inner(),
        ))
    }

    /// 打开 `KernelControl.WatchEvents` server-streaming 订阅（P4-b 事件订阅源）。
    ///
    /// `resume_tick == 0` 表示从当前快照开始。返回的流由事件订阅 task 驱动
    /// （`stream.next()` → `app.emit`）。流 EOF = core 断开。
    ///
    /// # Errors
    /// RPC 拒绝 / 掉线 → 相应 `AppError`（channel 由调用方保证已拨号）。
    pub async fn open_watch_stream(
        &self,
        channel: &Channel,
        resume_tick: u64,
    ) -> Result<tonic::Streaming<wire::RuntimeEvent>, AppError> {
        let mut client = KernelControlClient::new(channel.clone());
        let reply = client
            .watch_events(wire::WatchEventsRequest { resume_tick })
            .await
            .map_err(map_status)?;
        Ok(reply.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// R5：服务路由失败前缀 → typed AppError 变体（modal 触发），前缀被剥离。
    #[test]
    fn map_status_service_prefixes_map_to_typed_variants() {
        let not_running = map_status(Status::failed_precondition(
            "service_not_running|service installed but not running; start the service and reconnect",
        ));
        assert!(matches!(
            not_running,
            AppError::ServiceNotRunning(ref m) if m.contains("start the service")
        ));

        let start_failed = map_status(Status::failed_precondition(
            "service_start_failed|服务业务面未就绪（SCM 状态=Running，keepalive 未响应）",
        ));
        assert!(matches!(
            start_failed,
            AppError::ServiceNotRunning(ref m) if m.contains("keepalive")
        ));

        let connect_failed = map_status(Status::failed_precondition(
            "service_connect_failed|service engine connect: psk unreadable",
        ));
        assert!(matches!(
            connect_failed,
            AppError::ServiceConnectFailed(ref m) if m.contains("psk unreadable")
        ));
    }

    /// 非服务前缀的普通业务拒绝仍映射为 Internal（不误触发 modal）。
    #[test]
    fn map_status_plain_business_rejection_stays_internal() {
        let err = map_status(Status::failed_precondition("authorization refused"));
        assert!(matches!(err, AppError::Internal(_)));
        assert!(!matches!(err, AppError::ServiceNotRunning(_)));
        assert!(!matches!(err, AppError::ServiceConnectFailed(_)));
    }

    /// transport 类错误仍映射为 CoreUnreachable（modal 不因掉线触发）。
    #[test]
    fn map_status_transport_errors_map_to_core_unreachable() {
        for code in [
            Code::Unavailable,
            Code::Cancelled,
            Code::Unknown,
            Code::DeadlineExceeded,
        ] {
            let err = map_status(Status::new(code, "boom"));
            assert!(
                matches!(err, AppError::CoreUnreachable(_)),
                "code {code} must map to CoreUnreachable"
            );
        }
    }

    /// R5 变体 serde 形状稳定：`{kind,message}`（前端 command-error 识别）。
    #[test]
    fn service_error_variants_serialize_as_kind_message() {
        let err = AppError::ServiceNotRunning("please start".to_string());
        let json = serde_json::to_value(err).expect("serialize");
        assert_eq!(json["kind"], "service_not_running");
        assert_eq!(json["message"], "please start");

        let err = AppError::ServiceConnectFailed("connect failed".to_string());
        let json = serde_json::to_value(err).expect("serialize");
        assert_eq!(json["kind"], "service_connect_failed");
        assert_eq!(json["message"], "connect failed");
    }
}
