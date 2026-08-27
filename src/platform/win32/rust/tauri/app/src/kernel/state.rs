//! 运行时状态镜像（proto/exv/v1/common.proto: RuntimeSnapshot / RuntimeEvent /
//! ConnectPhase / OperationReply）。字段名与 proto 一致，serde 用 snake_case，
//! 供 Command 返回与 Event payload 复用。P4-b 与 core 的 gRPC 消息机械映射。

use serde::{Deserialize, Serialize};

use super::stats::RuntimeStats;

/// 连接阶段（proto ConnectPhase）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectPhase {
    ObservingOwnedState,
    AcquiringPlatformLease,
    ConnectingControl,
    AwaitingInteraction,
    NegotiatingTunnel,
    ApplyingPlatformTunnel,
    AttachingPacketBoundary,
    StartingDataPlane,
}

/// 结构化错误（proto VpnError 的精简 UI 视图）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnError {
    /// 稳定诊断代码，空表示无。
    pub code: String,
    /// 面向用户的简短描述（不含诊断栈）。
    pub message: String,
}

/// RuntimeSnapshot 的 state oneof 各分支。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RuntimeState {
    Idle {
        last_cleanup_at_ms: Option<i64>,
    },
    Connecting {
        phase: ConnectPhase,
        attempt_id: Option<String>,
        /// 已完成/进行中的连接阶段序号（0..=7），供前端进度显示。
        phase_index: u8,
    },
    AwaitingInteraction {
        attempt_id: Option<String>,
        prompt_deadline_ms: Option<u64>,
    },
    Connected {
        session_established_at_ms: Option<i64>,
        /// 简要连接信息（redacted：不含凭据/证书）。
        summary: Option<String>,
    },
    Stopping {
        reason: Option<String>,
    },
    Reconciling {
        blocking_error: Option<VpnError>,
    },
    FailedClean {
        error: Option<VpnError>,
    },
    FailedDirty {
        error: Option<VpnError>,
        /// 是否存在待恢复义务（recovery obligation）。
        has_obligation: bool,
    },
}

/// 检测到的上游代理 TUN 适配器（proto `ProxyTunAdapter`；Phase 7 C5-wire）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyTunAdapter {
    /// 友好名称（如 "Mihomo" / "Meta"）。
    pub name: String,
    /// 接口描述（如 "Wintun Userspace Tunnel"）。
    pub description: String,
    /// IPv4 接口索引。
    pub if_index: u32,
    /// 适配器种类（当前恒为 "proxy_tun"）。
    pub kind: String,
}

/// 上游代理 TUN 检测结果（proto `ProxyTunDetection`；Phase 7 C5-wire，仅状态上报）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyTunDetection {
    /// 是否检测到至少一个上游代理 TUN 适配器。
    pub detected: bool,
    /// 检测到的适配器（`detected == false` 时为空）。
    pub adapters: Vec<ProxyTunAdapter>,
    /// 共存路由策略："exv-before-proxy-tun" | "normal"。
    pub route_policy: String,
}

/// 系统代理检测结果（proto `SystemProxyDetection`；S2 系统代理，仅状态上报——不携带
/// 端点 URL / 注册表值 / 秘密，只有计数与短枚举串，与 RuntimeStats/LogEvent 同不变式）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemProxyDetection {
    /// 系统代理模式："disabled" | "manual" | "automatic" | "mixed"。
    pub mode: String,
    /// 检测到的系统代理端点数（endpoints 规范化后计数）。
    pub endpoint_count: u32,
    /// EXV 豁免条目是否已合并进系统代理设置（bypass 非空 = 已合并）。
    pub bypass_merged: bool,
    /// 四态拓扑（`(proxy_present, tunnel_present)` 的纯函数分类）："t0" | "t1" | "t2" | "t3"。
    pub topology: String,
}

/// 自动重连状态（proto `ReconnectStatus`；S4 重连，仅状态上报——重连决策仍在 host 侧
/// C3a 重连 worker）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconnectStatus {
    /// 自动重连开关（config `auto_reconnect`）。
    pub auto_reconnect: bool,
    /// 配置的重试预算（config `auto_reconnect_max_attempts`；0 = 无限）。
    pub max_attempts: u32,
    /// 本次连接已执行的重试次数（per-connection，Connected 时清零；0 = 无）。
    pub current_attempt: u32,
    /// 重连尝试是否正在飞行中。
    pub active: bool,
}

/// win32 engine SCM 服务状态（proto `ServiceStatus`；S3/D5，仅状态展示，非授权材料——
/// 服务存在性不构成 capability，peer 身份只来自验证过的传输元数据 + PSK）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatus {
    /// 服务是否已在 SCM 注册。
    pub installed: bool,
    /// SCM 服务状态："stopped" | "start_pending" | "stop_pending" | "running" | "other"。
    pub state: String,
    /// SCM 二进制路径（含启动参数）；未安装时为空。
    pub binary_path: Option<String>,
    /// R3 统一服务健康状态："healthy" | "scm_orphan" | "installed_unavailable" |
    /// "payload_orphan" | "not_installed"；host 未派生时为空。
    pub health_state: Option<String>,
}

/// `KernelControl.ServiceControl` 的 UI 视图（proto `ServiceControlReply`；S3/D5）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceControlReply {
    /// action 执行后（或 query 时）的当前服务状态；`None` = 查询失败未获取。
    pub service_status: Option<ServiceStatus>,
    /// action 是否成功（query 恒 true；变更 action 反映提权子命令结果）。
    pub ok: bool,
    /// 人类可读结果/详情（无秘密、无栈）。
    pub message: String,
}

/// `KernelControl.ServiceControl` 的 action（S3/D5：query 非提权读；变更走 runas 提权 seam）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceControlAction {
    Query,
    Install,
    Uninstall,
    Start,
}

/// RuntimeSnapshot 的 UI 视图（mirror 自 proto RuntimeSnapshot）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSnapshot {
    pub runtime: RuntimeState,
    /// 单调 tick（WatchEvents resume 游标），0 表示未知。
    pub monotonic_tick: u64,
    /// 快照携带的最新归一化统计（stats-wire 方案 A：`GetSnapshot`/`WatchEvents`
    /// 随状态附带；`None` = 尚无样本，前端显示占位）。
    pub stats: Option<RuntimeStats>,
    /// 快照携带的上游代理 TUN 检测（C5-wire：`GetSnapshot`/`WatchEvents` 随状态附带；
    /// `None` = 未探测/探测失败，`detected` 区分「探测到无」与「未探测」）。
    pub proxy_tun: Option<ProxyTunDetection>,
    /// 本快照所属的 in-flight 连接/停止操作 id（R1 契约，mirror proto
    /// `RuntimeSnapshot.operation_id`；`Some(hex16)` = 有在途操作，`None` = 无）。
    /// 前端据此只让「当前用户操作」的事件驱动 UI（旧操作迟到事件不扰动显示）。
    pub operation_id: Option<String>,
    /// 快照携带的 win32 engine SCM 服务状态（S3/D5：`GetSnapshot`/`WatchEvents` 随状态
    /// 附带；`None` = 尚未查询/查询失败）。仅展示，非授权材料。
    pub service_status: Option<ServiceStatus>,
    /// 快照携带的当前连接模式（S3/D3：`"auto" | "service" | "oneshot"`）。只展示，
    /// 不做路由输入——路由决策在 core 侧（M3 决策表），无 `ConnectIntent.mode` 字段。
    pub mode: String,
    /// 快照携带的系统代理检测（S2：`GetSnapshot`/`WatchEvents` 随状态附带；
    /// `None` = 未检测/检测失败）。
    pub system_proxy: Option<SystemProxyDetection>,
    /// 快照携带的自动重连状态（S4：`GetSnapshot`/`WatchEvents` 随状态附带；
    /// `None` = 重连不适用/从未建立连接）。
    pub reconnect: Option<ReconnectStatus>,
}

/// 运行时事件类型（proto RuntimeEventKind）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEventKind {
    Snapshot,
    Transition,
}

/// WatchEvents 的增量事件（proto RuntimeEvent）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub monotonic_tick: u64,
    pub kind: RuntimeEventKind,
    pub snapshot: RuntimeSnapshot,
    /// 本事件所属操作 id（R1 契约，mirror proto `RuntimeEvent.operation_id`；
    /// `Some(hex16)` = 有在途操作，`None` = 无）。
    pub operation_id: Option<String>,
}

/// 一条操作回复（proto OperationReply 的 UI 视图）。
///
/// R1w 异步契约：core 的 Connect/Stop 先回 `pending`（终态走 status 通道），故
/// [`OperationResult`] 增加 `Pending` 分支——前端收到 pending = 「已受理，等待
/// `exv://status` 事件」，**不是失败**（修复盲清缺陷 B-F1 的配套）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum OperationResult {
    /// 操作已受理（异步）：终态/阶段经 `exv://status` 事件驱动。
    Pending,
    Succeeded {
        effect_id: Option<String>,
        authority_epoch: Option<u64>,
    },
    Failed {
        error: Option<VpnError>,
    },
}

/// Command（connect/stop/...）的统一回复形状。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationReply {
    pub result: OperationResult,
    /// 本命令所属操作 id（UI 侧组装 intent 时生成，随回复回传前端做事件关联；
    /// `Some(hex16)` = 已受理（host 以该 id 关联状态事件），`None` = 未产生/被拒）。
    pub operation_id: Option<String>,
}

// 便于前端直接消费的派生显示辅助：state 的展示名。
impl RuntimeState {
    /// 前端用于 badge/文案的稳定状态名（P4-a 前端展示辅助；当前前端按枚举原样渲染）。
    #[allow(dead_code)]
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Idle { .. } => "idle",
            Self::Connecting { .. } => "connecting",
            Self::AwaitingInteraction { .. } => "awaiting_interaction",
            Self::Connected { .. } => "connected",
            Self::Stopping { .. } => "stopping",
            Self::Reconciling { .. } => "reconciling",
            Self::FailedClean { .. } => "failed_clean",
            Self::FailedDirty { .. } => "failed_dirty",
        }
    }
}

impl ConnectPhase {
    /// proto 序号，供前端进度条。
    pub fn index(self) -> u8 {
        match self {
            Self::ObservingOwnedState => 0,
            Self::AcquiringPlatformLease => 1,
            Self::ConnectingControl => 2,
            Self::AwaitingInteraction => 3,
            Self::NegotiatingTunnel => 4,
            Self::ApplyingPlatformTunnel => 5,
            Self::AttachingPacketBoundary => 6,
            Self::StartingDataPlane => 7,
        }
    }

    /// 中文展示名（前端默认语言为中文；P4-a 展示辅助）。
    #[allow(dead_code)]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::ObservingOwnedState => "观察自有状态",
            Self::AcquiringPlatformLease => "获取平台租约",
            Self::ConnectingControl => "连接控制通道",
            Self::AwaitingInteraction => "等待交互确认",
            Self::NegotiatingTunnel => "协商隧道",
            Self::ApplyingPlatformTunnel => "应用平台隧道",
            Self::AttachingPacketBoundary => "挂接数据边界",
            Self::StartingDataPlane => "启动数据面",
        }
    }
}
