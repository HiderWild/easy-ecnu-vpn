// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core 侧 `KernelControl` gRPC 服务（面向 Tauri UI 的语义源，P1-c 骨架 + P3-b2 写路径
//! 接业务 + P3-c1 事件订阅/gate/GetSnapshot 源化/RespondInteraction/Reconcile 重试）。
//!
//! 实现 `exv_vpn_wire::generated::kernel_control_server::KernelControl` trait，持有唯一
//! host composition（`Arc<Mutex<HostComposition>>`）、共享 engine 控制面
//! （[`crate::grpc_control::KernelEngineControl`]）、凭据目录、共享日志聚合器
//! （[`crate::log_aggregator::LogAggregator`]，组合时与 `LogControlService` 共享 Arc）
//! 与 `WatchEvents` 事件总线（[`EventBus`]）。所有写 RPC 先经 `KernelControlGate` 授权
//! （fail closed），再接业务语义：
//!
//! - **Connect**：读 `config_dir`（`ExvConfig` + 独立 `key.bin`，P3-a）→ 解密 → 组装
//!   一次性 `secret_payload` → 构建 `ConnectRequest`（`secret_payload` 即 wire 副本）→
//!   经 engine `apply_connect` 派发（P3-b1 已落地 `ApplyTunnelRequest.secret_payload`，
//!   秘密随 wire 走）→ 发送后 [`crate::credential::zeroize_connect_secret`] 清零 wire
//!   副本。凭据失败路径由 `CredentialsBundle` 的 RAII 兜底零化，host 状态不变。
//! - **Stop**：组装完整 `StopIntent`（lookup_key/request_digest）→ engine `stop_tunnel`。
//! - **Reconcile**：组装完整重试意图（lookup_key/request_digest，key.method 必须为
//!   RECONCILE）→ engine `get_operation` 观察当前义务 disposition；义务未终局时按
//!   [`reconcile_retry_plan`] 决策重试并经 `retry_obligation` seam 派发（engine 义务
//!   模型未在冻结 wire 上，真实重试 seam 当前返回 typed `Unimplemented`，已标注）。
//! - **GetSnapshot**：P3-c1 源化——先经 engine `ObserveOwnedState` 拉真实快照，engine
//!   无真实数据（Idle 占位）时回落 composition 派生的确定性快照（`prefer_snapshot`）。
//! - **GetOperation**：路由到 engine `GetOperation`（义务/操作 disposition 真实读取）。
//! - **RespondInteraction**：校验 interaction_id/runtime_epoch 后经 seam 转发 engine
//!   （engine 冻结 wire 无 interaction RPC，真实实现返回 typed `Unimplemented`，P5 补）。
//! - **WatchEvents**：P3-c1 真实订阅——[`EventBus`] 维护严格递增 tick、最新快照与多
//!   订阅者 fan-out；[`KernelControlService::spawn_status_forwarder`] 订阅 engine 独立
//!   状态流（`stream_connect_status` seam，真实通道 = `StreamConnectStatus`，R1w——
//!   **日志已退役为纯输出，绝不回流状态**）驱动 composition 状态机并归一化为
//!   `RuntimeEvent` 发布（增量 tick / 过渡事件 / 断线重放）。
//! - **统计 lane（P5-b）**：[`EventBus`] 另持统计 lane（与 wire 事件 lane 共存）；
//!   [`KernelControlService::spawn_stats_forwarder`] 订阅 engine `StreamStats` 流
//!   （`stream_stats` seam）经 [`crate::stats::TrafficSample`] 以累计字节增量归一化
//!   速度（权威口径）后 [`EventBus::publish_stats`] 发布。wire proto 冻结——统计为
//!   host 侧数据，UI 侧 P5-c 消费。

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::{Mutex, watch};
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Code, Request, Response, Status};
use uuid::Uuid;

use sha2::{Digest, Sha256};

use exv_engine::service::{SERVICE_CONTROL_PIPE, SERVICE_NAME};
use exv_engine::service_batch::{
    BatchStep, ServiceBatchRequest, ServiceBatchResult, MAX_REQUEST_BYTES,
};
use exv_vpn_data_plane::teardown::TeardownSide;
use exv_vpn_domain::error::VpnError;
use exv_vpn_domain::identity::{ConnectionBindingDigest, OperationMethod, PrincipalDigest};
use exv_vpn_domain::ports::{AuthorityEpoch, MonotonicTick};
use exv_vpn_resource::authority::{
    ConnectionBinding, PeerCapability, PeerContext, VerifiedConnectionMetadata,
};
use exv_vpn_win32_config::ExvConfig;
use exv_vpn_win32_ipc::peer_auth::{SYSTEM_SID, VerifiedPipePeer, current_user_sid};
use exv_vpn_win32_ipc::pipe_security::PipeSecurity;
use exv_vpn_win32_ipc::service_key::read_service_psk;
use exv_vpn_win32_resource::native_error::NativeError;
use exv_vpn_win32_resource::proxy_tun::{self, ProxyTunDetection};
use exv_vpn_win32_resource::system_proxy::{self, SystemProxyMode, SystemProxySnapshot, TopologyKind};
use exv_vpn_wire::generated::kernel_control_server::{KernelControl, KernelControlServer};
use windows::Win32::Foundation::{CloseHandle, GENERIC_WRITE};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SetFileSecurityW,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, WriteFile, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
};
use exv_vpn_wire::generated::{
    self as wire, ApplyTunnelReply, ApplyTunnelRequest, ConfigGetRequest, ConfigItem,
    ConfigPayload, ConfigReply, ConfigSetRequest, ConnectPhase, ConnectRequest,
    GetKernelOperationRequest, GetOperationRequest, InteractionResponse, KernelOperationReply,
    LogsClearReply, LogsClearRequest, LogsListReply, LogsListRequest, ObserveOwnedStateRequest,
    OperationReply, OperationState, ReconcileRequest, RuntimeEvent, RuntimeSnapshot,
    ServiceControlReply, ServiceControlRequest, ServiceSelfReport, SnapshotRequest, StopRequest,
    StopTunnelRequest, WatchEventsRequest, service_control_request,
};

use crate::composition::{HostComposition, HostEffect, HostEvent, HostPhase};
use crate::credential::{build_connect_request, load_credentials, zeroize_connect_secret};
use crate::engine_lifecycle::EngineSlot;
use crate::grpc_control::{
    EngineStatusEvent, GrpcClientError,
    KernelEngineControl,
};
use crate::kernel_control::ClearableSecret;
use crate::log_aggregator::LogAggregator;
use crate::process_lifecycle::{
    ENGINE_ADAPTER_NAME, EngineChild, engine_bin_path, spawn_engine_elevated,
};
use crate::service_status::{
    HealthState, RealServiceStatusSource, ServiceState, ServiceStatusSnapshot, ServiceStatusSource,
    derive_health, derive_health_with_self_report, query_service_status,
    service_health_from_snapshot,
};
use crate::stats::{RuntimeStats, TrafficSample, normalize_stats};

/// `KernelControl` 服务。
///
/// 持有唯一的 host composition、共享 engine 控制面（写路径派发；测试注入 fake）、
/// 凭据目录、共享日志聚合器与 `WatchEvents` 事件总线（[`EventBus`]）。构造为
/// [`KernelControlServer`] 后即可挂到 tonic `Server`。
///
/// `Clone` = 轻量共享句柄：所有字段为 `Arc`/`Copy`/克隆，克隆体与本体共享同一内部
/// 状态（C3a 重连 worker 持一个克隆调用 `run_connect`/路由等 `&self` 方法）。
#[derive(Clone)]
pub struct KernelControlService {
    /// 唯一的 host composition（写路径经 gate；读路径查 phase）。
    composition: Arc<Mutex<HostComposition>>,
    /// 共享 engine 控制面槽（P3 崩溃自愈换点；写路径派发经 [`EngineSlot::current`]
    /// 取当前 engine——respawn 换入新 client 后写路径自动指向新 engine）。
    engine: EngineSlot,
    /// Core 启动时的初始 oneshot engine。service 路由换入 service client 后仍保留此
    /// 引用，卸载服务后可在同一 Core 生命周期内恢复一次性连接路径。
    oneshot_engine: Arc<tokio::sync::Mutex<dyn KernelEngineControl>>,
    /// 凭据目录（测试可注入；产品默认目录由 `ExvConfig::load()` 语义给出）。
    config_dir: PathBuf,
    /// 共享日志聚合器（组合时与 `LogControlService` 共享 Arc；写路径产出 core 事件）。
    logs: Arc<LogAggregator>,
    /// `WatchEvents` 事件总线（P3-c1 真实订阅；engine 转发器发布，UI 订阅）。
    events: Arc<EventBus>,
    /// C5-wire：上游 proxy TUN 检测探针（默认真实枚举；测试注入确定性结果）。
    proxy_tun_probe: ProxyTunProbe,
    /// EXV_UNFREEZE 系统代理感知：系统代理探测探针（默认真实 WinINET 注册表捕获 +
    /// 拓扑分类；测试注入确定性结果）。
    system_proxy_probe: SystemProxyProbe,
    /// R1 attach-before-apply 就绪信号：`spawn_status_forwarder` 成功挂接
    /// `StreamConnectStatus` 后置 `true`；connect/stop 写路径派发前 await（硬约束——
    /// engine `StatusPublisher` 无快照、open 前事件丢弃）。
    status_ready: watch::Sender<bool>,
    /// R3-C1 `await_status_ready` 的有界等待上界（默认 [`STATUS_READY_WAIT`]；测试
    /// 注入短时长验证不悬挂语义——引擎永久不可达时不永久悬挂，放行派发报真实错误）。
    status_ready_wait: Duration,
    /// S3/D5：非提权 SCM 服务状态源（默认真实 `OpenSCManagerW`；测试注入确定性结果）。
    service_status_source: Arc<dyn ServiceStatusSource>,
    /// S3/D4：服务变更操作 seam（install/uninstall/start/stop——engine 子命令 runas；
    /// 测试注入 fake 记录语义）。
    service_ops: Arc<dyn ServiceControlOps>,
    /// S3/D3：service engine 连接 seam（真实实现 = 读 PSK + 拨号稳定服务管道 +
    /// SID-only 验证 + PSK-HMAC 挑战 + 返回客户端；测试注入 fake 换入 fake engine，
    /// 避免单测依赖真实 PSK 文件与服务管道）。
    service_connector: Arc<dyn ServiceEngineConnector>,
    /// R2：keepalive 就绪探活 seam（服务 Start 后 `wait_for_service_ready` 用；默认 =
    /// [`RealServiceProbe`]，测试注入 fake 返回确定性结果）。
    service_probe: Arc<dyn ServiceProbe>,
    /// R2：服务就绪轮询上界（默认 [`SERVICE_READY_TIMEOUT`]；测试注入短时长）。
    service_ready_timeout: Duration,
    /// R2：服务就绪轮询间隔（默认 [`SERVICE_READY_POLL`]；测试注入短间隔）。
    service_ready_poll: Duration,
    /// S3/D3：最近一次连接路由的实际模式（0=auto / 1=service / 2=oneshot；快照 `mode`
    /// 展示用，缺省 auto）。
    selected_mode: Arc<AtomicU8>,
    /// S3/D5：`DeleteService` 成功后的语义状态覆盖。
    ///
    /// Windows SCM 在删除成功后可能短暂保留 marked-for-delete 条目；在这段窗口内
    /// `OpenServiceW` 仍可能成功。Core 已经完成删除事务时，不能把这个中间 SCM 事实
    /// 再回传成"已安装"，否则 UI 会显示 completed 但仍提供卸载按钮。
    service_removed_override: Arc<AtomicBool>,
    /// 服务生命周期变更串行门，防止重复点击/并发 RPC 交叉执行 stop、install、uninstall。
    service_control_lock: Arc<tokio::sync::Mutex<()>>,
    /// C3a 自动重连：per-connection 重连尝试计数（每次自动重连派发递增；Connected 成功
    /// 后由状态转发器清零；`auto_reconnect_max_attempts` 耗尽即停止）。
    reconnect_attempts: Arc<AtomicU32>,
    /// C3a 自动重连：单次重连尝试在途标记（worker 派发后置 true；终态事件（Connected/
    /// Failed/Stopped）由状态转发器清 false——在途期间新的可重试掉线不重复触发，防重入）。
    reconnect_active: Arc<AtomicBool>,
    /// C3a 自动重连：状态转发器 → 重连 worker 的触发通道发送端（engine 掉线事件为
    /// 触发源；worker 拉起时换入自己的发送端并串行消费——天然杜绝并发重连；未拉起
    /// worker 时 `None`，信号被丢弃）。
    reconnect_tx: Arc<std::sync::Mutex<Option<mpsc::UnboundedSender<()>>>>,
}

/// `WatchEvents` 的 server-streaming 返回类型（P3-c1：真实订阅流，非单事件骨架）。
type WatchEventsStream = Pin<Box<dyn Stream<Item = Result<RuntimeEvent, Status>> + Send>>;

/// C5-wire：可注入的上游 proxy TUN 检测探针（默认真实 `GetAdaptersAddresses` 枚举；
/// 单测注入确定性结果，避免依赖真实 Win32 适配器状态）。
type ProxyTunProbe = Arc<dyn Fn() -> Result<ProxyTunDetection, NativeError> + Send + Sync>;

/// 默认真实探针：以 EXV 引擎适配器名（`ExvEngine`）为排除基准检测上游 proxy TUN。
fn default_proxy_tun_probe() -> ProxyTunProbe {
    Arc::new(|| proxy_tun::detect_upstream_proxy_tun(ENGINE_ADAPTER_NAME))
}

/// EXV_UNFREEZE 系统代理感知：可注入的系统代理探测探针（默认真实 WinINET 注册表
/// 捕获 + 拓扑分类；单测注入确定性结果，避免依赖真实注册表状态）。返回完整的
/// wire [`SystemProxyDetection`]（mode / endpoint_count / bypass_merged / 四态 topology）。
type SystemProxyProbe =
    Arc<dyn Fn() -> Result<wire::SystemProxyDetection, NativeError> + Send + Sync>;

/// 默认真实探针：当前进程用户 SID → `capture_for_user`（`HKU\<sid>\…\Internet Settings`
/// 五原始值）→ `snapshot_from_raw`（规范化快照）→ 转 wire。
///
/// 拓扑是 `(proxy_present, tunnel_present)` 的纯函数分类（设计 §2）；TUN 维度复用
/// `proxy_tun::detect_upstream_proxy_tun` 同源探测（与 proxy TUN 探针同一排除基准；
/// 探测失败按「无 TUN」保守处理，拓扑退 T0/T1 不虚报）。探测/解析失败 → typed 错误，
/// 由刷新点按 `None` 处理（状态上报不因探测失败而失败）。
fn default_system_proxy_probe() -> SystemProxyProbe {
    Arc::new(|| {
        let sid = current_user_sid().ok_or_else(|| {
            NativeError::from_win32(0, "当前进程用户 SID 不可解析（系统代理探测）")
        })?;
        let raw = system_proxy::capture_for_user(&sid)?;
        let snapshot = system_proxy::snapshot_from_raw(&raw)?;
        let tunnel_present = proxy_tun::detect_upstream_proxy_tun(ENGINE_ADAPTER_NAME)
            .map(|d| d.detected)
            .unwrap_or(false);
        Ok(system_proxy_snapshot_to_wire(&snapshot, tunnel_present))
    })
}

/// S3/D3 + M3：auto 决策表（core 侧路由连接）。服务 bootstrap 由 Core 统一维护，
/// 因此 `connect` 可在已安装但 stopped 时自动拉起服务。
///
/// 三态：
/// - 已装 + 在跑 → [`RouteDecision::Service`]（连接服务 engine）；
/// - 已装 + 未跑 → [`RouteDecision::PromptStart`]（需要 Core bootstrap 服务）；
/// - 未装 → [`RouteDecision::Oneshot`]（维持既有 oneshot 路径）。
/// 连接路由决策收编于 [`crate::guards`]（正交守卫层）——`RouteDecision`/`decide_route`
/// 单一权威，本模块 re-export 保持既有调用点与测试不变。
pub use crate::guards::{decide_route, RouteDecision, ServiceMode};

// ---------------------------------------------------------------------------
// R2：keepalive 就绪探活（服务 Start 后判定 engine 是否业务就绪；SCM running 或
// keepalive 回复先到先采纳，不死等 SCM）。
// ---------------------------------------------------------------------------

/// R2 默认服务就绪等待上界（`wait_for_service_ready`；服务 Start 后探活）。
pub const SERVICE_READY_TIMEOUT: Duration = Duration::from_secs(15);
/// R2 默认服务就绪轮询间隔。
///
/// SCM 查询是非提权的廉价本地调用；100ms 能把"服务已在 services.msc 出现/进入
/// Running"与 UI 反馈之间的观察窗口压到亚秒级，同时仍由 `SERVICE_READY_TIMEOUT`
/// 提供失败上界。
pub const SERVICE_READY_POLL: Duration = Duration::from_millis(100);
/// R2 单次 keepalive 探活 RPC 超时上界（`RealServiceProbe`）。
pub const SERVICE_PROBE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

/// R2 就绪达成来源（`ServiceReadiness.source`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessSource {
    /// SCM 报告 Running（先到先采纳的「SCM 先到」分支）。
    Scm,
    /// keepalive 探活已回复（先到先采纳的「keepalive 先到」分支）。
    Keepalive,
    /// 有界轮询到期，两者都未达成。
    Timeout,
}

/// R2 服务就绪判定结果（`wait_for_service_ready` 的产出；`ServiceControlReply` 的输入）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceReadiness {
    /// engine 是否业务就绪。
    pub ready: bool,
    /// 达成 / 失败来源（`ready=false` 时恒为 `Timeout`）。
    pub source: ReadinessSource,
    /// 轮询期间最后一次 SCM 状态（`None` = SCM 查询失败 / 未查到）。
    pub scm_state: Option<ServiceState>,
    /// 是否曾收到 keepalive 回复。
    pub keepalive: bool,
    /// 轮询经过的毫秒数。
    pub elapsed_ms: u64,
}

/// R2 keepalive 就绪探活 seam（测试注入 fake 返回确定性结果；产品 =
/// [`RealServiceProbe`]）。
#[tonic::async_trait]
pub trait ServiceProbe: Send + Sync {
    /// 执行一次 keepalive 探活：`true` = engine 已回复（业务就绪）。
    async fn probe(&self) -> bool;

    /// S3-B：执行一次 ServiceManage.query 深度自述探活（Tier 2 零 UAC 通道，健康加深的
    /// 源）。返回 engine 自述报告；`None` = 探针失败/未达成（拨号/PSK/超时/RPC 拒绝）——
    /// **保守保留 SCM 派生**，不把探针失败当引擎失败。
    async fn probe_self_report(&self) -> Option<ServiceSelfReport>;
}

/// 真实探活：读 `%ProgramData%\exv\service.key` → 拨号稳定服务管道 → 一条 `KeepAlive` RPC。
///
/// `true` = keepalive 已回复。PSK 不可读 / 拨号失败 / RPC 失败 / 超时 → `false`（本次
/// 探活未达成，由轮询下一拍重试——服务刚启动未绑管道的竞窗由
/// [`probe_service_engine`](crate::grpc_control::probe_service_engine) 内部的有界重试覆盖）。
pub struct RealServiceProbe;

#[tonic::async_trait]
impl ServiceProbe for RealServiceProbe {
    async fn probe(&self) -> bool {
        let Ok(psk) = read_service_psk() else {
            return false;
        };
        crate::grpc_control::probe_service_engine(
            SERVICE_CONTROL_PIPE,
            SYSTEM_SID,
            &psk,
            SERVICE_PROBE_ATTEMPT_TIMEOUT,
        )
        .await
        .is_ok()
    }

    async fn probe_self_report(&self) -> Option<ServiceSelfReport> {
        // 复用 keepalive 探活的同一通道（`SERVICE_CONTROL_PIPE` + `SYSTEM_SID` + PSK +
        // `SERVICE_PROBE_ATTEMPT_TIMEOUT`）；失败保守（`query_service_self` 内部不抛错）。
        let psk = read_service_psk().ok()?;
        crate::grpc_control::query_service_self(
            SERVICE_CONTROL_PIPE,
            SYSTEM_SID,
            &psk,
            SERVICE_PROBE_ATTEMPT_TIMEOUT,
        )
        .await
    }
}

/// R2 服务就绪判定：SCM running **或** keepalive 回复，先到先采纳；有界轮询。
///
/// 每拍先查询 SCM（廉价、非提权）；未 Running 时执行一次 keepalive 探活；两者任一达成
/// 即返回 `ready=true`（`source` 标注达成方）。单次探活不会占住整个 3s 的底层拨号
/// 重试：外层以一个轮询拍长为上界，超时后立即回到 SCM 查询，避免服务已经出现在
/// services.msc 但 Core 仍被一条旧拨号等待拖住。`timeout` 到期仍未达成 → `ready=false`
/// （`source=Timeout`，携带最后一次 SCM 状态与探活事实，供调用方构造可读信息）。
pub async fn wait_for_service_ready(
    source: &dyn ServiceStatusSource,
    probe: &dyn ServiceProbe,
    timeout: Duration,
    poll_interval: Duration,
) -> ServiceReadiness {
    let start = std::time::Instant::now();
    let mut scm_state: Option<ServiceState> = None;
    let mut keepalive = false;
    loop {
        let elapsed = start.elapsed();
        // 每拍先查 SCM（廉价、非提权）：Running 即采纳（SCM 先到）。
        if let Ok(snap) = query_service_status(source, SERVICE_NAME) {
            scm_state = Some(snap.state);
            if snap.state == ServiceState::Running {
                return ServiceReadiness {
                    ready: true,
                    source: ReadinessSource::Scm,
                    scm_state,
                    keepalive,
                    elapsed_ms: elapsed.as_millis() as u64,
                };
            }
        }
        // SCM 未 Running → 执行一次 keepalive 探活（服务已起但 SCM 未报 Running 时
        // 探活先行——keepalive 先到先采纳）。
        let probe_deadline = poll_interval
            .max(Duration::from_millis(1))
            .min(SERVICE_PROBE_ATTEMPT_TIMEOUT);
        if tokio::time::timeout(probe_deadline, probe.probe())
            .await
            .unwrap_or(false)
        {
            keepalive = true;
            return ServiceReadiness {
                ready: true,
                source: ReadinessSource::Keepalive,
                scm_state,
                keepalive,
                elapsed_ms: elapsed.as_millis() as u64,
            };
        }
        if elapsed >= timeout {
            return ServiceReadiness {
                ready: false,
                source: ReadinessSource::Timeout,
                scm_state,
                keepalive,
                elapsed_ms: elapsed.as_millis() as u64,
            };
        }
        tokio::time::sleep(poll_interval).await;
    }
}

/// S3/D4：服务变更操作 seam（install/uninstall/start/stop）。
///
/// 真实实现 = engine 子命令经 runas 提权（D4：host 非提权，SCM 操作在 engine 内）；
/// 测试注入 fake 记录调用并返回确定性结果。
#[tonic::async_trait]
pub trait ServiceControlOps: Send + Sync {
    /// 安装/修复 engine SCM 服务（重装轮换 PSK，M14）。
    async fn install(&self) -> Result<String, String>;
    /// 卸载 engine SCM 服务。
    async fn uninstall(&self) -> Result<String, String>;
    /// 启动 engine SCM 服务。
    async fn start(&self) -> Result<String, String>;
}

/// 真实服务操作：以 runas 提权拉起 engine 批量执行完整服务操作序列并等待退出
///（D4 边界——host 非提权，engine 是唯一特权进程；一次 runas = 1 次 UAC，S2-B）。
pub struct EngineSubcommandServiceOps {
    /// 批量提权 spawn（生产 = ShellExecuteExW runas；测试注入 fake 记录请求并写回结果）。
    spawn: Arc<dyn ServiceBatchSpawn>,
}

impl EngineSubcommandServiceOps {
    /// 真实批量 spawner（ShellExecuteExW runas）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            spawn: Arc::new(RealServiceBatchSpawn),
        }
    }
}

impl Default for EngineSubcommandServiceOps {
    fn default() -> Self {
        Self::new()
    }
}

#[tonic::async_trait]
impl ServiceControlOps for EngineSubcommandServiceOps {
    async fn install(&self) -> Result<String, String> {
        // 安装/修复 = 一次 runas 完成 [Install,Start,Verify]（含 REPAIR + SCM 启动 +
        // keepalive 探活）。config_dir 经批量请求 JSON 传递（engine `RealServiceOps`
        // 从请求读并写入 SCM 启动参数）。
        run_service_batch(
            vec![BatchStep::Install, BatchStep::Start, BatchStep::Verify],
            self.spawn.as_ref(),
        )
        .await
    }
    async fn uninstall(&self) -> Result<String, String> {
        run_service_batch(
            vec![BatchStep::Uninstall, BatchStep::VerifyRemoved],
            self.spawn.as_ref(),
        )
        .await
    }
    async fn start(&self) -> Result<String, String> {
        run_service_batch(vec![BatchStep::Start, BatchStep::Verify], self.spawn.as_ref()).await
    }
}

/// 批量提权 spawn seam（生产 = ShellExecuteExW runas；测试注入 fake 记录请求并模拟结果）。
///
/// 返回 `Ok(exit_code)` = 引擎进程已退出（0=ok，非零=fail）；`Err` = 提权 spawn 失败 /
/// 等待超时（调用方按其语义报失败）。
#[tonic::async_trait]
pub trait ServiceBatchSpawn: Send + Sync {
    /// 提权拉起 engine 执行 `--service-batch` 并等待退出，返回退出码。
    ///
    /// # Errors
    /// 提权 spawn 失败 / 超时 → 携带原因的字符串。
    async fn spawn_batch(&self, exe: &Path, args: &[String]) -> Result<i32, String>;
}

/// 批量等待上界（计划文档阶段 2：`SendChild::wait_exit_code(60_000)`）。
const SERVICE_BATCH_TIMEOUT_MS: u32 = 60_000;

/// 真实批量 spawner：`ShellExecuteExW(runas)` 提权拉起 engine `--service-batch`（1 次
/// UAC），有界等待退出（60s）。
pub struct RealServiceBatchSpawn;

#[tonic::async_trait]
impl ServiceBatchSpawn for RealServiceBatchSpawn {
    async fn spawn_batch(&self, exe: &Path, args: &[String]) -> Result<i32, String> {
        let (pid, handle) = spawn_engine_elevated(exe, args)?;
        // EngineChild 含 HANDLE（`*mut c_void`，非 Send）——经 SendChild 移入
        // spawn_blocking（等待/终止/关闭在闭包线程内串行，无并发关闭；镜像原
        // run_service_subcommand 的同一模式）。
        let child = SendChild(EngineChild::new(pid, handle));
        // 必须经方法调用触发 whole-struct 捕获——`move || child.0.wait_exit_code(...)`
        // 的 disjoint capture 会捕获 `child.0`（EngineChild，非 Send），绕过 SendChild
        // 的 Send impl（镜像 engine_lifecycle `WaitHandle` 的同一陷阱）。
        let exit_code = tokio::task::spawn_blocking(move || child.wait_exit_code(SERVICE_BATCH_TIMEOUT_MS))
            .await
            .map_err(|e| format!("service batch join: {e}"))?;
        exit_code.ok_or_else(|| format!("service batch timed out after {SERVICE_BATCH_TIMEOUT_MS}ms"))
    }
}

/// 批量临时文件清理：host 无论成功/失败都删除 req/res（engine 消费 req 后自删，
/// result 是 host 交付结果的唯一通道——读毕由 host 删；spawn 失败时 req 也可能残留）。
struct BatchFileCleanup<'a> {
    request: &'a Path,
    result: &'a Path,
}

impl Drop for BatchFileCleanup<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.request);
        let _ = std::fs::remove_file(self.result);
    }
}

/// 一次 runas 拉起 engine 批量执行完整服务操作序列（1 次 UAC）。
///
/// 经临时文件传请求/收结果（ShellExecuteExW 无 stdio，计划文档阶段 2）：
/// - **req 文件**：随机 uuid 文件名 + DACL（SYSTEM + 当前用户 SID，复用
///   [`PipeSecurity`] 冻结形状，随 `CreateFileW` 生效并保护继承）；
/// - engine 读 req → 执行 → 写 result → **finally 删 req**；result 文件保留——它是
///   ShellExecuteExW（无 stdio）下向 host 交付结果的唯一通道；
/// - host 在 `wait_exit_code` 后读 result、校验 JSON 形状（`deny_unknown_fields`）、
///   由 host 删除。
///
/// 语义映射：`result.ok && exit == 0` → 成功；否则失败（message 透传）。`--host-pid`
/// 携带自身 pid（孤儿 watchdog 接线由 S2-C 集成测试处理）。
///
/// # Errors
/// bin 缺失 / 请求写入或 DACL 失败 / spawn 失败或超时 / result 缺失或形状非法 /
/// 引擎报告失败 → 携带原因的字符串。
async fn run_service_batch(
    steps: Vec<BatchStep>,
    spawn: &dyn ServiceBatchSpawn,
) -> Result<String, String> {
    let request = ServiceBatchRequest {
        version: 1,
        sequence: steps,
        config_dir: exv_vpn_win32_config::config_dir()
            .to_string_lossy()
            .into_owned(),
    };
    let dir = std::env::temp_dir();
    let req = dir.join(format!("exv-batch-req-{}.json", Uuid::new_v4().simple()));
    let res = dir.join(format!("exv-batch-res-{}.json", Uuid::new_v4().simple()));
    write_batch_request_file(&req, &request)?;
    let _cleanup = BatchFileCleanup {
        request: &req,
        result: &res,
    };
    let exe = engine_bin_path().ok_or_else(|| "engine bin not found".to_string())?;
    let args = vec![
        "--service-batch".to_string(),
        "--request".to_string(),
        req.display().to_string(),
        "--result".to_string(),
        res.display().to_string(),
        "--host-pid".to_string(),
        std::process::id().to_string(),
    ];
    let t0 = Instant::now();
    let exit_code = spawn.spawn_batch(&exe, &args).await?;
    let spawn_elapsed_ms = t0.elapsed().as_millis();
    let result = read_batch_result_file(&res)?;
    let total_elapsed_ms = t0.elapsed().as_millis();
    eprintln!("[exv-host-batch] spawn+wait: steps={:?} exit={} spawn={}ms total={}ms", request.sequence, exit_code, spawn_elapsed_ms, total_elapsed_ms);
    if result.ok && exit_code == 0 {
        Ok(result.message)
    } else {
        Err(result.message)
    }
}

/// 写批量请求文件（随机 uuid 路径；DACL = SYSTEM + 当前用户 SID）。
///
/// DACL 复用 [`PipeSecurity`] 冻结形状（WSP1 §4：`D:(A;;GA;;;SY)(A;;GA;;;<user>)`），
/// 随 `CreateFileW` 的 `SECURITY_ATTRIBUTES` 在创建时生效（镜像
/// `write_service_psk` 的文件 DACL 模式）。`CreateFileW` 只复制 descriptor 的显式 DACL，
/// 父目录（temp）的可继承 ACE 仍会合并进来——再用 `SetFileSecurityW` +
/// `PROTECTED_DACL_SECURITY_INFORMATION` 去掉继承 ACE，使文件 DACL 恰为
/// SYSTEM + 当前用户（其余拒绝），且在任何内容写入前完成。
///
/// # Errors
/// 当前用户 SID 不可得 / DACL 构造失败 / `CreateFileW` / `SetFileSecurityW` /
/// `WriteFile` 失败 → 携带原因的字符串。
fn write_batch_request_file(path: &Path, request: &ServiceBatchRequest) -> Result<(), String> {
    let json = serde_json::to_vec(request).map_err(|e| format!("serialize batch request: {e}"))?;
    if json.len() > MAX_REQUEST_BYTES {
        return Err(format!("batch request exceeds {MAX_REQUEST_BYTES} bytes"));
    }
    let sid = current_user_sid().ok_or_else(|| "current user SID unavailable".to_string())?;
    let security = PipeSecurity::new(&sid, true)
        .map_err(|code| format!("batch request DACL build failed (code {code})"))?;
    let attributes = security.as_attributes();
    let wide: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `wide` 是活的 NUL 结尾宽字符串；`attributes` 是活 `SECURITY_ATTRIBUTES`，
    // 其 `lpSecurityDescriptor` 指向 `security` 拥有的活 descriptor（同作用域存活）。
    let handle = unsafe {
        CreateFileW(
            windows::core::PCWSTR(wide.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_READ,
            Some(&raw const attributes as *const _),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| format!("create batch request file {}: {e}", path.display()))?;
    // 保护 DACL 不受父目录继承（见函数注释）。descriptor 来自 PipeSecurity（活于本作用域）。
    // SAFETY: `wide` 仍存活；`PSECURITY_DESCRIPTOR` 指向 `security` 拥有的活 descriptor。
    let protect = unsafe {
        SetFileSecurityW(
            windows::core::PCWSTR(wide.as_ptr()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR(attributes.lpSecurityDescriptor),
        )
    };
    if !protect.as_bool() {
        // SAFETY: 无指针参数，读线程错误码。
        let code = unsafe { windows::Win32::Foundation::GetLastError().0 };
        // SAFETY: `handle` 是已打开句柄，使用后关闭。
        unsafe {
            let _ = CloseHandle(handle);
        }
        return Err(format!("protect batch request DACL failed (code {code})"));
    }
    let result = write_all_to_handle(handle, &json);
    // SAFETY: `handle` 是 `CreateFileW` 返回的已打开句柄，使用后关闭。
    unsafe {
        let _ = CloseHandle(handle);
    }
    result.map_err(|e| format!("write batch request {}: {e}", path.display()))
}

/// 一次性写满 `buf` 到句柄（`WriteFile`；短写视为失败——请求必须完整落盘）。
fn write_all_to_handle(
    handle: windows::Win32::Foundation::HANDLE,
    buf: &[u8],
) -> Result<(), String> {
    let mut written = 0u32;
    // SAFETY: handle 是已打开可写句柄；written 是活 out-param。
    unsafe {
        WriteFile(handle, Some(buf), Some(&raw mut written), None)
    }
    .map_err(|e| format!("write batch request: {e}"))?;
    if written as usize != buf.len() {
        return Err(format!(
            "short write: wrote {written}, expected {}",
            buf.len()
        ));
    }
    Ok(())
}

/// 读批量结果文件并校验 JSON 形状（`deny_unknown_fields`——旧字段/拼写错误在解析即拒）。
///
/// # Errors
/// 文件缺失 / 读取失败 / 形状非法 → 携带原因的字符串。
fn read_batch_result_file(path: &Path) -> Result<ServiceBatchResult, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("read batch result {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("batch result malformed: {e}"))
}

/// `EngineChild`（含 `windows` HANDLE）的 Send 封装：进程句柄是独立句柄值，可跨线程
/// `WaitForSingleObject`/`CloseHandle`——等待/终止/关闭在同一闭包线程串行完成，无并发
/// 关闭。镜像 `engine_lifecycle` 的 `WaitHandle` 模式。
struct SendChild(EngineChild);

impl SendChild {
    /// 有界等待子进程退出（whole-struct 方法——disjoint capture 绕过 Send impl）。
    fn wait_exit(mut self, timeout_ms: u32) -> bool {
        self.0.wait_exit(timeout_ms)
    }

    /// 有界等待子进程退出并读取退出码（`Some(code)`=已退出；`None`=超时）。
    fn wait_exit_code(mut self, timeout_ms: u32) -> Option<i32> {
        self.0.wait_exit_code(timeout_ms)
    }
}
// SAFETY: 句柄操作（wait_exit/terminate/Drop）在单一线程内串行；句柄值本身跨线程安全。
unsafe impl Send for SendChild {}

/// S3/D3：service engine 连接 seam（真实实现 = 读 PSK + 拨号稳定服务管道 + SID-only 验证
/// + PSK-HMAC 双向挑战 + 返回客户端；测试注入 fake 换入 fake engine）。
#[tonic::async_trait]
pub trait ServiceEngineConnector: Send + Sync {
    /// 连接 service-mode engine 并返回控制面客户端（后续写路径经 [`EngineSlot`] 换入）。
    ///
    /// # Errors
    /// 用户 SID / PSK 不可读 / 拨号 / 认证 / channel 构建失败 → 携带原因的字符串。
    async fn connect_service_engine(
        &self,
    ) -> Result<Arc<tokio::sync::Mutex<dyn KernelEngineControl>>, String>;
}

/// 真实 service engine 连接器（S3/D2/D7/S6）：读 `%ProgramData%\exv\service.key` → 拨号
/// 稳定服务管道 → engine 自报身份验证（**服务 engine 以 LocalSystem 运行 → 期望 SID 是
/// [`SYSTEM_SID`]**，非安装用户；S6 起改验 engine 自报身份，不再 `OpenProcess` 读 SYSTEM
/// 进程）+ PSK-HMAC 双向挑战 → 客户端。仅 Service 分支调用（幂等性由调用方保证）。
pub struct RealServiceEngineConnector;

#[tonic::async_trait]
impl ServiceEngineConnector for RealServiceEngineConnector {
    async fn connect_service_engine(
        &self,
    ) -> Result<Arc<tokio::sync::Mutex<dyn KernelEngineControl>>, String> {
        let psk = read_service_psk()?;
        let client = crate::grpc_control::EngineControlGrpcClient::connect_service(
            SERVICE_CONTROL_PIPE,
            SYSTEM_SID,
            &psk,
        )
        .await
        .map_err(|e| format!("service engine connect failed: {e:?}"))?;
        Ok(Arc::new(tokio::sync::Mutex::new(client)))
    }
}

impl KernelControlService {
    /// 构造服务：composition + engine 控制面 + 凭据目录 + 共享日志聚合器 + 事件总线。
    #[must_use]
    pub fn new(
        composition: Arc<Mutex<HostComposition>>,
        engine: EngineSlot,
        config_dir: PathBuf,
        logs: Arc<LogAggregator>,
    ) -> Self {
        let (status_ready, _) = watch::channel(false);
        let oneshot_engine = engine.initial();
        Self {
            composition,
            engine,
            oneshot_engine,
            config_dir,
            logs,
            events: Arc::new(EventBus::new()),
            proxy_tun_probe: default_proxy_tun_probe(),
            system_proxy_probe: default_system_proxy_probe(),
            status_ready,
            status_ready_wait: STATUS_READY_WAIT,
            service_status_source: Arc::new(RealServiceStatusSource),
            service_ops: Arc::new(EngineSubcommandServiceOps::new()),
            service_connector: Arc::new(RealServiceEngineConnector),
            service_probe: Arc::new(RealServiceProbe),
            service_ready_timeout: SERVICE_READY_TIMEOUT,
            service_ready_poll: SERVICE_READY_POLL,
            selected_mode: Arc::new(AtomicU8::new(ServiceMode::Auto.as_u8())),
            service_removed_override: Arc::new(AtomicBool::new(false)),
            service_control_lock: Arc::new(tokio::sync::Mutex::new(())),
            reconnect_attempts: Arc::new(AtomicU32::new(0)),
            reconnect_active: Arc::new(AtomicBool::new(false)),
            reconnect_tx: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// 注入非提权 SCM 服务状态源（S3/D5；测试注入确定性结果，避免依赖真实服务状态）。
    #[must_use]
    pub fn with_service_status_source(mut self, source: Arc<dyn ServiceStatusSource>) -> Self {
        self.service_status_source = source;
        self
    }

    /// 注入服务变更操作 seam（S3/D4；测试注入 fake 记录 install/start/stop）。
    #[must_use]
    pub fn with_service_ops(mut self, ops: Arc<dyn ServiceControlOps>) -> Self {
        self.service_ops = ops;
        self
    }

    /// 注入 service engine 连接 seam（S3/D3；测试注入 fake 换入 fake engine，避免真实
    /// PSK 文件与服务管道依赖）。
    #[must_use]
    pub fn with_service_connector(mut self, connector: Arc<dyn ServiceEngineConnector>) -> Self {
        self.service_connector = connector;
        self
    }

    /// 注入 keepalive 就绪探活 seam（R2；测试注入 fake 返回确定性结果，避免真实 PSK
    /// 文件与服务管道依赖）。
    #[must_use]
    pub fn with_service_probe(mut self, probe: Arc<dyn ServiceProbe>) -> Self {
        self.service_probe = probe;
        self
    }

    /// 注入服务就绪轮询上界（R2；测试注入短时长验证先到先采纳/超时语义，避免真实 15s）。
    #[must_use]
    pub fn with_service_ready_timeout(mut self, timeout: Duration) -> Self {
        self.service_ready_timeout = timeout;
        self
    }

    /// 注入服务就绪轮询间隔（R2；测试注入短间隔加快轮询收敛）。
    #[must_use]
    pub fn with_service_ready_poll(mut self, poll: Duration) -> Self {
        self.service_ready_poll = poll;
        self
    }

    /// 查询当前 SCM 服务状态（非提权；查询失败 → `Ok(None)`——状态上报不因查询失败而失败）。
    fn query_service_status_snapshot(&self) -> Option<ServiceStatusSnapshot> {
        let snapshot = query_service_status(self.service_status_source.as_ref(), SERVICE_NAME).ok()?;
        if !self
            .service_removed_override
            .load(Ordering::Acquire)
        {
            return Some(snapshot);
        }

        if !snapshot.state.is_installed() {
            // SCM 已经完全清场；从此恢复真实查询。
            self.clear_service_removed_override();
            return Some(snapshot);
        }

        // DeleteService 已经成功，SCM 的 marked-for-delete 观察窗口不再代表业务
        // 安装状态。返回确定性的"未安装"事实，避免 UI 让用户重复点击卸载。
        Some(ServiceStatusSnapshot {
            state: ServiceState::NotInstalled,
            binary_path: None,
        })
    }

    /// 查询当前 SCM 服务状态并派生 wire `ServiceStatus`（含 R3 `health_state`）。
    ///
    /// 廉价健康事实（`service_health_from_snapshot`：SCM 注册 / 二进制路径 / 引擎二进制
    /// 存在性 / PSK 可读）随快照计算；昂贵探针（控制面管道 / keepalive）不在此路径。
    fn query_service_status_wire(&self) -> Option<wire::ServiceStatus> {
        let snap = self.query_service_status_snapshot()?;
        let health = derive_health(&service_health_from_snapshot(&snap));
        Some(service_status_to_wire(&snap, health))
    }

    /// 记录最近一次连接路由的实际模式（快照 `mode` 展示用；缺省 auto）。`ServiceMode`
    /// 是 typed 编码（与 `ENGINE_KIND_*` 共享 0/1/2），存储沿用 `AtomicU8` 供 keepalive
    /// ticker 后台线程无锁读取。
    fn record_mode(&self, mode: ServiceMode) {
        self.selected_mode.store(mode.as_u8(), Ordering::Relaxed);
    }

    /// 当前展示模式字符串（`"auto"` / `"service"` / `"oneshot"`；未知码 fail-closed → auto）。
    fn mode_string(&self) -> String {
        ServiceMode::from_u8(self.selected_mode.load(Ordering::Relaxed))
            .as_wire_str()
            .to_string()
    }

    /// 卸载成功后标记「SCM marked-for-delete 观察窗口」覆盖：`DeleteService` 已成功但 SCM
    /// 可能短暂保留条目，此后 `query_service_status_snapshot` 强制报告 NotInstalled。
    fn mark_service_removed(&self) {
        self.service_removed_override.store(true, Ordering::Release);
    }

    /// 清除覆盖（安装成功 / 查询观察到 SCM 已完全清场）——恢复真实 SCM 查询。
    fn clear_service_removed_override(&self) {
        self.service_removed_override.store(false, Ordering::Release);
    }

    /// Core-owned service bootstrap：确保服务正在运行且业务面已经可用。
    ///
    /// 这是 install、显式 Start 和 connect-after-install 的共同入口。仅在本次操作
    /// 观察到 Stopped/Other/未知状态时提交一次提权 start；Running、StartPending、
    /// StopPending 均不重复提交，由 SCM 自己收敛。提交发生竞态时，若随后查询已经
    /// 变成 Running，仍按幂等成功处理。
    async fn ensure_service_ready(&self) -> Result<ServiceReadiness, String> {
        let initial_state = self
            .query_service_status_snapshot()
            .map(|snapshot| snapshot.state);
        // 这是一次连接/显式 Start 内的 bootstrap，不是后台守护：StartPending/StopPending
        // 由 SCM 自己收敛，重复提交 start 只会制造 ERROR_SERVICE_ALREADY_RUNNING 竞态。
        let needs_start = matches!(
            initial_state,
            None
                | Some(
                    ServiceState::Stopped
                        | ServiceState::NotInstalled
                        | ServiceState::Other(_)
                )
        );
        self.logs
            .append_core(
                "info",
                "kernel",
                "kernel.service_bootstrap.observed",
                "service bootstrap checked SCM state",
                &BTreeMap::from([
                    ("state".to_string(), format!("{:?}", initial_state)),
                    ("start_submitted".to_string(), needs_start.to_string()),
                ]),
            )
            .ok();
        if needs_start {
            if let Err(error) = self.service_ops.start().await {
                let running_after_race = self
                    .query_service_status_snapshot()
                    .is_some_and(|snapshot| snapshot.state == ServiceState::Running);
                if !running_after_race {
                    return Err(format!("start service: {error}"));
                }
            }
        }

        let readiness = wait_for_service_ready(
            self.service_status_source.as_ref(),
            self.service_probe.as_ref(),
            self.service_ready_timeout,
            self.service_ready_poll,
        )
        .await;
        if readiness.ready {
            Ok(readiness)
        } else {
            let scm_desc = match readiness.scm_state {
                Some(state) => format!("SCM 状态={state:?}"),
                None => "SCM 状态未知".to_string(),
            };
            Err(format!(
                "服务启动超时（{}ms）：{scm_desc}，keepalive 未响应",
                readiness.elapsed_ms
            ))
        }
    }

    /// Connect 内的服务启动门禁。
    ///
    /// 服务启动阶段的 readiness 只允许完成一次；真正的业务面门禁由后面的
    /// `connect_service_engine_with_bootstrap_retry` 完成（服务身份/PSK 握手 + owner
    /// lease）。这里不能在 SCM 已 Running 后再次开一条 KeepAlive 管道，否则会与服务
    /// accept-loop 的上一条 gRPC 管道释放形成竞态：探活成功而第二次 Dial(2)。
    async fn ensure_service_ready_for_connect(&self) -> Result<ServiceReadiness, String> {
        self.ensure_service_ready().await
    }

    /// S3/D3 + M3：auto 决策表路由（connect 派发前调用）。服务已安装但 stopped 时，
    /// 由 Core 自动完成 start + readiness，再继续连接。
    ///
    /// - **Service**：服务已装且在跑 → 把 engine 槽换到服务 engine（SCM 常驻）后返回。
    /// - **PromptStart**：服务已装未跑 → Core bootstrap 后继续走 service engine。
    /// - **Oneshot**：未装 → 维持既有 spawn engine 路径（engine 槽不动）。
    ///
    /// 服务状态查询失败（`None`）= **未知**（S5/MED[3] 加固）：安全兜底 oneshot（spawn
    /// engine 直连，不触碰 SCM、不因查询失败阻塞连接）。PSK 不可读 / 服务连接失败 →
    /// `failed_precondition`（服务模式必须持有共享秘密）。
    async fn route_connect(&self) -> Result<RouteDecision, Status> {
        let snap = self.query_service_status_snapshot();
        let Some(snap) = snap else {
            self.logs
                .append_core(
                    "warn",
                    "kernel",
                    "kernel.route.service_query_failed",
                    "service status query failed; treating as unknown and falling back to oneshot",
                    &BTreeMap::new(),
                )
                .ok();
            return Ok(RouteDecision::Oneshot);
        };
        self.logs
            .append_core(
                "info",
                "kernel",
                "kernel.route.scm_state",
                &format!(
                    "service scm state={:?} -> route={:?}",
                    snap.state,
                    decide_route(snap.state)
                ),
                &BTreeMap::new(),
            )
            .ok();
        match decide_route(snap.state) {
            RouteDecision::Service => {
                // SCM 已经观察到 Running：不要在 connect 上重复执行 install/start 的
                // readiness gate。真正的业务面门禁是 service pipe + owner lease；若服务
                // 在这一个快照之后停止，下面的有界 bootstrap retry 会处理该竞态。
                self.connect_service_engine_with_bootstrap_retry().await?;
                Ok(RouteDecision::Service)
            }
            RouteDecision::PromptStart => {
                self.ensure_service_ready_for_connect()
                    .await
                    .map_err(|error| {
                        Status::failed_precondition(format!("service_start_failed|{error}"))
                    })?;
                self.connect_service_engine_with_bootstrap_retry().await?;
                Ok(RouteDecision::Service)
            }
            RouteDecision::Oneshot => {
                // service 卸载后恢复 Core 初始 oneshot 控制面；不能只改展示 mode，
                // 否则下一次 connect 仍会把 ApplyTunnel 发给已经停止的 service client。
                self.swap_engine_for_route(self.oneshot_engine.clone()).await;
                Ok(RouteDecision::Oneshot)
            }
        }
    }

    /// 换 engine 控制面前先撤销旧状态流就绪标记，避免 `await_status_ready` 在转发器
    /// 重新挂接新 engine 前误放行 ApplyTunnel/StopTunnel。
    async fn swap_engine_for_route(
        &self,
        engine: Arc<tokio::sync::Mutex<dyn KernelEngineControl>>,
    ) {
        let current = self.engine.current().await;
        if Arc::ptr_eq(&current, &engine) {
            return;
        }
        let _ = self.status_ready.send(false);
        let _ = self.engine.swap(engine).await;
        self.logs
            .append_core(
                "info",
                "kernel",
                "kernel.route.engine_swapped",
                "engine slot swapped (route change); status_ready revoked until forwarder re-attaches",
                &BTreeMap::new(),
            )
            .ok();
    }

    /// 把 engine 槽换到 service-mode engine（S3/D2/D7）：经 [`ServiceEngineConnector`] seam
    /// 连接（真实实现 = 读 PSK + 拨号稳定服务管道 + SID-only 验证 + PSK-HMAC 双向挑战）→
    /// 换入槽（后续写路径自动指向服务 engine）。幂等性由调用方（路由决策）保证——仅在
    /// Service 分支调用。
    ///
    /// R2：对 connect-after-start 竞窗做**有界重试**（`connect_service_engine` 内部的
    /// 拨号重试覆盖未绑管道的竞窗，此处兜底 SCM running 后 service engine 尚未就绪的
    /// 窗口——少数尝试 + 小退避）。最终失败仍保持既有 `failed_precondition` 语义。
    async fn ensure_service_engine(&self) -> Result<(), Status> {
        // 断开后立即重连：若槽内已是 service client（上次服务连接后未切换），复用其
        // owner lease（host 侧幂等）——否则新建连接 acquire 会被引擎以「peer already
        // owns」拒绝（旧连接 owner 未释放；peer 含 per-connection digest，新连接=新
        // peer）→ ConnectionLost（实测：断开后立刻重连必现，等 3s 后旧 owner 释放才恢复）。
        // 复用失败（旧 client 已失效/服务重启）→ 落回下方新建路径。
        if self.selected_mode.load(Ordering::SeqCst) == ServiceMode::Service.as_u8() {
            let current = self.engine.current().await;
            let mut guard = current.lock().await;
            let reusable = guard.ensure_owner_lease().await.is_ok();
            drop(guard);
            if reusable {
                self.logs
                    .append_core(
                        "info",
                        "kernel",
                        "kernel.route.service_reuse",
                        "reusing existing service engine client (idempotent owner lease)",
                        &BTreeMap::new(),
                    )
                    .ok();
                return Ok(());
            }
        }
        const ATTEMPTS: u32 = 3;
        const BACKOFF: Duration = Duration::from_millis(300);
        let mut last_err = "no attempt".to_string();
        for attempt in 0..ATTEMPTS {
            match self.service_connector.connect_service_engine().await {
                Ok(engine) => {
                    // PSK/pipe 握手成功不等于 mutation 可用；先建立 owner lease，把
                    // 不可用尽早收敛为 service_connect_failed，而不是等 ApplyTunnel 才
                    // 映射成笼统的 engine control unavailable。
                    {
                        let mut guard = engine.lock().await;
                        if let Err(error) = guard.ensure_owner_lease().await {
                            last_err = format!("service engine owner lease: {error:?}");
                            self.logs
                                .append_core(
                                    "warn",
                                    "kernel",
                                    "kernel.route.service_lease_failed",
                                    &format!("service engine lease attempt {attempt}: {error:?}"),
                                    &BTreeMap::new(),
                                )
                                .ok();
                            if attempt + 1 < ATTEMPTS {
                                tokio::time::sleep(BACKOFF).await;
                            }
                            continue;
                        }
                    }
                    self.logs
                        .append_core(
                            "info",
                            "kernel",
                            "kernel.route.service_dial_ok",
                            &format!("service engine dial+lease ok on attempt {attempt}; swapping to service engine"),
                            &BTreeMap::new(),
                        )
                        .ok();
                    self.swap_engine_for_route(engine).await;
                    // 先切换维护策略，再让后续 connect 派发继续运行，避免 ticker 在
                    // service engine 已换入、快照 mode 尚未更新的竞窗内发送 KeepAlive。
                    self.record_mode(ServiceMode::Service);
                    return Ok(());
                }
                Err(e) => {
                    last_err = e.clone();
                    self.logs
                        .append_core(
                            "warn",
                            "kernel",
                            "kernel.route.service_dial_failed",
                            &format!("service engine dial attempt {attempt} failed: {e}"),
                            &BTreeMap::new(),
                        )
                        .ok();
                    if attempt + 1 < ATTEMPTS {
                        tokio::time::sleep(BACKOFF).await;
                    }
                }
            }
        }
        // R5：稳定前缀 `service_connect_failed|` ——UI 侧 map_status 映射为
        // `AppError::ServiceConnectFailed`（modal 触发）；人读信息保持在后缀。
        Err(Status::failed_precondition(format!(
            "service_connect_failed|service engine connect: {last_err}"
        )))
    }

    /// Service pipe 连接的一次性恢复边界：如果 engine 在本次连接刚开始时从 Running
    /// 崩掉并已经回到 stopped，补做一次 bootstrap，再重试一次 service pipe。这里不
    /// 开启常驻监控，也不对持续 Running 但业务面异常的服务无限重启。
    async fn connect_service_engine_with_bootstrap_retry(&self) -> Result<(), Status> {
        match self.ensure_service_engine().await {
            Ok(()) => Ok(()),
            Err(first_error) => {
                let stopped = self
                    .query_service_status_snapshot()
                    .is_some_and(|snapshot| {
                        snapshot.state.is_installed() && snapshot.state != ServiceState::Running
                    });
                if !stopped {
                    return Err(first_error);
                }
                self.ensure_service_ready_for_connect()
                    .await
                    .map_err(|error| {
                        Status::failed_precondition(format!("service_start_failed|{error}"))
                    })?;
                self.ensure_service_engine().await
            }
        }
    }

    /// 在 service install/uninstall 前清理当前 engine 的业务连接。
    ///
    /// service 与 oneshot 不能在同一 core 生命周期中并存：安装服务前清理 oneshot，
    /// 卸载服务前清理 service。`StopTunnel` 成功后把 host composition 收敛回 Idle，并
    /// 暂时将维护类型置为 auto，确保旧 oneshot 不再收到 KeepAlive；调用方在服务子命令
    /// 成功后再写入目标类型。
    async fn stop_engine_for_transition(&self, _source_mode: ServiceMode) -> Result<(), String> {
        let active = {
            let composition = self.composition.lock().await;
            !matches!(composition.phase(), HostPhase::Idle | HostPhase::Stopped)
        };
        if !active {
            // Stopped 是 teardown 已完成但 admission 可能仍关闭的合法中间观测态。
            // 服务变更是下一次业务操作的边界，必须在这里补齐显式 reopen，不能因为
            // selected_mode 与 transition 来源不一致而提前返回并把后续 connect 永久锁死。
            let mut composition = self.composition.lock().await;
            if composition.phase() == HostPhase::Stopped {
                composition.apply(HostEvent::ReopenAdmission);
            }
            drop(composition);
            self.record_mode(ServiceMode::Auto);
            return Ok(());
        }

        let runtime_epoch = {
            let composition = self.composition.lock().await;
            composition.runtime_epoch_bytes().to_vec()
        };
        let operation_id = Uuid::new_v4().as_bytes().to_vec();
        let request = StopTunnelRequest {
            lookup_key: Some(wire::OperationLookupKey {
                principal_digest: vec![0u8; 32],
                method: wire::OperationMethod::StopTunnel as i32,
                runtime_epoch,
                operation_id,
            }),
            request_digest: vec![0u8; 32],
        };
        let engine = self.engine.current().await;
        let mut engine = engine.lock().await;
        let lease_available = match engine.ensure_owner_lease().await {
            Ok(()) => true,
            Err(GrpcClientError::ConnectionLost) => {
                // 旧 engine 已经断开时，业务连接实际上已经消失；继续做本地 teardown，
                // 否则 admission 会永远保持 closed，后续 install/uninstall 也无法重试。
                false
            }
            Err(e) => {
                return Err(format!(
                    "ensure owner lease before service transition: {e:?}"
                ));
            }
        };
        if lease_available {
            match engine.stop_tunnel(request).await {
                Ok(_) => {}
                Err(GrpcClientError::ConnectionLost) => {
                    // 与 lease 阶段掉线相同：旧 engine 已不再可用，本地收敛仍必须继续。
                }
                Err(e) => {
                    return Err(format!("stop engine before service transition: {e:?}"));
                }
            }
        }
        drop(engine);

        let mut composition = self.composition.lock().await;
        composition.apply(HostEvent::Disconnect);
        composition.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl));
        composition.apply(HostEvent::TeardownSideJoined(TeardownSide::PacketData));
        composition.apply(HostEvent::ReopenAdmission);
        drop(composition);
        self.record_mode(ServiceMode::Auto);
        Ok(())
    }

    /// R5：路由失败（PromptStart / service engine connect 失败）的收敛补发。
    ///
    /// connect 受理时已把状态机推进到 Connecting（`HostEvent::Connect`），但路由在
    /// 派发前失败——engine 状态流永不携带 Failed，不补发则快照卡死 Connecting。
    /// 此处按状态转发器同源模式（`set_last_wire_error` + `ConnectFailed`）把相态收敛
    /// 到 Failed，并发布 Transition 事件让 UI 立即看到失败相态（而不仅是 connect RPC
    /// 拒绝）。`route_failure_wire_error` 以稳定 code（SessionBusy）构造 wire error。
    async fn apply_connect_failed_for_route(&self, status: &Status) {
        let wire_error = route_failure_wire_error(status);
        let domain_error = wire_vpn_error_to_domain(&wire_error);
        let mut composition = self.composition.lock().await;
        composition.set_last_wire_error(wire_error);
        composition.apply(HostEvent::ConnectFailed(domain_error));
        let snapshot = snapshot_for_phase(composition.phase(), &composition);
        drop(composition);
        self.events
            .publish(wire::RuntimeEventKind::Transition, snapshot);
    }

    /// 从一个已组合的 host 构造 (composition 句柄, 服务)。
    ///
    /// 调用方持有返回的 `Arc`，以便在服务之外驱动同一 composition（例如 P3 的
    /// engine 事件转发）。
    #[must_use]
    pub fn from_composition(
        composition: HostComposition,
        engine: EngineSlot,
        config_dir: PathBuf,
        logs: Arc<LogAggregator>,
    ) -> (Arc<Mutex<HostComposition>>, Self) {
        let shared = Arc::new(Mutex::new(composition));
        let service = Self::new(Arc::clone(&shared), engine, config_dir, logs);
        (shared, service)
    }

    /// 注入上游 proxy TUN 检测探针（C5-wire；默认 [`default_proxy_tun_probe`]）。
    ///
    /// 单测注入确定性结果（探测失败/无检测/检测到），避免 `GetSnapshot` 与事件转发器
    /// 依赖真实 Win32 适配器状态；产品路径保持默认真实枚举。
    #[must_use]
    pub fn with_proxy_tun_probe(mut self, probe: ProxyTunProbe) -> Self {
        self.proxy_tun_probe = probe;
        self
    }

    /// 注入系统代理探测探针（EXV_UNFREEZE；默认 [`default_system_proxy_probe`]）。
    ///
    /// 单测注入确定性结果（探测失败/disabled/manual…），避免 `GetSnapshot` 与事件转发器
    /// 依赖真实 WinINET 注册表状态；产品路径保持默认真实捕获。
    #[must_use]
    pub fn with_system_proxy_probe(mut self, probe: SystemProxyProbe) -> Self {
        self.system_proxy_probe = probe;
        self
    }

    /// 注入 `await_status_ready` 的有界等待上界（R3-C1；测试注入短时长验证"不悬挂、
    /// 放行派发报真实错误"语义）。产品路径保持默认 [`STATUS_READY_WAIT`]。
    #[must_use]
    pub fn with_status_ready_wait(mut self, wait: Duration) -> Self {
        self.status_ready_wait = wait;
        self
    }

    /// 转为 tonic `KernelControlServer`（P4 将其加入 `Server::builder()`）。
    #[must_use]
    pub fn into_server(self) -> KernelControlServer<KernelControlService> {
        KernelControlServer::new(self)
    }

    /// `WatchEvents` 事件总线句柄（测试可注入事件；`spawn_status_forwarder` 发布）。
    #[must_use]
    pub fn events(&self) -> Arc<EventBus> {
        Arc::clone(&self.events)
    }

    /// attach-before-apply 就绪接收端（R1）：`true` = status 转发器已挂接
    /// `StreamConnectStatus`。connect/stop 写路径派发前 await（硬约束）。
    #[must_use]
    pub fn status_ready(&self) -> watch::Receiver<bool> {
        self.status_ready.subscribe()
    }

    /// 等待 status 转发器已挂接 `StreamConnectStatus`（attach-before-apply 硬约束），
    /// **有界**（R3-C1）：引擎状态流永久不可达时不得永久悬挂。
    ///
    /// 转发器持续退避重连直至成功挂接；正常路径在毫秒级就绪。本方法在
    /// `status_ready_wait` 上界内等待就绪；上界到期（引擎仍不可达）→ 放行派发，由
    /// ApplyTunnel/StopTunnel 报真实 gRPC 错误上状态机（失败不静默）——有界等待保证
    /// 写路径不悬挂，但就绪仍是"状态通道可用"的尽力保证。
    async fn await_status_ready(&self) {
        let mut ready = self.status_ready();
        // 初始值即 `true`（挂接过）→ 立即通过；否则等待 watch 变更（有界）。
        let wait = tokio::time::timeout(self.status_ready_wait, async {
            while !*ready.borrow() {
                if ready.changed().await.is_err() {
                    return; // sender dropped（服务拆毁）→ 不悬挂，让后续 apply 自然失败。
                }
            }
        });
        // 上界到期（引擎永久不可达）→ 静默放行：派发报真实错误，不在此悬挂。
        let _ = wait.await;
    }

    /// 经 transport peer 认证路径授权 `KernelControl` gate（P3-c1）。
    ///
    /// host 侧核对 transport peer 身份（`VerifiedPipePeer` 携带进程 pid + user SID +
    /// account name，缺任一项即拒绝）后授权 gate——engine 侧 `peer_auth`（P1-b）已
    /// 落地，host 侧把已验 peer 身份接到 gate 的授权路径。进程生命周期（P3-c2）在
    /// 传输层认证后调用本方法；已授权后写 RPC 通过 gate。
    ///
    /// # Errors
    /// peer 无可用身份事实（pid/SID/account 缺失）→ `VpnError::Unauthorized`。
    pub async fn authorize_transport_peer(&self, peer: &VerifiedPipePeer) -> Result<(), VpnError> {
        let mut composition = self.composition.lock().await;
        composition.kernel_gate().authorize(peer)?;
        // R1：控制器（KernelControl transport peer）授权即绑定到唯一 runtime actor——
        // connect 受理（`HostEvent::Connect`）需要 actor 已绑定 peer+capability 才会
        // admitted。绑定用确定性的 peer+capability（固定字面量构造，镜像 acceptance /
        // portable H80 同款；真实绑定推导属 P3-c2 进程生命周期接线）。
        let (actor_peer, capability) = controller_peer_and_capability();
        composition.bind_controller(actor_peer, capability);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // C3a：自动重连 host 侧重连驱动。
    // -----------------------------------------------------------------------

    /// 一次 Connect 的核心（admission → route → attach-before-apply → execute_connect）。
    ///
    /// UI `KernelControl.Connect` 与 C3a 自动重连共用。凭据始终从磁盘（`config_dir`）
    /// 重新组装（本方法不持有 UI 提供的一次性 secret）；状态机受理（Idle/Connected/
    /// Failed → Connecting）、路由决策、SCM 状态刷新、attach-before-apply 与发送后
    /// 零化语义与既有 connect 完全一致。
    ///
    /// # Errors
    /// admission 拒绝 → `failed_precondition`；路由失败 → 对应 `Status`（已补发
    /// ConnectFailed）；凭据缺失/引擎不可达 → `execute_connect` 的相应 `Status`。
    async fn run_connect(
        &self,
        intent: wire::ConnectIntent,
    ) -> Result<Response<OperationReply>, Status> {
        // R1：connect 受理即驱动状态机（Idle/Connected/Failed → Connecting）。
        // 失败（admission closed / teardown in progress）→ 明确拒绝，不进 Connecting。
        let operation_id = intent
            .lookup_key
            .as_ref()
            .and_then(|k| <[u8; 16]>::try_from(k.operation_id.as_slice()).ok());
        {
            let mut composition = self.composition.lock().await;
            let effect = composition.apply(HostEvent::Connect);
            if let HostEffect::ConnectRefused(reason) = effect {
                return Err(Status::failed_precondition(format!("connect: {reason}")));
            }
            if let Some(id) = operation_id {
                composition.set_operation_id(id);
            }
        }

        // S3/D3 + M3：auto 决策表路由（core 侧）——服务在跑 → service；已装未跑 →
        // 本次 connect 内由 Core 自动启动并等待就绪；未装 → oneshot（connect 不触发
        // install）。服务启动只发生在本次连接操作内，不是后台监控。
        // 路由决策记录实际模式（快照 `mode` 展示用）；Service 分支把 engine 槽换到服务
        // engine（SCM 常驻，非提权拉起）；Oneshot 维持既有 spawn 路径。
        //
        // R5：路由失败（PromptStart / service engine connect 失败）时补发 ConnectFailed
        // ——connect 已把状态机推进到 Connecting，但路由在派发前失败、engine 状态流永不
        // 携带 Failed → 不补发则快照卡死 Connecting（R5 根因，modal 触发依赖 Failed 相态）。
        let route = match self.route_connect().await {
            Ok(route) => route,
            Err(status) => {
                self.apply_connect_failed_for_route(&status).await;
                return Err(status);
            }
        };
        self.record_mode(ServiceMode::from_route(route));
        self.events.refresh_service_mode(Some(self.mode_string()));
        // S3/D5 修复：connect 路由（含 ensure_service_ready 内部 bootstrap start 把
        // 服务从 Stopped 拉到 Running）后立即刷新 SCM 快照缓存——否则 WatchEvents
        // 发布的快照持续携带 connect 前的旧服务状态（UI 显示「已停止」而实际 Running）。
        {
            let service_status = self.query_service_status_wire();
            self.events.refresh_service_status(service_status.clone());
            self.logs
                .append_core(
                    "info",
                    "kernel",
                    "kernel.service.status_refreshed_on_route",
                    &format!(
                        "service status cache refreshed after connect route: installed={} state={}",
                        service_status.as_ref().map(|s| s.installed).unwrap_or(false),
                        service_status
                            .as_ref()
                            .map(|s| s.state.clone())
                            .unwrap_or_default(),
                    ),
                    &BTreeMap::new(),
                )
                .ok();
        }

        // R1 attach-before-apply（硬约束）：先等 status 流挂接再派发 ApplyTunnel——
        // engine `StatusPublisher` 无快照，open 前事件丢弃；挂接后才不会丢阶段事件。
        self.await_status_ready().await;

        // 凭据生命周期 + engine 派发 + 发送后零化（纯逻辑，测试注入 fake engine）。
        let engine = self.engine.current().await;
        let mut engine = engine.lock().await;
        let (reply, zeroized) = execute_connect(&mut *engine, &self.config_dir, intent).await?;
        drop(engine);

        // 发送完成：`execute_connect` 已确定性零化 KernelControl wire 副本（明文不再驻留）。
        self.logs
            .append_core(
                "info",
                "kernel",
                "kernel.connect.dispatched",
                "connect dispatched to engine (secret one-shot, wire zeroized)",
                &BTreeMap::new(),
            )
            .ok();
        let _ = zeroized;
        // R1：engine 的 ApplyTunnel 立即回 `pending`（ApplyAccepted，带 operation_id）；
        // 终态/阶段走 StreamConnectStatus（状态转发器驱动状态机 + UI 事件）。
        Ok(Response::new(operation_reply_from_apply(&reply)))
    }

    /// C3a 自动重连 worker：串行消费状态转发器发来的可重试掉线信号，驱动一次重连。
    ///
    /// 每个信号按序处理（天然防并发重连）；在途标记（`reconnect_active`）期间的新信号
    /// 直接跳过（防重入）。重连前判定：`auto_reconnect` 未开启 → 跳过；`max_attempts`
    /// 耗尽 → 跳过。每次实际重跑 connect 递增 `reconnect_attempts`（per-connection，
    /// Connected 成功后由状态转发器清零）。重连凭据从磁盘重新组装（`run_connect` 内部
    /// `execute_connect` load config + key.bin），不持有 engine 凭据。
    async fn drive_reconnect(&self) {
        // 防重入：上一次重连尝试仍在途（已派发、终态未到）→ 不重复触发。
        if self.reconnect_active.load(Ordering::Acquire) {
            self.logs
                .append_core(
                    "info",
                    "kernel",
                    "kernel.reconnect.skip_in_flight",
                    "auto reconnect skipped: a reconnect attempt is still in flight",
                    &BTreeMap::new(),
                )
                .ok();
            return;
        }
        // 重连判定：读 config 的 auto_reconnect / max_attempts。
        let cfg = match ExvConfig::load_from_dir(&self.config_dir) {
            Ok(cfg) => cfg,
            Err(e) => {
                self.logs
                    .append_core(
                        "warn",
                        "kernel",
                        "kernel.reconnect.config_unreadable",
                        &format!("auto reconnect config unreadable: {e:?}"),
                        &BTreeMap::new(),
                    )
                    .ok();
                return;
            }
        };
        if !cfg.auto_reconnect {
            self.logs
                .append_core(
                    "info",
                    "kernel",
                    "kernel.reconnect.disabled",
                    "retryable data-plane drop observed but auto_reconnect is disabled",
                    &BTreeMap::new(),
                )
                .ok();
            return;
        }
        let max = cfg.auto_reconnect_max_attempts;
        let attempts = self.reconnect_attempts.load(Ordering::Relaxed);
        if max != 0 && attempts >= max {
            self.logs
                .append_core(
                    "warn",
                    "kernel",
                    "kernel.reconnect.exhausted",
                    &format!(
                        "auto reconnect stopped: attempts={attempts} exhausted (max={max})"
                    ),
                    &BTreeMap::new(),
                )
                .ok();
            return;
        }

        // 重连执行：占用在途标记 + 计数 + 复用 run_connect（凭据从磁盘重新组装）。
        self.reconnect_active.store(true, Ordering::Release);
        self.reconnect_attempts.fetch_add(1, Ordering::Relaxed);
        let attempt = attempts + 1;
        self.logs
            .append_core(
                "info",
                "kernel",
                "kernel.reconnect.attempt",
                &format!(
                    "auto reconnect attempt {attempt} (max={})",
                    if max == 0 {
                        "unlimited".to_string()
                    } else {
                        max.to_string()
                    }
                ),
                &BTreeMap::new(),
            )
            .ok();
        match self.run_connect(reconnect_intent()).await {
            Ok(_reply) => {
                // 已派发：保持 in-flight（终态事件由状态转发器清 reconnect_active）。
                self.logs
                    .append_core(
                        "info",
                        "kernel",
                        "kernel.reconnect.dispatched",
                        &format!("auto reconnect attempt {attempt} dispatched (credentials re-assembled from disk)"),
                        &BTreeMap::new(),
                    )
                    .ok();
            }
            Err(status) => {
                // 同步失败：上报失败（ConnectFailed → 状态机 Failed），释放在途标记。
                self.reconnect_active.store(false, Ordering::Release);
                self.apply_connect_failed_for_route(&status).await;
                self.logs
                    .append_core(
                        "warn",
                        "kernel",
                        "kernel.reconnect.failed",
                        &format!(
                            "auto reconnect attempt {attempt} failed before dispatch: code={:?} msg={}",
                            status.code(),
                            status.message()
                        ),
                        &BTreeMap::new(),
                    )
                    .ok();
            }
        }
    }

    /// 拉起自动重连 worker 任务（C3a 生产接线）。worker 持服务克隆（轻量共享句柄，
    /// 内部全部 Arc/Copy），可调 `run_connect`/路由等 `&self` 方法；停机时必须 abort
    /// 本句柄释放 worker（否则服务被 worker 持有的克隆永久引用）。
    #[must_use]
    pub fn spawn_reconnect_worker(&self) -> tokio::task::JoinHandle<()> {
        // 换入绑定本 worker 接收端的发送端：此后状态转发器的信号经该通道到达本 worker。
        let (tx, mut rx) = mpsc::unbounded_channel::<()>();
        *self.reconnect_tx.lock().unwrap() = Some(tx);
        let service = self.clone();
        tokio::spawn(async move {
            while rx.recv().await.is_some() {
                service.drive_reconnect().await;
            }
        })
    }

    /// 订阅 engine connect-status 流并驱动状态机 + 事件总线（R1 真实订阅的 host 侧接线）。
    ///
    /// 后台任务循环：acquire engine `stream_connect_status`（R1w 独立 status 通道，
    /// **非 StreamLogs**——日志已退役为纯输出，绝不回流状态）→ 逐事件
    /// （[`EngineStatusEvent`]）驱动 composition 状态机（阶段推进 / 真实 Connected /
    /// 失败带 err / 停止收敛）并发布 `RuntimeEvent` → 状态流 EOF（engine 断开）→
    /// 发布断线过渡事件（Reconciling 表示）→ 退避重连（断线重放语义：核心状态机为
    /// 单一事实源，重连后从当前 phase 继续）。调用方（P3-c2 进程生命周期）在 engine
    /// 就绪后调用；返回 `JoinHandle` 供测试保持/终止。
    ///
    /// **attach-before-apply 硬约束**：本转发器持有唯一挂接的 status 流；connect/stop
    /// 写路径在派发前依赖它已挂接（engine `StatusPublisher` 无快照、open 前事件丢弃）。
    #[must_use]
    pub fn spawn_status_forwarder(&self) -> tokio::task::JoinHandle<()> {
        let slot = self.engine.clone();
        let events = Arc::clone(&self.events);
        let composition = Arc::clone(&self.composition);
        let reconnect_tx = Arc::clone(&self.reconnect_tx);
        let reconnect_attempts = Arc::clone(&self.reconnect_attempts);
        let reconnect_active = Arc::clone(&self.reconnect_active);
        // C4 wire unfreeze：重连状态需要 auto_reconnect/max_attempts 配置（每次从磁盘
        // 重读，mirror `drive_reconnect`）——转发器持 config_dir 克隆以组装 ReconnectStatus。
        let config_dir = self.config_dir.clone();
        let proxy_tun_probe = Arc::clone(&self.proxy_tun_probe);
        let system_proxy_probe = Arc::clone(&self.system_proxy_probe);
        let status_ready = self.status_ready.clone();
        let logs = Arc::clone(&self.logs);
        let mut slot_swaps = slot.subscribe_swaps();
        tokio::spawn(async move {
            let mut backoff = ENGINE_EVENT_RECONNECT_BASE;
            loop {
                let stream = {
                    // 从槽取当前 engine（P3 respawn 换入新 client 后，下一轮退避即拿到
                    // 新 engine——无需 abort/重拉转发器）。
                    let engine = slot.current().await;
                    let mut guard = engine.lock().await;
                    match guard.stream_connect_status().await {
                        Ok(stream) => stream,
                        Err(_) => {
                            // 无法订阅（断线）：撤销就绪（R3-C3 防 stale-true——窗口内
                            // 派发不误判已挂接）+ R2 收敛双保险（engine 不可达时若本机
                            // 正在停机收敛,补数据面侧加入→Stopped/Idle）+ 发布断线过渡
                            // + 退避后重试。
                            let _ = status_ready.send(false);
                            let _ = logs.append_core(
                                "warn",
                                "kernel",
                                "kernel.forward.status_attach_failed",
                                "status forwarder failed to subscribe current engine (will backoff)",
                                &BTreeMap::new(),
                            );
                            composition.lock().await.synthesize_data_plane_join();
                            let snapshot = snapshot_with_reconnect(
                                disconnected_snapshot(&*composition.lock().await),
                                Some(reconnect_status_from_config(
                                    &reconnect_attempts,
                                    &reconnect_active,
                                    &config_dir,
                                )),
                            );
                            refresh_bus_proxy_tun(&events, &proxy_tun_probe);
                            refresh_bus_system_proxy(&events, &system_proxy_probe);
                            events.publish(wire::RuntimeEventKind::Transition, snapshot);
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(ENGINE_EVENT_RECONNECT_MAX);
                            continue;
                        }
                    }
                };
                // attach-before-apply 就绪：status 流已挂接（engine `StatusPublisher`
                // 无快照、open 前事件丢弃）→ 写路径派发前可放心 apply。
                let _ = status_ready.send(true);
                let _ = logs.append_core(
                    "info",
                    "kernel",
                    "kernel.forward.status_attached",
                    "status forwarder attached to current engine",
                    &BTreeMap::new(),
                );
                backoff = ENGINE_EVENT_RECONNECT_BASE;
                let mut stream = stream;
                let mut engine_swapped = false;
                loop {
                    tokio::select! {
                        changed = slot_swaps.changed() => {
                            if changed.is_err() {
                                return;
                            }
                            // 当前 status stream 属于旧 engine；不要把旧流的 EOF 当作
                            // engine 断线，也不要让旧流继续吞掉新 engine 的状态事件。
                            let _ = status_ready.send(false);
                            engine_swapped = true;
                            break;
                        }
                        status_event = stream.next() => {
                            let Some(status_event) = status_event else {
                                break;
                            };
                            // R3-C2：终态事件（Connected/Failed/Idle）的 operation_id 与当前
                            // 在途操作不符 → 丢弃（防旧操作迟到终态驱动相态）；`None` = 丢弃。
                            if let Some((kind, snapshot)) =
                                runtime_event_from_status(&status_event, &composition).await
                            {
                                refresh_bus_proxy_tun(&events, &proxy_tun_probe);
                                refresh_bus_system_proxy(&events, &system_proxy_probe);
                                // S3/D5 修复：Connected 过渡时刷新 SCM 服务状态缓存——
                                // 服务可能由外部/bootstrap 启动，缓存若停留在 connect 前
                                // 旧值，WatchEvents 快照会让 UI 显示「已停止」而实际 Running。
                                //
                                // C3a：Connected = 一次真实成功连接（新连接生命周期）——
                                // 清零 per-connection 重连计数 + 释放重连在途标记（预算回到 0）。
                                if let EngineStatusEvent::Connected { .. } = &status_event {
                                    reconnect_attempts.store(0, Ordering::Relaxed);
                                    reconnect_active.store(false, Ordering::Release);
                                    if let Some(service_status) =
                                        query_service_status(&RealServiceStatusSource, SERVICE_NAME)
                                            .ok()
                                            .map(|snap| {
                                                let health = derive_health(
                                                    &service_health_from_snapshot(&snap),
                                                );
                                                service_status_to_wire(&snap, health)
                                            })
                                    {
                                        events.refresh_service_status(Some(service_status));
                                    }
                                }
                                // C3a：任何终态（Failed/Stopped）都释放重连在途标记——
                                // 本次重连尝试已结束（成功/失败），允许下一次可重试掉线触发。
                                if matches!(
                                    &status_event,
                                    EngineStatusEvent::Failed { .. }
                                        | EngineStatusEvent::Stopped { .. }
                                ) {
                                    reconnect_active.store(false, Ordering::Release);
                                }
                                // C4 wire unfreeze：发布前把当前重连状态附加到快照
                                // （forwarder 持 Arc + config_dir；GetSnapshot 同源组装）。
                                events.publish(
                                    kind,
                                    snapshot_with_reconnect(
                                        snapshot,
                                        Some(reconnect_status_from_config(
                                            &reconnect_attempts,
                                            &reconnect_active,
                                            &config_dir,
                                        )),
                                    ),
                                );
                                // C3a：可重试数据面掉线（stage=DataPlane + retry=
                                // RetrySameOperation——C2 唯一来源）→ 触发自动重连。
                                // 异步信号给重连 worker（worker 内再判 auto_reconnect 与
                                // 预算/在途）；不阻塞事件循环。未开启 auto_reconnect 时
                                // 由 worker 记「已掉线但未开启」日志（Connected 不降级，
                                // 保持现状）。
                                if let EngineStatusEvent::Failed { error, .. } = &status_event {
                                    if is_retryable_disconnect(error) {
                                        let _ = logs.append_core(
                                            "info",
                                            "kernel",
                                            "kernel.reconnect.trigger",
                                            "retryable data-plane drop detected; signaling reconnect worker",
                                            &BTreeMap::new(),
                                        );
                                        // worker 未拉起时 `None`，信号丢弃（无重连语义）。
                                        if let Some(tx) = reconnect_tx.lock().unwrap().as_ref() {
                                            let _ = tx.send(());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                if engine_swapped {
                    // 换点前已撤销 status_ready；回到循环后从 EngineSlot 重新挂接。
                    continue;
                }
                // 状态流 EOF = engine 断开：撤销就绪（R3-C3 防 stale-true——退避窗口内
                // 派发不误判已挂接）→ R2 收敛双保险（engine 侧 Idle 终态可能随断线丢失
                // → 若本机正在停机收敛,补数据面侧加入→Stopped/Idle）→ 发布断线过渡 +
                // 退避重连（无 resume tick；状态机为单一事实源，重连后从当前 phase 继续）。
                let _ = status_ready.send(false);
                composition.lock().await.synthesize_data_plane_join();
                let snapshot = snapshot_with_reconnect(
                    disconnected_snapshot(&*composition.lock().await),
                    Some(reconnect_status_from_config(
                        &reconnect_attempts,
                        &reconnect_active,
                        &config_dir,
                    )),
                );
                refresh_bus_proxy_tun(&events, &proxy_tun_probe);
                refresh_bus_system_proxy(&events, &system_proxy_probe);
                events.publish(wire::RuntimeEventKind::Transition, snapshot);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(ENGINE_EVENT_RECONNECT_MAX);
            }
        })
    }

    /// 订阅 engine 统计流并转发到事件总线（P5-b：core 统计归一化接入 EventBus）。
    ///
    /// 后台任务循环：acquire engine `stream_stats`（seam；真实通道 = `StreamStats`）→
    /// 逐 `StatsEvent` 经 [`TrafficSample`] 以累计字节增量归一化速度（权威口径，
    /// engine `rx_rate`/`tx_rate` convenience 不使用）→ [`EventBus::publish_stats`] 发布
    /// 到统计 lane → 统计流 EOF（engine 断开）→ 退避重连并**重建采样状态**（累计
    /// 计数即天然断点，重连后首条样本速率为 0，不跨断点虚构流量）。调用方（P3-c2 进程
    /// 生命周期 / `serve_kernel_control_pipe`）在 engine 就绪后与事件转发器一并拉起；
    /// 返回 `JoinHandle` 供测试保持/终止。
    #[must_use]
    pub fn spawn_stats_forwarder(&self) -> tokio::task::JoinHandle<()> {
        let slot = self.engine.clone();
        let events = Arc::clone(&self.events);
        tokio::spawn(async move {
            let mut backoff = ENGINE_EVENT_RECONNECT_BASE;
            // 与状态转发器一样监听 route/respawn 的 engine 换点：仅重连到旧 engine
            // 的 stats 流会使 UI 在已连接时永久拿不到新数据面的累计计数和速率。
            let mut slot_swaps = slot.subscribe_swaps();
            loop {
                let stream = {
                    // 从槽取当前 engine（P3 respawn 后自动指向新 engine）。
                    let engine = slot.current().await;
                    let mut guard = engine.lock().await;
                    match guard.stream_stats(0).await {
                        Ok(stream) => stream,
                        Err(_) => {
                            // 无法订阅（断线）：退避后重试。
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(ENGINE_EVENT_RECONNECT_MAX);
                            continue;
                        }
                    }
                };
                backoff = ENGINE_EVENT_RECONNECT_BASE;
                // 每次订阅重建采样状态：StreamStats 从当前累计计数开始，重连后首条
                // 样本速率 0，不把断点间隔误算为流量。
                let mut sample = TrafficSample::new();
                let mut stream = stream;
                let mut engine_swapped = false;
                loop {
                    tokio::select! {
                        changed = slot_swaps.changed() => {
                            // 所有 sender 已释放时没有可重连的 engine，结束任务。
                            if changed.is_err() {
                                return;
                            }
                            engine_swapped = true;
                            break;
                        }
                        stats_event = stream.next() => {
                            let Some(ev) = stats_event else {
                                break;
                            };
                            let stats = normalize_stats(&ev, &mut sample);
                            events.publish_stats(stats);
                        }
                    }
                }
                if engine_swapped {
                    // 新 engine 已可用；跳过退避，立即对当前槽重新订阅。
                    continue;
                }
                // 统计流 EOF = engine 断开：退避重连（无 resume tick；累计计数为断点）。
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(ENGINE_EVENT_RECONNECT_MAX);
            }
        })
    }

    /// 拉起 core 侧 KeepAlive 心跳 tick 任务（P2 有界存留）：按 `period` 周期发
    /// `KeepAlive` 到 engine——engine 侧刷新 `last_heartbeat` 单调计时，15s 未收到即
    /// 自清理+自退出（hung-core / 进程句柄路径故障兜底）。持共享 engine 控制面（与
    /// 事件/统计/日志转发器一致）；停机先中止（`CoreRuntime` 在 `shutdown_core` 前
    /// abort 本任务，释放 engine client 引用）。
    ///
    /// 失败（engine 掉线）best-effort：继续 tick，engine 恢复后自动续心跳——链接终止由
    /// liveness 监视/状态转发器驱动（本任务不改变业务状态）。
    #[must_use]
    pub fn spawn_keepalive_ticker(&self, period: Duration) -> tokio::task::JoinHandle<()> {
        crate::grpc_control::spawn_keepalive_ticker(
            self.engine.clone(),
            Arc::clone(&self.selected_mode),
            period,
        )
    }

    /// 订阅 engine 结构化日志流并聚合落盘（R3：日志纯单向输出链路）。
    ///
    /// 后台任务循环：acquire engine `stream_logs`（`resume_tick = 0`，从当前流位置
    /// 开始、不补拉——断线缺口由 engine raw 文件离线对账，O4）→ 逐条经
    /// [`ingest_engine_stream`] 落盘到共享聚合服务（磁盘为唯一真相源）→ 流 EOF /
    /// transport 错误（engine 断开）→ 退避重连。**纯单向输出**（D3 铁律）：本转发器
    /// 只写日志文件，绝不发布状态事件、绝不驱动状态机——`logs_never_drive_state`
    /// 不变量由此保持。调用方（P3-c2 进程生命周期 / `serve_kernel_control_pipe`）在
    /// engine 就绪后与事件/统计转发器一并拉起；返回 `JoinHandle` 供测试保持/终止。
    #[must_use]
    pub fn spawn_log_forwarder(&self) -> tokio::task::JoinHandle<()> {
        let slot = self.engine.clone();
        let logs = Arc::clone(&self.logs);
        let mut slot_swaps = slot.subscribe_swaps();
        tokio::spawn(async move {
            let mut backoff = ENGINE_LOG_RECONNECT_BASE;
            loop {
                let stream = {
                    // 从槽取当前 engine（P3 respawn / 路由换点后自动指向新 engine）。
                    let engine = slot.current().await;
                    let mut guard = engine.lock().await;
                    match guard.stream_logs(0).await {
                        Ok(stream) => stream,
                        Err(_) => {
                            // 无法订阅（断线）：退避后重试（日志缺口由 raw 离线对账）。
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(ENGINE_LOG_RECONNECT_MAX);
                            continue;
                        }
                    }
                };
                backoff = ENGINE_LOG_RECONNECT_BASE;
                let mut stream = std::pin::pin!(stream);
                let mut engine_swapped = false;
                loop {
                    tokio::select! {
                        changed = slot_swaps.changed() => {
                            // 路由换点（oneshot→service 等）：当前 log 流属于旧 engine。
                            // 中断本流、回到外层重新挂接新 engine——修复此前日志转发器
                            // 不监听换点、服务引擎日志从不进入聚合器的问题。
                            if changed.is_err() {
                                return;
                            }
                            engine_swapped = true;
                            break;
                        }
                        next = stream.next() => {
                            match next {
                                Some(Ok(event)) => {
                                    if let Err(e) = logs.append_engine(&event) {
                                        tracing::warn!(error = %e, "aggregate engine log failed");
                                    }
                                }
                                Some(Err(status)) => {
                                    tracing::warn!(error = %status, "engine log stream transport error; reconnect");
                                    break;
                                }
                                None => break, // EOF：退避重连。
                            }
                        }
                    }
                }
                if engine_swapped {
                    continue;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(ENGINE_LOG_RECONNECT_MAX);
            }
        })
    }
}

#[tonic::async_trait]
impl KernelControl for KernelControlService {
    type WatchEventsStream = WatchEventsStream;

    async fn connect(
        &self,
        request: Request<ConnectRequest>,
    ) -> Result<Response<OperationReply>, Status> {
        self.require_authorized().await?;
        let mut req = request.into_inner();
        let intent = match req.intent.take() {
            Some(intent) => intent,
            None => return Err(Status::invalid_argument("connect: missing connect intent")),
        };
        validate_intent(&intent)?;
        // 凭据来自 host 磁盘（P3-a：config + key.bin），UI 提供的一次性 secret_payload
        // 被忽略——但为卫生起见，绝不让其明文驻留 host 内存：确定性零化后随 req drop。
        zeroize_connect_secret(&mut req);

        // 纯逻辑核心（admission → route → attach-before-apply → execute_connect）与
        // C3a 自动重连共用；凭据始终从磁盘重新组装，本方法不持有 UI 的一次性 secret。
        self.run_connect(intent).await
    }

    async fn respond_interaction(
        &self,
        request: Request<InteractionResponse>,
    ) -> Result<Response<OperationReply>, Status> {
        self.require_authorized().await?;
        let response = request.into_inner();
        validate_interaction_response(&response)?;

        // P3-c1：经 seam 转发 engine。engine 冻结 wire 无 interaction RPC → 真实实现
        // 返回 typed `Unimplemented`（P5 补 wire 后替换）；fake 观测转发语义。
        let engine = self.engine.current().await;
        let mut engine = engine.lock().await;
        let reply = engine
            .respond_interaction(response)
            .await
            .map_err(grpc_error_to_status)?;
        drop(engine);

        self.logs
            .append_core(
                "info",
                "kernel",
                "kernel.interaction.responded",
                "interaction response forwarded to engine",
                &BTreeMap::new(),
            )
            .ok();
        Ok(Response::new(reply))
    }

    async fn stop(
        &self,
        request: Request<StopRequest>,
    ) -> Result<Response<OperationReply>, Status> {
        self.require_authorized().await?;
        let req = request.into_inner();
        let intent = req
            .intent
            .ok_or_else(|| Status::invalid_argument("stop: missing stop intent"))?;
        validate_stop_intent(&intent)?;

        // R1：stop 受理即驱动状态机（Connected/Connecting/Failed → Stopping）。
        // 状态机单一事实源：用户 Stop 是唯一业务取消，立即反映到 phase。控制面（host）
        // 侧即加入 teardown 屏障；engine 状态流先发 Idle（数据面侧）→ 双侧齐 → Stopped
        //（R1 收敛；R2 再补 core 合成 Idle 双保险）。
        let operation_id = intent
            .lookup_key
            .as_ref()
            .and_then(|k| <[u8; 16]>::try_from(k.operation_id.as_slice()).ok());
        {
            let mut composition = self.composition.lock().await;
            composition.apply(HostEvent::Disconnect);
            composition.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl));
            if let Some(id) = operation_id {
                composition.set_operation_id(id);
            }
        }

        // R1 attach-before-apply（硬约束）：先等 status 流挂接再派发 StopTunnel——
        // 停止收敛（engine 先发 Idle）也走独立 status 通道。
        self.await_status_ready().await;

        // engine 派发：StopTunnel 携带 stop 意图的 lookup_key + request_digest。
        let engine = self.engine.current().await;
        let mut engine = engine.lock().await;
        // P1-b lease 前置：StopTunnel 同样经 `bind_mutation` 要求 `core.owner`（幂等
        // ensure——即使无 prior connect 或 engine 重连后也满足，避免
        // `failed_precondition("no owner lease established")`）。
        engine
            .ensure_owner_lease()
            .await
            .map_err(grpc_error_to_status)?;
        // Bug E：engine-facing `StopTunnelRequest` 的 `wire_key.method` 必须是 engine
        // `stop_tunnel` 期待的 `StopTunnel`——UI Stop 意图的 method=Stop 直接传给 engine
        // 会让 `kernel_request_to_operation` 判 "kernel: operation: out of scope"。转换只改
        // method，保留 runtime_epoch/operation_id。
        let mut engine_key = intent.lookup_key.clone();
        if let Some(key) = engine_key.as_mut() {
            key.method = wire::OperationMethod::StopTunnel as i32;
        }
        let reply = engine
            .stop_tunnel(StopTunnelRequest {
                lookup_key: engine_key,
                request_digest: intent.request_digest.clone(),
            })
            .await
            .map_err(grpc_error_to_status)?;
        drop(engine);

        self.logs
            .append_core(
                "info",
                "kernel",
                "kernel.stop.dispatched",
                "stop dispatched to engine",
                &BTreeMap::new(),
            )
            .ok();
        Ok(Response::new(operation_reply_from_stop(&reply)))
    }

    async fn reconcile(
        &self,
        request: Request<ReconcileRequest>,
    ) -> Result<Response<OperationReply>, Status> {
        self.require_authorized().await?;
        let req = request.into_inner();
        let key = req
            .key
            .ok_or_else(|| Status::invalid_argument("reconcile: missing operation key"))?;
        let intent = ReconcileIntent::from_wire(key.clone(), req.request_digest.clone())
            .map_err(|e| Status::invalid_argument(e))?;

        // engine 派发：HelperControl 无 Reconcile RPC，经 GetOperation 观察当前义务的
        // disposition。
        let engine = self.engine.current().await;
        let mut engine = engine.lock().await;
        let op = engine
            .get_operation(GetOperationRequest {
                lookup_key: Some(intent.key.clone()),
            })
            .await
            .map_err(grpc_error_to_status)?;

        // P3-c1：义务未终局（Pending/Unknown/Absent/Rejected）→ 真实重试决策后经
        // `retry_obligation` seam 派发（重新 apply/acquire）。engine 义务模型未在冻结
        // wire 上（HelperControl 无 Reconcile RPC）→ seam 当前返回 typed `Unimplemented`
        // —— host 保留观测 disposition 作为回执并标注，不把重试缺失降级为 RPC 失败。
        if reconcile_retry_plan(&op.state) == ReconcileRetry::Retry {
            match engine
                .retry_obligation(ReconcileRequest {
                    key: Some(intent.key),
                    request_digest: intent.request_digest.clone(),
                })
                .await
            {
                Ok(_) => {}
                Err(GrpcClientError::Rpc(Code::Unimplemented, _)) => {
                    self.logs
                        .append_core(
                            "warn",
                            "kernel",
                            "kernel.reconcile.retry.unwired",
                            "engine obligation retry not on frozen wire (P3-c2 seam)",
                            &BTreeMap::new(),
                        )
                        .ok();
                }
                // 其余错误（掉线/超时）：保留观测 disposition，不掩盖 RPC 回执。
                Err(_) => {}
            }
        }
        drop(engine);

        self.logs
            .append_core(
                "info",
                "kernel",
                "kernel.reconcile.observed",
                "reconcile observed obligation disposition",
                &BTreeMap::new(),
            )
            .ok();
        Ok(Response::new(operation_reply_from_operation_state(
            op.state,
        )))
    }

    async fn get_operation(
        &self,
        request: Request<GetKernelOperationRequest>,
    ) -> Result<Response<KernelOperationReply>, Status> {
        // 读路径不 gate（与 GetSnapshot/WatchEvents 一致）：路由到 engine GetOperation
        // 真实读取义务/操作 disposition。
        let key = request
            .into_inner()
            .key
            .ok_or_else(|| Status::invalid_argument("get_operation: missing operation key"))?;
        let engine = self.engine.current().await;
        let mut engine = engine.lock().await;
        let op = engine
            .get_operation(GetOperationRequest {
                lookup_key: Some(key),
            })
            .await
            .map_err(grpc_error_to_status)?;
        drop(engine);
        Ok(Response::new(KernelOperationReply { state: op.state }))
    }

    async fn get_snapshot(
        &self,
        _request: Request<SnapshotRequest>,
    ) -> Result<Response<RuntimeSnapshot>, Status> {
        // P3-c1 源化：先经 engine `ObserveOwnedState` 拉真实快照（engine 是状态权威）；
        // engine 掉线或返回 Idle 占位（无真实数据）时回落 composition 派生的确定性
        // 快照（`prefer_snapshot` 选择源）。engine 锁在块结束即释放（不跨 await 持锁）。
        let engine_snapshot = {
            let engine = self.engine.current().await;
            let mut engine = engine.lock().await;
            engine
                .observe_owned_state(ObserveOwnedStateRequest { lookup_key: None })
                .await
                .ok()
                .and_then(|reply| reply.snapshot)
        };
        let composition = self.composition.lock().await;
        let composition_snapshot = snapshot_for_phase(composition.phase(), &composition);
        let confirmed_session_start = composition.session_established_at_ms();
        drop(composition);
        // P5-wire 方案 A：把 EventBus 统计 lane 的最新样本附加到快照（无样本 → None）。
        let stats = self.events.current_stats();
        // C5-wire：GetSnapshot 是 UI 拉取点——每次调用探测一次上游 proxy TUN 并刷新
        // 进事件总线缓存（启动即带共存状态，badge 无需等首次 engine 事件）。探测失败
        // → 缓存 None（`proxy_tun` 留空，状态上报不因探测失败而失败）。
        refresh_bus_proxy_tun(&self.events, &self.proxy_tun_probe);
        let proxy_tun = self.events.current_proxy_tun();
        // EXV_UNFREEZE：同点探测一次系统代理并刷新进缓存（启动即带系统代理感知状态，
        // 无需等首次 engine 事件）。探测失败 → 缓存 None（`system_proxy` 留空）。
        refresh_bus_system_proxy(&self.events, &self.system_proxy_probe);
        let system_proxy = self.events.current_system_proxy();
        // S3/D5：服务感知——GetSnapshot 是服务状态的拉取点（非提权查询；失败 → None，
        // 状态上报不因查询失败而失败）+ 模式展示（缺省 auto）。查询/模式同时刷新进
        // 事件总线缓存（`WatchEvents` 随快照附加同一事实）。
        let service_status = self.query_service_status_wire();
        let mode = self.mode_string();
        self.events.refresh_service_status(service_status.clone());
        self.events.refresh_service_mode(Some(mode.clone()));
        // C3a/C4：GetSnapshot 是重连状态的拉取点——从 host 原子 + config 组装
        // ReconnectStatus 并附加到快照（config 读失败 → 保守禁用 false/0）。
        let reconnect = reconnect_status_from_config(
            &self.reconnect_attempts,
            &self.reconnect_active,
            &self.config_dir,
        );
        Ok(Response::new(snapshot_with_reconnect(
            snapshot_with_service_context(
                snapshot_with_system_proxy(
                    snapshot_with_proxy_tun(
                        snapshot_with_stats(
                            snapshot_with_confirmed_session_start(
                                prefer_snapshot(engine_snapshot, composition_snapshot),
                                confirmed_session_start,
                            ),
                            stats,
                        ),
                        proxy_tun,
                    ),
                    system_proxy,
                ),
                service_status,
                Some(mode),
            ),
            Some(reconnect),
        )))
    }

    async fn watch_events(
        &self,
        request: Request<WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        // 读路径不 gate（与 GetSnapshot 一致）。真实订阅（P3-c1）：resume_tick 语义见
        // [`EventBus::subscribe`]——0 = 从当前快照开始；落后 → 重放当前快照；随后
        // 转发 tick 递增的现场事件。事件由 engine 状态转发器（`spawn_status_forwarder`）
        // 与写路径发布。
        let resume_tick = request.into_inner().resume_tick;
        let stream = self
            .events
            .subscribe(resume_tick)
            .map(Ok::<RuntimeEvent, Status>);
        Ok(Response::new(Box::pin(stream)))
    }

    async fn logs_list(
        &self,
        request: Request<LogsListRequest>,
    ) -> Result<Response<LogsListReply>, Status> {
        // 读路径不 gate（与 GetSnapshot 一致）：拉聚合日志历史（磁盘文件为真相源）。
        // 磁盘读取是阻塞 I/O：放 blocking pool，避免卡住 async worker——否则日志加载期间
        // 同 runtime 上的其它 RPC（连接/停止/设置）全部排队（并发响应被阻断）。
        let req = request.into_inner();
        let limit = if req.limit == 0 {
            100
        } else {
            req.limit as usize
        };
        let logs = Arc::clone(&self.logs);
        let page = tokio::task::spawn_blocking(move || logs.list(req.after_seq, limit))
            .await
            .map_err(|e| Status::internal(format!("logs_list: join {e}")))?
            .map_err(|e| Status::internal(format!("logs_list: {e:?}")))?;
        let entries = page
            .entries
            .into_iter()
            .map(|e| wire::LogEvent {
                level: e.level,
                component: e.component,
                code: e.code,
                message: e.message,
                fields: e.fields.into_iter().collect(),
                timestamp_ms: e.timestamp_ms,
            })
            .collect();
        Ok(Response::new(LogsListReply {
            entries,
            next_seq: page.next_seq,
        }))
    }

    async fn logs_clear(
        &self,
        _request: Request<LogsClearRequest>,
    ) -> Result<Response<LogsClearReply>, Status> {
        // 写路径 gate：清空聚合日志（运维操作，mutates 磁盘）。磁盘写放 blocking pool。
        self.require_authorized().await?;
        let removed = self.logs.last_seq();
        let logs = Arc::clone(&self.logs);
        tokio::task::spawn_blocking(move || logs.clear())
            .await
            .map_err(|e| Status::internal(format!("logs_clear: join {e}")))?
            .map_err(|e| Status::internal(format!("logs_clear: {e:?}")))?;
        Ok(Response::new(LogsClearReply {
            cleared: true,
            removed_entries: removed,
        }))
    }

    async fn config_get(
        &self,
        _request: Request<ConfigGetRequest>,
    ) -> Result<Response<ConfigPayload>, Status> {
        // 读路径不 gate：返回非 secret 配置项。
        let cfg = ExvConfig::load_from_dir(&self.config_dir)
            .map_err(|e| Status::internal(format!("config_get: {e:?}")))?;
        // password 是 AES-GCM 密文 blob：不回显（防泄漏），仅 remember_password 反映其状态。
        let items = vec![
            ConfigItem {
                key: "server".into(),
                value: cfg.server,
            },
            ConfigItem {
                key: "username".into(),
                value: cfg.username,
            },
            ConfigItem {
                key: "remember_password".into(),
                value: cfg.remember_password.to_string(),
            },
            ConfigItem {
                key: "routes".into(),
                value: cfg.routes.join(","),
            },
            ConfigItem {
                key: "user_agent".into(),
                value: cfg.user_agent,
            },
            ConfigItem {
                key: "mtu".into(),
                value: cfg.mtu.to_string(),
            },
            ConfigItem {
                key: "auto_reconnect".into(),
                value: cfg.auto_reconnect.to_string(),
            },
            ConfigItem {
                key: "auto_reconnect_max_attempts".into(),
                value: cfg.auto_reconnect_max_attempts.to_string(),
            },
        ];
        Ok(Response::new(ConfigPayload { items }))
    }

    async fn config_set(
        &self,
        request: Request<ConfigSetRequest>,
    ) -> Result<Response<ConfigReply>, Status> {
        // 写路径 gate：应用并持久化配置。
        self.require_authorized().await?;
        let mut cfg = ExvConfig::load_from_dir(&self.config_dir)
            .map_err(|e| Status::internal(format!("config_set: load {e:?}")))?;
        for item in request.into_inner().items {
            match item.key.as_str() {
                "server" => cfg.server = item.value,
                "username" => cfg.username = item.value,
                "remember_password" => {
                    cfg.remember_password = item.value.parse().map_err(|_| {
                        Status::invalid_argument("config_set: remember_password must be true/false")
                    })?;
                    // C++ 对齐（config_api.cpp）：不记住密码 → 清除已存密码（遗忘凭据）。
                    // 保留 key.bin——host 启动 ensure_key 已保证存在，未来重新保存密码可用。
                    if !cfg.remember_password {
                        cfg.password = String::new();
                    }
                }
                "routes" => {
                    cfg.routes = item
                        .value
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                }
                "user_agent" => cfg.user_agent = item.value,
                "mtu" => {
                    cfg.mtu = item
                        .value
                        .parse()
                        .map_err(|_| Status::invalid_argument("config_set: mtu must be a number"))?
                }
                "auto_reconnect" => {
                    cfg.auto_reconnect = item.value.parse().map_err(|_| {
                        Status::invalid_argument("config_set: auto_reconnect must be true/false")
                    })?
                }
                "auto_reconnect_max_attempts" => {
                    cfg.auto_reconnect_max_attempts = item.value.parse().map_err(|_| {
                        Status::invalid_argument(
                            "config_set: auto_reconnect_max_attempts must be a number",
                        )
                    })?
                }
                "password" => {
                    // 密码 AES-GCM 加密存储；留空 = 保持已保存密码（不修改）。
                    if !item.value.is_empty() {
                        let key = match ExvConfig::load_key(&self.config_dir) {
                            Ok(Some(key)) => key,
                            Ok(None) => {
                                return Err(Status::internal(
                                    "config_set: password key unavailable (reinstall?)",
                                ));
                            }
                            Err(e) => {
                                return Err(Status::internal(format!(
                                    "config_set: password key read {e:?}"
                                )));
                            }
                        };
                        cfg.set_password_encrypted(&item.value, &key)
                            .map_err(|e| Status::internal(format!("config_set: password encrypt {e:?}")))?;
                    }
                }
                _ => {
                    return Err(Status::invalid_argument(format!(
                        "config_set: unknown key '{}'",
                        item.key
                    )));
                }
            }
        }
        cfg.save_to_dir(&self.config_dir)
            .map_err(|e| Status::internal(format!("config_set: save {e:?}")))?;
        Ok(Response::new(ConfigReply { ok: true }))
    }

    async fn service_control(
        &self,
        request: Request<ServiceControlRequest>,
    ) -> Result<Response<ServiceControlReply>, Status> {
        let req = request.into_inner();
        let action = req
            .action
            .ok_or_else(|| Status::invalid_argument("service_control: no action"))?;
        // UI 已经有 busy 门，但 Core 仍必须把服务生命周期操作串行化：重复点击、
        // 多窗口或迟到 RPC 不能让 install/uninstall/start 交叉修改同一个 SCM 条目。
        let _service_transition_guard = if matches!(
            &action,
            service_control_request::Action::Query(_)
        ) {
            None
        } else {
            Some(self.service_control_lock.lock().await)
        };
        // 变更动作（install/uninstall/start）走 write path gate；query 为非提权读。
        match action {
            service_control_request::Action::Query(_) => {
                // S3-B：query 含健康加深（SCM Running/StartPending 时有界调 engine
                // 深度自述，把报告折进 health_state）。
                self.service_control_query_reply().await
            }
            service_control_request::Action::Install(_) => {
                self.require_authorized().await?;
                if let Err(error) = self.stop_engine_for_transition(ServiceMode::Oneshot).await {
                    return self.service_control_reply(true, Err(error)).await;
                }
                let outcome = self.service_ops.install().await;
                match outcome {
                    Ok(_) => {
                        // 安装成功后清除上一次卸载的 SCM 语义覆盖。安装阶段仍是
                        // auto：只有真正换入 service engine 的 connect 才记录 service，
                        // 避免把"安装完成"误当成"当前连接已经使用服务"。
                        self.clear_service_removed_override();
                        match self.ensure_service_ready().await {
                            Ok(readiness) => self.service_control_start_reply(readiness).await,
                            Err(error) => self.service_control_reply(true, Err(error)).await,
                        }
                    }
                    Err(error) => self.service_control_reply(true, Err(error)).await,
                }
            }
            service_control_request::Action::Uninstall(_) => {
                self.require_authorized().await?;
                if let Err(error) = self.stop_engine_for_transition(ServiceMode::Service).await {
                    return self.service_control_reply(true, Err(error)).await;
                }
                let outcome = self.service_ops.uninstall().await;
                if outcome.is_ok() {
                    // DeleteService 已返回成功；SCM marked-for-delete 的短暂残留不再
                    // 影响本次事务的业务状态回传。
                    self.mark_service_removed();
                    // 卸载完成的边界同时切回初始 oneshot。不能只改展示 mode：否则
                    // ticker 会把 KeepAlive 发给已经停止的 service client，初始 oneshot
                    // watchdog 随后退出并由 CoreRuntime 关闭 admission，下一次一次性
                    // connect 就会得到 `connect: admission closed`。
                    self.swap_engine_for_route(self.oneshot_engine.clone()).await;
                    self.record_mode(ServiceMode::Oneshot);
                }
                let outcome = outcome.map(|msg| friendly_service_message("uninstall", &msg));
                self.service_control_reply(true, outcome).await
            }
            service_control_request::Action::Start(_) => {
                self.require_authorized().await?;
                match self.ensure_service_ready().await {
                    Ok(readiness) => self.service_control_start_reply(readiness).await,
                    Err(error) => self.service_control_reply(true, Err(error)).await,
                }
            }
            // 服务停止 = 错误态（A5），修复对策是启动；wire 已删 Stop（tag 5 reserved），
            // match 四个显式 action 完备即穷尽，未知 action 由外层校验拒绝。
        }
    }
}

/// 把引擎侧硬编码的 `"batch completed"` 替换为面向用户的人类可读完成信息。
///
/// `msg` 非 `"batch completed"` 时原样返回（引擎失败信息、非标准路径均不拦截）。
fn friendly_service_message(action: &str, msg: &str) -> String {
    if msg == "batch completed" {
        match action {
            "install" => "服务安装完成并已启动。".to_string(),
            "uninstall" => "服务卸载完成。".to_string(),
            "start" => "服务已启动。".to_string(),
            _ => msg.to_string(),
        }
    } else {
        msg.to_string()
    }
}

impl KernelControlService {
    /// 组装 ServiceControl 回复：post-action 服务状态 + `ok` + 人类可读信息。
    ///
    /// 查询失败（SCM 打开/读取异常）→ `ok=false` + 错误信息，`service_status` 留空；
    /// 变更动作成功 → `ok=true` + 携带的完成信息；失败 → `ok=false` + 原因。
    async fn service_control_reply(
        &self,
        _is_mutation: bool,
        outcome: Result<String, String>,
    ) -> Result<Response<ServiceControlReply>, Status> {
        let (ok, message) = match outcome {
            Ok(msg) => (true, msg),
            Err(e) => (false, e),
        };
        let service_status = self.query_service_status_wire();
        self.events.refresh_service_status(service_status.clone());
        Ok(Response::new(ServiceControlReply {
            service_status,
            ok,
            message,
        }))
    }

    /// S3-B：组装 ServiceControl **query** 回复——SCM 状态 + **健康加深**。
    ///
    /// 与既有 [`Self::service_control_reply`] 的差异：query 是非提权读，且在 SCM 状态为
    /// Running/StartPending（服务在途/运行）时有界调用 engine 深度自述
    /// （`ServiceProbe::probe_self_report` → `ServiceManage.query`，Tier 2 零 UAC 通道），
    /// 把报告折进 `health_state`：self-not-ready → `InstalledUnavailable`（SCM Running 但
    /// 引擎控制面未就绪 / PSK 缺席）；探针失败（拨号/PSK/超时）→ 保守保留 SCM 派生。
    /// 非 Running/StartPending 不触发探针（A6）。
    async fn service_control_query_reply(&self) -> Result<Response<ServiceControlReply>, Status> {
        let service_status = self.query_service_status_deepened().await;
        self.events.refresh_service_status(service_status.clone());
        Ok(Response::new(ServiceControlReply {
            service_status,
            ok: true,
            message: "ok".to_string(),
        }))
    }

    /// S3-B：SCM 快照 → 健康加深后的 wire `ServiceStatus`。
    ///
    /// 廉价事实（`service_health_from_snapshot`）随快照计算；Running/StartPending 时
    /// 追加一次 engine 深度自述探活，报告折进 [`derive_health_with_self_report`]。
    async fn query_service_status_deepened(&self) -> Option<wire::ServiceStatus> {
        let snap = self.query_service_status_snapshot()?;
        let health = service_health_from_snapshot(&snap);
        let deepened = if matches!(
            health.state,
            ServiceState::Running | ServiceState::StartPending
        ) {
            // 有界探活（复用 keepalive 探针时限）；失败保守（None → 保留 SCM 派生）。
            let report = self.service_probe.probe_self_report().await;
            derive_health_with_self_report(&health, report.as_ref())
        } else {
            derive_health(&health)
        };
        Some(service_status_to_wire(&snap, deepened))
    }

    /// 组装 ServiceControl **Start** 回复（R2）：以 [`wait_for_service_ready`] 的就绪事实
    /// 驱动 `ok`/`message`（+ 最新 SCM 状态）。
    ///
    /// - 就绪（SCM running 或 keepalive 回复）→ `ok=true`，message 标注达成来源；
    /// - 超时（两者都未达成）→ `ok=false`，message 携带最后一次 SCM 状态 + keepalive
    ///   未响应 + 耗时（前端可读，非「操作未完成」）。
    async fn service_control_start_reply(
        &self,
        readiness: ServiceReadiness,
    ) -> Result<Response<ServiceControlReply>, Status> {
        let (ok, message) = if readiness.ready {
            let source = match readiness.source {
                ReadinessSource::Keepalive => "keepalive 回复".to_string(),
                _ => "SCM running".to_string(),
            };
            (true, format!("服务已就绪（{source}）"))
        } else {
            let scm_desc = match readiness.scm_state {
                Some(s) => format!("SCM 状态={s:?}"),
                None => "SCM 状态未知".to_string(),
            };
            (
                false,
                format!(
                    "服务启动超时（{}ms）：{scm_desc}，keepalive 未响应",
                    readiness.elapsed_ms
                ),
            )
        };
        let service_status = self.query_service_status_wire();
        self.events.refresh_service_status(service_status.clone());
        Ok(Response::new(ServiceControlReply {
            service_status,
            ok,
            message,
        }))
    }
}

impl KernelControlService {
    /// 写 RPC 的前置 gate 检查：transport peer 未授权 → `unauthenticated`。
    ///
    /// `KernelControlGate` 在 composition 内；授权由 transport peer 认证路径驱动
    /// （P3-c1 `authorize_transport_peer`，进程生命周期 P3-c2 在传输层认证后调用）。
    /// 本实现执行 fail-closed 的拒绝路径——任何未经授权的写 RPC 一律拒绝。
    async fn require_authorized(&self) -> Result<(), Status> {
        let mut composition = self.composition.lock().await;
        if !composition.kernel_gate().is_authorized() {
            return Err(Status::unauthenticated(
                "KernelControl transport peer not authorized (gate wiring lands in P3-c)",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Connect：凭据生命周期 + engine 派发 + 发送后零化（纯逻辑，测试可注入 fake engine）。
// ---------------------------------------------------------------------------

/// 执行一次 Connect：读凭据 → 组装一次性 `secret_payload` → 构建 KernelControl
/// `ConnectRequest`（`secret_payload` 即 wire 副本）→ 经 engine `apply_connect` 派发
/// （P3-b1 把秘密移入 `ApplyTunnelRequest.secret_payload`，随 wire 走）→ 发送后确定性
/// 零化 wire 副本。
///
/// 返回 engine reply 与**已零化**的 wire 副本（测试断言发送后零化）。失败路径由
/// `CredentialsBundle` 的 RAII 兜底零化明文，host 状态不变。
///
/// # Errors
/// 凭据缺失/解密失败 → `Status::internal`；意图非法 → `Status::invalid_argument`；
/// engine 掉线/超时/拒绝 → 相应 `Status`。
async fn execute_connect(
    engine: &mut dyn KernelEngineControl,
    config_dir: &Path,
    intent: wire::ConnectIntent,
) -> Result<(ApplyTunnelReply, ConnectRequest), Status> {
    // 凭据生命周期（P3-a）：config + key.bin → 解密 → 组装一次性 secret_payload。
    let mut bundle = load_credentials(config_dir)
        .map_err(|e| Status::internal(format!("connect: credential load: {e}")))?;
    let payload = bundle
        .assemble_secret_payload()
        .map_err(|e| Status::internal(format!("connect: secret assembly: {e}")))?;

    // KernelControl wire 副本（`secret_payload` 即一次性明文载体；发送后零化）。
    let mut connect_req = build_connect_request(intent.clone(), payload);
    // engine 请求：lookup_key/request_digest 派生自 connect 意图；plan 从 config 近似
    // 组装（真实协商地址/路由由 CSTP 协商 P5 替换）；`secret_payload` 由 `apply_connect`
    // 从 one-shot 槽移入。
    let apply = apply_request_from_connect(&connect_req, &bundle.config)?;

    // P1-b lease 前置：engine 的 `ApplyTunnel` 经 `bind_mutation` 要求 `core.owner` 已建立
    // （MaintainOwnerLease 授权握手）——缺失时 engine 返回 `failed_precondition("no owner
    // lease established")`。`ensure_owner_lease` 幂等（已握手则直接返回）。
    engine
        .ensure_owner_lease()
        .await
        .map_err(grpc_error_to_status)?;

    // engine 派发：槽持有明文，`apply_connect` 移入 wire 并发送后零化槽（成败两路径）。
    let mut secret = ClearableSecret::new(&connect_req.secret_payload);
    let reply = engine
        .apply_connect(apply, &mut secret)
        .await
        .map_err(grpc_error_to_status)?;

    // 发送完成：确定性零化 KernelControl wire 副本（明文不再驻留）。
    zeroize_connect_secret(&mut connect_req);
    Ok((reply, connect_req))
}

/// 校验 connect 意图：`request_digest` 32 字节 + `lookup_key.method` == CONNECT。
///
/// # Errors
/// digest 长度非法 / 缺 lookup_key / method 不匹配 → `Status::invalid_argument`。
fn validate_intent(intent: &wire::ConnectIntent) -> Result<(), Status> {
    if intent.request_digest.len() != 32 {
        return Err(Status::invalid_argument(
            "connect: request digest must be 32 bytes",
        ));
    }
    let key = intent
        .lookup_key
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("connect: missing lookup key"))?;
    if key.method != wire::OperationMethod::Connect as i32 {
        return Err(Status::invalid_argument(
            "connect: lookup key method must be CONNECT",
        ));
    }
    Ok(())
}

/// 从 KernelControl `ConnectRequest` 组装 engine `ApplyTunnelRequest`。
///
/// `lookup_key`/`request_digest` 派生自 connect 意图；`plan` 从 config 近似组装
/// （P3-b2：真实隧道地址/路由由 CSTP 协商 P5 替换，此处用确定性的 config 派生计划）；
/// `secret_payload` 留空，由 [`crate::grpc_control::KernelEngineControl::apply_connect`]
/// 从 one-shot 槽移入（P3-b1 契约）。
///
/// # Errors
/// 缺 connect 意图 / 缺 lookup_key → `Status::invalid_argument`。
fn apply_request_from_connect(
    connect_req: &wire::ConnectRequest,
    config: &ExvConfig,
) -> Result<wire::ApplyTunnelRequest, Status> {
    let intent = connect_req
        .intent
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("connect: missing connect intent"))?;
    let mut lookup_key = intent
        .lookup_key
        .clone()
        .ok_or_else(|| Status::invalid_argument("connect: missing lookup key"))?;
    // Bug E：engine-facing `ApplyTunnelRequest` 的 `wire_key.method` 必须是 engine
    // `apply_tunnel` 期待的 `ApplyTunnel`——UI Connect 意图的 method=Connect 直接传给
    // engine 会让 `kernel_request_to_operation` 判 `method != expected_method ->
    // "kernel: operation: out of scope"`。转换只改 method，保留 runtime_epoch/operation_id
    //（engine 侧以认证 peer 覆盖 principal，操作身份 = peer + ApplyTunnel + 该 key）。
    lookup_key.method = wire::OperationMethod::ApplyTunnel as i32;
    let request_digest = intent.request_digest.clone();
    let plan = plan_from_config(config, &request_digest);
    Ok(ApplyTunnelRequest {
        lookup_key: Some(lookup_key),
        plan: Some(plan),
        request_digest,
        secret_payload: vec![],
    })
}

/// 从用户 config 近似组装 `TunnelPlan`（P3-b2 / C1）。
///
/// `ipv4_routes` 从 `config.routes`（CIDR）解析；`control_bypass` 从
/// `config.server_bypass_ips`（Phase 7 C1：控制面物理出口 /32 目的地，消灭 P3-b2
/// 硬编码空表）解析为 4 字节 IPv4 八位组；`mtu` 取自 config（夹到 ≥ 576）；
/// `ipv4_address` 用确定性占位（真实客户端隧道地址来自 CSTP 协商，P5 替换）；
/// `opaque_intent` 用 connect 的 `request_digest`（32 字节，标识该意图）。
///
/// T5（系统代理感知 v1，设计 §5.4 零 wire 变更路径）：豁免条目由
/// [`crate::plan_exempt::derive_proxy_exempt_entries`] 从 `server_bypass_ips` +
/// `routes` 一并派生；wire 冻结期精确 IP 成员随 `control_bypass` 到达 engine，
/// CIDR 网段结构随既有 `ipv4_routes` 到达（engine 由 plan 派生 desired bypass）。
fn plan_from_config(config: &ExvConfig, intent_digest: &[u8]) -> wire::TunnelPlan {
    let ipv4_routes = config
        .routes
        .iter()
        .filter_map(|r| {
            parse_cidr(r).map(|(network, prefix_len)| wire::Ipv4Route {
                network,
                prefix_len,
            })
        })
        .collect();
    // C1：`server_bypass_ips` → wire `control_bypass`（每项 4 字节八位组；非法条目
    // 与 routes 同策略静默跳过——`convert::tunnel_plan_from_wire` 会拒绝非 4 字节项）。
    // T5：v1 豁免条目派生并入本装配链——`derive_proxy_exempt_entries` 的精确 IP
    // 条目（server 直通 + 不转通配的 CIDR 原串中可解析为 IPv4 地址者）同样经
    // `control_bypass` 下发，通配网段结构由 `ipv4_routes` 携带。
    //
    // EXV_UNFREEZE_PENDING: v1 借道 control_bypass；proxy_exempt 独立字段见
    // docs/superpowers/evidence/2026-08-24-system-proxy-wire-unfreeze.md。
    let proxy_exempt =
        crate::plan_exempt::derive_proxy_exempt_entries(&config.server_bypass_ips, &config.routes);
    let control_bypass: Vec<Vec<u8>> = proxy_exempt
        .iter()
        .filter_map(|s| s.parse::<Ipv4Addr>().ok().map(|ip| ip.octets().to_vec()))
        .collect();
    wire::TunnelPlan {
        // P3-b2 近似：客户端隧道地址来自 CSTP 协商（P5）；此处确定性占位。
        ipv4_address: vec![0, 0, 0, 0],
        ipv4_prefix_len: 32,
        mtu: config.mtu.max(576),
        ipv4_routes,
        dns_servers: vec![],
        control_bypass,
        // EXV_UNFREEZE 2026-08-24：proxy_exempt 独立字段（wire 解冻记录）；v1
        // 借道 control_bypass 下发精确 IP，此处暂置空、待 PAC/engine 消费接线。
        proxy_exempt: Vec::new(),
        opaque_intent: Some(wire::TunnelIntentRef {
            identity_digest: intent_digest.to_vec(),
        }),
    }
}

/// 解析 CIDR（`a.b.c.d/prefix`）→ (4 字节 network, prefix_len)；非法输入 → `None`。
fn parse_cidr(cidr: &str) -> Option<(Vec<u8>, u32)> {
    let (addr, prefix) = cidr.split_once('/')?;
    let prefix_len: u32 = prefix.parse().ok()?;
    if prefix_len > 32 {
        return None;
    }
    let octets: Vec<u8> = addr
        .split('.')
        .map(|o| o.parse::<u8>().ok())
        .collect::<Option<Vec<_>>>()?;
    (octets.len() == 4).then_some((octets, prefix_len))
}

// ---------------------------------------------------------------------------
// Stop / Reconcile：完整意图组装 + engine 派发。
// ---------------------------------------------------------------------------

/// 校验 stop 意图：`request_digest` 32 字节 + `lookup_key.method` == STOP。
///
/// # Errors
/// digest 长度非法 / 缺 lookup_key / method 不匹配 → `Status::invalid_argument`。
fn validate_stop_intent(intent: &wire::StopIntent) -> Result<(), Status> {
    if intent.request_digest.len() != 32 {
        return Err(Status::invalid_argument(
            "stop: request digest must be 32 bytes",
        ));
    }
    let key = intent
        .lookup_key
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("stop: missing lookup key"))?;
    if key.method != wire::OperationMethod::Stop as i32 {
        return Err(Status::invalid_argument(
            "stop: lookup key method must be STOP",
        ));
    }
    Ok(())
}

/// Reconcile 的完整重试意图（lookup_key + request_digest）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileIntent {
    /// 义务的完整 lookup key（method 必须为 RECONCILE）。
    pub key: wire::OperationLookupKey,
    /// 重试请求摘要（32 字节）。
    pub request_digest: Vec<u8>,
}

impl ReconcileIntent {
    /// 从 wire `ReconcileRequest` 组装完整意图：校验 `key.method` == RECONCILE 与
    /// `request_digest` 长度（32 字节）。
    ///
    /// # Errors
    /// method 不匹配或 digest 长度非法 → `&'static str`。
    pub fn from_wire(
        key: wire::OperationLookupKey,
        request_digest: Vec<u8>,
    ) -> Result<Self, &'static str> {
        if key.method != wire::OperationMethod::Reconcile as i32 {
            return Err("reconcile: lookup key method must be RECONCILE");
        }
        if request_digest.len() != 32 {
            return Err("reconcile: request digest must be 32 bytes");
        }
        Ok(Self {
            key,
            request_digest,
        })
    }
}

// ---------------------------------------------------------------------------
// engine 错误 → gRPC Status；engine reply → OperationReply。
// ---------------------------------------------------------------------------

/// 把 engine 控制面错误映射为 gRPC `Status`（transport 类 → unavailable；
/// 超时 → deadline_exceeded；其余透传 code）。
fn grpc_error_to_status(e: GrpcClientError) -> Status {
    match e {
        GrpcClientError::Transport(_) | GrpcClientError::ConnectionLost => {
            Status::unavailable("engine control unavailable")
        }
        GrpcClientError::Timeout => Status::deadline_exceeded("engine control timed out"),
        GrpcClientError::Rpc(code, message) => Status::new(code, message),
    }
}

/// 确定性 controller peer + capability（R1：authorize 时绑定到 runtime actor）。
///
/// 固定字面量构造，镜像 acceptance `crash_matrix::controller_peer_and_capability` 与
/// portable H80 `peer_and_capability` 同款（portable host 测试的确定性构造）。真实
/// 绑定推导（从 `VerifiedPipePeer` 派生 PrincipalDigest/Binding）属 P3-c2 进程生命周期
/// 接线；此处为 connect 受理路径提供确定性的已绑定 actor（非伪造外部身份）。
///
/// `pub(crate)`：P3 崩溃自愈（`crash_recovery`）重建 composition 后复用同一确定性
/// actor 绑定。
pub(crate) fn controller_peer_and_capability() -> (PeerContext, PeerCapability) {
    let principal = PrincipalDigest::try_from([0u8; 32]).expect("principal digest");
    let binding = ConnectionBindingDigest::try_from([1u8; 32]).expect("binding digest");
    let metadata = VerifiedConnectionMetadata::try_from((principal.clone(), binding.clone()))
        .expect("verified metadata");
    let peer = PeerContext::try_from(metadata).expect("peer context");
    let connection = ConnectionBinding::try_from(binding).expect("connection binding");
    let capability = PeerCapability::try_from((
        connection,
        principal,
        AuthorityEpoch::try_from(7u64).expect("authority epoch"),
        OperationMethod::Connect,
        MonotonicTick::try_from(42u64).expect("monotonic tick"),
    ))
    .expect("peer capability");
    (peer, capability)
}

/// `ApplyTunnelReply` → `OperationReply`（KernelControl 通用 mutation 回执）。
fn operation_reply_from_apply(reply: &ApplyTunnelReply) -> OperationReply {
    match reply.result.as_ref() {
        Some(wire::apply_tunnel_reply::Result::Applied(receipt)) => OperationReply {
            terminal: Some(wire::OperationTerminal {
                result: Some(wire::operation_terminal::Result::Succeeded(receipt.clone())),
            }),
        },
        Some(wire::apply_tunnel_reply::Result::Failed(failed)) => OperationReply {
            terminal: Some(wire::OperationTerminal {
                result: Some(wire::operation_terminal::Result::Failed(failed.clone())),
            }),
        },
        // R1w 机械适配（仅编译通过，不做 host 逻辑重构——那是 R1 范围）：
        // engine 的 ApplyTunnel 现为异步，先回 `pending` ApplyAccepted；终态走独立
        // StreamConnectStatus 通道。OperationReply 无 pending 分支，故映射为
        // `terminal: None`（尚无终局）；host 侧的 pending→status-channel 语义映射
        // 属 R1/R4 范围，此处仅保持编译绿。
        Some(wire::apply_tunnel_reply::Result::Pending(_)) | None => {
            OperationReply { terminal: None }
        }
    }
}

/// `StopTunnelReply` → `OperationReply`。
fn operation_reply_from_stop(reply: &wire::StopTunnelReply) -> OperationReply {
    let terminal = reply.result.as_ref().map(|r| match r {
        wire::stop_tunnel_reply::Result::Stopped(receipt) => wire::OperationTerminal {
            result: Some(wire::operation_terminal::Result::Succeeded(receipt.clone())),
        },
        wire::stop_tunnel_reply::Result::Failed(failed) => wire::OperationTerminal {
            result: Some(wire::operation_terminal::Result::Failed(failed.clone())),
        },
    });
    OperationReply { terminal }
}

/// `OperationState`（Reconcile 观察到的义务 disposition）→ `OperationReply`。
///
/// 仅 `Terminal` 状态透传为终局；Pending/Unknown/Absent/Rejected 无终局 →
/// `terminal: None`（UI 视作操作仍在进行）。
fn operation_reply_from_operation_state(state: Option<OperationState>) -> OperationReply {
    let terminal = match state.and_then(|s| s.state) {
        Some(wire::operation_state::State::Terminal(t)) => Some(t),
        _ => None,
    };
    OperationReply { terminal }
}

// ---------------------------------------------------------------------------
// GetSnapshot：phase → 完整 wire snapshot（attempt/lease/proof 结构性组装）。
// ---------------------------------------------------------------------------

/// `HostPhase` → `RuntimeSnapshot` 的完整组装。
///
/// phase 对应的 state 分支携带 attempt/lease/proof 结构：身份 ref 为纯 composition 的
/// 确定性 stand-in（runtime epoch = 能力签发 epoch，packet lease = W23B 附加的 lease），
/// 真实 attempt/lease/proof 数据由 P3-c 从 engine 事件源化替换。`Stopped` 无对应
/// Kernel 状态分支（连接已终结）回落 `Idle`。
///
/// R1：`ConnectingState.phase` 用状态机登记的当前细粒度 ConnectPhase（不再硬编码）；
/// `Failed` → `FailedDirtyState`（携带最后一次失败的结构化 err，不静默）；快照携带
/// 当前在途操作 operation_id（R1 契约）。
fn snapshot_for_phase(phase: HostPhase, composition: &HostComposition) -> RuntimeSnapshot {
    let state = match phase {
        HostPhase::Idle => Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
            last_cleanup: None,
        })),
        HostPhase::Connecting => Some(wire::runtime_snapshot::State::Connecting(
            wire::ConnectingState {
                attempt: Some(attempt_standin(composition)),
                phase: composition
                    .connect_phase()
                    .map(wire_connect_phase_from_domain)
                    .unwrap_or(wire::ConnectPhase::ObservingOwnedState)
                    as i32,
            },
        )),
        HostPhase::Connected => Some(wire::runtime_snapshot::State::Connected(
            wire::ConnectedState {
                session: Some(connected_session_standin(composition)),
                session_established_at_ms: composition.session_established_at_ms().unwrap_or(0),
            },
        )),
        HostPhase::Reconciling => Some(wire::runtime_snapshot::State::Reconciling(
            wire::ReconcilingState {
                context: Some(recovery_context_standin(composition)),
                obligation: Some(recovery_obligation_standin(composition)),
            },
        )),
        HostPhase::Stopping => Some(wire::runtime_snapshot::State::Stopping(
            wire::StoppingState {
                attempt: Some(attempt_standin(composition)),
                // host 不保留 stop 意图（P3-c 从 engine 事件源化）。
                stop: None,
                queued_connect: None,
            },
        )),
        // Stopped：连接已终结，无 FailedClean/Dirty 上下文 → 回落 Idle。
        HostPhase::Stopped => Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
            last_cleanup: None,
        })),
        // R1：connect 失败收敛为 FailedDirty（结构化 err + 恢复上下文；不再静默）。
        HostPhase::Failed => Some(wire::runtime_snapshot::State::FailedDirty(
            wire::FailedDirtyState {
                last_error: composition.last_wire_error().cloned(),
                context: Some(recovery_context_standin(composition)),
                obligation: Some(recovery_obligation_standin(composition)),
            },
        )),
    };
    // stats / proxy_tun 由 `snapshot_with_stats` / `snapshot_with_proxy_tun` 在
    // 发布/GetSnapshot 时附加（本函数只组装状态）。S3：service_status/mode 由
    // `snapshot_with_service_context` 在 GetSnapshot/发布时附加（缺省 None/空）。
    RuntimeSnapshot {
        state,
        stats: None,
        proxy_tun: None,
        // EXV_UNFREEZE 2026-08-24：系统代理感知状态（设计 §5.5），由感知链路附加；占位 None。
        system_proxy: None,
        // EXV_UNFREEZE 2026-08-25：自动重连状态（C3a host 驱动），由状态转发器附加；占位 None。
        reconnect: None,
        // R1：当前在途操作 operation_id（空 = 无在途操作）。
        operation_id: composition
            .operation_id()
            .map(|id| id.to_vec())
            .unwrap_or_default(),
        service_status: None,
        mode: String::new(),
    }
}

/// 把已由 engine 状态事件确认的会话起点补入后续快照。
///
/// `ObserveOwnedState` 允许返回只含相位/统计的 Connected 快照；该类完整性较低的
/// 刷新不能把已经展示的在线时长清成横线。若 engine 这次提供了正值，保留它作为
/// 最新权威值；只有缺失或 0 时才回退到当前会话已确认的起点。
#[must_use]
fn snapshot_with_confirmed_session_start(
    mut snapshot: RuntimeSnapshot,
    confirmed_session_start: Option<i64>,
) -> RuntimeSnapshot {
    let Some(confirmed_session_start) = confirmed_session_start.filter(|value| *value > 0) else {
        return snapshot;
    };
    if let Some(wire::runtime_snapshot::State::Connected(connected)) = snapshot.state.as_mut()
        && connected.session_established_at_ms <= 0
    {
        connected.session_established_at_ms = confirmed_session_start;
    }
    snapshot
}

/// domain `ConnectPhase` → wire `ConnectPhase`（8 级一一对应；状态机登记为单一来源）。
fn wire_connect_phase_from_domain(
    phase: exv_vpn_domain::model::ConnectPhase,
) -> wire::ConnectPhase {
    use exv_vpn_domain::model::ConnectPhase as P;
    match phase {
        P::ObservingOwnedState => wire::ConnectPhase::ObservingOwnedState,
        P::AcquiringPlatformLease => wire::ConnectPhase::AcquiringPlatformLease,
        P::ConnectingControl => wire::ConnectPhase::ConnectingControl,
        P::AwaitingInteraction => wire::ConnectPhase::AwaitingInteraction,
        P::NegotiatingTunnel => wire::ConnectPhase::NegotiatingTunnel,
        P::ApplyingPlatformTunnel => wire::ConnectPhase::ApplyingPlatformTunnel,
        P::AttachingPacketBoundary => wire::ConnectPhase::AttachingPacketBoundary,
        P::StartingDataPlane => wire::ConnectPhase::StartingDataPlane,
    }
}

/// host `RuntimeStats` → wire `RuntimeStats`（P5-wire 方案 A：快照携带统计）。
///
/// 字段一一对应；`phase` 是 wire `StatsPhase` i32（host `RuntimeStats.phase` 同源，
/// 直接 `as i32`，与 `stats_phase_from_i32` 互为往返）。
#[must_use]
fn runtime_stats_to_wire(stats: RuntimeStats) -> wire::RuntimeStats {
    wire::RuntimeStats {
        rx_bytes: stats.rx_bytes,
        tx_bytes: stats.tx_bytes,
        rx_rate_bps: stats.rx_rate_bps,
        tx_rate_bps: stats.tx_rate_bps,
        latency_ms: stats.latency_ms,
        phase: stats.phase as i32,
        engine_sequence: stats.engine_sequence,
        sample_tick: stats.sample_tick,
    }
}

/// 把最新归一化统计附加到 wire 快照（None → `stats` 留空）。
///
/// 统计是状态事件的伴生数据：`GetSnapshot` 与 `EventBus::publish`（`WatchEvents`
/// 事件）都从 `EventBus::current_stats` 读最新样本后经本函数附加。
#[must_use]
fn snapshot_with_stats(
    mut snapshot: RuntimeSnapshot,
    stats: Option<RuntimeStats>,
) -> RuntimeSnapshot {
    snapshot.stats = stats.map(runtime_stats_to_wire);
    snapshot
}

/// resource `ProxyTunDetection` → wire `ProxyTunDetection`（C5-wire；字段一一对应）。
///
/// `route_policy` 取 [`ProxyTunDetection::route_policy`]（`"exv-before-proxy-tun"` |
/// `"normal"`，对齐 C++ `to_json`）；`kind` 为 `&'static str`（始终 `"proxy_tun"`）。
#[must_use]
fn proxy_tun_detection_to_wire(detection: &ProxyTunDetection) -> wire::ProxyTunDetection {
    wire::ProxyTunDetection {
        detected: detection.detected,
        adapters: detection
            .adapters
            .iter()
            .map(|a| wire::ProxyTunAdapter {
                name: a.name.clone(),
                description: a.description.clone(),
                if_index: a.if_index,
                kind: a.kind.to_string(),
            })
            .collect(),
        route_policy: detection.route_policy().to_string(),
    }
}

/// 把上游 proxy TUN 检测状态附加到 wire 快照（None → `proxy_tun` 留空）。
///
/// C5-wire：检测是状态事件的伴生数据（mirror stats 方案 A）——`GetSnapshot` 与
/// `EventBus::publish`（`WatchEvents` 事件）都从缓存读最新检测后经本函数附加；
/// 仅状态上报，不改任何路由/行为（PRD O1）。
#[must_use]
fn snapshot_with_proxy_tun(
    mut snapshot: RuntimeSnapshot,
    detection: Option<wire::ProxyTunDetection>,
) -> RuntimeSnapshot {
    snapshot.proxy_tun = detection;
    snapshot
}

/// resource `SystemProxySnapshot` → wire `SystemProxyDetection`（EXV_UNFREEZE；
/// 字段一一对应 + 四态拓扑分类）。
///
/// `mode` 取 [`SystemProxyMode`] 的稳定字符串（`"disabled"` | `"manual"` |
/// `"automatic"` | `"mixed"`，对齐 proto 注释）；`endpoint_count` = 规范化端点数；
/// `bypass_merged` 从 [`SystemProxySnapshot::bypass_entries`] 判定（非空 = EXV 豁免已
/// 合并进系统代理设置，设计 §5.5）；`topology` 是 `(proxy_present, tunnel_present)`
/// 的纯函数分类（[`classify`]，设计 §2）——`proxy_present` 取
/// [`SystemProxySnapshot::is_present`]，`tunnel_present` 由调用方（探测链）给出。
#[must_use]
fn system_proxy_snapshot_to_wire(
    snapshot: &SystemProxySnapshot,
    tunnel_present: bool,
) -> wire::SystemProxyDetection {
    wire::SystemProxyDetection {
        mode: match snapshot.mode {
            SystemProxyMode::Disabled => "disabled",
            SystemProxyMode::Manual => "manual",
            SystemProxyMode::Automatic => "automatic",
            SystemProxyMode::Mixed => "mixed",
        }
        .to_string(),
        endpoint_count: snapshot.endpoints.len() as u32,
        bypass_merged: !snapshot.bypass_entries.is_empty(),
        topology: match system_proxy::classify(snapshot.is_present(), tunnel_present) {
            TopologyKind::T0 => "t0",
            TopologyKind::T1 => "t1",
            TopologyKind::T2 => "t2",
            TopologyKind::T3 => "t3",
        }
        .to_string(),
    }
}

/// 把系统代理检测状态附加到 wire 快照（None → `system_proxy` 留空）。
///
/// EXV_UNFREEZE：检测是状态事件的伴生数据（mirror proxy_tun 方案 A）——`GetSnapshot`
/// 与 `EventBus::publish`（`WatchEvents` 事件）都从缓存读最新检测后经本函数附加；
/// 仅状态上报，不改任何路由/行为。
#[must_use]
fn snapshot_with_system_proxy(
    mut snapshot: RuntimeSnapshot,
    detection: Option<wire::SystemProxyDetection>,
) -> RuntimeSnapshot {
    snapshot.system_proxy = detection;
    snapshot
}

/// 组装 wire `ReconnectStatus`（C4 wire unfreeze；纯字段映射，不读配置）。
///
/// `attempts`/`active` 取 host 侧 `reconnect_attempts`/`reconnect_active` 原子（C3a 状态
/// 转发器维护）；`auto_reconnect`/`max_attempts` 由调用方从配置读（0 = unlimited）。
#[must_use]
fn reconnect_status_from_state(
    attempts: u32,
    active: bool,
    auto_reconnect: bool,
    max_attempts: u32,
) -> wire::ReconnectStatus {
    wire::ReconnectStatus {
        auto_reconnect,
        max_attempts,
        current_attempt: attempts,
        active,
    }
}

/// 把自动重连状态附加到 wire 快照（None → `reconnect` 留空）。
///
/// EXV_UNFREEZE：重连状态是状态事件的伴生数据（mirror proxy_tun 方案 A）——
/// `GetSnapshot` 与状态转发器在发布前组装后经本函数附加；仅状态上报，不改任何
/// 重连行为（决策仍在 C3a 重连 worker）。
#[must_use]
fn snapshot_with_reconnect(
    mut snapshot: RuntimeSnapshot,
    reconnect: Option<wire::ReconnectStatus>,
) -> RuntimeSnapshot {
    snapshot.reconnect = reconnect;
    snapshot
}

/// 从当前 host 重连状态 + 配置组装 wire `ReconnectStatus`。
///
/// `auto_reconnect`/`max_attempts` 每次从 `config_dir` 重读（mirror `drive_reconnect`——
/// 配置可能被 UI 修改，状态上报须反映当前配置）；读失败时给保守值
/// `auto_reconnect=false, max_attempts=0`（重连已禁用，不得把不可读配置当作用中的
/// 自动重连）。`attempts`/`active` 取原子实时值。
///
/// 供状态转发器使用（持 Arc 克隆 + config_dir，不依赖 `&self`）。
#[must_use]
fn reconnect_status_from_config(
    attempts: &AtomicU32,
    active: &AtomicBool,
    config_dir: &Path,
) -> wire::ReconnectStatus {
    let (auto, max) = match ExvConfig::load_from_dir(config_dir) {
        Ok(cfg) => (cfg.auto_reconnect, cfg.auto_reconnect_max_attempts),
        // 配置不可读 → 保守禁用（false/0），不把不可读配置当作用中的自动重连。
        Err(_) => (false, 0),
    };
    reconnect_status_from_state(
        attempts.load(Ordering::Relaxed),
        active.load(Ordering::Acquire),
        auto,
        max,
    )
}

/// host `ServiceStatusSnapshot` → wire `ServiceStatus`（S3/D5 字段一一映射 + R3
/// `health_state` 派生结果）。
///
/// `state` 取 [`ServiceState`] 的稳定字符串（`"stopped"` / `"start_pending"` /
/// `"stop_pending"` / `"running"` / `"other"`）——UI 据此展示服务徽标。`health_state`
/// 取 [`HealthState::as_wire_str`] 的稳定字符串（5 态）。
#[must_use]
fn service_status_to_wire(
    snapshot: &ServiceStatusSnapshot,
    health: HealthState,
) -> wire::ServiceStatus {
    wire::ServiceStatus {
        installed: snapshot.state.is_installed(),
        // `as_wire_str` 覆盖全部状态（含新增 Paused 系）；`NotInstalled` 由 `installed=false`
        // 表达（state 占位 "stopped"，与既有 wire 行为一致）。
        state: snapshot.state.as_wire_str().to_string(),
        binary_path: snapshot.binary_path.clone().unwrap_or_default(),
        health_state: health.as_wire_str().to_string(),
    }
}

/// 把服务上下文（service_status + mode）附加到 wire 快照（S3/D5）。
///
/// `service_status` None → 留空（尚未查询/查询失败）；`mode` 缺省 `"auto"`（与解冻前
/// 展示语义一致——未发生连接路由时展示默认模式）。
#[must_use]
fn snapshot_with_service_context(
    mut snapshot: RuntimeSnapshot,
    service_status: Option<wire::ServiceStatus>,
    mode: Option<String>,
) -> RuntimeSnapshot {
    snapshot.service_status = service_status;
    snapshot.mode = mode.unwrap_or_else(|| ServiceMode::Auto.as_wire_str().to_string());
    snapshot
}

/// C5-wire：探测一次上游 proxy TUN 并把 wire 结果刷新进事件总线缓存。
///
/// 探测失败 → 刷新 `None`（快照 `proxy_tun` 留空，不因探测失败影响状态上报）。
/// `GetSnapshot` 与 engine 事件转发器在发布前调用，保证快照携带最新共存状态。
fn refresh_bus_proxy_tun(events: &EventBus, probe: &ProxyTunProbe) {
    let detection = probe().ok().map(|d| proxy_tun_detection_to_wire(&d));
    events.refresh_proxy_tun(detection);
}

/// EXV_UNFREEZE：探测一次系统代理并把 wire 结果刷新进事件总线缓存。
///
/// 探测失败（SID 不可解析 / 注册表不可读 / 快照自洽性失败）→ 刷新 `None`（快照
/// `system_proxy` 留空，状态上报不因探测失败而失败）。`GetSnapshot` 与 engine 事件
/// 转发器在发布前调用，保证快照携带最新系统代理感知状态（mirror proxy_tun 方案 A）。
fn refresh_bus_system_proxy(events: &EventBus, probe: &SystemProxyProbe) {
    let detection = probe().ok();
    events.refresh_system_proxy(detection);
}

/// 确定性 attempt stand-in（纯 composition 的一次性连接尝试身份：runtime epoch +
/// 固定 attempt id；真实 attempt 由 P3-c 从 engine 事件源化）。
fn attempt_standin(composition: &HostComposition) -> wire::Attempt {
    wire::Attempt {
        runtime_epoch: composition.runtime_epoch_bytes().to_vec(),
        attempt_id: deterministic_attempt_id().to_vec(),
        intent: None,
        prior_error: None,
    }
}

/// 确定性 attempt id 字节（`Uuid::from_u128(2)`，非 nil、与 epoch=1 区分）。
fn deterministic_attempt_id() -> [u8; 16] {
    *Uuid::from_u128(2).as_bytes()
}

/// 确定性 32 字节 digest stand-in（`tag` 首字节 + 零填充；snapshot 的身份 ref）。
fn digest_standin(tag: u8) -> [u8; 32] {
    let mut d = [0u8; 32];
    d[0] = tag;
    d
}

/// Connected 会话的完整组装：attempt + protocol_session/platform_ownership/packet_lease
/// refs + platform_ready/data_running proofs（refs 为确定性 stand-in）。
fn connected_session_standin(composition: &HostComposition) -> wire::ConnectedSession {
    let packet_lease = wire::PacketLeaseRef {
        identity_digest: composition.packet_lease_ref_bytes().to_vec(),
    };
    let protocol_session = wire::ProtocolSessionRef {
        identity_digest: digest_standin(b'P').to_vec(),
    };
    let platform_ownership = wire::PlatformOwnershipRef {
        identity_digest: digest_standin(b'O').to_vec(),
        ownership_version: 1,
        token_digest: digest_standin(b'T').to_vec(),
    };
    wire::ConnectedSession {
        attempt: Some(attempt_standin(composition)),
        protocol_session: Some(protocol_session.clone()),
        platform_ownership: Some(platform_ownership.clone()),
        packet_lease: Some(packet_lease.clone()),
        platform_ready: Some(wire::PlatformReadyProof {
            platform_ownership: Some(platform_ownership.clone()),
            evidence_digest: digest_standin(b'E').to_vec(),
        }),
        data_running: Some(wire::DataRunningProof {
            protocol_session: Some(protocol_session),
            platform_ownership: Some(platform_ownership),
            packet_lease: Some(packet_lease),
            evidence_digest: digest_standin(b'D').to_vec(),
        }),
    }
}

/// Reconciling 的 RecoveryContext stand-in：helper link lost ≈ 包边界丢失
/// （packet_boundary_lost，携带当前 attempt + packet lease）。
fn recovery_context_standin(composition: &HostComposition) -> wire::RecoveryContext {
    wire::RecoveryContext {
        context: Some(wire::recovery_context::Context::PacketBoundaryLost(
            wire::PacketBoundaryLostContext {
                attempt: Some(attempt_standin(composition)),
                packet_lease: Some(wire::PacketLeaseRef {
                    identity_digest: composition.packet_lease_ref_bytes().to_vec(),
                }),
            },
        )),
    }
}

/// Reconciling 的 RecoveryObligation stand-in（阻塞原因未知 → `blocking_error: None`）。
fn recovery_obligation_standin(composition: &HostComposition) -> wire::RecoveryObligation {
    wire::RecoveryObligation {
        owner_runtime_epoch: composition.runtime_epoch_bytes().to_vec(),
        // `bytes` 字段：空 = 无（proto 注释 optional）。
        retirement_operation_id: vec![],
        blocking_error: None,
        platform_ownership: Some(wire::PlatformOwnershipRef {
            identity_digest: digest_standin(b'O').to_vec(),
            ownership_version: 1,
            token_digest: digest_standin(b'T').to_vec(),
        }),
        packet_lease: Some(wire::PacketLeaseRef {
            identity_digest: composition.packet_lease_ref_bytes().to_vec(),
        }),
        canonical_inventory_digest: digest_standin(b'I').to_vec(),
    }
}

// ---------------------------------------------------------------------------
// EventBus：WatchEvents 的 host 侧订阅总线（P3-c1 真实订阅）
// ---------------------------------------------------------------------------

/// engine 事件转发器的初始重连退避。
const ENGINE_EVENT_RECONNECT_BASE: Duration = Duration::from_millis(100);
/// engine 事件转发器的重连退避上限。
const ENGINE_EVENT_RECONNECT_MAX: Duration = Duration::from_secs(5);
/// engine 日志转发器的初始重连退避（R3；聚合-only 消费，断线缺口由 raw 离线对账）。
const ENGINE_LOG_RECONNECT_BASE: Duration = Duration::from_millis(100);
/// engine 日志转发器的重连退避上限。
const ENGINE_LOG_RECONNECT_MAX: Duration = Duration::from_secs(5);
/// `await_status_ready` 的有界等待上限（R3-C1）：引擎状态流永久不可达时，connect/stop
/// 写路径在此上界后放行派发，由 ApplyTunnel/StopTunnel 报真实 gRPC 错误——不永久悬挂。
/// 正常路径下转发器首次挂接在毫秒级完成，此上界充分覆盖。
const STATUS_READY_WAIT: Duration = Duration::from_millis(2000);

/// `WatchEvents` 的 host 侧事件总线（P3-c1 真实订阅）。
///
/// 维护严格递增的 monotonic tick（host 铸造）、最新事件（断线/订阅重放路径）与
/// 多订阅者 fan-out broadcast 通道。`publish` 铸造下一 tick 并广播；`subscribe`
/// 先按 resume 语义发当前快照（SNAPSHOT）再转发现场事件（增量 tick）。
pub struct EventBus {
    /// live 事件 fan-out（多个 `WatchEvents` 订阅者）。
    live: broadcast::Sender<RuntimeEvent>,
    /// 串行化状态发布与已连接统计重发，避免 status / stats 两条后台转发器把较旧快照
    /// 在较新 tick 之后写回 `current`。
    publish_gate: std::sync::Mutex<()>,
    /// 下一 monotonic tick（严格递增；0 保留为"无事件"）。
    tick: AtomicU64,
    /// 最新事件（含快照；resume / 断线重放路径）。`std::sync::Mutex`（同步访问，
    /// 不跨 await 持锁）。
    current: std::sync::Mutex<Option<RuntimeEvent>>,
    /// P5-b 统计 fan-out（host 侧归一化后；供 core 内部订阅者消费）。
    stats_live: broadcast::Sender<RuntimeStats>,
    /// P5-b 最新统计（`publish_stats` 更新；已连接时与重发的快照使用同一 tick）。
    stats_current: std::sync::Mutex<Option<RuntimeStats>>,
    /// C5-wire 最新上游 proxy TUN 检测（`refresh_proxy_tun` 更新；`publish`/`GetSnapshot`
    /// 附加到快照——mirror stats 方案 A，检测是状态事件的伴生数据）。
    proxy_tun_current: std::sync::Mutex<Option<wire::ProxyTunDetection>>,
    /// EXV_UNFREEZE 最新系统代理检测（`refresh_system_proxy` 更新；`publish`/`GetSnapshot`
    /// 附加到快照——mirror proxy_tun 方案 A，检测是状态事件的伴生数据）。
    system_proxy_current: std::sync::Mutex<Option<wire::SystemProxyDetection>>,
    /// S3/D5 最新 SCM 服务状态（`refresh_service_status` 更新；`publish`/`GetSnapshot`
    /// 附加到快照——mirror proxy_tun 方案 A，状态上报不因查询失败而失败）。
    service_status_current: std::sync::Mutex<Option<wire::ServiceStatus>>,
    /// S3/D3 最新展示模式（`refresh_service_mode` 更新；`publish`/`GetSnapshot` 附加；
    /// 缺省 `None` → `"auto"`）。
    service_mode_current: std::sync::Mutex<Option<String>>,
}

impl EventBus {
    /// 构造空总线（无事件、无统计、无 proxy TUN 检测、tick=0）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            live: broadcast::channel(64).0,
            publish_gate: std::sync::Mutex::new(()),
            tick: AtomicU64::new(0),
            current: std::sync::Mutex::new(None),
            stats_live: broadcast::channel(64).0,
            stats_current: std::sync::Mutex::new(None),
            proxy_tun_current: std::sync::Mutex::new(None),
            system_proxy_current: std::sync::Mutex::new(None),
            service_status_current: std::sync::Mutex::new(None),
            service_mode_current: std::sync::Mutex::new(None),
        }
    }

    /// 铸造下一 monotonic tick（严格递增，从 1 开始）。
    fn next_tick(&self) -> u64 {
        self.tick.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// 当前已发布的最大 tick（0 = 尚无事件）。
    #[must_use]
    pub fn current_tick(&self) -> u64 {
        self.tick.load(Ordering::Relaxed)
    }

    /// 最新发布事件的快照（无事件 → `None`）。
    #[must_use]
    pub fn current_snapshot(&self) -> Option<RuntimeSnapshot> {
        self.current
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|ev| ev.snapshot.clone())
    }

    /// 发布一个带快照的事件：铸造下一 tick → 更新 `current` → 广播。
    ///
    /// `kind`：`SNAPSHOT` = 完整快照刷新；`TRANSITION` = 状态过渡。返回发布的事件
    /// （含 minted tick），调用方可用于观测。
    ///
    /// P5-wire 方案 A：发布时把 [`Self::current_stats`] 的最新统计附加到快照
    /// （统计是状态事件的伴生数据；无样本 → `stats` 留空）——`WatchEvents` 订阅者
    /// 随每个 snapshot 事件拿到统计。
    ///
    /// C5-wire：同点附加 [`Self::current_proxy_tun`]（上游 proxy TUN 检测，mirror
    /// stats 方案 A；无检测 → `proxy_tun` 留空）——`WatchEvents` 订阅者随每个
    /// snapshot 事件拿到共存状态（badge 展示）。
    ///
    /// EXV_UNFREEZE：再附加 [`Self::current_system_proxy`]（系统代理感知，mirror
    /// proxy_tun 方案 A；无检测 → `system_proxy` 留空）——订阅者随每个 snapshot 事件
    /// 拿到系统代理感知状态。
    pub fn publish(&self, kind: wire::RuntimeEventKind, snapshot: RuntimeSnapshot) -> RuntimeEvent {
        let _publish_gate = self.publish_gate.lock().unwrap();
        let tick = self.next_tick();
        let snapshot = snapshot_with_service_context(
            snapshot_with_system_proxy(
                snapshot_with_proxy_tun(
                    snapshot_with_stats(snapshot, self.current_stats()),
                    self.current_proxy_tun(),
                ),
                self.current_system_proxy(),
            ),
            self.current_service_status(),
            self.current_service_mode(),
        );
        let event = RuntimeEvent {
            monotonic_tick: tick,
            kind: kind as i32,
            snapshot: Some(snapshot.clone()),
            // R1：事件携带所属操作 id（镜像快照 operation_id）。
            operation_id: snapshot.operation_id,
        };
        *self.current.lock().unwrap() = Some(event.clone());
        // 无订阅者时 send 失败（无 receiver）——忽略；tick/current 已推进。
        let _ = self.live.send(event.clone());
        event
    }

    /// 订阅事件流（P3-c1 `WatchEvents` 语义）。
    ///
    /// `resume_tick == 0` → 先发当前快照 SNAPSHOT 事件（从当前开始）；
    /// `resume_tick > 0` 且已落后（当前 tick > resume）→ 重放当前快照（断线重放
    /// 语义：host 只保留最新快照，真事件日志属 P5）；随后转发 tick > resume 的
    /// 现场事件。
    pub fn subscribe(&self, resume_tick: u64) -> impl Stream<Item = RuntimeEvent> + Send + 'static {
        let current = self.current.lock().unwrap().clone();
        let replay = match &current {
            Some(ev) if resume_tick == 0 || ev.monotonic_tick > resume_tick => Some(ev.clone()),
            _ => None,
        };
        let rx = self.live.subscribe();
        let live = BroadcastStream::new(rx).filter_map(move |ev| match ev {
            Ok(ev) if ev.monotonic_tick > resume_tick => Some(ev),
            _ => None,
        });
        let init = replay.into_iter().collect::<Vec<_>>();
        tokio_stream::iter(init).chain(live)
    }

    // -----------------------------------------------------------------------
    // P5-b 统计 lane：与 wire 事件 lane 共存于同一总线（互不干扰；tick 对齐关联）。
    // -----------------------------------------------------------------------

    /// 发布一条归一化统计并更新 `stats_current`。若当前状态为已连接，则为该样本铸造
    /// 新 tick，并把携带该统计的 `SNAPSHOT` 重发到 `WatchEvents`；这使 Tauri 能持续
    /// 收到速率、累计量和会话起点，而不是只停在首次连接快照。其他状态不生成伪刷新，
    /// 样本沿用当前 tick。
    pub fn publish_stats(&self, mut stats: RuntimeStats) -> RuntimeStats {
        let _publish_gate = self.publish_gate.lock().unwrap();
        let current_snapshot = self.current_snapshot();
        let should_republish = matches!(
            current_snapshot.as_ref().and_then(|snapshot| snapshot.state.as_ref()),
            Some(wire::runtime_snapshot::State::Connected(_))
        );
        let tick = if should_republish {
            self.next_tick()
        } else {
            self.current_tick()
        };
        stats.sample_tick = tick;
        *self.stats_current.lock().unwrap() = Some(stats);
        // 无订阅者时 send 失败（无 receiver）——忽略；stats_current 已更新。
        let _ = self.stats_live.send(stats);

        // 统计随 RuntimeSnapshot 交付给 Tauri；若只更新内部 lane，已连接的 UI 会永久
        // 停在首次无样本快照。仅在 Connected 快照上重发，避免 Idle/Connecting 阶段
        // 因后台采样产生伪状态刷新。
        if let Some(snapshot) = current_snapshot.filter(|snapshot| {
            matches!(
                snapshot.state.as_ref(),
                Some(wire::runtime_snapshot::State::Connected(_))
            )
        }) {
            let snapshot = snapshot_with_stats(snapshot, Some(stats));
            let event = RuntimeEvent {
                monotonic_tick: tick,
                kind: wire::RuntimeEventKind::Snapshot as i32,
                snapshot: Some(snapshot.clone()),
                operation_id: snapshot.operation_id,
            };
            *self.current.lock().unwrap() = Some(event.clone());
            let _ = self.live.send(event);
        }
        stats
    }

    /// 最新归一化统计（无 → `None`）。
    #[must_use]
    pub fn current_stats(&self) -> Option<RuntimeStats> {
        self.stats_current.lock().unwrap().clone()
    }

    // -----------------------------------------------------------------------
    // C5-wire proxy TUN lane：与 wire 事件 lane / 统计 lane 共存（仅缓存，不铸造 tick；
    // `GetSnapshot` 与事件转发器在发布前刷新，`publish`/`GetSnapshot` 附加到快照）。
    // -----------------------------------------------------------------------

    /// 刷新最新上游 proxy TUN 检测缓存（`None` = 探测失败/尚未探测）。
    pub fn refresh_proxy_tun(&self, detection: Option<wire::ProxyTunDetection>) {
        *self.proxy_tun_current.lock().unwrap() = detection;
    }

    /// 最新上游 proxy TUN 检测（无 → `None`）。
    #[must_use]
    pub fn current_proxy_tun(&self) -> Option<wire::ProxyTunDetection> {
        self.proxy_tun_current.lock().unwrap().clone()
    }

    // -----------------------------------------------------------------------
    // EXV_UNFREEZE 系统代理 lane：与 wire 事件 lane / 统计 lane / proxy TUN lane 共存
    // （只缓存，不铸造 tick；`GetSnapshot` 与事件转发器在发布前刷新，`publish`/
    // `GetSnapshot` 附加到快照——mirror proxy_tun 方案 A）。
    // -----------------------------------------------------------------------

    /// 刷新最新系统代理检测缓存（`None` = 探测失败/尚未探测）。
    pub fn refresh_system_proxy(&self, detection: Option<wire::SystemProxyDetection>) {
        *self.system_proxy_current.lock().unwrap() = detection;
    }

    /// 最新系统代理检测（无 → `None`）。
    #[must_use]
    pub fn current_system_proxy(&self) -> Option<wire::SystemProxyDetection> {
        self.system_proxy_current.lock().unwrap().clone()
    }

    // -----------------------------------------------------------------------
    // S3/D5 服务上下文 lane：service_status + mode（mirror proxy_tun 方案 A；只缓存，
    // 不铸造 tick；`GetSnapshot`/connect 路径刷新，`publish`/`GetSnapshot` 附加）。
    // -----------------------------------------------------------------------

    /// 刷新最新 SCM 服务状态缓存（`None` = 尚未查询/查询失败——状态上报不失败）。
    pub fn refresh_service_status(&self, status: Option<wire::ServiceStatus>) {
        *self.service_status_current.lock().unwrap() = status;
    }

    /// 最新 SCM 服务状态（无 → `None`）。
    #[must_use]
    pub fn current_service_status(&self) -> Option<wire::ServiceStatus> {
        self.service_status_current.lock().unwrap().clone()
    }

    /// 刷新最新展示模式缓存（`None` → 快照缺省 `"auto"`）。
    pub fn refresh_service_mode(&self, mode: Option<String>) {
        *self.service_mode_current.lock().unwrap() = mode;
    }

    /// 最新展示模式（无 → `None`，调用方回退 `"auto"`）。
    #[must_use]
    pub fn current_service_mode(&self) -> Option<String> {
        self.service_mode_current.lock().unwrap().clone()
    }

    /// 订阅归一化统计流（host 内部；P5-c 消费）。
    ///
    /// `resume_tick == 0` 或落后 → 先发当前统计（含最新 `sample_tick`），随后转发
    /// 更新的统计。统计不独立铸造 tick，故 live 过滤以发布时刻的 `sample_tick` 判定。
    pub fn subscribe_stats(
        &self,
        resume_tick: u64,
    ) -> impl Stream<Item = RuntimeStats> + Send + 'static {
        let current = self.stats_current.lock().unwrap().clone();
        let replay = match &current {
            Some(stats) if resume_tick == 0 || stats.sample_tick > resume_tick => Some(*stats),
            _ => None,
        };
        let rx = self.stats_live.subscribe();
        let live = BroadcastStream::new(rx).filter_map(move |stats| match stats {
            Ok(s) if s.sample_tick > resume_tick => Some(s),
            _ => None,
        });
        let init = replay.into_iter().collect::<Vec<_>>();
        tokio_stream::iter(init).chain(live)
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// C3a：判定 wire 错误是否为「可重试数据面掉线」（自动重连的触发标记）。
///
/// C2 的掉线事件是**唯一** `stage=DataPlane + retry=RetrySameOperation` 来源（code=
/// EffectUnknown 不参与判定——它是平台类失败通用码，C2 未新增错误码避免 wire 契约
/// 变更）；据此把「连接建立后数据面掉线（可重试）」与「连接期失败（DoNotRetry）」
/// 明确区分。
#[must_use]
fn is_retryable_disconnect(error: &wire::VpnError) -> bool {
    error.stage == wire::ErrorStage::DataPlane as i32
        && error.retry == wire::RetryAdvice::RetrySameOperation as i32
}

/// C3a：自动重连的 connect 意图（host 侧从磁盘凭据重新组装的最小意图）。
///
/// 复用既有 connect 流程（`run_connect` → `execute_connect`）需要一份合法
/// `ConnectIntent`：`lookup_key.method=Connect` + 新随机 runtime_epoch/operation_id
/// （新操作——终态事件按 operation_id 关联，陈旧过滤可区分新旧尝试）+ 32 字节
/// request_digest。`principal_digest` 与 UI 同源派生（当前用户 SID → SHA256；
/// engine 侧操作身份以认证 peer 为准，`lookup_key_from_wire` 只用它做 32 字节合法
/// 性校验）；SID 不可用时回落全零（仍合法 32 字节）。凭据/plan 由 `execute_connect`
/// 从磁盘 `config_dir` 重新 load，本意图不携带任何秘密。
#[must_use]
fn reconnect_intent() -> wire::ConnectIntent {
    let principal_digest = current_user_sid()
        .map(|sid| crate::grpc_control::owner_principal_digest(&sid))
        .unwrap_or_else(|| vec![0u8; 32]);
    wire::ConnectIntent {
        lookup_key: Some(wire::OperationLookupKey {
            principal_digest,
            method: wire::OperationMethod::Connect as i32,
            runtime_epoch: Uuid::new_v4().as_bytes().to_vec(),
            operation_id: Uuid::new_v4().as_bytes().to_vec(),
        }),
        request_digest: Sha256::digest(Uuid::new_v4().as_bytes()).to_vec(),
        profile: None,
    }
}

/// 把归一化的 [`EngineStatusEvent`] 归一化为 `WatchEvents` 的 (kind, snapshot)
///（R1；R3-C2 增 operation_id 过滤）。状态只从 engine 独立 status 流来（D3 铁律：
/// 日志绝不回流状态）。
///
/// 每个事件**驱动 composition 状态机**（单一事实源）：阶段推进 → 记录细粒度
/// ConnectPhase；真实 Connected → `ProtocolEstablished`（`set_phase(Connected)` 的
/// 唯一驱动）；Failed → `ConnectFailed`（携带转换后的 err）；Idle（停止收敛）→
/// 数据面侧加入 teardown 屏障（Stopped 快照组装后 S1 显式派发 ReopenAdmission）。
/// 随后从状态机组装确定性快照。
///
/// **R3-C2 operation_id 过滤**：终态事件（Connected / Failed / Idle→Stopped）的
/// `operation_id` 与当前在途操作不符时返回 `None`（丢弃）——防止旧操作的迟到终态
/// 驱动当前相态。当前在途操作 = composition 登记的操作 id；**无登记（`None`）时
/// 不过滤**（无法判定陈旧，保守透传，避免破坏未登记场景的收敛）。Progress 仅推进
/// 细粒度 phase、风险低，不参与过滤（保持阶段事件真实推进）。
async fn runtime_event_from_status(
    ev: &EngineStatusEvent,
    composition: &Arc<Mutex<HostComposition>>,
) -> Option<(wire::RuntimeEventKind, RuntimeSnapshot)> {
    let mut guard = composition.lock().await;
    // 终态事件陈旧过滤：有登记的在途操作且事件 operation_id 不符 → 丢弃（不驱动
    // 状态机、不发布）。
    if matches!(
        ev,
        EngineStatusEvent::Connected { .. }
            | EngineStatusEvent::Failed { .. }
            | EngineStatusEvent::Stopped { .. }
    ) && stale_terminal_operation(&guard, ev)
    {
        return None;
    }
    match ev {
        EngineStatusEvent::Progress { connect_phase, .. } => {
            guard.apply(HostEvent::ConnectPhaseProgress(domain_connect_phase(
                *connect_phase,
            )));
            Some((
                wire::RuntimeEventKind::Transition,
                snapshot_for_phase(guard.phase(), &guard),
            ))
        }
        EngineStatusEvent::Connected {
            session_established_at_ms,
            ..
        } => {
            guard.apply(HostEvent::ProtocolEstablished);
            guard.set_session_established_at_ms(*session_established_at_ms);
            let snapshot = snapshot_for_phase(guard.phase(), &guard);
            Some((
                wire::RuntimeEventKind::Transition,
                snapshot,
            ))
        }
        EngineStatusEvent::Failed { error, .. } => {
            guard.set_last_wire_error(error.clone());
            let domain_error = wire_vpn_error_to_domain(error);
            guard.apply(HostEvent::ConnectFailed(domain_error));
            Some((
                wire::RuntimeEventKind::Transition,
                snapshot_for_phase(guard.phase(), &guard),
            ))
        }
        EngineStatusEvent::Stopped { .. } => {
            // engine 确认 teardown 完成：数据面（engine）侧加入屏障 → 与 host 侧
            // 齐全后 Stopped（R1 收敛；R2 再补 core 合成 Idle 双保险）。
            //
            // S1.5 (D13) Paused 映射：减负断开后 engine 运行时进入 **Paused**（session
            // 结束 + 路由清 + NIC 保留 adapter），host 侧**复用既有 Stopped 映射**——
            // `connect_status_from_wire` 把 engine Idle 终态归一化为
            // `EngineStatusEvent::Stopped`，此处数据面侧加入屏障 → Stopped → 显式
            // ReopenAdmission → Idle。冻结 portable `HostComposition` 不动：Paused 是
            // engine 运行时状态，host 只以 Stopped + 既有 fine-phase（`connect_phase`
            // 寄存器）映射；网卡保留由退出清理阶段（engine teardown）收敛到 0 残留。
            guard.apply(HostEvent::TeardownSideJoined(TeardownSide::PacketData));
            let snapshot = snapshot_for_phase(guard.phase(), &guard);
            // S1（D14）：Stopped 快照先可观测（快照已组装，Stopped → wire Idle），
            // 随后 controller 显式派发 ReopenAdmission——admission 重开 + phase 回落
            // Idle，同进程二次 Connect 可受理（问题 A 闩锁修复）。**不**在
            // TeardownSideJoined Released 臂内同步回落（Stopped pin 保持）；仅当
            // 屏障确实释放（phase == Stopped）才重开——Stopping/Failed 等其余相
            // 位 no-op，teardown 拒绝语义保留。
            if guard.phase() == HostPhase::Stopped {
                guard.apply(HostEvent::ReopenAdmission);
            }
            Some((wire::RuntimeEventKind::Transition, snapshot))
        }
    }
}

/// R3-C2：判定终态事件是否为"旧操作的迟到终态"——composition 有登记的在途操作且
/// 事件 `operation_id` 与之不符。
#[must_use]
fn stale_terminal_operation(composition: &HostComposition, ev: &EngineStatusEvent) -> bool {
    let Some(current) = composition.operation_id() else {
        return false; // 无登记在途操作：无法判定陈旧，保守透传（不破坏未登记场景）。
    };
    let event_id = match ev {
        EngineStatusEvent::Connected { operation_id, .. }
        | EngineStatusEvent::Failed { operation_id, .. }
        | EngineStatusEvent::Stopped { operation_id } => operation_id,
        EngineStatusEvent::Progress { .. } => return false,
    };
    current.as_slice() != event_id.as_slice()
}

/// wire `ConnectPhase` → domain `ConnectPhase`（8 级一一对应；Unspecified 回落
/// 首个可观测阶段——状态流不产生 Unspecified，防御性回落）。
fn domain_connect_phase(phase: ConnectPhase) -> exv_vpn_domain::model::ConnectPhase {
    use exv_vpn_domain::model::ConnectPhase as P;
    match phase {
        ConnectPhase::ObservingOwnedState => P::ObservingOwnedState,
        ConnectPhase::AcquiringPlatformLease => P::AcquiringPlatformLease,
        ConnectPhase::ConnectingControl => P::ConnectingControl,
        ConnectPhase::AwaitingInteraction => P::AwaitingInteraction,
        ConnectPhase::NegotiatingTunnel => P::NegotiatingTunnel,
        ConnectPhase::ApplyingPlatformTunnel => P::ApplyingPlatformTunnel,
        ConnectPhase::AttachingPacketBoundary => P::AttachingPacketBoundary,
        ConnectPhase::StartingDataPlane => P::StartingDataPlane,
        ConnectPhase::Unspecified => P::ObservingOwnedState,
    }
}

/// R5：路由失败（PromptStart / service engine connect 失败）→ wire `VpnError`。
///
/// 路由失败发生在派发前——engine 未观测到任何失败，故不伪造 engine 观测字段；
/// code/stage/certainty/retry 取服务路由不可用的确定性语义（`SessionBusy` /
/// `Admission` / `NoEffect` / `UseNewOperation`），subject 留空（`wire_vpn_error_to_domain`
/// 回落确定性 runtime stand-in）。该错误只作快照 `FailedDirty.last_error` 的稳定 code
/// 呈现；人读信息由 connect RPC 的 `failed_precondition` 消息承载。
fn route_failure_wire_error(_status: &Status) -> wire::VpnError {
    use wire::{EffectCertainty, ErrorCode, ErrorStage, RetryAdvice};
    wire::VpnError {
        code: ErrorCode::SessionBusy as i32,
        stage: ErrorStage::Admission as i32,
        certainty: EffectCertainty::NoEffect as i32,
        retry: RetryAdvice::UseNewOperation as i32,
        subject: None,
        resource: None,
        native: None,
    }
}

/// wire `VpnError` → domain `VpnError`（R1：失败 err 上状态机）。
///
/// 结构化字段（code/stage/certainty/retry）一一对应，绝不丢失；subject 按分支
/// best-effort 转换（External/Runtime 可解析；缺省/不可解析回落确定性的 runtime
/// stand-in——与 host `unauthorized_error` 同源，红色acted 非秘密）；resource/native
/// 可解析则转，否则 `None`。R1 阶段 engine 失败为占位（真实数据面 R1b 接入），
/// 转换保持诚实（不伪造外部 OperationId——spec §10）。
fn wire_vpn_error_to_domain(error: &wire::VpnError) -> VpnError {
    use exv_vpn_domain::error::{
        EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice,
    };
    let code = match wire::ErrorCode::try_from(error.code) {
        Ok(wire::ErrorCode::InvalidInput) => ErrorCode::InvalidInput,
        Ok(wire::ErrorCode::IdempotencyConflict) => ErrorCode::IdempotencyConflict,
        Ok(wire::ErrorCode::ConnectInProgress) => ErrorCode::ConnectInProgress,
        Ok(wire::ErrorCode::SessionBusy) => ErrorCode::SessionBusy,
        Ok(wire::ErrorCode::ReconnectAlreadyQueued) => ErrorCode::ReconnectAlreadyQueued,
        Ok(wire::ErrorCode::CancelledBeforeStart) => ErrorCode::CancelledBeforeStart,
        Ok(wire::ErrorCode::AuthorityAlreadyHeld) => ErrorCode::AuthorityAlreadyHeld,
        Ok(wire::ErrorCode::OwnershipAcquisitionPending) => ErrorCode::OwnershipAcquisitionPending,
        Ok(wire::ErrorCode::ObservedConflict) => ErrorCode::ObservedConflict,
        Ok(wire::ErrorCode::JournalCorrupt) => ErrorCode::JournalCorrupt,
        Ok(wire::ErrorCode::DataPlaneBackpressure) => ErrorCode::DataPlaneBackpressure,
        Ok(wire::ErrorCode::PacketLeaseAlreadyAttached) => ErrorCode::PacketLeaseAlreadyAttached,
        Ok(wire::ErrorCode::EffectUnknown) => ErrorCode::EffectUnknown,
        Ok(wire::ErrorCode::ObservationFailed) => ErrorCode::ObservationFailed,
        Ok(wire::ErrorCode::Unauthorized) => ErrorCode::Unauthorized,
        Ok(wire::ErrorCode::DeadlineExceeded) => ErrorCode::DeadlineExceeded,
        Ok(wire::ErrorCode::ActiveAttemptCannotReconcile) => {
            ErrorCode::ActiveAttemptCannotReconcile
        }
        Ok(wire::ErrorCode::ActiveSessionCannotReconcile) => {
            ErrorCode::ActiveSessionCannotReconcile
        }
        _ => ErrorCode::ObservationFailed,
    };
    let stage = match wire::ErrorStage::try_from(error.stage) {
        Ok(wire::ErrorStage::Ingress) => ErrorStage::Ingress,
        Ok(wire::ErrorStage::Admission) => ErrorStage::Admission,
        Ok(wire::ErrorStage::ObservingOwnedState) => ErrorStage::ObservingOwnedState,
        Ok(wire::ErrorStage::AcquiringPlatformLease) => ErrorStage::AcquiringPlatformLease,
        Ok(wire::ErrorStage::ConnectingControl) => ErrorStage::ConnectingControl,
        Ok(wire::ErrorStage::AwaitingInteraction) => ErrorStage::AwaitingInteraction,
        Ok(wire::ErrorStage::NegotiatingTunnel) => ErrorStage::NegotiatingTunnel,
        Ok(wire::ErrorStage::ApplyingPlatformTunnel) => ErrorStage::ApplyingPlatformTunnel,
        Ok(wire::ErrorStage::AttachingPacketBoundary) => ErrorStage::AttachingPacketBoundary,
        Ok(wire::ErrorStage::StartingDataPlane) => ErrorStage::StartingDataPlane,
        Ok(wire::ErrorStage::ProtocolSession) => ErrorStage::ProtocolSession,
        Ok(wire::ErrorStage::DataPlane) => ErrorStage::DataPlane,
        Ok(wire::ErrorStage::Teardown) => ErrorStage::Teardown,
        Ok(wire::ErrorStage::Recovery) => ErrorStage::Recovery,
        Ok(wire::ErrorStage::Journal) => ErrorStage::Journal,
        _ => ErrorStage::ObservingOwnedState,
    };
    let certainty = match wire::EffectCertainty::try_from(error.certainty) {
        Ok(wire::EffectCertainty::NoEffect) => EffectCertainty::NoEffect,
        Ok(wire::EffectCertainty::Applied) => EffectCertainty::Applied,
        Ok(wire::EffectCertainty::Partial) => EffectCertainty::Partial,
        Ok(wire::EffectCertainty::Unknown) => EffectCertainty::Unknown,
        _ => EffectCertainty::NoEffect,
    };
    let retry = match wire::RetryAdvice::try_from(error.retry) {
        Ok(wire::RetryAdvice::DoNotRetry) => RetryAdvice::DoNotRetry,
        Ok(wire::RetryAdvice::RetrySameOperation) => RetryAdvice::RetrySameOperation,
        Ok(wire::RetryAdvice::UseNewOperation) => RetryAdvice::UseNewOperation,
        Ok(wire::RetryAdvice::Reconcile) => RetryAdvice::Reconcile,
        Ok(wire::RetryAdvice::RestartProcess) => RetryAdvice::RestartProcess,
        _ => RetryAdvice::DoNotRetry,
    };
    let subject = error
        .subject
        .as_ref()
        .and_then(wire_subject_to_domain)
        .unwrap_or_else(|| {
            // 缺省/不可解析 → 确定性 runtime stand-in（与 host `unauthorized_error`
            // 同源；红色acted 非秘密；spec §10：不伪造外部 OperationId）。
            ErrorSubject::Runtime(
                exv_vpn_domain::identity::RuntimeEpoch::try_from(uuid::Uuid::from_u128(1))
                    .expect("non-nil runtime epoch"),
            )
        });
    VpnError::try_from((code, stage, certainty, retry, subject, None, None))
        .expect("valid error tuple")
}

/// wire `ErrorSubject` → domain `ErrorSubject`（best-effort：External/Runtime 可解析，
/// 其余分支或 malformed 字节 → `None`，由调用方回落 runtime stand-in）。
fn wire_subject_to_domain(
    subject: &wire::ErrorSubject,
) -> Option<exv_vpn_domain::error::ErrorSubject> {
    use exv_vpn_domain::error::ErrorSubject;
    use exv_vpn_domain::identity::{
        OperationId, OperationLookupKey, OperationMethod, RuntimeEpoch,
    };
    match subject.subject.as_ref()? {
        wire::error_subject::Subject::External(key) => {
            let principal_digest = <[u8; 32]>::try_from(key.principal_digest.as_slice()).ok()?;
            let method = match wire::OperationMethod::try_from(key.method).ok()? {
                wire::OperationMethod::Connect => OperationMethod::Connect,
                wire::OperationMethod::RespondInteraction => OperationMethod::RespondInteraction,
                wire::OperationMethod::Stop => OperationMethod::Stop,
                wire::OperationMethod::Reconcile => OperationMethod::Reconcile,
                wire::OperationMethod::AcquireLease => OperationMethod::AcquireLease,
                wire::OperationMethod::ApplyTunnel => OperationMethod::ApplyTunnel,
                wire::OperationMethod::StopTunnel => OperationMethod::StopTunnel,
                wire::OperationMethod::ReleaseLease => OperationMethod::ReleaseLease,
                _ => return None,
            };
            let runtime_epoch = uuid_from_16(&key.runtime_epoch)?;
            let operation_id = uuid_from_16(&key.operation_id)?;
            let domain_key = OperationLookupKey::try_from((
                exv_vpn_domain::identity::PrincipalDigest::try_from(principal_digest).ok()?,
                method,
                RuntimeEpoch::try_from(runtime_epoch).ok()?,
                OperationId::try_from(operation_id).ok()?,
            ))
            .ok()?;
            Some(ErrorSubject::External(domain_key))
        }
        wire::error_subject::Subject::Runtime(runtime) => {
            let epoch = uuid_from_16(&runtime.runtime_epoch)?;
            Some(ErrorSubject::Runtime(RuntimeEpoch::try_from(epoch).ok()?))
        }
        _ => None,
    }
}

/// 16 字节 wire bytes → `Uuid`（长度不符 → `None`）。
fn uuid_from_16(bytes: &[u8]) -> Option<uuid::Uuid> {
    let arr = <[u8; 16]>::try_from(bytes).ok()?;
    Some(uuid::Uuid::from_bytes(arr))
}

/// 断线表示的快照（engine 断开 → 包边界丢失的恢复上下文，Reconciling 状态）。
///
/// 与 composition 的 `HelperLinkLost` 语义对齐：helper 链路断开 ≈ 包边界丢失。host
/// 不在此处 mutate composition（那属 P3-c2 进程生命周期的 helper-link 处理）；仅向
/// UI 发布恢复中过渡。
fn disconnected_snapshot(composition: &HostComposition) -> RuntimeSnapshot {
    // R2 收敛双保险：已收敛的终态（Idle / Stopped / Failed）不得被 engine 状态流断线
    // 回归成 Reconciling——EOF 只表示 engine 侧掉线，不代表业务已回退。只有非终态
    // （Connecting / Connected / Stopping / Reconciling——连接在途、engine 提前离开）
    // 才以 Reconciling 表示待恢复。`Stopped`/`Idle` 回落 Idle 终态，`Failed` 保持
    // FailedDirty（终态不丢错误上下文）。
    match composition.phase() {
        HostPhase::Idle | HostPhase::Stopped | HostPhase::Failed => {
            return snapshot_for_phase(composition.phase(), composition);
        }
        _ => {}
    }
    wire::RuntimeSnapshot {
        state: Some(wire::runtime_snapshot::State::Reconciling(
            wire::ReconcilingState {
                context: Some(recovery_context_standin(composition)),
                obligation: Some(recovery_obligation_standin(composition)),
            },
        )),
        // stats / proxy_tun 由 `snapshot_with_stats` / `snapshot_with_proxy_tun`
        // 在发布时附加。S3：service_status/mode 由 `snapshot_with_service_context`
        // 在 GetSnapshot/发布时附加（缺省 None/空）。
        stats: None,
        proxy_tun: None,
        // EXV_UNFREEZE 2026-08-24：系统代理感知状态（设计 §5.5），由感知链路附加；占位 None。
        system_proxy: None,
        // EXV_UNFREEZE 2026-08-25：自动重连状态（C3a host 驱动），由状态转发器附加；占位 None。
        reconnect: None,
        operation_id: composition
            .operation_id()
            .map(|id| id.to_vec())
            .unwrap_or_default(),
        service_status: None,
        mode: String::new(),
    }
}

/// 选择快照源（P3-c1 `GetSnapshot` 源化）：engine 快照非 Idle（真实数据）→ engine；
/// engine Idle 占位而 composition 非 Idle（host 有更新知识）→ composition；其余 →
/// engine（Idle 即 Idle）。
fn prefer_snapshot(
    engine: Option<RuntimeSnapshot>,
    composition: RuntimeSnapshot,
) -> RuntimeSnapshot {
    let Some(engine) = engine else {
        return composition;
    };
    let engine_idle = matches!(engine.state, Some(wire::runtime_snapshot::State::Idle(_)));
    let composition_idle = matches!(
        composition.state,
        Some(wire::runtime_snapshot::State::Idle(_))
    );
    if engine_idle && !composition_idle {
        composition
    } else {
        engine
    }
}

// ---------------------------------------------------------------------------
// RespondInteraction / Reconcile 校验与重试决策（P3-c1）
// ---------------------------------------------------------------------------

/// 校验 `InteractionResponse`：`interaction_id` 与 `runtime_epoch` 必须 16 字节。
///
/// # Errors
/// 任一字段长度非法 → `Status::invalid_argument`。
fn validate_interaction_response(response: &wire::InteractionResponse) -> Result<(), Status> {
    if response.interaction_id.len() != 16 {
        return Err(Status::invalid_argument(
            "respond_interaction: interaction id must be 16 bytes",
        ));
    }
    if response.runtime_epoch.len() != 16 {
        return Err(Status::invalid_argument(
            "respond_interaction: runtime epoch must be 16 bytes",
        ));
    }
    Ok(())
}

/// `Reconcile` 的重试决策（P3-c1：义务 disposition → 真实重试）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReconcileRetry {
    /// 义务已终局（成功/失败）→ 无需重试，透传 terminal。
    Terminal,
    /// 义务仍待决（Pending/Unknown/Absent/Rejected）→ 需重试（重新 apply/acquire）。
    Retry,
}

/// 依据观察到的义务 disposition 决策是否重试（P3-c1）。
#[must_use]
fn reconcile_retry_plan(observed: &Option<OperationState>) -> ReconcileRetry {
    match observed.as_ref().and_then(|s| s.state.as_ref()) {
        Some(wire::operation_state::State::Terminal(_)) => ReconcileRetry::Terminal,
        _ => ReconcileRetry::Retry,
    }
}

// ---------------------------------------------------------------------------
// 单元测试：phase → 完整 snapshot、gate 拒绝路径、写路径（fake engine）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use crate::service_status::RawServiceQuery;
    use exv_vpn_win32_ipc::peer_auth::VerifiedPipePeer;
    use exv_vpn_wire::generated::{
        ServiceInstall, ServiceStart, ServiceStatusQuery, ServiceUninstall,
    };
    use windows::Win32::System::Services::{SERVICE_RUNNING, SERVICE_STOPPED};

    /// 已验 helper 身份（tests 共享）。
    fn helper() -> VerifiedPipePeer {
        VerifiedPipePeer {
            process_id: 4242,
            user_sid: "S-1-5-21-3980489076-1253412212-3874560562-1002".to_string(),
            logon_sid: Some("S-1-5-5-0-323470".to_string()),
            account_name: "EXV VPN Helper".to_string(),
        }
    }

    /// 记录派发的 fake engine（写路径语义的观测点；P3-c1 事件源/快照源可注入）。
    #[derive(Default)]
    struct FakeEngine {
        /// 每次 `apply_connect` 的 (请求, 收到的一次性秘密字节)。
        applies: std::sync::Mutex<Vec<(wire::ApplyTunnelRequest, Vec<u8>)>>,
        /// 每次 `stop_tunnel` 的请求。
        stops: std::sync::Mutex<Vec<wire::StopTunnelRequest>>,
        /// 每次 `get_operation` 的请求。
        ops: std::sync::Mutex<Vec<wire::GetOperationRequest>>,
        /// R1 状态源：`stream_connect_status` 消费（`None` = 无可订阅状态流）。
        events: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<EngineStatusEvent>>>,
        /// P5-b 统计源：`stream_stats` 消费（`None` = 无可订阅统计流）。
        stats: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<wire::StatsEvent>>>,
        /// R3 日志源：`stream_logs` 消费（`None` = 无可订阅日志流）。
        log_events: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<wire::LogEvent>>>,
        /// P3-c1 快照源：`observe_owned_state` 返回（`None` = 回落 Idle 占位）。
        owned_state: std::sync::Mutex<Option<wire::RuntimeSnapshot>>,
        /// P3-c1 `respond_interaction` 收到的应答。
        interactions: std::sync::Mutex<Vec<wire::InteractionResponse>>,
        /// P3-c1 `retry_obligation` 收到的重试请求。
        retries: std::sync::Mutex<Vec<wire::ReconcileRequest>>,
        /// S3-B `service_manage` 收到的请求（query 自述探针的观测点）。
        manages: std::sync::Mutex<Vec<wire::ServiceManageRequest>>,
        /// Bug D 回归观测：`ensure_owner_lease` 调用次数（connect/stop 前置必须各恰好
        /// 一次——engine 缺 lease 会返回 `failed_precondition("no owner lease established")`）。
        lease_ensures: std::sync::Mutex<u32>,
        /// 服务切换测试：模拟 owner lease 已因旧 engine 掉线而无法续租。
        owner_lease_error: std::sync::Mutex<Option<GrpcClientError>>,
        /// R1 异步：`apply_connect` 返回 `pending`（ApplyAccepted）而非 `applied`
        /// （镜像 R1w engine 的 async 契约；测试异步 connect 事件推进）。
        pending_apply: std::sync::Mutex<bool>,
        /// R3-C1：`apply_connect` 强制返回的 engine 错误（`Some` = 模拟引擎不可达/
        /// 真实 gRPC 失败；connect 有界等待后放行派发即得到它）。`None` = 正常成功。
        apply_error: std::sync::Mutex<Option<GrpcClientError>>,
        /// C3a：`apply_connect` 在派发后阻塞直到被 notify（`Some` = 模拟引擎处理慢、
        /// 重连在途；防重入/串行性测试用）。`None` = 不阻塞。
        apply_block: std::sync::Mutex<Option<Arc<tokio::sync::Notify>>>,
        /// C3a：apply 计数观测点（`apply_connect` 派发即 +1；独立于 engine 锁——串行性
        /// 测试在 apply 阻塞持锁期间免锁观测用）。
        apply_obs: std::sync::Mutex<Option<Arc<std::sync::atomic::AtomicUsize>>>,
        /// 服务切换测试：`Some` = 模拟旧 engine 无法完成 StopTunnel。
        stop_error: std::sync::Mutex<Option<GrpcClientError>>,
    }

    #[tonic::async_trait]
    impl KernelEngineControl for FakeEngine {
        async fn ensure_owner_lease(&mut self) -> Result<(), GrpcClientError> {
            *self.lease_ensures.lock().unwrap() += 1;
            if let Some(error) = self.owner_lease_error.lock().unwrap().clone() {
                return Err(error);
            }
            // fake：无真实 lease 语义——幂等成功（真实实现做 MaintainOwnerLease 握手）。
            Ok(())
        }

        async fn apply_connect(
            &mut self,
            request: wire::ApplyTunnelRequest,
            secret_payload: &mut ClearableSecret,
        ) -> Result<wire::ApplyTunnelReply, GrpcClientError> {
            // 观测：记录请求与收到的秘密（复制用于断言；复制不影响零化语义）。
            let captured = secret_payload.as_bytes().to_vec();
            let operation_id = request
                .lookup_key
                .as_ref()
                .map(|k| k.operation_id.clone())
                .unwrap_or_default();
            self.applies.lock().unwrap().push((request, captured));
            // 契约：RPC 完成后零化槽（镜像真实实现的发送后零化）。
            secret_payload.clear();
            // C3a：派发即计数（免锁观测点；串行性测试用）。
            if let Some(obs) = self.apply_obs.lock().unwrap().clone() {
                obs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            // C3a：模拟引擎处理慢——派发后阻塞直到测试放行（重连在途/串行性测试）。
            // 一次性消费 gate：只有下一个 apply 阻塞（后续 apply 不受影响）；先 take
            // 再 await，避免非 Send guard 跨 await。
            let block = self.apply_block.lock().unwrap().take();
            if let Some(block) = block {
                block.notified().await;
            }
            // R3-C1：注入的引擎不可达错误优先返回（connect 有界等待后放行派发即得真实错误）。
            if let Some(error) = self.apply_error.lock().unwrap().clone() {
                return Err(error);
            }
            if *self.pending_apply.lock().unwrap() {
                // R1 异步契约：回 `pending`（ApplyAccepted，带 operation_id）——终态
                // 走 status 通道（状态转发器驱动）。
                Ok(wire::ApplyTunnelReply {
                    result: Some(wire::apply_tunnel_reply::Result::Pending(
                        wire::ApplyAccepted {
                            operation_id,
                            authority_fence: None,
                        },
                    )),
                })
            } else {
                Ok(wire::ApplyTunnelReply {
                    result: Some(wire::apply_tunnel_reply::Result::Applied(
                        wire::MutationReceipt::default(),
                    )),
                })
            }
        }

        async fn stop_tunnel(
            &mut self,
            request: wire::StopTunnelRequest,
        ) -> Result<wire::StopTunnelReply, GrpcClientError> {
            self.stops.lock().unwrap().push(request);
            if let Some(error) = self.stop_error.lock().unwrap().clone() {
                return Err(error);
            }
            Ok(wire::StopTunnelReply {
                result: Some(wire::stop_tunnel_reply::Result::Stopped(
                    wire::MutationReceipt::default(),
                )),
            })
        }

        async fn get_operation(
            &mut self,
            request: wire::GetOperationRequest,
        ) -> Result<wire::GetOperationReply, GrpcClientError> {
            self.ops.lock().unwrap().push(request);
            Ok(wire::GetOperationReply { state: None })
        }

        async fn service_manage(
            &mut self,
            request: wire::ServiceManageRequest,
        ) -> Result<wire::ServiceManageReply, GrpcClientError> {
            // fake：记录请求并返回占位自述（connect/stop 写路径测试不触碰 query 语义）。
            self.manages.lock().unwrap().push(request);
            Ok(wire::ServiceManageReply {
                self_report: Some(wire::ServiceSelfReport {
                    control_plane_ready: true,
                    psk_present: true,
                    connection_mode: "service".to_string(),
                    runtime_epoch: vec![0u8; 16],
                    authority_fence: None,
                }),
            })
        }

        async fn keep_alive(
            &mut self,
            request: wire::KeepAliveRequest,
        ) -> Result<wire::KeepAliveReply, GrpcClientError> {
            // fake：回显 tick（镜像真实 engine 的 unary 心跳回复；ticker 测试观测点）。
            Ok(wire::KeepAliveReply {
                monotonic_tick: request.monotonic_tick,
            })
        }

        async fn observe_owned_state(
            &mut self,
            _request: wire::ObserveOwnedStateRequest,
        ) -> Result<wire::ObserveOwnedStateReply, GrpcClientError> {
            let snapshot = self
                .owned_state
                .lock()
                .unwrap()
                .clone()
                // 无注入快照时回落 Idle 占位（镜像真实 engine 的当前行为）。
                .unwrap_or_else(|| wire::RuntimeSnapshot {
                    state: Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
                        last_cleanup: None,
                    })),
                    stats: None,
                    proxy_tun: None,
        // EXV_UNFREEZE 2026-08-24：系统代理感知状态（设计 §5.5），由感知链路附加；占位 None。
        system_proxy: None,
        // EXV_UNFREEZE 2026-08-25：自动重连状态占位（测试字面量）。
        reconnect: None,
                    operation_id: Vec::new(),
                    service_status: None,
                    mode: String::new(),
                });
            Ok(wire::ObserveOwnedStateReply {
                snapshot: Some(snapshot),
                authority_fence: None,
            })
        }

        async fn stream_connect_status(
            &mut self,
        ) -> Result<crate::grpc_control::EngineStatusEventStream, GrpcClientError> {
            // 消费注入的状态源；无源 → 拒绝（forwarder 退避重试路径可测）。
            let rx = self.events.lock().unwrap().take().ok_or_else(|| {
                GrpcClientError::Rpc(Code::Unavailable, "no event source".to_string())
            })?;
            Ok(Box::pin(
                tokio_stream::wrappers::UnboundedReceiverStream::new(rx),
            ))
        }

        async fn stream_stats(
            &mut self,
            _sample_interval_ms: u32,
        ) -> Result<crate::grpc_control::StatsEventStream, GrpcClientError> {
            // 消费注入的统计源；无源 → 拒绝（统计转发器退避重试路径可测）。
            let rx = self.stats.lock().unwrap().take().ok_or_else(|| {
                GrpcClientError::Rpc(Code::Unavailable, "no stats source".to_string())
            })?;
            Ok(Box::pin(
                tokio_stream::wrappers::UnboundedReceiverStream::new(rx),
            ))
        }

        async fn stream_logs(
            &mut self,
            _resume_tick: u64,
        ) -> Result<crate::grpc_control::LogEventStream, GrpcClientError> {
            // 消费注入的日志源；无源 → 拒绝（日志转发器退避重试路径可测）。
            let rx = self.log_events.lock().unwrap().take().ok_or_else(|| {
                GrpcClientError::Rpc(Code::Unavailable, "no log source".to_string())
            })?;
            Ok(Box::pin(
                tokio_stream::wrappers::UnboundedReceiverStream::new(rx).map(Ok),
            ))
        }

        async fn respond_interaction(
            &mut self,
            response: wire::InteractionResponse,
        ) -> Result<wire::OperationReply, GrpcClientError> {
            self.interactions.lock().unwrap().push(response);
            Ok(wire::OperationReply { terminal: None })
        }

        async fn retry_obligation(
            &mut self,
            request: wire::ReconcileRequest,
        ) -> Result<wire::GetOperationReply, GrpcClientError> {
            self.retries.lock().unwrap().push(request);
            Ok(wire::GetOperationReply { state: None })
        }
    }

    /// C5-wire 确定性探针：总是报告「无上游 proxy TUN」（所有测试构造的默认探针，
    /// 保证单测不依赖真实 Win32 适配器枚举）。
    fn no_detection_probe() -> ProxyTunProbe {
        Arc::new(|| {
            Ok(ProxyTunDetection {
                detected: false,
                adapters: vec![],
            })
        })
    }

    /// C5-wire 确定性探针：总是报告「检测到上游 proxy TUN」（适配器名/描述可注入）。
    fn detection_probe(name: &'static str, description: &'static str) -> ProxyTunProbe {
        Arc::new(move || {
            Ok(ProxyTunDetection {
                detected: true,
                adapters: vec![exv_vpn_win32_resource::proxy_tun::ProxyTunAdapter {
                    name: name.to_string(),
                    description: description.to_string(),
                    if_index: 17,
                    kind: exv_vpn_win32_resource::proxy_tun::KIND_PROXY_TUN,
                }],
            })
        })
    }

    /// EXV_UNFREEZE 确定性系统代理探针：总是报告给定 wire 检测（测试构造注入，
    /// 避免 `GetSnapshot`/事件转发器依赖真实 WinINET 注册表状态）。
    fn system_proxy_probe(detection: wire::SystemProxyDetection) -> SystemProxyProbe {
        Arc::new(move || Ok(detection.clone()))
    }

    /// 构造持有指定 fake engine 的服务（已授权 gate；config_dir 可注入；proxy TUN
    /// 探针注入确定性「无检测」——单测不触真实 Win32）。
    fn service_with_config(
        engine: &Arc<tokio::sync::Mutex<FakeEngine>>,
        config_dir: PathBuf,
    ) -> (KernelControlService, tempfile::TempDir) {
        let mut composition =
            crate::composition::compose_nonprivileged_host(&helper()).expect("compose");
        composition
            .kernel_gate()
            .authorize(&helper())
            .expect("authorize");
        // R1：镜像 `authorize_transport_peer` 的 actor 绑定（connect 受理需要已绑定）。
        let (actor_peer, capability) = controller_peer_and_capability();
        composition.bind_controller(actor_peer, capability);
        let logs_dir = tempfile::tempdir().expect("logs tempdir");
        let logs =
            Arc::new(LogAggregator::open(&logs_dir.path().join("svc.jsonl")).expect("open logs"));
        let engine_dyn: Arc<tokio::sync::Mutex<dyn KernelEngineControl>> = engine.clone();
        let service = KernelControlService::new(
            Arc::new(Mutex::new(composition)),
            EngineSlot::new(engine_dyn),
            config_dir,
            logs,
        )
        .with_proxy_tun_probe(no_detection_probe())
        .with_service_status_source(fake_status_source(false, SERVICE_STOPPED.0));
        (service, logs_dir)
    }

    #[test]
    fn service_with_config_uses_deterministic_service_status_source() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with_config(&engine, PathBuf::new());

        let snapshot = service
            .query_service_status_snapshot()
            .expect("test service status source must return a snapshot");
        assert!(
            !snapshot.state.is_installed(),
            "service test helper must not read the machine SCM service"
        );
        assert_eq!(snapshot.state, ServiceState::NotInstalled);
    }

    /// 构造持有指定 fake engine 的服务（已授权 gate；无凭据目录）。
    fn service_with(
        engine: &Arc<tokio::sync::Mutex<FakeEngine>>,
    ) -> (KernelControlService, tempfile::TempDir) {
        service_with_config(engine, PathBuf::new())
    }

    /// 并发探针：`config_get` 必须不被在途的慢 `logs_list` 拖住。
    ///
    /// 用户现象：日志加载（前端分页拉 `logs_list`）期间点设置页，`config_get` 排到
    /// 日志后面才响应。断言 `config_get` 在慢 `logs_list` 仍 pending 时快速完成——
    /// `#[tokio::test]` 单线程 runtime 是最坏情况（一个 async worker）。
    #[tokio::test]
    async fn config_get_not_blocked_by_slow_logs_list() {
        use std::collections::BTreeMap;
        use std::time::{Duration, Instant};

        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let svc = Arc::new(service);

        // 灌入大量日志使 `logs_list` 的磁盘读（spawn_blocking）足够慢。
        {
            let fields = BTreeMap::new();
            for i in 0..50_000u32 {
                svc.logs
                    .append_core("info", "kernel", "probe", &format!("log {i}"), &fields)
                    .expect("append");
            }
        }

        let svc_for_logs = Arc::clone(&svc);
        let logs_handle = tokio::spawn(async move {
            let req = Request::new(wire::LogsListRequest {
                after_seq: 0,
                limit: 500,
                filter: String::new(),
            });
            let t0 = Instant::now();
            svc_for_logs.logs_list(req).await.expect("logs_list");
            t0.elapsed()
        });

        // 给 logs_list 一点时间开始读盘。
        tokio::time::sleep(Duration::from_millis(50)).await;

        let t0 = Instant::now();
        let req = Request::new(wire::ConfigGetRequest {});
        svc.config_get(req).await.expect("config_get");
        let config_elapsed = t0.elapsed();

        let logs_elapsed = logs_handle.await.expect("logs join");
        assert!(
            config_elapsed < Duration::from_millis(500),
            "config_get 被在途 logs_list 拖住：config={config_elapsed:?}, logs={logs_elapsed:?}"
        );
    }

    /// 注入状态源并拉起状态转发器（测试用）：镜像生产的 attach-before-apply——
    /// 转发器挂接 `StreamConnectStatus` 后置就绪，connect/stop 写路径不再悬挂。
    /// 等就绪后返回 `JoinHandle` 供测试 abort。
    async fn spawn_status_ready(
        service: &KernelControlService,
        engine: &Arc<tokio::sync::Mutex<FakeEngine>>,
    ) -> tokio::task::JoinHandle<()> {
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        engine.lock().await.events.lock().unwrap().replace(rx);
        let handle = service.spawn_status_forwarder();
        let mut ready = service.status_ready();
        while !*ready.borrow() {
            if ready.changed().await.is_err() {
                break;
            }
        }
        handle
    }

    /// service engine 换入后，状态转发器必须重新挂接新 engine 的状态流；不能一直
    /// 消费 Core 启动时的 oneshot 流，否则 service 业务状态不会回到 Core。
    #[tokio::test]
    async fn status_forwarder_rebinds_after_service_engine_swap() {
        let original = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let service_engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (original_tx, original_rx) = tokio::sync::mpsc::unbounded_channel();
        let (service_tx, service_rx) = tokio::sync::mpsc::unbounded_channel();
        original
            .lock()
            .await
            .events
            .lock()
            .unwrap()
            .replace(original_rx);
        service_engine
            .lock()
            .await
            .events
            .lock()
            .unwrap()
            .replace(service_rx);

        let (service, _logs_dir) = service_with(&original);
        let handle = service.spawn_status_forwarder();
        let mut ready = service.status_ready();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !*ready.borrow() {
                ready.changed().await.expect("status readiness sender");
            }
        })
        .await
        .expect("initial oneshot status stream attaches");

        service.engine.swap(service_engine.clone()).await;

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if service_engine.lock().await.events.lock().unwrap().is_none() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("status forwarder must attach the swapped service stream");

        drop(original_tx);
        drop(service_tx);
        handle.abort();
    }

    /// 构造持有指定 fake engine + proxy TUN 探针的服务（C5-wire 检测注入测试）。
    fn service_with_probe(
        engine: &Arc<tokio::sync::Mutex<FakeEngine>>,
        probe: ProxyTunProbe,
    ) -> (KernelControlService, tempfile::TempDir) {
        let (service, dir) = service_with_config(engine, PathBuf::new());
        (service.with_proxy_tun_probe(probe), dir)
    }

    /// 构造持有指定 fake engine + 系统代理探针的服务（EXV_UNFREEZE 检测注入测试）。
    fn service_with_system_proxy_probe(
        engine: &Arc<tokio::sync::Mutex<FakeEngine>>,
        probe: SystemProxyProbe,
    ) -> (KernelControlService, tempfile::TempDir) {
        let (service, dir) = service_with_config(engine, PathBuf::new());
        (service.with_system_proxy_probe(probe), dir)
    }

    /// 构造一个干净的 composition（gate 未授权，用于拒绝路径测试）。
    fn plain_composition() -> HostComposition {
        crate::composition::compose_nonprivileged_host(&helper()).expect("compose")
    }

    /// 16-byte 测试 operation id（wire `Vec<u8>` 形态）。
    fn uuid16(n: u8) -> Vec<u8> {
        uuid16_bytes(n).to_vec()
    }

    /// 16-byte 测试 operation id（`[u8; 16]` 形态，供 composition 登记）。
    fn uuid16_bytes(n: u8) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        bytes[1] = 0x42;
        bytes
    }

    fn seeded_config_dir(plaintext: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ExvConfig::ensure_key(dir.path()).expect("ensure key");
        let mut cfg = ExvConfig {
            server: "vpn-cn.ecnu.edu.cn".to_string(),
            username: "student".to_string(),
            routes: vec!["202.120.80.0/20".to_string(), "10.0.0.0/8".to_string()],
            // C1: 控制面物理出口 bypass 目的地（wire `control_bypass`）。
            server_bypass_ips: vec!["10.1.1.1".to_string(), "10.2.2.2".to_string()],
            ..ExvConfig::default()
        };
        cfg.set_password_encrypted(plaintext, &key)
            .expect("encrypt");
        cfg.save_to_dir(dir.path()).expect("save config");
        dir
    }

    fn connect_intent() -> wire::ConnectIntent {
        wire::ConnectIntent {
            lookup_key: Some(wire::OperationLookupKey {
                principal_digest: vec![0xAA; 32],
                method: wire::OperationMethod::Connect as i32,
                runtime_epoch: vec![0u8; 16],
                operation_id: vec![0u8; 16],
            }),
            request_digest: vec![0xBB; 32],
            profile: None,
        }
    }

    fn stop_intent() -> wire::StopIntent {
        wire::StopIntent {
            lookup_key: Some(wire::OperationLookupKey {
                principal_digest: vec![0xAA; 32],
                method: wire::OperationMethod::Stop as i32,
                runtime_epoch: vec![0u8; 16],
                operation_id: vec![0u8; 16],
            }),
            request_digest: vec![0xCC; 32],
        }
    }

    #[test]
    fn phase_maps_to_snapshot_states() {
        let composition = plain_composition();
        assert!(matches!(
            snapshot_for_phase(HostPhase::Idle, &composition).state,
            Some(wire::runtime_snapshot::State::Idle(_))
        ));
        assert!(matches!(
            snapshot_for_phase(HostPhase::Connecting, &composition).state,
            Some(wire::runtime_snapshot::State::Connecting(_))
        ));
        assert!(matches!(
            snapshot_for_phase(HostPhase::Connected, &composition).state,
            Some(wire::runtime_snapshot::State::Connected(_))
        ));
        assert!(matches!(
            snapshot_for_phase(HostPhase::Reconciling, &composition).state,
            Some(wire::runtime_snapshot::State::Reconciling(_))
        ));
        assert!(matches!(
            snapshot_for_phase(HostPhase::Stopping, &composition).state,
            Some(wire::runtime_snapshot::State::Stopping(_))
        ));
        // Stopped 回落 Idle。
        assert!(matches!(
            snapshot_for_phase(HostPhase::Stopped, &composition).state,
            Some(wire::runtime_snapshot::State::Idle(_))
        ));
    }

    /// GetSnapshot 完整组装：Connecting 带 attempt + phase；Connected 带完整
    /// attempt/lease/proof 结构；Reconciling 带 context + obligation。
    #[test]
    fn snapshot_assembles_attempt_lease_proof() {
        let mut composition = plain_composition();
        // R1：连接受理（bind controller + Connect）→ 状态机登记首个细粒度 phase。
        let (peer, cap) = controller_peer_and_capability();
        composition.bind_controller(peer, cap);
        let _ = composition.apply(HostEvent::Connect);

        // Connecting：attempt 携带 composition 的确定性 runtime epoch，phase 明确
        //（状态机登记的首个 ObservingOwnedState，不再硬编码 ConnectingControl）。
        let connecting = snapshot_for_phase(HostPhase::Connecting, &composition);
        let wire::runtime_snapshot::State::Connecting(connecting_state) = connecting.state.unwrap()
        else {
            panic!("expected connecting");
        };
        let attempt = connecting_state.attempt.expect("connecting has attempt");
        assert_eq!(attempt.runtime_epoch, composition.runtime_epoch_bytes());
        assert_eq!(attempt.attempt_id.len(), 16);
        assert_eq!(
            connecting_state.phase,
            wire::ConnectPhase::ObservingOwnedState as i32
        );

        // Connected：完整 session（attempt + protocol/platform/packet refs + proofs）。
        let connected = snapshot_for_phase(HostPhase::Connected, &composition);
        let wire::runtime_snapshot::State::Connected(connected_state) = connected.state.unwrap()
        else {
            panic!("expected connected");
        };
        let session = connected_state.session.expect("connected has session");
        assert!(session.attempt.is_some(), "session carries attempt");
        assert!(
            session.protocol_session.is_some(),
            "session carries protocol ref"
        );
        assert!(
            session.platform_ownership.is_some(),
            "session carries ownership ref"
        );
        assert_eq!(
            session
                .packet_lease
                .as_ref()
                .expect("packet lease")
                .identity_digest,
            composition.packet_lease_ref_bytes(),
            "packet lease must match the composition's W23B leg",
        );
        assert!(
            session.platform_ready.is_some(),
            "session carries ready proof"
        );
        assert!(
            session.data_running.is_some(),
            "session carries running proof"
        );

        // Reconciling：context（packet_boundary_lost）+ obligation。
        let reconciling = snapshot_for_phase(HostPhase::Reconciling, &composition);
        let wire::runtime_snapshot::State::Reconciling(reconciling_state) =
            reconciling.state.unwrap()
        else {
            panic!("expected reconciling");
        };
        assert!(
            matches!(
                reconciling_state.context.expect("context").context,
                Some(wire::recovery_context::Context::PacketBoundaryLost(_))
            ),
            "reconcile context = packet boundary lost (helper link lost analog)"
        );
        assert_eq!(
            reconciling_state
                .obligation
                .expect("obligation")
                .owner_runtime_epoch,
            composition.runtime_epoch_bytes(),
        );
    }

    /// 未授权的 gate 必须拒绝写 RPC（fail closed）。
    #[tokio::test]
    async fn mutations_require_authorized_gate() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let logs_dir = tempfile::tempdir().expect("logs tempdir");
        let logs =
            Arc::new(LogAggregator::open(&logs_dir.path().join("g.jsonl")).expect("open logs"));
        let (shared, service) = KernelControlService::from_composition(
            plain_composition(),
            EngineSlot::new(engine),
            PathBuf::new(),
            logs,
        );
        let _ = shared;

        let err = service
            .connect(Request::new(ConnectRequest::default()))
            .await
            .expect_err("unauthenticated");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    /// Connect：凭据组装 → engine 派发（lookup_key/request_digest/plan 正确 + 一次性
    /// 秘密送达）→ 发送后 wire 副本确定性零化。
    #[tokio::test]
    async fn connect_dispatches_apply_and_zeroizes_wire_secret() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let dir = seeded_config_dir("s3cret");
        let intent = connect_intent();

        let (reply, zeroized) =
            execute_connect(&mut *engine.lock().await, dir.path(), intent.clone())
                .await
                .expect("connect");

        // engine 收到 apply：lookup_key/request_digest 派生自 connect 意图。
        let engine_guard = engine.lock().await;
        // Bug D 回归：connect 派发 apply 前必须先建立 owner lease（P1-b `core.owner`
        // 前置；缺失时 engine 返回 `failed_precondition("no owner lease established")`）。
        assert_eq!(
            *engine_guard.lease_ensures.lock().unwrap(),
            1,
            "connect 必须恰好一次 ensure_owner_lease（apply 前置）"
        );
        let captured = &engine_guard.applies.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let (apply, secret) = &captured[0];
        // Bug E 回归：engine-facing 的 lookup_key.method 必须从 Connect 转为 ApplyTunnel
        // （engine `kernel_request_to_operation` 校验 method == expected_method，不转则
        // "kernel: operation: out of scope"）；runtime_epoch/operation_id 保持 connect 意图。
        let apply_key = apply.lookup_key.as_ref().expect("apply lookup key");
        let intent_key = intent.lookup_key.as_ref().expect("intent lookup key");
        assert_eq!(
            apply_key.method,
            wire::OperationMethod::ApplyTunnel as i32,
            "engine apply 的 lookup_key.method 必须为 ApplyTunnel"
        );
        assert_eq!(
            apply_key.runtime_epoch, intent_key.runtime_epoch,
            "apply 保留 connect 意图的 runtime_epoch"
        );
        assert_eq!(
            apply_key.operation_id, intent_key.operation_id,
            "apply 保留 connect 意图的 operation_id"
        );
        assert_eq!(apply.request_digest, intent.request_digest);
        // engine 收到的一次性秘密 = config 组装的 CredentialPackage（username/password）。
        let parsed = crate::credential::parse_secret_payload(secret).expect("parse");
        assert_eq!(parsed.username, "student");
        assert_eq!(parsed.password, "s3cret");
        assert!(
            !format!("{parsed:?}").contains("s3cret"),
            "Debug 不得泄漏明文"
        );
        // plan 从 config 派生（routes/mtu）。
        let plan = apply.plan.as_ref().expect("plan from config");
        assert_eq!(plan.mtu, 1290);
        assert_eq!(plan.ipv4_routes.len(), 2);
        assert_eq!(plan.ipv4_routes[0].network, vec![202, 120, 80, 0]);
        assert_eq!(plan.ipv4_routes[0].prefix_len, 20);
        // C1: control_bypass 从 config server_bypass_ips 派生（4 字节八位组）。
        assert_eq!(
            plan.control_bypass,
            vec![vec![10, 1, 1, 1], vec![10, 2, 2, 2]]
        );

        // 发送后 wire 副本已确定性零化。
        assert!(
            zeroized.secret_payload.iter().all(|&b| b == 0),
            "wire secret must be zeroed after send"
        );
        assert!(reply.result.is_some(), "engine apply accepted");
    }

    /// C1：`plan_from_config` 从 config `server_bypass_ips` 填 wire
    /// `control_bypass`（4 字节八位组）；非法条目（非 IPv4）与 routes 同策略静默
    /// 跳过，绝不产出非 4 字节项（`convert::tunnel_plan_from_wire` 会拒绝）。
    #[test]
    fn plan_from_config_fills_control_bypass_from_server_bypass_ips() {
        let cfg = ExvConfig {
            server_bypass_ips: vec![
                "10.9.9.9".to_string(),
                "not-an-ip".to_string(),
                "192.168.1.1".to_string(),
            ],
            ..ExvConfig::default()
        };
        let plan = plan_from_config(&cfg, &[0x33; 32]);
        assert_eq!(
            plan.control_bypass,
            vec![vec![10, 9, 9, 9], vec![192, 168, 1, 1]],
            "非法 bypass 条目被过滤，合法条目按配置顺序保留"
        );
    }

    /// C1 回归：空 `server_bypass_ips` 时 `control_bypass` 为空（P3-b2 空表语义
    /// 保留——用户未配置 bypass 时不得意外产生路由）。
    #[test]
    fn plan_from_config_empty_server_bypass_ips_yields_empty_control_bypass() {
        let cfg = ExvConfig::default();
        let plan = plan_from_config(&cfg, &[0x44; 32]);
        assert!(plan.control_bypass.is_empty());
    }

    /// T5 接入：豁免派生并入 control_bypass 装配链。wire 冻结期通配条目
    /// （`a.*` 形态）与 CIDR 精确串（含 `/`）无法表示为 4 字节八位组，被既有
    /// 过滤策略挡在 control_bypass 外（绝不产出非 4 字节项）；精确 IP 照常透传，
    /// 网段结构仍由 `ipv4_routes` 携带（设计 §5.4 双字段分工）。
    #[test]
    fn plan_from_config_derives_proxy_exempt_without_breaking_wire_shape() {
        let cfg = ExvConfig {
            server_bypass_ips: vec![
                "10.9.9.9".to_string(),
                "10.9.9.9".to_string(), // 重复条目：派生层去重。
                "bad-ip".to_string(),
            ],
            routes: vec![
                "10.0.0.0/8".to_string(),      // 对齐整段 → 通配 `10.*`（不进 bypass）。
                "202.120.80.0/20".to_string(), // 非 /8-/24 整段 → 精确串（不进 bypass）。
                "broken-route".to_string(),    // 非法条目静默跳过。
            ],
            ..ExvConfig::default()
        };
        let plan = plan_from_config(&cfg, &[0x55; 32]);
        // control_bypass 只收可表示为 4 字节的精确 IP（去重保序）；通配与 CIDR 串
        // 不污染 wire 形状。
        assert_eq!(plan.control_bypass, vec![vec![10, 9, 9, 9]]);
        // 路由字段不受豁免派生影响（网段结构照常携带给 engine 派生 desired bypass）。
        assert_eq!(plan.ipv4_routes.len(), 2);
    }

    /// 凭据缺失（config 无 key.bin）→ Connect fail closed，engine 不被调用。
    #[tokio::test]
    async fn connect_missing_credentials_fails_before_dispatch() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let empty_dir = tempfile::tempdir().expect("tempdir");
        let intent = connect_intent();

        let err = execute_connect(&mut *engine.lock().await, empty_dir.path(), intent)
            .await
            .expect_err("credentials must fail");
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(
            engine.lock().await.applies.lock().unwrap().is_empty(),
            "engine must not be called on credential failure"
        );
    }

    /// Connect 完整 RPC 路径：gate → 意图校验 → 凭据组装 → engine 派发（fake）→
    /// 发送后零化 → OperationReply。UI 提供的一次性 secret_payload（被忽略）必须
    /// 确定性零化，不驻留 host 内存。
    #[tokio::test]
    async fn connect_rpc_success_path_dispatches_and_zeroizes_ui_payload() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let dir = seeded_config_dir("s3cret");
        let (service, _logs_dir) = service_with_config(&engine, dir.path().to_path_buf());
        // R1 attach-before-apply：注入状态源 + 拉起转发器（否则 connect await 就绪悬挂）。
        let _forwarder = spawn_status_ready(&service, &engine).await;

        // UI 携带的一次性 secret_payload：host 从磁盘加载凭据，忽略此字段但零化。
        let mut intent = connect_intent();
        intent.profile = Some(wire::ConnectionProfileRef {
            identity_digest: vec![0x77; 32],
        });
        let request = Request::new(ConnectRequest {
            intent: Some(intent.clone()),
            secret_payload: b"{\"version\":1,\"username\":\"ui\",\"password\":\"ui-secret\"}"
                .to_vec(),
        });

        let reply = service
            .connect(request)
            .await
            .expect("connect rpc succeeds");
        assert!(reply.into_inner().terminal.is_some(), "apply accepted");

        // engine 收到 apply：lookup_key/request_digest 派生自意图，秘密为磁盘凭据。
        let engine_guard = engine.lock().await;
        let captured = &engine_guard.applies.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let (apply, secret) = &captured[0];
        // Bug E 回归：engine-facing 的 lookup_key.method 必须从 Connect 转为 ApplyTunnel。
        assert_eq!(
            apply.lookup_key.as_ref().expect("key").method,
            wire::OperationMethod::ApplyTunnel as i32,
            "engine apply 的 lookup_key.method 必须为 ApplyTunnel"
        );
        let parsed = crate::credential::parse_secret_payload(secret).expect("parse");
        assert_eq!(parsed.username, "student");
        assert_eq!(parsed.password, "s3cret");
        assert!(
            !format!("{parsed:?}").contains("ui-secret"),
            "UI payload must be ignored in favor of disk credentials"
        );
    }

    /// R1 异步 Connect RPC：engine 回 `pending`（ApplyAccepted）→ host 立即回
    /// 无终局 OperationReply（`terminal: None`），composition 已受理进 Connecting 并
    /// 登记 operation_id；随后经状态转发器的真实 Connected 事件驱动 → Connected。
    #[tokio::test]
    async fn connect_rpc_async_pending_then_status_event_drives_connected() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.pending_apply.lock().unwrap() = true;
        // 注入状态源：异步终态/阶段由 StreamConnectStatus 通道（状态转发器）驱动。
        let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        engine
            .lock()
            .await
            .events
            .lock()
            .unwrap()
            .replace(status_rx);
        let dir = seeded_config_dir("s3cret");
        let (service, _logs_dir) = service_with_config(&engine, dir.path().to_path_buf());
        let bus = service.events();
        let handle = service.spawn_status_forwarder();

        let intent = connect_intent();
        let request = Request::new(ConnectRequest {
            intent: Some(intent.clone()),
            secret_payload: vec![],
        });
        let reply = service
            .connect(request)
            .await
            .expect("connect rpc succeeds");
        // 异步契约：pending（无终局），终态走 status 通道。
        assert!(reply.into_inner().terminal.is_none(), "async pending reply");

        // Progress（细粒度 phase）→ composition 已在 Connecting（connect 受理），
        // 阶段真实推进。
        status_tx
            .send(EngineStatusEvent::Progress {
                operation_id: intent.lookup_key.as_ref().unwrap().operation_id.clone(),
                connect_phase: wire::ConnectPhase::ApplyingPlatformTunnel,
            })
            .unwrap();
        wait_snapshot_connecting_phase(&bus, wire::ConnectPhase::ApplyingPlatformTunnel).await;

        // 真实 Connected → Connected 终态（set_phase(Connected) 由状态流驱动）。
        status_tx
            .send(EngineStatusEvent::Connected {
                operation_id: intent.lookup_key.as_ref().unwrap().operation_id.clone(),
                session_established_at_ms: Some(1_700_000_000_123),
            })
            .unwrap();
        wait_snapshot_state(&bus, "connected").await;

        // 快照携带 connect 的 operation_id（R1 契约：operation 关联）。
        let snap = bus.current_snapshot().expect("published snapshot");
        assert_eq!(
            snap.operation_id,
            intent.lookup_key.as_ref().unwrap().operation_id
        );
        let Some(wire::runtime_snapshot::State::Connected(connected)) = snap.state else {
            panic!("connected status must publish a connected snapshot");
        };
        assert_eq!(
            connected.session_established_at_ms,
            1_700_000_000_123,
            "engine 状态流确认的会话起点必须贯穿至 WatchEvents"
        );

        drop(status_tx);
        handle.abort();
    }

    /// Connect RPC：非法意图（digest 长度错 / method 不匹配）→ fail closed，
    /// engine 不被调用。
    #[tokio::test]
    async fn connect_rpc_invalid_intent_rejected_before_dispatch() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let dir = seeded_config_dir("s3cret");
        let (service, _logs_dir) = service_with_config(&engine, dir.path().to_path_buf());

        // digest 长度非法。
        let mut bad_digest = connect_intent();
        bad_digest.request_digest = vec![0u8; 16];
        let err = service
            .connect(Request::new(ConnectRequest {
                intent: Some(bad_digest),
                secret_payload: vec![],
            }))
            .await
            .expect_err("invalid digest");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        // method 不匹配（STOP 而非 CONNECT）。
        let mut bad_method = connect_intent();
        bad_method.lookup_key.as_mut().expect("key").method = wire::OperationMethod::Stop as i32;
        let err = service
            .connect(Request::new(ConnectRequest {
                intent: Some(bad_method),
                secret_payload: vec![],
            }))
            .await
            .expect_err("wrong method");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        // 缺意图 → invalid_argument。
        let err = service
            .connect(Request::new(ConnectRequest::default()))
            .await
            .expect_err("missing intent");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        assert!(
            engine.lock().await.applies.lock().unwrap().is_empty(),
            "engine must not be called on invalid intent"
        );
    }

    // -----------------------------------------------------------------------
    // C3a：自动重连 host 侧重连驱动（掉线识别 → 判定 → 触发；计数/清零/耗尽/防重入）。
    // -----------------------------------------------------------------------

    /// C3a：带 auto_reconnect 配置的凭据目录（config + key.bin + 加密密码；重连凭据
    /// 从磁盘重新组装的验证基座）。
    fn reconnect_config_dir(auto: bool, max: u32) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ExvConfig::ensure_key(dir.path()).expect("ensure key");
        let mut cfg = ExvConfig {
            server: "vpn-cn.ecnu.edu.cn".to_string(),
            username: "student".to_string(),
            auto_reconnect: auto,
            auto_reconnect_max_attempts: max,
            ..ExvConfig::default()
        };
        cfg.set_password_encrypted("s3cret", &key).expect("encrypt");
        cfg.save_to_dir(dir.path()).expect("save config");
        dir
    }

    /// C3a：可重试数据面掉线错误（C2 唯一来源的标记：stage=DataPlane +
    /// retry=RetrySameOperation）。
    fn retryable_disconnect_error() -> wire::VpnError {
        use wire::{EffectCertainty, ErrorCode, ErrorStage, RetryAdvice};
        wire::VpnError {
            code: ErrorCode::EffectUnknown as i32,
            stage: ErrorStage::DataPlane as i32,
            certainty: EffectCertainty::NoEffect as i32,
            retry: RetryAdvice::RetrySameOperation as i32,
            subject: None,
            resource: None,
            native: None,
        }
    }

    /// 连接期失败错误（非可重试：stage=Ingress + retry=DoNotRetry——不得触发重连）。
    fn connection_phase_error() -> wire::VpnError {
        use wire::{EffectCertainty, ErrorCode, ErrorStage, RetryAdvice};
        wire::VpnError {
            code: ErrorCode::EffectUnknown as i32,
            stage: ErrorStage::Ingress as i32,
            certainty: EffectCertainty::NoEffect as i32,
            retry: RetryAdvice::DoNotRetry as i32,
            subject: None,
            resource: None,
            native: None,
        }
    }

    /// C3a：注入状态源 + 拉起状态转发器与重连 worker + 等就绪。
    ///
    /// 返回 (composition Arc, service, status_tx, 转发器句柄, worker 句柄, 凭据目录)。
    /// composition Arc 供测试在 apply 阻塞持 engine 锁期间免 engine 锁读在途
    /// operation_id（composition 锁与 engine 锁互不重叠）。
    #[allow(clippy::type_complexity)]
    async fn spawn_reconnect_harness(
        engine: &Arc<tokio::sync::Mutex<FakeEngine>>,
        auto: bool,
        max: u32,
    ) -> (
        Arc<Mutex<HostComposition>>,
        KernelControlService,
        tokio::sync::mpsc::UnboundedSender<EngineStatusEvent>,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
        tempfile::TempDir,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        engine.lock().await.events.lock().unwrap().replace(rx);
        let dir = reconnect_config_dir(auto, max);
        // 复用 `service_with_config` 的 composition 装配：gate 授权 + controller 绑定；
        // 改用 `from_composition` 以拿回共享 composition Arc（测试观测 operation_id）。
        let mut composition =
            crate::composition::compose_nonprivileged_host(&helper()).expect("compose");
        composition.kernel_gate().authorize(&helper()).expect("authorize");
        let (actor_peer, capability) = controller_peer_and_capability();
        composition.bind_controller(actor_peer, capability);
        let logs_dir = tempfile::tempdir().expect("logs tempdir");
        let logs = Arc::new(
            LogAggregator::open(&logs_dir.path().join("svc.jsonl")).expect("open logs"),
        );
        let engine_dyn: Arc<tokio::sync::Mutex<dyn KernelEngineControl>> = engine.clone();
        let (composition_arc, service) = KernelControlService::from_composition(
            composition,
            EngineSlot::new(engine_dyn),
            dir.path().to_path_buf(),
            logs,
        );
        let service = service
            .with_proxy_tun_probe(no_detection_probe())
            .with_service_status_source(fake_status_source(false, SERVICE_STOPPED.0));
        let forwarder = service.spawn_status_forwarder();
        let worker = service.spawn_reconnect_worker();
        let mut ready = service.status_ready();
        while !*ready.borrow() {
            if ready.changed().await.is_err() {
                break;
            }
        }
        (composition_arc, service, tx, forwarder, worker, dir)
    }

    /// C3a：轮询直到 fake engine 的 apply 计数 ≥ n（worker 异步派发收敛等待）。
    async fn wait_for_apply_count(engine: &Arc<tokio::sync::Mutex<FakeEngine>>, n: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if engine.lock().await.applies.lock().unwrap().len() >= n {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("apply count reached");
    }

    /// C3a：读取第 `idx` 次 apply 的 operation_id（重连意图随机生成，从派发观测读回）。
    async fn apply_op_id(engine: &Arc<tokio::sync::Mutex<FakeEngine>>, idx: usize) -> Vec<u8> {
        engine.lock().await.applies.lock().unwrap()[idx]
            .0
            .lookup_key
            .as_ref()
            .expect("apply lookup key")
            .operation_id
            .clone()
    }

    /// C3a：UI connect（异步 pending 契约）→ Connected，返回当前 operation_id。
    async fn drive_to_connected(
        service: &KernelControlService,
        status_tx: &tokio::sync::mpsc::UnboundedSender<EngineStatusEvent>,
    ) -> Vec<u8> {
        let intent = connect_intent();
        let op_id = intent.lookup_key.as_ref().expect("key").operation_id.clone();
        let reply = service
            .connect(Request::new(ConnectRequest {
                intent: Some(intent),
                secret_payload: vec![],
            }))
            .await
            .expect("connect");
        assert!(reply.into_inner().terminal.is_none(), "async pending");
        status_tx
            .send(EngineStatusEvent::Connected {
                operation_id: op_id.clone(),
                session_established_at_ms: Some(1_700_000_000_123),
            })
            .unwrap();
        wait_snapshot_state(&service.events(), "connected").await;
        op_id
    }

    /// C3a：识别——stage=DataPlane + retry=RetrySameOperation 判为可重试掉线；其余否。
    #[test]
    fn is_retryable_disconnect_detects_data_plane_same_operation_marker() {
        assert!(is_retryable_disconnect(&retryable_disconnect_error()));
        assert!(!is_retryable_disconnect(&connection_phase_error()));
        // DataPlane 但 DoNotRetry：不是可重试掉线（连接期失败）。
        let e = wire::VpnError {
            stage: wire::ErrorStage::DataPlane as i32,
            retry: wire::RetryAdvice::DoNotRetry as i32,
            ..connection_phase_error()
        };
        assert!(!is_retryable_disconnect(&e));
        // Ingress 但 RetrySameOperation：stage 不符，不是数据面掉线。
        let e = wire::VpnError {
            stage: wire::ErrorStage::Ingress as i32,
            retry: wire::RetryAdvice::RetrySameOperation as i32,
            ..retryable_disconnect_error()
        };
        assert!(!is_retryable_disconnect(&e));
    }

    /// C3a：重连意图 = 合法最小 Connect 意图（method=CONNECT、32 字节 digest、
    /// 16 字节 runtime_epoch/operation_id、32 字节 principal_digest）。
    #[test]
    fn reconnect_intent_is_valid_minimal_connect_intent() {
        let intent = reconnect_intent();
        assert_eq!(intent.request_digest.len(), 32);
        let key = intent.lookup_key.as_ref().expect("lookup key");
        assert_eq!(key.method, wire::OperationMethod::Connect as i32);
        assert_eq!(key.runtime_epoch.len(), 16);
        assert_eq!(key.operation_id.len(), 16);
        assert_eq!(key.principal_digest.len(), 32);
        assert!(validate_intent(&intent).is_ok(), "重连意图必须过 validate_intent");
    }

    /// C3a：可重试数据面掉线（stage=DataPlane+retry=RetrySameOperation）→ 自动重连；
    /// 重连凭据从磁盘重新组装（config + key.bin 的 username/password，非持 engine 凭据）。
    #[tokio::test]
    async fn retryable_disconnect_triggers_auto_reconnect_with_disk_credentials() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.pending_apply.lock().unwrap() = true;
        let (_composition, service, status_tx, forwarder, worker, _dir) =
            spawn_reconnect_harness(&engine, true, 0).await;

        let op0 = drive_to_connected(&service, &status_tx).await;
        assert_eq!(engine.lock().await.applies.lock().unwrap().len(), 1);

        // 可重试掉线 → 自动重连（第 2 次 apply）。
        status_tx
            .send(EngineStatusEvent::Failed {
                operation_id: op0,
                error: retryable_disconnect_error(),
            })
            .unwrap();
        wait_for_apply_count(&engine, 2).await;

        let engine_guard = engine.lock().await;
        let applies = engine_guard.applies.lock().unwrap();
        assert_eq!(applies.len(), 2, "可重试掉线必须触发一次自动重连");
        let (_, secret) = &applies[1];
        let parsed = crate::credential::parse_secret_payload(secret).expect("parse");
        assert_eq!(parsed.username, "student");
        assert_eq!(parsed.password, "s3cret");
        drop(applies);
        drop(engine_guard);

        forwarder.abort();
        worker.abort();
    }

    /// C3a：auto_reconnect=false → 可重试掉线不自动重连（保持现状 Connected 不降级；
    /// 掉线经 last_wire_error 记录）。
    #[tokio::test]
    async fn retryable_disconnect_with_auto_reconnect_disabled_does_not_reconnect() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.pending_apply.lock().unwrap() = true;
        let (_composition, service, status_tx, forwarder, worker, _dir) =
            spawn_reconnect_harness(&engine, false, 0).await;

        let op0 = drive_to_connected(&service, &status_tx).await;
        assert_eq!(engine.lock().await.applies.lock().unwrap().len(), 1);

        status_tx
            .send(EngineStatusEvent::Failed {
                operation_id: op0,
                error: retryable_disconnect_error(),
            })
            .unwrap();
        // 等 worker 处理（记 kernel.reconnect.disabled），但不得再派发。
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            engine.lock().await.applies.lock().unwrap().len(),
            1,
            "auto_reconnect=false 时不得自动重连"
        );

        forwarder.abort();
        worker.abort();
    }

    /// C3a：连接期失败（非可重试：stage=Ingress+DoNotRetry）不触发自动重连。
    #[tokio::test]
    async fn connection_phase_failure_does_not_trigger_auto_reconnect() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.pending_apply.lock().unwrap() = true;
        let (_composition, service, status_tx, forwarder, worker, _dir) =
            spawn_reconnect_harness(&engine, true, 0).await;

        let op0 = drive_to_connected(&service, &status_tx).await;
        status_tx
            .send(EngineStatusEvent::Failed {
                operation_id: op0,
                error: connection_phase_error(),
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            engine.lock().await.applies.lock().unwrap().len(),
            1,
            "连接期失败（DoNotRetry）不得触发自动重连"
        );

        forwarder.abort();
        worker.abort();
    }

    /// C3a：max_attempts=0 = 无限——连续掉线持续自动重连（预算不耗尽）。
    #[tokio::test]
    async fn auto_reconnect_zero_max_attempts_retries_without_limit() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.pending_apply.lock().unwrap() = true;
        let (_composition, service, status_tx, forwarder, worker, _dir) =
            spawn_reconnect_harness(&engine, true, 0).await;

        let op0 = drive_to_connected(&service, &status_tx).await;
        // 三轮掉线 → 三轮重连（无限预算）；每轮用当前在途操作的 id（掉线事件按
        // operation_id 关联当前重连尝试）。
        for i in 0..3usize {
            let op = if i == 0 {
                op0.clone()
            } else {
                apply_op_id(&engine, i).await
            };
            status_tx
                .send(EngineStatusEvent::Failed {
                    operation_id: op,
                    error: retryable_disconnect_error(),
                })
                .unwrap();
            wait_for_apply_count(&engine, i + 2).await;
        }
        assert_eq!(
            engine.lock().await.applies.lock().unwrap().len(),
            4,
            "max=0（无限）时第 4 次连接（初始+3 重连）照常派发"
        );

        forwarder.abort();
        worker.abort();
    }

    /// C3a：max_attempts=N → N 次重连后耗尽停止。
    #[tokio::test]
    async fn auto_reconnect_stops_after_max_attempts_exhausted() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.pending_apply.lock().unwrap() = true;
        let (_composition, service, status_tx, forwarder, worker, _dir) =
            spawn_reconnect_harness(&engine, true, 2).await;

        let op0 = drive_to_connected(&service, &status_tx).await;
        // 掉线 #1 → 重连 #1。
        status_tx
            .send(EngineStatusEvent::Failed {
                operation_id: op0,
                error: retryable_disconnect_error(),
            })
            .unwrap();
        wait_for_apply_count(&engine, 2).await;
        // 掉线 #2（对重连 #1 的 operation）→ 重连 #2。
        let op1 = apply_op_id(&engine, 1).await;
        status_tx
            .send(EngineStatusEvent::Failed {
                operation_id: op1,
                error: retryable_disconnect_error(),
            })
            .unwrap();
        wait_for_apply_count(&engine, 3).await;
        // 掉线 #3 → 预算（max=2）耗尽，不再重连。
        let op2 = apply_op_id(&engine, 2).await;
        status_tx
            .send(EngineStatusEvent::Failed {
                operation_id: op2,
                error: retryable_disconnect_error(),
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            engine.lock().await.applies.lock().unwrap().len(),
            3,
            "max=2 时第 3 次掉线后停止重连（初始 1 + 重连 2）"
        );

        forwarder.abort();
        worker.abort();
    }

    /// C3a：Connected 成功 → per-connection 重连计数清零，预算恢复（max=2 但每次成功
    /// 连接后重置，可持续重连）。
    #[tokio::test]
    async fn connected_resets_reconnect_counter_restoring_budget() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.pending_apply.lock().unwrap() = true;
        let (_composition, service, status_tx, forwarder, worker, _dir) =
            spawn_reconnect_harness(&engine, true, 2).await;

        let op0 = drive_to_connected(&service, &status_tx).await;
        // 掉线 #1 → 重连 #1（attempts=1）。
        status_tx
            .send(EngineStatusEvent::Failed {
                operation_id: op0,
                error: retryable_disconnect_error(),
            })
            .unwrap();
        wait_for_apply_count(&engine, 2).await;
        let op1 = apply_op_id(&engine, 1).await;
        // 重连 #1 成功 → Connected 清零计数（若未清零，max=2 早已用尽）。
        status_tx
            .send(EngineStatusEvent::Connected {
                operation_id: op1.clone(),
                session_established_at_ms: Some(1_700_000_000_123),
            })
            .unwrap();
        wait_snapshot_state(&service.events(), "connected").await;
        // 再掉线 → 预算已恢复，重连 #2 照常派发。
        status_tx
            .send(EngineStatusEvent::Failed {
                operation_id: op1,
                error: retryable_disconnect_error(),
            })
            .unwrap();
        wait_for_apply_count(&engine, 3).await;
        assert_eq!(
            engine.lock().await.applies.lock().unwrap().len(),
            3,
            "Connected 清零后预算恢复，第 3 次连接照常发生"
        );

        forwarder.abort();
        worker.abort();
    }

    /// C3a：防重入/串行——重连 #1 派发在途（apply 阻塞持 engine 锁）时，新的可重试
    /// 掉线不并发启动重连 #2；放行后 worker 串行处理下一次信号。观测走免锁计数
    /// （engine 锁被阻塞的 apply 持有，不能锁引擎观测）。
    #[tokio::test]
    async fn reconnect_runs_serially_without_concurrent_attempts() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.pending_apply.lock().unwrap() = true;
        let obs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        engine
            .lock()
            .await
            .apply_obs
            .lock()
            .unwrap()
            .replace(Arc::clone(&obs));
        let (composition, service, status_tx, forwarder, worker, _dir) =
            spawn_reconnect_harness(&engine, true, 3).await;

        let op0 = drive_to_connected(&service, &status_tx).await;
        assert_eq!(obs.load(std::sync::atomic::Ordering::Relaxed), 1);

        // 挂起重连 #1 的 apply（引擎处理慢 → 重连在途，engine 锁被持有）。
        let gate = Arc::new(tokio::sync::Notify::new());
        engine
            .lock()
            .await
            .apply_block
            .lock()
            .unwrap()
            .replace(Arc::clone(&gate));

        // 掉线 #1 → 重连 #1 到达 apply 并阻塞。
        status_tx
            .send(EngineStatusEvent::Failed {
                operation_id: op0,
                error: retryable_disconnect_error(),
            })
            .unwrap();
        wait_for_obs_count(&obs, 2).await;
        // 掉线 #2（对重连 #1 的 operation）→ 信号排队；重连 #1 仍在途。operation_id
        // 从 composition 读（重连意图随机生成；engine 锁被阻塞 apply 持有，不能锁引擎）。
        let op1 = composition
            .lock()
            .await
            .operation_id()
            .map(|id| id.to_vec())
            .expect("reconnect in-flight operation");
        status_tx
            .send(EngineStatusEvent::Failed {
                operation_id: op1,
                error: retryable_disconnect_error(),
            })
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            obs.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "重连 #1 在途时不得并发启动重连 #2（串行防重入）"
        );

        // 放行 → 重连 #1 完成；随后 worker 串行处理掉线 #2 → 重连 #2。
        gate.notify_one();
        wait_for_obs_count(&obs, 3).await;
        assert_eq!(
            engine.lock().await.applies.lock().unwrap().len(),
            3,
            "放行后串行完成第 2 次重连"
        );

        forwarder.abort();
        worker.abort();
    }

    /// C3a：轮询免锁 apply 观测计数 ≥ n（apply 阻塞持 engine 锁期间使用）。
    async fn wait_for_obs_count(obs: &Arc<std::sync::atomic::AtomicUsize>, n: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if obs.load(std::sync::atomic::Ordering::Relaxed) >= n {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("obs apply count reached");
    }

    // -----------------------------------------------------------------------
    // C4 wire unfreeze：自动重连状态上报（ReconnectStatus → RuntimeSnapshot.reconnect；
    // helper 双分支、状态组装、config 读失败保守值、GetSnapshot/forwarder 两条 attach 路径）。
    // -----------------------------------------------------------------------

    /// `snapshot_with_reconnect`：Some → 附加 ReconnectStatus；None → `reconnect` 留空。
    #[test]
    fn snapshot_with_reconnect_attaches_or_clears() {
        let base = snapshot_for_phase(HostPhase::Idle, &plain_composition());
        let status = wire::ReconnectStatus {
            auto_reconnect: true,
            max_attempts: 3,
            current_attempt: 1,
            active: true,
        };
        let with = snapshot_with_reconnect(base.clone(), Some(status.clone()));
        let attached = with.reconnect.expect("reconnect attached");
        assert!(attached.auto_reconnect);
        assert_eq!(attached.max_attempts, 3);
        assert_eq!(attached.current_attempt, 1);
        assert!(attached.active);

        let cleared = snapshot_with_reconnect(base, None);
        assert!(cleared.reconnect.is_none(), "None → reconnect 留空");
    }

    /// `reconnect_status_from_state`：attempts/active/auto/max 四字段一一映射。
    #[test]
    fn reconnect_status_from_state_maps_all_fields() {
        let status = reconnect_status_from_state(2, true, true, 0);
        assert!(status.auto_reconnect);
        assert_eq!(status.max_attempts, 0, "0 = unlimited");
        assert_eq!(status.current_attempt, 2);
        assert!(status.active);

        let disabled = reconnect_status_from_state(0, false, false, 5);
        assert!(!disabled.auto_reconnect);
        assert_eq!(disabled.max_attempts, 5);
        assert_eq!(disabled.current_attempt, 0);
        assert!(!disabled.active);
    }

    /// `reconnect_status_from_config`：auto/max 从磁盘 config 读、attempts/active 从原子读。
    #[test]
    fn reconnect_status_from_config_reads_disk_config_and_atomics() {
        let dir = reconnect_config_dir(true, 3);
        let attempts = AtomicU32::new(2);
        let active = AtomicBool::new(true);
        let status = reconnect_status_from_config(&attempts, &active, dir.path());
        assert!(status.auto_reconnect, "auto_reconnect 从磁盘配置读取");
        assert_eq!(status.max_attempts, 3, "max_attempts 从磁盘配置读取");
        assert_eq!(status.current_attempt, 2, "attempts 从原子读取");
        assert!(status.active, "active 从原子读取");
    }

    /// `reconnect_status_from_config`：config 读取失败（IO 错误，非缺失）→ 保守
    /// `auto_reconnect=false, max_attempts=0`（重连已禁用）；attempts/active 仍从原子上报。
    #[test]
    fn reconnect_status_from_config_unreadable_gives_conservative_disabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        // 让 config 路径是一个目录：`read_to_string` 返回非 NotFound 的 IO 错误
        // （Windows = AccessDenied）→ `ExvConfig::load_from_dir` Err → 保守禁用。
        std::fs::create_dir_all(dir.path().join("config.json")).expect("dir");
        let attempts = AtomicU32::new(1);
        let active = AtomicBool::new(false);
        let status = reconnect_status_from_config(&attempts, &active, dir.path());
        assert!(!status.auto_reconnect, "config 不可读 → auto_reconnect 保守 false");
        assert_eq!(status.max_attempts, 0, "config 不可读 → max_attempts 保守 0");
        assert_eq!(status.current_attempt, 1, "计数仍从原子上报");
        assert!(!status.active, "active 仍从原子上报");
    }

    /// GetSnapshot（C4 wire unfreeze）：从 host 原子 + config 组装 ReconnectStatus 并
    /// 附加到快照——auto/max 来自磁盘配置、attempt/active 来自 host 原子（注入 fake
    /// engine + 确定性 config 目录，不触真实注册表/凭据）。
    #[tokio::test]
    async fn get_snapshot_carries_reconnect_status() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let dir = reconnect_config_dir(true, 2);
        let (service, _logs_dir) = service_with_config(&engine, dir.path().to_path_buf());
        // 模拟一次重连进行中：计数 1 + 在途 true。
        service.reconnect_attempts.store(1, Ordering::Relaxed);
        service.reconnect_active.store(true, Ordering::Release);

        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        let reconnect = snap.reconnect.expect("reconnect carried by GetSnapshot");
        assert!(reconnect.auto_reconnect, "auto_reconnect 从配置读取");
        assert_eq!(reconnect.max_attempts, 2, "max_attempts 从配置读取");
        assert_eq!(reconnect.current_attempt, 1, "current_attempt 从 host 原子读取");
        assert!(reconnect.active, "active 从 host 原子读取");
    }

    /// 状态转发器（C4 wire unfreeze）：发布路径把当前重连状态附加到快照——Connected
    /// 清零计数/释放在途后上报 auto/max/attempt=0/active=false；随后 Progress 过渡
    /// 事件发布仍携带重连状态（计数/在途从原子实时读取，Progress 非终态不清 active）。
    #[tokio::test]
    async fn forwarder_published_snapshot_carries_reconnect_status() {
        use tokio_stream::StreamExt;

        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.pending_apply.lock().unwrap() = true;
        let (_composition, service, status_tx, forwarder, worker, _dir) =
            spawn_reconnect_harness(&engine, true, 3).await;

        // 订阅 live 流：订阅时无已发布事件（forwarder 尚无 status 事件）→ 首事件即
        // Connected 过渡（Connected 不降级语义见 composition `ConnectFailed` 处理——
        // 已建立连接不会被失败事件降级，故用 Progress 过渡验证实时计数/在途上报）。
        let mut stream = service
            .watch_events(Request::new(WatchEventsRequest::default()))
            .await
            .expect("watch stream")
            .into_inner();

        // Connected：真实成功连接——forwarder 清零 per-connection 计数并释放在途；
        // 发布快照携带重连状态（auto/max 来自配置，attempt=0、active=false）。
        drive_to_connected(&service, &status_tx).await;
        let ev = stream.next().await.expect("connected event").expect("ok");
        let reconnect = ev
            .snapshot
            .expect("connected snapshot")
            .reconnect
            .expect("forwarder publish carries reconnect");
        assert!(reconnect.auto_reconnect, "auto_reconnect 来自配置 (true)");
        assert_eq!(reconnect.max_attempts, 3, "max_attempts 来自配置 (3)");
        assert_eq!(reconnect.current_attempt, 0, "Connected 后 per-connection 计数清零");
        assert!(!reconnect.active, "Connected 后无在途重连");

        // 手工注入计数/在途 → Progress 过渡事件发布：重连状态随发布快照透传（计数/
        // 在途从 host 原子实时读取；Progress 非终态，不清 active）。
        service.reconnect_attempts.store(2, Ordering::Relaxed);
        service.reconnect_active.store(true, Ordering::Release);
        status_tx
            .send(EngineStatusEvent::Progress {
                operation_id: vec![0u8; 16],
                connect_phase: wire::ConnectPhase::ApplyingPlatformTunnel,
            })
            .unwrap();
        let ev = stream.next().await.expect("progress event").expect("ok");
        let reconnect = ev
            .snapshot
            .expect("progress snapshot")
            .reconnect
            .expect("progress publish carries reconnect");
        assert!(reconnect.auto_reconnect);
        assert_eq!(reconnect.max_attempts, 3);
        assert_eq!(reconnect.current_attempt, 2, "重连计数随过渡事件上报");
        assert!(reconnect.active, "Progress 非终态，在途标记保持 true");

        forwarder.abort();
        worker.abort();
    }

    /// GetSnapshot RPC：phase → 完整 wire snapshot（与 `snapshot_for_phase` 同构，
    /// 经服务层暴露）。
    #[tokio::test]
    async fn get_snapshot_rpc_maps_composition_phase() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);

        // 初始 composition phase = Idle → Idle snapshot。
        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        assert!(matches!(
            snap.state,
            Some(wire::runtime_snapshot::State::Idle(_))
        ));
    }

    /// 回归：engine 的 Connected 状态事件已经确认会话起点后，后续 `GetSnapshot`
    /// 不能用 composition 的占位 `0` 覆盖它。前端每秒轮询该 RPC；覆盖会让在线时长
    /// 在真实值与横线之间闪烁。
    #[tokio::test]
    async fn get_snapshot_preserves_confirmed_connected_session_start() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let established_at_ms = 1_700_000_000_123;

        let (kind, connected) = runtime_event_from_status(
            &EngineStatusEvent::Connected {
                operation_id: Vec::new(),
                session_established_at_ms: Some(established_at_ms),
            },
            &service.composition,
        )
        .await
        .expect("connected status must produce a snapshot");
        service.events().publish(kind, connected);

        let snapshot = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("get snapshot")
            .into_inner();
        let Some(wire::runtime_snapshot::State::Connected(connected)) = snapshot.state else {
            panic!("expected connected snapshot");
        };
        assert_eq!(
            connected.session_established_at_ms,
            established_at_ms,
            "已确认的会话起点必须在轮询快照中保持，而不能回退为 0"
        );
    }

    /// GetSnapshot RPC：gate 未授权仍可读快照（读路径不 gate；写路径才 gate）。
    #[tokio::test]
    async fn get_snapshot_read_path_not_gated() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let logs_dir = tempfile::tempdir().expect("logs tempdir");
        let logs =
            Arc::new(LogAggregator::open(&logs_dir.path().join("g.jsonl")).expect("open logs"));
        let (shared, service) = KernelControlService::from_composition(
            plain_composition(),
            EngineSlot::new(engine),
            PathBuf::new(),
            logs,
        );
        let service = service.with_proxy_tun_probe(no_detection_probe());
        let _ = shared;

        // 未授权 gate 下读快照成功（fail closed 只约束写路径）。
        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("read path not gated")
            .into_inner();
        assert!(snap.state.is_some());
    }

    /// WatchEvents 真实订阅（P3-c1）：resume=0 先发当前快照 SNAPSHOT，随后转发
    /// 现场事件；tick 严格递增、过渡事件种类正确、无事件时不结束（真实订阅流）。
    #[tokio::test]
    async fn watch_events_streams_current_then_live_with_incremental_ticks() {
        use tokio_stream::StreamExt;

        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();

        // 先发布一个 SNAPSHOT（当前快照）。
        let idle = snapshot_for_phase(
            HostPhase::Idle,
            &crate::composition::compose_nonprivileged_host(&helper()).expect("compose"),
        );
        let first = bus.publish(wire::RuntimeEventKind::Snapshot, idle);
        assert_eq!(first.monotonic_tick, 1);

        let mut stream = service
            .watch_events(Request::new(WatchEventsRequest::default()))
            .await
            .expect("watch stream")
            .into_inner();

        // 事件 1：resume=0 → 当前快照 SNAPSHOT（tick 1）。
        let ev1 = stream.next().await.expect("snapshot event").expect("ok");
        assert_eq!(ev1.monotonic_tick, 1);
        assert_eq!(ev1.kind, wire::RuntimeEventKind::Snapshot as i32);
        assert!(ev1.snapshot.is_some());

        // 事件 2：发布一个 TRANSITION（过渡）→ 现场转发，tick 递增。
        let connected = snapshot_for_phase(HostPhase::Connected, &plain_composition());
        bus.publish(wire::RuntimeEventKind::Transition, connected);
        let ev2 = stream.next().await.expect("transition event").expect("ok");
        assert_eq!(ev2.monotonic_tick, 2, "tick 必须严格递增");
        assert_eq!(ev2.kind, wire::RuntimeEventKind::Transition as i32);
        assert!(matches!(
            ev2.snapshot.map(|s| s.state),
            Some(Some(wire::runtime_snapshot::State::Connected(_)))
        ));

        // 事件 3：再一个 TRANSITION → tick 继续递增。
        let connecting = snapshot_for_phase(HostPhase::Connecting, &plain_composition());
        bus.publish(wire::RuntimeEventKind::Transition, connecting);
        let ev3 = stream.next().await.expect("second transition").expect("ok");
        assert_eq!(ev3.monotonic_tick, 3);
        assert!(matches!(
            ev3.snapshot.map(|s| s.state),
            Some(Some(wire::runtime_snapshot::State::Connecting(_)))
        ));
    }

    /// WatchEvents 多订阅者 fan-out（P3-c1）：两个订阅者都收到发布的过渡事件。
    #[tokio::test]
    async fn watch_events_fan_out_to_multiple_subscribers() {
        use tokio_stream::StreamExt;

        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();
        bus.publish(
            wire::RuntimeEventKind::Snapshot,
            snapshot_for_phase(HostPhase::Idle, &plain_composition()),
        );

        let mut a = service
            .watch_events(Request::new(WatchEventsRequest::default()))
            .await
            .expect("watch a")
            .into_inner();
        let mut b = service
            .watch_events(Request::new(WatchEventsRequest::default()))
            .await
            .expect("watch b")
            .into_inner();
        // 两个订阅者各自的初始快照（fan-out 前已存在）。
        let _ = a.next().await.expect("a initial").expect("ok");
        let _ = b.next().await.expect("b initial").expect("ok");

        bus.publish(
            wire::RuntimeEventKind::Transition,
            snapshot_for_phase(HostPhase::Connected, &plain_composition()),
        );
        let ea = a.next().await.expect("a live").expect("ok");
        let eb = b.next().await.expect("b live").expect("ok");
        assert_eq!(
            ea.monotonic_tick, eb.monotonic_tick,
            "两个订阅者看到同一事件"
        );
        assert_eq!(ea.kind, wire::RuntimeEventKind::Transition as i32);
    }

    /// WatchEvents 断线重放（P3-c1）：落后订阅者（resume_tick 低于当前 tick）先收到
    /// 重放的当前快照，再收到现场事件。
    #[tokio::test]
    async fn watch_events_disconnect_replay_resumes_current_snapshot() {
        use tokio_stream::StreamExt;

        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();

        // 已发布 tick 1（SNAPSHOT Idle）与 tick 2（TRANSITION Connected）。
        bus.publish(
            wire::RuntimeEventKind::Snapshot,
            snapshot_for_phase(HostPhase::Idle, &plain_composition()),
        );
        bus.publish(
            wire::RuntimeEventKind::Transition,
            snapshot_for_phase(HostPhase::Connected, &plain_composition()),
        );
        assert_eq!(bus.current_tick(), 2);

        // 落后订阅者：resume_tick=1（错过了 tick 2）→ 重放当前快照（tick 2）。
        let mut stream = service
            .watch_events(Request::new(WatchEventsRequest { resume_tick: 1 }))
            .await
            .expect("watch stream")
            .into_inner();
        let replay = stream.next().await.expect("replay").expect("ok");
        assert_eq!(replay.monotonic_tick, 2, "重放当前快照");
        assert!(matches!(
            replay.snapshot.map(|s| s.state),
            Some(Some(wire::runtime_snapshot::State::Connected(_)))
        ));

        // 随后转发现场事件（tick 3）。
        bus.publish(
            wire::RuntimeEventKind::Transition,
            snapshot_for_phase(HostPhase::Connecting, &plain_composition()),
        );
        let live = stream.next().await.expect("live").expect("ok");
        assert_eq!(live.monotonic_tick, 3);
    }

    /// WatchEvents resume 语义：resume_tick = 当前 tick → 不重放（只收未来事件）。
    #[tokio::test]
    async fn watch_events_resume_current_tick_skips_replay() {
        use tokio_stream::StreamExt;

        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();
        bus.publish(
            wire::RuntimeEventKind::Snapshot,
            snapshot_for_phase(HostPhase::Idle, &plain_composition()),
        );
        assert_eq!(bus.current_tick(), 1);

        let mut stream = service
            .watch_events(Request::new(WatchEventsRequest { resume_tick: 1 }))
            .await
            .expect("watch stream")
            .into_inner();
        // 无重放（resume 已是最新）→ 不收已发布的 tick 1；发布 tick 2 后收到。
        let delayed =
            tokio::time::timeout(std::time::Duration::from_millis(150), stream.next()).await;
        assert!(delayed.is_err(), "resume=current 不重放已发布事件");
        bus.publish(
            wire::RuntimeEventKind::Transition,
            snapshot_for_phase(HostPhase::Connected, &plain_composition()),
        );
        let ev = stream.next().await.expect("live").expect("ok");
        assert_eq!(ev.monotonic_tick, 2);
    }

    /// EventBus tick 铸造：严格递增、从 1 开始（P3-c1 增量语义底座）。
    #[test]
    fn event_bus_mints_strictly_increasing_ticks() {
        let bus = EventBus::new();
        assert_eq!(bus.current_tick(), 0);
        bus.publish(
            wire::RuntimeEventKind::Snapshot,
            snapshot_for_phase(HostPhase::Idle, &plain_composition()),
        );
        bus.publish(
            wire::RuntimeEventKind::Transition,
            snapshot_for_phase(HostPhase::Connected, &plain_composition()),
        );
        assert_eq!(bus.current_tick(), 2);
        assert_eq!(bus.next_tick(), 3);
    }

    /// P5-b 统计 lane：无状态快照时只缓存统计；已有 Connected 快照时必须铸造新的
    /// `WatchEvents` 快照，令 UI 收到实时统计而不是停在首次无统计的 Connected 状态。
    #[test]
    fn event_bus_stats_lane_publishes_and_recalls() {
        let bus = EventBus::new();
        assert_eq!(bus.current_stats(), None, "初始无统计");

        let stats = RuntimeStats {
            rx_bytes: 1000,
            tx_bytes: 500,
            rx_rate_bps: 200,
            tx_rate_bps: 100,
            latency_ms: 7,
            phase: wire::StatsPhase::Connected,
            engine_sequence: 3,
            sample_tick: 0,
        };
        let published = bus.publish_stats(stats);
        assert_eq!(published.sample_tick, 0, "无事件 → tick 0");
        assert_eq!(bus.current_stats(), Some(published));
        assert_eq!(bus.current_stats().unwrap().rx_rate_bps, 200);

        // Connected 快照已存在时，统计样本必须推进 status tick 并随新的状态事件发布。
        bus.publish(
            wire::RuntimeEventKind::Transition,
            snapshot_for_phase(HostPhase::Connected, &plain_composition()),
        );
        assert_eq!(bus.current_tick(), 1);
        let published2 = bus.publish_stats(stats);
        assert_eq!(published2.sample_tick, 2, "统计快照必须铸造下一个 status tick");
        assert_eq!(bus.current_tick(), 2, "统计更新必须送达 WatchEvents");
        assert_eq!(
            bus.current_snapshot()
                .and_then(|snapshot| snapshot.stats)
                .map(|snapshot| snapshot.sample_tick),
            Some(2),
            "最新状态快照必须携带同一条统计"
        );
    }

    /// 回归：首次 Connected 已送达 UI 后，后续来自 engine 的统计样本必须主动更新
    /// WatchEvents；此前仅写 `stats_current`，导致真实客户端一直显示 `—`。
    #[tokio::test]
    async fn event_bus_stats_sample_republishes_connected_snapshot_to_watchers() {
        let bus = EventBus::new();
        bus.publish(
            wire::RuntimeEventKind::Transition,
            snapshot_for_phase(HostPhase::Connected, &plain_composition()),
        );
        let mut watcher = bus.subscribe(1);
        let stats = RuntimeStats {
            rx_bytes: 8192,
            tx_bytes: 4096,
            rx_rate_bps: 2048,
            tx_rate_bps: 1024,
            latency_ms: 0,
            phase: wire::StatsPhase::Connected,
            engine_sequence: 2,
            sample_tick: 0,
        };

        let published = bus.publish_stats(stats);
        assert_eq!(published.sample_tick, 2);
        let event = tokio::time::timeout(Duration::from_millis(100), watcher.next())
            .await
            .expect("统计更新必须唤醒 status watcher")
            .expect("统计 status event");
        assert_eq!(event.monotonic_tick, 2);
        assert_eq!(
            event.snapshot.and_then(|snapshot| snapshot.stats),
            Some(runtime_stats_to_wire(published)),
            "WatchEvents 必须携带刚发布的 engine 统计"
        );
    }

    /// P5-b 共存：wire 事件 lane（P3-c1）与统计 lane 在同一总线互不干扰——统计发布
    /// 不改变 `current_snapshot`/tick，事件发布不改变 `current_stats`。
    #[test]
    fn event_bus_stats_lane_coexists_with_wire_events() {
        let bus = EventBus::new();
        let stats = RuntimeStats {
            rx_bytes: 0,
            tx_bytes: 0,
            rx_rate_bps: 0,
            tx_rate_bps: 0,
            latency_ms: 0,
            phase: wire::StatsPhase::Idle,
            engine_sequence: 1,
            sample_tick: 0,
        };
        bus.publish_stats(stats);
        assert_eq!(bus.current_tick(), 0, "统计不铸造事件 tick");
        assert_eq!(bus.current_snapshot(), None, "统计不改变事件快照");

        bus.publish(
            wire::RuntimeEventKind::Transition,
            snapshot_for_phase(HostPhase::Connected, &plain_composition()),
        );
        assert_eq!(bus.current_tick(), 1);
        assert_eq!(bus.current_stats(), Some(stats), "事件不改变统计");

        // WatchEvents wire 订阅只收事件（统计 lane 独立）。
        let current = bus.current_snapshot().expect("snapshot");
        assert!(matches!(
            current.state,
            Some(wire::runtime_snapshot::State::Connected(_))
        ));
    }

    /// P5-b `subscribe_stats`：resume=0 先发当前统计，随后转发更新；sample_tick 过滤。
    #[tokio::test]
    async fn subscribe_stats_resumes_current_then_live() {
        use tokio_stream::StreamExt;

        let bus = EventBus::new();
        let stats = RuntimeStats {
            rx_bytes: 100,
            tx_bytes: 50,
            rx_rate_bps: 0,
            tx_rate_bps: 0,
            latency_ms: 0,
            phase: wire::StatsPhase::Connected,
            engine_sequence: 1,
            sample_tick: 0,
        };
        bus.publish_stats(stats);

        let mut stream = bus.subscribe_stats(0);
        let replay = stream.next().await.expect("replay current stats");
        assert_eq!(replay.rx_bytes, 100);

        // 发布更新：已连接快照存在时，统计本身铸造下一事件 tick，并用该 tick 重发状态。
        bus.publish(
            wire::RuntimeEventKind::Transition,
            snapshot_for_phase(HostPhase::Connected, &plain_composition()),
        );
        let updated = RuntimeStats {
            rx_bytes: 300,
            ..stats
        };
        bus.publish_stats(updated);
        let live = stream.next().await.expect("live stats");
        assert_eq!(live.rx_bytes, 300);
        assert_eq!(live.sample_tick, 2, "更新统计与其重发的状态快照使用同一 tick");
    }

    /// P5-b 统计转发器：注入 fake engine 统计源 → 逐 `StatsEvent` 归一化（累计增量
    /// 权威速度）→ `publish_stats` 发布；EOF（drop 源）→ 断线退避（forwarder 不退出，
    /// 测试 abort）。
    #[tokio::test]
    async fn stats_forwarder_normalizes_and_publishes_to_bus() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<wire::StatsEvent>();
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        engine.lock().await.stats.lock().unwrap().replace(rx);
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();
        let handle = service.spawn_stats_forwarder();

        // 首条样本（累计 rx=1000, t=1000）：速率 0（无参照），累计透传。
        tx.send(wire::StatsEvent {
            sequence: 1,
            timestamp_ms: 1000,
            phase: wire::StatsPhase::Connected as i32,
            rx_bytes: 1000,
            tx_bytes: 500,
            rx_rate: 0,
            tx_rate: 0,
            latency_ms: 7,
        })
        .unwrap();
        wait_stats(&bus, |s| s.engine_sequence == 1).await;
        let first = bus.current_stats().expect("first stats");
        assert_eq!(first.rx_bytes, 1000);
        assert_eq!(first.tx_bytes, 500);
        assert_eq!(first.latency_ms, 7);
        assert_eq!(first.phase, wire::StatsPhase::Connected);
        assert_eq!(first.rx_rate_bps, 0, "首条样本速率 0");

        // 第二条样本（累计 rx=3000, t=2000 → delta 2000/1000ms = 2000 B/s）。
        // engine convenience rx_rate 喂错误值也必须被 core 归一化覆盖。
        tx.send(wire::StatsEvent {
            sequence: 2,
            timestamp_ms: 2000,
            phase: wire::StatsPhase::Connected as i32,
            rx_bytes: 3000,
            tx_bytes: 1500,
            rx_rate: 999_999,
            tx_rate: 0,
            latency_ms: 8,
        })
        .unwrap();
        wait_stats(&bus, |s| s.engine_sequence == 2).await;
        let second = bus.current_stats().expect("second stats");
        assert_eq!(second.rx_rate_bps, 2000, "core 权威增量归一化");
        assert_eq!(second.tx_rate_bps, 1000, "delta 1000 / 1000ms");
        assert_eq!(second.latency_ms, 8);

        // 统计 lane 与 wire 事件 lane 共存：转发器只发统计，事件快照保持初始。
        // （engine 事件转发器未拉起，bus 无事件发布——统计不影响事件侧。）
        assert_eq!(bus.current_tick(), 0, "统计转发器不铸造事件 tick");

        drop(tx);
        handle.abort();
    }

    /// 服务路由会把 `EngineSlot` 从初始 oneshot engine 切换为 service engine。统计
    /// 转发器必须像 status 转发器一样立刻放弃旧流，重新订阅新 engine；否则 UI 虽然能
    /// 收到 Connected，却永远拿不到真实速率、累计量和由此附带的在线指标。
    #[tokio::test]
    async fn stats_forwarder_resubscribes_after_engine_slot_swap() {
        let (old_tx, old_rx) = tokio::sync::mpsc::unbounded_channel::<wire::StatsEvent>();
        let old_engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        old_engine.lock().await.stats.lock().unwrap().replace(old_rx);
        let (service, _logs_dir) = service_with(&old_engine);
        let bus = service.events();
        let handle = service.spawn_stats_forwarder();

        // 先确认 forwarder 的确已占用旧 engine 流；只有这样 swap 才能复现 service
        // 路由中的真实断点，而不是碰巧在首次订阅前就读取了新槽。
        old_tx
            .send(wire::StatsEvent {
                sequence: 1,
                timestamp_ms: 1_000,
                phase: wire::StatsPhase::Connected as i32,
                rx_bytes: 100,
                tx_bytes: 50,
                rx_rate: 0,
                tx_rate: 0,
                latency_ms: 0,
            })
            .unwrap();
        wait_stats(&bus, |stats| stats.engine_sequence == 1).await;

        let (replacement_tx, replacement_rx) =
            tokio::sync::mpsc::unbounded_channel::<wire::StatsEvent>();
        let replacement = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        replacement
            .lock()
            .await
            .stats
            .lock()
            .unwrap()
            .replace(replacement_rx);
        let replacement_dyn: Arc<tokio::sync::Mutex<dyn KernelEngineControl>> = replacement;
        assert!(service.engine.swap(replacement_dyn).await, "route must replace engine slot");

        replacement_tx
            .send(wire::StatsEvent {
                sequence: 9,
                timestamp_ms: 2_000,
                phase: wire::StatsPhase::Connected as i32,
                rx_bytes: 900,
                tx_bytes: 450,
                rx_rate: 0,
                tx_rate: 0,
                latency_ms: 0,
            })
            .unwrap();
        wait_stats(&bus, |stats| stats.engine_sequence == 9).await;
        assert_eq!(bus.current_stats().expect("replacement stats").rx_bytes, 900);

        drop(old_tx);
        drop(replacement_tx);
        handle.abort();
    }

    /// 共存集成：engine 状态转发器（R1）与统计转发器（P5-b）同时驱动同一总线，
    /// 状态归一化与统计归一化互不干扰——状态发布带快照、统计发布带归一化速度。
    #[tokio::test]
    async fn status_and_stats_forwarders_coexist_on_bus() {
        let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        let (stats_tx, stats_rx) = tokio::sync::mpsc::unbounded_channel::<wire::StatsEvent>();
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        {
            let mut guard = engine.lock().await;
            guard.events.lock().unwrap().replace(status_rx);
            guard.stats.lock().unwrap().replace(stats_rx);
        }
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();
        let status_handle = service.spawn_status_forwarder();
        let stats_handle = service.spawn_stats_forwarder();

        // 状态侧：Connected → Connected 过渡快照（engine 状态流驱动）。
        status_tx
            .send(EngineStatusEvent::Connected {
                operation_id: uuid16(3),
                session_established_at_ms: Some(1_700_000_000_123),
        })
            .unwrap();
        wait_snapshot_state(&bus, "connected").await;
        assert!(matches!(
            bus.current_snapshot()
                .and_then(|snapshot| snapshot.state),
            Some(wire::runtime_snapshot::State::Connected(connected))
                if connected.session_established_at_ms == 1_700_000_000_123
        ));

        // 统计侧：累计增量 → 归一化速率发布。
        stats_tx
            .send(wire::StatsEvent {
                sequence: 1,
                timestamp_ms: 1000,
                phase: wire::StatsPhase::Connected as i32,
                rx_bytes: 1000,
                tx_bytes: 0,
                rx_rate: 0,
                tx_rate: 0,
                latency_ms: 5,
            })
            .unwrap();
        wait_stats(&bus, |s| s.engine_sequence == 1).await;
        stats_tx
            .send(wire::StatsEvent {
                sequence: 2,
                timestamp_ms: 2000,
                phase: wire::StatsPhase::Connected as i32,
                rx_bytes: 5000,
                tx_bytes: 0,
                rx_rate: 0,
                tx_rate: 0,
                latency_ms: 5,
            })
            .unwrap();
        wait_stats(&bus, |s| s.engine_sequence == 2).await;

        // 事件快照仍为 Connected（统计不干扰状态侧），统计速率正确（互不干扰）。
        assert!(matches!(
            bus.current_snapshot().map(|s| s.state),
            Some(Some(wire::runtime_snapshot::State::Connected(_)))
        ));
        let stats = bus.current_stats().expect("normalized stats");
        assert_eq!(stats.rx_rate_bps, 4000, "delta 4000 / 1000ms");
        assert_eq!(stats.phase, wire::StatsPhase::Connected);

        drop(status_tx);
        drop(stats_tx);
        status_handle.abort();
        stats_handle.abort();
    }

    /// 轮询总线直到统计到达期望判别（统计转发器测试的收敛等待）。
    async fn wait_stats(bus: &Arc<EventBus>, pred: impl Fn(&RuntimeStats) -> bool) {
        use std::time::Duration;
        for _ in 0..200 {
            if let Some(stats) = bus.current_stats() {
                if pred(&stats) {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("bus never reached expected stats");
    }

    /// engine 状态转发器（R1）：Progress → Connecting（携带细粒度 phase）；Connected
    /// 事件（engine 状态流）→ Connected 过渡快照；状态流 EOF（断线）→ Reconciling 过渡。
    #[tokio::test]
    async fn status_forwarder_drives_connect_and_publishes_to_bus() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        engine.lock().await.events.lock().unwrap().replace(rx);
        // 经 `from_composition` 构造以持有 composition Arc：先 bind + Connect 进
        // Connecting（镜像 connect 写路径），再拉起转发器。
        let mut composition = plain_composition();
        composition
            .kernel_gate()
            .authorize(&helper())
            .expect("authorize");
        let (peer, cap) = controller_peer_and_capability();
        composition.bind_controller(peer, cap);
        composition.set_operation_id(uuid16_bytes(3));
        let _ = composition.apply(HostEvent::Connect);
        let engine_dyn: Arc<tokio::sync::Mutex<dyn KernelEngineControl>> = engine.clone();
        let logs_dir = tempfile::tempdir().expect("logs tempdir");
        let logs =
            Arc::new(LogAggregator::open(&logs_dir.path().join("svc.jsonl")).expect("open logs"));
        let (composition_arc, service) = KernelControlService::from_composition(
            composition,
            EngineSlot::new(engine_dyn),
            PathBuf::new(),
            logs,
        );
        let _ = composition_arc;
        let bus = service.events();
        let handle = service.spawn_status_forwarder();

        // Progress(ApplyingPlatformTunnel) → 阶段推进（Connecting，携带细粒度 phase）。
        tx.send(EngineStatusEvent::Progress {
            operation_id: uuid16(3),
            connect_phase: wire::ConnectPhase::ApplyingPlatformTunnel,
        })
        .unwrap();
        wait_snapshot_connecting_phase(&bus, wire::ConnectPhase::ApplyingPlatformTunnel).await;

        // Connected（真实 Connected 驱动）→ Connected 过渡快照。
        tx.send(EngineStatusEvent::Connected {
            operation_id: uuid16(3),
            session_established_at_ms: Some(1_700_000_000_123),
        })
        .unwrap();
        wait_snapshot_state(&bus, "connected").await;

        // 状态流 EOF（drop tx）→ 断线过渡（Reconciling）。
        drop(tx);
        wait_snapshot_state(&bus, "reconciling").await;

        handle.abort();
    }

    /// D5 订阅保活（engine 持久化生命周期，P1）：host 状态转发器**单例**持有 engine
    /// 状态流 + engine **常驻** → 状态订阅**跨 connect/stop 保持**——不 EOF、不重连、
    /// `status_ready` 保持 `true`；attach-before-apply 热启动路径由此天然满足
    /// （connect/stop 写路径不重建订阅）。订阅只被真实 engine 断线（EOF）拆除——
    /// 对照断言：业务 connect/stop 不动订阅，EOF 才撤销就绪 + 触发重连。
    #[tokio::test]
    async fn status_subscription_survives_connect_stop() {
        use std::time::Duration;
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.pending_apply.lock().unwrap() = true;
        let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        engine
            .lock()
            .await
            .events
            .lock()
            .unwrap()
            .replace(status_rx);
        let dir = seeded_config_dir("s3cret");
        let (service, _logs_dir) = service_with_config(&engine, dir.path().to_path_buf());
        let bus = service.events();
        let handle = service.spawn_status_forwarder();

        // attach-before-apply：转发器挂接 status 流后 status_ready = true（保持）。
        let mut ready = service.status_ready();
        for _ in 0..200 {
            if *ready.borrow() {
                break;
            }
            if ready.changed().await.is_err() {
                break;
            }
        }
        assert!(*ready.borrow(), "forwarder attached → status_ready true");

        // ---- connect：写路径派发 apply → status 流推 Progress + Connected。 ----
        let intent = connect_intent();
        let reply = service
            .connect(Request::new(ConnectRequest {
                intent: Some(intent.clone()),
                secret_payload: vec![],
            }))
            .await
            .expect("connect dispatched");
        assert!(reply.into_inner().terminal.is_none(), "connect is pending");
        let op = intent.lookup_key.as_ref().unwrap().operation_id.clone();
        status_tx
            .send(EngineStatusEvent::Progress {
                operation_id: op.clone(),
                connect_phase: wire::ConnectPhase::ApplyingPlatformTunnel,
            })
            .unwrap();
        status_tx
            .send(EngineStatusEvent::Connected {
                operation_id: op,
                session_established_at_ms: Some(1_700_000_000_123),
            })
            .unwrap();
        wait_snapshot_state(&bus, "connected").await;

        // 订阅保持：connect 后 status_ready 仍 true + 转发器未结束（单例，无重连）。
        assert!(
            *ready.borrow(),
            "after connect: subscription still attached (status_ready true)"
        );
        assert!(
            !handle.is_finished(),
            "after connect: forwarder alive (singleton, no reconnect)"
        );

        // ---- stop：业务停机（engine 常驻，订阅保持）。 ----
        let stop_intent = stop_intent();
        service
            .stop(Request::new(StopRequest {
                intent: Some(stop_intent.clone()),
            }))
            .await
            .expect("stop dispatched");
        let stop_op = stop_intent
            .lookup_key
            .as_ref()
            .unwrap()
            .operation_id
            .clone();
        status_tx
            .send(EngineStatusEvent::Stopped {
                operation_id: stop_op,
            })
            .unwrap();
        // 收敛：engine 数据面侧加入 → Stopped（快照先可观测）→ controller 显式
        // ReopenAdmission → Idle + admission_open（S1：停机收敛后同进程可重连）。
        for _ in 0..200 {
            let guard = service.composition.lock().await;
            if guard.phase() == HostPhase::Idle && guard.admission_open() {
                break;
            }
            drop(guard);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        {
            let guard = service.composition.lock().await;
            assert_eq!(
                guard.phase(),
                HostPhase::Idle,
                "stop must converge to Idle (ReopenAdmission after Stopped)"
            );
            assert!(
                guard.admission_open(),
                "admission must reopen after stop convergence (S1)"
            );
        }

        // 订阅保持：stop 后 status_ready 仍 true + 转发器未结束。
        assert!(
            *ready.borrow(),
            "after stop: subscription still attached (status_ready true)"
        );
        assert!(
            !handle.is_finished(),
            "after stop: forwarder alive (engine resident, subscription held)"
        );

        // ---- 对照：只有真实 engine 断线（EOF）才拆除订阅——撤销就绪 + 重连。 ----
        drop(status_tx);
        for _ in 0..200 {
            if !*ready.borrow() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            !*ready.borrow(),
            "EOF (engine disconnect) → status_ready revoked (subscription torn down only by EOF, not by connect/stop)"
        );

        handle.abort();
    }

    /// `runtime_event_from_status` 归一化：Progress → Connecting（记录细粒度 phase）；
    /// Failed → FailedDirty（带 err 上状态机）；Stopped → 数据面加入屏障。
    #[tokio::test]
    async fn runtime_event_mapping_covers_progress_failed_stopped() {
        let composition = Arc::new(tokio::sync::Mutex::new(plain_composition()));
        // 模拟 connect 受理：绑定 controller（actor 需 peer+capability 才 admitted）+
        // 进 Connecting（镜像 connect 写路径）。
        {
            let mut guard = composition.lock().await;
            let (peer, cap) = controller_peer_and_capability();
            guard.bind_controller(peer, cap);
            guard.apply(HostEvent::Connect);
            guard.set_operation_id(uuid16_bytes(3));
        }

        // Progress → Connecting（细粒度 phase 记录到状态机）。
        let (kind, snap) = runtime_event_from_status(
            &EngineStatusEvent::Progress {
                operation_id: uuid16(3),
                connect_phase: wire::ConnectPhase::ApplyingPlatformTunnel,
            },
            &composition,
        )
        .await
        .expect("current-op progress passes filter");
        assert_eq!(kind, wire::RuntimeEventKind::Transition);
        assert!(matches!(
            snap.state,
            Some(wire::runtime_snapshot::State::Connecting(c))
                if c.phase == wire::ConnectPhase::ApplyingPlatformTunnel as i32
        ));
        assert_eq!(composition.lock().await.phase(), HostPhase::Connecting);

        // Failed → FailedDirty（err 上状态机：phase Failed + last_error 记录）。
        let error = wire::VpnError {
            code: 16,
            stage: 8,
            certainty: 0,
            retry: 2,
            subject: None,
            resource: None,
            native: None,
        };
        let (kind, snap) = runtime_event_from_status(
            &EngineStatusEvent::Failed {
                operation_id: uuid16(3),
                error: error.clone(),
            },
            &composition,
        )
        .await
        .expect("current-op failed passes filter");
        assert_eq!(kind, wire::RuntimeEventKind::Transition);
        assert!(matches!(
            snap.state,
            Some(wire::runtime_snapshot::State::FailedDirty(f))
                if f.last_error.as_ref() == Some(&error)
        ));
        {
            use exv_vpn_domain::error::ErrorCode;
            let guard = composition.lock().await;
            assert_eq!(guard.phase(), HostPhase::Failed);
            let last = guard.last_error().expect("error on state machine");
            assert_eq!(last.code(), &ErrorCode::DeadlineExceeded);
        }

        // Stopped（engine 确认 teardown）→ 数据面侧加入屏障 → Stopped。
        let (kind, snap) = runtime_event_from_status(
            &EngineStatusEvent::Stopped {
                operation_id: uuid16(3),
            },
            &composition,
        )
        .await
        .expect("current-op stopped passes filter");
        assert_eq!(kind, wire::RuntimeEventKind::Transition);
        // 此处仅验证 Stopped 事件在 Failed 相（未经 Disconnect）下不 panic 且返回
        // TRANSITION——本段断在 FailedDirty；完整收敛（Disconnect → Stopping →
        // engine Idle → Stopped）由 `stop_converges_to_stopped_on_engine_idle_status`
        // 覆盖。
        assert!(matches!(
            snap.state,
            Some(wire::runtime_snapshot::State::FailedDirty(_))
        ));
    }

    /// Stop：完整 StopIntent（lookup_key/request_digest）→ engine stop_tunnel。
    #[tokio::test]
    async fn stop_assembles_intent_and_dispatches() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        // R1 attach-before-apply：注入状态源 + 拉起转发器（stop await 就绪）。
        let _forwarder = spawn_status_ready(&service, &engine).await;
        let intent = stop_intent();

        let reply = service
            .stop(Request::new(StopRequest {
                intent: Some(intent.clone()),
            }))
            .await
            .expect("stop");
        assert!(reply.into_inner().terminal.is_some());

        let engine_guard = engine.lock().await;
        // Bug D 回归：stop 派发 StopTunnel 前同样确保 owner lease（StopTunnel 经
        // `bind_mutation` 要求 `core.owner`；幂等 ensure——无 prior connect 也满足）。
        assert_eq!(
            *engine_guard.lease_ensures.lock().unwrap(),
            1,
            "stop 必须恰好一次 ensure_owner_lease（stop_tunnel 前置）"
        );
        let stopped = &engine_guard.stops.lock().unwrap();
        assert_eq!(stopped.len(), 1);
        // Bug E 回归：engine-facing 的 lookup_key.method 必须从 Stop 转为 StopTunnel
        // （engine `kernel_request_to_operation` 校验 method == expected_method，不转则
        // "kernel: operation: out of scope"）；runtime_epoch/operation_id 保持 stop 意图。
        let stop_key = stopped[0].lookup_key.as_ref().expect("stop lookup key");
        let intent_key = intent.lookup_key.as_ref().expect("intent lookup key");
        assert_eq!(
            stop_key.method,
            wire::OperationMethod::StopTunnel as i32,
            "engine stop 的 lookup_key.method 必须为 StopTunnel"
        );
        assert_eq!(
            stop_key.runtime_epoch, intent_key.runtime_epoch,
            "stop 保留 stop 意图的 runtime_epoch"
        );
        assert_eq!(
            stop_key.operation_id, intent_key.operation_id,
            "stop 保留 stop 意图的 operation_id"
        );
        assert_eq!(stopped[0].request_digest, intent.request_digest);
    }

    /// R1 Stop 收敛：stop 受理（Disconnect + 控制面侧加入屏障 → Stopping）→ engine
    /// 状态流先发 Idle（数据面侧加入）→ 双侧齐 → Stopped。
    #[tokio::test]
    async fn stop_converges_to_stopped_on_engine_idle_status() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        // 注入状态源：引擎 Idle 事件经状态转发器驱动收敛。
        let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        engine
            .lock()
            .await
            .events
            .lock()
            .unwrap()
            .replace(status_rx);
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();
        let handle = service.spawn_status_forwarder();

        let intent = stop_intent();
        let reply = service
            .stop(Request::new(StopRequest {
                intent: Some(intent.clone()),
            }))
            .await
            .expect("stop");
        assert!(
            reply.into_inner().terminal.is_some(),
            "engine stop reply terminal"
        );

        // engine 状态流 Idle → 数据面侧加入屏障 → Stopped（终态收敛）。
        status_tx
            .send(EngineStatusEvent::Stopped {
                operation_id: intent.lookup_key.as_ref().unwrap().operation_id.clone(),
            })
            .unwrap();
        use std::time::Duration;
        for _ in 0..200 {
            if matches!(
                bus.current_snapshot().map(|s| s.state),
                Some(Some(wire::runtime_snapshot::State::Idle(_)))
            ) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("stop never converged to Stopped/Idle");
    }

    /// S1（D14）：停机收敛后 controller 显式派发 ReopenAdmission——Stopped 快照先可观测
    ///（回落 Idle wire 状态），随后 admission 重开 + phase 回落 Idle，二次 Connect 可受理
    ///（问题 A 闩锁修复）。teardown 拒绝语义保留（仅 Stopped 相位生效，其余 no-op）。
    #[tokio::test]
    async fn stopped_convergence_reopens_admission_for_reconnect() {
        let composition = Arc::new(tokio::sync::Mutex::new(plain_composition()));
        {
            let mut guard = composition.lock().await;
            let (peer, cap) = controller_peer_and_capability();
            guard.bind_controller(peer, cap);
            guard.apply(HostEvent::Connect);
            guard.apply(HostEvent::Disconnect);
            guard.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl));
            assert_eq!(guard.phase(), HostPhase::Stopping);
        }

        // engine 确认 teardown（Stopped）→ 数据面侧加入 → Stopped → 显式重开 admission。
        let (kind, snap) = runtime_event_from_status(
            &EngineStatusEvent::Stopped {
                operation_id: Vec::new(),
            },
            &composition,
        )
        .await
        .expect("stopped converges");
        assert_eq!(kind, wire::RuntimeEventKind::Transition);
        assert!(
            matches!(snap.state, Some(wire::runtime_snapshot::State::Idle(_))),
            "Stopped 快照先可观测（回落 Idle wire 状态）"
        );
        let guard = composition.lock().await;
        assert_eq!(
            guard.phase(),
            HostPhase::Idle,
            "ReopenAdmission 使 phase 回落 Idle"
        );
        assert!(guard.admission_open(), "停机收敛后 admission 重开");
    }

    /// S1.5 (D13) Paused 减负断开映射：engine 减负断开（session 结束 + 路由清 +
    /// NIC 保留 adapter）经既有 Idle → Stopped 映射收敛——host Stopped 相位保留
    /// fine-phase（连接阶段寄存器），ReopenAdmission → Idle 清 fine-phase + 重开
    /// admission（同进程可重连）。冻结 portable `HostComposition` 不动（Paused 是
    /// engine 运行时状态，host 只以 Stopped + fine-phase 映射）。
    #[tokio::test]
    async fn paused_disconnect_maps_to_stopped_then_idle_with_fine_phase() {
        let composition = Arc::new(tokio::sync::Mutex::new(plain_composition()));
        {
            let mut guard = composition.lock().await;
            let (peer, cap) = controller_peer_and_capability();
            guard.bind_controller(peer, cap);
            // 连接 → Connected（fine-phase = StartingDataPlane）。
            guard.apply(HostEvent::Connect);
            guard.apply(HostEvent::ProtocolEstablished);
            assert_eq!(guard.phase(), HostPhase::Connected);
            assert_eq!(
                guard.connect_phase(),
                Some(exv_vpn_domain::model::ConnectPhase::StartingDataPlane),
                "Connected 的 fine-phase = StartingDataPlane"
            );
            // 用户 stop → host 侧 Disconnect + ProtocolControl 加入 → Stopping。
            guard.apply(HostEvent::Disconnect);
            guard.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl));
            assert_eq!(guard.phase(), HostPhase::Stopping);
        }

        // engine 减负断开（Paused）→ 既有 Idle → Stopped 映射：数据面侧加入 → Stopped
        // → 显式 ReopenAdmission（S1 路径）→ Idle。
        let (kind, snap) = runtime_event_from_status(
            &EngineStatusEvent::Stopped {
                operation_id: uuid16(7),
            },
            &composition,
        )
        .await
        .expect("paused disconnect converges");
        assert_eq!(kind, wire::RuntimeEventKind::Transition);
        assert!(
            matches!(snap.state, Some(wire::runtime_snapshot::State::Idle(_))),
            "Stopped 快照先可观测（回落 Idle wire 状态；D13 Paused → Stopped 映射）"
        );
        let guard = composition.lock().await;
        // ReopenAdmission 已在 runtime_event_from_status 的 Stopped 臂内派发：
        // phase 回落 Idle + admission 重开 + fine-phase 清空（下次连接从零开始）。
        assert_eq!(
            guard.phase(),
            HostPhase::Idle,
            "D13 Paused 减负断开 → Stopped → Idle（可重连）"
        );
        assert!(guard.admission_open(), "admission 重开（同进程重连可受理）");
        assert_eq!(
            guard.connect_phase(),
            None,
            "Idle 清 fine-phase（重连从零开始）"
        );
    }

    /// R2 收敛双保险：`disconnected_snapshot` 不把已收敛的终态（Idle / Stopped /
    /// Failed）回归成 Reconciling——engine 状态流 EOF 只表示 engine 侧掉线，不代表
    /// 业务回退；仅非终态（Stopping 等连接在途）才以 Reconciling 表示待恢复。
    #[test]
    fn disconnected_snapshot_preserves_terminal_phases() {
        use wire::runtime_snapshot::State;

        // 从未连接（Idle）：断线快照保持 Idle（不回归 Reconciling）。
        let mut comp = plain_composition();
        assert_eq!(comp.phase(), HostPhase::Idle);
        assert!(
            matches!(disconnected_snapshot(&comp).state, Some(State::Idle(_))),
            "Idle 终态不得被断线回归成 Reconciling"
        );

        // 停机收敛中（Stopping，host 控制面侧已加入、数据面侧未加入）：非终态 →
        // Reconciling（连接在途、engine 提前离开）。
        comp.apply(HostEvent::Disconnect);
        comp.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl));
        assert_eq!(comp.phase(), HostPhase::Stopping);
        assert!(
            matches!(
                disconnected_snapshot(&comp).state,
                Some(State::Reconciling(_))
            ),
            "Stopping 在途 → Reconciling 表示待恢复"
        );

        // 收敛完成（数据面侧由 core 合成加入 → Stopped）：断线快照回落 Idle 终态
        //（不回归 Reconciling——断开->收敛->Idle 判据）。
        comp.synthesize_data_plane_join();
        assert_eq!(comp.phase(), HostPhase::Stopped);
        assert!(
            matches!(disconnected_snapshot(&comp).state, Some(State::Idle(_))),
            "Stopped 终态不得被断线回归成 Reconciling"
        );
    }

    /// R2 收敛双保险（P3-2/P3-3 消化）：用户 stop 后 engine 侧 Idle 终态事件随断线
    /// 丢失（状态流 EOF 先于/替代 Idle 到达）→ 状态转发器在 EOF 处合成数据面侧加入
    /// → 双侧齐 → 收敛 Stopped/Idle（不卡 Reconciling）。
    #[tokio::test]
    async fn status_forwarder_eof_synthesizes_convergence_when_stop_in_flight() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        // 注入状态源；故意**不**发 Idle 就 drop（模拟 engine 的 Idle 终态随断线丢失）。
        let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        engine
            .lock()
            .await
            .events
            .lock()
            .unwrap()
            .replace(status_rx);
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();
        let handle = service.spawn_status_forwarder();

        // 用户 stop → host 侧 Disconnect + ProtocolControl 加入 → Stopping。
        let intent = stop_intent();
        let reply = service
            .stop(Request::new(StopRequest {
                intent: Some(intent.clone()),
            }))
            .await
            .expect("stop");
        assert!(
            reply.into_inner().terminal.is_some(),
            "engine stop reply terminal"
        );

        // engine 状态流 EOF（drop 发送端 = 断线；engine 未及发 Idle）→ 转发器合成
        // 数据面侧加入 → 收敛 Stopped/Idle。
        drop(status_tx);
        use std::time::Duration;
        for _ in 0..200 {
            if matches!(
                bus.current_snapshot().map(|s| s.state),
                Some(Some(wire::runtime_snapshot::State::Idle(_)))
            ) {
                // 收敛确认：composition 相位必须是 Stopped（终态），不是 Stopping。
                assert_eq!(
                    service.composition.lock().await.phase(),
                    HostPhase::Stopped,
                    "EOF 合成必须把 Stopping 收敛到 Stopped 终态"
                );
                handle.abort();
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        handle.abort();
        panic!("engine EOF did not synthesize convergence to Stopped/Idle");
    }

    /// R2 收敛双保险：engine 状态流 EOF 不把已 Failed 的终态回归成 Reconciling
    ///（FailedDirty 携带结构化 err，断线不丢错误上下文）。
    #[tokio::test]
    async fn status_forwarder_eof_keeps_failed_terminal() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.pending_apply.lock().unwrap() = true;
        let (status_tx, status_rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        engine
            .lock()
            .await
            .events
            .lock()
            .unwrap()
            .replace(status_rx);
        let dir = seeded_config_dir("s3cret");
        let (service, _logs_dir) = service_with_config(&engine, dir.path().to_path_buf());
        let bus = service.events();
        let handle = service.spawn_status_forwarder();

        // connect 受理 → engine Failed 终态 → composition Failed（FailedDirty）。
        let intent = connect_intent();
        let reply = service
            .connect(Request::new(ConnectRequest {
                intent: Some(intent.clone()),
                secret_payload: vec![],
            }))
            .await
            .expect("connect");
        assert!(reply.into_inner().terminal.is_none(), "connect is pending");
        let operation_id = intent.lookup_key.as_ref().unwrap().operation_id.clone();
        status_tx
            .send(EngineStatusEvent::Failed {
                operation_id: operation_id.clone(),
                error: wire::VpnError {
                    code: 1,
                    stage: 8,
                    certainty: 0,
                    retry: 1,
                    subject: None,
                    resource: None,
                    native: None,
                },
            })
            .unwrap();
        use std::time::Duration;
        for _ in 0..200 {
            if matches!(
                bus.current_snapshot().map(|s| s.state),
                Some(Some(wire::runtime_snapshot::State::FailedDirty(_)))
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // engine 断线（EOF）：Failed 是终态 → 快照保持 FailedDirty，不回归 Reconciling。
        drop(status_tx);
        for _ in 0..200 {
            if matches!(
                bus.current_snapshot().map(|s| s.state),
                Some(Some(wire::runtime_snapshot::State::FailedDirty(_)))
            ) {
                handle.abort();
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        handle.abort();
        panic!("EOF regressed Failed terminal away from FailedDirty");
    }

    /// Stop：非法意图（method 不匹配 / digest 长度错）→ fail closed，engine 不被调用。
    #[tokio::test]
    async fn stop_invalid_intent_rejected() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);

        // digest 长度非法。
        let mut bad_digest = stop_intent();
        bad_digest.request_digest = vec![0u8; 16];
        let err = service
            .stop(Request::new(StopRequest {
                intent: Some(bad_digest),
            }))
            .await
            .expect_err("invalid digest");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        // method 不匹配（CONNECT 而非 STOP）。
        let mut bad_method = stop_intent();
        bad_method.lookup_key.as_mut().expect("key").method = wire::OperationMethod::Connect as i32;
        let err = service
            .stop(Request::new(StopRequest {
                intent: Some(bad_method),
            }))
            .await
            .expect_err("wrong method");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        assert!(
            engine.lock().await.stops.lock().unwrap().is_empty(),
            "engine must not be called on invalid intent"
        );
    }

    /// Reconcile：完整意图组装（lookup_key + request_digest 校验）→ engine get_operation。
    #[tokio::test]
    async fn reconcile_assembles_intent_and_dispatches() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);

        let key = wire::OperationLookupKey {
            principal_digest: vec![0xAA; 32],
            method: wire::OperationMethod::Reconcile as i32,
            runtime_epoch: vec![0u8; 16],
            operation_id: vec![0u8; 16],
        };
        let digest = vec![0xDD; 32];

        let reply = service
            .reconcile(Request::new(ReconcileRequest {
                key: Some(key.clone()),
                request_digest: digest.clone(),
            }))
            .await
            .expect("reconcile");
        assert!(
            reply.into_inner().terminal.is_none(),
            "observed disposition is non-terminal"
        );

        let engine_guard = engine.lock().await;
        let ops = &engine_guard.ops.lock().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].lookup_key, Some(key));
    }

    /// Reconcile 意图组装：method 必须为 RECONCILE、digest 必须 32 字节。
    #[test]
    fn reconcile_intent_from_wire_validates_method_and_digest() {
        let key = wire::OperationLookupKey {
            principal_digest: vec![0xAA; 32],
            method: wire::OperationMethod::Reconcile as i32,
            runtime_epoch: vec![0u8; 16],
            operation_id: vec![0u8; 16],
        };
        assert!(ReconcileIntent::from_wire(key.clone(), vec![0xDD; 32]).is_ok());

        let mut wrong_method = key.clone();
        wrong_method.method = wire::OperationMethod::Connect as i32;
        assert!(ReconcileIntent::from_wire(wrong_method, vec![0xDD; 32]).is_err());

        assert!(ReconcileIntent::from_wire(key, vec![0u8; 16]).is_err());
    }

    /// CIDR 解析：合法 → network+prefix；非法 → None。
    #[test]
    fn parse_cidr_handles_valid_and_invalid() {
        assert_eq!(
            parse_cidr("202.120.80.0/20"),
            Some((vec![202, 120, 80, 0], 20))
        );
        assert_eq!(parse_cidr("10.0.0.0/8"), Some((vec![10, 0, 0, 0], 8)));
        assert_eq!(parse_cidr("bad"), None);
        assert_eq!(parse_cidr("1.2.3.4/33"), None);
        assert_eq!(parse_cidr("1.2.3.256/8"), None);
    }

    // -----------------------------------------------------------------------
    // P3-c1：gate 授权路径、GetSnapshot 源化、RespondInteraction、GetOperation、
    // Reconcile 重试
    // -----------------------------------------------------------------------

    /// `authorize_transport_peer`（P3-c1）：transport peer 认证路径驱动 gate 授权——
    /// 未授权时写 RPC fail closed；授权后写 RPC 通过。
    #[tokio::test]
    async fn authorize_transport_peer_drives_gate() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let logs_dir = tempfile::tempdir().expect("logs tempdir");
        let logs =
            Arc::new(LogAggregator::open(&logs_dir.path().join("g.jsonl")).expect("open logs"));
        let (shared, service) = KernelControlService::from_composition(
            plain_composition(),
            EngineSlot::new(engine),
            PathBuf::new(),
            logs,
        );
        let _ = shared;

        // 未授权 → connect fail closed（unauthenticated）。
        let err = service
            .connect(Request::new(ConnectRequest::default()))
            .await
            .expect_err("must be refused");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        // 授权路径：host 侧核对已验 peer 身份后授权 gate。
        service
            .authorize_transport_peer(&helper())
            .await
            .expect("peer authorized");

        // 授权后：非法意图仍被校验拒绝（invalid_argument，证明已过 gate 到达语义层）。
        let err = service
            .connect(Request::new(ConnectRequest::default()))
            .await
            .expect_err("invalid intent after auth");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// `authorize_transport_peer` 拒绝无身份事实的 peer（pid/SID/account 缺失）。
    #[tokio::test]
    async fn authorize_transport_peer_refuses_identityless_peer() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let bogus = VerifiedPipePeer {
            process_id: 0,
            user_sid: String::new(),
            logon_sid: None,
            account_name: String::new(),
        };
        let err = service
            .authorize_transport_peer(&bogus)
            .await
            .expect_err("refused");
        assert_eq!(*err.code(), exv_vpn_domain::error::ErrorCode::Unauthorized);
    }

    /// GetSnapshot 源化（P3-c1）：engine `ObserveOwnedState` 返回真实快照（Connected）
    /// → GetSnapshot 返回 engine 快照，而非 composition 的 Idle 占位。
    #[tokio::test]
    async fn get_snapshot_sources_from_engine_owned_state() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        // 注入 engine 快照：Connected（真实数据，含 composition 无关的 attempt）。
        let engine_snapshot = wire::RuntimeSnapshot {
            state: Some(wire::runtime_snapshot::State::Connected(
                wire::ConnectedState {
                    session: Some(wire::ConnectedSession {
                        attempt: Some(wire::Attempt {
                            runtime_epoch: vec![0xEE; 16],
                            attempt_id: vec![0xEE; 16],
                            intent: None,
                            prior_error: None,
                        }),
                        protocol_session: None,
                        platform_ownership: None,
                        packet_lease: None,
                        platform_ready: None,
                        data_running: None,
                    }),
                    session_established_at_ms: 0,
                },
            )),
            // GetSnapshot 源化测试不关心统计/proxy_tun/operation_id；最终响应由
            // `snapshot_with_stats` / `snapshot_with_proxy_tun` 附加。
            stats: None,
            proxy_tun: None,
        // EXV_UNFREEZE 2026-08-24：系统代理感知状态（设计 §5.5），由感知链路附加；占位 None。
        system_proxy: None,
        // EXV_UNFREEZE 2026-08-25：自动重连状态占位（测试字面量）。
        reconnect: None,
            operation_id: Vec::new(),
            service_status: None,
            mode: String::new(),
        };
        engine
            .lock()
            .await
            .owned_state
            .lock()
            .unwrap()
            .replace(engine_snapshot.clone());
        let (service, _logs_dir) = service_with(&engine);

        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        // 必须来自 engine（Connected），composition 初始 Idle 不覆盖。
        let wire::runtime_snapshot::State::Connected(connected) = snap.state.expect("state") else {
            panic!("expected engine-connected snapshot");
        };
        let attempt = connected
            .session
            .expect("session")
            .attempt
            .expect("attempt");
        assert_eq!(attempt.runtime_epoch, vec![0xEE; 16]);
    }

    /// GetSnapshot 回落（P3-c1）：engine 返回 Idle 占位（无真实数据）+ composition 也
    /// Idle → 返回 Idle（engine 源优先）。
    #[tokio::test]
    async fn get_snapshot_falls_back_when_engine_has_only_idle_placeholder() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);

        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        assert!(matches!(
            snap.state,
            Some(wire::runtime_snapshot::State::Idle(_))
        ));
    }

    /// `prefer_snapshot` 源选择：engine Connected + composition Idle → engine；
    /// engine Idle 占位 + composition 非 Idle → composition（host 更新知识）。
    #[test]
    fn prefer_snapshot_selects_the_freshest_source() {
        let composition = plain_composition();
        let engine_connected = snapshot_for_phase(HostPhase::Connected, &composition);
        let idle = snapshot_for_phase(HostPhase::Idle, &composition);

        // engine 有真实数据 → engine。
        assert!(matches!(
            prefer_snapshot(Some(engine_connected.clone()), idle.clone()).state,
            Some(wire::runtime_snapshot::State::Connected(_))
        ));
        // engine Idle 占位 + composition 非 Idle → composition。
        assert!(matches!(
            prefer_snapshot(Some(idle.clone()), engine_connected.clone()).state,
            Some(wire::runtime_snapshot::State::Connected(_))
        ));
        // engine 缺失（掉线）→ composition。
        assert!(matches!(
            prefer_snapshot(None, idle.clone()).state,
            Some(wire::runtime_snapshot::State::Idle(_))
        ));
    }

    /// RespondInteraction（P3-c1）：校验通过后经 seam 转发 engine；engine 冻结 wire
    /// 无 interaction RPC → 真实实现 typed `Unimplemented`（fake 观测转发语义）。
    #[tokio::test]
    async fn respond_interaction_validates_and_forwards() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);

        let response = wire::InteractionResponse {
            interaction_id: vec![0x11; 16],
            runtime_epoch: vec![0x22; 16],
            response_payload: b"answer".to_vec(),
        };
        let reply = service
            .respond_interaction(Request::new(response.clone()))
            .await
            .expect("forwarded");
        assert!(
            reply.into_inner().terminal.is_none(),
            "fake returns pending"
        );

        // fake 观测到转发（engine seam 收到应答）。
        let received = engine.lock().await.interactions.lock().unwrap().clone();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].interaction_id, vec![0x11; 16]);
        assert_eq!(received[0].response_payload, b"answer");
    }

    /// RespondInteraction：非法字段（interaction_id/runtime_epoch 长度错）→
    /// fail closed，engine 不被调用。
    #[tokio::test]
    async fn respond_interaction_invalid_response_rejected() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);

        let bad_id = wire::InteractionResponse {
            interaction_id: vec![0x11; 8],
            runtime_epoch: vec![0x22; 16],
            response_payload: vec![],
        };
        let err = service
            .respond_interaction(Request::new(bad_id))
            .await
            .expect_err("bad interaction id");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        let bad_epoch = wire::InteractionResponse {
            interaction_id: vec![0x11; 16],
            runtime_epoch: vec![0x22; 4],
            response_payload: vec![],
        };
        let err = service
            .respond_interaction(Request::new(bad_epoch))
            .await
            .expect_err("bad runtime epoch");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);

        assert!(
            engine.lock().await.interactions.lock().unwrap().is_empty(),
            "engine must not be called on invalid response"
        );
    }

    /// GetOperation（P3-c1）：路由到 engine GetOperation，操作状态真实透传。
    #[tokio::test]
    async fn get_operation_routes_to_engine() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let key = wire::OperationLookupKey {
            principal_digest: vec![0xAA; 32],
            method: wire::OperationMethod::Connect as i32,
            runtime_epoch: vec![0u8; 16],
            operation_id: vec![0u8; 16],
        };

        let reply = service
            .get_operation(Request::new(wire::GetKernelOperationRequest {
                key: Some(key.clone()),
            }))
            .await
            .expect("get_operation")
            .into_inner();
        // fake 返回 `state: None`（Pending/unknown）——透传（host 不虚构状态）。
        assert!(reply.state.is_none());

        // 路由到 engine：lookup key 原样送达。
        let ops = engine.lock().await.ops.lock().unwrap().clone();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].lookup_key, Some(key));

        // 缺 key → invalid_argument。
        let err = service
            .get_operation(Request::new(wire::GetKernelOperationRequest { key: None }))
            .await
            .expect_err("missing key");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// Reconcile（P3-c1）：义务未终局（Pending/None）→ 决策 Retry → 经
    /// `retry_obligation` seam 派发（fake 观测）；回执保留观测 disposition。
    #[tokio::test]
    async fn reconcile_retries_pending_obligation() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);

        let key = wire::OperationLookupKey {
            principal_digest: vec![0xAA; 32],
            method: wire::OperationMethod::Reconcile as i32,
            runtime_epoch: vec![0u8; 16],
            operation_id: vec![0u8; 16],
        };
        let digest = vec![0xDD; 32];

        let reply = service
            .reconcile(Request::new(ReconcileRequest {
                key: Some(key.clone()),
                request_digest: digest.clone(),
            }))
            .await
            .expect("reconcile");
        assert!(reply.into_inner().terminal.is_none());

        // 观察（get_operation）+ 重试派发（retry_obligation）各一次。
        let engine_guard = engine.lock().await;
        assert_eq!(engine_guard.ops.lock().unwrap().len(), 1);
        let retries = engine_guard.retries.lock().unwrap().clone();
        assert_eq!(retries.len(), 1, "未终局义务必须触发重试 seam");
        assert_eq!(retries[0].key, Some(key));
        assert_eq!(retries[0].request_digest, digest);
    }

    /// `reconcile_retry_plan`（P3-c1）：Terminal 终局 → 不重试；Pending/None → 重试。
    #[test]
    fn reconcile_retry_plan_distinguishes_terminal_from_pending() {
        let terminal = Some(wire::OperationState {
            state: Some(wire::operation_state::State::Terminal(
                wire::OperationTerminal {
                    result: Some(wire::operation_terminal::Result::Succeeded(
                        wire::MutationReceipt::default(),
                    )),
                },
            )),
        });
        assert_eq!(reconcile_retry_plan(&terminal), ReconcileRetry::Terminal);

        let pending = Some(wire::OperationState {
            state: Some(wire::operation_state::State::Pending(
                wire::EmptyOperationState {},
            )),
        });
        assert_eq!(reconcile_retry_plan(&pending), ReconcileRetry::Retry);
        assert_eq!(reconcile_retry_plan(&None), ReconcileRetry::Retry);
    }

    /// 轮询事件总线直到当前快照状态到达期望判别（forwarder 测试的收敛等待）。
    async fn wait_snapshot_state(bus: &Arc<EventBus>, want: &str) {
        use std::time::Duration;
        for _ in 0..200 {
            let state = bus.current_snapshot().map(|s| s.state);
            let hit = match want {
                "connected" => matches!(
                    state,
                    Some(Some(wire::runtime_snapshot::State::Connected(_)))
                ),
                "failed_dirty" => matches!(
                    state,
                    Some(Some(wire::runtime_snapshot::State::FailedDirty(_)))
                ),
                "reconciling" => matches!(
                    state,
                    Some(Some(wire::runtime_snapshot::State::Reconciling(_)))
                ),
                _ => false,
            };
            if hit {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("bus never reached state {want}");
    }

    /// 轮询事件总线直到 Connecting 快照携带期望的细粒度 ConnectPhase（forwarder
    /// 阶段推进的收敛等待，R1）。
    async fn wait_snapshot_connecting_phase(bus: &Arc<EventBus>, want: wire::ConnectPhase) {
        use std::time::Duration;
        for _ in 0..200 {
            let hit = matches!(
                bus.current_snapshot().map(|s| s.state),
                Some(Some(wire::runtime_snapshot::State::Connecting(c)))
                    if c.phase == want as i32
            );
            if hit {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("bus never reached connecting phase {want:?}");
    }

    // -----------------------------------------------------------------------
    // P5-wire 方案 A：RuntimeSnapshot 携带统计（host → wire 映射 + 组装）。
    // -----------------------------------------------------------------------

    /// host `RuntimeStats` → wire `RuntimeStats`：字段一一对应、phase 为 wire i32。
    #[test]
    fn runtime_stats_to_wire_maps_all_fields() {
        let stats = RuntimeStats {
            rx_bytes: 1234,
            tx_bytes: 5678,
            rx_rate_bps: 2000,
            tx_rate_bps: 1000,
            latency_ms: 42,
            phase: exv_vpn_wire::generated::StatsPhase::Connected,
            engine_sequence: 7,
            sample_tick: 9,
        };
        let w = runtime_stats_to_wire(stats);
        assert_eq!(w.rx_bytes, 1234);
        assert_eq!(w.tx_bytes, 5678);
        assert_eq!(w.rx_rate_bps, 2000);
        assert_eq!(w.tx_rate_bps, 1000);
        assert_eq!(w.latency_ms, 42);
        assert_eq!(
            w.phase,
            exv_vpn_wire::generated::StatsPhase::Connected as i32
        );
        assert_eq!(w.engine_sequence, 7);
        assert_eq!(w.sample_tick, 9);
    }

    /// `snapshot_with_stats`：Some → 附加映射后的 stats；None → stats 留空。
    #[test]
    fn snapshot_with_stats_attaches_or_clears() {
        let base = snapshot_for_phase(HostPhase::Idle, &plain_composition());
        let stats = RuntimeStats {
            rx_bytes: 1,
            tx_bytes: 2,
            rx_rate_bps: 3,
            tx_rate_bps: 4,
            latency_ms: 5,
            phase: exv_vpn_wire::generated::StatsPhase::Idle,
            engine_sequence: 6,
            sample_tick: 7,
        };
        let with = snapshot_with_stats(base.clone(), Some(stats));
        assert_eq!(
            with.stats.expect("stats attached").rx_bytes,
            1,
            "Some → 附加统计"
        );
        let cleared = snapshot_with_stats(base, None);
        assert!(cleared.stats.is_none(), "None → 统计留空");
    }

    /// GetSnapshot：EventBus 统计 lane 的最新样本被附加到快照（P5-wire 方案 A）。
    #[tokio::test]
    async fn get_snapshot_carries_latest_stats_from_bus() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();

        // 先无统计 → GetSnapshot 的 stats 为空。
        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        assert!(snap.stats.is_none(), "无样本 → stats 留空");

        // 发布一条统计 → GetSnapshot 携带最新样本（sample_tick 由 publish_stats 铸造）。
        let published = bus.publish_stats(RuntimeStats {
            rx_bytes: 1000,
            tx_bytes: 500,
            rx_rate_bps: 0,
            tx_rate_bps: 0,
            latency_ms: 7,
            phase: exv_vpn_wire::generated::StatsPhase::Connecting,
            engine_sequence: 3,
            sample_tick: 0,
        });
        // sample_tick 与事件总线 tick 对齐（stats 不独立铸造 tick：无事件时 = 0）。
        assert_eq!(
            published.sample_tick,
            bus.current_tick(),
            "sample_tick 与事件总线 tick 对齐"
        );

        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        let stats = snap.stats.expect("stats attached after publish_stats");
        assert_eq!(stats.rx_bytes, 1000);
        assert_eq!(stats.tx_bytes, 500);
        assert_eq!(stats.latency_ms, 7);
        assert_eq!(
            stats.phase,
            exv_vpn_wire::generated::StatsPhase::Connecting as i32
        );
        assert_eq!(stats.engine_sequence, 3);
        assert_eq!(stats.sample_tick, published.sample_tick);
    }

    /// WatchEvents：`EventBus::publish` 把最新统计附加到快照——订阅者随事件拿到统计。
    #[tokio::test]
    async fn watch_events_published_snapshot_carries_stats() {
        use tokio_stream::StreamExt;

        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();

        // 先发布统计，再发布状态事件 → 事件快照带统计。
        bus.publish_stats(RuntimeStats {
            rx_bytes: 9000,
            tx_bytes: 4000,
            rx_rate_bps: 300,
            tx_rate_bps: 200,
            latency_ms: 11,
            phase: exv_vpn_wire::generated::StatsPhase::Connected,
            engine_sequence: 5,
            sample_tick: 0,
        });
        bus.publish(
            wire::RuntimeEventKind::Snapshot,
            snapshot_for_phase(HostPhase::Connected, &plain_composition()),
        );

        let mut stream = service
            .watch_events(Request::new(WatchEventsRequest::default()))
            .await
            .expect("watch stream")
            .into_inner();
        let ev = stream.next().await.expect("event").expect("ok");
        let stats = ev
            .snapshot
            .and_then(|s| s.stats)
            .expect("watch event snapshot carries stats");
        assert_eq!(stats.rx_bytes, 9000);
        assert_eq!(stats.rx_rate_bps, 300);
        assert_eq!(stats.tx_rate_bps, 200);
        assert_eq!(stats.latency_ms, 11);
        assert_eq!(
            stats.phase,
            exv_vpn_wire::generated::StatsPhase::Connected as i32
        );
        assert_eq!(stats.engine_sequence, 5);
    }

    // -----------------------------------------------------------------------
    // C5-wire：上游 proxy TUN 检测 → RuntimeSnapshot 状态上报（resource → wire 映射、
    // EventBus lane、GetSnapshot/WatchEvents 携带）。
    // -----------------------------------------------------------------------

    /// resource `ProxyTunDetection` → wire：detected/adapters/route_policy 一一对应，
    /// route_policy 取自 detection（检测到 → "exv-before-proxy-tun"；未检测 → "normal"）。
    #[test]
    fn proxy_tun_detection_to_wire_maps_all_fields() {
        use exv_vpn_win32_resource::proxy_tun::{
            KIND_PROXY_TUN, ROUTE_POLICY_EXV_BEFORE_PROXY_TUN, ROUTE_POLICY_NORMAL,
        };

        let detected = ProxyTunDetection {
            detected: true,
            adapters: vec![exv_vpn_win32_resource::proxy_tun::ProxyTunAdapter {
                name: "Mihomo".to_string(),
                description: "Wintun Userspace Tunnel".to_string(),
                if_index: 42,
                kind: KIND_PROXY_TUN,
            }],
        };
        let w = proxy_tun_detection_to_wire(&detected);
        assert!(w.detected, "detected 透传");
        assert_eq!(w.route_policy, ROUTE_POLICY_EXV_BEFORE_PROXY_TUN);
        assert_eq!(w.adapters.len(), 1);
        assert_eq!(w.adapters[0].name, "Mihomo");
        assert_eq!(w.adapters[0].description, "Wintun Userspace Tunnel");
        assert_eq!(w.adapters[0].if_index, 42);
        assert_eq!(w.adapters[0].kind, KIND_PROXY_TUN);

        let clear = proxy_tun_detection_to_wire(&ProxyTunDetection {
            detected: false,
            adapters: vec![],
        });
        assert!(!clear.detected);
        assert_eq!(clear.route_policy, ROUTE_POLICY_NORMAL);
        assert!(clear.adapters.is_empty(), "未检测 → adapters 为空");
    }

    /// `snapshot_with_proxy_tun`：Some → 附加映射后的检测；None → `proxy_tun` 留空。
    #[test]
    fn snapshot_with_proxy_tun_attaches_or_clears() {
        let base = snapshot_for_phase(HostPhase::Idle, &plain_composition());
        let detection = wire::ProxyTunDetection {
            detected: true,
            adapters: vec![wire::ProxyTunAdapter {
                name: "Meta".to_string(),
                description: String::new(),
                if_index: 3,
                kind: "proxy_tun".to_string(),
            }],
            route_policy: "exv-before-proxy-tun".to_string(),
        };
        let with = snapshot_with_proxy_tun(base.clone(), Some(detection.clone()));
        let attached = with.proxy_tun.expect("proxy_tun attached");
        assert_eq!(attached.detected, true);
        assert_eq!(attached.route_policy, "exv-before-proxy-tun");
        assert_eq!(attached.adapters.len(), 1);
        assert_eq!(attached.adapters[0].name, "Meta");

        let cleared = snapshot_with_proxy_tun(base, None);
        assert!(cleared.proxy_tun.is_none(), "None → proxy_tun 留空");
    }

    /// EventBus proxy TUN lane（C5-wire）：`refresh_proxy_tun` 更新缓存、`current_proxy_tun`
    /// 回读；与 wire 事件 lane / 统计 lane 共存（不铸造 tick、不改变事件/统计）。
    #[test]
    fn event_bus_proxy_tun_lane_refreshes_and_recalls() {
        let bus = EventBus::new();
        assert_eq!(bus.current_proxy_tun(), None, "初始无检测");

        let detection = wire::ProxyTunDetection {
            detected: true,
            adapters: vec![],
            route_policy: "exv-before-proxy-tun".to_string(),
        };
        bus.refresh_proxy_tun(Some(detection.clone()));
        assert_eq!(bus.current_proxy_tun(), Some(detection));
        assert_eq!(bus.current_tick(), 0, "刷新检测不铸造事件 tick");

        // 与统计 lane 共存：刷新检测不改变统计，发布统计不改变检测。
        bus.publish_stats(RuntimeStats {
            rx_bytes: 1,
            tx_bytes: 0,
            rx_rate_bps: 0,
            tx_rate_bps: 0,
            latency_ms: 0,
            phase: wire::StatsPhase::Idle,
            engine_sequence: 1,
            sample_tick: 0,
        });
        assert_eq!(
            bus.current_proxy_tun().expect("still cached").detected,
            true
        );
        assert_eq!(bus.current_stats().expect("stats").rx_bytes, 1);

        bus.refresh_proxy_tun(None);
        assert_eq!(bus.current_proxy_tun(), None, "清空检测");
    }

    /// GetSnapshot（C5-wire）：每次调用探测一次并把结果注入快照——检测到 → detected
    /// true + "exv-before-proxy-tun"；未检测 → detected false + "normal"。
    #[tokio::test]
    async fn get_snapshot_probes_and_carries_proxy_tun() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        // 检测到：确定性探针报告一个 Mihomo Wintun 适配器。
        let (service, _logs_dir) = service_with_probe(
            &engine,
            detection_probe("Mihomo", "Wintun Userspace Tunnel"),
        );

        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        let detected = snap.proxy_tun.expect("proxy_tun carried by GetSnapshot");
        assert!(detected.detected, "检测到 → detected true");
        assert_eq!(detected.route_policy, "exv-before-proxy-tun");
        assert_eq!(detected.adapters.len(), 1);
        assert_eq!(detected.adapters[0].name, "Mihomo");
        assert_eq!(detected.adapters[0].if_index, 17);
        assert_eq!(detected.adapters[0].kind, "proxy_tun");
    }

    /// GetSnapshot（C5-wire）：探针报告未检测 → detected false + "normal"（状态上报
    /// 仍完整，UI 据此显示普通模式）。
    #[tokio::test]
    async fn get_snapshot_probes_not_detected_yields_normal_policy() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with_probe(&engine, no_detection_probe());

        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        let detection = snap.proxy_tun.expect("proxy_tun carried");
        assert!(!detection.detected);
        assert_eq!(detection.route_policy, "normal");
        assert!(detection.adapters.is_empty());
    }

    /// GetSnapshot（C5-wire）：探测失败（Win32 枚举错误）→ `proxy_tun` 留空（状态
    /// 上报不因探测失败而降级为 RPC 失败）。
    #[tokio::test]
    async fn get_snapshot_probe_failure_leaves_proxy_tun_none() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let probe: ProxyTunProbe = Arc::new(|| {
            Err(NativeError::from_win32(
                31, // ERROR_GEN_FAILURE 类探测失败
                "probe failed (test)",
            ))
        });
        let (service, _logs_dir) = service_with_probe(&engine, probe);

        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot read must not fail")
            .into_inner();
        assert!(snap.proxy_tun.is_none(), "探测失败 → proxy_tun 留空");
        assert!(snap.state.is_some(), "状态上报不受探测失败影响");
    }

    /// WatchEvents（C5-wire）：`EventBus::publish` 把缓存的上游 proxy TUN 检测附加到
    /// 快照——订阅者随事件拿到共存状态（badge 数据源）。
    #[tokio::test]
    async fn watch_events_published_snapshot_carries_proxy_tun() {
        use tokio_stream::StreamExt;

        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();

        // 先刷新检测缓存，再发布状态事件 → 事件快照带检测。
        bus.refresh_proxy_tun(Some(wire::ProxyTunDetection {
            detected: true,
            adapters: vec![wire::ProxyTunAdapter {
                name: "Clash".to_string(),
                description: String::new(),
                if_index: 9,
                kind: "proxy_tun".to_string(),
            }],
            route_policy: "exv-before-proxy-tun".to_string(),
        }));
        bus.publish(
            wire::RuntimeEventKind::Snapshot,
            snapshot_for_phase(HostPhase::Connected, &plain_composition()),
        );

        let mut stream = service
            .watch_events(Request::new(WatchEventsRequest::default()))
            .await
            .expect("watch stream")
            .into_inner();
        let ev = stream.next().await.expect("event").expect("ok");
        let detection = ev
            .snapshot
            .and_then(|s| s.proxy_tun)
            .expect("watch event snapshot carries proxy_tun");
        assert!(detection.detected);
        assert_eq!(detection.route_policy, "exv-before-proxy-tun");
        assert_eq!(detection.adapters[0].name, "Clash");
    }

    /// engine 状态转发器（C5-wire 集成）：状态过渡时点刷新检测 → 发布的事件快照携带
    /// 最新共存状态（badge 随事件更新；GetSnapshot 之外的 WatchEvents 路径闭环）。
    #[tokio::test]
    async fn status_forwarder_refreshes_proxy_tun_on_event() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        engine.lock().await.events.lock().unwrap().replace(rx);
        let (service, _logs_dir) =
            service_with_probe(&engine, detection_probe("sing-box", "Wintun"));
        let bus = service.events();
        let handle = service.spawn_status_forwarder();

        // Connected（真实 Connected 驱动）→ Connected 过渡；转发器发布前刷新检测 → 快照带检测。
        tx.send(EngineStatusEvent::Connected {
            operation_id: uuid16(3),
            session_established_at_ms: Some(1_700_000_000_123),
        })
        .unwrap();
        wait_snapshot_state(&bus, "connected").await;

        let snapshot = bus.current_snapshot().expect("published snapshot");
        let detection = snapshot
            .proxy_tun
            .expect("forwarder event snapshot carries proxy_tun");
        assert!(detection.detected, "转发器发布前刷新检测");
        assert_eq!(detection.route_policy, "exv-before-proxy-tun");
        assert_eq!(detection.adapters[0].name, "sing-box");

        drop(tx);
        handle.abort();
    }

    // -----------------------------------------------------------------------
    // EXV_UNFREEZE：系统代理感知 → RuntimeSnapshot 状态上报（resource → wire 映射、
    // EventBus lane、GetSnapshot/WatchEvents 携带）。
    // -----------------------------------------------------------------------

    /// resource `SystemProxySnapshot` → wire：mode/endpoint_count/bypass_merged/topology
    /// 一一对应；topology 是 (proxy_present, tunnel_present) 的纯函数分类（设计 §2）。
    #[test]
    fn system_proxy_snapshot_to_wire_maps_all_fields() {
        use exv_vpn_win32_resource::system_proxy::{ProxyEndpoint, ProxyKind};

        // Manual + 2 端点 + 豁免条目非空 → bypass_merged=true；无 TUN → t1。
        let manual = SystemProxySnapshot {
            mode: SystemProxyMode::Manual,
            endpoints: vec![
                ProxyEndpoint { kind: ProxyKind::Http, host: "127.0.0.1".into(), port: 7890 },
                ProxyEndpoint { kind: ProxyKind::Socks, host: "10.0.0.2".into(), port: 1080 },
            ],
            bypass_entries: vec!["localhost".to_string(), "<local>".to_string()],
            pac_url: None,
            auto_discovery: false,
        };
        let w = system_proxy_snapshot_to_wire(&manual, false);
        assert_eq!(w.mode, "manual");
        assert_eq!(w.endpoint_count, 2);
        assert!(w.bypass_merged, "豁免条目非空 → 已合并");
        assert_eq!(w.topology, "t1", "有系统代理无 TUN → t1");

        // 双有（Manual + tunnel_present=true）→ t3；topology 随 tunnel_present 变化。
        let both = system_proxy_snapshot_to_wire(&manual, true);
        assert_eq!(both.topology, "t3", "有系统代理有 TUN → t3");

        // Disabled 全空 → mode=disabled、endpoint_count=0、bypass_merged=false；无 TUN → t0。
        let disabled = SystemProxySnapshot {
            mode: SystemProxyMode::Disabled,
            endpoints: vec![],
            bypass_entries: vec![],
            pac_url: None,
            auto_discovery: false,
        };
        let d = system_proxy_snapshot_to_wire(&disabled, false);
        assert_eq!(d.mode, "disabled");
        assert_eq!(d.endpoint_count, 0);
        assert!(!d.bypass_merged);
        assert_eq!(d.topology, "t0");
        // Disabled + TUN → t2（无系统代理有 TUN）。
        assert_eq!(system_proxy_snapshot_to_wire(&disabled, true).topology, "t2");

        // Automatic（PAC）→ mode=automatic；免谈端点 → endpoint_count=0。
        let automatic = SystemProxySnapshot {
            mode: SystemProxyMode::Automatic,
            endpoints: vec![],
            bypass_entries: vec![],
            pac_url: Some("http://pac.example.test/wpad.dat".to_string()),
            auto_discovery: false,
        };
        assert_eq!(system_proxy_snapshot_to_wire(&automatic, false).mode, "automatic");
    }

    /// `snapshot_with_system_proxy`：Some → 附加映射后的检测；None → `system_proxy` 留空。
    #[test]
    fn snapshot_with_system_proxy_attaches_or_clears() {
        let base = snapshot_for_phase(HostPhase::Idle, &plain_composition());
        let detection = wire::SystemProxyDetection {
            mode: "manual".to_string(),
            endpoint_count: 1,
            bypass_merged: false,
            topology: "t1".to_string(),
        };
        let with = snapshot_with_system_proxy(base.clone(), Some(detection.clone()));
        let attached = with.system_proxy.expect("system_proxy attached");
        assert_eq!(attached.mode, "manual");
        assert_eq!(attached.endpoint_count, 1);
        assert_eq!(attached.topology, "t1");

        let cleared = snapshot_with_system_proxy(base, None);
        assert!(cleared.system_proxy.is_none(), "None → system_proxy 留空");
    }

    /// EventBus 系统代理 lane（EXV_UNFREEZE）：`refresh_system_proxy` 更新缓存、
    /// `current_system_proxy` 回读；与 wire 事件 lane / 统计 lane 共存（不铸造 tick）。
    #[test]
    fn event_bus_system_proxy_lane_refreshes_and_recalls() {
        let bus = EventBus::new();
        assert_eq!(bus.current_system_proxy(), None, "初始无检测");

        let detection = wire::SystemProxyDetection {
            mode: "automatic".to_string(),
            endpoint_count: 0,
            bypass_merged: false,
            topology: "t1".to_string(),
        };
        bus.refresh_system_proxy(Some(detection.clone()));
        assert_eq!(bus.current_system_proxy(), Some(detection));
        assert_eq!(bus.current_tick(), 0, "刷新检测不铸造事件 tick");

        // 与统计 lane 共存：刷新检测不改变统计，发布统计不改变检测。
        bus.publish_stats(RuntimeStats {
            rx_bytes: 1,
            tx_bytes: 0,
            rx_rate_bps: 0,
            tx_rate_bps: 0,
            latency_ms: 0,
            phase: wire::StatsPhase::Idle,
            engine_sequence: 1,
            sample_tick: 0,
        });
        assert_eq!(
            bus.current_system_proxy().expect("still cached").mode,
            "automatic"
        );
        assert_eq!(bus.current_stats().expect("stats").rx_bytes, 1);

        bus.refresh_system_proxy(None);
        assert_eq!(bus.current_system_proxy(), None, "清空检测");
    }

    /// GetSnapshot（EXV_UNFREEZE）：每次调用探测一次并把结果注入快照——mode/
    /// endpoint_count/bypass_merged/topology 透传（注入确定性探针，不触真实注册表）。
    #[tokio::test]
    async fn get_snapshot_probes_and_carries_system_proxy() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with_system_proxy_probe(
            &engine,
            system_proxy_probe(wire::SystemProxyDetection {
                mode: "mixed".to_string(),
                endpoint_count: 3,
                bypass_merged: true,
                topology: "t3".to_string(),
            }),
        );

        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        let detection = snap.system_proxy.expect("system_proxy carried by GetSnapshot");
        assert_eq!(detection.mode, "mixed");
        assert_eq!(detection.endpoint_count, 3);
        assert!(detection.bypass_merged);
        assert_eq!(detection.topology, "t3");
    }

    /// GetSnapshot（EXV_UNFREEZE）：探测失败（注册表不可读/SID 不可解析类）→
    /// `system_proxy` 留空（状态上报不因探测失败而降级为 RPC 失败）。
    #[tokio::test]
    async fn get_snapshot_probe_failure_leaves_system_proxy_none() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let probe: SystemProxyProbe = Arc::new(|| {
            Err(NativeError::from_win32(
                5, // ERROR_ACCESS_DENIED 类探测失败
                "system proxy probe failed (test)",
            ))
        });
        let (service, _logs_dir) = service_with_system_proxy_probe(&engine, probe);

        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot read must not fail")
            .into_inner();
        assert!(snap.system_proxy.is_none(), "探测失败 → system_proxy 留空");
        assert!(snap.state.is_some(), "状态上报不受探测失败影响");
    }

    /// WatchEvents（EXV_UNFREEZE）：`EventBus::publish` 把缓存的系统代理检测附加到
    /// 快照——订阅者随事件拿到系统代理感知状态（状态卡数据源）。
    #[tokio::test]
    async fn watch_events_published_snapshot_carries_system_proxy() {
        use tokio_stream::StreamExt;

        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let bus = service.events();

        // 先刷新检测缓存，再发布状态事件 → 事件快照带检测。
        bus.refresh_system_proxy(Some(wire::SystemProxyDetection {
            mode: "manual".to_string(),
            endpoint_count: 2,
            bypass_merged: true,
            topology: "t1".to_string(),
        }));
        bus.publish(
            wire::RuntimeEventKind::Snapshot,
            snapshot_for_phase(HostPhase::Connected, &plain_composition()),
        );

        let mut stream = service
            .watch_events(Request::new(WatchEventsRequest::default()))
            .await
            .expect("watch stream")
            .into_inner();
        let ev = stream.next().await.expect("event").expect("ok");
        let detection = ev
            .snapshot
            .and_then(|s| s.system_proxy)
            .expect("watch event snapshot carries system_proxy");
        assert_eq!(detection.mode, "manual");
        assert_eq!(detection.endpoint_count, 2);
        assert!(detection.bypass_merged);
        assert_eq!(detection.topology, "t1");
    }

    /// engine 状态转发器（EXV_UNFREEZE 集成）：状态过渡时点刷新系统代理 → 发布的事件
    /// 快照携带最新感知状态（GetSnapshot 之外的 WatchEvents 路径闭环）。
    #[tokio::test]
    async fn status_forwarder_refreshes_system_proxy_on_event() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        engine.lock().await.events.lock().unwrap().replace(rx);
        let (service, _logs_dir) = service_with_system_proxy_probe(
            &engine,
            system_proxy_probe(wire::SystemProxyDetection {
                mode: "automatic".to_string(),
                endpoint_count: 0,
                bypass_merged: false,
                topology: "t1".to_string(),
            }),
        );
        let bus = service.events();
        let handle = service.spawn_status_forwarder();

        // Connected（真实 Connected 驱动）→ Connected 过渡；转发器发布前刷新检测 → 快照带检测。
        tx.send(EngineStatusEvent::Connected {
            operation_id: uuid16(3),
            session_established_at_ms: Some(1_700_000_000_123),
        })
        .unwrap();
        wait_snapshot_state(&bus, "connected").await;

        let snapshot = bus.current_snapshot().expect("published snapshot");
        let detection = snapshot
            .system_proxy
            .expect("forwarder event snapshot carries system_proxy");
        assert_eq!(detection.mode, "automatic");
        assert_eq!(detection.topology, "t1");

        drop(tx);
        handle.abort();
    }

    /// D3 铁律（R1）：日志是纯输出，绝不回流状态——写入/聚合日志后，`EventBus`
    /// 快照与 tick 均不动（无 log→state 路径残留）。
    #[tokio::test]
    async fn logs_never_drive_state_after_forwarder_retirement() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _dir) = service_with(&engine);
        let bus = service.events();
        let tick_before = bus.current_tick();
        let snap_before = bus.current_snapshot();

        // 写入多条结构化日志（含旧的"状态承载" code 形状——现在纯诊断）。
        for code in [
            "mutation.apply.applied",
            "mutation.stop.stopped",
            "lease.handshake.accepted",
        ] {
            service
                .logs
                .append_core("info", "engine", code, "diagnostic only", &BTreeMap::new())
                .expect("append");
        }

        // 断言：状态总线零变化（tick 未推进、快照未铸造）——日志不再驱动任何状态。
        assert_eq!(
            bus.current_tick(),
            tick_before,
            "logs must not mint event ticks"
        );
        assert_eq!(
            bus.current_snapshot().is_some(),
            snap_before.is_some(),
            "logs must not cast snapshots"
        );
    }

    #[tokio::test]
    async fn logs_list_returns_aggregated_entries() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _dir) = service_with(&engine);
        service
            .logs
            .append_core(
                "info",
                "kernel",
                "test.code",
                "hello logs",
                &BTreeMap::new(),
            )
            .expect("append");
        let reply = service
            .logs_list(Request::new(wire::LogsListRequest {
                after_seq: 0,
                limit: 10,
                filter: String::new(),
            }))
            .await
            .expect("logs_list ok")
            .into_inner();
        assert_eq!(reply.entries.len(), 1);
        assert_eq!(reply.entries[0].message, "hello logs");
        assert!(reply.next_seq >= 1);
    }

    #[tokio::test]
    async fn logs_clear_clears_and_reports_removed() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _dir) = service_with(&engine);
        service
            .logs
            .append_core("info", "kernel", "c", "m1", &BTreeMap::new())
            .expect("append");
        service
            .logs
            .append_core("warn", "kernel", "c", "m2", &BTreeMap::new())
            .expect("append");
        let removed = service.logs.last_seq();
        let reply = service
            .logs_clear(Request::new(wire::LogsClearRequest {}))
            .await
            .expect("clear ok")
            .into_inner();
        assert!(reply.cleared);
        assert_eq!(reply.removed_entries, removed);
        let list = service
            .logs_list(Request::new(wire::LogsListRequest {
                after_seq: 0,
                limit: 10,
                filter: String::new(),
            }))
            .await
            .expect("list after clear")
            .into_inner();
        assert!(list.entries.is_empty(), "aggregate cleared");
    }

    #[tokio::test]
    async fn config_get_returns_non_secret_items() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let config_dir = seeded_config_dir("s3cret");
        let (service, _dir) = service_with_config(&engine, config_dir.path().to_path_buf());
        let reply = service
            .config_get(Request::new(wire::ConfigGetRequest {}))
            .await
            .expect("config_get ok")
            .into_inner();
        let items: std::collections::HashMap<String, String> =
            reply.items.into_iter().map(|i| (i.key, i.value)).collect();
        assert_eq!(
            items.get("server").map(String::as_str),
            Some("vpn-cn.ecnu.edu.cn")
        );
        assert_eq!(items.get("username").map(String::as_str), Some("student"));
        assert!(items.contains_key("routes"));
        assert!(items.contains_key("mtu"));
        assert_eq!(
            items.get("auto_reconnect").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            items.get("auto_reconnect_max_attempts").map(String::as_str),
            Some("0")
        );
        assert!(
            !items.contains_key("password"),
            "password must not be returned"
        );
    }

    #[tokio::test]
    async fn config_set_applies_and_persists() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let config_dir = seeded_config_dir("s3cret");
        let (service, _dir) = service_with_config(&engine, config_dir.path().to_path_buf());
        let reply = service
            .config_set(Request::new(wire::ConfigSetRequest {
                items: vec![wire::ConfigItem {
                    key: "server".into(),
                    value: "vpn-new.example.com".into(),
                }],
            }))
            .await
            .expect("config_set ok")
            .into_inner();
        assert!(reply.ok);
        let loaded = ExvConfig::load_from_dir(config_dir.path()).expect("reload");
        assert_eq!(loaded.server, "vpn-new.example.com");
    }

    #[tokio::test]
    async fn config_set_auto_reconnect_roundtrips_via_config_get() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let config_dir = seeded_config_dir("s3cret");
        let (service, _dir) = service_with_config(&engine, config_dir.path().to_path_buf());
        let reply = service
            .config_set(Request::new(wire::ConfigSetRequest {
                items: vec![
                    wire::ConfigItem {
                        key: "auto_reconnect".into(),
                        value: "true".into(),
                    },
                    wire::ConfigItem {
                        key: "auto_reconnect_max_attempts".into(),
                        value: "5".into(),
                    },
                ],
            }))
            .await
            .expect("config_set ok")
            .into_inner();
        assert!(reply.ok);

        // config_get 回读一致。
        let reply = service
            .config_get(Request::new(wire::ConfigGetRequest {}))
            .await
            .expect("config_get ok")
            .into_inner();
        let items: std::collections::HashMap<String, String> =
            reply.items.into_iter().map(|i| (i.key, i.value)).collect();
        assert_eq!(items.get("auto_reconnect").map(String::as_str), Some("true"));
        assert_eq!(
            items.get("auto_reconnect_max_attempts").map(String::as_str),
            Some("5")
        );

        // 落盘持久化：重载后仍一致。
        let loaded = ExvConfig::load_from_dir(config_dir.path()).expect("reload");
        assert!(loaded.auto_reconnect);
        assert_eq!(loaded.auto_reconnect_max_attempts, 5);
    }

    #[tokio::test]
    async fn config_set_auto_reconnect_invalid_bool_rejected() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let config_dir = seeded_config_dir("s3cret");
        let (service, _dir) = service_with_config(&engine, config_dir.path().to_path_buf());
        let err = service
            .config_set(Request::new(wire::ConfigSetRequest {
                items: vec![wire::ConfigItem {
                    key: "auto_reconnect".into(),
                    value: "abc".into(),
                }],
            }))
            .await
            .expect_err("invalid bool must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn config_set_auto_reconnect_max_attempts_invalid_rejected() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let config_dir = seeded_config_dir("s3cret");
        let (service, _dir) = service_with_config(&engine, config_dir.path().to_path_buf());
        let err = service
            .config_set(Request::new(wire::ConfigSetRequest {
                items: vec![wire::ConfigItem {
                    key: "auto_reconnect_max_attempts".into(),
                    value: "abc".into(),
                }],
            }))
            .await
            .expect_err("invalid number must be rejected");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // -----------------------------------------------------------------------
    // R3 宿主健壮性：有界就绪等待 / 终态 operation_id 过滤 / status_ready 防 stale-true
    // -----------------------------------------------------------------------

    /// R3-C1：`await_status_ready` 有界等待——引擎状态流永久不可达（无状态源）时，
    /// connect 不在就绪等待上永久悬挂：有界等待后放行派发，ApplyTunnel 报真实 gRPC
    /// 错误（失败不静默）。
    #[tokio::test]
    async fn connect_proceeds_after_bounded_status_ready_wait_on_unreachable_engine() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        // 引擎不可达：apply_connect 返回真实 gRPC 错误（模拟 transport 断裂）。
        engine
            .lock()
            .await
            .apply_error
            .lock()
            .unwrap()
            .replace(GrpcClientError::Rpc(
                Code::Unavailable,
                "engine unreachable (test)".to_string(),
            ));
        // 无状态源：spawn_status_forwarder 永远无法挂接 → status_ready 恒 false。
        let config_dir = seeded_config_dir("s3cret");
        let (service, _logs_dir) = service_with_config(&engine, config_dir.path().to_path_buf());
        // 注入短有界等待（30ms）验证不悬挂语义。
        let service = service.with_status_ready_wait(std::time::Duration::from_millis(30));
        let intent = connect_intent();

        // 有界等待到期 → 放行派发 → ApplyTunnel 报真实错误；connect 在界内返回（不悬挂）。
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            service.connect(Request::new(ConnectRequest {
                intent: Some(intent),
                secret_payload: vec![],
            })),
        )
        .await
        .expect("connect must not hang on unreachable status stream")
        .expect_err("engine apply reports real error");
        assert_eq!(
            err.code(),
            tonic::Code::Unavailable,
            "真实 gRPC 错误上浮（不静默）"
        );
        // 状态机已受理（进 Connecting，操作已登记）——失败经 RPC 错误上浮，不悬挂。
        assert_eq!(
            service.composition.lock().await.phase(),
            HostPhase::Connecting
        );
    }

    /// R3-C2：operation_id 过滤——旧操作（id ≠ 当前在途操作）的迟到终态事件被丢弃，
    /// 不驱动相态；当前操作的终态正常通过并驱动状态机。
    #[tokio::test]
    async fn stale_terminal_event_with_mismatched_operation_id_is_dropped() {
        let composition = Arc::new(tokio::sync::Mutex::new(plain_composition()));
        {
            let mut guard = composition.lock().await;
            let (peer, cap) = controller_peer_and_capability();
            guard.bind_controller(peer, cap);
            guard.apply(HostEvent::Connect);
            guard.set_operation_id(uuid16_bytes(3)); // 当前在途操作 = op 3
        }

        // 旧操作（op 9）的迟到 Connected → 丢弃（None），不驱动 Connected 相态。
        let dropped = runtime_event_from_status(
            &EngineStatusEvent::Connected {
                operation_id: uuid16(9),
                session_established_at_ms: Some(1_700_000_000_123),
            },
            &composition,
        )
        .await;
        assert!(dropped.is_none(), "旧操作迟到 Connected 必须被丢弃");
        assert_eq!(
            composition.lock().await.phase(),
            HostPhase::Connecting,
            "相态不被旧终态驱动"
        );

        // 旧操作（op 9）的迟到 Failed → 同样丢弃。
        let dropped = runtime_event_from_status(
            &EngineStatusEvent::Failed {
                operation_id: uuid16(9),
                error: wire::VpnError {
                    code: 1,
                    stage: 8,
                    certainty: 0,
                    retry: 1,
                    subject: None,
                    resource: None,
                    native: None,
                },
            },
            &composition,
        )
        .await;
        assert!(dropped.is_none(), "旧操作迟到 Failed 必须被丢弃");

        // 当前操作（op 3）的 Connected → 正常通过并驱动 Connected 相态。
        let (kind, snap) = runtime_event_from_status(
            &EngineStatusEvent::Connected {
                operation_id: uuid16(3),
                session_established_at_ms: Some(1_700_000_000_123),
            },
            &composition,
        )
        .await
        .expect("current-op terminal passes filter");
        assert_eq!(kind, wire::RuntimeEventKind::Transition);
        assert!(matches!(
            snap.state,
            Some(wire::runtime_snapshot::State::Connected(_))
        ));
        assert_eq!(composition.lock().await.phase(), HostPhase::Connected);
    }

    /// R3-C3：status_ready 防 stale-true——状态流 EOF（engine 断开）→ 转发器撤销就绪
    /// （send(false)），退避窗口内派发不误判已挂接。
    #[tokio::test]
    async fn status_ready_clears_when_status_stream_eofs() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<EngineStatusEvent>();
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        engine.lock().await.events.lock().unwrap().replace(rx);
        let (service, _logs_dir) = service_with(&engine);
        let handle = service.spawn_status_forwarder();
        let mut ready = service.status_ready();

        // 挂接成功 → 就绪 true。
        while !*ready.borrow() {
            if ready.changed().await.is_err() {
                break;
            }
        }
        assert!(*ready.borrow(), "挂接后就绪 true");

        // 状态流 EOF（drop tx）→ 转发器撤销就绪（send(false)），不再误判已挂接。
        drop(tx);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while *ready.borrow() {
                if ready.changed().await.is_err() {
                    break;
                }
            }
        })
        .await
        .expect("status_ready must clear on stream EOF");
        assert!(!*ready.borrow(), "EOF 后就绪 false（防 stale-true）");

        handle.abort();
    }

    /// R3：日志转发器——engine `StreamLogs` 事件经聚合落盘（纯单向：磁盘行 = 真相源；
    /// 事件总线零变化——日志绝不驱动状态）。
    #[tokio::test]
    async fn log_forwarder_aggregates_engine_logs_to_disk() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<wire::LogEvent>();
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        engine.lock().await.log_events.lock().unwrap().replace(rx);
        let (service, logs_dir) = service_with(&engine);
        let bus = service.events();
        let tick_before = bus.current_tick();
        let handle = service.spawn_log_forwarder();

        // engine 推送两条日志事件（纯诊断，含旧"状态承载" code 形状——现在纯输出）。
        for (code, msg) in [("engine.log.a", "first"), ("engine.log.b", "second")] {
            tx.send(wire::LogEvent {
                level: "info".to_string(),
                component: "engine".to_string(),
                code: code.to_string(),
                message: msg.to_string(),
                fields: std::collections::HashMap::new(),
                timestamp_ms: 1_700_000_000_000,
            })
            .unwrap();
        }
        // 等待两条落盘（聚合文件 = `logs_dir/svc.jsonl`）。
        let agg_path = logs_dir.path().join("svc.jsonl");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let raw = std::fs::read_to_string(&agg_path).unwrap_or_default();
            if raw.lines().count() >= 2 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "logs not aggregated in time"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let raw = std::fs::read_to_string(&agg_path).expect("aggregate file");
        assert!(raw.contains("engine.log.a"), "first log aggregated");
        assert!(raw.contains("engine.log.b"), "second log aggregated");
        // 纯单向：日志落盘不铸造事件 tick（总线零变化）。
        assert_eq!(
            bus.current_tick(),
            tick_before,
            "logs must not mint event ticks"
        );

        drop(tx);
        handle.abort();
    }

    // -----------------------------------------------------------------------
    // S3/D3 + M3：auto 决策表三态契约测试（decide_route 纯函数 + connect RPC 三分支）。
    // R1：安装/连接独立——connect 不触发 install；已装但停止时，connect 内由 Core
    // 一次性 bootstrap，未装一律 oneshot。
    // -----------------------------------------------------------------------

    /// M3 决策表纯函数：服务状态三态矩阵。
    #[test]
    fn decide_route_three_state_matrix() {
        // Running → Service（连接服务 engine）。
        assert_eq!(decide_route(ServiceState::Running), RouteDecision::Service);
        // 已装非运行（Stopped/StartPending/StopPending/Paused/…/Other）→ PromptStart
        //（由 connect 内部 bootstrap，不需要用户先点 Start）。
        assert_eq!(decide_route(ServiceState::Stopped), RouteDecision::PromptStart);
        assert_eq!(
            decide_route(ServiceState::StopPending),
            RouteDecision::PromptStart
        );
        assert_eq!(decide_route(ServiceState::Other(9)), RouteDecision::PromptStart);
        // NotInstalled → Oneshot（维持既有路径；安装由 UI 独立发请求，connect 不触发 install）。
        assert_eq!(
            decide_route(ServiceState::NotInstalled),
            RouteDecision::Oneshot
        );
    }

    /// S3/D4 fake 服务操作 seam：记录 install/uninstall/start 调用次数。
    #[derive(Default)]
    struct FakeServiceOps {
        installs: std::sync::atomic::AtomicU32,
        uninstalls: std::sync::atomic::AtomicU32,
        starts: std::sync::atomic::AtomicU32,
    }

    #[tonic::async_trait]
    impl ServiceControlOps for FakeServiceOps {
        async fn install(&self) -> Result<String, String> {
            self.installs.fetch_add(1, Ordering::Relaxed);
            Ok("install".to_string())
        }
        async fn uninstall(&self) -> Result<String, String> {
            self.uninstalls.fetch_add(1, Ordering::Relaxed);
            Ok("uninstall".to_string())
        }
        async fn start(&self) -> Result<String, String> {
            self.starts.fetch_add(1, Ordering::Relaxed);
            Ok("start".to_string())
        }
    }

    /// S3/D5 fake 服务状态源：返回确定性 SCM 事实（running / stopped / not-installed）。
    struct FakeStatusSource {
        raw: RawServiceQuery,
    }
    impl ServiceStatusSource for FakeStatusSource {
        fn query_raw(&self, _name: &str) -> Result<RawServiceQuery, String> {
            Ok(self.raw.clone())
        }
    }
    fn fake_status_source(installed: bool, raw_state: u32) -> Arc<FakeStatusSource> {
        Arc::new(FakeStatusSource {
            raw: RawServiceQuery {
                installed,
                raw_state,
                binary_path: Some(r"C:\exv\exv-engine.exe --service".to_string()),
            },
        })
    }

    /// fake 状态源变体：binary_path 指向**真实存在的临时 engine 二进制**——让
    /// `service_health_from_snapshot` 的 `engine_binary_exists`/`binary_targets_engine`
    /// 为真（Running + binary_ok → Healthy 的输入；S3-B 健康加深测试用）。
    fn fake_status_source_with_exe(exe: &Path, installed: bool, raw_state: u32) -> Arc<FakeStatusSource> {
        Arc::new(FakeStatusSource {
            raw: RawServiceQuery {
                installed,
                raw_state,
                binary_path: Some(format!("{} --service", exe.display())),
            },
        })
    }

    /// S3/D3 fake service engine 连接器：直接返回注入的 fake engine（避免真实 PSK/管道）。
    struct FakeServiceConnector {
        engine: Arc<tokio::sync::Mutex<FakeEngine>>,
    }
    #[tonic::async_trait]
    impl ServiceEngineConnector for FakeServiceConnector {
        async fn connect_service_engine(
            &self,
        ) -> Result<Arc<tokio::sync::Mutex<dyn KernelEngineControl>>, String> {
            Ok(self.engine.clone())
        }
    }

    /// R2/S3-B fake 探活：返回确定性结果（避免真实 PSK 文件与服务管道依赖）。
    struct FakeProbe {
        /// keepalive 探活确定性结果。
        replies: std::sync::atomic::AtomicBool,
        /// S3-B 深度自述确定性报告（`None` = 探针失败——保守保留 SCM 派生）。
        self_reports: std::sync::Mutex<Option<wire::ServiceSelfReport>>,
        /// S3-B 深度自述探针触发计数（A6：Running 触发 / 非 Running 不触发）。
        self_probes: std::sync::atomic::AtomicU32,
    }
    #[tonic::async_trait]
    impl ServiceProbe for FakeProbe {
        async fn probe(&self) -> bool {
            self.replies.load(Ordering::Relaxed)
        }
        async fn probe_self_report(&self) -> Option<wire::ServiceSelfReport> {
            self.self_probes.fetch_add(1, Ordering::Relaxed);
            self.self_reports.lock().unwrap().clone()
        }
    }
    fn fake_probe(replies: bool) -> Arc<FakeProbe> {
        Arc::new(FakeProbe {
            replies: std::sync::atomic::AtomicBool::new(replies),
            self_reports: std::sync::Mutex::new(None),
            self_probes: std::sync::atomic::AtomicU32::new(0),
        })
    }

    /// M3 四态 @ connect RPC：已装 + 在跑 → 换入 service engine 并派发，mode=service。
    #[tokio::test]
    async fn connect_routes_to_service_engine_when_installed_and_running() {
        let original = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let service_engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let config_dir = seeded_config_dir("s3cret");
        let (service, _logs_dir) = service_with_config(&original, config_dir.path().to_path_buf());
        let ops = Arc::new(FakeServiceOps::default());
        let service = service
            .with_service_ops(ops.clone() as Arc<dyn ServiceControlOps>)
            .with_service_status_source(fake_status_source(true, SERVICE_RUNNING.0))
            .with_service_probe(fake_probe(true))
            .with_service_connector(Arc::new(FakeServiceConnector {
                engine: Arc::clone(&service_engine),
            }));
        spawn_status_ready(&service, &original).await;

        let reply = service
            .connect(Request::new(ConnectRequest {
                intent: Some(connect_intent()),
                secret_payload: vec![],
            }))
            .await
            .expect("connect routed to service engine");
        assert!(
            reply.into_inner().terminal.is_some(),
            "dispatch reaches the service engine"
        );
        // 换入生效：派发落在 service engine（非 original）。
        assert_eq!(
            service_engine.lock().await.applies.lock().unwrap().len(),
            1,
            "service engine received the connect"
        );
        assert_eq!(original.lock().await.applies.lock().unwrap().len(), 0);
        assert_eq!(
            ops.starts.load(Ordering::Relaxed),
            0,
            "running service is not restarted"
        );
        // 快照 mode=service（展示）。
        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        assert_eq!(snap.mode, ServiceMode::Service.as_wire_str(), "mode recorded as service");
    }

    /// `connect` 发现服务已安装但未运行时，Core 自动 bootstrap 服务，再走 service engine。
    /// 这是用户不需要手动点击 Start 的主路径回归测试。
    #[tokio::test]
    async fn connect_bootstraps_installed_but_not_running_service() {
        let original = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let service_engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let ops = Arc::new(FakeServiceOps::default());
        let config_dir = seeded_config_dir("s3cret");
        let (service, _logs_dir) = service_with_config(&original, config_dir.path().to_path_buf());
        let service = service
            .with_service_ops(ops.clone() as Arc<dyn ServiceControlOps>)
            .with_service_status_source(fake_status_source(true, SERVICE_STOPPED.0))
            .with_service_probe(fake_probe(true))
            .with_service_connector(Arc::new(FakeServiceConnector {
                engine: Arc::clone(&service_engine),
            }));
        spawn_status_ready(&service, &original).await;

        let reply = service
            .connect(Request::new(ConnectRequest {
                intent: Some(connect_intent()),
                secret_payload: vec![],
            }))
            .await
            .expect("Core starts service and continues connect");
        assert!(reply.into_inner().terminal.is_some());
        assert_eq!(
            ops.starts.load(Ordering::Relaxed),
            1,
            "bootstrap starts once"
        );
        assert_eq!(
            service_engine.lock().await.applies.lock().unwrap().len(),
            1,
            "connect is dispatched to service engine"
        );
    }

    /// 服务 engine 已换入后卸载服务，下一次 connect 必须恢复原 oneshot engine，
    /// 且 admission 必须保持可受理；不能把已停止的 service pipe 留在 EngineSlot 中。
    #[tokio::test]
    async fn uninstall_service_restores_oneshot_route_for_next_connect() {
        let original = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let service_engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let ops = Arc::new(FakeServiceOps::default());
        let config_dir = seeded_config_dir("s3cret");
        let (service, _logs_dir) = service_with_config(&original, config_dir.path().to_path_buf());
        let service = service
            .with_service_ops(ops.clone() as Arc<dyn ServiceControlOps>)
            .with_service_status_source(fake_status_source(true, SERVICE_RUNNING.0))
            .with_service_probe(fake_probe(true))
            .with_service_connector(Arc::new(FakeServiceConnector {
                engine: Arc::clone(&service_engine),
            }));
        spawn_status_ready(&service, &original).await;

        service
            .connect(Request::new(ConnectRequest {
                intent: Some(connect_intent()),
                secret_payload: vec![],
            }))
            .await
            .expect("service connect");
        assert_eq!(
            service_engine.lock().await.applies.lock().unwrap().len(),
            1,
            "first connect uses service engine"
        );

        service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Uninstall(
                    ServiceUninstall {},
                )),
            }))
            .await
            .expect("uninstall service");

        let service =
            service.with_service_status_source(fake_status_source(false, SERVICE_STOPPED.0));
        service
            .connect(Request::new(ConnectRequest {
                intent: Some(connect_intent()),
                secret_payload: vec![],
            }))
            .await
            .expect("oneshot connect after uninstall");

        assert_eq!(
            original.lock().await.applies.lock().unwrap().len(),
            1,
            "next connect returns to the original oneshot engine"
        );
        assert_eq!(
            service_engine.lock().await.applies.lock().unwrap().len(),
            1,
            "stopped service engine is not reused"
        );
        assert_eq!(service.mode_string(), ServiceMode::Oneshot.as_wire_str());
        assert!(service.composition.lock().await.admission_open());
        assert_eq!(ops.uninstalls.load(Ordering::Relaxed), 1);
    }

    /// R5：服务已装 + 在跑，但 service engine 连接失败（PSK/管道/握手）→
    /// `service_connect_failed|` 前缀 + 相态收敛 Failed（不卡死 Connecting）。
    #[tokio::test]
    async fn connect_service_engine_connect_failure_converges_to_failed() {
        struct FailingConnector;
        #[tonic::async_trait]
        impl ServiceEngineConnector for FailingConnector {
            async fn connect_service_engine(
                &self,
            ) -> Result<Arc<tokio::sync::Mutex<dyn KernelEngineControl>>, String> {
                Err("psk unreadable".to_string())
            }
        }

        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let service = service
            .with_service_status_source(fake_status_source(true, SERVICE_RUNNING.0))
            .with_service_probe(fake_probe(true))
            .with_service_connector(Arc::new(FailingConnector));

        let err = service
            .connect(Request::new(ConnectRequest {
                intent: Some(connect_intent()),
                secret_payload: vec![],
            }))
            .await
            .expect_err("service engine connect fails");
        assert_eq!(
            err.code(),
            tonic::Code::FailedPrecondition,
            "service engine connect failure is a failed_precondition"
        );
        assert!(
            err.message().starts_with("service_connect_failed|"),
            "machine-identifiable prefix（UI map_status 触发 modal）: {}",
            err.message()
        );
        assert_eq!(
            engine.lock().await.applies.lock().unwrap().len(),
            0,
            "no dispatch"
        );
        assert_eq!(
            service.composition.lock().await.phase(),
            HostPhase::Failed,
            "service_connect_failed must converge to Failed (not hang in Connecting)"
        );
    }

    /// M3 三态 @ connect RPC：未装 → oneshot（原 engine 派发，mode=oneshot；安装由
    /// UI 独立发 ServiceControl install，connect 不触发 install/start）。
    #[tokio::test]
    async fn connect_oneshot_when_not_installed() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let config_dir = seeded_config_dir("s3cret");
        let (service, _logs_dir) = service_with_config(&engine, config_dir.path().to_path_buf());
        let service =
            service.with_service_status_source(fake_status_source(false, SERVICE_STOPPED.0));
        spawn_status_ready(&service, &engine).await;

        let reply = service
            .connect(Request::new(ConnectRequest {
                intent: Some(connect_intent()),
                secret_payload: vec![],
            }))
            .await
            .expect("oneshot connect");
        assert!(reply.into_inner().terminal.is_some());
        assert_eq!(
            engine.lock().await.applies.lock().unwrap().len(),
            1,
            "oneshot dispatch"
        );
        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        assert_eq!(snap.mode, ServiceMode::Oneshot.as_wire_str(), "mode recorded as oneshot");
    }

    /// S5/MED[3] 加固 @ connect RPC：SCM 查询失败（未知）→ 安全兜底 oneshot——**不误装**
    /// （connect 路由不触发 install/start，零调用），原 engine 派发，mode=oneshot。
    #[tokio::test]
    async fn connect_oneshot_when_service_query_fails() {
        struct BoomSource;
        impl ServiceStatusSource for BoomSource {
            fn query_raw(&self, _name: &str) -> Result<RawServiceQuery, String> {
                Err("scm boom".to_string())
            }
        }
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let ops = Arc::new(FakeServiceOps::default());
        let config_dir = seeded_config_dir("s3cret");
        let (service, _logs_dir) = service_with_config(&engine, config_dir.path().to_path_buf());
        let service = service
            .with_service_status_source(Arc::new(BoomSource))
            .with_service_ops(ops.clone() as Arc<dyn ServiceControlOps>);
        spawn_status_ready(&service, &engine).await;

        let reply = service
            .connect(Request::new(ConnectRequest {
                intent: Some(connect_intent()),
                secret_payload: vec![],
            }))
            .await
            .expect("query failure → oneshot fallback");
        assert!(reply.into_inner().terminal.is_some());
        // 不误装：查询失败不得触发 install/start。
        assert_eq!(ops.installs.load(Ordering::Relaxed), 0, "no false install");
        assert_eq!(ops.starts.load(Ordering::Relaxed), 0, "no false start");
        // 原 engine 派发（oneshot 路径）。
        assert_eq!(
            engine.lock().await.applies.lock().unwrap().len(),
            1,
            "oneshot dispatch"
        );
        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        assert_eq!(snap.mode, ServiceMode::Oneshot.as_wire_str(), "mode recorded as oneshot");
    }

    // -----------------------------------------------------------------------
    // S3/D5：GetSnapshot 携带 service_status/mode。
    // -----------------------------------------------------------------------

    /// GetSnapshot：非提权服务状态附加到快照（installed/running/state）+ 缺省 mode=auto。
    #[tokio::test]
    async fn get_snapshot_carries_service_status_and_default_mode() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let service =
            service.with_service_status_source(fake_status_source(true, SERVICE_RUNNING.0));

        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        let status = snap.service_status.expect("service_status present");
        assert!(status.installed, "installed=true from fake source");
        assert_eq!(status.state, "running", "state mapped to running");
        assert!(!snap.mode.is_empty(), "mode present (default auto)");
        assert_eq!(snap.mode, ServiceMode::Auto.as_wire_str(), "no connect yet → default auto");
    }

    /// GetSnapshot：未安装 → service_status.installed=false；查询失败 → service_status=None。
    #[tokio::test]
    async fn get_snapshot_service_status_absent_when_query_fails() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        // 注入失败源：查询失败 → service_status=None（状态上报不因查询失败而失败）。
        struct BoomSource;
        impl ServiceStatusSource for BoomSource {
            fn query_raw(&self, _name: &str) -> Result<RawServiceQuery, String> {
                Err("scm boom".to_string())
            }
        }
        let service = service.with_service_status_source(Arc::new(BoomSource));

        let snap = service
            .get_snapshot(Request::new(SnapshotRequest::default()))
            .await
            .expect("snapshot")
            .into_inner();
        assert!(snap.service_status.is_none(), "query failure → None");
        assert_eq!(snap.mode, ServiceMode::Auto.as_wire_str(), "mode falls back to auto");
    }

    // -----------------------------------------------------------------------
    // S3/D4/D5：KernelControl.ServiceControl RPC（query/install/uninstall/start/stop）。
    // -----------------------------------------------------------------------

    /// ServiceControl：query 非提权读 + 变更动作走 fake ops。
    /// 已运行服务的 install/start 均为幂等操作，不重复调用底层 start。
    #[tokio::test]
    async fn service_control_query_and_mutations_with_fake_ops() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let ops = Arc::new(FakeServiceOps::default());
        let (service, _logs_dir) = service_with(&engine);
        let service = service
            .with_service_status_source(fake_status_source(true, SERVICE_RUNNING.0))
            .with_service_ops(ops.clone() as Arc<dyn ServiceControlOps>);

        // query（读）：ok + 当前服务状态。
        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Query(
                    ServiceStatusQuery {},
                )),
            }))
            .await
            .expect("query")
            .into_inner();
        assert!(reply.ok, "query ok");
        assert_eq!(
            reply.service_status.as_ref().map(|s| s.installed),
            Some(true)
        );
        assert_eq!(
            reply.service_status.as_ref().map(|s| s.state.as_str()),
            Some("running")
        );
        assert_eq!(
            ops.installs.load(Ordering::Relaxed),
            0,
            "query is read-only"
        );

        // install。
        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Install(ServiceInstall {})),
            }))
            .await
            .expect("install")
            .into_inner();
        assert!(reply.ok, "install ok");
        assert_eq!(ops.installs.load(Ordering::Relaxed), 1);

        // start。
        service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Start(ServiceStart {})),
            }))
            .await
            .expect("start")
            .into_inner();
        assert_eq!(
            ops.starts.load(Ordering::Relaxed),
            0,
            "running service needs no start"
        );

        // uninstall：停止/删除是一个业务事务；即便 fake SCM 仍返回 marked-for-delete
        // 的"已安装"事实，回复也必须直接显示未安装。
        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Uninstall(
                    ServiceUninstall {},
                )),
            }))
            .await
            .expect("uninstall")
            .into_inner();
        assert!(reply.ok, "uninstall ok");
        assert_eq!(ops.uninstalls.load(Ordering::Relaxed), 1);
        assert_eq!(
            reply.service_status.as_ref().map(|status| status.installed),
            Some(false),
            "DeleteService 成功后不能把 SCM marked-for-delete 误报为已安装"
        );
    }

    // -----------------------------------------------------------------------
    // S3-B：ServiceControl.query 健康加深——SCM Running/StartPending 时触发
    // ServiceManage 深度自述探针（Tier 2 零 UAC），报告折进 health_state；
    // 非 Running 不触发（A6）；探针失败保守保留 SCM 派生。
    // -----------------------------------------------------------------------

    /// S3-B fake 自述报告构造。
    fn fake_self_report(control_plane_ready: bool, psk_present: bool) -> wire::ServiceSelfReport {
        wire::ServiceSelfReport {
            control_plane_ready,
            psk_present,
            connection_mode: "service".to_string(),
            runtime_epoch: vec![0u8; 16],
            authority_fence: None,
        }
    }

    /// 构造 SCM Running + 真实二进制存在的服务（加深后 Healthy 的输入）。
    fn running_service_with_real_binary(
        engine: &Arc<tokio::sync::Mutex<FakeEngine>>,
    ) -> (KernelControlService, tempfile::TempDir, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        let exe = dir.path().join("exv-engine.exe");
        std::fs::write(&exe, b"engine").expect("write fake engine bin");
        let (service, logs_dir) = service_with(engine);
        let service = service.with_service_status_source(fake_status_source_with_exe(
            &exe,
            true,
            SERVICE_RUNNING.0,
        ));
        (service, logs_dir, dir)
    }

    /// ServiceControl.query：SCM Running + 探针触发（记录调用）+ self-not-ready →
    /// health_state 加深为 installed_unavailable（A5：`control_plane_ready=false`）。
    #[tokio::test]
    async fn service_control_query_deepens_health_when_running_and_self_not_ready() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let probe = fake_probe(true);
        *probe.self_reports.lock().unwrap() = Some(fake_self_report(false, true));
        let (service, _logs_dir, _bin_dir) = running_service_with_real_binary(&engine);
        let service = service.with_service_probe(probe.clone());

        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Query(
                    ServiceStatusQuery {},
                )),
            }))
            .await
            .expect("query")
            .into_inner();
        assert!(reply.ok, "query ok");
        assert_eq!(
            probe.self_probes.load(Ordering::Relaxed),
            1,
            "Running 时 query 必须触发深度自述探针"
        );
        assert_eq!(
            reply.service_status.as_ref().map(|s| s.health_state.as_str()),
            Some("installed_unavailable"),
            "self-not-ready → InstalledUnavailable（健康加深）"
        );
    }

    /// ServiceControl.query：SCM Running + self-ready → healthy（加深不降级）。
    #[tokio::test]
    async fn service_control_query_running_with_self_ready_stays_healthy() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let probe = fake_probe(true);
        *probe.self_reports.lock().unwrap() = Some(fake_self_report(true, true));
        let (service, _logs_dir, _bin_dir) = running_service_with_real_binary(&engine);
        let service = service.with_service_probe(probe.clone());

        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Query(
                    ServiceStatusQuery {},
                )),
            }))
            .await
            .expect("query")
            .into_inner();
        assert_eq!(
            reply.service_status.as_ref().map(|s| s.health_state.as_str()),
            Some("healthy")
        );
        assert_eq!(probe.self_probes.load(Ordering::Relaxed), 1);
    }

    /// ServiceControl.query：SCM Running + 探针失败（None）→ 保守保留 SCM 派生
    ///（不把探针失败当引擎失败）。
    #[tokio::test]
    async fn service_control_query_running_probe_failure_is_conservative() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let probe = fake_probe(true); // self_reports 缺省 None = 探针失败
        let (service, _logs_dir, _bin_dir) = running_service_with_real_binary(&engine);
        let service = service.with_service_probe(probe.clone());

        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Query(
                    ServiceStatusQuery {},
                )),
            }))
            .await
            .expect("query")
            .into_inner();
        assert_eq!(
            reply.service_status.as_ref().map(|s| s.health_state.as_str()),
            Some("healthy"),
            "探针失败保守保留 SCM 派生（Running+binary_ok → healthy）"
        );
        assert_eq!(probe.self_probes.load(Ordering::Relaxed), 1);
    }

    /// ServiceControl.query：非 Running（Stopped）→ 不触发探针（A6）。
    #[tokio::test]
    async fn service_control_query_non_running_does_not_trigger_probe() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let probe = fake_probe(false);
        *probe.self_reports.lock().unwrap() = Some(fake_self_report(false, true));
        let dir = tempfile::tempdir().expect("temp dir");
        let exe = dir.path().join("exv-engine.exe");
        std::fs::write(&exe, b"engine").expect("write fake engine bin");
        let (service, _logs_dir) = service_with(&engine);
        let service = service
            .with_service_status_source(fake_status_source_with_exe(&exe, true, SERVICE_STOPPED.0))
            .with_service_probe(probe.clone());

        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Query(
                    ServiceStatusQuery {},
                )),
            }))
            .await
            .expect("query")
            .into_inner();
        assert_eq!(
            probe.self_probes.load(Ordering::Relaxed),
            0,
            "非 Running 不得触发深度自述探针（A6）"
        );
        assert_eq!(
            reply.service_status.as_ref().map(|s| s.health_state.as_str()),
            Some("installed_unavailable"),
            "Stopped → SCM 派生的 installed_unavailable（无加深）"
        );
    }

    /// 服务安装前必须先清理当前 oneshot engine；清理成功后才允许 install。
    #[tokio::test]
    async fn service_control_install_stops_active_oneshot_before_install() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let ops = Arc::new(FakeServiceOps::default());
        let (service, _logs_dir) = service_with(&engine);
        let service = service
            .with_service_ops(ops.clone() as Arc<dyn ServiceControlOps>)
            .with_service_status_source(fake_status_source(true, SERVICE_STOPPED.0))
            .with_service_probe(fake_probe(true));
        service.record_mode(ServiceMode::Oneshot);
        service.composition.lock().await.apply(HostEvent::Connect);

        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Install(ServiceInstall {})),
            }))
            .await
            .expect("install request")
            .into_inner();

        assert!(reply.ok, "stop 成功后 install 应成功");
        assert_eq!(engine.lock().await.stops.lock().unwrap().len(), 1);
        assert_eq!(ops.installs.load(Ordering::Relaxed), 1);
        assert_eq!(
            ops.starts.load(Ordering::Relaxed),
            1,
            "install bootstraps service"
        );
        assert_eq!(service.mode_string(), ServiceMode::Auto.as_wire_str());
    }

    /// 旧 engine 已掉线时，服务切换仍需完成本地 teardown；ConnectionLost 不应把
    /// admission 永久留在 closed，也不应阻止目标服务安装。
    #[tokio::test]
    async fn service_control_install_converges_when_active_oneshot_is_lost() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.owner_lease_error.lock().unwrap() =
            Some(GrpcClientError::ConnectionLost);
        let ops = Arc::new(FakeServiceOps::default());
        let (service, _logs_dir) = service_with(&engine);
        let service = service
            .with_service_ops(ops.clone() as Arc<dyn ServiceControlOps>)
            .with_service_status_source(fake_status_source(true, SERVICE_RUNNING.0));
        service.record_mode(ServiceMode::Oneshot);
        service.composition.lock().await.apply(HostEvent::Connect);

        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Install(ServiceInstall {})),
            }))
            .await
            .expect("ConnectionLost is an already-disconnected old engine")
            .into_inner();

        assert!(reply.ok, "target service install should proceed");
        assert_eq!(ops.installs.load(Ordering::Relaxed), 1);
        assert!(service.composition.lock().await.admission_open());
        assert_eq!(service.composition.lock().await.phase(), HostPhase::Idle);
    }

    /// 服务卸载前必须先清理当前 service engine；清理成功后才允许 uninstall。
    #[tokio::test]
    async fn service_control_uninstall_stops_active_service_before_uninstall() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let ops = Arc::new(FakeServiceOps::default());
        let (service, _logs_dir) = service_with(&engine);
        let service = service.with_service_ops(ops.clone() as Arc<dyn ServiceControlOps>);
        service.record_mode(ServiceMode::Service);
        service.composition.lock().await.apply(HostEvent::Connect);

        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Uninstall(
                    ServiceUninstall {},
                )),
            }))
            .await
            .expect("uninstall request")
            .into_inner();

        assert!(reply.ok, "stop 成功后 uninstall 应成功");
        assert_eq!(engine.lock().await.stops.lock().unwrap().len(), 1);
        assert_eq!(ops.uninstalls.load(Ordering::Relaxed), 1);
        assert_eq!(service.mode_string(), ServiceMode::Oneshot.as_wire_str());
        assert_eq!(
            reply.service_status.as_ref().map(|status| status.installed),
            Some(false),
            "卸载事务完成后回复必须是未安装"
        );
    }

    /// 连接失败后旧 service engine 已断线时，卸载仍必须完成本地 teardown；否则
    /// `ConnectFailed` 留下的 closed admission 会让卸载后的下一次 oneshot connect
    /// 永久得到 `connect: admission closed`。
    #[tokio::test]
    async fn service_control_uninstall_reopens_admission_after_failed_service_engine_lost() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.owner_lease_error.lock().unwrap() =
            Some(GrpcClientError::ConnectionLost);
        let ops = Arc::new(FakeServiceOps::default());
        let (service, _logs_dir) = service_with(&engine);
        let service = service.with_service_ops(ops.clone() as Arc<dyn ServiceControlOps>);
        service.record_mode(ServiceMode::Service);
        {
            let mut composition = service.composition.lock().await;
            composition.apply(HostEvent::Connect);
            composition.apply(HostEvent::ConnectFailed(wire_vpn_error_to_domain(
                &wire::VpnError::default(),
            )));
            // 模拟 engine/control-link 终止后留下的 closed admission；Failed 本身并不
            // 自动关闭 admission，真实 terminal link 会额外发 StopNewAdmission。
            composition.apply(HostEvent::StopNewAdmission);
            assert_eq!(composition.phase(), HostPhase::Failed);
            assert!(!composition.admission_open());
        }

        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Uninstall(
                    ServiceUninstall {},
                )),
            }))
            .await
            .expect("uninstall request")
            .into_inner();

        assert!(reply.ok, "disconnected failed service must still uninstall");
        assert_eq!(ops.uninstalls.load(Ordering::Relaxed), 1);
        let composition = service.composition.lock().await;
        assert_eq!(composition.phase(), HostPhase::Idle);
        assert!(composition.admission_open());
    }

    /// 旧 engine 无法停止时，服务安装必须被阻止，避免新旧 engine 并存。
    #[tokio::test]
    async fn service_control_install_rejects_when_active_oneshot_cannot_stop() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        *engine.lock().await.stop_error.lock().unwrap() = Some(GrpcClientError::Rpc(
            Code::Unavailable,
            "stop failed".to_string(),
        ));
        let ops = Arc::new(FakeServiceOps::default());
        let (service, _logs_dir) = service_with(&engine);
        let service = service.with_service_ops(ops.clone() as Arc<dyn ServiceControlOps>);
        service.record_mode(ServiceMode::Oneshot);
        service.composition.lock().await.apply(HostEvent::Connect);

        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Install(ServiceInstall {})),
            }))
            .await
            .expect("install request")
            .into_inner();

        assert!(!reply.ok, "stop 失败时 install 必须失败");
        assert_eq!(ops.installs.load(Ordering::Relaxed), 0);
    }

    /// ServiceControl：缺 action → invalid_argument。
    #[tokio::test]
    async fn service_control_rejects_missing_action() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let err = service
            .service_control(Request::new(ServiceControlRequest { action: None }))
            .await
            .expect_err("no action");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    /// ServiceControl：变更动作（install/start）走 write-path gate——未授权 → 拒绝；
    /// query 非提权读不受 gate 约束。
    #[tokio::test]
    async fn service_control_mutations_gate_requires_authorized() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let logs_dir = tempfile::tempdir().expect("logs tempdir");
        let logs =
            Arc::new(LogAggregator::open(&logs_dir.path().join("g.jsonl")).expect("open logs"));
        let (shared, service) = KernelControlService::from_composition(
            plain_composition(),
            EngineSlot::new(engine),
            PathBuf::new(),
            logs,
        );
        let service = service.with_proxy_tun_probe(no_detection_probe());
        let _ = shared;

        // 未授权：install（变更动作）被拒。
        let err = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Install(ServiceInstall {})),
            }))
            .await
            .expect_err("mutation gate rejects unauthorized");
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    // -----------------------------------------------------------------------
    // R2：wait_for_service_ready 探活轮询（SCM/keepalive 先到先采纳 + 有界超时）。
    // -----------------------------------------------------------------------

    /// R2(a)：SCM running 先到 → ready=true, source=Scm（keepalive 探活不触发）。
    #[tokio::test]
    async fn wait_for_service_ready_scm_running_wins_first() {
        let source = fake_status_source(true, SERVICE_RUNNING.0);
        let probe = fake_probe(false); // 探活永不回复也无妨——SCM running 即就位。
        let readiness = wait_for_service_ready(
            source.as_ref() as &dyn ServiceStatusSource,
            probe.as_ref() as &dyn ServiceProbe,
            Duration::from_millis(200),
            Duration::from_millis(10),
        )
        .await;
        assert!(readiness.ready, "SCM running → 就位（不死等 keepalive）");
        assert_eq!(readiness.source, ReadinessSource::Scm);
        assert_eq!(readiness.scm_state, Some(ServiceState::Running));
        assert!(!readiness.keepalive, "SCM 先到 → keepalive 未触发");
    }

    /// R2(b)：SCM 未 running（stopped）但 keepalive 回复先到 → ready=true,
    /// source=Keepalive（服务已起但 SCM 未报 Running 时探活先行）。
    #[tokio::test]
    async fn wait_for_service_ready_keepalive_wins_when_scm_not_running() {
        let source = fake_status_source(true, SERVICE_STOPPED.0);
        let probe = fake_probe(true); // 探活回复 → 就位（不等 SCM）。
        let readiness = wait_for_service_ready(
            source.as_ref() as &dyn ServiceStatusSource,
            probe.as_ref() as &dyn ServiceProbe,
            Duration::from_millis(200),
            Duration::from_millis(10),
        )
        .await;
        assert!(readiness.ready, "keepalive 回复 → 就位（不等 SCM running）");
        assert_eq!(readiness.source, ReadinessSource::Keepalive);
        assert_eq!(readiness.scm_state, Some(ServiceState::Stopped));
        assert!(readiness.keepalive, "keepalive 曾回复");
    }

    /// R2(c)：两者都未达成 → 有界到期 ready=false, source=Timeout（携带最后 SCM 状态）。
    #[tokio::test]
    async fn wait_for_service_ready_times_out_when_neither_signal() {
        let source = fake_status_source(true, SERVICE_STOPPED.0);
        let probe = fake_probe(false); // 探活永不回复。
        let readiness = wait_for_service_ready(
            source.as_ref() as &dyn ServiceStatusSource,
            probe.as_ref() as &dyn ServiceProbe,
            Duration::from_millis(50),
            Duration::from_millis(10),
        )
        .await;
        assert!(!readiness.ready, "两者都未达成 → 未就绪");
        assert_eq!(readiness.source, ReadinessSource::Timeout);
        assert_eq!(readiness.scm_state, Some(ServiceState::Stopped));
        assert!(!readiness.keepalive);
        assert!(
            readiness.elapsed_ms >= 50,
            "有界等待后返回，elapsed={}",
            readiness.elapsed_ms
        );
    }

    /// R2(d)：单次拨号探活异常挂起时，不能阻塞掉后续 SCM 轮询；外层轮询拍长必须
    /// 成为探活尝试的硬上界。
    #[tokio::test]
    async fn wait_for_service_ready_bounds_hanging_probe_to_poll_interval() {
        struct HangingProbe;
        #[tonic::async_trait]
        impl ServiceProbe for HangingProbe {
            async fn probe(&self) -> bool {
                std::future::pending::<bool>().await
            }
            async fn probe_self_report(&self) -> Option<wire::ServiceSelfReport> {
                std::future::pending::<Option<wire::ServiceSelfReport>>().await
            }
        }

        let source = fake_status_source(true, SERVICE_STOPPED.0);
        let readiness = tokio::time::timeout(
            Duration::from_millis(100),
            wait_for_service_ready(
                source.as_ref() as &dyn ServiceStatusSource,
                &HangingProbe,
                Duration::from_millis(30),
                Duration::from_millis(10),
            ),
        )
        .await
        .expect("探活挂起时 wait_for_service_ready 仍必须有界返回");
        assert!(!readiness.ready);
        assert_eq!(readiness.source, ReadinessSource::Timeout);
    }

    // -----------------------------------------------------------------------
    // R2：ServiceControl Start 后就绪探活反映在回复（ok/message/service_status）。
    // -----------------------------------------------------------------------

    /// Start 成功 + SCM running → ok=true，message 标注「服务已就绪」。
    #[tokio::test]
    async fn service_control_start_reflects_scm_ready() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let service = service
            .with_service_ops(Arc::new(FakeServiceOps::default()) as Arc<dyn ServiceControlOps>)
            .with_service_status_source(fake_status_source(true, SERVICE_RUNNING.0))
            .with_service_probe(fake_probe(false));
        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Start(ServiceStart {})),
            }))
            .await
            .expect("start")
            .into_inner();
        assert!(reply.ok, "SCM running → 就绪");
        assert!(
            reply.message.contains("服务已就绪"),
            "message={}",
            reply.message
        );
        assert_eq!(
            reply.service_status.as_ref().map(|s| s.state.as_str()),
            Some("running")
        );
    }

    /// Start 成功 + SCM 未 running 但 keepalive 回复 → ok=true，message 标注 keepalive。
    #[tokio::test]
    async fn service_control_start_reflects_keepalive_ready() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let service = service
            .with_service_ops(Arc::new(FakeServiceOps::default()) as Arc<dyn ServiceControlOps>)
            .with_service_status_source(fake_status_source(true, SERVICE_STOPPED.0))
            .with_service_probe(fake_probe(true));
        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Start(ServiceStart {})),
            }))
            .await
            .expect("start")
            .into_inner();
        assert!(reply.ok, "keepalive 回复 → 就绪");
        assert!(
            reply.message.contains("keepalive"),
            "message={}",
            reply.message
        );
    }

    /// Start 成功但两者都未达成（注入短超时）→ ok=false，message 含「服务启动超时」。
    #[tokio::test]
    async fn service_control_start_times_out_reports_failure() {
        let engine = Arc::new(tokio::sync::Mutex::new(FakeEngine::default()));
        let (service, _logs_dir) = service_with(&engine);
        let service = service
            .with_service_ops(Arc::new(FakeServiceOps::default()) as Arc<dyn ServiceControlOps>)
            .with_service_status_source(fake_status_source(true, SERVICE_STOPPED.0))
            .with_service_probe(fake_probe(false))
            .with_service_ready_timeout(Duration::from_millis(50))
            .with_service_ready_poll(Duration::from_millis(10));
        let reply = service
            .service_control(Request::new(ServiceControlRequest {
                action: Some(service_control_request::Action::Start(ServiceStart {})),
            }))
            .await
            .expect("start")
            .into_inner();
        assert!(!reply.ok, "两者都未达成 → 超时未就绪");
        assert!(
            reply.message.contains("服务启动超时"),
            "message={}",
            reply.message
        );
    }
}

/// S2-B host `run_service_batch` 单测：请求形状 / DACL / uuid 文件名 / 退出码映射 /
/// result 生命周期。fake spawn 模拟 engine 消费 req + 写 result + 删 req。
#[cfg(test)]
mod service_batch_host_tests {
    use super::*;

    /// 模拟 engine 的 fake spawner：记录调用参数与请求形状，按配置写回 result / 退出码。
    struct FakeBatchSpawn {
        /// 模拟 engine 写回的结果（`None` = 不写 result 文件，模拟结果丢失）。
        result: Option<ServiceBatchResult>,
        /// 模拟的退出码。
        exit_code: i32,
        /// 记录的调用 `(exe, args)`。
        calls: std::sync::Mutex<Vec<(PathBuf, Vec<String>)>>,
        /// 记录的请求（engine 从 req 文件读回——host 写出的真实形状）。
        requests: std::sync::Mutex<Vec<ServiceBatchRequest>>,
    }

    impl FakeBatchSpawn {
        fn succeeding() -> Self {
            Self {
                result: Some(ServiceBatchResult {
                    ok: true,
                    steps: Vec::new(),
                    message: "batch completed".to_string(),
                }),
                exit_code: 0,
                calls: std::sync::Mutex::new(Vec::new()),
                requests: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[tonic::async_trait]
    impl ServiceBatchSpawn for FakeBatchSpawn {
        async fn spawn_batch(&self, exe: &Path, args: &[String]) -> Result<i32, String> {
            self.calls
                .lock()
                .unwrap()
                .push((exe.to_path_buf(), args.to_vec()));
            let req_path = PathBuf::from(batch_arg(args, "--request"));
            let res_path = PathBuf::from(batch_arg(args, "--result"));
            // 模拟 engine：读 req（deny_unknown_fields 形状校验）→ 写 result → finally 删 req。
            let req: ServiceBatchRequest =
                serde_json::from_slice(&std::fs::read(&req_path).expect("req written by host"))
                    .expect("req JSON shape valid (deny_unknown_fields)");
            self.requests.lock().unwrap().push(req);
            if let Some(result) = &self.result {
                std::fs::write(&res_path, serde_json::to_vec(result).expect("serialize result"))
                    .expect("write result");
            }
            let _ = std::fs::remove_file(&req_path);
            Ok(self.exit_code)
        }
    }

    /// 从 spawn 记录的 args 提取 `--flag` 的值。
    fn batch_arg(args: &[String], flag: &str) -> String {
        let i = args
            .iter()
            .position(|a| a == flag)
            .unwrap_or_else(|| panic!("args must include {flag}: {args:?}"));
        args[i + 1].clone()
    }

    /// 读取文件 DACL 的 SDDL（供 DACL 生效断言；镜像 ipc `peer_auth::dacl_sddl`）。
    fn file_dacl_sddl(path: &Path) -> String {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows::Win32::Security::GetFileSecurityW;

        let wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut needed = 0u32;
        // SAFETY: 第一次只查所需长度（descriptor=None、长度 0，不写任何位置）。
        let first = unsafe {
            GetFileSecurityW(
                windows::core::PCWSTR(wide.as_ptr()),
                DACL_SECURITY_INFORMATION.0,
                None,
                0,
                &raw mut needed,
            )
        };
        if !first.as_bool() {
            // ERROR_INSUFFICIENT_BUFFER (122) 是预期的（只查长度）；其它错误为真失败。
            // SAFETY: 无指针参数，读线程错误码。
            let code = unsafe { windows::Win32::Foundation::GetLastError().0 };
            assert_eq!(code, 122, "GetFileSecurityW 尺寸查询失败，code={code}");
        }
        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: buffer 是足够大小的活缓冲；GetFileSecurityW 写入自相关 descriptor。
        let ok = unsafe {
            GetFileSecurityW(
                windows::core::PCWSTR(wide.as_ptr()),
                DACL_SECURITY_INFORMATION.0,
                Some(PSECURITY_DESCRIPTOR(buffer.as_mut_ptr().cast())),
                needed,
                &raw mut needed,
            )
        };
        assert!(ok.as_bool(), "GetFileSecurityW 读取失败");
        let mut sddl = windows::core::PWSTR::null();
        // SAFETY: descriptor 是活缓冲；sddl 是 API 分配的 out-param，用后 LocalFree。
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                PSECURITY_DESCRIPTOR(buffer.as_mut_ptr().cast()),
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut sddl,
                None,
            )
            .expect("convert file descriptor to SDDL");
        }
        let s = unsafe { sddl.to_string() }.expect("SDDL is valid UTF-16");
        // SAFETY: sddl 由转换 API 分配，须经 LocalFree 释放。
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sddl.0.cast())));
        }
        s
    }

    /// `install` → 请求序列 [Install,Start,Verify]（version==1、config_dir 绝对、uuid 文件名、
    /// engine 消费后 req 被删）。
    #[tokio::test]
    async fn run_service_batch_install_writes_install_start_verify_request() {
        let fake = FakeBatchSpawn::succeeding();
        let outcome = run_service_batch(
            vec![BatchStep::Install, BatchStep::Start, BatchStep::Verify],
            &fake,
        )
        .await;
        assert_eq!(outcome.as_deref(), Ok("batch completed"));
        let (exe, args) = &fake.calls.lock().unwrap()[0];
        assert_eq!(exe, &engine_bin_path().expect("engine bin"));
        assert_eq!(args[0], "--service-batch");
        let req_path = PathBuf::from(batch_arg(args, "--request"));
        let req_name = req_path
            .file_name()
            .expect("req filename")
            .to_string_lossy()
            .into_owned();
        assert!(req_name.starts_with("exv-batch-req-"), "uuid 文件名: {req_name}");
        assert!(req_name.ends_with(".json"));
        let req = &fake.requests.lock().unwrap()[0];
        assert_eq!(req.version, 1, "version 必须为 1");
        assert_eq!(
            req.sequence,
            vec![BatchStep::Install, BatchStep::Start, BatchStep::Verify]
        );
        assert!(
            Path::new(&req.config_dir).is_absolute(),
            "config_dir 必须绝对: {}",
            req.config_dir
        );
        assert!(!req_path.exists(), "engine 消费 req 后删除（finally）");
    }

    /// `start` → 请求序列 [Start,Verify]。
    #[tokio::test]
    async fn run_service_batch_start_writes_start_verify_request() {
        let fake = FakeBatchSpawn::succeeding();
        run_service_batch(vec![BatchStep::Start, BatchStep::Verify], &fake)
            .await
            .expect("start batch succeeds");
        let req = &fake.requests.lock().unwrap()[0];
        assert_eq!(req.sequence, vec![BatchStep::Start, BatchStep::Verify]);
    }

    /// `uninstall` → 请求序列 [Uninstall,VerifyRemoved]。
    #[tokio::test]
    async fn run_service_batch_uninstall_writes_uninstall_verify_removed_request() {
        let fake = FakeBatchSpawn::succeeding();
        run_service_batch(vec![BatchStep::Uninstall, BatchStep::VerifyRemoved], &fake)
            .await
            .expect("uninstall batch succeeds");
        let req = &fake.requests.lock().unwrap()[0];
        assert_eq!(
            req.sequence,
            vec![BatchStep::Uninstall, BatchStep::VerifyRemoved]
        );
    }

    /// `--host-pid` 必须携带自身 pid（孤儿 watchdog 由 S2-C 接线，本任务只传值）。
    #[tokio::test]
    async fn run_service_batch_passes_own_host_pid() {
        let fake = FakeBatchSpawn::succeeding();
        run_service_batch(vec![BatchStep::Start], &fake)
            .await
            .expect("batch succeeds");
        let (_, args) = &fake.calls.lock().unwrap()[0];
        let pid = batch_arg(args, "--host-pid");
        assert_eq!(pid, std::process::id().to_string(), "必须传自身 pid");
        assert_ne!(pid, "0", "pid 不得为 0");
    }

    /// `exit 0 + result.ok=true` → 成功；`exit 非零`（即使 result.ok=true）→ 失败（message 透传）。
    #[tokio::test]
    async fn run_service_batch_exit_nonzero_fails_despite_ok_result() {
        let fake = FakeBatchSpawn {
            result: Some(ServiceBatchResult {
                ok: true,
                steps: Vec::new(),
                message: "batch completed".to_string(),
            }),
            exit_code: 3,
            calls: std::sync::Mutex::new(Vec::new()),
            requests: std::sync::Mutex::new(Vec::new()),
        };
        let err = run_service_batch(vec![BatchStep::Start], &fake)
            .await
            .expect_err("exit 非零必须失败");
        assert!(err.contains("batch completed"), "message 透传: {err}");
    }

    /// `exit 0 + result.ok=false` → 失败（message 透传）。
    #[tokio::test]
    async fn run_service_batch_result_not_ok_fails() {
        let fake = FakeBatchSpawn {
            result: Some(ServiceBatchResult {
                ok: false,
                steps: Vec::new(),
                message: "step 1 (install) failed: boom".to_string(),
            }),
            exit_code: 0,
            calls: std::sync::Mutex::new(Vec::new()),
            requests: std::sync::Mutex::new(Vec::new()),
        };
        let err = run_service_batch(vec![BatchStep::Install], &fake)
            .await
            .expect_err("result ok=false 必须失败");
        assert!(err.contains("boom"), "message 透传: {err}");
    }

    /// result 文件缺失（engine 异常退出未写）→ 失败。
    #[tokio::test]
    async fn run_service_batch_missing_result_file_fails() {
        let fake = FakeBatchSpawn {
            result: None,
            exit_code: 0,
            calls: std::sync::Mutex::new(Vec::new()),
            requests: std::sync::Mutex::new(Vec::new()),
        };
        let err = run_service_batch(vec![BatchStep::Start], &fake)
            .await
            .expect_err("result 缺失必须失败");
        assert!(err.contains("read batch result"), "got {err}");
    }

    /// result 文件解析后由 host 删除。
    #[tokio::test]
    async fn run_service_batch_deletes_result_file_after_parse() {
        let fake = FakeBatchSpawn::succeeding();
        run_service_batch(vec![BatchStep::Start], &fake)
            .await
            .expect("batch succeeds");
        let (_, args) = &fake.calls.lock().unwrap()[0];
        let res_path = PathBuf::from(batch_arg(args, "--result"));
        assert!(!res_path.exists(), "result 文件由 host 读后删除");
    }

    /// req 文件 DACL 生效：SYSTEM + 当前用户（其余拒绝，无广泛主体、无继承残留）。
    #[test]
    fn write_batch_request_file_sets_system_and_user_dacl() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("req.json");
        let request = ServiceBatchRequest {
            version: 1,
            sequence: vec![BatchStep::Start],
            config_dir: r"C:\Users\Alice\.exv".to_string(),
        };
        write_batch_request_file(&path, &request).expect("write request");
        let user = current_user_sid().expect("current user sid");
        let sddl = file_dacl_sddl(&path);
        assert!(sddl.contains(&user), "DACL 必须授当前用户 SID: {sddl}");
        assert!(sddl.contains("SY"), "DACL 必须授 SYSTEM: {sddl}");
        assert!(
            !sddl.contains("IU") && !sddl.contains("BU") && !sddl.contains("AU"),
            "DACL 不得含广泛主体（Interactive/Builtin/Authenticated Users）: {sddl}"
        );
        // 形状往返：写入的 JSON 在 deny_unknown_fields 下无多余字段。
        let bytes = std::fs::read(&path).expect("read request back");
        let parsed: ServiceBatchRequest =
            serde_json::from_slice(&bytes).expect("request JSON round-trips");
        assert_eq!(parsed, request, "请求字节往返一致");
    }

    /// `friendly_service_message` 把 `"batch completed"` 按 action 替换为人类可读文案。
    #[test]
    fn friendly_service_message_replaces_batch_completed() {
        assert_eq!(friendly_service_message("install", "batch completed"), "服务安装完成并已启动。");
        assert_eq!(friendly_service_message("uninstall", "batch completed"), "服务卸载完成。");
        assert_eq!(friendly_service_message("start", "batch completed"), "服务已启动。");
        // 未知 action → 原样返回。
        assert_eq!(friendly_service_message("unknown", "batch completed"), "batch completed");
        // 非 "batch completed" 消息原样透传（失败原因等）。
        assert_eq!(
            friendly_service_message("uninstall", "step 1 (uninstall) failed: boom"),
            "step 1 (uninstall) failed: boom"
        );
    }
}
