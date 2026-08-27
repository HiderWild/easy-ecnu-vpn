// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! engine 子进程监督（P3-c2：engine 由 core 拉起，core 停机时 engine 一并终止）。
//!
//! [`EngineSupervisor`] 是 core 对 engine 子进程的监督句柄：
//!
//! - **spawn**：[`EngineSupervisor::spawn_product`] 经可注入的 [`EngineSpawner`]（真实 =
//!   ShellExecuteExW(runas) 提权）拉起 engine，并做**拓扑门禁**——engine 必须 elevated
//!   （engine 是唯一特权进程；非提权即拒绝并终止）。
//! - **connect 接入**：[`EngineSupervisor::attach_client`] 挂接共享 gRPC 控制面客户端
//!   （`Arc<Mutex<dyn KernelEngineControl>>`，与 `KernelControlService` 共享）与掉线
//!   liveness 接收端（`watch::Receiver<bool>`，`EngineControlGrpcClient` 的 pub 字段）。
//! - **stop（D1 解耦，判据 8）**：[`EngineSupervisor::stop`] **发退出包**（`StopTunnel`
//!   业务停机，若已连接）后**即返**——不再 wait_exit 等 engine 自退（engine 回 Idle
//!   常驻，由退出包 / core 进程句柄 / 心跳（P2）三重保证随 core 退出）。UI 只等 core
//!   退、不等 engine 退（无递归等待，UI 关闭即时响应）。有界等待/强制终止降为崩溃
//!   恢复/验证路径（[`EngineSupervisor::verify_exit`]，P3 respawn 前回收旧 engine 用）。
//!
//! engine 意外死亡由 liveness 监测（`EngineControlGrpcClient` 后台监视 + 状态转发器
//! `spawn_status_forwarder` 断线重放）感知；本模块暴露 liveness 接收端供
//! `CoreRuntime` 在运行期驱动 `composition.on_helper_link_terminal`（P3-c2 接线）。

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{Mutex, watch};
use windows::Win32::Foundation::HANDLE;

use exv_vpn_wire::generated::StopTunnelRequest;

use crate::grpc_control::KernelEngineControl;
use crate::process_lifecycle::{
    EngineChild, engine_args_for_spawn, engine_bin_path, spawn_engine_elevated,
    verify_process_elevated,
};

/// 共享 engine 控制面槽（P3 崩溃自愈的换点）。
///
/// 服务（`KernelControlService`）、状态/统计/日志转发器与 KeepAlive tick 任务共享同一
/// `EngineSlot`；engine respawn 后经 [`EngineSlot::swap`] 换入新 client——转发器在下一轮
/// 重连即从 [`EngineSlot::current`] 拿到新 engine，无需 abort/重拉转发器。
#[derive(Clone)]
pub struct EngineSlot {
    inner: Arc<tokio::sync::Mutex<Arc<Mutex<dyn KernelEngineControl>>>>,
    initial: Arc<Mutex<dyn KernelEngineControl>>,
    generation: Arc<AtomicU64>,
    swaps: watch::Sender<u64>,
}

impl EngineSlot {
    /// 用初始 engine 控制面构造。
    #[must_use]
    pub fn new(engine: Arc<Mutex<dyn KernelEngineControl>>) -> Self {
        let (swaps, _) = watch::channel(0);
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(Arc::clone(&engine))),
            initial: engine,
            generation: Arc::new(AtomicU64::new(0)),
            swaps,
        }
    }

    /// Core 启动时的初始 oneshot engine。service 路由换点后，卸载服务可恢复此控制面。
    #[must_use]
    pub fn initial(&self) -> Arc<Mutex<dyn KernelEngineControl>> {
        Arc::clone(&self.initial)
    }

    /// 当前 engine 控制面 Arc（RPC 前取；respawn 后为最新）。
    pub async fn current(&self) -> Arc<Mutex<dyn KernelEngineControl>> {
        self.inner.lock().await.clone()
    }

    /// 订阅 engine 控制面换点通知（服务/respawn 路由切换状态流时使用）。
    pub fn subscribe_swaps(&self) -> watch::Receiver<u64> {
        self.swaps.subscribe()
    }

    /// 换入新 engine 控制面（respawn/service 路径）。返回是否真的发生换点；相同
    /// 控制面重复设置不制造无意义的状态流重连。
    pub async fn swap(&self, engine: Arc<Mutex<dyn KernelEngineControl>>) -> bool {
        let mut current = self.inner.lock().await;
        if Arc::ptr_eq(&*current, &engine) {
            return false;
        }
        *current = engine;
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        let _ = self.swaps.send(generation);
        true
    }
}

/// engine 提权 spawn 的可注入 seam（测试注入 fake，无真实 UAC）。
pub trait EngineSpawner: Send + Sync {
    /// 提权 spawn engine bin，返回 `(pid, handle)`。
    fn spawn(&self, exe: &Path, args: &[String]) -> Result<(u32, HANDLE), String>;
}

/// 真实 spawner：ShellExecuteExW(runas) 提权（engine 是唯一特权进程）。
pub struct ElevatedEngineSpawner;

impl EngineSpawner for ElevatedEngineSpawner {
    fn spawn(&self, exe: &Path, args: &[String]) -> Result<(u32, HANDLE), String> {
        spawn_engine_elevated(exe, args)
    }
}

/// engine spawn 失败（拓扑门禁 fail closed）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineSpawnError {
    /// engine bin 无法定位（未构建 / 部署缺失）。
    BinNotFound,
    /// 提权 spawn 失败（携带原因）。
    SpawnFailed(String),
    /// 拓扑门禁：engine token 非 elevated——engine 是唯一特权进程，非特权拒绝。
    ElevationRejected,
}

impl std::fmt::Display for EngineSpawnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BinNotFound => write!(f, "engine bin not found"),
            Self::SpawnFailed(reason) => write!(f, "engine spawn failed: {reason}"),
            Self::ElevationRejected => {
                write!(f, "engine elevation rejected (engine must be privileged)")
            }
        }
    }
}

impl std::error::Error for EngineSpawnError {}

/// engine 停机结果（`EngineSupervisor::stop` / `shutdown_core` 的 engine 侧事实）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineShutdownOutcome {
    /// 退出包（`StopTunnel` 业务停机）已发出（fire-and-forget，未等 engine 退出）——
    /// engine 回 Idle 常驻，由退出包 / core 进程句柄 / 心跳（P2）三重保证随 core 退出。
    /// UI 只等 core 退、不等 engine 退（判据 8）。
    ExitPacketSent,
    /// engine 未连接（无共享控制面客户端）——无退出包可发；core 退出后 engine 由
    /// 进程句柄（engine 侧 `wait_core_process_exit`）兜底随行。
    NoClient,
    /// 崩溃恢复/验证路径（`verify_exit`）：有界等待退出成功（engine 干净退出）。
    CleanExit,
    /// 崩溃恢复/验证路径（`verify_exit`）：有界等待超时后强制终止。
    Terminated,
}

/// core 对 engine 子进程的监督句柄。
pub struct EngineSupervisor {
    /// engine 子进程（pid + handle）；engine 已退出后为 `None`。
    child: Option<EngineChild>,
    /// 共享 gRPC 控制面客户端（与 `KernelControlService` 共享；`None` = 未连接/已释放）。
    client: Option<Arc<Mutex<dyn KernelEngineControl>>>,
    /// engine 掉线 liveness 接收端（`EngineControlGrpcClient::liveness` 的 clone；
    /// 运行期驱动 `on_helper_link_terminal`）。
    liveness: Option<watch::Receiver<bool>>,
}

impl EngineSupervisor {
    /// 提权拉起 engine 并做拓扑门禁（elevated 验证）。
    ///
    /// 流程：定位 bin → 构造参数 → spawner 提权拉起 → 观测 engine token 必须 elevated；
    /// 任一失败即 terminate 已拉起进程并返回 typed 错误（fail closed）。
    ///
    /// # Errors
    /// [`EngineSpawnError::BinNotFound`] / [`EngineSpawnError::SpawnFailed`] /
    /// [`EngineSpawnError::ElevationRejected`]。
    pub fn spawn_product(spawner: &dyn EngineSpawner) -> Result<Self, EngineSpawnError> {
        let Some(exe) = engine_bin_path() else {
            return Err(EngineSpawnError::BinNotFound);
        };
        // 存在性门禁：bin 未构建/部署缺失时 fail fast——`engine_bin_path` 的 fallback
        // 只拼路径不验存在，缺失时直接 runas 会弹 UAC 或挂起（应确定性报 BinNotFound）。
        if !exe.exists() {
            return Err(EngineSpawnError::BinNotFound);
        }
        let args = engine_args_for_spawn();
        let (pid, handle) = spawner
            .spawn(&exe, &args)
            .map_err(EngineSpawnError::SpawnFailed)?;
        let mut child = EngineChild::new(pid, handle);
        if !verify_process_elevated(pid) {
            child.terminate();
            return Err(EngineSpawnError::ElevationRejected);
        }
        Ok(Self {
            child: Some(child),
            client: None,
            liveness: None,
        })
    }

    /// 用既有子进程构造（测试/恢复路径；elevation 按需由调用方观测）。
    #[must_use]
    pub fn with_child(child: EngineChild) -> Self {
        Self {
            child: Some(child),
            client: None,
            liveness: None,
        }
    }

    /// 挂接共享控制面客户端 + 掉线 liveness 接收端（connect 成功后调用）。
    ///
    /// `client` 与 `KernelControlService` 共享同一 `Arc`——停机时先释放服务侧引用
    /// （drop 服务任务），再经 [`EngineSupervisor::stop`] 释放本侧引用，管道即关闭。
    pub fn attach_client(
        &mut self,
        client: Arc<Mutex<dyn KernelEngineControl>>,
        liveness: watch::Receiver<bool>,
    ) {
        self.client = Some(client);
        self.liveness = Some(liveness);
    }

    /// engine 子进程 PID（未拉起/已退出 → `None`）。
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(EngineChild::pid)
    }

    /// 共享控制面客户端引用（服务接线用）。
    #[must_use]
    pub fn client(&self) -> Option<&Arc<Mutex<dyn KernelEngineControl>>> {
        self.client.as_ref()
    }

    /// engine 掉线 liveness 接收端（运行期 `on_helper_link_terminal` 驱动用）。
    #[must_use]
    pub fn liveness(&self) -> Option<watch::Receiver<bool>> {
        self.liveness.clone()
    }

    /// 有序停止 engine（D1 解耦 / 判据 8）：发**退出包**（`StopTunnel` 业务停机，若已
    /// 连接）后**即返**——不再 wait_exit 等 engine 自退（engine 回 Idle 常驻，由退出包
    /// / core 进程句柄 / 心跳（P2）三重保证随 core 退出）。
    ///
    /// 关闭级联（UX）：UI 关 → 通知 core → 本方法发退出包 → `composition.exit()` →
    /// core 进程退出 → **UI 只等 core 退即关**；engine 由三重保证自行退出，core 停机链
    /// 不再递归等 engine 退。
    ///
    /// `self` 按值消费；child 句柄保持打开（`EngineChild::Drop` 是 O3 兜底——正常 core
    /// 经 `process::exit` 退出不跑析构，engine 经自身进程句柄等待干净随行；仅异常/测试
    /// 路径 Drop 强制终止，engine 不得遗留）。
    pub async fn stop(mut self) -> EngineShutdownOutcome {
        // 发退出包：经共享客户端发 StopTunnel（best-effort；engine 已死则忽略）。
        // fire-and-forget——只发业务停机包，不等 engine 进程退出。
        if let Some(client) = self.client.take() {
            let mut guard = client.lock().await;
            let _ = guard
                .stop_tunnel(StopTunnelRequest::default())
                .await
                .map_err(|_| ());
            drop(guard);
            EngineShutdownOutcome::ExitPacketSent
        } else {
            EngineShutdownOutcome::NoClient
        }
    }

    /// 崩溃恢复/验证路径：有界等待 engine 退出 → 超时强制终止（engine 不得遗留）。
    ///
    /// **UI 关闭路径不调用本方法**（[`EngineSupervisor::stop`] 已 fire-and-forget）——
    /// 仅崩溃恢复/验证时使用（如 P3 respawn 前回收旧 engine：确认旧 engine 已退出或
    /// 强制终止，再拉起新实例）。
    pub fn verify_exit(&mut self, wait_timeout_ms: u32) -> EngineShutdownOutcome {
        let outcome = if let Some(child) = &mut self.child {
            if child.wait_exit(wait_timeout_ms) {
                EngineShutdownOutcome::CleanExit
            } else {
                child.terminate();
                EngineShutdownOutcome::Terminated
            }
        } else {
            EngineShutdownOutcome::CleanExit
        };
        // child 已退出/terminate → 置 None（句柄已关闭）。
        self.child = None;
        outcome
    }

    /// 强制终止 engine（失败/异常路径兜底；幂等）。
    pub fn terminate(&mut self) {
        if let Some(child) = &mut self.child {
            child.terminate();
        }
        self.child = None;
    }
}

// ---------------------------------------------------------------------------
// 单元测试：spawn 失败路径（fake spawner）+ stop 顺序（fake client + 无真实子进程——
// 进程级 wait/terminate 由集成测试覆盖）。
// ---------------------------------------------------------------------------

/// 测试共享基建（`shutdown` 测试复用）：记录型 fake engine 控制面 + 占位 child。
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::grpc_control::{
        EngineStatusEventStream, GrpcClientError, LogEventStream, StatsEventStream,
    };
    use crate::kernel_control::ClearableSecret;
    use exv_vpn_wire::generated::{
        ApplyTunnelReply, ApplyTunnelRequest, GetOperationReply, GetOperationRequest,
        InteractionResponse, KeepAliveReply, KeepAliveRequest, ObserveOwnedStateReply,
        ObserveOwnedStateRequest, OperationReply, ReconcileRequest, ServiceManageReply,
        ServiceManageRequest, StopTunnelReply, StopTunnelRequest,
    };

    /// 记录型 fake engine 控制面（记录 stop 调用；其余 typed 拒绝/占位）。
    pub struct RecordingEngine {
        pub stops: std::sync::Mutex<Vec<StopTunnelRequest>>,
    }

    #[tonic::async_trait]
    impl KernelEngineControl for RecordingEngine {
        async fn ensure_owner_lease(&mut self) -> Result<(), GrpcClientError> {
            // fake：无真实 lease 语义——幂等成功（真实实现做 MaintainOwnerLease 握手）。
            Ok(())
        }

        async fn apply_connect(
            &mut self,
            _request: ApplyTunnelRequest,
            secret_payload: &mut ClearableSecret,
        ) -> Result<ApplyTunnelReply, GrpcClientError> {
            // 契约：发送后零化槽（镜像真实实现）。
            secret_payload.clear();
            Ok(ApplyTunnelReply { result: None })
        }

        async fn stop_tunnel(
            &mut self,
            request: StopTunnelRequest,
        ) -> Result<StopTunnelReply, GrpcClientError> {
            self.stops.lock().unwrap().push(request);
            Ok(StopTunnelReply { result: None })
        }

        async fn get_operation(
            &mut self,
            _request: GetOperationRequest,
        ) -> Result<GetOperationReply, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in test".to_string(),
            ))
        }

        async fn observe_owned_state(
            &mut self,
            _request: ObserveOwnedStateRequest,
        ) -> Result<ObserveOwnedStateReply, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in test".to_string(),
            ))
        }

        async fn service_manage(
            &mut self,
            _request: ServiceManageRequest,
        ) -> Result<ServiceManageReply, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in test".to_string(),
            ))
        }

        async fn keep_alive(
            &mut self,
            _request: KeepAliveRequest,
        ) -> Result<KeepAliveReply, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in test".to_string(),
            ))
        }

        async fn stream_connect_status(
            &mut self,
        ) -> Result<EngineStatusEventStream, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in test".to_string(),
            ))
        }

        async fn stream_stats(
            &mut self,
            _sample_interval_ms: u32,
        ) -> Result<StatsEventStream, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in test".to_string(),
            ))
        }

        async fn stream_logs(
            &mut self,
            _resume_tick: u64,
        ) -> Result<LogEventStream, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in test".to_string(),
            ))
        }

        async fn respond_interaction(
            &mut self,
            _response: InteractionResponse,
        ) -> Result<OperationReply, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in test".to_string(),
            ))
        }

        async fn retry_obligation(
            &mut self,
            _request: ReconcileRequest,
        ) -> Result<GetOperationReply, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in test".to_string(),
            ))
        }
    }

    /// 无真实子进程的占位 child（单元测试仅验证 stop 的顺序逻辑；进程级
    /// wait/terminate 由集成测试用真实 child 覆盖）。0 句柄仅作占位；stop 路径不触碰
    /// 它（child 为 None 路径或 wait 短路）。
    #[must_use]
    pub fn fake_child() -> EngineChild {
        EngineChild::new(0, HANDLE::default())
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{RecordingEngine, fake_child};
    use super::*;

    /// spawn 失败路径（fail-closed typed 拒绝，两条路径都覆盖）：
    /// bin 缺失（`engine_bin_path` 解析出的 sibling 不存在——测试流 deps 目录常无
    /// engine bin）→ 存在性门禁拦截 → `BinNotFound`；bin 存在但 spawner 拒绝 →
    /// `SpawnFailed`。两种结果都是合法 typed 拒绝，断言不允许第三种。
    #[test]
    fn spawn_product_bin_not_found_or_spawner_fails() {
        struct FailSpawner;
        impl EngineSpawner for FailSpawner {
            fn spawn(&self, _exe: &Path, _args: &[String]) -> Result<(u32, HANDLE), String> {
                Err("shell execute refused".to_string())
            }
        }
        let err = EngineSupervisor::spawn_product(&FailSpawner)
            .err()
            .expect("spawn must fail");
        match err {
            EngineSpawnError::BinNotFound => {
                // 门禁拦截（bin 缺失）：确定性 fail fast，不触碰 runas。
            }
            EngineSpawnError::SpawnFailed(_) => {
                // bin 存在但 spawner 拒绝。
            }
            other => panic!("unexpected error classification: {other:?}"),
        }
    }

    /// D1 解耦 / 判据 8：`stop` 发退出包（`StopTunnel` 恰好一次）后**即返**——不等待
    /// engine 退出、不触发 terminate 兜底（fire-and-forget；无 Terminated 出现）。
    #[tokio::test]
    async fn stop_fires_exit_packet_and_returns_immediately() {
        let engine = Arc::new(Mutex::new(RecordingEngine {
            stops: std::sync::Mutex::new(Vec::new()),
        }));
        let (tx, _rx) = watch::channel(true);
        let mut supervisor = EngineSupervisor::with_child(fake_child());
        supervisor.attach_client(engine.clone(), tx.subscribe());

        let outcome = supervisor.stop().await;
        // 业务退出包（StopTunnel）恰好一次。
        assert_eq!(engine.lock().await.stops.lock().unwrap().len(), 1);
        // fire-and-forget：发退出包即返，无 Terminated 兜底触发。
        assert_eq!(
            outcome,
            EngineShutdownOutcome::ExitPacketSent,
            "stop 发退出包后即返（UI 只等 core，不等 engine 退）——不得出现 Terminated"
        );
        let _ = tx;
    }

    /// D1 解耦：engine 未连接（无共享 client）→ `stop` 无退出包可发 → `NoClient`
    ///（core 退出后 engine 由进程句柄兜底随行）。
    #[tokio::test]
    async fn stop_without_client_reports_no_client() {
        let supervisor = EngineSupervisor::with_child(fake_child());
        let outcome = supervisor.stop().await;
        assert_eq!(
            outcome,
            EngineShutdownOutcome::NoClient,
            "未连接时无退出包可发 → NoClient（不出现 Terminated）"
        );
    }

    /// 崩溃恢复/验证路径：`verify_exit` 有界等待/终止（与 UI 关闭路径的 fire-and-forget
    /// 分离）。fake child（占位 0 句柄）wait 失败 → 超时强制终止（engine 不得遗留）。
    #[tokio::test]
    async fn verify_exit_bounded_wait_or_terminate() {
        let mut supervisor = EngineSupervisor::with_child(fake_child());
        let outcome = supervisor.verify_exit(1);
        assert_eq!(
            outcome,
            EngineShutdownOutcome::Terminated,
            "fake child（0 句柄）无法干净退出 → Terminated（崩溃恢复路径的强制终止兜底）"
        );
    }
}
