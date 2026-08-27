// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core 进程生命周期（P3-c2 / D1 解耦）：启动 → 拉起 engine → 运行 → 停机（发退出包）
//! → core 退出 → engine 由三重保证随行退出。
//!
//! 本模块是 core 的生命周期编排：
//!
//! - [`UiLifetime`]：UI 生命周期信号（**O3 强绑定**）——UI 最小化到托盘区**不视作退出**
//!   （UI 进程仍存活、连接仍在 → 信号保持 `true`）；UI **彻底退出**（进程退出 / 传输层
//!   掉线 / 显式通知）→ 信号翻转为 `false` → core 发起停机。
//! - [`CoreRuntime`]：运行期编排——持有 UI 信号、共享 composition、engine 监督句柄与
//!   KernelControl 服务/转发器任务；[`CoreRuntime::run`] 等待 UI 退出（或显式停机命令）后
//!   执行有序停机；运行期监听 engine 掉线（liveness）→ 驱动
//!   `composition.on_helper_link_terminal`（engine 死亡 ≠ core 死亡：撤销 admission +
//!   teardown，core 继续服务 UI 直到 UI 退出）。
//! - [`shutdown_core`]：**有序停机**（D1 解耦 / 判据 8——UI 只等 core 不等 engine）：
//!   1. 停止接收 UI 请求（`serving` 翻 false + 中止服务任务 + 取消待决 RPC waiter——
//!      `composition.on_rpc_waiter_cancel`，RPC cancel ≠ 业务 Stop，spec §8.3/§9.1）；
//!   2. engine **发退出包**（`StopTunnel` 业务停机，若在连）后即返——不等 engine 退；
//!   3. `composition.exit()`（幂等业务 Stop，关 admission，撤 packet leg）→ core 退出。
//!   退出包 / core 进程句柄 / 心跳（P2）三重保证 engine 随 core 退出；有界等待/强制
//!   终止降为崩溃恢复/验证路径（`EngineSupervisor::verify_exit`）。

use std::sync::Arc;

use tokio::sync::{watch, Mutex};

use crate::composition::HostComposition;
use crate::crash_recovery::CrashRecovery;
use crate::engine_lifecycle::{EngineShutdownOutcome, EngineSupervisor};

/// UI 生命周期信号（O3 强绑定）。
///
/// `true` = UI 存活（最小化到托盘仍存活——UI 进程与连接未断）；`false` = UI 彻底退出。
/// [`UiLifetime::on_ui_exited`] 由 P4 的 UI 传输层在连接掉线 / 窗口彻底关闭时调用。
#[derive(Clone)]
pub struct UiLifetime {
    tx: watch::Sender<bool>,
    rx: watch::Receiver<bool>,
}

impl UiLifetime {
    /// 构造：初始 `true`（UI 已连接/存活）。
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = watch::channel(true);
        Self { tx, rx }
    }

    /// UI 是否存活（当前信号值）。
    #[must_use]
    pub fn is_ui_alive(&self) -> bool {
        *self.rx.borrow()
    }

    /// UI 彻底退出（传输层掉线 / 窗口关闭）→ 信号翻 false → core 停机。
    pub fn on_ui_exited(&self) {
        let _ = self.tx.send(false);
    }

    /// 存活信号接收端（`CoreRuntime::run` 等待 UI 退出）。
    #[must_use]
    pub fn receiver(&self) -> watch::Receiver<bool> {
        self.rx.clone()
    }
}

impl Default for UiLifetime {
    fn default() -> Self {
        Self::new()
    }
}

/// core 停机结果（顺序契约的可观测事实）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreShutdownOutcome {
    /// engine 侧事实（D1 后 = 退出包已发 / 无 client；CleanExit/Terminated 仅崩溃
    /// 恢复/验证路径出现）。
    pub engine: EngineShutdownOutcome,
    /// composition 发出的业务 Stop 计数（唯一业务取消是 `exit()`——必须恰好 1）。
    pub stop_requests: u64,
    /// RPC waiter 取消计数（停机时取消待决 waiter——RPC cancel ≠ Stop）。
    pub rpc_waiter_cancellations: u64,
    /// 有界完整 teardown 是否已启动。
    pub teardown_started: bool,
}

/// 有序停机（D1 解耦 / 判据 8：UI 只等 core，不等 engine）。
///
/// 顺序（不可交换，测试钉死）：
/// 1. **停止接收 UI 请求**：取消待决 RPC waiter（`composition.on_rpc_waiter_cancel`——
///    记录取消，不改变业务状态；真正的业务取消只来自 `exit()`）。
/// 2. **engine 发退出包**：`EngineSupervisor::stop`——`StopTunnel` 业务停机（若在连）后
///    **即返**，不再有界等待 engine 退出/强制终止（engine 回 Idle 常驻，由退出包 / core
///    进程句柄 / 心跳（P2）三重保证随 core 退出）。
/// 3. **core 退出**：`composition.exit()`——幂等业务 Stop、关闭 admission、撤销 packet leg。
///
/// **R2 (a) CleanExit→synthesize 收敛保留在崩溃路径**：engine 异常死亡（状态流 EOF）时由
/// 状态转发器（`kernel_control_service::spawn_status_forwarder`）合成数据面侧加入收敛
/// Stopped/Idle；UI 关闭路径不等待 engine、不观测 CleanExit，故此处不再合成（core 即将
/// 退出，无收敛必要）。
///
/// 调用方须在进入本函数前 drop 服务任务 / 事件转发器（释放对共享 engine client 的引用）。
pub async fn shutdown_core(
    supervisor: EngineSupervisor,
    composition: &Arc<Mutex<HostComposition>>,
) -> CoreShutdownOutcome {
    // 1. 取消待决 RPC waiter（RPC cancel ≠ 业务 Stop：只记录，不改业务状态）。
    {
        let mut comp = composition.lock().await;
        comp.on_rpc_waiter_cancel();
    }
    // 2. engine 发退出包（fire-and-forget；不等待 engine 退出）。
    let engine = supervisor.stop().await;
    // 3. composition.exit()（幂等业务 Stop）。
    let mut comp = composition.lock().await;
    comp.exit();
    let stop_requests = comp.stop_requests();
    let rpc_waiter_cancellations = comp.rpc_waiter_cancellations();
    let teardown_started = comp.teardown_started();
    CoreShutdownOutcome {
        engine,
        stop_requests,
        rpc_waiter_cancellations,
        teardown_started,
    }
}

/// core 运行期（进程级编排）。
///
/// 生命周期：**启动**（外部先 compose + spawn + connect + 挂接服务/转发器）→
/// [`CoreRuntime::run`] 运行（等 UI 退出 / 显式停机；监听 engine 掉线）→ 有序停机
/// （发退出包后即返）→ 返回 [`CoreShutdownOutcome`]（core 退出；engine 由三重保证随行）。
pub struct CoreRuntime {
    /// UI 生命周期信号（O3 强绑定）。
    ui: UiLifetime,
    /// 服务开关：`true` = 接收 UI 请求；停机置 `false`（P4 传输层据此拒绝新请求）。
    serving_tx: watch::Sender<bool>,
    serving_rx: watch::Receiver<bool>,
    /// 显式停机命令（UI 发 stop / 系统信号；`request_shutdown`）。
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
    /// 共享 host composition（与 `KernelControlService` 共享同一 Arc）。
    composition: Arc<Mutex<HostComposition>>,
    /// engine 子进程监督句柄。
    supervisor: EngineSupervisor,
    /// KernelControl 服务任务（P4 传输层；停机先中止 = 停止接收 UI 请求）。
    serve_task: Option<tokio::task::JoinHandle<()>>,
    /// 事件转发器任务（持 engine client 引用；停机先中止释放引用）。
    forwarder_task: Option<tokio::task::JoinHandle<()>>,
    /// P5-b 统计转发器任务（持 engine client 引用；停机先中止释放引用）。
    stats_forwarder_task: Option<tokio::task::JoinHandle<()>>,
    /// R3 日志转发器任务（持 engine client 引用 + 日志聚合器引用；停机先中止释放引用）。
    logs_forwarder_task: Option<tokio::task::JoinHandle<()>>,
    /// C3a 自动重连 worker 任务（持服务克隆；停机先中止释放引用——否则 worker 永久
    /// 引用服务克隆）。
    reconnect_worker_task: Option<tokio::task::JoinHandle<()>>,
    /// P2 KeepAlive 心跳 tick 任务（持 engine client 引用；停机先中止释放引用——engine
    /// 侧据此刷新 `last_heartbeat`，15s 未收到即自清理+自退出）。
    keepalive_ticker_task: Option<tokio::task::JoinHandle<()>>,
    /// P3 崩溃自愈编排（engine 掉线 → respawn 全链路）；`None` = 不自愈（测试/降级）。
    crash_recovery: Option<CrashRecovery>,
}

impl CoreRuntime {
    /// 构造运行期。
    #[must_use]
    pub fn new(
        ui: UiLifetime,
        composition: Arc<Mutex<HostComposition>>,
        supervisor: EngineSupervisor,
    ) -> Self {
        let (serving_tx, serving_rx) = watch::channel(true);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            ui,
            serving_tx,
            serving_rx,
            shutdown_tx,
            shutdown_rx,
            composition,
            supervisor,
            serve_task: None,
            forwarder_task: None,
            stats_forwarder_task: None,
            logs_forwarder_task: None,
            reconnect_worker_task: None,
            keepalive_ticker_task: None,
            crash_recovery: None,
        }
    }

    /// UI 生命周期信号句柄。
    #[must_use]
    pub fn ui(&self) -> &UiLifetime {
        &self.ui
    }

    /// 共享 composition（对外驱动 `on_helper_link_terminal` / `exit` 或断言）。
    #[must_use]
    pub fn composition(&self) -> &Arc<Mutex<HostComposition>> {
        &self.composition
    }

    /// 服务开关接收端（P4 传输层据此在停机后拒绝新请求）。
    #[must_use]
    pub fn serving_receiver(&self) -> watch::Receiver<bool> {
        self.serving_rx.clone()
    }

    /// 挂接 KernelControl 服务任务（P4 传输层 serve future；停机先中止）。
    pub fn set_serve_task(&mut self, task: tokio::task::JoinHandle<()>) {
        self.serve_task = Some(task);
    }

    /// 挂接状态转发器任务（`KernelControlService::spawn_status_forwarder`；停机先中止）。
    pub fn set_forwarder_task(&mut self, task: tokio::task::JoinHandle<()>) {
        self.forwarder_task = Some(task);
    }

    /// 挂接统计转发器任务（`KernelControlService::spawn_stats_forwarder`，P5-b；停机先
    /// 中止——统计转发器同样持有 engine client Arc，须在 `shutdown_core` 前释放引用）。
    pub fn set_stats_forwarder_task(&mut self, task: tokio::task::JoinHandle<()>) {
        self.stats_forwarder_task = Some(task);
    }

    /// 挂接日志转发器任务（`KernelControlService::spawn_log_forwarder`，R3；停机先
    /// 中止——日志转发器持 engine client Arc 与日志聚合器 Arc，须在 `shutdown_core`
    /// 前释放引用。日志纯单向输出，中止无状态副作用）。
    pub fn set_logs_forwarder_task(&mut self, task: tokio::task::JoinHandle<()>) {
        self.logs_forwarder_task = Some(task);
    }

    /// 挂接自动重连 worker 任务（`KernelControlService::spawn_reconnect_worker`，C3a；
    /// 停机先中止——worker 持服务克隆，须在 `shutdown_core` 前释放引用，否则服务与
    /// 其引用的 engine client 不因停机释放）。
    pub fn set_reconnect_worker_task(&mut self, task: tokio::task::JoinHandle<()>) {
        self.reconnect_worker_task = Some(task);
    }

    /// 挂接 KeepAlive 心跳 tick 任务（P2：`KernelControlService::spawn_keepalive_ticker`；
    /// 停机先中止——ticker 持 engine client Arc，须在 `shutdown_core` 前释放引用。
    /// 中止后 engine 不再收到心跳；core 停机时 engine 由退出包/进程句柄随行退出）。
    pub fn set_keepalive_ticker_task(&mut self, task: tokio::task::JoinHandle<()>) {
        self.keepalive_ticker_task = Some(task);
    }

    /// 挂接崩溃自愈编排（P3：liveness 翻转 false → `CrashRecovery::run_respawn` 全链路；
    /// engine 死亡 ≠ core 死亡，core 自愈后继续服务 UI）。
    pub fn set_crash_recovery(&mut self, recovery: CrashRecovery) {
        self.crash_recovery = Some(recovery);
    }

    /// 显式请求停机（UI 发 stop / 系统信号）→ `run` 的 select 触发停机。
    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// 运行 core 生命周期：监听 engine 掉线 → 等 UI 彻底退出（或显式停机）→ 有序停机。
    ///
    /// `self` 按值消费（engine 监督句柄所有权终结于停机）。
    ///
    /// **停机信号**：`ui_rx.changed()`（[`UiLifetime::on_ui_exited`]，由传输层的
    /// UI 进程退出监视触发）或 `shutdown_rx.changed()`（显式停机命令）。**不**把 serve
    /// 任务 resolve 当 UI 断开信号——tonic `serve_with_incoming` 对单元素传入流在 accept
    /// 后立即返回（流耗尽即 break，连接任务 detached 继续服务），其 JoinHandle 会假
    /// resolve；真实 UI 退出由进程监视感知（见 `kernel_control_transport`）。
    pub async fn run(mut self) -> CoreShutdownOutcome {
        // 运行期：等 UI 彻底退出（O3：进程退出 → on_ui_exited）或显式停机命令；同时监听
        // engine 掉线（liveness 翻 false）→ 崩溃自愈 respawn（P3：engine 死亡 ≠ core 死亡，
        // core 自愈后继续服务 UI）。
        let mut ui_rx = self.ui.receiver();
        let mut shutdown_rx = self.shutdown_rx.clone();
        let mut liveness_rx = self.supervisor.liveness();
        let crash_recovery = self.crash_recovery.take();

        loop {
            // engine 掉线监听 future：liveness 翻 false → 返回 true（触发 respawn）；
            // 无 client（无 liveness）→ pending（无 engine 可等）。
            let liveness_fired = liveness_rx.clone().map(|mut rx| {
                Box::pin(async move {
                    loop {
                        if !*rx.borrow() {
                            return true;
                        }
                        if rx.changed().await.is_err() {
                            return false;
                        }
                    }
                })
            });
            tokio::select! {
                _ = ui_rx.changed() => break,
                _ = shutdown_rx.changed() => break,
                died = async {
                    if let Some(fut) = liveness_fired {
                        fut.await
                    } else {
                        std::future::pending::<()>().await;
                        false
                    }
                } => {
                    if died {
                        if let Some(recovery) = &crash_recovery {
                            match recovery.run_respawn(&mut self.supervisor).await {
                                Ok(outcome) => {
                                    // respawn 成功：新 supervisor 带新 liveness（初始 true），
                                    // 继续等 UI 退出 / 下次掉线。
                                    liveness_rx = self.supervisor.liveness();
                                    tracing::info!(?outcome, "engine respawned (crash self-heal)");
                                }
                                Err(reason) => {
                                    // respawn 被阻/失败：回 Idle/报错（不自动重连）。停止
                                    // 掉线监听（无新 engine 可等）；用户再点连接走正常登录。
                                    liveness_rx = None;
                                    tracing::warn!(error = %reason, "engine respawn failed; user reconnect required");
                                }
                            }
                        } else {
                            // 无崩溃自愈编排（测试/降级）：teardown 兜底 + 停止掉线监听
                            // （避免死循环；保留旧语义的 on_helper_link_terminal）。
                            self.composition.lock().await.on_helper_link_terminal();
                            liveness_rx = None;
                        }
                    }
                }
            }
        }

        // 停止接收 UI 请求：置 serving=false + 中止服务任务（router 持有的服务引用
        // drop，停止接受新请求；服务实际释放 engine client 引用由连接任务终结完成——
        // UI 退出时连接任务已因管道 EOF 结束）。
        let _ = self.serving_tx.send(false);
        if let Some(task) = self.serve_task.take() {
            task.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), task).await;
        }

        // 中止并等待事件转发器实际结束（其 future drop 时释放持有的 engine client Arc）。
        // 契约要求进入 shutdown_core 前服务侧引用已释放——abort 是异步取消，光 abort 不
        // 保证 Arc 立即 drop，故有界等待其完成（转发器在 await 点被取消，很快结束）。
        if let Some(task) = self.forwarder_task.take() {
            task.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), task).await;
        }

        // 统计转发器（P5-b）同样持 engine client Arc：中止并等待其结束，确保进入
        // shutdown_core 前服务侧引用已释放（否则 engine 不因 PeerClosed 退出）。
        if let Some(task) = self.stats_forwarder_task.take() {
            task.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), task).await;
        }

        // 日志转发器（R3）持 engine client Arc + 日志聚合器 Arc：中止并等待其结束，
        // 确保进入 shutdown_core 前服务侧引用已释放。日志纯单向输出，中止无状态副作用。
        if let Some(task) = self.logs_forwarder_task.take() {
            task.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), task).await;
        }

        // 自动重连 worker（C3a）持服务克隆（间接持 engine client 引用）：中止并等待
        // 其结束，确保进入 shutdown_core 前服务侧引用已释放。
        if let Some(task) = self.reconnect_worker_task.take() {
            task.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), task).await;
        }

        // KeepAlive 心跳 tick 任务（P2）持 engine client Arc：中止并等待其结束，确保
        // 进入 shutdown_core 前服务侧引用已释放（此后 engine 不再收到心跳；core 停机
        // 由退出包/进程句柄保证 engine 随行退出）。
        if let Some(task) = self.keepalive_ticker_task.take() {
            task.abort();
            let _ = tokio::time::timeout(std::time::Duration::from_millis(500), task).await;
        }

        // 有序停机（supervisor 所有权移入；engine 发退出包后即返；composition.exit()）。
        shutdown_core(self.supervisor, &self.composition).await
    }
}

// ---------------------------------------------------------------------------
// 单元测试：UiLifetime 翻转 + shutdown_core 顺序契约 + CoreRuntime 触发路径
// （UI 退出 / 显式停机）。进程级 wait/terminate 用 fake child（占位 0 句柄——
// WaitForSingleObject(null) 返回 WAIT_FAILED → 有界等待失败 → Terminated，确定性）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composition::compose_nonprivileged_host;
    use crate::engine_lifecycle::EngineSlot;
    use crate::process_lifecycle::EngineChild;
    use exv_vpn_win32_ipc::peer_auth::VerifiedPipePeer;
    use windows::Win32::Foundation::HANDLE;

    /// 无真实子进程的占位 child（0 句柄；stop 的 wait 对其返回 false → Terminated 路径）。
    fn fake_child() -> EngineChild {
        EngineChild::new(0, HANDLE::default())
    }

    /// 确定性已验 helper peer（与 process_boundary 同源构造）。
    fn helper_peer() -> VerifiedPipePeer {
        VerifiedPipePeer {
            process_id: 4242,
            user_sid: "S-1-5-21-3980489076-1253412212-3874560562-1002".to_string(),
            logon_sid: Some("S-1-5-5-0-323470".to_string()),
            account_name: "EXV VPN Helper".to_string(),
        }
    }

    /// 纯组合的共享 host composition（无真实 pipe/session I/O）。
    fn composition() -> Arc<Mutex<HostComposition>> {
        Arc::new(Mutex::new(
            compose_nonprivileged_host(&helper_peer()).expect("compose_nonprivileged_host"),
        ))
    }

    /// UiLifetime 初始为存活（UI 已连接）；`on_ui_exited` 翻转 → 触发 core 停机。
    #[test]
    fn ui_lifetime_starts_alive_and_flips_on_exit() {
        let ui = UiLifetime::new();
        assert!(ui.is_ui_alive(), "UI 初始必须视为存活（最小化到托盘仍存活）");
        ui.on_ui_exited();
        assert!(!ui.is_ui_alive(), "UI 彻底退出 → 信号翻转 false");
    }

    /// `UiLifetime` 可多克隆共享同一事实（P4 UI 传输层与 run select 各持一份）。
    #[test]
    fn ui_lifetime_clone_shares_signal_state() {
        let ui = UiLifetime::new();
        let ui2 = ui.clone();
        assert!(ui.is_ui_alive() && ui2.is_ui_alive());
        ui.on_ui_exited();
        assert!(!ui2.is_ui_alive(), "克隆必须观察到同一翻转");
    }

    /// shutdown_core 顺序契约（D1 解耦）：rpc_waiter_cancel（先）→ engine 发退出包后
    /// 即返（无 client → NoClient；无 Terminated 兜底触发）→ composition.exit()（恰好
    /// 一次业务 Stop）。
    #[tokio::test]
    async fn shutdown_core_orders_cancel_stop_exit() {
        let composition = composition();
        let supervisor = EngineSupervisor::with_child(fake_child());
        let outcome = shutdown_core(supervisor, &composition).await;

        // 顺序事实：RPC waiter 取消恰好一次（cancel ≠ 业务 Stop）。
        assert_eq!(outcome.rpc_waiter_cancellations, 1);
        // 业务 Stop 恰好一次（唯一业务取消是 exit()）。
        assert_eq!(outcome.stop_requests, 1);
        assert!(outcome.teardown_started, "exit 必须启动 teardown");
        // D1：无 client（未连接）→ NoClient；UI 关闭路径不等 engine、无 Terminated 兜底。
        assert_eq!(
            outcome.engine,
            EngineShutdownOutcome::NoClient,
            "UI 关闭路径发退出包后即返——不得出现 Terminated（判据 8）"
        );
    }

    /// D1 解耦（判据 8）：shutdown_core UI 关闭路径——engine 已连接时发退出包
    /// （StopTunnel 恰好一次）后即返，无 Terminated 兜底触发（fire-and-forget）。
    #[tokio::test]
    async fn shutdown_core_fires_exit_packet_and_returns_without_terminate() {
        let engine = Arc::new(Mutex::new(
            crate::engine_lifecycle::test_support::RecordingEngine {
                stops: std::sync::Mutex::new(Vec::new()),
            },
        ));
        let (tx, _rx) = watch::channel(true);
        let mut supervisor = EngineSupervisor::with_child(
            crate::engine_lifecycle::test_support::fake_child(),
        );
        supervisor.attach_client(engine.clone(), tx.subscribe());
        let composition = composition();

        let outcome = shutdown_core(supervisor, &composition).await;
        // 退出包（StopTunnel）恰好一次 + fire-and-forget（ExitPacketSent，无 Terminated）。
        assert_eq!(engine.lock().await.stops.lock().unwrap().len(), 1);
        assert_eq!(
            outcome.engine,
            EngineShutdownOutcome::ExitPacketSent,
            "UI 关闭路径发退出包后即返——不得出现 Terminated（判据 8）"
        );
        assert_eq!(outcome.stop_requests, 1);
        let _ = tx;
    }

    /// R2 (a) 收敛双保险：`synthesize_data_plane_join` 仅在停机收敛（Stopping，控制面
    /// 侧已加入屏障）时把数据面侧补上 → 双侧齐 → Stopped/Idle 终态；Idle / Connected /
    /// 已 Stopped 等相位 no-op（不制造虚假相位）。core 在 engine 干净退出（wait_exit
    /// 成功）时调用它——engine 侧 Idle 终态事件可能随断线丢失。
    #[tokio::test]
    async fn synthesize_data_plane_join_converges_only_in_stopping() {
        use crate::composition::{HostEvent, HostPhase};
        use exv_vpn_data_plane::teardown::TeardownSide;

        // Idle（从未连接）：synthesize no-op（不制造虚假 Stopped）。
        let mut comp = compose_nonprivileged_host(&helper_peer()).expect("compose");
        assert_eq!(comp.phase(), HostPhase::Idle);
        comp.synthesize_data_plane_join();
        assert_eq!(comp.phase(), HostPhase::Idle, "Idle 不得被合成相位");

        // Stopping（用户 stop：Disconnect + 控制面侧加入）：synthesize 补数据面侧 →
        // Stopped 终态（断开->收敛->Idle 判据）。
        comp.apply(HostEvent::Disconnect);
        comp.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl));
        assert_eq!(comp.phase(), HostPhase::Stopping);
        comp.synthesize_data_plane_join();
        assert_eq!(comp.phase(), HostPhase::Stopped, "双侧齐必须收敛到 Stopped");

        // 已 Stopped：synthesize no-op（幂等，不回归）。
        comp.synthesize_data_plane_join();
        assert_eq!(comp.phase(), HostPhase::Stopped, "已 Stopped 保持终态");

        // Connected（从未 Disconnect，teardown 屏障未开）：synthesize no-op（TeardownBarrier
        // 单侧加入为 Pending，不移动相位）。
        let mut comp2 = compose_nonprivileged_host(&helper_peer()).expect("compose");
        comp2.apply(HostEvent::ProtocolEstablished); // 无能力绑定下 actor 仍进入 Connected
        assert_eq!(comp2.phase(), HostPhase::Connected);
        comp2.synthesize_data_plane_join();
        assert_eq!(comp2.phase(), HostPhase::Connected, "未 Disconnect 不得被合成 Stopped");
    }

    /// `CoreRuntime::run`：UI 彻底退出（`on_ui_exited`）→ select 触发 → 有序停机。
    ///
    /// watch 语义（tokio `Receiver::clone` 保留原 receiver 的 last-seen version）：run 内
    /// 克隆的 receiver 版本旧于 on_ui_exited 后的 state 版本 → `changed()` 立即 resolve——
    /// 信号在 run 前发送即可，无需并发。
    #[tokio::test]
    async fn core_runtime_ui_exit_triggers_shutdown() {
        let ui = UiLifetime::new();
        let runtime = CoreRuntime::new(
            ui.clone(),
            composition(),
            EngineSupervisor::with_child(fake_child()),
        );
        ui.on_ui_exited();

        let outcome = runtime.run().await;
        assert_eq!(outcome.rpc_waiter_cancellations, 1);
        assert_eq!(outcome.stop_requests, 1, "UI 退出必须触发恰好一次业务 Stop");
        assert!(outcome.teardown_started);
    }

    /// `CoreRuntime::run`：显式停机命令（`request_shutdown`）同样触发有序停机。
    #[tokio::test]
    async fn core_runtime_request_shutdown_triggers_shutdown() {
        let ui = UiLifetime::new();
        let runtime = CoreRuntime::new(
            ui,
            composition(),
            EngineSupervisor::with_child(fake_child()),
        );
        runtime.request_shutdown();

        let outcome = runtime.run().await;
        assert_eq!(outcome.rpc_waiter_cancellations, 1);
        assert_eq!(outcome.stop_requests, 1, "显式停机必须触发业务 Stop");
        assert!(outcome.teardown_started);
    }

    /// `CoreRuntime::run`：serve 任务 **pending**（正常服务中）不是 UI 断开信号——
    /// UI 存活且无显式停机时，run 必须保持运行（不因 serve 任务存活/解析而假停机）。
    ///
    /// tonic `serve_with_incoming` 对单元素流在 accept 后立即返回、连接任务 detached
    /// 继续服务——若把 serve 任务 JoinHandle 当"UI 断开"判据会假 resolve 触发假停机。
    /// 本测试钉死：serve 任务 pending ≠ UI 退出，run 不返回。
    #[tokio::test]
    async fn core_runtime_pending_serve_task_does_not_fake_shutdown() {
        let ui = UiLifetime::new();
        let mut runtime = CoreRuntime::new(
            ui,
            composition(),
            EngineSupervisor::with_child(fake_child()),
        );
        // 一个保持 pending 的 serve 任务 = 正常服务中（UI 连接未断开）。
        runtime.set_serve_task(tokio::spawn(async {
            std::future::pending::<()>().await;
        }));
        // UI 存活 + 无显式停机：run 不得在短时间内返回（假停机回归护栏）。
        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(150),
            runtime.run(),
        )
        .await;
        assert!(
            outcome.is_err(),
            "serve 任务 pending 不是 UI 断开——run 必须保持运行"
        );
    }

    /// `CoreRuntime::run`：停机时**中止服务任务**（停止接收 UI 请求——router 持有的
    /// 服务引用释放）。serve 任务现在保持 pending 到停机，因此 run 必须显式 abort 它
    /// （旧实现依赖 serve 任务假 resolve 顺带 drop 服务；修复后由停机路径负责）。
    #[tokio::test]
    async fn core_runtime_aborts_serve_task_during_shutdown() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let ui = UiLifetime::new();
        let mut runtime = CoreRuntime::new(
            ui.clone(),
            composition(),
            EngineSupervisor::with_child(fake_child()),
        );
        // 一个在 abort（drop）时置位标志的 serve 任务——证明 run 停机路径中止了它。
        // 先经 started 握手确保任务已启动（DropFlag 已构造）：abort 一个从未 poll 的
        // 任务不会执行其 future 体（DropFlag 从未构造、drop 也不触发）。
        let aborted = Arc::new(AtomicBool::new(false));
        let guard = Arc::clone(&aborted);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel::<()>();
        runtime.set_serve_task(tokio::spawn(async move {
            struct DropFlag(Arc<AtomicBool>);
            impl Drop for DropFlag {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _flag = DropFlag(guard);
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        }));
        started_rx.await.expect("serve task must start before shutdown");

        ui.on_ui_exited();
        let outcome = runtime.run().await;
        assert_eq!(outcome.stop_requests, 1, "UI 退出必须触发恰好一次业务 Stop");
        assert!(
            aborted.load(Ordering::SeqCst),
            "停机必须中止 serve 任务（停止接收 UI 请求、释放服务引用）"
        );
    }

    // -----------------------------------------------------------------------
    // P3 崩溃自愈：`CoreRuntime::run` 的 liveness 掉线 → respawn 触发路径（引擎死 ≠ core
    // 死）。fake seam（0 残留 / fake 新 supervisor / 记录连接器）——无真实进程/提权。
    // -----------------------------------------------------------------------

    /// P3 respawn 触发的测试 fake：0 残留（硬断言放行）。
    struct TestResidue;

    impl crate::crash_recovery::ResidueProbe for TestResidue {
        fn probe(&self) -> Result<crate::crash_recovery::ResidueReport, String> {
            Ok(crate::crash_recovery::ResidueReport::default())
        }
    }

    /// P3 respawn 触发的测试 fake：新 supervisor（占位 child）。
    struct TestSupervisorFactory;

    impl crate::crash_recovery::RespawnSupervisorFactory for TestSupervisorFactory {
        fn spawn_supervisor(
            &self,
        ) -> Result<EngineSupervisor, crate::engine_lifecycle::EngineSpawnError> {
            Ok(EngineSupervisor::with_child(fake_child()))
        }
    }

    /// P3 respawn 触发的测试 fake：记录每次 connect 的连接器。
    struct TestConnector {
        pids: std::sync::Mutex<Vec<u32>>,
    }

    #[tonic::async_trait]
    impl crate::crash_recovery::RespawnClientConnector for TestConnector {
        async fn connect(
            &self,
            pid: u32,
            _user_sid: &str,
        ) -> Result<(Arc<Mutex<dyn crate::grpc_control::KernelEngineControl>>, watch::Receiver<bool>), String> {
            self.pids.lock().unwrap().push(pid);
            let engine = Arc::new(tokio::sync::Mutex::new(
                crate::engine_lifecycle::test_support::RecordingEngine {
                    stops: std::sync::Mutex::new(Vec::new()),
                },
            ));
            let engine: Arc<Mutex<dyn crate::grpc_control::KernelEngineControl>> = engine;
            let (_tx, rx) = watch::channel(true);
            Ok((engine, rx))
        }
    }

    /// `CoreRuntime::run`（P3）：engine 掉线（liveness 翻 false）→ `CrashRecovery::run_respawn`
    /// 触发（新 client 连接）→ 回 Idle 继续服务 UI → UI 退出仍有序停机。**不自动重连**：
    /// respawn 只重建进程/身份，不重放凭据（用户再点连接走正常登录）。
    ///
    /// `run` 不经 `tokio::spawn` 驱动（其 future 跨 respawn await 持有 `EngineSupervisor`
    /// 的 HANDLE——非 `Send`；生产经 `#[tokio::main]` 的 `block_on` 直接 await，不要求
    /// `Send`）。用独立 watcher 任务在 respawn 完成后触发 UI 退出。
    #[tokio::test]
    async fn core_runtime_engine_death_triggers_respawn_then_shutdown() {
        // 1. supervisor 挂接可控 liveness（初始 true）。
        let (liveness_tx, liveness_rx) = watch::channel(true);
        let mut supervisor = EngineSupervisor::with_child(fake_child());
        let initial_engine = Arc::new(tokio::sync::Mutex::new(
            crate::engine_lifecycle::test_support::RecordingEngine {
                stops: std::sync::Mutex::new(Vec::new()),
            },
        ));
        let initial: Arc<Mutex<dyn crate::grpc_control::KernelEngineControl>> =
            initial_engine.clone();
        supervisor.attach_client(initial, liveness_rx);
        let slot = EngineSlot::new(initial_engine);

        // 2. CrashRecovery（fake seam：0 残留 / fake 新 supervisor / 记录连接器）。
        let composition = composition();
        let connector = Arc::new(TestConnector {
            pids: std::sync::Mutex::new(Vec::new()),
        });
        let recovery = crate::crash_recovery::CrashRecovery::new(
            Arc::new(TestSupervisorFactory),
            connector.clone(),
            Arc::new(TestResidue),
            slot,
            Arc::clone(&composition),
            helper_peer(),
            "S-1-5-21-3980489076-1253412212-3874560562-1002".to_string(),
        );
        let ui = UiLifetime::new();
        let mut runtime = CoreRuntime::new(ui.clone(), Arc::clone(&composition), supervisor);
        runtime.set_crash_recovery(recovery);

        // 3. watcher 任务：respawn 完成（新 client 连接）后触发 UI 退出（run 直接 await，
        //    不经 spawn——non-Send future 生产侧 block_on 驱动）。
        let connector_watcher = Arc::clone(&connector);
        let ui_watcher = ui.clone();
        let watcher = tokio::spawn(async move {
            loop {
                if connector_watcher.pids.lock().unwrap().len() >= 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            ui_watcher.on_ui_exited();
        });

        // 4. liveness 翻 false（engine 死亡）→ run 触发 respawn → watcher 感知后 UI 退出 →
        //    有序停机。
        liveness_tx.send(false).unwrap();
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), runtime.run())
            .await
            .expect("run completes within timeout");
        assert!(
            watcher.await.is_ok(),
            "watcher 必须感知 respawn 完成并触发 UI 退出"
        );
        assert_eq!(
            connector.pids.lock().unwrap().len(),
            1,
            "engine 掉线必须触发 respawn（恰好一次新 client 连接）"
        );
        assert_eq!(
            outcome.stop_requests,
            1,
            "UI 退出必须触发恰好一次业务 Stop（respawn 后仍有序停机）"
        );
        let _ = liveness_tx;
    }
}
