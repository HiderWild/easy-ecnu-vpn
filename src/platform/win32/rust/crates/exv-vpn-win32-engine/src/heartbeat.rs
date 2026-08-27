// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// P2 心跳有界存留（plan D8 / 判据 7）：engine 侧 `last_heartbeat` 单调计时 + 超时自清理。
//
// 与 `wait_core_process_exit`（进程句柄 signaled，即时兜底）的关系：进程句柄覆盖 core
// 正常/崩溃/强杀退出；心跳提供**硬时间界 + hung-core 检测**（core 存活但不发心跳）——
// 两者互补，双保险。oneshot 专属：服务 engine（未来 SCM/LocalSystem 形态）生命周期自管，
// 不受心跳影响（无服务形态代码，文档声明）。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::status::{StatusEvent, StatusPublisher};
use crate::tunnel_runtime::TunnelRuntime;

/// 默认 core 侧心跳发送周期（10s，可调——`spawn_keepalive_ticker` 参数）。
pub const HEARTBEAT_PERIOD_MS: u64 = 10_000;
/// 默认 engine 侧心跳超时上界（15s，硬时间界；可调——watchdog 参数）。
pub const HEARTBEAT_TIMEOUT_MS: u64 = 15_000;

/// engine 侧心跳监视状态（单调计时，无跨线程锁：仅原子读改写）。
///
/// `last_ms` 是自引擎启动以来的单调毫秒；**0 = 引擎启动时刻**（尚无任何心跳）。watchdog
/// 以「距启动/最近心跳 > 超时上界」判超时——core 自引擎启动后 15s 内不发心跳即触发
/// 自清理+自退出（硬时间界，不依赖进程句柄）。
pub struct HeartbeatWatch {
    /// 单调参考零点（进程启动）。
    start: Instant,
    /// 最近一次收到 KeepAlive 的单调毫秒（0 = 启动时刻，尚无心跳）。
    last_ms: AtomicU64,
}

impl HeartbeatWatch {
    /// 建一个监视（计时从构造开始；`last_ms = 0` = 引擎启动）。
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    /// 当前单调毫秒（自构造起）。
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// 刷新最近心跳时间戳（`keep_alive` RPC handler 调用）。
    pub fn touch(&self) {
        self.last_ms.store(self.now_ms(), Ordering::SeqCst);
    }

    /// 距最近一次心跳已过的毫秒（0 = 引擎启动，尚无心跳）。
    #[must_use]
    pub fn elapsed_ms(&self) -> u64 {
        self.now_ms().saturating_sub(self.last_ms.load(Ordering::SeqCst))
    }

    /// 是否已超过指定超时上界（毫秒；硬时间界判据的通用形态）。
    #[must_use]
    pub fn elapsed_exceeds(&self, timeout_ms: u64) -> bool {
        self.elapsed_ms() > timeout_ms
    }

    /// 是否已超过心跳超时上界（硬时间界判据，默认 [`HEARTBEAT_TIMEOUT_MS`]）。
    #[must_use]
    pub fn timed_out(&self) -> bool {
        self.elapsed_exceeds(HEARTBEAT_TIMEOUT_MS)
    }
}

impl Default for HeartbeatWatch {
    fn default() -> Self {
        Self::new()
    }
}

/// 心跳超时 watchdog：周期检查 `elapsed_ms() > timeout_ms`，超时即 resolve（驱动 engine
/// 自退路径）。`check_period` 是检查节拍（默认 500ms；测试注入更小值加速）；`timeout_ms`
/// 是硬时间界上界（默认 [`HEARTBEAT_TIMEOUT_MS`]；测试注入小值）。
#[must_use]
pub fn heartbeat_timeout_watcher(
    heartbeat: Arc<HeartbeatWatch>,
    check_period: Duration,
    timeout_ms: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(check_period).await;
            if heartbeat.elapsed_ms() > timeout_ms {
                break;
            }
        }
    })
}

/// 心跳超时自清理（**复用 teardown 路径**，plan D8）：cancel 在途组装 → 有界等待组装在
/// 段边界自清理（5s 上限，镜像 `stop_tunnel`）→ teardown 数据面/特权资源 → post Idle。
///
/// 调用方随后 300ms flush + 进程退出——完整顺序：**teardown → post Idle → flush → 退**
///（「关机瞬间 connect 中」也满足：cancel 中止在途组装、teardown 撤网卡/路由，再发 Idle）。
///
/// oneshot 专属：服务 engine 不受影响（SCM 生命周期自管，无服务形态代码）。
pub async fn heartbeat_shutdown(runtime: Arc<dyn TunnelRuntime>, status: Arc<StatusPublisher>) {
    // 1. 置位取消令牌 → 有界等待在途组装在段边界取消并自清理（5s 上限，镜像 stop_tunnel）。
    runtime.cancel();
    // 2. teardown 数据面/特权资源（阻塞操作 → spawn_blocking 隔离，不占异步 worker）。
    let _ = tokio::task::spawn_blocking(move || {
        for _ in 0..100 {
            if !runtime.is_assembling() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        runtime.teardown()
    })
    .await;
    // 3. post Idle（coarse Idle 终态；空 operation_id——心跳超时无外部操作关联，host 侧
    //    R3-C2 陈旧过滤在无在途操作时保守透传/在途不符时丢弃，均为安全）。
    status.publish(StatusEvent::idle(Vec::new()));
}

// ---------------------------------------------------------------------------
// 单元测试：监视计时 / 超时判据 / watchdog 触发 / 自清理顺序（teardown→Idle）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::StatusPublisher;
    use crate::tunnel_runtime::{ApplyContext, TunnelError};

    /// 计时语义：构造时 `elapsed_ms = 0`（启动时刻）；`touch` 后 `elapsed_ms` 归零重置。
    #[test]
    fn heartbeat_watch_starts_at_launch_and_touches_reset() {
        let watch = HeartbeatWatch::new();
        assert_eq!(watch.elapsed_ms(), 0, "last_ms=0 = 引擎启动时刻，elapsed 为 0");
        // 推进时间（小睡眠）后 elapsed 增长。
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            watch.elapsed_ms() >= 20,
            "启动后 elapsed 必须随单调时间增长，got {}",
            watch.elapsed_ms()
        );
        // touch 重置最近心跳时刻 → elapsed 归零。
        watch.touch();
        assert!(watch.elapsed_ms() < 5, "touch 后 elapsed 必须归零");
    }

    /// 超时判据：默认上界 [`HEARTBEAT_TIMEOUT_MS`]（15s）——超时未到不触发；`elapsed`
    /// 增长超过较小上界即判超时（通用形态 `elapsed_exceeds`）。
    #[test]
    fn heartbeat_watch_timed_out_after_bound() {
        let watch = HeartbeatWatch::new();
        assert!(!watch.timed_out(), "启动即刻未超过 15s 上界");
        // 推进真实时间（20ms）→ elapsed 超过 10ms 的较小上界（通用判据）。
        std::thread::sleep(Duration::from_millis(20));
        assert!(
            watch.elapsed_exceeds(10),
            "elapsed 超过较小上界必须判超时（elapsed_ms={}）",
            watch.elapsed_ms()
        );
        // 20ms 远未达到 15s 默认上界。
        assert!(!watch.timed_out(), "20ms 远未达到 15s 默认上界");
    }

    /// watchdog：短超时上界 + 短检查节拍下，心跳停滞 → watchdog resolve（触发自退信号）。
    #[tokio::test]
    async fn heartbeat_timeout_watcher_fires_on_stalled_heartbeat() {
        let watch = Arc::new(HeartbeatWatch::new());
        let handle = heartbeat_timeout_watcher(Arc::clone(&watch), Duration::from_millis(20), 100);
        // 100ms 超时上界内无心跳 → watchdog 在约 100ms 后 resolve。
        let outcome = tokio::time::timeout(Duration::from_millis(500), handle).await;
        assert!(outcome.is_ok(), "心跳停滞超过上界必须触发 watchdog resolve");
    }

    /// watchdog：心跳持续刷新 → watchdog 保持 pending（不触发自退）。
    #[tokio::test]
    async fn heartbeat_timeout_watcher_stays_pending_while_heartbeats_flow() {
        let watch = Arc::new(HeartbeatWatch::new());
        let handle = heartbeat_timeout_watcher(Arc::clone(&watch), Duration::from_millis(20), 100);
        // 每 20ms 刷新一次心跳 → elapsed 恒 < 100ms 上界 → watchdog 不 resolve。
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            watch.touch();
        }
        let outcome = tokio::time::timeout(Duration::from_millis(50), handle).await;
        assert!(
            outcome.is_err(),
            "心跳持续刷新时 watchdog 必须保持 pending（不触发自退）"
        );
    }

    /// 测试专用 runtime：可置「在途组装」+ 记录 teardown（验证自清理顺序）。
    struct TestRuntime {
        assembling: std::sync::atomic::AtomicBool,
        teardown_count: std::sync::atomic::AtomicUsize,
        cancel_count: std::sync::atomic::AtomicUsize,
    }

    impl TestRuntime {
        fn connecting() -> Self {
            Self {
                assembling: std::sync::atomic::AtomicBool::new(true),
                teardown_count: std::sync::atomic::AtomicUsize::new(0),
                cancel_count: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl TunnelRuntime for TestRuntime {
        fn start_apply(self: Arc<Self>, _ctx: ApplyContext) -> Result<(), TunnelError> {
            unreachable!("heartbeat shutdown 测试不调用 start_apply")
        }
        fn cancel(&self) {
            self.cancel_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // 协作式取消：组装在段边界自清理（模拟 assembling 随 cancel 结束）。
            self.assembling
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
        fn disconnect(&self) -> Result<(), String> {
            self.teardown_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn teardown(&self) -> Result<(), String> {
            self.teardown_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn is_connected(&self) -> bool {
            false
        }
        fn is_assembling(&self) -> bool {
            self.assembling
                .load(std::sync::atomic::Ordering::SeqCst)
        }
        fn is_paused(&self) -> bool {
            false
        }
    }

    /// 自清理顺序（「关机瞬间 connect 中」完整序的可测投影）：cancel 在途组装 →
    /// teardown → post Idle（coarse Idle 终态到达 status 流）。host 侧 Idle 事件即
    /// 数据面侧加入 teardown 屏障的收敛信号。
    #[tokio::test]
    async fn heartbeat_shutdown_orders_cancel_teardown_then_idle() {
        let runtime_typed = Arc::new(TestRuntime::connecting());
        let runtime: Arc<dyn TunnelRuntime> = runtime_typed.clone();
        let status = Arc::new(StatusPublisher::new());
        let mut rx = status.open_stream();

        heartbeat_shutdown(Arc::clone(&runtime), Arc::clone(&status)).await;

        // 1. teardown 已执行（复用 teardown 路径；cancel 在 teardown 前）。
        assert_eq!(
            runtime_typed
                .cancel_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "心跳自清理必须先 cancel 在途组装"
        );
        assert_eq!(
            runtime_typed
                .teardown_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "心跳自清理必须执行 teardown（复用 teardown 路径）"
        );
        // 2. post Idle 终态（teardown 之后经 status 通道发布）。
        let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("idle within timeout")
            .expect("stream alive")
            .expect("event ok");
        assert_eq!(
            event.coarse_phase,
            exv_vpn_wire::generated::StatsPhase::Idle as i32,
            "心跳自清理必须在 teardown 后 post Idle 终态"
        );
    }
}
