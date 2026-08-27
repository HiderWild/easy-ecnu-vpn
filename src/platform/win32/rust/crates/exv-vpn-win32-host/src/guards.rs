// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// 服务生命周期 × 隧道状态的正交组合守卫层（纯决策函数）。
//
// 设计约束（治理硬约束，决定本层形态）：
// - **host 只能有一个业务状态机**（`composition.rs` 的 `runtime_actor_count` /
//   `kernel_control_owns_state_machine` killer-mutant 锚点）→ 本层是**无状态纯函数**：
//   不做任何转移、不存储状态、不建第二个 FSM。
// - **business-first 政策禁止跨系统联合状态机**（worktree AGENTS.md）→ 服务与隧道两个
//   维度正交，本层只在决策面组合二者的投影（输入投影、输出决策；两维都不由本层拥有）。
// - **SCM 是服务状态的唯一权威** → 本层守卫对齐既有 handler/route 的真实行为，不引入
//   新的拒绝；`Other(u32)` 走显式 fail-closed 分支（穷尽 match，无 `_` 静默兜底）。
//
// 收敛说明：`RouteDecision`/`decide_route`（原 kernel_control_service.rs）收编为本层
// 连接守卫；`can_start`/`can_uninstall` 是跨机不变量的命名权威，handler 按
// 需咨询（现有 `stop_engine_for_transition`/`ensure_service_ready` 原语是其实现载体）。

use crate::service_status::ServiceState;

/// 连接路由（服务状态 → 连接方式；M3 决策表）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteDecision {
    /// SCM 已观察到 Running：直连服务 engine。
    Service,
    /// 已装未运行（Stopped/StartPending/StopPending/Paused/…/`Other`）：connect 内部
    /// bootstrap（`ensure_service_ready`）启动服务后连接——不要求用户先点 Start。
    PromptStart,
    /// 未安装：一次性（oneshot）连接（维持既有路径；安装由 UI 独立发请求）。
    Oneshot,
}

/// 连接守卫：服务生命周期状态 → 连接路由（纯函数，穷尽；`Other(u32)` 归 PromptStart，
/// 与「已装非运行」同语义）。
#[must_use]
pub fn decide_route(state: ServiceState) -> RouteDecision {
    match state {
        ServiceState::Running => RouteDecision::Service,
        ServiceState::NotInstalled => RouteDecision::Oneshot,
        _ => RouteDecision::PromptStart,
    }
}

/// 连接模式（快照 `mode` 展示用；记录最近一次连接路由的实际模式）。
///
/// 与 `grpc_control::ENGINE_KIND_*` 共享编码（0=auto / 1=service / 2=oneshot）：
/// `as_u8`/`from_u8` 是跨层编码契约（`selected_mode` 的 `AtomicU8` 存储沿用该编码，
/// 供 keepalive ticker 后台线程无锁读取）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMode {
    Auto,
    Service,
    Oneshot,
}

impl ServiceMode {
    /// 存储编码（与 [`crate::grpc_control::ENGINE_KIND_*`] 一致）。
    #[must_use]
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Auto => 0,
            Self::Service => 1,
            Self::Oneshot => 2,
        }
    }

    /// 从存储编码解码（未知码 fail-closed → Auto）。
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Service,
            2 => Self::Oneshot,
            _ => Self::Auto,
        }
    }

    /// 稳定 wire 字符串（`RuntimeSnapshot.mode` 取值）。
    #[must_use]
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Service => "service",
            Self::Oneshot => "oneshot",
        }
    }

    /// 路由 → 记录模式（与 M3 决策表一致：`PromptStart` 记 Auto——服务 bootstrap 尚未
    /// 换入 service engine）。
    #[must_use]
    pub fn from_route(route: RouteDecision) -> Self {
        match route {
            RouteDecision::Service => Self::Service,
            RouteDecision::Oneshot => Self::Oneshot,
            RouteDecision::PromptStart => Self::Auto,
        }
    }
}

/// 隧道粗状态（决策输入；从引擎状态投影，不由本层拥有）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelCoarse {
    /// 隧道空闲（可发起连接 / 可执行服务生命周期变更）。
    Idle,
    /// 隧道忙碌（连接中/已连接/停止中/重连中——服务生命周期变更须先经
    /// `stop_engine_for_transition` 收敛）。
    Busy,
}

impl TunnelCoarse {
    /// 从 host 快照 runtime 状态投影（纯函数；`"idle"` 之外一律视为忙碌——fail-closed）。
    #[must_use]
    pub fn from_runtime_state(state: &str) -> Self {
        if state == "idle" {
            Self::Idle
        } else {
            Self::Busy
        }
    }
}

/// 阻止服务生命周期动作的跨机不变量。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// 服务未安装（无可启动/卸载）。
    ServiceNotInstalled,
    /// 服务已运行（启动动作冗余；`ensure_service_ready` 不重复提交 start）。
    ServiceAlreadyRunning,
    /// 服务处于 SCM 过渡态（start/stop/pause/continue pending——操作与过渡竞态）。
    ServiceTransitioning,
    /// 隧道忙碌（卸载等变更要求隧道先收敛到空闲）。
    TunnelBusy,
}

/// 启动守卫：只有「已安装且已停止/未知」才需要提交 start（对齐 `ensure_service_ready`
/// 的 `needs_start`——不重复提交 Running/StartPending/StopPending/Paused）。
#[must_use]
pub fn can_start(service: ServiceState) -> Result<(), BlockReason> {
    match service {
        ServiceState::Stopped | ServiceState::NotInstalled | ServiceState::Other(_) => Ok(()),
        ServiceState::Running | ServiceState::Paused => Err(BlockReason::ServiceAlreadyRunning),
        ServiceState::StartPending
        | ServiceState::StopPending
        | ServiceState::PausePending
        | ServiceState::ContinuePending => Err(BlockReason::ServiceTransitioning),
    }
}

/// 卸载守卫（跨维度）：服务已安装 + 隧道空闲。运行中/过渡态交由
/// `stop_engine_for_transition` 先收敛（本守卫不拒绝——卸载语义是「先停引擎、再删服务」）。
#[must_use]
pub fn can_uninstall(service: ServiceState, tunnel: TunnelCoarse) -> Result<(), BlockReason> {
    if !service.is_installed() {
        return Err(BlockReason::ServiceNotInstalled);
    }
    if tunnel == TunnelCoarse::Busy {
        return Err(BlockReason::TunnelBusy);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 单元测试：守卫决策矩阵（穷尽性 + 与既有 handler/route 行为一致）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// M3 决策表纯函数：服务状态三态矩阵。
    #[test]
    fn decide_route_three_state_matrix() {
        // Running → Service（连接服务 engine）。
        assert_eq!(decide_route(ServiceState::Running), RouteDecision::Service);
        // 已装非运行（含过渡态与未知）→ PromptStart（由 connect 内部 bootstrap）。
        assert_eq!(decide_route(ServiceState::Stopped), RouteDecision::PromptStart);
        assert_eq!(
            decide_route(ServiceState::StopPending),
            RouteDecision::PromptStart
        );
        assert_eq!(decide_route(ServiceState::Paused), RouteDecision::PromptStart);
        assert_eq!(decide_route(ServiceState::Other(9)), RouteDecision::PromptStart);
        // NotInstalled → Oneshot。
        assert_eq!(decide_route(ServiceState::NotInstalled), RouteDecision::Oneshot);
    }

    /// 启动守卫：与 `ensure_service_ready` 的 needs_start 一致。
    #[test]
    fn can_start_matches_needs_start_semantics() {
        assert_eq!(can_start(ServiceState::Stopped), Ok(()));
        assert_eq!(can_start(ServiceState::NotInstalled), Ok(()));
        assert_eq!(can_start(ServiceState::Other(9)), Ok(()));
        assert_eq!(can_start(ServiceState::Running), Err(BlockReason::ServiceAlreadyRunning));
        assert_eq!(can_start(ServiceState::Paused), Err(BlockReason::ServiceAlreadyRunning));
        assert_eq!(can_start(ServiceState::StartPending), Err(BlockReason::ServiceTransitioning));
        assert_eq!(can_start(ServiceState::StopPending), Err(BlockReason::ServiceTransitioning));
    }

    /// 卸载守卫：跨维度——未安装拒绝；隧道忙碌拒绝；其余放行（运行/过渡交由
    /// `stop_engine_for_transition` 收敛）。
    #[test]
    fn can_uninstall_gates_on_installed_and_tunnel_idle() {
        assert_eq!(
            can_uninstall(ServiceState::NotInstalled, TunnelCoarse::Idle),
            Err(BlockReason::ServiceNotInstalled)
        );
        assert_eq!(
            can_uninstall(ServiceState::Running, TunnelCoarse::Busy),
            Err(BlockReason::TunnelBusy)
        );
        assert_eq!(can_uninstall(ServiceState::Running, TunnelCoarse::Idle), Ok(()));
        assert_eq!(can_uninstall(ServiceState::Stopped, TunnelCoarse::Idle), Ok(()));
    }

    /// 隧道投影：`"idle"` → Idle；其余（含空/未知）→ Busy（fail-closed）。
    #[test]
    fn tunnel_coarse_projection_fails_closed() {
        assert_eq!(TunnelCoarse::from_runtime_state("idle"), TunnelCoarse::Idle);
        assert_eq!(TunnelCoarse::from_runtime_state("connected"), TunnelCoarse::Busy);
        assert_eq!(TunnelCoarse::from_runtime_state("connecting"), TunnelCoarse::Busy);
        assert_eq!(TunnelCoarse::from_runtime_state(""), TunnelCoarse::Busy);
        assert_eq!(TunnelCoarse::from_runtime_state("???"), TunnelCoarse::Busy);
    }

    /// `ServiceMode` 编码契约：与 `ENGINE_KIND_*` 共享 0/1/2；未知码 fail-closed → Auto。
    #[test]
    fn service_mode_encoding_round_trips() {
        assert_eq!(ServiceMode::Auto.as_u8(), 0);
        assert_eq!(ServiceMode::Service.as_u8(), 1);
        assert_eq!(ServiceMode::Oneshot.as_u8(), 2);
        assert_eq!(ServiceMode::from_u8(0), ServiceMode::Auto);
        assert_eq!(ServiceMode::from_u8(1), ServiceMode::Service);
        assert_eq!(ServiceMode::from_u8(2), ServiceMode::Oneshot);
        assert_eq!(ServiceMode::from_u8(99), ServiceMode::Auto, "未知码 fail-closed → Auto");
        assert_eq!(ServiceMode::Auto.as_wire_str(), "auto");
        assert_eq!(ServiceMode::Service.as_wire_str(), "service");
        assert_eq!(ServiceMode::Oneshot.as_wire_str(), "oneshot");
        assert_eq!(ServiceMode::from_route(RouteDecision::Service), ServiceMode::Service);
        assert_eq!(ServiceMode::from_route(RouteDecision::Oneshot), ServiceMode::Oneshot);
        assert_eq!(ServiceMode::from_route(RouteDecision::PromptStart), ServiceMode::Auto);
    }
}
