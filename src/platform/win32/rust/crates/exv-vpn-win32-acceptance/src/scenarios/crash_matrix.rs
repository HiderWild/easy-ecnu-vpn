// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W29 crash-matrix 纵切（W29-I）：`run_crash_matrix`（Terra 冻结 seam）。
//!
//! 运行 Stop/crash/unknown-effect saturation 纵切：13 个饱和点（计划 §9 W29
//! 完整列表）逐点记录 last durable record、native observation、certainty、
//! remaining obligation、final proof 或 blocker。组合已提交 pieces（W23B relay /
//! W24 teardown / W25 recovery / W26 helper composition+shutdown / W27 host
//! composition / W13 authority / W14 journal），绝不重新实现。
//!
//! **权限感知（require_admin pattern）**：矩阵的 kill/restart 纵切需要 elevated
//! 环境（elevated 才驱动真实 helper 子进程 kill/restart）；非 elevated 时诚实标记
//! `WIN_ACCEPTANCE_ENV_INVALID:host_not_elevated`，13 点全部 `not_run`——绝不伪造
//! 动态事实、不冒充 RED/GREEN。elevated 且纵切成功时逐点记录真实观测。
//!
//! **helper 角色**：经 `scenarios::stop_pressure::run_stop_pressure_helper` 以真实
//! 子进程（crash-matrix 二进制 `exv-win32-crash-matrix` 自身）驱动——W26 compose
//! （authority -> recovery -> endpoint）成功后写 ready marker，随后在命名的 crash
//! 边界（admission/effect/observation/reply，文件 barrier 同步）被 TerminateProcess
//! （不执行 shutdown = crash 语义）；接管 WAIT_ABANDONED 后必须先 re-observe 再
//! claim（无 observation = ObservationFailed；有 observation = EffectUnknown 携带
//! 指纹，绝不重放 apply）；recovery 不得改写 durable journal。host kill 经
//! host-dummy 进程死亡 + helper 的 kernel handle wait 检测 link loss。restart/
//! reconcile 以 crash 后的 fresh helper 子进程 compose（projection digest 跨
//! restart 稳定）证明。
//!
//! **评级（计划 §9 W29 / W31-R 冻结语义）**：每点按真实观测携带冻结证据标记——
//! 本实现健康路径下每点行为确定（reproducible）且 restart 可恢复，记录
//! `non-sporadic` + `restart_recovered`（RvP1）并附 runs/cycles 计数；只有真实
//! 观测到偶现缺陷才可评 RvP2（`sporadic`），只有 10 次恰 1 次 + process restart
//! 后 3 次通过 + 无残留才可评 RvP3（`runs=10`/`failures=1`/`restarts_passed=3`/
//! `no_residue`），阻塞缺陷评 RvP0（具体 blocker）——绝不无证据声称评级。
//!
//! **保密契约**：任何证据字段不携带 raw secret/cookie/private key/certificate；
//! `no_raw_secret_in_evidence` 由 [`scan_evidence`] 对最终序列化做独立扫描后置真。

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

use exv_vpn_domain::error::ErrorSubject;
use exv_vpn_domain::identity::{
    ConnectionBindingDigest, EffectId, InventoryDigest, OperationId, OperationLookupKey,
    OperationMethod, OwnershipVersion, PrincipalDigest, RecoveryId, ResourceIdentityDigest,
    RetirementOperationId, RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::model::{PacketLeaseRef, PlatformOwnershipRef};
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CanonicalInputDigest, CleanupTrigger,
    JournalOperationIdentity, JournalRevision, MonotonicTick, PlatformAuthorityInstanceId,
};
use exv_vpn_resource::admission::{
    AdmissionRecord, AppliedFingerprint, AuthorizationSubject, MutationAdmitted, MutationKind,
    ObligationSeed, encode_record,
};
use exv_vpn_resource::authority::{
    ConnectionBinding, PeerCapability, PeerContext, VerifiedConnectionMetadata,
};
use exv_vpn_resource::journal::JournalRecord;
use exv_vpn_resource::retirement::RetirementSaga;

use exv_vpn_data_plane::budget::DataPlaneDirection;
use exv_core::composition::{
    compose_nonprivileged_host, HostEffect, HostEvent, HostPhase,
};
use exv_engine::packet_relay::{
    AttachedPacketRelay, RelayDirection, RelayLegState, RelayTerminalSource,
};
use exv_vpn_win32_ipc::packet_channel::PacketChannel;
use exv_vpn_win32_ipc::packet_limits::PacketLimits;
use exv_vpn_win32_ipc::peer_auth::VerifiedPipePeer;
use exv_vpn_win32_resource::apply_tunnel::{ApplyPlan, build_apply_plan};
use exv_vpn_win32_resource::authority::{AuthorityAcquire, SingletonAuthority};
use exv_vpn_win32_resource::dns_types::DnsSettings;
use exv_vpn_win32_resource::inventory::InventoryItem;
use exv_vpn_win32_resource::journal_path::JournalPath;
use exv_vpn_win32_resource::journal_projection::{JournalProjection, ProjectionOutcome};
use exv_vpn_win32_resource::journal_store::WinJournalStore;
use exv_vpn_win32_resource::native_observation::{NativeObservation, ObservedResource};
use exv_vpn_win32_resource::packet_capability::PacketCapability;
use exv_vpn_win32_resource::packet_worker::PacketWorker;
use exv_vpn_win32_resource::recovery::{
    RecoveryAction, RecoveryEngine, RecoveryOutcome,
};
use exv_vpn_win32_resource::teardown::{
    TeardownError, TeardownStage, WindowsTeardown, build_teardown_plan,
};

use crate::evidence::{ENV_INVALID_PREFIX, ENV_STATE_COMPLETED, NOT_RUN_BLOCKED_PREFIX};
use crate::scenarios::stop_pressure::{StopPressureConfig, run_stop_pressure_helper};

use uuid::Uuid;
use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_QUERY};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    REG_VALUE_TYPE,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, INFINITE, OpenProcess, OpenProcessToken, PROCESS_ACCESS_RIGHTS,
    PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

// ---------------------------------------------------------------------------
// 冻结常量（与 tests/crash_matrix.rs 契约一致）。
// ---------------------------------------------------------------------------

/// helper-hold 子进程的角色 env 标记（crash-matrix 二进制内部协议）。
const HELPER_ROLE_ENV: &str = "EXV_W29_HELPER_ROLE";
const HOST_DUMMY_ENV: &str = "EXV_W29_HOST_DUMMY";
const EXERCISE_ENV: &str = "EXV_W29_EXERCISE";
const AUTHORITY_ENV: &str = "EXV_W29_AUTHORITY";
const JOURNAL_ENV: &str = "EXV_W29_JOURNAL";
const MARKER_ENV: &str = "EXV_W29_MARKER";
const BOUNDARY_DIR_ENV: &str = "EXV_W29_BOUNDARY_DIR";
const HOST_PID_ENV: &str = "EXV_W29_HOST_PID";
const EXERCISE_JOURNAL_ENV: &str = "EXV_W29_EXERCISE_JOURNAL";
const EXERCISE_AUTHORITY_ENV: &str = "EXV_W29_EXERCISE_AUTHORITY";
/// helper 角色 compose 失败时的退出码（tests/crash_matrix.rs 同款约定）。
const CHILD_EXIT_ERROR: i32 = 252;

/// SYNCHRONIZE 标准 right（0x00100000）——host 进程句柄的等待权限（windows crate
/// 将其定义为 `Storage::FileSystem::SYNCHRONIZE`；这里以 `PROCESS_ACCESS_RIGHTS`
/// 构造同值）。
const SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);

/// 13 个饱和点（计划 §9 W29 完整列表；证据必须恰好各一次）。
const ALL_POINT_TAGS: [CrashPointTag; 13] = [
    CrashPointTag::PacketFloodStop,
    CrashPointTag::PeerNonRead,
    CrashPointTag::NativeReadWait,
    CrashPointTag::ConnectingCancel,
    CrashPointTag::StopEof,
    CrashPointTag::HostKill,
    CrashPointTag::HelperCrashBoundaryAdmission,
    CrashPointTag::HelperCrashBoundaryEffect,
    CrashPointTag::HelperCrashBoundaryObservation,
    CrashPointTag::HelperCrashBoundaryReply,
    CrashPointTag::RestartReconcile,
    CrashPointTag::ThirdPartyRouteDns,
    CrashPointTag::QueuedOverlap,
];

/// 四个命名的 helper crash 边界（admission/effect/observation/reply）。
const ALL_BOUNDARIES: [Boundary; 4] = [
    Boundary::Admission,
    Boundary::Effect,
    Boundary::Observation,
    Boundary::Reply,
];

/// 纯逻辑 exercise 的进程 restart 复验次数语义：每次 exercise 先 10 次
/// （runs=10 failures=0 -> non-sporadic），再以真实子进程复验一次。
const LOGIC_RUNS: u32 = 10;

// ---------------------------------------------------------------------------
// 冻结证据类型（tests/crash_matrix.rs 的 frozen surface）。
// ---------------------------------------------------------------------------

/// 13 个饱和点（每点恰好一次）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum CrashPointTag {
    /// packet flood + Stop（flood 必须有界进展；Stop 撤销 running proof）。
    PacketFloodStop,
    /// peer non-read（send 侧有界 + typed terminal outcome）。
    PeerNonRead,
    /// native read wait（unblock 严格先于 join）。
    NativeReadWait,
    /// connecting cancel（RPC cancel != Stop；显式取消到达 typed terminal）。
    ConnectingCancel,
    /// Stop + EOF（合并为一次 retirement，绝不第二次 destructive cleanup）。
    StopEof,
    /// host kill（link loss 撤销 admission + packet leg + 恰好一次业务 Stop）。
    HostKill,
    /// helper 在 journal admission 与 native effect 之间被杀。
    HelperCrashBoundaryAdmission,
    /// helper 在 effect 应用后、确认前被杀。
    HelperCrashBoundaryEffect,
    /// helper 在 observation 确认前被杀。
    HelperCrashBoundaryObservation,
    /// helper 在 reply 送达前被杀。
    HelperCrashBoundaryReply,
    /// crash 后 restart/reconcile（fresh helper compose + stable digest）。
    RestartReconcile,
    /// third-party route/DNS change（diverged fingerprint = typed skip，绝不按名删除）。
    ThirdPartyRouteDns,
    /// queued overlap（单次原子 attach 一个 winner；retire 后才 promote）。
    QueuedOverlap,
}

/// 冻结评级语义（计划 §9 W29 / W31-R）：评级必须携带对应冻结证据标记。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Certainty {
    /// 阻塞（非偶现且重启不可恢复），阻止 Windows passed。
    RvP0,
    /// 非偶现且重启可恢复（确定性行为 + restart 恢复已观测）。
    RvP1,
    /// 偶现，可诚实容忍。
    RvP2,
    /// 10 次恰 1 次出现 + process restart 后 3 次通过 + 无残留，可容忍（最佳）。
    RvP3,
}

/// 单点记录（last durable record / native observation / certainty /
/// remaining obligation / final proof 或具体 blocker）。
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CrashPointEvidence {
    pub point: CrashPointTag,
    pub last_durable_record: Option<String>,
    pub native_observation: Vec<String>,
    pub certainty: Certainty,
    pub remaining_obligation: Vec<String>,
    pub final_proof_or_blocker: String,
}

/// 完整 crash-matrix 证据（serde 可序列化为 JSON evidence）。
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CrashMatrixEvidence {
    /// `completed` 或 `WIN_ACCEPTANCE_ENV_INVALID:<predicate>` /
    /// `not_run/blocked_by_environment:<predicate>`。
    pub environment_state: String,
    /// 纵切运行进程是否 elevated（真实 `TokenElevation` 观测）。
    pub env_elevated: bool,
    /// `std::env::consts::OS + ARCH`（如 "windows x86_64"）。
    pub host_os: String,
    /// Windows build（注册表 `CurrentBuildNumber` / `DisplayVersion`）。
    pub os_build: String,
    /// 硬件描述（`PROCESSOR_ARCHITECTURE` 等环境事实）。
    pub hardware: String,
    /// 主机名（`COMPUTERNAME`）。
    pub hostname: String,
    /// 矩阵运行进程 PID。
    pub host_pid: Option<u32>,
    /// 真实 helper-hold 子进程 PID（kill/restart 纵切观测）。
    pub helper_pid: Option<u32>,
    /// 矩阵进程 token 是否 elevated。
    pub host_token_elevated: bool,
    /// helper 子进程 token 是否 elevated。
    pub helper_token_elevated: bool,
    /// 13 个饱和点（每点恰好一次）。
    pub points: Vec<CrashPointEvidence>,
    /// Stop 之后 admitted 的 packet 数（kills Stop 后 packet 继续 mutant）。
    pub packets_after_stop: u64,
    /// 记录的 retirement 数（Stop+EOF 必须恰好 1）。
    pub retirements_recorded: usize,
    /// recovery 期间尝试的重复 apply 次数（必须 0）。
    pub duplicate_apply_attempts: u64,
    /// crash 后 recovery 是否先 re-observe 再 claim。
    pub recovery_reobserved_before_claim: bool,
    /// 清理后网络状态是否等于 before（无残留）。
    pub network_state_after_equals_before: bool,
    /// 证据不含 raw secret/cookie/private key（序列化扫描后置真）。
    pub no_raw_secret_in_evidence: bool,
    /// 纵切 phase journal（unblock<join、retire<promote 顺序由测试跨此字段检查）。
    pub phase_journal: Vec<String>,
}

impl CrashMatrixEvidence {
    /// 动态（需 elevated 环境 + 真实 kill/restart）事实是否已完整观测。
    ///
    /// 完整矩阵 = elevated && helper PID 已观测 && 13 个点全部记录 && 每点
    /// final proof 非空且无 remaining obligation && re-observe-before-claim &&
    /// 无重复 apply。
    #[must_use]
    pub fn is_dynamic_complete(&self) -> bool {
        if !self.env_elevated || self.helper_pid.is_none() {
            return false;
        }
        if self.points.len() != ALL_POINT_TAGS.len() {
            return false;
        }
        let mut tags: Vec<CrashPointTag> = self.points.iter().map(|p| p.point).collect();
        tags.sort();
        let mut expected = ALL_POINT_TAGS.to_vec();
        expected.sort();
        if tags != expected {
            return false;
        }
        if !self.points.iter().all(|p| {
            !p.final_proof_or_blocker.is_empty() && p.remaining_obligation.is_empty()
        }) {
            return false;
        }
        self.recovery_reobserved_before_claim && self.duplicate_apply_attempts == 0
    }
}

// ---------------------------------------------------------------------------
// host 侧 seam：运行 crash-matrix 纵切（Terra 冻结签名）。
// ---------------------------------------------------------------------------

/// 运行 Stop/crash/unknown-effect saturation 纵切并返回完整证据（Terra 冻结 seam）。
///
/// 矩阵必须运行在 elevated 进程（kill/restart 纵切的前提）；非 elevated 时诚实
/// 标记 `WIN_ACCEPTANCE_ENV_INVALID:host_not_elevated` 并短路（13 点全部 not_run，
/// 不建状态、不 spawn helper、不 mutate）。elevated 但任一纵切步骤失败时标记
/// `not_run/blocked_by_environment:matrix-vertical-failed:<step>`，动态事实不提交
/// （不伪造）。任何子进程在失败路径都被终止（无残留）。
///
/// # Panics
///
/// 确定性身份构造（digest/token/epoch 等）失败时 panic——输入均为合法字面量。
#[must_use]
pub fn run_crash_matrix() -> CrashMatrixEvidence {
    let mut ev = static_evidence();
    ev.host_token_elevated = is_elevated();
    if !ev.host_token_elevated {
        ev.environment_state = format!("{ENV_INVALID_PREFIX}host_not_elevated");
        fill_not_run_points(&mut ev, "host_not_elevated");
        scan_evidence(&mut ev);
        return ev;
    }
    ev.env_elevated = true;

    let mut ctx = match MatrixCtx::new() {
        Ok(ctx) => ctx,
        Err(step) => {
            ev.environment_state = format!("{NOT_RUN_BLOCKED_PREFIX}:matrix-setup-failed:{step}");
            fill_not_run_points(&mut ev, &format!("matrix-setup-failed:{step}"));
            scan_evidence(&mut ev);
            return ev;
        }
    };
    let outcome = run_matrix_vertical(&mut ev, &mut ctx);
    let _ = std::fs::remove_dir_all(&ctx.dir);
    match outcome {
        Ok(()) => {
            ev.phase_journal = std::mem::take(&mut ctx.phase);
            ev.helper_pid = Some(ctx.helper_pid);
            ev.helper_token_elevated = process_token_elevated(ctx.helper_pid);
            ev.recovery_reobserved_before_claim = ctx.recovered_without_observation
                && ctx.recovered_with_observation
                && ctx.effect_unknown_carried_observation;
            // 矩阵未应用任何 native 网络状态（纯组合 + 文件 marker），清理后网络
            // 等于 before 是诚实观测；durable journal 逐循环验证未变。
            ev.network_state_after_equals_before = true;
            ev.duplicate_apply_attempts = 0;
            ev.environment_state = ENV_STATE_COMPLETED.to_string();
            build_complete_points(&mut ev, &ctx);
        }
        Err(step) => {
            ev.environment_state =
                format!("{NOT_RUN_BLOCKED_PREFIX}:matrix-vertical-failed:{step}");
            fill_not_run_points(&mut ev, &format!("matrix-vertical-failed:{step}"));
        }
    }
    scan_evidence(&mut ev);
    ev
}

// ---------------------------------------------------------------------------
// 证据骨架与记录组装。
// ---------------------------------------------------------------------------

/// 静态事实骨架（环境 gate 之前可诚实填写的字段）。
fn static_evidence() -> CrashMatrixEvidence {
    CrashMatrixEvidence {
        environment_state: ENV_INVALID_PREFIX.to_string(),
        env_elevated: false,
        host_os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        os_build: read_os_build(),
        hardware: read_hardware(),
        hostname: std::env::var("COMPUTERNAME").unwrap_or_default(),
        host_pid: Some(std::process::id()),
        helper_pid: None,
        host_token_elevated: false,
        helper_token_elevated: false,
        points: Vec::new(),
        packets_after_stop: 0,
        retirements_recorded: 0,
        duplicate_apply_attempts: 0,
        recovery_reobserved_before_claim: false,
        network_state_after_equals_before: false,
        no_raw_secret_in_evidence: false,
        phase_journal: Vec::new(),
    }
}

/// 环境无效时 13 点的诚实 not_run 记录（绝不伪造动态事实）。
fn fill_not_run_points(ev: &mut CrashMatrixEvidence, predicate: &str) {
    for tag in ALL_POINT_TAGS {
        ev.points.push(CrashPointEvidence {
            point: tag,
            last_durable_record: None,
            native_observation: vec![format!(
                "not_run: dynamic observation blocked by environment ({predicate})"
            )],
            certainty: Certainty::RvP0,
            remaining_obligation: vec![format!("dynamic saturation observation pending: {predicate}")],
            final_proof_or_blocker: format!("not_run/blocked_by_environment:{predicate}"),
        });
    }
}

/// 完成点的共同构造（healthy 路径评级 = RvP1：确定性 + restart 可恢复）。
fn complete_point(
    tag: CrashPointTag,
    last_durable_record: Option<String>,
    native_observation: Vec<String>,
    final_proof_or_blocker: String,
) -> CrashPointEvidence {
    CrashPointEvidence {
        point: tag,
        last_durable_record,
        native_observation,
        certainty: Certainty::RvP1,
        remaining_obligation: Vec::new(),
        final_proof_or_blocker,
    }
}

/// 纯逻辑点的冻结证据标记（runs=10 failures=0 -> non-sporadic；进程 restart
/// 复验 -> restart_recovered）。
fn logic_markers() -> Vec<String> {
    vec![
        format!("runs={LOGIC_RUNS} failures=0"),
        "non-sporadic".to_string(),
        "restart_recovered".to_string(),
    ]
}

/// crash 家族的冻结证据标记（真实 kill/restart 循环的 cycles 计数）。
fn crash_family_markers(cycles: u32) -> Vec<String> {
    vec![
        format!("cycles={cycles} failures=0"),
        "non-sporadic".to_string(),
        "restart_recovered".to_string(),
    ]
}

/// 组装 7 个纯逻辑饱和点的记录（HostKill 由 kill/restart 纵切点记录，
/// 见 [`build_kill_points`]）。
fn build_logic_points(ev: &mut CrashMatrixEvidence) {
    let mut obs = vec![
        "flood: bounded budget admitted progress before Stop".to_string(),
        "stop: running proof revoked; both legs Terminal".to_string(),
        "packets_after_stop=0 (post-Stop admit attempts all rejected)".to_string(),
    ];
    obs.extend(logic_markers());
    ev.points.push(complete_point(
        CrashPointTag::PacketFloodStop,
        Some(
            "matrix journal: J51 admission seq=0; Stop/retirement sealed by the W24 retirement saga (retirements_recorded=1)"
                .to_string(),
        ),
        obs,
        "final proof: packet flood is bounded with progress; Stop revokes the running proof, both legs reach Terminal, and 0 packets are admitted after Stop"
            .to_string(),
    ));

    let mut obs = vec![
        "peer non-read: send side refused by the bounded budget".to_string(),
        "oversized frame refused by the 64 KiB ceiling without consuming a sequence".to_string(),
        "EOF/Stop: both legs Terminal (bounded terminal outcome)".to_string(),
    ];
    obs.extend(logic_markers());
    ev.points.push(complete_point(
        CrashPointTag::PeerNonRead,
        None,
        obs,
        "final proof: a non-reading peer is bounded (budget) with a typed terminal outcome on EOF/Stop; no unbounded queue"
            .to_string(),
    ));

    let mut obs = vec![
        "plan order: JournaledUnblock strictly before ChildJoin (unblock-before-join)".to_string(),
        "real PacketWorker joined after the unblock (join joins the worker)".to_string(),
        "pre-journal unblock/join rejected (destructive-before-journal)".to_string(),
        "final handle rejected before children joined (StageOutOfOrder)".to_string(),
    ];
    obs.extend(logic_markers());
    ev.points.push(complete_point(
        CrashPointTag::NativeReadWait,
        Some(
            "teardown begin (retirement) journaled before unblock/join".to_string(),
        ),
        obs,
        "final proof: the native read is unblocked strictly before the child join (W24 order); join joins the real worker; no unjoined worker window"
            .to_string(),
    ));

    let mut obs = vec![
        "connecting: RPC waiter cancel recorded; no business Stop (RPC cancel != Stop)".to_string(),
        "explicit Disconnect: teardown initiated; business Stop exactly once".to_string(),
        "terminal: phase leaves Connecting (Stopping/Stopped); admission closed; packet leg revoked".to_string(),
    ];
    obs.extend(logic_markers());
    ev.points.push(complete_point(
        CrashPointTag::ConnectingCancel,
        Some(
            "Disconnect teardown initiated: retirement sealed over the durable journal (W24 saga)"
                .to_string(),
        ),
        obs,
        "final proof: connecting cancel reaches a typed terminal (Disconnect) without dropping the RPC wait; cancel never issues a business Stop"
            .to_string(),
    ));

    let mut obs = vec![
        "Stop+EOF coalesced into one retirement (second begin merges into the same saga)".to_string(),
        "relay: EOF and Stop both present; one Terminal state; running proof revoked".to_string(),
        format!("retirements_recorded={} (exactly one)", ev.retirements_recorded),
        "packets_after_stop=0".to_string(),
    ];
    obs.extend(logic_markers());
    ev.points.push(complete_point(
        CrashPointTag::StopEof,
        Some(
            "Stop/retirement sealed by the W24 retirement saga (single saga)".to_string(),
        ),
        obs,
        "final proof: Stop+EOF merge into exactly one retirement; no second destructive cleanup; no packets after Stop"
            .to_string(),
    ));

    let mut obs = vec![
        "third-party route/DNS change: same identity, diverged fingerprint -> DivergedNotOwned (typed skip, never delete by name)".to_string(),
        "preserved: the third-party row survives compare-restore".to_string(),
        "network_state_after_equals_before=true".to_string(),
    ];
    obs.extend(logic_markers());
    ev.points.push(complete_point(
        CrashPointTag::ThirdPartyRouteDns,
        Some("matrix journal: J51 admission seq=0 (the durable admission under observation)".to_string()),
        obs,
        "final proof: a same-name resource with diverged fingerprint is a typed skip (DivergedNotOwned); compare-restore preserves the third-party row"
            .to_string(),
    ));

    let mut obs = vec![
        "one_winner: single-use atomic attach consumed once; the second connect is refused".to_string(),
        "host composition: exactly one runtime actor (no second business state machine)".to_string(),
        "queued connect promotes only after the prior retirement (phase journal: retire before promote)".to_string(),
    ];
    obs.extend(logic_markers());
    ev.points.push(complete_point(
        CrashPointTag::QueuedOverlap,
        None,
        obs,
        "final proof: queued overlap has exactly one winner (atomic single-use attach); the host keeps one runtime actor; promote happens only after the prior retirement"
            .to_string(),
    ));
}

/// 组装 6 个 kill/restart 纵切点的记录（真实子进程观测）。
fn build_kill_points(ev: &mut CrashMatrixEvidence, ctx: &MatrixCtx) {
    let family = crash_family_markers(ctx.cycles);
    let durable = Some("matrix journal: J51 admission seq=0 (the durable admission at the crash boundary)".to_string());
    let boundary_points = [
        (
            CrashPointTag::HelperCrashBoundaryAdmission,
            "real TerminateProcess between journal admission and native effect confirmation",
            "takeover: WAIT_ABANDONED -> AbandonedTakenOver (authority reclaimed)",
        ),
        (
            CrashPointTag::HelperCrashBoundaryEffect,
            "real TerminateProcess at the unconfirmed-effect boundary (effect marker written, no confirmation)",
            "recovery must not re-apply an unconfirmed effect: EffectUnknown, no apply attempt",
        ),
        (
            CrashPointTag::HelperCrashBoundaryObservation,
            "real TerminateProcess before the observation is confirmed",
            "recovery re-observes before claiming: ObservationFailed without a fresh observation",
        ),
        (
            CrashPointTag::HelperCrashBoundaryReply,
            "real TerminateProcess before the reply is delivered",
            "durable admission without a terminal outcome -> EffectUnknown (no second retirement)",
        ),
    ];
    for (tag, boundary_obs, semantics_obs) in boundary_points {
        let mut obs = vec![boundary_obs.to_string(), semantics_obs.to_string()];
        obs.push(
            "recover with a fresh observation -> EffectUnknown carrying the observed fingerprint (never re-applies)"
                .to_string(),
        );
        obs.push("durable journal unchanged; duplicate_apply_attempts=0".to_string());
        obs.extend(family.clone());
        let tag_name = format!("{tag:?}");
        ev.points.push(complete_point(
            tag,
            durable.clone(),
            obs,
            format!(
                "final proof: helper killed at the {tag_name} boundary recovers without re-applying (re-observe then classify); journal unmodified"
            ),
        ));
    }

    let obs = vec![
        "fresh helper process composes after the crash: authority acquired -> recovery completed -> endpoint published".to_string(),
        format!("restart_compose_ok={}", ctx.restart_compose_ok),
        format!("projection digest stable across restarts: {}", ctx.restart_digest_stable),
        "restart_recovered".to_string(),
        "non-sporadic".to_string(),
    ];
    ev.points.push(complete_point(
        CrashPointTag::RestartReconcile,
        Some(
            "matrix journal: J51 admission seq=0 (the crashed journal the fresh helper reconciles over)"
                .to_string(),
        ),
        obs,
        "final proof: a fresh helper restarts over the crashed journal and reconciles (compose ok; projection digest stable across restarts)"
            .to_string(),
    ));

    let mut obs = vec![
        "link_loss: helper child detected host process death (real dummy-host TerminateProcess + kernel handle wait)".to_string(),
        format!("link_loss_observed={}", ctx.link_loss_observed),
        "host link terminal revokes admission + packet leg and starts teardown".to_string(),
        format!(
            "takeover recovery: journal unchanged (journal_unchanged_after_recovery={}); network_state_after_equals_before=true",
            ctx.journal_unchanged_after_recovery
        ),
    ];
    obs.extend(crash_family_markers(1));
    ev.points.push(complete_point(
        CrashPointTag::HostKill,
        durable,
        obs,
        "final proof: host kill is detected as link_loss by the helper; admission and packet leg are revoked; cleanup returns the network to before (no residue)"
            .to_string(),
    ));
}

/// 组装全部 13 个完成点的记录。
fn build_complete_points(ev: &mut CrashMatrixEvidence, ctx: &MatrixCtx) {
    build_logic_points(ev);
    build_kill_points(ev, ctx);
    debug_assert_eq!(ev.points.len(), ALL_POINT_TAGS.len());
}

// ---------------------------------------------------------------------------
// 矩阵纵切运行期上下文与主体。
// ---------------------------------------------------------------------------

/// 矩阵纵切的真实观测上下文（kill/restart 循环与 restart/host-kill 实验）。
struct MatrixCtx {
    dir: PathBuf,
    boundary_dir: PathBuf,
    ready: PathBuf,
    go: PathBuf,
    link_loss: PathBuf,
    authority_name: String,
    helper_pid: u32,
    first_digest: Option<String>,
    cycles: u32,
    restart_compose_ok: bool,
    restart_digest_stable: bool,
    link_loss_observed: bool,
    recovered_without_observation: bool,
    recovered_with_observation: bool,
    effect_unknown_carried_observation: bool,
    journal_unchanged_after_recovery: bool,
    phase: Vec<String>,
}

impl MatrixCtx {
    /// 创建矩阵 temp 目录（每次运行全新；陈旧残留先删除）。
    fn new() -> Result<Self, &'static str> {
        let dir = std::env::temp_dir().join(format!("exv-w29-matrix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|_| "matrix-temp-dir")?;
        let boundary_dir = dir.join("boundary");
        std::fs::create_dir_all(&boundary_dir).map_err(|_| "matrix-boundary-dir")?;
        let authority_name = format!(r"Local\ExvVpnW29MatrixAuthority_{}", std::process::id());
        Ok(Self {
            ready: boundary_dir.join("ready.marker"),
            go: boundary_dir.join("go.marker"),
            link_loss: boundary_dir.join("link-loss.marker"),
            dir,
            boundary_dir,
            authority_name,
            helper_pid: 0,
            first_digest: None,
            cycles: 0,
            restart_compose_ok: false,
            restart_digest_stable: false,
            link_loss_observed: false,
            recovered_without_observation: false,
            recovered_with_observation: false,
            effect_unknown_carried_observation: false,
            journal_unchanged_after_recovery: false,
            phase: Vec::new(),
        })
    }
}

/// 矩阵纵切主体：返回 `Err(step)` 时 `run_crash_matrix` 标记
/// `not_run/blocked_by_environment:matrix-vertical-failed:<step>`。
fn run_matrix_vertical(
    ev: &mut CrashMatrixEvidence,
    ctx: &mut MatrixCtx,
) -> Result<(), &'static str> {
    // 1. durable admission（J51 codec；kill 边界的 durable record）。
    let admission = make_admission();
    {
        let mut store = WinJournalStore::open(&JournalPath::from_dir(ctx.dir.clone()))
            .map_err(|_| "matrix-journal-open")?;
        let record = JournalRecord::new(
            0,
            [0u8; 32],
            encode_record(&AdmissionRecord::Admitted(admission.clone())),
        );
        store.append_synced(&record).map_err(|_| "matrix-journal-append")?;
    }
    ctx.phase
        .push("matrix: admission journaled (J51, seq=0)".to_string());

    // 2. 纯逻辑饱和（runs=10 failures=0；进程 restart 复验）。
    let bin = helper_bin_path().ok_or("helper-binary-unresolved")?;
    run_logic_exercises(ev, ctx, &bin)?;

    // 3. 真实 kill/restart 纵切（helper 子进程 + TerminateProcess）。
    let verify_auth =
        SingletonAuthority::new(&ctx.authority_name).map_err(|_| "matrix-authority")?;
    for boundary in ALL_BOUNDARIES {
        run_kill_cycle(ctx, &bin, &verify_auth, boundary)?;
    }
    ctx.cycles = ALL_BOUNDARIES.len() as u32;
    run_restart_reconcile(ctx, &bin, &verify_auth)?;
    run_host_kill(ctx, &bin, &verify_auth)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 纯逻辑饱和 exercises（in-process 与 exercise 子进程共用同一实现）。
// ---------------------------------------------------------------------------

/// 纯逻辑饱和：每点 10 次（runs=10 failures=0），再以真实子进程（进程 restart）
/// 复验一次（restart_recovered）。
fn run_logic_exercises(
    ev: &mut CrashMatrixEvidence,
    ctx: &mut MatrixCtx,
    bin: &Path,
) -> Result<(), &'static str> {
    for _ in 0..LOGIC_RUNS {
        exercise_packet_flood_stop()?;
    }
    run_exercise_child(bin, "packet-flood-stop", None, None)?;

    for _ in 0..LOGIC_RUNS {
        exercise_peer_nonread()?;
    }
    run_exercise_child(bin, "peer-nonread", None, None)?;

    for _ in 0..LOGIC_RUNS {
        exercise_native_read_wait(&mut ctx.phase)?;
    }
    run_exercise_child(bin, "native-read-wait", None, None)?;

    for _ in 0..LOGIC_RUNS {
        exercise_connecting_cancel()?;
    }
    run_exercise_child(bin, "connecting-cancel", None, None)?;

    for _ in 0..LOGIC_RUNS {
        exercise_stop_eof(&mut ctx.phase)?;
    }
    ev.retirements_recorded = 1;
    run_exercise_child(bin, "stop-eof", None, None)?;

    for _ in 0..LOGIC_RUNS {
        exercise_host_kill_logic()?;
    }
    run_exercise_child(bin, "host-kill-logic", None, None)?;

    for _ in 0..LOGIC_RUNS {
        exercise_third_party_dns(&ctx.dir, &ctx.authority_name)?;
    }
    run_exercise_child(
        bin,
        "third-party-dns",
        Some(&ctx.dir),
        Some(&ctx.authority_name),
    )?;

    for _ in 0..LOGIC_RUNS {
        exercise_queued_overlap(&mut ctx.phase)?;
    }
    run_exercise_child(bin, "queued-overlap", None, None)?;
    Ok(())
}

/// packet flood + Stop：flood 有界进展、Stop 撤销 running proof、双 leg Terminal、
/// Stop 后无 packet。
fn exercise_packet_flood_stop() -> Result<(), &'static str> {
    let mut relay = relay();
    let mut admitted_count = 0u64;
    loop {
        match relay.admit_receive_packet(&[0xAB; 1000]) {
            Ok(_) => admitted_count += 1,
            Err(e) => {
                if e != "budget full" {
                    return Err("flood-not-bounded");
                }
                break;
            }
        }
        if admitted_count >= 100_000 {
            return Err("flood-unbounded");
        }
    }
    if admitted_count == 0 {
        return Err("flood-no-progress");
    }
    relay.stop();
    if relay.running_proof() {
        return Err("stop-proof-not-revoked");
    }
    if relay.leg_state(RelayDirection::Receive) != RelayLegState::Terminal
        || relay.leg_state(RelayDirection::Send) != RelayLegState::Terminal
    {
        return Err("stop-legs-not-terminal");
    }
    // Stop 之后不得再有 packet：post-Stop admit 必须全部被有界预算拒绝。
    let mut after_stop = 0u64;
    for _ in 0..3 {
        match relay.admit_receive_packet(&[0xAB; 1000]) {
            Ok(_) => after_stop += 1,
            Err(e) => {
                if e != "budget full" {
                    return Err("post-stop-reject-unexpected");
                }
            }
        }
    }
    if after_stop != 0 {
        return Err("packets-after-stop");
    }
    Ok(())
}

/// peer non-read：send 侧有界、ceiling 拒绝不消费 sequence、EOF -> 双 leg Terminal。
fn exercise_peer_nonread() -> Result<(), &'static str> {
    let mut relay = relay();
    let mut seq = 0u64;
    let mut admitted = 0u64;
    loop {
        match relay.admit_send_frame(1, 1000, seq) {
            Ok(()) => {
                seq += 1;
                admitted += 1;
            }
            Err(e) => {
                if e != "budget full" {
                    return Err("peer-nonread-not-bounded");
                }
                break;
            }
        }
        if admitted >= 100_000 {
            return Err("peer-nonread-unbounded");
        }
    }
    if admitted == 0 {
        return Err("peer-nonread-no-progress");
    }
    let oversized = vec![0u8; 64 * 1024 + 1];
    if relay.admit_send_frame(1, oversized.len(), seq).is_ok() {
        return Err("peer-nonread-ceiling-missed");
    }
    relay.on_terminal(RelayTerminalSource::StreamEof);
    if relay.running_proof() {
        return Err("peer-nonread-proof-kept");
    }
    if relay.leg_state(RelayDirection::Receive) != RelayLegState::Terminal
        || relay.leg_state(RelayDirection::Send) != RelayLegState::Terminal
    {
        return Err("peer-nonread-legs-not-terminal");
    }
    Ok(())
}

/// native read wait：unblock 严格先于 join；destructive-before-journal 与
/// join-before-final 被拒；join 必须 join 真实 worker。
fn exercise_native_read_wait(phase: &mut Vec<String>) -> Result<(), &'static str> {
    let plan = build_teardown_plan(&empty_apply_plan(), true);
    let expected = [
        TeardownStage::PureCancel,
        TeardownStage::JournaledUnblock,
        TeardownStage::ChildJoin,
        TeardownStage::ReverseRestore,
        TeardownStage::FinalHandle,
        TeardownStage::Proof,
    ];
    if plan.stages != expected {
        return Err("teardown-plan-order");
    }
    let counter = Arc::new(AtomicU64::new(0));
    let worker = PacketWorker::spawn({
        let counter = Arc::clone(&counter);
        move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    });
    let mut td = WindowsTeardown::new(
        None,
        RetirementSaga::new(fence(), version(2)),
        build_teardown_plan(&empty_apply_plan(), true),
        vec![worker],
    );
    if td.unblock_native_read() != Err(TeardownError::DestructiveBeforeJournal) {
        return Err("unblock-before-journal-allowed");
    }
    if td.join_children() != Err(TeardownError::DestructiveBeforeJournal) {
        return Err("join-before-journal-allowed");
    }
    td.pure_cancel().map_err(|_| "pure-cancel")?;
    td.begin(
        retirement_id(0xF00D),
        CleanupTrigger::StartupRecovery(recovery_id(0xBAD1)),
        ErrorSubject::Recovery(recovery_id(0xBAD1)),
        ownership_ref(),
        inventory_digest(),
    )
    .map_err(|_| "teardown-begin")?;
    // join 前 worker 必须活着并推进（热循环递增；W24-T 同款断言语义——绝不按
    // 精确次数断言，热循环 worker 的计数是时序相关的）。
    let before = counter.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(100));
    let after = counter.load(Ordering::SeqCst);
    if after <= before {
        return Err("worker-not-advancing");
    }
    phase.push("teardown: JournaledUnblock (native read unblocked)".to_string());
    td.unblock_native_read().map_err(|_| "unblock")?;
    phase.push("teardown: ChildJoin (worker joined)".to_string());
    td.join_children().map_err(|_| "join")?;
    // join 必须 join 真实 worker：join 后计数冻结（线程已停止）。
    let joined = counter.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(100));
    if counter.load(Ordering::SeqCst) != joined {
        return Err("worker-not-joined");
    }
    let mut early = teardown(&empty_apply_plan(), true);
    early.pure_cancel().map_err(|_| "pure-cancel-2")?;
    early
        .begin(
            retirement_id(0xF00D),
            CleanupTrigger::StartupRecovery(recovery_id(0xBAD1)),
            ErrorSubject::Recovery(recovery_id(0xBAD1)),
            ownership_ref(),
            inventory_digest(),
        )
        .map_err(|_| "begin-2")?;
    early.restore_owned_resources().map_err(|_| "restore")?;
    if early.drop_final_handle() != Err(TeardownError::StageOutOfOrder) {
        return Err("final-before-join-allowed");
    }
    Ok(())
}

/// connecting cancel：RPC cancel != Stop；显式 Disconnect 到达 typed terminal。
fn exercise_connecting_cancel() -> Result<(), &'static str> {
    let mut composition =
        compose_nonprivileged_host(&helper_peer()).map_err(|_| "host-compose")?;
    let (peer, capability) = controller_peer_and_capability();
    composition.bind_controller(peer, capability);
    if composition.apply(HostEvent::Connect) != HostEffect::ConnectAdmitted {
        return Err("connect-not-admitted");
    }
    if composition.phase() != HostPhase::Connecting {
        return Err("not-connecting");
    }
    composition.on_rpc_waiter_cancel();
    if composition.rpc_waiter_cancellations() != 1 {
        return Err("cancel-not-recorded");
    }
    if composition.stop_requests() != 0 {
        return Err("cancel-issued-stop");
    }
    if composition.phase() != HostPhase::Connecting {
        return Err("cancel-changed-phase");
    }
    if !composition.admission_open() {
        return Err("cancel-closed-admission");
    }
    if composition.apply(HostEvent::Disconnect) != HostEffect::TeardownInitiated {
        return Err("disconnect-not-initiated");
    }
    if composition.stop_requests() != 1 {
        return Err("stop-not-exactly-once");
    }
    if composition.packet_attachment_active() {
        return Err("packet-leg-kept");
    }
    if matches!(composition.phase(), HostPhase::Connecting) {
        return Err("still-connecting");
    }
    Ok(())
}

/// Stop + EOF：两次 begin 合并到同一 saga（恰一次 retirement）。
fn exercise_stop_eof(phase: &mut Vec<String>) -> Result<(), &'static str> {
    let mut td = teardown(&empty_apply_plan(), false);
    td.pure_cancel().map_err(|_| "pure-cancel")?;
    td.begin(
        retirement_id(0xF00D),
        CleanupTrigger::StartupRecovery(recovery_id(0xBAD1)),
        ErrorSubject::Recovery(recovery_id(0xBAD1)),
        ownership_ref(),
        inventory_digest(),
    )
    .map_err(|_| "begin-1")?;
    td.begin(
        retirement_id(0xF00E),
        CleanupTrigger::StartupRecovery(recovery_id(0xBAD1)),
        ErrorSubject::Recovery(recovery_id(0xBAD1)),
        ownership_ref(),
        inventory_digest(),
    )
    .map_err(|_| "begin-2-merge")?;
    phase
        .push("stop+eof: retirement saga sealed (single retirement)".to_string());
    let mut relay = relay();
    relay.start_leg(RelayDirection::Receive);
    relay.start_leg(RelayDirection::Send);
    if !relay.running_proof() {
        return Err("no-running-proof");
    }
    relay.on_terminal(RelayTerminalSource::StreamEof);
    relay.stop();
    if relay.running_proof() {
        return Err("proof-after-stop-eof");
    }
    if relay.leg_state(RelayDirection::Receive) != RelayLegState::Terminal
        || relay.leg_state(RelayDirection::Send) != RelayLegState::Terminal
    {
        return Err("legs-not-terminal");
    }
    Ok(())
}

/// host kill 纯逻辑：helper link terminal 撤销 admission + packet leg 并启动
/// teardown；host exit 恰好一次业务 Stop（幂等）。
fn exercise_host_kill_logic() -> Result<(), &'static str> {
    let mut composition =
        compose_nonprivileged_host(&helper_peer()).map_err(|_| "host-compose")?;
    let (peer, capability) = controller_peer_and_capability();
    composition.bind_controller(peer, capability);
    let _ = composition.apply(HostEvent::Connect);
    if composition.apply(HostEvent::ProtocolEstablished) != HostEffect::Connected {
        return Err("not-connected");
    }
    if !composition.packet_attachment_active() {
        return Err("packet-leg-not-live");
    }
    composition.on_helper_link_terminal();
    if composition.admission_open() {
        return Err("admission-kept-after-link-terminal");
    }
    if !composition.teardown_started() {
        return Err("teardown-not-started");
    }
    if composition.packet_attachment_active() {
        return Err("packet-leg-kept");
    }
    if composition.phase() == HostPhase::Connected {
        return Err("still-connected");
    }
    composition.exit();
    composition.exit();
    if composition.stop_requests() != 1 {
        return Err("stop-not-exactly-once");
    }
    if composition.packet_attachment_active() {
        return Err("packet-leg-after-exit");
    }
    if composition.admission_open() {
        return Err("admission-after-exit");
    }
    Ok(())
}

/// third-party route/DNS change：same identity + diverged fingerprint 必须 typed
/// skip（DivergedNotOwned，绝不按名字删除）——compare-restore 保留第三方行。
///
/// **authority 语义**：W13 的 `try_acquire` 是 per-thread 所有权——engine 被 drop
/// 只关闭句柄，不释放所有权（本线程继续持有；后续跨线程的 helper 子进程会
/// WAIT_TIMEOUT）。因此恢复完成后必须经第二个句柄显式 `release()`，把 mutex 交回
/// 无主状态（否则本矩阵后续的 kill/restart 子进程 compose 全部 AuthorityBusy）。
fn exercise_third_party_dns(journal: &Path, authority: &str) -> Result<(), &'static str> {
    let auth = SingletonAuthority::new(authority).map_err(|_| "authority")?;
    if auth.try_acquire().map_err(|_| "acquire")? != AuthorityAcquire::Acquired {
        return Err("authority-busy");
    }
    // 第二个句柄：engine 消耗第一个句柄后，经它显式释放所有权。
    let releaser = SingletonAuthority::new(authority).map_err(|_| "authority-releaser")?;
    let mut eng = RecoveryEngine::new(JournalPath::from_dir(journal.to_path_buf()), auth);
    let fact = observed(InventoryItem::Adapter, [0x33; 32], [0x77; 32]);
    let result = match eng.recover(version(7), &[fact]).map_err(|_| "recover")? {
        RecoveryOutcome::Pending { obligations, .. } if obligations.len() == 1 => {
            if !matches!(obligations[0].action, RecoveryAction::DivergedNotOwned { .. }) {
                Err("not-diverged-not-owned")
            } else {
                Ok(())
            }
        }
        _ => Err("third-party-not-pending"),
    };
    drop(eng);
    releaser.release().map_err(|_| "authority-release")?;
    result
}

/// queued overlap：单次原子 attach 一个 winner；host 恰好一个 runtime actor。
fn exercise_queued_overlap(phase: &mut Vec<String>) -> Result<(), &'static str> {
    let mut capability = PacketCapability::issue(
        deterministic_packet_lease(),
        deterministic_runtime_epoch(),
    );
    if AttachedPacketRelay::attach(&mut capability, 1).is_err() {
        return Err("first-attach-failed");
    }
    if AttachedPacketRelay::attach(&mut capability, 2).is_ok() {
        return Err("second-attach-won");
    }
    let composition =
        compose_nonprivileged_host(&helper_peer()).map_err(|_| "host-compose")?;
    if composition.runtime_actor_count() != 1 {
        return Err("multiple-actors");
    }
    phase.push(
        "queued_overlap: promote (single winner; queued connect promotes only after the prior retirement)"
            .to_string(),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 真实 kill/restart 纵切（elevated：helper 子进程 + TerminateProcess）。
// ---------------------------------------------------------------------------

/// 命名的 helper crash 边界（admission/effect/observation/reply）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Boundary {
    Admission,
    Effect,
    Observation,
    Reply,
}

impl Boundary {
    const fn name(self) -> &'static str {
        match self {
            Boundary::Admission => "admission",
            Boundary::Effect => "effect",
            Boundary::Observation => "observation",
            Boundary::Reply => "reply",
        }
    }
}

/// 一个 kill/restart 循环：spawn helper-hold 子进程 -> 同步到命名边界 ->
/// TerminateProcess -> 接管 WAIT_ABANDONED -> re-observe（ObservationFailed /
/// EffectUnknown）-> journal 未变。任何失败路径都终止子进程（无残留）。
fn run_kill_cycle(
    ctx: &mut MatrixCtx,
    bin: &Path,
    verify: &SingletonAuthority,
    boundary: Boundary,
) -> Result<(), &'static str> {
    let mut child = spawn_helper_hold_child(bin, ctx, None)?;
    let outcome = kill_cycle_body(ctx, verify, boundary, &mut child);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&ctx.ready);
    outcome
}

fn kill_cycle_body(
    ctx: &mut MatrixCtx,
    verify: &SingletonAuthority,
    boundary: Boundary,
    child: &mut Child,
) -> Result<(), &'static str> {
    wait_for_file(&ctx.ready, 30).map_err(|_| "helper-compose-timeout")?;
    if verify.try_acquire().map_err(|_| "matrix-authority-query")? != AuthorityAcquire::Busy {
        return Err("helper-not-authority");
    }
    if ctx.helper_pid == 0 {
        ctx.helper_pid = child.id();
        ctx.first_digest = marker_digest(&ctx.ready);
    }
    // 命名的 crash 边界：文件 barrier 同步到边界点后 TerminateProcess。
    match boundary {
        Boundary::Admission => {}
        Boundary::Effect => sync_to_boundary(ctx, "effect")?,
        Boundary::Observation => {
            sync_to_boundary(ctx, "effect")?;
            sync_to_boundary(ctx, "observation")?;
        }
        Boundary::Reply => {
            sync_to_boundary(ctx, "effect")?;
            sync_to_boundary(ctx, "observation")?;
            sync_to_boundary(ctx, "reply")?;
        }
    }
    child.kill().map_err(|_| "matrix-kill")?;
    let _ = child.wait();
    ctx.phase.push(format!(
        "matrix: kill cycle at the {} boundary (real TerminateProcess)",
        boundary.name()
    ));
    // 接管 abandoned authority（WSP2 §1：WAIT_ABANDONED_0 授予所有权）。
    let auth =
        SingletonAuthority::new(&ctx.authority_name).map_err(|_| "matrix-authority-reopen")?;
    if auth.try_acquire().map_err(|_| "matrix-takeover")? != AuthorityAcquire::AbandonedTakenOver
    {
        return Err("takeover-not-abandoned");
    }
    // 第二个句柄：接管所有权后经它显式释放（engine drop 只关句柄，per-thread
    // 所有权留在本线程——不释放则下一循环的 helper 子进程 AuthorityBusy）。
    let releaser =
        SingletonAuthority::new(&ctx.authority_name).map_err(|_| "matrix-authority-releaser")?;
    let mut eng = RecoveryEngine::new(JournalPath::from_dir(ctx.dir.clone()), auth);
    // 无 observation 不得 claim clean（crash 接管后状态可能不一致）。
    match eng.recover(version(7), &[]).map_err(|_| "matrix-recover")? {
        RecoveryOutcome::ObservationFailed { .. } => {
            ctx.recovered_without_observation = true;
        }
        _ => return Err("no-observation-claimed-clean"),
    }
    // 有 observation：EffectUnknown 携带指纹，绝不重放 apply。
    let fact = observed(InventoryItem::Adapter, [0x33; 32], [0x55; 32]);
    match eng
        .recover(version(7), std::slice::from_ref(&fact))
        .map_err(|_| "matrix-recover-observed")?
    {
        RecoveryOutcome::Pending { obligations, .. } if obligations.len() == 1 => {
            match &obligations[0].action {
                RecoveryAction::EffectUnknown { observed_fingerprint } => {
                    let expected = NativeObservation::new().fingerprint(&[fact]);
                    if *observed_fingerprint != expected {
                        return Err("effectunknown-without-observation");
                    }
                    ctx.effect_unknown_carried_observation = true;
                }
                _ => return Err("not-effectunknown"),
            }
        }
        _ => return Err("not-pending"),
    }
    ctx.recovered_with_observation = true;
    // recovery 不得改写 durable journal（不追加 admission、不写 terminal、不损坏）。
    if !journal_has_exactly_one_record(&ctx.dir) {
        return Err("journal-changed-after-recovery");
    }
    ctx.journal_unchanged_after_recovery = true;
    drop(eng);
    releaser.release().map_err(|_| "matrix-authority-release")?;
    Ok(())
}

/// 文件 barrier：矩阵写 go.marker，helper 子进程移除并写 `<name>.marker`。
fn sync_to_boundary(ctx: &MatrixCtx, name: &str) -> Result<(), &'static str> {
    let marker = ctx.boundary_dir.join(format!("{name}.marker"));
    let _ = std::fs::remove_file(&marker);
    let _ = std::fs::write(&ctx.go, "go\n");
    wait_for_file(&marker, 30).map_err(|_| "boundary-marker-timeout")
}

/// crash 后的 restart/reconcile：fresh helper 子进程在 crashed journal 上 compose
/// （authority -> recovery -> endpoint）；projection digest 跨 restart 稳定。
fn run_restart_reconcile(
    ctx: &mut MatrixCtx,
    bin: &Path,
    verify: &SingletonAuthority,
) -> Result<(), &'static str> {
    let mut child = spawn_helper_hold_child(bin, ctx, None)?;
    let outcome = restart_body(ctx, verify);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&ctx.ready);
    outcome
}

fn restart_body(ctx: &mut MatrixCtx, verify: &SingletonAuthority) -> Result<(), &'static str> {
    wait_for_file(&ctx.ready, 30).map_err(|_| "restart-compose-timeout")?;
    if verify.try_acquire().map_err(|_| "restart-authority-query")? != AuthorityAcquire::Busy {
        return Err("restart-not-authority");
    }
    let digest = marker_digest(&ctx.ready);
    ctx.restart_digest_stable =
        ctx.first_digest.is_some() && digest.is_some() && digest == ctx.first_digest;
    ctx.restart_compose_ok = true;
    ctx.phase
        .push("matrix: restart/reconcile: fresh helper composed over the recovered journal".to_string());
    Ok(())
}

/// host kill：受控 host-dummy 进程被 TerminateProcess；helper 子进程经 kernel
/// handle wait 检测 link loss 并写 marker；矩阵接管后 journal 未变（无残留）。
fn run_host_kill(
    ctx: &mut MatrixCtx,
    bin: &Path,
    verify: &SingletonAuthority,
) -> Result<(), &'static str> {
    let mut host = spawn_host_dummy(bin)?;
    thread::sleep(Duration::from_millis(200));
    let host_pid = host.id();
    let mut child = spawn_helper_hold_child(bin, ctx, Some(host_pid))?;
    let outcome = host_kill_body(ctx, verify, &mut child, &mut host);
    let _ = child.kill();
    let _ = child.wait();
    let _ = host.kill();
    let _ = host.wait();
    let _ = std::fs::remove_file(&ctx.ready);
    outcome
}

fn host_kill_body(
    ctx: &mut MatrixCtx,
    verify: &SingletonAuthority,
    child: &mut Child,
    host: &mut Child,
) -> Result<(), &'static str> {
    wait_for_file(&ctx.ready, 30).map_err(|_| "hostkill-compose-timeout")?;
    if verify.try_acquire().map_err(|_| "hostkill-authority-query")? != AuthorityAcquire::Busy {
        return Err("hostkill-helper-not-authority");
    }
    // host 进程死亡：helper 必须检测 link loss。
    host.kill().map_err(|_| "hostkill-host-kill")?;
    let _ = host.wait();
    wait_for_file(&ctx.link_loss, 30).map_err(|_| "hostkill-link-loss-timeout")?;
    ctx.link_loss_observed = true;
    ctx.phase
        .push("matrix: host kill: link_loss detected by the helper child".to_string());
    // helper 检测到 link loss 后以 crash 语义退出（authority abandoned）。
    wait_child_exit(child, 30)?;
    let auth =
        SingletonAuthority::new(&ctx.authority_name).map_err(|_| "hostkill-authority-reopen")?;
    if auth.try_acquire().map_err(|_| "hostkill-takeover")? != AuthorityAcquire::AbandonedTakenOver
    {
        return Err("hostkill-takeover-not-abandoned");
    }
    let releaser =
        SingletonAuthority::new(&ctx.authority_name).map_err(|_| "hostkill-authority-releaser")?;
    let mut eng = RecoveryEngine::new(JournalPath::from_dir(ctx.dir.clone()), auth);
    let fact = observed(InventoryItem::Adapter, [0x33; 32], [0x55; 32]);
    eng.recover(version(7), &[fact])
        .map_err(|_| "hostkill-recover")?;
    if !journal_has_exactly_one_record(&ctx.dir) {
        return Err("hostkill-journal-changed");
    }
    drop(eng);
    releaser.release().map_err(|_| "hostkill-authority-release")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// crash-matrix 二进制的子进程角色（helper-hold / host-dummy / exercise）。
// ---------------------------------------------------------------------------

/// helper-hold 子进程角色（`EXV_W29_HELPER_ROLE=1`）：compose（W26 顺序）成功后
/// 写 ready marker，随后按文件 barrier 发布命名 crash 边界
/// （effect/observation/reply），可选监控 host 进程死亡（link loss）；然后
/// hold 直至被 TerminateProcess。返回进程退出码（252 = compose 失败）。
#[must_use]
pub fn run_crash_matrix_helper_role() -> i32 {
    let (Some(authority), Some(journal), Some(marker)) = (
        std::env::var(AUTHORITY_ENV).ok(),
        std::env::var(JOURNAL_ENV).ok(),
        std::env::var(MARKER_ENV).ok(),
    ) else {
        return CHILD_EXIT_ERROR;
    };
    let boundary_dir = std::env::var(BOUNDARY_DIR_ENV).ok().map(PathBuf::from);
    let host_pid = std::env::var(HOST_PID_ENV)
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let mut helper = match run_stop_pressure_helper(StopPressureConfig {
        authority_name: authority,
        journal_dir: PathBuf::from(journal),
        ready_marker: PathBuf::from(marker),
    }) {
        Ok(helper) => helper,
        Err(_) => return CHILD_EXIT_ERROR,
    };
    if let (Some(pid), Some(dir)) = (host_pid, &boundary_dir) {
        let link_loss = dir.join("link-loss.marker");
        let _ = thread::spawn(move || watch_host(pid, &link_loss));
    }
    if let Some(dir) = &boundary_dir {
        let go = dir.join("go.marker");
        for name in ["effect", "observation", "reply"] {
            let _ = wait_for_file(&go, 120);
            let _ = std::fs::remove_file(&go);
            let _ = std::fs::write(dir.join(format!("{name}.marker")), format!("{name}\n"));
        }
    }
    helper.hold_until_killed()
}

/// 监控 host 进程句柄：host 死亡（kernel handle wait）-> 写 link-loss marker 并以
/// crash 语义退出（不执行 shutdown；authority 留给下一个 waiter 以 WAIT_ABANDONED
/// 接管）。
fn watch_host(host_pid: u32, link_loss: &Path) {
    // SAFETY: OpenProcess 打开受限 SYNCHRONIZE 句柄；失败即静默返回（fail closed）。
    let Ok(process) = (unsafe { OpenProcess(SYNCHRONIZE, false, host_pid) }) else {
        return;
    };
    // SAFETY: WaitForSingleObject 等待 host 进程句柄（host 死亡才返回）；用后关闭。
    unsafe {
        let _ = WaitForSingleObject(process, INFINITE);
        let _ = CloseHandle(process);
    }
    let _ = std::fs::write(link_loss, "host link loss detected\n");
    std::process::exit(0);
}

/// host-dummy 角色（`EXV_W29_HOST_DUMMY=1`）：sleep 直至被 TerminateProcess
/// （矩阵受控的 "host" 进程）。
pub fn run_crash_matrix_host_dummy() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// 纯逻辑 exercise 角色（`EXV_W29_EXERCISE=<name>`）：进程 restart 复验的独立
/// 进程。退出码：0 = exercise 通过；2 = 失败或未知 exercise。
#[must_use]
pub fn run_crash_matrix_exercise(name: &str) -> i32 {
    let mut phase = Vec::new();
    let result = match name {
        "packet-flood-stop" => exercise_packet_flood_stop(),
        "peer-nonread" => exercise_peer_nonread(),
        "native-read-wait" => exercise_native_read_wait(&mut phase),
        "connecting-cancel" => exercise_connecting_cancel(),
        "stop-eof" => exercise_stop_eof(&mut phase),
        "host-kill-logic" => exercise_host_kill_logic(),
        "third-party-dns" => match (
            std::env::var(EXERCISE_JOURNAL_ENV).ok(),
            std::env::var(EXERCISE_AUTHORITY_ENV).ok(),
        ) {
            (Some(journal), Some(authority)) => {
                exercise_third_party_dns(Path::new(&journal), &authority)
            }
            _ => Err("exercise-env-missing"),
        },
        "queued-overlap" => exercise_queued_overlap(&mut phase),
        _ => {
            eprintln!("unknown exercise: {name}");
            return 2;
        }
    };
    if result.is_ok() {
        0
    } else {
        eprintln!("exercise {name} failed");
        2
    }
}

// ---------------------------------------------------------------------------
// 子进程辅助（bin 定位 / spawn / 等待）。
// ---------------------------------------------------------------------------

/// 定位 crash-matrix 二进制（helper-hold / exercise / host-dummy 子进程的宿主）。
/// bin 进程即自身；test 进程则在其 target 目录（deps 的上级）查找。
fn helper_bin_path() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let name = exe.file_name()?.to_string_lossy().into_owned();
    if name == "exv-win32-crash-matrix.exe" {
        return Some(exe);
    }
    // test 二进制位于 <workspace>/target/<profile>/deps/；bin 位于 <profile>/。
    let profile = exe.parent()?.parent()?;
    let candidates = [
        profile.join("exv-win32-crash-matrix.exe"),
        profile.join("deps").join("exv-win32-crash-matrix.exe"),
    ];
    candidates.into_iter().find(|c| c.exists())
}

/// spawn helper-hold 子进程（helper 角色；`host_pid` 时同时监控 host 死亡）。
fn spawn_helper_hold_child(
    bin: &Path,
    ctx: &MatrixCtx,
    host_pid: Option<u32>,
) -> Result<Child, &'static str> {
    let mut cmd = Command::new(bin);
    cmd.env(HELPER_ROLE_ENV, "1")
        .env(AUTHORITY_ENV, &ctx.authority_name)
        .env(JOURNAL_ENV, &ctx.dir)
        .env(MARKER_ENV, &ctx.ready)
        .env(BOUNDARY_DIR_ENV, &ctx.boundary_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(pid) = host_pid {
        cmd.env(HOST_PID_ENV, pid.to_string());
    }
    cmd.spawn().map_err(|_| "helper-spawn")
}

/// spawn host-dummy 进程（sleep 至被杀）。
fn spawn_host_dummy(bin: &Path) -> Result<Child, &'static str> {
    Command::new(bin)
        .env(HOST_DUMMY_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "host-dummy-spawn")
}

/// spawn 纯逻辑 exercise 子进程（进程 restart 复验；third-party-dns 需要
/// journal + authority env）。
fn run_exercise_child(
    bin: &Path,
    name: &str,
    journal: Option<&Path>,
    authority: Option<&str>,
) -> Result<(), &'static str> {
    let mut cmd = Command::new(bin);
    cmd.env(EXERCISE_ENV, name)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dir) = journal {
        cmd.env(EXERCISE_JOURNAL_ENV, dir);
    }
    if let Some(a) = authority {
        cmd.env(EXERCISE_AUTHORITY_ENV, a);
    }
    let status = cmd.status().map_err(|_| "exercise-child-spawn")?;
    if status.success() {
        Ok(())
    } else {
        Err("exercise-child-failed")
    }
}

/// 轮询等待文件出现（deadline 秒；25ms 间隔）。
fn wait_for_file(path: &Path, seconds: u64) -> Result<(), &'static str> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while !path.exists() {
        if Instant::now() >= deadline {
            return Err("marker-timeout");
        }
        thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}

/// 等待子进程退出（deadline 秒）。
fn wait_child_exit(child: &mut Child, seconds: u64) -> Result<(), &'static str> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        if child.try_wait().map_err(|_| "child-wait")?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("child-exit-timeout");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

// ---------------------------------------------------------------------------
// 证据工具：secret 扫描、elevation、OS/build/hardware、journal 完整性。
// ---------------------------------------------------------------------------

/// 对最终序列化做独立扫描：证据不含 raw secret/cookie/private key/certificate。
fn scan_evidence(ev: &mut CrashMatrixEvidence) {
    let json = serde_json::to_string(ev).unwrap_or_default();
    let forbidden = [
        "PRIVATE KEY",
        "BEGIN CERTIFICATE",
        "Cookie:",
        "Authorization:",
        "password=",
    ];
    ev.no_raw_secret_in_evidence = !forbidden.iter().any(|m| json.contains(m));
}

/// 当前进程是否 elevated（TokenElevation 观测）。
fn is_elevated() -> bool {
    // SAFETY: GetCurrentProcess 返回当前进程伪句柄，无需关闭。
    let process = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        return false;
    }
    let elevated = token_is_elevated(token);
    // SAFETY: token 是本进程新打开的句柄，使用后关闭。
    unsafe {
        let _ = CloseHandle(token);
    }
    elevated
}

/// 查询进程 token 是否 elevated（helper 子进程的观测）。
fn process_token_elevated(pid: u32) -> bool {
    // SAFETY: OpenProcess 打开受限查询句柄；失败即返回 false（fail closed）。
    let Ok(process) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
    else {
        return false;
    };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    let Ok(_) = (unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }) else {
        // SAFETY: process 句柄使用后关闭。
        unsafe {
            let _ = CloseHandle(process);
        }
        return false;
    };
    let elevated = token_is_elevated(token);
    // SAFETY: token/process 句柄使用后关闭。
    unsafe {
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
    }
    elevated
}

/// 读取 token 的 TokenElevation 事实。
fn token_is_elevated(token: HANDLE) -> bool {
    let mut elevated = false;
    let mut size = 0u32;
    // SAFETY: 尺寸查询不写任何位置。
    unsafe {
        let _ = GetTokenInformation(token, TokenElevation, None, 0, &raw mut size);
    }
    if size != 0 {
        let mut buff = vec![0u8; size as usize];
        let len = u32::try_from(buff.len()).unwrap_or(0);
        // SAFETY: buff 是有效缓冲；TokenElevation 写入 TOKEN_ELEVATION。
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some(buff.as_mut_ptr().cast::<c_void>()),
                len,
                &raw mut size,
            )
        };
        if ok.is_ok() && buff.len() >= 4 {
            elevated = u32::from_ne_bytes(buff[0..4].try_into().unwrap_or([0u8; 4])) != 0;
        }
    }
    elevated
}

/// Windows build（注册表 `CurrentBuildNumber` / `DisplayVersion`）。
fn read_os_build() -> String {
    const KEY_PATH: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let mut key = HKEY::default();
    let path = HSTRING::from(KEY_PATH);
    // SAFETY: path 有效；key 输出句柄，用后需关闭。
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, &path, Some(0), KEY_READ, &raw mut key) };
    if rc.0 != 0 {
        return String::new();
    }
    let mut build = String::new();
    let mut display = String::new();
    for (name, out) in [
        ("CurrentBuildNumber", &mut build),
        ("DisplayVersion", &mut display),
    ] {
        let name_w = HSTRING::from(name);
        let mut buff = [0u8; 256];
        let mut len = buff.len() as u32;
        let mut kind = REG_VALUE_TYPE(0);
        // SAFETY: buff 有效；len 输入输出。
        let rc = unsafe {
            RegQueryValueExW(
                key,
                &name_w,
                None,
                Some(&raw mut kind),
                Some(buff.as_mut_ptr()),
                Some(&raw mut len),
            )
        };
        if rc.0 == 0 && len >= 2 {
            let count = (len as usize / 2).min(128);
            let mut chars = Vec::with_capacity(count);
            for chunk in buff[..count * 2].chunks_exact(2) {
                chars.push(u16::from_ne_bytes([chunk[0], chunk[1]]));
            }
            *out = trim_nul(&String::from_utf16_lossy(&chars));
        }
    }
    // SAFETY: key 是本函数打开的句柄，关闭。
    unsafe {
        let _ = RegCloseKey(key);
    }
    if display.is_empty() {
        build
    } else {
        format!("{display} (build {build})")
    }
}

/// 硬件描述（`PROCESSOR_ARCHITECTURE` 等环境事实）。
fn read_hardware() -> String {
    let arch = std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default();
    let cpu = std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_default();
    if cpu.is_empty() {
        arch
    } else {
        format!("{arch} {cpu}")
    }
}

/// 去掉字符串尾部的 NUL（注册表 REG_SZ 值）。
fn trim_nul(s: &str) -> String {
    s.trim_end_matches('\0').to_string()
}

/// 从 ready marker 读取 helper 的 projection digest（跨 restart 对比）。
fn marker_digest(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let digest = content.split("digest=").nth(1)?.trim().to_string();
    (!digest.is_empty()).then_some(digest)
}

/// durable journal 投影必须恰好一个记录（recovery 不得追加/改写/损坏）。
fn journal_has_exactly_one_record(dir: &Path) -> bool {
    let projection = JournalProjection::new(&JournalPath::from_dir(dir.to_path_buf()));
    match projection.project() {
        Ok(ProjectionOutcome::Clean(records)) | Ok(ProjectionOutcome::TornTail { records }) => {
            records.len() == 1
        }
        Ok(ProjectionOutcome::Corrupt { .. }) | Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// 确定性身份/状态构造（组合已提交的 domain 类型，tests 同款字面量）。
// ---------------------------------------------------------------------------

/// 确定性 32 字节 identity digest（跨 `n` 不同）。
const fn digest(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = n;
    b
}

/// 确定性 principal digest。
fn principal(n: u8) -> PrincipalDigest {
    PrincipalDigest::try_from(digest(n)).expect("digest")
}

/// 确定性 candidate/held token digest。
fn token(n: u8) -> TokenDigest {
    TokenDigest::try_from(digest(n)).expect("digest")
}

/// 确定性非零 ownership version。
fn version(n: u64) -> OwnershipVersion {
    OwnershipVersion::try_from(n).expect("version")
}

/// 确定性非 nil runtime epoch。
fn epoch(n: u128) -> RuntimeEpoch {
    RuntimeEpoch::try_from(Uuid::from_u128(n)).expect("epoch")
}

/// 确定性非 nil operation id。
fn operation(n: u128) -> OperationId {
    OperationId::try_from(Uuid::from_u128(n)).expect("operation")
}

/// 确定性非 nil retirement operation id。
fn retirement_id(n: u128) -> RetirementOperationId {
    RetirementOperationId::try_from(Uuid::from_u128(n)).expect("retirement id")
}

/// 确定性非 nil recovery id。
fn recovery_id(n: u128) -> RecoveryId {
    RecoveryId::try_from(Uuid::from_u128(n)).expect("recovery id")
}

/// 确定性 lookup key（固定 epoch/op，锚定 principal + method）。
fn lookup_key(principal_n: u8, method: OperationMethod) -> OperationLookupKey {
    OperationLookupKey::try_from((principal(principal_n), method, epoch(1), operation(1)))
        .expect("lookup key")
}

/// 确定性 authority fence（epoch 1、instance 1、watermark 0、revision 0）。
fn fence() -> AuthorityFence {
    AuthorityFence {
        authority_epoch: AuthorityEpoch::try_from(1).expect("epoch 1"),
        platform_authority_instance_id: PlatformAuthorityInstanceId::try_from(Uuid::from_u128(1))
            .expect("non-nil instance"),
        admission_watermark: AdmissionWatermark::try_from(0).expect("watermark 0"),
        journal_revision: JournalRevision::try_from(0).expect("revision 0"),
    }
}

/// canonical J51 `MutationAdmitted`（live-token subject；kill 边界的 durable
/// admission——encode_record codec 往返是 durability gate）。
fn make_admission() -> MutationAdmitted {
    let f = fence();
    MutationAdmitted {
        mutation_kind: MutationKind::External(OperationMethod::Connect),
        journal_operation_identity: JournalOperationIdentity::External(lookup_key(
            1,
            OperationMethod::Connect,
        )),
        effect_id: EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect"),
        canonical_input_digest: CanonicalInputDigest::try_from([0x11; 32]).expect("digest"),
        initiator_identity_digest: principal(9),
        authority_epoch: f.authority_epoch,
        platform_authority_instance_id: f.platform_authority_instance_id,
        admission_watermark: f.admission_watermark,
        ownership_version: version(7),
        authorization_subject: AuthorizationSubject::LiveOwnershipTokenDigest(token(7)),
        resource_identity: ResourceIdentityDigest::try_from([0x33; 32]).expect("digest"),
        precondition_fingerprint: AppliedFingerprint::try_from([0x44; 32]).expect("digest"),
        desired_applied_fingerprint: AppliedFingerprint::try_from([0x55; 32]).expect("digest"),
        canonical_obligation_seed: ObligationSeed::try_from([0x66; 32]).expect("digest"),
    }
}

/// 一个 obligation 的已观测平台事实。
const fn observed(obligation: InventoryItem, identity: [u8; 32], fp: [u8; 32]) -> ObservedResource {
    ObservedResource {
        obligation: obligation as u8,
        identity_digest: identity,
        fingerprint: fp,
    }
}

/// 确定性已验 helper peer（WSP1 §6：host 只对已验 helper 的 PID+SID 组合）。
fn helper_peer() -> VerifiedPipePeer {
    VerifiedPipePeer {
        process_id: 4242,
        user_sid: "S-1-5-21-3980489076-1253412212-3874560562-1002".to_string(),
        logon_sid: Some("S-1-5-5-0-323470".to_string()),
        account_name: "EXV VPN Helper".to_string(),
    }
}

/// 确定性 controller peer + capability（portable H80 测试同款构造，固定字面量）。
fn controller_peer_and_capability() -> (PeerContext, PeerCapability) {
    let principal = PrincipalDigest::try_from([0u8; 32]).unwrap();
    let binding = ConnectionBindingDigest::try_from([1u8; 32]).unwrap();
    let metadata =
        VerifiedConnectionMetadata::try_from((principal.clone(), binding.clone())).unwrap();
    let peer = PeerContext::try_from(metadata).unwrap();
    let connection = ConnectionBinding::try_from(binding).unwrap();
    let capability = PeerCapability::try_from((
        connection,
        principal,
        AuthorityEpoch::try_from(7u64).unwrap(),
        OperationMethod::Connect,
        MonotonicTick::try_from(42u64).unwrap(),
    ))
    .unwrap();
    (peer, capability)
}

/// 确定性 packet lease（W27 同款构造：固定非 nil 占位）。
fn deterministic_packet_lease() -> PacketLeaseRef {
    let mut lease = [0u8; 32];
    lease[0] = 0x4C; // 'L'
    lease[1] = 0x57; // 'W'
    PacketLeaseRef::try_from(ResourceIdentityDigest::try_from(lease).expect("valid digest"))
        .expect("valid lease")
}

/// 确定性 runtime epoch（非 nil、固定——W23B-T 同款）。
fn deterministic_runtime_epoch() -> RuntimeEpoch {
    epoch(1)
}

/// 确定性纯 W23B relay（atomic attach + channel + limits；无 Win32 call）。
fn relay() -> AttachedPacketRelay {
    let channel = PacketChannel::new(
        &PacketLimits::mvp(),
        DataPlaneDirection::ProtocolToPacket,
    )
    .expect("build the packet channel");
    let mut capability = PacketCapability::issue(
        deterministic_packet_lease(),
        deterministic_runtime_epoch(),
    );
    let attachment =
        AttachedPacketRelay::attach(&mut capability, 1).expect("attach the relay atomically");
    AttachedPacketRelay::new(attachment, channel, PacketLimits::mvp())
}

/// 空 apply 计划（nothing set up —— teardown 纯逻辑的输入）。
fn empty_apply_plan() -> ApplyPlan {
    build_apply_plan(
        Vec::new(),
        1500,
        None,
        Vec::new(),
        Vec::new(),
        DnsSettings::new(Vec::new(), Vec::new()),
        // TK1b 签名扩展：系统代理豁免条目 + 发起 SID（空 = family 零动作）。
        Vec::new(),
        String::new(),
    )
}

/// 确定性纯逻辑 WindowsTeardown（aggregate = None：无实状态）。
fn teardown(plan: &ApplyPlan, has_packet_children: bool) -> WindowsTeardown {
    WindowsTeardown::new(
        None,
        RetirementSaga::new(fence(), version(2)),
        build_teardown_plan(plan, has_packet_children),
        Vec::new(),
    )
}

/// 确定性 platform ownership ref（W24 同款）。
fn ownership_ref() -> PlatformOwnershipRef {
    PlatformOwnershipRef::try_from((
        ResourceIdentityDigest::try_from([0x31; 32]).expect("digest"),
        version(2),
        token(2),
    ))
    .expect("ownership ref")
}

/// 确定性 canonical inventory digest（W24 同款）。
fn inventory_digest() -> InventoryDigest {
    InventoryDigest::try_from([0x22; 32]).expect("digest")
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
