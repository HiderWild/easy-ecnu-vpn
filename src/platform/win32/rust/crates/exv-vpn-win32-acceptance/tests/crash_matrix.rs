// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W29-T terra: Stop/crash/unknown-effect saturation（crash matrix）。test names 是
// docs/superpowers/plans/2026-08-12-vpn-rust-native-runtime-mvp-terra-oracle-plan.md §6.1
// `W29-T` 行的**完整且精确**集合（Terra 不得改名/增删/合并）；frozen seam 是
// `run_crash_matrix`（exv-vpn-win32-acceptance `scenarios::crash_matrix`）。Win32 子计划
// §9 `W29-T/I` 行必测的饱和点（每点一个测试）：packet flood + Stop、peer non-read、
// native read wait、connecting cancel、Stop+EOF、host kill、helper 在
// admission/effect/observation/reply 边界 kill、restart/reconcile、third-party
// route/DNS change、queued overlap。killer mutants：**crash=no-effect**（oracle）、
// **Stop 后 packet 继续**、**recovery 重放 apply / 无 observation 声称 clean**、
// **double retirement（Stop+EOF 两次清理）**、**host kill 后仍 Connected**、
// **third-party route/DNS 被 compare-restore 破坏**、**queued overlap 双 winner**。
//
// 依赖（矩阵纵切组合的已提交 pieces；本测试对它们做非提权纯逻辑断言）：W23B
// `AttachedPacketRelay`（89ab0bbb）、W24 `WindowsTeardown`/`build_teardown_plan`
// （85d4a837）、W25 `RecoveryEngine`/`JournalProjection`/`NativeObservation`（d6e0a5c9）、
// W26 helper `composition`/`shutdown`（1f4d880d，经 W29 `scenarios::stop_pressure`
// helper 角色组合）、W27 host `composition`/`kernel_control`（7178869e）、W13
// `SingletonAuthority`、W14 `WinJournalStore`、W17 `PacketWorker`。WSP2 事实
// （native-authority-storage-facts.md）：owner 被 TerminateProcess 杀死而不释放时下一个
// waiter 得 WAIT_ABANDONED_0=128 并被授予所有权，接管后必须先观察再谈 clean；torn tail
// 恢复到最后一个完整记录、corrupt middle 报 Corrupt 不跳过。TK80（testkit crash.rs）的
// named crash point / before/after sync barrier seam 目前是 scaffold 占位（无符号）——
// W29-I 在 scenarios::stop_pressure 的 helper 角色内提供等价的命名 crash 边界
// （admission/effect/observation/reply）并驱动真实 kill/restart；本测试只消费 W29
// scenario 模块的 public surface。
//
// 本测试对 seam 追加的契约（W29-I 必须提供下列 exact 名称，否则本测试编译失败 = RED）：
//   exv_vpn_win32_acceptance::scenarios::crash_matrix（frozen seam `run_crash_matrix`）
//     run_crash_matrix() -> CrashMatrixEvidence
//       —— 运行整个 crash-matrix 纵切（组合已提交 pieces；helper 角色经
//          scenarios::stop_pressure 的 run_stop_pressure_helper 以真实子进程驱动，
//          环境允许时真实 kill/restart），逐点记录证据；环境无效时只填静态事实并
//          标记 `WIN_ACCEPTANCE_ENV_INVALID:<predicate>` /
//          `not_run/blocked_by_environment:<predicate>`，绝不伪造动态事实。
//     CrashMatrixEvidence（Clone/Debug/PartialEq/serde::Serialize）
//       { environment_state: String, env_elevated: bool, host_os: String,
//         os_build: String, hardware: String, hostname: String,
//         host_pid: Option<u32>, helper_pid: Option<u32>,
//         host_token_elevated: bool, helper_token_elevated: bool,
//         points: Vec<CrashPointEvidence>, packets_after_stop: u64,
//         retirements_recorded: usize, duplicate_apply_attempts: u64,
//         recovery_reobserved_before_claim: bool,
//         network_state_after_equals_before: bool,
//         no_raw_secret_in_evidence: bool, phase_journal: Vec<String> }
//     CrashMatrixEvidence::is_dynamic_complete(&self) -> bool
//       —— env_elevated && helper_pid 已观测 && 13 个点全部记录 && 每点
//          final_proof_or_blocker 非空 && remaining_obligation 为空 &&
//          recovery_reobserved_before_claim && duplicate_apply_attempts == 0
//     CrashPointTag { PacketFloodStop, PeerNonRead, NativeReadWait, ConnectingCancel,
//       StopEof, HostKill, HelperCrashBoundaryAdmission, HelperCrashBoundaryEffect,
//       HelperCrashBoundaryObservation, HelperCrashBoundaryReply, RestartReconcile,
//       ThirdPartyRouteDns, QueuedOverlap }
//       （Debug/Clone/Copy/PartialEq/Eq/PartialOrd/Ord —— 13 个饱和点，每点恰好一次）
//     CrashPointEvidence { point: CrashPointTag,
//       last_durable_record: Option<String>, native_observation: Vec<String>,
//       certainty: Certainty, remaining_obligation: Vec<String>,
//       final_proof_or_blocker: String }（Clone/Debug/PartialEq）
//       —— 计划 §9 W29：每点记录 last durable record、native observation、certainty、
//          remaining obligation、final proof 或具体 blocker。
//     Certainty { RvP0, RvP1, RvP2, RvP3 }（Debug/Clone/Copy/PartialEq/Eq）
//       —— 冻结评级语义（计划 §9 W29 / W31-R）：RvP0=阻塞（非偶现且重启不可恢复），
//          阻止 Windows passed；RvP1=非偶现且重启可恢复（诚实记录真实缺陷，阻止
//          passed）；RvP2=偶现，可诚实容忍；RvP3=10 次恰 1 次出现 + process restart
//          后 3 次通过 + 无残留，可容忍（最佳）。评级必须携带对应冻结证据标记
//          （见 oracle_kills_crash_equals_noeffect_mutant 的 P1/P3 门禁 marker）。
//   exv_vpn_win32_acceptance::scenarios::stop_pressure（helper 角色 seam）
//     run_stop_pressure_helper(config: StopPressureConfig)
//       -> Result<StopPressureHelper, StopPressureError>
//       （StopPressureError: Debug/Clone/PartialEq/Eq）
//     StopPressureConfig { pub authority_name: String, pub journal_dir: PathBuf,
//       pub ready_marker: PathBuf }（Debug/Clone/PartialEq/Eq）
//       —— compose（authority -> recovery -> endpoint，W26 顺序）成功后**才**写
//          ready_marker 文件（= composition live、authority 持有中），随后 hold
//          直至被 TerminateProcess（不执行 shutdown，模拟 crash 语义）。
//     StopPressureHelper::hold_until_killed(&mut self) -> !
//     StopPressureHelper::shutdown(self) -> Result<(), StopPressureError>
//
// 本文件 RED / test-only：引用 W29-I 的**尚不存在**的 scenario 模块
// （scenarios::crash_matrix / scenarios::stop_pressure），在 W29-I 实现 seam 前必须
// 编译失败（E0432，diagnostic 含 frozen seam `run_crash_matrix`）。纯逻辑断言全部
// 非提权可运行（无 Wintun/网络/pipe 依赖）；真实 kill/restart 测试 elevation-aware
// （require_admin pattern）：环境无效只产生 `WIN_ACCEPTANCE_ENV_INVALID:<predicate>`
// 或 `not_run/blocked_by_environment`，不得冒充 RED 或 GREEN。GREEN 固定为
// `10 passed; 0 failed; 0 ignored`。

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

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
use exv_vpn_resource::retirement::RetirementSaga;

use exv_vpn_data_plane::budget::DataPlaneDirection;
use exv_core::composition::{
    compose_nonprivileged_host, HostEffect, HostEvent, HostPhase,
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
    ObligationRecovery, RecoveryAction, RecoveryEngine, RecoveryOutcome,
};
use exv_vpn_win32_resource::teardown::{
    TeardownError, TeardownStage, WindowsTeardown, build_teardown_plan,
};
use exv_engine::packet_relay::{
    AttachedPacketRelay, RelayDirection, RelayLegState, RelayTerminalSource,
};

// W29-I frozen seam（RED anchor：W29-I 提供前编译失败 = E0432）。
use exv_vpn_win32_acceptance::scenarios::crash_matrix::{
    Certainty, CrashMatrixEvidence, CrashPointEvidence, CrashPointTag, run_crash_matrix,
};
use exv_vpn_win32_acceptance::scenarios::stop_pressure::{
    StopPressureConfig, run_stop_pressure_helper,
};

use uuid::Uuid;

// ---------------------------------------------------------------------------
// 冻结契约常量（测试拥有；production `scenarios/crash_matrix.rs` 必须满足，不可漂移）
// ---------------------------------------------------------------------------

/// `environment_state` 取值契约（计划 §6.1）：完整矩阵唯一值。
const ENV_STATE_COMPLETED: &str = "completed";
/// 环境无效标记前缀（后随精确 predicate，如 `host_not_elevated`）。
const ENV_INVALID_PREFIX: &str = "WIN_ACCEPTANCE_ENV_INVALID:";
/// 环境无效的另一合法标记（如 `requires_admin`）。
const NOT_RUN_BLOCKED_PREFIX: &str = "not_run/blocked_by_environment";

/// 13 个饱和点（计划 §9 W29 列表；evidence 必须恰好各一次）。
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

/// RvP3 门禁的冻结证据标记（计划 §9：10 次恰 1 次 + process restart 后 3 次通过 +
/// 无残留才可为 RvP3）。
const P3_MARKERS: [&str; 4] = ["runs=10", "failures=1", "restarts_passed=3", "no_residue"];
/// RvP1 的冻结证据标记（非偶现且重启可恢复）。
const P1_MARKERS: [&str; 2] = ["non-sporadic", "restart_recovered"];
/// RvP2 的冻结证据标记（偶现）。
const P2_MARKER: &str = "sporadic";

/// 证据 JSON 中禁止出现的 raw secret/cookie/private key/certificate 标记
/// （独立于 production 自报的序列化扫描）。
const FORBIDDEN_EVIDENCE_MARKERS: [&str; 5] = [
    "PRIVATE KEY",
    "BEGIN CERTIFICATE",
    "Cookie:",
    "Authorization:",
    "password=",
];

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// A fresh, per-test temp directory: %TEMP%\exv-w29-<pid>-<tag>. Any stale copy from a
/// prior crashed run is removed so every test starts clean.
fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("exv-w29-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A unique `Local\`-scoped authority mutex name per test (tag + pid), so parallel tests
/// and repeated runs never collide.
fn authority_name(tag: &str) -> String {
    format!(r"Local\ExvVpnW29Authority_{tag}_{}", std::process::id())
}

/// Marker file under %TEMP%, shared by parent and child (path passed via env).
fn marker_path(tag: &str, kind: &str) -> PathBuf {
    std::env::temp_dir().join(format!("exv-w29-{tag}-{kind}.marker"))
}

/// Deterministic 32-byte identity digest that differs across `n`.
fn digest(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = n;
    b
}

/// Deterministic principal digest that differs across `n`.
fn principal(n: u8) -> PrincipalDigest {
    PrincipalDigest::try_from(digest(n)).expect("digest")
}

/// Deterministic candidate/held token digest that differs across `n`.
fn token(n: u8) -> TokenDigest {
    TokenDigest::try_from(digest(n)).expect("digest")
}

/// Deterministic non-zero ownership version for the given `n`.
fn version(n: u64) -> OwnershipVersion {
    OwnershipVersion::try_from(n).expect("version")
}

/// Deterministic non-nil runtime epoch for the given `n`.
fn epoch(n: u128) -> RuntimeEpoch {
    RuntimeEpoch::try_from(Uuid::from_u128(n)).expect("epoch")
}

/// Deterministic non-nil operation id for the given `n`.
fn operation(n: u128) -> OperationId {
    OperationId::try_from(Uuid::from_u128(n)).expect("operation")
}

/// Deterministic non-nil retirement operation id for the given `n`.
fn retirement_id(n: u128) -> RetirementOperationId {
    RetirementOperationId::try_from(Uuid::from_u128(n)).expect("retirement id")
}

/// Deterministic non-nil recovery id for the given `n`.
fn recovery_id(n: u128) -> RecoveryId {
    RecoveryId::try_from(Uuid::from_u128(n)).expect("recovery id")
}

/// Deterministic lookup key anchored to the given principal and method (fixed epoch/op).
fn lookup_key(principal_n: u8, method: OperationMethod) -> OperationLookupKey {
    OperationLookupKey::try_from((principal(principal_n), method, epoch(1), operation(1)))
        .expect("lookup key")
}

/// Deterministic authority fence minted at epoch 1, instance 1, watermark 0, revision 0.
fn fence() -> AuthorityFence {
    AuthorityFence {
        authority_epoch: AuthorityEpoch::try_from(1).expect("epoch 1"),
        platform_authority_instance_id: PlatformAuthorityInstanceId::try_from(Uuid::from_u128(1))
            .expect("non-nil instance"),
        admission_watermark: AdmissionWatermark::try_from(0).expect("watermark 0"),
        journal_revision: JournalRevision::try_from(0).expect("revision 0"),
    }
}

/// A canonical J51 `MutationAdmitted` sealed as a durable admission record (the
/// `encode_record` codec round-trip is the durability gate, mutation_ingress 同款).
fn admitted(
    key: &OperationLookupKey,
    ownership_version: OwnershipVersion,
    subject: AuthorizationSubject,
    resource_identity: [u8; 32],
    desired_fingerprint: [u8; 32],
    mutation_kind: MutationKind,
) -> MutationAdmitted {
    let f = fence();
    MutationAdmitted {
        mutation_kind,
        journal_operation_identity: JournalOperationIdentity::External(key.clone()),
        effect_id: EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect"),
        canonical_input_digest: CanonicalInputDigest::try_from([0x11; 32]).expect("digest"),
        initiator_identity_digest: principal(9),
        authority_epoch: f.authority_epoch,
        platform_authority_instance_id: f.platform_authority_instance_id,
        admission_watermark: f.admission_watermark,
        ownership_version,
        authorization_subject: subject,
        resource_identity: ResourceIdentityDigest::try_from(resource_identity).expect("digest"),
        precondition_fingerprint: AppliedFingerprint::try_from([0x44; 32]).expect("digest"),
        desired_applied_fingerprint: AppliedFingerprint::try_from(desired_fingerprint)
            .expect("digest"),
        canonical_obligation_seed: ObligationSeed::try_from([0x66; 32]).expect("digest"),
    }
}

/// Append one J51 admission as the next chained journal record (J50 frame + FlushFileBuffers
/// durability via the committed W14 store).
fn append_admission(store: &mut WinJournalStore, seq: u64, prev: [u8; 32], m: &MutationAdmitted) {
    let rec = exv_vpn_resource::journal::JournalRecord::new(
        seq,
        prev,
        encode_record(&AdmissionRecord::Admitted(m.clone())),
    );
    store
        .append_synced(&rec)
        .expect("append_synced a J51 admission record");
}

/// An observed platform fact for one obligation (the native observation result).
fn observed(obligation: InventoryItem, identity: [u8; 32], fp: [u8; 32]) -> ObservedResource {
    ObservedResource {
        obligation: obligation as u8,
        identity_digest: identity,
        fingerprint: fp,
    }
}

/// The obligations of a Pending recovery outcome.
fn obligations(outcome: &RecoveryOutcome) -> &[ObligationRecovery] {
    match outcome {
        RecoveryOutcome::Pending { obligations, .. } => obligations,
        other => panic!("expected a Pending recovery outcome, got {other:?}"),
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

/// A pure W23B relay (atomic attach + channel + limits; no Win32 call).
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

/// 构造纯逻辑 WindowsTeardown（aggregate = None：无实状态）。
fn teardown(plan: &ApplyPlan, has_packet_children: bool) -> WindowsTeardown {
    WindowsTeardown::new(
        None,
        RetirementSaga::new(fence(), version(2)),
        build_teardown_plan(plan, has_packet_children),
        Vec::new(),
    )
}

// ---------------------------------------------------------------------------
// 纵切证据（W29-I seam 的消费点 + PowerShell anchor 的证据发布点）
// ---------------------------------------------------------------------------

/// 矩阵只跑一次，各项断言共享同一份观测（确定性；同时是 PowerShell anchor 的
/// 证据发布点）。
fn matrix() -> &'static CrashMatrixEvidence {
    static EVIDENCE: OnceLock<CrashMatrixEvidence> = OnceLock::new();
    EVIDENCE.get_or_init(|| {
        let ev = run_crash_matrix();
        publish_evidence(&ev);
        ev
    })
}

/// 幂等发布证据给 native scenario：`EXV_RUST_VPN_EVIDENCE_DIR` 设置时写
/// `crash-matrix.json`；无论设置与否都打印一行 `CRASH_MATRIX_EVIDENCE:<json>`
/// （script grep 该行）。测试侧执行，不引入 production 依赖。
fn publish_evidence(ev: &CrashMatrixEvidence) {
    let json = serde_json::to_string(ev).unwrap_or_else(|e| format!("evidence-serialize-error:{e}"));
    if let Some(dir) = std::env::var_os("EXV_RUST_VPN_EVIDENCE_DIR") {
        let path = PathBuf::from(dir).join("crash-matrix.json");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&path, &json).is_err() {
            eprintln!("WARNING: cannot write evidence file {}", path.display());
        }
    }
    println!("CRASH_MATRIX_EVIDENCE:{json}");
}

/// elevation/完整性门禁（require_admin pattern）：环境有效（elevated 且动态事实完整）
/// 返回 `true` 并继续真实断言；否则验证环境无效标记的诚实性并返回 `false`
/// （not_run，不伪造）。
fn env_complete_or_honest_not_run(ev: &CrashMatrixEvidence) -> bool {
    if ev.env_elevated && ev.is_dynamic_complete() {
        assert_eq!(
            ev.environment_state, ENV_STATE_COMPLETED,
            "完整矩阵必须标记 environment_state=completed"
        );
        true
    } else {
        assert!(
            ev.environment_state.starts_with(ENV_INVALID_PREFIX)
                || ev.environment_state.starts_with(NOT_RUN_BLOCKED_PREFIX),
            "环境无效必须产生 {ENV_INVALID_PREFIX}<predicate> 或 {NOT_RUN_BLOCKED_PREFIX}（不得冒充 RED/GREEN），got {:?}",
            ev.environment_state
        );
        assert!(
            !ev.env_elevated || !ev.is_dynamic_complete(),
            "elevated 且动态事实完整时 environment_state 必须是 completed"
        );
        false
    }
}

/// The point record of `tag` (missing point = contract violation).
fn point(ev: &CrashMatrixEvidence, tag: CrashPointTag) -> &CrashPointEvidence {
    ev.points
        .iter()
        .find(|p| p.point == tag)
        .unwrap_or_else(|| panic!("evidence 必须包含饱和点 {tag:?}"))
}

/// 每点的诚实性/完整性门禁：矩阵未完成时 final_proof_or_blocker 必须诚实标记
/// `not_run` / `blocked`；完成时必须有 final proof 且无 remaining obligation。
fn assert_point_honest_or_complete(p: &CrashPointEvidence, gate: bool) {
    if gate {
        assert!(
            !p.final_proof_or_blocker.is_empty(),
            "完成的点必须记录 final proof 或具体 blocker（{:?}）",
            p.point
        );
        assert!(
            p.remaining_obligation.is_empty(),
            "完成的点不得有 remaining obligation（{:?}），got {:?}",
            p.point,
            p.remaining_obligation
        );
    } else {
        assert!(
            p.final_proof_or_blocker.starts_with("not_run")
                || p.final_proof_or_blocker.starts_with("blocked"),
            "not_run 点必须诚实标记 blocker（{:?}），got {:?}",
            p.point,
            p.final_proof_or_blocker
        );
    }
}

/// phase journal 中 `first` 严格出现在 `second` 之前。
fn journal_has_before(journal: &[String], first: &str, second: &str) -> bool {
    let pos = |needle: &str| journal.iter().position(|e| e.contains(needle));
    match (pos(first), pos(second)) {
        (Some(a), Some(b)) => a < b,
        _ => false,
    }
}

/// 确定性纯逻辑的评级合规检查（oracle_kills_crash_equals_noeffect_mutant 使用）：
/// 评级必须携带冻结证据标记，not_run 不得冒充证明。
fn rating_conforms(p: &CrashPointEvidence, gate: bool) -> Result<(), String> {
    if !gate {
        if p.final_proof_or_blocker.starts_with("not_run")
            || p.final_proof_or_blocker.starts_with("blocked")
        {
            return Ok(());
        }
        return Err(format!(
            "not_run 点 {:?} 必须诚实标记 blocker（got {:?}）",
            p.point, p.final_proof_or_blocker
        ));
    }
    match p.certainty {
        Certainty::RvP3 => {
            for marker in P3_MARKERS {
                if !p.native_observation.iter().any(|s| s.contains(marker)) {
                    return Err(format!(
                        "RvP3 必须携带冻结 P3 门禁证据 {marker:?}（{:?}），got {:?}",
                        p.point, p.native_observation
                    ));
                }
            }
        }
        Certainty::RvP1 => {
            for marker in P1_MARKERS {
                if !p.native_observation.iter().any(|s| s.contains(marker)) {
                    return Err(format!(
                        "RvP1 必须携带非偶现+重启可恢复证据 {marker:?}（{:?}），got {:?}",
                        p.point, p.native_observation
                    ));
                }
            }
        }
        Certainty::RvP2 => {
            if !p.native_observation.iter().any(|s| s.contains(P2_MARKER)) {
                return Err(format!(
                    "RvP2 必须携带偶现证据 {P2_MARKER:?}（{:?}），got {:?}",
                    p.point, p.native_observation
                ));
            }
        }
        Certainty::RvP0 => {
            if !p.final_proof_or_blocker.contains("blocker") {
                return Err(format!(
                    "RvP0 必须记录具体 blocker（{:?}），got {:?}",
                    p.point, p.final_proof_or_blocker
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Child-process sentinels（helper-hold 角色：真实 kill/restart 复现，W13-T/W25-T 同款）
// ---------------------------------------------------------------------------

const CHILD_ENV: &str = "EXV_W29_CHILD";
const AUTHORITY_ENV: &str = "EXV_W29_AUTHORITY";
const JOURNAL_ENV: &str = "EXV_W29_JOURNAL";
const MARKER_ENV: &str = "EXV_W29_MARKER";
/// The helper-role child hit an error instead of composing + holding.
const CHILD_EXIT_ERROR: i32 = 252;

/// Re-execute this test binary as the helper child. libtest's `--exact` runs only the
/// named test; that test checks `child_role()` first and exits before any parent work.
fn spawn_helper_hold(name: &str, journal_dir: &str, marker: &str, exact_test: &str) -> Child {
    Command::new(std::env::current_exe().expect("current test exe"))
        .env(CHILD_ENV, "helper-hold")
        .env(AUTHORITY_ENV, name)
        .env(JOURNAL_ENV, journal_dir)
        .env(MARKER_ENV, marker)
        .arg("--exact")
        .arg(exact_test)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the helper-hold child")
}

/// Child role entry, called at the top of every test that can be re-executed as a child.
/// Returns the exit code when running as a child; `None` in the parent role.
fn child_role() -> Option<i32> {
    let mode = std::env::var(CHILD_ENV).ok()?;
    let name = std::env::var(AUTHORITY_ENV).expect("child must receive the authority name");
    let journal_dir = std::env::var(JOURNAL_ENV).expect("child must receive the journal dir");
    let marker = std::env::var(MARKER_ENV).expect("child must receive the marker path");
    match mode.as_str() {
        // Helper-hold role: compose the W29 helper (authority -> recovery -> endpoint),
        // write the ready marker ONLY when the composition is live, then hold until the
        // parent TerminateProcess-es this process WITHOUT executing shutdown (crash).
        "helper-hold" => match run_stop_pressure_helper(StopPressureConfig {
            authority_name: name,
            journal_dir: PathBuf::from(journal_dir),
            ready_marker: PathBuf::from(marker),
        }) {
            Ok(mut helper) => helper.hold_until_killed(),
            Err(_) => Some(CHILD_EXIT_ERROR),
        },
        other => panic!("unknown child mode {other}"),
    }
}

// ---------------------------------------------------------------------------
// 1. packet flood + Stop（计划 §9 第一饱和点）
// ---------------------------------------------------------------------------

/// 杀 **Stop 后 packet 继续** mutant + flood 饿死 Stop：packet flood 必须先产生有界
/// 进展（progress），Stop 才能有意义；Stop 后 running proof 必须撤销（双 leg Terminal）、
/// 证据中 Stop 后 packet 数必须为 0。
#[test]
fn packet_flood_and_stop_make_progress() {
    // 纯逻辑（W23B 已提交 piece，非提权）：flood 有界 + progress，Stop 撤销 running proof。
    let mut relay = relay();
    let mut admitted_count = 0u64;
    loop {
        match relay.admit_receive_packet(&[0xAB; 1000]) {
            Ok(_) => admitted_count += 1,
            Err(e) => {
                assert_eq!(
                    e, "budget full",
                    "flood 必须被有界预算拒绝（typed，不 panic、不挂起）"
                );
                break;
            }
        }
        assert!(admitted_count < 100_000, "flood 必须有界（bounded budget）");
    }
    assert!(admitted_count > 0, "flood 必须先产生进展（progress），Stop 才有意义");
    relay.stop();
    assert!(!relay.running_proof(), "Stop 后 running proof 必须撤销");
    assert_eq!(relay.leg_state(RelayDirection::Receive), RelayLegState::Terminal);
    assert_eq!(relay.leg_state(RelayDirection::Send), RelayLegState::Terminal);

    // 纵切证据：flood+Stop 点诚实记录；完成时 Stop 后无 packet。
    let ev = matrix();
    let gate = env_complete_or_honest_not_run(ev);
    let p = point(ev, CrashPointTag::PacketFloodStop);
    assert_point_honest_or_complete(p, gate);
    if gate {
        assert_eq!(
            ev.packets_after_stop, 0,
            "Stop 之后不得再有 packet（kills Stop 后 packet 继续 mutant）"
        );
        assert!(
            p.last_durable_record.is_some(),
            "flood+Stop 必须记录最后 durable record（Stop/retirement）"
        );
        assert!(
            p.native_observation.iter().any(|s| s.contains("flood")),
            "flood 进展必须记录在 native observation，got {:?}",
            p.native_observation
        );
    }
}

// ---------------------------------------------------------------------------
// 2. peer non-read（计划 §9 第二饱和点）
// ---------------------------------------------------------------------------

/// 杀 **unbounded queue / 无 terminal outcome** mutant：对端不读时 send 侧必须被
/// 有界预算拒绝（typed，绝不无界增长或挂起），且任何 terminal source（EOF/panic/
/// native terminal/Stop）都使双 leg Terminal——有界的 terminal outcome。
#[test]
fn peer_nonread_has_bounded_terminal_outcome() {
    // 纯逻辑（W23B 已提交 piece，非提权）：预算填满 = 有界；ceiling 拒绝不消费 sequence。
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
                assert_eq!(
                    e, "budget full",
                    "对端不读时 send 必须被有界预算拒绝（typed，不 panic/不挂起）"
                );
                break;
            }
        }
        assert!(admitted < 100_000, "对端不读必须是有界的（bounded）");
    }
    assert!(admitted > 0, "有界之前必须先产生进展");
    let oversized = vec![0u8; 64 * 1024 + 1];
    assert!(
        relay.admit_send_frame(1, oversized.len(), seq).is_err(),
        "超 64 KiB ceiling 必须被拒（typed，不消费 sequence）"
    );
    relay.on_terminal(RelayTerminalSource::StreamEof);
    assert!(!relay.running_proof(), "EOF 必须使 running proof 失效");
    assert_eq!(relay.leg_state(RelayDirection::Receive), RelayLegState::Terminal);
    assert_eq!(relay.leg_state(RelayDirection::Send), RelayLegState::Terminal);

    // 纵切证据：peer non-read 点诚实记录；完成时有界 terminal outcome。
    let ev = matrix();
    let gate = env_complete_or_honest_not_run(ev);
    let p = point(ev, CrashPointTag::PeerNonRead);
    assert_point_honest_or_complete(p, gate);
    if gate {
        assert!(
            p.native_observation.iter().any(|s| s.contains("bounded")),
            "peer non-read 必须有界（bounded）terminal outcome，got {:?}",
            p.native_observation
        );
    }
}

// ---------------------------------------------------------------------------
// 3. native read wait（计划 §9 第三饱和点）
// ---------------------------------------------------------------------------

/// 杀 **native read wait 未 unblock 就 join（deadlock/UAF）** mutant：teardown plan
/// 必须把 `JournaledUnblock` 严格排在 `ChildJoin` 之前（W17/W24 顺序：join 在 session
/// end 之前，而 read 必须先被唤醒）；journal 前的 unblock/join 必须被拒绝
/// （destructive-before-journal）；final handle 在 join 前必须被拒绝（StageOutOfOrder）。
#[test]
fn native_read_wait_is_unblocked_before_join() {
    // 纯逻辑（W24 已提交 piece，非提权）：plan 顺序是 W24 mutant seam。
    let plan = build_teardown_plan(&empty_apply_plan(), true);
    assert_eq!(
        plan.stages,
        vec![
            TeardownStage::PureCancel,
            TeardownStage::JournaledUnblock,
            TeardownStage::ChildJoin,
            TeardownStage::ReverseRestore,
            TeardownStage::FinalHandle,
            TeardownStage::Proof,
        ],
        "native read 必须先 unblock 再 join（unblock-before-join mutant 死于此）"
    );

    // 真实 PacketWorker（非提权可 spawn）：join 必须 join 真实 worker。
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
    let ownership = PlatformOwnershipRef::try_from((
        ResourceIdentityDigest::try_from([0x31; 32]).expect("digest"),
        version(2),
        token(2),
    ))
    .expect("ownership ref");
    let inventory_digest = InventoryDigest::try_from([0x22; 32]).expect("digest");
    // journal 前不得 unblock / join（destructive-before-journal）。
    assert_eq!(
        td.unblock_native_read(),
        Err(TeardownError::DestructiveBeforeJournal),
        "journal 前不得 unblock native read（benign guard）"
    );
    assert_eq!(
        td.join_children(),
        Err(TeardownError::DestructiveBeforeJournal),
        "journal 前不得 join（destructive-before-journal）"
    );
    td.pure_cancel().expect("pure cancel");
    td.begin(
        retirement_id(0xF00D),
        CleanupTrigger::StartupRecovery(recovery_id(0xBAD1)),
        ErrorSubject::Recovery(recovery_id(0xBAD1)),
        ownership,
        inventory_digest,
    )
    .expect("journaled begin");
    td.unblock_native_read().expect("unblock after journal");
    td.join_children().expect("join after unblock");
    // join 必须 join 真实 worker。计数不能断言为 1：W17 冻结契约
    // （packet_worker.rs，已提交 34cc6254）是循环调用闭包直到 join
    // （"repeatedly runs a user closure until joined"）——worker 存活期间闭包被
    // 热循环快速调用（实测为数千次量级，join 前循环次数是时序相关的），
    // `== 1` 在循环语义下不可能成立。`> 0` 保留 mutant 杀伤力：join 的是 dummy
    // 或未 join（闭包从未执行）时计数为 0，仍被杀。
    assert!(
        counter.load(Ordering::SeqCst) > 0,
        "join 必须 join 真实 worker（dummy/未 join -> counter==0 仍被杀）"
    );

    // final handle 在 join 前必须被拒绝（children 未 join 时 drop_final_handle）。
    let mut early = teardown(&empty_apply_plan(), true);
    early.pure_cancel().expect("pure cancel");
    early
        .begin(
            retirement_id(0xF00D),
            CleanupTrigger::StartupRecovery(recovery_id(0xBAD1)),
            ErrorSubject::Recovery(recovery_id(0xBAD1)),
            PlatformOwnershipRef::try_from((
                ResourceIdentityDigest::try_from([0x31; 32]).expect("digest"),
                version(2),
                token(2),
            ))
            .expect("ownership ref"),
            InventoryDigest::try_from([0x22; 32]).expect("digest"),
        )
        .expect("journaled begin");
    early.restore_owned_resources().expect("reverse restore");
    assert_eq!(
        early.drop_final_handle(),
        Err(TeardownError::StageOutOfOrder),
        "packet children 未 join 时 final handle 必须被拒绝（join-before-final）"
    );

    // 纵切证据：native read wait 点诚实记录；完成时 unblock 严格在 join 之前。
    let ev = matrix();
    let gate = env_complete_or_honest_not_run(ev);
    let p = point(ev, CrashPointTag::NativeReadWait);
    assert_point_honest_or_complete(p, gate);
    if gate {
        assert!(
            journal_has_before(&ev.phase_journal, "unblock", "join"),
            "phase journal 必须记录 unblock 严格在 join 之前，got {:?}",
            ev.phase_journal
        );
    }
}

// ---------------------------------------------------------------------------
// 4. connecting cancel（计划 §9 第四饱和点）
// ---------------------------------------------------------------------------

/// 杀 **connecting 中 cancel 被丢弃 / cancel 无 typed terminal** mutant：connecting
/// 阶段的 RPC waiter cancel 只取消等待（绝不发出业务 Stop、不改变业务状态——
/// RPC cancel ≠ Stop）；显式业务取消（Disconnect）必须使 connecting 到达有界 typed
/// terminal（phase 离开 Connecting、admission 关闭、packet leg 撤销、Stop 恰好一次）。
#[test]
fn connecting_cancel_reaches_typed_terminal() {
    // 纯逻辑（W27 已提交 piece，非提权）。
    let mut composition =
        compose_nonprivileged_host(&helper_peer()).expect("compose_nonprivileged_host");
    let (peer, capability) = controller_peer_and_capability();
    composition.bind_controller(peer, capability);
    assert_eq!(
        composition.apply(HostEvent::Connect),
        HostEffect::ConnectAdmitted,
        "fresh host 必须接纳 connect（进入 Connecting）"
    );
    assert_eq!(composition.phase(), HostPhase::Connecting);

    // connecting 中 RPC waiter cancel：只取消等待，绝不业务 Stop。
    composition.on_rpc_waiter_cancel();
    assert_eq!(composition.rpc_waiter_cancellations(), 1, "cancel 必须被记录");
    assert_eq!(
        composition.stop_requests(),
        0,
        "RPC cancel ≠ Stop（spec §8.3/§9.1）——connecting cancel 不得发出业务 Stop"
    );
    assert_eq!(composition.phase(), HostPhase::Connecting, "cancel 不得改变业务状态");
    assert!(composition.admission_open(), "cancel 不得关闭 admission");

    // 显式业务取消：connecting 到达有界 typed terminal。
    assert_eq!(
        composition.apply(HostEvent::Disconnect),
        HostEffect::TeardownInitiated,
        "显式业务取消必须启动有界 teardown"
    );
    assert_eq!(composition.stop_requests(), 1, "业务 Stop 恰好一次");
    assert!(
        !composition.packet_attachment_active(),
        "teardown 必须撤销 packet leg"
    );
    assert_ne!(
        composition.phase(),
        HostPhase::Connecting,
        "connecting cancel 必须到达 typed terminal（不悬挂在 Connecting）"
    );
    assert!(
        matches!(composition.phase(), HostPhase::Stopping | HostPhase::Stopped),
        "terminal phase 必须是 Stopping/Stopped，got {:?}",
        composition.phase()
    );

    // 纵切证据：connecting cancel 点诚实记录；完成时有 typed terminal。
    let ev = matrix();
    let gate = env_complete_or_honest_not_run(ev);
    let p = point(ev, CrashPointTag::ConnectingCancel);
    assert_point_honest_or_complete(p, gate);
    if gate {
        assert!(
            p.last_durable_record.is_some(),
            "connecting cancel 必须记录最后 durable record"
        );
        assert!(
            p.native_observation.iter().any(|s| s.contains("terminal")),
            "cancel 必须到达 typed terminal，got {:?}",
            p.native_observation
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Stop + EOF（计划 §9 第五饱和点）
// ---------------------------------------------------------------------------

/// 杀 **double retirement（Stop+EOF 两次清理）** mutant：Stop 与 EOF 同时到达必须
/// 合并为**一次** retirement（spec §6.1：相同/不同 Stop 意图合并到同一 saga，绝不
/// 第二次 destructive cleanup）；relay 上 EOF 与 Stop 先后到达最终都只有一个 terminal
/// 状态；证据中 retirements_recorded == 1 且 Stop 后无 packet。
#[test]
fn stop_and_eof_coalesce_into_one_retirement() {
    // 纯逻辑（W24 已提交 piece，非提权）：第二次 begin 合并到同一 saga。
    let mut td = teardown(&empty_apply_plan(), false);
    let ownership = PlatformOwnershipRef::try_from((
        ResourceIdentityDigest::try_from([0x31; 32]).expect("digest"),
        version(2),
        token(2),
    ))
    .expect("ownership ref");
    let inventory_digest = InventoryDigest::try_from([0x22; 32]).expect("digest");
    td.pure_cancel().expect("pure cancel");
    td.begin(
        retirement_id(0xF00D),
        CleanupTrigger::StartupRecovery(recovery_id(0xBAD1)),
        ErrorSubject::Recovery(recovery_id(0xBAD1)),
        ownership.clone(),
        inventory_digest.clone(),
    )
    .expect("first Stop journaled");
    td.begin(
        retirement_id(0xF00E),
        CleanupTrigger::StartupRecovery(recovery_id(0xBAD1)),
        ErrorSubject::Recovery(recovery_id(0xBAD1)),
        ownership,
        inventory_digest,
    )
    .expect("Stop+EOF 同时到达必须合并到同一 saga（绝不第二次 destructive cleanup）");

    // 纯逻辑（W23B 已提交 piece）：EOF 与 Stop 先后到达只有一个 terminal 状态。
    let mut relay = relay();
    relay.start_leg(RelayDirection::Receive);
    relay.start_leg(RelayDirection::Send);
    assert!(relay.running_proof(), "双方 Running 时 running proof 成立");
    relay.on_terminal(RelayTerminalSource::StreamEof);
    relay.stop(); // Stop 同时到达
    assert!(!relay.running_proof(), "Stop+EOF 后 running proof 必须失效");
    assert_eq!(relay.leg_state(RelayDirection::Receive), RelayLegState::Terminal);
    assert_eq!(relay.leg_state(RelayDirection::Send), RelayLegState::Terminal);

    // 纵切证据：StopEof 点诚实记录；完成时恰好一次 retirement。
    let ev = matrix();
    let gate = env_complete_or_honest_not_run(ev);
    let p = point(ev, CrashPointTag::StopEof);
    assert_point_honest_or_complete(p, gate);
    if gate {
        assert_eq!(
            ev.retirements_recorded, 1,
            "Stop+EOF 必须合并为一次 retirement（double retirement mutant 死于此）"
        );
        assert_eq!(
            ev.packets_after_stop, 0,
            "Stop 之后不得再有 packet（Stop 后 packet 继续 mutant）"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. host kill（计划 §9 第六饱和点）
// ---------------------------------------------------------------------------

/// 杀 **host kill 后仍 Connected / host exit 不触发 Stop** mutant：helper link
/// terminal 必须撤销 admission + packet leg 并启动有界完整 teardown；host 进程退出
/// 路径必须触发恰好一次业务 Stop（幂等）。真实 host kill（helper 检测 link loss 并
/// revoke admission + teardown + 清理 owned state）由纵切在 elevated 环境记录证据；
/// 环境无效时诚实 not_run。
#[test]
fn host_kill_revokes_packet_and_cleans_owned_state() {
    // 纯逻辑（W27 已提交 piece，非提权）：helper link terminal 语义。
    let mut composition =
        compose_nonprivileged_host(&helper_peer()).expect("compose_nonprivileged_host");
    let (peer, capability) = controller_peer_and_capability();
    composition.bind_controller(peer, capability);
    let _ = composition.apply(HostEvent::Connect);
    assert_eq!(
        composition.apply(HostEvent::ProtocolEstablished),
        HostEffect::Connected
    );
    assert!(composition.packet_attachment_active(), "Connected 后 packet leg 必须 live");

    composition.on_helper_link_terminal();
    assert!(
        !composition.admission_open(),
        "helper link terminal 必须撤销 admission（host kill 后仍 Connected 是 mutant）"
    );
    assert!(
        composition.teardown_started(),
        "helper link terminal 必须启动有界完整 teardown"
    );
    assert!(
        !composition.packet_attachment_active(),
        "helper link terminal 必须撤销 packet leg"
    );
    assert_ne!(composition.phase(), HostPhase::Connected);
    assert!(
        matches!(
            composition.apply(HostEvent::Connect),
            HostEffect::ConnectRefused(_)
        ),
        "admission 撤销后 Connect 必须被拒绝"
    );

    // host exit：恰好一次业务 Stop（幂等）。
    composition.exit();
    composition.exit();
    assert_eq!(
        composition.stop_requests(),
        1,
        "host exit 必须恰好一次业务 Stop（幂等）"
    );
    assert!(!composition.packet_attachment_active(), "host exit 必须撤销 packet leg");
    assert!(!composition.admission_open(), "host exit 必须关闭 admission");

    // 纵切证据：host kill 点诚实记录；完成时 helper 检测 link loss、清理回到 before。
    let ev = matrix();
    let gate = env_complete_or_honest_not_run(ev);
    let p = point(ev, CrashPointTag::HostKill);
    assert_point_honest_or_complete(p, gate);
    if gate {
        assert!(
            ev.helper_pid.is_some(),
            "host kill 纵切必须记录 helper PID（真实 helper 进程）"
        );
        assert!(
            p.native_observation.iter().any(|s| s.contains("link_loss")),
            "helper 必须检测 host link loss，got {:?}",
            p.native_observation
        );
        assert!(
            ev.network_state_after_equals_before,
            "host kill 后 owned state 必须清理且网络回到 before（无残留）"
        );
    }
}

// ---------------------------------------------------------------------------
// 7. helper 在 admission/effect/observation/reply 边界 kill（计划 §9 第七/八饱和点）
// ---------------------------------------------------------------------------

/// 杀 **crash 后 recovery 重放 apply / 无 observation 声称 clean / apply 未确认的
/// effect** mutant：helper 在 journal admission 与 native effect 之间被杀（真实
/// 子进程 + TerminateProcess，W13-T/W25-T 同款）→ 接管 WAIT_ABANDONED 后必须先
/// re-observe 才能 claim（无 observation = ObservationFailed）；有 observation 时
/// durable admission 无 terminal outcome = EffectUnknown（携带 observation，绝不重放
/// apply）；recovery 不得改写 durable journal。admission 边界 kill 非提权可复现；
/// effect/observation/reply 边界（native effect 需 elevated 环境）经纵切证据断言
/// （require_admin gate）。
#[test]
fn helper_crash_boundaries_recover_without_duplicate_apply() {
    if let Some(code) = child_role() {
        std::process::exit(code);
    }

    let dir = test_dir("helper-crash");
    let name = authority_name("helper-crash");
    let ready = marker_path("helper-crash", "ready");
    let _ = std::fs::remove_file(&ready);

    // durable admission for the CURRENT ownership（live-token subject）：helper 在
    // journal admission 之后、native effect 确认之前被杀。
    let key = lookup_key(1, OperationMethod::Connect);
    let m0 = admitted(
        &key,
        version(7),
        AuthorizationSubject::LiveOwnershipTokenDigest(token(7)),
        [0x33; 32],
        [0x55; 32],
        MutationKind::External(OperationMethod::Connect),
    );
    {
        let mut store =
            WinJournalStore::open(&JournalPath::from_dir(dir.clone())).expect("open the journal");
        append_admission(&mut store, 0, [0u8; 32], &m0);
    }

    // parent 先持有 mutex 句柄（内核对象在 child 死后仍存活；W25-T 同款）。
    let parent_auth = SingletonAuthority::new(&name).expect("parent opens the authority mutex");

    // helper 子进程：compose（authority -> recovery -> endpoint，ready 后才算 live），
    // 然后 hold 直至被杀。
    let mut owner = spawn_helper_hold(
        &name,
        &dir.to_string_lossy(),
        &ready.to_string_lossy(),
        "helper_crash_boundaries_recover_without_duplicate_apply",
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !ready.exists() {
        assert!(
            Instant::now() < deadline,
            "helper child 从未完成 compose（ready marker 超时）"
        );
        thread::sleep(Duration::from_millis(25));
    }
    // live 的 helper 必须持有 authority：无第二 helper（WSP2 §1：loser 直接退出）。
    let busy = parent_auth.try_acquire().expect("wait on the busy mutex");
    if !matches!(busy, AuthorityAcquire::Busy) {
        let _ = owner.kill();
        let _ = owner.wait();
        panic!("helper child 存活时必须持有 authority（got {busy:?}）");
    }

    // 杀 helper（不释放 authority —— 模拟 crash between journal admission and effect）。
    owner.kill().expect("kill the helper child");
    let _ = owner.wait();
    let _ = std::fs::remove_file(&ready);

    // 接管 abandoned authority（WSP2 §1：WAIT_ABANDONED_0=128 授予所有权）。
    let taken = parent_auth.try_acquire().expect("take over the abandoned mutex");
    assert!(
        matches!(taken, AuthorityAcquire::AbandonedTakenOver),
        "crash 后接管必须观测到 abandoned takeover（got {taken:?}）"
    );

    // 无 observation 不得 claim clean（crash 接管后状态可能不一致）。
    let mut eng = RecoveryEngine::new(JournalPath::from_dir(dir.clone()), parent_auth);
    let no_obs = eng.recover(version(7), &[]).expect("recover without observation");
    assert!(
        matches!(no_obs, RecoveryOutcome::ObservationFailed { .. }),
        "crash 接管后无 native observation 不得 claim clean（ObservationFailed）"
    );

    // 有 observation：EffectUnknown —— 携带 observation，绝不重放 apply
    // （不 apply 未确认的 effect；recovery 永不执行或重放 apply）。
    let fact = observed(InventoryItem::Adapter, [0x33; 32], [0x55; 32]);
    let expected_fp = NativeObservation::new().fingerprint(std::slice::from_ref(&fact));
    let outcome = eng.recover(version(7), &[fact]).expect("recover with observation");
    let obs_list = obligations(&outcome);
    assert_eq!(obs_list.len(), 1, "恰好一个 durable admission 进入决策");
    match &obs_list[0].action {
        RecoveryAction::EffectUnknown { observed_fingerprint } => {
            assert_eq!(
                *observed_fingerprint, expected_fp,
                "decision 必须携带 native observation（observe before action）"
            );
        }
        other => panic!(
            "durable admission 无 terminal outcome 必须 EffectUnknown（绝不重放 apply），got {other:?}"
        ),
    }

    // recovery 不得改写 durable journal（不追加 admission、不写 terminal、不损坏）。
    let proj = JournalProjection::new(&JournalPath::from_dir(dir.clone()));
    let records = match proj.project().expect("project the journal") {
        ProjectionOutcome::Clean(records) => records,
        ProjectionOutcome::TornTail { records } => records,
        ProjectionOutcome::Corrupt { offset } => {
            panic!("recovery 不得损坏 durable journal（corrupt at {offset}）")
        }
    };
    assert_eq!(
        records.len(),
        1,
        "recovery 不得追加/改写 durable journal（无 apply of un-admitted effect）"
    );

    // 纵切证据：四个 crash 边界 + restart/reconcile 点诚实记录；无重复 apply。
    let ev = matrix();
    let gate = env_complete_or_honest_not_run(ev);
    for tag in [
        CrashPointTag::HelperCrashBoundaryAdmission,
        CrashPointTag::HelperCrashBoundaryEffect,
        CrashPointTag::HelperCrashBoundaryObservation,
        CrashPointTag::HelperCrashBoundaryReply,
        CrashPointTag::RestartReconcile,
    ] {
        let p = point(ev, tag);
        assert_point_honest_or_complete(p, gate);
    }
    if gate {
        assert_eq!(
            ev.duplicate_apply_attempts, 0,
            "crash 后不得重复 apply（duplicate apply mutant 死于此）"
        );
        assert!(
            ev.recovery_reobserved_before_claim,
            "recovery 必须先 re-observe 再 claim（crash 后不得无观察声称 clean）"
        );
    } else {
        assert!(
            !ev.recovery_reobserved_before_claim,
            "not_run 时不得伪造 recovery 事实"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 8. third-party route/DNS change（计划 §9 第九饱和点）
// ---------------------------------------------------------------------------

/// 杀 **compare-restore 破坏 third-party 变更 / 同名字资源被误删** mutant：
/// 会话中途第三方改动 route/DNS 行（same identity、diverged fingerprint）——
/// recovery/cleanup 必须 typed skip（DivergedNotOwned，绝不按名字删除），native
/// observation 指纹必须不匹配；清理后网络状态回到 before 且第三方行保留。
#[test]
fn third_party_route_and_dns_changes_survive() {
    // 纯逻辑（W25 已提交 piece，非提权）：same name + diverged fingerprint = 不 owned。
    let dir = test_dir("third-party");
    let key = lookup_key(1, OperationMethod::Connect);
    let m0 = admitted(
        &key,
        version(7),
        AuthorizationSubject::LiveOwnershipTokenDigest(token(7)),
        [0x33; 32],
        [0x55; 32],
        MutationKind::External(OperationMethod::Connect),
    );
    {
        let mut store =
            WinJournalStore::open(&JournalPath::from_dir(dir.clone())).expect("open the journal");
        append_admission(&mut store, 0, [0u8; 32], &m0);
    }

    let obs = NativeObservation::new();
    let third_party = observed(InventoryItem::Adapter, [0x33; 32], [0x77; 32]);
    let observed_fp = obs.fingerprint(std::slice::from_ref(&third_party));
    let applied = AppliedFingerprint::try_from([0x55; 32]).expect("applied fingerprint");
    assert!(
        !obs.matches(&observed_fp, &applied),
        "diverged fingerprint（third-party 变更）不得匹配 durable applied fingerprint"
    );

    let authority =
        SingletonAuthority::new(&authority_name("third-party")).expect("create the authority");
    assert!(
        matches!(
            authority.try_acquire().expect("acquire the authority"),
            AuthorityAcquire::Acquired
        ),
        "recovery 只在排他 authority 下运行"
    );
    let mut eng = RecoveryEngine::new(JournalPath::from_dir(dir.clone()), authority);
    let outcome = eng
        .recover(version(7), &[third_party])
        .expect("recover with the third-party observation");
    let obs_list = obligations(&outcome);
    assert_eq!(obs_list.len(), 1);
    assert!(
        matches!(obs_list[0].action, RecoveryAction::DivergedNotOwned { .. }),
        "same identity + diverged fingerprint 必须 typed skip（绝不按名字删除）—— \
         third-party route/DNS 变更必须被 compare-restore 保留"
    );

    // 纵切证据：third-party 变更点诚实记录；完成时清理后网络回到 before。
    let ev = matrix();
    let gate = env_complete_or_honest_not_run(ev);
    let p = point(ev, CrashPointTag::ThirdPartyRouteDns);
    assert_point_honest_or_complete(p, gate);
    if gate {
        assert!(
            ev.network_state_after_equals_before,
            "third-party route/DNS 变更必须被 compare-restore 保留（清理后网络等于 before）"
        );
        assert!(
            p.native_observation.iter().any(|s| s.contains("preserved")),
            "third-party 行必须记录为 preserved，got {:?}",
            p.native_observation
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 9. queued overlap（计划 §9 第十饱和点）
// ---------------------------------------------------------------------------

/// 杀 **queued overlap 双 winner / 第二业务状态机** mutant：并发连接竞争 packet
/// capability 只有一个 winner（单次原子消费，后来者被拒）；host 组合恰好一个 runtime
/// actor（第二连接不可能制造第二状态机）；完成后排队连接只能在 prior retirement 之后
/// promote（phase journal 顺序）。
#[test]
fn queued_overlap_promotes_only_after_retirement() {
    // 纯逻辑（W23B 已提交 piece，非提权）：single-use 原子 attach，一个 winner。
    let mut capability = PacketCapability::issue(
        deterministic_packet_lease(),
        deterministic_runtime_epoch(),
    );
    let first = AttachedPacketRelay::attach(&mut capability, 1);
    assert!(first.is_ok(), "第一个连接必须赢得 attach");
    let second = AttachedPacketRelay::attach(&mut capability, 2);
    assert!(
        second.is_err(),
        "queued overlap 只有一个 winner（单次原子消费，后来者必须被拒）"
    );

    // 纯逻辑（W27 已提交 piece，非提权）：host 恰好一个 runtime actor。
    let composition =
        compose_nonprivileged_host(&helper_peer()).expect("compose_nonprivileged_host");
    assert_eq!(
        composition.runtime_actor_count(),
        1,
        "host 组合必须恰好一个 runtime actor（第二业务状态机是 mutant）"
    );

    // 纵切证据：queued overlap 点诚实记录；完成时 promote 只在 retirement 之后。
    let ev = matrix();
    let gate = env_complete_or_honest_not_run(ev);
    let p = point(ev, CrashPointTag::QueuedOverlap);
    assert_point_honest_or_complete(p, gate);
    if gate {
        assert!(
            p.native_observation.iter().any(|s| s.contains("one_winner")),
            "queued overlap 必须记录 one_winner，got {:?}",
            p.native_observation
        );
        assert!(
            journal_has_before(&ev.phase_journal, "retire", "promote"),
            "queued connect 只能在 prior retirement 之后 promote，got {:?}",
            ev.phase_journal
        );
    }
}

// ---------------------------------------------------------------------------
// 10. oracle：crash=no-effect mutant（纯逻辑，非提权必须通过）
// ---------------------------------------------------------------------------

/// 杀 **crash=no-effect** mutant：评级语义必须按冻结规则携带证据——RvP3 必须带
/// 10 次恰 1 次 + restart 后 3 次通过 + 无残留 门禁；RvP1 必须带非偶现 + 重启可恢复；
/// RvP2 必须带偶现；RvP0 必须带具体 blocker。crash 后的 recovery 必须先 re-observe
/// 再 claim（recovery_reobserved_before_claim）且绝不重复 apply；任何 crash 点不得
/// 声称 no-effect。环境无效时所有点必须诚实标记 blocker，不得伪造完成。证据序列化
/// 不得含 raw secret/cookie/private key/certificate。
#[test]
fn oracle_kills_crash_equals_noeffect_mutant() {
    let ev = matrix();
    let gate = env_complete_or_honest_not_run(ev);

    // 13 个饱和点恰好各一次。
    let mut seen: Vec<CrashPointTag> = ev.points.iter().map(|p| p.point).collect();
    seen.sort();
    let mut expected: Vec<CrashPointTag> = ALL_POINT_TAGS.to_vec();
    expected.sort();
    assert_eq!(
        seen, expected,
        "evidence 必须恰好覆盖全部 13 个饱和点（每点一次），got {seen:?}"
    );

    // 每点评级合规（纯逻辑 checker）。
    for p in &ev.points {
        rating_conforms(p, gate).unwrap_or_else(|e| panic!("{e}"));
        assert_point_honest_or_complete(p, gate);
    }

    if gate {
        // crash=no-effect mutant：crash 后 recovery 必须先 re-observe 再 claim，
        // 且绝不重复 apply；有 durable record 的 crash 点不得声称 no-effect。
        assert!(
            ev.recovery_reobserved_before_claim,
            "crash 后必须 re-observe 再 claim（crash=no-effect mutant 死于此）"
        );
        assert_eq!(
            ev.duplicate_apply_attempts, 0,
            "crash 后不得重复 apply（crash=no-effect mutant 死于此）"
        );
        for p in &ev.points {
            if p.last_durable_record.is_some() {
                assert!(
                    !p.final_proof_or_blocker.contains("no-effect"),
                    "crash 点不得声称 no-effect（{:?}），got {:?}",
                    p.point,
                    p.final_proof_or_blocker
                );
            }
        }
    } else {
        // not_run 诚实性：不得伪造任何动态事实。
        assert!(
            !ev.recovery_reobserved_before_claim,
            "not_run 时不得伪造 recovery 事实"
        );
        assert_eq!(ev.packets_after_stop, 0, "not_run 时不得伪造 Stop 后流量");
        assert_eq!(ev.retirements_recorded, 0, "not_run 时不得伪造 retirement");
    }

    // 独立于 production 自报的序列化扫描（证据形状纯逻辑检查）。
    assert!(
        ev.no_raw_secret_in_evidence,
        "证据必须声明不含 raw secret/cookie/private key"
    );
    let json = serde_json::to_string(ev).unwrap_or_else(|e| format!("evidence-serialize-error:{e}"));
    for marker in FORBIDDEN_EVIDENCE_MARKERS {
        assert!(
            !json.contains(marker),
            "evidence JSON 不得包含 {marker:?}"
        );
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
