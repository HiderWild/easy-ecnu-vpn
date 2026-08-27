// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W25-T terra: startup recovery over the durable journal + native observation. These tests pin the
// recovery / journal_projection / native_observation API that W25-I implements in
// exv_vpn_win32_resource::{recovery, journal_projection, native_observation}. The frozen
// contracts are:
//   - plan W25 row: `recovery.rs`：admission/effect/outcome/proof/retirement/token-slot crash
//     points、native observe before action；production files `recovery.rs, journal_projection.rs,
//     native_observation.rs`；killer mutants: **timeout replay apply** / **prior token auth** /
//     **delete same-name without ownership**；
//   - architecture §5.1 (启动恢复): 平台 resource owner 在查 journal 和原生状态前先获取排他
//     mutation authority；只返回 EXV 已记录但未退休的 obligation；对 durable intent 未有
//     terminal outcome 的 operation 按冻结 predicate 观察并 reconcile——绝不重放 apply；没有
//     durable EXV ownership 证据的资源不凭名字或推测删除；
//   - architecture §7.4 (crash rules): torn/incomplete admission 不是 admission；corrupt middle
//     → JournalCorrupt 不跳过、不出 proof；`MutationAdmitted` durable 后先 observation 不重放
//     apply；token slot/connection/authority 终止 → token 失效清零，journal 中的 ownership
//     必须先 recovery/retirement，不并行签发新 token；
//   - architecture §7.5: destructive cleanup 只由 durable recovery authority
//     （`AuthorizationSubject::RecoveryAuthority(RetirementOperationId)`）授予，prior token
//     或其 digest 永不授权；proof 绑定 `journal_root_or_projection_digest`；
//   - WSP2 facts (native-authority-storage-facts.md §1/§4): torn final tail 恢复到最后一个
//     完整 record；corrupt middle 报 Corrupt 不跳过；owner 被 TerminateProcess 杀死而不释放时
//     下一个 waiter 得 WAIT_ABANDONED_0=128 并被授予所有权，接管后必须先观察再谈 clean。
//
// W25-I pinned seam（W25-I 必须提供下列 exact 名称，否则本测试编译失败 = RED）：
//   journal_projection::ProjectionOutcome { Clean(Vec<JournalRecord>),
//     TornTail { records: Vec<JournalRecord> }, Corrupt { offset: usize } }
//     （Debug/Clone/PartialEq）—— torn tail 只保留最后一个完整 record；corrupt middle 报
//     offset，不跳过（WSP2 §4）
//   journal_projection::JournalProjection::new(journal: &JournalPath) -> Self
//   journal_projection::JournalProjection::project(&self) -> Result<ProjectionOutcome, NativeError>
//   journal_projection::JournalProjection::projection_digest(&self, records: &[JournalRecord])
//     -> [u8; 32] —— durable projection digest（CleanProof 的 journal_root_or_projection_digest
//     输入；同一 projection 重复计算必须稳定）
//   native_observation::ObservedResource { pub obligation: u8, pub identity_digest: [u8; 32],
//     pub fingerprint: [u8; 32] }（Debug/Clone/PartialEq/Eq）—— obligation 为
//     inventory::InventoryItem 的 u8 标签；identity_digest 是平台资源身份（adapter 名/地址行…）
//   native_observation::ObservedFingerprint（TryFrom<[u8; 32]>，Error = &'static str；
//     Debug/Clone/PartialEq/Eq）
//   native_observation::NativeObservation::new() -> Self
//   native_observation::NativeObservation::fingerprint(&self, facts: &[ObservedResource])
//     -> ObservedFingerprint —— 纯逻辑，无 I/O
//   native_observation::NativeObservation::matches(&self, observed: &ObservedFingerprint,
//     applied: &AppliedFingerprint) -> bool —— 纯逻辑指纹比对
//   recovery::RecoveryAction { EffectUnknown { observed_fingerprint: ObservedFingerprint },
//     CleanOwned { observed_fingerprint: ObservedFingerprint },
//     DivergedNotOwned { observed_fingerprint: ObservedFingerprint },
//     PriorOwnershipStale { observed_fingerprint: ObservedFingerprint } }
//     （Debug/Clone/PartialEq）
//   recovery::ObligationRecovery { pub obligation: u8,
//     pub applied_fingerprint: AppliedFingerprint,
//     pub observed_fingerprint: ObservedFingerprint, pub action: RecoveryAction }
//     （Debug/Clone/PartialEq）
//   recovery::RecoveryOutcome { ProvenClean { projection_digest: [u8; 32] },
//     Pending { obligations: Vec<ObligationRecovery>, projection_digest: [u8; 32] },
//     ObservationFailed { obligation: u8 }, Corrupt { offset: usize } }
//     （Debug/Clone/PartialEq；镜像架构 §7.5 CleanupOutcome：ProvenClean / StillOwned（→
//     CleanOwned）/ EffectUnknown / ObservationFailed）
//   recovery::RecoveryEngine::new(journal: JournalPath, authority: SingletonAuthority) -> Self
//     —— 类型层强制：恢复必须在排他 mutation authority 之后（架构 §5.1 第一步；W13 顺序：
//     先 lock 后 scan）；engine 持有 authority 直到恢复完成
//   recovery::RecoveryEngine::recover(&mut self, current_ownership_version: OwnershipVersion,
//     observed: &[ObservedResource]) -> Result<RecoveryOutcome, NativeError>
//     —— `observed` 是必填输入：native observation 必须先于任何 action（observe before
//     action）；engine 永不执行或重放 apply。分类契约（W25-I 必须实现，按序判定）：
//       1) projection Corrupt -> RecoveryOutcome::Corrupt{offset}（不跳过、不出 proof）；
//       2) 无未退休 intent -> ProvenClean{projection_digest}；
//       3) 逐条解码 projection 中的 admission（torn 尾帧不是 admission，不进入决策）：
//          a) ownership_version != current -> PriorOwnershipStale（prior token/digest 只关联
//             历史，永不授权 —— mutant: prior token auth 死于此）；
//          b) 该 obligation 无 observed 事实 -> ObservationFailed{obligation}（绝不猜测）；
//          c) observed fingerprint != desired_applied_fingerprint -> DivergedNotOwned
//             （同名字也绝不删除 —— mutant: delete same-name without ownership 死于此）；
//          d) fingerprint 匹配且 admission 为 durable RecoveryAuthority(id) -> CleanOwned
//             （destructive cleanup 只由 durable retirement identity 授予，绝不由 token 授予）；
//          e) 其余（durable admission 后无 terminal outcome，live-token subject）-> EffectUnknown
//             （native effect 可能已发生：观察并 reconcile，绝不重放 apply —— mutant:
//             timeout replay apply 死于此）；
//       4) 全部未退休 obligation 分类完成 -> Pending{obligations, projection_digest}。
//
// 所有测试在每测独立 temp 目录（%TEMP%\exv-w25-<pid>-<tag>）做真实 journal I/O 并自清理；
// 纯逻辑（决策分类、指纹比对、J50 decode 结果）与真实 journal 往返测试在非提权宿主必须
// 通过。abandoned-mutex 接管用真子进程：测试二进制以 EXV_W25_CHILD 环境变量 + libtest
// --exact 重执行（authority_singleton.rs 同款模式）；parent 先持有 mutex 句柄使内核对象
// 在子进程被 TerminateProcess 后仍存活，接管后 recovery 必须先观察（never ProvenClean
// without observation）。prior token 明文不可持久、trace 或 debug；digest 只关联历史，
// 永远不授权（W15 冻结行）。

use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use exv_vpn_domain::error::ErrorSubject;
use exv_vpn_domain::identity::{
    ConnectionBindingDigest, EffectId, InventoryDigest, OperationId, OperationLookupKey,
    OperationMethod, OwnershipVersion, PrincipalDigest, RecoveryId, RequestDigest,
    ResourceIdentityDigest, RetirementOperationId, RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::model::PlatformOwnershipRef;
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CanonicalInputDigest, CleanupTrigger,
    JournalOperationIdentity, JournalRevision, PlatformAuthorityInstanceId,
};
use exv_vpn_resource::admission::{
    AdmissionRecord, AppliedFingerprint, AuthorizationSubject, MutationAdmitted, MutationKind,
    ObligationSeed, encode_record,
};
use exv_vpn_resource::authority::ConnectionBinding;
use exv_vpn_resource::delivery::{
    DeliveryOutcome, OwnershipTokenDelivery, TerminateOutcome, TokenDeliveryRequest,
};
use exv_vpn_resource::journal::{encode, verify_chain, JournalRecord};
use exv_vpn_resource::retirement::{RetirementPhase, RetirementSaga};
use exv_vpn_win32_resource::authority::{AuthorityAcquire, SingletonAuthority};
use exv_vpn_win32_resource::inventory::InventoryItem;
use exv_vpn_win32_resource::journal_path::JournalPath;
use exv_vpn_win32_resource::journal_projection::{JournalProjection, ProjectionOutcome};
use exv_vpn_win32_resource::journal_store::WinJournalStore;
use exv_vpn_win32_resource::native_observation::{
    NativeObservation, ObservedFingerprint, ObservedResource,
};
use exv_vpn_win32_resource::recovery::{
    ObligationRecovery, RecoveryAction, RecoveryEngine, RecoveryOutcome,
};

use uuid::Uuid;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A fresh, per-test temp directory: %TEMP%\exv-w25-<pid>-<tag>. Any stale copy from a
/// prior crashed run is removed so every test starts clean.
fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("exv-w25-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A unique `Local\`-scoped authority mutex name per test (tag + pid), so parallel tests
/// and repeated runs never collide.
fn authority_name(tag: &str) -> String {
    format!(r"Local\ExvVpnW25Authority_{tag}_{}", std::process::id())
}

/// Marker file under %TEMP%, shared by parent and child (path passed via env).
fn marker_path(tag: &str, kind: &str) -> PathBuf {
    std::env::temp_dir().join(format!("exv-w25-{tag}-{kind}.marker"))
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

/// Deterministic request digest that differs across `n`.
fn request_digest(n: u8) -> RequestDigest {
    RequestDigest::try_from(digest(n)).expect("digest")
}

/// Deterministic candidate/held token digest that differs across `n`.
fn token(n: u8) -> TokenDigest {
    TokenDigest::try_from(digest(n)).expect("digest")
}

/// Deterministic connection binding that differs across `n`.
fn binding(n: u8) -> ConnectionBinding {
    let connection_digest = ConnectionBindingDigest::try_from(digest(n)).expect("digest");
    ConnectionBinding::try_from(connection_digest).expect("binding")
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

/// A durable `MutationAdmitted` of kind Retirement sealed with the recovery authority
/// subject — the exact shape `RetirementSaga::begin` seals (retirement.rs 同款固定 digest)。
fn retirement_admitted(id: &RetirementOperationId, ownership_version: OwnershipVersion) -> MutationAdmitted {
    let f = fence();
    MutationAdmitted {
        mutation_kind: MutationKind::Retirement,
        journal_operation_identity: JournalOperationIdentity::Retirement(id.clone()),
        effect_id: EffectId::try_from(Uuid::from_u128(0xF00D_0000_0000_0000))
            .expect("non-nil effect id"),
        canonical_input_digest: CanonicalInputDigest::try_from([0x11; 32]).expect("digest"),
        initiator_identity_digest: principal(9),
        authority_epoch: f.authority_epoch,
        platform_authority_instance_id: f.platform_authority_instance_id,
        admission_watermark: f.admission_watermark,
        ownership_version,
        authorization_subject: AuthorizationSubject::RecoveryAuthority(id.clone()),
        resource_identity: ResourceIdentityDigest::try_from([0x33; 32]).expect("digest"),
        precondition_fingerprint: AppliedFingerprint::try_from([0x44; 32]).expect("digest"),
        desired_applied_fingerprint: AppliedFingerprint::try_from([0x55; 32]).expect("digest"),
        canonical_obligation_seed: ObligationSeed::try_from([0x66; 32]).expect("digest"),
    }
}

/// Append one J51 admission as the next chained journal record (J50 frame + FlushFileBuffers
/// durability via the committed W14 store). Returns the record and its byte offset.
fn append_admission(
    store: &mut WinJournalStore,
    seq: u64,
    prev: [u8; 32],
    m: &MutationAdmitted,
) -> (JournalRecord, u64) {
    let rec = JournalRecord::new(seq, prev, encode_record(&AdmissionRecord::Admitted(m.clone())));
    let offset = store.append_synced(&rec).expect("append_synced a J51 admission record");
    (rec, offset)
}

/// An observed platform fact for one obligation (the native observation result).
fn observed(obligation: InventoryItem, identity: [u8; 32], fp: [u8; 32]) -> ObservedResource {
    ObservedResource {
        obligation: obligation as u8,
        identity_digest: identity,
        fingerprint: fp,
    }
}

/// Build a recovery engine that has already acquired the exclusive mutation authority
/// (architecture §5.1 step 1: authority BEFORE journal/native scan).
fn engine(jp: JournalPath, tag: &str) -> RecoveryEngine {
    let authority =
        SingletonAuthority::new(&authority_name(tag)).expect("create the authority mutex");
    assert!(
        matches!(
            authority.try_acquire().expect("acquire the authority"),
            AuthorityAcquire::Acquired
        ),
        "recovery runs only under exclusive mutation authority"
    );
    RecoveryEngine::new(jp, authority)
}

/// The obligations of a Pending recovery outcome.
fn obligations(outcome: &RecoveryOutcome) -> &[ObligationRecovery] {
    match outcome {
        RecoveryOutcome::Pending { obligations, .. } => obligations,
        other => panic!("expected a Pending recovery outcome, got {other:?}"),
    }
}

/// The projection digest of a digest-carrying recovery outcome.
fn outcome_digest(outcome: &RecoveryOutcome) -> [u8; 32] {
    match outcome {
        RecoveryOutcome::Pending { projection_digest, .. }
        | RecoveryOutcome::ProvenClean { projection_digest } => *projection_digest,
        other => panic!("expected a digest-carrying recovery outcome, got {other:?}"),
    }
}

/// The single journal file the store created in `dir` (never hard-code the file name).
fn journal_file_in(dir: &PathBuf) -> PathBuf {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read the journal directory")
        .map(|e| e.expect("a directory entry").path())
        .filter(|p| p.is_file())
        .collect();
    assert_eq!(files.len(), 1, "the journal directory must contain exactly one file");
    files.remove(0)
}

// ---------------------------------------------------------------------------
// Child-process sentinels (abandoned-mutex takeover)
// ---------------------------------------------------------------------------

const CHILD_ENV: &str = "EXV_W25_CHILD";
const MUTEX_ENV: &str = "EXV_W25_MUTEX";
const MARKER_ENV: &str = "EXV_W25_MARKER";
/// The child hit a NativeError instead of the expected result.
const CHILD_EXIT_ERROR: i32 = 252;
/// The hold-role child failed to acquire the mutex it was supposed to own.
const CHILD_EXIT_NOT_OWNER: i32 = 253;

/// Re-execute this test binary as the child. libtest's `--exact` runs only the named
/// test; that test checks `child_role()` first and exits before any parent work.
fn spawn_child(mode: &str, name: &str, marker: &str, exact_test: &str) -> Child {
    Command::new(std::env::current_exe().expect("current test exe"))
        .env(CHILD_ENV, mode)
        .env(MUTEX_ENV, name)
        .env(MARKER_ENV, marker)
        .arg("--exact")
        .arg(exact_test)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the child test process")
}

/// Child role entry, called at the top of every test that can be re-executed as a child.
/// Returns the exit code when running as a child; `None` in the parent role.
fn child_role() -> Option<i32> {
    let mode = std::env::var(CHILD_ENV).ok()?;
    let name = std::env::var(MUTEX_ENV).expect("child must receive the mutex name");
    let marker = std::env::var(MARKER_ENV).expect("child must receive the marker path");
    let auth = match SingletonAuthority::new(&name) {
        Ok(a) => a,
        Err(_) => return Some(CHILD_EXIT_ERROR),
    };
    match mode.as_str() {
        // Owner role: take ownership, signal readiness, then hold forever until the
        // parent TerminateProcess-es this process WITHOUT releasing the mutex.
        "hold" => match auth.try_acquire() {
            Ok(AuthorityAcquire::Acquired) => {
                let _ = std::fs::write(&marker, b"ready");
                loop {
                    thread::sleep(Duration::from_secs(3600));
                }
            }
            _ => Some(CHILD_EXIT_NOT_OWNER),
        },
        other => panic!("unknown child mode {other}"),
    }
}

// ---------------------------------------------------------------------------
// The 8 pinned cases
// ---------------------------------------------------------------------------

/// Kills 'torn tail treated as clean / torn record admitted' (WSP2 facts §4 at the recovery
/// level): a truncated final J50 frame projects as TornTail with only the complete records,
/// the torn frame is NOT an admission (架构 §7.4：torn/incomplete record 不是 admission), and
/// the recovery decision never acts on the torn operation.
#[test]
fn torn_tail_recovers_to_last_complete_admission() {
    let dir = test_dir("torn");
    let jp = JournalPath::from_dir(dir.clone());
    let key = lookup_key(1, OperationMethod::Connect);
    let m0 = admitted(
        &key,
        version(7),
        AuthorizationSubject::LiveOwnershipTokenDigest(token(7)),
        [0x33; 32],
        [0x55; 32],
        MutationKind::External(OperationMethod::Connect),
    );
    let m1 = admitted(
        &key,
        version(7),
        AuthorizationSubject::LiveOwnershipTokenDigest(token(8)),
        [0x34; 32],
        [0x56; 32],
        MutationKind::External(OperationMethod::Connect),
    );

    // Record 0 is complete and durable; record 1's frame is torn mid-header (never durable).
    let (r0, _) = {
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        append_admission(&mut store, 0, [0u8; 32], &m0)
    }; // drop the append handle so the file can be appended raw

    let file = journal_file_in(&dir);
    let torn_frame = encode(&JournalRecord::new(1, r0.digest, encode_record(&AdmissionRecord::Admitted(m1))));
    {
        let mut raw = std::fs::OpenOptions::new()
            .append(true)
            .open(&file)
            .expect("reopen the journal file for the torn frame");
        raw.write_all(&torn_frame[..40]).expect("write a partial header as the torn frame");
    }

    // Projection: the torn tail must recover to the last complete record only.
    let proj = JournalProjection::new(&jp);
    match proj.project().expect("project the journal") {
        ProjectionOutcome::TornTail { records } => {
            assert_eq!(records.len(), 1, "the torn tail must recover to the last complete record");
            assert_eq!(records[0].sequence, 0, "only the durable record survives");
            assert!(
                verify_chain(&records).is_ok(),
                "the recovered records must form a valid J50 digest chain"
            );
        }
        other => panic!("a truncated final frame must project as TornTail, got {other:?}"),
    }

    // Recovery: the torn frame's operation never enters the decision.
    let fact = observed(InventoryItem::Adapter, [0x33; 32], [0x55; 32]);
    let mut eng = engine(JournalPath::from_dir(dir.clone()), "torn");
    let outcome = eng.recover(version(7), &[fact]).expect("recover");
    let obs_list = obligations(&outcome);
    assert_eq!(
        obs_list.len(),
        1,
        "the torn frame must NOT surface as an obligation (torn/incomplete record is not an admission)"
    );
    assert!(
        matches!(obs_list[0].action, RecoveryAction::EffectUnknown { .. }),
        "the one complete admission (no terminal outcome) must be EffectUnknown"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'corruption skipped / recovery proceeds past a corrupt middle record' (WSP2 facts
/// §4 + 架构 §7.4): a corrupt middle record yields Corrupt at that record's offset, and
/// recovery refuses to act — no skip forward, no proof.
#[test]
fn corrupt_middle_journal_is_corrupt_no_skip_forward() {
    let dir = test_dir("corrupt");
    let jp = JournalPath::from_dir(dir.clone());
    let key = lookup_key(1, OperationMethod::Connect);
    let m0 = admitted(
        &key,
        version(7),
        AuthorizationSubject::LiveOwnershipTokenDigest(token(7)),
        [0x33; 32],
        [0x55; 32],
        MutationKind::External(OperationMethod::Connect),
    );
    let m1 = admitted(
        &key,
        version(7),
        AuthorizationSubject::LiveOwnershipTokenDigest(token(8)),
        [0x34; 32],
        [0x56; 32],
        MutationKind::External(OperationMethod::Connect),
    );
    let m2 = admitted(
        &key,
        version(7),
        AuthorizationSubject::LiveOwnershipTokenDigest(token(9)),
        [0x35; 32],
        [0x57; 32],
        MutationKind::External(OperationMethod::Connect),
    );

    let r1_offset;
    {
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        let (r0, _) = append_admission(&mut store, 0, [0u8; 32], &m0);
        let (r1, off) = append_admission(&mut store, 1, r0.digest, &m1);
        r1_offset = off;
        let (_, _) = append_admission(&mut store, 2, r1.digest, &m2);
    } // drop closes the append handle so the file can be rewritten

    let file = journal_file_in(&dir);
    let mut bytes = std::fs::read(&file).expect("read the journal file");
    // Flip a byte inside record 1's payload (frame starts at r1_offset, payload at +45).
    let payload_byte = (r1_offset as usize) + 45;
    assert!(payload_byte < bytes.len(), "record 1 payload byte must be within the file");
    bytes[payload_byte] ^= 0xFF;
    std::fs::write(&file, &bytes).expect("rewrite the corrupted journal file");

    // Projection level: Corrupt at record 1's frame offset.
    let proj = JournalProjection::new(&jp);
    match proj.project().expect("project the journal") {
        ProjectionOutcome::Corrupt { offset } => {
            assert_eq!(
                offset, r1_offset as usize,
                "the corrupt record offset must be record 1's frame offset"
            );
        }
        other => panic!("a corrupt middle record must project as Corrupt, got {other:?}"),
    }

    // Engine level: recovery must refuse the corrupt journal — no skip, no proof.
    let mut eng = engine(JournalPath::from_dir(dir.clone()), "corrupt");
    let outcome = eng.recover(version(7), &[]).expect("recover");
    match outcome {
        RecoveryOutcome::Corrupt { offset } => {
            assert_eq!(
                offset, r1_offset as usize,
                "recovery must refuse to skip the corrupt middle record"
            );
        }
        other => panic!("a corrupt middle journal must be Corrupt for recovery (no skip), got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'timeout replay apply' (plan W25 mutant): a durable `MutationAdmitted` with no
/// terminal outcome (native effect deadline timed out / crash before outcome) is recovered
/// as EffectUnknown — native observation happens first and is carried into the decision,
/// and the apply is NEVER replayed (架构 §7.4：MutationAdmitted durable 后先做 platform
/// observation，不重放 apply).
#[test]
fn durable_admission_without_outcome_observes_never_replays_apply() {
    let dir = test_dir("timeout");
    let jp = JournalPath::from_dir(dir.clone());
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
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        append_admission(&mut store, 0, [0u8; 32], &m0);
    }

    // The durable projection digest is the CleanProof `journal_root_or_projection_digest`
    // input and must be stable.
    let proj = JournalProjection::new(&jp);
    let records = match proj.project().expect("project the journal") {
        ProjectionOutcome::Clean(records) => records,
        other => panic!("expected a Clean projection, got {other:?}"),
    };
    let proof_digest = proj.projection_digest(&records);

    // Native observation happened BEFORE the action: the observed fact feeds the decision,
    // and the decision carries the observed fingerprint — never an apply replay.
    let observed_fact = observed(InventoryItem::Adapter, [0x33; 32], [0x55; 32]);
    let expected_fp = NativeObservation::new().fingerprint(std::slice::from_ref(&observed_fact));

    let mut eng = engine(JournalPath::from_dir(dir.clone()), "timeout");
    let outcome = eng.recover(version(7), &[observed_fact]).expect("recover");
    let obs_list = obligations(&outcome);
    assert_eq!(obs_list.len(), 1, "exactly one durable admission must be decided");
    assert_eq!(
        outcome_digest(&outcome),
        proof_digest,
        "the proof input digest must be the durable projection digest"
    );
    match &obs_list[0].action {
        RecoveryAction::EffectUnknown { observed_fingerprint } => {
            assert_eq!(
                *observed_fingerprint, expected_fp,
                "the decision must carry the native observation (observe before action)"
            );
        }
        other => panic!(
            "a durable admission with no terminal outcome must be EffectUnknown (observe and \
             reconcile, NEVER replay apply), got {other:?}"
        ),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'prior token auth' (plan W25 mutant): a prior-ownership admission (prior token
/// subject) is history only — the prior token digest never authorizes destructive cleanup.
/// Cleanup is granted only by the durable recovery authority (架构 §6.5/§7.5：prior token
/// 或其 digest 不得授权 mutation；cleanup 只由 durable RetirementOperationId 授予).
#[test]
fn cleanup_granted_only_by_durable_recovery_authority_never_prior_token() {
    // Common saga composition (committed): begin seals a Retirement admission whose subject
    // is RecoveryAuthority(id) — reproduced by the J51 codec round-trip; the prior token
    // digest never authorizes destructive cleanup.
    let id = retirement_id(0xF00D);
    let mut saga = RetirementSaga::new(fence(), version(2));
    saga.begin(
        id.clone(),
        CleanupTrigger::StartupRecovery(recovery_id(0xBAD1)),
        ErrorSubject::Recovery(recovery_id(0xBAD1)),
        PlatformOwnershipRef::try_from((
            ResourceIdentityDigest::try_from([0x31; 32]).expect("digest"),
            version(2),
            token(2),
        ))
        .expect("ownership ref"),
        vec![InventoryItem::Adapter as u8],
        InventoryDigest::try_from([0x22; 32]).expect("digest"),
    )
    .expect("begin must seal the recovery-authority retirement");
    assert_eq!(
        saga.phase(),
        RetirementPhase::Started,
        "begin must advance the saga to Started"
    );
    assert!(
        saga.grant_cleanup(&id).is_ok(),
        "the durable retirement identity grants cleanup"
    );
    assert!(
        saga.grant_cleanup(&retirement_id(0xF00E)).is_err(),
        "a forged parallel retirement identity must NOT grant cleanup"
    );

    // Engine: journal = prior-version admission (prior token subject) + a durable retirement
    // admission (RecoveryAuthority). The prior-token admission must be PriorOwnershipStale
    // (history only); only the recovery-authority admission is granted cleanup.
    let dir = test_dir("prior-token");
    let jp = JournalPath::from_dir(dir.clone());
    let key = lookup_key(1, OperationMethod::Connect);
    let m_prior = admitted(
        &key,
        version(2),
        AuthorizationSubject::LiveOwnershipTokenDigest(token(2)),
        [0x40; 32],
        [0x47; 32],
        MutationKind::External(OperationMethod::Connect),
    );
    let m_retire = retirement_admitted(&id, version(7));
    {
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        let (r0, _) = append_admission(&mut store, 0, [0u8; 32], &m_prior);
        append_admission(&mut store, 1, r0.digest, &m_retire);
    }

    let mut eng = engine(JournalPath::from_dir(dir.clone()), "prior-token");
    let outcome = eng
        .recover(version(7), &[observed(InventoryItem::Adapter, [0x33; 32], [0x55; 32])])
        .expect("recover");
    let obs_list = obligations(&outcome);
    assert_eq!(obs_list.len(), 2, "both admissions must be decided in projection order");
    assert!(
        matches!(obs_list[0].action, RecoveryAction::PriorOwnershipStale { .. }),
        "a prior-ownership admission (prior token subject) is history only — the prior token \
         never authorizes (mutant: prior token auth)"
    );
    assert!(
        matches!(obs_list[1].action, RecoveryAction::CleanOwned { .. }),
        "destructive cleanup is granted only by the durable recovery authority, never by a \
         token digest"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'delete same-name without ownership' (plan W25 mutant): a platform resource with
/// the SAME identity (name) as the durable record but a DIVERGED fingerprint is NOT owned
/// by this session — typed skip, never delete by name (架构 §5.1：没有 durable EXV ownership
/// 证据的资源不凭名字或推测删除).
#[test]
fn same_name_resource_without_ownership_fingerprint_is_never_deleted() {
    let dir = test_dir("same-name");
    let jp = JournalPath::from_dir(dir.clone());
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
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        append_admission(&mut store, 0, [0u8; 32], &m0);
    }

    // The observed platform resource has the SAME identity (name) as the durable record but
    // a DIFFERENT fingerprint: a third party (or a pre-existing row) holds it.
    let third_party = observed(InventoryItem::Adapter, [0x33; 32], [0x77; 32]);
    let obs = NativeObservation::new();
    let observed_fp = obs.fingerprint(std::slice::from_ref(&third_party));
    let applied = AppliedFingerprint::try_from([0x55; 32]).expect("applied fingerprint");
    assert!(
        !obs.matches(&observed_fp, &applied),
        "a diverged fingerprint must NOT match the durable applied fingerprint"
    );

    let mut eng = engine(JournalPath::from_dir(dir.clone()), "same-name");
    let outcome = eng.recover(version(7), &[third_party]).expect("recover");
    let obs_list = obligations(&outcome);
    assert_eq!(obs_list.len(), 1);
    assert!(
        matches!(obs_list[0].action, RecoveryAction::DivergedNotOwned { .. }),
        "a same-name resource whose fingerprint diverges is NOT owned by this session — typed \
         skip, NEVER delete by name (mutant: delete same-name without ownership)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'recovery non-deterministic / stateful across restarts': recovery is idempotent —
/// an empty journal is ProvenClean on every run, and two engine lifetimes over the same
/// journal reproduce the EXACT same Pending decision (same classification, same projection
/// digest).
#[test]
fn recovery_is_deterministic_and_idempotent_across_restarts() {
    let dir = test_dir("idempotent");
    let jp = JournalPath::from_dir(dir.clone());

    // Empty journal: every run claims ProvenClean (nothing un-retired to act on).
    let mut eng = engine(JournalPath::from_dir(dir.clone()), "idem-a");
    let first = eng.recover(version(7), &[]).expect("recover the empty journal");
    assert!(
        matches!(first, RecoveryOutcome::ProvenClean { .. }),
        "an empty projection must recover as ProvenClean"
    );
    let first_again = eng.recover(version(7), &[]).expect("recover the empty journal again");
    assert_eq!(first, first_again, "recovery must be idempotent on the same journal");

    // Populated journal: identical Pending decisions across two engine lifetimes.
    let key = lookup_key(1, OperationMethod::Connect);
    let m_prior = admitted(
        &key,
        version(2),
        AuthorizationSubject::LiveOwnershipTokenDigest(token(2)),
        [0x40; 32],
        [0x47; 32],
        MutationKind::External(OperationMethod::Connect),
    );
    let m0 = admitted(
        &key,
        version(7),
        AuthorizationSubject::LiveOwnershipTokenDigest(token(7)),
        [0x33; 32],
        [0x55; 32],
        MutationKind::External(OperationMethod::Connect),
    );
    {
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        let (r0, _) = append_admission(&mut store, 0, [0u8; 32], &m_prior);
        append_admission(&mut store, 1, r0.digest, &m0);
    }

    let fact = observed(InventoryItem::Adapter, [0x33; 32], [0x55; 32]);
    let pending_a = eng
        .recover(version(7), std::slice::from_ref(&fact))
        .expect("recover the populated journal");
    assert!(
        !matches!(pending_a, RecoveryOutcome::ProvenClean { .. }),
        "un-retired obligations must never recover as ProvenClean"
    );
    let mut eng_b = engine(JournalPath::from_dir(dir.clone()), "idem-b");
    let pending_b = eng_b.recover(version(7), &[fact]).expect("recover with a fresh engine");
    assert_eq!(
        pending_a, pending_b,
        "a restarted engine must reproduce the exact same recovery decision"
    );

    let obs_list = obligations(&pending_a);
    assert_eq!(obs_list.len(), 2);
    assert!(
        matches!(obs_list[0].action, RecoveryAction::PriorOwnershipStale { .. }),
        "the prior-version admission is history only, in projection order"
    );
    assert!(
        matches!(obs_list[1].action, RecoveryAction::EffectUnknown { .. }),
        "the current-version admission without a terminal outcome is EffectUnknown"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'recovery ignores an abandoned owner / claims clean without observation' (WSP2
/// facts §1 + 架构 §5.1): the next waiter takes over a WAIT_ABANDONED_0 authority, and the
/// recovery built on the taken-over authority must re-observe before any clean claim —
/// without native observation it refuses (ObservationFailed), with observation the pending
/// intent is EffectUnknown (never a replayed apply).
#[test]
fn abandoned_authority_takeover_reobserves_before_any_clean_claim() {
    if let Some(code) = child_role() {
        std::process::exit(code);
    }

    let name = authority_name("abandoned");
    let ready = marker_path("abandoned", "ready");
    let _ = std::fs::remove_file(&ready);

    // Journal: one durable admission for the current ownership (written before the child).
    let dir = test_dir("abandoned");
    let jp = JournalPath::from_dir(dir.clone());
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
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        append_admission(&mut store, 0, [0u8; 32], &m0);
    }

    // The parent opens the mutex FIRST so its handle keeps the kernel object alive after the
    // child (the sole acquiring process) is terminated. Without this, the last handle closes
    // on child death and the object is DESTROYED (a later open creates a new unowned mutex,
    // no WAIT_ABANDONED).
    let parent_auth = SingletonAuthority::new(&name).expect("parent opens the authority mutex");

    // Child opens the same mutex, takes ownership, writes the ready marker, holds forever.
    let mut owner = spawn_child(
        "hold",
        &name,
        &ready.to_string_lossy(),
        "abandoned_authority_takeover_reobserves_before_any_clean_claim",
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() {
        assert!(
            Instant::now() < deadline,
            "the child never acquired the authority mutex"
        );
        thread::sleep(Duration::from_millis(25));
    }

    // Kill the owner without letting it release the mutex (TerminateProcess).
    // SAFETY: pid is the live child's id; PROCESS_TERMINATE is the minimal access.
    let proc_handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, owner.id()) }
        .expect("open the owner process for termination");
    // SAFETY: proc_handle is a valid handle to the live owner we spawned.
    let killed = unsafe { TerminateProcess(proc_handle, 1) };
    // SAFETY: proc_handle was opened above and must be closed.
    unsafe { let _ = CloseHandle(proc_handle); }
    assert!(killed.is_ok(), "TerminateProcess must kill the mutex owner");
    let _ = owner.wait(); // reap the terminated child
    let _ = std::fs::remove_file(&ready);

    // The next waiter takes over the abandoned authority (WAIT_ABANDONED_0=128, WSP2 §1).
    let taken = parent_auth.try_acquire().expect("wait on the abandoned mutex");
    assert!(
        matches!(taken, AuthorityAcquire::AbandonedTakenOver),
        "the recovery entry must observe the abandoned-owner takeover, got {taken:?}"
    );

    // Recovery over the taken-over authority: WITHOUT native observation it must refuse to
    // claim clean (the takeover means the prior state may be inconsistent).
    let mut eng = RecoveryEngine::new(JournalPath::from_dir(dir.clone()), parent_auth);
    let no_obs = eng.recover(version(7), &[]).expect("recover without observation");
    assert!(
        matches!(no_obs, RecoveryOutcome::ObservationFailed { .. }),
        "after an abandoned-owner takeover, recovery must NOT claim clean without native \
         observation"
    );

    // WITH the observation, the pending intent is EffectUnknown — never a replayed apply.
    let outcome = eng
        .recover(version(7), &[observed(InventoryItem::Adapter, [0x33; 32], [0x55; 32])])
        .expect("recover with observation");
    let obs_list = obligations(&outcome);
    assert_eq!(obs_list.len(), 1);
    assert!(
        matches!(obs_list[0].action, RecoveryAction::EffectUnknown { .. }),
        "the taken-over recovery must observe first and never replay the apply"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'recovery mints a parallel token / terminated slot re-sends' (架构 §7.4 token-slot
/// crash rule): a terminated connection slot is Resolved — the same request is NEVER
/// re-sent (AlreadyDelivered, no parallel mint); the durable ownership whose slot was lost
/// can only enter recovery (EffectUnknown), and recovery never issues a new token.
#[test]
fn terminated_token_slot_never_reissues_parallel_token() {
    // J52 delivery seam: issue exactly once, invalidate on connection termination, then the
    // same key+digest+version retry must NEVER re-send.
    let conn = binding(1);
    let key = lookup_key(1, OperationMethod::Connect);
    let req = request_digest(1);
    let tok = token(9);
    let v = version(7);
    let mut slot = OwnershipTokenDelivery::new();
    let issued = slot.deliver(TokenDeliveryRequest {
        connection: conn.clone(),
        key: key.clone(),
        request_digest: req.clone(),
        ownership_version: v,
        candidate_token: tok.clone(),
    });
    assert!(
        matches!(issued, DeliveryOutcome::Issued { token } if token == tok),
        "the empty slot must issue the candidate token exactly once"
    );
    let invalidated = slot.terminate_connection(&conn);
    assert!(
        matches!(
            invalidated,
            TerminateOutcome::Invalidated {
                token,
                ownership_version,
            } if token == tok && ownership_version == v
        ),
        "terminating the connection must invalidate the held token and zero the slot"
    );
    let redeliver = slot.deliver(TokenDeliveryRequest {
        connection: conn.clone(),
        key: key.clone(),
        request_digest: req,
        ownership_version: v,
        candidate_token: tok.clone(),
    });
    assert!(
        matches!(redeliver, DeliveryOutcome::AlreadyDelivered),
        "a terminated slot must never re-send the token (no parallel token mint)"
    );

    // Engine: the durable ownership whose slot was lost can only enter recovery — the
    // journaled intent is EffectUnknown (observe/reconcile), never a new token.
    let dir = test_dir("token-slot");
    let jp = JournalPath::from_dir(dir.clone());
    let m0 = admitted(
        &key,
        v,
        AuthorizationSubject::LiveOwnershipTokenDigest(tok),
        [0x33; 32],
        [0x55; 32],
        MutationKind::External(OperationMethod::Connect),
    );
    {
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        append_admission(&mut store, 0, [0u8; 32], &m0);
    }
    let mut eng = engine(JournalPath::from_dir(dir.clone()), "token-slot");
    let outcome = eng
        .recover(v, &[observed(InventoryItem::Adapter, [0x33; 32], [0x55; 32])])
        .expect("recover");
    let obs_list = obligations(&outcome);
    assert_eq!(obs_list.len(), 1);
    assert!(
        matches!(obs_list[0].action, RecoveryAction::EffectUnknown { .. }),
        "orphaned durable ownership must enter recovery — never a parallel token"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
