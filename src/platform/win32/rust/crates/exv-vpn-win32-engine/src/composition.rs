// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Privileged helper process composition (W26-I).
//!
//! [`compose_privileged_helper`] builds the [`HelperComposition`] by composing the
//! committed leaf pieces — W13 [`SingletonAuthority`], W14 [`JournalPath`] /
//! [`JournalProjection`], W15 [`MutationIngress`], W25 [`RecoveryEngine`] — in the
//! frozen startup order (架构 §5.1: 先 lock 后 scan；endpoint publication 是最后一步):
//!
//! 1. acquire the exclusive mutation authority FIRST
//!    ([`CompositionPhase::AuthorityAcquired`]); a WAIT_TIMEOUT loser returns
//!    [`ComposeError::AuthorityBusy`] before any scan/observe/publish (WSP2 §1);
//! 2. run startup recovery over the durable journal under the authority
//!    ([`CompositionPhase::RecoveryCompleted`]); only a corrupt projection
//!    ([`ComposeError::RecoveryCorrupt`]) or a native failure
//!    ([`ComposeError::Recovery`]) blocks endpoint publication — every other
//!    outcome completes recovery (Pending 也算完成);
//! 3. publish the endpoint LAST ([`CompositionPhase::EndpointPublished`]) — the
//!    composition's authenticated ingress is the helper's only mutation surface.
//!
//! Any failure path releases the acquired authority before returning: the failed
//! compose leaves no state behind.
//!
//! The W22/W24 aggregate/teardown machinery activates when the W28 vertical slice
//! starts real Wintun workers; this pure composition records the worker count
//! (zero) it actually started, and shutdown joins exactly that many.

use std::path::{Path, PathBuf};

use exv_vpn_domain::identity::OwnershipVersion;
use exv_vpn_win32_resource::authority::{AuthorityAcquire, SingletonAuthority};
use exv_vpn_win32_resource::journal_path::JournalPath;
use exv_vpn_win32_resource::journal_projection::{JournalProjection, ProjectionOutcome};
use exv_vpn_win32_resource::native_error::NativeError;
use exv_vpn_win32_resource::native_observation::ObservedResource;
use exv_vpn_win32_resource::recovery::{RecoveryEngine, RecoveryOutcome};

use crate::mutation_ingress::MutationIngress;

/// The composition's boot ownership version.
///
/// Any durable admission already in the journal belongs to a prior session: its
/// ownership version never equals the fresh helper's boot version, so a prior
/// token/digest is classified as stale history (架构 §7.5: prior token 永不授权)
/// rather than an actionable obligation.
const BOOT_OWNERSHIP_VERSION: u64 = 1;

/// Configuration the privileged helper composes over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposeConfig {
    /// The `Local\`-scoped authority mutex name (W13; one authority per name).
    pub authority_name: String,
    /// The durable journal directory (W14).
    pub journal_dir: PathBuf,
}

/// Typed failure of [`compose_privileged_helper`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposeError {
    /// A second helper instance holds the authority (WAIT_TIMEOUT); the loser
    /// exits before any scan/observe/publish (WSP2 §1).
    AuthorityBusy,
    /// The authority mutex could not be created or acquired (W13).
    Authority(NativeError),
    /// The durable journal could not be opened or read (W14).
    Journal(NativeError),
    /// Startup recovery cannot complete: the projection is corrupt at `offset`
    /// (WSP2 §4: corrupt middle 不跳过) — the endpoint must NOT be published.
    RecoveryCorrupt { offset: usize },
    /// Startup recovery failed with a native error (W25).
    Recovery(NativeError),
}

/// The startup phase record of a helper composition (the W26 order-mutant seam).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositionPhase {
    /// The exclusive mutation authority was acquired — before any journal/native
    /// scan (架构 §5.1: 先 lock 后 scan).
    AuthorityAcquired,
    /// Startup recovery over the durable journal returned an outcome (W25).
    RecoveryCompleted,
    /// The endpoint was published — the last composition step.
    EndpointPublished,
}

/// The composed privileged helper: the published endpoint surface.
///
/// Held for the helper's whole lifetime; [`crate::shutdown::shutdown_composition`]
/// consumes it for the orderly teardown. The W25 recovery engine is the W13
/// authority holder — the helper's exclusive mutation authority lives exactly as
/// long as this composition.
pub struct HelperComposition {
    /// The startup phase record (authority -> recovery -> endpoint).
    phases: Vec<CompositionPhase>,
    /// The helper's ONLY mutation surface (W15 sync-before-reply ingress).
    ingress: MutationIngress,
    /// The native workers this helper started; shutdown joins exactly these.
    native_workers: usize,
    /// The durable projection digest rebuilt at compose time (restart-rebuild
    /// contract: 同一 projection 重复计算必须稳定).
    projection_digest: [u8; 32],
    /// The recovery engine holding the singleton authority (released at shutdown).
    pub(crate) recovery: RecoveryEngine,
}

impl std::fmt::Debug for HelperComposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `RecoveryEngine` carries no `Debug` (W25 同款) — surface the startup
        // record, the worker count and the durable projection digest only.
        f.debug_struct("HelperComposition")
            .field("phases", &self.phases)
            .field("native_workers", &self.native_workers)
            .field("projection_digest", &self.projection_digest)
            .finish_non_exhaustive()
    }
}

impl HelperComposition {
    /// The startup order recorded by compose: authority acquired, recovery
    /// completed, endpoint published — in that exact order (W26 order mutant).
    #[must_use]
    pub fn phases(&self) -> &[CompositionPhase] {
        &self.phases
    }

    /// The helper's ONLY mutation surface: an ordinary user's mutation RPC is
    /// refused until a durable J51 admission opens the gate (W15).
    pub fn ingress(&mut self) -> &mut MutationIngress {
        &mut self.ingress
    }

    /// The number of native workers this helper started.
    ///
    /// This pure composition starts no real Wintun workers (zero); the W28
    /// vertical slice adds them, and shutdown must join exactly this many.
    #[must_use]
    pub const fn native_workers(&self) -> usize {
        self.native_workers
    }

    /// The durable projection digest rebuilt at compose time from the journal.
    #[must_use]
    pub const fn projection_digest(&self) -> [u8; 32] {
        self.projection_digest
    }

    /// Join every native worker this helper started (W17/W24 join-before-final).
    ///
    /// The single seam through which shutdown joins workers: with real workers it
    /// joins exactly `native_workers`; in this pure composition phase that count
    /// is zero, so nothing is left behind and no worker is detached.
    #[must_use]
    pub(crate) const fn join_workers(&mut self) -> usize {
        self.native_workers
    }
}

/// Compose the privileged helper process (the W26-T frozen seam).
///
/// The startup order is the W26 killer-mutant seam: the exclusive mutation
/// authority is acquired FIRST (架构 §5.1: 先 lock 后 scan), startup recovery runs
/// SECOND under the authority, and the endpoint is published LAST. A failed
/// composition releases the acquired authority before returning — no state is
/// left behind (the recovery engine drops with its authority handle).
///
/// # Errors
///
/// Returns [`ComposeError::AuthorityBusy`] when a second helper instance holds
/// the authority (the loser exits before any scan/observe/publish);
/// [`ComposeError::Authority`] / [`ComposeError::Journal`] /
/// [`ComposeError::Recovery`] for typed native failures; and
/// [`ComposeError::RecoveryCorrupt`] when the durable projection is corrupt at
/// `offset` — the endpoint must not be published over a corrupt journal
/// (WSP2 §4: corrupt middle 不跳过).
pub fn compose_privileged_helper(
    config: ComposeConfig,
) -> Result<HelperComposition, ComposeError> {
    let mut phases = Vec::with_capacity(3);

    // 1. Acquire the exclusive mutation authority BEFORE any journal/native scan
    //    (架构 §5.1: 先 lock 后 scan; WSP2 §1: WAIT_TIMEOUT loser 直接退出，不
    //    scan/observe/publish). WAIT_ABANDONED_0 (前任 owner 死亡) 接管后与
    //    WAIT_OBJECT_0 一样持有 authority（WSP2 §1）。
    let authority =
        SingletonAuthority::new(&config.authority_name).map_err(ComposeError::Authority)?;
    match authority.try_acquire().map_err(ComposeError::Authority)? {
        AuthorityAcquire::Acquired | AuthorityAcquire::AbandonedTakenOver => {}
        AuthorityAcquire::Busy => return Err(ComposeError::AuthorityBusy),
    }
    phases.push(CompositionPhase::AuthorityAcquired);

    // 2. Startup recovery over the durable journal under the authority (W25).
    //    completed = recover() 返回了 outcome；只有 corrupt / native failure 阻止
    //    endpoint publication。
    let mut engine = RecoveryEngine::new(JournalPath::from_dir(config.journal_dir.clone()), authority);
    let observed: &[ObservedResource] = &[];
    let outcome = engine
        .recover(boot_ownership_version(), observed)
        .map_err(ComposeError::Recovery)?;
    let projection_digest = match outcome {
        RecoveryOutcome::Corrupt { offset } => {
            // WSP2 §4: corrupt middle 不跳过；endpoint 不得发布。engine 在此 return
            // 时 drop，其持有的 authority 一并释放——失败 compose 不留状态。
            return Err(ComposeError::RecoveryCorrupt { offset });
        }
        RecoveryOutcome::ProvenClean { projection_digest }
        | RecoveryOutcome::Pending { projection_digest, .. } => projection_digest,
        // recover() 返回了 outcome（启动恢复完成），但 ObservationFailed 不带
        // digest：直接从同一 durable journal 投影计算（restart-rebuild 契约不变）。
        RecoveryOutcome::ObservationFailed { .. } => projection_digest_of(&config.journal_dir)?,
    };
    phases.push(CompositionPhase::RecoveryCompleted);

    // 3. Publish the endpoint LAST (endpoint 先发布 mutant 死于此): the composition
    //    value is the published surface — its ingress is the only mutation entry.
    phases.push(CompositionPhase::EndpointPublished);

    Ok(HelperComposition {
        phases,
        ingress: MutationIngress::new(),
        native_workers: 0,
        projection_digest,
        recovery: engine,
    })
}

/// The composition's boot ownership version (see [`BOOT_OWNERSHIP_VERSION`]).
#[must_use]
fn boot_ownership_version() -> OwnershipVersion {
    OwnershipVersion::try_from(BOOT_OWNERSHIP_VERSION).expect("boot ownership version mints")
}

/// Re-project the durable journal for its projection digest.
///
/// Only reachable when the W25 engine returned `ObservationFailed` — an outcome
/// that completes startup recovery but carries no digest. The engine already
/// projected the same journal under this process's authority (the journal is
/// immutable during startup), so this supplementary projection can only yield
/// `Clean` / `TornTail`; a `Corrupt` here is a defensive typed error, never a
/// skipped projection.
fn projection_digest_of(journal_dir: &Path) -> Result<[u8; 32], ComposeError> {
    let projection = JournalProjection::new(&JournalPath::from_dir(journal_dir.to_path_buf()));
    let records = match projection.project().map_err(ComposeError::Journal)? {
        ProjectionOutcome::Clean(records) | ProjectionOutcome::TornTail { records } => records,
        ProjectionOutcome::Corrupt { offset } => {
            return Err(ComposeError::RecoveryCorrupt { offset });
        }
    };
    Ok(projection.projection_digest(&records))
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
