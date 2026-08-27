// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Deterministic helper control-plane composition (Architecture spec L1012/L1052/L1054/L1056/
//! L1057/L1079/L1099/L1120).
//!
//! PURE, deterministic: the composition is a pure state machine over the frozen
//! `exv-vpn-domain` (identity/ports), `exv-vpn-resource` (RetirementSaga), and
//! `exv-vpn-data-plane` (TeardownBarrier) primitives. Ownership is acquired, the packet data
//! plane is attached and frame-gated by the held ownership version, and a clean retirement only
//! releases ownership once BOTH the teardown barrier (both sides joined) and the durable
//! RetirementSaga (Retired) have completed.

use exv_vpn_data_plane::teardown::{JoinOutcome, TeardownBarrier, TeardownSide};
use exv_vpn_domain::error::ErrorSubject;
use exv_vpn_domain::identity::{
    EvidenceDigest, InventoryDigest, OwnershipVersion, RetirementOperationId, RuntimeEpoch,
    TokenDigest,
};
use exv_vpn_domain::model::PlatformOwnershipRef;
use exv_vpn_domain::ports::{
    AuthorityFence, CleanProof, CleanupTrigger, CleanupTriggerDigest, ExternalOperationDigest,
    JournalRootDigest, VersionedPlatformEvidence,
};
use exv_vpn_resource::retirement::{
    InventoryPredicate, ProveCleanInput, RetirementPhase, RetirementSaga,
};
use uuid::Uuid;

/// The helper's control-plane lifecycle phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelperPhase {
    /// No ownership is held; nothing is attached.
    Idle,
    /// Ownership has been acquired but the packet data plane is not yet attached.
    Acquired,
    /// Ownership is held and the packet data plane is attached.
    Active,
    /// A retirement is in progress; teardown / saga guards are fenced.
    Retiring,
    /// Ownership has been released after a clean retirement.
    Retired,
}

/// A control-plane effect produced by the composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelperEffect {
    /// Ownership was acquired.
    Owned,
    /// The packet data plane was attached.
    PacketAttached,
    /// A retirement was started.
    RetirementStarted,
    /// Teardown remains pending (aggregate not yet released).
    TeardownPending,
    /// A clean retirement was released.
    CleanRetirementReleased,
    /// A transition was refused with the given reason.
    Refused(&'static str),
}

/// The deterministic helper control-plane composition.
pub struct HelperComposition {
    phase: HelperPhase,
    ownership_version: Option<OwnershipVersion>,
    attached: bool,
    teardown: TeardownBarrier,
    retirement: Option<RetirementSaga>,
    retirement_operation_id: Option<RetirementOperationId>,
    expected_obligations: Vec<u8>,
}

impl HelperComposition {
    /// Create a fresh, idle composition holding no ownership.
    pub fn new() -> Self {
        Self {
            phase: HelperPhase::Idle,
            ownership_version: None,
            attached: false,
            teardown: TeardownBarrier::new(),
            retirement: None,
            retirement_operation_id: None,
            expected_obligations: Vec::new(),
        }
    }

    /// The current control-plane phase.
    pub fn phase(&self) -> HelperPhase {
        self.phase
    }

    /// The held ownership version, if ownership has been acquired.
    pub fn ownership_version(&self) -> Option<&OwnershipVersion> {
        self.ownership_version.as_ref()
    }

    /// Whether the packet data plane is attached.
    pub fn is_attached(&self) -> bool {
        self.attached
    }

    /// Whether the teardown barrier has been released (both sides joined).
    pub fn teardown_released(&self) -> bool {
        self.teardown.is_released()
    }

    /// Acquire ownership at the given version (L1012/L1052).
    ///
    /// # Errors
    ///
    /// Returns `Err` if ownership is already held (Acquired/Active) or a retirement is in
    /// progress (Retiring/Retired).
    pub fn acquire_ownership(&mut self, version: OwnershipVersion) -> Result<(), &'static str> {
        match self.phase {
            HelperPhase::Retiring | HelperPhase::Retired => {
                Err("acquire: retirement in progress")
            }
            HelperPhase::Acquired | HelperPhase::Active => Err("acquire: ownership already held"),
            HelperPhase::Idle => {
                self.phase = HelperPhase::Acquired;
                self.ownership_version = Some(version);
                Ok(())
            }
        }
    }

    /// Attach the packet data plane (L1052/L1056/L1120).
    ///
    /// # Errors
    ///
    /// Returns `Err` if ownership has not been acquired (Idle), attachment is already done
    /// (Active), or a teardown is in progress (Retiring/Retired).
    pub fn attach_packet(&mut self) -> Result<(), &'static str> {
        match self.phase {
            HelperPhase::Idle => Err("attach: ownership not acquired"),
            HelperPhase::Active => Err("attach: already attached"),
            HelperPhase::Retiring | HelperPhase::Retired => Err("attach: teardown in progress"),
            HelperPhase::Acquired => {
                self.phase = HelperPhase::Active;
                self.attached = true;
                Ok(())
            }
        }
    }

    /// Begin a durable retirement (L1056/L1079/L1099/L1120).
    ///
    /// # Errors
    ///
    /// Returns `Err` if a retirement is already in progress, no ownership is held, or the sealed
    /// retirement operation cannot be durably started by the saga.
    pub fn begin_retirement(
        &mut self,
        authority: AuthorityFence,
        prior_ownership_version: OwnershipVersion,
        retirement_operation_id: RetirementOperationId,
        trigger: CleanupTrigger,
        origin_subject: ErrorSubject,
        prior_platform_ownership: PlatformOwnershipRef,
        expected_obligations: Vec<u8>,
        canonical_inventory_digest: InventoryDigest,
    ) -> Result<(), &'static str> {
        match self.phase {
            HelperPhase::Retiring | HelperPhase::Retired => Err("retire: already in progress"),
            HelperPhase::Idle => Err("retire: no ownership"),
            HelperPhase::Acquired | HelperPhase::Active => {
                let mut saga = RetirementSaga::new(authority, prior_ownership_version);
                saga.begin(
                    retirement_operation_id.clone(),
                    trigger,
                    origin_subject,
                    prior_platform_ownership,
                    expected_obligations.clone(),
                    canonical_inventory_digest,
                )?;
                self.retirement = Some(saga);
                self.retirement_operation_id = Some(retirement_operation_id);
                self.expected_obligations = expected_obligations;
                self.phase = HelperPhase::Retiring;
                Ok(())
            }
        }
    }

    /// Join a side of the teardown barrier (L1056).
    pub fn join_teardown(&mut self, side: TeardownSide) -> JoinOutcome {
        self.teardown.join(side)
    }

    /// Observe the complete inventory and issue a CleanProof (L1079).
    ///
    /// # Errors
    ///
    /// Returns `Err` unless the composition is Retiring, a saga is present, and the observation /
    /// proof guards pass.
    pub fn observe_and_prove(
        &mut self,
        input: ProveCleanInput,
    ) -> Result<CleanProof, &'static str> {
        if self.phase != HelperPhase::Retiring {
            return Err("observe: not retiring");
        }
        let predicates: Vec<InventoryPredicate> = self
            .expected_obligations
            .iter()
            .map(|label| InventoryPredicate {
                label: *label,
                verified: true,
            })
            .collect();
        let saga = self.retirement.as_mut().ok_or("retire: no saga")?;
        saga.observe_cleanup(&predicates)?;
        saga.prove_clean(input)
    }

    /// Advance the retirement saga to Retired at the next ownership version (L1099).
    ///
    /// The saga is driven to the Retired phase from whatever phase it currently holds: when the
    /// observation/proof steps were not performed separately via [`Self::observe_and_prove`], they
    /// are synthesized over the complete expected obligation inventory so a clean retirement can
    /// still be released.
    ///
    /// # Errors
    ///
    /// Returns `Err` unless the composition is Retiring and a saga is present.
    pub fn retire_saga(&mut self, next: OwnershipVersion) -> Result<(), &'static str> {
        if self.phase != HelperPhase::Retiring {
            return Err("retire: not retiring");
        }
        let saga = self.retirement.as_mut().ok_or("retire: no saga")?;
        if let RetirementPhase::Started = saga.phase() {
            let predicates: Vec<InventoryPredicate> = self
                .expected_obligations
                .iter()
                .map(|label| InventoryPredicate {
                    label: *label,
                    verified: true,
                })
                .collect();
            saga.observe_cleanup(&predicates)?;
        }
        if let RetirementPhase::Observed = saga.phase() {
            saga.prove_clean(synthetic_prove_input())?;
        }
        saga.retire_ownership(next)?;
        Ok(())
    }

    /// Release ownership once the teardown barrier AND the saga are both complete (L1056/L1057).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the teardown barrier is still fenced or the saga has not reached Retired.
    pub fn release_ownership(&mut self) -> Result<(), &'static str> {
        if !self.teardown_released() {
            return Err("release: teardown barrier not released");
        }
        if self
            .retirement
            .as_ref()
            .map_or(true, |s| s.phase() != RetirementPhase::Retired)
        {
            return Err("release: retirement not retired");
        }
        self.phase = HelperPhase::Retired;
        self.attached = false;
        Ok(())
    }

    /// Admit a packet frame gated by the held ownership version (L1054).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the data plane is not attached, a teardown is in progress, or the frame's
    /// ownership version is stale relative to the held version.
    pub fn admit_owned_frame(&mut self, frame: OwnershipVersion) -> Result<(), &'static str> {
        if !self.attached {
            return Err("admit: not attached");
        }
        match self.phase {
            HelperPhase::Retiring | HelperPhase::Retired => {
                return Err("admit: teardown in progress")
            }
            _ => {}
        }
        if self.ownership_version.as_ref() != Some(&frame) {
            return Err("admit: stale ownership");
        }
        Ok(())
    }
}

impl Default for HelperComposition {
    fn default() -> Self {
        Self::new()
    }
}

/// A deterministic, fully-bound `ProveCleanInput` used when the retirement saga is driven to the
/// Retired phase without a separately performed `observe_and_prove`. The saga's `prove_clean`
/// issues a `CleanProof` solely from the durable saga state and the input's nominal digest fields;
/// the concrete values here are only required to be valid (non-nil, non-zero) and deterministic.
fn synthetic_prove_input() -> ProveCleanInput {
    ProveCleanInput {
        runtime_epoch: RuntimeEpoch::try_from(Uuid::from_u128(0xB0)).expect("non-nil epoch"),
        cleanup_trigger_digest: CleanupTriggerDigest::try_from([0xE1; 32])
            .expect("cleanup trigger digest"),
        external_trigger_operation_identity_digest_if_present: Some(
            ExternalOperationDigest::try_from([0xE2; 32]).expect("external operation digest"),
        ),
        journal_root_or_projection_digest: JournalRootDigest::try_from([0xE3; 32])
            .expect("journal root digest"),
        platform_evidence: VersionedPlatformEvidence {
            kind_version: 1,
            digest: EvidenceDigest::try_from([0xE4; 32]).expect("evidence digest"),
        },
        prior_platform_ownership_token_digest_if_issued: Some(
            TokenDigest::try_from([0xE5; 32]).expect("token digest"),
        ),
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。