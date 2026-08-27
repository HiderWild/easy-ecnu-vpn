// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Durable retirement lifecycle + scoped CleanProof saga (Architecture spec §7.5,
//! crash rules L1202-L1207).
//!
//! PURE, deterministic, no I/O. Durability is a surrogate: [`RetirementSaga::begin`] seals a
//! J51 `MutationAdmitted` (kind Retirement, `JournalOperationIdentity::Retirement`,
//! `AuthorizationSubject::RecoveryAuthority`) and round-trips it through the J51 codec,
//! requiring reproduction of the exact [`RetirementOperationId`]. The ordered phases
//! (Pending → Started → Observed → Proved → Retired) enforce the crash rules: destructive
//! cleanup is only grantable after the retirement is durably started for the exact internal
//! identity, a CleanProof is only issued against a complete re-verified inventory, and the next
//! ownership version only advances once ownership is durably retired.

use std::collections::HashSet;

use exv_vpn_domain::error::ErrorSubject;
use exv_vpn_domain::identity::{
    EffectId, InventoryDigest, OwnershipVersion, PrincipalDigest, ResourceIdentityDigest,
    RetirementOperationId, RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::model::PlatformOwnershipRef;
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CanonicalInputDigest, CleanProof,
    CleanupTrigger, CleanupTriggerDigest, ExternalOperationDigest, JournalRevision,
    JournalRootDigest, JournalOperationIdentity, OwnershipRetired, PlatformAuthorityInstanceId,
    VersionedPlatformEvidence,
};
use uuid::Uuid;

use crate::admission::{
    AdmissionRecord, AppliedFingerprint, AuthorizationSubject, MutationAdmitted, MutationKind,
    ObligationSeed, decode_record, encode_record,
};

/// The sagas's durable retirement phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetirementPhase {
    /// The retirement operation has not been durably started.
    Pending,
    /// The retirement operation has been sealed and cleanup may be granted.
    Started,
    /// The complete cleanup inventory has been observed and re-verified.
    Observed,
    /// A CleanProof has been issued over the complete inventory.
    Proved,
    /// Ownership has been durably retired at the next ownership version.
    Retired,
}

/// A single cleanup inventory predicate: an expected obligation label and whether it was
/// re-verified as clean.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InventoryPredicate {
    /// The obligation label from the canonical obligation inventory.
    pub label: u8,
    /// Whether this obligation was re-verified clean during observation.
    pub verified: bool,
}

/// The fully-bound inputs required to produce a CleanProof.
#[derive(Clone)]
pub struct ProveCleanInput {
    /// The runtime epoch being proved clean.
    pub runtime_epoch: RuntimeEpoch,
    /// The digest of the cleanup trigger that drove the retirement.
    pub cleanup_trigger_digest: CleanupTriggerDigest,
    /// The digests of any external-trigger operation identity present.
    pub external_trigger_operation_identity_digest_if_present: Option<ExternalOperationDigest>,
    /// The journal root (or projection) digest at proof time.
    pub journal_root_or_projection_digest: JournalRootDigest,
    /// The platform evidence gathered during cleanup.
    pub platform_evidence: VersionedPlatformEvidence,
    /// The prior platform ownership token digest, if one had been issued.
    pub prior_platform_ownership_token_digest_if_issued: Option<TokenDigest>,
}

/// Validate that a CleanProof carries no unresolved obligations.
///
/// # Errors
///
/// Returns `Err` iff `proof.unresolved_obligation_count != 0`.
pub fn validate_clean_proof(proof: &CleanProof) -> Result<(), &'static str> {
    if proof.unresolved_obligation_count != 0 {
        return Err("clean proof: unresolved obligation count must be zero");
    }
    Ok(())
}

/// The durable retirement lifecycle saga.
pub struct RetirementSaga {
    authority_epoch: AuthorityEpoch,
    authority_instance: PlatformAuthorityInstanceId,
    admission_watermark: AdmissionWatermark,
    journal_revision: JournalRevision,
    prior_ownership_version: OwnershipVersion,
    retirement_operation_id: Option<RetirementOperationId>,
    expected_obligations: Vec<u8>,
    canonical_inventory_digest: InventoryDigest,
    next_ownership_version: Option<OwnershipVersion>,
    phase: RetirementPhase,
}

impl RetirementSaga {
    /// Begin a retirement saga under the given authority fence and prior ownership version.
    pub fn new(authority: AuthorityFence, prior_ownership_version: OwnershipVersion) -> Self {
        Self {
            authority_epoch: authority.authority_epoch,
            authority_instance: authority.platform_authority_instance_id,
            admission_watermark: authority.admission_watermark,
            journal_revision: authority.journal_revision,
            prior_ownership_version,
            retirement_operation_id: None,
            expected_obligations: Vec::new(),
            canonical_inventory_digest: InventoryDigest::try_from([0u8; 32])
                .expect("zero digest is a valid inventory digest"),
            next_ownership_version: None,
            phase: RetirementPhase::Pending,
        }
    }

    /// Durably start the retirement: seal a J51 `MutationAdmitted` and round-trip it through the
    /// J51 codec, requiring reproduction of the exact retirement operation identity.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the retirement is already started, or if the sealed admission record
    /// cannot be reproduced with the exact journal identity and recovery-authority subject.
    ///
    /// The `trigger`, `origin_subject`, and `prior_platform_ownership` parameters are accepted for
    /// signature fidelity but are not serialized; the ordering invariants flow from the durable id
    /// round-trip.
    pub fn begin(
        &mut self,
        retirement_operation_id: RetirementOperationId,
        _trigger: CleanupTrigger,
        _origin_subject: ErrorSubject,
        _prior_platform_ownership: PlatformOwnershipRef,
        expected_obligations: Vec<u8>,
        canonical_inventory_digest: InventoryDigest,
    ) -> Result<(), &'static str> {
        if self.retirement_operation_id.is_some() {
            return Err("retirement: already started");
        }

        let admission = MutationAdmitted {
            mutation_kind: MutationKind::Retirement,
            journal_operation_identity: JournalOperationIdentity::Retirement(
                retirement_operation_id.clone(),
            ),
            effect_id: EffectId::try_from(Uuid::from_u128(0xF00D_0000_0000_0000))
                .expect("non-nil effect id"),
            canonical_input_digest: CanonicalInputDigest::try_from([0x11; 32])
                .expect("fixed canonical input digest"),
            initiator_identity_digest: PrincipalDigest::try_from([0x99; 32])
                .expect("fixed initiator identity digest"),
            authority_epoch: self.authority_epoch,
            platform_authority_instance_id: self.authority_instance.clone(),
            admission_watermark: self.admission_watermark,
            ownership_version: self.prior_ownership_version,
            authorization_subject: AuthorizationSubject::RecoveryAuthority(
                retirement_operation_id.clone(),
            ),
            resource_identity: ResourceIdentityDigest::try_from([0x77; 32])
                .expect("fixed resource identity digest"),
            precondition_fingerprint: AppliedFingerprint::try_from([0x44; 32])
                .expect("fixed precondition fingerprint"),
            desired_applied_fingerprint: AppliedFingerprint::try_from([0x55; 32])
                .expect("fixed desired applied fingerprint"),
            canonical_obligation_seed: ObligationSeed::try_from([0x66; 32])
                .expect("fixed canonical obligation seed"),
        };

        let sealed = encode_record(&AdmissionRecord::Admitted(admission));
        let recovered = match decode_record(&sealed) {
            Ok(AdmissionRecord::Admitted(rec)) => rec,
            _ => return Err("retirement: admission record round-trip failed"),
        };
        if recovered.journal_operation_identity
            != JournalOperationIdentity::Retirement(retirement_operation_id.clone())
        {
            return Err("retirement: journal operation identity not reproduced");
        }
        if recovered.authorization_subject
            != AuthorizationSubject::RecoveryAuthority(retirement_operation_id.clone())
        {
            return Err("retirement: recovery authority subject not reproduced");
        }

        self.retirement_operation_id = Some(retirement_operation_id);
        self.expected_obligations = expected_obligations;
        self.canonical_inventory_digest = canonical_inventory_digest;
        self.phase = RetirementPhase::Started;
        Ok(())
    }

    /// Grant destructive cleanup for the durable internal retirement identity.
    ///
    /// # Errors
    ///
    /// Returns `Err` unless the retirement is in the Started phase and `retirement_operation_id`
    /// matches the durable internal identity.
    pub fn grant_cleanup(
        &self,
        retirement_operation_id: &RetirementOperationId,
    ) -> Result<(), &'static str> {
        if self.phase != RetirementPhase::Started {
            return Err("retirement: cleanup not started");
        }
        if self.retirement_operation_id.as_ref() != Some(retirement_operation_id) {
            return Err("retirement: forged parallel retirement identity");
        }
        Ok(())
    }

    /// Observe and re-verify the complete cleanup inventory.
    ///
    /// # Errors
    ///
    /// Returns `Err` unless the retirement is in the Started phase and every predicate is verified
    /// against an expected obligation with the complete inventory observed.
    pub fn observe_cleanup(
        &mut self,
        observed: &[InventoryPredicate],
    ) -> Result<(), &'static str> {
        if self.phase != RetirementPhase::Started {
            return Err("retirement: cleanup not started");
        }
        let mut seen: HashSet<u8> = HashSet::new();
        for obs in observed {
            if !obs.verified {
                return Err("retirement: unverified inventory predicate");
            }
            if !self.expected_obligations.contains(&obs.label) {
                return Err("retirement: unexpected obligation label");
            }
            seen.insert(obs.label);
        }
        if seen.len() != self.expected_obligations.len() {
            return Err("retirement: incomplete inventory");
        }
        self.phase = RetirementPhase::Observed;
        Ok(())
    }

    /// Issue a CleanProof over the complete observed inventory.
    ///
    /// # Errors
    ///
    /// Returns `Err` unless the retirement is in the Observed phase.
    pub fn prove_clean(&mut self, input: ProveCleanInput) -> Result<CleanProof, &'static str> {
        if self.phase != RetirementPhase::Observed {
            return Err("retirement: cleanup not observed");
        }
        let id = self
            .retirement_operation_id
            .clone()
            .ok_or("retirement: no durable operation id")?;
        let proof = CleanProof {
            runtime_epoch: input.runtime_epoch,
            platform_authority_instance: self.authority_instance.clone(),
            prior_ownership_version: self.prior_ownership_version,
            prior_platform_ownership_token_digest_if_issued:
                input.prior_platform_ownership_token_digest_if_issued,
            retirement_operation_id: id,
            cleanup_trigger_digest: input.cleanup_trigger_digest,
            external_trigger_operation_identity_digest_if_present:
                input.external_trigger_operation_identity_digest_if_present,
            canonical_obligation_inventory_digest: self.canonical_inventory_digest.clone(),
            journal_root_or_projection_digest: input.journal_root_or_projection_digest,
            journal_revision: self.journal_revision,
            platform_evidence: input.platform_evidence,
            unresolved_obligation_count: 0,
        };
        validate_clean_proof(&proof)?;
        self.phase = RetirementPhase::Proved;
        Ok(proof)
    }

    /// Durably retire ownership at the next ownership version.
    ///
    /// # Errors
    ///
    /// Returns `Err` unless the retirement is in the Proved phase and ownership has not already
    /// been retired.
    pub fn retire_ownership(
        &mut self,
        next_ownership_version: OwnershipVersion,
    ) -> Result<OwnershipRetired, &'static str> {
        if self.phase != RetirementPhase::Proved {
            return Err("retirement: not proved");
        }
        if self.next_ownership_version.is_some() {
            return Err("retirement: ownership already retired");
        }
        self.next_ownership_version = Some(next_ownership_version);
        self.phase = RetirementPhase::Retired;
        Ok(OwnershipRetired {
            next_ownership_version,
        })
    }

    /// The current retirement phase.
    pub fn phase(&self) -> RetirementPhase {
        self.phase
    }

    /// The durable internal retirement operation identity, if started.
    pub fn retirement_operation_id(&self) -> Option<&RetirementOperationId> {
        self.retirement_operation_id.as_ref()
    }

    /// The next ownership version, once ownership has been durably retired.
    pub fn next_ownership_version(&self) -> Option<&OwnershipVersion> {
        self.next_ownership_version.as_ref()
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。