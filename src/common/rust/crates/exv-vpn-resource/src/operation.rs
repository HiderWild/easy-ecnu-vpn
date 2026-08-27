// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Single-write admission sequencer (Architecture spec §7.2).
//!
//! `AdmissionIndex` is the durable, in-memory admission sequencer. Every admission, rejection, and
//! absence fence mints a watermark from ONE shared monotonic sequencer, so the durable record is a
//! total order over the authority's lifetime. Idempotent re-submissions of the same key+digest
//! reuse the original record and watermark; same-key different-digest submissions conflict.

use std::collections::HashMap;

use exv_vpn_domain::identity::{
    canonical_lookup_digest, EffectId, OperationLookupKey, OperationLookupKeyDigest,
    PrincipalDigest, RequestDigest, ResourceIdentityDigest, OwnershipVersion,
};
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CanonicalInputDigest,
    JournalOperationIdentity, OperationState, PlatformAuthorityInstanceId, RejectionReason,
};

use crate::admission::{
    AppliedFingerprint, AuthorizationSubject, MutationAdmitted, MutationKind, ObligationSeed,
    OperationAbsentFence, OperationRejected,
};

/// The input to a single admission decision.
#[derive(Clone)]
pub struct MutationAdmissionInput {
    pub key: OperationLookupKey,
    pub request_digest: RequestDigest,
    pub effect_id: EffectId,
    pub initiator_identity_digest: PrincipalDigest,
    pub canonical_input_digest: CanonicalInputDigest,
    pub mutation_kind: MutationKind,
    pub ownership_version: OwnershipVersion,
    pub authorization_subject: AuthorizationSubject,
    pub resource_identity: ResourceIdentityDigest,
    pub precondition_fingerprint: AppliedFingerprint,
    pub desired_applied_fingerprint: AppliedFingerprint,
    pub canonical_obligation_seed: ObligationSeed,
}

/// The outcome of an admission decision.
#[derive(Clone, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// The mutation was admitted and sealed as a single durable record.
    Admitted { record: MutationAdmitted },
    /// The mutation collided with a prior durable rejection of the same key+digest.
    RejectedNoEffect { record: OperationRejected },
    /// The mutation was closed by a prior absence fence on the same key+digest.
    ClosedByAbsenceProof,
    /// The same lookup key was already resolved with a different request digest.
    IdempotencyConflict,
}

/// A single durable entry keyed by the canonical lookup digest.
enum IndexEntry {
    Admitted {
        request_digest: RequestDigest,
        record: MutationAdmitted,
    },
    Rejected {
        request_digest: RequestDigest,
        record: OperationRejected,
    },
    AbsentFenced {
        request_digest: RequestDigest,
        record: OperationAbsentFence,
    },
}

/// The single-write admission sequencer.
pub struct AdmissionIndex {
    authority_epoch: AuthorityEpoch,
    authority_instance: PlatformAuthorityInstanceId,
    next_watermark: u64,
    entries: HashMap<OperationLookupKeyDigest, IndexEntry>,
}

impl AdmissionIndex {
    /// Build an empty sequencer under the given authority fence.
    #[must_use]
    pub fn new(authority: AuthorityFence) -> Self {
        let AuthorityFence {
            authority_epoch,
            platform_authority_instance_id,
            ..
        } = authority;
        Self {
            authority_epoch,
            authority_instance: platform_authority_instance_id,
            next_watermark: 0,
            entries: HashMap::new(),
        }
    }

    /// Mint the next watermark from the shared monotonic sequencer.
    fn mint_watermark(&mut self) -> AdmissionWatermark {
        let watermark = AdmissionWatermark::try_from(self.next_watermark).expect("watermark mints");
        self.next_watermark += 1;
        watermark
    }

    /// Submit a mutation for admission.
    #[must_use]
    pub fn admit(&mut self, input: MutationAdmissionInput) -> AdmissionOutcome {
        let digest = canonical_lookup_digest(&input.key);
        if let Some(entry) = self.entries.get(&digest) {
            return match entry {
                IndexEntry::Admitted {
                    request_digest,
                    record,
                } => {
                    if *request_digest == input.request_digest {
                        AdmissionOutcome::Admitted {
                            record: record.clone(),
                        }
                    } else {
                        AdmissionOutcome::IdempotencyConflict
                    }
                }
                IndexEntry::Rejected {
                    request_digest,
                    record,
                } => {
                    if *request_digest == input.request_digest {
                        AdmissionOutcome::RejectedNoEffect {
                            record: record.clone(),
                        }
                    } else {
                        AdmissionOutcome::IdempotencyConflict
                    }
                }
                IndexEntry::AbsentFenced { request_digest, .. } => {
                    if *request_digest == input.request_digest {
                        AdmissionOutcome::ClosedByAbsenceProof
                    } else {
                        AdmissionOutcome::IdempotencyConflict
                    }
                }
            };
        }

        let watermark = self.mint_watermark();
        let record = MutationAdmitted {
            mutation_kind: input.mutation_kind,
            journal_operation_identity: JournalOperationIdentity::External(input.key.clone()),
            effect_id: input.effect_id,
            canonical_input_digest: input.canonical_input_digest,
            initiator_identity_digest: input.initiator_identity_digest,
            authority_epoch: self.authority_epoch,
            platform_authority_instance_id: self.authority_instance.clone(),
            admission_watermark: watermark,
            ownership_version: input.ownership_version,
            authorization_subject: input.authorization_subject,
            resource_identity: input.resource_identity,
            precondition_fingerprint: input.precondition_fingerprint,
            desired_applied_fingerprint: input.desired_applied_fingerprint,
            canonical_obligation_seed: input.canonical_obligation_seed,
        };
        self.entries.insert(
            digest,
            IndexEntry::Admitted {
                request_digest: input.request_digest,
                record: record.clone(),
            },
        );
        AdmissionOutcome::Admitted { record }
    }

    /// Record a durable no-effect rejection.
    #[must_use]
    pub fn reject(
        &mut self,
        key: &OperationLookupKey,
        request_digest: &RequestDigest,
        rejection_reason: RejectionReason,
    ) -> OperationRejected {
        let digest = canonical_lookup_digest(key);
        if let Some(IndexEntry::Rejected {
            request_digest: existing,
            record,
        }) = self.entries.get(&digest)
            && existing == request_digest
        {
            return record.clone();
        }

        let watermark = self.mint_watermark();
        let record = OperationRejected {
            lookup_key: key.clone(),
            request_digest: request_digest.clone(),
            authority_epoch: self.authority_epoch,
            rejection_reason,
            admission_watermark: watermark,
        };
        self.entries.insert(
            digest,
            IndexEntry::Rejected {
                request_digest: request_digest.clone(),
                record: record.clone(),
            },
        );
        record
    }

    /// Establish (or reuse) an absence fence over a key.
    ///
    /// Accepts the request digest either by reference or by value.
    #[must_use]
    pub fn establish_absence_fence(
        &mut self,
        key: &OperationLookupKey,
        request_digest: impl std::borrow::Borrow<RequestDigest>,
    ) -> OperationAbsentFence {
        let request_digest = request_digest.borrow();
        let digest = canonical_lookup_digest(key);
        if let Some(IndexEntry::AbsentFenced { record, .. }) = self.entries.get(&digest) {
            return record.clone();
        }

        let watermark = self.mint_watermark();
        let record = OperationAbsentFence {
            lookup_key: key.clone(),
            request_digest: request_digest.clone(),
            authority_epoch: self.authority_epoch,
            admission_watermark: watermark,
        };
        self.entries.insert(
            digest,
            IndexEntry::AbsentFenced {
                request_digest: request_digest.clone(),
                record: record.clone(),
            },
        );
        record
    }

    /// Read-only lookup of an operation's state. Never mints a watermark.
    #[must_use]
    pub fn get_operation(
        &self,
        key: &OperationLookupKey,
        _request_digest: &RequestDigest,
    ) -> OperationState {
        let digest = canonical_lookup_digest(key);
        match self.entries.get(&digest) {
            Some(IndexEntry::Admitted { .. }) => OperationState::Pending,
            Some(IndexEntry::Rejected { record, .. }) => OperationState::RejectedNoEffect {
                reason: record.rejection_reason.clone(),
            },
            Some(IndexEntry::AbsentFenced { record, .. }) => OperationState::AbsentNoEffect {
                lookup_key_digest: canonical_lookup_digest(key),
                authority_epoch: record.authority_epoch,
                admission_watermark: record.admission_watermark,
            },
            None => OperationState::Unknown,
        }
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。