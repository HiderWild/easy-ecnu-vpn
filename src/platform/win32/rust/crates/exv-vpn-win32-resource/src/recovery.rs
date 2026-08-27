// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Startup recovery over the durable journal + native observation (W25-I).
//!
//! Architecture §5.1: the platform resource owner acquires the exclusive
//! mutation authority BEFORE scanning the journal or the native state (W13
//! order: lock first, then scan) — the engine holds the [`SingletonAuthority`]
//! until recovery completes. §7.4 crash rules: a torn/incomplete admission is
//! not an admission; a corrupt middle journal is `Corrupt` — never skipped, no
//! proof; a durable `MutationAdmitted` with no terminal outcome is observed
//! first, never replayed. §7.5: destructive cleanup is granted only by a
//! durable `RecoveryAuthority(RetirementOperationId)` — a prior token or its
//! digest never authorizes — and a same-name resource whose fingerprint
//! diverges is a typed skip, never deleted by name.
//!
//! The engine composes the committed leaf pieces — W14 projection
//! ([`crate::journal_projection`] over the W14 store) and the J51 admission
//! codec — without re-implementing them, and never executes or replays an
//! apply.

use exv_vpn_domain::identity::{OwnershipVersion, ResourceIdentityDigest};
use exv_vpn_resource::admission::{
    decode_record, AdmissionRecord, AppliedFingerprint, AuthorizationSubject, MutationAdmitted,
};

use crate::authority::SingletonAuthority;
use crate::journal_path::JournalPath;
use crate::journal_projection::{JournalProjection, ProjectionOutcome};
use crate::native_error::NativeError;
use crate::native_observation::{NativeObservation, ObservedFingerprint, ObservedResource};

/// The per-obligation recovery decision (架构 §7.5 mirror of `CleanupOutcome`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// A durable admission with no terminal outcome and a live-token subject:
    /// the native effect may already have happened — observe and reconcile,
    /// never replay the apply.
    EffectUnknown {
        /// The native observation carried into the decision (observe before
        /// action).
        observed_fingerprint: ObservedFingerprint,
    },
    /// The fingerprint matches and the admission is a durable
    /// `RecoveryAuthority(id)`: destructive cleanup is granted by the durable
    /// retirement identity, never by a token digest.
    CleanOwned {
        /// The native observation carried into the decision.
        observed_fingerprint: ObservedFingerprint,
    },
    /// A same-identity resource whose observed fingerprint diverges is NOT
    /// owned by this session: typed skip, never delete by name.
    DivergedNotOwned {
        /// The native observation carried into the decision.
        observed_fingerprint: ObservedFingerprint,
    },
    /// A prior-ownership admission is history only: the prior token (or its
    /// digest) never authorizes.
    PriorOwnershipStale {
        /// The native observation carried into the decision.
        observed_fingerprint: ObservedFingerprint,
    },
}

/// The recovery decision for one durable admission, in projection order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationRecovery {
    /// The canonical obligation tag (`inventory::InventoryItem as u8`) of the
    /// observed resource that matches the admission's resource identity.
    pub obligation: u8,
    /// The durable desired applied fingerprint of the admission.
    pub applied_fingerprint: AppliedFingerprint,
    /// The native observation carried into the decision (observe before
    /// action).
    pub observed_fingerprint: ObservedFingerprint,
    /// The classification of the admission.
    pub action: RecoveryAction,
}

/// The outcome of a recovery pass (架构 §7.5 `CleanupOutcome` mirror).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// No un-retired intent: nothing to act on. Only reachable after the
    /// projection and the native observation were considered — never claimed
    /// without observation when an un-retired obligation exists.
    ProvenClean {
        /// The durable projection digest (`journal_root_or_projection_digest`).
        projection_digest: [u8; 32],
    },
    /// Every un-retired admission was classified.
    Pending {
        /// The per-admission decisions, in projection order.
        obligations: Vec<ObligationRecovery>,
        /// The durable projection digest (`journal_root_or_projection_digest`).
        projection_digest: [u8; 32],
    },
    /// An admission's obligation has no observed fact: never guess.
    ObservationFailed {
        /// The obligation tag the admission maps to (the observed facts are
        /// empty, so no identity join is possible; the zero tag is the
        /// deterministic fallback).
        obligation: u8,
    },
    /// The journal is corrupt at `offset`: no skip forward, no proof.
    Corrupt { offset: usize },
}

/// The startup recovery engine (架构 §5.1 step 1: exclusive mutation authority
/// BEFORE journal/native scan).
pub struct RecoveryEngine {
    projection: JournalProjection,
    /// The exclusive mutation authority, held until recovery completes.
    _authority: SingletonAuthority,
}

impl RecoveryEngine {
    /// Build a recovery engine over `journal` under the exclusive mutation
    /// authority.
    ///
    /// The type-level seam enforces that recovery runs only with a
    /// [`SingletonAuthority`] value in hand (W13 order: lock first, then
    /// scan); the engine holds the authority until it is dropped.
    #[must_use]
    pub fn new(journal: JournalPath, authority: SingletonAuthority) -> Self {
        Self {
            projection: JournalProjection::from_dir(journal),
            _authority: authority,
        }
    }

    /// Recover: project the journal, then classify every un-retired admission
    /// against the mandatory native observation (`observed` must be provided
    /// before any action; the engine never executes or replays an apply).
    ///
    /// The classification ladder, in order:
    /// 1. a corrupt projection -> [`RecoveryOutcome::Corrupt`] (no skip, no
    ///    proof);
    /// 2. no un-retired intent -> [`RecoveryOutcome::ProvenClean`];
    /// 3. per admission (a torn tail frame is not an admission and never
    ///    enters the decision):
    /// 4. `ownership_version != current` -> `PriorOwnershipStale` (prior
    ///    token/digest never authorizes);
    /// 5. no observed fact for the obligation -> `ObservationFailed` (never
    ///    guess);
    /// 6. observed fingerprint != desired applied fingerprint ->
    ///    `DivergedNotOwned` (same name never deletes);
    /// 7. fingerprint matches and the admission is a durable
    ///    `RecoveryAuthority(id)` -> `CleanOwned` (cleanup granted only by the
    ///    durable retirement identity);
    /// 8. otherwise (durable admission, no terminal outcome, live-token
    ///    subject) -> `EffectUnknown` (observe and reconcile, never replay
    ///    apply);
    /// 9. all un-retired obligations classified -> [`RecoveryOutcome::Pending`].
    ///
    /// # Errors
    ///
    /// Returns a typed [`NativeError`] when the journal cannot be opened, read
    /// or projected.
    pub fn recover(
        &mut self,
        current_ownership_version: OwnershipVersion,
        observed: &[ObservedResource],
    ) -> Result<RecoveryOutcome, NativeError> {
        let records = match self.projection.project()? {
            ProjectionOutcome::Corrupt { offset } => return Ok(RecoveryOutcome::Corrupt { offset }),
            ProjectionOutcome::Clean(records) | ProjectionOutcome::TornTail { records } => records,
        };
        let projection_digest = self.projection.projection_digest(&records);

        let observation = NativeObservation::new();
        let mut obligations = Vec::new();
        for record in &records {
            let Some(admitted) = decode_admission(&record.payload) else {
                continue;
            };
            let matched: Vec<ObservedResource> = observed
                .iter()
                .filter(|fact| observes(&admitted, fact))
                .cloned()
                .collect();
            let obligation = match matched.first() {
                Some(fact) => fact.obligation,
                None => 0,
            };
            let observed_fingerprint = observation.fingerprint(&matched);
            let action = if admitted.ownership_version != current_ownership_version {
                // (a) Prior ownership is history only.
                RecoveryAction::PriorOwnershipStale {
                    observed_fingerprint: observed_fingerprint.clone(),
                }
            } else if matched.is_empty() {
                // (b) Never guess an unobserved obligation.
                return Ok(RecoveryOutcome::ObservationFailed { obligation });
            } else if !observation.matches(&observed_fingerprint, &admitted.desired_applied_fingerprint)
            {
                // (c) Same name is not ownership.
                RecoveryAction::DivergedNotOwned {
                    observed_fingerprint: observed_fingerprint.clone(),
                }
            } else {
                // (d)/(e) The fingerprint matches the durable intent.
                match &admitted.authorization_subject {
                    AuthorizationSubject::RecoveryAuthority(_) => RecoveryAction::CleanOwned {
                        observed_fingerprint: observed_fingerprint.clone(),
                    },
                    AuthorizationSubject::LiveOwnershipTokenDigest(_) => RecoveryAction::EffectUnknown {
                        observed_fingerprint: observed_fingerprint.clone(),
                    },
                }
            };
            obligations.push(ObligationRecovery {
                obligation,
                applied_fingerprint: admitted.desired_applied_fingerprint.clone(),
                observed_fingerprint,
                action,
            });
        }

        if obligations.is_empty() {
            Ok(RecoveryOutcome::ProvenClean { projection_digest })
        } else {
            Ok(RecoveryOutcome::Pending {
                obligations,
                projection_digest,
            })
        }
    }
}

/// Decode a journal payload into a durable `MutationAdmitted`.
///
/// A torn tail frame is excluded by the projection; `Rejected` /
/// `AbsentFence` are terminal records — neither is an un-retired intent, so
/// neither enters the recovery decision.
fn decode_admission(payload: &[u8]) -> Option<MutationAdmitted> {
    match decode_record(payload) {
        Ok(AdmissionRecord::Admitted(admitted)) => Some(admitted),
        Ok(_) | Err(_) => None,
    }
}

/// Whether `fact` observes the same platform resource identity as the
/// admission.
///
/// Both sides are 32-byte digests; the opaque `ResourceIdentityDigest` is
/// compared through its committed construction seam and derived equality —
/// composition, never reimplementation.
fn observes(admitted: &MutationAdmitted, fact: &ObservedResource) -> bool {
    ResourceIdentityDigest::try_from(fact.identity_digest)
        .is_ok_and(|observed_identity| observed_identity == admitted.resource_identity)
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
