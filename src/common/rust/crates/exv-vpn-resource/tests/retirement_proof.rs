// RED tests for the durable retirement lifecycle + scoped CleanProof
// (Architecture spec §7.5, crash rules L1202-L1207, vpn-rust-native-runtime-mvp).
// PURE, deterministic: no I/O, no filesystem, no sleep, no randomness —
// identifiers and digests come only from Uuid::from_u128 and fixed byte literals.
//
// The retirement seam `exv_vpn_resource::retirement` is an empty stub; J53-I implements it.
// Until then this file FAILS TO COMPILE (unresolved imports) — that is the intended RED.

use exv_vpn_domain::error::ErrorSubject;
use exv_vpn_domain::identity::{
    EvidenceDigest, InventoryDigest, OperationId, OperationLookupKey, OperationMethod,
    OwnershipVersion, PrincipalDigest, RequestDigest, ResourceIdentityDigest,
    RetirementOperationId, RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::model::PlatformOwnershipRef;
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CleanProof, CleanupTrigger,
    CleanupTriggerDigest, ExternalOperationDigest, JournalRevision, JournalRootDigest,
    OwnershipRetired, PlatformAuthorityInstanceId, VersionedPlatformEvidence,
};
use exv_vpn_resource::retirement::{
    InventoryPredicate, ProveCleanInput, RetirementPhase, RetirementSaga, validate_clean_proof,
};
use uuid::Uuid;

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

/// Deterministic 32-byte digest whose first byte differs across `n` (non-nil).
fn digest32(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = n;
    b
}

/// Deterministic durable retirement id that differs across `n`.
fn retirement_id(n: u128) -> RetirementOperationId {
    RetirementOperationId::try_from(Uuid::from_u128(n)).expect("non-nil retirement id")
}

/// Deterministic runtime epoch across `n`.
fn runtime_epoch(n: u128) -> RuntimeEpoch {
    RuntimeEpoch::try_from(Uuid::from_u128(n)).expect("non-nil epoch")
}

/// Deterministic non-zero ownership version across `n`.
fn ownership_version(n: u64) -> OwnershipVersion {
    OwnershipVersion::try_from(n).expect("non-zero version")
}

/// Deterministic canonical inventory digest across `n`.
fn inventory_digest(n: u8) -> InventoryDigest {
    InventoryDigest::try_from(digest32(n)).expect("digest")
}

/// A deterministic platform ownership ref (non-nil identity digest).
fn platform_ownership() -> PlatformOwnershipRef {
    PlatformOwnershipRef::try_from((
        ResourceIdentityDigest::try_from(digest32(0x31)).expect("digest"),
        ownership_version(1),
        TokenDigest::try_from(digest32(0x32)).expect("digest"),
    ))
    .expect("ownership ref")
}

/// A deterministic external-stop cleanup trigger.
fn cleanup_trigger() -> CleanupTrigger {
    CleanupTrigger::ExternalStop {
        lookup_key: OperationLookupKey::try_from((
            PrincipalDigest::try_from(digest32(0x41)).expect("digest"),
            OperationMethod::Stop,
            runtime_epoch(1),
            OperationId::try_from(Uuid::from_u128(3)).expect("non-nil op"),
        ))
        .expect("key"),
        request_digest: RequestDigest::try_from(digest32(0x42)).expect("digest"),
    }
}

/// A deterministic origin subject (runtime epoch).
fn origin_subject() -> ErrorSubject {
    ErrorSubject::Runtime(runtime_epoch(1))
}

/// A canonical, fully-bound ProveCleanInput (all distinct nominal digest types).
fn prove_input() -> ProveCleanInput {
    ProveCleanInput {
        runtime_epoch: runtime_epoch(1),
        cleanup_trigger_digest: CleanupTriggerDigest::try_from(digest32(0x0a)).expect("digest"),
        external_trigger_operation_identity_digest_if_present: Some(
            ExternalOperationDigest::try_from(digest32(0x0b)).expect("digest"),
        ),
        journal_root_or_projection_digest: JournalRootDigest::try_from(digest32(0x0c))
            .expect("digest"),
        platform_evidence: VersionedPlatformEvidence {
            kind_version: 1,
            digest: EvidenceDigest::try_from(digest32(0x0d)).expect("digest"),
        },
        prior_platform_ownership_token_digest_if_issued: Some(
            TokenDigest::try_from(digest32(0x0e)).expect("digest"),
        ),
    }
}

/// Drive a fresh saga deterministically into the Started phase (single obligation #1).
fn to_started(saga: &mut RetirementSaga) {
    assert!(
        saga.begin(
            retirement_id(1),
            cleanup_trigger(),
            origin_subject(),
            platform_ownership(),
            vec![1],
            inventory_digest(1),
        )
        .is_ok(),
        "begin must seal the retirement operation and reach Started"
    );
}

/// Drive a fresh saga deterministically into the Observed phase (complete inventory).
fn to_observed(saga: &mut RetirementSaga) {
    to_started(saga);
    let id = retirement_id(1);
    assert!(saga.grant_cleanup(&id).is_ok(), "grant cleanup in Started");
    assert!(
        saga.observe_cleanup(&[InventoryPredicate { label: 1, verified: true }]).is_ok(),
        "observe complete inventory reaches Observed"
    );
}

/// Drive a fresh saga deterministically into the Proved phase and return the CleanProof.
fn to_proved(saga: &mut RetirementSaga) -> CleanProof {
    to_observed(saga);
    saga.prove_clean(prove_input()).expect("prove_clean in Observed")
}

/// Destructive cleanup must NOT be grantable while the retirement is still Pending
/// (crash rule L1202). Kills: "grants destructive cleanup while Pending".
#[test]
fn cleanup_not_granted_before_retirement_started_durable() {
    let saga = RetirementSaga::new(fence(), ownership_version(1));
    assert!(matches!(saga.phase(), RetirementPhase::Pending));
    assert!(
        saga.grant_cleanup(&retirement_id(1)).is_err(),
        "destructive cleanup must be refused before the retirement is durably started"
    );
}

/// Durable retirement must seal exactly one operation identity; a second begin is rejected
/// (crash rule L1206). Kills: "two parallel retirement identities".
#[test]
fn duplicate_begin_rejected() {
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    assert!(
        saga.begin(
            retirement_id(1),
            cleanup_trigger(),
            origin_subject(),
            platform_ownership(),
            vec![1],
            inventory_digest(1),
        )
        .is_ok()
    );
    assert!(
        saga.begin(
            retirement_id(2),
            cleanup_trigger(),
            origin_subject(),
            platform_ownership(),
            vec![1],
            inventory_digest(1),
        )
        .is_err(),
        "a second begin must be rejected"
    );
    assert!(matches!(saga.phase(), RetirementPhase::Started));
}

/// Destructive cleanup is only grantable for the durable internal id, never a forged/parallel
/// external identity (crash rule L1203). Kills: "reuses a forged/new external identity".
#[test]
fn forged_parallel_retirement_identity_rejected() {
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    let id1 = retirement_id(1);
    let id2 = retirement_id(2);
    assert!(saga.begin(id1.clone(), cleanup_trigger(), origin_subject(), platform_ownership(), vec![1], inventory_digest(1)).is_ok());
    assert!(saga.grant_cleanup(&id1).is_ok());
    assert!(
        saga.grant_cleanup(&id2).is_err(),
        "forged parallel identity must not grant destructive cleanup"
    );
}

/// A CleanProof must not be issued before cleanup has been observed. Kills: "issues CleanProof
/// before cleanup observation".
#[test]
fn prove_clean_before_observation_rejected() {
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    to_started(&mut saga);
    let id = retirement_id(1);
    assert!(saga.grant_cleanup(&id).is_ok());
    assert!(
        saga.prove_clean(prove_input()).is_err(),
        "prove_clean must be refused before observe_cleanup"
    );
    assert!(matches!(saga.phase(), RetirementPhase::Started));
}

/// A CleanProof must not be issued against an incomplete inventory (crash rule L1204): only one
/// of two expected obligations observed. Kills: "issues CleanProof without complete inventory /
/// re-verifying every predicate".
#[test]
fn incomplete_inventory_rejected() {
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    let id = retirement_id(1);
    assert!(saga.begin(id.clone(), cleanup_trigger(), origin_subject(), platform_ownership(), vec![1, 2], inventory_digest(1)).is_ok());
    assert!(saga.grant_cleanup(&id).is_ok());
    assert!(
        saga.observe_cleanup(&[InventoryPredicate { label: 1, verified: true }]).is_err(),
        "partial inventory must not be accepted as complete"
    );
    assert!(!matches!(saga.phase(), RetirementPhase::Observed));
}

/// A durable CleanProof must carry unresolved_obligation_count == 0, and validate_clean_proof
/// must reject any hand-built proof whose count is non-zero (crash rule L717). Kills: "CleanProof
/// accepts unresolved_obligation_count != 0".
#[test]
fn unresolved_obligation_count_only_zero() {
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    let proof = to_proved(&mut saga);
    assert_eq!(proof.unresolved_obligation_count, 0);
    assert!(validate_clean_proof(&proof).is_ok(), "zero-count proof must validate");

    // Hand-built proof with a non-zero unresolved obligation count must be rejected.
    let synthetic = CleanProof {
        runtime_epoch: runtime_epoch(1),
        platform_authority_instance: PlatformAuthorityInstanceId::try_from(Uuid::from_u128(1))
            .expect("non-nil instance"),
        prior_ownership_version: ownership_version(1),
        prior_platform_ownership_token_digest_if_issued: Some(
            TokenDigest::try_from(digest32(0x0e)).expect("digest"),
        ),
        retirement_operation_id: retirement_id(1),
        cleanup_trigger_digest: CleanupTriggerDigest::try_from(digest32(0x0a)).expect("digest"),
        external_trigger_operation_identity_digest_if_present: Some(
            ExternalOperationDigest::try_from(digest32(0x0b)).expect("digest"),
        ),
        canonical_obligation_inventory_digest: inventory_digest(1),
        journal_root_or_projection_digest: JournalRootDigest::try_from(digest32(0x0c))
            .expect("digest"),
        journal_revision: JournalRevision::try_from(0).expect("revision 0"),
        platform_evidence: VersionedPlatformEvidence {
            kind_version: 1,
            digest: EvidenceDigest::try_from(digest32(0x0d)).expect("digest"),
        },
        unresolved_obligation_count: 1,
    };
    assert!(
        validate_clean_proof(&synthetic).is_err(),
        "non-zero unresolved_obligation_count must fail validation"
    );
}

/// The next ownership version must not be advanced before OwnershipRetired is durable
/// (crash rule L1207). Kills: "advances next_ownership_version before OwnershipRetired durable".
#[test]
fn next_version_not_advanced_before_ownership_retired() {
    // Right after begin (Started): no advance, no next version.
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    to_started(&mut saga);
    assert!(saga.retire_ownership(ownership_version(2)).is_err());
    assert!(saga.next_ownership_version().is_none());

    // After observe (Observed): still no advance, still no next version.
    let id = retirement_id(1);
    assert!(saga.grant_cleanup(&id).is_ok());
    assert!(saga.observe_cleanup(&[InventoryPredicate { label: 1, verified: true }]).is_ok());
    assert!(matches!(saga.phase(), RetirementPhase::Observed));
    assert!(saga.retire_ownership(ownership_version(2)).is_err());
    assert!(saga.next_ownership_version().is_none());
}

/// Ownership must retire exactly once: a second retire_ownership is rejected and the next
/// version is never incremented again (crash rule L1207). Kills: "increments
/// next_ownership_version more than once".
#[test]
fn no_extra_version_increment_after_retired() {
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    to_proved(&mut saga);
    let nv2 = ownership_version(2);
    let retired: OwnershipRetired = saga.retire_ownership(nv2).expect("retire in Proved");
    assert_eq!(retired.next_ownership_version, nv2);
    assert!(matches!(saga.phase(), RetirementPhase::Retired));

    assert!(saga.retire_ownership(ownership_version(3)).is_err());
    assert_eq!(saga.next_ownership_version(), Some(&nv2));
}

/// The next ownership version/token must not be issued on CleanProof while the prior ownership
/// is not yet durably retired (crash rule L1205). Kills: "issues next token/version after
/// CleanProof while prior ownership not retired".
#[test]
fn next_token_not_issued_before_ownership_retired() {
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    let proof = to_proved(&mut saga);
    assert!(matches!(saga.phase(), RetirementPhase::Proved));
    assert_eq!(proof.unresolved_obligation_count, 0);
    assert!(
        saga.next_ownership_version().is_none(),
        "no next token/version may be issued while ownership is still Proved, not Retired"
    );
}

/// The CleanProof must bind the exact complete ownership projection inventory digest
/// (crash rule L1204). Kills: "guesses/omits the complete ownership projection digest".
#[test]
fn proof_binds_complete_inventory_digest() {
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    let inventory = inventory_digest(0x5a);
    let id = retirement_id(1);
    assert!(saga.begin(id.clone(), cleanup_trigger(), origin_subject(), platform_ownership(), vec![1], inventory.clone()).is_ok());
    assert!(saga.grant_cleanup(&id).is_ok());
    assert!(saga.observe_cleanup(&[InventoryPredicate { label: 1, verified: true }]).is_ok());
    let proof = saga.prove_clean(prove_input()).expect("prove_clean in Observed");
    assert!(proof.canonical_obligation_inventory_digest == inventory);
}

/// The cleanup trigger digest must be carried as its own nominal CleanupTriggerDigest type
/// (crash rule L717). Kills: "reuses plain EvidenceDigest for cleanup_trigger_digest".
#[test]
fn cleanup_trigger_digest_is_distinct() {
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    to_observed(&mut saga);
    let trigger_digest = CleanupTriggerDigest::try_from(digest32(0xaa)).expect("digest");

    let mut input = prove_input();
    input.cleanup_trigger_digest = trigger_digest.clone();
    let proof = saga.prove_clean(input).expect("prove_clean in Observed");

    // Compile-time pin: the field has the distinct nominal type, not a bare EvidenceDigest.
    let captured: CleanupTriggerDigest = proof.cleanup_trigger_digest.clone();
    assert!(captured == trigger_digest);
}

/// The external-trigger and journal-root digests must survive as their own distinct nominal
/// types (crash rule L717). Kills: "reuses plain EvidenceDigest for external-trigger /
/// journal-root digests".
#[test]
fn external_and_journal_root_digests_are_distinct() {
    let mut saga = RetirementSaga::new(fence(), ownership_version(1));
    to_observed(&mut saga);
    let external = ExternalOperationDigest::try_from(digest32(0xbb)).expect("digest");
    let journal_root = JournalRootDigest::try_from(digest32(0xcc)).expect("digest");

    let mut input = prove_input();
    input.external_trigger_operation_identity_digest_if_present = Some(external.clone());
    input.journal_root_or_projection_digest = journal_root.clone();
    let proof = saga.prove_clean(input).expect("prove_clean in Observed");

    // Compile-time pins: each field keeps its distinct nominal type.
    let captured_external: ExternalOperationDigest =
        proof.external_trigger_operation_identity_digest_if_present.clone().expect("external present");
    assert!(captured_external == external);

    let captured_journal: JournalRootDigest = proof.journal_root_or_projection_digest.clone();
    assert!(captured_journal == journal_root);
}