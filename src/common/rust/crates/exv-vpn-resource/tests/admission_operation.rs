// RED tests for the §7.2 admission operation (Architecture spec, vpn-rust-native-runtime-mvp).
// PURE, deterministic: single-write admission sequencer + durable admission records.
// No I/O, no filesystem, no sleep, no randomness — identifiers come only from Uuid::from_u128.
//
// The production seam `exv_vpn_resource::admission` and `exv_vpn_resource::operation` does not
// exist yet; J51-I implements it. Until then this file FAILS TO COMPILE (unresolved imports) —
// that is the intended RED.

use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::{
    EffectId, OperationId, OperationLookupKey, OperationMethod, OwnershipVersion, PrincipalDigest,
    RequestDigest, ResourceIdentityDigest, RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CanonicalInputDigest, JournalRevision,
    OperationState, PlatformAuthorityInstanceId, RejectionReason,
};
use exv_vpn_resource::admission::{
    AdmissionRecord, AppliedFingerprint, AuthorizationSubject, MutationKind, ObligationSeed,
    decode_record, encode_record,
};
use exv_vpn_resource::journal::{DecodeOutcome, JournalRecord, decode, encode};
use exv_vpn_resource::operation::{AdmissionIndex, AdmissionOutcome, MutationAdmissionInput};
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

/// Deterministic principal digest that differs across `n`.
fn principal(n: u8) -> PrincipalDigest {
    let mut b = [0u8; 32];
    b[0] = n;
    PrincipalDigest::try_from(b).expect("digest")
}

/// Deterministic request digest that differs across `n`.
fn request(n: u8) -> RequestDigest {
    let mut b = [0u8; 32];
    b[0] = n;
    RequestDigest::try_from(b).expect("digest")
}

/// Deterministic lookup key from a principal, method, epoch id and operation id.
fn key(p: PrincipalDigest, method: OperationMethod, epoch_id: u128, op_id: u128) -> OperationLookupKey {
    OperationLookupKey::try_from((
        p,
        method,
        RuntimeEpoch::try_from(Uuid::from_u128(epoch_id)).expect("non-nil epoch"),
        OperationId::try_from(Uuid::from_u128(op_id)).expect("non-nil op"),
    ))
    .expect("key")
}

/// A canonical MutationAdmissionInput for the given key/digest/effect/mutation kind.
fn input(
    key: OperationLookupKey,
    request_digest: RequestDigest,
    effect_id: EffectId,
    mutation_kind: MutationKind,
) -> MutationAdmissionInput {
    MutationAdmissionInput {
        key,
        request_digest,
        effect_id,
        initiator_identity_digest: principal(9),
        canonical_input_digest: CanonicalInputDigest::try_from([0x11; 32]).expect("digest"),
        mutation_kind,
        ownership_version: OwnershipVersion::try_from(1).expect("version 1"),
        authorization_subject: AuthorizationSubject::LiveOwnershipTokenDigest(
            TokenDigest::try_from([0x22; 32]).expect("digest"),
        ),
        resource_identity: ResourceIdentityDigest::try_from([0x33; 32]).expect("digest"),
        precondition_fingerprint: AppliedFingerprint::try_from([0x44; 32]).expect("digest"),
        desired_applied_fingerprint: AppliedFingerprint::try_from([0x55; 32]).expect("digest"),
        canonical_obligation_seed: ObligationSeed::try_from([0x66; 32]).expect("digest"),
    }
}

/// Wrap an encoded admission record in a single durable journal frame and decode it back.
fn round_trip_payload(payload: Vec<u8>) -> Vec<JournalRecord> {
    let jr = JournalRecord::new(0, [0u8; 32], payload);
    let bytes = encode(&jr);
    match decode(&bytes) {
        DecodeOutcome::Clean(recs) => recs,
        _ => panic!("expected a clean single-record round trip"),
    }
}

/// admit(K,D) then admit(K,D) again must return the SAME admitted record (same watermark) with no
/// second entry. Kills: "idempotency not recognized, second admission double-admits".
#[test]
fn same_lookup_and_digest_is_idempotent() {
    let mut index = AdmissionIndex::new(fence());
    let k = key(principal(1), OperationMethod::Connect, 10, 100);
    let d = request(1);
    let e = EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect");
    let kind = MutationKind::External(OperationMethod::Connect);

    let first = index.admit(input(k.clone(), d.clone(), e.clone(), kind.clone()));
    let second = index.admit(input(k.clone(), d.clone(), e.clone(), kind.clone()));

    match (first, second) {
        (AdmissionOutcome::Admitted { record: r1 }, AdmissionOutcome::Admitted { record: r2 }) => {
            assert_eq!(
                r1.admission_watermark, r2.admission_watermark,
                "idempotent re-admit must reuse the original watermark, not mint a new one"
            );
            assert!(
                r1.journal_operation_identity == r2.journal_operation_identity,
                "idempotent re-admit must report the original operation identity"
            );
        }
        _ => panic!("expected both admits of the same key+digest to succeed idempotently"),
    }
}

/// admit(K,D1) then admit(K,D2) must conflict — D2 is never admitted. Kills: "same key + diff
/// digest silently re-admitted".
#[test]
fn same_lookup_different_digest_conflicts() {
    let mut index = AdmissionIndex::new(fence());
    let k = key(principal(1), OperationMethod::Connect, 10, 100);
    let e = EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect");
    let kind = MutationKind::External(OperationMethod::Connect);

    let first = index.admit(input(k.clone(), request(1), e.clone(), kind.clone()));
    let second = index.admit(input(k, request(2), e, kind));

    assert!(
        matches!(first, AdmissionOutcome::Admitted { .. }),
        "first admission of (K,D1) must be admitted"
    );
    assert!(
        matches!(second, AdmissionOutcome::IdempotencyConflict),
        "same lookup key with a different request digest must conflict"
    );
}

/// Two keys differing ONLY in principal_digest must both be admitted. Kills: "index keys on
/// operation_id alone, colliding across principals".
#[test]
fn different_principal_does_not_collide() {
    let mut index = AdmissionIndex::new(fence());
    let e = EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect");
    let kind = MutationKind::External(OperationMethod::Connect);

    let a = index.admit(input(key(principal(1), OperationMethod::Connect, 10, 100), request(1), e.clone(), kind.clone()));
    let b = index.admit(input(key(principal(2), OperationMethod::Connect, 10, 100), request(2), e, kind));

    assert!(matches!(a, AdmissionOutcome::Admitted { .. }), "first principal must admit");
    assert!(matches!(b, AdmissionOutcome::Admitted { .. }), "different principal must NOT collide");
}

/// Two keys differing ONLY in OperationMethod must both be admitted. Kills: "index keys ignoring
/// method".
#[test]
fn different_method_does_not_collide() {
    let mut index = AdmissionIndex::new(fence());
    let e = EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect");

    let a = index.admit(input(
        key(principal(1), OperationMethod::Connect, 10, 100),
        request(1),
        e.clone(),
        MutationKind::External(OperationMethod::Connect),
    ));
    let b = index.admit(input(
        key(principal(1), OperationMethod::Stop, 10, 100),
        request(2),
        e,
        MutationKind::External(OperationMethod::Stop),
    ));

    assert!(matches!(a, AdmissionOutcome::Admitted { .. }), "Connect method must admit");
    assert!(matches!(b, AdmissionOutcome::Admitted { .. }), "different method must NOT collide");
}

/// Two keys differing ONLY in runtime_epoch must both be admitted. Kills: "index keys ignoring
/// runtime epoch".
#[test]
fn different_epoch_does_not_collide() {
    let mut index = AdmissionIndex::new(fence());
    let e = EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect");
    let kind = MutationKind::External(OperationMethod::Connect);

    let a = index.admit(input(key(principal(1), OperationMethod::Connect, 10, 100), request(1), e.clone(), kind.clone()));
    let b = index.admit(input(key(principal(1), OperationMethod::Connect, 11, 100), request(2), e, kind));

    assert!(matches!(a, AdmissionOutcome::Admitted { .. }), "epoch 10 must admit");
    assert!(matches!(b, AdmissionOutcome::Admitted { .. }), "different epoch must NOT collide");
}

/// An admission must persist as EXACTLY ONE durable MutationAdmitted record (never an
/// OperationAccepted + MutationIntent split). Kills: "admission split into OperationAccepted +
/// MutationIntent".
#[test]
fn mutation_admitted_is_one_atomic_record() {
    let mut index = AdmissionIndex::new(fence());
    let k = key(principal(1), OperationMethod::Connect, 10, 100);
    let e = EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect");

    let outcome = index.admit(input(k, request(1), e, MutationKind::External(OperationMethod::Connect)));
    let record = match outcome {
        AdmissionOutcome::Admitted { record } => record,
        _ => panic!("expected admission"),
    };

    let recs = round_trip_payload(encode_record(&AdmissionRecord::Admitted(record)));
    assert_eq!(recs.len(), 1, "admission must be a single atomic journal record");
    match decode_record(&recs[0].payload).expect("decodes") {
        AdmissionRecord::Admitted(_) => {}
        _ => panic!("expected exactly one MutationAdmitted record"),
    }
}

/// A mutation's effect must never be acknowledged without a durable MutationAdmitted record that
/// carries the same effect_id and round-trips. Kills: "effect acknowledged without a durable
/// MutationAdmitted record".
#[test]
fn effect_never_precedes_durable_admission() {
    let mut index = AdmissionIndex::new(fence());
    let k = key(principal(1), OperationMethod::Connect, 10, 100);
    let e = EffectId::try_from(Uuid::from_u128(999)).expect("non-nil effect");

    let outcome = index.admit(input(k, request(1), e.clone(), MutationKind::External(OperationMethod::Connect)));
    let record = match outcome {
        AdmissionOutcome::Admitted { record } => record,
        _ => panic!("expected admission"),
    };
    assert_eq!(record.effect_id, e, "admitted record must carry the effect_id");

    let recs = round_trip_payload(encode_record(&AdmissionRecord::Admitted(record)));
    assert_eq!(recs.len(), 1);
    match decode_record(&recs[0].payload).expect("decodes") {
        AdmissionRecord::Admitted(r2) => assert_eq!(r2.effect_id, e, "effect must survive the durable round trip"),
        _ => panic!("expected a single MutationAdmitted"),
    }
}

/// A no-effect rejection must persist as a durable OperationRejected that round-trips, and
/// get_operation must report RejectedNoEffect. Kills: "rejection returned volatile with no durable
/// record".
#[test]
fn rejected_no_effect_is_durable() {
    let mut index = AdmissionIndex::new(fence());
    let k = key(principal(1), OperationMethod::Connect, 10, 100);
    let d = request(1);
    let reason = RejectionReason {
        error: VpnError::try_from((
            ErrorCode::Unauthorized,
            ErrorStage::Admission,
            EffectCertainty::NoEffect,
            RetryAdvice::DoNotRetry,
            ErrorSubject::External(k.clone()),
            None,
            None,
        ))
        .expect("vpn error"),
        authority_fence: fence(),
    };

    let rejected = index.reject(&k, &d, reason);
    assert!(rejected.lookup_key == k, "rejection must carry the lookup key");
    assert_eq!(rejected.request_digest, d, "rejection must carry the request digest");

    let recs = round_trip_payload(encode_record(&AdmissionRecord::Rejected(rejected)));
    assert_eq!(recs.len(), 1, "rejection must be a single durable record");
    match decode_record(&recs[0].payload).expect("decodes") {
        AdmissionRecord::Rejected(_) => {}
        _ => panic!("expected a durable OperationRejected record"),
    }
    assert!(
        matches!(index.get_operation(&k, &d), OperationState::RejectedNoEffect { .. }),
        "get_operation must report RejectedNoEffect for a durably rejected key"
    );
}

/// get_operation on a never-seen key must be Unknown and must NOT create a fence. Kills:
/// "missing-without-watermark falsely returns NoEffect/AbsentNoEffect".
#[test]
fn not_found_without_fence_is_unknown() {
    let mut index = AdmissionIndex::new(fence());
    let k = key(principal(1), OperationMethod::Connect, 10, 100);
    let d = request(1);

    assert!(
        matches!(index.get_operation(&k, &d), OperationState::Unknown),
        "a never-seen key must be Unknown"
    );
    assert!(
        matches!(index.get_operation(&k, &d), OperationState::Unknown),
        "a read-only lookup must not create a fence (still Unknown)"
    );
}

/// An absence fence at watermark W followed by an admission of a distinct key must be Admitted at
/// watermark W+1 — ONE shared sequencer. Kills: "fence uses a separate sequencer/watermark from
/// admission".
#[test]
fn absent_fence_serializes_with_delayed_admission() {
    let mut index = AdmissionIndex::new(fence());
    let fk = key(principal(1), OperationMethod::Connect, 10, 100);
    let fd = request(1);
    let fence_rec = index.establish_absence_fence(&fk, &fd);

    let ak = key(principal(2), OperationMethod::Connect, 10, 200);
    let e = EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect");
    let outcome = index.admit(input(ak, request(2), e, MutationKind::External(OperationMethod::Connect)));

    match outcome {
        AdmissionOutcome::Admitted { record } => {
            assert_ne!(
                fence_rec.admission_watermark,
                record.admission_watermark,
                "fence and admission must share one rising sequencer, so their watermarks differ"
            );
        }
        _ => panic!("a distinct key must admit after an absence fence"),
    }
}

/// After an absence fence on (K,D), a delayed same-key+same-digest mutation must be closed by the
/// fence (ClosedByAbsenceProof), never freshly admitted. Kills: "fence not consulted — delayed
/// same-key mutation freshly admitted".
#[test]
fn delayed_same_digest_is_closed_by_fence() {
    let mut index = AdmissionIndex::new(fence());
    let k = key(principal(1), OperationMethod::Connect, 10, 100);
    let d = request(1);
    let e = EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect");

    index.establish_absence_fence(&k, &d);
    let outcome = index.admit(input(k, d, e, MutationKind::External(OperationMethod::Connect)));

    assert!(
        matches!(outcome, AdmissionOutcome::ClosedByAbsenceProof),
        "a delayed same-key mutation after an absence fence must be closed by the fence"
    );
}

/// After an absence fence on (K,D1), a delayed same-key + different-digest mutation must conflict.
/// Kills: "fence not consulted — delayed diff-digest re-admitted".
#[test]
fn delayed_different_digest_conflicts() {
    let mut index = AdmissionIndex::new(fence());
    let k = key(principal(1), OperationMethod::Connect, 10, 100);
    let e = EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect");

    index.establish_absence_fence(&k, request(1));
    let outcome = index.admit(input(k, request(2), e, MutationKind::External(OperationMethod::Connect)));

    assert!(
        matches!(outcome, AdmissionOutcome::IdempotencyConflict),
        "a delayed same-key different-digest mutation after an absence fence must conflict"
    );
}