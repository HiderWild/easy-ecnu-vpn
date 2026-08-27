// EXV D10-T: identity/value validation integration tests for exv-vpn-domain.
// These tests reference the D10 construction seams (validating TryFrom constructors and
// validation fns). They are expected to be RED until D10-I implements those seams.
//
// The 5 remaining gap tests (14-18) are present here and reference the pinned D10 seams:
//   - 14 tunnel_plan_rejects_invalid_ipv4_prefix_or_mtu: `TunnelPlan::try_from((Ipv4Addr, u8,
//     u16, Vec<Ipv4Route>, Vec<Ipv4Addr>, Vec<Ipv4Addr>, TunnelIntentRef))` (reject prefix>32
//     and mtu<576) built on `TunnelIntentRef::try_from(ResourceIdentityDigest)`.
//   - 15 request_cross_links_reject_mismatched_retirement: the `ReconcileRequest` retirement
//     cross-link validation seam (a request whose retirement_operation_id does not match the
//     bound obligation's recorded retirement id is rejected), plus the `RetirementOperationId`
//     and `RecoveryObligation` TryFrom construction paths it needs.
//   - 16/17/18 prompt_deadline_*: `PromptDeadline::try_from((MonotonicTick, Duration))`
//     (reject zero budget, >300s ceiling, and tick overflow) built on
//     `MonotonicTick::try_from(u64)`.

use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, OpaqueResourceRef, ResourceKind,
    RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::{
    EvidenceDigest, InventoryDigest, OperationId, OperationLookupKey, OperationMethod,
    OwnershipVersion, PrincipalDigest, RequestDigest, ResourceIdentityDigest,
    RetirementOperationId, RuntimeEpoch, canonical_lookup_digest,
};
use exv_vpn_domain::limits::{MvpLimits, validate_limits};
use exv_vpn_domain::model::{CleanupProofRef, PromptDeadline, RecoveryObligation};
use exv_vpn_domain::ports::{
    Ipv4Route, MonotonicTick, ReconcileRequest, TunnelIntentRef, TunnelPlan,
};
use std::net::Ipv4Addr;
use std::time::Duration;
use uuid::Uuid;

#[test]
fn rejects_empty_runtime_epoch() {
    // A nil (all-zero) Uuid is not a valid runtime epoch identifier; the validating
    // TryFrom<Uuid> must reject it.
    assert!(RuntimeEpoch::try_from(Uuid::nil()).is_err());
}

#[test]
fn rejects_zero_ownership_version() {
    // Ownership versions are 1-based; zero must be rejected by the validating TryFrom<u64>.
    assert!(OwnershipVersion::try_from(0u64).is_err());
}

#[test]
fn rejects_wrong_digest_length() {
    // A 32-byte digest must be accepted by the validating TryFrom<[u8; 32]>.
    let _valid = PrincipalDigest::try_from([0u8; 32]).unwrap();
    // A wrong-length input must be rejected (no TryFrom accepts a non-32-byte array).
    let wrong: [u8; 31] = [0xAB; 31];
    assert!(PrincipalDigest::try_from(wrong).is_err());
}

#[test]
fn lookup_key_separates_principal() {
    let epoch = RuntimeEpoch::try_from(Uuid::new_v4()).unwrap();
    let id = OperationId::try_from(Uuid::new_v4()).unwrap();
    let key_a = OperationLookupKey::try_from((
        PrincipalDigest::try_from([0x11; 32]).unwrap(),
        OperationMethod::Connect,
        epoch.clone(),
        id.clone(),
    ))
    .unwrap();
    let key_b = OperationLookupKey::try_from((
        PrincipalDigest::try_from([0x22; 32]).unwrap(),
        OperationMethod::Connect,
        epoch,
        id,
    ))
    .unwrap();
    // The canonical lookup digest must depend on the principal (kills D10-M1 if it only
    // hashes operation_id).
    assert_ne!(
        canonical_lookup_digest(&key_a),
        canonical_lookup_digest(&key_b)
    );
}

#[test]
fn lookup_key_separates_method() {
    let principal = PrincipalDigest::try_from([0x11; 32]).unwrap();
    let epoch = RuntimeEpoch::try_from(Uuid::new_v4()).unwrap();
    let id = OperationId::try_from(Uuid::new_v4()).unwrap();
    let key_a = OperationLookupKey::try_from((
        principal.clone(),
        OperationMethod::Connect,
        epoch.clone(),
        id.clone(),
    ))
    .unwrap();
    let key_b =
        OperationLookupKey::try_from((principal, OperationMethod::Stop, epoch, id)).unwrap();
    // The canonical lookup digest must separate operations by method.
    assert_ne!(
        canonical_lookup_digest(&key_a),
        canonical_lookup_digest(&key_b)
    );
}

#[test]
fn lookup_key_separates_runtime_epoch() {
    let principal = PrincipalDigest::try_from([0x11; 32]).unwrap();
    let id = OperationId::try_from(Uuid::new_v4()).unwrap();
    let key_a = OperationLookupKey::try_from((
        principal.clone(),
        OperationMethod::Connect,
        RuntimeEpoch::try_from(Uuid::new_v4()).unwrap(),
        id.clone(),
    ))
    .unwrap();
    let key_b = OperationLookupKey::try_from((
        principal,
        OperationMethod::Connect,
        RuntimeEpoch::try_from(Uuid::new_v4()).unwrap(),
        id,
    ))
    .unwrap();
    // The canonical lookup digest must separate operations across runtime epochs.
    assert_ne!(
        canonical_lookup_digest(&key_a),
        canonical_lookup_digest(&key_b)
    );
}

#[test]
fn request_digest_is_not_lookup_identity() {
    let principal = PrincipalDigest::try_from([0x11; 32]).unwrap();
    let epoch = RuntimeEpoch::try_from(Uuid::new_v4()).unwrap();
    let key_a = OperationLookupKey::try_from((
        principal.clone(),
        OperationMethod::Connect,
        epoch.clone(),
        OperationId::try_from(Uuid::new_v4()).unwrap(),
    ))
    .unwrap();
    let key_b = OperationLookupKey::try_from((
        principal,
        OperationMethod::Connect,
        epoch,
        OperationId::try_from(Uuid::new_v4()).unwrap(),
    ))
    .unwrap();
    // The lookup identity is a function of principal+method+epoch, NOT the request/operation
    // id, so two distinct requests over the same key resolve to a single lookup identity.
    assert_eq!(
        canonical_lookup_digest(&key_a),
        canonical_lookup_digest(&key_b)
    );
    // Their request digests are nonetheless distinct.
    let req_a = RequestDigest::try_from([0xAA; 32]).unwrap();
    let req_b = RequestDigest::try_from([0xBB; 32]).unwrap();
    assert_ne!(req_a, req_b);
}

#[test]
fn same_key_different_digest_is_conflict() {
    let key = OperationLookupKey::try_from((
        PrincipalDigest::try_from([0x11; 32]).unwrap(),
        OperationMethod::Connect,
        RuntimeEpoch::try_from(Uuid::new_v4()).unwrap(),
        OperationId::try_from(Uuid::new_v4()).unwrap(),
    ))
    .unwrap();
    let req_a = RequestDigest::try_from([0xAA; 32]).unwrap();
    let req_b = RequestDigest::try_from([0xBB; 32]).unwrap();
    assert_ne!(req_a, req_b);
    // Replaying the same operation key with a different request digest is an idempotency
    // conflict: the domain must model it as IdempotencyConflict, not a duplicate success.
    let _conflict = VpnError::try_from((
        ErrorCode::IdempotencyConflict,
        ErrorStage::Admission,
        EffectCertainty::NoEffect,
        RetryAdvice::DoNotRetry,
        ErrorSubject::External(key),
        None,
        None,
    ))
    .unwrap();
}

#[test]
fn error_debug_redacts_native_and_secret_text() {
    let secret_uuid = Uuid::new_v4();
    let secret_uuid_str = secret_uuid.to_string();
    let key = OperationLookupKey::try_from((
        PrincipalDigest::try_from([0xBB; 32]).unwrap(),
        OperationMethod::Connect,
        RuntimeEpoch::try_from(Uuid::new_v4()).unwrap(),
        OperationId::try_from(secret_uuid).unwrap(),
    ))
    .unwrap();
    let secret_ref = OpaqueResourceRef::try_from((
        ResourceKind::ProtocolSession,
        ResourceIdentityDigest::try_from([0xAA; 32]).unwrap(),
    ))
    .unwrap();
    let err = VpnError::try_from((
        ErrorCode::Unauthorized,
        ErrorStage::Admission,
        EffectCertainty::NoEffect,
        RetryAdvice::DoNotRetry,
        ErrorSubject::External(key),
        Some(secret_ref),
        None,
    ))
    .unwrap();
    let rendered = format!("{:?}", err);
    // Raw secret material must not leak into the Debug representation (kills D10-M2).
    assert!(
        !rendered.contains(&secret_uuid_str),
        "operation id leaked into Debug output"
    );
    assert!(
        !rendered.contains("[170,"),
        "resource identity digest leaked into Debug output"
    );
}

#[test]
fn limits_reject_zero_and_inverted_budgets() {
    let base = || MvpLimits {
        normal_mailbox_messages: 64,
        completion_mailbox_messages: 16,
        stop_waiters: 8,
        snapshot_receivers: 4,
        packet_queue_messages: 1024,
        packet_queue_bytes: 1 << 20,
        max_packet_batch_packets: 64,
        max_packet_batch_bytes: 1 << 16,
        max_control_message_bytes: 1 << 12,
        max_packet_message_bytes: 1 << 14,
        normal_cleanup_budget: Duration::from_secs(5),
        queued_connect_budget: Duration::from_secs(10),
        owner_lease_ttl: Duration::from_secs(60),
        packet_loss_cleanup_grace: Duration::from_secs(2),
    };
    // A zero budget is invalid.
    let zero = MvpLimits {
        normal_cleanup_budget: Duration::ZERO,
        ..base()
    };
    assert!(validate_limits(&zero).is_err());
    // An inverted budget ordering (connect budget shorter than the cleanup budget) is invalid.
    let inverted = MvpLimits {
        queued_connect_budget: Duration::from_secs(1),
        ..base()
    };
    assert!(validate_limits(&inverted).is_err());
}

#[test]
fn opaque_refs_require_validated_constructor() {
    let digest = ResourceIdentityDigest::try_from([0x11; 32]).unwrap();
    let r = OpaqueResourceRef::try_from((ResourceKind::ProtocolSession, digest)).unwrap();
    // The opaque ref's fields are private; the validating TryFrom is the only construction
    // path, and its result flows into a VpnError resource slot.
    let _err = VpnError::try_from((
        ErrorCode::Unauthorized,
        ErrorStage::Admission,
        EffectCertainty::NoEffect,
        RetryAdvice::DoNotRetry,
        ErrorSubject::Runtime(RuntimeEpoch::try_from(Uuid::new_v4()).unwrap()),
        Some(r),
        None,
    ))
    .unwrap();
}

#[test]
fn opaque_refs_reject_nil_identity() {
    let nil_digest = ResourceIdentityDigest::try_from([0u8; 32]).unwrap();
    // An opaque ref must reject a nil (all-zero) identity digest.
    assert!(OpaqueResourceRef::try_from((ResourceKind::Runtime, nil_digest)).is_err());
}

#[test]
fn clean_proof_rejects_unresolved_obligations() {
    // A clean proof must not be minted against an obligation inventory that still holds
    // unresolved obligations (represented here by a nil/unresolved inventory digest).
    let unresolved_inventory = InventoryDigest::try_from([0u8; 32]).unwrap();
    let evidence = EvidenceDigest::try_from([0x22; 32]).unwrap();
    assert!(CleanupProofRef::try_from((unresolved_inventory, evidence)).is_err());
}

#[test]
fn tunnel_plan_rejects_invalid_ipv4_prefix_or_mtu() {
    // A TunnelPlan is constructed from a validating TryFrom over its semantic fields. It must
    // reject an IPv4 prefix above 32 and an MTU below the 576 byte minimum (D10-M3); the opaque
    // intent ref is a nominal wrapper over a resource identity digest.
    let intent =
        TunnelIntentRef::try_from(ResourceIdentityDigest::try_from([0x11; 32]).unwrap()).unwrap();
    let plan = |prefix: u8, mtu: u16| {
        TunnelPlan::try_from((
            Ipv4Addr::from([10, 0, 0, 1]),
            prefix,
            mtu,
            vec![Ipv4Route {
                network: Ipv4Addr::from([10, 0, 0, 0]),
                prefix_len: 24,
            }],
            vec![Ipv4Addr::from([1, 1, 1, 1])],
            vec![Ipv4Addr::from([8, 8, 8, 8])],
            intent.clone(),
        ))
    };
    // A prefix above 32 is not a valid IPv4 prefix.
    assert!(plan(33, 1400).is_err());
    // An MTU below the 576 byte minimum is not routable.
    assert!(plan(24, 575).is_err());
    // A valid prefix/MTU combination is accepted.
    assert!(plan(24, 1400).is_ok());
}

#[test]
fn request_cross_links_reject_mismatched_retirement() {
    // A ReconcileRequest binds a retirement_operation_id to the obligation it reconciles. The
    // validating cross-link constructor must reject a request whose retirement id does not match
    // the obligation's recorded retirement id (D10-M3).
    let epoch = RuntimeEpoch::try_from(Uuid::new_v4()).unwrap();
    let inventory = InventoryDigest::try_from([0u8; 32]).unwrap();
    let blocker = VpnError::try_from((
        ErrorCode::EffectUnknown,
        ErrorStage::Recovery,
        EffectCertainty::Unknown,
        RetryAdvice::Reconcile,
        ErrorSubject::Runtime(epoch.clone()),
        None,
        None,
    ))
    .unwrap();
    let matching_id = RetirementOperationId::try_from(Uuid::new_v4()).unwrap();
    let other_id = RetirementOperationId::try_from(Uuid::new_v4()).unwrap();
    let obligation = |retirement: Option<RetirementOperationId>| {
        RecoveryObligation::try_from((
            epoch.clone(),
            retirement,
            blocker.clone(),
            None, // platform_ownership
            None, // packet_lease
            inventory.clone(),
        ))
        .unwrap()
    };
    // A request whose retirement id matches the obligation's recorded id cross-links cleanly.
    let _ok =
        ReconcileRequest::try_from((matching_id.clone(), obligation(Some(matching_id.clone()))))
            .unwrap();
    // A mismatched retirement id must be rejected.
    assert!(ReconcileRequest::try_from((other_id, obligation(Some(matching_id)))).is_err());
}

#[test]
fn prompt_deadline_rejects_zero_budget() {
    // A zero interaction-prompt budget cannot yield a usable absolute deadline.
    let tick = MonotonicTick::try_from(1_000_000u64).unwrap();
    assert!(PromptDeadline::try_from((tick, Duration::ZERO)).is_err());
}

#[test]
fn prompt_deadline_rejects_over_ceiling_budget() {
    // The interaction prompt budget ceiling is 300s; a 301s budget must be rejected before any
    // tick narrowing (D10 clock-domain invariant).
    let tick = MonotonicTick::try_from(1_000_000u64).unwrap();
    assert!(PromptDeadline::try_from((tick, Duration::from_secs(301))).is_err());
}

#[test]
fn prompt_deadline_rejects_tick_overflow() {
    // A budget that pushes the absolute deadline past u64::MAX must be rejected by checked_add
    // rather than wrapping the monotonic tick.
    let tick = MonotonicTick::try_from(u64::MAX - 100).unwrap();
    assert!(PromptDeadline::try_from((tick, Duration::from_secs(300))).is_err());
}
