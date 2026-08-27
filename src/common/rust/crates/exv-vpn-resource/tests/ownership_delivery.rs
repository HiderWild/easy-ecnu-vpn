// RED tests for §7.4 per-connection single-unacknowledged ownership-token delivery slot
// (Architecture spec, vpn-rust-native-runtime-mvp, L1210-1213).
// PURE, deterministic: no I/O, no filesystem, no sleep, no randomness — identifiers come only from
// fixed byte arrays and fixed u128 literals.
//
// The production seam `exv_vpn_resource::delivery` does not exist yet; J52-I implements it
// (in `src/delivery.rs` + `pub mod delivery;` in `src/lib.rs`). Until then this file FAILS TO
// COMPILE (unresolved imports of OwnershipTokenDelivery, DeliveryOutcome, AckOutcome,
// TerminateOutcome, TokenDeliveryRequest, OwnershipTokenAck) — that is the intended RED.
//
// NOTE: TokenDigest and OperationLookupKey have NO Debug, so outcomes are asserted with
// `matches!` (with token binding) and equality is checked via PartialEq (==/!=) — never assert_eq!.

use exv_vpn_domain::identity::{
    ConnectionBindingDigest, OperationId, OperationLookupKey, OperationMethod, OwnershipVersion,
    PrincipalDigest, RequestDigest, RuntimeEpoch, TokenDigest,
};
use exv_vpn_resource::authority::ConnectionBinding;
use exv_vpn_resource::delivery::{
    AckOutcome, DeliveryOutcome, OwnershipTokenAck, OwnershipTokenDelivery, TerminateOutcome,
    TokenDeliveryRequest,
};
use uuid::Uuid;

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

/// Deterministic lookup key anchored to the given principal and method (fixed epoch/op).
fn lookup_key(principal_n: u8, method: OperationMethod) -> OperationLookupKey {
    OperationLookupKey::try_from((principal(principal_n), method, epoch(1), operation(1)))
        .expect("lookup key")
}

/// Build a token delivery request.
fn deliver_request(
    connection: ConnectionBinding,
    key: OperationLookupKey,
    request_digest: RequestDigest,
    ownership_version: OwnershipVersion,
    candidate_token: TokenDigest,
) -> TokenDeliveryRequest {
    TokenDeliveryRequest {
        connection,
        key,
        request_digest,
        ownership_version,
        candidate_token,
    }
}

/// Build an ownership token ack.
fn ack_request(
    connection: ConnectionBinding,
    key: OperationLookupKey,
    request_digest: RequestDigest,
    ownership_version: OwnershipVersion,
    token: TokenDigest,
) -> OwnershipTokenAck {
    OwnershipTokenAck {
        connection,
        key,
        request_digest,
        ownership_version,
        token,
    }
}

/// Assert that `deliver` replays the held token `expected` (never mints a new one).
fn assert_replay(delivery: &mut OwnershipTokenDelivery, request: TokenDeliveryRequest, expected: TokenDigest) {
    let outcome = delivery.deliver(request);
    assert!(
        matches!(outcome, DeliveryOutcome::Replayed { ref token } if **token == expected),
        "expected a replay of the held token, not a fresh issuance"
    );
}

/// A same key+digest+version retry must replay the SAME held token, never a new candidate.
/// Kills: 'issue a second token on retry'.
#[test]
fn retry_same_key_digest_returns_same_token() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);
    let cand_b = token(21);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(
        matches!(issued, DeliveryOutcome::Issued { ref token } if *token == cand_a),
        "the first deliver must issue the candidate token"
    );

    let replayed = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_b.clone(),
    ));
    assert!(
        matches!(replayed, DeliveryOutcome::Replayed { ref token } if *token == cand_a && *token != cand_b),
        "a same-key/digest retry must replay the SAME held token, never a new one"
    );
}

/// Repeated same-key/digest retries never mint a second token; each replays the held token.
/// Kills: 'issue a second token on retry'.
#[test]
fn same_key_retries_never_mint_second_token() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    for n in 21..=25u8 {
        let candidate = token(n);
        assert_replay(
            &mut delivery,
            deliver_request(conn.clone(), key.clone(), d1.clone(), v1, candidate),
            cand_a.clone(),
        );
    }
}

/// A different acquire key is rejected while the slot is held; no second token is issued.
/// Kills: 'a different acquire key gets a token while a slot is held'.
#[test]
fn different_acquire_key_rejected_while_slot_held() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let k1 = lookup_key(1, OperationMethod::Connect);
    let k2 = lookup_key(2, OperationMethod::Connect);
    let d1 = request_digest(10);
    let d2 = request_digest(11);
    let v1 = version(1);
    let cand_a = token(20);
    let cand_b = token(21);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        k1.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    let rejected = delivery.deliver(deliver_request(
        conn.clone(),
        k2.clone(),
        d2.clone(),
        v1,
        cand_b.clone(),
    ));
    assert!(
        matches!(rejected, DeliveryOutcome::OtherKeyHeld),
        "a different acquire key must be rejected while the slot is held"
    );
}

/// The other-acquire-key rejection is stable across repeated attempts.
/// Kills: 'other acquire key gets a token' (stability).
#[test]
fn other_acquire_key_rejected_stably() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let k1 = lookup_key(1, OperationMethod::Connect);
    let k2 = lookup_key(2, OperationMethod::Connect);
    let d1 = request_digest(10);
    let d2 = request_digest(11);
    let v1 = version(1);
    let cand_a = token(20);
    let cand_b = token(21);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        k1.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    for _ in 0..2 {
        let rejected = delivery.deliver(deliver_request(
            conn.clone(),
            k2.clone(),
            d2.clone(),
            v1,
            cand_b.clone(),
        ));
        assert!(
            matches!(rejected, DeliveryOutcome::OtherKeyHeld),
            "a different acquire key must be rejected on every attempt"
        );
    }
}

/// ACK must reject the wrong connection (NoSlot) and leave the held slot intact.
/// Kills: 'ACK clears a slot without verifying connection'.
#[test]
fn ack_rejects_wrong_connection() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn1 = binding(3);
    let conn2 = binding(4);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);

    let issued = delivery.deliver(deliver_request(
        conn1.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    let ack = delivery.ack(ack_request(conn2, key.clone(), d1.clone(), v1, cand_a.clone()));
    assert!(
        matches!(ack, AckOutcome::NoSlot),
        "an ACK for a different connection must not touch the held slot"
    );

    assert_replay(
        &mut delivery,
        deliver_request(conn1.clone(), key.clone(), d1.clone(), v1, token(22)),
        cand_a.clone(),
    );
}

/// ACK must reject a wrong ownership version and retain the slot.
/// Kills: 'ACK clears without verifying version'.
#[test]
fn ack_rejects_wrong_ownership_version() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let v2 = version(2);
    let cand_a = token(20);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    let ack = delivery.ack(ack_request(conn.clone(), key.clone(), d1.clone(), v2, cand_a.clone()));
    assert!(
        matches!(ack, AckOutcome::Mismatch),
        "an ACK with the wrong ownership version must be a mismatch and retain the slot"
    );

    assert_replay(
        &mut delivery,
        deliver_request(conn.clone(), key.clone(), d1.clone(), v1, token(22)),
        cand_a.clone(),
    );
}

/// ACK must reject a wrong request digest and retain the slot.
/// Kills: 'ACK clears without verifying digest'.
#[test]
fn ack_rejects_wrong_request_digest() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let d2 = request_digest(11);
    let v1 = version(1);
    let cand_a = token(20);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    let ack = delivery.ack(ack_request(conn.clone(), key.clone(), d2, v1, cand_a.clone()));
    assert!(
        matches!(ack, AckOutcome::Mismatch),
        "an ACK with the wrong request digest must be a mismatch and retain the slot"
    );

    assert_replay(
        &mut delivery,
        deliver_request(conn.clone(), key.clone(), d1.clone(), v1, token(22)),
        cand_a.clone(),
    );
}

/// ACK must reject a wrong token and retain the slot.
/// Kills: 'ACK clears without verifying token'.
#[test]
fn ack_rejects_wrong_token() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);
    let wrong = token(30);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    let ack = delivery.ack(ack_request(conn.clone(), key.clone(), d1.clone(), v1, wrong));
    assert!(
        matches!(ack, AckOutcome::Mismatch),
        "an ACK carrying the wrong token must be a mismatch and retain the slot"
    );

    assert_replay(
        &mut delivery,
        deliver_request(conn.clone(), key.clone(), d1.clone(), v1, token(22)),
        cand_a.clone(),
    );
}

/// Only a fully matching ACK clears the slot; every mismatched ACK leaves it replayable.
/// Kills: 'ACK clears without verifying connection/version/digest/token'.
#[test]
fn ack_clears_slot_only_with_matching_credentials() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let d2 = request_digest(11);
    let v1 = version(1);
    let v2 = version(2);
    let cand_a = token(20);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    // Wrong version, wrong digest, and wrong token each mismatch and retain the slot.
    assert!(matches!(
        delivery.ack(ack_request(conn.clone(), key.clone(), d1.clone(), v2, cand_a.clone())),
        AckOutcome::Mismatch
    ));
    assert_replay(
        &mut delivery,
        deliver_request(conn.clone(), key.clone(), d1.clone(), v1, token(22)),
        cand_a.clone(),
    );

    assert!(matches!(
        delivery.ack(ack_request(conn.clone(), key.clone(), d2, v1, cand_a.clone())),
        AckOutcome::Mismatch
    ));
    assert_replay(
        &mut delivery,
        deliver_request(conn.clone(), key.clone(), d1.clone(), v1, token(23)),
        cand_a.clone(),
    );

    assert!(matches!(
        delivery.ack(ack_request(conn.clone(), key.clone(), d1.clone(), v1, token(30))),
        AckOutcome::Mismatch
    ));
    assert_replay(
        &mut delivery,
        deliver_request(conn.clone(), key.clone(), d1.clone(), v1, token(24)),
        cand_a.clone(),
    );

    // Only the fully matching ACK clears the slot.
    assert!(matches!(
        delivery.ack(ack_request(conn.clone(), key.clone(), d1.clone(), v1, cand_a.clone())),
        AckOutcome::Cleared
    ));
}

/// Connection termination invalidates the held token; no new token is ever issued afterward.
/// Kills: 'connection termination does not invalidate the token'.
#[test]
fn terminate_invalidates_token() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    let terminated = delivery.terminate_connection(&conn);
    assert!(
        matches!(
            terminated,
            TerminateOutcome::Invalidated { ref token, ref ownership_version }
                if *token == cand_a && *ownership_version == v1
        ),
        "termination must invalidate the held token and its ownership version"
    );

    let after = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        token(21),
    ));
    assert!(
        matches!(after, DeliveryOutcome::AlreadyDelivered),
        "the token must never be re-sent after the connection is terminated"
    );
}

/// Terminating another connection must not touch the held slot.
/// Kills: 'termination not scoped to the terminating connection'.
#[test]
fn terminate_other_connection_leaves_slot() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn1 = binding(3);
    let conn2 = binding(4);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);

    let issued = delivery.deliver(deliver_request(
        conn1.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    let terminated = delivery.terminate_connection(&conn2);
    assert!(
        matches!(terminated, TerminateOutcome::NothingHeld),
        "terminating an unrelated connection must be a no-op for the held slot"
    );

    assert_replay(
        &mut delivery,
        deliver_request(conn1.clone(), key.clone(), d1.clone(), v1, token(22)),
        cand_a.clone(),
    );
}

/// After a correct ACK the token is never re-sent; the slot is resolved.
/// Kills: 'token re-sent after ACK'.
#[test]
fn no_token_resent_after_ack() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    let ack = delivery.ack(ack_request(conn.clone(), key.clone(), d1.clone(), v1, cand_a.clone()));
    assert!(matches!(ack, AckOutcome::Cleared));

    let after = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        token(21),
    ));
    assert!(
        matches!(after, DeliveryOutcome::AlreadyDelivered),
        "the token must never be re-sent after a matching ACK"
    );
}

/// After an ACK the lease is closed: repeated delivers never yield a fresh token.
/// Kills: 'token re-sent after ACK' (repeated).
#[test]
fn after_ack_lease_must_end_not_resend() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    let ack = delivery.ack(ack_request(conn.clone(), key.clone(), d1.clone(), v1, cand_a.clone()));
    assert!(matches!(ack, AckOutcome::Cleared));

    for n in 21..=25u8 {
        let after = delivery.deliver(deliver_request(
            conn.clone(),
            key.clone(),
            d1.clone(),
            v1,
            token(n),
        ));
        assert!(
            matches!(after, DeliveryOutcome::AlreadyDelivered),
            "after the ACK the slot must be resolved and never re-send a token"
        );
    }
}

/// A new ownership version while one is pending must not mint a parallel token.
/// Kills: 'parallel token issued while a version is pending'.
#[test]
fn no_parallel_token_while_version_pending() {
    let mut delivery = OwnershipTokenDelivery::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let v2 = version(2);
    let cand_a = token(20);
    let cand_b = token(21);

    let issued = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v1,
        cand_a.clone(),
    ));
    assert!(matches!(issued, DeliveryOutcome::Issued { .. }));

    let parallel = delivery.deliver(deliver_request(
        conn.clone(),
        key.clone(),
        d1.clone(),
        v2,
        cand_b.clone(),
    ));
    assert!(
        matches!(parallel, DeliveryOutcome::VersionPending),
        "a different ownership version while one is pending must not issue a parallel token"
    );
}