// RED tests for the exv-vpn-testkit deterministic scripted Clock/EntropySource and fixture
// builders (TK80-83). This is a PURE, deterministic test: no I/O, no filesystem, no sleep, no
// OS randomness. Every UUID/tick is a contrived constant; every assertion is a pure function of
// the pinned seam.
//
// The production modules `exv_vpn_testkit::clock::{ScriptedClock}`,
// `exv_vpn_testkit::entropy::{ScriptedEntropy}`, and
// `exv_vpn_testkit::fixture::{peer_context, peer_capability, mvp_limits, authority_fence}` do
// not exist yet (the src/: clock.rs is a stub, entropy.rs and fixture.rs are empty stubs).
// Until then this file FAILS TO COMPILE (unresolved names E0433) — that is the intended RED.

use exv_vpn_domain::identity::{ConnectionBindingDigest, OperationMethod, PrincipalDigest};
use exv_vpn_domain::limits::{validate_limits, MvpLimits};
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, Clock, EntropySource, JournalRevision,
    MonotonicTick, PlatformAuthorityInstanceId,
};
use exv_vpn_resource::authority::ConnectionBinding;
use exv_vpn_resource::journal::{decode, encode, DecodeOutcome, JournalRecord};
use exv_vpn_testkit::clock::ScriptedClock;
use exv_vpn_testkit::entropy::ScriptedEntropy;
use exv_vpn_testkit::fixture::{authority_fence, mvp_limits, peer_capability, peer_context};
use uuid::Uuid;

fn tick(v: u64) -> MonotonicTick {
    MonotonicTick::try_from(v).expect("in-range tick")
}

// ---- clock -------------------------------------------------------------------------------------

/// `from_script([t1,t2,t3])` yields t1,t2,t3 in order.
/// Kills: "returns ticks out of order".
#[test]
fn scripted_clock_returns_script_in_order() {
    let clock = ScriptedClock::from_script(vec![tick(10), tick(20), tick(30)]);
    assert_eq!(clock.monotonic_now(), tick(10));
    assert_eq!(clock.monotonic_now(), tick(20));
    assert_eq!(clock.monotonic_now(), tick(30));
}

/// After the script is exhausted, subsequent calls return the final tick.
/// Kills: "returns a zero/other tick after exhaustion".
#[test]
fn scripted_clock_repeats_last_tick_after_script_exhausted() {
    let clock = ScriptedClock::from_script(vec![tick(7), tick(9)]);
    let _ = clock.monotonic_now(); // 7
    let _ = clock.monotonic_now(); // 9 (script exhausted)
    assert_eq!(clock.monotonic_now(), tick(9));
    assert_eq!(clock.monotonic_now(), tick(9));
}

/// `constant(t)` yields `t` on every call.
/// Kills: "constant returns a different tick".
#[test]
fn constant_clock_always_reports_same_tick() {
    let clock = ScriptedClock::constant(tick(42));
    for _ in 0..5 {
        assert_eq!(clock.monotonic_now(), tick(42));
    }
}

/// The scripted sequence is monotonically non-decreasing (never decreases, even after exhaustion).
/// Kills: "non-monotonic tick".
#[test]
fn scripted_clock_advances_monotonically() {
    let clock = ScriptedClock::from_script(vec![tick(1), tick(2), tick(2), tick(5)]);
    let mut prev = clock.monotonic_now();
    for _ in 0..50 {
        let cur = clock.monotonic_now();
        // cur must not be strictly before prev: `cur.exceeded_by(prev)` is true iff prev > cur.
        assert!(!cur.exceeded_by(prev), "clock moved backwards");
        prev = cur;
    }
}

/// Compile-time check that `ScriptedClock` implements `Clock` and is `Send + Sync`.
/// Kills: "uses Rc<RefCell> interior mutability".
#[test]
fn scripted_clock_is_send_and_sync() {
    fn assert_clock_send_sync<T: Clock + Send + Sync>() {}
    assert_clock_send_sync::<ScriptedClock>();
}

/// Two `from_script` instances with different scripts yield their own sequences.
/// Kills: "shares global script state".
#[test]
fn two_scripted_clocks_are_independent() {
    let a = ScriptedClock::from_script(vec![tick(1), tick(2)]);
    let b = ScriptedClock::from_script(vec![tick(100), tick(200)]);
    assert_eq!(a.monotonic_now(), tick(1));
    assert_eq!(b.monotonic_now(), tick(100));
    assert_eq!(a.monotonic_now(), tick(2));
    assert_eq!(b.monotonic_now(), tick(200));
}

// ---- entropy -----------------------------------------------------------------------------------

/// `from_script([u1,u2,u3])` yields u1,u2,u3 in order.
/// Kills: "returns a different UUID".
#[test]
fn scripted_entropy_returns_uuids_in_order() {
    let u1 = Uuid::from_u128(1);
    let u2 = Uuid::from_u128(2);
    let u3 = Uuid::from_u128(3);
    let ent = ScriptedEntropy::from_script(vec![u1, u2, u3]);
    assert_eq!(ent.next_uuid(), u1);
    assert_eq!(ent.next_uuid(), u2);
    assert_eq!(ent.next_uuid(), u3);
}

/// After the script is exhausted, `next_uuid` returns `Uuid::nil()`.
/// Kills: "panics or repeats first UUID".
#[test]
fn scripted_entropy_returns_nil_after_exhausted() {
    let ent = ScriptedEntropy::from_script(vec![Uuid::from_u128(5)]);
    let _ = ent.next_uuid(); // 5 (script exhausted)
    assert_eq!(ent.next_uuid(), Uuid::nil());
    assert_eq!(ent.next_uuid(), Uuid::nil());
}

/// The same script yields the same sequence across two fresh instances.
/// Kills: "calls Uuid::new_v4()".
#[test]
fn scripted_entropy_is_deterministic_not_os_rng() {
    let script = vec![Uuid::from_u128(1), Uuid::from_u128(2)];
    let a = ScriptedEntropy::from_script(script.clone());
    let b = ScriptedEntropy::from_script(script);
    for _ in 0..6 {
        assert_eq!(a.next_uuid(), b.next_uuid());
    }
}

/// Two instances with different scripts yield their own sequences.
/// Kills: "shares global script state".
#[test]
fn two_scripted_entropy_sources_are_independent() {
    let a = ScriptedEntropy::from_script(vec![Uuid::from_u128(1), Uuid::from_u128(2)]);
    let b = ScriptedEntropy::from_script(vec![Uuid::from_u128(9), Uuid::from_u128(8)]);
    assert_eq!(a.next_uuid(), Uuid::from_u128(1));
    assert_eq!(b.next_uuid(), Uuid::from_u128(9));
    assert_eq!(a.next_uuid(), Uuid::from_u128(2));
    assert_eq!(b.next_uuid(), Uuid::from_u128(8));
}

/// Every scripted UUID is yielded exactly once.
/// Kills: "drops a scripted UUID".
#[test]
fn scripted_entropy_yields_every_scripted_uuid() {
    let script = vec![Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3)];
    let mut ent = ScriptedEntropy::from_script(script.clone());
    let mut collected = Vec::new();
    for _ in 0..script.len() {
        collected.push(ent.next_uuid());
    }
    assert_eq!(collected, script);
}

/// Compile-time check that `ScriptedEntropy` implements `EntropySource` and is `Send + Sync`.
/// Kills: "uses Rc<RefCell>".
#[test]
fn scripted_entropy_is_send_and_sync() {
    fn assert_entropy_send_sync<T: EntropySource + Send + Sync>() {}
    assert_entropy_send_sync::<ScriptedEntropy>();
}

// ---- fixture -----------------------------------------------------------------------------------

/// `peer_context([1;32],[2;32]).principal()` is the principal built from `[1;32]`.
/// Kills: "wrong principal".
#[test]
fn peer_context_returns_principal() {
    let ctx = peer_context([1u8; 32], [2u8; 32]);
    assert!(
        ctx.principal() == &PrincipalDigest::try_from([1u8; 32]).unwrap(),
        "peer_context must surface the declared principal"
    );
}

/// `peer_context(...).connection()` anchors to the connection built from `[2;32]`.
/// Kills: "wrong connection".
#[test]
fn peer_context_returns_connection() {
    let ctx = peer_context([1u8; 32], [2u8; 32]);
    let expected =
        ConnectionBinding::try_from(ConnectionBindingDigest::try_from([2u8; 32]).unwrap()).unwrap();
    assert!(
        ctx.connection() == &expected,
        "peer_context must anchor to the declared connection binding"
    );
}

/// `verify_declared_principal` accepts the authenticated principal and rejects a foreign one.
/// Kills: "verify_declared_principal always true".
#[test]
fn peer_context_verifies_declared_principal() {
    let ctx = peer_context([9u8; 32], [2u8; 32]);
    let own = PrincipalDigest::try_from([9u8; 32]).unwrap();
    let other = PrincipalDigest::try_from([8u8; 32]).unwrap();
    assert!(ctx.verify_declared_principal(&own), "authenticated principal must verify");
    assert!(
        !ctx.verify_declared_principal(&other),
        "a foreign principal must not verify"
    );
}

/// `can_forward_to` is true for the capability's own connection and false for a foreign one.
/// Kills: "capability forwardable".
#[test]
fn peer_capability_anchors_to_its_connection() {
    let ctx = peer_context([1u8; 32], [2u8; 32]);
    let cap = peer_capability(&ctx, OperationMethod::Connect, 1, tick(100));
    let foreign = ConnectionBinding::try_from(
        ConnectionBindingDigest::try_from([0xEEu8; 32]).unwrap(),
    )
    .unwrap();
    assert!(cap.can_forward_to(ctx.connection()), "must forward to its own connection");
    assert!(!cap.can_forward_to(&foreign), "must not forward to a foreign connection");
}

/// A capability bound to tick T is not expired at T and is expired strictly after T.
/// Kills: "never reports expiry".
#[test]
fn peer_capability_expires_at_scripted_tick() {
    let ctx = peer_context([1u8; 32], [2u8; 32]);
    let t = tick(500);
    let cap = peer_capability(&ctx, OperationMethod::Connect, 1, t);
    assert!(!cap.is_expired_at(t), "not expired exactly at the expiry tick");
    assert!(cap.is_expired_at(tick(501)), "expired strictly after the expiry tick");
}

/// `authorizes` admits the matching request before expiry and rejects a wrong operation.
/// Kills: "authorizes unconditionally".
#[test]
fn peer_capability_authorizes_expected_request() {
    let ctx = peer_context([1u8; 32], [2u8; 32]);
    let authority = AuthorityEpoch::try_from(3).unwrap();
    let expires = tick(1000);
    let cap = peer_capability(&ctx, OperationMethod::Connect, 3, expires);
    let now = tick(999);
    assert!(
        cap.authorizes(ctx.principal(), ctx.connection(), OperationMethod::Connect, authority, now),
        "must authorize the matching operation under the matching authority before expiry"
    );
    assert!(
        !cap.authorizes(ctx.principal(), ctx.connection(), OperationMethod::Stop, authority, now),
        "must not authorize a different operation"
    );
}

/// `mvp_limits()` must pass `validate_limits`.
/// Kills: "a budget field zeroed".
#[test]
fn mvp_limits_fixture_passes_validate_limits() {
    let limits: MvpLimits = mvp_limits();
    assert!(
        validate_limits(&limits).is_ok(),
        "fixture MvpLimits must pass validate_limits"
    );
}

/// The queued-connect budget must be at least the cleanup budget.
/// Kills: "inverted budget ordering".
#[test]
fn mvp_limits_fixture_orders_budgets_correctly() {
    let limits: MvpLimits = mvp_limits();
    assert!(
        limits.queued_connect_budget >= limits.normal_cleanup_budget,
        "queued_connect_budget must be >= normal_cleanup_budget"
    );
}

/// `authority_fence(1,0,0)` carries a valid non-nil `platform_authority_instance_id`.
/// Kills: "nil platform instance".
#[test]
fn authority_fence_fixture_is_valid() {
    let fence = authority_fence(1, 0, 0);
    let expected = AuthorityFence {
        authority_epoch: AuthorityEpoch::try_from(1).unwrap(),
        // The fixture mints the canonical non-nil test instance (convention: Uuid 1).
        platform_authority_instance_id: PlatformAuthorityInstanceId::try_from(Uuid::from_u128(1))
            .unwrap(),
        admission_watermark: AdmissionWatermark::try_from(0).unwrap(),
        journal_revision: JournalRevision::try_from(0).unwrap(),
    };
    assert!(
        fence == expected,
        "authority_fence must mint a valid non-nil platform authority instance"
    );
}

/// `authority_fence(5,7,9)` carries epoch 5, watermark 7, revision 9.
/// Kills: "wrong epoch/watermark/revision".
#[test]
fn authority_fence_fixture_fields_match_script() {
    let fence = authority_fence(5, 7, 9);
    assert!(fence.authority_epoch == AuthorityEpoch::try_from(5).unwrap(), "wrong epoch");
    assert!(
        fence.admission_watermark == AdmissionWatermark::try_from(7).unwrap(),
        "wrong watermark"
    );
    assert!(fence.journal_revision == JournalRevision::try_from(9).unwrap(), "wrong revision");
}

// For arbitrary (sequence, previous_digest, payload), encode→decode round-trips to a single
// Clean record whose fields match the original.
// Kills: "encode drops bytes / decode skips verification".
proptest::proptest! {
    #[test]
    fn journal_codec_round_trip_property(
        sequence in 0u64..1000,
        previous_digest in proptest::array::uniform32(proptest::arbitrary::any::<u8>()),
        payload in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..4096),
    ) {
        let rec = JournalRecord::new(sequence, previous_digest, payload.clone());
        let bytes = encode(&rec);
        assert!(
            matches!(&decode(&bytes), DecodeOutcome::Clean(records)
                if records.len() == 1
                    && records[0].sequence == rec.sequence
                    && records[0].previous_digest == rec.previous_digest
                    && records[0].payload == rec.payload
                    && records[0].digest == rec.digest),
            "encode→decode must preserve every record field"
        );
    }
}

// For arbitrary (sequence, previous_digest, payload), the decoded record's payload and digest
// equal the original (the digest is recomputed, never trusted).
// Kills: "decode accepts a mismatched digest".
proptest::proptest! {
    #[test]
    fn journal_codec_round_trip_preserves_payload_and_digest(
        sequence in 0u64..1000,
        previous_digest in proptest::array::uniform32(proptest::arbitrary::any::<u8>()),
        payload in proptest::collection::vec(proptest::arbitrary::any::<u8>(), 0..4096),
    ) {
        let rec = JournalRecord::new(sequence, previous_digest, payload);
        let bytes = encode(&rec);
        assert!(
            matches!(&decode(&bytes), DecodeOutcome::Clean(records)
                if records.len() == 1
                    && records[0].payload == rec.payload
                    && records[0].digest == rec.digest),
            "the decoded record must preserve the payload and recomputed digest"
        );
    }
}