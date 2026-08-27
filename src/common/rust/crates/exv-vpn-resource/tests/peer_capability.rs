// RED tests for the §9.4 authenticated-transport peer capability model (Architecture spec,
// vpn-rust-native-runtime-mvp, L1360-1363).
// PURE, deterministic: no I/O, no filesystem, no sleep, no randomness — identifiers come only from
// fixed byte arrays.
//
// The production seam `exv_vpn_resource::authority` does not exist yet; X70-I implements it.
// Until then this file FAILS TO COMPILE (unresolved imports of ConnectionBinding, PeerContext,
// PeerCapability, VerifiedConnectionMetadata) — that is the intended RED.

use exv_vpn_domain::identity::{ConnectionBindingDigest, OperationMethod, PrincipalDigest};
use exv_vpn_domain::ports::{AuthorityEpoch, MonotonicTick};
use exv_vpn_resource::authority::{
    ConnectionBinding, PeerCapability, PeerContext, VerifiedConnectionMetadata,
};

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

/// Deterministic connection binding that differs across `n`.
fn binding(n: u8) -> ConnectionBinding {
    let connection_digest = ConnectionBindingDigest::try_from(digest(n)).expect("digest");
    ConnectionBinding::try_from(connection_digest).expect("binding")
}

/// Deterministic authority epoch for the given `n`.
fn epoch(n: u64) -> AuthorityEpoch {
    AuthorityEpoch::try_from(n).expect("epoch")
}

/// Deterministic monotonic tick for the given `n`.
fn tick(n: u64) -> MonotonicTick {
    MonotonicTick::try_from(n).expect("tick")
}

/// A verified peer context authenticating `p` over the connection bound to digest `d`.
fn peer(p: PrincipalDigest, d: [u8; 32]) -> PeerContext {
    let connection_digest = ConnectionBindingDigest::try_from(d).expect("digest");
    let metadata = VerifiedConnectionMetadata::try_from((p, connection_digest))
        .expect("verified metadata");
    PeerContext::try_from(metadata).expect("peer context")
}

/// PeerContext must reject a peer-provided principal; only the authenticated one verifies.
/// Kills: 'accepts a self-reported principal'.
#[test]
fn peer_context_rejects_self_reported_principal() {
    let ctx = peer(principal(1), digest(7));
    assert!(
        !ctx.verify_declared_principal(&principal(2)),
        "a self-reported principal must not override the authenticated one"
    );
    assert!(
        ctx.verify_declared_principal(ctx.principal()),
        "the authenticated principal must verify"
    );
}

/// PeerContext surfaces ONLY the authenticated principal, never a declared/other one.
/// Kills: 'lets a declared/other principal override the authenticated one'.
#[test]
fn peer_context_principal_is_authenticated_only() {
    let ctx = peer(principal(1), digest(7));
    assert!(
        ctx.principal() == &principal(1),
        "the peer must carry the authenticated principal, not any declared one"
    );
}

/// A capability forwards only to its own connection binding, never to another.
/// Kills: 'capability forwarded to a different connection'.
#[test]
fn capability_cannot_forward_to_other_connection() {
    let ctx = peer(principal(1), digest(7));
    let cap = ctx
        .bind_capability(OperationMethod::Connect, epoch(1), tick(100))
        .expect("bind capability");
    assert!(
        cap.can_forward_to(ctx.connection()),
        "a capability must forward to its own binding"
    );
    assert!(
        !cap.can_forward_to(&binding(8)),
        "a capability must never forward to a different binding"
    );
}

/// authorizes must reject a matching request that targets a different connection.
/// Kills: 'ignores connection'.
#[test]
fn authorizes_rejects_foreign_connection() {
    let ctx = peer(principal(1), digest(7));
    let cap = ctx
        .bind_capability(OperationMethod::Connect, epoch(1), tick(100))
        .expect("bind capability");
    assert!(
        !cap.authorizes(
            ctx.principal(),
            &binding(8),
            OperationMethod::Connect,
            epoch(1),
            tick(50)
        ),
        "a capability must reject a different connection"
    );
}

/// authorizes must reject a capability once the clock is strictly past its expiry.
/// Kills: 'ignores expiry'.
#[test]
fn authorizes_rejects_expired_capability() {
    let ctx = peer(principal(1), digest(7));
    let cap = ctx
        .bind_capability(OperationMethod::Connect, epoch(1), tick(100))
        .expect("bind capability");
    assert!(
        !cap.authorizes(
            ctx.principal(),
            ctx.connection(),
            OperationMethod::Connect,
            epoch(1),
            tick(101)
        ),
        "a capability past its expiry must not authorize"
    );
    assert!(
        cap.authorizes(
            ctx.principal(),
            ctx.connection(),
            OperationMethod::Connect,
            epoch(1),
            tick(100)
        ),
        "a capability at its deadline must authorize"
    );
}

/// is_expired_at is strict: at the deadline it is not (yet) expired; after it is.
/// Kills: 'never reports expiry'.
#[test]
fn capability_is_expired_at_deadline() {
    let ctx = peer(principal(1), digest(7));
    let cap = ctx
        .bind_capability(OperationMethod::Connect, epoch(1), tick(100))
        .expect("bind capability");
    assert!(
        !cap.is_expired_at(tick(100)),
        "at the deadline the capability is not yet expired"
    );
    assert!(
        cap.is_expired_at(tick(101)),
        "strictly after the deadline the capability is expired"
    );
}

/// authorizes must reject a request whose operation differs from the bound one.
/// Kills: 'binds only principal, not operation'.
#[test]
fn authorizes_rejects_wrong_operation() {
    let ctx = peer(principal(1), digest(7));
    let cap = ctx
        .bind_capability(OperationMethod::Connect, epoch(1), tick(100))
        .expect("bind capability");
    assert!(
        !cap.authorizes(
            ctx.principal(),
            ctx.connection(),
            OperationMethod::Stop,
            epoch(1),
            tick(50)
        ),
        "a Connect-bounded capability must reject Stop"
    );
    assert!(
        cap.authorizes(
            ctx.principal(),
            ctx.connection(),
            OperationMethod::Connect,
            epoch(1),
            tick(50)
        ),
        "a capability must authorize its bound operation"
    );
}

/// authorizes must reject a request under a different authority epoch.
/// Kills: 'binds only principal, not authority'.
#[test]
fn authorizes_rejects_wrong_authority() {
    let ctx = peer(principal(1), digest(7));
    let cap = ctx
        .bind_capability(OperationMethod::Connect, epoch(1), tick(100))
        .expect("bind capability");
    assert!(
        !cap.authorizes(
            ctx.principal(),
            ctx.connection(),
            OperationMethod::Connect,
            epoch(2),
            tick(50)
        ),
        "a capability must reject a different authority epoch"
    );
    assert!(
        cap.authorizes(
            ctx.principal(),
            ctx.connection(),
            OperationMethod::Connect,
            epoch(1),
            tick(50)
        ),
        "a capability must authorize its bound authority epoch"
    );
}

/// A capability is anchored to the verified connection digest only — never an endpoint name/path.
/// Kills: 'endpoint name/path treated as a capability'.
#[test]
fn endpoint_name_is_not_a_capability() {
    let ctx = peer(principal(1), digest(7));
    let cap = ctx
        .bind_capability(OperationMethod::Connect, epoch(1), tick(100))
        .expect("bind capability");
    assert!(
        cap.connection() == ctx.connection(),
        "a capability must be anchored to the verified connection digest only, never an endpoint name/path"
    );
}

/// authorizes must reject a principal other than the capability's owner.
/// Kills: 'grants any principal'.
#[test]
fn authorizes_rejects_unauthorized_principal() {
    let ctx = peer(principal(1), digest(7));
    let cap = ctx
        .bind_capability(OperationMethod::Connect, epoch(1), tick(100))
        .expect("bind capability");
    assert!(
        !cap.authorizes(
            &principal(2),
            ctx.connection(),
            OperationMethod::Connect,
            epoch(1),
            tick(50)
        ),
        "a capability must reject a principal other than its owner"
    );
    assert!(
        cap.authorizes(
            ctx.principal(),
            ctx.connection(),
            OperationMethod::Connect,
            epoch(1),
            tick(50)
        ),
        "a capability must authorize its owner principal"
    );
}