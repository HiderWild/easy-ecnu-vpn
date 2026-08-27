// X71K-T kernel control-plane adapter tests.
//
// Pinned seam (X71K-I, src/kernel.rs): the adapter binds a wire request to a
// domain operation whose identity is a function of the AUTHENTICATED peer
// principal only (never the self-reported wire principal), rejecting
// out-of-scope methods, capabilities that do not authorize the request,
// authority-epoch mismatches, and expired capabilities.
//
// This file is RED / test-only: it exists to fail-to-compile against the
// empty `kernel` module until X71K-I implements the seam. PURE + deterministic:
// no I/O, no sleep, no randomness; fixed byte literal inputs only.

use exv_vpn_domain::identity::{
    canonical_lookup_digest, ConnectionBindingDigest, OperationMethod, PrincipalDigest,
    RequestDigest,
};
use exv_vpn_domain::ports::{AuthorityEpoch, MonotonicTick};
use exv_vpn_local_rpc::kernel::{kernel_request_to_operation, BoundKernelOperation, KernelRequest};
use exv_vpn_resource::authority::{PeerCapability, PeerContext, VerifiedConnectionMetadata};
use exv_vpn_wire::convert::lookup_key_from_wire;
use exv_vpn_wire::generated;

// ---------------------------------------------------------------------------
// Deterministic builders (fixed literals only)
// ---------------------------------------------------------------------------

fn principal(byte: u8) -> PrincipalDigest {
    PrincipalDigest::try_from([byte; 32]).expect("32-byte principal")
}

fn conn_binding(byte: u8) -> ConnectionBindingDigest {
    ConnectionBindingDigest::try_from([byte; 32]).expect("32-byte connection digest")
}

/// Authenticated peer context { principal=[byte;32], connection=[conn;32] }.
fn peer(principal_byte: u8, conn_byte: u8) -> PeerContext {
    let metadata =
        VerifiedConnectionMetadata::try_from((principal(principal_byte), conn_binding(conn_byte)))
            .expect("verified metadata");
    PeerContext::try_from(metadata).expect("peer context")
}

/// A wire lookup key carrying a self-reported principal; identity is never
/// derived from this field.
fn wire_key(self_reported_principal: u8, method: generated::OperationMethod) -> generated::OperationLookupKey {
    generated::OperationLookupKey {
        principal_digest: vec![self_reported_principal; 32],
        method: method as i32,
        runtime_epoch: vec![1u8; 16],
        operation_id: vec![2u8; 16],
    }
}

const AUTH_EPOCH: u64 = 3;
const NOW: u64 = 50;
const FAR_FUTURE: u64 = 1000;
const REQUEST_DIGEST: u8 = 7;

// ---------------------------------------------------------------------------
// 1. The adapter must NOT trust a self-reported wire principal.
// ---------------------------------------------------------------------------
#[test]
fn kernel_adapter_ignores_self_reported_wire_principal() {
    let peer = peer(1, 2); // authenticated principal = 1
    let cap = peer
        .bind_capability(
            OperationMethod::Connect,
            AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
            MonotonicTick::try_from(FAR_FUTURE).unwrap(),
        )
        .expect("capability");
    let key = wire_key(200, generated::OperationMethod::Connect); // self-reported = 200
    let request = KernelRequest::new(key.clone(), vec![REQUEST_DIGEST; 32], OperationMethod::Connect);

    let bound = kernel_request_to_operation(
        &request,
        &peer,
        &cap,
        AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
        MonotonicTick::try_from(NOW).unwrap(),
    );

    assert!(matches!(bound, Ok(_)), "self-reported wire principal must not be trusted");
    let bound = bound.unwrap();

    // Identity derives from the AUTHENTICATED principal (1), ...
    let auth_key = lookup_key_from_wire(&key, principal(1)).unwrap();
    assert_eq!(
        canonical_lookup_digest(&bound.lookup_key),
        canonical_lookup_digest(&auth_key),
        "bound identity must match the authenticated-principal key"
    );
    // ... and differs from the key that the self-reported principal (200) would produce.
    let self_reported_key = lookup_key_from_wire(&key, principal(200)).unwrap();
    assert_ne!(
        canonical_lookup_digest(&bound.lookup_key),
        canonical_lookup_digest(&self_reported_key),
        "self-reported wire principal must not affect bound identity"
    );
}

// ---------------------------------------------------------------------------
// 2. A capability for a different principal must not authorize the peer.
// ---------------------------------------------------------------------------
#[test]
fn rejects_unauthorized_peer() {
    let peer = peer(1, 2); // authenticated principal = 1
    let other_principal = principal(5);
    let cap = PeerCapability::try_from((
        peer.connection().clone(),
        other_principal, // capability bound to a DIFFERENT principal
        AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
        OperationMethod::Connect,
        MonotonicTick::try_from(FAR_FUTURE).unwrap(),
    ))
    .expect("capability");

    let request = KernelRequest::new(
        wire_key(1, generated::OperationMethod::Connect),
        vec![REQUEST_DIGEST; 32],
        OperationMethod::Connect,
    );

    let result = kernel_request_to_operation(
        &request,
        &peer,
        &cap,
        AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
        MonotonicTick::try_from(NOW).unwrap(),
    );

    assert!(matches!(result, Err(_)), "a capability for another principal must reject");
}

// ---------------------------------------------------------------------------
// 3. Bound identity is a function of the authenticated principal only.
// ---------------------------------------------------------------------------
#[test]
fn bound_identity_is_function_of_authenticated_principal_only() {
    let peer = peer(1, 2); // same authenticated peer for both requests
    let cap = peer
        .bind_capability(
            OperationMethod::Connect,
            AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
            MonotonicTick::try_from(FAR_FUTURE).unwrap(),
        )
        .expect("capability");

    // Identical except the self-reported wire principal field (9 vs 10).
    let request_a =
        KernelRequest::new(wire_key(9, generated::OperationMethod::Connect), vec![REQUEST_DIGEST; 32], OperationMethod::Connect);
    let request_b =
        KernelRequest::new(wire_key(10, generated::OperationMethod::Connect), vec![REQUEST_DIGEST; 32], OperationMethod::Connect);

    let op_a = kernel_request_to_operation(
        &request_a,
        &peer,
        &cap,
        AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
        MonotonicTick::try_from(NOW).unwrap(),
    )
    .unwrap();
    let op_b = kernel_request_to_operation(
        &request_b,
        &peer,
        &cap,
        AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
        MonotonicTick::try_from(NOW).unwrap(),
    )
    .unwrap();

    assert_eq!(
        canonical_lookup_digest(&op_a.lookup_key),
        canonical_lookup_digest(&op_b.lookup_key),
        "self-reported principal must not change the bound identity"
    );
}

// ---------------------------------------------------------------------------
// 4. An out-of-scope operation (wire method != expected method) is rejected.
// ---------------------------------------------------------------------------
#[test]
fn rejects_out_of_scope_operation() {
    let peer = peer(1, 2);
    let cap = peer
        .bind_capability(
            OperationMethod::Connect, // capability matches the WIRE method
            AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
            MonotonicTick::try_from(FAR_FUTURE).unwrap(),
        )
        .expect("capability");

    // Stop RPC carrying a wire key whose method is Connect.
    let request = KernelRequest::new(
        wire_key(1, generated::OperationMethod::Connect),
        vec![REQUEST_DIGEST; 32],
        OperationMethod::Stop,
    );

    let result = kernel_request_to_operation(
        &request,
        &peer,
        &cap,
        AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
        MonotonicTick::try_from(NOW).unwrap(),
    );

    assert!(matches!(result, Err(_)), "out-of-scope operation must be rejected");
}

// ---------------------------------------------------------------------------
// 5. A request forbidden by the capability is rejected.
// ---------------------------------------------------------------------------
#[test]
fn rejects_operation_forbidden_by_capability() {
    let peer = peer(1, 2);
    let cap = peer
        .bind_capability(
            OperationMethod::Connect, // capability covers ONLY Connect
            AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
            MonotonicTick::try_from(FAR_FUTURE).unwrap(),
        )
        .expect("capability");

    // A Stop request, not covered by the capability.
    let request = KernelRequest::new(
        wire_key(1, generated::OperationMethod::Stop),
        vec![REQUEST_DIGEST; 32],
        OperationMethod::Stop,
    );

    let result = kernel_request_to_operation(
        &request,
        &peer,
        &cap,
        AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
        MonotonicTick::try_from(NOW).unwrap(),
    );

    assert!(matches!(result, Err(_)), "a capability-forbidden operation must be rejected");
}

// ---------------------------------------------------------------------------
// 6. An authority-epoch mismatch is rejected.
// ---------------------------------------------------------------------------
#[test]
fn rejects_authority_mismatch() {
    let peer = peer(1, 2);
    let cap = peer
        .bind_capability(
            OperationMethod::Connect,
            AuthorityEpoch::try_from(99).unwrap(), // capability bound to epoch 99
            MonotonicTick::try_from(FAR_FUTURE).unwrap(),
        )
        .expect("capability");

    let request = KernelRequest::new(
        wire_key(1, generated::OperationMethod::Connect),
        vec![REQUEST_DIGEST; 32],
        OperationMethod::Connect,
    );

    let result = kernel_request_to_operation(
        &request,
        &peer,
        &cap,
        AuthorityEpoch::try_from(3).unwrap(), // runtime current epoch = 3
        MonotonicTick::try_from(NOW).unwrap(),
    );

    assert!(matches!(result, Err(_)), "authority-epoch mismatch must be rejected");
}

// ---------------------------------------------------------------------------
// 7. An expired capability is rejected.
// ---------------------------------------------------------------------------
#[test]
fn rejects_expired_capability() {
    let peer = peer(1, 2);
    let cap = peer
        .bind_capability(
            OperationMethod::Connect,
            AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
            MonotonicTick::try_from(60).unwrap(), // expires at tick 60
        )
        .expect("capability");

    let request = KernelRequest::new(
        wire_key(1, generated::OperationMethod::Connect),
        vec![REQUEST_DIGEST; 32],
        OperationMethod::Connect,
    );

    let result = kernel_request_to_operation(
        &request,
        &peer,
        &cap,
        AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
        MonotonicTick::try_from(100).unwrap(), // now = tick 100
    );

    assert!(matches!(result, Err(_)), "an expired capability must be rejected");
}

// ---------------------------------------------------------------------------
// 8. Positive control: a valid, unexpired, authorized operation is accepted.
// ---------------------------------------------------------------------------
#[test]
fn accepts_authorized_operation() {
    let peer = peer(1, 2);
    let cap = peer
        .bind_capability(
            OperationMethod::Connect,
            AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
            MonotonicTick::try_from(FAR_FUTURE).unwrap(),
        )
        .expect("capability");
    let key = wire_key(1, generated::OperationMethod::Connect);
    let request = KernelRequest::new(key.clone(), vec![REQUEST_DIGEST; 32], OperationMethod::Connect);

    let result = kernel_request_to_operation(
        &request,
        &peer,
        &cap,
        AuthorityEpoch::try_from(AUTH_EPOCH).unwrap(),
        MonotonicTick::try_from(NOW).unwrap(),
    );

    assert!(matches!(result, Ok(_)), "an authorized operation must be accepted");
    let bound = result.unwrap();

    // The bound request digest is the caller-supplied digest.
    assert_eq!(
        bound.request_digest,
        RequestDigest::try_from([REQUEST_DIGEST; 32]).unwrap(),
        "bound request digest must match the supplied digest"
    );

    // The bound lookup key's identity matches the key built from the authenticated principal.
    let auth_key = lookup_key_from_wire(&key, principal(1)).unwrap();
    assert_eq!(
        canonical_lookup_digest(&bound.lookup_key),
        canonical_lookup_digest(&auth_key),
        "bound identity must match the authenticated-principal key"
    );
}