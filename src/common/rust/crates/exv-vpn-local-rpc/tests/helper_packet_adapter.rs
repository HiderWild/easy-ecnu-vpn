// X71H-T helper packet adapter tests (spec L1011/L1012/L1296/L1300/L1301/L1363, TG-06).
//
// Pinned seam (X71H-I, src/packet.rs): `HelperPacketAdapter` binds a one-shot
// packet capability to the attached peer, rejects a second attach, refuses an
// expired / cross-principal / cross-connection capability, gates teardown on
// BOTH sides actually joining the barrier, refuses `release` until the barrier
// is released AND the retirement CleanProof is clean, and admits data-plane
// frames only for the current ownership version.
//
// This file is RED / test-only: it references the empty `packet` module and must
// fail to compile until X71H-I implements the seam. PURE + deterministic: no I/O,
// no sleep, no randomness; fixed byte/u64 literals only.

use exv_vpn_local_rpc::packet::HelperPacketAdapter;

use std::time::Duration;
use uuid::Uuid;

use exv_vpn_data_plane::budget::DataPlaneDirection;
use exv_vpn_data_plane::teardown::{JoinOutcome, TeardownSide};
use exv_vpn_domain::error::ErrorCode;
use exv_vpn_domain::identity::{
    ConnectionBindingDigest, EvidenceDigest, InventoryDigest, OperationMethod, OwnershipVersion,
    PrincipalDigest, RetirementOperationId, RuntimeEpoch,
};
use exv_vpn_domain::limits::MvpLimits;
use exv_vpn_domain::ports::{
    AuthorityEpoch, CleanProof, CleanupTriggerDigest, JournalRevision, JournalRootDigest,
    MonotonicTick, PlatformAuthorityInstanceId, VersionedPlatformEvidence,
};
use exv_vpn_resource::authority::{
    ConnectionBinding, PeerCapability, PeerContext, VerifiedConnectionMetadata,
};

// ---------------------------------------------------------------------------
// Deterministic builders (fixed literals only)
// ---------------------------------------------------------------------------

const NOW: u64 = 50;
const FAR_FUTURE: u64 = 1000;

fn principal(byte: u8) -> PrincipalDigest {
    PrincipalDigest::try_from([byte; 32]).expect("32-byte principal")
}

fn conn_binding(byte: u8) -> ConnectionBindingDigest {
    ConnectionBindingDigest::try_from([byte; 32]).expect("32-byte connection digest")
}

/// Authenticated peer context { principal=[p;32], connection=[c;32] }.
fn peer(principal_byte: u8, conn_byte: u8) -> PeerContext {
    let metadata =
        VerifiedConnectionMetadata::try_from((principal(principal_byte), conn_binding(conn_byte)))
            .expect("verified metadata");
    PeerContext::try_from(metadata).expect("peer context")
}

/// Fixed non-nil runtime epoch (never new_v4).
fn epoch() -> RuntimeEpoch {
    RuntimeEpoch::try_from(Uuid::from_u128(1)).expect("non-nil runtime epoch")
}

fn authority() -> AuthorityEpoch {
    AuthorityEpoch::try_from(3).expect("authority epoch")
}

fn ownership(v: u64) -> OwnershipVersion {
    OwnershipVersion::try_from(v).expect("nonzero ownership version")
}

fn now() -> MonotonicTick {
    MonotonicTick::try_from(NOW).expect("now tick")
}

fn far_future() -> MonotonicTick {
    MonotonicTick::try_from(FAR_FUTURE).expect("future tick")
}

/// A packet-attach capability bound to `peer`, valid until tick 1000.
fn attach_capability(peer: &PeerContext) -> PeerCapability {
    peer.bind_capability(OperationMethod::ApplyTunnel, authority(), far_future())
        .expect("capability")
}

/// Small packet knobs, real durations (see Q60 tests).
fn base_limits() -> MvpLimits {
    MvpLimits {
        normal_mailbox_messages: 16,
        completion_mailbox_messages: 16,
        stop_waiters: 4,
        snapshot_receivers: 4,
        packet_queue_messages: 4,
        packet_queue_bytes: 1024,
        max_packet_batch_packets: 2,
        max_packet_batch_bytes: 512,
        max_control_message_bytes: 256,
        max_packet_message_bytes: 256,
        normal_cleanup_budget: Duration::from_secs(30),
        queued_connect_budget: Duration::from_secs(60),
        owner_lease_ttl: Duration::from_secs(120),
        packet_loss_cleanup_grace: Duration::from_secs(5),
    }
}

/// A CleanProof with the given unresolved-obligation count (0 == clean).
fn proof_with_unresolved(count: u32) -> CleanProof {
    CleanProof {
        runtime_epoch: epoch(),
        platform_authority_instance: PlatformAuthorityInstanceId::try_from(Uuid::from_u128(2))
            .expect("non-nil instance id"),
        prior_ownership_version: ownership(4),
        prior_platform_ownership_token_digest_if_issued: None,
        retirement_operation_id: RetirementOperationId::try_from(Uuid::from_u128(3))
            .expect("non-nil retirement id"),
        cleanup_trigger_digest: CleanupTriggerDigest::try_from([0x21; 32])
            .expect("cleanup trigger digest"),
        external_trigger_operation_identity_digest_if_present: None,
        canonical_obligation_inventory_digest: InventoryDigest::try_from([0x22; 32])
            .expect("inventory digest"),
        journal_root_or_projection_digest: JournalRootDigest::try_from([0x23; 32])
            .expect("journal root digest"),
        journal_revision: JournalRevision::try_from(1).expect("journal revision"),
        platform_evidence: VersionedPlatformEvidence {
            kind_version: 1,
            digest: EvidenceDigest::try_from([0x24; 32]).expect("evidence digest"),
        },
        unresolved_obligation_count: count,
    }
}

fn clean_proof() -> CleanProof {
    proof_with_unresolved(0)
}

// ---------------------------------------------------------------------------
// 1. A second packet attach is rejected.
// ---------------------------------------------------------------------------
#[test]
fn second_attach_is_rejected() {
    let peer = peer(1, 2);
    let cap = attach_capability(&peer);
    let mut adapter =
        HelperPacketAdapter::new(epoch(), authority(), ownership(5), cap, &base_limits())
            .expect("adapter");
    assert!(adapter.attach(&peer, now()).is_ok(), "first attach must succeed");
    let err = adapter
        .attach(&peer, now())
        .expect_err("second attach must be rejected");
    assert_eq!(*err.code(), ErrorCode::PacketLeaseAlreadyAttached);
}

// ---------------------------------------------------------------------------
// 2. Attach without a valid capability (bound to a different principal) is rejected.
// ---------------------------------------------------------------------------
#[test]
fn attach_without_valid_capability_is_rejected() {
    let peer = peer(1, 2); // authenticated principal = 1
    let cap = PeerCapability::try_from((
        peer.connection().clone(),
        principal(5), // capability bound to principal 5
        authority(),
        OperationMethod::ApplyTunnel,
        far_future(),
    ))
    .expect("capability");
    let mut adapter =
        HelperPacketAdapter::new(epoch(), authority(), ownership(5), cap, &base_limits())
            .expect("adapter");
    let err = adapter
        .attach(&peer, now())
        .expect_err("attach without a valid capability must be rejected");
    assert_eq!(*err.code(), ErrorCode::Unauthorized);
}

// ---------------------------------------------------------------------------
// 3. A capability does not forward across connections.
// ---------------------------------------------------------------------------
#[test]
fn attach_for_different_connection_is_rejected() {
    let peer = peer(1, 2); // peer on connection 2
    let cap = PeerCapability::try_from((
        ConnectionBinding::try_from(conn_binding(3)).expect("connection binding"), // anchored to 3
        peer.principal().clone(),
        authority(),
        OperationMethod::ApplyTunnel,
        far_future(),
    ))
    .expect("capability");
    let mut adapter =
        HelperPacketAdapter::new(epoch(), authority(), ownership(5), cap, &base_limits())
            .expect("adapter");
    let err = adapter
        .attach(&peer, now())
        .expect_err("capability forwarding across connections must be rejected");
    assert_eq!(*err.code(), ErrorCode::Unauthorized);
}

// ---------------------------------------------------------------------------
// 4. Teardown is not released before BOTH sides join.
// ---------------------------------------------------------------------------
#[test]
fn teardown_not_released_before_both_sides_join() {
    let peer = peer(1, 2);
    let cap = attach_capability(&peer);
    let mut adapter =
        HelperPacketAdapter::new(epoch(), authority(), ownership(5), cap, &base_limits())
            .expect("adapter");
    assert_eq!(
        adapter.join_teardown(TeardownSide::ProtocolControl),
        JoinOutcome::Pending,
        "a single-sided join must stay pending"
    );
    assert!(!adapter.is_teardown_released(), "barrier must not be released yet");
}

// ---------------------------------------------------------------------------
// 5. Teardown releases once both sides join (positive control).
// ---------------------------------------------------------------------------
#[test]
fn teardown_released_once_both_sides_join() {
    let peer = peer(1, 2);
    let cap = attach_capability(&peer);
    let mut adapter =
        HelperPacketAdapter::new(epoch(), authority(), ownership(5), cap, &base_limits())
            .expect("adapter");
    assert_eq!(adapter.join_teardown(TeardownSide::ProtocolControl), JoinOutcome::Pending);
    assert_eq!(adapter.join_teardown(TeardownSide::PacketData), JoinOutcome::Released);
    assert!(adapter.is_teardown_released(), "release requires both joins");
}

// ---------------------------------------------------------------------------
// 6. Release is rejected without a clean retirement CleanProof.
// ---------------------------------------------------------------------------
#[test]
fn release_rejected_without_clean_proof() {
    let peer = peer(1, 2);
    let cap = attach_capability(&peer);
    let mut adapter =
        HelperPacketAdapter::new(epoch(), authority(), ownership(5), cap, &base_limits())
            .expect("adapter");
    adapter.join_teardown(TeardownSide::ProtocolControl);
    adapter.join_teardown(TeardownSide::PacketData);
    assert!(adapter.is_teardown_released());
    let err = adapter
        .release(&proof_with_unresolved(3))
        .expect_err("release with unresolved obligations must be rejected");
    assert_eq!(err, "clean proof: unresolved obligation count must be zero");
}

// ---------------------------------------------------------------------------
// 7. Release requires the helper to have joined the barrier.
// ---------------------------------------------------------------------------
#[test]
fn release_requires_helper_joined_barrier() {
    let peer = peer(1, 2);
    let cap = attach_capability(&peer);
    let mut adapter =
        HelperPacketAdapter::new(epoch(), authority(), ownership(5), cap, &base_limits())
            .expect("adapter");
    // The barrier is never joined; release must be refused even with a clean proof.
    let err = adapter
        .release(&clean_proof())
        .expect_err("release before the barrier is released must be rejected");
    assert_eq!(err, "teardown barrier");
}

// ---------------------------------------------------------------------------
// 8. An expired capability cannot attach.
// ---------------------------------------------------------------------------
#[test]
fn expired_capability_attach_is_rejected() {
    let peer = peer(1, 2);
    let cap = PeerCapability::try_from((
        peer.connection().clone(),
        peer.principal().clone(),
        authority(),
        OperationMethod::ApplyTunnel,
        MonotonicTick::try_from(60).expect("expiry tick"), // expires at tick 60
    ))
    .expect("capability");
    let mut adapter =
        HelperPacketAdapter::new(epoch(), authority(), ownership(5), cap, &base_limits())
            .expect("adapter");
    let err = adapter
        .attach(&peer, MonotonicTick::try_from(100).expect("now=100"))
        .expect_err("expired capability must be rejected");
    assert_eq!(*err.code(), ErrorCode::Unauthorized);
}

// ---------------------------------------------------------------------------
// 9. An old-ownership frame is rejected.
// ---------------------------------------------------------------------------
#[test]
fn old_ownership_frame_is_rejected() {
    let peer = peer(1, 2);
    let cap = attach_capability(&peer);
    let mut adapter =
        HelperPacketAdapter::new(epoch(), authority(), ownership(5), cap, &base_limits())
            .expect("adapter");
    assert!(adapter.attach(&peer, now()).is_ok(), "attach must succeed");
    let result = adapter.admit_owned_frame(
        DataPlaneDirection::PacketToProtocol,
        1,
        100,
        ownership(4), // older than the current ownership version 5
    );
    assert!(result.is_err(), "an old-ownership frame must be rejected");
}

// ---------------------------------------------------------------------------
// 10. A valid attach admits a current-ownership frame (positive control).
// ---------------------------------------------------------------------------
#[test]
fn valid_attach_and_current_ownership_frame_admitted() {
    let peer = peer(1, 2);
    let cap = attach_capability(&peer);
    let mut adapter =
        HelperPacketAdapter::new(epoch(), authority(), ownership(5), cap, &base_limits())
            .expect("adapter");
    assert!(adapter.attach(&peer, now()).is_ok(), "attach must succeed");
    let result = adapter.admit_owned_frame(
        DataPlaneDirection::PacketToProtocol,
        1,
        100,
        ownership(5), // matches the current ownership version
    );
    assert!(result.is_ok(), "a current-ownership frame must be admitted");
}