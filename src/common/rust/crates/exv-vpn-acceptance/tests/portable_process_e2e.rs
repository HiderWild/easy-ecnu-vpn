// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! E89 portable-side acceptance anchor: a fake process that runs
//! connect -> connected -> data -> disconnect end-to-end (spec TG-07 L1451, L1598).
//!
//! PURE + deterministic: no I/O, no real sockets, no sleep, no randomness. The production
//! testkit process driver (`exv_vpn_testkit::process`) is not yet implemented, so this file
//! intentionally does NOT compile (resolves to the pinned seam) — the RED tests for E89-I.

use exv_vpn_data_plane::budget::{AdmissionVerdict, DataPlaneDirection};
use exv_vpn_data_plane::pump::{DirectionReadiness, PollDecision};
use exv_vpn_data_plane::teardown::{JoinOutcome, TeardownSide};
use exv_vpn_domain::identity::{
    InventoryDigest, OperationMethod, OwnershipVersion, RetirementOperationId, RuntimeEpoch,
};
use exv_vpn_domain::ports::MonotonicTick;
use exv_vpn_host::composition::{HostEffect, HostPhase};
use exv_vpn_resource::retirement::InventoryPredicate;
use exv_vpn_testkit::fixture::{authority_fence, mvp_limits, peer_capability, peer_context};
use exv_vpn_testkit::process::{FakeProcessDriver, ProcessPhase};
use uuid::Uuid;

/// A fresh fake-process driver pinned to the canonical MVP limits and authority fence.
fn fresh_driver() -> FakeProcessDriver {
    FakeProcessDriver::new(
        &mvp_limits(),
        RuntimeEpoch::try_from(Uuid::from_u128(1)).expect("non-nil runtime epoch"),
        authority_fence(1, 0, 0),
        OwnershipVersion::try_from(1).expect("non-zero ownership version"),
    )
    .expect("fresh driver")
}

/// Bind a peer capability over the canonical peer and drive connect -> Connected.
fn connected_driver() -> FakeProcessDriver {
    let peer = peer_context([1u8; 32], [2u8; 32]);
    let mut driver = fresh_driver();
    driver.bind_peer(
        peer.clone(),
        peer_capability(
            &peer,
            OperationMethod::Connect,
            1,
            MonotonicTick::try_from(1000).expect("non-zero tick"),
        ),
    );
    let _ = driver.connect();
    let _ = driver.protocol_established();
    driver
}

/// Drive a connected driver all the way to Stopped via both teardown sides joining.
fn stopped_driver() -> FakeProcessDriver {
    let mut driver = connected_driver();
    let _ = driver.disconnect();
    let _ = driver.join_teardown(TeardownSide::ProtocolControl);
    let _ = driver.join_teardown(TeardownSide::PacketData);
    driver
}

/// Kills 'ProtocolEstablished does not advance Connecting->Connected'.
#[test]
fn full_lifecycle_connect_to_retired_completes() {
    let peer = peer_context([1u8; 32], [2u8; 32]);
    let mut driver = fresh_driver();
    driver.bind_peer(
        peer.clone(),
        peer_capability(
            &peer,
            OperationMethod::Connect,
            1,
            MonotonicTick::try_from(1000).expect("non-zero tick"),
        ),
    );

    assert_eq!(driver.connect(), HostEffect::ConnectAdmitted);
    assert_eq!(driver.phase(), ProcessPhase::Connecting);

    assert_eq!(driver.protocol_established(), HostEffect::Connected);
    assert_eq!(driver.phase(), ProcessPhase::Connected);

    assert!(driver.attach_packet().is_ok());
    assert_eq!(driver.phase(), ProcessPhase::DataPlaneLive);

    assert_eq!(
        driver.admit_packet(DataPlaneDirection::ProtocolToPacket, 1, 64),
        AdmissionVerdict::Admitted
    );

    let ready = DirectionReadiness { has_data: true, backed_up: false };
    let decision = driver.pump(ready, ready);
    assert!(matches!(decision, PollDecision::Poll(_)));

    assert_eq!(driver.disconnect(), HostEffect::TeardownInitiated);
    assert_eq!(driver.phase(), ProcessPhase::Stopping);

    assert_eq!(
        driver.join_teardown(TeardownSide::ProtocolControl),
        JoinOutcome::Pending
    );
    assert_eq!(driver.phase(), ProcessPhase::Stopping);

    assert_eq!(
        driver.join_teardown(TeardownSide::PacketData),
        JoinOutcome::Released
    );
    assert_eq!(driver.phase(), ProcessPhase::Stopped);

    let id = RetirementOperationId::try_from(Uuid::from_u128(2)).expect("non-nil id");
    let digest = InventoryDigest::try_from([0u8; 32]).expect("valid inventory digest");
    assert!(driver.begin_retirement(id, vec![0x01, 0x02], digest).is_ok());
    assert!(driver.observe_cleanup(&[
        InventoryPredicate { label: 0x01, verified: true },
        InventoryPredicate { label: 0x02, verified: true },
    ]).is_ok());
    assert!(driver.prove_clean().is_ok());
    assert!(driver.retire_ownership(OwnershipVersion::try_from(2).expect("non-zero")).is_ok());
    assert_eq!(driver.phase(), ProcessPhase::Retired);
    assert!(driver.is_terminal());
}

/// Kills 'single-side join releases the aggregate'.
#[test]
fn teardown_releases_only_after_both_sides_join() {
    let mut driver = connected_driver();
    assert_eq!(driver.disconnect(), HostEffect::TeardownInitiated);
    assert_eq!(driver.phase(), ProcessPhase::Stopping);

    assert_eq!(
        driver.join_teardown(TeardownSide::ProtocolControl),
        JoinOutcome::Pending
    );
    assert_eq!(driver.host_phase(), HostPhase::Stopping);
    assert!(!driver.is_terminal());

    assert_eq!(
        driver.join_teardown(TeardownSide::PacketData),
        JoinOutcome::Released
    );
    assert_eq!(driver.host_phase(), HostPhase::Stopped);
    assert!(driver.is_terminal());
}

/// Kills 'retire_ownership accepts a non-Proved phase'.
#[test]
fn retirement_ownership_gate_holds_until_proved() {
    let mut driver = stopped_driver();
    let id = RetirementOperationId::try_from(Uuid::from_u128(3)).expect("non-nil id");
    let digest = InventoryDigest::try_from([0u8; 32]).expect("valid inventory digest");
    assert!(driver.begin_retirement(id, vec![0x01], digest).is_ok());
    assert!(driver.observe_cleanup(&[InventoryPredicate { label: 0x01, verified: true }]).is_ok());

    // Retiring before the cleanup is proved must be refused.
    assert!(driver.retire_ownership(OwnershipVersion::try_from(2).expect("non-zero")).is_err());
    assert_ne!(driver.phase(), ProcessPhase::Retired);

    assert!(driver.prove_clean().is_ok());
    assert!(driver.retire_ownership(OwnershipVersion::try_from(2).expect("non-zero")).is_ok());
    assert_eq!(driver.phase(), ProcessPhase::Retired);
}

/// Kills 'observe_cleanup drops the completeness check'.
#[test]
fn retirement_requires_complete_observed_inventory() {
    let mut driver = stopped_driver();
    let id = RetirementOperationId::try_from(Uuid::from_u128(4)).expect("non-nil id");
    let digest = InventoryDigest::try_from([0u8; 32]).expect("valid inventory digest");
    assert!(driver.begin_retirement(id, vec![0x01, 0x02], digest).is_ok());

    // Missing one of the two expected obligations must be refused.
    let incomplete = vec![InventoryPredicate { label: 0x01, verified: true }];
    assert!(driver.observe_cleanup(&incomplete).is_err());

    // A full but unverified predicate set must be refused.
    let unverified = vec![
        InventoryPredicate { label: 0x01, verified: true },
        InventoryPredicate { label: 0x02, verified: false },
    ];
    assert!(driver.observe_cleanup(&unverified).is_err());
}

/// Kills 'second attach granted'.
#[test]
fn stale_second_attach_is_rejected() {
    let mut driver = connected_driver();
    assert!(driver.attach_packet().is_ok());
    assert_eq!(driver.phase(), ProcessPhase::DataPlaneLive);
    assert!(driver.attach_packet().is_err());
}

/// Kills 'connect admitted without capability'.
#[test]
fn missing_peer_capability_refuses_connect() {
    let mut driver = fresh_driver();
    let effect = driver.connect();
    assert!(matches!(effect, HostEffect::ConnectRefused(_)));
    assert_eq!(driver.host_phase(), HostPhase::Idle);
}

/// Kills 'pump always polls ProtocolToPacket'.
#[test]
fn pump_alternates_data_plane_directions() {
    let mut driver = fresh_driver();
    let ready = DirectionReadiness { has_data: true, backed_up: false };
    let first = driver.pump(ready, ready);
    let second = driver.pump(ready, ready);
    assert!(matches!(first, PollDecision::Poll(_)));
    assert!(matches!(second, PollDecision::Poll(_)));
    assert_ne!(first, second);
}

/// Kills 'host stuck at Stopping after both sides join'.
#[test]
fn process_reaches_terminal_stopped_after_full_disconnect() {
    let mut driver = connected_driver();
    let _ = driver.attach_packet();
    assert_eq!(driver.disconnect(), HostEffect::TeardownInitiated);
    let _ = driver.join_teardown(TeardownSide::ProtocolControl);
    assert_eq!(
        driver.join_teardown(TeardownSide::PacketData),
        JoinOutcome::Released
    );
    assert_eq!(driver.phase(), ProcessPhase::Stopped);
    assert!(driver.is_terminal());

    let id = RetirementOperationId::try_from(Uuid::from_u128(8)).expect("non-nil id");
    let digest = InventoryDigest::try_from([0u8; 32]).expect("valid inventory digest");
    assert!(driver.begin_retirement(id, vec![0x01], digest).is_ok());
    assert!(driver.observe_cleanup(&[InventoryPredicate { label: 0x01, verified: true }]).is_ok());
    assert!(driver.prove_clean().is_ok());
    assert!(driver.retire_ownership(OwnershipVersion::try_from(2).expect("non-zero")).is_ok());
    assert_eq!(driver.phase(), ProcessPhase::Retired);
    assert!(driver.is_terminal());
}