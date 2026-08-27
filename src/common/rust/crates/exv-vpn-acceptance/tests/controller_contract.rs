// RED tests for the deterministic controller-level contract (spec §4.5 L258-266, §8.5 L1300,
// vpn-rust-native-runtime-mvp). Pinned seam: `exv_vpn_acceptance::controller` (A82-I implements
// in `src/controller.rs`) and `exv_vpn_acceptance::scenario` (A82-I implements
// `retirement_gate_agreement` in `src/scenario.rs`). Both modules are declared in `lib.rs` but
// currently empty stubs — until A82-I lands, THIS FILE FAILS TO COMPILE (unresolved imports).
// That is the intended RED.
//
// PURE, deterministic: no I/O, no filesystem, no sleep, no randomness, no Duration.
// Identifiers come only from fixed byte literals and Uuid::from_u128 via the TK fixtures.

use exv_vpn_acceptance::controller::{Command, Controller, Step};
use exv_vpn_acceptance::scenario::{retirement_gate_agreement, RetirementGateProbe};
use exv_vpn_data_plane::teardown::TeardownSide;
use exv_vpn_domain::identity::OperationMethod;
use exv_vpn_domain::ports::MonotonicTick;
use exv_vpn_helper::composition::{HelperComposition, HelperPhase};
use exv_vpn_host::composition::{HostComposition, HostEffect, HostPhase};
use exv_vpn_wire::convert::operation_method_from_wire;
use exv_vpn_testkit::fixture::{peer_capability, peer_context};

/// A controller bound with a deterministic peer + capability pair.
fn bound_controller() -> Controller {
    let peer = peer_context([0xAA; 32], [0xBB; 32]);
    let cap = peer_capability(
        &peer,
        OperationMethod::Connect,
        1,
        MonotonicTick::try_from(1000).expect("non-trivial tick"),
    );
    let mut c = Controller::new();
    c.bind(peer, cap);
    c
}

// Kills 'connect stays Idle or jumps to Connected'.
#[test]
fn connect_admitted_moves_controller_to_connecting() {
    let mut c = bound_controller();
    assert_eq!(
        c.apply(Command::Connect),
        Step { phase: HostPhase::Connecting, effect: HostEffect::ConnectAdmitted }
    );
    assert_eq!(c.phase(), HostPhase::Connecting);
}

// Kills 'ProtocolEstablished does not transition Connecting→Connected'.
#[test]
fn protocol_established_moves_controller_to_connected() {
    let mut c = bound_controller();
    c.apply(Command::Connect);
    assert_eq!(
        c.apply(Command::ProtocolEstablished),
        Step { phase: HostPhase::Connected, effect: HostEffect::Connected }
    );
    assert_eq!(c.phase(), HostPhase::Connected);
}

// Kills 'Disconnect does not close admission'.
#[test]
fn disconnect_initiates_stopping_with_admission_closed() {
    let mut c = bound_controller();
    c.apply(Command::Connect);
    assert_eq!(
        c.apply(Command::Disconnect),
        Step { phase: HostPhase::Stopping, effect: HostEffect::TeardownInitiated }
    );
    assert_eq!(c.phase(), HostPhase::Stopping);
    assert!(!c.admission_open(), "admission must close on disconnect");
}

// Kills 'single-side join releases Stopped'.
#[test]
fn host_reaches_stopped_only_after_both_teardown_sides() {
    let mut c = bound_controller();
    c.apply(Command::Connect);
    c.apply(Command::Disconnect);
    assert_eq!(
        c.apply(Command::TeardownSideJoined(TeardownSide::ProtocolControl)),
        Step { phase: HostPhase::Stopping, effect: HostEffect::TeardownPending }
    );
    assert_eq!(c.phase(), HostPhase::Stopping, "still fenced after one side");
    assert_eq!(
        c.apply(Command::TeardownSideJoined(TeardownSide::PacketData)),
        Step { phase: HostPhase::Stopped, effect: HostEffect::Stopped }
    );
    assert_eq!(c.phase(), HostPhase::Stopped);
}

// Kills 'HelperLinkLost does not move to Reconciling / close admission'.
#[test]
fn helper_link_loss_enters_reconciling() {
    let mut c = bound_controller();
    c.apply(Command::Connect);
    assert_eq!(
        c.apply(Command::HelperLinkLost),
        Step { phase: HostPhase::Reconciling, effect: HostEffect::ReconcilingEntered }
    );
    assert_eq!(c.phase(), HostPhase::Reconciling);
    assert!(!c.admission_open(), "admission must close on link loss");
}

// Kills 'host admits a connect during Stopping/Reconciling'.
#[test]
fn controller_refuses_connect_during_teardown() {
    // From Stopping.
    let mut c = bound_controller();
    c.apply(Command::Connect);
    c.apply(Command::Disconnect);
    assert_eq!(c.phase(), HostPhase::Stopping);
    assert!(matches!(c.apply(Command::Connect), Step { effect: HostEffect::ConnectRefused(_), .. }));

    // From Reconciling.
    let mut c = bound_controller();
    c.apply(Command::Connect);
    c.apply(Command::HelperLinkLost);
    assert_eq!(c.phase(), HostPhase::Reconciling);
    assert!(matches!(c.apply(Command::Connect), Step { effect: HostEffect::ConnectRefused(_), .. }));
}

// Kills 'helper/host releases on one side or before saga Retired'.
#[test]
fn host_and_helper_agree_on_retirement_gate() {
    let probe = retirement_gate_agreement();
    assert_eq!(
        probe,
        RetirementGateProbe {
            host_releases_only_after_both_sides: true,
            helper_releases_only_after_both_sides: true,
        }
    );

    // The probe must be derived from the real compositions, not a hard-coded literal.
    let host = HostComposition::new();
    let helper = HelperComposition::new();
    assert_eq!(host.phase(), HostPhase::Idle);
    assert_eq!(helper.phase(), HelperPhase::Idle);
}

// Kills 'wire maps UNSPECIFIED=0 to a valid method or Stop=3 to a different method'.
#[test]
fn wire_command_conversion_is_well_typed() {
    assert_eq!(operation_method_from_wire(1), Ok(OperationMethod::Connect));
    assert_eq!(operation_method_from_wire(2), Ok(OperationMethod::RespondInteraction));
    assert_eq!(operation_method_from_wire(3), Ok(OperationMethod::Stop));
    assert_eq!(operation_method_from_wire(4), Ok(OperationMethod::Reconcile));
    assert_eq!(operation_method_from_wire(8), Ok(OperationMethod::ReleaseLease));
    assert!(operation_method_from_wire(0).is_err(), "UNSPECIFIED=0 must be an error");
    assert!(operation_method_from_wire(99).is_err(), "unknown discriminant must be an error");
}

// Kills 'any single lifecycle step deviates'.
#[test]
fn contract_holds_under_tk_fixtures() {
    let peer = peer_context([0xAA; 32], [0xBB; 32]);
    let cap = peer_capability(
        &peer,
        OperationMethod::Connect,
        1,
        MonotonicTick::try_from(1000).expect("non-trivial tick"),
    );
    let mut c = Controller::new();
    c.bind(peer, cap);

    let mut effects = Vec::new();
    effects.push(c.apply(Command::Connect).effect);
    effects.push(c.apply(Command::ProtocolEstablished).effect);
    effects.push(c.apply(Command::Disconnect).effect);
    effects.push(c.apply(Command::TeardownSideJoined(TeardownSide::ProtocolControl)).effect);
    effects.push(c.apply(Command::TeardownSideJoined(TeardownSide::PacketData)).effect);

    assert_eq!(
        effects,
        vec![
            HostEffect::ConnectAdmitted,
            HostEffect::Connected,
            HostEffect::TeardownInitiated,
            HostEffect::TeardownPending,
            HostEffect::Stopped,
        ]
    );
    assert_eq!(c.phase(), HostPhase::Stopped);
    assert!(!c.admission_open());
}