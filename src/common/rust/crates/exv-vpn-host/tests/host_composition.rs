// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! RED tests for the host control-plane composition (spec L1072/L1074/L1079/L1296/L1300).
//!
//! Pinned seam: `exv_vpn_host::composition` (H80-I implements it in `src/composition.rs`).
//! Pure + deterministic: no I/O, no filesystem, no sleep, no randomness, no Duration.
//!
//! R1 additions: `ConnectFailed`/`ConnectPhaseProgress` events, `Failed` phase,
//! and the fine-phase register — see `src/composition.rs`.

use exv_vpn_data_plane::teardown::TeardownSide;
use exv_vpn_domain::error::{EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError};
use exv_vpn_domain::identity::{ConnectionBindingDigest, OperationMethod, PrincipalDigest, RuntimeEpoch};
use exv_vpn_domain::model::ConnectPhase;
use exv_vpn_domain::ports::{AuthorityEpoch, MonotonicTick};
use exv_vpn_host::composition::{HostComposition, HostEffect, HostEvent, HostPhase};
use exv_vpn_resource::authority::{
    ConnectionBinding, PeerCapability, PeerContext, VerifiedConnectionMetadata,
};
use uuid::Uuid;

/// A deterministic domain error (fixed runtime epoch, no secret payload).
fn deterministic_error() -> VpnError {
    VpnError::try_from((
        ErrorCode::DeadlineExceeded,
        ErrorStage::ApplyingPlatformTunnel,
        EffectCertainty::NoEffect,
        RetryAdvice::RetrySameOperation,
        ErrorSubject::Runtime(RuntimeEpoch::try_from(Uuid::from_u128(1)).expect("non-nil uuid")),
        None,
        None,
    ))
    .expect("valid error tuple")
}

/// Build a deterministic peer + capability pair using fixed literals only.
fn peer_and_capability() -> (PeerContext, PeerCapability) {
    let principal = PrincipalDigest::try_from([0u8; 32]).unwrap();
    let binding = ConnectionBindingDigest::try_from([1u8; 32]).unwrap();
    let metadata =
        VerifiedConnectionMetadata::try_from((principal.clone(), binding.clone())).unwrap();
    let peer = PeerContext::try_from(metadata).unwrap();
    let connection = ConnectionBinding::try_from(binding).unwrap();
    let capability = PeerCapability::try_from((
        connection,
        principal,
        AuthorityEpoch::try_from(7u64).unwrap(),
        OperationMethod::Connect,
        MonotonicTick::try_from(42u64).unwrap(),
    ))
    .unwrap();
    (peer, capability)
}

/// Drive a fresh composition into the Connected phase.
fn connected_composition() -> (HostComposition, HostEffect) {
    let (peer, cap) = peer_and_capability();
    let mut c = HostComposition::new();
    c.bind_peer(peer, cap);
    let _ = c.apply(HostEvent::Connect);
    let effect = c.apply(HostEvent::ProtocolEstablished);
    (c, effect)
}

// Kills 'connect without capability is admitted'.
#[test]
fn connect_without_capability_is_refused() {
    let mut c = HostComposition::new();
    assert!(matches!(
        c.apply(HostEvent::Connect),
        HostEffect::ConnectRefused(_)
    ));
    assert_eq!(c.phase(), HostPhase::Idle);
}

// Kills 'connect without open admission is admitted'.
#[test]
fn connect_without_open_admission_is_refused() {
    let (peer, cap) = peer_and_capability();
    let mut c = HostComposition::new();
    c.bind_peer(peer, cap);
    assert_eq!(
        c.apply(HostEvent::StopNewAdmission),
        HostEffect::AdmissionStopped
    );
    assert!(!c.admission_open());
    assert_eq!(c.phase(), HostPhase::Idle);
    assert!(matches!(
        c.apply(HostEvent::Connect),
        HostEffect::ConnectRefused(_)
    ));
}

// Kills 'disconnect resolves after one side joins'.
#[test]
fn disconnect_waits_for_both_teardown_sides() {
    let (c, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected);
    let mut c = c;
    assert_eq!(c.apply(HostEvent::Disconnect), HostEffect::TeardownInitiated);
    assert_eq!(c.phase(), HostPhase::Stopping);
    assert_eq!(
        c.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl)),
        HostEffect::TeardownPending
    );
    assert_eq!(c.phase(), HostPhase::Stopping);
    assert_eq!(
        c.apply(HostEvent::TeardownSideJoined(TeardownSide::PacketData)),
        HostEffect::Stopped
    );
    assert_eq!(c.phase(), HostPhase::Stopped);
}

// Kills 'helper-link loss keeps host Connected'.
#[test]
fn helper_link_loss_enters_reconciling_not_connected() {
    let (c, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected);
    let mut c = c;
    assert_eq!(c.apply(HostEvent::HelperLinkLost), HostEffect::ReconcilingEntered);
    assert_eq!(c.phase(), HostPhase::Reconciling);
    assert_ne!(c.phase(), HostPhase::Connected);
}

// Kills 'connect accepted during teardown'.
#[test]
fn connect_refused_while_teardown_in_progress() {
    let (c, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected);
    let mut c = c;
    assert_eq!(c.apply(HostEvent::Disconnect), HostEffect::TeardownInitiated);
    assert_eq!(c.phase(), HostPhase::Stopping);
    assert!(matches!(
        c.apply(HostEvent::Connect),
        HostEffect::ConnectRefused(_)
    ));
}

// Kills 'admission stays open while barrier engages'.
#[test]
fn teardown_closes_admission_before_engaging_barrier() {
    let (c, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected);
    let mut c = c;
    assert_eq!(c.apply(HostEvent::Disconnect), HostEffect::TeardownInitiated);
    assert!(!c.admission_open());
}

// Kills 'over-strict guard refuses valid connect' + validates the full flow.
#[test]
fn connect_admitted_with_capability_and_open_admission_full_flow() {
    let c = HostComposition::new();
    assert_eq!(c.phase(), HostPhase::Idle);
    assert!(c.admission_open());
    let mut c = c;
    let (peer, cap) = peer_and_capability();
    c.bind_peer(peer, cap);
    assert_eq!(c.apply(HostEvent::Connect), HostEffect::ConnectAdmitted);
    assert_eq!(c.phase(), HostPhase::Connecting);
    assert_eq!(
        c.apply(HostEvent::ProtocolEstablished),
        HostEffect::Connected
    );
    assert_eq!(c.apply(HostEvent::Disconnect), HostEffect::TeardownInitiated);
    assert_eq!(c.phase(), HostPhase::Stopping);
    assert_eq!(
        c.apply(HostEvent::TeardownSideJoined(TeardownSide::PacketData)),
        HostEffect::TeardownPending
    );
    assert_eq!(
        c.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl)),
        HostEffect::Stopped
    );
    assert_eq!(c.phase(), HostPhase::Stopped);
}

// ---------------------------------------------------------------------------
// R1: ConnectFailed / ConnectPhaseProgress / Failed phase.
// ---------------------------------------------------------------------------

// Kills 'connect failure leaves a silent Connecting half-state'.
#[test]
fn connect_failure_moves_connecting_to_failed_with_error() {
    let (peer, cap) = peer_and_capability();
    let mut c = HostComposition::new();
    c.bind_peer(peer, cap);
    assert_eq!(c.apply(HostEvent::Connect), HostEffect::ConnectAdmitted);
    assert_eq!(c.phase(), HostPhase::Connecting);

    let err = deterministic_error();
    assert_eq!(
        c.apply(HostEvent::ConnectFailed(err.clone())),
        HostEffect::ConnectFailed
    );
    assert_eq!(c.phase(), HostPhase::Failed);
    assert_eq!(c.last_error(), Some(&err));
}

// Kills 'failed state refuses a retry connect'.
#[test]
fn failed_state_accepts_retry_connect() {
    let (peer, cap) = peer_and_capability();
    let mut c = HostComposition::new();
    c.bind_peer(peer, cap);
    let _ = c.apply(HostEvent::Connect);
    let _ = c.apply(HostEvent::ConnectFailed(deterministic_error()));
    assert_eq!(c.phase(), HostPhase::Failed);

    assert_eq!(c.apply(HostEvent::Connect), HostEffect::ConnectAdmitted);
    assert_eq!(c.phase(), HostPhase::Connecting);
    assert_eq!(c.last_error(), None, "retry clears the prior error");
}

// Kills 'connect progress does not move the lifecycle phase'.
#[test]
fn connect_phase_progress_records_fine_phase_within_connecting() {
    let (peer, cap) = peer_and_capability();
    let mut c = HostComposition::new();
    c.bind_peer(peer, cap);
    let _ = c.apply(HostEvent::Connect);
    assert_eq!(c.connect_phase(), Some(ConnectPhase::ObservingOwnedState));

    assert_eq!(
        c.apply(HostEvent::ConnectPhaseProgress(ConnectPhase::NegotiatingTunnel)),
        HostEffect::PhaseProgressed
    );
    assert_eq!(c.phase(), HostPhase::Connecting, "phase stays Connecting");
    assert_eq!(
        c.connect_phase(),
        Some(ConnectPhase::NegotiatingTunnel),
        "fine phase register advances"
    );
}

// Kills 'connected can be spuriously downgraded by a failure event'.
#[test]
fn connected_survives_spurious_failure_event() {
    let (c, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected);
    let mut c = c;
    let _ = c.apply(HostEvent::ConnectFailed(deterministic_error()));
    assert_eq!(c.phase(), HostPhase::Connected, "Connected is never downgraded");
    assert_eq!(c.last_error(), Some(&deterministic_error()), "error still surfaced");
}

// Kills 'ProtocolEstablished reports the wrong fine phase'.
#[test]
fn protocol_established_sets_starting_data_plane_phase() {
    let (c, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected);
    assert_eq!(
        c.connect_phase(),
        Some(ConnectPhase::StartingDataPlane),
        "connected attempt ends at StartingDataPlane"
    );
}

// ---------------------------------------------------------------------------
// S1: ReopenAdmission — reconnect after a completed teardown (D14).
// ---------------------------------------------------------------------------

// Kills 'Stopped stays latched closed forever' (the admission latch bug).
// stop → Stopped (pin holds) → ReopenAdmission → Idle/admission_open →
// 二次 Connect admitted → 二次 ProtocolEstablished → Connected.
#[test]
fn reopen_admission_migrates_stopped_to_idle_and_readmits_connect() {
    let (c, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected);
    let mut c = c;
    assert_eq!(c.apply(HostEvent::Disconnect), HostEffect::TeardownInitiated);
    assert_eq!(
        c.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl)),
        HostEffect::TeardownPending
    );
    // Stopped pin: both sides joined → Stopped, admission stays closed.
    assert_eq!(
        c.apply(HostEvent::TeardownSideJoined(TeardownSide::PacketData)),
        HostEffect::Stopped
    );
    assert_eq!(c.phase(), HostPhase::Stopped);
    assert!(!c.admission_open(), "admission stays closed while Stopped");

    // Controller explicitly dispatches ReopenAdmission → Idle + admission open.
    assert_eq!(
        c.apply(HostEvent::ReopenAdmission),
        HostEffect::AdmissionReopened
    );
    assert_eq!(c.phase(), HostPhase::Idle);
    assert!(c.admission_open(), "admission reopened");

    // A second connect is admitted WITHOUT re-binding the peer (D4) and reaches
    // Connected again.
    assert_eq!(c.apply(HostEvent::Connect), HostEffect::ConnectAdmitted);
    assert_eq!(c.phase(), HostPhase::Connecting);
    assert_eq!(c.apply(HostEvent::ProtocolEstablished), HostEffect::Connected);
    assert_eq!(c.phase(), HostPhase::Connected);
}

// Kills 'ReopenAdmission reopens admission mid-teardown'.
#[test]
fn reopen_admission_outside_stopped_is_ignored() {
    // In Stopping (barrier engaged): ignored, admission stays closed.
    let (c, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected);
    let mut c = c;
    assert_eq!(c.apply(HostEvent::Disconnect), HostEffect::TeardownInitiated);
    assert_eq!(c.phase(), HostPhase::Stopping);
    assert!(!c.admission_open());
    assert_eq!(
        c.apply(HostEvent::ReopenAdmission),
        HostEffect::AdmissionReopenIgnored
    );
    assert_eq!(c.phase(), HostPhase::Stopping, "teardown in progress: phase stays Stopping");
    assert!(
        !c.admission_open(),
        "teardown in progress: admission must stay closed (teardown-rejection pin)"
    );

    // From a fresh Idle (no teardown): ignored but harmless.
    let mut c = HostComposition::new();
    assert_eq!(
        c.apply(HostEvent::ReopenAdmission),
        HostEffect::AdmissionReopenIgnored
    );
    assert_eq!(c.phase(), HostPhase::Idle);
    assert!(c.admission_open());
}

// Kills 'reopen drops the bound peer/capability' (D4: owner/lease held across connections).
#[test]
fn reopen_keeps_bound_peer_and_capability_across_connections() {
    let (mut c, _) = connected_composition();
    // Complete the teardown and reopen.
    let _ = c.apply(HostEvent::Disconnect);
    let _ = c.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl));
    assert_eq!(
        c.apply(HostEvent::TeardownSideJoined(TeardownSide::PacketData)),
        HostEffect::Stopped
    );
    assert_eq!(c.apply(HostEvent::ReopenAdmission), HostEffect::AdmissionReopened);

    // No re-bind: the previously bound peer+capability still admits the next
    // connect — a reconnect must not require a new authorize.
    assert_eq!(c.apply(HostEvent::Connect), HostEffect::ConnectAdmitted);
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。