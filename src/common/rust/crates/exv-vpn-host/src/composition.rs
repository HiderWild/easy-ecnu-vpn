// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Deterministic host control-plane composition (spec L1072/L1074/L1079/L1296/L1300).
//!
//! Owns the host's phase machine, admission gate, and the two-sided data-plane teardown barrier.
//! Pure + deterministic: no I/O, no filesystem, no sleep, no randomness, no Duration.

use exv_vpn_data_plane::teardown::{JoinOutcome, TeardownBarrier, TeardownSide};
use exv_vpn_domain::error::VpnError;
use exv_vpn_domain::model::ConnectPhase;
use exv_vpn_resource::authority::{PeerCapability, PeerContext};

/// The host control-plane lifecycle phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostPhase {
    /// No connection established; admission is open.
    Idle,
    /// A connect has been admitted but the protocol has not yet established.
    Connecting,
    /// The protocol is established and the data plane is live.
    Connected,
    /// A helper-link loss triggered reconciliation.
    Reconciling,
    /// Teardown has been initiated; awaiting both sides to join the barrier.
    Stopping,
    /// Both teardown sides joined; the aggregate is released.
    Stopped,
    /// The connect attempt failed with a reported error (R1); retry re-admits.
    Failed,
}

/// Events the host composition reacts to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostEvent {
    /// A new connection is requested.
    Connect,
    /// The protocol has established over the admitted peer.
    ProtocolEstablished,
    /// The user/operator requested a disconnect.
    Disconnect,
    /// The helper link was lost.
    HelperLinkLost,
    /// Stop accepting new admissions (soft gate).
    StopNewAdmission,
    /// One side joined the teardown barrier.
    TeardownSideJoined(TeardownSide),
    /// The connect attempt failed with a reported error (R1). The only event
    /// that may move [`HostPhase::Connecting`] to [`HostPhase::Failed`]; the
    /// error detail is retained for snapshot reporting (no silent half-state).
    ConnectFailed(VpnError),
    /// The fine connect phase advanced (R1, driven by the engine status
    /// stream). Records the latest observed [`ConnectPhase`] on the attempt.
    ConnectPhaseProgress(ConnectPhase),
    /// Reopen admission after a completed teardown (S1). The controller
    /// dispatches this AFTER [`HostPhase::Stopped`] is observable — it is the
    /// only migration that moves [`HostPhase::Stopped`] back to
    /// [`HostPhase::Idle`] with admission open, so a later Connect is admitted
    /// without restarting the process. It is deliberately NOT dispatched inside
    /// the `TeardownSideJoined` Released arm: the Stopped pin (both sides →
    /// Stopped) holds until the controller explicitly reopens.
    ReopenAdmission,
}

/// The observable effect of applying an event to the composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostEffect {
    /// The connect was admitted and the host moved to [`HostPhase::Connecting`].
    ConnectAdmitted,
    /// The connect was refused, with a reason.
    ConnectRefused(&'static str),
    /// The protocol established; host is now live.
    Connected,
    /// A helper-link loss moved the host into reconciliation.
    ReconcilingEntered,
    /// Admission was stopped.
    AdmissionStopped,
    /// Teardown was initiated; host is now [`HostPhase::Stopping`].
    TeardownInitiated,
    /// A teardown side joined but the peer has not yet; still pending.
    TeardownPending,
    /// The aggregate teardown was released; host is now [`HostPhase::Stopped`].
    Stopped,
    /// The connect attempt failed; host is now [`HostPhase::Failed`] (R1).
    ConnectFailed,
    /// The fine connect phase advanced on the current attempt (R1).
    PhaseProgressed,
    /// Admission was reopened after a completed teardown (S1): host is back to
    /// [`HostPhase::Idle`] with admission open — a later Connect is admitted.
    AdmissionReopened,
    /// [`HostEvent::ReopenAdmission`] was dispatched outside [`HostPhase::Stopped`]
    /// and was a no-op (teardown in progress, or admission already open).
    AdmissionReopenIgnored,
}

/// The deterministic host control-plane composition.
pub struct HostComposition {
    phase: HostPhase,
    admission_open: bool,
    teardown: TeardownBarrier,
    peer: Option<PeerContext>,
    capability: Option<PeerCapability>,
    /// The latest fine connect phase observed on the current attempt (R1).
    connect_phase: Option<ConnectPhase>,
    /// The error reported by the last [`HostEvent::ConnectFailed`] (R1).
    last_error: Option<VpnError>,
}

impl HostComposition {
    /// Create a fresh composition in [`HostPhase::Idle`] with admission open.
    pub fn new() -> Self {
        Self {
            phase: HostPhase::Idle,
            admission_open: true,
            teardown: TeardownBarrier::new(),
            peer: None,
            capability: None,
            connect_phase: None,
            last_error: None,
        }
    }

    /// The current lifecycle phase.
    #[must_use]
    pub fn phase(&self) -> HostPhase {
        self.phase
    }

    /// Whether new connections are still admitted.
    #[must_use]
    pub fn admission_open(&self) -> bool {
        self.admission_open
    }

    /// The latest fine connect phase observed on the current attempt (R1).
    #[must_use]
    pub fn connect_phase(&self) -> Option<ConnectPhase> {
        self.connect_phase
    }

    /// The error reported by the last [`HostEvent::ConnectFailed`] (R1), if any.
    #[must_use]
    pub fn last_error(&self) -> Option<&VpnError> {
        self.last_error.as_ref()
    }

    /// Bind the authenticated peer and its capability to this composition.
    ///
    /// Must be called before a [`HostEvent::Connect`] can be admitted.
    pub fn bind_peer(&mut self, peer: PeerContext, capability: PeerCapability) {
        self.peer = Some(peer);
        self.capability = Some(capability);
    }

    /// Apply an event and return the resulting effect.
    pub fn apply(&mut self, event: HostEvent) -> HostEffect {
        match event {
            HostEvent::Connect => {
                if !self.admission_open {
                    HostEffect::ConnectRefused("connect: admission closed")
                } else if self.capability.is_none() {
                    HostEffect::ConnectRefused("connect: no peer capability")
                } else if self.phase == HostPhase::Stopping
                    || self.phase == HostPhase::Reconciling
                {
                    HostEffect::ConnectRefused("connect: teardown in progress")
                } else {
                    // R1: a fresh attempt (re-admitted from Idle, Connected or
                    // Failed) clears the prior error and starts at the first
                    // fine phase; the engine status stream advances it.
                    self.phase = HostPhase::Connecting;
                    self.connect_phase = Some(ConnectPhase::ObservingOwnedState);
                    self.last_error = None;
                    HostEffect::ConnectAdmitted
                }
            }
            HostEvent::ProtocolEstablished => {
                // R1: only the engine status stream's real Connected drives this
                // (the log code path is retired); it is the single setter of
                // `Connected`. The attempt is complete: last fine phase is
                // StartingDataPlane and any prior error is cleared.
                self.phase = HostPhase::Connected;
                self.connect_phase = Some(ConnectPhase::StartingDataPlane);
                self.last_error = None;
                HostEffect::Connected
            }
            HostEvent::ConnectPhaseProgress(phase) => {
                // R1: records the latest observed fine phase on the attempt.
                // Kept as a register so a progress event outside Connecting
                // (a stale or terminal-adjacent event) still surfaces honestly
                // without moving the lifecycle phase.
                self.connect_phase = Some(phase);
                HostEffect::PhaseProgressed
            }
            HostEvent::ConnectFailed(error) => {
                // R1: the connect attempt failed with a reported error. From
                // Connecting this moves to Failed (no silent half-state); the
                // error is always retained for snapshot reporting. Connected is
                // never downgraded by a spurious failure event.
                self.last_error = Some(error);
                if self.phase == HostPhase::Connecting {
                    self.phase = HostPhase::Failed;
                }
                HostEffect::ConnectFailed
            }
            HostEvent::Disconnect => {
                self.admission_open = false;
                self.phase = HostPhase::Stopping;
                self.teardown = TeardownBarrier::new();
                HostEffect::TeardownInitiated
            }
            HostEvent::HelperLinkLost => {
                if self.phase == HostPhase::Connecting || self.phase == HostPhase::Connected {
                    self.admission_open = false;
                    self.phase = HostPhase::Reconciling;
                    HostEffect::ReconcilingEntered
                } else {
                    HostEffect::AdmissionStopped
                }
            }
            HostEvent::StopNewAdmission => {
                self.admission_open = false;
                HostEffect::AdmissionStopped
            }
            HostEvent::TeardownSideJoined(side) => match self.teardown.join(side) {
                JoinOutcome::Released => {
                    self.phase = HostPhase::Stopped;
                    HostEffect::Stopped
                }
                JoinOutcome::Pending | JoinOutcome::Rejected => HostEffect::TeardownPending,
            },
            HostEvent::ReopenAdmission => {
                // S1: the only migration out of Stopped. Guarded to Stopped so a
                // premature dispatch (mid-teardown) never reopens admission while
                // the barrier is engaged — the teardown-rejection semantics hold.
                if self.phase == HostPhase::Stopped {
                    self.admission_open = true;
                    self.phase = HostPhase::Idle;
                    // A reopened Idle carries no active attempt: clear the fine-phase
                    // register so the next Connect starts fresh.
                    self.connect_phase = None;
                    HostEffect::AdmissionReopened
                } else {
                    HostEffect::AdmissionReopenIgnored
                }
            }
        }
    }
}

impl Default for HostComposition {
    fn default() -> Self {
        Self::new()
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。