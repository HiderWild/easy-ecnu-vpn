// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Deterministic controller-level seam over the host control-plane composition (spec §4.5
//! L258-266, §8.5 L1300). Pure + deterministic: no I/O, no filesystem, no sleep, no randomness.
//!
//! The [`Controller`] forwards lifecycle commands to an inner [`HostComposition`] and surfaces
//! each command's resulting phase + effect as a [`Step`].

use exv_vpn_data_plane::teardown::TeardownSide;
use exv_vpn_host::composition::{HostComposition, HostEffect, HostEvent, HostPhase};
use exv_vpn_resource::authority::{PeerCapability, PeerContext};

/// A lifecycle command accepted by the controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// A new connection is requested.
    Connect,
    /// The protocol has established over the admitted peer.
    ProtocolEstablished,
    /// The user/operator requested a disconnect.
    Disconnect,
    /// The helper link was lost.
    HelperLinkLost,
    /// One side joined the teardown barrier.
    TeardownSideJoined(TeardownSide),
}

/// The observable outcome of applying a command: the resulting phase and effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// The host phase after the command was applied.
    pub phase: HostPhase,
    /// The effect the command produced.
    pub effect: HostEffect,
}

/// A deterministic controller bound to a peer + capability, forwarding commands to the host
/// composition.
pub struct Controller {
    host: HostComposition,
}

impl Controller {
    /// Create a fresh controller in [`HostPhase::Idle`] with admission open.
    #[must_use]
    pub fn new() -> Self {
        Self { host: HostComposition::new() }
    }

    /// Bind the authenticated peer and its capability to this controller.
    pub fn bind(&mut self, peer: PeerContext, capability: PeerCapability) {
        self.host.bind_peer(peer, capability);
    }

    /// Apply a lifecycle command and return the resulting [`Step`].
    pub fn apply(&mut self, command: Command) -> Step {
        let event = match command {
            Command::Connect => HostEvent::Connect,
            Command::ProtocolEstablished => HostEvent::ProtocolEstablished,
            Command::Disconnect => HostEvent::Disconnect,
            Command::HelperLinkLost => HostEvent::HelperLinkLost,
            Command::TeardownSideJoined(side) => HostEvent::TeardownSideJoined(side),
        };
        let effect = self.host.apply(event);
        Step { phase: self.host.phase(), effect }
    }

    /// The current host lifecycle phase.
    #[must_use]
    pub fn phase(&self) -> HostPhase {
        self.host.phase()
    }

    /// Whether new connections are still admitted.
    #[must_use]
    pub fn admission_open(&self) -> bool {
        self.host.admission_open()
    }
}

impl Default for Controller {
    fn default() -> Self {
        Self::new()
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。