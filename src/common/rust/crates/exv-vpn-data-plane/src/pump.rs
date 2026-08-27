// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Fair directional pump scheduler (spec §8.5 L1298).
//!
//! The two data-plane directions are served in strict alternation so that neither leg is
//! permanently starved in front of the other. Readiness is decomposed into "has data" and
//! "backed up"; a direction is pollable only when it has data and is not backed up.

use crate::budget::DataPlaneDirection;

/// Whether a directional leg is ready to be pumped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectionReadiness {
    pub has_data: bool,
    pub backed_up: bool,
}

/// What the scheduler decided for the current round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollDecision {
    Poll(DataPlaneDirection),
    Idle,
}

/// Round-robin scheduler that alternates the preferred direction each round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PumpScheduler {
    next: DataPlaneDirection,
}

impl PumpScheduler {
    /// A fresh scheduler whose preferred direction is ProtocolToPacket.
    pub const fn new() -> Self {
        Self {
            next: DataPlaneDirection::ProtocolToPacket,
        }
    }

    /// Decide which direction to poll this round.
    ///
    /// `preferred` is polled first; if it is not pollable, the other direction is tried. If
    /// neither is pollable, the scheduler idles. Either way the preferred direction rotates,
    /// so the two legs alternate fairly across rounds.
    pub fn next(
        &mut self,
        protocol_to_packet: DirectionReadiness,
        packet_to_protocol: DirectionReadiness,
    ) -> PollDecision {
        let preferred = self.next;
        let other = opposite(preferred);

        let preferred_ready = (preferred == DataPlaneDirection::ProtocolToPacket && protocol_to_packet.has_data && !protocol_to_packet.backed_up)
            || (preferred == DataPlaneDirection::PacketToProtocol && packet_to_protocol.has_data && !packet_to_protocol.backed_up);
        let other_ready = if preferred == DataPlaneDirection::ProtocolToPacket {
            packet_to_protocol.has_data && !packet_to_protocol.backed_up
        } else {
            protocol_to_packet.has_data && !protocol_to_packet.backed_up
        };

        // Rotate the preferred direction for the next round regardless of the outcome, keeping
        // the scheduler alternating even while idling.
        self.next = opposite(preferred);

        if preferred_ready {
            PollDecision::Poll(preferred)
        } else if other_ready {
            PollDecision::Poll(other)
        } else {
            PollDecision::Idle
        }
    }

    /// The direction that will be preferred on the next round.
    pub const fn next_direction(&self) -> DataPlaneDirection {
        self.next
    }
}

/// The opposite leg of the packet boundary.
fn opposite(direction: DataPlaneDirection) -> DataPlaneDirection {
    match direction {
        DataPlaneDirection::ProtocolToPacket => DataPlaneDirection::PacketToProtocol,
        DataPlaneDirection::PacketToProtocol => DataPlaneDirection::ProtocolToPacket,
    }
}