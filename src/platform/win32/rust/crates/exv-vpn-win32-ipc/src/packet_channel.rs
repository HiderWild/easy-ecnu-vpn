// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Sequence-ordered, budgeted admission for one leg of the packet boundary (W23A-I).
//!
//! The channel pairs a Q60 [`PacketBudget`] (per-batch and queue-budget admission, built from
//! the [`PacketLimits`]) with a Q61 [`PumpScheduler`] (fair directional alternation, spec
//! §8.5), and stamps every admitted batch with a strictly increasing X71H ownership-version
//! sequence so stale owned frames can be refused.

use crate::packet_limits::PacketLimits;
use exv_vpn_data_plane::budget::{AdmissionVerdict, DataPlaneDirection, PacketBudget};
use exv_vpn_data_plane::pump::{DirectionReadiness, PollDecision, PumpScheduler};
use exv_vpn_domain::error::VpnError;
use exv_vpn_domain::limits::MvpLimits;
use std::time::Duration;

/// Outcome of a [`PacketChannel::admit`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelVerdict {
    /// The batch was admitted and stamped with its ownership-version sequence.
    Admitted { sequence: u64 },
    /// The batch exceeded a per-batch cap or the directional queue budget.
    Rejected,
}

/// Admission gate for the packet channel: a Q60 [`PacketBudget`] charged against the
/// channel's primary direction, a Q61 [`PumpScheduler`] for fair polling, and the X71H
/// ownership-version sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketChannel {
    sequence: u64,
    budget: PacketBudget,
    pump: PumpScheduler,
    direction: DataPlaneDirection,
}

impl PacketChannel {
    /// Build a channel from the given limits; `direction` is the primary queue all admits
    /// charge against.
    ///
    /// # Errors
    ///
    /// Returns [`VpnError`] (`ErrorCode::InvalidInput`) when the derived budget knobs are
    /// zero; see [`PacketBudget::from_limits`].
    pub fn new(limits: &PacketLimits, direction: DataPlaneDirection) -> Result<Self, VpnError> {
        let budget = PacketBudget::from_limits(&mvp_limits(limits))?;
        Ok(Self {
            sequence: 0,
            budget,
            pump: PumpScheduler::new(),
            direction,
        })
    }

    /// Attempt to admit a batch of `packets` totalling `bytes` bytes.
    ///
    /// Per-batch caps (`max_batch_packets` / `max_batch_bytes`) are enforced before any
    /// aggregate accounting, and each admitted batch consumes exactly one strictly increasing
    /// sequence number.
    #[must_use]
    pub fn admit(&mut self, packets: usize, bytes: usize) -> ChannelVerdict {
        // The budget enforces the per-batch caps derived from the same limits, then checks
        // the directional queue budget. Any non-admitted outcome rejects the batch.
        match self.budget.try_admit(self.direction, packets, bytes) {
            AdmissionVerdict::Admitted => {
                let sequence = self.sequence;
                self.sequence += 1;
                ChannelVerdict::Admitted { sequence }
            }
            AdmissionVerdict::OverMaxBatch
            | AdmissionVerdict::OverBudget
            | AdmissionVerdict::Backpressure => ChannelVerdict::Rejected,
        }
    }

    /// The sequence the next admitted batch will receive.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.sequence
    }

    /// Admit a frame owned by the transport, carrying its ownership version.
    ///
    /// Only the current sequence is admitted (X71H): a stale frame is refused without
    /// consuming a sequence number.
    ///
    /// # Errors
    ///
    /// Returns `Err("old frame")` when `frame_sequence` is not the channel's current
    /// `next_sequence`, and `Err("budget full")` when the batch passes the ownership check
    /// but the queue budget rejects it.
    pub fn admit_owned_frame(
        &mut self,
        packets: usize,
        bytes: usize,
        frame_sequence: u64,
    ) -> Result<(), &'static str> {
        if frame_sequence != self.next_sequence() {
            return Err("old frame");
        }
        match self.admit(packets, bytes) {
            ChannelVerdict::Admitted { .. } => Ok(()),
            ChannelVerdict::Rejected => Err("budget full"),
        }
    }

    /// Decide which data-plane leg to poll this round (Q61 strict alternation).
    #[must_use]
    pub fn pump_decision(
        &mut self,
        p2p: DirectionReadiness,
        p2x: DirectionReadiness,
    ) -> PollDecision {
        self.pump.next(p2p, p2x)
    }
}

/// Derive the domain [`MvpLimits`] from the channel [`PacketLimits`]: the queue byte budget
/// equals `max_batch_bytes` (the queue must not hold two oversized batches, so a cumulative
/// admission past it is refused), the queue message budget is 8x the batch packet cap, and
/// the per-batch knobs carry over unchanged. The remaining knobs are MVP defaults never
/// consulted by the packet budget.
fn mvp_limits(limits: &PacketLimits) -> MvpLimits {
    MvpLimits {
        normal_mailbox_messages: 64,
        completion_mailbox_messages: 64,
        stop_waiters: 8,
        snapshot_receivers: 8,
        packet_queue_messages: limits.max_batch_packets * 8,
        packet_queue_bytes: limits.max_batch_bytes,
        max_packet_batch_packets: limits.max_batch_packets,
        max_packet_batch_bytes: limits.max_batch_bytes,
        max_control_message_bytes: limits.max_message_bytes,
        max_packet_message_bytes: limits.max_message_bytes,
        normal_cleanup_budget: Duration::from_secs(30),
        queued_connect_budget: Duration::from_secs(30),
        owner_lease_ttl: Duration::from_secs(30),
        packet_loss_cleanup_grace: Duration::from_secs(30),
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
