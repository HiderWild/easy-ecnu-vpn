// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Bounded byte-budget admission for the packet data plane (spec §6.3/§7.3).

use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::RuntimeEpoch;
use exv_vpn_domain::limits::MvpLimits;
use uuid::Uuid;

/// Which leg of the packet boundary an admission is requested on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DataPlaneDirection {
    ProtocolToPacket,
    PacketToProtocol,
}

/// Outcome of a [`PacketBudget::try_admit`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionVerdict {
    Admitted,
    OverMaxBatch,
    OverBudget,
    Backpressure,
}

/// Number of consecutive full-direction admit events that must be exceeded before the
/// direction reports sustained-full and admission returns [`AdmissionVerdict::Backpressure`].
const SUSTAINED_FULL_THRESHOLD: usize = 3;

/// Tracks per-direction packet-queue usage against the configured queue and batch budgets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketBudget {
    packet_queue_messages: usize,
    packet_queue_bytes: usize,
    max_packet_batch_packets: usize,
    max_packet_batch_bytes: usize,
    in_flight_messages: [usize; 2],
    in_flight_bytes: [usize; 2],
    sustained_full: usize,
}

impl PacketBudget {
    /// Build a budget from the given limits, rejecting any zero knob.
    ///
    /// # Errors
    ///
    /// Returns [`exv_vpn_domain::error::ErrorCode::InvalidInput`] when any of the four
    /// budget knobs is zero.
    pub fn from_limits(limits: &MvpLimits) -> Result<Self, VpnError> {
        if limits.packet_queue_messages == 0
            || limits.packet_queue_bytes == 0
            || limits.max_packet_batch_packets == 0
            || limits.max_packet_batch_bytes == 0
        {
            return Err(invalid_input());
        }
        Ok(Self {
            packet_queue_messages: limits.packet_queue_messages,
            packet_queue_bytes: limits.packet_queue_bytes,
            max_packet_batch_packets: limits.max_packet_batch_packets,
            max_packet_batch_bytes: limits.max_packet_batch_bytes,
            in_flight_messages: [0; 2],
            in_flight_bytes: [0; 2],
            sustained_full: 0,
        })
    }

    /// Request admission for a batch; see [`AdmissionVerdict`] for the outcomes.
    #[must_use]
    pub fn try_admit(
        &mut self,
        direction: DataPlaneDirection,
        packets: usize,
        bytes: usize,
    ) -> AdmissionVerdict {
        // Per-batch cap is enforced first, before any aggregate accounting.
        if packets > self.max_packet_batch_packets || bytes > self.max_packet_batch_bytes {
            return AdmissionVerdict::OverMaxBatch;
        }

        let (cur_messages, cur_bytes) = self.in_flight(direction);
        let would_be_messages = cur_messages + packets;
        let would_be_bytes = cur_bytes + bytes;
        let would_be_full = would_be_messages >= self.packet_queue_messages
            || would_be_bytes >= self.packet_queue_bytes;

        // Aggregate budget: a single call may not exceed the queue message cap, and the
        // cumulative byte usage may not overflow the queue byte budget.
        if packets > self.packet_queue_messages || would_be_bytes > self.packet_queue_bytes {
            if would_be_full {
                self.sustained_full += 1;
            }
            if self.sustained_full > SUSTAINED_FULL_THRESHOLD {
                return AdmissionVerdict::Backpressure;
            }
            return AdmissionVerdict::OverBudget;
        }

        let (messages, bytes_ref) = self.in_flight_mut(direction);
        *messages = would_be_messages;
        *bytes_ref = would_be_bytes;
        if would_be_full {
            self.sustained_full += 1;
        }
        if self.sustained_full > SUSTAINED_FULL_THRESHOLD {
            return AdmissionVerdict::Backpressure;
        }
        AdmissionVerdict::Admitted
    }

    /// Free previously admitted usage (never below zero).
    pub fn release(&mut self, direction: DataPlaneDirection, packets: usize, bytes: usize) {
        let (messages, bytes_ref) = self.in_flight_mut(direction);
        *messages = messages.saturating_sub(packets);
        *bytes_ref = bytes_ref.saturating_sub(bytes);
    }

    /// Whether either direction has crossed the sustained-full threshold.
    #[must_use]
    pub const fn is_sustained_full(&self) -> bool {
        self.sustained_full > SUSTAINED_FULL_THRESHOLD
    }

    /// Current in-flight `(messages, bytes)` usage for a direction.
    #[must_use]
    pub const fn in_flight(&self, direction: DataPlaneDirection) -> (usize, usize) {
        let index = direction_index(direction);
        (self.in_flight_messages[index], self.in_flight_bytes[index])
    }

    fn in_flight_mut(&mut self, direction: DataPlaneDirection) -> (&mut usize, &mut usize) {
        let index = direction_index(direction);
        (
            &mut self.in_flight_messages[index],
            &mut self.in_flight_bytes[index],
        )
    }
}

/// Stable array index for a direction.
const fn direction_index(direction: DataPlaneDirection) -> usize {
    match direction {
        DataPlaneDirection::ProtocolToPacket => 0,
        DataPlaneDirection::PacketToProtocol => 1,
    }
}

/// Generic invalid-input admission error.
fn invalid_input() -> VpnError {
    VpnError::try_from((
        ErrorCode::InvalidInput,
        ErrorStage::Admission,
        EffectCertainty::NoEffect,
        RetryAdvice::DoNotRetry,
        ErrorSubject::Runtime(
            RuntimeEpoch::try_from(Uuid::from_u128(1)).expect("non-nil runtime epoch"),
        ),
        None,
        None,
    ))
    .expect("valid error tuple")
}