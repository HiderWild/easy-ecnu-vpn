// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Two-sided cancellation barrier for data-plane teardown (spec §8.5 L1296-1301, TG-06 L1449).
//!
//! Pure + deterministic: no I/O, no filesystem, no sleep, no randomness, no Duration. The aggregate
//! teardown is released only once BOTH sides (`ProtocolControl` and `PacketData`) have actually
//! joined. A new capability/attach is refused while the barrier is held (fenced), and EOF on one
//! side cancels the peer.

/// Which side of the two-sided barrier is signalling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TeardownSide {
    /// The protocol-control side (control plane).
    ProtocolControl,
    /// The packet-data side (data plane).
    PacketData,
}

/// Outcome of a side attempting to join the barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinOutcome {
    /// Joined but the peer has not yet joined; aggregate still fenced.
    Pending,
    /// Joined and this was the final side; aggregate released.
    Released,
    /// Join refused (already released, or this side already joined).
    Rejected,
}

/// Result of signalling EOF on a side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EofSignal {
    /// This side cancelled the peer.
    PeerCancelled,
    /// The peer was already cancelled.
    PeerAlreadyCancelled,
}

/// Two-sided cancellation barrier for data-plane teardown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeardownBarrier {
    joined: [bool; 2],
    cancelled: [bool; 2],
    released: bool,
}

impl TeardownBarrier {
    /// Create a fresh, fenced barrier with neither side joined nor cancelled.
    pub const fn new() -> Self {
        Self {
            joined: [false; 2],
            cancelled: [false; 2],
            released: false,
        }
    }

    /// Attempt to join the barrier on `side`.
    ///
    /// Returns `Rejected` if the aggregate is already released or if this side already joined.
    /// Returns `Released` when this is the final joining side; otherwise `Pending`.
    pub fn join(&mut self, side: TeardownSide) -> JoinOutcome {
        if self.released {
            return JoinOutcome::Rejected;
        }
        let index = side_index(side);
        if self.joined[index] {
            return JoinOutcome::Rejected;
        }
        self.joined[index] = true;
        if self.joined[0] && self.joined[1] {
            self.released = true;
            JoinOutcome::Released
        } else {
            JoinOutcome::Pending
        }
    }

    /// Signal EOF on `side`, cancelling the peer.
    ///
    /// Returns `PeerAlreadyCancelled` if the peer was already cancelled; otherwise `PeerCancelled`.
    pub fn signal_eof(&mut self, side: TeardownSide) -> EofSignal {
        let index = side_index(side);
        let peer = 1 - index;
        self.cancelled[index] = true;
        if !self.cancelled[peer] {
            self.cancelled[peer] = true;
            EofSignal::PeerCancelled
        } else {
            EofSignal::PeerAlreadyCancelled
        }
    }

    /// Whether `side` has been cancelled.
    pub const fn is_cancelled(&self, side: TeardownSide) -> bool {
        self.cancelled[side_index(side)]
    }

    /// Whether the barrier is still fenced (i.e. not yet released). A fenced barrier refuses new
    /// capability/attach while the aggregate teardown is held.
    pub const fn is_fenced(&self) -> bool {
        !self.released
    }

    /// Whether the aggregate teardown has been released (both sides joined).
    pub const fn is_released(&self) -> bool {
        self.released
    }
}

/// Map a side to its index in the `[bool; 2]` arrays.
const fn side_index(side: TeardownSide) -> usize {
    match side {
        TeardownSide::ProtocolControl => 0,
        TeardownSide::PacketData => 1,
    }
}