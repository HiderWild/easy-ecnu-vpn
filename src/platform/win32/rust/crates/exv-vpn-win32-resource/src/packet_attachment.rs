// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Packet-boundary attachment record (W23B-I).
//!
//! [`PacketAttachment`] is the pure record produced by the atomic attach
//! transition: it links one relay leg (the stream that won the race for a
//! single-use [`PacketCapability`](crate::packet_capability::PacketCapability))
//! to a packet channel leg, carrying the winner's `connection_id` and the
//! packet lease the capability granted. The `packet_relay` contract pins
//! `Clone/Debug/PartialEq/Eq` plus `connection_id`/`lease` accessors; the
//! record is immutable once created. No Win32 calls: pure data over the
//! attach facts.

use exv_vpn_domain::model::PacketLeaseRef;

/// The attachment record produced by a successful atomic attach.
///
/// Pairs the connection (relay stream) that owns the leg with the packet
/// lease the capability granted. Immutable once created by the attach
/// transition ([`PacketAttachment::new`]); the helper's relay carries it as
/// the leg's identity.
#[derive(Clone, PartialEq, Eq)]
pub struct PacketAttachment {
    /// The connection id of the stream that won the attach.
    connection_id: u64,
    /// The packet lease this attachment carries.
    lease: PacketLeaseRef,
}

impl PacketAttachment {
    /// The connection (relay stream) this attachment binds.
    #[must_use]
    pub const fn connection_id(&self) -> u64 {
        self.connection_id
    }

    /// The packet lease this attachment carries.
    #[must_use]
    pub fn lease(&self) -> PacketLeaseRef {
        self.lease.clone()
    }
}

impl PacketAttachment {
    /// Build the attachment record for a won attach transition.
    ///
    /// Called by the capability's atomic
    /// [`attach`](crate::packet_capability::PacketCapability::attach); the
    /// relay produces the transition, it does not hand-assemble the record.
    #[must_use]
    pub const fn new(connection_id: u64, lease: PacketLeaseRef) -> Self {
        Self {
            connection_id,
            lease,
        }
    }
}

impl std::fmt::Debug for PacketAttachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque: the lease digest is a sensitive identity fact
        // and is never Debug-printed (plan §5; the domain's `PacketLeaseRef`
        // has no Debug for the same reason). The contract test only needs
        // `Debug` for `Result::expect`/`Option::expect` on values of this
        // type.
        f.debug_struct("PacketAttachment")
            .field("connection_id", &self.connection_id)
            .finish_non_exhaustive()
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
