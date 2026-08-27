// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Single-use packet-boundary capability (W23B-I).
//!
//! [`PacketCapability`] is the pure capability/fact record of a pending
//! packet-boundary attach: it binds a [`PacketLeaseRef`] to the
//! [`RuntimeEpoch`] that issued it and is consumed exactly once by the atomic
//! `Pending(capability) -> Attached(connection_id)` transition that the
//! helper's `AttachedPacketRelay::attach` executes (the `packet_relay`
//! contract, spec §5.5). Concurrent or repeated use of an already-consumed
//! capability
//! is rejected with [`ErrorCode::PacketLeaseAlreadyAttached`] and a consumed
//! capability is never reused (spec §9.2). No Win32 calls: the capability
//! owner lives in this resource crate and this module is pure logic over the
//! lease/epoch facts.

use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::RuntimeEpoch;
use exv_vpn_domain::model::PacketLeaseRef;

use crate::packet_attachment::PacketAttachment;

/// A single-use authorization to attach one relay leg to a packet channel.
///
/// Issued fresh (unconsumed) by [`PacketCapability::issue`]; the attach
/// transition ([`PacketCapability::attach`], built on
/// [`PacketCapability::try_consume`]) consumes it exactly once. The test
/// contract pins `issue`/`lease`/`is_consumed`; the consume action is
/// executed atomically by the relay's `attach` so a second stream racing the
/// same capability always loses with `PacketLeaseAlreadyAttached`.
#[derive(Clone, PartialEq, Eq)]
pub struct PacketCapability {
    /// The packet lease this capability binds (the resource the attach grants).
    lease: PacketLeaseRef,
    /// The runtime epoch this capability was issued for.
    epoch: RuntimeEpoch,
    /// Whether the attach transition has already consumed this capability.
    consumed: bool,
}

impl PacketCapability {
    /// Issue a fresh, unconsumed capability binding `lease` to `epoch`.
    #[must_use]
    pub const fn issue(lease: PacketLeaseRef, epoch: RuntimeEpoch) -> Self {
        Self {
            lease,
            epoch,
            consumed: false,
        }
    }

    /// The packet lease this capability binds.
    #[must_use]
    pub fn lease(&self) -> PacketLeaseRef {
        self.lease.clone()
    }

    /// The runtime epoch this capability was issued for.
    #[must_use]
    pub fn epoch(&self) -> RuntimeEpoch {
        self.epoch.clone()
    }

    /// Whether the attach transition has already consumed this capability.
    #[must_use]
    pub const fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Atomically consume the capability exactly once.
    ///
    /// The first call marks the capability consumed and returns `Ok`; any
    /// later call — same capability on any connection, or a concurrent stream
    /// serialized by the caller's lock (the relay contract's two-stream race
    /// serializes through `Arc<Mutex<PacketCapability>>`) — returns
    /// [`ErrorCode::PacketLeaseAlreadyAttached`] and changes no state.
    ///
    /// # Errors
    ///
    /// Returns [`VpnError`] with `PacketLeaseAlreadyAttached` when the
    /// capability is already consumed.
    pub fn try_consume(&mut self) -> Result<(), VpnError> {
        if self.consumed {
            return Err(already_attached(self.epoch.clone()));
        }
        self.consumed = true;
        Ok(())
    }

    /// Execute the atomic attach transition: consume the capability exactly
    /// once and produce the [`PacketAttachment`] binding `connection_id`.
    ///
    /// The transition is single-shot — a second call (even with a different
    /// `connection_id`) is rejected, killing the 'capability consumed twice /
    /// attach not atomic' mutant.
    ///
    /// # Errors
    ///
    /// Returns [`VpnError`] with `PacketLeaseAlreadyAttached` when the
    /// capability is already consumed.
    pub fn attach(&mut self, connection_id: u64) -> Result<PacketAttachment, VpnError> {
        self.try_consume()?;
        Ok(PacketAttachment::new(connection_id, self.lease.clone()))
    }
}

impl std::fmt::Debug for PacketCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque: the lease digest is a sensitive identity fact
        // (plan §5: capability plaintext is never debugged; the domain's
        // `PacketLeaseRef` has no Debug for the same reason). The contract
        // test only needs `Debug` for `Mutex::lock().expect(...)`.
        f.debug_struct("PacketCapability")
            .field("epoch", &self.epoch)
            .field("consumed", &self.consumed)
            .finish_non_exhaustive()
    }
}

/// The typed conflict for a second attach on an already-consumed capability
/// (same construction as the domain `PacketAttachGuard::try_attach`).
fn already_attached(epoch: RuntimeEpoch) -> VpnError {
    VpnError::try_from((
        ErrorCode::PacketLeaseAlreadyAttached,
        ErrorStage::AttachingPacketBoundary,
        EffectCertainty::NoEffect,
        RetryAdvice::DoNotRetry,
        ErrorSubject::Runtime(epoch),
        None,
        None,
    ))
    .expect("valid error tuple")
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
