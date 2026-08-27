// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Single-slot packet attach guard (spec TG-06).

use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::RuntimeEpoch;

/// Guards the single packet-boundary attach slot for a runtime epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketAttachGuard {
    runtime_epoch: RuntimeEpoch,
    attached: bool,
}

impl PacketAttachGuard {
    /// Create an unattached guard for the given runtime epoch.
    #[must_use]
    pub const fn new(runtime_epoch: RuntimeEpoch) -> Self {
        Self {
            runtime_epoch,
            attached: false,
        }
    }

    /// Acquire the attach slot; a second call on an already-attached guard is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`exv_vpn_domain::error::ErrorCode::PacketLeaseAlreadyAttached`] when the
    /// slot is already held.
    pub fn try_attach(&mut self) -> Result<(), VpnError> {
        if self.attached {
            return Err(already_attached(self.runtime_epoch.clone()));
        }
        self.attached = true;
        Ok(())
    }

    /// Release the attach slot.
    pub const fn detach(&mut self) {
        self.attached = false;
    }

    /// Whether the slot is currently held.
    #[must_use]
    pub const fn is_attached(&self) -> bool {
        self.attached
    }
}

/// Error for a second attach on an already-held slot.
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