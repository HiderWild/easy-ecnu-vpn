// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Helper-side packet adapter (spec L1011/L1012/L1296/L1300/L1301/L1363, TG-06).
//!
//! Binds a one-shot packet capability to the attached peer, rejects a second attach,
//! refuses an expired / cross-principal / cross-connection capability, gates teardown
//! on BOTH sides actually joining the barrier, refuses `release` until the barrier is
//! released AND the retirement CleanProof is clean, and admits data-plane frames only
//! for the current ownership version. PURE + deterministic: no I/O, no sleep, no
//! randomness.

use exv_vpn_data_plane::attachment::PacketAttachGuard;
use exv_vpn_data_plane::budget::{AdmissionVerdict, DataPlaneDirection, PacketBudget};
use exv_vpn_data_plane::teardown::{JoinOutcome, TeardownBarrier, TeardownSide};
use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::{OperationMethod, OwnershipVersion, RuntimeEpoch};
use exv_vpn_domain::limits::MvpLimits;
use exv_vpn_domain::ports::{AuthorityEpoch, CleanProof, MonotonicTick};
use exv_vpn_resource::authority::{PeerCapability, PeerContext};
use exv_vpn_resource::retirement::validate_clean_proof;

/// The single operation the packet attach capability authorizes.
const PACKET_ATTACH_OPERATION: OperationMethod = OperationMethod::ApplyTunnel;

/// One-shot helper-side packet adapter (spec L1011/L1012/L1296/L1300/L1301/L1363).
pub struct HelperPacketAdapter {
    runtime_epoch: RuntimeEpoch,
    authority: AuthorityEpoch,
    ownership_version: OwnershipVersion,
    capability: Option<PeerCapability>,
    attach_guard: PacketAttachGuard,
    budget: PacketBudget,
    barrier: TeardownBarrier,
    released: bool,
}

impl HelperPacketAdapter {
    /// Build a fresh, unattached adapter for the given epoch / authority / ownership, holding the
    /// provided packet-attach capability and budgeted against `limits`.
    ///
    /// # Errors
    ///
    /// Returns the underlying admission error when `PacketBudget::from_limits` rejects the limits.
    pub fn new(
        runtime_epoch: RuntimeEpoch,
        authority: AuthorityEpoch,
        ownership_version: OwnershipVersion,
        capability: PeerCapability,
        limits: &MvpLimits,
    ) -> Result<Self, VpnError> {
        let budget = PacketBudget::from_limits(limits)?;
        let guard_epoch = runtime_epoch.clone();
        Ok(Self {
            runtime_epoch,
            authority,
            ownership_version,
            capability: Some(capability),
            attach_guard: PacketAttachGuard::new(guard_epoch),
            budget,
            barrier: TeardownBarrier::new(),
            released: false,
        })
    }

    /// Attach the helper to the peer, consuming the one-shot packet capability.
    ///
    /// Rejects an unauthorized / expired capability, a fenced teardown barrier, and a second
    /// attach on an already-held slot.
    ///
    /// # Errors
    ///
    /// Returns a typed `VpnError` when the capability does not authorize the attach, the
    /// barrier is fenced, or the slot is already attached.
    pub fn attach(&mut self, peer: &PeerContext, now: MonotonicTick) -> Result<(), VpnError> {
        if self.barrier.is_released() {
            return Err(admission_err(
                self.runtime_epoch.clone(),
                ErrorStage::AttachingPacketBoundary,
                ErrorCode::DataPlaneBackpressure,
            ));
        }
        if self.attach_guard.is_attached() {
            return Err(admission_err(
                self.runtime_epoch.clone(),
                ErrorStage::AttachingPacketBoundary,
                ErrorCode::PacketLeaseAlreadyAttached,
            ));
        }
        if self
            .capability
            .as_ref()
            .map_or(true, |c| !c.authorizes(
                peer.principal(),
                peer.connection(),
                PACKET_ATTACH_OPERATION,
                self.authority,
                now,
            ))
        {
            return Err(admission_err(
                self.runtime_epoch.clone(),
                ErrorStage::AttachingPacketBoundary,
                ErrorCode::Unauthorized,
            ));
        }
        self.capability = None;
        self.attach_guard.try_attach()
    }

    /// Join the helper's side of the two-sided teardown barrier.
    pub fn join_teardown(&mut self, side: TeardownSide) -> JoinOutcome {
        self.barrier.join(side)
    }

    /// Whether the aggregate teardown barrier has been released (both sides joined).
    #[must_use]
    pub const fn is_teardown_released(&self) -> bool {
        self.barrier.is_released()
    }

    /// Release the helper once the teardown barrier is released AND the retirement CleanProof is clean.
    ///
    /// # Errors
    ///
    /// Returns `Err("teardown barrier")` when the barrier is not yet released, or the
    /// `validate_clean_proof` error when the proof carries unresolved obligations.
    pub fn release(&mut self, proof: &CleanProof) -> Result<(), &'static str> {
        if !self.barrier.is_released() {
            return Err("teardown barrier");
        }
        validate_clean_proof(proof)?;
        self.released = true;
        Ok(())
    }

    /// Admit a data-plane frame for the current ownership version.
    ///
    /// Rejects when the slot is not attached, the teardown barrier is released, the frame carries
    /// a stale ownership version, or the budget refuses the batch.
    ///
    /// # Errors
    ///
    /// Returns a typed `VpnError` for a non-attached slot, a released barrier, a stale ownership
    /// version, or a non-admitted budget verdict.
    pub fn admit_owned_frame(
        &mut self,
        direction: DataPlaneDirection,
        packets: usize,
        bytes: usize,
        frame_ownership_version: OwnershipVersion,
    ) -> Result<(), VpnError> {
        if !self.attach_guard.is_attached() {
            return Err(admission_err(
                self.runtime_epoch.clone(),
                ErrorStage::DataPlane,
                ErrorCode::Unauthorized,
            ));
        }
        if self.barrier.is_released() {
            return Err(admission_err(
                self.runtime_epoch.clone(),
                ErrorStage::DataPlane,
                ErrorCode::DataPlaneBackpressure,
            ));
        }
        if frame_ownership_version != self.ownership_version {
            return Err(admission_err(
                self.runtime_epoch.clone(),
                ErrorStage::DataPlane,
                ErrorCode::ObservedConflict,
            ));
        }
        match self.budget.try_admit(direction, packets, bytes) {
            AdmissionVerdict::Admitted => Ok(()),
            _ => Err(admission_err(
                self.runtime_epoch.clone(),
                ErrorStage::DataPlane,
                ErrorCode::DataPlaneBackpressure,
            )),
        }
    }
}

/// Build a typed admission error shaped like the existing attachment.rs seam.
fn admission_err(epoch: RuntimeEpoch, stage: ErrorStage, code: ErrorCode) -> VpnError {
    VpnError::try_from((
        code,
        stage,
        EffectCertainty::NoEffect,
        RetryAdvice::DoNotRetry,
        ErrorSubject::Runtime(epoch),
        None,
        None,
    ))
    .expect("valid error tuple")
}