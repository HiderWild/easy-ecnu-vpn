// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! `KernelControl` gate: controller transport peer auth before any secret conversion (W27-I).
//!
//! The gate admits `KernelControl` commands through the host pipe. Authorization
//! is strictly first (X71K: secret decode before controller auth is a mutant)
//! and fails closed: an unauthorized secret conversion is refused with no
//! dispatch side effects. Secrets are moved into a [`ClearableSecret`] slot
//! that zeroes its contents on `clear` and on drop — `KernelControl` command
//! secrets must never linger in host memory.

use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::RuntimeEpoch;
use exv_vpn_win32_ipc::peer_auth::VerifiedPipePeer;

use uuid::Uuid;

/// A secret buffer that zeroes its bytes on [`ClearableSecret::clear`] and on
/// drop. `KernelControl` command secrets must never linger after use.
pub struct ClearableSecret {
    /// The secret bytes; zeroed in place by `clear` / `Drop`.
    bytes: Vec<u8>,
}

impl ClearableSecret {
    /// Move `secret` into a zeroable slot.
    ///
    /// The caller's bytes are copied into the slot; the slot owns the secret
    /// from here on and zeroes it on `clear` / drop.
    #[must_use]
    pub fn new(secret: &[u8]) -> Self {
        Self {
            bytes: secret.to_vec(),
        }
    }

    /// The current secret bytes (all zero after [`ClearableSecret::clear`]).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Zero the secret buffer in place (no plaintext remains in the slot).
    pub fn clear(&mut self) {
        for byte in &mut self.bytes {
            *byte = 0;
        }
    }
}

impl Drop for ClearableSecret {
    fn drop(&mut self) {
        self.clear();
    }
}

/// The gate that admits `KernelControl` commands through the host pipe (W27-I).
///
/// Authorization precedes secret conversion (spec §5.2/§9.1): the controller
/// transport peer must be authorized before any secret is converted, and a
/// refused conversion changes no gate or business state (fail closed).
pub struct KernelControlGate {
    /// Whether the controller transport peer has been authorized.
    authorized: bool,
}

impl KernelControlGate {
    /// A fresh gate: unauthorized (fail closed) until [`KernelControlGate::authorize`].
    #[must_use]
    pub fn new() -> Self {
        Self { authorized: false }
    }

    /// Verify the controller transport peer identity and authorize it.
    ///
    /// The peer's identity facts (PID, user SID, account name) must be
    /// present; a peer without verifiable identity facts is refused — the
    /// same fail-closed predicate the host applies to its verified helper
    /// (WSP1 §6, anti fake-helper: an endpoint name alone is not a
    /// capability).
    ///
    /// # Errors
    ///
    /// Returns [`VpnError`] (`ErrorCode::Unauthorized`) when the peer carries
    /// no verifiable identity facts.
    pub fn authorize(&mut self, peer: &VerifiedPipePeer) -> Result<(), VpnError> {
        if peer.process_id == 0 || peer.user_sid.is_empty() || peer.account_name.is_empty() {
            return Err(unauthorized_error());
        }
        self.authorized = true;
        Ok(())
    }

    /// Whether the controller transport peer has been authorized.
    #[must_use]
    pub fn is_authorized(&self) -> bool {
        self.authorized
    }

    /// Convert a controller command secret into a clearable slot.
    ///
    /// Refused while the gate is unauthorized (controller auth precedes
    /// secret conversion); the refusal changes no gate state and dispatches
    /// nothing. After authorization the secret is moved into the returned
    /// [`ClearableSecret`] slot, which zeroes itself on `clear` / drop.
    ///
    /// # Errors
    ///
    /// Returns [`VpnError`] (`ErrorCode::Unauthorized`) when the gate is not
    /// authorized.
    pub fn convert_secret(&mut self, secret: &[u8]) -> Result<ClearableSecret, VpnError> {
        if !self.authorized {
            return Err(unauthorized_error());
        }
        Ok(ClearableSecret::new(secret))
    }
}

impl Default for KernelControlGate {
    fn default() -> Self {
        Self::new()
    }
}

/// The typed fail-closed refusal for the gate's unauthorized paths.
///
/// Deterministic construction (fixed runtime epoch, never carries secret
/// bytes), matching the established `exv_vpn_data_plane` error pattern.
fn unauthorized_error() -> VpnError {
    VpnError::try_from((
        ErrorCode::Unauthorized,
        ErrorStage::Admission,
        EffectCertainty::NoEffect,
        RetryAdvice::DoNotRetry,
        ErrorSubject::Runtime(RuntimeEpoch::try_from(Uuid::from_u128(1)).expect("non-nil uuid")),
        None,
        None,
    ))
    .expect("valid error tuple")
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
