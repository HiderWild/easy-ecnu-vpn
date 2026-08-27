// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Native observation of platform resources (W25-I).
//!
//! The observed-state record the recovery engine compares against: pure types
//! and comparison logic, no I/O (架构 §5.1: native observation happens before
//! any action — observe before action; the engine never acts on an unobserved
//! obligation, and a decision carries the observation, never a replayed apply).

use exv_vpn_resource::admission::AppliedFingerprint;

/// One observed platform fact: a canonical inventory obligation's resource
/// identity and its observed fingerprint.
///
/// `obligation` is the `u8` tag of [`crate::inventory::InventoryItem`];
/// `identity_digest` is the platform resource identity (adapter name / address
/// line / ...); `fingerprint` is the observed fingerprint of that resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedResource {
    /// The canonical obligation tag (`inventory::InventoryItem as u8`).
    pub obligation: u8,
    /// The platform resource identity (adapter name / address line / ...).
    pub identity_digest: [u8; 32],
    /// The observed fingerprint of the resource.
    pub fingerprint: [u8; 32],
}

/// The observed fingerprint: a 32-byte digest over an observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedFingerprint([u8; 32]);

impl TryFrom<[u8; 32]> for ObservedFingerprint {
    type Error = &'static str;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        Ok(ObservedFingerprint(bytes))
    }
}

/// Pure-logic observed-state fingerprinting and comparison (W25-I).
#[derive(Debug, Default)]
pub struct NativeObservation;

impl NativeObservation {
    /// A fresh observation-fingerprint computer (pure logic, no I/O).
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// The observed fingerprint of `facts`.
    ///
    /// The recovery engine fingerprints the identity-matched subset of one
    /// admission — at most one fact — so the fingerprint is that resource's
    /// raw observed fingerprint. An empty observation yields the zero digest
    /// (nothing was observed).
    #[must_use]
    pub fn fingerprint(&self, facts: &[ObservedResource]) -> ObservedFingerprint {
        let bytes = facts.first().map_or([0u8; 32], |fact| fact.fingerprint);
        ObservedFingerprint(bytes)
    }

    /// Whether the observed fingerprint equals the durable applied fingerprint.
    ///
    /// The applied fingerprint is opaque by design; both are compared through
    /// the committed construction seam (`AppliedFingerprint::try_from`) and
    /// the derived equality of the committed type — composition, never
    /// reimplementation.
    #[must_use]
    pub fn matches(&self, observed: &ObservedFingerprint, applied: &AppliedFingerprint) -> bool {
        AppliedFingerprint::try_from(observed.0)
            .is_ok_and(|observed_as_applied| observed_as_applied == *applied)
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
