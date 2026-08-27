// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! DNS settings domain types + applied-state fingerprint + compare-and-restore
//! planning (W21). Pure logic only — no Win32 calls here.
//!
//! Frozen facts (`docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md`
//! WSP4 §4): the interface DNS state is a GUID-keyed set of nameservers and
//! search suffixes; the Wintun read-back is an **exact, order-preserving list**
//! (排序指纹会掩盖第三方重排); and compare-and-restore must compare the current
//! state against the **applied** fingerprint before restoring the original
//! snapshot — an unconditional restore would clobber third-party changes.

use sha2::{Digest, Sha256};

/// GUID-keyed interface DNS settings: nameservers + search suffixes, in
/// system order (the Wintun read-back is an exact, order-preserving list).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsSettings {
    /// The interface's DNS servers (system order preserved).
    pub nameservers: Vec<String>,
    /// The interface's DNS search suffixes (system order preserved).
    pub search_suffixes: Vec<String>,
}

impl DnsSettings {
    /// Build settings from the server list and the search suffix list.
    #[must_use]
    pub fn new(nameservers: Vec<String>, search_suffixes: Vec<String>) -> Self {
        Self {
            nameservers,
            search_suffixes,
        }
    }
}

/// A deterministic, **order-sensitive** fingerprint of applied DNS settings
/// (opaque value; only equality is observable).
///
/// The digest is a SHA-256 over a canonical encoding of the nameservers then
/// the search suffixes — each list item NUL-terminated, the two lists separated
/// by `0xFF` (DNS server / suffix values are hostnames or IPs and never contain
/// those bytes, so the encoding is unambiguous). Any value change or reorder
/// changes the digest, so a third-party edit of either list is detected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsFingerprint {
    digest: Vec<u8>,
}

impl DnsFingerprint {
    /// Fingerprint `settings` (nameservers + search suffixes, order-sensitive).
    #[must_use]
    pub fn of(settings: &DnsSettings) -> Self {
        let mut bytes: Vec<u8> = Vec::new();
        for ns in &settings.nameservers {
            bytes.extend_from_slice(ns.as_bytes());
            bytes.push(0);
        }
        bytes.push(0xFF);
        for suffix in &settings.search_suffixes {
            bytes.extend_from_slice(suffix.as_bytes());
            bytes.push(0);
        }
        Self {
            digest: Sha256::digest(&bytes).to_vec(),
        }
    }
}

/// Compare-and-restore planning outcome (W21).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreDecision {
    /// The current state still equals the applied fingerprint: safe to restore
    /// the original snapshot.
    Restore,
    /// The current state differs from the applied fingerprint (a third party
    /// changed the settings): restore must be skipped — an unconditional
    /// restore would clobber the third-party change (WSP4 mutant).
    SkipThirdPartyChange,
}

impl RestoreDecision {
    /// Plan the restore: `Restore` only when `current == applied`; any
    /// divergence means a third party modified the interface since we applied,
    /// so the restore is skipped with a typed conflict.
    #[must_use]
    pub fn plan(current: &DnsFingerprint, applied: &DnsFingerprint) -> Self {
        if current == applied {
            RestoreDecision::Restore
        } else {
            RestoreDecision::SkipThirdPartyChange
        }
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
