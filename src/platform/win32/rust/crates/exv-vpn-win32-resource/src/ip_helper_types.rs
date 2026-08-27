// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Pure IPv4 unicast address row / plan types (W18).
//!
//! Frozen facts (`docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md`
//! §6): row identity is `address + interface_luid`; prefix length lives in
//! `OnLinkPrefixLength` (UINT8). The read-back fields (prefix/suffix origin,
//! dad state, lifetime) are filled by `capture` and never participate in
//! identity or fingerprint comparison. This module is pure logic — no Win32
//! calls.

use std::net::Ipv4Addr;

/// A single IPv4 unicast address row on an interface.
///
/// Identity is `address + interface_luid` (WSP4 §6); the read-back fields
/// (`prefix_origin`, `suffix_origin`, `dad_state`, `lifetime_infinite`) are
/// populated by [`crate::ip_address::IpAddressController::capture`] and are
/// not part of identity or fingerprint comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressRow {
    /// The IPv4 address.
    pub address: Ipv4Addr,
    /// The interface LUID the row lives on (64-bit).
    pub interface_luid: u64,
    /// `OnLinkPrefixLength` (UINT8) — IPv4 max is 32.
    pub on_link_prefix_length: u8,
    /// `SkipAsSource` — false for the rows this crate creates (WSP4 frozen).
    pub skip_as_source: bool,
    /// `PrefixOrigin` (`MIB_IP_ORIGIN`) — read-back only, filled by capture.
    pub prefix_origin: u8,
    /// `SuffixOrigin` (`MIB_IP_ORIGIN`) — read-back only, filled by capture.
    pub suffix_origin: u8,
    /// `DadState` (`MIB_IP_DAD_STATE`) — read-back only, filled by capture.
    pub dad_state: u8,
    /// Read-back lifetime is infinite (0xffffffff) — read-back only.
    pub lifetime_infinite: bool,
}

impl IpAddressRow {
    /// Build an input row for apply: `skip_as_source=false` (WSP4 frozen); the
    /// read-back fields are left as neutral defaults and filled by capture.
    #[must_use]
    pub const fn new(address: Ipv4Addr, interface_luid: u64, on_link_prefix_length: u8) -> Self {
        Self {
            address,
            interface_luid,
            on_link_prefix_length,
            skip_as_source: false,
            prefix_origin: 0,
            suffix_origin: 0,
            dad_state: 0,
            lifetime_infinite: false,
        }
    }
}

/// The admission plan for a desired set of rows against a captured table.
///
/// Rows already present (same identity `address + interface_luid`) are
/// `pre_existing` and never owned; the rest are `to_add` and become owned by
/// this admission. Identity matching does not compare read-back fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressPlan {
    /// Desired rows absent from the captured table — this admission will own them.
    pub to_add: Vec<IpAddressRow>,
    /// Desired rows already present — never owned, never deleted by restore.
    pub pre_existing: Vec<IpAddressRow>,
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
