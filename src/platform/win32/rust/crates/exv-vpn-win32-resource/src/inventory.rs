// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Canonical obligation inventory (W22-I): the frozen 9-item list of
//! platform obligations owned by the single aggregate
//! (`docs/superpowers/plans/2026-08-12-vpn-rust-native-runtime-mvp-win32-plan.md`
//! W22 row: adapter / session / address / MTU / bypass / routes / DNS / packet /
//! running effects).
//!
//! Architecture §7.1: every live platform ownership has one canonical
//! obligation inventory; proof inventories derive from the durable canonical
//! projection, and a caller cannot arbitrarily omit an item. Windows' single
//! aggregate owns both the Wintun adapter/config and the packet session — no
//! split adapter/session ownership.
//!
//! Pure logic — no Win32 calls.

/// One canonical obligation of the aggregate (plan W22 row, verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryItem {
    /// Wintun adapter (create/open, close removes the adapter on creator).
    Adapter,
    /// Wintun packet session (`WintunStartSession` handle + ring).
    Session,
    /// IPv4 unicast addresses (W18 leaf).
    Address,
    /// Interface MTU, IPv4 + IPv6 rows (W19 leaf).
    Mtu,
    /// Bypass route (W20 leaf; installed before the tunnel routes).
    BypassRoute,
    /// Tunnel routes (W20 leaf).
    Route,
    /// Interface DNS settings (W21 leaf).
    Dns,
    /// Packet attachment (W23B: relay capability ownership).
    PacketAttachment,
    /// Running effects (W24/W25: journaled teardown + recovery).
    RunningEffect,
}

/// The platform-frozen complete inventory: exactly the 9 canonical
/// obligations enumerated by the plan W22 row. Missing any one item is an
/// omit-one-inventory-item mutant.
pub const COMPLETE_INVENTORY: &[InventoryItem] = &[
    InventoryItem::Adapter,
    InventoryItem::Session,
    InventoryItem::Address,
    InventoryItem::Mtu,
    InventoryItem::BypassRoute,
    InventoryItem::Route,
    InventoryItem::Dns,
    InventoryItem::PacketAttachment,
    InventoryItem::RunningEffect,
];

/// Completeness check: all 9 canonical obligations must be present.
///
/// Any omission — however small — makes the inventory incomplete; the
/// aggregate composes the four leaf families (address / MTU / routes+bypass /
/// DNS) plus adapter/session/packet/running-effects obligations, it never
/// re-implements a family behind the inventory's back.
#[must_use]
pub fn is_complete(items: &[InventoryItem]) -> bool {
    COMPLETE_INVENTORY
        .iter()
        .all(|required| items.contains(required))
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
