// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Single logical aggregate owner (W22-I): one type owns both the Wintun
//! adapter and the Wintun packet session (architecture §7.1 — no split
//! adapter/session ownership), and composes the four committed leaf families
//! (W18 address / W19 MTU / W20 routes+bypass / W21 DNS) for full-family
//! capture. The apply/restore orchestration lives in
//! [`crate::apply_tunnel`]; this module holds the composed one-shot capture
//! ([`TunnelSnapshot`]) and the applied state recorded by `apply`.
//!
//! Frozen facts (`docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md`
//! WSP4 §3/§6): bypass is captured/installed **before** the tunnel routes;
//! cleanup runs in reverse install order; compare-and-restore must compare the
//! current state against the applied fingerprint before restoring (an
//! unconditional restore of the old snapshot would clobber third-party
//! changes); a family failure makes `capture` return `Err` — never a partial
//! snapshot with a missing family.

use windows::core::GUID;
use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToGuid;
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

use crate::apply_tunnel::AppliedState;
use crate::dns::DnsCapture;
use crate::dns_types::DnsSettings;
use crate::inventory::{InventoryItem, COMPLETE_INVENTORY};
use crate::ip_address::IpAddressController;
use crate::ip_helper_types::IpAddressRow;
use crate::mtu::{MtuController, MtuFamily, MtuSnapshot};
use crate::native_error::NativeError;
use crate::routes::{capture_rows, RouteRow};
use crate::wintun_adapter::WintunAdapter;
use crate::wintun_session::WintunSession;

/// `ERROR_NOT_FOUND`：V6 接口行不存在（`capture` 中 `mtu_v6` -> None）或 LUID -> GUID
/// 转换失败（DNS 族回读键不可得）。
const ERROR_NOT_FOUND: u32 = 1168;

/// One-shot capture across all four families.
///
/// The field types are exactly the committed leaf types (W18 `IpAddressRow` /
/// W19 `MtuSnapshot` / W20 `RouteRow` / W21 `DnsSettings`) — composition, never
/// reimplementation (redefining row/snapshot types would break the W22-T
/// compile-time seam).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelSnapshot {
    /// W18 类型：接口 IPv4 单播地址行（leaf 回读）。
    pub address_rows: Vec<IpAddressRow>,
    /// W19 类型：IPv4 接口 MTU（leaf 回读）。
    pub mtu_v4: MtuSnapshot,
    /// W19 类型：IPv6 接口 MTU（V6 接口行存在时为 `Some`，不存在时为 `None`）。
    pub mtu_v6: Option<MtuSnapshot>,
    /// W20 类型：接口全部 IPv4 路由行（leaf 回读；含 bypass 行）。
    pub routes: Vec<RouteRow>,
    /// W21 类型：接口 DNS 设置（leaf 回读，顺序保持）。
    pub dns: DnsSettings,
}

/// The single logical aggregate owner: owns both the Wintun adapter and the
/// Wintun packet session (a split owner cannot satisfy the
/// [`Aggregate::new`] signature).
///
/// While alive, [`Aggregate::inventory`] always returns the complete 9-item
/// canonical obligation list (`inventory::is_complete` is always true).
/// Dropping the aggregate ends the session first and closes the adapter after
/// (W17 SAFETY-ORDER): the session's `WintunEndSession` runs before the
/// adapter's close, which — on a creator handle — removes the adapter and all
/// of its IP/routes/DNS, leaving no residue.
pub struct Aggregate {
    /// The packet session, owned by this aggregate.
    ///
    /// `Option` is the explicit ordering mechanism of [`Drop`](Self): the
    /// session is taken out and ended **before** the adapter field drops, so
    /// the W17 SAFETY-ORDER does not depend on field declaration position.
    session: Option<WintunSession>,
    /// The adapter, owned by this aggregate (creator close removes the adapter).
    adapter: WintunAdapter,
    /// Applied state recorded by [`crate::apply_tunnel::apply`] — the
    /// compare-and-restore inputs of [`crate::apply_tunnel::restore`];
    /// `None` while nothing has been applied.
    pub(crate) applied: Option<AppliedState>,
}

impl Aggregate {
    /// The single constructor receiving both owners (a split adapter/session
    /// owner cannot satisfy this signature).
    #[must_use]
    pub fn new(adapter: WintunAdapter, session: WintunSession) -> Self {
        Self {
            session: Some(session),
            adapter,
            applied: None,
        }
    }

    /// The owned adapter (same identity as at creation).
    #[must_use]
    pub fn adapter(&self) -> &WintunAdapter {
        &self.adapter
    }

    /// The owned session (same identity as at creation).
    ///
    /// # Panics
    ///
    /// Never panics: the invariant is that the session is `Some` for the whole
    /// lifetime of the aggregate — it is only taken out inside [`Drop`](Self),
    /// where this accessor is unreachable.
    #[must_use]
    pub fn session(&self) -> &WintunSession {
        self.session
            .as_ref()
            .expect("Aggregate 存活期间 session 恒为 Some（仅 Drop 中 take）")
    }

    /// This aggregate's canonical obligation inventory: always the complete
    /// 9-item list (`inventory::is_complete` holds while the aggregate lives).
    #[must_use]
    pub fn inventory(&self) -> &[InventoryItem] {
        COMPLETE_INVENTORY
    }

    /// Capture the full family state in one read-back composition.
    ///
    /// Every family is read through the committed leaf controllers (real
    /// `Get` calls, never cached): address rows via
    /// [`IpAddressController::capture`], MTU via [`MtuController::capture`]
    /// (V6 row absent -> `mtu_v6: None`, any other V6 failure -> `Err`),
    /// routes via [`capture_rows`] and DNS via [`DnsCapture::capture`] keyed by
    /// the interface GUID.
    ///
    /// # Errors
    ///
    /// Returns a typed [`NativeError`] when any family read fails — a partial
    /// snapshot missing a family is never returned.
    pub fn capture(&self) -> Result<TunnelSnapshot, NativeError> {
        let luid = self.adapter.luid();
        let address_rows = IpAddressController::new(luid).capture()?;
        let mtu_v4 = MtuController::new(luid, MtuFamily::V4).capture()?;
        let mtu_v6 = match MtuController::new(luid, MtuFamily::V6).capture() {
            Ok(snap) => Some(snap),
            Err(e) if e.code == ERROR_NOT_FOUND => None,
            Err(e) => return Err(e),
        };
        let routes = capture_rows(luid)?;
        let guid = luid_to_guid(luid).ok_or_else(|| {
            NativeError::from_win32(
                ERROR_NOT_FOUND,
                "aggregate: 接口 LUID 无法转换为 GUID（DNS 族回读）",
            )
        })?;
        let dns = DnsCapture::capture(&guid)?;
        Ok(TunnelSnapshot {
            address_rows,
            mtu_v4,
            mtu_v6,
            routes,
            dns,
        })
    }
}

impl Drop for Aggregate {
    fn drop(&mut self) {
        // W17 SAFETY-ORDER (frozen, native-wintun-facts.md §2): the session
        // must end BEFORE the adapter close — `WintunEndSession` destroys the
        // session object, and a creator close then removes the adapter with
        // all of its config. Taking the session out first makes the order
        // explicit and independent of field declaration position; the adapter
        // field then drops naturally (`WintunCloseAdapter`), and `applied` is
        // plain data with no drop side effects.
        if let Some(session) = self.session.take() {
            drop(session);
        }
    }
}

/// LUID -> interface GUID (the DNS API key; WSP4-frozen:
/// `ConvertInterfaceLuidToGuid`).
#[must_use]
pub(crate) fn luid_to_guid(luid: u64) -> Option<GUID> {
    let l = NET_LUID_LH { Value: luid };
    let mut guid = GUID::zeroed();
    // SAFETY: guid 由系统填充（ConvertInterfaceLuidToGuid 成功即有效 GUID）。
    if unsafe { ConvertInterfaceLuidToGuid(&raw const l, &raw mut guid) }.0 != 0 {
        return None;
    }
    Some(guid)
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
