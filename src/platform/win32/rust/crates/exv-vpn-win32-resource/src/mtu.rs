// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Interface MTU capture / apply / read-back / compare-and-restore (W19).
//!
//! Frozen facts (`docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md`
//! §2, WSP4 elevated measurements) are the contract:
//! - Wintun v4/v6 interface rows start at `NlMtu = 0xFFFF` (Wintun max packet);
//! - `SetIpInterfaceEntry` rejects the Get-filled IPv4 row (`SitePrefixLength=64`)
//!   with 87 unless `SitePrefixLength` is forced to 0 before Set (IPv6 rows have
//!   no such constraint, and are left untouched);
//! - 1420/1280/576/65535 are writable; 0 is a no-op (rc=0 but the read-back
//!   keeps the previous value, it does not reset to default); 1 (below the IPv4
//!   minimum 68) → 87;
//! - a third-party change is detected by read-back (≠ the value we applied);
//!   re-Setting the same value is idempotent;
//! - restore: Set back the original value only when the current value still
//!   equals the applied value (compare-and-restore). Restoring the old snapshot
//!   unconditionally would clobber a third-party change (W19 killer mutant).

use windows::Win32::NetworkManagement::IpHelper::{
    GetIpInterfaceEntry, InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW, SetIpInterfaceEntry,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6};

use crate::native_error::NativeError;

/// IPv4 最小 MTU（低于 68 的 Set 返回 `ERROR_INVALID_PARAMETER`(87)，WSP4 实测）。
const IPV4_MIN_MTU: u32 = 68;
/// Wintun 最大包（0xFFFF = 接口 MTU 上限，WSP4 冻结基准）。
const MTU_MAX: u32 = 0xFFFF;
/// `ERROR_INVALID_PARAMETER`（非法 MTU 值 / Get 填充的 IPv4 行未清 `SitePrefixLength` 直接 Set）。
const ERROR_INVALID_PARAMETER: u32 = 87;

/// The address family of the interface row being managed (WSP4: both the IPv4
/// and IPv6 rows of a Wintun interface are readable and writable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MtuFamily {
    /// IPv4 interface row (`AF_INET`).
    V4,
    /// IPv6 interface row (`AF_INET6`).
    V6,
}

impl MtuFamily {
    /// The `ADDRESS_FAMILY` of this row family.
    #[must_use]
    const fn to_address_family(self) -> ADDRESS_FAMILY {
        match self {
            MtuFamily::V4 => AF_INET,
            MtuFamily::V6 => AF_INET6,
        }
    }
}

/// A captured interface MTU with its interface identity (LUID + family).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtuSnapshot {
    /// The interface LUID the snapshot belongs to.
    pub luid: u64,
    /// The address family of the interface row.
    pub family: MtuFamily,
    /// The captured `NlMtu` value.
    pub value: u32,
}

impl MtuSnapshot {
    /// Build a snapshot with the given identity and value.
    #[must_use]
    pub fn new(luid: u64, family: MtuFamily, value: u32) -> Self {
        Self { luid, family, value }
    }
}

/// Result of a compare-and-restore decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The current value still equals the applied value; the original value was
    /// written back.
    Restored,
    /// A third party changed the value after our apply; restore was skipped so
    /// the third-party value is preserved.
    SkippedThirdPartyChanged,
}

/// An MTU controller over one interface row (`luid` + `family`).
///
/// `capture`/`read_back` are real `GetIpInterfaceEntry` reads (no cached local
/// state — a third-party change must be observable); `apply` is
/// `SetIpInterfaceEntry` with the WSP4-frozen `SitePrefixLength=0` precondition
/// for IPv4 rows.
pub struct MtuController {
    /// The interface LUID the controller operates on.
    luid: u64,
    /// The address family of the interface row.
    family: MtuFamily,
}

impl MtuController {
    /// Build a controller for the interface row identified by `luid` + `family`.
    #[must_use]
    pub fn new(luid: u64, family: MtuFamily) -> MtuController {
        MtuController { luid, family }
    }

    /// Capture the current MTU as a snapshot (`GetIpInterfaceEntry` → `NlMtu`).
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if `GetIpInterfaceEntry` fails (e.g. 1168
    /// `ERROR_NOT_FOUND` for a missing interface).
    pub fn capture(&self) -> Result<MtuSnapshot, NativeError> {
        let _t = crate::timing::Timed::new("resource.mtu.capture");
        let value = read_nl_mtu(self.luid, self.family)?;
        Ok(MtuSnapshot::new(self.luid, self.family, value))
    }

    /// Apply `value` via `SetIpInterfaceEntry` (forcing `SitePrefixLength=0`
    /// before Set, per the WSP4-frozen IPv4 requirement).
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if `value` is rejected by
    /// [`validate_mtu_value`] (code 87) or `SetIpInterfaceEntry` fails.
    pub fn apply(&self, value: u32) -> Result<(), NativeError> {
        let _t = crate::timing::Timed::new("resource.mtu.apply");
        validate_mtu_value(value)?;
        set_nl_mtu(self.luid, self.family, value)
    }

    /// Re-read the current MTU with a fresh `GetIpInterfaceEntry` (a real
    /// system read — never cached or trusted local state, so a third-party
    /// change is detected).
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if the read fails.
    pub fn read_back(&self) -> Result<u32, NativeError> {
        read_nl_mtu(self.luid, self.family)
    }

    /// Compare-and-restore: restore `original.value` only if the current value
    /// still equals `applied.value` (i.e. nobody changed the interface after our
    /// apply). If a third party changed the value, restore is skipped and the
    /// third-party value is preserved (WSP4 §2 / W21: unconditional restore of
    /// the old snapshot would clobber third-party changes).
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if the current-value read or the restore
    /// `SetIpInterfaceEntry` fails.
    pub fn compare_and_restore(
        &self,
        applied: &MtuSnapshot,
        original: &MtuSnapshot,
    ) -> Result<RestoreOutcome, NativeError> {
        let current = self.capture()?;
        match decide_restore(applied, &current) {
            RestoreOutcome::Restored => {
                self.apply(original.value)?;
                Ok(RestoreOutcome::Restored)
            }
            RestoreOutcome::SkippedThirdPartyChanged => {
                Ok(RestoreOutcome::SkippedThirdPartyChanged)
            }
        }
    }
}

/// Compare-and-restore decision (pure logic): restore only if `current.value`
/// still equals `applied.value`. Any difference — including a third party
/// setting the value back to the original — means somebody else touched the
/// interface, and the restore is skipped.
#[must_use]
pub fn decide_restore(applied: &MtuSnapshot, current: &MtuSnapshot) -> RestoreOutcome {
    if current.value == applied.value {
        RestoreOutcome::Restored
    } else {
        RestoreOutcome::SkippedThirdPartyChanged
    }
}

/// Validate an MTU value before applying: `0` (no-op semantics) or
/// `[68..=0xFFFF]` (IPv4 minimum .. Wintun max packet) are legal; anything else
/// is `ERROR_INVALID_PARAMETER` (87), the WSP4-frozen reject code.
///
/// # Errors
///
/// Returns a [`NativeError`] with `code == 87` for values outside `0 |
/// 68..=0xFFFF`.
pub fn validate_mtu_value(value: u32) -> Result<(), NativeError> {
    if value == 0 || (IPV4_MIN_MTU..=MTU_MAX).contains(&value) {
        Ok(())
    } else {
        Err(NativeError::from_win32(
            ERROR_INVALID_PARAMETER,
            "mtu: 非法 MTU 值（0 或 68..=65535）",
        ))
    }
}

/// Read `NlMtu` for the interface row via `GetIpInterfaceEntry` (real read).
fn read_nl_mtu(luid: u64, family: MtuFamily) -> Result<u32, NativeError> {
    let row = interface_row(luid, family)?;
    Ok(row.NlMtu)
}

/// Write `NlMtu` via `SetIpInterfaceEntry`, forcing `SitePrefixLength=0` on the
/// Get-filled IPv4 row first (WSP4 frozen: the IPv4 row comes back with
/// `SitePrefixLength=64` and a direct Set is rejected with 87; IPv6 rows have
/// no such constraint and are left untouched).
fn set_nl_mtu(luid: u64, family: MtuFamily, value: u32) -> Result<(), NativeError> {
    let mut row = interface_row(luid, family)?;
    if family == MtuFamily::V4 {
        row.SitePrefixLength = 0;
    }
    row.NlMtu = value;
    // SAFETY: row 由 GetIpInterfaceEntry 填满（Family+Luid 有效）；
    // IPv4 行 SitePrefixLength 已强制清零（WSP4 实测：不清直接 Set 返回 87）。
    let rc = unsafe { SetIpInterfaceEntry(std::ptr::addr_of_mut!(row)).0 };
    if rc != 0 {
        return Err(NativeError::from_win32(
            rc,
            "mtu: SetIpInterfaceEntry 失败（写入接口 MTU）",
        ));
    }
    Ok(())
}

/// Get a `MIB_IPINTERFACE_ROW` filled by `GetIpInterfaceEntry` for the row
/// identified by `luid` + `family`.
fn interface_row(luid: u64, family: MtuFamily) -> Result<MIB_IPINTERFACE_ROW, NativeError> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: Initialize 写入行（文档模式：Family + InterfaceLuid + Get 填满）。
    unsafe { InitializeIpInterfaceEntry(std::ptr::addr_of_mut!(row)) };
    row.Family = family.to_address_family();
    // SAFETY: NET_LUID_LH 是 union；写成员是安全的（读成员才需 unsafe）。
    row.InterfaceLuid = NET_LUID_LH { Value: luid };
    // SAFETY: row 的 Family+Luid 有效；Get 填满行，返回 WIN32_ERROR（0 = 成功）。
    let rc = unsafe { GetIpInterfaceEntry(std::ptr::addr_of_mut!(row)).0 };
    if rc != 0 {
        return Err(NativeError::from_win32(
            rc,
            "mtu: GetIpInterfaceEntry 失败（读取接口 MTU）",
        ));
    }
    Ok(row)
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
