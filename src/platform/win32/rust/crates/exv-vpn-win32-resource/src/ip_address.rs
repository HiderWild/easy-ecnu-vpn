// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! IPv4 unicast address capture / apply / restore controller (W18).
//!
//! Frozen facts (`docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md`
//! §1/§6, elevated-verified): row identity = `address + interface_luid`; prefix
//! length lives in `OnLinkPrefixLength` (UINT8); create reads back exactly
//! `OnLinkPrefixLength=24`, `PrefixOrigin/SuffixOrigin=1` (Manual),
//! `DadState=1` (Tentative right after create), `SkipAsSource=false`, lifetime
//! 0xffffffff; duplicate create -> 5010 (`ERROR_OBJECT_ALREADY_EXISTS`, not
//! 183); invalid prefix 33 (IPv4 max 32) -> 87 (`ERROR_INVALID_PARAMETER`);
//! missing interface LUID -> 1168 (`ERROR_NOT_FOUND`).
//!
//! Byte order (elevated-verified): `IN_ADDR.S_un.S_addr` is stored in network
//! byte order in memory; on x86 (LE) write with `from_le_bytes`, read with
//! `to_le_bytes` — `from_be_bytes` would write 1.88.88.10 for 10.88.88.1.
//!
//! Each `unsafe` block carries a reviewed `// SAFETY:` comment (workspace
//! enforces `unsafe_op_in_unsafe_fn = deny`).

use std::net::Ipv4Addr;

use windows::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, FreeMibTable,
    GetUnicastIpAddressTable, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

use crate::ip_helper_types::IpAddressPlan;
use crate::ip_helper_types::IpAddressRow;
use crate::native_error::NativeError;

/// WSP4-frozen: duplicate create of an already-existing address -> 5010
/// (`ERROR_OBJECT_ALREADY_EXISTS`, not 183).
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;

/// WSP4-frozen: infinite lifetime read-back is 0xffffffff.
const LIFETIME_INFINITE: u32 = 0xFFFF_FFFF;

/// The outcome of [`IpAddressController::apply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The entry was created (effect happened once).
    Applied,
    /// The exact row already exists (5010) — no second effect.
    AlreadyExists,
}

/// A controller over the IPv4 unicast addresses of one interface
/// (wraps `interface_luid`).
///
/// `capture` reads the real unicast table (never cached); `apply` /
/// `delete` create / delete by the full exact row (`address + interface_luid`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAddressController {
    interface_luid: u64,
}

impl IpAddressController {
    /// Build a controller for the interface with the given 64-bit LUID.
    #[must_use]
    pub const fn new(interface_luid: u64) -> Self {
        Self { interface_luid }
    }

    /// Capture the interface's current IPv4 unicast address rows.
    ///
    /// `GetUnicastIpAddressTable(AF_INET)` filtered to this interface (real
    /// Get, never cached); read-back fields are populated from the OS row.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if the table query fails.
    pub fn capture(&self) -> Result<Vec<IpAddressRow>, NativeError> {
        let _t = crate::timing::Timed::new("resource.ip_address.capture");
        // SAFETY: table 是系统分配的输出指针；成功（rc==0 且非空）后必须 FreeMibTable。
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        let rc = unsafe { GetUnicastIpAddressTable(AF_INET, &raw mut table).0 };
        if rc != 0 || table.is_null() {
            return Err(NativeError::from_win32(
                rc,
                "GetUnicastIpAddressTable 失败",
            ));
        }
        // SAFETY: table 由系统填充；NumEntries 界内访问（显式 from_raw_parts）。
        let table_ref = unsafe { &*table };
        let rows = unsafe {
            std::slice::from_raw_parts(table_ref.Table.as_ptr(), table_ref.NumEntries as usize)
        };
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            // SAFETY: 读 NET_LUID_LH union 成员 Value。
            let luid = unsafe { row.InterfaceLuid.Value };
            if luid == self.interface_luid {
                out.push(ipv4_row_from_mib(row, luid));
            }
        }
        // SAFETY: 释放系统分配的表（成功路径，无早退泄漏）。
        unsafe { FreeMibTable(table.cast()) };
        Ok(out)
    }

    /// Apply (create) an exact row on this interface.
    ///
    /// `CreateUnicastIpAddressEntry` on the full exact row; 5010 is mapped to
    /// [`ApplyOutcome::AlreadyExists`] (no second effect); every other failure
    /// (87 invalid parameter, 1168 missing interface, ...) is a typed
    /// [`NativeError`].
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] for any create failure other than 5010.
    pub fn apply(&self, row: &IpAddressRow) -> Result<ApplyOutcome, NativeError> {
        let _t = crate::timing::Timed::new("resource.ip_address.apply");
        let entry = unicast_entry_for(row);
        // SAFETY: entry 已按文档初始化（InitializeUnicastIpAddressEntry），地址/接口有效。
        let rc = unsafe { CreateUnicastIpAddressEntry(&raw const entry).0 };
        if rc == 0 {
            return Ok(ApplyOutcome::Applied);
        }
        if rc == ERROR_OBJECT_ALREADY_EXISTS {
            return Ok(ApplyOutcome::AlreadyExists);
        }
        Err(NativeError::from_win32(
            rc,
            "CreateUnicastIpAddressEntry 失败",
        ))
    }

    /// Delete an exact row by full identity (`address + interface_luid`).
    ///
    /// `DeleteUnicastIpAddressEntry` matches the full exact row, so an
    /// address-only match can never delete another interface's row.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if the delete fails (e.g. 1168 when the
    /// target identity no longer exists).
    pub fn delete(&self, row: &IpAddressRow) -> Result<(), NativeError> {
        let entry = unicast_entry_for(row);
        // SAFETY: entry 是完整精确行（address + interface_luid）；目标不存在时返回错误码。
        let rc = unsafe { DeleteUnicastIpAddressEntry(&raw const entry).0 };
        if rc == 0 {
            Ok(())
        } else {
            Err(NativeError::from_win32(
                rc,
                "DeleteUnicastIpAddressEntry 失败",
            ))
        }
    }
}

/// Admission: split `desired` into pre-existing (already in `captured`, same
/// identity address+luid — never owned) and to-add (absent — owned by this
/// admission). Identity matching does not compare read-back fields.
#[must_use]
pub fn plan_addresses(captured: &[IpAddressRow], desired: &[IpAddressRow]) -> IpAddressPlan {
    let mut to_add = Vec::new();
    let mut pre_existing = Vec::new();
    for row in desired {
        if captured.iter().any(|c| same_identity(c, row)) {
            pre_existing.push(row.clone());
        } else {
            to_add.push(row.clone());
        }
    }
    IpAddressPlan { to_add, pre_existing }
}

/// Compare-delete planning: the subset of `applied` (owned) rows that still
/// exist **and** whose fingerprint (`address`/`luid`/`prefix`/`skip_as_source`)
/// is unchanged in `current`. Disappeared rows and rows modified by a third
/// party are skipped; pre-existing rows are never in `applied`. Result order
/// preserves `applied` order.
#[must_use]
pub fn restore_owned_addresses(applied: &[IpAddressRow], current: &[IpAddressRow]) -> Vec<IpAddressRow> {
    applied
        .iter()
        .filter(|owned| current.iter().any(|c| same_fingerprint(c, owned)))
        .cloned()
        .collect()
}

/// Row identity = `address + interface_luid` (WSP4 §6). Read-back fields are
/// deliberately not compared.
fn same_identity(a: &IpAddressRow, b: &IpAddressRow) -> bool {
    a.address == b.address && a.interface_luid == b.interface_luid
}

/// Fingerprint for compare-and-restore: `address` / `luid` / `prefix` /
/// `skip_as_source` (WSP4-frozen; read-back fields excluded).
fn same_fingerprint(a: &IpAddressRow, b: &IpAddressRow) -> bool {
    same_identity(a, b)
        && a.on_link_prefix_length == b.on_link_prefix_length
        && a.skip_as_source == b.skip_as_source
}

/// Build the OS entry row for an [`IpAddressRow`] (Initialize + fields).
fn unicast_entry_for(row: &IpAddressRow) -> MIB_UNICASTIPADDRESS_ROW {
    let mut entry = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: Initialize 写入行（iphlpapi 文档要求）。
    unsafe { InitializeUnicastIpAddressEntry(&raw mut entry) };
    entry.Address = sockaddr_ipv4(row.address);
    entry.InterfaceLuid = NET_LUID_LH {
        Value: row.interface_luid,
    };
    entry.OnLinkPrefixLength = row.on_link_prefix_length;
    entry.SkipAsSource = row.skip_as_source;
    entry
}

/// `Ipv4Addr` -> `SOCKADDR_INET` (`S_addr` network byte order; x86 LE:
/// `from_le_bytes`).
fn sockaddr_ipv4(addr: Ipv4Addr) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    // edition 2024：非引用 place 上的 union 字段写是安全操作（先设 family 再写 sin_addr）。
    sa.Ipv4.sin_family = AF_INET;
    sa.Ipv4.sin_addr.S_un.S_addr = u32::from_le_bytes(addr.octets());
    sa
}

/// OS row -> pure row with read-back fields (`S_addr` -> `to_le_bytes`).
fn ipv4_row_from_mib(row: &MIB_UNICASTIPADDRESS_ROW, interface_luid: u64) -> IpAddressRow {
    // SAFETY: 读 SOCKADDR_INET union 的 sin_addr 成员（AF_INET 表查询保证 family）。
    let s_addr = unsafe { row.Address.Ipv4.sin_addr.S_un.S_addr };
    IpAddressRow {
        address: Ipv4Addr::from(s_addr.to_le_bytes()),
        interface_luid,
        on_link_prefix_length: row.OnLinkPrefixLength,
        skip_as_source: row.SkipAsSource,
        prefix_origin: u8::try_from(row.PrefixOrigin.0).unwrap_or(0),
        suffix_origin: u8::try_from(row.SuffixOrigin.0).unwrap_or(0),
        dad_state: u8::try_from(row.DadState.0).unwrap_or(0),
        lifetime_infinite: row.ValidLifetime == LIFETIME_INFINITE
            && row.PreferredLifetime == LIFETIME_INFINITE,
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
