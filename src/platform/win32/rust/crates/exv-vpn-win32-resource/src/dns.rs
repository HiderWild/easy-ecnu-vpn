// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! GUID-keyed DNS capture / apply / compare-and-restore over the real Win32
//! IpHelper DNS settings APIs (W21).
//!
//! Frozen facts (`docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md`
//! WSP4 §4): `GetInterfaceDnsSettings` fills the caller's structure **in place**
//! (`Version = 1` selects the v1 string layout — `0` returns 87), with `Flags`
//! empty; the embedded strings are system-allocated and must be released with
//! `FreeInterfaceDnsSettings`. `SetInterfaceDnsSettings` accepts the v1 string
//! layout on this host (fallback: the 80-byte v2 `DNS_INTERFACE_SETTINGS_EX`
//! layout, where `NameServer`/`SearchList` are still strings — the 104-byte
//! `DNS_ADDRESS_ARRAY` misconstruction dereferences the @24 `{ver,count}` as a
//! `PWSTR` and access-violates). Flag values are hand-written (0x0001 is
//! `DNS_SETTING_IPV6`; 0x0002 = NAMESERVER; 0x0004 = SEARCHLIST — the crate's
//! windows 0.62.2 does not export them). Clearing means empty-string pointers
//! with the flags set (NULL pointers neither clear nor succeed — 87).
//!
//! W21 contract: apply must return the **applied fingerprint** from an
//! independent read-back (API success is not proof); compare-and-restore must
//! compare the current state against the applied fingerprint and skip when a
//! third party modified the interface (typed `SkipThirdPartyChange`, never
//! clobbered); every failure path is a typed [`NativeError`], never silent.

use windows::core::{GUID, HSTRING, PWSTR};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeInterfaceDnsSettings, GetInterfaceDnsSettings, SetInterfaceDnsSettings,
    DNS_INTERFACE_SETTINGS,
};

use crate::dns_types::{DnsFingerprint, DnsSettings, RestoreDecision};
use crate::native_error::NativeError;

/// `DNS_SETTING_NAMESERVER` (windows crate 0.62.2 未导出；WSP4 实测修正：0x0001 是
/// `DNS_SETTING_IPV6`，用错返回 87)。
const DNS_FLAG_NAMESERVER: u64 = 0x0002;
/// `DNS_SETTING_SEARCHLIST`（同上，手写）。
const DNS_FLAG_SEARCH_LIST: u64 = 0x0004;

/// GUID-keyed capture of the live interface DNS settings (W21 seam).
pub struct DnsCapture;

impl DnsCapture {
    /// Read the interface's DNS settings, keyed by interface GUID.
    ///
    /// `GetInterfaceDnsSettings` fills the caller's v1 structure in place
    /// (`Version = 1`); the system-allocated embedded strings are parsed into
    /// [`DnsSettings`] and released with `FreeInterfaceDnsSettings`.
    ///
    /// # Errors
    ///
    /// Returns a typed [`NativeError`] when `GetInterfaceDnsSettings` fails
    /// (e.g. `ERROR_NOT_FOUND` (1168) for an absent interface GUID).
    pub fn capture(interface_guid: &GUID) -> Result<DnsSettings, NativeError> {
        let _t = crate::timing::Timed::new("resource.dns.capture");
        // WSP4 实测修正：Version 必须设为期望布局（1 = v1 字符串格式，与 crate 的
        // DNS_INTERFACE_SETTINGS 布局一致），0 → 87；Get 原地填充，Flags 必须为空。
        let mut storage = DNS_INTERFACE_SETTINGS { Version: 1, ..Default::default() };
        // SAFETY: storage 是调用方所有、Version=1 的 v1 结构，由 Get 原地填充；内嵌
        // 字符串由系统分配，用毕必须 FreeInterfaceDnsSettings 释放（下方解析后释放）。
        let rc = unsafe { GetInterfaceDnsSettings(*interface_guid, &mut storage) }.0;
        if rc != 0 {
            return Err(NativeError::from_win32(
                rc,
                "dns: GetInterfaceDnsSettings failed",
            ));
        }
        let nameservers = pwstr_list(storage.NameServer);
        let search_suffixes = pwstr_list(storage.SearchList);
        // SAFETY: Get 成功，storage 持有系统分配的字符串；必须恰好释放一次。
        unsafe { FreeInterfaceDnsSettings(&mut storage) };
        Ok(DnsSettings::new(nameservers, search_suffixes))
    }
}

/// GUID-keyed apply + applied-fingerprint tracking + compare-and-restore (W21 seam).
pub struct DnsApplier;

impl DnsApplier {
    /// Apply `desired` to the interface and return the **applied fingerprint**.
    ///
    /// Set success is not proof (W21): the returned fingerprint comes from an
    /// independent read-back after the Set, and the read-back must match
    /// `desired` — otherwise the apply is reported as a typed error instead of
    /// silently trusting API success.
    ///
    /// # Errors
    ///
    /// Returns a typed [`NativeError`] if the Set fails (e.g. 87 for a
    /// non-IP nameserver) or the independent read-back does not match
    /// `desired`.
    pub fn apply(
        interface_guid: &GUID,
        desired: &DnsSettings,
    ) -> Result<DnsFingerprint, NativeError> {
        let _t = crate::timing::Timed::new("resource.dns.apply");
        set_dns(interface_guid, desired)?;
        let readback = DnsCapture::capture(interface_guid)?;
        if readback != *desired {
            return Err(NativeError::from_win32(
                0,
                "dns: read-back after apply does not match desired settings",
            ));
        }
        Ok(DnsFingerprint::of(&readback))
    }

    /// Compare-and-restore: restore the `original` snapshot only if the current
    /// state still equals the `applied` fingerprint.
    ///
    /// If a third party modified the interface since [`DnsApplier::apply`], the
    /// restore is skipped with the typed [`RestoreDecision::SkipThirdPartyChange`]
    /// — the third-party change is preserved, never clobbered (WSP4 mutant:
    /// unconditional restore would clobber it). When the interface is
    /// unmodified, the original snapshot is re-applied and the read-back must
    /// match it.
    ///
    /// # Errors
    ///
    /// Returns a typed [`NativeError`] (`restore_failures`, never silent) if
    /// the current state cannot be captured (e.g. absent interface GUID → 1168)
    /// or the re-applied original does not read back identically.
    pub fn restore(
        interface_guid: &GUID,
        applied: &DnsFingerprint,
        original: &DnsSettings,
    ) -> Result<RestoreDecision, NativeError> {
        // Compare first: capture the current state and plan against the applied
        // fingerprint — restore is allowed only when the interface is unmodified.
        let current = DnsCapture::capture(interface_guid)?;
        let decision = RestoreDecision::plan(&DnsFingerprint::of(&current), applied);
        if decision == RestoreDecision::SkipThirdPartyChange {
            return Ok(decision);
        }
        set_dns(interface_guid, original)?;
        // Restore 失败是类型化错误（restore_failures），不得静默：独立回读验证原始快照。
        let verify = DnsCapture::capture(interface_guid)?;
        if DnsFingerprint::of(&verify) != DnsFingerprint::of(original) {
            return Err(NativeError::from_win32(
                0,
                "dns: restore failed to return the interface to the original snapshot",
            ));
        }
        Ok(RestoreDecision::Restore)
    }
}

/// Parse a system-allocated `PWSTR` list (`NameServer`/`SearchList` string:
/// comma- or whitespace-separated values, per the v1 documentation). NULL means
/// the setting is absent → empty list.
fn pwstr_list(p: PWSTR) -> Vec<String> {
    if p.is_null() {
        return Vec::new();
    }
    // SAFETY: p 是 NUL 结尾宽字符串，属系统分配、在 FreeInterfaceDnsSettings 前有效。
    let Some(text) = (unsafe { p.to_string() }).ok() else {
        return Vec::new();
    };
    text.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

/// Set the interface DNS settings (nameservers joined by space; search suffixes
/// joined by space). Empty settings = explicit clear: empty-string pointers
/// with the flags set (NULL pointers neither clear nor succeed — 87, WSP4).
///
/// Strategy (WSP4 实测): try the v1 string layout first; on failure fall back
/// to the full 80-byte v2 (`DNS_INTERFACE_SETTINGS_EX`) layout — the 104-byte
/// `DNS_ADDRESS_ARRAY` misconstruction access-violates (AV 0xC0000005).
fn set_dns(interface_guid: &GUID, settings: &DnsSettings) -> Result<(), NativeError> {
    let nameserver = settings.nameservers.join(" ");
    let search = settings.search_suffixes.join(" ");
    if nameserver.is_empty() && search.is_empty() {
        let (buf, keep) =
            dns_settings_v2_raw_flags("", "", DNS_FLAG_NAMESERVER | DNS_FLAG_SEARCH_LIST);
        // SAFETY: buf 是完整 80 字节 DNS_INTERFACE_SETTINGS_EX 布局；keep 在调用期间存活。
        let rc = unsafe { SetInterfaceDnsSettings(*interface_guid, buf.as_ptr().cast()).0 };
        drop(keep);
        return set_result(rc);
    }
    let (v1_settings, keep_v1) = dns_settings_v1(&nameserver, &search);
    // SAFETY: v1_settings 是合法 v1 结构，PWSTR 指向 keep_v1 的 HSTRING 缓冲区
    // （调用期间存活）。
    let rc_v1 = unsafe { SetInterfaceDnsSettings(*interface_guid, &v1_settings).0 };
    drop(keep_v1);
    if rc_v1 == 0 {
        return Ok(());
    }
    let (v2_buf, keep_v2) = dns_settings_v2_raw_flags(&nameserver, &search, flags_of(settings));
    // SAFETY: v2_buf 是完整 80 字节 v2(EX) 布局（零填充；keep_v2 在调用期间存活）。
    let rc_v2 = unsafe { SetInterfaceDnsSettings(*interface_guid, v2_buf.as_ptr().cast()).0 };
    drop(keep_v2);
    set_result(rc_v2)
}

/// Map a `SetInterfaceDnsSettings` return code to success or a typed error.
fn set_result(rc: u32) -> Result<(), NativeError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(NativeError::from_win32(
            rc,
            "dns: SetInterfaceDnsSettings failed",
        ))
    }
}

/// The v1 `DNS_INTERFACE_SETTINGS` structure (string format; empty string =
/// clear that setting). Returns the structure plus the `HSTRING`s that keep its
/// `PWSTR`s alive — the caller must hold the second element across the Set.
fn dns_settings_v1(nameserver: &str, search: &str) -> (DNS_INTERFACE_SETTINGS, Vec<HSTRING>) {
    let mut settings = DNS_INTERFACE_SETTINGS { Version: 1, ..Default::default() };
    let mut flags = 0u64;
    if !nameserver.is_empty() {
        flags |= DNS_FLAG_NAMESERVER;
    }
    if !search.is_empty() {
        flags |= DNS_FLAG_SEARCH_LIST;
    }
    settings.Flags = flags;
    let ns = HSTRING::from(nameserver);
    let sl = HSTRING::from(search);
    settings.NameServer = PWSTR::from_raw(ns.as_ptr() as *mut u16);
    settings.SearchList = PWSTR::from_raw(sl.as_ptr() as *mut u16);
    (settings, vec![ns, sl])
}

/// The full 80-byte v2 (`DNS_INTERFACE_SETTINGS_EX`) layout, built manually
/// (WSP4 实测修正: `NameServer`/`SearchList` are still **strings**; the
/// 104-byte `DNS_ADDRESS_ARRAY` misconstruction access-violates). Explicit
/// `flags` let the clear path (empty strings + flags set) reuse this builder.
fn dns_settings_v2_raw_flags(
    nameserver: &str,
    search: &str,
    flags: u64,
) -> (Vec<u8>, Vec<HSTRING>) {
    let ns = HSTRING::from(nameserver);
    let sl = HSTRING::from(search);
    let mut buf = vec![0u8; 80];
    let put_u32 = |buf: &mut [u8], off: usize, v: u32| {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };
    let put_u64 = |buf: &mut [u8], off: usize, v: u64| {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    };
    put_u32(&mut buf, 0, 2); // SettingsV1.Version = DNS_INTERFACE_SETTINGS_VERSION2
    put_u64(&mut buf, 8, flags);
    // SettingsV1.Domain @16 = null（buf 已零）。
    // SettingsV1.NameServer @24 / SearchList @32：只要对应 flag 置位就写指针
    // （空字符串指针 = 清空语义；NULL = 不生效——实测 cleanup 用 NULL 返回 87 且不清除）。
    if flags & DNS_FLAG_NAMESERVER != 0 {
        put_u64(&mut buf, 24, ns.as_ptr() as u64);
    }
    if flags & DNS_FLAG_SEARCH_LIST != 0 {
        put_u64(&mut buf, 32, sl.as_ptr() as u64);
    }
    // SettingsV1.RegistrationEnabled..QueryAdapterName @40..56 = 0，ProfileNameServer @56 = null。
    // DisableUnconstrainedQueries @64 = 0；SupplementalSearchList @72 = null（buf 已零）。
    (buf, vec![ns, sl])
}

/// The Set flags for the given settings (0x0002 = NAMESERVER, 0x0004 = SEARCHLIST).
fn flags_of(settings: &DnsSettings) -> u64 {
    let mut flags = 0u64;
    if !settings.nameservers.is_empty() {
        flags |= DNS_FLAG_NAMESERVER;
    }
    if !settings.search_suffixes.is_empty() {
        flags |= DNS_FLAG_SEARCH_LIST;
    }
    flags
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
