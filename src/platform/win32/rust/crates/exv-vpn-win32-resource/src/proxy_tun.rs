// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Upstream proxy TUN adapter detection (Phase 7 C5-pre, PRD G-⑥).
//!
//! Detects upstream proxy virtual-TUN adapters (Mihomo / Clash / sing-box and
//! wintun-like virtual adapters) so the product can report the coexistence
//! route policy (`route_policy`) and, in a later batch, decide behavior. This
//! stage is **detect-and-report only** — it never changes routing or any other
//! behavior (PRD O1: align with C++ which only reports status).
//!
//! Reference semantics (C++ `src/platform/common/proxy_tun_detector.cpp`, the
//! frozen behavior contract):
//!   - EXV's own adapter is never a proxy TUN: exclude when the friendly name
//!     equals the EXV interface name, or contains "exv", or the description
//!     contains "openconnect tunnel" (our `ExvEngine` adapter).
//!   - Non-proxy virtual adapters are blacklisted (vmware / virtualbox /
//!     hyper-v / vethernet / docker / wsl / bluetooth / loopback / tailscale /
//!     wireguard / openvpn / zerotier).
//!   - A candidate is detected when its combined name+description carries a
//!     proxy token (clash / mihomo / sing-box / tun2socks / …) or is a
//!     virtualish TUN adapter (tun / tap / utun / wintun) — PRD O2 broad match.
//!
//! C5-pre deliberately does **not** inspect the route table (the C++ probe also
//! parses `Get-NetRoute` default/split-default/fake-ip evidence to gate
//! detection on route impact). The route-table dimension is deferred to the
//! C5-wire batch; at detect-only stage the adapter feature match is the
//! decision input, faithful to the C++ token sets. This is recorded in the
//! Phase 7 handoff so C5-wire can re-introduce route-impact gating if needed.
//!
//! The pure filter is separated from Win32 enumeration: unit tests drive the
//! filter with injected [`AdapterRecord`] lists and never depend on real
//! machine state.

use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::Networking::WinSock::AF_UNSPEC;

use crate::native_error::NativeError;

/// Adapter kind emitted for every detected proxy TUN
/// (aligns with C++ `make_proxy_tun_adapter`, `kind="proxy_tun"`).
pub const KIND_PROXY_TUN: &str = "proxy_tun";

/// `route_policy` when an upstream proxy TUN is detected
/// (aligns with C++ `to_json`, `"exv-before-proxy-tun"`).
pub const ROUTE_POLICY_EXV_BEFORE_PROXY_TUN: &str = "exv-before-proxy-tun";

/// `route_policy` when no upstream proxy TUN is detected
/// (aligns with C++ `to_json`, `"normal"`).
pub const ROUTE_POLICY_NORMAL: &str = "normal";

/// `ERROR_BUFFER_OVERFLOW`: first `GetAdaptersAddresses` call asks for size.
const ERROR_BUFFER_OVERFLOW: u32 = 111;

/// A raw adapter record fed to the pure filter (injectable, no Win32
/// dependency). Produced by the Win32 enumerator from `GetAdaptersAddresses`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterRecord {
    /// Friendly name (`FriendlyName`, e.g. "Mihomo" / "Meta" / "以太网").
    pub name: String,
    /// Interface description (`Description`, e.g. "Wintun Userspace Tunnel").
    pub description: String,
    /// IPv4 interface index (`IfIndex`).
    pub if_index: u32,
}

/// A detected upstream proxy TUN adapter (result item).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTunAdapter {
    /// Friendly name.
    pub name: String,
    /// Interface description.
    pub description: String,
    /// IPv4 interface index.
    pub if_index: u32,
    /// Adapter kind — always [`KIND_PROXY_TUN`] (aligns with C++ `kind`).
    pub kind: &'static str,
}

/// Detection outcome for upstream proxy TUN adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTunDetection {
    /// Whether at least one upstream proxy TUN adapter was detected.
    pub detected: bool,
    /// The detected adapters (empty when `detected == false`).
    pub adapters: Vec<ProxyTunAdapter>,
}

impl ProxyTunDetection {
    /// The coexistence route policy: `"exv-before-proxy-tun"` when detected,
    /// `"normal"` otherwise (aligns with C++ `to_json` `route_policy`).
    #[must_use]
    pub fn route_policy(&self) -> &'static str {
        if self.detected {
            ROUTE_POLICY_EXV_BEFORE_PROXY_TUN
        } else {
            ROUTE_POLICY_NORMAL
        }
    }
}

// ---------------------------------------------------------------------------
// Pure filter (unit-tested with injected records; no Win32 calls).
// ---------------------------------------------------------------------------

/// Filter a list of adapter records down to upstream proxy TUN adapters.
///
/// Rules (aligned with C++ `proxy_tun_detector.cpp`, C5-pre detect-only):
///  1. The EXV adapter itself is never a proxy TUN (friendly name equals
///     `exv_interface`, or contains "exv", or description contains
///     "openconnect tunnel").
///  2. Non-proxy virtual adapters are blacklisted.
///  3. A record with an empty name is not a useful candidate.
///  4. A candidate is detected when its combined name+description carries a
///     proxy token (mihomo / clash / sing-box / …) or is a virtualish TUN
///     adapter (tun / tap / utun / wintun) — PRD O2 broad match.
#[must_use]
pub fn filter_proxy_tun_adapters(records: &[AdapterRecord], exv_interface: &str) -> Vec<ProxyTunAdapter> {
    records
        .iter()
        .filter(|r| !r.name.is_empty())
        .filter(|r| !is_exv_adapter(r, exv_interface))
        .filter(|r| !is_blacklisted_adapter(&combined(r)))
        .filter(|r| has_proxy_token(&combined(r)) || is_virtualish_adapter(&combined(r)))
        .map(|r| ProxyTunAdapter {
            name: r.name.clone(),
            description: r.description.clone(),
            if_index: r.if_index,
            kind: KIND_PROXY_TUN,
        })
        .collect()
}

/// Build the detection outcome from a filtered adapter list.
#[must_use]
pub fn detection_from_adapters(adapters: Vec<ProxyTunAdapter>) -> ProxyTunDetection {
    let detected = !adapters.is_empty();
    ProxyTunDetection { detected, adapters }
}

/// Lower-cased `name + " " + description` (matching C++ `lower(name + " " + detail)`).
#[must_use]
fn combined(record: &AdapterRecord) -> String {
    format!("{} {}", record.name, record.description).to_ascii_lowercase()
}

/// Whether this record is EXV's own adapter (never a proxy TUN).
#[must_use]
fn is_exv_adapter(record: &AdapterRecord, exv_interface: &str) -> bool {
    let lower_name = record.name.to_ascii_lowercase();
    let lower_detail = record.description.to_ascii_lowercase();
    let lower_exv = exv_interface.to_ascii_lowercase();
    (!lower_exv.is_empty() && lower_name == lower_exv)
        || lower_name.contains("exv")
        || lower_detail.contains("openconnect tunnel")
}

/// Whether the combined text carries a non-proxy virtual adapter marker
/// (C++ `is_blacklisted_adapter` token set, verbatim).
#[must_use]
fn is_blacklisted_adapter(combined: &str) -> bool {
    const TOKENS: [&str; 13] = [
        "vmware", "virtualbox", "hyper-v", "hyperv", "vethernet", "docker",
        "wsl", "bluetooth", "loopback", "tailscale", "wireguard", "openvpn",
        "zerotier",
    ];
    TOKENS.iter().any(|t| combined.contains(t))
}

/// Whether the combined text carries a known proxy software token
/// (C++ `has_proxy_token` token set, verbatim).
#[must_use]
fn has_proxy_token(combined: &str) -> bool {
    const TOKENS: [&str; 13] = [
        "clash", "mihomo", "sing-box", "singbox", "tun2socks", "nekoray",
        "nekobox", "hiddify", "surge", "stash", "loon", "quantumult",
        "shadowrocket",
    ];
    TOKENS.iter().any(|t| combined.contains(t))
}

/// Whether the combined text looks like a TUN/TAP virtual adapter
/// (C++ `is_virtualish_adapter` token set; "loopback" is blacklisted anyway).
#[must_use]
fn is_virtualish_adapter(combined: &str) -> bool {
    const TOKENS: [&str; 5] = ["tun", "tap", "utun", "wintun", "loopback"];
    TOKENS.iter().any(|t| combined.contains(t))
}

// ---------------------------------------------------------------------------
// Win32 enumeration (two-pass GetAdaptersAddresses; broad AF_UNSPEC match).
// ---------------------------------------------------------------------------

/// Detect upstream proxy TUN adapters on this host.
///
/// Enumerates all adapters via `GetAdaptersAddresses` (`AF_UNSPEC` — broad
/// detection independent of an adapter's IPv4 configuration), collects raw
/// records, and runs the pure filter. Detection-only: no routing or other
/// behavior is touched.
///
/// # Errors
///
/// `GetAdaptersAddresses` failure → [`NativeError`].
pub fn detect_upstream_proxy_tun(exv_interface: &str) -> Result<ProxyTunDetection, NativeError> {
    let records = enumerate_adapter_records()?;
    let adapters = filter_proxy_tun_adapters(&records, exv_interface);
    Ok(detection_from_adapters(adapters))
}

/// Enumerate all adapter records via two-pass `GetAdaptersAddresses`
/// (same pattern as `direct_connect.rs` `find_physical_nics`, but `AF_UNSPEC`
/// and no physical-NIC gating — detection needs every virtual adapter).
fn enumerate_adapter_records() -> Result<Vec<AdapterRecord>, NativeError> {
    let mut size: u32 = 0;
    // SAFETY: first call only queries the required buffer size (adapter buffer
    // None; size filled by the system). AF_UNSPEC = 0 (windows crate constant).
    let rc = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_UNSPEC.0),
            GAA_FLAG_INCLUDE_GATEWAYS,
            None,
            None,
            &raw mut size,
        )
    };
    if rc != 0 && rc != ERROR_BUFFER_OVERFLOW {
        return Err(NativeError::from_win32(rc, "GetAdaptersAddresses 失败"));
    }
    // Alignment: u64 buffer (IP_ADAPTER_ADDRESSES_LH needs 8-byte alignment).
    let mut buf = vec![0u64; size as usize / 8 + 2];
    let ptr = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    // usize -> u32 is intentional: the Win32 API takes a u32 size, and the
    // u64 buffer (8-byte aligned, at least the requested byte size) always fits
    // in u32 on any supported target (direct_connect.rs same pattern).
    #[allow(clippy::cast_possible_truncation)]
    let mut out_size = (buf.len() * 8) as u32;
    // SAFETY: buffer allocated to the requested size and aligned; the system
    // fills the linked list (buf outlives the call).
    let rc = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_UNSPEC.0),
            GAA_FLAG_INCLUDE_GATEWAYS,
            None,
            Some(ptr),
            &raw mut out_size,
        )
    };
    if rc != 0 {
        return Err(NativeError::from_win32(rc, "GetAdaptersAddresses 失败"));
    }
    let mut out = Vec::new();
    // SAFETY: system-filled linked list; Next chain bounded by Length (Windows
    // guarantees valid pointers; same walk as direct_connect.rs).
    let mut cur = ptr;
    while !cur.is_null() {
        let a = unsafe { &*cur };
        // SAFETY: PWSTR strings are null-terminated; to_string reads until NUL.
        let name = unsafe { a.FriendlyName.to_string() }.unwrap_or_default();
        let description = unsafe { a.Description.to_string() }.unwrap_or_default();
        // SAFETY: read union member Anonymous1.Anonymous.IfIndex (IPv4 ifindex;
        // direct_connect.rs same read path).
        let if_index = unsafe { a.Anonymous1.Anonymous.IfIndex };
        out.push(AdapterRecord {
            name,
            description,
            if_index,
        });
        cur = a.Next;
    }
    Ok(out)
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
