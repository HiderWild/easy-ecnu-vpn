// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// C5-pre proxy TUN detection contract (PRD G-⑥, Phase 7). These tests pin the
// pure filter seam in `src/proxy_tun.rs` and run on ANY host — they drive the
// filter with injected [`exv_vpn_win32_resource::proxy_tun::AdapterRecord`]
// lists and never depend on real machine state (a real-machine manual check is
// optional and separate).
//
// Reference semantics (C++ `src/platform/common/proxy_tun_detector.cpp`):
//   - EXV's own adapter is never a proxy TUN (name == exv_interface, or
//     contains "exv", or description contains "openconnect tunnel");
//   - non-proxy virtual adapters are blacklisted (vmware / virtualbox /
//     hyper-v / vethernet / docker / wsl / bluetooth / loopback / tailscale /
//     wireguard / openvpn / zerotier);
//   - detected when name+description carries a proxy token (mihomo / clash /
//     sing-box / …) or is a virtualish TUN adapter (tun / tap / utun / wintun);
//   - route_policy = "exv-before-proxy-tun" when detected, "normal" otherwise.

use exv_vpn_win32_resource::proxy_tun::{
    detection_from_adapters, filter_proxy_tun_adapters, AdapterRecord, KIND_PROXY_TUN,
    ROUTE_POLICY_EXV_BEFORE_PROXY_TUN, ROUTE_POLICY_NORMAL,
};

/// EXV's own `ExvEngine` adapter friendly name (matches the live product).
const EXV_INTERFACE: &str = "ExvEngine";

/// Build an adapter record with a friendly name + optional description.
fn record(name: &str, description: &str, if_index: u32) -> AdapterRecord {
    AdapterRecord {
        name: name.to_string(),
        description: description.to_string(),
        if_index,
    }
}

/// Filter a list of names (with empty description) and return their `if_index`es.
fn detected_indexes(records: &[AdapterRecord], exv_interface: &str) -> Vec<u32> {
    filter_proxy_tun_adapters(records, exv_interface)
        .into_iter()
        .map(|a| a.if_index)
        .collect()
}

#[test]
fn mihomo_tun_adapter_is_detected() {
    let records = [record("Mihomo", "Wintun Userspace Tunnel", 7)];
    let adapters = filter_proxy_tun_adapters(&records, EXV_INTERFACE);
    assert_eq!(adapters.len(), 1);
    assert_eq!(adapters[0].name, "Mihomo");
    assert_eq!(adapters[0].description, "Wintun Userspace Tunnel");
    assert_eq!(adapters[0].if_index, 7);
    assert_eq!(adapters[0].kind, KIND_PROXY_TUN);
}

#[test]
fn clash_tun_adapter_is_detected() {
    let records = [record("Clash", "Clash Virtual Adapter", 9)];
    assert_eq!(detected_indexes(&records, EXV_INTERFACE), vec![9]);
}

#[test]
fn sing_box_tun_adapter_is_detected() {
    let records = [record("sing-box", "TUN mode", 11)];
    assert_eq!(detected_indexes(&records, EXV_INTERFACE), vec![11]);
}

#[test]
fn generic_wintun_tunnel_is_detected_broad_match() {
    // PRD O2: wintun-like virtual adapters are broad-matched even without a
    // named proxy token (e.g. "Meta" adapter whose description is "Wintun").
    let records = [record("Meta", "Wintun Userspace Tunnel", 13)];
    assert_eq!(detected_indexes(&records, EXV_INTERFACE), vec![13]);
}

#[test]
fn generic_tun_is_detected_broad_match() {
    let records = [record("Virtual Tunnel", "TUN adapter", 15)];
    assert_eq!(detected_indexes(&records, EXV_INTERFACE), vec![15]);
}

#[test]
fn exv_own_adapter_is_excluded() {
    // Same friendly name as the EXV interface must never be detected.
    let records = [record(EXV_INTERFACE, "Wintun Userspace Tunnel", 3)];
    assert!(detected_indexes(&records, EXV_INTERFACE).is_empty());
}

#[test]
fn exv_named_adapter_is_excluded_even_when_tun_like() {
    // Friendly name containing "exv" (e.g. "ExvEngine") is excluded even
    // though "wintun" would otherwise broad-match.
    let records = [record("ExvEngine", "Wintun Userspace Tunnel", 3)];
    assert!(detected_indexes(&records, EXV_INTERFACE).is_empty());
}

#[test]
fn openconnect_tunnel_description_is_excluded() {
    // Description containing "openconnect tunnel" marks the EXV data adapter.
    let records = [record("EXV Adapter", "OpenConnect Tunnel", 5)];
    assert!(detected_indexes(&records, EXV_INTERFACE).is_empty());
}

#[test]
fn exv_interface_name_match_is_case_insensitive() {
    let records = [record("exvengine", "Wintun Userspace Tunnel", 3)];
    assert!(detected_indexes(&records, EXV_INTERFACE).is_empty());
}

#[test]
fn blacklisted_virtual_adapters_are_excluded() {
    // Non-proxy virtual adapters (C++ blacklist) must not be reported as proxy
    // TUN even though they contain "tun"-ish tokens.
    let records = [
        record("Tailscale", "Tailscale tunnel", 20),
        record("WireGuard Tunnel", "WireGuard Tunnel Adapter", 21),
        record("OpenVPN TAP", "TAP-Windows Adapter", 22),
        record("vEthernet (Default Switch)", "Hyper-V Virtual Switch", 23),
        record("DockerNAT", "Docker NAT", 24),
        record("Loopback Pseudo-Interface", "Software Loopback Interface", 25),
    ];
    assert!(detected_indexes(&records, EXV_INTERFACE).is_empty());
}

#[test]
fn physical_ethernet_and_wifi_are_not_detected() {
    let records = [
        record("以太网", "Intel(R) Ethernet Connection", 1),
        record("Wi-Fi", "Intel(R) Wi-Fi 6 AX201", 2),
    ];
    assert!(detected_indexes(&records, EXV_INTERFACE).is_empty());
}

#[test]
fn empty_name_is_not_a_candidate() {
    let records = [record("", "Wintun Userspace Tunnel", 30)];
    assert!(detected_indexes(&records, EXV_INTERFACE).is_empty());
}

#[test]
fn multiple_proxy_tuns_are_all_reported() {
    let records = [
        record("Mihomo", "Wintun Userspace Tunnel", 7),
        record("Clash", "Clash Virtual Adapter", 9),
        record("以太网", "Intel(R) Ethernet Connection", 1),
    ];
    assert_eq!(detected_indexes(&records, EXV_INTERFACE), vec![7, 9]);
}

#[test]
fn proxy_token_in_description_only_still_detects() {
    // Token can live in the description, not only the friendly name.
    let records = [record("Meta", "Mihomo TUN adapter", 31)];
    assert_eq!(detected_indexes(&records, EXV_INTERFACE), vec![31]);
}

#[test]
fn matching_is_case_insensitive() {
    let records = [record("MIHOMO", "WINTUN USERSpace Tunnel", 41)];
    assert_eq!(detected_indexes(&records, EXV_INTERFACE), vec![41]);
}

#[test]
fn detection_route_policy_is_exv_before_proxy_tun_when_detected() {
    let records = [record("Mihomo", "Wintun Userspace Tunnel", 7)];
    let adapters = filter_proxy_tun_adapters(&records, EXV_INTERFACE);
    let detection = detection_from_adapters(adapters);
    assert!(detection.detected);
    assert_eq!(detection.adapters.len(), 1);
    assert_eq!(detection.route_policy(), ROUTE_POLICY_EXV_BEFORE_PROXY_TUN);
}

#[test]
fn detection_route_policy_is_normal_when_nothing_detected() {
    let records = [
        record("以太网", "Intel(R) Ethernet Connection", 1),
        record("ExvEngine", "Wintun Userspace Tunnel", 3),
    ];
    let adapters = filter_proxy_tun_adapters(&records, EXV_INTERFACE);
    let detection = detection_from_adapters(adapters);
    assert!(!detection.detected);
    assert!(detection.adapters.is_empty());
    assert_eq!(detection.route_policy(), ROUTE_POLICY_NORMAL);
}

#[test]
fn detection_route_policy_ignores_empty_exv_interface() {
    // Empty exv_interface means "no EXV adapter known"; the ExvEngine name is
    // still excluded via the "exv" token, and a Mihomo TUN is still detected.
    let records = [
        record("Mihomo", "Wintun Userspace Tunnel", 7),
        record("ExvEngine", "Wintun Userspace Tunnel", 3),
    ];
    let adapters = filter_proxy_tun_adapters(&records, "");
    assert_eq!(detected_indexes_from(&adapters), vec![7]);
}

fn detected_indexes_from(adapters: &[exv_vpn_win32_resource::proxy_tun::ProxyTunAdapter]) -> Vec<u32> {
    adapters.iter().map(|a| a.if_index).collect()
}

// ---------------------------------------------------------------------------
// Real Win32 path (state-independent): GetAdaptersAddresses must succeed and
// yield a well-formed detection on ANY Windows host, detected or not. This
// exercises the live enumeration wiring without asserting on machine state.
// ---------------------------------------------------------------------------

#[test]
fn real_detection_succeeds_on_any_host() {
    let detection = exv_vpn_win32_resource::proxy_tun::detect_upstream_proxy_tun(EXV_INTERFACE)
        .expect("GetAdaptersAddresses enumeration must succeed");
    // detected may be true or false (depends on the host); both are valid.
    // Invariant: adapters is empty iff not detected.
    assert!(detection.adapters.is_empty() != detection.detected);
    // route_policy must be one of the two frozen constants.
    assert!(
        detection.route_policy() == ROUTE_POLICY_EXV_BEFORE_PROXY_TUN
            || detection.route_policy() == ROUTE_POLICY_NORMAL
    );
}
