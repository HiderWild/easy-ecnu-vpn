// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! 系统代理豁免条目派生（T5，设计 §5.4 v1 零 wire 变更路径）。
//!
//! 从用户 config 的 `server_bypass_ips`（VPN 服务器 IP）与 `routes`（校园网段
//! CIDR）派生系统代理豁免条目，供 [`crate::kernel_control_service::plan_from_config`]
//! 并入 plan 派生链。转换语义与 win32-resource 车道 `system_proxy_override.rs`
//! 的 `cidr_to_wildcard_opt`（拍板结论 2）一致：
//!
//! - 服务器 IP 直接透传为精确条目；
//! - CIDR 仅 **/8、/16、/24 且网络地址对齐** 转通配形式 `a.*` / `a.b.*` /
//!   `a.b.c.*`；其余前缀长度（含 /0-/7、/9-/15、/17-/23、/25-/31、/32）与
//!   主机位非零（不对齐网段，如 `10.1.2.3/24`）保持原始串 IP 精确条目——不猜、
//!   不归一；
//! - 去重按 ASCII case-insensitive 归一（WinINET 条目比较不区分大小写），保留
//!   首次出现顺序；空输入返回空 vec。
//!
//! EXV_UNFREEZE_PENDING: v1 借道 control_bypass；proxy_exempt 独立字段见
//! docs/superpowers/evidence/2026-08-24-system-proxy-wire-unfreeze.md。

/// 从服务器 IP 列表与 CIDR 网段列表派生系统代理豁免条目（保序去重）。
///
/// - `server_bypass_ips`：VPN 服务器 IP（点分 IPv4）。可解析的直接透传为精确
///   条目；非法条目静默跳过（与 [`plan_from_config`](crate::kernel_control_service::plan_from_config)
///   既有 bypass 装配策略一致）。
/// - `routes_cidrs`：IPv4 CIDR 网段。仅对齐的 /8、/16、/24 转通配形式；其余
///   保持原始串精确条目；无法按 IPv4 CIDR 解析的条目静默跳过。
///
/// 返回值按输入顺序排列（server 组在前、CIDR 组在后），重复条目只保留首次
/// 出现（大小写不敏感）；空输入返回空 vec。
#[must_use]
pub fn derive_proxy_exempt_entries(
    server_bypass_ips: &[String],
    routes_cidrs: &[String],
) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut entries: Vec<String> = Vec::new();
    // server IP：精确条目直接透传（非法条目静默跳过，对齐既有 bypass 装配策略）。
    for ip in server_bypass_ips {
        if ip.trim().parse::<std::net::Ipv4Addr>().is_err() {
            continue;
        }
        push_unique(&mut seen, &mut entries, ip);
    }
    // 校园网段 CIDR → 通配豁免条目（拍板结论 2：仅 /8–/24 整段转 a.b.c.*）。
    for cidr in routes_cidrs {
        match wildcard_or_exact(cidr) {
            Some(entry) => push_unique(&mut seen, &mut entries, &entry),
            None => continue, // 非 IPv4 CIDR：静默跳过（对齐 parse_cidr 过滤策略）。
        }
    }
    entries
}

/// 大小写归一去重追加：key 未出现过则压入（保序）。
fn push_unique(seen: &mut Vec<String>, entries: &mut Vec<String>, entry: &str) {
    let key = entry.to_ascii_lowercase();
    if !seen.contains(&key) {
        seen.push(key);
        entries.push(entry.to_string());
    }
}

/// IPv4 CIDR → 豁免条目：仅对齐 /8→`a.*`、/16→`a.b.*`、/24→`a.b.c.*` 转
/// 通配；其余前缀长度与主机位非零（不对齐）网段保持原串精确条目；无法解析
/// （缺 `/`、段溢出、前缀 >32 等）返回 `None`。
///
/// 语义对齐 win32-resource 车道 `system_proxy_override::cidr_to_wildcard_opt`
/// （拍板结论 2 冻结契约）：主机位非零不猜、不归一。
fn wildcard_or_exact(cidr: &str) -> Option<String> {
    let (addr_part, prefix_part) = cidr.split_once('/')?;
    let prefix: u8 = prefix_part.parse().ok()?;
    // 前缀 >32 非法（u8 可容纳到 255，必须显式拒绝；对齐宿主 parse_cidr 策略）。
    if prefix > 32 {
        return None;
    }
    let octets = parse_ipv4_octets(addr_part)?;
    let addr = u32::from_be_bytes(octets);
    if prefix < 32 {
        let host_bits = u32::from(32 - prefix);
        let mask = (1u32 << host_bits).wrapping_sub(1);
        // 主机位非零 → 非对齐网络地址：保持精确条目，不猜、不归一。
        if addr & mask != 0 {
            return Some(cidr.to_string());
        }
    }
    match prefix {
        8 => Some(format!("{}.*", octets[0])),
        16 => Some(format!("{}.{}.*", octets[0], octets[1])),
        24 => Some(format!("{}.{}.{}.*", octets[0], octets[1], octets[2])),
        _ => Some(cidr.to_string()),
    }
}

/// 解析点分 IPv4 地址为四个八位组（恰四段、每段十进制 0-255、拒绝前导零，
/// 与 `Ipv4Addr::parse` 严格性一致）。
fn parse_ipv4_octets(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for slot in &mut octets {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        *slot = part.parse::<u8>().ok()?;
    }
    parts.next().is_none().then_some(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| (*i).to_string()).collect()
    }

    /// 服务器 IP 直接透传为精确条目，保配置顺序。
    #[test]
    fn derive_proxy_exempt_server_ips_pass_through_in_order() {
        let got = derive_proxy_exempt_entries(&s(&["10.1.1.1", "192.168.1.1"]), &[]);
        assert_eq!(got, s(&["10.1.1.1", "192.168.1.1"]));
    }

    /// 非法服务器 IP 条目静默跳过（对齐既有 bypass 装配策略），合法条目保留。
    #[test]
    fn derive_proxy_exempt_invalid_server_ip_skipped() {
        let got = derive_proxy_exempt_entries(&s(&["not-an-ip", "10.9.9.9", "1.2.3"]), &[]);
        assert_eq!(got, s(&["10.9.9.9"]));
    }

    /// /8 对齐网段 → `a.*`。
    #[test]
    fn derive_proxy_exempt_slash_8_aligned_becomes_first_octet_wildcard() {
        let got = derive_proxy_exempt_entries(&[], &s(&["10.0.0.0/8"]));
        assert_eq!(got, s(&["10.*"]));
    }

    /// /16 对齐网段 → `a.b.*`。
    #[test]
    fn derive_proxy_exempt_slash_16_aligned_becomes_two_octet_wildcard() {
        let got = derive_proxy_exempt_entries(&[], &s(&["172.16.0.0/16"]));
        assert_eq!(got, s(&["172.16.*"]));
    }

    /// /24 对齐网段 → `a.b.c.*`。
    #[test]
    fn derive_proxy_exempt_slash_24_aligned_becomes_three_octet_wildcard() {
        let got = derive_proxy_exempt_entries(&[], &s(&["192.168.1.0/24"]));
        assert_eq!(got, s(&["192.168.1.*"]));
    }

    /// /7（前缀不足 8）不转通配，保持精确条目。
    #[test]
    fn derive_proxy_exempt_slash_7_stays_exact() {
        let got = derive_proxy_exempt_entries(&[], &s(&["10.0.0.0/7"]));
        assert_eq!(got, s(&["10.0.0.0/7"]));
    }

    /// /9（超过 /8 但不足 /16）不转通配，保持精确条目。
    #[test]
    fn derive_proxy_exempt_slash_9_stays_exact() {
        let got = derive_proxy_exempt_entries(&[], &s(&["10.0.0.0/9"]));
        assert_eq!(got, s(&["10.0.0.0/9"]));
    }

    /// /17 不转通配；/25、/26（超过 /24）同样不转通配。
    #[test]
    fn derive_proxy_exempt_slash_17_and_25_and_26_stay_exact() {
        let got = derive_proxy_exempt_entries(
            &[],
            &s(&["192.168.1.0/17", "10.1.1.0/25", "10.1.1.128/26"]),
        );
        assert_eq!(
            got,
            s(&["192.168.1.0/17", "10.1.1.0/25", "10.1.1.128/26"])
        );
    }

    /// /32 单机网段保持精确条目。
    #[test]
    fn derive_proxy_exempt_slash_32_stays_exact() {
        let got = derive_proxy_exempt_entries(&[], &s(&["10.1.1.1/32"]));
        assert_eq!(got, s(&["10.1.1.1/32"]));
    }

    /// 主机位非零（不对齐网络地址）不转通配、不归一：`10.1.2.3/24` 保持原串。
    #[test]
    fn derive_proxy_exempt_misaligned_network_stays_exact_not_normalized() {
        let got = derive_proxy_exempt_entries(&[], &s(&["10.1.2.3/24", "10.1.2.3/8"]));
        assert_eq!(got, s(&["10.1.2.3/24", "10.1.2.3/8"]));
    }

    /// 对齐边界对照：同地址不同前缀只有整段对齐才转（/8 vs /9、/24 vs /25 已覆盖，
    /// 此处补 /16 vs /17 同址对照）。
    #[test]
    fn derive_proxy_exempt_aligned_vs_misaligned_same_address_contrast() {
        let got = derive_proxy_exempt_entries(&[], &s(&["172.16.0.0/16", "172.16.0.0/17"]));
        assert_eq!(got, s(&["172.16.*", "172.16.0.0/17"]));
    }

    /// 无法按 IPv4 CIDR 解析的条目静默跳过（对齐 parse_cidr 过滤策略）。
    #[test]
    fn derive_proxy_exempt_unparseable_cidr_skipped() {
        let got = derive_proxy_exempt_entries(&[], &s(&["no-slash", "1.2.3.4.5/8", "10.0.0.0/33", "10.0.0.256/24"]));
        assert!(got.is_empty(), "非法 CIDR 全部静默跳过");
    }

    /// 去重：大小写归一（WinINET 条目比较不区分大小写）、保首次出现顺序；
    /// server 组在前、CIDR 组在后。
    #[test]
    fn derive_proxy_exempt_dedup_case_insensitive_keeps_first_order_groups_before_cidrs() {
        let got = derive_proxy_exempt_entries(
            &s(&["10.1.1.1", "10.1.1.1"]),
            &s(&["10.1.1.1", "10.0.0.0/8", "10.0.0.0/8"]),
        );
        assert_eq!(got, s(&["10.1.1.1", "10.*"]));
    }

    /// 大小写变体视为同一条目（首现形式保留）。非 IP 字面量先被跳过，此处用
    /// 大小写不同的同形 CIDR 串验证归一去重。
    #[test]
    fn derive_proxy_exempt_case_variants_dedup_to_first_occurrence() {
        let got = derive_proxy_exempt_entries(&s(&["10.1.1.1", "10.0.0.0/8"]), &s(&["10.0.0.0/8"]));
        assert_eq!(got, s(&["10.1.1.1", "10.*"]));
    }

    /// 空输入返回空 vec。
    #[test]
    fn derive_proxy_exempt_empty_inputs_yield_empty_vec() {
        assert!(derive_proxy_exempt_entries(&[], &[]).is_empty());
    }

    /// 综合形态：server 组 + CIDR 组混合派生，组间有序、组内保序。
    #[test]
    fn derive_proxy_exempt_combined_groups_derive_in_order() {
        let got = derive_proxy_exempt_entries(
            &s(&["202.120.80.4", "bad-entry"]),
            &s(&["202.120.80.0/20", "10.0.0.0/8", "192.168.8.0/24"]),
        );
        // /20 与非法条目不转不通配：/20 保持精确；/8、/24 整段转通配。
        assert_eq!(
            got,
            s(&["202.120.80.4", "202.120.80.0/20", "10.*", "192.168.8.*"])
        );
    }
}
