// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! WSP4-T Terra oracle：address / MTU / route / DNS 网络设置观测。
//!
//! 本测试在**真实 Windows 宿主**上运行原生 spike seam
//! `run_network_settings_fact_probe`，并断言探针观测到的事实（把它们冻结为契约）。
//! 若未来实现破坏某个冻结事实（例如按 CIDR 直接删路由、无条件恢复 DNS 旧快照、
//! 地址字节序用错、MTU Set 不清 SitePrefixLength、恢复失败静默吞掉），对应测试必然失败。
//!
//! 静态事实（宿主信息、权限判定）无需 admin，任何宿主都必须成立。
//! 动态事实（address/MTU/route/DNS 四族的增删改与 compare-and-restore）需要 admin；
//! 非 elevated 宿主记为 `not_run / blocked_by_environment`（`env_elevated=false`，
//! 动态事实不完整），不伪造。GREEN 固定为 7 passed; 0 failed。

use std::sync::OnceLock;

use exv_vpn_win32_acceptance::network_settings_facts::{
    run_network_settings_fact_probe, NetworkSettingsFacts, SPARK_ADAPTER_NAME, SPARK_DNS_SEARCH,
    SPARK_DNS_SERVER, SPARK_IP_A, SPARK_MTU, SPARK_ROUTE_METRIC,
};

/// 探针只跑一次，各项断言共享同一份观测（保持确定性、避免重复建测试接口）。
fn facts() -> &'static NetworkSettingsFacts {
    static FACTS: OnceLock<NetworkSettingsFacts> = OnceLock::new();
    FACTS.get_or_init(|| {
        let dll = exv_vpn_win32_acceptance::network_settings_facts::resolve_wintun_dll_path(None);
        run_network_settings_fact_probe(&dll)
    })
}

/// 反假绿：探针必须完整返回（默认 facts 非空、host 字段齐全），且权限判定自洽。
#[test]
fn probe_completes_with_host_facts_and_elevation_consistency() {
    let f = facts();
    assert!(!f.host_os.is_empty(), "host_os 必须记录");
    assert!(!f.hostname.is_empty(), "hostname 必须记录");
    assert!(
        !f.env_elevated || f.wintun_dll_loaded,
        "elevated 时必须能加载 Wintun DLL（测试接口载体）"
    );
    // 非 elevated 时动态事实必须不完整（诚实 not_run，不伪造）。
    if !f.env_elevated {
        assert!(!f.is_dynamic_complete(), "非 elevated 时动态事实必须不完整");
    }
}

/// 测试接口身份：elevated 时必须拿到 LUID/index/GUID/alias（Wintun adapter）。
#[test]
fn test_interface_identity_when_elevated() {
    let f = facts();
    if !f.env_elevated {
        return; // not_run_blocked_by_environment
    }
    assert!(
        f.test_if_blocked_reason.is_none(),
        "elevated 时测试接口必须可用，blocked_reason={:?}",
        f.test_if_blocked_reason
    );
    assert_eq!(f.test_if_name.as_deref(), Some(SPARK_ADAPTER_NAME));
    assert!(f.test_if_luid_value.is_some(), "必须取到测试接口 LUID");
    assert!(f.test_if_ifindex.is_some(), "必须取到测试接口 ifIndex");
    assert!(f.test_if_guid.is_some(), "必须取到测试接口 GUID（DNS 族需要）");
    assert!(f.test_if_alias.is_some(), "必须取到测试接口 alias");
}

/// Address 族：精确行身份（实测冻结：OnLinkPrefixLength=24 / PrefixOrigin=Manual(1) /
/// SuffixOrigin=Manual(1) / **DadState=Tentative(1)** / SkipAsSource=false / lifetime 无限 /
/// CreationTimeStamp 可观测）、already-exists（**5010**）、partial/unknown（87/1168）、
/// 第三方删除检测、compare-and-restore。
#[test]
fn address_family_exact_row_identity_and_restore() {
    let f = facts();
    if !f.env_elevated || f.test_if_blocked_reason.is_some() {
        return; // not_run_blocked_by_environment
    }
    assert!(f.address_precondition_clean, "新接口上不得存在测试地址");
    assert!(f.address_prep_no_effect, "只构建行不 Create 必须无副作用");
    assert!(f.address_created, "CreateUnicastIpAddressEntry 必须成功");
    assert_eq!(f.address_create_error, Some(0), "create 必须返回 ERROR_SUCCESS");
    assert_eq!(
        f.address_readback_addr.as_deref(),
        Some(SPARK_IP_A),
        "回读地址必须精确等于所加地址（字节序：S_addr 网络序 → to_le_bytes 还原）"
    );
    assert_eq!(
        f.address_readback_onlink_prefix,
        Some(24),
        "回读 OnLinkPrefixLength 必须等于 24（Win11 SDK 布局：前缀长度在 OnLinkPrefixLength）"
    );
    assert_eq!(
        f.address_readback_prefix_origin,
        Some(1),
        "手动添加地址 PrefixOrigin 必须 = IpPrefixOriginManual(1)"
    );
    assert_eq!(
        f.address_readback_suffix_origin,
        Some(1),
        "手动添加地址 SuffixOrigin 必须 = IpSuffixOriginManual(1)"
    );
    assert_eq!(
        f.address_readback_dad_state,
        Some(1),
        "实测：IPv4 手动地址在 Wintun 接口上 DAD = IpDadStateTentative(1)（创建后立即回读，未收敛到 Preferred）"
    );
    assert_eq!(
        f.address_readback_skip_as_source,
        Some(false),
        "SkipAsSource 必须保持 false（默认）"
    );
    assert_eq!(
        f.address_readback_valid_lifetime,
        Some(u32::MAX),
        "手动地址 ValidLifetime 必须 = 0xffffffff（无限）"
    );
    assert_eq!(
        f.address_readback_preferred_lifetime,
        Some(u32::MAX),
        "手动地址 PreferredLifetime 必须 = 0xffffffff（无限）"
    );
    assert!(
        f.address_readback_creation_ts.is_some(),
        "CreationTimeStamp 必须可观测（Win11 SDK 布局）"
    );
    assert_eq!(
        f.address_already_exists_error,
        Some(5010),
        "实测：重复添加同一地址返回 ERROR_OBJECT_ALREADY_EXISTS(5010)（非 183）"
    );
    assert_eq!(
        f.address_partial_invalid_prefix_error,
        Some(87),
        "IPv4 前缀长度 33 必须返回 ERROR_INVALID_PARAMETER(87)"
    );
    assert_eq!(
        f.address_partial_bogus_interface_error,
        Some(1168),
        "接口 LUID 不存在必须返回 ERROR_NOT_FOUND(1168)"
    );
    assert!(
        f.address_third_party_deleted_detected,
        "第三方删除 .2 后回读必须检测到（.1 在、.2 不在）"
    );
    assert!(
        f.address_restore_verified,
        "compare-and-restore 后测试接口上不得残留探针地址"
    );
}

/// MTU 族：实测冻结——Wintun 接口 v4 行基准 MTU=65535（0xFFFF，Wintun 最大包）；
/// SetIpInterfaceEntry 必须先把 Get 填充行的 SitePrefixLength 清零（IPv4 要求，实测
/// 不清会 87）；1420/1280/576/0/65535 均可写，**0 是无操作**（回读保持原值），1 非法（87）；
/// 第三方改值检测、同值幂等、compare-and-restore；IPv6 行同样可写并恢复。
#[test]
fn mtu_family_set_readback_third_party_and_restore() {
    let f = facts();
    if !f.env_elevated || f.test_if_blocked_reason.is_some() {
        return; // not_run_blocked_by_environment
    }
    assert_eq!(f.mtu_before, Some(65535), "Wintun 接口 v4 基准 MTU = 0xFFFF");
    assert_eq!(f.mtu_v6_before, Some(65535), "Wintun 接口 v6 基准 MTU = 0xFFFF");
    assert!(f.mtu_prep_no_effect, "只构建行不 Set 必须无副作用");
    assert!(f.mtu_applied, "SetIpInterfaceEntry(NlMtu=1420, SitePrefixLength=0) 必须成功");
    assert_eq!(f.mtu_apply_error, Some(0));
    assert_eq!(f.mtu_after, Some(SPARK_MTU), "Set 后回读必须等于所设值");
    // 逐值尝试（实测冻结）：
    let by_value = |v: u32| f.mtu_set_attempts.iter().find(|a| a.value == v);
    assert_eq!(by_value(1420).map(|a| a.rc), Some(0), "1420 可写");
    assert_eq!(by_value(1280).map(|a| a.rc), Some(0), "1280 可写");
    assert_eq!(by_value(576).map(|a| a.rc), Some(0), "576 可写");
    assert_eq!(
        by_value(0).map(|a| a.rc),
        Some(0),
        "0 = 无操作（成功但不变）"
    );
    assert_eq!(
        by_value(0).and_then(|a| a.readback),
        Some(576),
        "实测：Set(0) 后回读保持上一个值（576），不重置为默认"
    );
    assert_eq!(by_value(65535).map(|a| a.rc), Some(0), "65535（当前值）可写");
    assert_eq!(
        by_value(1).map(|a| a.rc),
        Some(87),
        "MTU=1（低于 IPv4 最小 68）必须返回 ERROR_INVALID_PARAMETER(87)"
    );
    assert!(
        f.mtu_third_party_detected,
        "第三方改值（1400）后回读必须检测到（≠ 我们的 1420）"
    );
    assert!(
        f.mtu_same_value_idempotent,
        "同值再 Set 必须成功且状态不变（幂等）"
    );
    assert_eq!(
        f.mtu_illegal_value_error,
        Some(87),
        "非法值（1）必须产生 ERROR_INVALID_PARAMETER"
    );
    assert!(
        f.mtu_restore_verified,
        "compare-and-restore 后 v4/v6 MTU 必须回到基准值 65535"
    );
    assert!(
        f.probe_notes.iter().any(|n| n.contains("mtu v4 row dump") && n.contains("siteprefix=")),
        "Get 填充的 v4 行 SitePrefixLength 观测必须记录在 notes（Set 前必须清零）"
    );
}

/// Route 族（实测冻结）：bypass 路由（加隧道路由**之前**，本宿主为 Mihomo 接口的默认路由）；
/// **CreateIpForwardEntry2 正确构造 = Initialize + dest/nexthop/luid（+metric/lifetime）**——
/// 字节序用错（host-order 写 S_addr）时前缀含主机位 → 87；回读精确行
/// （metric=5 / protocol=MIB_IPPROTO_NETMGMT(3) / nexthop=10.88.88.1 / luid 匹配）；
/// **GetBestRoute2 无源限制仍返回 bypass（Wintun 接口未"connected"，隧道路由不参与
/// 无源查找）；带源限制的查找返回 1168**；already-exists=5010；partial=87；
/// 第三方 Get+Delete 检测；**mutant：Get 按 CIDR 通配匹配（rc=0）但直接 Delete 必须
/// 失败（rc=2）——必须先 Get 填满精确行再 Delete**；恢复回 bypass。
#[test]
fn route_family_bypass_exact_row_mutant_and_restore() {
    let f = facts();
    if !f.env_elevated || f.test_if_blocked_reason.is_some() {
        return; // not_run_blocked_by_environment
    }
    assert!(
        f.route_bypass_before_dest.is_some(),
        "加隧道路由前必须能观测到 bypass 路由（GetBestRoute2）"
    );
    assert_eq!(
        f.route_bypass_before_dest.as_deref(),
        Some("0.0.0.0/0"),
        "本宿主 10.99.99.2 的 bypass 是默认路由（无更精确路由）"
    );
    assert!(f.route_bypass_before_nexthop.is_some(), "bypass 路由必须带 next-hop");
    assert!(f.route_bypass_before_interface_alias.is_some(), "bypass 接口别名必须可观测");
    assert!(f.route_prep_no_effect, "只构建行不 Create 必须无副作用");
    assert!(
        f.route_created,
        "CreateIpForwardEntry2（正确字节序的 init+full 行）必须成功"
    );
    assert_eq!(
        f.route_create_success_variant.as_deref(),
        Some("init+full"),
        "标准文档构造（Initialize + dest/nexthop/luid）必须是首个成功变体"
    );
    assert_eq!(f.route_create_error, Some(0));
    assert_eq!(
        f.route_readback_metric,
        Some(SPARK_ROUTE_METRIC),
        "回读精确行 Metric 必须等于所设值"
    );
    assert_eq!(
        f.route_readback_protocol,
        Some(3),
        "CreateIpForwardEntry2 添加的路由 Protocol 必须 = MIB_IPPROTO_NETMGMT(3)"
    );
    assert_eq!(
        f.route_readback_nexthop.as_deref(),
        Some(SPARK_IP_A),
        "回读精确行 NextHop 必须等于所设值"
    );
    assert!(
        f.route_readback_luid_matches,
        "回读行 InterfaceLuid 必须等于测试接口 LUID"
    );
    assert!(
        !f.route_superseded_bypass,
        "实测冻结：GetBestRoute2（无源限制）在 Wintun 接口上仍返回 bypass——隧道路由在表内但不参与无源查找（接口未 connected）；带源限制的查找是 VPN 的正确姿势"
    );
    assert_eq!(
        f.route_already_exists_error,
        Some(5010),
        "实测：重复添加同一精确路由行返回 ERROR_OBJECT_ALREADY_EXISTS(5010)"
    );
    assert_eq!(
        f.route_partial_invalid_prefix_error,
        Some(87),
        "前缀长度 33 必须返回 ERROR_INVALID_PARAMETER(87)"
    );
    assert!(
        f.route_third_party_delete_detected,
        "第三方删除后回读必须检测到（absent 且 best 回到 bypass）"
    );
    // mutant 语义（实测冻结）：
    assert_eq!(
        f.route_mutant_delete_by_cidr_only_error,
        Some(0),
        "GetIpForwardEntry2 对 dest-only key 通配匹配并填满行（rc=0）——'按 CIDR 查'可行"
    );
    assert!(
        f.probe_notes
            .iter()
            .any(|n| n.contains("route mutant delete-by-CIDR-only-direct: rc=2")),
        "直接按 CIDR Delete（未 Get 填行）必须失败 rc=2（ERROR_FILE_NOT_FOUND）——删除必须用精确行"
    );
    assert!(
        f.route_delete_full_row_succeeded,
        "Get 填满精确行后 DeleteIpForwardEntry2 必须成功"
    );
    assert!(
        f.route_restore_verified,
        "compare-and-restore 后 GetBestRoute2 必须回到 bypass 路由"
    );
    assert!(
        f.probe_notes
            .iter()
            .any(|n| n.contains("route best-after (source=10.88.88.1): GetBestRoute2 rc=1168")),
        "带源限制的 GetBestRoute2 在 Wintun 接口上必须观测到 1168（ERROR_NOT_FOUND）——冻结该语义"
    );
}

/// DNS 族（实测冻结）：**GetInterfaceDnsSettings 是原地填充（Version 必须设为 1/2/3，
/// 0 会 87）**；v1 字符串布局可用；**Flags 文档值 = NAMESERVER 0x0002 / SEARCHLIST 0x0004
/// （0x0001 是 IPV6——用错 87）**；capture → apply → read-back fingerprint → 第三方冲突 →
/// **mutant：无条件恢复旧快照会覆盖第三方变更（compare-and-restore 必须比较）** →
/// 最终状态 == 原始状态。
#[test]
fn dns_family_fingerprint_third_party_and_compare_restore() {
    let f = facts();
    if !f.env_elevated || f.test_if_blocked_reason.is_some() {
        return; // not_run_blocked_by_environment
    }
    assert_eq!(
        f.dns_before_version,
        Some(1),
        "GetInterfaceDnsSettings(Version=1) 原地填充 v1 布局"
    );
    assert_eq!(f.dns_before_flags, Some(0), "全新 Wintun 接口 flags=0");
    assert!(
        f.dns_before_nameservers.is_empty() && f.dns_before_search_list.is_empty(),
        "全新 Wintun 接口的 DNS 快照必须为空"
    );
    assert!(f.dns_prep_no_effect, "只构建 settings 不 Set 必须无副作用");
    assert!(f.dns_applied, "SetInterfaceDnsSettings（v1 + 正确 flags）必须成功");
    assert_eq!(f.dns_apply_error, Some(0));
    assert_eq!(f.dns_set_version_used, Some(1), "v1 Set 在 Win11 26200 可用");
    assert!(
        f.dns_readback_nameservers.contains(&SPARK_DNS_SERVER.to_string()),
        "回读 nameserver 必须包含所设的 {}（指纹）",
        SPARK_DNS_SERVER
    );
    assert!(
        f.dns_readback_search_list.contains(&SPARK_DNS_SEARCH.to_string()),
        "回读 search list 必须包含所设的 {}",
        SPARK_DNS_SEARCH
    );
    assert!(
        f.dns_third_party_detected,
        "第三方改值后回读必须检测到（≠ 我们的值）"
    );
    assert!(
        f.dns_same_value_idempotent,
        "同值再 Set 必须成功且状态不变（幂等）"
    );
    assert_eq!(
        f.dns_partial_unknown_error,
        Some(87),
        "非法 nameserver（非 IP）必须返回 ERROR_INVALID_PARAMETER(87)"
    );
    // mutant 语义：当前状态 ≠ 原始快照 → compare-and-restore 必须跳过恢复，
    // 无条件恢复旧快照会覆盖第三方变更（该 mutant 是 W20/W21 的反例）。
    assert!(
        f.dns_restore_skipped_third_party,
        "第三方变更存在时恢复必须被跳过（不得无条件恢复旧快照）"
    );
    assert!(
        f.dns_mutant_unconditional_restore_would_clobber,
        "无条件恢复旧快照会覆盖第三方变更（mutant 事实必须为真）"
    );
    assert!(
        f.dns_final_state_equals_original,
        "清理后最终状态必须等于原始快照（fingerprint 一致）"
    );
}

/// 反假绿：`is_dynamic_complete` 在 elevated 且四族全部观测成功时必须为真；
/// 恢复失败列表为空；测试接口（adapter）必须被移除。
#[test]
fn dynamic_complete_restore_ok_and_adapter_cleanup() {
    let f = facts();
    if !f.env_elevated {
        return; // not_run_blocked_by_environment
    }
    if f.test_if_blocked_reason.is_some() {
        return; // 环境阻塞（如 Wintun 不可用）：诚实 not_run，不伪造动态断言
    }
    assert!(
        f.is_dynamic_complete(),
        "elevated 且四族成功时所有动态事实必须完整观测"
    );
    assert!(
        f.restore_ok,
        "恢复失败必须为空（类型化恢复失败: {:?}）",
        f.restore_failures
    );
    assert!(
        f.restore_failures.is_empty(),
        "restore_failures 必须为空列表，got {:?}",
        f.restore_failures
    );
    assert!(
        f.adapter_removed_by_close,
        "创建者 WintunCloseAdapter 后测试接口必须被移除（无残留）"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
