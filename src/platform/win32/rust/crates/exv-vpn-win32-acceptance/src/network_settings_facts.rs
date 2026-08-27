// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! WSP4 事实探针：address / MTU / route / DNS 观测 spike（Win32 IpHelper 原生 API）。
//!
//! 本模块在**真实 Windows 宿主**（需管理员）上运行，用 `windows` crate（0.62.2）的
//! IpHelper 原生 API 直接冻结网络设置事实：
//!
//! - **Address**：`CreateUnicastIpAddressEntry` / `DeleteUnicastIpAddressEntry` /
//!   `GetUnicastIpAddressTable`——在探针自建的 Wintun 测试接口上增删 IPv4 地址，
//!   回读精确行（地址/前缀/on-link prefix/PrefixOrigin/SuffixOrigin/DadState/
//!   SkipAsSource/lifetime/CreationTimeStamp），already-exists 与非法参数行为。
//! - **MTU**：`GetIpInterfaceEntry` / `SetIpInterfaceEntry`——读基准 MTU，改值回读，
//!   第三方改值检测，同值幂等，非法值行为，compare-and-restore。
//! - **Route**：`GetBestRoute2`（加隧道路由**之前**的 bypass 路由）→
//!   `CreateIpForwardEntry2`（精确行）→ 回读精确行 → `GetBestRoute2` 确认隧道路由
//!   取代 bypass → 第三方删除 → **mutant：按 CIDR 单独删（必须用精确行）** →
//!   正确路径（`GetIpForwardEntry2` 填满行后 `DeleteIpForwardEntry2`）→ 恢复。
//! - **DNS**：`GetInterfaceDnsSettings` / `SetInterfaceDnsSettings`（v1 字符串格式 +
//!   v2 数组格式回退）——capture → apply → read-back fingerprint → 第三方冲突 →
//!   **mutant：无条件恢复旧快照会覆盖第三方变更（compare-and-restore 必须比较）**。
//!
//! 测试接口 = 探针自建 Wintun adapter（`ExvNetSpike`，WSP3 冻结路径加载 DLL；驱动在
//! 本宿主已安装且运行）。所有变更均在探针结束时 compare-and-restore；恢复失败是
//! **类型化错误**（记入 `restore_failures`），不是静默。本文件是 Terra 冻结的 seam
//! （`WSP4-T`）：oracle 测试与 `exv-win32-network-settings-spike` 二进制都调用
//! `run_network_settings_fact_probe()`。
//!
//! 事实权威文件：
//! `docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md`。
//!
//! 需要管理员；非 elevated 时动态部分记为 `not_run / blocked_by_environment`，不伪造。
//! 这是平台 FFI 路径：`unsafe` 经过审阅，每块带 `// SAFETY:`，工作区强制
//! `unsafe_op_in_unsafe_fn = deny`。

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use serde::Serialize;

use windows::core::{GUID, HSTRING, PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE, ERROR_INVALID_PARAMETER};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex,
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, FreeInterfaceDnsSettings, FreeMibTable, GetBestRoute2,
    GetInterfaceDnsSettings, GetIpForwardEntry2, GetIpForwardTable2, GetIpInterfaceEntry,
    GetUnicastIpAddressTable, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, SetInterfaceDnsSettings, SetIpForwardEntry2,
    SetIpInterfaceEntry, DNS_INTERFACE_SETTINGS, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, MIB_IPPROTO_NETMGMT, NlroManual,
    SOCKADDR_INET,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

/// 探针自建的测试接口（Wintun adapter）名称。
pub const SPARK_ADAPTER_NAME: &str = "ExvNetSpike";
/// WintunCreateAdapter 的 TunnelType 参数。
pub const SPARK_TUNNEL_TYPE: &str = "EXV VPN";
/// 地址族测试地址（保持到探针结束，作为路由族 next-hop）。
pub const SPARK_IP_A: &str = "10.88.88.1";
/// 地址族第三方删除测试地址。
pub const SPARK_IP_B: &str = "10.88.88.2";
/// 地址族 partial 测试地址。
pub const SPARK_IP_C: &str = "10.88.88.3";
/// 地址族前缀长度。
pub const SPARK_PREFIX_LEN: u8 = 24;
/// 路由族目标网络 / 探测地址 / 前缀 / 度量。
pub const SPARK_ROUTE_NETWORK: &str = "10.99.99.0";
pub const SPARK_ROUTE_PROBE: &str = "10.99.99.2";
pub const SPARK_ROUTE_PREFIX_LEN: u8 = 24;
pub const SPARK_ROUTE_METRIC: u32 = 5;
/// MTU 测试值（应用）/ 第三方改值 / 非法值。
pub const SPARK_MTU: u32 = 1420;
pub const SPARK_MTU_THIRD_PARTY: u32 = 1400;
pub const SPARK_MTU_ILLEGAL: u32 = 1;
/// DNS 测试值（应用）/ 第三方改值 / search list。
pub const SPARK_DNS_SERVER: &str = "10.88.88.53";
pub const SPARK_DNS_SERVER_TP: &str = "10.88.88.54";
pub const SPARK_DNS_SEARCH: &str = "exv.test";

// DNS_INTERFACE_SETTINGS Flags（当前 SDK 文档值；windows crate 0.62.2 未导出这些常量）。
// 实测教训：0x0001 是 DNS_SETTING_IPV6，0x0002 是 NAMESERVER，0x0004 是 SEARCHLIST——
// 用错（0x1/0x2）会让 Set 返回 ERROR_INVALID_PARAMETER(87)。
const DNS_FLAG_NAMESERVER: u64 = 0x0002;
const DNS_FLAG_SEARCH_LIST: u64 = 0x0004;

/// 冻结的默认 Wintun DLL 搜索路径（可被 `EXV_RUST_VPN_WINTUN_DLL` 覆盖）。
pub fn default_wintun_dll_path() -> PathBuf {
    PathBuf::from("C:\\Users\\TomLi\\.exv\\wintun\\wintun\\bin\\amd64\\wintun.dll")
}

/// 解析 Wintun DLL 搜索路径：显式 > 环境变量 > 冻结默认值。
pub fn resolve_wintun_dll_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    std::env::var_os("EXV_RUST_VPN_WINTUN_DLL")
        .map(PathBuf::from)
        .unwrap_or_else(default_wintun_dll_path)
}

/// MTU Set 尝试的观测结果。
#[derive(Clone, Debug, Serialize)]
pub struct MtuAttempt {
    pub value: u32,
    pub rc: u32,
    pub readback: Option<u32>,
}

/// 路由 Create 变体的观测结果。
#[derive(Clone, Debug, Serialize)]
pub struct RouteVariantResult {
    pub label: String,
    pub rc: u32,
}

/// 一次事实探针的完整观测结果。serde 可序列化为 JSON evidence。
#[derive(Clone, Debug, Serialize)]
pub struct NetworkSettingsFacts {
    // 宿主与权限
    pub host_os: String,
    pub hostname: String,
    pub env_elevated: bool,
    // 测试接口（Wintun adapter）
    pub wintun_dll_path: String,
    pub wintun_dll_loaded: bool,
    pub test_if_blocked_reason: Option<String>,
    pub test_if_name: Option<String>,
    pub test_if_luid_value: Option<u64>,
    pub test_if_ifindex: Option<u32>,
    pub test_if_guid: Option<String>,
    pub test_if_alias: Option<String>,
    // ---- Address 族 ----
    pub address_precondition_clean: bool,
    pub address_prep_no_effect: bool,
    pub address_created: bool,
    pub address_create_error: Option<u32>,
    pub address_readback_addr: Option<String>,
    pub address_readback_onlink_prefix: Option<u8>,
    pub address_readback_prefix_origin: Option<i32>,
    pub address_readback_suffix_origin: Option<i32>,
    pub address_readback_dad_state: Option<i32>,
    pub address_readback_skip_as_source: Option<bool>,
    pub address_readback_valid_lifetime: Option<u32>,
    pub address_readback_preferred_lifetime: Option<u32>,
    pub address_readback_creation_ts: Option<i64>,
    pub address_third_party_deleted_detected: bool,
    pub address_already_exists_error: Option<u32>,
    pub address_partial_invalid_prefix_error: Option<u32>,
    pub address_partial_bogus_interface_error: Option<u32>,
    pub address_restore_verified: bool,
    // ---- MTU 族 ----
    pub mtu_before: Option<u32>,
    pub mtu_v6_before: Option<u32>,
    pub mtu_prep_no_effect: bool,
    /// 逐值 Set 尝试（value, rc, readback）——诊断 Wintun 接口的 MTU 可写性。
    pub mtu_set_attempts: Vec<MtuAttempt>,
    pub mtu_applied: bool,
    pub mtu_apply_error: Option<u32>,
    pub mtu_after: Option<u32>,
    pub mtu_third_party_detected: bool,
    pub mtu_same_value_idempotent: bool,
    pub mtu_illegal_value_error: Option<u32>,
    pub mtu_restore_verified: bool,
    // ---- Route 族 ----
    pub route_bypass_before_dest: Option<String>,
    pub route_bypass_before_nexthop: Option<String>,
    pub route_bypass_before_metric: Option<u32>,
    pub route_bypass_before_protocol: Option<i32>,
    pub route_bypass_before_interface_alias: Option<String>,
    pub route_bypass_before_luid: Option<u64>,
    pub route_prep_no_effect: bool,
    /// 测试接口上的逐变体 Create 尝试（诊断 87 根因）。
    pub route_create_variants: Vec<RouteVariantResult>,
    /// 对照：同一行构造在 bypass 接口（真实接口）上 Create 的结果。
    pub route_control_on_bypass_rc: Option<u32>,
    pub route_control_cleanup_rc: Option<u32>,
    /// 首个成功的变体标签（若无任何变体成功 → None = blocked_by_interface）。
    pub route_create_success_variant: Option<String>,
    pub route_created: bool,
    pub route_create_error: Option<u32>,
    pub route_readback_metric: Option<u32>,
    pub route_readback_protocol: Option<i32>,
    pub route_readback_nexthop: Option<String>,
    pub route_readback_luid_matches: bool,
    pub route_best_after_nexthop: Option<String>,
    pub route_best_after_luid_matches: bool,
    pub route_superseded_bypass: bool,
    pub route_third_party_delete_detected: bool,
    pub route_already_exists_error: Option<u32>,
    pub route_partial_invalid_prefix_error: Option<u32>,
    pub route_mutant_delete_by_cidr_only_error: Option<u32>,
    pub route_delete_full_row_succeeded: bool,
    pub route_restore_verified: bool,
    // ---- DNS 族 ----
    pub dns_before_version: Option<u32>,
    pub dns_before_flags: Option<u64>,
    pub dns_before_nameservers: Vec<String>,
    pub dns_before_search_list: Vec<String>,
    pub dns_prep_no_effect: bool,
    pub dns_applied: bool,
    pub dns_apply_error: Option<u32>,
    pub dns_set_version_used: Option<u32>,
    pub dns_readback_nameservers: Vec<String>,
    pub dns_readback_search_list: Vec<String>,
    pub dns_readback_flags: Option<u64>,
    pub dns_readback_version: Option<u32>,
    pub dns_third_party_detected: bool,
    pub dns_same_value_idempotent: bool,
    pub dns_partial_unknown_error: Option<u32>,
    pub dns_restore_skipped_third_party: bool,
    pub dns_mutant_unconditional_restore_would_clobber: bool,
    pub dns_final_state_equals_original: bool,
    // ---- cleanup / restore ----
    pub adapter_removed_by_close: bool,
    pub restore_failures: Vec<String>,
    pub restore_ok: bool,
    pub probe_notes: Vec<String>,
}

impl NetworkSettingsFacts {
    /// 动态（需 admin）事实是否已完整观测。
    pub fn is_dynamic_complete(&self) -> bool {
        if !self.env_elevated {
            return false;
        }
        if self.test_if_blocked_reason.is_some() {
            return false;
        }
        self.address_created
            && self.address_restore_verified
            && self.mtu_applied
            && self.mtu_restore_verified
            && self.route_created
            && self.route_restore_verified
            && self.dns_applied
            && self.dns_final_state_equals_original
            && self.restore_ok
    }
}

pub fn default_facts() -> NetworkSettingsFacts {
    NetworkSettingsFacts {
        host_os: String::new(),
        hostname: String::new(),
        env_elevated: false,
        wintun_dll_path: String::new(),
        wintun_dll_loaded: false,
        test_if_blocked_reason: None,
        test_if_name: None,
        test_if_luid_value: None,
        test_if_ifindex: None,
        test_if_guid: None,
        test_if_alias: None,
        address_precondition_clean: false,
        address_prep_no_effect: false,
        address_created: false,
        address_create_error: None,
        address_readback_addr: None,
        address_readback_onlink_prefix: None,
        address_readback_prefix_origin: None,
        address_readback_suffix_origin: None,
        address_readback_dad_state: None,
        address_readback_skip_as_source: None,
        address_readback_valid_lifetime: None,
        address_readback_preferred_lifetime: None,
        address_readback_creation_ts: None,
        address_third_party_deleted_detected: false,
        address_already_exists_error: None,
        address_partial_invalid_prefix_error: None,
        address_partial_bogus_interface_error: None,
        address_restore_verified: false,
        mtu_before: None,
        mtu_v6_before: None,
        mtu_prep_no_effect: false,
        mtu_set_attempts: Vec::new(),
        mtu_applied: false,
        mtu_apply_error: None,
        mtu_after: None,
        mtu_third_party_detected: false,
        mtu_same_value_idempotent: false,
        mtu_illegal_value_error: None,
        mtu_restore_verified: false,
        route_bypass_before_dest: None,
        route_bypass_before_nexthop: None,
        route_bypass_before_metric: None,
        route_bypass_before_protocol: None,
        route_bypass_before_interface_alias: None,
        route_bypass_before_luid: None,
        route_prep_no_effect: false,
        route_create_variants: Vec::new(),
        route_control_on_bypass_rc: None,
        route_control_cleanup_rc: None,
        route_create_success_variant: None,
        route_created: false,
        route_create_error: None,
        route_readback_metric: None,
        route_readback_protocol: None,
        route_readback_nexthop: None,
        route_readback_luid_matches: false,
        route_best_after_nexthop: None,
        route_best_after_luid_matches: false,
        route_superseded_bypass: false,
        route_third_party_delete_detected: false,
        route_already_exists_error: None,
        route_partial_invalid_prefix_error: None,
        route_mutant_delete_by_cidr_only_error: None,
        route_delete_full_row_succeeded: false,
        route_restore_verified: false,
        dns_before_version: None,
        dns_before_flags: None,
        dns_before_nameservers: Vec::new(),
        dns_before_search_list: Vec::new(),
        dns_prep_no_effect: false,
        dns_applied: false,
        dns_apply_error: None,
        dns_set_version_used: None,
        dns_readback_nameservers: Vec::new(),
        dns_readback_search_list: Vec::new(),
        dns_readback_flags: None,
        dns_readback_version: None,
        dns_third_party_detected: false,
        dns_same_value_idempotent: false,
        dns_partial_unknown_error: None,
        dns_restore_skipped_third_party: false,
        dns_mutant_unconditional_restore_would_clobber: false,
        dns_final_state_equals_original: false,
        adapter_removed_by_close: false,
        restore_failures: Vec::new(),
        restore_ok: true,
        probe_notes: Vec::new(),
    }
}

/// 诊断进度文件（EXV_WSP4_DEBUG_LOG 时追加一行）——提权运行中崩溃时定位阶段。
fn dbg_log(msg: &str) {
    if let Ok(path) = std::env::var("EXV_WSP4_DEBUG_LOG") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(f, "{msg}");
            let _ = f.flush();
        }
    }
}

/// 运行完整事实探针，返回观测到的 `NetworkSettingsFacts`。
///
/// 任何单个 case 失败都不吞掉整体：出错 case 记录为 `None`/`false`，其余继续；
/// 恢复失败是类型化错误（`restore_failures`）。需要管理员；非 elevated 时动态部分
/// 记为 `not_run / blocked_by_environment`（不伪造）。这是 Terra 冻结的 seam（`WSP4-T`）。
pub fn run_network_settings_fact_probe(wintun_dll: &Path) -> NetworkSettingsFacts {
    let mut notes = Vec::new();
    dbg_log("probe: start");
    let mut f = default_facts();
    f.host_os = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    f.hostname = std::env::var("COMPUTERNAME").unwrap_or_default();
    f.env_elevated = is_elevated();
    f.wintun_dll_path = wintun_dll.display().to_string();
    dbg_log(&format!("probe: elevated={}", f.env_elevated));

    if std::mem::size_of::<usize>() != 8 {
        notes.push(format!(
            "WSP4 仅支持 x64（DNS_INTERFACE_SETTINGS 的 v2+ 布局按 x64 偏移解析）；当前 usize={}",
            std::mem::size_of::<usize>()
        ));
        f.probe_notes = notes;
        return f;
    }

    // ---- 动态加载 Wintun DLL（测试接口载体；WSP3 冻结路径）。 ----
    dbg_log("probe: loading wintun");
    let wf = match load_wintun(wintun_dll) {
        Ok(w) => {
            f.wintun_dll_loaded = true;
            w
        }
        Err(e) => {
            notes.push(format!("wintun dll load failed: {e}"));
            f.test_if_blocked_reason = Some(format!("wintun dll load failed: {e}"));
            f.probe_notes = notes;
            return f;
        }
    };

    if !f.env_elevated {
        notes.push(
            "not elevated: address/mtu/route/dns cases = not_run_blocked_by_environment".to_string(),
        );
        f.probe_notes = notes;
        // SAFETY: 探针持有的 DLL 引用最后一次使用后释放。
        unsafe { let _ = FreeLibrary(wf.hmod); }
        return f;
    }

    // ---- 创建测试接口（Wintun adapter）。 ----
    dbg_log("probe: creating test adapter");
    let adapter = match create_test_adapter(&wf) {
        Ok(h) => h,
        Err(e) => {
            notes.push(format!("create test adapter failed: {e}"));
            f.test_if_blocked_reason = Some(format!("create test adapter failed: {e}"));
            f.probe_notes = notes;
            // SAFETY: 释放 DLL 引用。
            unsafe { let _ = FreeLibrary(wf.hmod); }
            return f;
        }
    };

    let mut luid = NET_LUID_LH::default();
    // SAFETY: adapter 句柄有效；WintunGetAdapterLUID 写入 luid。
    let ok = unsafe { (wf.get_luid)(adapter, &mut luid) };
    if ok == 0 {
        notes.push("WintunGetAdapterLUID failed".to_string());
        f.test_if_blocked_reason = Some("WintunGetAdapterLUID failed".to_string());
        // SAFETY: 关闭 adapter（创建者 close → 移除）。
        unsafe { (wf.close)(adapter); }
        // SAFETY: 释放 DLL 引用。
        unsafe { let _ = FreeLibrary(wf.hmod); }
        f.probe_notes = notes;
        return f;
    }
    f.test_if_name = Some(SPARK_ADAPTER_NAME.to_string());
    // SAFETY: 读 union 成员 Value。
    f.test_if_luid_value = Some(unsafe { luid.Value });
    f.test_if_ifindex = luid_to_index(&luid);
    // SAFETY: if_guid 由系统填充（ConvertInterfaceLuidToGuid）。
    let mut if_guid = GUID::zeroed();
    let guid_ok = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut if_guid) }.0 == 0;
    f.test_if_guid = guid_ok.then(|| guid_string(&if_guid));
    f.test_if_alias = luid_to_alias(&luid);
    notes.push(format!(
        "test interface: {} luid={} ifindex={} guid={} alias={}",
        SPARK_ADAPTER_NAME,
        f.test_if_luid_value.unwrap_or_default(),
        f.test_if_ifindex.unwrap_or_default(),
        f.test_if_guid.as_deref().unwrap_or("?"),
        f.test_if_alias.as_deref().unwrap_or("?")
    ));

    // ---- Address 族（.1 保持到探针结束，作为路由族 next-hop）。 ----
    dbg_log("probe: address family");
    probe_address_family(&mut f, &luid, &mut notes);
    dbg_log("probe: address family done");

    // ---- Route 族。 ----
    dbg_log("probe: route family");
    probe_route_family(&mut f, &luid, &mut notes);
    dbg_log("probe: route family done");

    // ---- MTU 族。 ----
    dbg_log("probe: mtu family");
    probe_mtu_family(&mut f, &luid, &mut notes);
    dbg_log("probe: mtu family done");

    // ---- DNS 族。 ----
    dbg_log("probe: dns family");
    if guid_ok {
        probe_dns_family(&mut f, &if_guid, &mut notes);
    } else {
        notes.push("ConvertInterfaceLuidToGuid failed; DNS family = not_run".to_string());
    }
    dbg_log("probe: dns family done");

    // ---- 最终清理：删除地址族 .1（compare-and-restore）。 ----
    if let Some(ip) = f.address_created.then_some(SPARK_IP_A) {
        let row = unicast_row_for(ip, &luid, SPARK_PREFIX_LEN);
        // SAFETY: row 是合法 unicast row（.1 存在且属于测试接口）。
        let rc = unsafe { DeleteUnicastIpAddressEntry(&row).0 };
        if rc != 0 {
            push_restore_failure(&mut f, &format!("address.delete.{ip}: rc={rc}"));
        }
        // 验证：测试接口上不再有 .1。
        let present = unicast_table_has(&luid, ip);
        f.address_restore_verified = !present;
        if !f.address_restore_verified {
            push_restore_failure(&mut f, &format!("address.restore-verify.{ip}: still present"));
        }
        notes.push(format!(
            "address family compare-and-restore: delete {ip} rc={rc}, verified_absent={}",
            !present
        ));
    }

    // ---- 关闭 adapter（创建者 close → 移除）。 ----
    // SAFETY: adapter 是创建所得句柄；WintunCloseAdapter 释放并移除。
    unsafe { (wf.close)(adapter); }
    // 验证移除：open-by-name 应失败。
    let name = HSTRING::from(SPARK_ADAPTER_NAME);
    // SAFETY: name 是合法宽字符串；NULL 表示已不存在。
    let after = unsafe { (wf.open)(PCWSTR::from_raw(name.as_ptr())) };
    if after.is_null() {
        f.adapter_removed_by_close = true;
    } else {
        // SAFETY: 意外仍存在，关闭非创建者句柄（不删除）。
        unsafe { (wf.close)(after); }
        notes.push("adapter still openable after creator close (unexpected)".to_string());
    }

    // SAFETY: 探针持有的 DLL 引用最后一次使用后释放。
    unsafe { let _ = FreeLibrary(wf.hmod); }

    f.restore_ok = f.restore_failures.is_empty();
    f.probe_notes = notes;
    dbg_log("probe: done");
    f
}

/// 在测试接口上冻结 Address 族事实。`keep_alive` 地址（.1）保持到探针结束。
fn probe_address_family(f: &mut NetworkSettingsFacts, luid: &NET_LUID_LH, notes: &mut Vec<String>) {
    // 1) 前置条件：接口上没有我们的地址（fresh adapter）。
    let clean = !unicast_table_has(luid, SPARK_IP_A)
        && !unicast_table_has(luid, SPARK_IP_B)
        && !unicast_table_has(luid, SPARK_IP_C);
    f.address_precondition_clean = clean;
    notes.push(format!("address precondition clean={clean}"));

    // 2) no-effect-before-durable-intent：只构建行（InitializeUnicastIpAddressEntry +
    //    字段赋值），不调用 Create —— 表必须不变。
    {
        let _row = unicast_row_for(SPARK_IP_A, luid, SPARK_PREFIX_LEN);
        let still_clean = !unicast_table_has(luid, SPARK_IP_A);
        f.address_prep_no_effect = still_clean;
        notes.push(format!("address prep-only no-effect={still_clean}"));
    }

    // 3) durable intent：Create .1/24，回读精确行。
    let row_a = unicast_row_for(SPARK_IP_A, luid, SPARK_PREFIX_LEN);
    // SAFETY: row 已按文档初始化（InitializeUnicastIpAddressEntry），地址/接口有效。
    let rc = unsafe { CreateUnicastIpAddressEntry(&row_a).0 };
    f.address_create_error = Some(rc);
    f.address_created = rc == 0;
    notes.push(format!("address create {SPARK_IP_A}/{SPARK_PREFIX_LEN} rc={rc}"));
    if f.address_created {
        if let Some(row) = unicast_row_of(luid, SPARK_IP_A) {
            f.address_readback_addr = ipv4_of(&row.Address);
            f.address_readback_onlink_prefix = Some(row.OnLinkPrefixLength);
            f.address_readback_prefix_origin = Some(row.PrefixOrigin.0);
            f.address_readback_suffix_origin = Some(row.SuffixOrigin.0);
            f.address_readback_dad_state = Some(row.DadState.0);
            f.address_readback_skip_as_source = Some(row.SkipAsSource);
            f.address_readback_valid_lifetime = Some(row.ValidLifetime);
            f.address_readback_preferred_lifetime = Some(row.PreferredLifetime);
            f.address_readback_creation_ts = Some(row.CreationTimeStamp);
            notes.push(format!(
                "address read-back: {}/{} origin={}/{} dad={} skip={} valid=0x{:x} pref=0x{:x} ts={}",
                f.address_readback_addr.as_deref().unwrap_or("?"),
                row.OnLinkPrefixLength,
                row.PrefixOrigin.0,
                row.SuffixOrigin.0,
                row.DadState.0,
                row.SkipAsSource,
                row.ValidLifetime,
                row.PreferredLifetime,
                row.CreationTimeStamp
            ));
        } else {
            notes.push("address read-back: row NOT found after create".to_string());
        }
    }

    // 4) already-exists：对已存在的 .1 再 Create 一次 → 记录错误码。
    if f.address_created {
        // SAFETY: row 与已存在地址相同；预期返回 already-exists 类错误。
        let rc2 = unsafe { CreateUnicastIpAddressEntry(&row_a).0 };
        f.address_already_exists_error = Some(rc2);
        notes.push(format!("address create-already-exists rc={rc2}"));
    }

    // 5) partial/unknown：(a) 非法前缀长度 33（IPv4 上限 32）；
    //    (b) 合法地址但接口 LUID 不存在。
    if f.address_created {
        let mut bad = unicast_row_for(SPARK_IP_C, luid, 33);
        bad.OnLinkPrefixLength = 33;
        // SAFETY: row 结构完整；前缀非法，预期 ERROR_INVALID_PARAMETER。
        let rc3 = unsafe { CreateUnicastIpAddressEntry(&bad).0 };
        f.address_partial_invalid_prefix_error = Some(rc3);
        notes.push(format!("address invalid-prefix-len(33) rc={rc3}"));

        let mut bogus = unicast_row_for(SPARK_IP_C, luid, SPARK_PREFIX_LEN);
        // SAFETY: 写 union 成员 Value（edition 2024：非引用 place 上的 union 字段写是安全操作）。
        bogus.InterfaceLuid.Value = 0xFFFFFFFF_FFFFFFFF;
        // SAFETY: row 结构完整；接口不存在，预期 ERROR_NOT_FOUND。
        let rc4 = unsafe { CreateUnicastIpAddressEntry(&bogus).0 };
        f.address_partial_bogus_interface_error = Some(rc4);
        notes.push(format!("address bogus-interface rc={rc4}"));
    }

    // 6) 第三方变更检测：Create .2（第三方路径创建），第三方 Delete .2，回读确认 .2
    //    消失而 .1 仍在 —— read-back 反映真实系统状态，不是探针缓存。
    //    （先记录 netsh 的 ground truth：接口上真实存在的地址。）
    if f.address_created {
        let show_args = [
            "interface",
            "ipv4",
            "show",
            "addresses",
            "name=\"ExvNetSpike\"",
        ]
        .map(String::from)
        .to_vec();
        if let Some((ok, out)) =
            run_cmd_checked("netsh", &show_args, std::time::Duration::from_secs(12))
        {
            let out_clean: String = out
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            notes.push(format!(
                "netsh ground-truth addresses: ok={ok} out={out_clean:?}"
            ));
        }
    }
    if f.address_created {
        let row_b = unicast_row_for(SPARK_IP_B, luid, SPARK_PREFIX_LEN);
        // SAFETY: row 合法；.2 尚不存在。
        let rcb = unsafe { CreateUnicastIpAddressEntry(&row_b).0 };
        notes.push(format!("address third-party create {SPARK_IP_B} rc={rcb}"));
        if rcb == 0 {
            // SAFETY: 第三方路径删除 .2。
            let rcd = unsafe { DeleteUnicastIpAddressEntry(&row_b).0 };
            notes.push(format!("address third-party delete {SPARK_IP_B} rc={rcd}"));
        }
        let a_still = unicast_table_has(luid, SPARK_IP_A);
        let b_gone = !unicast_table_has(luid, SPARK_IP_B);
        f.address_third_party_deleted_detected = a_still && b_gone;
        notes.push(format!(
            "address third-party detection: .1 present={a_still}, .2 absent={b_gone}"
        ));
    }
}

/// 在测试接口上冻结 Route 族事实。next-hop 用地址族保留的 .1。
fn probe_route_family(f: &mut NetworkSettingsFacts, luid: &NET_LUID_LH, notes: &mut Vec<String>) {
    // 1) 前置条件：加隧道路由**之前**的 bypass 路由（GetBestRoute2）。
    if let Some(bypass) = best_route_for(SPARK_ROUTE_PROBE) {
        f.route_bypass_before_dest = Some(format!(
            "{}/{}",
            ipv4_of(&bypass.DestinationPrefix.Prefix)
                .unwrap_or_else(|| "?".to_string()),
            bypass.DestinationPrefix.PrefixLength
        ));
        f.route_bypass_before_nexthop = ipv4_of(&bypass.NextHop);
        f.route_bypass_before_metric = Some(bypass.Metric);
        f.route_bypass_before_protocol = Some(bypass.Protocol.0);
        f.route_bypass_before_interface_alias = luid_to_alias(&bypass.InterfaceLuid);
        // SAFETY: 读 union 成员 Value。
        f.route_bypass_before_luid = Some(unsafe { bypass.InterfaceLuid.Value });
        notes.push(format!(
            "route bypass-before: dest={} nexthop={} metric={} protocol={} ifalias={} luid={}",
            f.route_bypass_before_dest.as_deref().unwrap_or("?"),
            f.route_bypass_before_nexthop.as_deref().unwrap_or("?"),
            f.route_bypass_before_metric.unwrap_or(0),
            f.route_bypass_before_protocol.unwrap_or(-1),
            f.route_bypass_before_interface_alias.as_deref().unwrap_or("?"),
            f.route_bypass_before_luid.unwrap_or(0)
        ));
    } else {
        notes.push("route bypass-before: GetBestRoute2 failed".to_string());
    }

    // 2) no-effect-before-durable-intent：只构建行，不 Create —— 路由表不变。
    {
        let _row = forward_row_for(luid);
        let before = best_route_for(SPARK_ROUTE_PROBE)
            .and_then(|r| ipv4_of(&r.NextHop));
        // 仅当前置 bypass 已观测到时才可断言 no-effect（避免双 None 误报）。
        f.route_prep_no_effect = f.route_bypass_before_nexthop.is_some() && before == f.route_bypass_before_nexthop;
        notes.push(format!(
            "route prep-only no-effect={} (bypass nexthop before/after: {:?}/{:?})",
            f.route_prep_no_effect, f.route_bypass_before_nexthop, before
        ));
    }

    // 3) durable intent：Create 精确路由行（dest 10.99.99.0/24 via 10.88.88.1, metric 5）。
    //    一次 87 后改为逐变体诊断：记录每个变体的结果 + 首成功变体。
    let base = forward_row_for(luid);
    let mut variants: Vec<(&'static str, MIB_IPFORWARD_ROW2)> = Vec::new();
    let mut v1 = base;
    v1.Origin = Default::default(); // 不显式设 Origin（用 Initialize 默认）
    let mut v2 = base;
    v2.InterfaceIndex = f.test_if_ifindex.unwrap_or(0); // 显式带 InterfaceIndex
    let mut v3 = base;
    v3.SitePrefixLength = 0; // 显式 SitePrefixLength = 0
    let mut v4 = base;
    v4.Protocol = MIB_IPPROTO_NETMGMT; // 显式 Protocol = NETMGMT
    let mut v5 = base;
    v5.SitePrefixLength = 0; // 组合修复：SitePrefixLength=0 + Protocol=NETMGMT
    v5.Protocol = MIB_IPPROTO_NETMGMT;
    let mut v6 = base;
    v6.SitePrefixLength = 0; // 全清：siteprefix/protocol/loopback/auto/publish 全部修正
    v6.Protocol = MIB_IPPROTO_NETMGMT;
    v6.Loopback = false;
    v6.AutoconfigureAddress = false;
    v6.Publish = false;
    let mut v7 = base;
    v7.SitePrefixLength = 0; // 全清 + NextHop=0.0.0.0（文档：本地/直连路由 next hop 用全零）
    v7.Protocol = MIB_IPPROTO_NETMGMT;
    v7.Loopback = false;
    v7.AutoconfigureAddress = false;
    v7.Publish = false;
    v7.NextHop = sockaddr_ipv4("0.0.0.0");
    variants.push(("init+full", base));
    variants.push(("no-origin", v1));
    variants.push(("with-ifindex", v2));
    variants.push(("siteprefix-0", v3));
    variants.push(("protocol-netmgmt", v4));
    variants.push(("siteprefix-0+protocol-netmgmt", v5));
    variants.push(("full-clean", v6));
    variants.push(("full-clean+nexthop0", v7));
    // 8) 决定性对照：直接复用 OS 自己填充的 bypass 行（GetBestRoute2 输出），只改
    //    DestinationPrefix —— 若它也 87，说明本宿主的 CreateIpForwardEntry2 拒绝所有
    //    构造；若成功，说明问题在我的行构造。
    if let Some(mut os_row) = best_route_for(SPARK_ROUTE_PROBE) {
        os_row.DestinationPrefix.Prefix = sockaddr_ipv4(SPARK_ROUTE_NETWORK);
        os_row.DestinationPrefix.PrefixLength = SPARK_ROUTE_PREFIX_LEN;
        dbg_log("route: variant from-os-row");
        // SAFETY: os_row 是 OS 填充的合法行；只改 dest。
        let rc_os = unsafe { CreateIpForwardEntry2(&os_row) }.0;
        f.route_create_variants.push(RouteVariantResult {
            label: "from-os-row".to_string(),
            rc: rc_os,
        });
        notes.push(format!("route create variant from-os-row: rc={rc_os}"));
        if rc_os == 0 {
            // 清理（Get 填满精确行 → Delete）。
            let mut exact = os_row;
            // SAFETY: exact 关键字段与刚创建的路由一致；Get 填满行。
            let rc_g = unsafe { GetIpForwardEntry2(&mut exact).0 };
            if rc_g == 0 {
                // SAFETY: 行已填满；删除。
                let rc_d = unsafe { DeleteIpForwardEntry2(&exact).0 };
                notes.push(format!("route from-os-row cleanup delete rc={rc_d}"));
            } else {
                push_restore_failure(f, &format!("route.from-os-row-cleanup.get: rc={rc_g}"));
            }
        }
    }
    notes.push(format!(
        "route create diagnostic: dest={SPARK_ROUTE_NETWORK}/{SPARK_ROUTE_PREFIX_LEN} via {SPARK_IP_A} metric {SPARK_ROUTE_METRIC} on luid={} (init row: siteprefix={} valid=0x{:x} pref=0x{:x} protocol={} origin={} loopback={} auto={} publish={} immortal={} age={})",
        f.test_if_luid_value.unwrap_or(0),
        base.SitePrefixLength,
        base.ValidLifetime,
        base.PreferredLifetime,
        base.Protocol.0,
        base.Origin.0,
        base.Loopback,
        base.AutoconfigureAddress,
        base.Publish,
        base.Immortal,
        base.Age
    ));
    let mut chosen: Option<(String, MIB_IPFORWARD_ROW2)> = None;
    for (label, row) in &variants {
        dbg_log(&format!("route: variant {label}"));
        // SAFETY: row 已按文档初始化；dest/nexthop/luid 有效（变体诊断）。
        let rc = unsafe { CreateIpForwardEntry2(row).0 };
        f.route_create_variants.push(RouteVariantResult {
            label: (*label).to_string(),
            rc,
        });
        notes.push(format!("route create variant {label}: rc={rc}"));
        if rc == 0 && chosen.is_none() {
            chosen = Some(((*label).to_string(), *row));
        }
    }
    f.route_create_success_variant = chosen.as_ref().map(|(l, _)| l.clone());
    f.route_create_error = Some(
        chosen
            .as_ref()
            .map(|_| 0)
            .or_else(|| f.route_create_variants.first().map(|v| v.rc))
            .unwrap_or(87),
    );
    f.route_created = chosen.is_some();

    // 3b) 对照实验：同一行构造在 bypass 接口（真实接口）上 Create。
    if let Some(bypass_luid) = f.route_bypass_before_luid {
        let mut control = MIB_IPFORWARD_ROW2::default();
        // SAFETY: Initialize 写入行。
        unsafe { InitializeIpForwardEntry(&mut control) };
        control.DestinationPrefix.Prefix = sockaddr_ipv4(SPARK_ROUTE_NETWORK);
        control.DestinationPrefix.PrefixLength = SPARK_ROUTE_PREFIX_LEN;
        control.NextHop = sockaddr_ipv4(f.route_bypass_before_nexthop.as_deref().unwrap_or("0.0.0.0"));
        // SAFETY: 写 union 成员 Value。
        control.InterfaceLuid.Value = bypass_luid;
        control.Metric = SPARK_ROUTE_METRIC;
        control.ValidLifetime = u32::MAX;
        control.PreferredLifetime = u32::MAX;
        control.Origin = NlroManual;
        dbg_log(&format!("route: control create on bypass luid={bypass_luid}"));
        // SAFETY: control 行关键字段有效（真实接口 + 真实网关 next-hop）。
        let rc_control = unsafe { CreateIpForwardEntry2(&control).0 };
        f.route_control_on_bypass_rc = Some(rc_control);
        notes.push(format!("route control create on bypass interface luid={bypass_luid}: rc={rc_control}"));
        if rc_control == 0 {
            // 清理对照路由（Get 填满精确行 → Delete）。
            let mut exact = control;
            // SAFETY: exact 关键字段与刚创建的路由一致；Get 填满行。
            let rc_g = unsafe { GetIpForwardEntry2(&mut exact).0 };
            if rc_g == 0 {
                // SAFETY: 行已填满；删除。
                let rc_d = unsafe { DeleteIpForwardEntry2(&exact).0 };
                f.route_control_cleanup_rc = Some(rc_d);
                notes.push(format!("route control cleanup delete rc={rc_d}"));
            } else {
                f.route_control_cleanup_rc = Some(rc_g);
                push_restore_failure(f, &format!("route.control-cleanup.get: rc={rc_g}"));
            }
        }
    }

    // 3c) netsh 对照：路由表本身是否接受新路由（CreateIpForwardEntry2 全变体 87 时
    //     区分"API 层拒绝"与"宿主路由表锁定"）。带 watchdog（WSP3 教训：netsh 可能挂死）。
    if f.route_create_variants.iter().all(|v| v.rc != 0) {
        let add_args = [
            "interface",
            "ipv4",
            "add",
            "route",
            "10.99.99.0/24",
            "interface=\"ExvNetSpike\"",
        ]
        .map(String::from)
        .to_vec();
        if let Some((ok, out)) =
            run_cmd_checked("netsh", &add_args, std::time::Duration::from_secs(12))
        {
            notes.push(format!("route netsh control add: ok={ok} out={out:?}"));
            if ok {
                // 表读取诊断：GetIpForwardTable2 的 rc / 行数 / 与 netsh 路由相关的行。
                dump_forward_table_diag(luid, notes);
                // netsh 建的路由在转发表中的精确行（验证 read-back 对真实路由成立，
                // 并拿"表里的真实行"再试 CreateIpForwardEntry2）。
                if let Some(tbl_row) = forward_row_readback(luid) {
                    notes.push(format!(
                        "route netsh row in table: metric={} protocol={} nexthop={} siteprefix={} origin={} luid_match=true",
                        tbl_row.Metric,
                        tbl_row.Protocol.0,
                        ipv4_of(&tbl_row.NextHop).unwrap_or_else(|| "?".to_string()),
                        tbl_row.SitePrefixLength,
                        tbl_row.Origin.0
                    ));
                    // 决定性：用表里的真实行原样 Create。
                    // SAFETY: tbl_row 是系统填充的合法行。
                    let rc_tbl = unsafe { CreateIpForwardEntry2(&tbl_row) }.0;
                    notes.push(format!("route create from-table-row rc={rc_tbl}"));
                    if rc_tbl == 0 {
                        // 清理（避免重复）。
                        // SAFETY: 行已填满；删除。
                        let rc_d = unsafe { DeleteIpForwardEntry2(&tbl_row).0 };
                        notes.push(format!("route from-table-row cleanup delete rc={rc_d}"));
                    }
                    // SetIpForwardEntry2（upsert 语义）尝试。
                    // SAFETY: tbl_row 是系统填充的合法行；Set 创建或修改。
                    let rc_set = unsafe { SetIpForwardEntry2(&tbl_row).0 };
                    notes.push(format!("route SetIpForwardEntry2 (upsert) rc={rc_set}"));
                    if rc_set == 0 {
                        // SAFETY: 行已填满；删除。
                        let rc_d2 = unsafe { DeleteIpForwardEntry2(&tbl_row).0 };
                        notes.push(format!("route SetIpForwardEntry2 cleanup delete rc={rc_d2}"));
                    }
                }
                let del_args = [
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    "10.99.99.0/24",
                    "interface=\"ExvNetSpike\"",
                ]
                .map(String::from)
                .to_vec();
                if let Some((okd, outd)) =
                    run_cmd_checked("netsh", &del_args, std::time::Duration::from_secs(12))
                {
                    notes.push(format!("route netsh control delete: ok={okd} out={outd:?}"));
                }
            }
        } else {
            notes.push("route netsh control: timeout/exec failure".to_string());
        }
    }

    if let Some((label, row)) = chosen {
        notes.push(format!("route create success variant: {label}"));
        // 4) 回读精确行。
        if let Some(row) = forward_row_readback(luid) {
            f.route_readback_metric = Some(row.Metric);
            f.route_readback_protocol = Some(row.Protocol.0);
            f.route_readback_nexthop = ipv4_of(&row.NextHop);
            // SAFETY: 读 union 成员 Value。
            f.route_readback_luid_matches = unsafe { row.InterfaceLuid.Value }
                == unsafe { luid.Value };
            notes.push(format!(
                "route read-back: metric={} protocol={} (MIB_IPPROTO_NETMGMT={}) nexthop={} luid_match={}",
                row.Metric,
                row.Protocol.0,
                MIB_IPPROTO_NETMGMT.0,
                f.route_readback_nexthop.as_deref().unwrap_or("?"),
                f.route_readback_luid_matches
            ));
        } else {
            notes.push("route read-back: row NOT found after create".to_string());
        }

        // 5) GetBestRoute2：隧道路由取代 bypass（无源限制的查找）。
        if let Some(best) = best_route_for(SPARK_ROUTE_PROBE) {
            f.route_best_after_nexthop = ipv4_of(&best.NextHop);
            // SAFETY: 读 union 成员 Value。
            f.route_best_after_luid_matches =
                unsafe { best.InterfaceLuid.Value } == unsafe { luid.Value };
            f.route_superseded_bypass = f.route_best_after_nexthop.as_deref() == Some(SPARK_IP_A)
                && f.route_best_after_luid_matches;
            notes.push(format!(
                "route best-after (no source): nexthop={} luid_match={} superseded={}",
                f.route_best_after_nexthop.as_deref().unwrap_or("?"),
                f.route_best_after_luid_matches,
                f.route_superseded_bypass
            ));
        }
        // 5b) 带源地址限制的 GetBestRoute2（VPN 场景：源 = 隧道接口地址）。
        //     文档：指定源地址后查找被限制在源地址的接口上。
        let src = sockaddr_ipv4(SPARK_IP_A);
        let dest = sockaddr_ipv4(SPARK_ROUTE_PROBE);
        let mut best_src_row = MIB_IPFORWARD_ROW2::default();
        let mut best_src_addr = SOCKADDR_INET::default();
        // SAFETY: src/dest 是合法 SOCKADDR_INET；best_src_row/best_src_addr 由系统填充。
        let rc_src = unsafe {
            GetBestRoute2(None, 0, Some(&src), &dest, 0, &mut best_src_row, &mut best_src_addr).0
        };
        if rc_src == 0 {
            let nh = ipv4_of(&best_src_row.NextHop);
            // SAFETY: 读 union 成员 Value。
            let luid_m = unsafe { best_src_row.InterfaceLuid.Value } == unsafe { luid.Value };
            let selected = nh.as_deref() == Some(SPARK_IP_A) && luid_m;
            notes.push(format!(
                "route best-after (source={SPARK_IP_A}): rc=0 nexthop={} luid_match={} tunnel_selected={selected}",
                nh.unwrap_or_else(|| "?".to_string()),
                luid_m
            ));
        } else {
            notes.push(format!(
                "route best-after (source={SPARK_IP_A}): GetBestRoute2 rc={rc_src} (source-restricted lookup failed)"
            ));
        }

        // 6) already-exists：同一精确行再 Create → 错误码。
        // SAFETY: row 与已存在路由相同；预期 already-exists 类错误。
        let rc2 = unsafe { CreateIpForwardEntry2(&row).0 };
        f.route_already_exists_error = Some(rc2);
        notes.push(format!("route create-already-exists rc={rc2}"));

        // 7) partial/unknown：前缀长度 33（IPv4 上限 32）→ 错误码。
        let mut bad = forward_row_for(luid);
        bad.DestinationPrefix.PrefixLength = 33;
        // SAFETY: row 结构完整；前缀非法，预期 ERROR_INVALID_PARAMETER。
        let rc3 = unsafe { CreateIpForwardEntry2(&bad).0 };
        f.route_partial_invalid_prefix_error = Some(rc3);
        notes.push(format!("route invalid-prefix-len(33) rc={rc3}"));

        // 8) 第三方变更：用全新行（Initialize + dest/nexthop/luid）Get+Delete —— 模拟
        //    外部 actor 删除我们的路由；回读确认消失、best 回到 bypass。
        let mut fresh = MIB_IPFORWARD_ROW2::default();
        // SAFETY: Initialize 写入行。
        unsafe { InitializeIpForwardEntry(&mut fresh) };
        fresh.DestinationPrefix = row.DestinationPrefix;
        fresh.NextHop = row.NextHop;
        fresh.InterfaceLuid = row.InterfaceLuid;
        // SAFETY: fresh 的关键字段与已存在路由一致；Get 填满行。
        let rc4 = unsafe { GetIpForwardEntry2(&mut fresh).0 };
        if rc4 == 0 {
            // SAFETY: 行已填满（精确行身份）；删除。
            let rc5 = unsafe { DeleteIpForwardEntry2(&fresh).0 };
            notes.push(format!("route third-party delete rc={rc5}"));
        } else {
            notes.push(format!("route third-party GetIpForwardEntry2 rc={rc4}"));
        }
        let absent = !forward_table_has(luid);
        let best_back = best_route_for(SPARK_ROUTE_PROBE)
            .and_then(|b| ipv4_of(&b.NextHop))
            == f.route_bypass_before_nexthop;
        f.route_third_party_delete_detected = absent && best_back;
        notes.push(format!(
            "route third-party detection: absent={absent}, best-back-to-bypass={best_back}"
        ));

        // 9) 重新创建我们的路由（供 mutant 测试）。
        // SAFETY: row 与刚删除的路由相同；重新创建。
        let rc6 = unsafe { CreateIpForwardEntry2(&row).0 };
        notes.push(format!("route re-create rc={rc6}"));

        // 10) mutant：只按 CIDR（dest/prefix）删 —— 不填 next-hop / luid。
        //     实测：GetIpForwardEntry2 对 dest-only key 按通配匹配并**填满**行
        //     （rc=0）——"按 CIDR 查"是可行的；真正危险的 mutant 是**不 Get 直接
        //     Delete**（dest-only 行不是合法删除规格）。
        let mut cidr_only = MIB_IPFORWARD_ROW2::default();
        // SAFETY: Initialize 写入行。
        unsafe { InitializeIpForwardEntry(&mut cidr_only) };
        cidr_only.DestinationPrefix = row.DestinationPrefix;
        // SAFETY: dest-only key；观测 Get 的匹配行为（通配 or 拒绝）。
        let rc7 = unsafe { GetIpForwardEntry2(&mut cidr_only).0 };
        f.route_mutant_delete_by_cidr_only_error = Some(rc7);
        notes.push(format!(
            "route mutant get-by-CIDR-only: GetIpForwardEntry2 rc={rc7} (zero nexthop/luid = wildcard match, row filled)"
        ));
        // 确认路由仍在（Get 本身不删）。
        let still_there = forward_table_has(luid);
        notes.push(format!("route after-mutant-get still-present={still_there}"));
        // mutant 第二步：不 Get 直接用 dest-only 行 Delete。
        let mut cidr_only2 = MIB_IPFORWARD_ROW2::default();
        // SAFETY: Initialize 写入行。
        unsafe { InitializeIpForwardEntry(&mut cidr_only2) };
        cidr_only2.DestinationPrefix = row.DestinationPrefix;
        // SAFETY: dest-only 行直接 Delete（未填 next-hop/luid）。
        let rc7b = unsafe { DeleteIpForwardEntry2(&cidr_only2).0 };
        notes.push(format!(
            "route mutant delete-by-CIDR-only-direct: rc={rc7b} (must Get-fill exact row first)"
        ));

        // 11) 正确路径：Get 填满精确行 → Delete —— 成功。
        let mut exact = MIB_IPFORWARD_ROW2::default();
        // SAFETY: Initialize 写入行。
        unsafe { InitializeIpForwardEntry(&mut exact) };
        exact.DestinationPrefix = row.DestinationPrefix;
        exact.NextHop = row.NextHop;
        exact.InterfaceLuid = row.InterfaceLuid;
        // SAFETY: exact 的关键字段与已存在路由一致；Get 填满行。
        let rc8 = unsafe { GetIpForwardEntry2(&mut exact).0 };
        if rc8 == 0 {
            // SAFETY: 行已填满（精确行身份）；删除。
            let rc9 = unsafe { DeleteIpForwardEntry2(&exact).0 };
            f.route_delete_full_row_succeeded = rc9 == 0;
            notes.push(format!("route delete-full-row rc={rc9}"));
        } else {
            f.route_delete_full_row_succeeded = false;
            notes.push(format!("route delete-full-row Get rc={rc8}"));
        }

        // 12) compare-and-restore：best 回到 bypass。
        let best_final = best_route_for(SPARK_ROUTE_PROBE)
            .and_then(|b| ipv4_of(&b.NextHop))
            == f.route_bypass_before_nexthop;
        let gone = !forward_table_has(luid);
        f.route_restore_verified = best_final && gone;
        if !f.route_restore_verified {
            push_restore_failure(f, "route.restore-verify: best route did not return to bypass");
        }
        notes.push(format!(
            "route compare-and-restore: gone={gone}, best-back-to-bypass={best_final}"
        ));
    }
}

/// 在测试接口上冻结 MTU 族事实（IPv4 行；IPv6 行只读记录）。
fn probe_mtu_family(f: &mut NetworkSettingsFacts, luid: &NET_LUID_LH, notes: &mut Vec<String>) {
    // 1) 前置条件：基准 MTU（IPv4 + IPv6 行）。
    let before = interface_row(luid, AF_INET);
    f.mtu_before = before.map(|r| r.NlMtu);
    f.mtu_v6_before = interface_row(luid, AF_INET6).map(|r| r.NlMtu);
    notes.push(format!(
        "mtu baseline: v4={} v6={}",
        f.mtu_before.map(|m| m.to_string()).unwrap_or_else(|| "err".into()),
        f.mtu_v6_before.map(|m| m.to_string()).unwrap_or_else(|| "err".into())
    ));

    // 2) no-effect-before-durable-intent：构建行但只读 —— 不变。
    {
        let _row = interface_row(luid, AF_INET);
        let after = interface_row(luid, AF_INET).map(|r| r.NlMtu);
        f.mtu_prep_no_effect = after == f.mtu_before;
        notes.push(format!("mtu prep-only no-effect={}", f.mtu_prep_no_effect));
    }

    // 3) durable intent：逐值 Set 尝试（诊断 Wintun 接口的 MTU 可写性）。
    //    值集：1420（我们的测试值）、1280、576、0（默认语义）、65535（当前值）、
    //    1（非法，IPv4 最小 68 之下）。
    let attempt_values = [
        SPARK_MTU,
        1280,
        576,
        0,
        65535,
        SPARK_MTU_ILLEGAL,
    ];
    for value in attempt_values {
        dbg_log(&format!("mtu: attempt {value}"));
        if let Some(mut row) = interface_row(luid, AF_INET) {
            // 实测：Get 填充的 IPv4 行带 SitePrefixLength=64，Set 拒绝（87）；
            // 文档要求 IPv4 的 SitePrefixLength 必须为 0——强制清零后再 Set。
            row.SitePrefixLength = 0;
            row.NlMtu = value;
            // SAFETY: row 由 GetIpInterfaceEntry 填满（Family+Luid 有效）；SitePrefixLength=0 + 改 NlMtu。
            let rc = unsafe { SetIpInterfaceEntry(&mut row).0 };
            let readback = interface_row(luid, AF_INET).map(|r| r.NlMtu);
            f.mtu_set_attempts.push(MtuAttempt {
                value,
                rc,
                readback,
            });
            notes.push(format!(
                "mtu set {value} rc={rc} readback={:?}",
                readback
            ));
        } else {
            notes.push("mtu family: GetIpInterfaceEntry(AF_INET) failed".to_string());
            break;
        }
    }
    f.mtu_apply_error = f.mtu_set_attempts.first().map(|a| a.rc);
    f.mtu_applied = f.mtu_set_attempts.first().map(|a| a.rc == 0).unwrap_or(false);
    f.mtu_after = f.mtu_set_attempts.first().and_then(|a| a.readback);
    f.mtu_illegal_value_error = f
        .mtu_set_attempts
        .iter()
        .find(|a| a.value == SPARK_MTU_ILLEGAL)
        .map(|a| a.rc);
    // IPv4 行诊断 dump（Set 失败的可能字段）。
    if let Some(row4) = interface_row(luid, AF_INET) {
        notes.push(format!(
            "mtu v4 row dump: family={} siteprefix={} metric={} autometric={} nlmtu={}",
            row4.Family.0,
            row4.SitePrefixLength,
            row4.Metric,
            row4.UseAutomaticMetric,
            row4.NlMtu
        ));
    }
    // Initialize 构建的 v4 行尝试（不 Get 填充；仅 Family+Luid+NlMtu）——诊断
    // Get 填充行是否携带 Set 拒绝的字段。
    {
        let mut rowi = MIB_IPINTERFACE_ROW::default();
        // SAFETY: Initialize 写入行。
        unsafe { InitializeIpInterfaceEntry(&mut rowi) };
        rowi.Family = AF_INET;
        rowi.InterfaceLuid = *luid;
        rowi.NlMtu = SPARK_MTU;
        // SAFETY: 文档模式（Initialize + Family/Luid + 修改字段）。
        let rci = unsafe { SetIpInterfaceEntry(&mut rowi).0 };
        notes.push(format!("mtu v4 init-built row set {SPARK_MTU} rc={rci}"));
    }
    // IPv6 行尝试（诊断不同 family 行的可写性差异）。
    if let Some(mut row6) = interface_row(luid, AF_INET6) {
        row6.NlMtu = SPARK_MTU;
        // SAFETY: row6 由 Get 填满；IPv6 行尝试。
        let rc6 = unsafe { SetIpInterfaceEntry(&mut row6).0 };
        notes.push(format!("mtu v6 row set {SPARK_MTU} rc={rc6}"));
        if rc6 == 0 {
            let rb6 = interface_row(luid, AF_INET6).map(|r| r.NlMtu);
            notes.push(format!("mtu v6 row read-back after set: {rb6:?}"));
            // 恢复 v6 行（compare-and-restore）。
            if let Some(baseline6) = f.mtu_v6_before
                && let Some(mut restore6) = interface_row(luid, AF_INET6)
            {
                restore6.NlMtu = baseline6;
                // SAFETY: restore6 由 Get 填满；恢复基准值。
                let rcr6 = unsafe { SetIpInterfaceEntry(&mut restore6).0 };
                if rcr6 != 0 {
                    push_restore_failure(f, &format!("mtu.v6-restore-set: rc={rcr6}"));
                }
            }
            let rb6f = interface_row(luid, AF_INET6).map(|r| r.NlMtu);
            if rb6f != f.mtu_v6_before {
                push_restore_failure(
                    f,
                    &format!("mtu.v6-restore-verify: final={rb6f:?} expected={:?}", f.mtu_v6_before),
                );
            }
            notes.push(format!(
                "mtu v6 compare-and-restore: final={rb6f:?}",
            ));
        }
    }

    if f.mtu_applied {
        // 4) 第三方改值：独立 Get→改→Set 路径设 1400，回读 ≠ 我们的 1420。
        if let Some(mut tp) = interface_row(luid, AF_INET) {
            tp.SitePrefixLength = 0;
            tp.NlMtu = SPARK_MTU_THIRD_PARTY;
            // SAFETY: tp 由 Get 填满（SitePrefixLength 强制 0）；模拟第三方 Set。
            let rct = unsafe { SetIpInterfaceEntry(&mut tp).0 };
            notes.push(format!("mtu third-party set {SPARK_MTU_THIRD_PARTY} rc={rct}"));
            let now = interface_row(luid, AF_INET).map(|r| r.NlMtu);
            f.mtu_third_party_detected = now == Some(SPARK_MTU_THIRD_PARTY);
            notes.push(format!(
                "mtu third-party detection: now={:?} (ours={SPARK_MTU})",
                now
            ));
        }

        // 5) 同值幂等：再 Set 同一个值（第三方现值 1400）→ 成功且不变。
        if let Some(mut same) = interface_row(luid, AF_INET) {
            same.SitePrefixLength = 0;
            same.NlMtu = SPARK_MTU_THIRD_PARTY;
            // SAFETY: same 由 Get 填满（SitePrefixLength 强制 0）；同值 Set。
            let rcs = unsafe { SetIpInterfaceEntry(&mut same).0 };
            let after_same = interface_row(luid, AF_INET).map(|r| r.NlMtu);
            f.mtu_same_value_idempotent = rcs == 0 && after_same == Some(SPARK_MTU_THIRD_PARTY);
            notes.push(format!(
                "mtu same-value idempotent rc={rcs} after={:?}",
                after_same
            ));
        }
    }

    // 6) compare-and-restore：最终 v4 回读 == 基准值。若某次尝试改变了 MTU，
    //    显式 Set 回基准并验证；若接口不可写（所有尝试 87），状态从未改变，
    //    恢复即验证回读 == 基准（无需 Set）。
    let final_mtu = interface_row(luid, AF_INET).map(|r| r.NlMtu);
    if final_mtu != f.mtu_before
        && let Some(baseline) = f.mtu_before
        && let Some(mut restore) = interface_row(luid, AF_INET)
    {
        restore.SitePrefixLength = 0;
        restore.NlMtu = baseline;
        // SAFETY: restore 由 Get 填满（SitePrefixLength 强制 0）；恢复基准值。
        let rcr = unsafe { SetIpInterfaceEntry(&mut restore).0 };
        if rcr != 0 {
            push_restore_failure(f, &format!("mtu.restore-set: rc={rcr}"));
        }
    }
    let final_mtu2 = interface_row(luid, AF_INET).map(|r| r.NlMtu);
    f.mtu_restore_verified = final_mtu2 == f.mtu_before;
    if !f.mtu_restore_verified {
        push_restore_failure(
            f,
            &format!(
                "mtu.restore-verify: final={:?} expected={:?}",
                final_mtu2, f.mtu_before
            ),
        );
    }
    notes.push(format!(
        "mtu compare-and-restore: final={:?} verified={}",
        final_mtu2, f.mtu_restore_verified
    ));
}

/// 在测试接口上冻结 DNS 族事实。mutant：无条件恢复旧快照会覆盖第三方变更。
fn probe_dns_family(f: &mut NetworkSettingsFacts, guid: &GUID, notes: &mut Vec<String>) {
    // 1) 前置条件：原始快照（fingerprint）。
    dbg_log("dns: get-before");
    let before = match get_dns(guid) {
        Ok(s) => s,
        Err(rc) => {
            notes.push(format!("dns get-before failed rc={rc}"));
            return;
        }
    };
    f.dns_before_version = Some(before.version);
    f.dns_before_flags = Some(before.flags);
    f.dns_before_nameservers = before.nameservers.clone();
    f.dns_before_search_list = before.search_list.clone();
    let fp_before = dns_fingerprint(&before);
    notes.push(format!(
        "dns before: ver={} flags=0x{:x} ns={:?} search={:?} fp={fp_before}",
        before.version, before.flags, before.nameservers, before.search_list
    ));

    // 2) no-effect-before-durable-intent：只构建 settings 结构，不 Set —— 不变。
    {
        let (_settings, _keep) = dns_settings_v1(SPARK_DNS_SERVER, SPARK_DNS_SEARCH);
        match get_dns(guid) {
            Ok(s) => f.dns_prep_no_effect = dns_fingerprint(&s) == fp_before,
            Err(_) => f.dns_prep_no_effect = false,
        }
        notes.push(format!("dns prep-only no-effect={}", f.dns_prep_no_effect));
    }

    // 3) durable intent：Set nameserver + search list，回读 fingerprint。
    //    实测：Win11 26200 的 Set 拒绝 v1（87），v2 全布局可用——set_dns 自动回退。
    dbg_log("dns: set");
    let (rc, ver_used) = set_dns(guid, SPARK_DNS_SERVER, SPARK_DNS_SEARCH);
    dbg_log(&format!("dns: set rc={rc} ver={ver_used}"));
    f.dns_apply_error = Some(rc);
    f.dns_applied = rc == 0;
    f.dns_set_version_used = Some(ver_used);
    notes.push(format!(
        "dns set v{ver_used} ns={SPARK_DNS_SERVER} search={SPARK_DNS_SEARCH} rc={rc}"
    ));

    if f.dns_applied {
        if let Ok(after) = get_dns(guid) {
            f.dns_readback_version = Some(after.version);
            f.dns_readback_flags = Some(after.flags);
            f.dns_readback_nameservers = after.nameservers.clone();
            f.dns_readback_search_list = after.search_list.clone();
            notes.push(format!(
                "dns read-back: ver={} flags=0x{:x} ns={:?} search={:?}",
                after.version, after.flags, after.nameservers, after.search_list
            ));
        } else {
            notes.push("dns read-back: get failed".to_string());
        }

        // 4) 第三方冲突：独立 Set 改 nameserver → 回读 ≠ 我们的值。
        let (rct, _ver_tp) = set_dns(guid, SPARK_DNS_SERVER_TP, SPARK_DNS_SEARCH);
        notes.push(format!("dns third-party set ns={SPARK_DNS_SERVER_TP} rc={rct}"));
        if let Ok(tp_state) = get_dns(guid) {
            f.dns_third_party_detected =
                tp_state.nameservers == vec![SPARK_DNS_SERVER_TP.to_string()];
            notes.push(format!(
                "dns third-party detection: ns={:?} detected={}",
                tp_state.nameservers, f.dns_third_party_detected
            ));
        }

        // 5) 同值幂等：再 Set 同样的第三方值 → 成功且不变。
        let (rcs, _ver_same) = set_dns(guid, SPARK_DNS_SERVER_TP, SPARK_DNS_SEARCH);
        if let Ok(same_state) = get_dns(guid) {
            f.dns_same_value_idempotent =
                rcs == 0 && same_state.nameservers == vec![SPARK_DNS_SERVER_TP.to_string()];
        }
        notes.push(format!("dns same-value idempotent rc={rcs}"));

        // 6) partial/unknown：非法 nameserver 字符串（非 IP）→ 记录错误。
        let (rcb, _ver_bad) = set_dns(guid, "not-an-ip", SPARK_DNS_SEARCH);
        f.dns_partial_unknown_error = Some(rcb);
        notes.push(format!("dns partial/unknown nameserver rc={rcb}"));

        // 7) compare-and-restore：当前状态 ≠ 原始快照（第三方改过）→ **跳过**恢复
        //    （无条件恢复会覆盖第三方变更 = mutant）；随后显式清理探针自己的产物。
        let now = get_dns(guid).ok();
        let now_fp = now.as_ref().map(dns_fingerprint);
        let third_party_changed = now_fp.as_deref() != Some(&fp_before);
        f.dns_restore_skipped_third_party = third_party_changed;
        f.dns_mutant_unconditional_restore_would_clobber = third_party_changed;
        notes.push(format!(
            "dns compare-and-restore: third_party_changed={third_party_changed} -> restore SKIPPED (unconditional restore of old snapshot would clobber; mutant)"
        ));

        // 显式清理：把 nameserver/search 清回原始（compare-and-restore 的"移除自己
        // 的产物"步骤；空数组 + NAMESERVER|SEARCH_LIST flags = 清空语义）。
        let rcc = clear_dns(guid);
        notes.push(format!("dns explicit cleanup rc={rcc}"));
        let final_state = get_dns(guid).ok();
        let final_fp = final_state.as_ref().map(dns_fingerprint);
        f.dns_final_state_equals_original = final_fp.as_deref() == Some(&fp_before);
        if !f.dns_final_state_equals_original {
            push_restore_failure(
                f,
                &format!(
                    "dns.restore-verify: final_fp={:?} expected={fp_before}",
                    final_fp
                ),
            );
        }
        notes.push(format!(
            "dns final-state-==-original: {}",
            f.dns_final_state_equals_original
        ));
    }
}

// ---------------------------------------------------------------------------
// 原生 API 小封装（每个 unsafe 块带 SAFETY）。
// ---------------------------------------------------------------------------

/// 测试接口行（IPv4 地址）：Initialize + Address + InterfaceLuid + 字段。
fn unicast_row_for(ip: &str, luid: &NET_LUID_LH, prefix_len: u8) -> MIB_UNICASTIPADDRESS_ROW {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: Initialize 写入行。
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.Address = sockaddr_ipv4(ip);
    row.InterfaceLuid = *luid;
    row.OnLinkPrefixLength = prefix_len;
    row.SkipAsSource = false;
    row
}

/// 从 unicast 表回读指定地址的精确行（按 InterfaceLuid 过滤）。
fn unicast_row_of(luid: &NET_LUID_LH, ip: &str) -> Option<MIB_UNICASTIPADDRESS_ROW> {
    // SAFETY: table 指针由系统分配，用完 FreeMibTable。
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    let rc = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table).0 };
    if rc != 0 || table.is_null() {
        return None;
    }
    // SAFETY: table 由系统填充；NumEntries 界内访问（显式 from_raw_parts，避免
    // 隐式 autoref 引用裸指针解引用）。
    let table_ref = unsafe { &*table };
    let rows = unsafe {
        std::slice::from_raw_parts(table_ref.Table.as_ptr(), table_ref.NumEntries as usize)
    };
    let found = rows.iter().find(|r| {
        // r: &&Row；显式解引用避免 auto-deref 歧义。
        let row = *r;
        // SAFETY: 读 union 成员（InterfaceLuid.Value）。
        let same_luid = unsafe { row.InterfaceLuid.Value == luid.Value };
        let same_ip = ipv4_of(&row.Address).as_deref() == Some(ip);
        same_luid && same_ip
    });
    let out = found.copied();
    // SAFETY: 释放系统分配的表。
    unsafe { FreeMibTable(table.cast()) };
    out
}

/// 测试接口上是否存在指定地址。
fn unicast_table_has(luid: &NET_LUID_LH, ip: &str) -> bool {
    unicast_row_of(luid, ip).is_some()
}

/// 隧道路由行：Initialize + dest/next-hop/luid/metric/lifetime。
fn forward_row_for(luid: &NET_LUID_LH) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: Initialize 写入行。
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.DestinationPrefix.Prefix = sockaddr_ipv4(SPARK_ROUTE_NETWORK);
    row.DestinationPrefix.PrefixLength = SPARK_ROUTE_PREFIX_LEN;
    row.NextHop = sockaddr_ipv4(SPARK_IP_A);
    row.InterfaceLuid = *luid;
    row.Metric = SPARK_ROUTE_METRIC;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.Origin = NlroManual;
    row
}

/// 从转发表回读隧道路由的精确行（按 dest 前缀 + luid 过滤）。
fn forward_row_readback(luid: &NET_LUID_LH) -> Option<MIB_IPFORWARD_ROW2> {
    // SAFETY: table 指针由系统分配，用完 FreeMibTable。
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let rc = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table).0 };
    if rc != 0 || table.is_null() {
        return None;
    }
    // SAFETY: table 由系统填充；NumEntries 界内访问（显式 from_raw_parts，避免
    // 隐式 autoref 引用裸指针解引用）。
    let table_ref = unsafe { &*table };
    let rows = unsafe {
        std::slice::from_raw_parts(table_ref.Table.as_ptr(), table_ref.NumEntries as usize)
    };
    let found = rows.iter().find(|r| {
        // r: &&Row；显式解引用避免 auto-deref 歧义。
        let row = *r;
        // SAFETY: 读 union 成员（InterfaceLuid.Value）。
        let same_luid = unsafe { row.InterfaceLuid.Value == luid.Value };
        let same_prefix = row.DestinationPrefix.PrefixLength == SPARK_ROUTE_PREFIX_LEN;
        let same_net =
            ipv4_of(&row.DestinationPrefix.Prefix).as_deref() == Some(SPARK_ROUTE_NETWORK);
        same_luid && same_prefix && same_net
    });
    let out = found.copied();
    // SAFETY: 释放系统分配的表。
    unsafe { FreeMibTable(table.cast()) };
    out
}

/// 转发表上是否仍存在隧道路由。
fn forward_table_has(luid: &NET_LUID_LH) -> bool {
    forward_row_readback(luid).is_some()
}

/// 转发表读取诊断：记录 GetIpForwardTable2 的 rc、行数，以及与测试接口或
/// 10.99.99.0/24 相关的行（定位 read-back 找不到 netsh 路由的原因）。
fn dump_forward_table_diag(luid: &NET_LUID_LH, notes: &mut Vec<String>) {
    // SAFETY: table 指针由系统分配，用完 FreeMibTable。
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let rc = unsafe { GetIpForwardTable2(AF_INET, &mut table).0 };
    if rc != 0 {
        notes.push(format!("forward table diag: GetIpForwardTable2(AF_INET) rc={rc}"));
        return;
    }
    if table.is_null() {
        notes.push("forward table diag: table is NULL".to_string());
        return;
    }
    // SAFETY: table 由系统填充；NumEntries 界内访问。
    let table_ref = unsafe { &*table };
    let rows = unsafe {
        std::slice::from_raw_parts(table_ref.Table.as_ptr(), table_ref.NumEntries as usize)
    };
    notes.push(format!("forward table diag: num_entries={}", rows.len()));
    let mut hit = 0usize;
    for (i, r) in rows.iter().enumerate() {
        // SAFETY: 读 union 成员。
        let same_luid = unsafe { r.InterfaceLuid.Value == luid.Value };
        let is_net = ipv4_of(&r.DestinationPrefix.Prefix).as_deref() == Some(SPARK_ROUTE_NETWORK);
        if same_luid || is_net {
            hit += 1;
            notes.push(format!(
                "forward table diag row[{i}]: dest={}/{} nexthop={} metric={} protocol={} luid_match={same_luid} net_match={is_net}",
                ipv4_of(&r.DestinationPrefix.Prefix).unwrap_or_else(|| "?".to_string()),
                r.DestinationPrefix.PrefixLength,
                ipv4_of(&r.NextHop).unwrap_or_else(|| "?".to_string()),
                r.Metric,
                r.Protocol.0
            ));
        }
    }
    if hit == 0 {
        notes.push("forward table diag: no rows match test luid or 10.99.99.0/24".to_string());
    }
    // SAFETY: 释放系统分配的表。
    unsafe { FreeMibTable(table.cast()) };
}

/// GetBestRoute2：查指定目的地址的最优路由（含源地址选择）。
fn best_route_for(dest_ip: &str) -> Option<MIB_IPFORWARD_ROW2> {
    let dest = sockaddr_ipv4(dest_ip);
    let mut best = MIB_IPFORWARD_ROW2::default();
    let mut best_src = SOCKADDR_INET::default();
    // SAFETY: dest 是合法 SOCKADDR_INET；best/best_src 由系统填充。
    let rc = unsafe { GetBestRoute2(None, 0, None, &dest, 0, &mut best, &mut best_src).0 };
    if rc != 0 {
        None
    } else {
        Some(best)
    }
}

/// 获取接口行（指定 family）。
fn interface_row(luid: &NET_LUID_LH, family: ADDRESS_FAMILY) -> Option<MIB_IPINTERFACE_ROW> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: Initialize 写入行。
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family;
    row.InterfaceLuid = *luid;
    // SAFETY: row 的 Family+Luid 有效；Get 填满行。
    let rc = unsafe { GetIpInterfaceEntry(&mut row).0 };
    if rc != 0 {
        None
    } else {
        Some(row)
    }
}

/// LUID → 接口 index。
fn luid_to_index(luid: &NET_LUID_LH) -> Option<u32> {
    let mut idx = 0u32;
    // SAFETY: idx 由系统填充。
    let rc = unsafe { ConvertInterfaceLuidToIndex(luid, &mut idx).0 };
    if rc != 0 { None } else { Some(idx) }
}

/// LUID → 接口别名。
fn luid_to_alias(luid: &NET_LUID_LH) -> Option<String> {
    let mut buf = [0u16; 256];
    // SAFETY: buf 是 256 宽字符缓冲（IF_MAX_STRING_SIZE 语义）；系统写入别名。
    let rc = unsafe { ConvertInterfaceLuidToAlias(luid, &mut buf).0 };
    if rc != 0 {
        return None;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]))
}

// ---------------------------------------------------------------------------
// DNS settings（windows crate 0.62.2 的 DNS_INTERFACE_SETTINGS 是 v1 布局；
// Get 可能返回 v2+ 布局——按 x64 偏移手动解析，诚实记录返回的版本）。
// ---------------------------------------------------------------------------

/// 解析后的 DNS 快照。
#[derive(Clone, Debug)]
struct DnsSnapshot {
    version: u32,
    flags: u64,
    nameservers: Vec<String>,
    search_list: Vec<String>,
}

/// 指纹字符串（比较语义：nameservers + search + flags）。
fn dns_fingerprint(s: &DnsSnapshot) -> String {
    format!(
        "ns={:?};search={:?};flags=0x{:x}",
        s.nameservers, s.search_list, s.flags
    )
}

/// GetInterfaceDnsSettings（文档语义，实测修正）：**原地填充**调用方结构——调用方把
/// `Version` 设为期望的布局版本（VERSION1 = 1，与 windows crate 0.62.2 的
/// `DNS_INTERFACE_SETTINGS` v1 布局一致），`Flags` 必须为空；内嵌字符串由系统分配，
/// 用毕必须 `FreeInterfaceDnsSettings` 释放。
fn get_dns(guid: &GUID) -> Result<DnsSnapshot, u32> {
    // 文档语义（实测修正）：Version 必须设为期望的布局版本（1 = v1 字符串格式，
    // 与 crate 的 DNS_INTERFACE_SETTINGS 布局一致），Flags 必须为空；Get **原地填充**。
    let mut storage = DNS_INTERFACE_SETTINGS { Version: 1, ..Default::default() };
    // SAFETY: storage 由调用方提供且 Version=1；Get 原地填充 v1 布局。
    dbg_log("dns.get: calling GetInterfaceDnsSettings");
    let rc = unsafe { GetInterfaceDnsSettings(*guid, &mut storage).0 };
    dbg_log(&format!("dns.get: rc={rc}"));
    if rc != 0 {
        return Err(rc);
    }
    if !(1..=4).contains(&storage.Version) {
        return Err(ERROR_INVALID_PARAMETER.0);
    }
    let snap = parse_dns_ptr(std::ptr::addr_of!(storage));
    // SAFETY: Get 返回的结构内嵌字符串由系统分配，必须 FreeInterfaceDnsSettings 释放。
    dbg_log("dns.get: calling FreeInterfaceDnsSettings");
    unsafe { FreeInterfaceDnsSettings(&mut storage) };
    dbg_log("dns.get: freed");
    Ok(snap)
}

/// 按 x64 布局解析 DNS 指针（v1：字符串；v2+：数组）。
fn parse_dns_ptr(p: *const DNS_INTERFACE_SETTINGS) -> DnsSnapshot {
    let bytes = p as *const u8;
    let read_u32 = |off: usize| -> u32 {
        // SAFETY: p 指向系统分配的有效结构；x64 对齐偏移。
        unsafe { std::ptr::read_unaligned(bytes.add(off).cast::<u32>()) }
    };
    let read_u64 = |off: usize| -> u64 {
        // SAFETY: 同 read_u32。
        unsafe { std::ptr::read_unaligned(bytes.add(off).cast::<u64>()) }
    };
    let read_pwstr = |off: usize| -> Option<String> {
        // SAFETY: 同 read_u32。
        let p = unsafe { std::ptr::read_unaligned(bytes.add(off).cast::<PCWSTR>()) };
        if p.is_null() {
            return None;
        }
        // SAFETY: 读取 NUL 结尾宽字符串（系统分配，探针生命周期内有效）。
        unsafe { p.to_string().ok() }
    };
    let version = read_u32(0);
    let flags = read_u64(8);
    if version == 1 {
        let mut snap = DnsSnapshot {
            version,
            flags,
            nameservers: Vec::new(),
            search_list: Vec::new(),
        };
        // v1：NameServer @24 / SearchList @32（文档：逗号或空格分隔的字符串）。
        if let Some(ns) = read_pwstr(24) {
            snap.nameservers = ns
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
        }
        if let Some(sl) = read_pwstr(32) {
            snap.search_list = sl
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
        }
        snap
    } else {
        // v2+：NameServer = DNS_ADDRESS_ARRAY @24 {u32 ver, u32 count, SOCKADDR_INET[count] @32, stride 28}；
        // SearchList = DNS_SUFFIX_ARRAY {u32 ver, u32 count, PWSTR[count] @base+8, stride 8}，
        // base = align8(24 + 8 + 28*ns_count)。
        let ns_count = read_u32(28);
        let mut nameservers = Vec::new();
        for i in 0..ns_count {
            let off = 32usize + 28usize * i as usize;
            // SAFETY: 数组元素在系统分配的结构界内。
            let sa = unsafe { std::ptr::read_unaligned(bytes.add(off).cast::<SOCKADDR_INET>()) };
            let s = ipv4_of(&sa).unwrap_or_else(|| ipv6_hex_of(&sa));
            nameservers.push(s);
        }
        let search_base = (24usize + 8 + 28 * ns_count as usize + 7) & !7usize;
        let sl_count = read_u32(search_base + 4);
        let mut search_list = Vec::new();
        for i in 0..sl_count {
            let off = search_base + 8usize + 8usize * i as usize;
            // SAFETY: 数组元素在系统分配的结构界内。
            let p = unsafe { std::ptr::read_unaligned(bytes.add(off).cast::<PCWSTR>()) };
            if !p.is_null() {
                // SAFETY: 读取 NUL 结尾宽字符串（系统分配）。
                if let Ok(s) = unsafe { p.to_string() } {
                    search_list.push(s);
                }
            }
        }
        DnsSnapshot {
            version,
            flags,
            nameservers,
            search_list,
        }
    }
}

/// v1 DNS settings 结构（字符串格式；空串 = 清空该设置）。
///
/// 返回 (结构, 保持字符串生命的 HSTRING 列表)——调用方必须在 `SetInterfaceDnsSettings`
/// 调用期间持有第二项（裸 PCWSTR 指向 HSTRING 缓冲区，drop 即失效）。
fn dns_settings_v1(nameserver: &str, search: &str) -> (DNS_INTERFACE_SETTINGS, Vec<HSTRING>) {
    let mut s = DNS_INTERFACE_SETTINGS { Version: 1, ..Default::default() };
    let mut flags = 0u64;
    if !nameserver.is_empty() {
        flags |= DNS_FLAG_NAMESERVER;
    }
    if !search.is_empty() {
        flags |= DNS_FLAG_SEARCH_LIST;
    }
    s.Flags = flags;
    let ns = HSTRING::from(nameserver);
    let sl = HSTRING::from(search);
    s.NameServer = PWSTR::from_raw(ns.as_ptr() as *mut u16);
    s.SearchList = PWSTR::from_raw(sl.as_ptr() as *mut u16);
    (s, vec![ns, sl])
}

/// v2 DNS settings 结构（手动构造 x64 布局；Set 时 v1 被拒的回退）。
///
/// 返回 (原始字节缓冲, 保持字符串生命的 HSTRING 列表)——同上，调用期间持有第二项。
/// v2 DNS settings 结构（手动构造**完整**的 80 字节 `DNS_INTERFACE_SETTINGS_EX` 布局，
/// x64；文档实测修正：VERSION2 = DNS_INTERFACE_SETTINGS_EX = { SettingsV1（64 字节，
/// NameServer/SearchList 仍是**字符串**）+ DisableUnconstrainedQueries + SupplementalSearchList }。
/// 教训：误按 DNS_ADDRESS_ARRAY 布局构造（104 字节）会让 Set 把 @24 处 {ver,count} 当
/// PWSTR 指针解引用 → AV 0xC0000005）。
///
/// 返回 (原始字节缓冲, 保持字符串生命的 HSTRING 列表)——调用期间持有第二项。
fn dns_settings_v2_raw(nameserver: &str, search: &str) -> (Vec<u8>, Vec<HSTRING>) {
    let mut flags = 0u64;
    if !nameserver.is_empty() {
        flags |= DNS_FLAG_NAMESERVER;
    }
    if !search.is_empty() {
        flags |= DNS_FLAG_SEARCH_LIST;
    }
    dns_settings_v2_raw_flags(nameserver, search, flags)
}

/// 带显式 flags 的 v2 布局构造（清空场景需要 flags 存在但字符串为空）。
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
    // SettingsV1.NameServer @24 / SearchList @32：**只要对应 flag 置位就写指针**
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

/// 清空接口 DNS 设置（nameserver + search list）——显式带 NAMESERVER|SEARCH_LIST flags，
/// 空字符串 = 清空语义。返回 rc。
fn clear_dns(guid: &GUID) -> u32 {
    let (b, keep) = dns_settings_v2_raw_flags(
        "",
        "",
        DNS_FLAG_NAMESERVER | DNS_FLAG_SEARCH_LIST,
    );
    // SAFETY: b 是完整 v2(EX) 布局（80 字节零填充；keep 在调用期间存活）。
    let rc = unsafe { SetInterfaceDnsSettings(*guid, b.as_ptr().cast()).0 };
    drop(keep);
    rc
}

/// Set 接口 DNS 设置（nameserver + search list；空串 = 清空）。返回 (rc, 使用的版本)。
/// 实测：Win11 26200 的 Set 拒绝 v1（ERROR_INVALID_PARAMETER），v2 全布局可用——
/// 先试 v1，失败自动回退 v2，诚实记录哪个版本被接受。
fn set_dns(guid: &GUID, nameserver: &str, search: &str) -> (u32, u32) {
    let (s1, keep1) = dns_settings_v1(nameserver, search);
    // SAFETY: s1 是合法 v1 结构（keep1 在调用期间存活）。
    let rc1 = unsafe { SetInterfaceDnsSettings(*guid, &s1).0 };
    drop(keep1);
    if rc1 == 0 {
        return (0, 1);
    }
    let (b2, keep2) = dns_settings_v2_raw(nameserver, search);
    // SAFETY: b2 是完整 v2 布局（104 字节零填充；keep2 在调用期间存活）。
    let rc2 = unsafe { SetInterfaceDnsSettings(*guid, b2.as_ptr().cast()).0 };
    drop(keep2);
    (rc2, 2)
}

// ---------------------------------------------------------------------------
// Wintun 动态加载（测试接口载体；WSP3 冻结路径）。
// ---------------------------------------------------------------------------

type WintunCreateAdapterFn = unsafe extern "system" fn(PCWSTR, PCWSTR, *const GUID) -> *mut c_void;
type WintunGetAdapterLuidFn = unsafe extern "system" fn(*mut c_void, *mut NET_LUID_LH) -> i32;
type WintunCloseAdapterFn = unsafe extern "system" fn(*mut c_void);
type WintunOpenAdapterFn = unsafe extern "system" fn(PCWSTR) -> *mut c_void;

struct WintunFns {
    #[allow(dead_code)]
    hmod: HMODULE,
    create: WintunCreateAdapterFn,
    get_luid: WintunGetAdapterLuidFn,
    close: WintunCloseAdapterFn,
    open: WintunOpenAdapterFn,
}

fn load_wintun(path: &Path) -> Result<WintunFns, String> {
    let h = HSTRING::from(path.as_os_str());
    // SAFETY: h 是合法宽字符串路径；返回模块句柄（0.62.2 绑定返回 Result）。
    let hmod = match unsafe { LoadLibraryW(&h) } {
        Ok(m) => m,
        Err(e) => return Err(format!("LoadLibraryW {} failed: {e}", path.display())),
    };
    let resolve = |name: &str| -> Result<unsafe extern "system" fn() -> isize, String> {
        let cname = std::ffi::CString::new(name).map_err(|e| e.to_string())?;
        // SAFETY: hmod 有效；cname 是 NUL 结尾 ANSI 名称。
        let fp = unsafe { GetProcAddress(hmod, PCSTR::from_raw(cname.as_ptr().cast::<u8>())) };
        fp.ok_or_else(|| format!("{name} not exported"))
    };
    let cast_fn = |fp: unsafe extern "system" fn() -> isize| -> usize { fp as usize };
    // SAFETY: 调用方用已知签名声明；GetProcAddress 返回的地址即该导出入口。
    let create: WintunCreateAdapterFn =
        unsafe { std::mem::transmute_copy(&cast_fn(resolve("WintunCreateAdapter")?)) };
    let get_luid: WintunGetAdapterLuidFn =
        unsafe { std::mem::transmute_copy(&cast_fn(resolve("WintunGetAdapterLUID")?)) };
    let close: WintunCloseAdapterFn =
        unsafe { std::mem::transmute_copy(&cast_fn(resolve("WintunCloseAdapter")?)) };
    let open: WintunOpenAdapterFn =
        unsafe { std::mem::transmute_copy(&cast_fn(resolve("WintunOpenAdapter")?)) };
    Ok(WintunFns {
        hmod,
        create,
        get_luid,
        close,
        open,
    })
}

fn create_test_adapter(wf: &WintunFns) -> Result<*mut c_void, String> {
    let name = HSTRING::from(SPARK_ADAPTER_NAME);
    let tunnel = HSTRING::from(SPARK_TUNNEL_TYPE);
    // SAFETY: name/tunnel 是合法宽字符串；RequestedGUID=NULL 让系统随机选 GUID。
    // 返回 adapter 句柄；失败返回 NULL。需 WintunCloseAdapter 释放。
    let h = unsafe {
        (wf.create)(
            PCWSTR::from_raw(name.as_ptr()),
            PCWSTR::from_raw(tunnel.as_ptr()),
            std::ptr::null(),
        )
    };
    if h.is_null() {
        Err(format!("WintunCreateAdapter failed, GetLastError={}", last_error()))
    } else {
        Ok(h)
    }
}

// ---------------------------------------------------------------------------
// 通用小工具。
// ---------------------------------------------------------------------------

fn last_error() -> u32 {
    // SAFETY: 无指针参数，纯读线程错误码。
    unsafe { GetLastError().0 }
}

/// 供 spike 二进制在 panic 兜底时读取权限状态的公开入口。
pub fn is_elevated_exported() -> bool {
    is_elevated()
}

fn is_elevated() -> bool {
    // SAFETY: GetCurrentProcess 返回伪句柄，无需关闭。
    let proc_h = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    let mut token = windows::Win32::Foundation::HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    let ok = unsafe {
        windows::Win32::System::Threading::OpenProcessToken(
            proc_h,
            windows::Win32::Security::TOKEN_QUERY,
            &mut token,
        )
    };
    if ok.is_err() {
        return false;
    }
    let mut elevated = false;
    let mut size = 0u32;
    // SAFETY: 首次探测调用（null 缓冲）预期返回 ERROR_INSUFFICIENT_BUFFER，
    // 仅用其回填的 size 分配缓冲（WSP3 验证过的模式：忽略该调用的 Err）。
    let _query = unsafe {
        windows::Win32::Security::GetTokenInformation(
            token,
            windows::Win32::Security::TokenElevation,
            Some(std::ptr::null_mut()),
            0,
            &mut size,
        )
    };
    let mut buf = vec![0u8; size as usize];
    // SAFETY: buf 是有效缓冲；TokenElevation 返回 TOKEN_ELEVATION { TokenIsElevated: BOOL }。
    let ok2 = unsafe {
        windows::Win32::Security::GetTokenInformation(
            token,
            windows::Win32::Security::TokenElevation,
            Some(buf.as_mut_ptr().cast()),
            buf.len() as u32,
            &mut size,
        )
    };
    if ok2.is_ok() && buf.len() >= std::mem::size_of::<u32>() {
        elevated = u32::from_ne_bytes(buf[0..4].try_into().unwrap_or([0u8; 4])) != 0;
    }
    // SAFETY: token 是本进程新打开句柄，使用后关闭。
    unsafe { let _ = windows::Win32::Foundation::CloseHandle(token); }
    elevated
}

/// GUID → 标准字符串（windows::core::GUID 在 0.62.2 未实现 Display）。
fn guid_string(g: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}

/// 把 IPv4 字符串解析为 SOCKADDR_INET（非法输入 → family 0）。
fn sockaddr_ipv4(ip: &str) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    let octets: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if octets.len() == 4 {
        // 实测修正（forward table diag 暴露字节序）：S_addr 在内存中按网络字节序存储；
        // 在 x86（LE）上写入/读取都必须用 from_le_bytes/to_le_bytes——用
        // from_be_bytes 会把 10.99.99.0 写成 0.99.99.10（netsh/表读回均验证）。
        let v = u32::from_le_bytes([octets[0], octets[1], octets[2], octets[3]]);
        // edition 2024：非引用 place 上的 union 字段写是安全操作（先设 family 再写 sin_addr）。
        sa.Ipv4.sin_family = AF_INET;
        sa.Ipv4.sin_addr.S_un.S_addr = v;
    }
    sa
}

/// SOCKADDR_INET → IPv4 点分字符串（非 AF_INET 返回 None）。
fn ipv4_of(sa: &SOCKADDR_INET) -> Option<String> {
    // SAFETY: 读 union 的公共初始成员 si_family；AF_INET 时读 sin_addr。
    unsafe {
        if sa.si_family != AF_INET {
            return None;
        }
        // 实测修正：S_addr 按网络字节序存于内存（x86 LE）→ to_le_bytes 还原字节。
        let b = sa.Ipv4.sin_addr.S_un.S_addr.to_le_bytes();
        Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
    }
}

/// SOCKADDR_INET → IPv6 十六进制串（非 AF_INET6 返回 "?"）。
fn ipv6_hex_of(sa: &SOCKADDR_INET) -> String {
    // SAFETY: 读 union 成员。
    unsafe {
        if sa.si_family != AF_INET6 {
            return "?".to_string();
        }
        let mut out = String::new();
        // IN6_ADDR 是 [u8; 16]；逐字节读。
        let base = std::ptr::addr_of!(sa.Ipv6.sin6_addr) as *const u8;
        for i in 0..8 {
            // SAFETY: IN6_ADDR 16 字节，界内。
            let hi = std::ptr::read_unaligned(base.add(i * 2));
            let lo = std::ptr::read_unaligned(base.add(i * 2 + 1));
            if i > 0 {
                out.push(':');
            }
            out.push_str(&format!("{hi:02x}{lo:02x}"));
        }
        out
    }
}

fn push_restore_failure(f: &mut NetworkSettingsFacts, what: &str) {
    f.restore_failures.push(what.to_string());
    f.restore_ok = false;
}

/// 带 watchdog 的子进程调用（WSP3 教训：netsh 在本机可能无限阻塞）。
fn run_cmd_checked(
    program: &str,
    args: &[String],
    timeout: std::time::Duration,
) -> Option<(bool, String)> {
    use std::io::Read;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None; // 超时
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            Err(_) => return None,
        }
    };
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    let _ = child.wait();
    Some((status.success(), format!("{out}{err}")))
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
