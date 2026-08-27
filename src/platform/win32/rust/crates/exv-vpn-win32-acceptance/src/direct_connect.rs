// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// 规格：docs/superpowers/specs/2026-08-15-vpn-gateway-direct-connect-guarantee.md；cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! 双线可信网关解析（DoH → 绑物理网卡 UDP/53）+ `/32` 直连路由生命周期（VGDC）。
//!
//! **C4 提升后本模块的 DNS 双线解析已提升进生产**（`exv-vpn-win32-resource::vgdc_dns`，
//! PRD G-⑤ / C4）；本模块对 DNS 部分作**薄重导出**（不 fork 两份），保留：
//!
//! - **同步 shim**：[`resolve_gateway_dual_line`]（`rt` + `block_on`）适配既有 acceptance
//!   调用面（school/coordination scenario 已持有 `tokio::runtime::Runtime`）；生产侧用
//!   `vgdc_dns::resolve_gateway_dual_line` 的 async 入口。
//! - **`/32` 直连路由生命周期**（`ensure_gateway_route` / `remove_gateway_route` /
//!   `gateway_route_absent` / `snapshot_ipv4_routes`；复用 `exv-vpn-win32-resource::routes`
//!   原语，回读证明）。
//!
//! 双线解析语义（L1 DoH / L2 UDP/53 绑网卡 / fake-ip 过滤 / 逐层 typed 失败）见
//! `exv-vpn-win32-resource::vgdc_dns`。

use std::net::Ipv4Addr;

use exv_vpn_win32_resource::native_error::NativeError;
use exv_vpn_win32_resource::routes::{RemoveOutcome, RouteRow};
// VGDC 双线 DNS 生产实现重导出（acceptance 调用面保持 `direct_connect::*` 稳定）。
pub use exv_vpn_win32_resource::vgdc_dns::{
    NicInfo, ResolutionSource, ResolveLayerError, DohErrorKind, DohEndpoint, DualLineConfig,
    Udp53ErrorKind, doh_query, dns_a_query_udp, find_physical_nics, is_fake_ip_v4,
    socket_binder_for_ifindex,
};
use windows::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIpForwardTable2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows::Win32::Networking::WinSock::AF_INET;

/// `/32` 直连路由前缀长度。
const GATEWAY_ROUTE_PREFIX: u8 = 32;
/// 新装 `/32` 直连路由的度量（crate 既有测试冻结值 5；已存在路由按实测行采纳其度量）。
const GATEWAY_ROUTE_METRIC: u32 = 5;
/// `ERROR_OBJECT_ALREADY_EXISTS`（`CreateIpForwardEntry2` 重复精确行）。
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;
/// `ERROR_NOT_FOUND`（`GetIpForwardTable2`/`GetIpForwardEntry2` 无该路由）。
const ERROR_NOT_FOUND: u32 = 1168;

// ---------------------------------------------------------------------------
// 双线解析（重导出 `exv-vpn-win32-resource::vgdc_dns` 的 DNS 部分）。
// ---------------------------------------------------------------------------

/// 双线可信解析同步 shim（既有 acceptance 调用面：`rt.block_on` 生产 async 入口）。
///
/// gateway host 为 IPv4 字面量时直接采用（`ResolutionSource::System`；fake-ip 字面量
/// 拒绝）；否则按配置顺序试 DoH 全部 endpoint，再试 UDP/53 全部 resolver。
///
/// # Errors
///
/// 全部线路失败 → [`ResolveLayerError`] 向量（每层一条；证据 `describe()`）。
pub fn resolve_gateway_dual_line(
    cfg: &DualLineConfig,
    rt: &tokio::runtime::Runtime,
    host: &str,
) -> Result<(Ipv4Addr, ResolutionSource), Vec<ResolveLayerError>> {
    rt.block_on(exv_vpn_win32_resource::vgdc_dns::resolve_gateway_dual_line(
        cfg, host,
    ))
}

// ---------------------------------------------------------------------------
// /32 直连路由生命周期（复用 exv-vpn-win32-resource::routes 原语：
// install/remove/RouteRow/RemoveOutcome；回读证明 = GetIpForwardTable2 全表扫描）。
// ---------------------------------------------------------------------------

/// 全路由表扫描：目标 `/32` 精确行（read-back 证明；非 IPv4 行跳过）。
///
/// # Errors
///
/// `GetIpForwardTable2` 失败 → [`NativeError`]。
pub fn find_route_for_dest(dest: Ipv4Addr) -> Result<Option<RouteRow>, NativeError> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: table 由系统分配；用毕必须 FreeMibTable（routes.rs capture_rows 同款路径）。
    let rc = unsafe { GetIpForwardTable2(AF_INET, &raw mut table) }.0;
    if rc != 0 {
        return Err(NativeError::from_win32(rc, "GetIpForwardTable2 失败"));
    }
    if table.is_null() {
        return Ok(None);
    }
    // SAFETY: table 由系统填充；NumEntries 界内访问（显式 from_raw_parts）。
    let table_ref = unsafe { &*table };
    let rows = unsafe { std::slice::from_raw_parts(table_ref.Table.as_ptr(), table_ref.NumEntries as usize) };
    let mut found: Option<RouteRow> = None;
    for r in rows {
        if r.DestinationPrefix.PrefixLength != GATEWAY_ROUTE_PREFIX {
            continue;
        }
        if let Some(row) = route_row_from_api(r)
            && row.network == dest
        {
            found = Some(row);
            break;
        }
    }
    // SAFETY: 释放系统分配的表。
    unsafe { FreeMibTable(table.cast()) };
    Ok(found)
}

/// `MIB_IPFORWARD_ROW2` → `RouteRow`（非 IPv4 行返回 `None`；routes.rs `from_api_row`
/// 的接受 crate 侧复刻——`from_api_row` 是 resource crate 的 pub(crate)）。
#[must_use]
fn route_row_from_api(api: &MIB_IPFORWARD_ROW2) -> Option<RouteRow> {
    let sa = &api.DestinationPrefix.Prefix;
    if unsafe { sa.si_family } != AF_INET {
        return None;
    }
    // SAFETY: AF_INET 分支下 sin_addr 有效（S_addr 网络字节序于内存）。
    let octets = unsafe { sa.Ipv4.sin_addr.S_un.S_addr }.to_le_bytes();
    let next_hop_sa = &api.NextHop;
    if unsafe { next_hop_sa.si_family } != AF_INET {
        return None;
    }
    // SAFETY: AF_INET 分支下 sin_addr 有效。
    let next_hop_octets = unsafe { next_hop_sa.Ipv4.sin_addr.S_un.S_addr }.to_le_bytes();
    // SAFETY: 读 union 成员 InterfaceLuid.Value。
    let interface_luid = unsafe { api.InterfaceLuid.Value };
    Some(RouteRow {
        network: Ipv4Addr::from(octets),
        prefix_len: api.DestinationPrefix.PrefixLength,
        next_hop: Ipv4Addr::from(next_hop_octets),
        interface_luid,
        metric: api.Metric,
        protocol: u32::try_from(api.Protocol.0).unwrap_or(0),
    })
}

/// `/32` 直连路由 ensure 结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsureRouteOutcome {
    /// 实际持有的精确行（已存在时采纳实测行——含其 metric/protocol，删除全字段匹配）。
    pub row: RouteRow,
    /// 路由已就位（verify 命中或 install 成功）。
    pub installed: bool,
    /// 目标 `/32` 行已存在（非本次安装；verify 路径）。
    pub preexisting: bool,
    /// 已存在行的网关/LUID 与物理网卡不一致（typed route conflict；不覆盖第三方）。
    pub conflict: bool,
}

/// 在物理网卡上 verify-or-add `<real_ip>/32 → 网关` 直连路由（`CreateIpForwardEntry2`；
/// `ERROR_OBJECT_ALREADY_EXISTS` 5010 容忍并重读采纳）。
///
/// 已存在且网关/LUID 与物理网卡一致 → 采纳实测行（`preexisting=true`）；
/// 已存在但网关/LUID 不一致 → `conflict=true`（不安装、不覆盖第三方修改）。
///
/// # Errors
///
/// 发现/安装失败（`nics` 为空 → 1168；`CreateIpForwardEntry2` 其他失败）→
/// [`NativeError`]。
pub fn ensure_gateway_route(real_ip: Ipv4Addr, nics: &[NicInfo]) -> Result<EnsureRouteOutcome, NativeError> {
    let nic = nics.first().ok_or_else(|| {
        NativeError::from_win32(ERROR_NOT_FOUND, "no-physical-nic")
    })?;
    let existing = find_route_for_dest(real_ip)?;
    if let Some(row) = existing {
        if row.next_hop == nic.gateway && row.interface_luid == nic.luid {
            return Ok(EnsureRouteOutcome {
                row,
                installed: true,
                preexisting: true,
                conflict: false,
            });
        }
        return Ok(EnsureRouteOutcome {
            row,
            installed: true,
            preexisting: true,
            conflict: true,
        });
    }
    let desired = RouteRow::new(real_ip, GATEWAY_ROUTE_PREFIX, nic.gateway, nic.luid, GATEWAY_ROUTE_METRIC);
    match exv_vpn_win32_resource::routes::install(&desired) {
        Ok(()) => Ok(EnsureRouteOutcome {
            row: desired,
            installed: true,
            preexisting: false,
            conflict: false,
        }),
        Err(e) if e.code == ERROR_OBJECT_ALREADY_EXISTS => {
            // 5010：并发/已存在——重读采纳（绝不覆盖）。
            match find_route_for_dest(real_ip)? {
                Some(row) => {
                    let conflict =
                        row.next_hop != nic.gateway || row.interface_luid != nic.luid;
                    Ok(EnsureRouteOutcome {
                        row,
                        installed: true,
                        preexisting: true,
                        conflict,
                    })
                }
                None => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// 移除 `/32` 直连路由（`GetIpForwardEntry2` 填满行全字段比对 → `DeleteIpForwardEntry2`；
/// AlreadyAbsent 幂等——routes.rs `remove` 原语）。
///
/// # Errors
///
/// 填满行与请求行不一致（拒绝删除）/ Get/Delete 失败 → [`NativeError`]。
pub fn remove_gateway_route(row: &RouteRow) -> Result<RemoveOutcome, NativeError> {
    exv_vpn_win32_resource::routes::remove(row)
}

/// 移除回读证明：目标 `/32` 行已不在路由表。
///
/// # Errors
///
/// `GetIpForwardTable2` 失败 → [`NativeError`]。
pub fn gateway_route_absent(dest: Ipv4Addr) -> Result<bool, NativeError> {
    Ok(find_route_for_dest(dest)?.is_none())
}

/// 全系统 IPv4 路由表快照（`route print -4` 语义；`GetIpForwardTable2` 全表逐行
/// 格式化为 `net/prefix via next-hop metric ifindex` 行）。供隧道路由期间的
/// 存活证据（校园路由在系统路由表实锤；非仅证据记录）。
///
/// # Errors
///
/// `GetIpForwardTable2` 失败 → [`NativeError`]。
pub fn snapshot_ipv4_routes() -> Result<Vec<String>, NativeError> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: table 由系统分配；用毕必须 FreeMibTable（find_route_for_dest 同款路径）。
    let rc = unsafe { GetIpForwardTable2(AF_INET, &raw mut table) }.0;
    if rc != 0 {
        return Err(NativeError::from_win32(rc, "GetIpForwardTable2 失败"));
    }
    if table.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: table 由系统填充；NumEntries 界内访问（显式 from_raw_parts）。
    let table_ref = unsafe { &*table };
    let rows = unsafe { std::slice::from_raw_parts(table_ref.Table.as_ptr(), table_ref.NumEntries as usize) };
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        if let Some(row) = route_row_from_api(r) {
            out.push(format!(
                "{}/{} via {} metric {} if={}",
                row.network, row.prefix_len, row.next_hop, row.metric, row.interface_luid
            ));
        }
    }
    out.sort();
    // SAFETY: 释放系统分配的表。
    unsafe { FreeMibTable(table.cast()) };
    Ok(out)
}

// ---------------------------------------------------------------------------
// 机制测试：同步 shim（IP 字面量路径，无需网络）+ 路由幂等原语 + live 解析。
// DNS 双线机制测试已随实现提升进 `exv-vpn-win32-resource::vgdc_dns`。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用目标（TEST-NET-1：本宿主不可能有该路由）。
    const TEST_NET_DEST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 55);

    // ---- 同步 shim（IP 字面量路径；无需网络/假服务器） ----

    #[test]
    fn sync_shim_ip_literal_uses_system_source() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let production = DualLineConfig::production(None).expect("production config");
        let cfg = DualLineConfig {
            doh_endpoints: Vec::new(),
            doh_client_config: production.doh_client_config,
            udp53_resolvers: Vec::new(),
            udp53_ifindex: None,
        };
        let (ip, src) =
            resolve_gateway_dual_line(&cfg, &rt, "222.66.117.109").expect("IP 字面量直接采用");
        assert_eq!(ip, Ipv4Addr::new(222, 66, 117, 109));
        assert_eq!(src, ResolutionSource::System);
    }

    // ---- 路由生命周期原语（非 elevated；幂等/拒绝路径） ----

    #[test]
    fn remove_absent_gateway_route_is_idempotent() {
        let row = RouteRow::new(TEST_NET_DEST, GATEWAY_ROUTE_PREFIX, Ipv4Addr::new(192, 168, 31, 1), 0x1234, GATEWAY_ROUTE_METRIC);
        let outcome = remove_gateway_route(&row).expect("absent 行移除必须幂等成功");
        assert_eq!(outcome, RemoveOutcome::AlreadyAbsent);
    }

    #[test]
    fn dest_only_key_removal_is_rejected() {
        let row = RouteRow::dest_only(TEST_NET_DEST, GATEWAY_ROUTE_PREFIX);
        let err = remove_gateway_route(&row).expect_err("dest-only 通配 key 不是合法删除输入");
        assert_eq!(err.code, 87, "按 CIDR 删除是 mutant（facts §3）");
    }

    #[test]
    fn find_route_for_absent_dest_returns_none() {
        assert_eq!(find_route_for_dest(TEST_NET_DEST).expect("表扫描必须成功"), None);
        assert!(gateway_route_absent(TEST_NET_DEST).expect("回读必须成功"));
    }

    // ---- live 解析（本宿主；`--ignored` 门控：Mihomo 运行中，双线解析真实网关）。 ----

    /// 真机 live 解析：在 Mihomo TUN + fake-ip 运行中，双线解析 `vpn-ct.ecnu.edu.cn`
    /// 必须返回真实 IP 222.66.117.109（非 fake 198.18.1.15），来源 doh。
    #[test]
    #[ignore = "live network verification on the W30 host (Mihomo running)"]
    fn live_resolve_vpn_gateway() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let cfg = DualLineConfig::production(None).expect("production config");
        match resolve_gateway_dual_line(&cfg, &rt, "vpn-ct.ecnu.edu.cn") {
            Ok((ip, src)) => {
                println!("LIVE_RESOLVE: ip={ip} source={}", src.as_str());
                assert_eq!(ip, Ipv4Addr::new(222, 66, 117, 109));
                assert_eq!(src.as_str(), "doh");
            }
            Err(errors) => {
                let detail: Vec<String> = errors.iter().map(ResolveLayerError::describe).collect();
                panic!("LIVE_RESOLVE failed: {}", detail.join("; "));
            }
        }
    }

    /// 真机物理网卡发现：打印候选物理网卡（`/32` 路由与 UDP/53 绑网卡的事实基础）。
    #[test]
    #[ignore = "live network verification on the W30 host"]
    fn live_find_physical_nics() {
        let nics = find_physical_nics().expect("物理网卡发现必须成功");
        assert!(!nics.is_empty(), "宿主必须至少有一个物理网卡");
        for n in &nics {
            println!(
                "LIVE_NIC: name={} luid={} ifindex={} gateway={} local_ip={} metric={}",
                n.friendly_name, n.luid, n.ifindex, n.gateway, n.local_ip, n.ipv4_metric
            );
        }
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// 规格：docs/superpowers/specs/2026-08-15-vpn-gateway-direct-connect-guarantee.md；cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
