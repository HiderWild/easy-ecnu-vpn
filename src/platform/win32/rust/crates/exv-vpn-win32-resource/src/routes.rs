// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! IPv4 route install / read-back / remove and plan construction (W20-I).
//!
//! Frozen facts (`docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md`
//! §3, WSP4 elevated measurements): a route row must be `InitializeIpForwardEntry` +
//! explicit `SitePrefixLength=0` + network-byte-order `S_addr` (a host-order write
//! leaves host bits in the prefix and `CreateIpForwardEntry2` returns 87); read-back
//! rows carry `protocol=3` (`MIB_IPPROTO_NETMGMT`) and the set metric; deleting by a
//! dest-only key is a mutant — delete must first `GetIpForwardEntry2` the exact row,
//! compare the filled row, and treat an already-absent row as `Ok(AlreadyAbsent)`;
//! cleanup runs in reverse install order.

use std::net::Ipv4Addr;

use windows::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardEntry2,
    GetIpForwardTable2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{AF_INET, MIB_IPPROTO_NETMGMT, NlroManual, SOCKADDR_INET};

use crate::native_error::NativeError;

/// IPv4 前缀长度上限（facts §3：前缀 33 -> `CreateIpForwardEntry2` 返回 87）。
const MAX_PREFIX_LEN: u8 = 32;
/// `ERROR_NOT_FOUND`（facts §3：已 absent 的路由是合法状态，Get 返回 1168）。
const ERROR_NOT_FOUND: u32 = 1168;
/// `ERROR_INVALID_PARAMETER`（facts §3：非法前缀 / 非法删除输入 -> 87）。
const ERROR_INVALID_PARAMETER: u32 = 87;

/// 一条精确的 IPv4 路由行，与 WSP4 回读行一一对应。
///
/// 行相等是**全字段**相等（facts §3 / W20-T 契约：只按 CIDR 判等会漏删错行——
/// 'delete by CIDR' mutant 在此死）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRow {
    /// 网络地址（`new`/`dest_only` 已屏蔽主机位）。
    pub network: Ipv4Addr,
    /// 前缀长度（0..=32；>32 的非法行由安装路径以 87 拒绝）。
    pub prefix_len: u8,
    /// 下一跳地址。
    pub next_hop: Ipv4Addr,
    /// 接口 LUID（`NET_LUID_LH.Value`）。
    pub interface_luid: u64,
    /// 路由度量。
    pub metric: u32,
    /// 路由协议（安装行固定为 3 = `MIB_IPPROTO_NETMGMT`，facts §3 回读冻结值）。
    pub protocol: u32,
}

impl RouteRow {
    /// 从字段构造精确行。
    ///
    /// 规范化：`prefix_len <= 32` 时屏蔽主机位（前缀含主机位会让
    /// `CreateIpForwardEntry2` 返回 87——WSP4 字节序陷阱的宿主位化身，mutant 在此死）；
    /// `protocol` 固定为 3（`MIB_IPPROTO_NETMGMT`，facts §3 回读冻结值）。
    #[must_use]
    pub fn new(
        network: Ipv4Addr,
        prefix_len: u8,
        next_hop: Ipv4Addr,
        interface_luid: u64,
        metric: u32,
    ) -> Self {
        Self {
            network: masked_network(network, prefix_len),
            prefix_len,
            next_hop,
            interface_luid,
            metric,
            protocol: u32::try_from(MIB_IPPROTO_NETMGMT.0).unwrap_or(0),
        }
    }

    /// 构造 dest-only 通配 key（facts §3 冻结：`next_hop` 为 `0.0.0.0`，`interface_luid`、
    /// `metric`、`protocol` 均为 0）。
    ///
    /// `GetIpForwardEntry2` 对这类 key 按通配匹配并填满行；它**不是**精确行（与
    /// 精确行只共享 CIDR 身份），也**不是**合法删除输入——按 CIDR 删除是 mutant。
    #[must_use]
    pub fn dest_only(network: Ipv4Addr, prefix_len: u8) -> Self {
        Self {
            network: masked_network(network, prefix_len),
            prefix_len,
            next_hop: Ipv4Addr::UNSPECIFIED,
            interface_luid: 0,
            metric: 0,
            protocol: 0,
        }
    }

    /// 本行的 CIDR 身份 `(network, prefix_len)`——供查找的谓词，不是行身份。
    #[must_use]
    pub const fn dest_key(&self) -> RouteKey {
        RouteKey {
            network: self.network,
            prefix_len: self.prefix_len,
        }
    }
}

/// 路由行的 CIDR 身份：`(network, prefix_len)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RouteKey {
    /// 网络地址。
    pub network: Ipv4Addr,
    /// 前缀长度。
    pub prefix_len: u8,
}

/// `remove` 的结果；已 absent 是合法、幂等的状态（facts §3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveOutcome {
    /// 精确行找到并被删除。
    Removed,
    /// 不存在该路由，无需处理（facts §3：already-absent 是合法状态，不是错误）。
    AlreadyAbsent,
}

/// 捕获 `interface_luid` 上的全部 IPv4 路由行（read-back 证明：API 成功不是证明，
/// 由调用方对捕获行断言）。
///
/// # Errors
///
/// `GetIpForwardTable2` 失败时返回 [`NativeError`]。
pub fn capture_rows(interface_luid: u64) -> Result<Vec<RouteRow>, NativeError> {
    let _t = crate::timing::Timed::new("resource.routes.capture_rows");
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: table 由系统分配；用毕必须 FreeMibTable（facts §3 同款读表路径）。
    let rc = unsafe { GetIpForwardTable2(AF_INET, &raw mut table) }.0;
    if rc != 0 {
        return Err(NativeError::from_win32(rc, "GetIpForwardTable2 失败"));
    }
    if table.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: table 由系统填充；NumEntries 界内访问（显式 from_raw_parts）。
    let table_ref = unsafe { &*table };
    let rows = unsafe {
        std::slice::from_raw_parts(table_ref.Table.as_ptr(), table_ref.NumEntries as usize)
    };
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        // SAFETY: 读 union 成员 InterfaceLuid.Value。
        if unsafe { r.InterfaceLuid.Value } != interface_luid {
            continue;
        }
        if let Some(row) = from_api_row(r) {
            out.push(row);
        }
    }
    // SAFETY: 释放系统分配的表。
    unsafe { FreeMibTable(table.cast()) };
    Ok(out)
}

/// 安装一条精确路由行（`CreateIpForwardEntry2`：Initialize + 显式
/// `SitePrefixLength=0` + 网络字节序前缀 + `MIB_IPPROTO_NETMGMT`，facts §3）。
///
/// 重复安装同一精确行失败并携带 5010（`ERROR_OBJECT_ALREADY_EXISTS`）。
///
/// # Errors
///
/// 行非法（前缀 > 32 -> 87）或 `CreateIpForwardEntry2` 失败（如重复精确行 -> 5010）
/// 时返回 [`NativeError`]。
pub fn install(row: &RouteRow) -> Result<(), NativeError> {
    let _t = crate::timing::Timed::new("resource.routes.install");
    if row.prefix_len > MAX_PREFIX_LEN {
        return Err(NativeError::from_win32(
            ERROR_INVALID_PARAMETER,
            "install: 非法前缀（IPv4 前缀上限 32）",
        ));
    }
    let api_row = to_api_row(row);
    // SAFETY: api_row 已完整构造（Initialize + 全部关键字段）；失败由 rc 表达。
    let rc = unsafe { CreateIpForwardEntry2(&raw const api_row) }.0;
    if rc != 0 {
        return Err(NativeError::from_win32(
            rc,
            "CreateIpForwardEntry2 失败（重复精确行 -> 5010）",
        ));
    }
    Ok(())
}

/// 删除一条精确路由行。
///
/// 删除前先用 `GetIpForwardEntry2` 取精确行（facts §3：dest-only 直接 Delete 返回
/// 2——'delete by CIDR' mutant 在此死）；通配填满的行必须与请求行全字段一致，
/// 不一致 -> Err 且绝不删除。已 absent -> `Ok(RemoveOutcome::AlreadyAbsent)`（幂等）。
///
/// # Errors
///
/// dest-only 通配 key 输入、填满行与请求行不一致、或 Get/Delete 失败时返回
/// [`NativeError`]。
pub fn remove(row: &RouteRow) -> Result<RemoveOutcome, NativeError> {
    let _t = crate::timing::Timed::new("resource.routes.remove");
    // dest-only 通配 key（nexthop/luid 为零）不是合法删除输入：拒绝，绝不静默成功。
    if row.next_hop == Ipv4Addr::UNSPECIFIED && row.interface_luid == 0 {
        return Err(NativeError::from_win32(
            ERROR_INVALID_PARAMETER,
            "remove: dest-only key 不是合法删除输入（facts §3：按 CIDR 删除是 mutant）",
        ));
    }
    let mut api_row = to_api_row(row);
    // SAFETY: api_row 携带请求行的完整 key；Get 成功时按通配/精确匹配填满行
    // （facts §3：dest-only 通配填满、完整 key 精确命中）。
    let rc_get = unsafe { GetIpForwardEntry2(&raw mut api_row) }.0;
    if rc_get == ERROR_NOT_FOUND {
        // 已 absent：合法状态，幂等（facts §3）。
        return Ok(RemoveOutcome::AlreadyAbsent);
    }
    if rc_get != 0 {
        return Err(NativeError::from_win32(rc_get, "GetIpForwardEntry2 失败"));
    }
    // 通配填满的行必须与请求行全字段一致；不一致 -> Err，不得删除。
    let filled = from_api_row(&api_row).ok_or_else(|| {
        NativeError::from_win32(ERROR_NOT_FOUND, "remove: 填满的行不是 IPv4 行，拒绝删除")
    })?;
    if &filled != row {
        return Err(NativeError::from_win32(
            ERROR_INVALID_PARAMETER,
            "remove: GetIpForwardEntry2 填满的行与请求行不一致，拒绝删除",
        ));
    }
    // SAFETY: 行已填满精确行（facts §3 的正确路径 Get -> Delete）。
    let rc_del = unsafe { DeleteIpForwardEntry2(&raw const api_row) }.0;
    if rc_del != 0 {
        return Err(NativeError::from_win32(rc_del, "DeleteIpForwardEntry2 失败"));
    }
    Ok(RemoveOutcome::Removed)
}

/// 批量安装路由行，失败时整批不留半状态（'partial failure' mutant 在此死）。
///
/// 先预验证全部行（任一非法行 -> 整批 87，且不安装任何行）；随后逐行安装，任一
/// 安装失败时按**逆序**回滚已安装的行（cleanup 逆序语义）再返回错误。
///
/// # Errors
///
/// 首个失败行的 [`NativeError`]（非法前缀 -> 87；重复精确行 -> 5010）。
pub fn install_plan(rows: &[RouteRow]) -> Result<(), NativeError> {
    let _t = crate::timing::Timed::new("resource.routes.install_plan");
    // 预验证：任一非法行 -> 整批 87，不安装任何行（无半状态）。
    if rows.iter().any(|r| r.prefix_len > MAX_PREFIX_LEN) {
        return Err(NativeError::from_win32(
            ERROR_INVALID_PARAMETER,
            "install_plan: 非法前缀（IPv4 前缀上限 32）",
        ));
    }
    let mut installed: Vec<&RouteRow> = Vec::with_capacity(rows.len());
    for row in rows {
        if let Err(e) = install(row) {
            // 回滚：已安装的行逆序删除（best-effort），不留半状态。
            for done in installed.iter().rev().copied() {
                let _ = remove(done);
            }
            return Err(e);
        }
        installed.push(row);
    }
    Ok(())
}

/// 构建安装计划：bypass 行永远排在全部隧道路由**之前**（先 bypass 再 tunnel，
/// 否则控制流量会被隧道路由劫持——'bypass after default route' mutant 在此死）。
/// 无 bypass 时计划就是隧道路由本身。
#[must_use]
pub fn build_install_plan(bypass: Option<&RouteRow>, tunnel: &[RouteRow]) -> Vec<RouteRow> {
    let mut plan = Vec::with_capacity(tunnel.len() + usize::from(bypass.is_some()));
    if let Some(b) = bypass {
        plan.push(b.clone());
    }
    plan.extend_from_slice(tunnel);
    plan
}

/// 构建清理计划：安装顺序的**逆序**（最后安装的先删除——'cleanup in forward
/// order' mutant 在此死）。行保持精确身份（全字段行，不按 CIDR 重新配对）。
#[must_use]
pub fn build_cleanup_order(installed: &[RouteRow]) -> Vec<RouteRow> {
    installed.iter().rev().cloned().collect()
}

/// IPv4 `SOCKADDR_INET`（`S_addr` 用 `from_le_bytes`：内存中按网络字节序存储，
/// facts §3 实测修正；用 `from_be_bytes` 会把 10.99.99.0 写成 0.99.99.10）。
#[must_use]
pub(crate) fn to_sockaddr(ip: Ipv4Addr) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    // edition 2024：局部变量上的 union Copy 字段写是安全操作（WSP4 spike 同款）。
    sa.Ipv4.sin_family = AF_INET;
    sa.Ipv4.sin_addr.S_un.S_addr = u32::from_le_bytes(ip.octets());
    sa
}

/// 把系统 `MIB_IPFORWARD_ROW2` 转为 `RouteRow`（非 IPv4 行返回 None——无法表达）。
/// 供本模块及 `bypass_route`（`GetBestRoute2` 输出）共用。
#[must_use]
pub(crate) fn from_api_row(api: &MIB_IPFORWARD_ROW2) -> Option<RouteRow> {
    let network = ipv4_of(&api.DestinationPrefix.Prefix)?;
    let next_hop = ipv4_of(&api.NextHop)?;
    // SAFETY: 读 union 成员 InterfaceLuid.Value。
    let interface_luid = unsafe { api.InterfaceLuid.Value };
    Some(RouteRow {
        network,
        prefix_len: api.DestinationPrefix.PrefixLength,
        next_hop,
        interface_luid,
        metric: api.Metric,
        protocol: u32::try_from(api.Protocol.0).unwrap_or(0),
    })
}

/// 屏蔽主机位；前缀 > 32 的行保持原样（非法行由安装路径以 87 拒绝）。
#[must_use]
fn masked_network(network: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let mask = match prefix_len {
        0 => 0,
        1..=32 => u32::MAX << (32 - prefix_len),
        _ => u32::MAX,
    };
    Ipv4Addr::from(u32::from(network) & mask)
}

/// 构造 `CreateIpForwardEntry2` 用的精确行（WSP4 实测成功变体 `init+full`：
/// Initialize + dest/next-hop/luid/metric/lifetime + 显式 `SitePrefixLength=0` +
/// `MIB_IPPROTO_NETMGMT`；直接 default 的行带 SitePrefixLength=255 等哨兵会让
/// Create 返回 87）。
#[must_use]
fn to_api_row(row: &RouteRow) -> MIB_IPFORWARD_ROW2 {
    let mut api = MIB_IPFORWARD_ROW2::default();
    // SAFETY: Initialize 把行初始化为合法基线（facts §3 实测修正）。
    unsafe { InitializeIpForwardEntry(&raw mut api) };
    api.DestinationPrefix.Prefix = to_sockaddr(row.network);
    api.DestinationPrefix.PrefixLength = row.prefix_len;
    api.NextHop = to_sockaddr(row.next_hop);
    api.InterfaceLuid = NET_LUID_LH { Value: row.interface_luid };
    api.Metric = row.metric;
    api.Protocol = MIB_IPPROTO_NETMGMT;
    api.SitePrefixLength = 0; // IPv4 必须显式 0（facts §3 实测修正）
    api.ValidLifetime = u32::MAX;
    api.PreferredLifetime = u32::MAX;
    api.Origin = NlroManual;
    api
}

/// `SOCKADDR_INET` -> IPv4 地址（非 `AF_INET` 返回 None）。
#[must_use]
fn ipv4_of(sa: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    // SAFETY: si_family 是 union 的公共初始成员。
    if unsafe { sa.si_family } != AF_INET {
        return None;
    }
    // SAFETY: AF_INET 分支下 sin_addr 有效；S_addr 按网络字节序存于内存
    // （x86 LE：to_le_bytes 还原字节顺序，facts §3 实测修正）。
    let octets = unsafe { sa.Ipv4.sin_addr.S_un.S_addr }.to_le_bytes();
    Some(Ipv4Addr::from(octets))
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
