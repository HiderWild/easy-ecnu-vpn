// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! engine 侧特权初始化 + teardown（R1b 产品移植，S1.5 三 owner 拆分）。
//!
//! 本模块是 acceptance `scenarios/controlled::helper_apply` / `helper_stop` 的
//! **产品移植**——复用同一组 `exv-vpn-win32-resource` leaf seams（W18 地址 / W19
//! MTU / W20 路由+bypass / W21 DNS），不依赖 acceptance crate（test-only）。
//!
//! **R0 归因铁律（不得带回验收组装工件）**：
//! - `sleep_6s`（controlled.rs:2056）与 `sleep_8s`（:2088）是无条件 `thread::sleep`，
//!   纯验收组装工件——本移植**不带**；
//! - DAD 收敛轮询（:2094-2106，10s deadline）实测 DadState 恒 Tentative、纯烧
//!   budget——本移植**不带**（如需「路由可查」，R1c 用真实路由回读/短沉降替代）。
//! 移除三个等待后 apply ≈ 0.3s（R0 归因 §4）。
//!
//! **W24 路由残留根因修复（保留）**：路由安装后**回读生效行**（Windows 存有效
//! metric，实测 5 -> 10），restore 用回读行做全字段精确 remove——避免请求行全字段
//! 不匹配被 87 拒绝并静默容忍导致路由残留（W24 实测根因）。
//!
//! ## S1.5 三 owner 划界（D17 / D11）
//!
//! 本模块承载 **NIC owner**（adapter 句柄 + session 生命周期）与 **route owner**
//! （路由 + DNS + 地址族 apply，经 NIC 交出的 LUID 驱动）：
//!
//! - [`NicOwner::ensure`]：**首次连接**建 adapter（D12），存续复用；只做 adapter
//!   创建 + 接口级配置（DAD 禁用 / 接口启用）。断开**不拆**（D12）——adapter 由
//!   协调者持有到退出清理阶段才 close。
//! - [`NicOwner::apply_offer`]：在已 ensure 的 adapter 上按真实 CSTP offer 应用四族
//!   网络设置，返回 per-connection 的 [`RouteOwner`] + [`PlatformFacts`]。
//! - [`RouteOwner::clear`]：**减负断开**（D13）清理——逆序移除地址 / 路由 / MTU /
//!   DNS，**保留 adapter**（网卡以无地址惰性存续）。
//! - [`NicOwner`] Drop（adapter creator close）＝**退出清理**移除 adapter，连带四族
//!   配置——0 网卡残留兜底。
//!
//! DP-01 create-then-idle：本模块**不创建 Wintun session、不启动 ring worker**——数据
//! 面由 `crate::data_plane` 在 route 应用后接续（同一 adapter 上 `WintunSession::start`）。

use std::net::Ipv4Addr;
use std::path::Path;

use exv_vpn_cstp::session::TunnelOffer;
use exv_vpn_win32_resource::dns::{DnsApplier, DnsCapture};
use exv_vpn_win32_resource::dns_types::{DnsFingerprint, DnsSettings};
use exv_vpn_win32_resource::ip_address::{IpAddressController, plan_addresses, restore_owned_addresses};
use exv_vpn_win32_resource::ip_helper_types::IpAddressRow;
use exv_vpn_win32_resource::mtu::{MtuController, MtuFamily, MtuSnapshot};
use exv_vpn_win32_resource::routes::{self, RouteRow};
use exv_vpn_win32_resource::system_proxy::RawInternetSettings;
use exv_vpn_win32_resource::system_proxy_family::SystemProxyFamilyStep;
use exv_vpn_win32_resource::system_proxy_family_exec::{
    apply_system_proxy_with_pac, restore_system_proxy_step, SystemProxyApplyResult,
    SystemProxyRestoreOutcome,
};
use exv_vpn_win32_resource::wintun_adapter::WintunAdapter;
use exv_vpn_win32_resource::wintun_api::WintunLibrary;
use windows::core::GUID;
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToGuid, GetIfEntry, GetIpInterfaceEntry, InitializeIpInterfaceEntry,
    MIB_IFROW, MIB_IPINTERFACE_ROW, SetIfEntry, SetIpInterfaceEntry,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::AF_INET;

/// 隧道接口类型（与 acceptance `TUNNEL_TYPE` 冻结一致）。
const TUNNEL_TYPE: &str = "EXV VPN";
/// 隧道路由安装 metric（与 acceptance 一致，WSP4 实测自动 metric 化）。
const ROUTE_METRIC: u32 = 5;
/// 已存在路由的容忍码（`ERROR_OBJECT_ALREADY_EXISTS`，5010）。
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;

/// 解析一条路由目标字符串（C++ `parse_destination` 语义对齐）：
/// `"a.b.c.d"`（裸 IP）→ `/32` 主机路由；`"a.b.c.d/n"`（CIDR）→ `(ip, n)`。
/// 非法 IPv4 或 `n > 32` → `None`。
#[must_use]
fn parse_route_destination(route: &str) -> Option<(Ipv4Addr, u8)> {
    let (net, prefix) = match route.split_once('/') {
        Some((net, prefix)) => (net, prefix.parse::<u8>().ok()?),
        None => (route, 32),
    };
    let net: Ipv4Addr = net.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((net, prefix))
}

/// LUID → interface GUID（DNS API 键；WSP4 冻结转换）。resource 内 `luid_to_guid`
/// 是 `pub(crate)`，engine 侧复刻同一 5 行 Win32 调用（不 fork 语义）。
#[must_use]
fn luid_to_guid(luid: u64) -> Option<GUID> {
    let l = NET_LUID_LH { Value: luid };
    let mut guid = GUID::zeroed();
    // SAFETY: guid 由系统填充（ConvertInterfaceLuidToGuid 成功即有效 GUID）。
    if unsafe { ConvertInterfaceLuidToGuid(&raw const l, &raw mut guid) }.0 != 0 {
        return None;
    }
    Some(guid)
}

/// 禁用 IPv4 接口行的 DAD（`DadTransmits = 0`），使隧道地址立即进入 Preferred。
///
/// **R0 归因根因**（native-network-settings-facts / R0 §2.1）：Wintun 接口的 IPv4 地址
/// `DadState` 在 10s+ 内恒为 `Tentative`、从不收敛到 `Preferred`——Tentative 地址不能
/// 作源地址，业务流量（ping/SSH）无法发出。隧道适配器无重复地址风险，DAD 无意义且
/// 有害；标准解法是 `SetIpInterfaceEntry(DadTransmits=0)`（VPN 隧道接口通例）。
///
/// 在**地址 apply 之前**调用（DAD 参数是接口级配置，须先于地址创建生效）。接口级
/// 配置跨连接存续（S1.5：DAD 禁用随 adapter 建一次，重连不重复设）。
///
/// # Errors
///
/// `GetIpInterfaceEntry` / `SetIpInterfaceEntry` 失败 → `String`。
fn disable_ipv4_dad(luid: u64) -> Result<(), String> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: Initialize 写入行（文档模式：Family + InterfaceLuid + Get 填满）。
    unsafe { InitializeIpInterfaceEntry(std::ptr::addr_of_mut!(row)) };
    row.Family = AF_INET;
    // SAFETY: NET_LUID_LH 是 union；写成员是安全的。
    row.InterfaceLuid = NET_LUID_LH { Value: luid };
    // SAFETY: row 的 Family+Luid 有效；Get 填满行，返回 WIN32_ERROR（0 = 成功）。
    let rc = unsafe { GetIpInterfaceEntry(std::ptr::addr_of_mut!(row)).0 };
    if rc != 0 {
        return Err(format!("GetIpInterfaceEntry (dad): {rc}"));
    }
    // WSP4 冻结前提：Get 填充的 IPv4 行含 `SitePrefixLength=64`，直接 Set 会被 87 拒。
    row.SitePrefixLength = 0;
    row.DadTransmits = 0;
    // SAFETY: row 已 Get 填满 + 修正前提；Set 写回 DAD 参数（API 接受 *mut，读路径
    // 无并发写者，调用线程独占该行）。
    let rc = unsafe { SetIpInterfaceEntry(&raw mut row).0 };
    if rc != 0 {
        return Err(format!("SetIpInterfaceEntry (dad): {rc}"));
    }
    Ok(())
}

/// 接口启用（IpHelper `SetIfEntry`，生产 API——非 netsh；best-effort：顺序与
/// WSP3/W17 冻结路径一致：address → enable → route（路由安装前启用））。
fn enable_interface_best_effort(ifindex: u32) -> Result<(), String> {
    let mut row = MIB_IFROW {
        dwIndex: ifindex,
        ..Default::default()
    };
    // SAFETY: row 是有效输出参数；GetIfEntry 填充接口行。
    let rc = unsafe { GetIfEntry(&raw mut row) };
    if rc != 0 {
        return Err(format!("GetIfEntry failed: {rc}"));
    }
    row.dwAdminStatus = 1; // MIB_IF_ADMIN_STATUS_UP
    // SAFETY: row 已由 GetIfEntry 填充（身份字段一致），SetIfEntry 写回。
    let rc = unsafe { SetIfEntry(&raw const row) };
    if rc != 0 {
        return Err(format!("SetIfEntry failed: {rc}"));
    }
    Ok(())
}

/// 特权初始化后的 adapter/网络事实（供日志/证据；ApplyAccepted 不经此回包——R1w
/// pending 不携带事实）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlatformFacts {
    /// 已应用的接口地址 `address/prefix`。
    pub address_applied: Option<String>,
    /// 已应用的 MTU 值。
    pub mtu_applied: Option<u32>,
    /// 已应用的路由（隧道路由 + 校园路由，回读采纳）。
    pub routes_applied: Vec<String>,
    /// 已应用的 DNS 服务器。
    pub dns_applied: Vec<String>,
    /// adapter LUID。
    pub luid: u64,
    /// adapter 接口 index。
    pub ifindex: u32,
}

/// **NIC owner（D11/D17）**：创建者 adapter 句柄 + WintunLibrary + 名称，跨连接存续。
///
/// S1.5 生命周期（D12）：`NicOwner::ensure` **首次连接**建 adapter；断开**不拆**
/// （网卡以无地址惰性存续）；退出清理阶段由协调者 close（Drop = adapter creator
/// close 移除 adapter）。
///
/// **字段声明顺序即 Drop 顺序（W17 SAFETY-ORDER + 资源逆序）**：`adapter`（creator
/// close 移除 adapter）在 `_lib`（释放 DLL 加载）之后——`WintunAdapter::Drop` 用内嵌
/// close export 副本，不依赖 lib 存活；但 lib 保持 DLL 加载直到最后，保证 close 时
/// DLL 已加载。
pub struct NicOwner {
    /// 保持 Wintun DLL 加载（adapter close 依赖内嵌 export 副本；`_lib` 最后 drop）。
    _lib: WintunLibrary,
    /// 创建者 adapter 句柄（drop = creator close 移除 adapter）。
    adapter: WintunAdapter,
    /// adapter 名称（create 名；宿主按此名可观测）。
    adapter_name: String,
}

// SAFETY: `NicOwner` 持有 `WintunAdapter`（HANDLE + close export 副本）与
// `WintunLibrary`（HMODULE + exports 函数指针副本）——两者自身非 `Send`（原始
// HANDLE 指针）。`unsafe impl Send` 的论证镜像旧 `PlatformTunnel` 的既存 impl：
// 句柄值只经方法（`&self`/`&mut self`）访问、`Drop`（adapter creator close / lib
// free）恰好执行一次，且本类型恒处于协调者的 `Mutex` 串行访问下（
// `tunnel_runtime::RealTunnelRuntime.nic`）。移动句柄值跨线程安全——底层资源属
// 内核/系统，与线程无关。
unsafe impl Send for NicOwner {}

impl NicOwner {
    /// **首次连接建 adapter（D12）**：`WintunLibrary::load` + `WintunAdapter::create`
    /// + 接口级配置（DAD 禁用 + 接口启用，均跨连接存续）。重复调用由协调者保证
    /// 不触发（`nic` 已存在则复用）。
    ///
    /// # Errors
    ///
    /// lib 加载 / adapter 创建 / DAD 设置失败 → typed `String`。
    pub fn ensure(dll: &Path, adapter_name: &str) -> Result<Self, String> {
        let lib = WintunLibrary::load(dll).map_err(|e| format!("wintun-load:{e:?}"))?;
        let (adapter, _open) = WintunAdapter::create(&lib, adapter_name, TUNNEL_TYPE)
            .map_err(|e| format!("wintun-create:{e:?}"))?;
        let luid = adapter.luid();
        // 禁用 DAD（地址 apply 之前；R0 归因根因——Wintun IPv4 地址恒 Tentative）。
        // 接口级配置：建一次，跨连接存续。
        disable_ipv4_dad(luid)?;
        // 接口启用（在隧道路由安装之前——WSP3/W17 冻结顺序：address → enable → route）。
        let _ = enable_interface_best_effort(adapter.ifindex());
        Ok(Self {
            _lib: lib,
            adapter,
            adapter_name: adapter_name.to_string(),
        })
    }

    /// 接口 LUID（route owner 驱动 + 数据面接续用）。
    #[must_use]
    pub fn luid(&self) -> u64 {
        self.adapter.luid()
    }

    /// 接口 index（证据）。
    #[must_use]
    pub fn ifindex(&self) -> u32 {
        self.adapter.ifindex()
    }

    /// adapter 创建者句柄引用（`data_plane::EngineDataPlane::start` 直接在该句柄上
    /// `WintunSession::start`，不再 open-by-name）。
    #[must_use]
    pub fn adapter(&self) -> &WintunAdapter {
        &self.adapter
    }

    /// WintunLibrary 引用（`WintunSession::start` 需要）。
    #[must_use]
    pub fn library(&self) -> &WintunLibrary {
        &self._lib
    }

    /// adapter 名称（create 名；宿主按此名可观测）。
    #[must_use]
    pub fn adapter_name(&self) -> &str {
        &self.adapter_name
    }

    /// 在已 ensure 的 adapter 上应用一次连接的 offer（地址/DNS/路由，经 LUID 驱动）
    /// ——**route owner** 的 per-connection 状态生产。
    ///
    /// `offer` 是**真实 CSTP 协商**的隧道计划；`campus_routes` 是 config 驱动的校园
    /// 路由。返回 [`RouteOwner`]（per-connection 应用态；`clear` 供减负断开清理）+
    /// [`PlatformFacts`]（日志/证据）。
    ///
    /// # Errors
    ///
    /// 任一 leaf 失败 → typed `String`；[`RouteOwner::apply`] 内部 all-or-nothing
    /// 回滚（已生效族逆序恢复，不留半状态）。
    /// 应用真实 CSTP offer 的四族网络状态 + **系统代理豁免族**（设计 §5.3）。
    ///
    /// `core_user_sid` 为发起连接的用户 SID：`Some` 时 RouteOwner 额外执行
    /// 系统代理 family（豁免条目由校园路由派生，写入该用户 HKU 的 ProxyOverride）；
    /// `None`（engine 未知发起用户）→ 跳过该族（fail-closed 不猜测写谁）。
    ///
    /// # Errors
    ///
    /// 任一 leaf 失败 → typed `String`；[`RouteOwner::apply`] 内部 all-or-nothing
    /// 回滚（已生效族逆序恢复，不留半状态）。
    pub fn apply_offer(
        &self,
        offer: &TunnelOffer,
        campus_routes: &[String],
        core_user_sid: Option<String>,
    ) -> Result<(RouteOwner, PlatformFacts), String> {
        // 接口启用（路由安装前；WSP3 顺序 address → enable → route）。接口级配置
        // 在 ensure 时已启用，但地址 apply 后再次启用是既有 W17 路径，保持幂等。
        let _ = enable_interface_best_effort(self.adapter.ifindex());
        RouteOwner::apply(
            self.luid(),
            self.adapter.ifindex(),
            offer,
            campus_routes,
            core_user_sid,
        )
    }
}

/// **Route owner（D11/D17）**：per-connection 已应用的四族网络状态（地址/MTU/路由/
/// DNS），经 NIC 交出的 LUID 驱动。
///
/// 生命周期：每次连接经 [`RouteOwner::apply`] 创建；**减负断开**（D13）经
/// [`RouteOwner::clear`] 逆序清理（保留 adapter）；退出清理随协调者丢弃（Drop 不
/// 额外动作——地址/路由已由 clear 移除，adapter 由 NicOwner close）。
pub struct RouteOwner {
    /// 目标 LUID（地址/路由控制器键）。
    luid: u64,
    /// 本 apply 创建的地址行（clear 精确删除；pre-existing 永不 owned）。
    owned_addresses: Vec<IpAddressRow>,
    /// 已安装路由的**回读生效行**（clear 逆序精确 remove；W24 根因修复）。
    installed_routes: Vec<RouteRow>,
    /// MTU `(applied, original)`（clear 输入；V4 族）。
    mtu_applied: Option<MtuSnapshot>,
    mtu_original: Option<MtuSnapshot>,
    /// DNS applied fingerprint + 原始快照（GUID-keyed）。
    dns_fingerprint: DnsFingerprint,
    dns_original: DnsSettings,
    dns_guid: GUID,
    /// 系统代理豁免族已生效状态（设计 §5.3；`None` = 未生效——SID 缺失 /
    /// 无系统代理 / PAC detected skip）。
    system_proxy: Option<SystemProxyApplied>,
}

/// 系统代理豁免族已应用状态（clear 的 compare-and-restore 输入）。
struct SystemProxyApplied {
    /// 发起用户 SID（还原写回同一用户的 HKU）。
    sid: String,
    /// 连接前五值 prestate（精确还原依据）。
    prestate: RawInternetSettings,
    /// 写入后指纹基准（compare 输入）。
    written_fingerprint: Vec<u8>,
    /// PAC 开环包装的 loopback 端点（`Some` = Automatic 模式已改指 AutoConfigURL；
    /// teardown 还原注册表后 drop 关闭，遵循 §5.6 零扰动顺序）。
    pac_endpoint: Option<exv_vpn_win32_resource::system_proxy_pac::PacEndpoint>,
}

impl RouteOwner {
    /// 四族 leaf apply（address → MTU → 隧道路由 + 校园路由 → DNS，admission-first）。
    ///
    /// **all-or-nothing（D16）**：任一 leaf 失败 → 内部逆序回滚已生效族（DNS → 路由 →
    /// MTU → 地址），返回 `Err` 不带半状态。地址族 `plan_addresses` 只 apply 新增行
    /// （pre-existing 不 owned）；路由族安装后回读生效行（W24）。
    ///
    /// # Errors
    ///
    /// 任一 leaf 失败（admission-first 拒绝 / Win32 调用失败）→ typed `String`（已
    /// 回滚，无残留）。
    fn apply(
        luid: u64,
        ifindex: u32,
        offer: &TunnelOffer,
        campus_routes: &[String],
        core_user_sid: Option<String>,
    ) -> Result<(Self, PlatformFacts), String> {
        // ---- admission-first：plan 整体校验（W22 语义，零效果拒绝）。 ----
        let address: Ipv4Addr = offer.ipv4_address;
        let prefix: u8 = offer.prefix;
        if prefix > 32 {
            return Err("invalid prefix".to_string());
        }
        let mtu = u32::from(offer.mtu);
        for route in offer.routes.iter().chain(campus_routes.iter()) {
            parse_route_destination(route).ok_or("route shape")?;
        }
        for ns in &offer.dns_servers {
            let _: Ipv4Addr = *ns;
        }

        // 局部可回滚状态（失败逆序恢复）。
        let mut owned_addresses: Vec<IpAddressRow> = Vec::new();
        let mut installed_routes: Vec<RouteRow> = Vec::new();
        let mut mtu_state: Option<(MtuSnapshot, MtuSnapshot)> = None;
        let mut dns_state: Option<(DnsFingerprint, DnsSettings, GUID)> = None;
        let mut system_proxy_state: Option<SystemProxyApplied> = None;

        let apply = (|| -> Result<(), String> {
            // ---- address 族（W18 leaf：pre-existing 不 owned；owned 行记录供 clear）。 ----
            let controller = IpAddressController::new(luid);
            let captured_addr =
                controller.capture().map_err(|e| format!("addr-capture:{e:?}"))?;
            let addr_row = IpAddressRow::new(address, luid, prefix);
            let addr_plan = plan_addresses(&captured_addr, &[addr_row]);
            for row in &addr_plan.to_add {
                controller.apply(row).map_err(|e| format!("address-apply:{e:?}"))?;
            }
            owned_addresses = addr_plan.to_add.clone();

            // 接口启用（路由安装前；WSP3 顺序 address → enable → route）。
            let _ = enable_interface_best_effort(ifindex);

            // ---- MTU 族（W19 leaf：Set 前原始快照；clear 输入）。 ----
            let mtu_ctrl = MtuController::new(luid, MtuFamily::V4);
            let mtu_original = mtu_ctrl.capture().map_err(|e| format!("mtu-capture:{e:?}"))?;
            mtu_ctrl.apply(mtu).map_err(|e| format!("mtu-apply:{e:?}"))?;
            let mtu_applied = MtuSnapshot::new(luid, MtuFamily::V4, mtu);
            mtu_state = Some((mtu_applied, mtu_original));

            // ---- 隧道路由族 + 校园路由族（W20 leaf：精确行安装，回读生效行，逆序清理）。 ----
            for route in offer.routes.iter().chain(campus_routes.iter()) {
                let (net, prefix) = parse_route_destination(route).ok_or("route shape")?;
                let row = RouteRow::new(net, prefix, address, luid, ROUTE_METRIC);
                match routes::install(&row) {
                    Ok(()) => {}
                    // 校园路由可能已存在：回读采纳（不视为失败）。
                    Err(e) if e.code == ERROR_OBJECT_ALREADY_EXISTS => {}
                    Err(e) => return Err(format!("route-install:{e:?}")),
                }
                // 逆序清理必须按**回读生效行**记录：Windows 在表中存有效 metric
                // （请求 metric + 接口自动 metric，实测 5 -> 10）；用请求行做全字段精确
                // remove 会以 87 拒绝并被静默容忍，导致路由残留（W24 实测根因）。
                let actual = routes::capture_rows(luid)
                    .map_err(|e| format!("route-read-back:{e:?}"))?
                    .into_iter()
                    .find(|r| r.dest_key() == row.dest_key())
                    .ok_or_else(|| "route-read-back-missing".to_string())?;
                installed_routes.push(actual);
            }

            // ---- DNS 族（W21 leaf：applied fingerprint + 原始快照）。 ----
            let guid = luid_to_guid(luid).ok_or("luid-to-guid:failed")?;
            let dns_original = DnsCapture::capture(&guid).map_err(|e| format!("dns-capture:{e:?}"))?;
            let dns_settings = DnsSettings::new(
                offer.dns_servers.iter().map(ToString::to_string).collect(),
                Vec::new(),
            );
            let dns_fingerprint =
                DnsApplier::apply(&guid, &dns_settings).map_err(|e| format!("dns-apply:{e:?}"))?;
            dns_state = Some((dns_fingerprint, dns_original, guid));

            // ---- 系统代理豁免族（设计 §5.3；PAC 开环包装 v1 未接线，见
            //      EXV_PAC_FAMILY_PENDING）。豁免条目 = 校园路由按拍板规则派生
            //      （IP 精确直通 + /8-/16-/24 整段转通配）。best-effort：注册表
            //      失败只降级「未豁免」+ 日志，不使核心隧道失败（业务流优先——
            //      附加功能不得阻断连接）。
            if let Some(sid) = &core_user_sid {
                let desired: Vec<String> = campus_routes
                    .iter()
                    .filter_map(|r| {
                        exv_vpn_win32_resource::system_proxy_override::cidr_to_wildcard_opt(r)
                            .map(|e| e.as_str().to_owned())
                    })
                    .collect();
                match apply_system_proxy_with_pac(sid, &desired) {
                    Ok(SystemProxyApplyResult::Applied {
                        step,
                        written_fingerprint,
                    })
                    | Ok(SystemProxyApplyResult::Pac {
                        step,
                        written_fingerprint,
                        endpoint: None,
                    }) => {
                        system_proxy_state = Some(SystemProxyApplied {
                            sid: sid.clone(),
                            prestate: step.prestate,
                            written_fingerprint,
                            pac_endpoint: None,
                        });
                    }
                    Ok(SystemProxyApplyResult::Pac {
                        step,
                        written_fingerprint,
                        endpoint: Some(endpoint),
                    }) => {
                        system_proxy_state = Some(SystemProxyApplied {
                            sid: sid.clone(),
                            prestate: step.prestate,
                            written_fingerprint,
                            pac_endpoint: Some(endpoint),
                        });
                    }
                    Ok(SystemProxyApplyResult::SkippedNoProxy) => {}
                    Err(e) => {
                        tracing::warn!(?e, "system-proxy apply degraded (best-effort)");
                    }
                }
            }
            Ok(())
        })();

        if let Err(e) = apply {
            // all-or-nothing 回滚（D16）：逆序恢复已生效族（DNS → 路由 → MTU → 地址）。
            if let Some((fingerprint, original, guid)) = dns_state.take() {
                let _ = DnsApplier::restore(&guid, &fingerprint, &original);
            }
            for row in installed_routes.iter().rev() {
                match routes::remove(row) {
                    Ok(_) => {}
                    Err(remove_e) if remove_e.code == 87 => {}
                    Err(remove_e) => {
                        tracing::warn!(?remove_e, "route rollback remove failed");
                    }
                }
            }
            if let Some((applied, original)) = mtu_state.take() {
                let ctrl = MtuController::new(applied.luid, applied.family);
                let _ = ctrl.compare_and_restore(&applied, &original);
            }
            let controller = IpAddressController::new(luid);
            if let Ok(current) = controller.capture() {
                for row in restore_owned_addresses(&owned_addresses, &current) {
                    let _ = controller.delete(&row);
                }
            }
            return Err(e);
        }

        let mut routes_applied: Vec<String> = offer.routes.clone();
        routes_applied.extend_from_slice(campus_routes);
        let facts = PlatformFacts {
            address_applied: Some(format!("{address}/{prefix}")),
            mtu_applied: Some(mtu),
            routes_applied,
            dns_applied: offer.dns_servers.iter().map(ToString::to_string).collect(),
            luid,
            ifindex,
        };
        let (fingerprint, original, guid) = dns_state
            .expect("dns applied (apply ok)");
        Ok((
            Self {
                luid,
                owned_addresses,
                installed_routes,
                mtu_applied: mtu_state.as_ref().map(|(a, _)| a.clone()),
                mtu_original: mtu_state.as_ref().map(|(_, o)| o.clone()),
                dns_fingerprint: fingerprint,
                dns_original: original,
                dns_guid: guid,
                system_proxy: system_proxy_state,
            },
            facts,
        ))
    }

    /// **减负断开清理（D13）**：逆序 compare-and-restore + 移除地址，**保留 adapter**
    /// （网卡以无地址惰性存续，D12）。
    ///
    /// 顺序 = 逆序：DNS → 路由（逆序精确 remove）→ MTU → 地址（owned 行 compare-delete）。
    /// 第三方变更 typed skip（不覆盖）。
    ///
    /// # Errors
    ///
    /// 任一 leaf restore 硬失败 → typed `String`（绝不静默）；调用方应据错误决定兜底
    /// （adapter 保留，退出清理仍会 close）。
    pub fn clear(&mut self) -> Result<(), String> {
        // DNS 逆序。
        DnsApplier::restore(&self.dns_guid, &self.dns_fingerprint, &self.dns_original)
            .map_err(|e| format!("dns-restore:{e:?}"))?;
        // 系统代理族逆序（设计 §5.3：DNS 先撤、system_proxy 在路由/bypass 之前撤）。
        // compare-and-restore：第三方改动 typed skip（不覆盖）；硬失败传播。
        if let Some(applied) = self.system_proxy.take() {
            let sid = applied.sid.clone();
            let pac = applied.pac_endpoint.is_some();
            match restore_system_proxy_step(
                &sid,
                &SystemProxyFamilyStep {
                    prestate: applied.prestate,
                    desired_entries: Vec::new(),
                    originating_sid: applied.sid,
                    pac_detected: pac,
                },
                &applied.written_fingerprint,
            ) {
                Ok(SystemProxyRestoreOutcome::TypedSkip)
                | Ok(SystemProxyRestoreOutcome::Restored { .. }) => {}
                Err(e) => return Err(format!("system-proxy-restore:{e:?}")),
            }
            // §5.6 零扰动顺序：先还原注册表并广播，端点随后 drop 关闭（Drop 即关
            // listener；浏览器已缓存包装脚本，短期重取失败回退直连，属降级不断网）。
            drop(applied.pac_endpoint);
        }
        // 路由逆序（最后安装的先删）。
        for row in self.installed_routes.iter().rev() {
            match routes::remove(row) {
                Ok(_) => {}
                // Leaf 拒绝（填满行 != 请求行）：第三方修改——typed skip。
                Err(e) if e.code == 87 => {}
                Err(e) => return Err(format!("route-remove:{e:?}")),
            }
        }
        self.installed_routes.clear();
        // MTU 逆序（V4 族）。
        if let (Some(applied), Some(original)) = (&self.mtu_applied, &self.mtu_original) {
            let ctrl = MtuController::new(applied.luid, applied.family);
            ctrl.compare_and_restore(applied, original)
                .map_err(|e| format!("mtu-restore:{e:?}"))?;
        }
        // 地址：compare-delete owned 行。
        let ctrl = IpAddressController::new(self.luid);
        let current = ctrl.capture().map_err(|e| format!("addr-capture:{e:?}"))?;
        for row in restore_owned_addresses(&self.owned_addresses, &current) {
            ctrl.delete(&row).map_err(|e| format!("addr-delete:{e:?}"))?;
        }
        self.owned_addresses.clear();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 单元测试：纯逻辑（路由目标解析）。真实特权路径由集成/业务门禁覆盖。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 路由目标解析：裸 IP → /32；CIDR → (ip, n)；非法 → None。
    #[test]
    fn route_destination_parse_semantics() {
        assert_eq!(
            parse_route_destination("10.99.99.0/24"),
            Some((Ipv4Addr::new(10, 99, 99, 0), 24))
        );
        assert_eq!(
            parse_route_destination("219.228.60.69"),
            Some((Ipv4Addr::new(219, 228, 60, 69), 32))
        );
        assert_eq!(
            parse_route_destination("10.0.0.1/0"),
            Some((Ipv4Addr::new(10, 0, 0, 1), 0))
        );
        assert!(parse_route_destination("not-an-ip").is_none());
        assert!(parse_route_destination("10.0.0.1/33").is_none());
        assert!(parse_route_destination("10.0.0.1/").is_none());
        assert!(parse_route_destination("").is_none());
    }
}
