// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W22-T Terra: aggregate（Wintun adapter/session 与 address/MTU/bypass/routes/DNS 配置的
// **单一 owner**）契约。这些测试钉住 W22-I 在 exv_vpn_win32_resource::{aggregate,
// inventory, apply_tunnel} 实现的 seam。契约来源：
//   - 计划 W22 行：`aggregate.rs`：adapter/session/address/MTU/bypass/routes/DNS/packet/
//     running effects complete inventory 与 proof；生产文件 `aggregate.rs,inventory.rs,
//     apply_tunnel.rs`；killer mutant：omit one inventory item / split adapter/session
//     owner / effect before admission；
//   - 架构 §7.1（单一 logical aggregate owner）：每个活动平台 ownership 有一个 canonical
//     obligation inventory；proof inventory 从 durable canonical projection 派生，调用者
//     不能任意遗漏一项；**Windows 的 aggregate 必须同时拥有 Wintun adapter/config 与
//     packet session**，不再由两套 NativeWintun 分拆 ownership；
//   - WSP4 事实（native-network-settings-facts.md §3/§6，W20-W21 已冻结）：bypass 必须在
//     隧道路由**之前**捕获/安装（否则控制流量被隧道路由劫持）；cleanup 按安装顺序**逆序**；
//     compare-and-restore 必须先比较当前状态与 applied 指纹再恢复（无条件恢复旧快照 =
//     mutant）；MTU=1（低于 IPv4 最小 68）-> 87；重复精确行/地址 -> 5010。
//
// W22-I pinned seam（src/inventory.rs + src/apply_tunnel.rs + src/aggregate.rs；W22-I 必须
// 提供下列 exact 名称，否则本测试编译失败 = RED）：
//   inventory::InventoryItem { Adapter, Session, Address, Mtu, BypassRoute, Route, Dns,
//     PacketAttachment, RunningEffect }（Debug/Clone/Copy/PartialEq/Eq）
//     —— 9 项 canonical obligation（计划 W22 行逐字枚举：adapter/session/address/MTU/
//     bypass/routes/DNS/packet/running effects；缺一项 = mutant）
//   inventory::COMPLETE_INVENTORY: &[InventoryItem] —— 平台冻结的 9 项完整清单
//   inventory::is_complete(items: &[InventoryItem]) -> bool
//     —— 全部 9 项在列才算 complete；缺任一项必须 false
//   apply_tunnel::FamilyStep { Address, Mtu, Bypass, Routes, Dns }（Debug/Clone/Copy/PartialEq/Eq）
//   apply_tunnel::ApplyPlan {
//       pub steps: Vec<FamilyStep>,
//       pub addresses: Vec<IpAddressRow>,   // W18 类型（组合，不得重新实现）
//       pub mtu_v4: u32, pub mtu_v6: Option<u32>,
//       pub bypass: Vec<RouteRow>,          // W20 类型；bypass 族步骤必须先于 Routes 族
//       pub tunnel_routes: Vec<RouteRow>,   // W20 类型
//       pub dns: DnsSettings,               // W21 类型
//   }（Debug/Clone/PartialEq/Eq）
//   apply_tunnel::build_apply_plan(addresses, mtu_v4, mtu_v6, bypass, tunnel_routes, dns)
//     -> ApplyPlan —— 纯逻辑：steps 中 Bypass 族在 Routes 族**之前**
//   apply_tunnel::build_restore_plan(apply: &ApplyPlan) -> Vec<FamilyStep>
//     —— 纯逻辑：apply.steps 的**精确逆序**（最后应用的族先恢复；路由先删、bypass 最后删）
//   apply_tunnel::apply(aggregate: &mut Aggregate, plan: &ApplyPlan)
//     -> Result<(), NativeError>
//     —— admission 先于 effect：先完整验证/承认整个 plan（任一族非法，如 MTU=1 -> 87，
//     则 **零效果**，绝不半状态）；通过后才按 steps 顺序逐族 effect（委托 leaf seam）
//   apply_tunnel::restore(aggregate: &mut Aggregate) -> Result<(), NativeError>
//     —— 逆 family 顺序 compare-and-restore（委托 leaf seam 的 compare-and-restore；
//     第三方修改 -> typed 跳过，绝不覆盖）
//   aggregate::Aggregate —— 单一类型同时拥有 WintunAdapter 与 WintunSession
//     （split adapter/session owner = mutant）；Drop 必须 session 先 EndSession、
//     adapter 后 close（W17 语义，测试依赖 drop 自清理）
//     Aggregate::new(adapter: WintunAdapter, session: WintunSession) -> Self
//       —— 单个构造器同时接收两者（分拆 owner 无法满足此签名）
//     Aggregate::adapter(&self) -> &WintunAdapter；Aggregate::session(&self) -> &WintunSession
//     Aggregate::inventory(&self) -> &[InventoryItem] —— 存活期间必须 is_complete（9 项）
//     Aggregate::capture(&self) -> Result<TunnelSnapshot, NativeError>
//       —— 全族真实回读组合（任一族失败 -> Err，绝不返回缺项 partial 快照）
//   aggregate::TunnelSnapshot {
//       pub address_rows: Vec<IpAddressRow>,   // W18 类型（leaf 回读行）
//       pub mtu_v4: MtuSnapshot,               // W19 类型
//       pub mtu_v6: Option<MtuSnapshot>,       // W19 类型（V6 行存在时为 Some）
//       pub routes: Vec<RouteRow>,             // W20 类型（leaf 回读行，含 bypass）
//       pub dns: DnsSettings,                  // W21 类型
//   }（Debug/Clone/PartialEq/Eq）—— 字段类型就是已提交 leaf 的类型（组合而非重新实现；
//   W22-I 自己定义行/快照类型会让本测试编译失败）
//
// 纯逻辑测试（inventory 完整性 / apply-restore 计划顺序 / 快照组合）在任何宿主都必须
// 通过。真实跨族 mutation 测试在探针自建的 scratch Wintun adapter + session 上运行，
// 需要 admin；非 elevated 宿主上短路为 `not_run / blocked_by_environment`（明确输出，
// 不伪造假绿）。每个 mutation 测试以 Aggregate::new(adapter, session) 构造单一 owner，
// 结束（含 panic 早退）时 drop aggregate：session 先 EndSession、创建者 close 移除
// adapter 及其全部 IP/路由/DNS（W16 事实；W20-T 同款自清理语义），无残留。

use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::path::Path;

use exv_vpn_win32_resource::aggregate::{Aggregate, TunnelSnapshot};
use exv_vpn_win32_resource::apply_tunnel::{
    apply, build_apply_plan, build_restore_plan, restore, FamilyStep,
};
use exv_vpn_win32_resource::dns::DnsApplier;
use exv_vpn_win32_resource::dns_types::{DnsFingerprint, DnsSettings};
use exv_vpn_win32_resource::inventory::{is_complete, InventoryItem, COMPLETE_INVENTORY};
use exv_vpn_win32_resource::ip_address::{plan_addresses, IpAddressController};
use exv_vpn_win32_resource::ip_helper_types::{IpAddressPlan, IpAddressRow};
use exv_vpn_win32_resource::mtu::{MtuController, MtuFamily, MtuSnapshot};
use exv_vpn_win32_resource::native_error::NativeError;
use exv_vpn_win32_resource::routes::{install, RouteRow};
use exv_vpn_win32_resource::wintun_adapter::{AdapterOpen, WintunAdapter};
use exv_vpn_win32_resource::wintun_api::WintunLibrary;
use exv_vpn_win32_resource::wintun_session::WintunSession;

use windows::core::GUID;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToGuid;
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 冻结的 amd64 wintun-0.14.1 DLL 精确路径（WSP3/WSP4 冻结路径；PATH DLL 是 mutant）。
const FROZEN_DLL_PATH: &str = "C:\\Users\\TomLi\\.exv\\wintun\\wintun\\bin\\amd64\\wintun.dll";
/// WintunCreateAdapter 的 TunnelType 参数（WSP4 冻结值）。
const TUNNEL_TYPE: &str = "EXV VPN";
/// Wintun ring capacity 官方下限（wintun.h：min 0x20000；W17-T 同款）。
const RING_CAPACITY: u32 = 131072;
/// 测试网络常量（WSP3/WSP4 冻结，与 W18/W20/W21-T 完全一致）。
const PROBE_IP: Ipv4Addr = Ipv4Addr::new(10, 88, 88, 1);
const TUNNEL_NET: Ipv4Addr = Ipv4Addr::new(10, 99, 99, 0);
const TUNNEL_PREFIX: u8 = 24;
const TUNNEL_METRIC: u32 = 5;
/// MTU 应用值（WSP4 冻结：1420/1280/576/65535 可写）。
const MTU_APPLY: u32 = 1420;
/// 非法 MTU（低于 IPv4 最小 68 -> 87，W19 冻结）。
const MTU_INVALID: u32 = 1;
/// DNS 测试值（WSP4 冻结，W21-T 同款）。
const DNS_SERVER: &str = "10.88.88.53";
const DNS_SEARCH: &str = "exv.test";
/// `ERROR_INVALID_PARAMETER`（非法 MTU 的冻结拒绝码）。
const ERROR_INVALID_PARAMETER: u32 = 87;

/// 计划 W22 行逐字枚举的 9 项 canonical obligation。
const ALL_ITEMS: [InventoryItem; 9] = [
    InventoryItem::Adapter,
    InventoryItem::Session,
    InventoryItem::Address,
    InventoryItem::Mtu,
    InventoryItem::BypassRoute,
    InventoryItem::Route,
    InventoryItem::Dns,
    InventoryItem::PacketAttachment,
    InventoryItem::RunningEffect,
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 取 Err 并 panic 掉意外 Ok（不给 T 强加 Debug bound）。
fn expect_native_error<T>(r: Result<T, NativeError>, ctx: &str) -> NativeError {
    match r {
        Err(e) => e,
        Ok(_) => panic!("{ctx}: 必须返回 Err(NativeError)"),
    }
}

/// 取 Ok 并 panic 掉意外 Err（不给 T 强加 Debug bound）。
fn expect_ok<T>(r: Result<T, NativeError>, ctx: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{ctx}: 失败 {e:?}"),
    }
}

/// 当前进程是否 elevated（admin token）——模式与 W16-T / W17-T / W21-T 一致。
fn is_elevated() -> bool {
    // SAFETY: GetCurrentProcess 返回伪句柄，无需关闭。
    let proc_h = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    let ok = unsafe { OpenProcessToken(proc_h, TOKEN_QUERY, &mut token) };
    if ok.is_err() {
        return false;
    }
    let mut elevated = false;
    let mut size = 0u32;
    // SAFETY: 首次查询请求所需缓冲区大小（输出为 size）。
    unsafe {
        let _ = GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::null_mut()),
            0,
            &mut size,
        );
    }
    let mut buff = vec![0u8; size as usize];
    // SAFETY: buff 是有效缓冲；TokenElevation 返回 TOKEN_ELEVATION { TokenIsElevated: BOOL }。
    let ok2 = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(buff.as_mut_ptr().cast::<c_void>()),
            buff.len() as u32,
            &mut size,
        )
    };
    if ok2.is_ok() && buff.len() >= 4 {
        elevated = u32::from_ne_bytes(buff[0..4].try_into().unwrap_or([0u8; 4])) != 0;
    }
    // SAFETY: token 是本进程新打开句柄，使用后关闭。
    unsafe { let _ = CloseHandle(token); }
    elevated
}

/// 动态断言的前置：非 elevated 时输出显式 `not_run / blocked_by_environment` 并短路。
fn require_admin(test: &str) -> bool {
    if is_elevated() {
        return true;
    }
    eprintln!(
        "[not_run/blocked_by_environment] {test}: 创建 scratch adapter/session 并跨族 \
         mutation 需要提权（elevated admin token）；当前进程非 elevated，跳过动态断言"
    );
    false
}

/// 加载冻结 DLL 的便捷入口（W16/W17-T 同款；LoadLibraryW 引用计数安全）。
fn load_frozen() -> WintunLibrary {
    expect_ok(
        WintunLibrary::load(Path::new(FROZEN_DLL_PATH)),
        "load 冻结 wintun.dll",
    )
}

/// 唯一 adapter 名（按测试用途分前缀，pid 防并行/残留碰撞；W17-T 同款）。
fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", std::process::id())
}

/// 创建真实 adapter（创建者 owned；drop 即移除 adapter——W16 事实）。
fn create_adapter(lib: &WintunLibrary, prefix: &str) -> WintunAdapter {
    let name = unique_name(prefix);
    let (adapter, opened) =
        expect_ok(WintunAdapter::create(lib, &name, TUNNEL_TYPE), "create adapter");
    assert!(
        matches!(opened, AdapterOpen::Created),
        "create 必须返回 AdapterOpen::Created"
    );
    adapter
}

/// 在真实 adapter 上以冻结容量启动 session。
fn start_session(lib: &WintunLibrary, adapter: &WintunAdapter) -> WintunSession {
    expect_ok(
        WintunSession::start(lib, adapter, RING_CAPACITY),
        "start session",
    )
}

/// LUID -> 接口 GUID（DNS API 的键；WSP4 冻结：LUID → ConvertInterfaceLuidToGuid）。
fn luid_to_guid(luid: u64) -> Option<GUID> {
    let l = NET_LUID_LH { Value: luid };
    let mut guid = GUID::zeroed();
    // SAFETY: guid 由系统填充（ConvertInterfaceLuidToGuid 成功即有效 GUID）。
    if unsafe { ConvertInterfaceLuidToGuid(&l, &mut guid) }.0 != 0 {
        return None;
    }
    Some(guid)
}

// ---------------------------------------------------------------------------
// 纯逻辑契约（任何宿主都必须通过；不触碰系统状态）
// ---------------------------------------------------------------------------

/// canonical obligation inventory 必须恰好包含计划 W22 行逐字枚举的 9 项
/// （adapter/session/address/MTU/bypass/routes/DNS/packet/running effects）。
/// 杀死 'omit one inventory item'（canonical 清单缺项）。
#[test]
fn inventory_canonical_list_contains_all_nine_items() {
    assert_eq!(
        COMPLETE_INVENTORY.len(),
        9,
        "canonical obligation inventory 必须恰好 9 项（计划 W22 行枚举）"
    );
    assert!(
        is_complete(COMPLETE_INVENTORY),
        "canonical 清单自身必须 complete"
    );
    for item in ALL_ITEMS {
        assert!(
            COMPLETE_INVENTORY.contains(&item),
            "canonical 清单缺少 {item:?}（omit one inventory item mutant）"
        );
    }
}

/// 完整性判定必须逐项检查：9 项中缺任一项都必须判为 incomplete——proof 侧的
/// '调用者不能任意遗漏一项'（架构 §7.1）在计划层即被钉死。
/// 杀死 'omit one inventory item'（is_complete 漏检项）。
#[test]
fn inventory_completeness_rejects_any_omission() {
    for omitted in ALL_ITEMS {
        let mut partial: Vec<InventoryItem> = COMPLETE_INVENTORY.to_vec();
        partial.retain(|i| *i != omitted);
        assert!(
            !is_complete(&partial),
            "缺少 {omitted:?} 的清单必须判为 incomplete（omit one inventory item mutant）"
        );
    }
}

/// apply 计划（跨族顺序）：bypass 族步骤必须排在 routes 族步骤**之前**——bypass 先安装、
/// 隧道路由后安装，否则控制流量被隧道路由劫持（WSP4 §3 冻结；W20 单族语义的跨族推广）。
/// 杀死 'apply 顺序中 bypass 置于隧道路由之后'。
#[test]
fn apply_plan_orders_bypass_before_routes() {
    let bypass = RouteRow::new(
        Ipv4Addr::UNSPECIFIED,
        0,
        Ipv4Addr::new(198, 18, 0, 2),
        0xABC,
        0,
    );
    let t1 = RouteRow::new(TUNNEL_NET, TUNNEL_PREFIX, PROBE_IP, 0x7777, TUNNEL_METRIC);
    let t2 = RouteRow::new(
        Ipv4Addr::new(10, 88, 88, 0),
        24,
        PROBE_IP,
        0x7777,
        TUNNEL_METRIC,
    );
    let plan = build_apply_plan(
        Vec::new(),
        1500,
        None,
        vec![bypass],
        vec![t1, t2],
        DnsSettings::new(Vec::new(), Vec::new()),
    );

    let bypass_at = plan
        .steps
        .iter()
        .position(|s| *s == FamilyStep::Bypass)
        .expect("apply 计划必须含 bypass 族步骤");
    let routes_at = plan
        .steps
        .iter()
        .position(|s| *s == FamilyStep::Routes)
        .expect("apply 计划必须含 routes 族步骤");
    assert!(
        bypass_at < routes_at,
        "bypass 族必须排在隧道路由族之前（先 bypass 再 tunnel，否则控制流量被隧道路由劫持）"
    );
    assert_eq!(
        plan.steps.iter().filter(|s| **s == FamilyStep::Bypass).count(),
        1,
        "bypass 族步骤必须恰好出现一次"
    );
    assert_eq!(
        plan.steps.iter().filter(|s| **s == FamilyStep::Routes).count(),
        1,
        "routes 族步骤必须恰好出现一次"
    );
}

/// restore 计划必须是 apply 步骤的**精确逆序**（最后应用的族先恢复——W20 'cleanup 按
/// 安装顺序逆序' 的跨族推广）：逆序中隧道路由族先于 bypass 族删除（路由先删、bypass 最后删）。
/// 杀死 'restore 按 forward family order'。
#[test]
fn restore_plan_reverses_apply_family_order() {
    let bypass = RouteRow::new(
        Ipv4Addr::UNSPECIFIED,
        0,
        Ipv4Addr::new(198, 18, 0, 2),
        0xABC,
        0,
    );
    let t1 = RouteRow::new(TUNNEL_NET, TUNNEL_PREFIX, PROBE_IP, 0x7777, TUNNEL_METRIC);
    let plan = build_apply_plan(
        vec![IpAddressRow::new(PROBE_IP, 0x7777, TUNNEL_PREFIX)],
        MTU_APPLY,
        Some(MTU_APPLY),
        vec![bypass],
        vec![t1],
        DnsSettings::new(vec![DNS_SERVER.to_string()], vec![DNS_SEARCH.to_string()]),
    );

    let mut expected = plan.steps.clone();
    expected.reverse();
    assert_eq!(
        build_restore_plan(&plan),
        expected,
        "restore 必须是 apply 步骤的精确逆序（最后应用的族先恢复）"
    );

    let restore_steps = build_restore_plan(&plan);
    let routes_at = restore_steps
        .iter()
        .position(|s| *s == FamilyStep::Routes)
        .expect("restore 计划必须含 routes 族步骤");
    let bypass_at = restore_steps
        .iter()
        .position(|s| *s == FamilyStep::Bypass)
        .expect("restore 计划必须含 bypass 族步骤");
    assert!(
        routes_at < bypass_at,
        "逆序 restore 中隧道路由族必须先于 bypass 族删除（bypass 最后删）"
    );
}

/// aggregate 快照是已提交 leaf 类型（W18 IpAddressRow / W19 MtuSnapshot / W20 RouteRow /
/// W21 DnsSettings）的**组合**，不是重新实现：字段类型、取值与 leaf 指纹全部直接可用。
/// 若 W22-I 定义自己的行/快照类型，本测试无法编译。
/// 杀死 'aggregate 重新实现 leaf 行/快照类型'。
#[test]
fn snapshot_composes_leaf_types_not_reimplemented() {
    let luid = 0x1234_5678_9ABC_DEF0u64;
    let row = IpAddressRow::new(PROBE_IP, luid, TUNNEL_PREFIX);
    // 快照的 address_rows 由 leaf 的 admission plan（W18 plan_addresses）产出——组合证明。
    let plan: IpAddressPlan = plan_addresses(&[], std::slice::from_ref(&row));
    assert_eq!(
        plan.to_add,
        vec![row.clone()],
        "admission 必须先于 effect：to_add 必须产出 desired 行"
    );
    assert!(plan.pre_existing.is_empty());

    let mtu4 = MtuSnapshot::new(luid, MtuFamily::V4, MTU_APPLY);
    let mtu6 = Some(MtuSnapshot::new(luid, MtuFamily::V6, 0xFFFF));
    let route = RouteRow::new(TUNNEL_NET, TUNNEL_PREFIX, PROBE_IP, luid, TUNNEL_METRIC);
    let dns = DnsSettings::new(vec![DNS_SERVER.to_string()], vec![DNS_SEARCH.to_string()]);

    let snap = TunnelSnapshot {
        address_rows: plan.to_add,
        mtu_v4: mtu4.clone(),
        mtu_v6: mtu6.clone(),
        routes: vec![route.clone()],
        dns: dns.clone(),
    };
    assert_eq!(snap.address_rows, vec![row], "快照 address 字段必须是 W18 的 IpAddressRow");
    assert_eq!(snap.mtu_v4, mtu4, "快照 MTU 字段必须是 W19 的 MtuSnapshot");
    assert_eq!(snap.mtu_v6, mtu6, "快照 V6 MTU 字段必须是 W19 的 MtuSnapshot");
    assert_eq!(snap.routes, vec![route], "快照路由字段必须是 W20 的 RouteRow");
    assert_eq!(snap.dns, dns, "快照 DNS 字段必须是 W21 的 DnsSettings");
    // 快照的 DNS 部分可直接经 leaf 指纹（W21 DnsFingerprint::of）——若 aggregate 重新实现
    // 自己的 DNS 类型，此断言无法编译。
    assert_eq!(
        DnsFingerprint::of(&snap.dns),
        DnsFingerprint::of(&dns),
        "快照 DNS 字段必须是 leaf 的 DnsSettings（顺序敏感指纹可直接作用其上）"
    );
}

// ---------------------------------------------------------------------------
// 真实跨族 mutation 契约（需要 admin；非 elevated 记为 not_run）
// ---------------------------------------------------------------------------

/// 单一 aggregate 同时拥有 adapter 与 session：同一实例暴露两者且身份与创建时一致；
/// 存活期间 inventory 必须完整（9 项 canonical obligation）。
/// 杀死 'split adapter/session owner'（分拆 owner 无法从同一实例同时提供两者）。
#[test]
fn aggregate_owns_adapter_and_session_as_one() {
    if !require_admin("aggregate_owns_adapter_and_session_as_one") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW22Owner");
    let luid = adapter.luid();
    let session = start_session(&lib, &adapter);

    let agg = Aggregate::new(adapter, session);
    assert_eq!(
        agg.adapter().luid(),
        luid,
        "aggregate 必须持有创建时的 adapter（单一 owner）"
    );
    assert_eq!(
        agg.session().ring_capacity(),
        RING_CAPACITY,
        "aggregate 必须持有启动的 session（单一 owner）"
    );
    assert!(
        is_complete(agg.inventory()),
        "存活 aggregate 的 obligation inventory 必须包含全部 9 项 canonical obligation \
         （adapter/session/address/MTU/bypass/routes/DNS/packet/running effects）"
    );
    // drop(agg)：session 先 EndSession、adapter 后 close（W17 语义由 W22-I 保证）——
    // 创建者 close 移除 adapter，无残留。
}

/// aggregate capture 是 leaf 回读的完整组合：经已提交 leaf seam（W18/W19/W20/W21）在
/// scratch 接口上应用已知配置后，Aggregate::capture 必须逐族回读这些值——任一族缺失/
/// 回退（如跳过 DNS）都会让断言失败（'omit one inventory item' 的 capture 侧化身；
/// API success 不是 proof，回读才是）。capture 返回 Result<TunnelSnapshot, NativeError>
/// ——任一族失败必须 Err，绝不返回缺项 partial 快照。
#[test]
fn aggregate_capture_is_complete_composition() {
    if !require_admin("aggregate_capture_is_complete_composition") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW22Capture");
    let luid = adapter.luid();
    let session = start_session(&lib, &adapter);
    let mut agg = Aggregate::new(adapter, session);

    // 经 leaf seam 直接应用各族已知配置（组合证明：aggregate 的 capture 必须委托 leaf
    // 回读，不得重新实现）。
    let addr = IpAddressRow::new(PROBE_IP, luid, TUNNEL_PREFIX);
    expect_ok(IpAddressController::new(luid).apply(&addr), "leaf apply address");
    expect_ok(
        MtuController::new(luid, MtuFamily::V4).apply(MTU_APPLY),
        "leaf apply mtu",
    );
    let tunnel = RouteRow::new(TUNNEL_NET, TUNNEL_PREFIX, PROBE_IP, luid, TUNNEL_METRIC);
    expect_ok(install(&tunnel), "leaf install tunnel route");
    let guid = luid_to_guid(luid).expect("scratch adapter LUID -> GUID");
    let dns = DnsSettings::new(vec![DNS_SERVER.to_string()], vec![DNS_SEARCH.to_string()]);
    expect_ok(DnsApplier::apply(&guid, &dns), "leaf apply dns");

    let snap = expect_ok(agg.capture(), "aggregate capture（全族）");
    assert!(
        snap.address_rows
            .iter()
            .any(|r| r.address == PROBE_IP && r.interface_luid == luid && r.on_link_prefix_length == TUNNEL_PREFIX),
        "address 族必须真实回读（缺族回读 = omit one inventory item mutant）"
    );
    assert_eq!(
        snap.mtu_v4,
        MtuSnapshot::new(luid, MtuFamily::V4, MTU_APPLY),
        "MTU 族必须真实回读"
    );
    assert!(
        snap.routes.contains(&tunnel),
        "routes 族必须真实回读（精确行全字段相等）"
    );
    assert_eq!(snap.dns, dns, "DNS 族必须真实回读（顺序保持）");
    drop(agg);
}

/// admission 先于 effect：plan 含任一非法族（MTU=1，低于 IPv4 最小 68 -> 87）时，
/// apply 必须**零效果**返回 Err(87)——不得先应用 address/route 再在半路失败。
/// 杀死 'effect before admission' + 'partial failure leaves half state'。
#[test]
fn apply_rejects_invalid_plan_without_any_effect() {
    if !require_admin("apply_rejects_invalid_plan_without_any_effect") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW22NoEffect");
    let luid = adapter.luid();
    let session = start_session(&lib, &adapter);
    let mut agg = Aggregate::new(adapter, session);
    let original = expect_ok(agg.capture(), "capture 原始状态");

    // plan 本身可构造（规划是纯逻辑）；非法性在 apply 的完整验证阶段被拒绝。
    let addr = IpAddressRow::new(PROBE_IP, luid, TUNNEL_PREFIX);
    let tunnel = RouteRow::new(TUNNEL_NET, TUNNEL_PREFIX, PROBE_IP, luid, TUNNEL_METRIC);
    let dns = DnsSettings::new(vec![DNS_SERVER.to_string()], vec![DNS_SEARCH.to_string()]);
    let invalid = build_apply_plan(
        vec![addr],
        MTU_INVALID,
        None,
        Vec::new(),
        vec![tunnel],
        dns,
    );

    let err = expect_native_error(apply(&mut agg, &invalid), "apply 非法 plan");
    assert_eq!(
        err.code, ERROR_INVALID_PARAMETER,
        "非法 MTU 必须 87（ERROR_INVALID_PARAMETER，W19 冻结），got {}",
        err.code
    );

    let after = expect_ok(agg.capture(), "apply 失败后 capture");
    assert_eq!(
        after, original,
        "apply 失败必须零效果（address/MTU/routes/DNS 全部保持原始状态）——\
         'effect before admission' / 'partial failure leaves half state' mutant 在此死"
    );
    drop(agg);
}

/// 完整往返：aggregate apply 全族配置 -> 逐族回读证明 effect -> 逆族序
/// compare-and-restore -> 回到原始快照（address/mtu/dns 严格相等、路由族无残留隧道路由
/// 且无新增行）。任一族被 inventory 遗漏（omit one inventory item 的 native 化身）都会
/// 让该族无法恢复、往返断言失败。
#[test]
fn aggregate_apply_restore_roundtrip_returns_to_original() {
    if !require_admin("aggregate_apply_restore_roundtrip_returns_to_original") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW22Roundtrip");
    let luid = adapter.luid();
    let session = start_session(&lib, &adapter);
    let mut agg = Aggregate::new(adapter, session);
    let original = expect_ok(agg.capture(), "capture 原始状态");

    let addr = IpAddressRow::new(PROBE_IP, luid, TUNNEL_PREFIX);
    let tunnel = RouteRow::new(TUNNEL_NET, TUNNEL_PREFIX, PROBE_IP, luid, TUNNEL_METRIC);
    let dns = DnsSettings::new(vec![DNS_SERVER.to_string()], vec![DNS_SEARCH.to_string()]);
    let plan = build_apply_plan(
        vec![addr.clone()],
        MTU_APPLY,
        None,
        Vec::new(),
        vec![tunnel.clone()],
        dns.clone(),
    );

    expect_ok(apply(&mut agg, &plan), "aggregate apply 全族配置");
    let applied = expect_ok(agg.capture(), "apply 后 capture");
    assert!(
        applied
            .address_rows
            .iter()
            .any(|r| r.address == PROBE_IP && r.interface_luid == luid && r.on_link_prefix_length == TUNNEL_PREFIX),
        "apply 后 address 必须真实回读（API success 不是 proof）"
    );
    assert_eq!(
        applied.mtu_v4,
        MtuSnapshot::new(luid, MtuFamily::V4, MTU_APPLY),
        "apply 后 MTU 必须真实回读"
    );
    assert!(
        applied.routes.contains(&tunnel),
        "apply 后隧道路由必须真实回读（精确行）"
    );
    assert_eq!(applied.dns, dns, "apply 后 DNS 必须真实回读");
    assert!(
        is_complete(agg.inventory()),
        "存活 aggregate 的 inventory 必须完整（9 项）"
    );

    expect_ok(restore(&mut agg), "aggregate 逆族序 compare-and-restore");
    let restored = expect_ok(agg.capture(), "restore 后 capture");
    assert_eq!(
        restored.address_rows,
        original.address_rows,
        "restore 必须删除 owned 地址（pre-existing 永不删）"
    );
    assert_eq!(
        restored.mtu_v4,
        original.mtu_v4,
        "MTU 必须 compare-and-restore 回原始值"
    );
    assert_eq!(
        restored.mtu_v6,
        original.mtu_v6,
        "V6 MTU 必须未被触碰"
    );
    assert_eq!(
        restored.dns,
        original.dns,
        "DNS 必须恢复原始快照（不得无条件覆盖第三方变更）"
    );
    assert!(
        !restored
            .routes
            .iter()
            .any(|r| r.network == TUNNEL_NET && r.prefix_len == TUNNEL_PREFIX),
        "隧道路由必须已删除（逆序清理）"
    );
    assert!(
        restored.routes.iter().all(|r| original.routes.contains(r)),
        "restore 后不得出现原始状态之外的新路由（complete restore）"
    );
    drop(agg);
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
