// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W18-T Terra: 接口 IPv4 地址（CreateUnicastIpAddressEntry / DeleteUnicastIpAddressEntry /
// GetUnicastIpAddressTable）契约测试。这些测试钉住 W18-I 在 exv_vpn_win32_resource::
// {ip_address, ip_helper_types} 实现的 seam（src/ip_address.rs、src/ip_helper_types.rs，
// 当前均为空占位——本文件即 RED）。冻结事实
// （docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md，
// WSP4 提权实测）是契约：
//   - 行身份 = Address + InterfaceLuid（facts §6）；前缀长度在 OnLinkPrefixLength（UINT8）；
//   - Create 回读精确行：地址、OnLinkPrefixLength=24、PrefixOrigin=1（Manual）、
//     SuffixOrigin=1（Manual）、DadState=1（Tentative，创建后立即回读未收敛到 Preferred）、
//     SkipAsSource=false、lifetime 0xffffffff（无限）——W18 不得用 API success 代替 proof；
//   - 重复 Create 同一地址 -> 5010（ERROR_OBJECT_ALREADY_EXISTS，非 183）——已存在行必须
//     在 effect 前被 admission 识别，不得重复 Create；
//   - 非法前缀 33（IPv4 上限 32）-> 87（ERROR_INVALID_PARAMETER）；接口 LUID 不存在 ->
//     1168（ERROR_NOT_FOUND）；
//   - compare-and-restore：restore 只删除本 admission owned 的行，且仅当该行仍存在且未被
//     第三方修改（无条件恢复/按地址-only 删除 = killer mutant，会 clobber 第三方变更或
//     删除他接口上的同地址行）。
//
// W18-I pinned seam（src/ip_address.rs + src/ip_helper_types.rs，W18-I 必须按此实现，
// 否则 GREEN 编译失败）：
//   pub struct IpAddressRow { pub address: Ipv4Addr, pub interface_luid: u64,
//       pub on_link_prefix_length: u8, pub skip_as_source: bool,
//       pub prefix_origin: u8, pub suffix_origin: u8, pub dad_state: u8,
//       pub lifetime_infinite: bool }                    // derive(Debug, Clone, PartialEq, Eq)
//   impl IpAddressRow { pub fn new(address: Ipv4Addr, interface_luid: u64,
//       on_link_prefix_length: u8) -> Self }             // skip_as_source=false；回读字段由 capture 填充
//   pub struct IpAddressPlan { pub to_add: Vec<IpAddressRow>,
//       pub pre_existing: Vec<IpAddressRow> }            // derive(Debug, Clone, PartialEq, Eq)
//   pub enum ApplyOutcome { Applied, AlreadyExists }     // derive(Debug, Clone, Copy, PartialEq, Eq)
//   pub struct IpAddressController                       // 包装 interface_luid
//   impl IpAddressController {
//     pub fn new(interface_luid: u64) -> IpAddressController
//     pub fn capture(&self) -> Result<Vec<IpAddressRow>, NativeError>
//       // GetUnicastIpAddressTable 过滤到本接口（IPv4 行；真实 Get，不得缓存/伪造）
//     pub fn apply(&self, row: &IpAddressRow) -> Result<ApplyOutcome, NativeError>
//       // CreateUnicastIpAddressEntry；5010 -> AlreadyExists；87/1168 -> 类型化 Err
//     pub fn delete(&self, row: &IpAddressRow) -> Result<(), NativeError>
//       // DeleteUnicastIpAddressEntry 按完整精确行（address + interface_luid）
//   }
//   纯逻辑（非提权可测）：
//   pub fn plan_addresses(captured: &[IpAddressRow], desired: &[IpAddressRow]) -> IpAddressPlan
//     // admission：desired ∩ captured（同身份 address+luid）-> pre_existing（永不 owned）；
//     // desired ∖ captured -> to_add（本 admission 将成为 owned）。身份匹配不比较回读字段。
//   pub fn restore_owned_addresses(applied: &[IpAddressRow], current: &[IpAddressRow])
//     -> Vec<IpAddressRow>
//     // compare-delete：applied 的子集——仍存在且 fingerprint（address/luid/prefix/
//     // skip_as_source）未变的 owned 行；已消失或已被第三方修改的行跳过；pre-existing 永不
//     // 进入。返回顺序保持 applied 顺序。
//
// 提权设计（W17-T/W19-T 同款）：纯逻辑测试（plan 拆分、compare-delete 规划）在非提权宿主
// 上必须全部通过；真实地址变更测试经 require_admin 门禁（非提权记为
// [not_run/blocked_by_environment]，不伪造假绿），且只变更测试自建的 scratch Wintun
// adapter（WSP4 spike 同款：测试网络 10.88.88.0/24，前缀 24；drop 创建者句柄即移除接口，
// 地址状态随接口消失——panic 路径进程退出同样关闭句柄，无残留）；每个变更测试同时把
// owned 地址显式删除（所有路径清理）。

use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::path::Path;

use exv_vpn_win32_resource::ip_address::{
    ApplyOutcome, IpAddressController, plan_addresses, restore_owned_addresses,
};
use exv_vpn_win32_resource::ip_helper_types::{IpAddressPlan, IpAddressRow};
use exv_vpn_win32_resource::native_error::NativeError;
use exv_vpn_win32_resource::wintun_adapter::{AdapterOpen, WintunAdapter};
use exv_vpn_win32_resource::wintun_api::WintunLibrary;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 冻结的 amd64 wintun-0.14.1 DLL 精确路径（PATH DLL 是 W16 mutant；哈希由 WintunLibrary::load 校验）。
const FROZEN_DLL_PATH: &str = "C:\\Users\\TomLi\\.exv\\wintun\\wintun\\bin\\amd64\\wintun.dll";
/// 与 WSP3/WSP4 探针一致的 tunnel type。
const TUNNEL_TYPE: &str = "EXV VPN";
/// 纯逻辑测试用的任意接口 LUID（纯逻辑不触碰 OS，值任意但固定 -> 确定性）。
const PURE_TEST_LUID_A: u64 = 0x1234_5678_9ABC_DEF1;
const PURE_TEST_LUID_B: u64 = 0x1234_5678_9ABC_DEF2;
/// WSP4 冻结错误码：非法前缀（IPv4 上限 32）-> ERROR_INVALID_PARAMETER(87)。
const ERROR_INVALID_PARAMETER: u32 = 87;
/// WSP4 冻结错误码：接口 LUID 不存在 -> ERROR_NOT_FOUND(1168)。
const ERROR_NOT_FOUND: u32 = 1168;
/// WSP4 冻结回读值：PrefixOrigin=1（Manual）、SuffixOrigin=1（Manual）、
/// DadState=1（Tentative——创建后立即回读未收敛到 Preferred）。
const PREFIX_ORIGIN_MANUAL: u8 = 1;
const SUFFIX_ORIGIN_MANUAL: u8 = 1;
const DAD_STATE_TENTATIVE: u8 = 1;
/// WSP4 测试网络（spike 冻结）：10.88.88.0/24，测试地址 .1/.2/.3，前缀 24。
const TEST_IP_1: [u8; 4] = [10, 88, 88, 1];
const TEST_IP_2: [u8; 4] = [10, 88, 88, 2];
const TEST_IP_3: [u8; 4] = [10, 88, 88, 3];
const TEST_PREFIX: u8 = 24;

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

/// 构造输入行（apply 用）：skip_as_source=false（WSP4 冻结），回读字段由 capture 填充。
fn ip_row(addr: [u8; 4], luid: u64, prefix: u8) -> IpAddressRow {
    IpAddressRow::new(
        Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
        luid,
        prefix,
    )
}

/// capture 返回的行带 OS 回读字段（prefix_origin 等），不能与 `new` 构造的输入行全等比较；
/// 身份断言按 address + interface_luid（WSP4 §6：行身份 = Address+InterfaceLuid）。
fn contains_identity(rows: &[IpAddressRow], addr: [u8; 4], luid: u64) -> bool {
    let want = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    rows.iter()
        .any(|r| r.address == want && r.interface_luid == luid)
}

/// 当前进程是否 elevated（admin token）——模式与 W16-T / W17-T / W19-T / WSP3 spike 一致。
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
    unsafe {
        let _ = CloseHandle(token);
    }
    elevated
}

/// 动态断言的前置：非 elevated 时输出显式 `not_run / blocked_by_environment` 并短路。
fn require_admin(test: &str) -> bool {
    if is_elevated() {
        return true;
    }
    eprintln!(
        "[not_run/blocked_by_environment] {test}: 创建 scratch Wintun adapter 并修改其 \
         接口地址需要提权（elevated admin token）；当前进程非 elevated，跳过动态断言"
    );
    false
}

/// 唯一 adapter 名（按测试用途分前缀，pid 防并行/残留碰撞）。
fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", std::process::id())
}

/// 加载冻结 DLL 的便捷入口（各测试独立加载，LoadLibraryW 引用计数安全）。
fn load_frozen() -> WintunLibrary {
    expect_ok(
        WintunLibrary::load(Path::new(FROZEN_DLL_PATH)),
        "load 冻结 wintun.dll",
    )
}

/// 创建真实 adapter（创建者 owned；drop 即移除 adapter——scratch 接口，地址状态随接口消失）。
fn create_adapter(lib: &WintunLibrary, prefix: &str) -> WintunAdapter {
    let name = unique_name(prefix);
    let (adapter, opened) = expect_ok(
        WintunAdapter::create(lib, &name, TUNNEL_TYPE),
        "create adapter",
    );
    assert!(
        matches!(opened, AdapterOpen::Created),
        "create 必须返回 AdapterOpen::Created"
    );
    adapter
}

/// 在 scratch adapter 的接口上构造地址 controller（WSP4 冻结：行身份 = Address + InterfaceLuid）。
fn controller_for(adapter: &WintunAdapter) -> IpAddressController {
    IpAddressController::new(adapter.luid())
}

/// 断言 `current` 中不再存在该身份的行（compare-delete 的 absent 证明）。
fn assert_absent(rows: &[IpAddressRow], addr: [u8; 4], luid: u64, ctx: &str) {
    assert!(
        !contains_identity(rows, addr, luid),
        "{ctx}: 该地址必须已 absent（compare-and-restore 的 read-back 证明）"
    );
}

// ---------------------------------------------------------------------------
// 纯逻辑契约（非提权宿主必须全部通过；不触碰 OS）
// ---------------------------------------------------------------------------

/// 行身份 = address + interface_luid（WSP4 §6）：同地址不同接口是两行；restore 规划只按
/// 完整身份删除 owned 行，同地址他接口的行绝不进入 delete 计划。杀死 'delete by
/// address only'（规划侧：按地址-only 匹配会把另一接口的同地址行当作本行）。
#[test]
fn row_identity_is_address_plus_interface_luid() {
    let row_a = ip_row(TEST_IP_1, PURE_TEST_LUID_A, TEST_PREFIX);
    let row_b = ip_row(TEST_IP_1, PURE_TEST_LUID_B, TEST_PREFIX);
    assert_ne!(
        row_a, row_b,
        "行身份 = address + interface_luid：同地址不同接口必须是不相同的两行"
    );

    // restore 只按身份删除 owned 行：current 中同地址、他接口的行（第三方/其他接口）
    // 不得被误判为本行进入 delete 计划。
    let applied = vec![row_a.clone()];
    let current = vec![row_a.clone(), row_b.clone()];
    let to_delete = restore_owned_addresses(&applied, &current);
    assert_eq!(
        to_delete.len(),
        1,
        "restore 必须只删除 LUID_A 上的 owned 行（他接口同地址行不得被地址-only 匹配）"
    );
    assert_eq!(
        to_delete[0], row_a,
        "delete 计划必须返回精确 owned 行（address + interface_luid）"
    );
}

/// plan（admission）把 desired 拆分为 pre-existing 与 to-add：已在 captured 表内（同身份
/// address+luid）的行 -> pre_existing（永不 owned、永不删除），不在表内的行 -> to_add
/// （本 admission 将成为 owned）。身份匹配不比较回读字段（capture 行带 OS 回读值）。
/// 杀死 'pre-existing marked owned'（规划侧：把已存在行标 owned 会让 restore 误删它）。
#[test]
fn plan_splits_pre_existing_from_to_add() {
    let captured = vec![
        ip_row(TEST_IP_1, PURE_TEST_LUID_A, TEST_PREFIX),
        ip_row(TEST_IP_2, PURE_TEST_LUID_A, TEST_PREFIX),
    ];
    let desired = vec![
        ip_row(TEST_IP_1, PURE_TEST_LUID_A, TEST_PREFIX),
        ip_row(TEST_IP_2, PURE_TEST_LUID_A, TEST_PREFIX),
        ip_row(TEST_IP_3, PURE_TEST_LUID_A, TEST_PREFIX),
    ];
    let plan: IpAddressPlan = plan_addresses(&captured, &desired);
    assert_eq!(
        plan.to_add.len(),
        1,
        "只有不在表内的 .3 才能成为 to_add（owned）；已在表内的行被标 owned = mutant"
    );
    assert!(
        plan.to_add
            .contains(&ip_row(TEST_IP_3, PURE_TEST_LUID_A, TEST_PREFIX))
    );
    assert_eq!(
        plan.pre_existing.len(),
        2,
        "表内已存在的 .1/.2 必须归 pre_existing"
    );
    assert!(
        plan.pre_existing
            .contains(&ip_row(TEST_IP_1, PURE_TEST_LUID_A, TEST_PREFIX))
    );
    assert!(
        plan.pre_existing
            .contains(&ip_row(TEST_IP_2, PURE_TEST_LUID_A, TEST_PREFIX))
    );

    // 身份按 address+luid：同地址、不同接口的行不是本接口的 pre-existing（Create 目标
    // 是另一接口），必须 to_add。
    let plan_other_iface: IpAddressPlan = plan_addresses(
        &captured,
        &[ip_row(TEST_IP_1, PURE_TEST_LUID_B, TEST_PREFIX)],
    );
    assert_eq!(
        plan_other_iface.to_add.len(),
        1,
        "他接口的同地址行不是本接口 pre-existing"
    );
    assert!(plan_other_iface.pre_existing.is_empty());

    // 同身份但前缀不同的已存在行仍按身份判定 pre-existing（再 Create 会 5010；不得因
    // 字段差异标 owned 后重复 Create）。
    let plan_same_identity: IpAddressPlan = plan_addresses(
        &[ip_row(TEST_IP_1, PURE_TEST_LUID_A, 16)],
        &[ip_row(TEST_IP_1, PURE_TEST_LUID_A, TEST_PREFIX)],
    );
    assert_eq!(
        plan_same_identity.pre_existing.len(),
        1,
        "同身份（address+luid）即 pre-existing"
    );
    assert!(plan_same_identity.to_add.is_empty());
}

/// compare-delete 规划：restore 只删除 applied（owned）中仍存在且 fingerprint 未被第三方
/// 修改的行；已消失（第三方删除）与已被修改（第三方改前缀）的行跳过；从未 owned 的行
/// 永不进入。杀死 'unconditional restore / delete by address only'（恢复侧）。
#[test]
fn restore_plan_deletes_only_owned_present_unchanged() {
    let applied = vec![
        ip_row(TEST_IP_1, PURE_TEST_LUID_A, TEST_PREFIX), // 仍在且未变 -> 需删除
        ip_row(TEST_IP_2, PURE_TEST_LUID_A, TEST_PREFIX), // 第三方改为前缀 16 -> 跳过
        ip_row(TEST_IP_3, PURE_TEST_LUID_A, TEST_PREFIX), // 第三方已删除 -> 跳过
    ];
    let current = vec![
        ip_row(TEST_IP_1, PURE_TEST_LUID_A, TEST_PREFIX),
        ip_row(TEST_IP_2, PURE_TEST_LUID_A, 16), // 第三方修改的 fingerprint
        // .3 不在表中（第三方已删除）
        ip_row([10, 88, 88, 9], PURE_TEST_LUID_A, TEST_PREFIX), // pre-existing：从未 owned
        ip_row(TEST_IP_1, PURE_TEST_LUID_B, TEST_PREFIX),       // 同地址他接口：身份不同
    ];
    let to_delete = restore_owned_addresses(&applied, &current);
    assert_eq!(
        to_delete.len(),
        1,
        "只有 .1（仍存在且未变）可删；.2 第三方改过、.3 已消失、pre-existing 与他接口行一律跳过"
    );
    assert_eq!(
        to_delete[0], applied[0],
        "delete 计划必须返回精确的 owned 行"
    );
}

// ---------------------------------------------------------------------------
// 真实地址契约（需要 admin；非 elevated 记为 not_run）
// ---------------------------------------------------------------------------

/// admit-before-effect 顺序 + 精确行回读（WSP4 facts §1）：plan（admission）先于 apply
/// （effect）；apply 后 read-back 必须是真实 GetUnicastIpAddressTable 的精确行——地址
/// 10.88.88.1、OnLinkPrefixLength=24、SkipAsSource=false、PrefixOrigin=1（Manual）、
/// SuffixOrigin=1（Manual）、DadState=1（Tentative）、lifetime 0xffffffff。
/// 杀死 'effect 无 read-back proof（API success 即 proof）'。
#[test]
fn apply_then_readback_is_exact_frozen_row() {
    if !require_admin("apply_then_readback_is_exact_frozen_row") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW18ExactRow");
    let ctrl = controller_for(&adapter);
    let row = ip_row(TEST_IP_1, adapter.luid(), TEST_PREFIX);

    // admission 先于 effect：先对空接口（新建 adapter 无地址）产出 plan，to_add 必须含该行。
    let plan: IpAddressPlan = plan_addresses(&[], std::slice::from_ref(&row));
    assert!(
        plan.to_add.contains(&row),
        "admission 必须先于 effect：plan 必须产出 to_add"
    );
    assert!(plan.pre_existing.is_empty());

    let outcome = expect_ok(ctrl.apply(&row), "apply 10.88.88.1/24");
    assert!(
        matches!(outcome, ApplyOutcome::Applied),
        "新行首次 apply 必须 Applied"
    );

    // 回读精确行：全部字段逐项断言（W18 不得用 API success 代替 proof）。
    let rows = expect_ok(ctrl.capture(), "apply 后 capture（真实 Get）");
    assert_eq!(rows.len(), 1, "新接口上只应有我们创建的这一行");
    let observed = &rows[0];
    assert_eq!(
        observed.address,
        Ipv4Addr::new(10, 88, 88, 1),
        "回读地址必须精确"
    );
    assert_eq!(
        observed.interface_luid,
        adapter.luid(),
        "回读 LUID 必须精确"
    );
    assert_eq!(
        observed.on_link_prefix_length, TEST_PREFIX,
        "回读 OnLinkPrefixLength 必须 = 24"
    );
    assert!(!observed.skip_as_source, "回读 SkipAsSource 必须 false");
    assert_eq!(
        observed.prefix_origin, PREFIX_ORIGIN_MANUAL,
        "回读 PrefixOrigin 必须 = 1（Manual）"
    );
    assert_eq!(
        observed.suffix_origin, SUFFIX_ORIGIN_MANUAL,
        "回读 SuffixOrigin 必须 = 1（Manual）"
    );
    assert_eq!(
        observed.dad_state, DAD_STATE_TENTATIVE,
        "创建后立即回读 DadState 必须 = 1（Tentative，未收敛到 Preferred）"
    );
    assert!(
        observed.lifetime_infinite,
        "回读 lifetime 必须 0xffffffff（无限）"
    );

    // 清理：删除 owned 行并验证 absent（compare-delete 的 read-back 证明），随后移除接口。
    expect_ok(ctrl.delete(&row), "清理：delete owned 地址");
    let after = expect_ok(ctrl.capture(), "delete 后 capture");
    assert_absent(&after, TEST_IP_1, adapter.luid(), "delete 后");
    drop(adapter);
}

/// already-exists：重复 apply 同一行必须 AlreadyExists（WSP4 冻结：重复 Create 同一地址 ->
/// 5010 ERROR_OBJECT_ALREADY_EXISTS，非 183），且不得产生第二次 effect（表中仍只有一行）。
/// 杀死 'effect without admission / duplicate effect（admit-before-effect 顺序）'。
#[test]
fn duplicate_apply_returns_already_exists_5010() {
    if !require_admin("duplicate_apply_returns_already_exists_5010") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW18Dup");
    let ctrl = controller_for(&adapter);
    let row = ip_row(TEST_IP_1, adapter.luid(), TEST_PREFIX);

    let first = expect_ok(ctrl.apply(&row), "首次 apply");
    assert!(
        matches!(first, ApplyOutcome::Applied),
        "首次 apply 必须 Applied"
    );
    let second = expect_ok(ctrl.apply(&row), "重复 apply 同一行");
    assert!(
        matches!(second, ApplyOutcome::AlreadyExists),
        "重复 apply 必须 AlreadyExists（5010 ERROR_OBJECT_ALREADY_EXISTS，非 183）"
    );

    // 已存在行被 admission 识别：不得重复 Create（回读必须仍只有一行）。
    let rows = expect_ok(ctrl.capture(), "重复 apply 后 capture");
    assert_eq!(
        rows.len(),
        1,
        "重复 apply 不得产生第二行（effect 只允许一次）"
    );

    expect_ok(ctrl.delete(&row), "清理：delete owned 地址");
    let after = expect_ok(ctrl.capture(), "delete 后 capture");
    assert_absent(&after, TEST_IP_1, adapter.luid(), "delete 后");
    drop(adapter);
}

/// delete 必须按完整精确行（address + interface_luid）：用错误 LUID 的同地址行 delete
/// 不得删掉真行（真行仍在），用精确行 delete 才删除。杀死 'delete by address only'
/// （OS 侧 killer mutant——只按地址删会删掉他接口/错误身份的同地址行）。
#[test]
fn delete_with_wrong_luid_leaves_row_intact() {
    if !require_admin("delete_with_wrong_luid_leaves_row_intact") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW18ExactDelete");
    let ctrl = controller_for(&adapter);
    let luid = adapter.luid();
    let row = ip_row(TEST_IP_1, luid, TEST_PREFIX);

    let outcome = expect_ok(ctrl.apply(&row), "apply 10.88.88.1/24");
    assert!(matches!(outcome, ApplyOutcome::Applied));

    // 错误身份：同地址、不同 LUID（保证不是本接口、不是本行）。
    let wrong_luid = luid ^ 0x8000_0000_0000_0000;
    let wrong_row = ip_row(TEST_IP_1, wrong_luid, TEST_PREFIX);
    // 不得 panic；Ok（no-op）或 Err（typed，目标行不存在）均可——但绝不能删掉真行。
    match ctrl.delete(&wrong_row) {
        Ok(()) => {}
        Err(e) => eprintln!("[info] delete 错误 LUID 行返回 Err({e:?})（允许：目标身份不存在）"),
    }
    let rows = expect_ok(ctrl.capture(), "错误 LUID delete 后 capture");
    assert!(
        contains_identity(&rows, TEST_IP_1, luid),
        "用错误 LUID 的 delete 必须不删真行——delete by address only（mutant）在此暴露"
    );

    // 精确行 delete：身份匹配（address + interface_luid）才删除。
    expect_ok(ctrl.delete(&row), "delete 精确行");
    let after = expect_ok(ctrl.capture(), "精确 delete 后 capture");
    assert_absent(&after, TEST_IP_1, luid, "精确行 delete 后");
    drop(adapter);
}

/// pre-existing 区分端到端：接口上已存在的地址（seeded 于本 admission 之前）在 plan 中
/// 必须归 pre_existing（永不 owned），compare-delete restore 只删本 admission owned 的
/// 新行，pre-existing 行必须幸存。杀死 'pre-existing marked owned'（W18 killer mutant）——
/// 若已存在行被标 owned，restore 会把它误删。
#[test]
fn pre_existing_row_survives_compare_delete_restore() {
    if !require_admin("pre_existing_row_survives_compare_delete_restore") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW18PreExisting");
    let ctrl = controller_for(&adapter);
    let luid = adapter.luid();
    let seed = ip_row(TEST_IP_2, luid, TEST_PREFIX); // 本 admission 之前已存在（seed 模拟 OS 已有状态）
    let fresh = ip_row(TEST_IP_1, luid, TEST_PREFIX);

    // Seed 已存在行（测试扮演“OS/第三方此前已配置”），capture 应反映真实状态。
    let seeded = expect_ok(ctrl.apply(&seed), "seed 10.88.88.2/24");
    assert!(matches!(seeded, ApplyOutcome::Applied));

    // Admission：desired 含已存在的 .2 与新的 .1 -> .2 必须 pre_existing，只有 .1 to_add。
    let captured = expect_ok(ctrl.capture(), "seed 后 capture");
    assert!(
        contains_identity(&captured, TEST_IP_2, luid),
        "seed 必须可观测（真实 Get）"
    );
    let plan: IpAddressPlan = plan_addresses(&captured, &[seed.clone(), fresh.clone()]);
    assert_eq!(
        plan.to_add.len(),
        1,
        "只有 .1 是 to_add；已存在的 .2 被标 owned = mutant"
    );
    assert!(plan.to_add.contains(&fresh));
    assert_eq!(
        plan.pre_existing.len(),
        1,
        ".2 必须归 pre_existing（永不 owned、永不删除）"
    );
    assert!(plan.pre_existing.contains(&seed));

    expect_ok(ctrl.apply(&fresh), "apply 10.88.88.1/24");
    let current = expect_ok(ctrl.capture(), "apply 后 capture");
    // compare-delete restore：owned = to_add（.1），pre-existing（.2）不得进入 delete 计划。
    let to_delete = restore_owned_addresses(&plan.to_add, &current);
    assert_eq!(to_delete.len(), 1, "restore 只删本 admission owned 的 .1");
    assert_eq!(to_delete[0], fresh);
    expect_ok(ctrl.delete(&to_delete[0]), "delete owned .1");

    let after = expect_ok(ctrl.capture(), "restore 后 capture");
    assert_absent(&after, TEST_IP_1, luid, "restore 删除 owned 后");
    assert!(
        contains_identity(&after, TEST_IP_2, luid),
        "pre-existing 行 .2 必须幸存——pre-existing marked owned（mutant）会把它误删"
    );

    // 清理：删除测试 seed 的 pre-existing 行，随后移除接口。
    expect_ok(ctrl.delete(&seed), "清理：delete seeded 地址");
    let final_rows = expect_ok(ctrl.capture(), "清理后 capture");
    assert_absent(&final_rows, TEST_IP_2, luid, "清理后");
    drop(adapter);
}

/// partial/unknown 类型化错误（WSP4 facts §1）：非法前缀 33（IPv4 上限 32）-> 87
/// （ERROR_INVALID_PARAMETER）；接口 LUID 不存在（0xFFFFFFFFFFFFFFFF）-> 1168
/// （ERROR_NOT_FOUND）。均不得 panic，且不得产生副作用（表仍为空）。
#[test]
fn invalid_prefix_and_missing_interface_are_typed_errors() {
    if !require_admin("invalid_prefix_and_missing_interface_are_typed_errors") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW18Errors");
    let ctrl = controller_for(&adapter);
    let luid = adapter.luid();

    let bad_prefix = ip_row(TEST_IP_1, luid, 33); // IPv4 前缀上限 32
    let e1 = expect_native_error(ctrl.apply(&bad_prefix), "apply 前缀 33");
    assert_eq!(
        e1.code, ERROR_INVALID_PARAMETER,
        "前缀 33 必须 ERROR_INVALID_PARAMETER(87), got {}",
        e1.code
    );

    let missing_iface = ip_row(TEST_IP_1, u64::MAX, TEST_PREFIX); // 0xFFFFFFFFFFFFFFFF
    let e2 = expect_native_error(ctrl.apply(&missing_iface), "apply 不存在接口");
    assert_eq!(
        e2.code, ERROR_NOT_FOUND,
        "不存在接口必须 ERROR_NOT_FOUND(1168), got {}",
        e2.code
    );

    // 非法参数不得产生副作用：接口上仍无地址。
    let rows = expect_ok(ctrl.capture(), "非法 apply 后 capture");
    assert!(
        rows.is_empty(),
        "非法参数（87/1168）不得产生任何地址效果（admission 校验先于 effect）"
    );
    drop(adapter);
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
