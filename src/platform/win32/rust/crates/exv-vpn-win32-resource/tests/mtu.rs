// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W19-T Terra: interface MTU（GetIpInterfaceEntry / SetIpInterfaceEntry）契约测试。
// 这些测试钉住 W19-I 在 exv_vpn_win32_resource::mtu 实现的 seam（src/mtu.rs，当前为空
// 占位——本文件即 RED）。冻结事实
// （docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md，
// WSP4 提权实测）是契约：
//   - Wintun 接口 v4/v6 行 NlMtu 基准均为 65535（0xFFFF = Wintun 最大包）；
//   - SetIpInterfaceEntry 前必须强制 SitePrefixLength=0（Get 填充的 IPv4 行带 64，
//     不清直接 Set 返回 87；IPv6 行无此约束）；
//   - 1420/1280/576/65535 均可写；0 是无操作（rc=0 但回读保持上一个值，不重置默认）；
//     1（低于 IPv4 最小 68）→ 87（ERROR_INVALID_PARAMETER）；
//   - 第三方改值后回读必须检测（≠ 我们设的值）；同值再 Set 幂等成功；
//   - restore：Set 回 65535（SitePrefixLength=0）→ 回读 65535，verified=true；
//     compare-and-restore 必须比较当前值与 applied 值，仅当未被第三方修改才恢复——
//     无条件恢复旧快照 = W19 killer mutant（会覆盖第三方变更）。
//
// W19-I pinned seam（src/mtu.rs，W19-I 必须按此实现，否则 GREEN 编译失败）：
//   pub enum MtuFamily { V4, V6 }                                  // derive(Debug, Clone, Copy, PartialEq, Eq)
//   pub struct MtuSnapshot { pub luid: u64, pub family: MtuFamily, pub value: u32 }
//                                                                // derive(Debug, Clone, PartialEq, Eq)
//   impl MtuSnapshot { pub fn new(luid: u64, family: MtuFamily, value: u32) -> Self }
//   pub enum RestoreOutcome { Restored, SkippedThirdPartyChanged }  // derive(Debug, Clone, Copy, PartialEq, Eq)
//   pub struct MtuController                                       // 包装 (luid, family)
//   impl MtuController {
//     pub fn new(luid: u64, family: MtuFamily) -> MtuController
//     pub fn capture(&self) -> Result<MtuSnapshot, NativeError>     // GetIpInterfaceEntry → NlMtu
//     pub fn apply(&self, value: u32) -> Result<(), NativeError>    // SetIpInterfaceEntry（Set 前强制 SitePrefixLength=0）
//     pub fn read_back(&self) -> Result<u32, NativeError>           // 重新 capture 取 value（真实 Get，不得缓存本地状态）
//     pub fn compare_and_restore(&self, applied: &MtuSnapshot, original: &MtuSnapshot)
//         -> Result<RestoreOutcome, NativeError>                    // 仅 current == applied 时 Set(original.value)
//   }
//   纯逻辑（非提权可测）：
//   pub fn decide_restore(applied: &MtuSnapshot, current: &MtuSnapshot) -> RestoreOutcome
//   pub fn validate_mtu_value(value: u32) -> Result<(), NativeError>  // 0 或 [68..=0xFFFF] Ok；其余 ERROR_INVALID_PARAMETER(87)
//
// 提权设计（W17-T 同款）：纯逻辑测试（restore 决策、apply 值校验）在非提权宿主上必须
// 全部通过；真实 MTU 变更测试经 require_admin 门禁（非提权记为
// [not_run/blocked_by_environment]，不伪造假绿），且只变更测试自建的 scratch Wintun
// adapter（WSP4 spike 同款：drop 创建者句柄即移除接口，MTU 状态随接口消失）；每个
// 变更测试同时把 MTU 显式恢复原值（所有路径清理）。

use std::ffi::c_void;
use std::path::Path;

use exv_vpn_win32_resource::mtu::{
    decide_restore, validate_mtu_value, MtuController, MtuFamily, MtuSnapshot, RestoreOutcome,
};
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
const PURE_TEST_LUID: u64 = 0x1234_5678_9ABC_DEF0;
/// WSP4 冻结基准：Wintun 接口 v4/v6 行 NlMtu = 0xFFFF（Wintun 最大包）。
const WINTUN_BASELINE_MTU: u32 = 65535;
/// IPv4 最小 MTU（低于 68 的 Set 返回 ERROR_INVALID_PARAMETER(87)，WSP4 实测）。
const ERROR_INVALID_PARAMETER: u32 = 87;

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

/// 当前进程是否 elevated（admin token）——模式与 W16-T / W17-T / WSP3 spike 一致。
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
        "[not_run/blocked_by_environment] {test}: 创建 scratch Wintun adapter 并修改其 \
         interface MTU 需要提权（elevated admin token）；当前进程非 elevated，跳过动态断言"
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

/// 创建真实 adapter（创建者 owned；drop 即移除 adapter——scratch 接口，MTU 变更随接口消失）。
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

/// 在 scratch adapter 的接口上构造 MTU controller（WSP4 冻结：v4/v6 行均可读写）。
fn controller_for(adapter: &WintunAdapter, family: MtuFamily) -> MtuController {
    MtuController::new(adapter.luid(), family)
}

// ---------------------------------------------------------------------------
// 纯逻辑契约（非提权宿主必须全部通过；不触碰 OS）
// ---------------------------------------------------------------------------

/// compare-and-restore 决策：当前值 == applied 值（自 apply 后未被第三方修改）时必须
/// Restored。杀死 'unmodified case skipped / 该恢复不恢复'。
#[test]
fn restore_decision_restores_when_unmodified() {
    let original = MtuSnapshot::new(PURE_TEST_LUID, MtuFamily::V4, WINTUN_BASELINE_MTU);
    let applied = MtuSnapshot::new(PURE_TEST_LUID, MtuFamily::V4, 1420);
    let current = MtuSnapshot::new(PURE_TEST_LUID, MtuFamily::V4, 1420); // 仍是我们设的值
    assert_eq!(
        decide_restore(&applied, &current),
        RestoreOutcome::Restored,
        "current == applied（无第三方修改）时必须恢复原始快照"
    );
    // applied == original == current（同值）：Set 幂等（WSP4 事实），仍必须 Restored。
    assert_eq!(
        decide_restore(&original, &original),
        RestoreOutcome::Restored,
        "同值再 Set 幂等成功：applied == original 也必须 Restored"
    );
}

/// compare-and-restore 决策：当前值 != applied 值（第三方已改值）时必须
/// SkippedThirdPartyChanged。杀死 'unconditional restore'（W19 killer mutant）——
/// 无条件恢复旧快照会覆盖第三方变更 1400。
#[test]
fn restore_decision_skips_when_third_party_changed() {
    let original = MtuSnapshot::new(PURE_TEST_LUID, MtuFamily::V4, WINTUN_BASELINE_MTU);
    let applied = MtuSnapshot::new(PURE_TEST_LUID, MtuFamily::V4, 1420);
    let current = MtuSnapshot::new(PURE_TEST_LUID, MtuFamily::V4, 1400); // 第三方改值
    assert_eq!(
        decide_restore(&applied, &current),
        RestoreOutcome::SkippedThirdPartyChanged,
        "current != applied（第三方改值）时必须跳过恢复；无条件恢复会 clobber 第三方值"
    );
    // 第三方恰好改回 original 也视为改值（current != applied）——跳过仍安全。
    let back_to_original = MtuSnapshot::new(PURE_TEST_LUID, MtuFamily::V4, WINTUN_BASELINE_MTU);
    assert_eq!(
        decide_restore(&applied, &back_to_original),
        RestoreOutcome::SkippedThirdPartyChanged,
        "current != applied 一律跳过恢复（决策只比较 applied 与 current）"
    );
}

/// apply 值校验（apply 的纯逻辑前置）：0（无操作）与 [68..=65535] 合法；低于 IPv4 最小
/// 68 的 1/67 必须 ERROR_INVALID_PARAMETER(87)。杀死 'illegal value accepted by planning'。
#[test]
fn apply_value_validation_enforces_frozen_rules() {
    for (v, ctx) in [
        (0u32, "0 = 无操作（成功，回读保持上一个值）"),
        (68u32, "68 = IPv4 最小边界，合法"),
        (576u32, "576（WSP4 实测可写）"),
        (WINTUN_BASELINE_MTU, "65535 = Wintun 最大包"),
    ] {
        validate_mtu_value(v).unwrap_or_else(|e| {
            panic!("validate_mtu_value({v}): {ctx} 必须 Ok，得到 Err({e:?})")
        });
    }
    for (v, ctx) in [
        (1u32, "1 = 低于 IPv4 最小 68"),
        (67u32, "67 = 低于 IPv4 最小 68"),
    ] {
        let e = expect_native_error(validate_mtu_value(v), "validate_mtu_value 非法值");
        assert_eq!(
            e.code, ERROR_INVALID_PARAMETER,
            "{ctx} 必须 ERROR_INVALID_PARAMETER(87), got {}",
            e.code
        );
    }
}

// ---------------------------------------------------------------------------
// 真实 MTU 契约（需要 admin；非 elevated 记为 not_run）
// ---------------------------------------------------------------------------

/// capture 真实 GetIpInterfaceEntry：scratch Wintun adapter 接口 v4/v6 行基准
/// NlMtu=65535（0xFFFF），快照必须回显 family/luid/value。
/// 杀死 'capture 读错行 / 快照身份字段丢失'。
#[test]
fn capture_reads_wintun_baseline_65535_v4_and_v6() {
    if !require_admin("capture_reads_wintun_baseline_65535_v4_and_v6") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW19Baseline");
    let luid = adapter.luid();

    let v4 = controller_for(&adapter, MtuFamily::V4);
    let snap4 = expect_ok(v4.capture(), "capture v4 MTU");
    assert_eq!(snap4.family, MtuFamily::V4, "v4 快照 family 必须回显 V4");
    assert_eq!(snap4.luid, luid, "v4 快照 luid 必须回显 adapter LUID");
    assert_eq!(
        snap4.value, WINTUN_BASELINE_MTU,
        "Wintun 接口 v4 基准 MTU = 0xFFFF"
    );

    let v6 = controller_for(&adapter, MtuFamily::V6);
    let snap6 = expect_ok(v6.capture(), "capture v6 MTU");
    assert_eq!(snap6.family, MtuFamily::V6, "v6 快照 family 必须回显 V6");
    assert_eq!(
        snap6.value, WINTUN_BASELINE_MTU,
        "Wintun 接口 v6 基准 MTU = 0xFFFF"
    );
    // 只读测试无状态变更；drop adapter（创建者 close 移除接口）。
    drop(adapter);
}

/// apply 后 read_back 必须等于所设值（v4 与 v6 行均可写，WSP4 冻结）。apply 必须
/// Set 前强制 SitePrefixLength=0——若 impl 忘记清零，SetIpInterfaceEntry 返回 87，
/// expect_ok 立即失败。杀死 'SitePrefixLength 未清零 / apply 无效（87）'。
#[test]
fn apply_then_read_back_roundtrips_v4_and_v6() {
    if !require_admin("apply_then_read_back_roundtrips_v4_and_v6") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW19Roundtrip");

    for family in [MtuFamily::V4, MtuFamily::V6] {
        let c = controller_for(&adapter, family);
        let original = expect_ok(c.capture(), "capture 原始 MTU");
        expect_ok(c.apply(1420), "apply NlMtu=1420 必须成功（Set 前强制 SitePrefixLength=0）");
        assert_eq!(
            expect_ok(c.read_back(), "read_back 1420"),
            1420,
            "Set 后回读必须等于所设值 1420"
        );
        // 清理：显式恢复原始 MTU（所有变更路径都恢复）。
        expect_ok(c.apply(original.value), "清理：恢复原始 MTU");
        assert_eq!(
            expect_ok(c.read_back(), "read_back 恢复后"),
            original.value,
            "恢复后回读必须等于原始值"
        );
    }
    drop(adapter);
}

/// MTU=0 是无操作（WSP4 实测冻结）：Set(0) 返回 Ok 但回读保持上一个值（不重置默认）。
/// 杀死 '0 被当作重置为默认'。
#[test]
fn apply_zero_is_noop_keeps_previous_value() {
    if !require_admin("apply_zero_is_noop_keeps_previous_value") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW19ZeroNoop");
    let c = controller_for(&adapter, MtuFamily::V4);
    let original = expect_ok(c.capture(), "capture 原始 MTU");

    expect_ok(c.apply(1420), "apply 1420");
    expect_ok(c.apply(0), "apply 0 必须成功（无操作语义，不得 Err）");
    assert_eq!(
        expect_ok(c.read_back(), "Set(0) 后回读"),
        1420,
        "实测冻结：Set(0) 后回读保持上一个值 1420，不重置为默认"
    );

    expect_ok(c.apply(original.value), "清理：恢复原始 MTU");
    drop(adapter);
}

/// 低于 IPv4 最小 MTU 68 的 Set 必须返回 ERROR_INVALID_PARAMETER(87)（WSP4 实测冻结）。
/// 杀死 'illegal value accepted by the OS path'。
#[test]
fn apply_below_ipv4_minimum_returns_error_87() {
    if !require_admin("apply_below_ipv4_minimum_returns_error_87") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW19Illegal");
    let c = controller_for(&adapter, MtuFamily::V4);
    let original = expect_ok(c.capture(), "capture 原始 MTU");

    let e = expect_native_error(c.apply(1), "apply MTU=1（低于 IPv4 最小 68）");
    assert_eq!(
        e.code, ERROR_INVALID_PARAMETER,
        "MTU=1 必须 ERROR_INVALID_PARAMETER(87), got {}",
        e.code
    );
    // 非法值不得产生副作用：回读仍是原始值。
    assert_eq!(
        expect_ok(c.read_back(), "非法 Set 后回读"),
        original.value,
        "非法 Set 不得改变接口状态"
    );

    expect_ok(c.apply(original.value), "清理：恢复原始 MTU（幂等）");
    drop(adapter);
}

/// read_back 必须是真实 Get（不得缓存/信任本地状态）：独立 controller（第三方路径）改值
/// 1400 后，我们的 read_back 必须检测到 1400 != 1420。杀死 'read-back 用缓存值/本地状态'。
#[test]
fn read_back_detects_third_party_change() {
    if !require_admin("read_back_detects_third_party_change") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW19ThirdParty");
    let c = controller_for(&adapter, MtuFamily::V4);
    let third_party = controller_for(&adapter, MtuFamily::V4); // 独立实例 = 独立系统路径
    let original = expect_ok(c.capture(), "capture 原始 MTU");

    expect_ok(c.apply(1420), "apply 1420");
    expect_ok(third_party.apply(1400), "第三方独立 Set 1400");
    assert_eq!(
        expect_ok(c.read_back(), "第三方改值后 read_back"),
        1400,
        "第三方改值后回读必须检测到（1400 ≠ 我们的 1420）——read_back 不得返回缓存/本地状态"
    );

    expect_ok(c.apply(original.value), "清理：恢复原始 MTU");
    drop(adapter);
}

/// compare-and-restore 完整流：第三方改值后必须 SkippedThirdPartyChanged，且第三方值
/// 1400 保持（不得被 clobber 回 65535）。杀死 'unconditional restore'（W19 killer
/// mutant，集成级验证）。
#[test]
fn compare_and_restore_skips_after_third_party_change() {
    if !require_admin("compare_and_restore_skips_after_third_party_change") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW19RestoreSkip");
    let c = controller_for(&adapter, MtuFamily::V4);
    let third_party = controller_for(&adapter, MtuFamily::V4);
    let original = expect_ok(c.capture(), "capture 原始 MTU（基准 65535）");
    assert_eq!(original.value, WINTUN_BASELINE_MTU, "scratch 接口基准必须是 0xFFFF");

    expect_ok(c.apply(1420), "apply 1420");
    expect_ok(third_party.apply(1400), "第三方改值 1400");
    let applied = MtuSnapshot::new(adapter.luid(), MtuFamily::V4, 1420);
    let outcome = expect_ok(
        c.compare_and_restore(&applied, &original),
        "compare_and_restore 必须成功返回决策",
    );
    assert_eq!(
        outcome,
        RestoreOutcome::SkippedThirdPartyChanged,
        "第三方改值后 current != applied：必须跳过恢复（无条件恢复旧快照 = mutant，会覆盖 1400）"
    );
    assert_eq!(
        expect_ok(c.read_back(), "跳过恢复后回读"),
        1400,
        "跳过恢复后第三方值 1400 必须保持（不得被 clobber 回 65535）"
    );

    expect_ok(c.apply(original.value), "清理：恢复原始 MTU");
    drop(adapter);
}

/// compare-and-restore 完整流：未被第三方修改时必须 Restored，回读验证回到原始值
/// （WSP4 事实：Set 回 65535 → 回读 65535，verified=true）。
/// 杀死 'restore 不实际写 / 恢复写错值'。
#[test]
fn compare_and_restore_restores_original_when_unmodified() {
    if !require_admin("compare_and_restore_restores_original_when_unmodified") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW19RestoreOk");
    let c = controller_for(&adapter, MtuFamily::V4);
    let original = expect_ok(c.capture(), "capture 原始 MTU（基准 65535）");

    expect_ok(c.apply(1420), "apply 1420");
    let applied = MtuSnapshot::new(adapter.luid(), MtuFamily::V4, 1420);
    let outcome = expect_ok(
        c.compare_and_restore(&applied, &original),
        "compare_and_restore 必须成功返回决策",
    );
    assert_eq!(
        outcome,
        RestoreOutcome::Restored,
        "current == applied（未被第三方修改）时必须恢复原始快照"
    );
    assert_eq!(
        expect_ok(c.read_back(), "恢复后回读"),
        original.value,
        "compare-and-restore 后 MTU 必须回到基准值 65535（verified=true）"
    );

    drop(adapter);
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
