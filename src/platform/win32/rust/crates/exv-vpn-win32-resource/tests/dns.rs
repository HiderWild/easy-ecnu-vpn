// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W21-T Terra: DNS settings 契约（GUID 键控 capture / apply / applied fingerprint /
// third-party conflict / compare-and-restore）。这些测试钉住 W21-I 在
// exv_vpn_win32_resource::{dns, dns_types} 实现的 seam。冻结事实
// （docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md，
// WSP4 提权实测）是契约：
//   - Get 语义：原地填充调用方结构（Version=1，与 windows crate 0.62.2 的
//     DNS_INTERFACE_SETTINGS v1 布局一致；0 → 87），Flags 必须为空；内嵌字符串由系统
//     分配，用毕必须 FreeInterfaceDnsSettings 释放；
//   - Flags 文档值（实测修正）：DNS_SETTING_NAMESERVER=0x0002、DNS_SETTING_SEARCHLIST=0x0004
//     （0x0001 是 DNS_SETTING_IPV6——用错 87）；windows crate 0.62.2 未导出，需手写；
//   - v2 布局（实测修正）：VERSION2 = DNS_INTERFACE_SETTINGS_EX（80 字节，
//     NameServer/SearchList 仍是**字符串**）；误按 DNS_ADDRESS_ARRAY（104 字节）构造会
//     让 Set 把 @24 的 {ver,count} 当 PWSTR 解引用 → AV 0xC0000005；
//   - apply/read-back：Set v1（Version=1，flags=0x6，ns=10.88.88.53，search=exv.test）
//     rc=0；回读 fingerprint ns=[10.88.88.53]、search=[exv.test]（回读 flags=0）；
//   - 第三方冲突：独立 Set 改 10.88.88.54 → 回读 ≠ 我们的值；同值再 Set 幂等；
//   - partial/unknown：nameserver 非 IP（"not-an-ip"）→ 87；
//   - mutant（无条件恢复旧快照 = 反例）：第三方改值后当前状态 ≠ 原始快照 →
//     compare-and-restore 必须**跳过**恢复（无条件恢复会覆盖第三方变更）；随后显式清理
//     （空字符串指针 + flags 置位 = 清空语义；NULL 指针不清除且返回 87）→ 最终
//     fingerprint == 原始；
//   - 恢复失败是类型化错误（restore_failures），不得静默。
//
// W21-I pinned seam（src/dns_types.rs + src/dns.rs）：
//   dns_types::DnsSettings { pub nameservers: Vec<String>, pub search_suffixes: Vec<String> }
//     （Clone/Debug/PartialEq/Eq）；DnsSettings::new(nameservers, search_suffixes) -> Self
//   dns_types::DnsFingerprint（Clone/Debug/PartialEq/Eq，不透明值）；
//     DnsFingerprint::of(&DnsSettings) -> Self —— nameservers + search_suffixes 的确定性
//     指纹，**顺序敏感**（WSP4 回读是精确列表；排序指纹会掩盖第三方重排）
//   dns_types::RestoreDecision { Restore, SkipThirdPartyChange }（Clone/Debug/PartialEq/Eq）；
//     RestoreDecision::plan(current: &DnsFingerprint, applied: &DnsFingerprint) -> Self
//     —— 当前 == applied 才 Restore；当前 != applied（第三方改过）→ SkipThirdPartyChange
//   dns::DnsCapture::capture(interface_guid: &GUID) -> Result<DnsSettings, NativeError>
//     —— GUID 键控：GetInterfaceDnsSettings 原地填充 + FreeInterfaceDnsSettings 释放
//   dns::DnsApplier::apply(interface_guid: &GUID, desired: &DnsSettings)
//     -> Result<DnsFingerprint, NativeError> —— Set + 独立回读，返回 **applied 指纹**
//     （API success 不等于 proof；W21 不得用 API success 代替 proof）
//   dns::DnsApplier::restore(interface_guid: &GUID, applied: &DnsFingerprint,
//     original: &DnsSettings) -> Result<RestoreDecision, NativeError>
//     —— compare-and-restore：先比较当前状态与 applied 指纹，相等才恢复 original；
//     第三方已修改 → Ok(SkipThirdPartyChange)（typed 冲突，不得覆盖）；失败是类型化
//     Err（restore_failures），不得静默
//
// 纯逻辑测试（指纹比较 / restore 计划）在任何宿主都必须通过。真实 DNS mutation 测试
// 在探针自建的 scratch Wintun adapter（WSP4 冻结动态加载路径）上运行，需要 admin；
// 非 elevated 宿主上短路为 `not_run / blocked_by_environment`（明确输出，不伪造假绿）。
// 每个 mutation 测试：创建 scratch adapter → 捕获原始 DNS → 断言 → 恢复原始状态 →
// 创建者 close 移除 adapter（无残留）；DnsCleanupGuard 保证 panic/早退路径也恢复。

use std::ffi::{c_void, CString};
use std::path::{Path, PathBuf};

use exv_vpn_win32_resource::dns::{DnsApplier, DnsCapture};
use exv_vpn_win32_resource::dns_types::{DnsFingerprint, DnsSettings, RestoreDecision};
use exv_vpn_win32_resource::native_error::NativeError;

use windows::core::{GUID, HSTRING, PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, FreeLibrary, GetLastError, HANDLE, HMODULE};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToGuid, SetInterfaceDnsSettings, DNS_INTERFACE_SETTINGS,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 冻结的 amd64 wintun-0.14.1 DLL 精确路径（WSP4 冻结路径；PATH DLL 是 mutant）。
const FROZEN_DLL_PATH: &str = "C:\\Users\\TomLi\\.exv\\wintun\\wintun\\bin\\amd64\\wintun.dll";
/// WintunCreateAdapter 的 TunnelType 参数（WSP4 冻结值）。
const TUNNEL_TYPE: &str = "EXV VPN";
/// DNS 测试值（WSP4 冻结）：应用 / 第三方改值 / search suffix。
const SPARK_DNS_SERVER: &str = "10.88.88.53";
const SPARK_DNS_SERVER_TP: &str = "10.88.88.54";
const SPARK_DNS_SEARCH: &str = "exv.test";
/// DNS_INTERFACE_SETTINGS Flags（windows crate 0.62.2 未导出，需手写）：
/// 0x0001 是 DNS_SETTING_IPV6；0x0002 = NAMESERVER；0x0004 = SEARCHLIST（WSP4 实测修正）。
const DNS_FLAG_NAMESERVER: u64 = 0x0002;
const DNS_FLAG_SEARCH_LIST: u64 = 0x0004;

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

/// 当前进程是否 elevated（admin token）——模式与 W16-T / W17-T / WSP4 spike 一致。
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
        "[not_run/blocked_by_environment] {test}: 创建 scratch adapter 并修改 DNS 需要提权 \
         （elevated admin token）；当前进程非 elevated，跳过动态断言"
    );
    false
}

/// Wintun 动态加载的最小函数集（WSP4 冻结路径；仅用于创建 scratch adapter）。
type WintunCreateAdapterFn = unsafe extern "system" fn(PCWSTR, PCWSTR, *const GUID) -> *mut c_void;
type WintunGetAdapterLuidFn = unsafe extern "system" fn(*mut c_void, *mut NET_LUID_LH) -> i32;
type WintunCloseAdapterFn = unsafe extern "system" fn(*mut c_void);

struct WintunFns {
    hmod: HMODULE,
    create: WintunCreateAdapterFn,
    get_luid: WintunGetAdapterLuidFn,
    close: WintunCloseAdapterFn,
}

/// 加载冻结的 wintun.dll（路径：EXV_RUST_VPN_WINTUN_DLL > 冻结默认值，WSP3/WSP4 语义）。
fn load_wintun(path: &Path) -> Result<WintunFns, String> {
    let h = HSTRING::from(path.as_os_str());
    // SAFETY: h 是合法宽字符串路径；返回模块句柄（0.62.2 绑定返回 Result）。
    let hmod = match unsafe { LoadLibraryW(&h) } {
        Ok(m) => m,
        Err(e) => return Err(format!("LoadLibraryW {} failed: {e}", path.display())),
    };
    let resolve = |name: &str| -> Result<unsafe extern "system" fn() -> isize, String> {
        let cname = CString::new(name).map_err(|e| e.to_string())?;
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
    Ok(WintunFns {
        hmod,
        create,
        get_luid,
        close,
    })
}

/// scratch Wintun adapter 句柄；drop 时创建者 close = 移除 adapter（无残留）。
struct ScratchAdapter {
    fns: WintunFns,
    handle: *mut c_void,
}

impl ScratchAdapter {
    /// 接口 GUID（DNS API 的键；WSP4 冻结：LUID → ConvertInterfaceLuidToGuid）。
    fn guid(&self) -> Option<GUID> {
        let mut luid = NET_LUID_LH::default();
        // SAFETY: luid 由系统填充（WintunGetAdapterLUID 写入）。
        let ok = unsafe { (self.fns.get_luid)(self.handle, &mut luid) };
        if ok != 0 {
            return None;
        }
        let mut guid = GUID::zeroed();
        // SAFETY: guid 由系统填充（ConvertInterfaceLuidToGuid 成功即有效 GUID）。
        if unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) }.0 != 0 {
            return None;
        }
        Some(guid)
    }
}

impl Drop for ScratchAdapter {
    fn drop(&mut self) {
        // SAFETY: handle 是 create 返回的有效 adapter 句柄；创建者 close 即移除 adapter。
        unsafe { (self.fns.close)(self.handle) };
        // SAFETY: hmod 是 LoadLibraryW 返回的模块句柄（close 后释放 DLL 引用）。
        unsafe { let _ = FreeLibrary(self.fns.hmod); }
    }
}

/// 创建探针自建的 scratch Wintun adapter（WSP4 冻结路径：动态加载 + RequestedGUID=NULL
/// 让系统随机选 GUID）。失败（DLL 缺失 / create 失败）时输出
/// `not_run/blocked_by_environment` 并返回 None——诚实短路，不伪造动态断言。
fn create_scratch(tag: &str) -> Option<ScratchAdapter> {
    let path = std::env::var_os("EXV_RUST_VPN_WINTUN_DLL")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(FROZEN_DLL_PATH));
    let fns = match load_wintun(&path) {
        Ok(f) => f,
        Err(msg) => {
            eprintln!("[not_run/blocked_by_environment] {tag}: 无法加载 wintun.dll：{msg}");
            return None;
        }
    };
    let name = format!("ExvW21-{tag}-{}", std::process::id());
    let name_h = HSTRING::from(&name);
    let tunnel = HSTRING::from(TUNNEL_TYPE);
    // SAFETY: name/tunnel 是合法宽字符串；RequestedGUID=NULL 让系统随机选 GUID（WSP4 冻结）。
    let handle = unsafe {
        (fns.create)(
            PCWSTR::from_raw(name_h.as_ptr()),
            PCWSTR::from_raw(tunnel.as_ptr()),
            std::ptr::null(),
        )
    };
    if handle.is_null() {
        // SAFETY: 纯读线程错误码。
        let err = unsafe { GetLastError().0 };
        eprintln!(
            "[not_run/blocked_by_environment] {tag}: WintunCreateAdapter({name}) 失败（错误 \
             {err}）；跳过动态断言"
        );
        return None;
    }
    Some(ScratchAdapter { fns, handle })
}

/// v1 DNS settings 结构（字符串格式；空串 = 清空该设置）。
/// 返回 (结构, 保持字符串生命的 HSTRING 列表)——调用方必须在 SetInterfaceDnsSettings
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

/// v2(EX) DNS settings 结构（手动构造完整 80 字节 DNS_INTERFACE_SETTINGS_EX 布局，x64；
/// WSP4 实测修正：VERSION2 = { SettingsV1（64 字节，NameServer/SearchList 仍是字符串）+
/// DisableUnconstrainedQueries + SupplementalSearchList }；误按 DNS_ADDRESS_ARRAY（104
/// 字节）构造会让 Set 把 @24 处 {ver,count} 当 PWSTR 解引用 → AV 0xC0000005）。
/// 带显式 flags：清空场景需要 flags 置位但字符串为空（空字符串指针 = 清空语义；
/// NULL 指针不清除且返回 87）。
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

/// Set 接口 DNS 设置（nameserver + search suffix；空串 = 清空该设置）。
/// WSP4 实测：先试 v1（本宿主可用），失败回退 v2(EX) 全布局。
fn raw_set_dns(guid: &GUID, nameserver: &str, search: &str) -> Result<(), u32> {
    let (s1, keep1) = dns_settings_v1(nameserver, search);
    // SAFETY: s1 是合法 v1 结构（keep1 在调用期间存活）。
    let rc1 = unsafe { SetInterfaceDnsSettings(*guid, &s1).0 };
    drop(keep1);
    if rc1 == 0 {
        return Ok(());
    }
    let mut flags = 0u64;
    if !nameserver.is_empty() {
        flags |= DNS_FLAG_NAMESERVER;
    }
    if !search.is_empty() {
        flags |= DNS_FLAG_SEARCH_LIST;
    }
    let (b2, keep2) = dns_settings_v2_raw_flags(nameserver, search, flags);
    // SAFETY: b2 是完整 v2(EX) 布局（80 字节零填充；keep2 在调用期间存活）。
    let rc2 = unsafe { SetInterfaceDnsSettings(*guid, b2.as_ptr().cast()).0 };
    drop(keep2);
    if rc2 == 0 {
        Ok(())
    } else {
        Err(rc2)
    }
}

/// 清空接口 DNS 设置（nameserver + search suffix）——显式带 NAMESERVER|SEARCH_LIST flags，
/// 空字符串指针 = 清空语义（NULL 指针不清除且返回 87，WSP4 实测）。
fn raw_clear_dns(guid: &GUID) -> Result<(), u32> {
    let (b, keep) = dns_settings_v2_raw_flags("", "", DNS_FLAG_NAMESERVER | DNS_FLAG_SEARCH_LIST);
    // SAFETY: b 是完整 v2(EX) 布局（80 字节零填充；keep 在调用期间存活）。
    let rc = unsafe { SetInterfaceDnsSettings(*guid, b.as_ptr().cast()).0 };
    drop(keep);
    if rc == 0 {
        Ok(())
    } else {
        Err(rc)
    }
}

/// 每个 mutation 测试的清理兜底：drop 时把 scratch 接口的 DNS 恢复为测试前捕获的原始
/// 值（原始为空 = 显式清空：空字符串指针 + flags 置位，NULL 无效）。恢复失败只记录不
/// panic——真正的恢复证明由各测试断言，guard 保证任何 panic/早退路径都不残留。
struct DnsCleanupGuard {
    guid: GUID,
    original: DnsSettings,
}

impl DnsCleanupGuard {
    fn new(guid: GUID) -> Self {
        // 测试开始前捕获原始状态（与 WSP4 spike 的 dns.before 语义一致）。
        let original = expect_ok(DnsCapture::capture(&guid), "capture 原始 DNS 状态");
        Self { guid, original }
    }
}

impl Drop for DnsCleanupGuard {
    fn drop(&mut self) {
        let result =
            if self.original.nameservers.is_empty() && self.original.search_suffixes.is_empty() {
                raw_clear_dns(&self.guid)
            } else {
                raw_set_dns(
                    &self.guid,
                    &self.original.nameservers.join(" "),
                    &self.original.search_suffixes.join(" "),
                )
            };
        if let Err(rc) = result {
            eprintln!("[cleanup] DNS 恢复失败 rc={rc}");
        }
    }
}

// ---------------------------------------------------------------------------
// 纯逻辑契约（任何宿主都必须通过；不触碰系统状态）
// ---------------------------------------------------------------------------

/// 指纹必须钉住 nameservers + search suffixes（任一变化 → 指纹不同）。
/// 杀死 'fingerprint 不追踪 / 折叠设置值'。
#[test]
fn fingerprint_pins_servers_and_suffixes() {
    let base = DnsSettings::new(
        vec![SPARK_DNS_SERVER.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    );
    let same = DnsSettings::new(
        vec![SPARK_DNS_SERVER.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    );
    assert_eq!(
        DnsFingerprint::of(&base),
        DnsFingerprint::of(&same),
        "相同 servers/suffixes 必须产生相同指纹"
    );

    let other_server = DnsSettings::new(
        vec![SPARK_DNS_SERVER_TP.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    );
    assert_ne!(
        DnsFingerprint::of(&base),
        DnsFingerprint::of(&other_server),
        "nameserver 不同必须产生不同指纹（否则第三方改 nameserver 无法检测）"
    );

    let other_suffix = DnsSettings::new(
        vec![SPARK_DNS_SERVER.to_string()],
        vec!["other.example".to_string()],
    );
    assert_ne!(
        DnsFingerprint::of(&base),
        DnsFingerprint::of(&other_suffix),
        "search suffix 不同必须产生不同指纹（否则第三方改 suffix 无法检测）"
    );
}

/// 指纹顺序敏感：相同集合不同顺序 → 不同指纹（WSP4 回读是精确列表；排序指纹会掩盖
/// 第三方重排）。
/// 杀死 '排序指纹掩盖重排'。
#[test]
fn fingerprint_is_order_sensitive() {
    let ab = DnsSettings::new(
        vec![SPARK_DNS_SERVER.to_string(), SPARK_DNS_SERVER_TP.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    );
    let ba = DnsSettings::new(
        vec![SPARK_DNS_SERVER_TP.to_string(), SPARK_DNS_SERVER.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    );
    assert_ne!(
        DnsFingerprint::of(&ab),
        DnsFingerprint::of(&ba),
        "相同集合不同顺序必须产生不同指纹（回读精确列表语义）"
    );
}

/// compare-and-restore 计划：当前状态 ≠ applied 指纹（第三方改过）→ SkipThirdPartyChange。
/// 杀死 '无条件恢复旧快照'（纯逻辑半边：恢复前必须比较当前状态与快照）。
#[test]
fn restore_plan_skips_on_third_party_change() {
    let applied = DnsFingerprint::of(&DnsSettings::new(
        vec![SPARK_DNS_SERVER.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    ));
    let third_party = DnsFingerprint::of(&DnsSettings::new(
        vec![SPARK_DNS_SERVER_TP.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    ));
    assert_eq!(
        RestoreDecision::plan(&third_party, &applied),
        RestoreDecision::SkipThirdPartyChange,
        "当前状态 != applied 指纹时必须跳过恢复（无条件恢复会覆盖第三方变更 = mutant）"
    );
}

/// compare-and-restore 计划：当前状态 == applied 指纹（未被动过）→ Restore。
/// 杀死 '总是跳过 / 永不恢复'。
#[test]
fn restore_plan_restores_when_unmodified() {
    let applied = DnsFingerprint::of(&DnsSettings::new(
        vec![SPARK_DNS_SERVER.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    ));
    assert_eq!(
        RestoreDecision::plan(&applied, &applied),
        RestoreDecision::Restore,
        "当前状态 == applied 指纹时必须恢复原始快照"
    );
}

// ---------------------------------------------------------------------------
// 真实 DNS mutation 契约（需要 admin；非 elevated 记为 not_run）
// ---------------------------------------------------------------------------

/// capture 是 GUID 键控的：对 scratch 接口 apply 后，capture 必须精确回读 nameservers +
/// search suffixes（顺序保持）。杀死 'capture 回错接口 / 丢 suffix'。
#[test]
fn capture_reads_guid_keyed_servers_and_suffixes() {
    if !require_admin("capture_reads_guid_keyed_servers_and_suffixes") {
        return;
    }
    let Some(adapter) = create_scratch("capture") else {
        return;
    };
    let guid = adapter.guid().expect("scratch adapter LUID -> GUID");
    let guard = DnsCleanupGuard::new(guid);

    let desired = DnsSettings::new(
        vec![SPARK_DNS_SERVER.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    );
    expect_ok(DnsApplier::apply(&guid, &desired), "apply 已知 DNS 值");

    let got = expect_ok(DnsCapture::capture(&guid), "capture 回读");
    assert_eq!(
        got.nameservers,
        vec![SPARK_DNS_SERVER.to_string()],
        "回读 nameservers 必须等于所设值（GUID 键控，顺序保持）"
    );
    assert_eq!(
        got.search_suffixes,
        vec![SPARK_DNS_SEARCH.to_string()],
        "回读 search suffixes 必须等于所设值"
    );
    drop(guard);
}

/// apply 必须返回 **applied 指纹**（Set 后独立回读的指纹），不是 desired 的想当然值——
/// API success 不等于 proof（W21 不得用 API success 代替 proof）。同值再 apply 幂等。
/// 杀死 'applied 指纹未追踪 / 伪造指纹'。
#[test]
fn apply_returns_applied_fingerprint_matching_readback() {
    if !require_admin("apply_returns_applied_fingerprint_matching_readback") {
        return;
    }
    let Some(adapter) = create_scratch("apply-fp") else {
        return;
    };
    let guid = adapter.guid().expect("scratch adapter LUID -> GUID");
    let guard = DnsCleanupGuard::new(guid);

    let desired = DnsSettings::new(
        vec![SPARK_DNS_SERVER.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    );
    let applied = expect_ok(DnsApplier::apply(&guid, &desired), "apply");
    // 独立回读（不经 apply 返回值）：applied 指纹必须等于独立回读的指纹。
    let readback = expect_ok(DnsCapture::capture(&guid), "独立回读");
    assert_eq!(
        applied,
        DnsFingerprint::of(&readback),
        "apply 返回的指纹必须是 Set 后的真实回读指纹（API success 不是 proof）"
    );

    // 同值再 apply：幂等成功，且指纹与上次 applied 一致（WSP4: 同值再 Set 幂等）。
    let reapplied = expect_ok(DnsApplier::apply(&guid, &desired), "同值再 apply");
    assert_eq!(
        reapplied, applied,
        "同值再 apply 必须幂等（指纹不变）"
    );
    drop(guard);
}

/// 第三方修改检测 + compare-and-restore：第三方（独立原始路径）改值后 restore 必须
/// 跳过（typed SkipThirdPartyChange）且不得覆盖第三方值（回读仍 = 第三方值）。
/// 杀死 '无条件恢复旧快照'（native 半边）+ '覆盖第三方冲突'。
#[test]
fn third_party_change_restore_skips_and_preserves() {
    if !require_admin("third_party_change_restore_skips_and_preserves") {
        return;
    }
    let Some(adapter) = create_scratch("tp-conflict") else {
        return;
    };
    let guid = adapter.guid().expect("scratch adapter LUID -> GUID");
    let guard = DnsCleanupGuard::new(guid);
    let original = expect_ok(DnsCapture::capture(&guid), "capture 原始状态");

    let desired = DnsSettings::new(
        vec![SPARK_DNS_SERVER.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    );
    let applied = expect_ok(DnsApplier::apply(&guid, &desired), "apply");

    // 第三方：独立路径（原始 Set，不经 seam）改 nameserver。
    raw_set_dns(&guid, SPARK_DNS_SERVER_TP, SPARK_DNS_SEARCH)
        .unwrap_or_else(|rc| panic!("第三方 Set 失败 rc={rc}"));

    let decision = expect_ok(
        DnsApplier::restore(&guid, &applied, &original),
        "compare-and-restore",
    );
    assert_eq!(
        decision,
        RestoreDecision::SkipThirdPartyChange,
        "第三方改值后必须跳过恢复（typed 冲突，不得覆盖）"
    );
    let after = expect_ok(DnsCapture::capture(&guid), "restore 后回读");
    assert_eq!(
        after.nameservers,
        vec![SPARK_DNS_SERVER_TP.to_string()],
        "跳过恢复后第三方值必须原样保留（无条件恢复旧快照会覆盖它 = mutant）"
    );
    drop(guard);
}

/// compare-and-restore 正例：未被动过的接口 restore 必须恢复原始快照（回读 == 原始
/// 指纹）。杀死 '总是跳过 / 永不恢复'（native 半边）。
#[test]
fn restore_restores_original_when_unmodified() {
    if !require_admin("restore_restores_original_when_unmodified") {
        return;
    }
    let Some(adapter) = create_scratch("restore-ok") else {
        return;
    };
    let guid = adapter.guid().expect("scratch adapter LUID -> GUID");
    let guard = DnsCleanupGuard::new(guid);
    let original = expect_ok(DnsCapture::capture(&guid), "capture 原始状态");
    let original_fp = DnsFingerprint::of(&original);

    let desired = DnsSettings::new(
        vec![SPARK_DNS_SERVER.to_string()],
        vec![SPARK_DNS_SEARCH.to_string()],
    );
    let applied = expect_ok(DnsApplier::apply(&guid, &desired), "apply");

    // 未被动过：compare-and-restore 必须恢复原始快照。
    let decision = expect_ok(
        DnsApplier::restore(&guid, &applied, &original),
        "compare-and-restore",
    );
    assert_eq!(
        decision,
        RestoreDecision::Restore,
        "当前状态 == applied 指纹时必须恢复原始快照"
    );
    let after = expect_ok(DnsCapture::capture(&guid), "restore 后回读");
    assert_eq!(
        DnsFingerprint::of(&after),
        original_fp,
        "恢复后必须回到原始快照（fingerprint 精确相等）"
    );
    drop(guard);
}

/// 恢复失败必须是类型化错误（restore_failures），不得静默——不存在的接口 GUID 上
/// restore 必须 Err(NativeError)（code != 0 且带信息），绝不 Ok/panic。
/// 杀死 '恢复失败静默 / panic'。
#[test]
fn restore_on_absent_interface_is_typed_error() {
    if !require_admin("restore_on_absent_interface_is_typed_error") {
        return;
    }
    // 固定但极不可能存在的接口 GUID（与 WSP4 的接口不存在 → 1168 语义一致；不是
    // scratch adapter 的 GUID）。
    let absent = GUID::from_values(0x57A3D54E, 0x3F4B, 0x4C7E, [
        0x8F, 0x2A, 0x9B, 0x1C, 0x2D, 0x3E, 0x4F, 0x50,
    ]);
    let original = DnsSettings::new(Vec::new(), Vec::new());
    let applied = DnsFingerprint::of(&original);
    let err = expect_native_error(
        DnsApplier::restore(&absent, &applied, &original),
        "restore 不存在的接口",
    );
    assert_ne!(err.code, 0, "恢复失败必须返回类型化 Err（code != 0），不得静默");
    assert!(
        !err.message.is_empty(),
        "类型化错误必须带诊断信息（不得空壳静默）"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
