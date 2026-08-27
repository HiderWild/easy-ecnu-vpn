// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W16-T Terra: Wintun adapter 加载/所有权/LUID 契约。这些测试钉住 W16-I 在
// exv_vpn_win32_resource::{wintun_api, wintun_adapter} 实现的 seam。冻结事实
// （docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-wintun-facts.md，
// WSP3 提权实测）是契约：
//   - DLL：amd64 wintun-0.14.1，SHA-256 e5da8447...dafce，Authenticode（DigiCert 2021）；
//     14 个导出全部可解析（含 WintunDeleteDriver）；WintunGetAdapterName 在 0.14.1 不存在；
//   - PATH DLL 是 mutant：只能按精确路径/哈希加载，绝不按 PATH 搜索；
//   - create-vs-open 所有权：open-before-create 失败 ERROR_NOT_FOUND(1168)；
//     创建后 open-by-name 成功（第二句柄，Opened 非 owned）；非创建者 close 不删除 adapter；
//     创建者 WintunCloseAdapter 即移除 adapter（0.14.1 无 delete-adapter 导出——真实清理谓词）；
//   - LUID 经 WintunGetAdapterLUID；ifindex 经 ConvertInterfaceLuidToIndex；
//     alias 经 ConvertInterfaceLuidToAlias。
//
// 本测试在真实 Windows 宿主上创建真实的 Wintun adapter（需要 admin）。每个测试
// 通过 Drop 释放全部句柄，由创建者 close 移除 adapter（无残留）。非 elevated 宿主
// 上动态断言短路为 `not_run / blocked_by_environment`（明确输出，不伪造假绿）；
// DLL 静态断言（哈希/导出/精确路径）任何宿主都必须成立。

use std::ffi::{c_void, CString};
use std::path::Path;

use exv_vpn_win32_resource::native_error::NativeError;
use exv_vpn_win32_resource::wintun_adapter::{AdapterOpen, WintunAdapter};
use exv_vpn_win32_resource::wintun_api::{WintunExports, WintunLibrary};

use sha2::{Digest, Sha256};
use windows::core::{HSTRING, PCSTR};
use windows::Win32::Foundation::{CloseHandle, FreeLibrary, HANDLE, HMODULE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 冻结的 amd64 wintun-0.14.1 DLL 精确路径（WSP3 冻结值；PATH DLL 是 mutant）。
const FROZEN_DLL_PATH: &str = "C:\\Users\\TomLi\\.exv\\wintun\\wintun\\bin\\amd64\\wintun.dll";
/// 冻结的 wintun.dll SHA-256（native-wintun-facts.md §1）。
const FROZEN_DLL_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
/// 0.14.1 实测存在的 14 个导出（native-wintun-facts.md §1）。
const WINTUN_EXPECTED_EXPORTS: [&str; 14] = [
    "WintunAllocateSendPacket",
    "WintunCloseAdapter",
    "WintunCreateAdapter",
    "WintunDeleteDriver",
    "WintunEndSession",
    "WintunGetAdapterLUID",
    "WintunGetReadWaitEvent",
    "WintunGetRunningDriverVersion",
    "WintunOpenAdapter",
    "WintunReceivePacket",
    "WintunReleaseReceivePacket",
    "WintunSendPacket",
    "WintunSetLogger",
    "WintunStartSession",
];
/// 0.14.1 不存在的导出（计划清单里提到但实测缺失；load 不得依赖它）。
const WINTUN_EXPORT_ABSENT: &str = "WintunGetAdapterName";
/// open 一个不存在的 adapter 的错误码（ERROR_NOT_FOUND）。
const ERROR_NOT_FOUND: u32 = 1168;
/// 与 WSP3 探针一致的 tunnel type。
const TUNNEL_TYPE: &str = "EXV VPN";

/// GetProcAddress 返回的裸函数指针（与 WSP3 探针一致）。
type ProcAddr = unsafe extern "system" fn() -> isize;

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

/// 当前进程是否 elevated（admin token）——模式来自 WSP3 spike
/// （exv-vpn-win32-acceptance/src/wintun_facts.rs::is_elevated）。
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
        "[not_run/blocked_by_environment] {test}: 创建/打开 Wintun adapter 需要提权 \
         （elevated admin token）；当前进程非 elevated，跳过动态断言"
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

/// 磁盘文件 SHA-256 十六进制（小写）。
fn sha256_hex(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("读取 DLL");
    let digest = Sha256::digest(&bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// 按精确绝对路径加载 DLL（与 WSP3 探针 load_library 一致）。
fn load_library_exact(path: &Path) -> HMODULE {
    let h = HSTRING::from(path.as_os_str());
    // SAFETY: h 是合法宽字符串路径；返回模块句柄。
    unsafe { LoadLibraryW(&h) }.expect("LoadLibraryW 精确路径")
}

/// GetProcAddress：按名称解析导出（与 WSP3 探针 get_export 一致）。
fn get_export(hmod: HMODULE, name: &str) -> Option<ProcAddr> {
    let cname = CString::new(name).ok()?;
    // SAFETY: hmod 有效；cname 是 NUL 结尾 ANSI 名称。CString::as_ptr 返回 *const i8，
    // PCSTR 期望 *const u8，转换是同一地址。
    unsafe { GetProcAddress(hmod, PCSTR::from_raw(cname.as_ptr().cast::<u8>())) }
}

// ---------------------------------------------------------------------------
// DLL 加载契约（任何宿主都必须成立，无需 admin）
// ---------------------------------------------------------------------------

/// 冻结 DLL 必须按精确哈希+完整导出表加载；`WintunGetAdapterName` 不被依赖。
#[test]
fn loads_frozen_dll_with_exact_hash_and_all_exports() {
    // 磁盘上就是冻结 DLL（哈希与冻结值一致）——防 'PATH DLL accepted / wrong hash'。
    assert_eq!(
        sha256_hex(Path::new(FROZEN_DLL_PATH)),
        FROZEN_DLL_SHA256,
        "wintun.dll 磁盘哈希必须等于冻结值 e5da8447..."
    );
    // seam：load 校验哈希、LoadLibraryW、解析全部 14 个导出；
    // WintunGetAdapterName 在 0.14.1 不存在，load 不得要求它（要求即 Err → 本断言失败）。
    let lib = load_frozen();
    let _exports: &WintunExports = lib.exports();
    // 独立核对（不依赖 W16-I 的字段命名）：14 个冻结导出全部可解析。
    let hmod = load_library_exact(Path::new(FROZEN_DLL_PATH));
    for name in WINTUN_EXPECTED_EXPORTS {
        assert!(
            get_export(hmod, name).is_some(),
            "冻结导出 {name} 必须可从 wintun-0.14.1 解析"
        );
    }
    // WintunGetAdapterName 在 0.14.1 不存在。
    assert!(
        get_export(hmod, WINTUN_EXPORT_ABSENT).is_none(),
        "WintunGetAdapterName 在 0.14.1 必须不存在"
    );
    // SAFETY: hmod 是本次 LoadLibraryW 打开的引用，FreeLibrary 平衡。
    unsafe { let _ = FreeLibrary(hmod); }
}

/// 哈希 != 冻结值的 DLL 必须被拒绝（任何 DLL 都被接受是 mutant）。
#[test]
fn load_rejects_wrong_hash() {
    let dir = std::env::temp_dir().join(format!("exv-w16-wrong-hash-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let fake = dir.join("wintun.dll");
    std::fs::write(&fake, [0u8; 4096]).expect("写入假 DLL");
    // 同一路径、错误内容 → 必须 Err（防 'any DLL accepted'）。
    let _err = expect_native_error(
        WintunLibrary::load(&fake),
        "load 错误哈希 DLL（拒绝原因在断言之下）",
    );
    // 同一路径、冻结字节 → 必须 Ok：拒绝只因哈希，而非路径本身。
    std::fs::copy(Path::new(FROZEN_DLL_PATH), &fake).expect("复制冻结 DLL 到临时路径");
    expect_ok(
        WintunLibrary::load(&fake),
        "load 哈希正确的 DLL 副本",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// loader 只接受精确绝对路径：绝不 PATH/目录搜索（PATH DLL 是 mutant）。
#[test]
fn loads_only_from_exact_path_not_path_search() {
    // 在测试可执行文件所在目录种一棵真实的 wintun.dll：LoadLibraryW 的裸文件名
    // 搜索顺序先命中应用目录，任何走搜索路径的 loader 必然找到它并成功；
    // 契约要求裸文件名仍返回 Err → 搜索型 mutant 必被杀。
    let exe_dir = std::env::current_exe()
        .expect("current_exe")
        .parent()
        .expect("exe 所在目录")
        .to_path_buf();
    let plant = exe_dir.join("wintun.dll");
    std::fs::copy(Path::new(FROZEN_DLL_PATH), &plant)
        .expect("在测试 exe 目录种入真实 wintun.dll");
    // 裸文件名（搜索可解析，但 loader 必须拒绝）。
    let _err = expect_native_error(
        WintunLibrary::load(Path::new("wintun.dll")),
        "load 裸文件名",
    );
    // 只有精确绝对路径可用。
    expect_ok(
        WintunLibrary::load(Path::new(FROZEN_DLL_PATH)),
        "load 精确绝对路径",
    );
    // 目录正确但文件名错误的绝对路径也拒绝。
    let wrong = exe_dir.join("wintun-not-the-frozen-one.dll");
    std::fs::write(&wrong, [0u8; 1024]).expect("写入错误文件名的假 DLL");
    expect_native_error(WintunLibrary::load(&wrong), "load 错误文件名绝对路径");
    let _ = std::fs::remove_file(&plant);
    let _ = std::fs::remove_file(&wrong);
}

// ---------------------------------------------------------------------------
// create-vs-open 所有权与清理契约（需要 admin；非 elevated 记为 not_run）
// ---------------------------------------------------------------------------

/// open-before-create 失败 ERROR_NOT_FOUND(1168)；create 成功（Created，owned）；
/// 创建后 open-by-name 成功（Opened，非 owned）。
#[test]
fn create_before_open_and_open_before_create() {
    if !require_admin("create_before_open_and_open_before_create") {
        return;
    }
    let lib = load_frozen();
    let name = unique_name("ExvW16Ownership");
    // open-before-create：adapter 尚不存在，必须 ERROR_NOT_FOUND(1168)。
    let err = expect_native_error(WintunAdapter::open(&lib, &name), "open-before-create");
    assert_eq!(
        err.code, ERROR_NOT_FOUND,
        "open-before-create 必须失败 ERROR_NOT_FOUND(1168), got {}",
        err.code
    );
    // create 成功 → Created（创建者 owned）。
    let (adapter, opened) = expect_ok(WintunAdapter::create(&lib, &name, TUNNEL_TYPE), "create");
    assert!(
        matches!(opened, AdapterOpen::Created),
        "create 必须返回 AdapterOpen::Created"
    );
    // 创建后 open-by-name 成功 → Opened（第二句柄，非 owned）。
    let (second, opened2) = expect_ok(WintunAdapter::open(&lib, &name), "open-by-name after create");
    assert!(
        matches!(opened2, AdapterOpen::Opened),
        "open 已有 adapter 必须返回 AdapterOpen::Opened"
    );
    // 清理：先非创建者，后创建者（创建者 close = 移除 adapter）。
    drop(second);
    drop(adapter);
}

/// 非创建者 close 不删除 adapter：drop 第二句柄后 open-by-name 仍成功。
#[test]
fn non_creator_close_does_not_remove_adapter() {
    if !require_admin("non_creator_close_does_not_remove_adapter") {
        return;
    }
    let lib = load_frozen();
    let name = unique_name("ExvW16NonCreator");
    let (creator, _opened) =
        expect_ok(WintunAdapter::create(&lib, &name, TUNNEL_TYPE), "create");
    let (second, opened2) = expect_ok(WintunAdapter::open(&lib, &name), "second open");
    assert!(
        matches!(opened2, AdapterOpen::Opened),
        "second open 必须返回 Opened"
    );
    // 非创建者 close：不得删除 adapter。
    drop(second);
    let (third, opened3) = expect_ok(
        WintunAdapter::open(&lib, &name),
        "非创建者 close 后 open-by-name",
    );
    assert!(
        matches!(opened3, AdapterOpen::Opened),
        "adapter 必须仍存在（非创建者 close 不删除）"
    );
    drop(third);
    // 清理：创建者 close = 移除 adapter。
    drop(creator);
}

/// 创建者 close 移除 adapter（0.14.1 真实清理谓词）：之后 open-by-name 失败。
#[test]
fn creator_close_removes_adapter() {
    if !require_admin("creator_close_removes_adapter") {
        return;
    }
    let lib = load_frozen();
    let name = unique_name("ExvW16CreatorClose");
    let (creator, _opened) =
        expect_ok(WintunAdapter::create(&lib, &name, TUNNEL_TYPE), "create");
    // 创建者 close = 移除 adapter（无 delete-adapter 导出）。
    drop(creator);
    let err = expect_native_error(
        WintunAdapter::open(&lib, &name),
        "创建者 close 后 open-by-name",
    );
    assert_eq!(
        err.code, ERROR_NOT_FOUND,
        "创建者 close 后 adapter 必须已移除（ERROR_NOT_FOUND 1168）, got {}",
        err.code
    );
}

/// LUID/ifindex/alias 解析：create 后 luid 非零、ifindex 为正接口索引、alias 等于创建名。
#[test]
fn luid_ifindex_alias_resolve() {
    if !require_admin("luid_ifindex_alias_resolve") {
        return;
    }
    let lib = load_frozen();
    let name = unique_name("ExvW16Luids");
    let (adapter, _opened) = expect_ok(WintunAdapter::create(&lib, &name, TUNNEL_TYPE), "create");
    let luid = adapter.luid();
    assert_ne!(luid, 0, "WintunGetAdapterLUID 不得为 0");
    let ifindex = adapter.ifindex();
    assert!(
        ifindex > 0 && ifindex != u32::MAX,
        "ConvertInterfaceLuidToIndex 必须给出正接口索引, got {ifindex}"
    );
    let alias = adapter.alias();
    assert_eq!(
        alias, name,
        "ConvertInterfaceLuidToAlias 必须等于创建名, got {alias}"
    );
    drop(adapter);
}
