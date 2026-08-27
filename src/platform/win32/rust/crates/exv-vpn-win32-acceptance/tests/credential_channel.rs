// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! 学校凭据一次性通道（provide → verify → destroy）机制测试。
//!
//! 覆盖 W30 提权运行（`Start-Process -Verb RunAs` 无 pipe stdin）的**文件式 one-shot
//! 凭据入口**（`src/scenarios/school.rs` 的 `provide_school_credential_channel` /
//! `read_school_credential_channel`）：
//!
//! 1. **provide**：受限临时文件（`%TEMP%\exv-school-cred-<pid>-<seq>.txt`）ACL 只含
//!    当前用户 + SYSTEM（protected DACL；crate 的 `assert_not_tamperable` pattern 断言
//!    无 BUILTIN\Users / Everyone），内容恰为两行（学号、密码）。
//! 2. **verify**：scenario 的读取路径按行序消费两行（第一行学号、第二行密码）。
//! 3. **destroy**：两行读出后文件**立即删除**；凭据缓冲 zeroize 后全零（长度保留）。
//! 4. **negative**：文件缺失 / 行数不符 / 空行 / ACL 宽泛 → typed error
//!    （`CredentialChannelError`），绝不 panic。
//! 5. **anti-leak**：凭据值绝不出现于 scenario 二进制任何输出面（stdout/stderr/log/
//!    evidence JSON）；`--cred-file` 只携带路径；wire 的 `redact_secret` 是固定标记。
//!
//! **非提权运行**：全部机制测试只依赖"同一用户上下文"（文件 ACL 检查
//! `GetNamedSecurityInfoW(SE_FILE_OBJECT)` 非提权可读），**不依赖 elevation、不依赖
//! 学校服务、不依赖 Wintun**——提权消费路径由 `school_scenario.rs`（W30-T Terra gate）
//! 覆盖，本文件不伪造 RED/GREEN。

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use exv_vpn_win32_acceptance::scenarios::school::{
    CredentialChannelError, provide_school_credential_channel, read_school_credential_channel,
};
use exv_vpn_win32_resource::storage_security::{assert_file_not_tamperable, ensure_secure_file};

use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{CloseHandle, GetLastError, HLOCAL, LocalFree, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SID_AND_ATTRIBUTES, SetFileSecurityW, TOKEN_QUERY,
    TokenUser, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SDDL_REVISION_1,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// ---------------------------------------------------------------------------
// 测试内工具（唯一临时路径 / 通道文件写入 / SDDL 辅助）。
// ---------------------------------------------------------------------------

static SEQ: AtomicU64 = AtomicU64::new(0);

/// 断言读取路径必须失败并返回 typed error（`SchoolChannelCredentials` 有意不实现
/// `Debug`——凭据对象不得被 Debug 渲染；因此不用 `expect_err`，用显式 match）。
fn expect_channel_err(
    result: Result<exv_vpn_win32_acceptance::scenarios::school::SchoolChannelCredentials,
        CredentialChannelError>,
    context: &str,
) -> CredentialChannelError {
    match result {
        Ok(_) => panic!("{context}：必须返回 typed error，绝不 panic"),
        Err(e) => e,
    }
}

/// 唯一临时路径（`%TEMP%` 下；PID + 序号，测试并行无碰撞）。
fn unique_temp_path(tag: &str) -> PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "exv-cred-test-{tag}-{}-{seq}.txt",
        std::process::id()
    ))
}

/// 写入通道文件并收紧 ACL（模拟 provide 侧：写后立即 `ensure_secure_file`）。
fn write_secure_channel(path: &Path, content: &[u8]) {
    std::fs::write(path, content).expect("write channel file");
    ensure_secure_file(path).expect("secure channel file ACL");
}

/// 当前进程 user SID 字符串（`S-1-5-...`；宽泛 ACL 篡改测试用）。
fn current_user_sid() -> String {
    // SAFETY: GetCurrentProcess 返回当前进程伪句柄，无需关闭。
    let process = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需 CloseHandle。
    unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.expect("OpenProcessToken");
    let mut buff = [0u8; 4096];
    let mut ret = 0u32;
    // SAFETY: buff 存活于调用期间；返回的 PSID 指向 token 内部内存。
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buff.as_mut_ptr().cast()),
            buff.len() as u32,
            &mut ret,
        )
    }
    .expect("GetTokenInformation(TokenUser)");
    // SAFETY: token 是本进程打开的句柄。
    unsafe {
        let _ = CloseHandle(token);
    }
    // SAFETY: TokenUser 返回 SID_AND_ATTRIBUTES，首字段是 PSID；buff 可能未对齐，用 read_unaligned。
    let sa = unsafe { std::ptr::read_unaligned(buff.as_ptr().cast::<SID_AND_ATTRIBUTES>()) };
    let mut p = PWSTR::null();
    // SAFETY: sa.Sid 是有效 SID 指针；返回的字符串由系统分配，必须 LocalFree。
    unsafe { ConvertSidToStringSidW(sa.Sid, &mut p) }.expect("ConvertSidToStringSidW");
    let s = unsafe { p.to_string() }.expect("PWSTR to String");
    // SAFETY: ConvertSidToStringSidW 用 LocalAlloc 分配，LocalFree 配对释放。
    unsafe {
        let _ = LocalFree(Some(HLOCAL(p.0.cast::<std::ffi::c_void>())));
    }
    s
}

/// 用 SDDL 重写文件 DACL（protected，不继承；篡改测试用）。
fn set_file_dacl_sddl(path: &Path, sddl: &str) -> Result<(), String> {
    let hsddl = HSTRING::from(sddl);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: psd 是输出参数；ConvertStringSecurityDescriptorToSecurityDescriptorW 用
    // LocalAlloc 分配 descriptor，调用方必须 LocalFree。
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(&hsddl, SDDL_REVISION_1, std::ptr::addr_of_mut!(psd), None) }
        .map_err(|e| format!("SDDL convert: {e:?}"))?;
    let hpath = HSTRING::from(path.to_string_lossy().as_ref());
    let info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: hpath 是合法路径 PCWSTR；psd 是存活 descriptor，调用期间有效。
    let applied = unsafe { SetFileSecurityW(&hpath, info, psd) };
    // SAFETY: psd 由 SDDL 转换 API 分配，SetFileSecurityW 返回后必须 LocalFree。
    unsafe {
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    if !applied.as_bool() {
        // SAFETY: SetFileSecurityW 失败后 GetLastError 读取线程错误码。
        let code = unsafe { GetLastError().0 };
        return Err(format!("SetFileSecurityW: {code}"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 1. provide：通道文件 ACL 仅当前用户 + SYSTEM，内容恰为两行
// ---------------------------------------------------------------------------

/// 杀 **宽泛 ACL 通道** mutant：provide 侧必须创建当前用户-only 的受限临时文件
/// （`ensure_secure_file`，protected DACL：SYSTEM + 当前用户；拒绝 BUILTIN\Users /
/// Everyone / IU），内容恰为两行（学号、密码）。ACL 断言用 crate 的
/// `assert_not_tamperable` pattern（`assert_file_not_tamperable`），同一用户上下文
/// 即可，非提权通过。
#[test]
fn provide_creates_user_only_acl_channel_with_exactly_two_lines() {
    let path = provide_school_credential_channel(b"school-user", b"school-pass")
        .expect("provide_school_credential_channel 必须成功创建通道");
    assert!(path.is_file(), "通道文件必须存在");
    // 内容恰为两行（学号、密码），每行 `\n` 终结。
    let raw = std::fs::read(&path).expect("通道文件必须可读");
    assert_eq!(
        raw, b"school-user\nschool-pass\n",
        "通道文件必须恰为两行（第一行学号、第二行密码）"
    );
    // ACL：crate 的 assert_not_tamperable pattern——无 BUILTIN\Users / Everyone / IU。
    assert_file_not_tamperable(&path)
        .expect("通道 ACL 必须只含当前用户 + SYSTEM（拒绝 BUILTIN\\Users / Everyone）");
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 2. verify：scenario 读取路径按行序消费两行（学号 → 密码）
// ---------------------------------------------------------------------------

/// 杀 **行序错乱** mutant：`read_school_credential_channel`（scenario 的 verify 侧
/// 读取路径）必须按行序消费两行——第一行是学号、第二行是密码。
#[test]
fn verify_read_consumes_username_then_password_in_order() {
    let path = provide_school_credential_channel(b"first-line-user", b"second-line-pass")
        .expect("provide");
    let creds = read_school_credential_channel(&path).expect("read");
    assert_eq!(creds.username(), b"first-line-user", "第一行必须是学号");
    assert_eq!(creds.password(), b"second-line-pass", "第二行必须是密码");
    assert!(!path.exists(), "读取后通道文件必须已删除（one-shot）");
}

// ---------------------------------------------------------------------------
// 3. destroy：读取后文件立即删除；凭据缓冲 zeroize 后全零
// ---------------------------------------------------------------------------

/// 杀 **destroy 缺失** mutant：两行读出后通道文件必须**立即删除**（one-shot，绝不
/// 留下明文凭据文件）；凭据缓冲 `zeroize_all` 后必须全零（长度保留、内容清零）。
#[test]
fn destroy_deletes_channel_file_and_zeroizes_buffers_after_consumption() {
    let path = provide_school_credential_channel(b"destroy-user-4f1", b"destroy-pass-4f1")
        .expect("provide");
    assert!(path.is_file(), "读取前通道文件必须存在");
    let mut creds = read_school_credential_channel(&path).expect("read");
    assert!(
        !path.exists(),
        "两行读出后通道文件必须立即删除（destroy；one-shot 消费）"
    );
    assert_eq!(creds.username(), b"destroy-user-4f1");
    assert_eq!(creds.password(), b"destroy-pass-4f1");
    assert!(
        creds.username().iter().any(|&b| b != 0) && creds.password().iter().any(|&b| b != 0),
        "zeroize 前缓冲必须持有真实值（否则断言无意义）"
    );
    creds.zeroize_all();
    assert_eq!(
        creds.username(),
        &[0u8; 16],
        "zeroize 后学号缓冲必须全零（长度保留、内容清零）"
    );
    assert_eq!(
        creds.password(),
        &[0u8; 16],
        "zeroize 后密码缓冲必须全零（长度保留、内容清零）"
    );
}

// ---------------------------------------------------------------------------
// 4. negative：缺失 / 行数不符 / 空行 / ACL 宽泛 → typed error（绝不 panic）
// ---------------------------------------------------------------------------

/// 杀 **panic 路径** mutant：文件缺失必须返回 typed error
/// （[`CredentialChannelError::Missing`]），绝不 panic。
#[test]
fn negative_missing_channel_file_yields_typed_error_not_panic() {
    let missing = unique_temp_path("missing");
    let err = expect_channel_err(read_school_credential_channel(&missing), "缺失文件");
    assert!(matches!(err, CredentialChannelError::Missing), "got {err:?}");
}

/// 杀 **行数放行** mutant：通道文件行数不是 2 必须返回 typed error
/// （[`CredentialChannelError::WrongLineCount`]），且错误路径同样立即删除文件
/// （one-shot：绝不让行数异常的文件留在磁盘）。
#[test]
fn negative_wrong_line_count_yields_typed_error_and_destroys_file() {
    let path = unique_temp_path("wrong-count");
    write_secure_channel(&path, b"user\npass\nextra\n");
    let err = expect_channel_err(read_school_credential_channel(&path), "三行通道");
    assert_eq!(
        err,
        CredentialChannelError::WrongLineCount {
            expected: 2,
            actual: 3
        },
        "got {err:?}"
    );
    assert!(
        !path.exists(),
        "错误路径也必须立即删除文件（one-shot，不留下明文）"
    );
}

/// 空行凭据（`user\n\n`）必须返回 typed error（[`CredentialChannelError::EmptyLine`]）。
#[test]
fn negative_empty_line_yields_typed_error() {
    let path = unique_temp_path("empty-line");
    write_secure_channel(&path, b"user\n\n");
    let err = expect_channel_err(read_school_credential_channel(&path), "空行通道");
    assert_eq!(err, CredentialChannelError::EmptyLine, "got {err:?}");
    assert!(!path.exists(), "错误路径也必须删除文件");
}

/// 杀 **宽泛 ACL 读侧放行** mutant：ACL 宽泛（Everyone 可读）的凭据文件必须被
/// 读取侧拒绝（[`CredentialChannelError::NotUserOnlyAcl`]）——当前用户-only 是通道
/// 属性，读取侧强制执行（防凭据混淆）；未读取的文件不删除，由测试清理。
#[test]
fn negative_broad_acl_channel_is_rejected_with_typed_error() {
    let path = unique_temp_path("broad-acl");
    write_secure_channel(&path, b"user\npass\n");
    // 篡改：DACL 改为 Everyone + 当前用户（宽泛可读）——读取必须被拒。
    let user_sid = current_user_sid();
    set_file_dacl_sddl(&path, &format!("D:(A;;FA;;;WD)(A;;FA;;;{user_sid})"))
        .expect("设置宽泛 ACL 必须成功");
    let err = expect_channel_err(read_school_credential_channel(&path), "宽泛 ACL 凭据文件");
    assert_eq!(err, CredentialChannelError::NotUserOnlyAcl, "got {err:?}");
    assert!(
        path.exists(),
        "未读取的宽泛文件不得由读侧删除（未消费；由测试清理）"
    );
    // 清理：DACL 含当前用户 FA → 可直接删除。
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// 5. anti-leak：凭据值绝不出现于任何输出面（argv/env/log/evidence/stdout）
// ---------------------------------------------------------------------------

/// 杀 **输出泄漏** mutant（进程内 API 面）：凭据值绝不进入通道 API 产生的任何
/// 字符串（错误 Debug / 路径）；`--cred-file` 只携带路径。wire 的 `redact_secret`
/// seam（`exv-vpn-wire`）对任何 secret 渲染都是固定标记 `<redacted>`，绝不回显
/// 内容——渲染面不可能泄漏。
#[test]
fn anti_leak_channel_api_never_renders_credential_values() {
    let path = provide_school_credential_channel(b"api-leak-user-7c2", b"api-leak-pass-7c2")
        .expect("provide");
    let mut creds = read_school_credential_channel(&path).expect("read");
    assert_eq!(creds.username(), b"api-leak-user-7c2");
    assert_eq!(creds.password(), b"api-leak-pass-7c2");
    let surfaces = [
        format!("{:?}", CredentialChannelError::Missing),
        format!(
            "{:?}",
            CredentialChannelError::WrongLineCount {
                expected: 2,
                actual: 3
            }
        ),
        path.display().to_string(),
    ];
    for s in &surfaces {
        assert!(
            !s.contains("api-leak-user-7c2") && !s.contains("api-leak-pass-7c2"),
            "API 输出面不得携带凭据值（got {s:?}）"
        );
    }
    assert_eq!(
        exv_vpn_wire::redact::redact_secret(creds.username()),
        "<redacted>",
        "wire redact_secret 必须是固定标记，绝不回显 secret 内容"
    );
    assert_eq!(
        exv_vpn_wire::redact::redact_secret(creds.password()),
        "<redacted>",
        "wire redact_secret 必须是固定标记，绝不回显 secret 内容"
    );
    creds.zeroize_all();
}

/// 杀 **argv/stdout/log/evidence 泄漏** mutant（二进制输出面）：以 `--cred-file
/// <path>`（只携带路径）派发学校 scenario 二进制（`CARGO_BIN_EXE_*`），mock 凭据值
/// 绝不出现于 stdout/stderr/日志文件/evidence JSON。非 elevated / 无学校服务时必须
/// honest not_run（退出码 2，绝不连接学校）。
#[test]
fn anti_leak_scenario_binary_output_never_contains_credential_values() {
    let cred_path = provide_school_credential_channel(b"bin-leak-user-3d8", b"bin-leak-pass-3d8")
        .expect("provide");
    let ev_dir = std::env::temp_dir().join(format!(
        "exv-cred-test-evidence-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    let log_path = ev_dir.join("school-scenario.log");
    let _ = std::fs::create_dir_all(&ev_dir);

    let out = Command::new(env!("CARGO_BIN_EXE_exv-win32-school-scenario"))
        .arg("--cred-file")
        .arg(&cred_path)
        .arg("--evidence-dir")
        .arg(&ev_dir)
        .arg("--log-file")
        .arg(&log_path)
        // 禁止子进程走真实学校 flow：任何情况下都不得连接学校/消费凭据后外发。
        .env_remove("EXV_RUST_VPN_SCHOOL_TARGET")
        .env_remove("EXV_RUST_VPN_SCHOOL_FLOW_TARGET")
        .env_remove("EXV_RUST_VPN_EVIDENCE_DIR")
        .output()
        .expect("spawn school scenario binary");

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    let evidence_json = std::fs::read_to_string(ev_dir.join("school-scenario.json")).unwrap_or_default();

    for value in ["bin-leak-user-3d8", "bin-leak-pass-3d8"] {
        assert!(!stdout.contains(value), "stdout 不得携带凭据值（{value:?} 泄漏）");
        assert!(!stderr.contains(value), "stderr 不得携带凭据值（{value:?} 泄漏）");
        assert!(!log.contains(value), "日志文件不得携带凭据值（{value:?} 泄漏）");
        assert!(
            !evidence_json.contains(value),
            "evidence JSON 不得携带凭据值（{value:?} 泄漏）"
        );
    }
    // 输出面仍然完整（evidence 行存在、honest not_run 退出码 2）。
    assert!(
        stdout.contains("SCHOOL_SCENARIO_EVIDENCE:"),
        "scenario 必须发布 evidence 行"
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "非 elevated / 无学校服务必须 honest not_run（退出码 2；stdout 尾部: {:?}）",
        stdout.lines().last()
    );

    let _ = std::fs::remove_file(&cred_path);
    let _ = std::fs::remove_dir_all(&ev_dir);
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
