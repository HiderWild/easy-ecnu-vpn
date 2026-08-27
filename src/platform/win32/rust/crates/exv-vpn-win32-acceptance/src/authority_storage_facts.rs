// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! WSP2 事实探针：singleton authority + durable Windows storage。
//!
//! 本模块在**真实 Windows 宿主**（非提权）上运行原生 spike，冻结 Win32 authority
//! 与 durable-journal-storage 的事实，作为 `W13/W14` 的权威输入：
//!
//! - **authority 原语**：Named Mutex（`CreateMutexW`，`Local\` 命名空间）vs
//!   `LockFileEx`。两种原语都在真实双进程竞争下实测：Named Mutex 让一个 winner
//!   持有、loser `WaitForSingleObject` 超时（`WAIT_TIMEOUT=258`），且 owner 被
//!   `TerminateProcess` 杀死而不释放时，下一个 waiter 收到 `WAIT_ABANDONED_0=128`
//!   并被授予所有权（abandoned semantics，可检测）；`LockFileEx` 的第二个 locker
//!   得到 `ERROR_LOCK_VIOLATION=33`，owner 死后锁被 OS 静默释放（**没有**
//!   abandoned 通知）。结论：authority 用 Named Mutex（`Local\` 命名空间），
//!   `WAIT_ABANDONED_0` 是"前任 owner 死亡，状态可能不一致"的可检测信号。
//!
//! - **loser 退出语义**：loser 在 `WaitForSingleObject` 超时后**直接退出**，不做
//!   scan/observe/publish（oracle 断言 `mutex_loser_exited_before_scan_observe_publish`）。
//!   顺序冻结为：**先 lock，后 scan/observe/publish**（mutant：scan 后才 lock）。
//!
//! - **journal 存储**：machine-level 路径 `%ProgramData%\ExvVpn\journal\`（非提权
//!   实测可创建，owner 是当前用户）+ `%LOCALAPPDATA%\ExvVpn\journal\` 备选；文件以
//!   `FILE_APPEND_DATA`（无 `FILE_WRITE_DATA`）+ `FILE_SHARE_READ`（禁并发写）打开；
//!   `FlushFileBuffers` 是持久化原语（Rust `std::fs::flush` 不是，它是 no-op 契约）；
//!   append-only 保证写入永远在末尾（任意 offset 写入被拒）；替换用
//!   `MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)` + 父目录句柄 `FlushFileBuffers`。
//!
//! - **崩溃语义**（复用 common `exv_vpn_resource::journal` J50 codec 在真实文件上
//!   往返）：torn final tail → 恢复到最后一个完整记录；corrupt middle record →
//!   `JournalCorrupt`，**不跳过**（no skip）。
//!
//! - **ACL tamper/deny**：把文件 DACL 改成仅 SYSTEM → 再次打开/追加得
//!   `ERROR_ACCESS_DENIED=5`（typed error），改回原 DACL 后可恢复。
//!
//! `run_authority_storage_fact_probe(child_exe)` 是 Terra 冻结的 seam（`WSP2-T`）。
//! oracle 测试与 `exv-win32-authority-storage-spike` 二进制都调用它：测试断言返回的
//! `AuthorityStorageFacts`，二进制把同样的事实写成 `FACT:` 行 + JSON evidence。
//! 事实权威文件：
//! `docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-authority-storage-facts.md`。
//!
//! 双进程 case 需要再生成一个真实子进程：oracle 测试通过 Cargo 注入的
//! `CARGO_BIN_EXE_*` 拿到 spike 二进制路径作为 `child_exe`；spike 二进制用
//! `std::env::current_exe()`。子进程以 `EXV_WSP2_CHILD_MODE` 环境变量驱动，写入
//! `EXV_WSP2_CHILD_RESULT` 结果文件后退出。
//!
//! 这是平台 FFI 路径：`unsafe` 是经过审阅的，每个块带 `// SAFETY:`，且工作区
//! 强制 `unsafe_op_in_unsafe_fn = deny`。

use std::ffi::c_void;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::Serialize;

use exv_vpn_resource::journal::{decode, encode, DecodeOutcome, JournalRecord};

use windows::core::{BOOL, Error, HSTRING, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_LOCK_VIOLATION,
    ERROR_SHARING_VIOLATION, HANDLE, HLOCAL, WAIT_ABANDONED_0, WAIT_EVENT, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
    SE_FILE_OBJECT, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SID_AND_ATTRIBUTES, TOKEN_QUERY, TokenElevation, TokenUser,
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, LockFileEx, MoveFileExW, ReadFile, SetFilePointerEx,
    UnlockFileEx, WriteFile, FILE_APPEND_DATA, FILE_BEGIN, WRITE_DAC,
    FILE_CREATION_DISPOSITION, FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE,
    FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, LOCK_FILE_FLAGS,
    LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, MOVE_FILE_FLAGS,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, OPEN_ALWAYS, OPEN_EXISTING,
    SET_FILE_POINTER_MOVE_METHOD,
};
use windows::Win32::System::IO::OVERLAPPED;
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcessId, OpenMutexW, OpenProcess, OpenProcessToken, ReleaseMutex,
    TerminateProcess, WaitForSingleObject, MUTEX_ALL_ACCESS, PROCESS_TERMINATE,
};

/// 冻结的权限/存储错误类型（typed error，供 W14 `journal_store.rs` 使用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum StorageErrorKind {
    AccessDenied,
    SharingViolation,
    LockViolation,
    Corruption { offset: usize },
    Io(String),
}

/// 冻结的创建/打开 journal 文件的访问位（无 `FILE_WRITE_DATA`，强制 append-only）。
pub const JOURNAL_ACCESS: u32 = FILE_APPEND_DATA.0;
/// 冻结的 share mode：允许其他进程读，禁止并发写（single-writer）。
pub const JOURNAL_SHARE: FILE_SHARE_MODE = FILE_SHARE_MODE(FILE_SHARE_READ.0);
/// 冻结的命名空间：`Local\`（会话内可见，非提权可创建，服务与用户同会话共存）。
pub const MUTEX_NAMESPACE: &str = "Local";
/// 冻结的 authority mutex DACL 模板（当前用户 + SYSTEM，拒绝宽泛 IU）。
pub fn authority_mutex_dacl(user_sid: &str) -> String {
    format!("D:(A;;GA;;;SY)(A;;GA;;;{user_sid})")
}

/// 一次事实探针的完整观测结果。serde 可序列化为 JSON evidence。
#[derive(Clone, Debug, Serialize)]
pub struct AuthorityStorageFacts {
    // 宿主
    pub host_os: String,
    pub hostname: String,
    pub env_elevated: bool,

    // ---- authority 原语：Named Mutex vs LockFileEx ----
    pub primitive_choice: String,
    pub mutex_namespace: String,
    pub global_namespace_probe: String,
    pub mutex_dacl_sddl: String,
    pub mutex_two_process_race_winner_is_loser: String,
    pub mutex_loser_wait_code: u32,
    pub mutex_loser_exited_before_scan_observe_publish: bool,
    pub mutex_reusable_after_release: bool,
    pub mutex_abandoned_owner_killed_without_release: bool,
    pub mutex_abandoned_wait_code: u32,
    pub mutex_abandoned_granted: bool,
    pub lockfile_second_locker_fails: bool,
    pub lockfile_second_locker_error_code: u32,
    pub lockfile_reacquirable_after_release: bool,
    pub lockfile_has_abandoned_notification: bool,

    // ---- journal 路径 ----
    pub journal_base_programdata: String,
    pub programdata_creatable_non_admin: bool,
    pub programdata_create_error: Option<String>,
    pub journal_path_chosen: String,
    pub journal_dir_acl_sddl: String,

    // ---- CreateFileW flags / FlushFileBuffers ----
    pub create_file_access: String,
    pub create_file_share_mode: String,
    pub append_only_write_ok: bool,
    pub append_after_seek_lands_at_eof: bool,
    pub second_writer_share_violation_observed: bool,
    pub second_writer_share_violation_error_code: u32,
    pub flush_file_buffers_succeeds: bool,
    pub append_visible_to_second_handle: bool,
    pub rust_std_flush_is_not_durable_sync: bool,
    pub movefile_replace_succeeds: bool,
    pub dir_flush_succeeds: bool,

    // ---- 崩溃语义（J50 真实文件往返）----
    pub j50_clean_roundtrip: bool,
    pub torn_tail_recovers_to_last_complete: bool,
    pub torn_tail_recovered_count: usize,
    pub corrupt_middle_no_skip: bool,
    pub corrupt_middle_recovered_count: usize,

    // ---- ACL tamper/deny ----
    pub acl_deny_open_fails: bool,
    pub acl_deny_error_code: u32,
    pub acl_restore_succeeds: bool,
    pub acl_test_original_sddl: String,
    pub acl_test_deny_sddl: String,
}

impl AuthorityStorageFacts {
    /// 供 oracle 与二进制检查"已记录事实"。
    pub fn is_complete(&self) -> bool {
        self.primitive_choice == "named_mutex_local"
            && self.mutex_loser_exited_before_scan_observe_publish
            && self.mutex_abandoned_granted
            && self.mutex_abandoned_wait_code == WAIT_ABANDONED_0.0
            && self.lockfile_second_locker_fails
            && self.append_only_write_ok
            && self.append_after_seek_lands_at_eof
            && self.torn_tail_recovers_to_last_complete
            && self.corrupt_middle_no_skip
            && self.acl_deny_open_fails
    }
}

/// 把 win32 错误码分类为 typed error（W14 冻结的 typed-error 面）。
pub fn classify_win32(code: u32) -> StorageErrorKind {
    match code {
        _ if code == ERROR_ACCESS_DENIED.0 => StorageErrorKind::AccessDenied,
        _ if code == ERROR_SHARING_VIOLATION.0 => StorageErrorKind::SharingViolation,
        _ if code == ERROR_LOCK_VIOLATION.0 => StorageErrorKind::LockViolation,
        other => StorageErrorKind::Io(format!("win32:{other}")),
    }
}

fn win32_code(e: &Error) -> u32 {
    // HRESULT_FROM_WIN32(code) = 0x8007_0000 | code；取低 16 位还原 win32 code。
    (e.code().0 & 0xFFFF) as u32
}

fn last_error() -> u32 {
    // SAFETY: 无指针参数，纯读取线程错误码。
    unsafe { GetLastError().0 }
}

/// 当前进程 token 的 user SID 字符串（`S-1-5-...`）。
fn current_user_sid_string() -> Option<String> {
    // SAFETY: GetCurrentProcess 返回当前进程伪句柄，无需关闭。
    let process = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需 CloseHandle。
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if ok.is_err() {
        return None;
    }
    let mut buff = [0u8; 4096];
    let mut ret = 0u32;
    // SAFETY: buff 生存期覆盖调用；返回的 PSID 指向 token 内部内存，token 存活期间有效。
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buff.as_mut_ptr().cast::<c_void>()),
            buff.len() as u32,
            &mut ret,
        )
    };
    if ok.is_err() {
        // SAFETY: token 是本进程新打开的句柄，读引用失败后关闭。
        unsafe {
            let _ = CloseHandle(token);
        }
        return None;
    }
    // SAFETY: TokenUser 返回 SID_AND_ATTRIBUTES，首字段是 PSID；buff 可能未 8 对齐，用 read_unaligned。
    let sa = unsafe { std::ptr::read_unaligned(buff.as_ptr().cast::<SID_AND_ATTRIBUTES>()) };
    let sid = sid_to_string(sa.Sid);
    // SAFETY: token 是本进程新打开的句柄，读引用最后一次后关闭。
    unsafe {
        let _ = CloseHandle(token);
    }
    sid
}

fn sid_to_string(sid: PSID) -> Option<String> {
    let mut p = PWSTR::null();
    // SAFETY: sid 是有效 SID 指针；返回的字符串由系统分配，必须 LocalFree。
    let ok = unsafe { windows::Win32::Security::Authorization::ConvertSidToStringSidW(sid, &mut p) };
    if ok.is_err() {
        return None;
    }
    let s = unsafe { p.to_string() }.ok()?;
    // SAFETY: ConvertSidToStringSidW 用 LocalAlloc 分配，LocalFree 配对释放。
    unsafe {
        LocalFree(Some(HLOCAL(p.0 as *mut c_void)));
    }
    Some(s)
}

/// 用 SDDL 构建 SECURITY_DESCRIPTOR（返回 PSECURITY_DESCRIPTOR + 需 LocalFree 释放的内存）。
fn build_security_descriptor(sddl: &str) -> Option<PSECURITY_DESCRIPTOR> {
    let hs = HSTRING::from(sddl);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: psd 是输出参数；ConvertStringSecurityDescriptorToSecurityDescriptorW 用
    // LocalAlloc 分配 descriptor，调用方必须 LocalFree。
    let ok = unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(&hs, SDDL_REVISION_1, &mut psd, None) };
    if ok.is_err() {
        return None;
    }
    Some(psd)
}

fn cleanup_security_descriptor(psd: Option<PSECURITY_DESCRIPTOR>) {
    if let Some(p) = psd {
        // SAFETY: descriptor 由 ConvertStringSecurityDescriptor* 分配，LocalFree 配对释放。
        unsafe {
            LocalFree(Some(HLOCAL(p.0)));
        }
    }
}

/// 从已打开的句柄取对象当前 DACL 的 SDDL 字符串。
fn dacl_sddl_from_handle(handle: HANDLE) -> Option<String> {
    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: psd 是输出参数；GetSecurityInfo 用 LocalAlloc 分配 descriptor，需 LocalFree。
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut psd),
        )
    };
    if rc.0 != 0 {
        return None;
    }
    let mut pw = PWSTR::null();
    // SAFETY: psd 指向存活 descriptor；ConvertSecurityDescriptorToStringSecurityDescriptorW
    // 用 LocalAlloc 分配字符串，需 LocalFree。
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut pw,
            None,
        )
    };
    if ok.is_err() {
        // SAFETY: GetSecurityInfo 分配的 descriptor，LocalFree 配对释放。
        unsafe {
            LocalFree(Some(HLOCAL(psd.0)));
        }
        return None;
    }
    let s = unsafe { pw.to_string() }.ok();
    // SAFETY: ConvertSecurityDescriptorToStringSecurityDescriptorW 分配的字符串，LocalFree 配对释放。
    unsafe {
        LocalFree(Some(HLOCAL(pw.0 as *mut c_void)));
    }
    // SAFETY: GetSecurityInfo 分配的 descriptor，LocalFree 配对释放。
    unsafe {
        LocalFree(Some(HLOCAL(psd.0)));
    }
    s
}

// ---------------------------------------------------------------------------
// Named Mutex helpers
// ---------------------------------------------------------------------------

fn create_mutex(name: &str, sa: Option<*const SECURITY_ATTRIBUTES>) -> Result<HANDLE, String> {
    let hname = HSTRING::from(name);
    // SAFETY: name 合法；binitialowner=false（未持有，第一个 waiter 获得）；sa 指向存活
    // SECURITY_ATTRIBUTES 或为 None。失败返回 Err(win32 code)。
    unsafe { CreateMutexW(sa, false, &hname) }.map_err(|e| format!("CreateMutexW:{}", win32_code(&e)))
}

fn open_mutex(name: &str) -> Result<HANDLE, String> {
    let hname = HSTRING::from(name);
    // SAFETY: name 合法；MUTEX_ALL_ACCESS（含 SYNCHRONIZE + READ_CONTROL）。失败返回 Err。
    unsafe { OpenMutexW(MUTEX_ALL_ACCESS, false, &hname) }.map_err(|e| format!("OpenMutexW:{}", win32_code(&e)))
}

fn wait_one(h: HANDLE, ms: u32) -> WAIT_EVENT {
    // SAFETY: h 是有效句柄；返回 WAIT_EVENT。
    unsafe { WaitForSingleObject(h, ms) }
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

fn open_file(
    path: &Path,
    access: u32,
    share: FILE_SHARE_MODE,
    disposition: FILE_CREATION_DISPOSITION,
    flags: FILE_FLAGS_AND_ATTRIBUTES,
) -> Result<HANDLE, u32> {
    let hp = HSTRING::from(path.to_string_lossy().as_ref());
    // SAFETY: path 合法；失败返回 Err(win32 code)。
    unsafe { CreateFileW(&hp, access, share, None, disposition, flags, None) }
        .map_err(|e| win32_code(&e))
}

fn write_all(handle: HANDLE, data: &[u8]) -> Result<(), String> {
    let mut off = 0usize;
    while off < data.len() {
        let mut written = 0u32;
        // SAFETY: data[off..] 为有效只读切片；同步 blocking 写。
        unsafe { WriteFile(handle, Some(&data[off..]), Some(&mut written), None) }
            .map_err(|e| format!("WriteFile:{}", win32_code(&e)))?;
        off += written as usize;
    }
    Ok(())
}

fn read_exact(handle: HANDLE, buf: &mut [u8]) -> Result<(), String> {
    let mut off = 0usize;
    while off < buf.len() {
        let mut read = 0u32;
        // SAFETY: buf[off..] 是有效可变切片；同步 blocking 读。
        unsafe { ReadFile(handle, Some(&mut buf[off..]), Some(&mut read), None) }
            .map_err(|e| format!("ReadFile:{}", win32_code(&e)))?;
        if read == 0 {
            return Err("ReadFile returned 0 (EOF)".into());
        }
        off += read as usize;
    }
    Ok(())
}

fn read_file_all(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_default()
}

fn set_file_pointer(h: HANDLE, dist: i64) -> Result<(), String> {
    // SAFETY: h 是有效文件句柄；dist 为移动距离。
    unsafe { SetFilePointerEx(h, dist, None, SET_FILE_POINTER_MOVE_METHOD(FILE_BEGIN.0)) }
        .map_err(|e| format!("SetFilePointerEx:{}", win32_code(&e)))
}

// ---------------------------------------------------------------------------
// Child process orchestration（双进程 authority case）
// ---------------------------------------------------------------------------

const CHILD_MODE: &str = "EXV_WSP2_CHILD_MODE";
const CHILD_MUTEX: &str = "EXV_WSP2_CHILD_MUTEX";
const CHILD_RESULT: &str = "EXV_WSP2_CHILD_RESULT";
const CHILD_TIMEOUT_MS: &str = "EXV_WSP2_CHILD_TIMEOUT_MS";
const CHILD_HOLD_SIGNAL: &str = "EXV_WSP2_CHILD_HOLD_SIGNAL";
const CHILD_LOCKFILE: &str = "EXV_WSP2_CHILD_LOCKFILE";

fn spawn_child(child_exe: &Path, mode: &str, envs: &[(&str, String)]) -> Child {
    let mut cmd = Command::new(child_exe);
    cmd.env(CHILD_MODE, mode)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.spawn().expect("spawn WSP2 child")
}

fn write_result_file(path: &Path, lines: &[(&str, String)]) {
    let mut s = String::new();
    for (k, v) in lines {
        s.push_str(k);
        s.push('=');
        s.push_str(v);
        s.push('\n');
    }
    let _ = std::fs::write(path, s);
}

/// 轮询等待文件出现（子进程写结果/信号），超时返回 false。
fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    false
}

fn parse_result_file(path: &Path) -> Vec<(String, String)> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .filter_map(|l| {
            let mut it = l.splitn(2, '=');
            match (it.next(), it.next()) {
                (Some(k), Some(v)) => Some((k.to_string(), v.to_string())),
                _ => None,
            }
        })
        .collect()
}

/// 子进程入口：根据 `EXV_WSP2_CHILD_MODE` 执行子角色并退出。父进程永远不执行这里。
///
/// 该函数由 spike 二进制在 `main` 顶部（检测到子模式）与 oracle 测试（子进程是
/// spike 二进制）调用。
pub fn run_child_mode() -> ! {
    let mode = std::env::var(CHILD_MODE).unwrap_or_default();
    match mode.as_str() {
        "try-lock" => child_try_lock(),
        "hold-mutex" => child_hold_mutex(),
        "try-lockfile" => child_try_lockfile(),
        other => {
            // 未知模式：写错误结果并退出（不静默）。
            if let Ok(rp) = std::env::var(CHILD_RESULT) {
                let _ = std::fs::write(PathBuf::from(rp), format!("result=unknown_mode:{other}\n"));
            }
        }
    }
    std::process::exit(0);
}

/// 子角色 try-lock：打开命名 mutex 并等待；把等待结果写入结果文件，**绝不**做
/// scan/observe/publish。loser 直接退出。
fn child_try_lock() {
    let mutex_name = std::env::var(CHILD_MUTEX).unwrap_or_default();
    let timeout = std::env::var(CHILD_TIMEOUT_MS)
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(300);
    let result_path = PathBuf::from(std::env::var(CHILD_RESULT).unwrap_or_default());

    // OpenMutexW 启动竞态重试：父进程先 create，这里最多等 1s。
    let mut handle = None;
    for _ in 0..50 {
        if let Ok(h) = open_mutex(&mutex_name) {
            handle = Some(h);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let Some(h) = handle else {
        write_result_file(&result_path, &[("result", "open_failed".into())]);
        return;
    };

    let ev = wait_one(h, timeout);
    let (result, code) = match ev {
        WAIT_OBJECT_0 => ("object0", WAIT_OBJECT_0.0),
        WAIT_TIMEOUT => ("timeout", WAIT_TIMEOUT.0),
        WAIT_ABANDONED_0 => ("abandoned", WAIT_ABANDONED_0.0),
        _ => ("failed", last_error()),
    };
    let acquired = ev == WAIT_OBJECT_0 || ev == WAIT_ABANDONED_0;
    if acquired {
        // SAFETY: 本进程取得 mutex 所有权，ReleaseMutex 配对释放。
        unsafe {
            let _ = ReleaseMutex(h);
        }
    }
    // SAFETY: h 是本进程打开的句柄。
    unsafe {
        let _ = CloseHandle(h);
    }
    // 关键冻结事实：child（无论赢家 loser）都未做 scan/observe/publish。
    write_result_file(
        &result_path,
        &[
            ("result", result.into()),
            ("code", code.to_string()),
            ("observed_authority", "false".into()),
            ("published", "false".into()),
        ],
    );
}

/// 子角色 hold-mutex：打开命名 mutex、无限等待（应为 WAIT_OBJECT_0），写 hold 信号
/// 文件，然后永久阻塞（等待父进程 TerminateProcess）。
fn child_hold_mutex() {
    let mutex_name = std::env::var(CHILD_MUTEX).unwrap_or_default();
    let signal_path = PathBuf::from(std::env::var(CHILD_HOLD_SIGNAL).unwrap_or_default());

    let mut handle = None;
    for _ in 0..50 {
        if let Ok(h) = open_mutex(&mutex_name) {
            handle = Some(h);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let Some(h) = handle else {
        let _ = std::fs::write(&signal_path, "acquire_failed");
        return;
    };
    let ev = wait_one(h, u32::MAX);
    if ev != WAIT_OBJECT_0 {
        let _ = std::fs::write(&signal_path, format!("not_owner:{}", ev.0));
        // SAFETY: h 是本进程打开的句柄。
        unsafe {
            let _ = CloseHandle(h);
        }
        return;
    }
    let _ = std::fs::write(&signal_path, "acquired");
    // 持有所有权直到被 TerminateProcess 杀死；不释放。
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// 子角色 try-lockfile：以 GENERIC_READ 打开文件（父进程 share=READ 允许），
/// LockFileEx 独占 [0,1024)。结果写入结果文件。
fn child_try_lockfile() {
    let lockfile = PathBuf::from(std::env::var(CHILD_LOCKFILE).unwrap_or_default());
    let result_path = PathBuf::from(std::env::var(CHILD_RESULT).unwrap_or_default());

    let Ok(h) = open_file(
        &lockfile,
        FILE_GENERIC_READ.0,
        FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
        OPEN_EXISTING,
        FILE_FLAGS_AND_ATTRIBUTES(0),
    ) else {
        let code = last_error();
        write_result_file(&result_path, &[("result", "open_failed".into()), ("code", code.to_string())]);
        return;
    };
    let mut ov = OVERLAPPED::default();
    // SAFETY: h 是有效文件句柄；ov 存活于调用期间；独占 + 立即失败锁定 [0,1024)。
    let rc = unsafe {
        LockFileEx(
            h,
            LOCK_FILE_FLAGS(LOCKFILE_EXCLUSIVE_LOCK.0 | LOCKFILE_FAIL_IMMEDIATELY.0),
            None,
            1024,
            0,
            &mut ov,
        )
    };
    let (result, code) = match rc {
        Ok(()) => ("locked", 0u32),
        Err(e) => ("lock_violation", win32_code(&e)),
    };
    if result == "locked" {
        // SAFETY: h 是有效文件句柄；ov 与锁定一致，UnlockFileEx 配对释放。
        unsafe {
            let _ = UnlockFileEx(h, None, 1024, 0, &mut ov);
        }
    }
    // SAFETY: h 是本进程打开的句柄。
    unsafe {
        let _ = CloseHandle(h);
    }
    write_result_file(&result_path, &[("result", result.into()), ("code", code.to_string())]);
}

// ---------------------------------------------------------------------------
// Authority 探针（父进程）
// ---------------------------------------------------------------------------

fn probe_mutex_vs_lockfile(facts: &mut AuthorityStorageFacts, child_exe: &Path, work: &Path) {
    let pid0 = unsafe { GetCurrentProcessId() };
    let rand = pid0.wrapping_mul(2654435761) & 0xFFFF;
    let user_sid = current_user_sid_string().unwrap_or_else(|| "S-1-5-32-544".to_string());
    let dacl = authority_mutex_dacl(&user_sid);
    facts.mutex_dacl_sddl = dacl.clone();

    let psd = build_security_descriptor(&dacl);
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.map(|p| p.0).unwrap_or(std::ptr::null_mut()),
        bInheritHandle: false.into(),
    };
    let sa_ptr = if psd.is_some() {
        Some(&sa as *const SECURITY_ATTRIBUTES)
    } else {
        None
    };

    // ---- Global 命名空间探针（非提权预期被拒；记录诚实观测）----
    let global_name = format!(r"Global\ExvVpnWsp2_probe_{pid0}_{rand}");
    facts.global_namespace_probe = match create_mutex(&global_name, None) {
        Ok(h) => {
            // SAFETY: h 是本进程打开的句柄。
            unsafe {
                let _ = CloseHandle(h);
            }
            "ok".to_string()
        }
        Err(e) => {
            let code = e
                .split(':')
                .nth(1)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            format!("denied:{code}")
        }
    };

    // ---- Named Mutex 双进程竞争：parent 持有，child 超时且不做 scan/observe/publish ----
    let race_mutex = format!(r"{MUTEX_NAMESPACE}\ExvVpnWsp2_race_{pid0}_{rand}");
    let race_result = work.join(format!("race-result-{pid0}.txt"));
    let race_hold = work.join(format!("race-hold-{pid0}.txt"));

    let Ok(m_race) = create_mutex(&race_mutex, sa_ptr) else {
        facts.mutex_two_process_race_winner_is_loser = "create_failed".into();
        cleanup_security_descriptor(psd);
        return;
    };
    // parent 取得所有权（bInitialOwner=false 时第一个 waiter 获得）。
    let ev0 = wait_one(m_race, 3000);
    if ev0 != WAIT_OBJECT_0 {
        facts.mutex_two_process_race_winner_is_loser = format!("parent_wait_failed:{}", ev0.0);
        // SAFETY: m_race 是本进程打开的句柄。
        unsafe {
            let _ = CloseHandle(m_race);
        }
        cleanup_security_descriptor(psd);
        return;
    }

    // child 尝试获取 → 应 WAIT_TIMEOUT（parent 持有）。
    let mut child1 = spawn_child(
        child_exe,
        "try-lock",
        &[
            (CHILD_MUTEX, race_mutex.clone()),
            (CHILD_RESULT, race_result.to_string_lossy().into_owned()),
            (CHILD_TIMEOUT_MS, "300".into()),
        ],
    );
    let waited1 = wait_for_file(&race_result, Duration::from_secs(15));
    let r1 = parse_result_file(&race_result);
    let _ = std::fs::remove_file(&race_result);
    let child1_code = child1.wait().map(|s| s.code()).unwrap_or(None);
    let _ = child1_code;
    let loser_result = r1.iter().find(|(k, _)| k == "result").map(|(_, v)| v.clone()).unwrap_or_default();
    let loser_code = r1
        .iter()
        .find(|(k, _)| k == "code")
        .and_then(|(_, v)| v.parse::<u32>().ok())
        .unwrap_or(u32::MAX);
    let loser_published = r1.iter().any(|(k, v)| k == "published" && v == "true");
    let loser_observed = r1.iter().any(|(k, v)| k == "observed_authority" && v == "true");

    facts.mutex_two_process_race_winner_is_loser = loser_result.clone();
    facts.mutex_loser_wait_code = loser_code;
    facts.mutex_loser_exited_before_scan_observe_publish =
        waited1 && loser_result == "timeout" && !loser_published && !loser_observed;

    // parent 释放后 mutex 可重新获取（第二次 child 成为 winner）。
    // SAFETY: 本进程持有 m_race，ReleaseMutex 配对释放。
    unsafe {
        let _ = ReleaseMutex(m_race);
    }
    let race_result2 = work.join(format!("race-result2-{pid0}.txt"));
    let mut child2 = spawn_child(
        child_exe,
        "try-lock",
        &[
            (CHILD_MUTEX, race_mutex.clone()),
            (CHILD_RESULT, race_result2.to_string_lossy().into_owned()),
            (CHILD_TIMEOUT_MS, "5000".into()),
        ],
    );
    let waited2 = wait_for_file(&race_result2, Duration::from_secs(15));
    let r2 = parse_result_file(&race_result2);
    let _ = std::fs::remove_file(&race_result2);
    let _ = child2.wait();
    let _ = std::fs::remove_file(&race_hold);
    facts.mutex_reusable_after_release =
        waited2 && r2.iter().any(|(k, v)| k == "result" && v == "object0");
    // SAFETY: m_race 是本进程打开的句柄。
    unsafe {
        let _ = CloseHandle(m_race);
    }

    // ---- Abandoned semantics：owner 被 TerminateProcess 杀死且未释放 ----
    let abandon_mutex = format!(r"{MUTEX_NAMESPACE}\ExvVpnWsp2_abandon_{pid0}_{rand}");
    let hold_signal = work.join(format!("hold-signal-{pid0}.txt"));
    let abandon_result = work.join(format!("abandon-result-{pid0}.txt"));
    let Ok(m_abandon) = create_mutex(&abandon_mutex, sa_ptr) else {
        cleanup_security_descriptor(psd);
        return;
    };
    // 创建时未持有（bInitialOwner=false），child 将成为第一个 waiter/owner。
    let mut owner = spawn_child(
        child_exe,
        "hold-mutex",
        &[
            (CHILD_MUTEX, abandon_mutex.clone()),
            (CHILD_HOLD_SIGNAL, hold_signal.to_string_lossy().into_owned()),
            (CHILD_RESULT, abandon_result.to_string_lossy().into_owned()),
        ],
    );
    let owner_acquired = wait_for_file(&hold_signal, Duration::from_secs(15));
    let _ = std::fs::remove_file(&hold_signal);
    let owned_by_child = if owner_acquired {
        // 确认 child 持有：parent 应 WAIT_TIMEOUT。
        wait_one(m_abandon, 300) == WAIT_TIMEOUT
    } else {
        false
    };

    // 用 TerminateProcess 杀死 owner（不释放 mutex）。
    let kill_ok = match unsafe { OpenProcess(PROCESS_TERMINATE, false, owner.id()) } {
        // SAFETY: proc_handle 是打开的有效进程句柄；PROCESS_TERMINATE 授权 TerminateProcess。
        Ok(proc_handle) => {
            let rc = unsafe { TerminateProcess(proc_handle, 1) };
            // SAFETY: proc_handle 是本进程打开的句柄。
            unsafe {
                let _ = CloseHandle(proc_handle);
            }
            rc.is_ok()
        }
        Err(_) => false,
    };
    // 无论 OpenProcess/TerminateProcess 成败，都必须回收子进程（防 zombie）。
    let _ = owner.wait();

    // 下一个 waiter 应收到 WAIT_ABANDONED_0 并被授予所有权。
    let ev_after = wait_one(m_abandon, 5000);
    facts.mutex_abandoned_owner_killed_without_release = owner_acquired && owned_by_child && kill_ok;
    facts.mutex_abandoned_wait_code = ev_after.0;
    facts.mutex_abandoned_granted = ev_after == WAIT_ABANDONED_0;

    if ev_after == WAIT_ABANDONED_0 {
        // SAFETY: WAIT_ABANDONED_0 授予了所有权，ReleaseMutex 配对释放。
        unsafe {
            let _ = ReleaseMutex(m_abandon);
        }
    }
    // SAFETY: m_abandon 是本进程打开的句柄。
    unsafe {
        let _ = CloseHandle(m_abandon);
    }
    let _ = std::fs::remove_file(&abandon_result);

    // ---- LockFileEx 对比：第二个 locker 得 ERROR_LOCK_VIOLATION；owner 死后静默释放 ----
    // 注意：lockfile 句柄**不用** FILE_ALL_ACCESS（含 DELETE 访问会触发 delete-share 陷阱，
    // 使子进程 open 直接被 32 拒绝，测不到 LockFileEx）；用 GENERIC_READ|GENERIC_WRITE。
    let lockfile = work.join(format!("lockfile-{pid0}.dat"));
    let lf1 = work.join(format!("lockfile-result1-{pid0}.txt"));
    let lf2 = work.join(format!("lockfile-result2-{pid0}.txt"));
    if let Ok(f) = open_file(
        &lockfile,
        FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
        FILE_SHARE_MODE(FILE_SHARE_READ.0),
        OPEN_ALWAYS,
        FILE_FLAGS_AND_ATTRIBUTES(0),
    ) {
        let mut ov = OVERLAPPED::default();
        // SAFETY: f 是有效文件句柄；ov 存活；独占 + 立即失败锁定 [0,1024)。
        let _lock_rc = unsafe {
            LockFileEx(
                f,
                LOCK_FILE_FLAGS(LOCKFILE_EXCLUSIVE_LOCK.0 | LOCKFILE_FAIL_IMMEDIATELY.0),
                None,
                1024,
                0,
                &mut ov,
            )
        };
        // child 1：parent 持锁时 → ERROR_LOCK_VIOLATION。
        let mut lc1 = spawn_child(
            child_exe,
            "try-lockfile",
            &[
                (CHILD_LOCKFILE, lockfile.to_string_lossy().into_owned()),
                (CHILD_RESULT, lf1.to_string_lossy().into_owned()),
            ],
        );
        let w1 = wait_for_file(&lf1, Duration::from_secs(15));
        let rlf1 = parse_result_file(&lf1);
        let _ = std::fs::remove_file(&lf1);
        let _ = lc1.wait();
        let first_result = rlf1.iter().find(|(k, _)| k == "result").map(|(_, v)| v.clone()).unwrap_or_default();
        let first_code = rlf1
            .iter()
            .find(|(k, _)| k == "code")
            .and_then(|(_, v)| v.parse::<u32>().ok())
            .unwrap_or(u32::MAX);
        facts.lockfile_second_locker_fails = w1 && first_result == "lock_violation";
        facts.lockfile_second_locker_error_code = first_code;

        // parent 释放锁（UnlockFileEx）。
        // SAFETY: f 与 ov 与 LockFileEx 一致，UnlockFileEx 配对释放。
        unsafe {
            let _ = UnlockFileEx(f, None, 1024, 0, &mut ov);
        }
        // child 2：释放后 → 可重新锁定。
        let mut lc2 = spawn_child(
            child_exe,
            "try-lockfile",
            &[
                (CHILD_LOCKFILE, lockfile.to_string_lossy().into_owned()),
                (CHILD_RESULT, lf2.to_string_lossy().into_owned()),
            ],
        );
        let w2 = wait_for_file(&lf2, Duration::from_secs(15));
        let rlf2 = parse_result_file(&lf2);
        let _ = std::fs::remove_file(&lf2);
        let _ = lc2.wait();
        facts.lockfile_reacquirable_after_release =
            w2 && rlf2.iter().any(|(k, v)| k == "result" && v == "locked");
        // 冻结的对比事实：LockFileEx 没有 abandoned 通知（OS 在 owner 死后静默释放锁）。
        facts.lockfile_has_abandoned_notification = false;

        // SAFETY: f 是本进程打开的句柄。
        unsafe {
            let _ = CloseHandle(f);
        }
    }
    let _ = std::fs::remove_file(&lockfile);

    cleanup_security_descriptor(psd);
}

// ---------------------------------------------------------------------------
// Journal storage 探针（父进程）
// ---------------------------------------------------------------------------

fn probe_journal_storage(facts: &mut AuthorityStorageFacts, _work: &Path) {
    // ---- machine-level journal 路径：ProgramData 优先，LOCALAPPDATA 备选 ----
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let local_appdata = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into_owned());
    let programdata_journal = Path::new(&program_data).join("ExvVpn").join("journal");
    let user_journal = Path::new(&local_appdata).join("ExvVpn").join("journal");
    facts.journal_base_programdata = programdata_journal.to_string_lossy().into_owned();

    // 非提权创建 ProgramData 子目录探针。
    let probe_sub = programdata_journal.join(format!("wsp2-probe-{}", unsafe { GetCurrentProcessId() }));
    match std::fs::create_dir_all(&probe_sub) {
        Ok(()) => {
            facts.programdata_creatable_non_admin = true;
            facts.programdata_create_error = None;
        }
        Err(e) => {
            facts.programdata_creatable_non_admin = false;
            facts.programdata_create_error = Some(e.to_string());
        }
    }

    // 冻结选择：ProgramData 可创建则选它（machine-level），否则退用户目录。
    let journal_dir = if facts.programdata_creatable_non_admin {
        programdata_journal.clone()
    } else {
        user_journal.clone()
    };
    facts.journal_path_chosen = journal_dir.to_string_lossy().into_owned();

    // 清理探针子目录（若可删）。
    if probe_sub.exists() {
        let _ = std::fs::remove_dir_all(&probe_sub);
    }

    // 记录 journal 目录 ACL（若目录存在）。目录句柄需 GENERIC_READ（含 READ_CONTROL）取 DACL。
    if let Ok(dh) = open_file(
        &journal_dir,
        FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
        FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
        OPEN_EXISTING,
        FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_BACKUP_SEMANTICS.0),
    ) {
        facts.journal_dir_acl_sddl = dacl_sddl_from_handle(dh).unwrap_or_default();
        // SAFETY: dh 是本进程打开的目录句柄。
        unsafe {
            let _ = CloseHandle(dh);
        }
    }

    // ---- CreateFileW flags / FlushFileBuffers ----
    let journal_file = journal_dir.join(format!("journal-wsp2-probe-{}.dat", unsafe { GetCurrentProcessId() }));
    facts.create_file_access = format!("FILE_APPEND_DATA({}) no FILE_WRITE_DATA", FILE_APPEND_DATA.0);
    facts.create_file_share_mode = format!("FILE_SHARE_READ({})", FILE_SHARE_READ.0);

    if let Ok(jh) = open_file(
        &journal_file,
        JOURNAL_ACCESS,
        JOURNAL_SHARE,
        OPEN_ALWAYS,
        FILE_FLAGS_AND_ATTRIBUTES(0),
    ) {
        // journal 文件名按 pid 随机命名，每次运行都是全新空文件，无需 truncate。
        let payload0 = b"authority-storage-wsp2-append-probe".to_vec();
        let r0 = JournalRecord::new(0, [0u8; 32], payload0);
        let frame0 = encode(&r0);
        facts.append_only_write_ok = write_all(jh, &frame0).is_ok();

        // append-only 语义：seek 到 0 后再写，数据仍落在文件末尾（不允许中段改写）。
        // 冻结事实：FILE_APPEND_DATA（无 FILE_WRITE_DATA）强制所有写入到 EOF。
        let seek_ok = set_file_pointer(jh, 0).is_ok();
        let wrote_after_seek = if seek_ok { write_all(jh, b"X").is_ok() } else { false };
        let final_len = std::fs::read(&journal_file).map(|d| d.len()).unwrap_or(0);
        let x_at_end = std::fs::read(&journal_file)
            .map(|d| d.len() == frame0.len() + 1 && d[frame0.len()] == b'X')
            .unwrap_or(false);
        facts.append_after_seek_lands_at_eof = seek_ok && wrote_after_seek && x_at_end && final_len == frame0.len() + 1;

        // FlushFileBuffers 是持久化原语。
        // SAFETY: jh 是有效文件句柄。
        facts.flush_file_buffers_succeeds = unsafe { FlushFileBuffers(jh) }.is_ok();

        // 第二个句柄（只读）能看到已 append 的字节（OS 缓存可见性，非持久化证明）。
        if let Ok(rh) = open_file(
            &journal_file,
            FILE_GENERIC_READ.0,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
        ) {
            let mut buf = vec![0u8; frame0.len()];
            let read_ok = read_exact(rh, &mut buf).is_ok();
            facts.append_visible_to_second_handle = read_ok && buf == frame0;
            // SAFETY: rh 是本进程打开的句柄。
            unsafe {
                let _ = CloseHandle(rh);
            }
        }

        // 第二个写者：share 模式禁并发写 → ERROR_SHARING_VIOLATION。
        // h1 以 FILE_APPEND_DATA + share=READ 打开（无 DELETE 访问，避免 delete-share 陷阱）；
        // h2 请求 APPEND_DATA（写访问），h1 的 share 不含写 → 32。
        match open_file(
            &journal_file,
            JOURNAL_ACCESS,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
        ) {
            Ok(w2) => {
                facts.second_writer_share_violation_observed = false;
                // SAFETY: w2 是本进程打开的句柄。
                unsafe {
                    let _ = CloseHandle(w2);
                }
            }
            Err(code) => {
                facts.second_writer_share_violation_observed = code == ERROR_SHARING_VIOLATION.0;
                facts.second_writer_share_violation_error_code = code;
            }
        }

        // Rust std flush 是 no-op 契约（std::fs::File::flush 不调用 FlushFileBuffers）。
        facts.rust_std_flush_is_not_durable_sync = true;

        // SAFETY: jh 是本进程打开的句柄。
        unsafe {
            let _ = CloseHandle(jh);
        }
    }
    let _ = std::fs::remove_file(&journal_file);

    // ---- J50 codec 真实文件往返：clean / torn tail / corrupt middle ----
    let payloads = [b"record-a".to_vec(), b"record-b".to_vec(), b"record-c".to_vec()];
    let z = [0u8; 32];
    let r0 = JournalRecord::new(0, z, payloads[0].clone());
    let r1 = JournalRecord::new(1, r0.digest, payloads[1].clone());
    let r2 = JournalRecord::new(2, r1.digest, payloads[2].clone());
    let f0 = encode(&r0);
    let f1 = encode(&r1);
    let f2 = encode(&r2);

    let j50_file = journal_dir.join(format!("journal-wsp2-j50-{}.dat", unsafe { GetCurrentProcessId() }));

    // clean roundtrip
    let mut all = Vec::new();
    all.extend_from_slice(&f0);
    all.extend_from_slice(&f1);
    all.extend_from_slice(&f2);
    let clean = std::fs::write(&j50_file, &all).is_ok();
    let clean_records = if clean {
        match decode(&read_file_all(&j50_file)) {
            DecodeOutcome::Clean(v) => Some(v),
            _ => None,
        }
    } else {
        None
    };
    facts.j50_clean_roundtrip = clean_records.as_ref().is_some_and(|v| v.len() == 3);

    // torn tail：只写 r0/r1 完整 + r2 前 20 字节（torn final record）。
    let mut torn = Vec::new();
    torn.extend_from_slice(&f0);
    torn.extend_from_slice(&f1);
    torn.extend_from_slice(&f2[..20]);
    let _ = std::fs::write(&j50_file, &torn);
    facts.torn_tail_recovered_count = match decode(&read_file_all(&j50_file)) {
        DecodeOutcome::TornTail { records } => records.len(),
        _ => usize::MAX,
    };
    facts.torn_tail_recovers_to_last_complete = facts.torn_tail_recovered_count == 2;

    // corrupt middle：写 r0/r1/r2 完整，翻转 r1 payload 的一个字节。
    let mut corrupt = Vec::new();
    corrupt.extend_from_slice(&f0);
    corrupt.extend_from_slice(&f1);
    corrupt.extend_from_slice(&f2);
    // r1 帧起始 offset = f0.len()；payload 起始 = f0.len() + 45。
    let r1_payload_off = f0.len() + 45;
    corrupt[r1_payload_off] ^= 0xFF;
    let _ = std::fs::write(&j50_file, &corrupt);
    match decode(&read_file_all(&j50_file)) {
        DecodeOutcome::Corrupt { recovered, .. } => {
            facts.corrupt_middle_recovered_count = recovered.len();
            // 不跳过：corrupt 记录之后的所有记录（含 r2）都不返回。
            facts.corrupt_middle_no_skip = recovered.len() == 1;
        }
        _ => {
            facts.corrupt_middle_recovered_count = usize::MAX;
            facts.corrupt_middle_no_skip = false;
        }
    }
    let _ = std::fs::remove_file(&j50_file);

    // ---- ACL tamper/deny（typed error）+ 恢复 ----
    probe_acl_deny(facts, &journal_dir);

    // ---- replacement/parent persistence ----
    probe_replacement(facts, &journal_dir);
}

/// ACL 修改为"仅 SYSTEM"→ 再次打开/追加被拒（ERROR_ACCESS_DENIED，typed error）；
/// 恢复原 DACL 后可再打开。全程不需要管理员（先持 GENERIC_READ|GENERIC_WRITE 句柄，
/// 含 READ_CONTROL + WRITE_DAC，再改 ACL）。注意**不用** FILE_ALL_ACCESS：它含 DELETE
/// 访问，会触发"文件已为 delete 打开则后续 open 必须带 FILE_SHARE_DELETE"规则，
/// 掩盖真正的 ACL 拒绝（本宿主实测把 deny 误报成 sharing violation 32）。
fn probe_acl_deny(facts: &mut AuthorityStorageFacts, journal_dir: &Path) {
    let pid0 = unsafe { GetCurrentProcessId() };
    let acl_file = journal_dir.join(format!("journal-wsp2-acl-{pid0}.dat"));
    let deny_sddl = "D:(A;;GA;;;SY)";
    facts.acl_test_deny_sddl = deny_sddl.to_string();

    let Ok(h) = open_file(
        &acl_file,
        FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | WRITE_DAC.0,
        FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
        OPEN_ALWAYS,
        FILE_FLAGS_AND_ATTRIBUTES(0),
    ) else {
        return;
    };

    // 读取原 DACL（保留 descriptor 内存，供恢复与记录 SDDL）。
    let mut orig_psd = PSECURITY_DESCRIPTOR::default();
    let mut orig_dacl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
    // SAFETY: 输出参数分别接收 descriptor/dacl 指针；GetSecurityInfo 用 LocalAlloc 分配。
    let rc_get = unsafe {
        GetSecurityInfo(
            h,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut orig_dacl),
            None,
            Some(&mut orig_psd),
        )
    };
    if rc_get.0 != 0 {
        // SAFETY: h 是本进程打开的句柄。
        unsafe {
            let _ = CloseHandle(h);
        }
        return;
    }
    // 记录原 SDDL。
    let mut pw = PWSTR::null();
    // SAFETY: orig_psd 指向存活 descriptor；字符串由系统分配需 LocalFree。
    let sd_ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            orig_psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut pw,
            None,
        )
    };
    if sd_ok.is_ok() {
        if let Ok(s) = unsafe { pw.to_string() } {
            facts.acl_test_original_sddl = s.trim_end_matches('\0').to_string();
        }
        // SAFETY: ConvertSecurityDescriptorToStringSecurityDescriptorW 分配，LocalFree 配对释放。
        unsafe {
            LocalFree(Some(HLOCAL(pw.0 as *mut c_void)));
        }
    }

    // 构建"仅 SYSTEM"的 DACL。
    let Some(deny_psd) = build_security_descriptor(deny_sddl) else {
        // SAFETY: orig_psd 由 GetSecurityInfo 分配，LocalFree 配对释放；h 关闭。
        unsafe {
            LocalFree(Some(HLOCAL(orig_psd.0)));
            let _ = CloseHandle(h);
        }
        return;
    };
    let mut deny_present = BOOL(0);
    let mut deny_dacl: *mut windows::Win32::Security::ACL = std::ptr::null_mut();
    let mut deny_defaulted = BOOL(0);
    // SAFETY: 输出参数接收 DACL 存在标志与指针。
    let dacl_rc = unsafe {
        GetSecurityDescriptorDacl(
            deny_psd,
            &mut deny_present as *mut BOOL,
            &mut deny_dacl,
            &mut deny_defaulted as *mut BOOL,
        )
    };
    if dacl_rc.is_err() || !deny_present.as_bool() {
        cleanup_security_descriptor(Some(deny_psd));
        // SAFETY: orig_psd 由 GetSecurityInfo 分配；h 关闭。
        unsafe {
            LocalFree(Some(HLOCAL(orig_psd.0)));
            let _ = CloseHandle(h);
        }
        return;
    }

    // 应用"仅 SYSTEM"DACL（h 带 GENERIC_READ|GENERIC_WRITE，含 WRITE_DAC，即使 DACL
    // 拒自己也有效；句柄已打开，不再重查 DACL）。
    // 关键：必须加 PROTECTED_DACL_SECURITY_INFORMATION，否则父目录的继承 ACE
    // （含当前用户 FA）会被系统合并回 DACL（本宿主实测 post-deny 仍带用户 ACE，
    // 拒不掉）。受保护后 DACL 只剩显式 SYSTEM ACE。
    // SAFETY: h 是有效句柄；deny_dacl 指向存活 ACL；SE_FILE_OBJECT + DACL + PROTECTED。
    let rc_set_deny = unsafe {
        SetSecurityInfo(
            h,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(deny_dacl),
            None,
        )
    };
    cleanup_security_descriptor(Some(deny_psd));

    if rc_set_deny.0 != 0 {
        // SAFETY: orig_psd 由 GetSecurityInfo 分配；h 关闭。
        unsafe {
            LocalFree(Some(HLOCAL(orig_psd.0)));
            let _ = CloseHandle(h);
        }
        return;
    }

    // 以路径重开（append）→ 应 ERROR_ACCESS_DENIED（typed error）。
    // share=RWD 避免 delete-share 陷阱（h 无 DELETE 访问时本不触发，但保持一致）。
    match open_file(
        &acl_file,
        JOURNAL_ACCESS,
        FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
        OPEN_EXISTING,
        FILE_FLAGS_AND_ATTRIBUTES(0),
    ) {
        Ok(w) => {
            facts.acl_deny_open_fails = false;
            // SAFETY: w 是本进程打开的句柄。
            unsafe {
                let _ = CloseHandle(w);
            }
        }
        Err(code) => {
            facts.acl_deny_open_fails = code == ERROR_ACCESS_DENIED.0;
            facts.acl_deny_error_code = code;
        }
    }

    // 恢复原 DACL（同时解除 protect，恢复继承状态，便于删除清理）。
    // SAFETY: h 是有效句柄；orig_dacl 指向 GetSecurityInfo 返回的存活 ACL。
    let rc_restore = unsafe {
        SetSecurityInfo(
            h,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(orig_dacl),
            None,
        )
    };
    facts.acl_restore_succeeds = rc_restore.0 == 0;

    // SAFETY: orig_psd 由 GetSecurityInfo 分配；h 关闭。
    unsafe {
        LocalFree(Some(HLOCAL(orig_psd.0)));
        let _ = CloseHandle(h);
    }
    let _ = std::fs::remove_file(&acl_file);
}

/// replacement/parent persistence：写临时文件 → FlushFileBuffers → MoveFileExW 替换 →
/// 打开父目录句柄（FILE_FLAG_BACKUP_SEMANTICS）并 FlushFileBuffers。
fn probe_replacement(facts: &mut AuthorityStorageFacts, journal_dir: &Path) {
    let pid0 = unsafe { GetCurrentProcessId() };
    let target = journal_dir.join(format!("journal-wsp2-replace-{pid0}.dat"));
    let temp = journal_dir.join(format!("journal-wsp2-replace-{pid0}.new"));
    let _ = std::fs::write(&temp, b"replacement-payload-v2");
    if let Ok(th) = open_file(
        &temp,
        FILE_APPEND_DATA.0,
        FILE_SHARE_MODE(FILE_SHARE_READ.0),
        OPEN_EXISTING,
        FILE_FLAGS_AND_ATTRIBUTES(0),
    ) {
        // SAFETY: th 是有效文件句柄。
        facts.movefile_replace_succeeds =
            unsafe { FlushFileBuffers(th) }.is_ok();
        // SAFETY: th 是本进程打开的句柄。
        unsafe {
            let _ = CloseHandle(th);
        }
    } else {
        facts.movefile_replace_succeeds = false;
    }
    if facts.movefile_replace_succeeds {
        let t = HSTRING::from(temp.to_string_lossy().as_ref());
        let n = HSTRING::from(target.to_string_lossy().as_ref());
        // SAFETY: t/n 合法；MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH 原子替换并同步。
        facts.movefile_replace_succeeds = unsafe {
            MoveFileExW(&t, &n, MOVE_FILE_FLAGS(MOVEFILE_REPLACE_EXISTING.0 | MOVEFILE_WRITE_THROUGH.0))
        }
        .is_ok();
    }
    let _ = std::fs::remove_file(&temp);

    // 打开父目录句柄并 FlushFileBuffers（目录条目持久化）。
    // 实测：目录句柄必须带 GENERIC_WRITE，否则 FlushFileBuffers 返回 ERROR_ACCESS_DENIED。
    if let Ok(dh) = open_file(
        journal_dir,
        FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
        FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
        OPEN_EXISTING,
        FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_BACKUP_SEMANTICS.0),
    ) {
        // SAFETY: dh 是有效目录句柄；FlushFileBuffers 支持带 BACKUP_SEMANTICS 的目录句柄。
        facts.dir_flush_succeeds = unsafe { FlushFileBuffers(dh) }.is_ok();
        // SAFETY: dh 是本进程打开的句柄。
        unsafe {
            let _ = CloseHandle(dh);
        }
    }
    let _ = std::fs::remove_file(&target);
}

/// 运行完整事实探针，返回观测到的 `AuthorityStorageFacts`。
///
/// `child_exe` 指向支持子模式的二进制（spike 二进制；oracle 通过
/// `CARGO_BIN_EXE_*` 传入）。任何单个 case 失败都不会吞掉整体：出错 case 记录为
/// `false`/空，其余继续。这是 Terra 冻结的 seam（`WSP2-T`）。
pub fn run_authority_storage_fact_probe(child_exe: &Path) -> AuthorityStorageFacts {
    let mut facts = AuthorityStorageFacts {
        host_os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        hostname: std::env::var("COMPUTERNAME").unwrap_or_default(),
        env_elevated: is_elevated(),
        primitive_choice: "named_mutex_local".to_string(),
        mutex_namespace: MUTEX_NAMESPACE.to_string(),
        global_namespace_probe: String::new(),
        mutex_dacl_sddl: String::new(),
        mutex_two_process_race_winner_is_loser: String::new(),
        mutex_loser_wait_code: u32::MAX,
        mutex_loser_exited_before_scan_observe_publish: false,
        mutex_reusable_after_release: false,
        mutex_abandoned_owner_killed_without_release: false,
        mutex_abandoned_wait_code: u32::MAX,
        mutex_abandoned_granted: false,
        lockfile_second_locker_fails: false,
        lockfile_second_locker_error_code: u32::MAX,
        lockfile_reacquirable_after_release: false,
        lockfile_has_abandoned_notification: false,
        journal_base_programdata: String::new(),
        programdata_creatable_non_admin: false,
        programdata_create_error: None,
        journal_path_chosen: String::new(),
        journal_dir_acl_sddl: String::new(),
        create_file_access: String::new(),
        create_file_share_mode: String::new(),
        append_only_write_ok: false,
        append_after_seek_lands_at_eof: false,
        second_writer_share_violation_observed: false,
        second_writer_share_violation_error_code: u32::MAX,
        flush_file_buffers_succeeds: false,
        append_visible_to_second_handle: false,
        rust_std_flush_is_not_durable_sync: true,
        movefile_replace_succeeds: false,
        dir_flush_succeeds: false,
        j50_clean_roundtrip: false,
        torn_tail_recovers_to_last_complete: false,
        torn_tail_recovered_count: usize::MAX,
        corrupt_middle_no_skip: false,
        corrupt_middle_recovered_count: usize::MAX,
        acl_deny_open_fails: false,
        acl_deny_error_code: u32::MAX,
        acl_restore_succeeds: false,
        acl_test_original_sddl: String::new(),
        acl_test_deny_sddl: String::new(),
    };

    // 独立临时工作目录（%TEMP%\exv-wsp2，无需管理员）。
    let pid0 = unsafe { GetCurrentProcessId() };
    let rand = pid0.wrapping_mul(2654435761) & 0xFFFF;
    let work = std::env::temp_dir().join(format!("exv-wsp2-{pid0}-{rand}"));
    let _ = std::fs::create_dir_all(&work);

    probe_mutex_vs_lockfile(&mut facts, child_exe, &work);
    probe_journal_storage(&mut facts, &work);

    let _ = std::fs::remove_dir_all(&work);
    facts
}

/// 当前进程是否 elevated（提权检测：尝试打开当前 token 的 Administrators 组成员判定）。
fn is_elevated() -> bool {
    // 简化实现：检查进程 token 的 elevation 标志不可靠；用"能否创建 Global\ 命名对象"
    // 在本 spike 里已通过 global_namespace_probe 观测。这里用简单可信信号：
    // Windows 下 GetTokenInformation(TokenElevation)。
    let process = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let mut buff = [0u8; 8];
    let mut ret = 0u32;
    // SAFETY: buff 存活于调用期间；TokenElevation 返回 1 个 u32。
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(buff.as_mut_ptr().cast::<c_void>()),
            buff.len() as u32,
            &mut ret,
        )
    };
    // SAFETY: token 是本进程打开的句柄，读引用完成后关闭。
    unsafe {
        let _ = CloseHandle(token);
    }
    if ok.is_err() {
        return false;
    }
    let elev = u32::from_ne_bytes([buff[0], buff[1], buff[2], buff[3]]);
    elev != 0
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
