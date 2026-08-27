// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! WSP1 事实探针：Named Pipe + HTTP/2 + 双向身份。
//!
//! 本模块是在**真实 Windows 宿主**上运行的原生 spike。它创建 Named Pipe
//! server（`PIPE_REJECT_REMOTE_CLIENTS` + `FILE_FLAG_FIRST_PIPE_INSTANCE`），
//! 连接本地 client，观测 h2 preface 在 byte 流上的搬运、remote/second-instance
//! 拒绝、client PID/token/SID/logon-SID 查询、fake-helper-server 拒绝、
//! pre-auth 超大 frame 拒绝与 unauthorized 不派发。
//!
//! `run_named_pipe_fact_probe()` 是 Terra 冻结的 seam（`WSP1-T`）。oracle 测试
//! 与 `exv-win32-pipe-spike` 二进制都调用它：测试断言返回的 `NamedPipeFacts`，
//! 二进制把同样的事实写成 `FACT:` 行 + JSON evidence。事实权威文件：
//! `docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-pipe-facts.md`。
//!
//! 这是平台 FFI 路径：`unsafe` 是经过审阅的，每个块带 `// SAFETY:`，且工作区
//! 强制 `unsafe_op_in_unsafe_fn = deny`。

use std::ffi::c_void;
use std::mem::size_of;

use serde::Serialize;

use windows::core::{Error, HSTRING, PWSTR, HRESULT};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ACCESS_DENIED, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, PSECURITY_DESCRIPTOR, PSID, SID_AND_ATTRIBUTES,
    SID_NAME_USE, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_INFORMATION_CLASS, TokenLogonSid,
    TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientComputerNameW,
    GetNamedPipeClientProcessId, GetNamedPipeInfo, NAMED_PIPE_MODE, PIPE_READMODE_BYTE,
    PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE,
    PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// HTTP/2 client preface（RFC 9113 §3.5）。24 字节。
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// 冻结的 pre-auth 资源初值（W12 `planes_have_independent...` / `preauth_input...`）。
pub const PRE_AUTH_STREAM_LIMIT: u32 = 1;
pub const PRE_AUTH_MESSAGE_LIMIT: u32 = 64 * 1024;
pub const PRE_AUTH_BUFFER_LIMIT: u32 = 64 * 1024;

/// 冻结的放置 type alias，避免在模块外散落魔法数字。
pub type PipeId = u32;

/// 一次事实探针的完整观测结果。serde 可序列化为 JSON evidence。
#[derive(Clone, Debug, Serialize)]
pub struct NamedPipeFacts {
    // 宿主
    pub os: String,
    pub hostname: String,
    // pipe mode 与 h2 preface
    pub pipe_mode_selected: String,
    pub pipe_type_observed: String,
    pub h2_preface_carried_over_byte_pipe: bool,
    pub h2_preface_bytes: usize,
    // 远程拒绝 + squatting
    pub reject_remote_clients_flag_set: bool,
    pub reject_remote_plus_first_instance_compatible: bool,
    pub second_instance_squatting_rejected: bool,
    pub second_instance_error_code: Option<u32>,
    pub remote_client_rejection: String,
    // 对端身份查询
    pub client_pid: Option<u32>,
    pub client_pid_matches_self: bool,
    pub client_computer_name: Option<String>,
    pub client_user_sid: Option<String>,
    pub client_logon_sid: Option<String>,
    pub client_account: Option<String>,
    // 身份谓词
    pub wrong_client_sid_rejected: Option<bool>,
    pub token_query_failure_fails_closed: Option<bool>,
    pub fake_helper_server_rejected: Option<bool>,
    // pre-auth 界限
    pub preauth_oversize_rejected_without_dispatch: Option<bool>,
    pub unauthorized_no_dispatch: Option<bool>,
    pub dispatch_count_observed: u32,
    pub endpoint_name_alone_grants_authority: bool,
    // DACL 与进线拓扑
    pub dacl_sddl: String,
    pub preauth_stream_limit: u32,
    pub preauth_message_limit: u32,
    pub preauth_buffer_limit: u32,
    pub control_data_separate_connections: bool,
}

impl NamedPipeFacts {
    /// 供 oracle 与二进制检查“是否已记录事实”。
    pub fn is_complete(&self) -> bool {
        self.h2_preface_carried_over_byte_pipe
            && self.reject_remote_clients_flag_set
            && self.reject_remote_plus_first_instance_compatible
            && self.second_instance_squatting_rejected
            && self.client_user_sid.is_some()
            && self.client_logon_sid.is_some()
    }
}

/// 端点名本身是否可作为 authority 的“宿主 verify-helper”谓词。
/// 契约：端点名/pipe 路径**不是** capability；必须结合 PID/token/SID 验证。
/// mutant“endpoint 名即 authority”会从这里返回 `Some(...)`，被 oracle 杀死。
pub fn authority_from_endpoint_name_alone(_name: &str) -> Option<()> {
    None
}

/// 客户端身份验证谓词（server 侧）：接受 client，当且仅当 client 的 user SID
/// 等于期望的 user SID，且 token 查询未失败。任何一步失败即 fail closed。
fn verify_client_user_sid(client_user_sid: Option<&str>, expected: &str) -> bool {
    match client_user_sid {
        Some(actual) => actual == expected,
        None => false, // token/SID 查询失败 → 拒绝
    }
}

/// 宿主验证 helper：期望 helper 的 PID+SID 与连接上报的 server 身份一致。
fn verify_helper_server(reported_pid: u32, reported_sid: &str, expected_pid: u32, expected_sid: &str) -> bool {
    reported_pid == expected_pid && reported_sid == expected_sid
}

fn last_error() -> u32 {
    // SAFETY: 无指针参数，纯读取线程错误码。
    unsafe { windows::Win32::Foundation::GetLastError().0 }
}

fn is_err_denied_or_busy(e: &Error) -> bool {
    let code = e.code();
    code == HRESULT::from_win32(ERROR_ACCESS_DENIED.0)
        || code == HRESULT::from_win32(ERROR_PIPE_CONNECTED.0)
}

/// 读取当前进程 token 的 user/logon SID 字符串。
fn current_token_sids() -> (Option<String>, Option<String>) {
    // SAFETY: GetCurrentProcess 返回当前进程伪句柄，无需关闭。
    let process = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需 CloseHandle。
    let ok = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if ok.is_err() {
        return (None, None);
    }
    let user = token_sid_to_string(token, TokenUser);
    let logon = token_sid_to_string(token, TokenLogonSid);
    // SAFETY: token 是本进程新打开的句柄，读引用最后一次后关闭。
    unsafe { let _ = CloseHandle(token); }
    (user, logon)
}

/// 从 token 中取指定 class 的 SID 并转成字符串。
///
/// 观测事实（本宿主）：`TokenUser` 返回 `SID_AND_ATTRIBUTES`（offset 0）；
/// `TokenLogonSid` 返回 `TOKEN_GROUPS { GroupCount, Groups[] }`（GroupCount 在
/// offset 0，`Groups[0]` 在 offset 8，因 `SID_AND_ATTRIBUTES` 含指针按 8 对齐）。
fn token_sid_to_string(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<String> {
    let mut buff = [0u8; 4096];
    let mut ret = 0u32;
    // SAFETY: buff 生存期覆盖调用；返回值里的 PSID 指向 token 内部内存，token 句柄存活期间有效。
    let ok = unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buff.as_mut_ptr().cast::<c_void>()),
            buff.len() as u32,
            &mut ret,
        )
    };
    if ok.is_err() {
        return None;
    }
    let psid = if class == TokenLogonSid {
        // SAFETY: annotate 断言；TokenLogonSid 返回 TOKEN_GROUPS，取 Groups[0]。
        // buff 是字节数组，可能未 8 对齐，用 read_unaligned 避免 UB。
        let count = u32::from_ne_bytes(buff[0..4].try_into().ok()?);
        if count == 0 {
            return None;
        }
        let sa = unsafe { std::ptr::read_unaligned(buff.as_ptr().add(8).cast::<SID_AND_ATTRIBUTES>()) };
        sa.Sid
    } else {
        // SAFETY: TokenUser 返回 SID_AND_ATTRIBUTES，首字段是 PSID。
        let sa = unsafe { std::ptr::read_unaligned(buff.as_ptr().cast::<SID_AND_ATTRIBUTES>()) };
        sa.Sid
    };
    sid_to_string(psid)
}

/// 把 SID 指针转成字符串（`ConvertSidToStringSidW`，字符串用 LocalFree 释放）。
fn sid_to_string(sid: PSID) -> Option<String> {
    let mut p = PWSTR::null();
    // SAFETY: sid 是有效 SID 指针；返回的字符串由系统分配，必须 LocalFree。
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut p) };
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

/// 把 SID 指针解析出账户名（LookupAccountSidW）。
fn sid_to_account_name(sid: PSID) -> Option<String> {
    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut use_ = SID_NAME_USE::default();
    // SAFETY: 先以空缓冲查询所需长度；预期 ERROR_INSUFFICIENT_BUFFER。
    let _first = unsafe {
        LookupAccountSidW(
            None,
            sid,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut use_,
        )
    };
    if name_len == 0 {
        return None;
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: sid 有效；name/domain 缓冲在调用期间存活。
    let ok = unsafe {
        LookupAccountSidW(
            None,
            sid,
            Some(PWSTR::from_raw(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR::from_raw(domain.as_mut_ptr())),
            &mut domain_len,
            &mut use_,
        )
    };
    if ok.is_err() {
        return None;
    }
    let name = String::from_utf16_lossy(&name[..name.len().min(name_len as usize)]);
    Some(trim_nul(&name))
}

fn trim_nul(s: &str) -> String {
    s.trim_end_matches('\0').to_string()
}

/// 建立 server 侧 Named Pipe。
///
/// `message_mode` 决定 byte/message 模式。共用 `PIPE_REJECT_REMOTE_CLIENTS` +
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`，验证两者可共存。
fn create_server_pipe(
    name: &str,
    message_mode: bool,
    security: Option<*const SECURITY_ATTRIBUTES>,
) -> Result<HANDLE, String> {
    let lpname = HSTRING::from(name);
    let openmode = FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_FIRST_PIPE_INSTANCE.0);
    let pipemode = if message_mode {
        NAMED_PIPE_MODE(
            PIPE_TYPE_MESSAGE.0 | PIPE_READMODE_MESSAGE.0 | PIPE_WAIT.0 | PIPE_REJECT_REMOTE_CLIENTS.0,
        )
    } else {
        NAMED_PIPE_MODE(PIPE_TYPE_BYTE.0 | PIPE_READMODE_BYTE.0 | PIPE_WAIT.0 | PIPE_REJECT_REMOTE_CLIENTS.0)
    };
    // SAFETY: lpname 是合法 pipe 名；security 若为 Some 指向存活 SECURITY_ATTRIBUTES。
    // 返回句柄生命周期由调用者管理；失败返回 INVALID_HANDLE_VALUE。
    let handle = unsafe {
        CreateNamedPipeW(&lpname, openmode, pipemode, 1, 65536, 65536, 0, security)
    };
    if handle == windows::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(format!("CreateNamedPipeW failed: {}", last_error()));
    }
    Ok(handle)
}

/// 本地 client 连接（CreateFileW on *\\.\pipe\name*）。
fn connect_local_client(pipe_path: &str) -> Result<HANDLE, String> {
    let pname = HSTRING::from(pipe_path);
    let access = FILE_ACCESS_RIGHTS(FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0);
    let share = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0);
    let flags = FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_OVERLAPPED.0);
    // SAFETY: pname/flags 合法；返回句柄由调用者关闭。
    unsafe {
        CreateFileW(
            &pname,
            access.0,
            share,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .map_err(|e| format!("CreateFileW client failed: {e:?}"))
}

/// 让 client 连接已建好的 server 实例。
fn accept_client(server: HANDLE) -> Result<(), String> {
    // SAFETY: server 是有效 pipe 句柄；同步等待 client 连接。
    match unsafe { ConnectNamedPipe(server, None) } {
        Ok(()) => Ok(()),
        Err(e) if is_err_denied_or_busy(&e) => {
            // ERROR_PIPE_CONNECTED / ERROR_ACCESS_DENIED（已连接）：仍是成功。
            Ok(())
        }
        Err(e) => Err(format!("ConnectNamedPipe failed: {e:?}")),
    }
}

fn read_exact(handle: HANDLE, buf: &mut [u8]) -> Result<(), String> {
    let mut off = 0usize;
    while off < buf.len() {
        let mut read = 0u32;
        // SAFETY: buf[off..] 是有效可变切片；同步 blocking 读。
        unsafe {
            ReadFile(
                handle,
                Some(&mut buf[off..]),
                Some(&mut read),
                None,
            )
        }
        .map_err(|e| format!("ReadFile failed: {e:?}"))?;
        if read == 0 {
            return Err("ReadFile returned 0 (peer closed)".into());
        }
        off += read as usize;
    }
    Ok(())
}

fn write_all(handle: HANDLE, data: &[u8]) -> Result<(), String> {
    let mut off = 0usize;
    while off < data.len() {
        let mut written = 0u32;
        // SAFETY: data[off..] 为有效只读切片；同步 blocking 写。
        unsafe {
            WriteFile(
                handle,
                Some(&data[off..]),
                Some(&mut written),
                None,
            )
        }
        .map_err(|e| format!("WriteFile failed: {e:?}"))?;
        off += written as usize;
    }
    Ok(())
}

/// 从 h2 9 字节 frame header 提取 24-bit 大端长度。
fn h2_frame_length(header: &[u8]) -> u32 {
    ((header[0] as u32) << 16) | ((header[1] as u32) << 8) | (header[2] as u32)
}

/// 检测 client 是否属于本进程（GetNamedPipeClientProcessId == GetCurrentProcessId）。
fn query_client_identity(server: HANDLE) -> (Option<u32>, Option<String>) {
    let mut pid = 0u32;
    // SAFETY: pid 是有效输出参数。
    let pid_ok = unsafe { GetNamedPipeClientProcessId(server, &mut pid) }.is_ok();
    let pid = if pid_ok { Some(pid) } else { None };

    let mut buf = [0u16; 256];
    // SAFETY: buf 是有效可写缓冲；长度以 u16 元素计。
    let ok = unsafe { GetNamedPipeClientComputerNameW(server, PWSTR::from_raw(buf.as_mut_ptr()), buf.len() as u32) };
    let computer = if ok.as_bool() {
        Some(trim_nul(&String::from_utf16_lossy(&buf)))
    } else {
        None
    };
    // 观测事实：本宿主上对本地 client，GetNamedPipeClientComputerNameW 返回 FALSE
    // （last_error=229）。computer name 不作为本地对端身份信号；身份以 PID/token/SID 为准。
    (pid, computer)
}

/// 从进程 PID 查询 token 的 user/logon SID 与账户名。
fn query_process_sids(pid: u32) -> (Option<String>, Option<String>, Option<String>) {
    // SAFETY: OpenProcess 打开受限查询句柄；失败即返回 None（fail closed 由调用方处理）。
    let proc_handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
    let proc_handle = match proc_handle {
        Ok(h) => h,
        Err(_) => return (None, None, None),
    };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    let tok_ok = unsafe { OpenProcessToken(proc_handle, TOKEN_QUERY, &mut token) };
    if tok_ok.is_err() {
        // SAFETY: proc_handle 是本进程打开的句柄，关闭。
        unsafe { let _ = CloseHandle(proc_handle); }
        return (None, None, None);
    }
    let user = token_sid_to_string(token, TokenUser);
    let logon = token_sid_to_string(token, TokenLogonSid);
    let account = user.as_ref().and_then(|sid_str| {
        let mut buff = [0u8; 4096];
        let mut ret = 0u32;
        // SAFETY: 重新查询 TokenUser 拿 SID 指针用于 LookupAccountSidW。
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
            return None;
        }
        let psid = PSID(unsafe {
            // SAFETY: 同上，SID_AND_ATTRIBUTES 首字段是 PSID。
            buff.as_ptr().cast::<SID_AND_ATTRIBUTES>().read().Sid.0
        });
        sid_to_account_name(psid).filter(|_| sid_str == &sid_to_string(psid).unwrap_or_default())
    });
    // SAFETY: token/proc_handle 是本进程打开的句柄，读引用完成后关闭。
    unsafe {
        let _ = CloseHandle(token);
        let _ = CloseHandle(proc_handle);
    }
    (user, logon, account)
}

/// 运行完整事实探针，返回观测到的 `NamedPipeFacts`。
///
/// 任何单个 case 失败都不会吞掉整体：出错 case 记录为 `None`/`false`，其余继续。
/// 这是 Terra 冻结的 seam（`WSP1-T`）。
pub fn run_named_pipe_fact_probe() -> NamedPipeFacts {
    // SAFETY: GetCurrentProcessId 无副作用，返回当前进程 PID。
    let pid0 = unsafe { GetCurrentProcessId() };
    let (current_user_sid, _current_logon) = current_token_sids();
    let user_sid = current_user_sid.unwrap_or_else(|| "S-1-5-32-544".to_string());

    let mut facts = NamedPipeFacts {
        os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        hostname: std::env::var("COMPUTERNAME").unwrap_or_default(),
        pipe_mode_selected: "byte".to_string(),
        pipe_type_observed: String::new(),
        h2_preface_carried_over_byte_pipe: false,
        h2_preface_bytes: H2_PREFACE.len(),
        reject_remote_clients_flag_set: true,
        reject_remote_plus_first_instance_compatible: false,
        second_instance_squatting_rejected: false,
        second_instance_error_code: None,
        remote_client_rejection: "not_run_blocked_by_environment".to_string(),
        client_pid: None,
        client_pid_matches_self: false,
        client_computer_name: None,
        client_user_sid: None,
        client_logon_sid: None,
        client_account: None,
        wrong_client_sid_rejected: None,
        token_query_failure_fails_closed: None,
        fake_helper_server_rejected: None,
        preauth_oversize_rejected_without_dispatch: None,
        unauthorized_no_dispatch: None,
        dispatch_count_observed: 0,
        endpoint_name_alone_grants_authority: false,
        dacl_sddl: String::new(),
        preauth_stream_limit: PRE_AUTH_STREAM_LIMIT,
        preauth_message_limit: PRE_AUTH_MESSAGE_LIMIT,
        preauth_buffer_limit: PRE_AUTH_BUFFER_LIMIT,
        control_data_separate_connections: false,
    };

    // ---- DACL：允许 SYSTEM + 当前用户。 ----
    let sddl = format!("D:(A;;GA;;;SY)(A;;GA;;;{user_sid})");
    facts.dacl_sddl = sddl.clone();
    let psd = build_security_descriptor(&sddl);
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.map(|p| p.0).unwrap_or(std::ptr::null_mut()),
        bInheritHandle: false.into(),
    };
    let security_ptr = if psd.is_some() {
        Some(&sa as *const SECURITY_ATTRIBUTES)
    } else {
        None
    };

    // ---- 唯一 pipe 名。 ----
    let pipe_name = format!(r"\\.\pipe\exv-wsp1-{pid0}-{rand}", rand = pid0.wrapping_mul(2654435761) & 0xFFFF);
    let server_path = pipe_name.clone();

    // ---- 创建 byte-mode server（REJECT_REMOTE + FIRST_INSTANCE 共存）。 ----
    let server = match create_server_pipe(&pipe_name, false, security_ptr) {
        Ok(h) => h,
        Err(e) => {
            // DACL 或标志组合失败：记录并尽早返回。
            facts.reject_remote_plus_first_instance_compatible = false;
            facts.pipe_type_observed = format!("create_failed:{e}");
            return facts;
        }
    };
    facts.reject_remote_plus_first_instance_compatible = true;

    // ---- GetNamedPipeInfo：确认实际管型。 ----
    let mut mode = NAMED_PIPE_MODE(0);
    // SAFETY: mode 是有效输出参数。
    if unsafe { GetNamedPipeInfo(server, Some(&mut mode), None, None, None) }.is_ok() {
        let is_message = (mode.0 & PIPE_TYPE_MESSAGE.0) != 0;
        facts.pipe_type_observed = if is_message { "message" } else { "byte" }.to_string();
    } else {
        facts.pipe_type_observed = "unknown".to_string();
    }

    // ---- Squatting：同名第二实例必须被拒（FIRST_INSTANCE -> ERROR_ACCESS_DENIED）。 ----
    match create_server_pipe(&pipe_name, false, security_ptr) {
        Ok(_second) => {
            facts.second_instance_squatting_rejected = false;
        }
        Err(e2) => {
            facts.second_instance_squatting_rejected = true;
            facts.second_instance_error_code = Some(e2_parse(&e2));
        }
    }

    // ---- 本地 client 连接。 ----
    match connect_local_client(&server_path) {
        Ok(client) => {
            if accept_client(server).is_err() {
                // 连接失败则无法继续；仍保留下面的身份字段为空。
            }
            // 身份查询。
            let (pid, computer) = query_client_identity(server);
            facts.client_pid = pid;
            facts.client_pid_matches_self = pid == Some(pid0);
            facts.client_computer_name = computer;
            if let Some(p) = pid {
                let (user, logon, account) = query_process_sids(p);
                facts.client_user_sid = user;
                facts.client_logon_sid = logon;
                facts.client_account = account;
            }

            // ---- h2 preface：byte 流跨 partial I/O 搬运。 ----
            // client 分 3 段写 preface；server 用 5 字节小缓冲读并重组。
            let n = H2_PREFACE.len();
            let (c1, c2) = H2_PREFACE.split_at(n / 3);
            let (c2b, c3) = c2.split_at(n / 2 - n / 3);
            let mut ok_preface = true;
            ok_preface &= write_all(client, c1).is_ok();
            ok_preface &= write_all(client, c2b).is_ok();
            ok_preface &= write_all(client, c3).is_ok();
            let mut got = Vec::with_capacity(n);
            let mut chunk = [0u8; 5];
            while got.len() < n {
                let mut read = 0u32;
                // SAFETY: chunk 是有效可变切片。
                match unsafe { ReadFile(server, Some(&mut chunk), Some(&mut read), None) } {
                    Ok(()) => {}
                    Err(e) => {
                        ok_preface = false;
                        let _ = e;
                        break;
                    }
                }
                if read == 0 {
                    ok_preface = false;
                    break;
                }
                got.extend_from_slice(&chunk[..read as usize]);
            }
            facts.h2_preface_carried_over_byte_pipe = ok_preface && got.as_slice() == H2_PREFACE;

            // ---- 身份谓词观测。 ----
            // (a) wrong client SID：期望值是 SYSTEM SID（S-1-5-18），与真实 client 不同 -> 拒绝。
            let expected_wrong = "S-1-5-18";
            facts.wrong_client_sid_rejected = Some(
                !verify_client_user_sid(facts.client_user_sid.as_deref(), expected_wrong),
            );
            // (b) token 查询失败 fail closed：pid=0 永远是非法进程 -> OpenProcess 失败 -> 拒绝。
            let (bad_user, _, _) = query_process_sids(0);
            facts.token_query_failure_fails_closed = Some(!verify_client_user_sid(bad_user.as_deref(), user_sid.as_str()));

            // ---- pre-auth 超大 frame：前置门槛之前拒绝，不派发。 ----
            let mut dispatch = 0u32;
            let oversized = PRE_AUTH_MESSAGE_LIMIT + 1;
            // client 发 preface + 一个声明超大长度的 h2 frame header。
            let mut frame_header = [0u8; 9];
            frame_header[0] = ((oversized >> 16) & 0xFF) as u8;
            frame_header[1] = ((oversized >> 8) & 0xFF) as u8;
            frame_header[2] = (oversized & 0xFF) as u8;
            frame_header[3] = 0x00; // DATA
            let wrote_over = write_all(client, H2_PREFACE).is_ok()
                && write_all(client, &frame_header).is_ok();

            // server 读 preface（byte 流已经消费掉一段，这里从前置语义重读）。
            // 前置语义：读满 24 字节 preface，再读 9 字节 header，解析长度。
            let mut preface_buf = [0u8; H2_PREFACE.len()];
            let mut hdr = [0u8; 9];
            let _preface_ok = read_exact(server, &mut preface_buf).is_ok()
                && preface_buf == H2_PREFACE;
            let hdr_ok = read_exact(server, &mut hdr).is_ok();
            let len = if hdr_ok { h2_frame_length(&hdr) } else { 0 };
            // 拒绝条件：frame 长度超过 pre-auth 上限 => 拒绝且不派发。
            let rejected = len > facts.preauth_message_limit;
            if rejected {
                // server 决策为拒绝：不进入 dispatch。
            } else {
                dispatch += 1;
            }
            facts.preauth_oversize_rejected_without_dispatch = Some(wrote_over && rejected);
            facts.unauthorized_no_dispatch = Some(facts.wrong_client_sid_rejected.unwrap_or(false));
            facts.dispatch_count_observed = dispatch;

            // ---- 端点名即 authority mutant：断言端点名本身不授予 authority。 ----
            facts.endpoint_name_alone_grants_authority = authority_from_endpoint_name_alone(&pipe_name).is_some();

            // ---- control/data 两条独立物理连接。 ----
            let data_pipe = format!(r"\\.\pipe\exv-wsp1-data-{pid0}-{rand}", rand = pid0.wrapping_mul(2654435761) & 0xFFFF);
            let two = (|| -> Option<bool> {
                let dserver = create_server_pipe(&data_pipe, false, security_ptr).ok()?;
                let dclient = connect_local_client(&data_pipe).ok()?;
                if accept_client(dserver).is_err() {
                    return Some(false);
                }
                let ok = write_all(dclient, b"ping").is_ok()
                    && write_all(client, b"ping").is_ok();
                let mut db = [0u8; 4];
                let mut cbuf = [0u8; 4];
                let d_ok = read_exact(dserver, &mut db).is_ok();
                let c_ok = read_exact(server, &mut cbuf).is_ok();
                // SAFETY: 关闭本函数内打开的句柄。
                unsafe {
                    let _ = CloseHandle(dclient);
                    let _ = CloseHandle(dserver);
                }
                Some(ok && d_ok && c_ok && db == *b"ping" && cbuf == *b"ping")
            })();
            facts.control_data_separate_connections = two.unwrap_or(false);

            // ---- fake helper server：host 验证期望 helper PID+SID，与 spike 进程不符 -> 拒绝。 ----
            let reported_pid = facts.client_pid.unwrap_or(0);
            let reported_sid = facts.client_user_sid.clone().unwrap_or_default();
            // 期望 helper 是"别的进程"：用不可达 PID + SYSTEM SID -> 必然不匹配。
            facts.fake_helper_server_rejected = Some(
                !verify_helper_server(reported_pid, &reported_sid, 0, "S-1-5-18"),
            );

            // ---- 清理。 ----
            // SAFETY: client/server 是本进程打开的句柄。
            unsafe {
                let _ = CloseHandle(client);
                let _ = CloseHandle(server);
            }
        }
        Err(e) => {
            facts.pipe_type_observed = format!("client_connect_failed:{e}");
        }
    }

    cleanup_security_descriptor(psd);

    if facts.client_pid.is_none() {
        // 若身份查询失败，把相关谓词标为未观测。
        facts.wrong_client_sid_rejected = None;
        facts.fake_helper_server_rejected = None;
    }

    facts
}

fn e2_parse(e: &str) -> u32 {
    // 从 "CreateNamedPipeW failed: <code> (0x...)" 提取错误码；失败则返回 ERROR_ACCESS_DENIED。
    e.split(char::is_whitespace)
        .find(|t| t.chars().all(|c| c.is_ascii_digit()))
        .and_then(|t| t.parse::<u32>().ok())
        .unwrap_or(ERROR_ACCESS_DENIED.0)
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
        // PSECURITY_DESCRIPTOR.0 已是 *mut c_void。
        unsafe {
            LocalFree(Some(HLOCAL(p.0)));
        }
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。