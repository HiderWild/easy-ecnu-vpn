// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W11-I: peer authentication over a Windows byte-mode Named Pipe. The frozen WSP1 facts
// (native-pipe-facts.md §5) pin the identity query path: `GetNamedPipeClientProcessId` for the
// client PID, `OpenProcess` + `OpenProcessToken` + `GetTokenInformation(TokenUser)` for the user
// SID, `TokenLogonSid` parsed as `TOKEN_GROUPS` (`Groups[0]` at offset 8) for the logon SID, and
// `LookupAccountSidW` for the account name. Every query failure fails closed; the host verifies
// the helper PID+SID (anti fake-helper, §6).

use windows::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, SidTypeUser, TokenLogonSid, TokenUser, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, PSID,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::core::PWSTR;

use crate::named_pipe_io::NamedPipeByteStream;

/// The well-known LocalSystem account SID（`NT AUTHORITY\SYSTEM`）。服务模式 engine 由 SCM
/// 以 LocalSystem 运行——core 侧验证 service engine（server）进程身份时以此为准（D2：
/// 服务 engine 必须是特权系统服务，而非用户态冒名进程）。
pub const SYSTEM_SID: &str = "S-1-5-18";

/// A process's self-identity (PID + user SID), read from its own token.
///
/// 引擎侧自报身份的载体：engine 在 pre-gRPC 握手帧中携带自身 PID + SID，core 据此验证
/// server 身份（取代 core 侧 `OpenProcess` 读 SYSTEM 会话 0 进程 SID 的路径——该路径在
/// 标准用户下必失败，S5 真机实测 `OpenProcess` 即 err=5，见
/// `docs/superpowers/evidence/2026-08-20-service-form-closeout.md` §4.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    /// The process ID (self-identity; core cross-checks it against the pipe server PID).
    pub process_id: u32,
    /// The user SID of this process (self-identity; core compares it to the expected SID).
    pub user_sid: String,
}

/// Reads the current process's own identity (PID + user SID).
///
/// 读自进程 token 免特权（进程恒可读自身 token）——SYSTEM 服务 engine 用它自报身份，
/// 标准用户 core 无需 `OpenProcess` 该 SYSTEM 进程。任何查询失败 → `None`（fail closed）。
#[must_use]
pub fn current_process_identity() -> Option<ProcessIdentity> {
    Some(ProcessIdentity {
        process_id: std::process::id(),
        user_sid: current_user_sid()?,
    })
}

// ---------------------------------------------------------------------------
// pre-gRPC 自报身份帧（握手第 0 步；S6 engine 自报身份方案）。
//
// 线格式（固定 6 字节头 + 变长 UTF-8 SID，无自描述长度前缀歧义——先读头再读体）：
//   offset 0: process_id（u32 LE）
//   offset 4: sid_len（u16 LE）
//   offset 6: sid（UTF-8，sid_len 字节）
//
// 编解码统一放 ipc（engine 与 host 共享），避免两侧线格式漂移。
// ---------------------------------------------------------------------------

/// Self-identity frame header length：pid（u32 LE）+ sid_len（u16 LE）。
pub const IDENTITY_FRAME_HEADER_LEN: usize = 6;
/// SID 字符串长度上限（真实 SID 远短于此；恶意超长帧 fail closed）。
pub const IDENTITY_FRAME_MAX_SID_LEN: usize = 512;

/// Encodes a self-identity frame（pid + sid_len + sid）。SID 超长 → 截断到上限
/// （解码方比对真实期望 SID 时会 mismatch → fail closed，不会放行）。
#[must_use]
pub fn encode_identity_frame(identity: &ProcessIdentity) -> Vec<u8> {
    let sid_bytes = identity.user_sid.as_bytes();
    let sid_len = sid_bytes.len().min(IDENTITY_FRAME_MAX_SID_LEN);
    let mut out = Vec::with_capacity(IDENTITY_FRAME_HEADER_LEN + sid_len);
    out.extend_from_slice(&identity.process_id.to_le_bytes());
    out.extend_from_slice(&(sid_len as u16).to_le_bytes());
    out.extend_from_slice(&sid_bytes[..sid_len]);
    out
}

/// Decodes a self-identity frame。帧过短 / SID 长度超限 / 越界 / 非 UTF-8 → `None`
/// （fail closed）。
#[must_use]
pub fn decode_identity_frame(bytes: &[u8]) -> Option<ProcessIdentity> {
    if bytes.len() < IDENTITY_FRAME_HEADER_LEN {
        return None;
    }
    let process_id = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let len = u16::from_le_bytes(bytes[4..6].try_into().ok()?) as usize;
    if len > IDENTITY_FRAME_MAX_SID_LEN {
        return None;
    }
    let end = IDENTITY_FRAME_HEADER_LEN.checked_add(len)?;
    if bytes.len() < end {
        return None;
    }
    let user_sid = std::str::from_utf8(&bytes[IDENTITY_FRAME_HEADER_LEN..end])
        .ok()?
        .to_string();
    Some(ProcessIdentity {
        process_id,
        user_sid,
    })
}

/// The authenticated identity of a connected named-pipe peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPipePeer {
    /// Process ID of the connected client.
    pub process_id: u32,
    /// User SID of the connected client.
    pub user_sid: String,
    /// Logon SID of the connected client, when its token carries one.
    pub logon_sid: Option<String>,
    /// Account name resolved from the client's user SID.
    pub account_name: String,
}

/// A peer-authentication failure. Every variant fails closed (WSP1 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAuthError {
    /// A token/identity query failed; carries the raw Win32 error code.
    TokenQueryFailed(u32),
    /// The actual helper PID/SID does not match the expected one.
    SidsMismatch(String, String),
    /// A remote client was refused.
    RemoteRejected,
    /// The peer's user SID does not match the expected SID.
    NotAuthorized,
}

/// Verifies the identity of named-pipe peers against a single expected user SID.
pub struct PeerAuthenticator {
    /// The SID an authenticating peer must present (WSP1 §5 fail-closed predicate).
    expected_user_sid: String,
}

impl PeerAuthenticator {
    /// Creates an authenticator that accepts only `expected_user_sid`.
    #[must_use]
    pub const fn new(expected_user_sid: String) -> Self {
        Self { expected_user_sid }
    }

    /// Authenticates the connected client behind `server_handle`, resolving its PID, user SID,
    /// logon SID and account name. Any token/identity query failure fails closed.
    ///
    /// # Errors
    /// Returns `Err(PeerAuthError::TokenQueryFailed)` when the client PID or token cannot be
    /// resolved (e.g. no client is connected, so the query reports `ERROR_PIPE_NOT_CONNECTED`),
    /// and `Err(PeerAuthError::NotAuthorized)` when the client's user SID does not match the
    /// expected SID.
    pub fn authenticate_client(
        &self,
        server_handle: &NamedPipeByteStream,
    ) -> Result<VerifiedPipePeer, PeerAuthError> {
        let pipe = server_handle.raw_handle();

        // Resolve the client PID. Any failure (e.g. no client connected) must fail closed rather
        // than fabricate an identity.
        let mut pid: u32 = 0;
        // SAFETY: `pipe` is the owned server handle and `pid` is a live out-param for the call.
        if let Err(e) = unsafe { GetNamedPipeClientProcessId(pipe, &raw mut pid) } {
            return Err(PeerAuthError::TokenQueryFailed(win32_code(&e)));
        }

        // Open the client process with the minimum rights needed to read its token.
        // SAFETY: `pid` was resolved above; the returned handle (or error) is checked immediately.
        let process = match unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
        } {
            Ok(p) => p,
            Err(e) => return Err(PeerAuthError::TokenQueryFailed(win32_code(&e))),
        };

        // Open the client's process token. The token handle is released on every path below.
        let mut token = HANDLE(std::ptr::null_mut());
        // SAFETY: `process` is an open handle and `token` is a live out-param for the call.
        if let Err(e) = unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } {
            // SAFETY: `process` was opened above and is not closed elsewhere; release it here.
            unsafe {
                let _ = CloseHandle(process);
            }
            return Err(PeerAuthError::TokenQueryFailed(win32_code(&e)));
        }

        // Read the user SID, logon SID and account name; any query failure fails closed.
        let identity = read_identity(token);

        // SAFETY: `token` and `process` were opened above and are not closed elsewhere; release
        // them now that every query is complete.
        unsafe {
            let _ = CloseHandle(token);
            let _ = CloseHandle(process);
        }

        let (user_sid, logon_sid, account_name) = match identity {
            Ok(identity) => identity,
            Err(code) => return Err(PeerAuthError::TokenQueryFailed(code)),
        };

        if user_sid != self.expected_user_sid {
            return Err(PeerAuthError::NotAuthorized);
        }

        Ok(VerifiedPipePeer {
            process_id: pid,
            user_sid,
            logon_sid,
            account_name,
        })
    }

    /// Verifies that the observed helper identity (`actual_pid` + `actual_identity`) matches the
    /// expected helper identity (`expected_pid` + `expected_identity`), failing closed (WSP1 §6
    /// anti fake-helper). The authenticator's own expected SID is carried on `self` so the host
    /// can construct it from its configuration.
    ///
    /// # Errors
    /// Returns `Err(PeerAuthError::SidsMismatch)` when either the PID or the SID differs.
    pub fn verify_helper_identity(
        &self,
        expected_pid: u32,
        expected_identity: &str,
        actual_pid: u32,
        actual_identity: &str,
    ) -> Result<(), PeerAuthError> {
        let _ = self;
        if actual_pid != expected_pid || actual_identity != expected_identity {
            return Err(PeerAuthError::SidsMismatch(
                format!("{expected_pid}:{expected_identity}"),
                format!("{actual_pid}:{actual_identity}"),
            ));
        }
        Ok(())
    }
}

/// Resolves the current process's user SID string (the SID the local user token presents).
///
/// This is the same user SID a locally-connected named-pipe peer carries, so both the engine
/// (server-side `PeerAuthenticator::new`) and the core (client-side `verify_engine_server`) can
/// pin their expected peer SID to it (WSP1 §5).
#[must_use]
pub fn current_user_sid() -> Option<String> {
    // SAFETY: GetCurrentProcess returns a process pseudo-handle owned by the OS, never closed.
    let process = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    let mut token = HANDLE(std::ptr::null_mut());
    // SAFETY: `token` is a live out-param for the call; the opened handle is released below.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        return None;
    }
    // 自身身份只需要 TokenUser。LocalSystem 服务没有交互式 Logon SID，不能复用
    // 对端认证的完整 read_identity（它还要求 TokenLogonSid + account name）。
    let sid = read_user_sid(token).ok();
    // SAFETY: `token` was opened above and is not closed elsewhere; release it here.
    unsafe {
        let _ = CloseHandle(token);
    }
    sid
}

/// Resolves the user SID of the process with `pid`, or `None` when the process cannot be opened
/// or its token cannot be read. Every query failure returns `None` (fail closed).
#[must_use]
pub fn process_sid(pid: u32) -> Option<String> {
    // SAFETY: `pid` was resolved by the caller; the returned handle (or error) is checked now.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut token = HANDLE(std::ptr::null_mut());
    // SAFETY: `token` is a live out-param for the call; the opened handles are released below.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        // SAFETY: `process` was opened above and is not closed elsewhere; release it here.
        unsafe {
            let _ = CloseHandle(process);
        }
        return None;
    }
    let sid = read_identity(token).ok().map(|(user_sid, _, _)| user_sid);
    // SAFETY: `token` and `process` were opened above and are not closed elsewhere; release them.
    unsafe {
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
    }
    sid
}

/// Reads the user SID, logon SID and account name from `token`, in that order. Any query failure
/// propagates as the raw Win32 error code (fail closed).
fn read_identity(token: HANDLE) -> Result<(String, Option<String>, String), u32> {
    let user_buf = token_query(token, TokenUser)?;
    // SAFETY: `user_buf` begins with a valid `TOKEN_USER` whose `User.Sid` points into the buffer;
    // `Vec<u64>` and `TOKEN_USER` are both 8-byte aligned, so the pointer cast is alignment-safe.
    let user = unsafe { &*(user_buf.as_ptr().cast::<TOKEN_USER>()) };
    let user_sid = sid_to_string(user.User.Sid)?;

    let logon_buf = token_query(token, TokenLogonSid)?;
    // SAFETY: `logon_buf` begins with a valid `TOKEN_GROUPS` (`GroupCount` at offset 0, `Groups[0]`
    // at offset 8 — the frozen WSP1 §5 layout); `Vec<u64>` and `TOKEN_GROUPS` are both 8-byte
    // aligned, so the pointer cast is alignment-safe.
    let logon_sid = unsafe {
        let groups = &*(logon_buf.as_ptr().cast::<TOKEN_GROUPS>());
        if groups.GroupCount == 0 {
            None
        } else {
            Some(sid_to_string(groups.Groups[0].Sid)?)
        }
    };

    let account_name = lookup_account_name(user.User.Sid)?;

    Ok((user_sid, logon_sid, account_name))
}

/// 只读取 token 的用户 SID，供服务自身身份自报使用。
///
/// 该路径必须兼容 LocalSystem：服务 token 通常没有 `TokenLogonSid`，也不需要做账户名
/// 反查；对端认证仍使用上面的 [`read_identity`]，继续保留完整 fail-closed 校验。
fn read_user_sid(token: HANDLE) -> Result<String, u32> {
    let user_buf = token_query(token, TokenUser)?;
    // SAFETY: `user_buf` begins with a valid `TOKEN_USER`; `token_query` keeps the buffer
    // 8-byte aligned and alive for the duration of this read.
    let user = unsafe { &*(user_buf.as_ptr().cast::<TOKEN_USER>()) };
    sid_to_string(user.User.Sid)
}

/// Queries a token information class into a `Vec<u64>` buffer, sizing on the first call. The
/// `u64` element type keeps the buffer 8-byte aligned so it can be cast to `TOKEN_USER` /
/// `TOKEN_GROUPS` without a stricter-alignment cast.
fn token_query(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>, u32> {
    let mut len: u32 = 0;
    // SAFETY: the size-only query with a null buffer cannot write anywhere; `len` is a live
    // out-param the API fills with the required byte count.
    unsafe {
        let _ = GetTokenInformation(token, class, None, 0, &raw mut len);
    }
    if len == 0 {
        return Err(ERROR_INVALID_PARAMETER.0);
    }
    let size = usize::try_from(len).map_err(|_| ERROR_INVALID_PARAMETER.0)?;
    let mut buf = vec![0u64; size.div_ceil(8)];
    // SAFETY: `buf` is a live buffer of at least `len` bytes; the API writes the structure plus
    // the SID data into it and reports the same length back.
    if let Err(e) = unsafe {
        GetTokenInformation(token, class, Some(buf.as_mut_ptr().cast()), len, &raw mut len)
    } {
        return Err(win32_code(&e));
    }
    Ok(buf)
}

/// Converts a valid `PSID` to its string form, freeing the OS-allocated buffer.
fn sid_to_string(sid: PSID) -> Result<String, u32> {
    let mut ptr = PWSTR::null();
    // SAFETY: `sid` is a valid PSID owned by the caller's token buffer and `ptr` is a live
    // out-param the API allocates; the result is freed with `LocalFree` below.
    if let Err(e) = unsafe { ConvertSidToStringSidW(sid, &raw mut ptr) } {
        return Err(win32_code(&e));
    }
    let s = unsafe { ptr.to_string() }.map_err(|_| ERROR_INVALID_PARAMETER.0)?;
    // SAFETY: the string was allocated by `ConvertSidToStringSidW` and must be released.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(ptr.0.cast())));
    }
    Ok(s)
}

/// Resolves the account name for `sid` via `LookupAccountSidW` into a fixed-size buffer.
fn lookup_account_name(sid: PSID) -> Result<String, u32> {
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let mut name_len = u32::try_from(name.len()).map_err(|_| ERROR_INVALID_PARAMETER.0)?;
    let mut domain_len = u32::try_from(domain.len()).map_err(|_| ERROR_INVALID_PARAMETER.0)?;
    let mut use_enum = SidTypeUser;
    // SAFETY: `name`/`domain` are live buffers with matching length params, `use_enum` is a live
    // out-param, and `sid` is a valid PSID owned by the caller's token buffer.
    if let Err(e) = unsafe {
        LookupAccountSidW(
            None,
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &raw mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &raw mut domain_len,
            &raw mut use_enum,
        )
    } {
        return Err(win32_code(&e));
    }
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    Ok(String::from_utf16_lossy(&name[..end]))
}

/// Decodes the raw Win32 error code from a `windows` error. These kernel32 security APIs return
/// `HRESULT_FROM_WIN32`-encoded errors, which place the Win32 code in the low 16 bits.
fn win32_code(err: &windows::core::Error) -> u32 {
    let bits = u32::from_ne_bytes(err.code().0.to_ne_bytes());
    bits & 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 自报身份帧编解码往返：pid + SID 一致。
    #[test]
    fn identity_frame_round_trip() {
        let identity = ProcessIdentity {
            process_id: 0x1234_5678,
            user_sid: SYSTEM_SID.to_string(),
        };
        let frame = encode_identity_frame(&identity);
        let decoded = decode_identity_frame(&frame).expect("decode round-trip");
        assert_eq!(decoded, identity, "编解码往返必须一致");
    }

    /// `current_process_identity` 与 `current_user_sid` 一致（自进程 token 恒可读）。
    #[test]
    fn current_process_identity_matches_current_user_sid() {
        let identity = current_process_identity().expect("self identity resolvable");
        let sid = current_user_sid().expect("current user sid");
        assert_eq!(identity.user_sid, sid, "自报 SID 必须等于自进程 token 的 user SID");
        assert_eq!(identity.process_id, std::process::id(), "自报 PID 必须等于当前进程");
    }

    /// 畸形帧 fail closed：帧过短 / SID 长度越界 / 声明长度超出实际字节。
    #[test]
    fn identity_frame_malformed_fails_closed() {
        // 帧短于 6 字节头。
        assert!(decode_identity_frame(&[0u8; 3]).is_none());
        // SID 长度超出上限（u16 大值）→ 拒绝。
        let mut header_too_long = vec![0u8; IDENTITY_FRAME_HEADER_LEN];
        header_too_long[4..6]
            .copy_from_slice(&(IDENTITY_FRAME_MAX_SID_LEN as u16 + 1).to_le_bytes());
        assert!(decode_identity_frame(&header_too_long).is_none());
        // 声明长度超出实际帧长 → 拒绝。
        let mut truncated = vec![0u8; IDENTITY_FRAME_HEADER_LEN];
        truncated[4..6].copy_from_slice(&10u16.to_le_bytes());
        truncated.extend_from_slice(b"S-1-5"); // 只有 5 字节，声明 10 → 不足。
        assert!(decode_identity_frame(&truncated).is_none());
        // 非 UTF-8 SID 字节 → 拒绝。
        let mut bad_utf8 = vec![0u8; IDENTITY_FRAME_HEADER_LEN];
        bad_utf8[4..6].copy_from_slice(&1u16.to_le_bytes());
        bad_utf8.push(0xFF);
        assert!(decode_identity_frame(&bad_utf8).is_none());
    }

    /// 超长 SID 编码被截断到上限（解码方比对真实 SID 时会 mismatch → fail closed）。
    #[test]
    fn identity_frame_long_sid_truncated() {
        let long_sid = "S-1-5-21-".to_string() + &"9".repeat(IDENTITY_FRAME_MAX_SID_LEN + 10);
        let identity = ProcessIdentity {
            process_id: 7,
            user_sid: long_sid,
        };
        let frame = encode_identity_frame(&identity);
        let decoded = decode_identity_frame(&frame).expect("decodes");
        assert_eq!(decoded.user_sid.len(), IDENTITY_FRAME_MAX_SID_LEN, "截断到上限");
        assert_eq!(decoded.process_id, 7);
    }
}
