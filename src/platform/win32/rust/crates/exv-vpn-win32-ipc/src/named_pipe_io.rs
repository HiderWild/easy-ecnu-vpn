// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W10-I: a byte-mode Windows Named Pipe stream. This is the platform FFI path; the frozen
// WSP1 facts (native-pipe-facts.md) pin byte mode (PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
// PIPE_WAIT) as the only transport that carries an h2 preface across partial I/O. Message
// mode is a wrong mutant and is never created here.

use std::iter::once;

use crate::pipe_security::PipeSecurity;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, GENERIC_READ, GENERIC_WRITE, ERROR_BROKEN_PIPE, ERROR_NO_DATA,
    ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAGS_AND_ATTRIBUTES,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, FILE_SHARE_MODE,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PeekNamedPipe, SetNamedPipeHandleState, WaitNamedPipeW,
    NAMED_PIPE_MODE, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::core::{Error as Win32Error, PCWSTR};

/// A byte-mode Windows Named Pipe stream producing/consuming a raw byte stream.
///
/// The pipe is created in byte mode (`PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT`), which
/// is the only mode that preserves an h2/gRPC byte stream across partial reads and writes
/// (WSP1 §1). Message mode would re-introduce message framing and is rejected by construction.
#[derive(Debug)]
pub struct NamedPipeByteStream {
    /// Owned handle from `CreateNamedPipeW` (server) or `CreateFileW` (client). Closed by `Drop`.
    handle: HANDLE,
}

// SAFETY: `NamedPipeByteStream` owns a Windows pipe `HANDLE`。管道句柄是内核对象，
// 任何线程都可用；所有权跨线程转移是 sound 的，只要排除并发使用（由所有权转移 /
// 调用方的 Mutex 保证）。本类型刻意**不**实现 `Sync`：多个线程经共享 `&self` 并发
// `read` 会在同一句柄上竞争，不 sound。
unsafe impl Send for NamedPipeByteStream {}

/// I/O result for the byte-mode pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipeIoError {
    /// The peer closed its end of the pipe (EOF, broken pipe, or pipe not connected).
    PeerClosed,
    /// A Win32 error, carrying the raw `GetLastError`/`HRESULT`-decoded code.
    Io(u32),
}

impl NamedPipeByteStream {
    /// Creates a server-side byte-mode pipe instance. `max_instances` bounds concurrent
    /// client connections; `FILE_FLAG_FIRST_PIPE_INSTANCE` makes a second create of the same
    /// name fail (anti-squatting, WSP1 §2) and `PIPE_REJECT_REMOTE_CLIENTS` (WSP1 §2) refuses
    /// remote clients at the NT layer.
    ///
    /// The pipe is created with no explicit DACL (the caller's default ACL applies); use
    /// [`create_server_with_dacl`](Self::create_server_with_dacl) to grant a specific user.
    ///
    /// # Errors
    /// Returns `Err(PipeIoError::Io(code))` if `CreateNamedPipeW` fails (e.g. the name is
    /// already owned by another first instance, WSP1 §2 anti-squatting).
    pub fn create_server(name: &str, max_instances: u32) -> Result<Self, PipeIoError> {
        Self::create_server_with_dacl(name, max_instances, None)
    }

    /// Creates a server-side byte-mode pipe instance whose DACL grants `SYSTEM` plus exactly
    /// `allowed_user_sid`, both `GA` (the frozen WSP1 §4 shape, via [`PipeSecurity`]).
    ///
    /// Without an explicit DACL a pipe created by the elevated engine falls back to the default
    /// ACL, which only admits SYSTEM and the Administrators group — refusing the unelevated core
    /// client with `ERROR_ACCESS_DENIED` (5). Passing `Some(core_user_sid)` grants that user,
    /// so the ordinary-token core can connect across the elevated/unelevated boundary.
    ///
    /// When `allowed_user_sid` is `None` the pipe is created with no explicit DACL, preserving
    /// the [`create_server`](Self::create_server) behavior.
    ///
    /// # Errors
    /// Returns `Err(PipeIoError::Io(code))` if the DACL cannot be materialized or
    /// `CreateNamedPipeW` fails (e.g. the name is already owned by another first instance,
    /// WSP1 §2 anti-squatting).
    pub fn create_server_with_dacl(
        name: &str,
        max_instances: u32,
        allowed_user_sid: Option<&str>,
    ) -> Result<Self, PipeIoError> {
        Self::create_server_inner(name, max_instances, allowed_user_sid, true)
    }

    /// 创建同名的**额外** server 实例（不带 `FILE_FLAG_FIRST_PIPE_INSTANCE`）。第一个
    /// 实例由 [`create_server_with_dacl`](Self::create_server_with_dacl) 建（反 squat，
    /// 确保唯一 server 持名）；其余实例供多客户端同时连入（如 log 管道——engine + 未来
    /// UI 各占一个实例）。断开后由 accept 循环重建同款额外实例。
    ///
    /// `max_instances` 必须与第一实例一致（`CreateNamedPipeW` 以它作为该管道名的总实例
    /// 上限）。
    ///
    /// # Errors
    /// 同 [`create_server_with_dacl`](Self::create_server_with_dacl)：`CreateNamedPipeW`
    /// 失败（通常为已达 `max_instances` 上限 → `ERROR_PIPE_BUSY`）。
    pub fn create_server_additional_with_dacl(
        name: &str,
        max_instances: u32,
        allowed_user_sid: Option<&str>,
    ) -> Result<Self, PipeIoError> {
        Self::create_server_inner(name, max_instances, allowed_user_sid, false)
    }

    fn create_server_inner(
        name: &str,
        max_instances: u32,
        allowed_user_sid: Option<&str>,
        first_instance: bool,
    ) -> Result<Self, PipeIoError> {
        let wide = to_wide(name);
        let pipe_mode = NAMED_PIPE_MODE(
            PIPE_TYPE_BYTE.0 | PIPE_READMODE_BYTE.0 | PIPE_WAIT.0 | PIPE_REJECT_REMOTE_CLIENTS.0,
        );
        let mut open_flags = PIPE_ACCESS_DUPLEX.0;
        if first_instance {
            open_flags |= FILE_FLAG_FIRST_PIPE_INSTANCE.0;
        }
        let open_mode = FILE_FLAGS_AND_ATTRIBUTES(open_flags);
        // Build the DACL (SYSTEM + allowed user SID) when one is requested. `sec` owns the
        // descriptor that `sec_attrs` points into; both stay alive for the CreateNamedPipeW call.
        let sec = allowed_user_sid
            .map(|sid| PipeSecurity::new(sid, true).map_err(PipeIoError::Io))
            .transpose()?;
        let sec_attrs = sec.as_ref().map(PipeSecurity::as_attributes);
        let lp_security_attrs = sec_attrs
            .as_ref()
            .map(|a| a as *const SECURITY_ATTRIBUTES);
        // SAFETY: `wide` is a live, null-terminated wide buffer for the lifetime of this call;
        // `lp_security_attrs` (when `Some`) points at the live `sec_attrs` copy, whose
        // `lpSecurityDescriptor` points at the live `sec`-owned descriptor. The returned handle
        // (or INVALID_HANDLE_VALUE) is checked immediately below.
        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                open_mode,
                pipe_mode,
                max_instances,
                4096,
                4096,
                0,
                lp_security_attrs,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            // SAFETY: checked immediately after the failed CreateNamedPipeW, so this reads the
            // error code that call set.
            return Err(PipeIoError::Io(unsafe { GetLastError().0 }));
        }
        Ok(Self { handle })
    }

    /// Blocks until a client connects to this server instance. Returns `Ok` if the client is
    /// already connected (`ERROR_PIPE_CONNECTED`), which can happen across a create/connect
    /// race on the same instance.
    ///
    /// # Errors
    /// Returns `Err(PipeIoError::Io(code))` if `ConnectNamedPipe` fails for a reason other than
    /// the already-connected `ERROR_PIPE_CONNECTED` case.
    pub fn connect(&self) -> Result<(), PipeIoError> {
        // SAFETY: `self.handle` is the owned server pipe handle for the lifetime of `self`.
        match unsafe { ConnectNamedPipe(self.handle, None) } {
            Ok(()) => Ok(()),
            Err(e) => {
                if win32_error_code(&e) == ERROR_PIPE_CONNECTED.0 {
                    Ok(())
                } else {
                    Err(PipeIoError::Io(win32_error_code(&e)))
                }
            }
        }
    }

    /// Connects to an existing server pipe at `\\.\pipe\<name>`. If the pipe is momentarily
    /// busy (`ERROR_PIPE_BUSY`), waits for an instance and retries a bounded number of times.
    /// Then pins the client to byte read mode, failing closed if that cannot be established.
    ///
    /// # Errors
    /// Returns `Err(PipeIoError::Io(code))` if the pipe cannot be opened (and retries are
    /// exhausted on `ERROR_PIPE_BUSY`), or `Err` if the byte read mode cannot be pinned.
    pub fn connect_client(name: &str) -> Result<Self, PipeIoError> {
        let wide = to_wide(name);
        let name_ptr = PCWSTR(wide.as_ptr());
        let mut handle: Option<HANDLE> = None;
        for _ in 0..5 {
            // SAFETY: `name_ptr` points into the live null-terminated `wide` buffer; the
            // returned handle is validated by the wrapper (INVALID_HANDLE_VALUE -> Err).
            match unsafe {
                CreateFileW(
                    name_ptr,
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(0),
                    None,
                )
            } {
                Ok(h) => {
                    handle = Some(h);
                    break;
                }
                Err(e) => {
                    let code = win32_error_code(&e);
                    if code != ERROR_PIPE_BUSY.0 {
                        return Err(PipeIoError::Io(code));
                    }
                    // SAFETY: `name_ptr` points into the live null-terminated `wide` buffer;
                    // the BOOL return is ignored on the retry path, which re-attempts CreateFileW.
                    unsafe {
                        let _ = WaitNamedPipeW(name_ptr, 5000);
                    }
                }
            }
        }
        let handle = handle.ok_or(PipeIoError::Io(ERROR_PIPE_BUSY.0))?;
        let mode = NAMED_PIPE_MODE(PIPE_READMODE_BYTE.0);
        // SAFETY: `self.handle` is the owned client pipe handle; `mode` is live for the call.
        // Fail closed: if we cannot pin byte read mode, release the handle and error out.
        let result = unsafe { SetNamedPipeHandleState(handle, Some(&raw const mode), None, None) };
        if let Err(e) = result {
            // SAFETY: `handle` was created by CreateFileW above and is not closed elsewhere;
            // releasing it on the error path avoids leaking the kernel object.
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err(PipeIoError::Io(win32_error_code(&e)));
        }
        Ok(Self { handle })
    }

    /// Reads up to `buf.len()` bytes. Returns `PeerClosed` on a clean peer EOF (zero bytes
    /// read) or when the peer's pipe is broken/not connected.
    ///
    /// Takes `&self` because the underlying `ReadFile` needs only the (`Copy`) handle plus a
    /// caller-owned mutable buffer; the test contract calls `read` on immutable server bindings.
    ///
    /// # Errors
    /// Returns `Err(PipeIoError::PeerClosed)` on EOF / broken pipe, or
    /// `Err(PipeIoError::Io(code))` for any other `ReadFile` failure.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize, PipeIoError> {
        let mut bytes_read: u32 = 0;
        // SAFETY: `self.handle` is the owned pipe handle; `buf` is a live mutable slice and
        // `bytes_read` is a live out-param for the duration of the call.
        match unsafe { ReadFile(self.handle, Some(buf), Some(&raw mut bytes_read), None) } {
            Ok(()) if bytes_read == 0 => Err(PipeIoError::PeerClosed),
            Ok(()) => Ok(bytes_read as usize),
            Err(e) => {
                let code = win32_error_code(&e);
                if code == ERROR_BROKEN_PIPE.0 || code == ERROR_PIPE_NOT_CONNECTED.0 {
                    Err(PipeIoError::PeerClosed)
                } else {
                    Err(PipeIoError::Io(code))
                }
            }
        }
    }

    /// Writes all of `buf`, looping over partial `WriteFile` writes. A peer that has gone away
    /// mid-write is reported as `PeerClosed`.
    ///
    /// # Errors
    /// Returns `Err(PipeIoError::PeerClosed)` if the peer goes away mid-write, or
    /// `Err(PipeIoError::Io(code))` for any other `WriteFile` failure.
    pub fn write_all(&mut self, mut buf: &[u8]) -> Result<(), PipeIoError> {
        while !buf.is_empty() {
            let mut written: u32 = 0;
            // SAFETY: `self.handle` is the owned pipe handle; `buf` is a live slice for the
            // duration of the call and `written` is a live out-param.
            match unsafe { WriteFile(self.handle, Some(buf), Some(&raw mut written), None) } {
                Ok(()) => buf = &buf[written as usize..],
                Err(e) => {
                    let code = win32_error_code(&e);
                    if code == ERROR_NO_DATA.0 || code == ERROR_BROKEN_PIPE.0 {
                        return Err(PipeIoError::PeerClosed);
                    }
                    return Err(PipeIoError::Io(code));
                }
            }
        }
        Ok(())
    }

    /// Returns `true` because this stream is always created in byte mode, never message mode.
    #[must_use]
    pub fn is_byte_mode(&self) -> bool {
        true
    }

    /// Returns the underlying Win32 pipe handle for platform identity/authentication calls.
    ///
    /// The handle remains owned by this stream and is only borrowed for the duration of the
    /// caller's use; the caller must not close it.
    #[must_use]
    pub(crate) fn raw_handle(&self) -> HANDLE {
        self.handle
    }

    /// Returns `true` when the pipe has at least one byte available to read without blocking.
    ///
    /// This is a non-consuming peek (`PeekNamedPipe`, byte mode), used by the control-plane
    /// client to drain a reply batch after its primary reply without a second blocking read.
    #[must_use]
    pub fn has_pending_data(&self) -> bool {
        let mut total_bytes_avail = 0u32;
        // SAFETY: `self.handle` is the owned pipe handle for the lifetime of `self`; the
        // `PeekNamedPipe` byte-mode call does not consume data and writes only `total_bytes_avail`.
        let ok = unsafe {
            PeekNamedPipe(
                self.handle,
                None,
                0,
                None,
                Some(&raw mut total_bytes_avail),
                None,
            )
        }
        .is_ok();
        ok && total_bytes_avail > 0
    }
}

impl Drop for NamedPipeByteStream {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is the owned pipe handle created by CreateNamedPipeW/CreateFileW
        // and has not been closed elsewhere; closing it releases the kernel pipe object.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Encodes a Rust string as a null-terminated UTF-16 buffer for the `*W` APIs.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(once(0)).collect()
}

/// Decodes the raw Win32 error code from a `windows` error. These kernel32 pipe/file functions
/// return `HRESULT_FROM_WIN32`-encoded errors, which place the Win32 code in the low 16 bits.
fn win32_error_code(err: &Win32Error) -> u32 {
    let bits = u32::from_ne_bytes(err.code().0.to_ne_bytes());
    bits & 0xFFFF
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    use super::*;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_pipe(tag: &str) -> String {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(r"\\.\pipe\exv-named-pipe-io-{tag}-{}-{n}", std::process::id())
    }

    /// DACL 授权当前用户时，当前用户（即使是非提权 token）能连上 server pipe。
    #[test]
    fn server_dacl_allows_current_user_connect() {
        let sid = crate::peer_auth::current_user_sid().expect("current user sid");
        let name = unique_pipe("dacl-allow");
        let server =
            NamedPipeByteStream::create_server_with_dacl(&name, 1, Some(&sid)).expect("create server");
        let client = NamedPipeByteStream::connect_client(&name)
            .expect("current user must connect through the user-SID DACL");
        server.connect().expect("server accept");
        drop(client);
    }

    /// DACL 未授权当前用户时，客户端连接必须被拒（ERROR_ACCESS_DENIED = 5）——证明
    /// `create_server_with_dacl` 确实把 DACL 交到了 `CreateNamedPipeW`（旧的 `create_server`
    /// 无 DACL，默认 ACL 会让本机用户连上，此测试对旧实现会失败）。
    #[test]
    fn server_dacl_denies_unlisted_user() {
        // 一个当前用户不可能持有的伪造域 SID；DACL = SYSTEM + 该 SID，普通（非 SYSTEM）
        // 客户端在 CreateFileW 阶段即被 ACL 拒绝。
        let bogus = "S-1-5-21-1000000000-1000000000-1000000000-1001";
        let name = unique_pipe("dacl-deny");
        let server = NamedPipeByteStream::create_server_with_dacl(&name, 1, Some(bogus))
            .expect("create server with dacl");
        let err = NamedPipeByteStream::connect_client(&name)
            .expect_err("unlisted user must be denied by the DACL");
        assert_eq!(
            err,
            PipeIoError::Io(ERROR_ACCESS_DENIED.0),
            "unlisted user connect must fail with ERROR_ACCESS_DENIED (5)"
        );
        drop(server);
    }

    /// `create_server`（无 DACL）仍保持原行为：当前用户可连（向后兼容测试路径）。
    #[test]
    fn create_server_without_dacl_still_connects_current_user() {
        let name = unique_pipe("no-dacl");
        let server = NamedPipeByteStream::create_server(&name, 1).expect("create server");
        let client = NamedPipeByteStream::connect_client(&name).expect("connect client");
        server.connect().expect("server accept");
        drop(client);
    }

    /// 多实例 server：第一实例 + 额外实例可同时 accept 两个 client（多客户端 pipe server
    /// ——log 管道的 `engine + UI` 并发拓扑）。
    #[test]
    fn multi_instance_accepts_two_clients() {
        let name = unique_pipe("multi");
        let sid = crate::peer_auth::current_user_sid().expect("current user sid");
        // 第一实例（FIRST_PIPE_INSTANCE）+ 一个额外实例。
        let s1 =
            NamedPipeByteStream::create_server_with_dacl(&name, 4, Some(&sid)).expect("first");
        let s2 = NamedPipeByteStream::create_server_additional_with_dacl(&name, 4, Some(&sid))
            .expect("additional");

        let c1 = NamedPipeByteStream::connect_client(&name).expect("client 1 connects");
        let c2 = NamedPipeByteStream::connect_client(&name).expect("client 2 connects");
        s1.connect().expect("server 1 accept");
        s2.connect().expect("server 2 accept");

        // 两个实例各自可完成一次写读往返。
        let mut s1 = s1;
        let mut s2 = s2;
        s1.write_all(b"one").expect("s1 write");
        s2.write_all(b"two").expect("s2 write");
        let mut b1 = [0u8; 3];
        let mut b2 = [0u8; 3];
        c1.read(&mut b1).expect("c1 read");
        c2.read(&mut b2).expect("c2 read");
        assert_eq!(&b1, b"one");
        assert_eq!(&b2, b"two");
    }
}
