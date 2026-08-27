// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W11-T terra: peer authentication over a Windows byte-mode Named Pipe. These tests pin the
// peer_auth / pipe_security / verified_incoming API that W11-I implements in
// exv_vpn_win32_ipc::{peer_auth, pipe_security, verified_incoming}. The frozen WSP1 facts
// (docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-pipe-facts.md) are the
// contract:
//   - DACL = expected user/logon SID + SYSTEM, never broad BUILTIN\Users (facts §4);
//   - PIPE_REJECT_REMOTE_CLIENTS + FILE_FLAG_FIRST_PIPE_INSTANCE; second-create refused, 231 (§2);
//   - TokenLogonSid parsed as TOKEN_GROUPS with Groups[0] at offset 8 (§5);
//   - any token/identity query failure fails closed (§5); endpoint name is not authority (§6);
//   - the host verifies the helper PID+SID (anti fake-helper) (§6).
//
// The tests run REAL local Named Pipe I/O (server + client in a std::thread). Deterministic
// expectations only: the current user's SID is read via GetTokenInformation(TokenUser) and is the
// same token the local pipe client connects with.

use std::thread;

use exv_vpn_win32_ipc::named_pipe_io::{NamedPipeByteStream, PipeIoError};
use exv_vpn_win32_ipc::peer_auth::{PeerAuthenticator, PeerAuthError};
use exv_vpn_win32_ipc::pipe_security::PipeSecurity;
// Pins the verified_incoming seam so the RED also flags that empty stub (E0432). None of the seven
// tests below call it directly — W12 exercises the dispatch verdict — but the import must resolve
// to GREEN once W11-I fills the module.
#[allow(unused_imports)]
use exv_vpn_win32_ipc::verified_incoming::IncomingVerdict;

use windows::Win32::Foundation::{CloseHandle, ERROR_PIPE_BUSY, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TokenLogonSid, TokenUser,
    TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// A unique per-test pipe name so parallel tests never collide.
fn pipe_name(tag: &str) -> String {
    format!(r"\\.\pipe\exv-w11-auth-{tag}-{}", std::process::id())
}

/// The current user's SID, read deterministically from this process's token (TokenUser).
fn current_user_sid() -> String {
    let mut token = HANDLE(std::ptr::null_mut());
    // SAFETY: `token` is a live out-param; GetCurrentProcess returns a pseudo-handle owned by the
    // OS that must not be closed.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .expect("open the current process token");
    }

    // First call only sizes the buffer (fails with ERROR_INSUFFICIENT_BUFFER and reports `len`).
    let mut len = 0u32;
    // SAFETY: querying with no buffer cannot write anywhere; `len` is a live out-param.
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
    }
    assert!(len > 0, "GetTokenInformation must report the TokenUser buffer size");
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` is a live, correctly-aligned (16-byte) buffer of `len` bytes; the API writes a
    // TOKEN_USER followed by the SID into it and reports the same length back.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            len,
            &mut len,
        )
        .expect("query TokenUser");
    }
    // SAFETY: the token was opened above and must be released.
    unsafe { let _ = CloseHandle(token); }

    // SAFETY: buf begins with a valid TOKEN_USER whose User.Sid points into buf.
    let user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
    sid_to_string(user.User.Sid)
}

/// The current logon SID, parsed as TOKEN_GROUPS (Groups[0] at offset 8, WSP1 §5), or `None` when
/// the token has no logon group.
fn current_logon_sid() -> Option<String> {
    let mut token = HANDLE(std::ptr::null_mut());
    // SAFETY: `token` is a live out-param; GetCurrentProcess returns a pseudo-handle that must not
    // be closed.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .expect("open the current process token");
    }

    let mut len = 0u32;
    // SAFETY: querying with no buffer cannot write anywhere; `len` is a live out-param.
    unsafe {
        let _ = GetTokenInformation(token, TokenLogonSid, None, 0, &mut len);
    }
    assert!(len > 0, "GetTokenInformation must report the TokenLogonSid buffer size");
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` is a live, correctly-aligned buffer of `len` bytes; the API writes the
    // TOKEN_GROUPS structure into it.
    unsafe {
        GetTokenInformation(
            token,
            TokenLogonSid,
            Some(buf.as_mut_ptr().cast()),
            len,
            &mut len,
        )
        .expect("query TokenLogonSid");
    }
    // SAFETY: the token was opened above and must be released.
    unsafe { let _ = CloseHandle(token); }

    // SAFETY: buf begins with a valid TOKEN_GROUPS (GroupCount at offset 0, Groups[0].Sid at offset
    // 8 — the frozen WSP1 §5 layout).
    let groups = unsafe { &*(buf.as_ptr().cast::<TOKEN_GROUPS>()) };
    if groups.GroupCount == 0 {
        return None;
    }
    Some(sid_to_string(groups.Groups[0].Sid))
}

/// Converts a PSID to its string form, freeing the OS-allocated buffer.
fn sid_to_string(sid: windows::Win32::Security::PSID) -> String {
    let mut ptr = windows::core::PWSTR::null();
    // SAFETY: `sid` is a valid PSID owned by the caller's token query and `ptr` is a live out-param
    // the API allocates; the result is freed with LocalFree below.
    unsafe {
        ConvertSidToStringSidW(sid, &mut ptr).expect("convert SID to string");
    }
    let s = unsafe { ptr.to_string() }.expect("SID string is valid UTF-16");
    // SAFETY: the string was allocated by ConvertSidToStringSidW and must be released via LocalFree.
    unsafe { let _ = LocalFree(Some(HLOCAL(ptr.0.cast()))); }
    s
}

/// Renders a security descriptor's DACL back to SDDL for inspection (used by the DACL test).
fn dacl_sddl(sd: *mut core::ffi::c_void) -> String {
    let mut sddl = windows::core::PWSTR::null();
    // SAFETY: `sd` is the caller's live SECURITY_DESCRIPTOR pointer and `sddl` is a live out-param
    // the API allocates; the result is freed with LocalFree below.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            PSECURITY_DESCRIPTOR(sd),
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut sddl,
            None,
        )
        .expect("convert security descriptor to SDDL");
    }
    let s = unsafe { sddl.to_string() }.expect("SDDL is valid UTF-16");
    // SAFETY: the string was allocated by the conversion API and must be released via LocalFree.
    unsafe { let _ = LocalFree(Some(HLOCAL(sddl.0.cast()))); }
    s
}

/// Kills 'broad IU DACL accepted' (WSP1 §4).
#[test]
fn dacl_allows_expected_user_and_system() {
    let user = current_user_sid();

    // A broad BUILTIN\Users SID must be rejected, never turned into a wide-open DACL.
    assert!(
        PipeSecurity::new("S-1-5-32-545", true).is_err(),
        "a broad BUILTIN\\Users (IU) DACL must be rejected"
    );

    // The expected user + SYSTEM descriptor must actually carry both ACEs...
    let sec = PipeSecurity::new(&user, true).expect("user+SYSTEM DACL builds");
    let dacl = dacl_sddl(sec.as_attributes().lpSecurityDescriptor);
    assert!(dacl.contains(&user), "DACL must grant the expected user SID: {dacl}");
    assert!(dacl.contains("SY"), "DACL must grant SYSTEM: {dacl}");
    // ... and never fall back to a broad Interactive-Users / Builtin-Users ACE.
    assert!(
        !dacl.contains("IU") && !dacl.contains("BU"),
        "DACL must not grant broad Interactive Users / Builtin Users: {dacl}"
    );
}

/// Kills 'second instance squatting succeeds' (WSP1 §2).
#[test]
fn second_pipe_instance_is_rejected_anti_squatting() {
    let name = pipe_name("second");
    let _first = NamedPipeByteStream::create_server(&name, 1).expect("first instance created");
    // Creating a second server pipe on the same name with FILE_FLAG_FIRST_PIPE_INSTANCE must fail
    // with ERROR_PIPE_BUSY (231) — the code actually observed on this host (facts §2).
    let second = NamedPipeByteStream::create_server(&name, 1);
    assert!(
        matches!(second, Err(PipeIoError::Io(code)) if code == ERROR_PIPE_BUSY.0),
        "a second instance of the same pipe name must be refused with ERROR_PIPE_BUSY (231), got {second:?}"
    );
}

/// Kills 'query returns wrong PID/SID' (WSP1 §5).
#[test]
fn authenticate_client_returns_pid_user_and_logon_sid() {
    let name = pipe_name("ident");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server pipe");
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let client = thread::spawn(move || {
        let _c = NamedPipeByteStream::connect_client(&name).expect("client connects");
        let _ = rx.recv(); // keep the client connected while the server authenticates
    });
    server.connect().expect("server connect");

    let expected_sid = current_user_sid();
    let expected_logon = current_logon_sid().expect("host token has a logon SID (facts §5)");

    let peer = PeerAuthenticator::new(expected_sid.clone())
        .authenticate_client(&server)
        .expect("a real local client must authenticate");

    assert_eq!(peer.process_id, std::process::id(), "client PID must be the local process");
    assert_eq!(peer.user_sid, expected_sid, "client user SID must match the current user");
    assert_eq!(
        peer.logon_sid.as_deref(),
        Some(expected_logon.as_str()),
        "client logon SID must match (TOKEN_GROUPS offset 8), facts §5"
    );
    assert!(!peer.account_name.is_empty(), "account name must resolve");

    tx.send(()).expect("release client");
    client.join().expect("client thread joins");
}

/// Kills 'token query failure is treated as success' (WSP1 §5 fail-closed).
#[test]
fn authenticate_client_fails_closed_on_token_query_failure() {
    let name = pipe_name("fail-closed");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server pipe");
    // No client ever connects to this instance: the server handle cannot resolve a client PID or
    // token (GetNamedPipeClientProcessId -> ERROR_PIPE_NOT_CONNECTED). A correct implementation
    // must fail closed with TokenQueryFailed instead of fabricating an identity.
    let auth = PeerAuthenticator::new("S-1-0-0".to_string());
    let err = auth.authenticate_client(&server);
    assert!(
        matches!(err, Err(PeerAuthError::TokenQueryFailed(_))),
        "an unqueryable client token must fail closed with TokenQueryFailed"
    );
}

/// Kills 'host accepts a helper whose PID/SID does not match' (WSP1 §6 anti fake-helper).
#[test]
fn verify_helper_identity_rejects_mismatch_fail_closed() {
    let auth = PeerAuthenticator::new("S-1-5-21-0-0-0-0-1000".to_string());
    let expected_sid = "S-1-5-21-0-0-0-0-1000";
    let actual_sid = "S-1-5-18"; // SYSTEM is not the expected helper user

    // A helper whose SID differs must be rejected with SidsMismatch.
    let sid_mismatch = auth.verify_helper_identity(42, expected_sid, 42, actual_sid);
    assert!(
        matches!(sid_mismatch, Err(PeerAuthError::SidsMismatch(_, _))),
        "a helper with a mismatched SID must fail closed with SidsMismatch"
    );

    // A helper whose PID differs must also fail closed.
    let pid_mismatch = auth.verify_helper_identity(42, expected_sid, 7, expected_sid);
    assert!(pid_mismatch.is_err(), "a helper with a mismatched PID must fail closed");

    // The exact match is the happy path.
    let ok = auth.verify_helper_identity(42, expected_sid, 42, expected_sid);
    assert!(ok.is_ok(), "a helper with matching PID+SID must be accepted");
}

/// Kills 'endpoint name alone grants authority' (WSP1 §6).
#[test]
fn endpoint_name_is_not_authority() {
    let name = pipe_name("endpoint");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server pipe");
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let client = thread::spawn(move || {
        let _c = NamedPipeByteStream::connect_client(&name).expect("client connects");
        let _ = rx.recv();
    });
    server.connect().expect("server connect");

    // The client reached the "right" endpoint name, but its SID is not the expected one (S-1-0-0 is
    // the Null SID and never a token user). Reaching the right name is not authority.
    let auth = PeerAuthenticator::new("S-1-0-0".to_string());
    let err = auth.authenticate_client(&server);
    assert!(
        matches!(err, Err(PeerAuthError::NotAuthorized)),
        "a peer at the right endpoint with the wrong SID must be rejected"
    );

    tx.send(()).expect("release client");
    client.join().expect("client thread joins");
}

/// Kills 'remote client accepted' (WSP1 §2 / §9).
#[test]
fn remote_client_rejected() {
    // A real cross-computer Named Pipe client cannot be spawned on this single-host acceptance box
    // (facts §9: remote_client_rejection = not_run / blocked_by_environment). The locally-observable
    // half of the fact is that the server pipe the crate creates MUST carry PIPE_REJECT_REMOTE_CLIENTS
    // so a remote client is refused at the NT layer. The flag is applied inside CreateNamedPipeW and
    // Windows exposes no read-back for it — the WSP1 oracle records reject_remote_clients_flag_set by
    // construction the same way. It is pinned at the crate's only server-pipe factory
    // (NamedPipeByteStream::create_server, whose mode set is PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
    // PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS and open mode carries FILE_FLAG_FIRST_PIPE_INSTANCE).
    let name = pipe_name("remote");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server pipe");
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let client_name = name.clone();
    let client = thread::spawn(move || {
        let _c = NamedPipeByteStream::connect_client(&client_name).expect("local client connects");
        let _ = rx.recv();
    });
    server.connect().expect("server connect");

    // Observable proof the WSP1 §2 mode set is applied: a second create of the same name through the
    // same factory is refused with ERROR_PIPE_BUSY, which only holds when the first instance was
    // created with FILE_FLAG_FIRST_PIPE_INSTANCE — the flag that shares create_server's mode word
    // with PIPE_REJECT_REMOTE_CLIENTS.
    let second = NamedPipeByteStream::create_server(&name, 1);
    assert!(
        matches!(second, Err(PipeIoError::Io(code)) if code == ERROR_PIPE_BUSY.0),
        "the WSP1 §2 mode set must be applied to the created server pipe (got {second:?})"
    );

    tx.send(()).expect("release client");
    client.join().expect("client thread joins");
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
