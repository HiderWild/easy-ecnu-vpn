// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W13-T terra: singleton authority over a Local\ named mutex. These tests pin the
// SingletonAuthority / AuthorityAcquire / NativeError API that W13-I implements in
// exv_vpn_win32_resource::{authority, native_error}. The frozen WSP2 facts
// (docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-authority-storage-facts.md)
// are the contract:
//   - Named Mutex in the Local\ namespace is the authority primitive (facts §1);
//   - the loser of the race observes WAIT_TIMEOUT (258) and exits BEFORE any
//     scan/observe/publish (mutex_loser_exited_before_scan_observe_publish);
//   - an owner killed by TerminateProcess without releasing yields WAIT_ABANDONED_0
//     (128) to the next waiter, which is GRANTED ownership and can release;
//   - a released mutex is reacquirable (mutex_reusable_after_release);
//   - the mutex DACL is SYSTEM + the current user only, never broad IU (facts §1).
//
// The two-process cases spawn a real child process: the test binary is re-executed
// (std::env::current_exe) with EXV_W13_CHILD + libtest's --exact filter so only the
// spawning test runs in the child. The child role (child_role) exits before doing any
// parent work, so there is no recursion.

use std::ffi::c_void;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use exv_vpn_win32_resource::authority::{AuthorityAcquire, SingletonAuthority};
use exv_vpn_win32_resource::native_error::{NativeError, NativeErrorKind};

use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_FILE_NOT_FOUND, HANDLE, HLOCAL, WAIT_OBJECT_0};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW, GetSecurityInfo,
    SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SID_AND_ATTRIBUTES, TOKEN_QUERY, TokenUser,
    DACL_SECURITY_INFORMATION,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenMutexW, OpenProcess, OpenProcessToken, ReleaseMutex, TerminateProcess,
    WaitForSingleObject, MUTEX_ALL_ACCESS, PROCESS_TERMINATE,
};

// ---------------------------------------------------------------------------
// Child-process sentinels (subprocess exit codes)
// ---------------------------------------------------------------------------

const CHILD_ENV: &str = "EXV_W13_CHILD";
const MUTEX_ENV: &str = "EXV_W13_MUTEX";
const MARKER_ENV: &str = "EXV_W13_MARKER";

/// The loser observed `Busy` (WAIT_TIMEOUT=258) and exited cleanly, having done
/// NO scan/observe/publish. This is the only acceptable loser exit code.
const CHILD_EXIT_BUSY: i32 = 250;
/// The loser was (wrongly) granted authority — the double-master mutant. It then
/// "publishes" (writes the marker) and exits 255.
const CHILD_EXIT_PUBLISHED: i32 = 255;
/// The child hit a NativeError instead of the expected result.
const CHILD_EXIT_ERROR: i32 = 252;
/// The hold-role child failed to acquire the mutex it was supposed to own.
const CHILD_EXIT_NOT_OWNER: i32 = 253;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// A unique `Local\`-scoped mutex name per test (tag + pid), so parallel tests and
/// repeated runs never collide.
fn authority_name(tag: &str) -> String {
    format!(r"Local\ExvVpnAuthority_{tag}_{}", std::process::id())
}

/// Marker file under %TEMP%, shared by parent and child (path passed via env).
fn marker_path(tag: &str, kind: &str) -> PathBuf {
    std::env::temp_dir().join(format!("exv-w13-{tag}-{kind}.marker"))
}

/// Re-execute this test binary as the child. libtest's `--exact` runs only the named
/// test; that test checks `child_role()` first and exits before any parent work.
fn spawn_child(mode: &str, name: &str, marker: &str, exact_test: &str) -> Child {
    Command::new(std::env::current_exe().expect("current test exe"))
        .env(CHILD_ENV, mode)
        .env(MUTEX_ENV, name)
        .env(MARKER_ENV, marker)
        .arg("--exact")
        .arg(exact_test)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the child test process")
}

/// Child role entry, called at the top of every test that can be re-executed as a
/// child. Returns the exit code when running as a child; `None` in the parent role.
fn child_role() -> Option<i32> {
    let mode = std::env::var(CHILD_ENV).ok()?;
    let name = std::env::var(MUTEX_ENV).expect("child must receive the mutex name");
    let marker = std::env::var(MARKER_ENV).expect("child must receive the marker path");
    let auth = match SingletonAuthority::new(&name) {
        Ok(a) => a,
        Err(_) => return Some(CHILD_EXIT_ERROR),
    };
    match mode.as_str() {
        // Loser role: probe the held mutex. On Busy the loser exits immediately,
        // BEFORE any scan/observe/publish. Getting ownership here is the
        // double-master mutant, and then the child "publishes".
        "try-acquire" => match auth.try_acquire() {
            Ok(AuthorityAcquire::Busy) => Some(CHILD_EXIT_BUSY),
            Ok(_) => {
                let _ = std::fs::write(&marker, b"published");
                Some(CHILD_EXIT_PUBLISHED)
            }
            Err(_) => Some(CHILD_EXIT_ERROR),
        },
        // Owner role: take ownership, signal readiness, then hold forever until the
        // parent TerminateProcess-es this process WITHOUT releasing the mutex.
        "hold" => match auth.try_acquire() {
            Ok(AuthorityAcquire::Acquired) => {
                let _ = std::fs::write(&marker, b"ready");
                loop {
                    thread::sleep(Duration::from_secs(3600));
                }
            }
            _ => Some(CHILD_EXIT_NOT_OWNER),
        },
        other => panic!("unknown child mode {other}"),
    }
}

/// The current user's SID, read deterministically from this process's token (TokenUser).
fn current_user_sid() -> String {
    // SAFETY: `token` is a live out-param; GetCurrentProcess returns a pseudo-handle
    // owned by the OS that must not be closed.
    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .expect("open the current process token");
    }

    let mut buff = [0u8; 4096];
    let mut ret = 0u32;
    // SAFETY: buff lives for the call; the returned PSID points into token-owned
    // memory that stays valid while the token handle is open.
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
        // SAFETY: token was opened above and must be closed.
        unsafe { let _ = CloseHandle(token); }
        panic!("query TokenUser");
    }
    // SAFETY: TokenUser returns a SID_AND_ATTRIBUTES whose first field is the PSID;
    // the buffer may be unaligned so read_unaligned is used.
    let sa = unsafe { std::ptr::read_unaligned(buff.as_ptr().cast::<SID_AND_ATTRIBUTES>()) };
    let sid = sid_to_string(sa.Sid).expect("convert user SID to string");
    // SAFETY: token was opened above and must be closed.
    unsafe { let _ = CloseHandle(token); }
    sid
}

/// Converts a PSID to its string form, freeing the OS-allocated buffer.
fn sid_to_string(sid: PSID) -> Option<String> {
    let mut p = PWSTR::null();
    // SAFETY: sid is a valid PSID owned by the caller's token query and `p` is a live
    // out-param the API allocates; the result is freed with LocalFree below.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut p) };
    if ok.is_err() {
        return None;
    }
    let s = unsafe { p.to_string() }.ok()?;
    // SAFETY: the string was allocated by ConvertSidToStringSidW and must be released.
    unsafe { let _ = LocalFree(Some(HLOCAL(p.0 as *mut c_void))); }
    Some(s)
}

/// Reads the DACL of the named mutex (opened by the `Local\` name) and renders it as
/// SDDL for inspection.
fn mutex_dacl_sddl(name: &str) -> String {
    let hname = HSTRING::from(name);
    // SAFETY: `name` is valid; MUTEX_ALL_ACCESS includes READ_CONTROL + SYNCHRONIZE and
    // the restricted DACL grants the current user full access.
    let h = unsafe { OpenMutexW(MUTEX_ALL_ACCESS, false, &hname) }
        .expect("open the authority mutex to read its DACL");

    let mut psd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: psd is a live out-param; GetSecurityInfo allocates the descriptor with
    // LocalAlloc, which the caller must free via LocalFree.
    let rc = unsafe {
        GetSecurityInfo(
            h,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut psd),
        )
    };
    assert_eq!(rc.0, 0, "GetSecurityInfo must succeed on the authority mutex");

    let mut pw = PWSTR::null();
    // SAFETY: psd points to the live descriptor; the conversion API allocates the
    // string with LocalAlloc, which the caller must free via LocalFree.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut pw,
            None,
        )
    };
    // SAFETY: psd was allocated by GetSecurityInfo and must be released.
    unsafe { let _ = LocalFree(Some(HLOCAL(psd.0))); }
    assert!(ok.is_ok(), "convert the mutex DACL to SDDL");

    let s = unsafe { pw.to_string() }.expect("SDDL is valid UTF-16");
    // SAFETY: the string was allocated by the conversion API and must be released.
    unsafe { let _ = LocalFree(Some(HLOCAL(pw.0 as *mut c_void))); }
    s
}

// ---------------------------------------------------------------------------
// The 7 pinned cases
// ---------------------------------------------------------------------------

/// Kills 'loser scans/observes/publishes without authority' and 'second instance
/// scans before authority' (WSP2 facts §1: the loser exits on WAIT_TIMEOUT before
/// any scan/observe/publish).
#[test]
fn mutex_is_authority_and_loser_exits_before_scan_observe_publish() {
    if let Some(code) = child_role() {
        std::process::exit(code);
    }

    let name = authority_name("two-proc");
    let marker = marker_path("two-proc", "published");
    let _ = std::fs::remove_file(&marker);

    let authority = SingletonAuthority::new(&name).expect("create the authority mutex");
    assert!(
        matches!(
            authority.try_acquire().expect("parent acquires authority"),
            AuthorityAcquire::Acquired
        ),
        "the parent must be the first authority"
    );

    // The child races the parent: it must observe Busy (WAIT_TIMEOUT) and exit with
    // the CHILD_EXIT_BUSY sentinel, having done NO scan/observe/publish.
    let mut child = spawn_child(
        "try-acquire",
        &name,
        &marker.to_string_lossy(),
        "mutex_is_authority_and_loser_exits_before_scan_observe_publish",
    );
    let output = child.wait_with_output().expect("the child finishes");
    let code = output.status.code().expect("the child exits with a code");

    assert_eq!(
        code,
        CHILD_EXIT_BUSY,
        "the loser must observe Busy and exit with sentinel {CHILD_EXIT_BUSY} (no \
         scan/observe/publish); got exit {code} (double-master/publish/error mutant)"
    );
    assert!(
        !marker.exists(),
        "the loser must NOT publish: the published marker must not exist"
    );

    authority.release().expect("parent releases before dropping");
}

/// Kills 'abandoned owner not detected / not taken over' (WSP2 facts §1:
/// WAIT_ABANDONED_0=128 grants ownership to the next waiter).
#[test]
fn abandoned_mutex_transfers_ownership_to_next_waiter() {
    if let Some(code) = child_role() {
        std::process::exit(code);
    }

    let name = authority_name("abandoned");
    let ready = marker_path("abandoned", "ready");
    let _ = std::fs::remove_file(&ready);

    // The parent opens the mutex FIRST so its handle keeps the kernel object alive
    // after the child (the sole acquiring process) is terminated. Without this, the
    // last handle would close on child death and the object would be DESTROYED, so
    // a later open would create a brand-new unowned mutex (no WAIT_ABANDONED).
    let parent_auth = SingletonAuthority::new(&name).expect("parent opens the authority mutex");

    // Child opens the same mutex, takes ownership, writes the ready marker, holds forever.
    let mut owner = spawn_child(
        "hold",
        &name,
        &ready.to_string_lossy(),
        "abandoned_mutex_transfers_ownership_to_next_waiter",
    );

    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() {
        assert!(
            Instant::now() < deadline,
            "the child never acquired the authority mutex"
        );
        thread::sleep(Duration::from_millis(25));
    }

    // Kill the owner without letting it release the mutex (TerminateProcess).
    // SAFETY: pid is the live child's id; PROCESS_TERMINATE is the minimal access.
    let proc_handle = unsafe { OpenProcess(PROCESS_TERMINATE, false, owner.id()) }
        .expect("open the owner process for termination");
    // SAFETY: proc_handle is a valid handle to the live owner we spawned.
    let killed = unsafe { TerminateProcess(proc_handle, 1) };
    // SAFETY: proc_handle was opened above and must be closed.
    unsafe { let _ = CloseHandle(proc_handle); }
    assert!(killed.is_ok(), "TerminateProcess must kill the mutex owner");
    let _ = owner.wait(); // reap the terminated child
    let _ = std::fs::remove_file(&ready);

    // The next waiter (the parent's surviving handle) must observe WAIT_ABANDONED_0
    // and be GRANTED ownership, because the mutex object is still alive and was owned
    // by the terminated child.
    let outcome = parent_auth.try_acquire().expect("wait on the abandoned mutex");
    assert!(
        matches!(outcome, AuthorityAcquire::AbandonedTakenOver),
        "the next waiter must take over an abandoned mutex (WAIT_ABANDONED_0=128), got {outcome:?}"
    );
    // Ownership was transferred: the successor can release the mutex.
    parent_auth.release().expect("the successor releases the taken-over mutex");
}

/// Kills 'mutex not reacquirable after release' (WSP2 facts §1:
/// mutex_reusable_after_release=true).
#[test]
fn mutex_reusable_after_release() {
    let name = authority_name("reuse");
    let first = SingletonAuthority::new(&name).expect("create the authority mutex");
    assert!(
        matches!(
            first.try_acquire().expect("first acquire"),
            AuthorityAcquire::Acquired
        ),
        "first acquire must be Acquired"
    );
    first.release().expect("release the mutex");

    // A fresh handle to the same name must acquire again (not Busy).
    let second = SingletonAuthority::new(&name).expect("reopen the authority mutex");
    assert!(
        matches!(
            second.try_acquire().expect("reacquire after release"),
            AuthorityAcquire::Acquired
        ),
        "the mutex must be reacquirable after release (not Busy)"
    );
    second.release().expect("release again");
}

/// Kills 'second authority granted (double-master)': a mutex held by one thread must
/// yield Busy (WAIT_TIMEOUT=258) to a different thread's acquire.
#[test]
fn authority_acquire_returns_busy_when_held() {
    let name = authority_name("held");
    let holder = SingletonAuthority::new(&name).expect("create the authority mutex");
    assert!(
        matches!(
            holder.try_acquire().expect("main thread acquires"),
            AuthorityAcquire::Acquired
        ),
        "main thread must be the authority"
    );

    // A DIFFERENT thread contending for the same named mutex must observe Busy (a
    // named mutex is recursive only for its owning thread).
    let contender_name = name.clone();
    let contender = thread::spawn(move || {
        let other = SingletonAuthority::new(&contender_name).expect("second handle");
        other.try_acquire().expect("contender probe")
    });
    let outcome = contender.join().expect("contender thread joins");
    assert!(
        matches!(outcome, AuthorityAcquire::Busy),
        "a held mutex must yield Busy for a different thread (got {outcome:?}) — double-master mutant"
    );

    holder.release().expect("main thread releases");
}

/// Kills 'error kind not mapped / all Unknown' (WSP2 facts §5: win32 5 -> AccessDenied
/// is a typed error; the pinned seam maps 5 -> Permission and 33 -> Resource).
#[test]
fn native_error_maps_win32_code_to_kind() {
    let denied = NativeError::from_win32(5, "access denied");
    assert!(
        matches!(denied.kind(), NativeErrorKind::Permission),
        "win32 5 (ERROR_ACCESS_DENIED) must map to Permission, got {:?}",
        denied.kind()
    );

    let lock = NativeError::from_win32(33, "lock violation");
    assert!(
        matches!(lock.kind(), NativeErrorKind::Resource),
        "win32 33 (ERROR_LOCK_VIOLATION) must map to Resource, got {:?}",
        lock.kind()
    );

    let unknown = NativeError::from_win32(12345, "no such code");
    assert!(
        matches!(unknown.kind(), NativeErrorKind::Unknown),
        "an unmapped win32 code must map to Unknown, got {:?}",
        unknown.kind()
    );
}

/// Kills 'authority uses Global/session-inappropriate namespace' (WSP2 facts §1: the
/// frozen choice is the Local\ namespace).
#[test]
fn mutex_is_local_namespace() {
    let local_name = authority_name("namespace");
    let authority = SingletonAuthority::new(&local_name).expect("create a Local\\ mutex");
    assert!(
        matches!(
            authority.try_acquire().expect("acquire the Local\\ mutex"),
            AuthorityAcquire::Acquired
        ),
        "the Local\\ mutex must be a valid, acquirable kernel object"
    );
    authority.release().expect("release the Local\\ mutex");

    // The object must be reachable under its Local\ name...
    let hname = HSTRING::from(&local_name);
    // SAFETY: local_name is a valid string; the mutex was created above and the
    // restricted DACL grants the current user full access.
    let h = unsafe { OpenMutexW(MUTEX_ALL_ACCESS, false, &hname) }
        .expect("the Local\\ object must be openable by name");
    // SAFETY: h is a valid handle; the mutex is free (released above) so the wait
    // succeeds with WAIT_OBJECT_0.
    let ev = unsafe { WaitForSingleObject(h, 0) };
    assert_eq!(ev, WAIT_OBJECT_0, "the Local\\ mutex must be a live, unheld object");
    // SAFETY: WaitForSingleObject granted ownership; release before closing.
    unsafe { ReleaseMutex(h) }.expect("release the direct wait");
    // SAFETY: h was opened above and must be closed.
    unsafe { let _ = CloseHandle(h); }

    // ... and must NOT live in the Global namespace: we never created a Global twin,
    // so opening it fails with ERROR_FILE_NOT_FOUND (2) deterministically.
    let global_name = local_name.replacen("Local\\", "Global\\", 1);
    let gname = HSTRING::from(&global_name);
    // SAFETY: global_name is a valid string; only the Local\ object exists.
    let g_open = unsafe { OpenMutexW(MUTEX_ALL_ACCESS, false, &gname) };
    assert!(
        matches!(g_open, Err(ref e) if ((e.code().0 & 0xFFFF) as u32) == ERROR_FILE_NOT_FOUND.0),
        "a Global\\ twin of the Local\\ mutex must not exist (the object lives in Local\\), got {g_open:?}"
    );
}

/// Kills 'broad IU DACL for the authority mutex' (WSP2 facts §1: DACL is SYSTEM + the
/// current user only, never broad Interactive/Builtin Users).
#[test]
fn authority_dacl_rejects_broad_iu() {
    let name = authority_name("dacl");
    let authority = SingletonAuthority::new(&name).expect("create with the restricted DACL");
    assert!(
        matches!(
            authority.try_acquire().expect("acquire"),
            AuthorityAcquire::Acquired
        ),
        "acquire before inspecting the DACL"
    );

    let user = current_user_sid();
    let sddl = mutex_dacl_sddl(&name);

    // The frozen DACL grants SYSTEM and the current user...
    assert!(sddl.contains("SY"), "DACL must grant SYSTEM: {sddl}");
    assert!(sddl.contains(&user), "DACL must grant the current user {user}: {sddl}");
    // ... and never falls back to a broad Interactive-Users / Builtin-Users /
    // Administrators grant (the NULL-DACL default would add BA and be killed here).
    assert!(
        !sddl.contains("IU") && !sddl.contains("BU") && !sddl.contains("BA"),
        "DACL must not carry broad Interactive-Users / Builtin-Users / Administrators ACEs: {sddl}"
    );

    authority.release().expect("release before dropping");
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
