// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W14-T terra: durable journal store over the Win32 platform. These tests pin the
// WinJournalStore / JournalPath / storage_security API that W14-I implements in
// exv_vpn_win32_resource::{journal_store, journal_path, storage_security}. The frozen
// WSP2 facts (docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-authority-storage-facts.md)
// are the contract:
//   - journal path is %ProgramData%\ExvVpn\journal (facts §2), with a %LOCALAPPDATA%
//     fallback when ProgramData is not writable;
//   - the journal file is opened FILE_APPEND_DATA + FILE_SHARE_READ, and each
//     append_synced is durable via FlushFileBuffers — Rust std::fs::flush is a no-op and
//     must NOT be the durability point (facts §3/§7);
//   - a torn final tail recovers to the last complete record; a corrupt middle record
//     yields Corrupt and never skips forward (facts §4);
//   - the journal dir ACL is SYSTEM + the current user, never broad BUILTIN\Users / IU
//     (facts §2/§5);
//   - an ACL tamper that denies the current user surfaces as a typed NativeError with kind
//     Permission, never a panic (facts §5);
//   - compaction replaces the journal file with only the kept records (facts §3).
//
// All tests do real I/O in per-test temp dirs (%TEMP%\exv-w14-<pid>-<tag>) and clean them
// up. Record framing uses the J50 codec (exv_vpn_resource::journal): the raw journal file
// must be a concatenation of J50 frames, so the tests read the raw bytes and decode them.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::Command;

use exv_vpn_resource::journal::{decode, encode, verify_chain, DecodeOutcome, JournalRecord};
use exv_vpn_win32_resource::journal_path::JournalPath;
use exv_vpn_win32_resource::journal_store::{RecoverOutcome, WinJournalStore};
use exv_vpn_win32_resource::native_error::{NativeError, NativeErrorKind};
use exv_vpn_win32_resource::storage_security::{assert_not_tamperable, ensure_secure_dir};

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::{
    GetTokenInformation, PSID, SID_AND_ATTRIBUTES, TOKEN_QUERY, TokenUser,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A fresh, per-test temp directory: %TEMP%\exv-w14-<pid>-<tag>. Any stale copy from a
/// prior crashed run is removed so every test starts clean.
fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("exv-w14-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Deterministic chained records: sequence 0..n, each linked to the previous digest.
fn chained_records(n: usize) -> Vec<JournalRecord> {
    let mut prev = [0u8; 32];
    (0..n as u64)
        .map(|seq| {
            let rec = JournalRecord::new(seq, prev, format!("payload-{seq}").into_bytes());
            prev = rec.digest;
            rec
        })
        .collect()
}

/// The single journal file the store created in `dir`. Locating it by scanning the
/// directory (rather than hard-coding a file name) keeps these tests independent of the
/// exact file name W14-I chooses.
fn journal_file_in(dir: &Path) -> PathBuf {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .expect("read the journal directory")
        .map(|e| e.expect("a directory entry").path())
        .filter(|p| p.is_file())
        .collect();
    assert_eq!(files.len(), 1, "the journal directory must contain exactly one file");
    files.remove(0)
}

/// Run an `icacls` command against `path` (used to simulate ACL tampering for the
/// secure-ACL cases). Returns true when icacls exits 0.
fn run_icacls(path: &Path, args: &[&str]) -> bool {
    Command::new("icacls")
        .arg(path)
        .args(args)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
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

/// Assert `got` equals `expected` record-for-record (sequence, payload, previous digest,
/// digest) and that the recovered records form a valid J50 digest chain.
fn assert_records(expected: &[JournalRecord], got: &[JournalRecord]) {
    assert_eq!(expected.len(), got.len(), "recovered record count");
    for (i, (e, g)) in expected.iter().zip(got.iter()).enumerate() {
        assert_eq!(e.sequence, g.sequence, "record {i} sequence");
        assert_eq!(e.payload, g.payload, "record {i} payload");
        assert_eq!(e.previous_digest, g.previous_digest, "record {i} previous_digest");
        assert_eq!(e.digest, g.digest, "record {i} digest");
    }
    assert!(
        verify_chain(got).is_ok(),
        "recovered records must form a valid J50 digest chain"
    );
}

// ---------------------------------------------------------------------------
// The 8 pinned cases
// ---------------------------------------------------------------------------

/// Kills 'journal path not machine-level' (WSP2 facts §2): the path must resolve under
/// %ProgramData%\ExvVpn\journal (or the %LOCALAPPDATA% fallback), not a per-user scratch
/// location.
#[test]
fn machine_default_path_uses_programdata() {
    let jp = JournalPath::machine_default();
    let path = jp.as_path();
    let s = path.to_string_lossy();

    let program_expected =
        PathBuf::from(std::env::var_os("ProgramData").expect("ProgramData is set on Windows"))
            .join("ExvVpn")
            .join("journal");
    let local_expected =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").expect("LOCALAPPDATA is set on Windows"))
            .join("ExvVpn")
            .join("journal");

    assert!(
        path.starts_with(&program_expected) || path.starts_with(&local_expected),
        "machine_default must resolve under %ProgramData%\\ExvVpn\\journal (or the \
         %LOCALAPPDATA% fallback), got {s}"
    );
}

/// Kills 'append drops bytes / recover misreads' (WSP2 facts §3/§4): 3 chained records
/// appended must recover as Clean, in order, and the raw file must decode as J50 frames.
#[test]
fn append_sync_then_recover_roundtrips() {
    let dir = test_dir("roundtrip");
    let jp = JournalPath::from_dir(dir.clone());
    let records = chained_records(3);

    let mut store = WinJournalStore::open(&jp).expect("open the journal");
    let mut offsets = Vec::new();
    for rec in &records {
        offsets.push(store.append_synced(rec).expect("append_synced a record"));
    }
    assert_eq!(offsets[0], 0, "the first record must land at byte offset 0");
    assert_eq!(
        offsets[1],
        encode(&records[0]).len() as u64,
        "record 1 must land immediately after the J50 frame of record 0"
    );

    match store.recover().expect("recover the journal") {
        RecoverOutcome::Clean(got) => assert_records(&records, &got),
        _ => panic!("expected Clean after a clean roundtrip, got a different recover outcome"),
    }

    // The store must persist J50 codec frames: decoding the raw bytes yields the same records.
    let raw = std::fs::read(journal_file_in(&dir)).expect("read the raw journal file");
    match decode(&raw) {
        DecodeOutcome::Clean(got) => assert_records(&records, &got),
        _ => panic!("the raw journal file must decode cleanly as J50 frames"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'torn tail treated as clean / torn record included' (WSP2 facts §4): a partial
/// final frame recovers as TornTail with only the complete records; the torn record is
/// excluded.
#[test]
fn torn_final_tail_recovers_to_last_complete() {
    let dir = test_dir("torn");
    let jp = JournalPath::from_dir(dir.clone());
    let records = chained_records(3);

    {
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        for rec in &records {
            store.append_synced(rec).expect("append_synced a record");
        }
    } // drop closes the append handle so the file can be truncated

    let file = journal_file_in(&dir);
    let mut bytes = std::fs::read(&file).expect("read the journal file");
    assert!(bytes.len() > 10, "the journal file must be long enough to truncate");
    bytes.truncate(bytes.len() - 10); // tear the final record's trailing digest bytes
    // Persist the torn tail back to disk so recover() sees the truncated file.
    std::fs::write(&file, &bytes).expect("write the torn journal tail to disk");

    let store = WinJournalStore::open(&jp).expect("reopen the journal");
    match store.recover().expect("recover the journal") {
        RecoverOutcome::TornTail { records: got } => {
            assert_records(&records[..2], &got);
        }
        _ => panic!(
            "expected TornTail after truncating the last 10 bytes, got a different recover outcome"
        ),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'corruption skipped and later records returned' (WSP2 facts §4): a corrupt middle
/// record yields Corrupt at that record's offset and never skips forward to later records.
#[test]
fn corrupt_middle_is_journal_corrupt_no_skip() {
    let dir = test_dir("corrupt");
    let jp = JournalPath::from_dir(dir.clone());
    let records = chained_records(3);

    let r1_offset;
    {
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        store.append_synced(&records[0]).expect("append record 0");
        r1_offset = store.append_synced(&records[1]).expect("append record 1 -> its frame offset");
        store.append_synced(&records[2]).expect("append record 2");
    } // drop closes the append handle so the file can be rewritten

    let file = journal_file_in(&dir);
    let mut bytes = std::fs::read(&file).expect("read the journal file");
    // Flip a byte inside record 1's payload (frame starts at r1_offset, payload at +45).
    let payload_byte = (r1_offset as usize) + 45;
    assert!(payload_byte < bytes.len(), "record 1 payload byte must be within the file");
    bytes[payload_byte] ^= 0xFF;
    std::fs::write(&file, &bytes).expect("rewrite the corrupted journal file");

    let store = WinJournalStore::open(&jp).expect("reopen the journal");
    match store.recover().expect("recover the journal") {
        RecoverOutcome::Corrupt { offset } => {
            assert_eq!(
                offset,
                r1_offset as usize,
                "the corrupt record offset must be record 1's frame offset"
            );
        }
        _ => panic!(
            "expected Corrupt after flipping a byte in record 1's payload, got a different \
             recover outcome"
        ),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'flush/destructor treated as durable' (WSP2 facts §3/§7): append_synced itself is
/// the durability point (FlushFileBuffers). After the appending store is gone, a brand-new
/// store over the same dir must still recover the record.
#[test]
fn flush_is_explicit_not_drop_based() {
    let dir = test_dir("flush");
    let jp = JournalPath::from_dir(dir.clone());
    let records = chained_records(1);

    {
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        store
            .append_synced(&records[0])
            .expect("append_synced must persist the record itself");
    } // the first store goes away; durability must already live in append_synced

    let store = WinJournalStore::open(&jp).expect("reopen the journal");
    match store.recover().expect("recover the journal") {
        RecoverOutcome::Clean(got) => assert_records(&records, &got),
        _ => panic!("expected Clean after append + reopen, got a different recover outcome"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'broad IU journal dir ACL' (WSP2 facts §2/§5): ensure_secure_dir must grant
/// SYSTEM and the current user and never BUILTIN\Users / IU; assert_not_tamperable
/// must accept the secured dir and reject a simulated broad-ACL dir.
#[test]
fn secure_dir_acl_rejects_broad_iu() {
    let base = test_dir("acl");
    let secure = base.join("secure");
    let broad = base.join("broad");
    std::fs::create_dir_all(&base).expect("create the base temp dir");

    ensure_secure_dir(&secure)
        .expect("ensure_secure_dir must create the dir with a restricted ACL");
    assert!(secure.is_dir(), "ensure_secure_dir must create the directory");
    assert_not_tamperable(&secure)
        .expect("a dir secured by ensure_secure_dir must not be tamperable");

    // Simulate the broad-ACL mutant: grant BUILTIN\Users full control on a fresh dir.
    std::fs::create_dir_all(&broad).expect("create the broad-ACL dir");
    let granted = run_icacls(&broad, &["/grant", "*S-1-5-32-545:(OI)(CI)F", "/inheritance:r"]);
    assert!(granted, "icacls must be able to grant BUILTIN\\Users full control");
    assert!(
        assert_not_tamperable(&broad).is_err(),
        "a directory granting BUILTIN\\Users full control must be flagged tamperable"
    );

    let _ = std::fs::remove_dir_all(&base);
}

/// Kills 'compaction keeps stale/dropped records' (WSP2 facts §3): compact must replace the
/// file with only the kept records, so a fresh store recovers exactly those.
#[test]
fn compact_replaces_with_kept_records_only() {
    let dir = test_dir("compact");
    let jp = JournalPath::from_dir(dir.clone());
    let records = chained_records(5);

    let mut store = WinJournalStore::open(&jp).expect("open the journal");
    for rec in &records {
        store.append_synced(rec).expect("append_synced a record");
    }
    store
        .compact(&records[..2])
        .expect("compact must replace the file with only the kept records");

    drop(store);
    let store = WinJournalStore::open(&jp).expect("reopen the journal");
    match store.recover().expect("recover the journal") {
        RecoverOutcome::Clean(got) => assert_records(&records[..2], &got),
        _ => panic!("expected Clean([r0, r1]) after compaction, got a different recover outcome"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Kills 'ACL tamper ignored / non-typed error' (WSP2 facts §5): an ACL tamper that denies
/// the current user surfaces as a typed NativeError with kind Permission, never a panic.
#[test]
fn acl_tamper_deny_is_typed_error() {
    let base = test_dir("deny");
    let dir = base.join("store");
    let jp = JournalPath::from_dir(dir.clone());
    let records = chained_records(1);

    // Create the secure journal dir + a real journal file, and prove appends work pre-tamper.
    {
        let mut store = WinJournalStore::open(&jp).expect("open the journal");
        store
            .append_synced(&records[0])
            .expect("append works before the ACL tamper");
    } // drop closes the append handle before the file's ACL is tampered

    let file = journal_file_in(&dir);
    let sid = current_user_sid();
    let deny_arg = format!("*{sid}:(W)");
    let denied = run_icacls(&file, &["/deny", &deny_arg]);
    assert!(denied, "icacls must be able to deny the current user write access");

    let res = WinJournalStore::open(&jp);
    match res {
        Ok(_) => panic!(
            "a subsequent open after an ACL tamper must fail, not succeed (ACL tamper ignored)"
        ),
        Err(e) => {
            let typed: &NativeError = &e;
            assert_eq!(
                typed.kind(),
                NativeErrorKind::Permission,
                "an ACL-denied journal must fail with a typed Permission error, got {e:?}"
            );
        }
    }

    // Restore the file's ACL so the temp dir can be cleaned up.
    let _ = run_icacls(&file, &["/remove:d", &format!("*{sid}")]);
    let _ = std::fs::remove_dir_all(&base);
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
