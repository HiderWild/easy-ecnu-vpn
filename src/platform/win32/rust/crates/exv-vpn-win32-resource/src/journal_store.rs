// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Durable append-only journal store over the Win32 platform (W14).
//!
//! The WSP2 facts (native-authority-storage-facts.md §3/§4) freeze the
//! durability contract: each `append_synced` is durable via `FlushFileBuffers`
//! (Rust `std::fs::flush` is a no-op and must not be the durability point), a
//! torn final tail recovers to the last complete record, a corrupt middle record
//! yields `Corrupt` and never skips forward, and compaction replaces the file
//! with only the kept records via `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use exv_vpn_resource::journal::{decode, encode, DecodeOutcome, JournalRecord};

use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};

use crate::journal_path::JournalPath;
use crate::native_error::NativeError;
use crate::storage_security::ensure_secure_dir;

/// The single journal file name inside the journal directory.
const JOURNAL_FILE: &str = "journal.bin";

/// Result of reading the journal back from disk.
pub enum RecoverOutcome {
    /// Every record decoded cleanly.
    Clean(Vec<JournalRecord>),
    /// The final frame is torn; `records` are the complete records before it.
    TornTail { records: Vec<JournalRecord> },
    /// A record failed validation at byte `offset`; later records are not trusted.
    Corrupt { offset: usize },
}

/// An append-only, FlushFileBuffers-durable journal over one directory.
///
/// The journal file handle is held open for appends. It is temporarily taken
/// out (set to `None`) during compaction so the atomic replace can run against a
/// closed target.
pub struct WinJournalStore {
    dir: std::path::PathBuf,
    file_path: std::path::PathBuf,
    file: Option<std::fs::File>,
    write_pos: u64,
}

impl WinJournalStore {
    /// Open (creating on demand) the journal in `dir`.
    ///
    /// The directory is secured to SYSTEM + the current user, then the journal
    /// file is opened for read + append + create.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if the directory cannot be secured or the file
    /// cannot be opened (including a Permission error after an ACL tamper).
    pub fn open(dir: &JournalPath) -> Result<Self, NativeError> {
        let dir_path = dir.as_path().to_path_buf();
        ensure_secure_dir(&dir_path)?;
        let file_path = dir_path.join(JOURNAL_FILE);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .open(&file_path)
            .map_err(|e| io_native("journal_store: open", &e))?;
        let write_pos = file
            .metadata()
            .map_err(|e| io_native("journal_store: metadata", &e))?
            .len();
        Ok(Self {
            dir: dir_path,
            file_path,
            file: Some(file),
            write_pos,
        })
    }

    /// The live journal append/read handle.
    fn handle(&self) -> &std::fs::File {
        self.file.as_ref().expect("journal file handle is open")
    }

    /// The live journal append/read handle, mutably.
    fn handle_mut(&mut self) -> &mut std::fs::File {
        self.file.as_mut().expect("journal file handle is open")
    }

    /// Append `record` as a J50 frame and flush it to disk (`FlushFileBuffers`).
    ///
    /// Returns the byte offset where the frame was written.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if the frame cannot be written or flushed.
    pub fn append_synced(&mut self, record: &JournalRecord) -> Result<u64, NativeError> {
        let offset = self.write_pos;
        let bytes = encode(record);
        let file = self.handle_mut();
        file.write_all(&bytes)
            .map_err(|e| io_native("journal_store: append write", &e))?;
        // std::fs::sync_all maps to FlushFileBuffers on Windows — the durability point.
        file.sync_all()
            .map_err(|e| io_native("journal_store: flush", &e))?;
        self.write_pos = file
            .metadata()
            .map_err(|e| io_native("journal_store: metadata", &e))?
            .len();
        Ok(offset)
    }

    /// Read the whole journal and classify it via the J50 codec.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if the journal cannot be read.
    pub fn recover(&self) -> Result<RecoverOutcome, NativeError> {
        let mut handle = self.handle();
        handle
            .seek(SeekFrom::Start(0))
            .map_err(|e| io_native("journal_store: seek", &e))?;
        let mut bytes = Vec::new();
        handle
            .read_to_end(&mut bytes)
            .map_err(|e| io_native("journal_store: read", &e))?;
        Ok(match decode(&bytes) {
            DecodeOutcome::Clean(records) => RecoverOutcome::Clean(records),
            DecodeOutcome::TornTail { records } => RecoverOutcome::TornTail { records },
            DecodeOutcome::Corrupt { offset, .. } => RecoverOutcome::Corrupt { offset },
        })
    }

    /// Replace the journal file with only `keep_records`, durably.
    ///
    /// The kept records are written to a temp file, flushed, moved over the
    /// journal file with `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`, and the
    /// parent directory is flushed.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if the temp file, the replace, or the reopen
    /// fails.
    pub fn compact(&mut self, keep_records: &[JournalRecord]) -> Result<(), NativeError> {
        let mut buf = Vec::new();
        for record in keep_records {
            buf.extend_from_slice(&encode(record));
        }

        let temp_path = self.dir.join("journal.bin.compact");
        {
            let mut tmp = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)
                .map_err(|e| io_native("journal_store: compact temp open", &e))?;
            tmp.write_all(&buf)
                .map_err(|e| io_native("journal_store: compact temp write", &e))?;
            tmp.sync_all()
                .map_err(|e| io_native("journal_store: compact temp flush", &e))?;
        }

        // Close the journal handle so the atomic replace can run against a closed
        // target (MoveFileExW + MOVEFILE_WRITE_THROUGH fails with ACCESS_DENIED while
        // the destination is open).
        let _ = self.file.take();

        let src = HSTRING::from(temp_path.to_string_lossy().as_ref());
        let dst = HSTRING::from(self.file_path.to_string_lossy().as_ref());
        // SAFETY: `src` and `dst` are valid PCWSTRs for the temp and journal paths
        // and both live for the call.
        unsafe { MoveFileExW(&src, &dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) }
            .map_err(|e| NativeError::from_win32(win32_code(&e), "journal_store: compact replace"))?;

        flush_directory(&self.dir)?;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .create(true)
            .append(true)
            .open(&self.file_path)
            .map_err(|e| io_native("journal_store: compact reopen", &e))?;
        self.write_pos = file
            .metadata()
            .map_err(|e| io_native("journal_store: metadata", &e))?
            .len();
        self.file = Some(file);
        Ok(())
    }
}

/// Flush the directory metadata for `dir` so a completed rename is durable.
fn flush_directory(dir: &Path) -> Result<(), NativeError> {
    let hpath = HSTRING::from(dir.to_string_lossy().as_ref());
    // SAFETY: `hpath` is a valid directory path; a directory handle is opened with
    // FILE_FLAG_BACKUP_SEMANTICS and closed below.
    let handle: HANDLE = unsafe {
        CreateFileW(
            &hpath,
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .map_err(|e| NativeError::from_win32(win32_code(&e), "journal_store: open dir"))?;

    // SAFETY: `handle` is a valid open directory handle owned by this function.
    let flushed = unsafe { FlushFileBuffers(handle) };
    // SAFETY: `handle` is owned by this function and must be closed exactly once.
    unsafe { let _ = CloseHandle(handle); }

    flushed.map_err(|e| NativeError::from_win32(win32_code(&e), "journal_store: flush dir"))
}

/// Map an `std::io::Error` to a typed [`NativeError`], preserving the Win32 code.
#[must_use]
fn io_native(context: &str, error: &std::io::Error) -> NativeError {
    let code = error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .unwrap_or(0);
    NativeError::from_win32(code, context)
}

/// Extract the Win32 code from a `windows` crate `Error` (facility-7 encoding).
#[must_use]
fn win32_code(error: &windows::core::Error) -> u32 {
    windows::Win32::Foundation::WIN32_ERROR::from_error(error).map_or(0, |win32| win32.0)
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
