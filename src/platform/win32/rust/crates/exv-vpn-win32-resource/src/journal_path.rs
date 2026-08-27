// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Machine-level journal directory path resolution (W14).
//!
//! The WSP2 facts (native-authority-storage-facts.md §2) freeze the journal root
//! at `%ProgramData%\ExvVpn\journal`, with `%LOCALAPPDATA%\ExvVpn\journal` as the
//! fallback when `ProgramData` is not creatable/writable.

use std::path::{Path, PathBuf};

/// The journal directory path. Resolves to `%ProgramData%\ExvVpn\journal`
/// (machine-level, multi-instance shared) when that location is
/// creatable/writable, otherwise the `%LOCALAPPDATA%\ExvVpn\journal` fallback.
pub struct JournalPath {
    path: PathBuf,
}

impl JournalPath {
    /// The machine-default journal directory.
    #[must_use]
    pub fn machine_default() -> Self {
        if let Some(program_data) = std::env::var_os("PROGRAMDATA") {
            let candidate = PathBuf::from(program_data).join("ExvVpn").join("journal");
            if dir_is_usable(&candidate) {
                return Self { path: candidate };
            }
        }
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            let fallback = PathBuf::from(local_app_data).join("ExvVpn").join("journal");
            return Self { path: fallback };
        }
        Self {
            path: std::env::temp_dir().join("ExvVpn").join("journal"),
        }
    }

    /// A journal directory pinned to `dir` (used by tests and custom layouts).
    #[must_use]
    pub const fn from_dir(dir: PathBuf) -> Self {
        Self { path: dir }
    }

    /// The journal directory path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

/// True when `dir` can be used as the journal directory: it exists (created on
/// demand) and a probe file can be written and removed inside it.
#[must_use]
fn dir_is_usable(dir: &Path) -> bool {
    if !dir.is_dir() && std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe_id = std::process::id();
    let probe = dir.join(format!(".exv-journal-write-probe-{probe_id}"));
    match std::fs::File::create(&probe) {
        Ok(file) => {
            drop(file);
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
