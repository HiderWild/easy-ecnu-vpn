// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Secure-directory ACL enforcement for the journal (W14).
//!
//! The WSP2 facts (native-authority-storage-facts.md §2/§5) freeze the journal
//! directory ACL to SYSTEM + the current user only, protected against
//! inheritance, never a broad BUILTIN\Users / Everyone grant. An ACL tamper
//! surfaces as a typed [`NativeError`], never a panic.

use std::ffi::c_void;
use std::path::Path;

use windows::core::HSTRING;
use windows::Win32::Foundation::{GetLastError, LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SetFileSecurityW,
};

use crate::authority::current_user_sid;
use crate::native_error::NativeError;

/// Ensure `dir` exists and carries a DACL of SYSTEM + the current user only,
/// protected against inheritance (never broad BUILTIN\Users / IU / Everyone).
///
/// # Errors
///
/// Returns a [`NativeError`] if the directory cannot be created or its security
/// descriptor cannot be applied.
pub fn ensure_secure_dir(dir: &Path) -> Result<(), NativeError> {
    std::fs::create_dir_all(dir).map_err(|e| io_native("storage_security: create_dir_all", &e))?;
    ensure_secure_path(dir)
}

/// Ensure `file` (which must already exist) carries a DACL of SYSTEM + the
/// current user only, protected against inheritance (never broad
/// BUILTIN\Users / IU / Everyone). Used by the school credential one-shot
/// channel: a restricted temp file that only the same user can read.
///
/// # Errors
///
/// Returns a [`NativeError`] if the file's security descriptor cannot be applied.
pub fn ensure_secure_file(file: &Path) -> Result<(), NativeError> {
    ensure_secure_path(file)
}

/// Apply the SYSTEM + current-user-only DACL to `path` (file or directory),
/// protected against inheritance.
fn ensure_secure_path(path: &Path) -> Result<(), NativeError> {
    let user_sid = current_user_sid().ok_or_else(|| {
        NativeError::from_win32(0, "storage_security: cannot read the current user SID")
    })?;
    // SYSTEM + current user, full control, object/container inherit, protected DACL.
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user_sid})");
    let hsddl = HSTRING::from(&sddl);

    let mut psd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // SAFETY: `psd` is a live out-param the API allocates; it is freed below with
    // LocalFree once the descriptor has been applied. `hsddl` is a valid PCWSTR.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &hsddl,
            SDDL_REVISION_1,
            std::ptr::addr_of_mut!(psd),
            None,
        )
    };
    if ok.is_err() {
        return Err(NativeError::from_win32(
            unsafe { GetLastError().0 },
            "storage_security: invalid security descriptor",
        ));
    }

    let hpath = HSTRING::from(path.to_string_lossy().as_ref());
    let info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    // SAFETY: `hpath` is a valid path PCWSTR and `psd` is a valid self-relative
    // descriptor that stays alive for the call; the API copies what it needs.
    let applied = unsafe { SetFileSecurityW(&hpath, info, psd) };
    // SAFETY: psd was allocated by the SDDL conversion API and must be released
    // now that SetFileSecurityW has returned.
    unsafe { let _ = LocalFree(Some(HLOCAL(psd.0))); }
    if !applied.as_bool() {
        return Err(NativeError::from_win32(
            unsafe { GetLastError().0 },
            "storage_security: SetFileSecurityW failed",
        ));
    }
    Ok(())
}

/// Verify `dir`'s effective DACL is not broad: no BUILTIN\Users / Interactive
/// Users / BUILTIN\Administrators / Everyone allow-grant ACEs, and the DACL is
/// not null.
///
/// # Errors
///
/// Returns a [`NativeError`] if the ACL cannot be read or a broad allow ACE is
/// present.
pub fn assert_not_tamperable(dir: &Path) -> Result<(), NativeError> {
    assert_path_not_tamperable(dir)
}

/// Verify a single `file`'s effective DACL is not broad (same contract as
/// [`assert_not_tamperable`], for the school credential one-shot channel: a
/// credential-carrying temp file must never be readable by BUILTIN\Users /
/// Interactive Users / Everyone).
///
/// # Errors
///
/// Returns a [`NativeError`] if the ACL cannot be read or a broad allow ACE is
/// present.
pub fn assert_file_not_tamperable(file: &Path) -> Result<(), NativeError> {
    assert_path_not_tamperable(file)
}

/// Shared ACL-breadth check for any file-system object (`GetNamedSecurityInfoW`
/// with `SE_FILE_OBJECT` applies to files and directories alike).
fn assert_path_not_tamperable(path: &Path) -> Result<(), NativeError> {
    let mut psd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let hpath = HSTRING::from(path.to_string_lossy().as_ref());
    // SAFETY: `hpath` is a valid path PCWSTR; `psd` is a live out-param the API
    // allocates and that must be freed with LocalFree below.
    let err = unsafe {
        GetNamedSecurityInfoW(
            &hpath,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            std::ptr::addr_of_mut!(psd),
        )
    };
    if !err.is_ok() {
        return Err(NativeError::from_win32(
            err.0,
            "storage_security: GetNamedSecurityInfoW failed",
        ));
    }

    let mut pstr = windows::core::PWSTR::null();
    // SAFETY: psd is a valid descriptor; `pstr` is a live out-param the API
    // allocates and that must be freed with LocalFree below.
    let rendered = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            std::ptr::addr_of_mut!(pstr),
            None,
        )
    };
    // SAFETY: psd was allocated by GetNamedSecurityInfoW and must be released.
    unsafe { let _ = LocalFree(Some(HLOCAL(psd.0))); }
    if rendered.is_err() {
        return Err(NativeError::from_win32(
            unsafe { GetLastError().0 },
            "storage_security: render security descriptor",
        ));
    }
    // SAFETY: pstr points at the null-terminated string the API allocated.
    let sddl = unsafe { pstr.to_string() };
    // SAFETY: the string was allocated by ConvertSecurityDescriptorToStringSecurityDescriptorW
    // and must be released with LocalFree.
    unsafe { let _ = LocalFree(Some(HLOCAL(pstr.0.cast::<c_void>()))); }
    let sddl = sddl.map_err(|_| NativeError::from_win32(0, "storage_security: invalid SDDL string"))?;

    if dacl_is_broad(&sddl) {
        return Err(NativeError::from_win32(
            5,
            "storage_security: ACL grants broad access (BUILTIN\\Users / Everyone / IU)",
        ));
    }
    Ok(())
}

/// True when a rendered DACL has no DACL section at all (a null DACL grants
/// everyone full access) or contains an allow ACE for a broad principal.
#[must_use]
fn dacl_is_broad(sddl: &str) -> bool {
    if !sddl.contains("D:") {
        return true;
    }
    let body = sddl.strip_prefix("D:").unwrap_or(sddl);
    for ace in body.split('(') {
        let ace = ace.trim_end_matches(')');
        if !ace.starts_with("A;") {
            continue;
        }
        let fields: Vec<&str> = ace.split(';').collect();
        if fields.len() < 6 {
            continue;
        }
        if is_broad_sid(fields[5]) {
            return true;
        }
    }
    false
}

/// True when the SDDL principal denotes a broad (per-user/per-group-wide) SID.
#[must_use]
fn is_broad_sid(sid: &str) -> bool {
    // SDDL abbreviations for BUILTIN\Users, Interactive Users, BUILTIN\Administrators,
    // and Everyone, plus their explicit SID spellings.
    matches!(sid, "BU" | "IU" | "BA" | "WD")
        || matches!(sid, "S-1-5-32-545" | "S-1-5-4" | "S-1-5-32-544" | "S-1-1-0")
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

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
