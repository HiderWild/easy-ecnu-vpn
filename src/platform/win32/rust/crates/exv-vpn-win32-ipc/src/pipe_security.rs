// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W11-I: pipe DACL construction. The frozen WSP1 facts (native-pipe-facts.md §4) pin the DACL
// shape to `SYSTEM` + the expected user SID with `GA` (generic all), and forbid any broad
// principal such as `BUILTIN\Users`. The SDDL is built dynamically from the caller-supplied user
// SID and materialized with `ConvertStringSecurityDescriptorToSecurityDescriptorW`.

use core::mem::size_of;
use std::iter::once;

use windows::Win32::Foundation::{ERROR_INVALID_PARAMETER, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::core::PCWSTR;

/// A `SECURITY_ATTRIBUTES` carrying a DACL that grants `SYSTEM` plus exactly one expected user
/// SID. The heap-allocated security descriptor is owned here and released on drop.
pub struct PipeSecurity {
    /// Heap-allocated security descriptor produced by the SDDL conversion, freed with `LocalFree`.
    descriptor: PSECURITY_DESCRIPTOR,
    /// Cached attributes whose `lpSecurityDescriptor` points at `descriptor`.
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    /// Builds a DACL granting `SYSTEM` (when `allow_system`) and `allow_user_sid`, both `GA`,
    /// shaped as `D:(A;;GA;;;SY)(A;;GA;;;<user_sid>)` — the WSP1 §4 frozen shape. A broad
    /// principal (`BUILTIN\Users`, `Everyone`, ...) is rejected instead of being granted.
    ///
    /// # Errors
    /// Returns `Err(ERROR_INVALID_PARAMETER)` when `allow_user_sid` names a broad principal, or
    /// the raw Win32 error code when the SDDL cannot be materialized.
    pub fn new(allow_user_sid: &str, allow_system: bool) -> Result<Self, u32> {
        if is_broad_sid(allow_user_sid) {
            return Err(ERROR_INVALID_PARAMETER.0);
        }

        let mut sddl = String::from("D:");
        if allow_system {
            sddl.push_str("(A;;GA;;;SY)");
        }
        sddl.push_str("(A;;GA;;;");
        sddl.push_str(allow_user_sid);
        sddl.push(')');

        let wide: Vec<u16> = sddl.encode_utf16().chain(once(0)).collect();
        let mut sd = PSECURITY_DESCRIPTOR(core::ptr::null_mut());
        // SAFETY: `wide` is a live, null-terminated wide buffer for the lifetime of this call;
        // `sd` is a live out-param the API allocates (released via `LocalFree` on drop).
        if let Err(e) = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &raw mut sd,
                None,
            )
        } {
            return Err(win32_code(&e));
        }

        let n_length = u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| ERROR_INVALID_PARAMETER.0)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: n_length,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        Ok(Self { descriptor: sd, attributes })
    }

    /// Returns the security attributes. The descriptor pointer stays valid while this value is
    /// alive.
    #[must_use]
    pub const fn as_attributes(&self) -> SECURITY_ATTRIBUTES {
        self.attributes
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        // SAFETY: `self.descriptor` was allocated by
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW` and has not been freed elsewhere;
        // `LocalFree` is the matching deallocator.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
        }
    }
}

/// Returns `true` when `sid` names a broad principal that must never be granted pipe access.
fn is_broad_sid(sid: &str) -> bool {
    let upper = sid.to_ascii_uppercase();
    if upper.contains("USERS") || upper.contains("EVERYONE") || upper.contains("BUILTIN") {
        return true;
    }
    // SID string form carries no names, so the well-known broad values are matched explicitly:
    // Everyone, Authenticated Users, and BUILTIN\Users.
    matches!(sid, "S-1-1-0" | "S-1-5-11" | "S-1-5-32-545")
}

/// Decodes the raw Win32 error code from a `windows` error. These security APIs return
/// `HRESULT_FROM_WIN32`-encoded errors, which place the Win32 code in the low 16 bits.
fn win32_code(err: &windows::core::Error) -> u32 {
    let bits = u32::from_ne_bytes(err.code().0.to_ne_bytes());
    bits & 0xFFFF
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
