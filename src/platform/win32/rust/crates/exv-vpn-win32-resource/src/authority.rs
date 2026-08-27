// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Singleton authority over a `Local\`-scoped Named Mutex (W13).
//!
//! The WSP2 facts (native-authority-storage-facts.md) freeze the primitive: a
//! Named Mutex in the `Local\` namespace, whose DACL is SYSTEM + the current
//! user (never broad IU). A loser of the two-process race observes `WAIT_TIMEOUT`
//! and exits before scan/observe/publish; an owner killed without release yields
//! `WAIT_ABANDONED` to the next waiter, which takes over ownership.

use std::ffi::c_void;

use windows::core::HSTRING;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, HLOCAL, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT, HANDLE,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SID_AND_ATTRIBUTES, TOKEN_QUERY, TokenUser,
    SECURITY_ATTRIBUTES,
};
use windows::Win32::System::Threading::{
    CreateMutexW, GetCurrentProcess, OpenProcessToken, ReleaseMutex, WaitForSingleObject,
};

use crate::native_error::NativeError;

/// Wait result for [`SingletonAuthority::try_acquire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityAcquire {
    /// The mutex was free and this caller acquired it (`WAIT_OBJECT_0`).
    Acquired,
    /// The previous owner died without releasing; this caller took over (`WAIT_ABANDONED`).
    AbandonedTakenOver,
    /// Another owner holds the mutex (`WAIT_TIMEOUT`); the caller is NOT the authority.
    Busy,
}

/// A named-mutex singleton authority. Only one holder at a time; a killed holder
/// abandons and the next waiter takes over.
#[derive(Debug)]
pub struct SingletonAuthority {
    handle: HANDLE,
}

impl SingletonAuthority {
    /// Create/open the `Local\`-scoped named mutex with a DACL of
    /// `D:(A;;GA;;;SY)(A;;GA;;;<current-user-SID>)` (the WSP2-frozen shape).
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if the current user SID cannot be read or the
    /// mutex cannot be created.
    pub fn new(name: &str) -> Result<Self, NativeError> {
        let user_sid = current_user_sid().ok_or_else(|| {
            NativeError::from_win32(0, "authority: cannot read the current user SID")
        })?;
        let sddl = format!("D:(A;;GA;;;SY)(A;;GA;;;{user_sid})");
        let hsddl = HSTRING::from(&sddl);

        // Build the self-relative security descriptor from the SDDL DACL. It is
        // allocated by the API with LocalAlloc and must be freed by the caller.
        let mut psd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        // SAFETY: `psd` is a live out-param the API allocates; it is freed below
        // with LocalFree after CreateMutexW no longer references it. `hsddl` is a
        // valid PCWSTR for the SDDL string.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(&hsddl, SDDL_REVISION_1, std::ptr::addr_of_mut!(psd), None)
        };
        if ok.is_err() {
            return Err(NativeError::from_win32(
                unsafe { GetLastError().0 },
                "authority: invalid security descriptor",
            ));
        }

        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: psd.0,
            bInheritHandle: false.into(),
        };

        let hname = HSTRING::from(name);
        // SAFETY: `attrs` points at the live restricted descriptor (kept alive for
        // the call); `hname` is a valid name; the returned HANDLE is owned by the
        // caller (or the API errors). CreateMutexW fails with Err on a bad name or
        // a DACL that denies the caller.
        let handle = unsafe { CreateMutexW(Some(std::ptr::addr_of!(attrs)), false, &hname) }
            .map_err(|e| {
            // SAFETY: psd was allocated by the SDDL conversion API; free it now that
            // CreateMutexW has returned and no longer references the descriptor.
            unsafe { let _ = LocalFree(Some(HLOCAL(psd.0))); }
            NativeError::from_win32(u32::try_from(e.code().0).unwrap_or(0), "authority: CreateMutexW failed")
        })?;

        // SAFETY: psd was allocated by the SDDL conversion API and must be released;
        // it is no longer referenced by the kernel after CreateMutexW.
        unsafe { let _ = LocalFree(Some(HLOCAL(psd.0))); }
        // SAFETY: attrs is a stack value; it is dropped at end of scope. The mutex
        // handle is now independent of the descriptor.
        let _ = &mut attrs;

        Ok(Self { handle })
    }

    /// Try to take the singleton authority without blocking.
    ///
    /// Returns [`AuthorityAcquire::Acquired`] on `WAIT_OBJECT_0`,
    /// [`AuthorityAcquire::AbandonedTakenOver`] on `WAIT_ABANDONED` (a killed owner
    /// transferred ownership), and [`AuthorityAcquire::Busy`] on `WAIT_TIMEOUT`.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if the wait itself failed.
    pub fn try_acquire(&self) -> Result<AuthorityAcquire, NativeError> {
        // SAFETY: `self.handle` is the valid, open mutex handle owned by this value.
        let result = unsafe { WaitForSingleObject(self.handle, 0) };
        if result == WAIT_OBJECT_0 {
            Ok(AuthorityAcquire::Acquired)
        } else if result == WAIT_ABANDONED {
            Ok(AuthorityAcquire::AbandonedTakenOver)
        } else if result == WAIT_TIMEOUT {
            Ok(AuthorityAcquire::Busy)
        } else if result == WAIT_FAILED {
            Err(NativeError::from_win32(
                unsafe { GetLastError().0 },
                "authority: WaitForSingleObject failed",
            ))
        } else {
            Err(NativeError::from_win32(
                result.0,
                "authority: unexpected wait result",
            ))
        }
    }

    /// Release the mutex so another holder can acquire it.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if the release fails.
    pub fn release(&self) -> Result<(), NativeError> {
        // SAFETY: `self.handle` is the valid, open mutex handle owned by this value;
        // the caller holds ownership (acquired via `try_acquire`).
        unsafe { ReleaseMutex(self.handle) }.map_err(|e| {
            NativeError::from_win32(u32::try_from(e.code().0).unwrap_or(0), "authority: ReleaseMutex failed")
        })
    }
}

impl Drop for SingletonAuthority {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is the mutex handle owned by this value; CloseHandle
        // is safe on any valid open handle and must be called exactly once.
        unsafe { let _ = CloseHandle(self.handle); }
    }
}

/// Read the current process's user SID as an SDDL string.
pub(crate) fn current_user_sid() -> Option<String> {
    // SAFETY: GetCurrentProcess returns a pseudo-handle owned by the OS; it must
    // NOT be closed. OpenProcessToken writes the token out-param.
    let mut token = HANDLE::default();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, std::ptr::addr_of_mut!(token)) };
    if ok.is_err() {
        return None;
    }

    let mut buff = [0u8; 4096];
    let mut ret = 0u32;
    // SAFETY: `buff` lives for the call; the returned PSID points into token-owned
    // memory that stays valid while the token handle is open.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buff.as_mut_ptr().cast::<c_void>()),
            u32::try_from(buff.len()).unwrap_or(0),
            std::ptr::addr_of_mut!(ret),
        )
    };
    if ok.is_err() {
        // SAFETY: `token` was opened above and must be closed.
        unsafe { let _ = CloseHandle(token); }
        return None;
    }
    // SAFETY: TokenUser returns a SID_AND_ATTRIBUTES whose first field is the PSID;
    // the buffer may be unaligned so read_unaligned is used.
    let sa = unsafe { std::ptr::read_unaligned(buff.as_ptr().cast::<SID_AND_ATTRIBUTES>()) };
    let sid = sid_to_string(sa.Sid);
    // SAFETY: `token` was opened above and must be closed.
    unsafe { let _ = CloseHandle(token); }
    sid
}

/// Convert a PSID to its string form, freeing the OS-allocated buffer.
fn sid_to_string(sid: PSID) -> Option<String> {
    let mut p = windows::core::PWSTR::null();
    // SAFETY: `sid` is a valid PSID owned by the caller's token query and `p` is a
    // live out-param the API allocates; the result is freed with LocalFree below.
    let ok = unsafe { ConvertSidToStringSidW(sid, std::ptr::addr_of_mut!(p)) };
    if ok.is_err() {
        return None;
    }
    let s = unsafe { p.to_string() }.ok()?;
    // SAFETY: the string was allocated by ConvertSidToStringSidW and must be released.
    unsafe { let _ = LocalFree(Some(HLOCAL(p.0.cast::<c_void>()))); }
    Some(s)
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。