// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Typed Win32 native errors (W13). Maps raw `GetLastError` codes to a coarse
//! kind so callers can branch on category without leaking raw message text.

/// The coarse category of a native Win32 error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeErrorKind {
    Permission,
    Transport,
    Protocol,
    Resource,
    Storage,
    Observation,
    Unsupported,
    Unknown,
}

/// A typed native error: category + raw code + a short human message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeError {
    pub kind: NativeErrorKind,
    pub code: u32,
    pub message: String,
}

impl NativeError {
    /// Build from a Win32 `GetLastError`-style code. Known codes are mapped to a
    /// category (W13: win32 5 -> Permission, 33 -> Resource); unmapped codes are
    /// `Unknown`.
    #[must_use]
    pub fn from_win32(code: u32, message: &str) -> Self {
        let kind = match code {
            5 => NativeErrorKind::Permission, // ERROR_ACCESS_DENIED
            33 => NativeErrorKind::Resource,  // ERROR_LOCK_VIOLATION
            2 | 3 => NativeErrorKind::Storage, // ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND
            _ => NativeErrorKind::Unknown,
        };
        Self {
            kind,
            code,
            message: message.to_string(),
        }
    }

    /// The coarse category of this native error.
    #[must_use]
    pub fn kind(&self) -> NativeErrorKind {
        self.kind
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。