// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Typed error for config load/save and password crypto.

use std::fmt;

/// Errors surfaced by [`crate::ExvConfig`] loading/saving and by the
/// AES-256-GCM password helpers.
#[derive(Debug)]
pub enum ConfigError {
    /// Filesystem error while reading/writing `config.json` or `key.bin`.
    Io(std::io::Error),
    /// `config.json` is not valid JSON or does not match the schema.
    Json(serde_json::Error),
    /// AES-GCM seal/open failure (bad key, tampered ciphertext).
    Crypto(aes_gcm::Error),
    /// Base64 decoding of the stored password failed.
    Base64(base64::DecodeError),
    /// The ciphertext blob is malformed (not `nonce || tag || ciphertext`).
    Malformed(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "config io: {e}"),
            Self::Json(e) => write!(f, "config json: {e}"),
            Self::Crypto(e) => write!(f, "config crypto: {e}"),
            Self::Base64(e) => write!(f, "config base64: {e}"),
            Self::Malformed(why) => write!(f, "config malformed: {why}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::Base64(e) => Some(e),
            // aes_gcm::Error is a unit struct and does not implement
            // std::error::Error; the message is carried in Display only.
            Self::Crypto(_) | Self::Malformed(_) => None,
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<aes_gcm::Error> for ConfigError {
    fn from(e: aes_gcm::Error) -> Self {
        Self::Crypto(e)
    }
}

impl From<base64::DecodeError> for ConfigError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Base64(e)
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
