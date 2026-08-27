// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! AES-256-GCM password sealing, matching the 0x01 blob layout.
//!
//! A stored password is `base64( nonce(12) || tag(16) || ciphertext )`, keyed by
//! a 32-byte key read from the separate `key.bin` (never embedded in
//! `config.json`). This mirrors the C++ `Config.password` ciphertext field
//! semantics (independent key file, decrypt only with the key) while using the
//! AEAD/GCM construction the MVP plan pinned.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use crate::error::ConfigError;

/// AES-GCM nonce length (12 bytes).
pub(crate) const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length (16 bytes).
pub(crate) const TAG_LEN: usize = 16;
/// AES-256 key length (32 bytes).
pub const KEY_LEN: usize = 32;

/// Encrypt `plaintext` with `key`, returning `base64( nonce || tag || ct )`.
///
/// The returned blob has no associated data; it is fully self-contained except
/// for the key, which the caller supplies from `key.bin`.
///
/// # Errors
///
/// Returns [`ConfigError::Crypto`] if sealing fails (never expected with a
/// well-formed 32-byte key), or [`ConfigError::Io`] if the OS RNG fails.
pub fn encrypt_password(plaintext: &str, key: &[u8; KEY_LEN]) -> Result<String, ConfigError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| ConfigError::Io(std::io::Error::other(e.to_string())))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // aes-gcm `encrypt` returns ct || tag appended; we re-layout to
    // nonce || tag || ct for the on-disk 0x01 format.
    let ct_with_tag = cipher.encrypt(nonce, Payload::from(plaintext.as_bytes()))?;

    let (ct, tag) = ct_with_tag.split_at(ct_with_tag.len() - TAG_LEN);
    let mut blob = Vec::with_capacity(NONCE_LEN + TAG_LEN + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(tag);
    blob.extend_from_slice(ct);
    Ok(BASE64.encode(blob))
}

/// Decrypt a blob produced by [`encrypt_password`].
///
/// # Errors
///
/// Returns [`ConfigError::Malformed`] if the blob is too short to contain
/// nonce + tag, [`ConfigError::Base64`] on bad encoding, or
/// [`ConfigError::Crypto`] if the tag does not authenticate (wrong key or
/// tampered ciphertext).
pub fn decrypt_password(blob_b64: &str, key: &[u8; KEY_LEN]) -> Result<String, ConfigError> {
    let blob = BASE64.decode(blob_b64)?;
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(ConfigError::Malformed("blob shorter than nonce+tag"));
    }

    let nonce_bytes = &blob[..NONCE_LEN];
    let tag = &blob[NONCE_LEN..NONCE_LEN + TAG_LEN];
    let ct = &blob[NONCE_LEN + TAG_LEN..];

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);

    // Re-layout to ct || tag, which is what `decrypt` expects.
    let mut ct_with_tag = Vec::with_capacity(ct.len() + TAG_LEN);
    ct_with_tag.extend_from_slice(ct);
    ct_with_tag.extend_from_slice(tag);

    let plaintext = cipher.decrypt(nonce, Payload::from(ct_with_tag.as_slice()))?;
    String::from_utf8(plaintext).map_err(|_| ConfigError::Malformed("decrypted password is not UTF-8"))
}

/// Generate a fresh random 32-byte key.
///
/// # Errors
///
/// Returns [`ConfigError::Io`] if the OS RNG fails.
pub fn generate_key() -> Result<[u8; KEY_LEN], ConfigError> {
    let mut key = [0u8; KEY_LEN];
    getrandom::fill(&mut key)
        .map_err(|e| ConfigError::Io(std::io::Error::other(e.to_string())))?;
    Ok(key)
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
