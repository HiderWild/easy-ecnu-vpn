// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Win32 config crate (MVP subset).
//!
//! Phase-2 of the vpn-rust-native-runtime-mvp architecture: the coordinator
//! (core) reads `config.json` (target/routes/credential ciphertext), decrypts
//! the credential one-shot using the independent `key.bin`, and hands the
//! plaintext over the control-plane pipe to the engine. This crate owns that
//! file format and the AES-256-GCM credential sealing.
//!
//! Files (under `%USERPROFILE%\.exv` by default):
//!
//! - `config.json` — [`ExvConfig`] user configuration
//! - `key.bin`     — 32-byte AES key (key separation; never embedded in config)

mod crypto;
mod error;
mod paths;

pub use config::ExvConfig;
pub use error::ConfigError;
pub use paths::{config_dir, config_path, key_path};

mod config;

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
