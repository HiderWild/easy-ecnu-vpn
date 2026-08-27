// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! The MVP `ExvConfig` structure plus load/save and credential helpers.
//!
//! Field names and default values are aligned with the C++ config
//! (`src/core/config/config.hpp` at v3.3.7 and `distribution/ecnu.json`).
//! The MVP subset covers: target server, routes, server control-plane bypass
//! destinations, and credentials (username + AES-sealed password). The password
//! is stored as ciphertext and decrypted one-shot with the independent
//! `key.bin` key.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::{decrypt_password, encrypt_password, KEY_LEN};
use crate::error::ConfigError;
use crate::paths::{config_path, key_path};

/// Default gateway hostname (`distribution/ecnu.json` `default_vpn_server`).
pub const DEFAULT_SERVER: &str = "vpn-cn.ecnu.edu.cn";
/// Default campus routes (`distribution/ecnu.json` `default_routes`).
pub const DEFAULT_ROUTES: [&str; 9] = [
    "49.52.4.0/25",
    "59.78.176.0/20",
    "59.78.199.0/21",
    "58.198.176.128/25",
    "219.228.60.69",
    "59.78.189.128/25",
    "219.228.63.0/21",
    "202.120.80.0/20",
    "222.66.117.0/24",
];
/// Default Windows user-agent (`distribution/ecnu.json` `default_user_agents.windows`).
pub const DEFAULT_USER_AGENT: &str = "AnyConnect Win_x86_64 4.10.05095";
/// Default MTU, matching the C++ `Config` default (1290).
pub const DEFAULT_MTU: u32 = 1290;

/// User VPN configuration (MVP subset).
///
/// Fields mirror the C++ `Config` JSON keys. `password` holds the AES-256-GCM
/// ciphertext (`base64( nonce || tag || ct )`), never the plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExvConfig {
    /// Gateway hostname, e.g. `vpn-cn.ecnu.edu.cn`.
    pub server: String,
    /// Login username.
    pub username: String,
    /// AES-GCM sealed password (base64), or empty when not remembered.
    pub password: String,
    /// Whether `password` should be remembered across sessions.
    pub remember_password: bool,
    /// Campus routes to push into the tunnel.
    pub routes: Vec<String>,
    /// Server control-plane destinations to keep on the physical egress
    /// (Phase 7 C1: `control_bypass` — one `/32` bypass route per entry,
    /// installed before the tunnel routes; mirrors C++ `tunnel_config.hpp`
    /// `server_bypass_ips`, the `X-CSTP-Bypass-Route` + config double source).
    pub server_bypass_ips: Vec<String>,
    /// Client user-agent presented to the gateway.
    #[serde(rename = "useragent")]
    pub user_agent: String,
    /// Tunnel MTU.
    pub mtu: u32,
    /// Whether to automatically reconnect after an unexpected disconnect.
    pub auto_reconnect: bool,
    /// Maximum auto-reconnect attempts (0 = unlimited).
    pub auto_reconnect_max_attempts: u32,
}

impl Default for ExvConfig {
    fn default() -> Self {
        Self {
            server: DEFAULT_SERVER.to_string(),
            username: String::new(),
            password: String::new(),
            remember_password: false,
            routes: DEFAULT_ROUTES.iter().map(|r| (*r).to_string()).collect(),
            server_bypass_ips: Vec::new(),
            user_agent: DEFAULT_USER_AGENT.to_string(),
            mtu: DEFAULT_MTU,
            auto_reconnect: false,
            auto_reconnect_max_attempts: 0,
        }
    }
}

impl ExvConfig {
    /// Load the user config from the resolved config directory.
    ///
    /// Mirrors C++ `config_initialization`: a missing file (or a file that is
    /// not valid JSON / not an object) yields a fresh default config, so the
    /// caller can `save()` to persist it.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] only on filesystem read failures, never on a
    /// missing/malformed file (those produce the default).
    pub fn load() -> Result<Self, ConfigError> {
        Self::load_from_dir(&crate::paths::config_dir())
    }

    /// Load the user config from an explicit directory (testable / overridable).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] on a filesystem read failure; a missing or
    /// malformed `config.json` yields the default config, never an error.
    pub fn load_from_dir(dir: &Path) -> Result<Self, ConfigError> {
        let path = config_path(dir);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        match serde_json::from_str::<Self>(&text) {
            Ok(cfg) => Ok(cfg),
            Err(_) => Ok(Self::default()),
        }
    }

    /// Persist this config to the resolved config directory (creating it if
    /// needed).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] on any filesystem or serialization failure.
    pub fn save(&self) -> Result<(), ConfigError> {
        self.save_to_dir(&crate::paths::config_dir())
    }

    /// Persist this config to an explicit directory.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] on any filesystem or serialization failure.
    pub fn save_to_dir(&self, dir: &Path) -> Result<(), ConfigError> {
        std::fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(config_path(dir), json)?;
        Ok(())
    }

    /// Ensure a 32-byte key exists in `dir`, generating and persisting a new
    /// one if the file is missing or malformed.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the key file cannot be read/written.
    pub fn ensure_key(dir: &Path) -> Result<[u8; KEY_LEN], ConfigError> {
        if let Ok(Some(key)) = Self::load_key(dir) {
            Ok(key)
        } else {
            let key = crate::crypto::generate_key()?;
            Self::save_key(dir, &key)?;
            Ok(key)
        }
    }

    /// Read the 32-byte key from `<dir>/key.bin`.
    ///
    /// Returns `Ok(None)` when the key file does not exist, and `Err` on
    /// unreadable or wrong-length files.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] on an unreadable key file, or
    /// [`ConfigError::Malformed`] when the file is not exactly 32 bytes.
    pub fn load_key(dir: &Path) -> Result<Option<[u8; KEY_LEN]>, ConfigError> {
        let path = key_path(dir);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() != KEY_LEN {
            return Err(ConfigError::Malformed(
                "key.bin must be exactly 32 bytes (AES-256)",
            ));
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&bytes);
        Ok(Some(key))
    }

    /// Write a 32-byte key to `<dir>/key.bin` (creating `dir` if needed).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] if the directory or key file cannot be
    /// written.
    pub fn save_key(dir: &Path, key: &[u8; KEY_LEN]) -> Result<(), ConfigError> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(key_path(dir), key)?;
        Ok(())
    }

    /// Decrypt the stored password with the supplied key.
    ///
    /// Returns an empty string when `password` is empty (not remembered). Any
    /// decryption failure (wrong key, tampered ciphertext) is surfaced as a
    /// typed [`ConfigError`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Malformed`] for an empty or badly-shaped blob,
    /// [`ConfigError::Base64`] for bad base64, or [`ConfigError::Crypto`] when
    /// authentication fails (wrong key or tampered ciphertext).
    pub fn decrypt_password(&self, key: &[u8; KEY_LEN]) -> Result<String, ConfigError> {
        if self.password.is_empty() {
            return Ok(String::new());
        }
        decrypt_password(&self.password, key)
    }

    /// Encrypt `plaintext` with `key` and store the ciphertext, marking the
    /// password as remembered.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Io`] if the OS RNG fails or
    /// [`ConfigError::Crypto`] if sealing fails.
    pub fn set_password_encrypted(
        &mut self,
        plaintext: &str,
        key: &[u8; KEY_LEN],
    ) -> Result<(), ConfigError> {
        self.password = encrypt_password(plaintext, key)?;
        self.remember_password = !plaintext.is_empty();
        Ok(())
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
