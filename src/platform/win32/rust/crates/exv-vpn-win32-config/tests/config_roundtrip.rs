// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Integration tests: config load/save round-trip, credential round-trip, and
//! default alignment with `distribution/ecnu.json`.

use exv_vpn_win32_config::{
    config_dir, config_path, key_path, ConfigError, ExvConfig,
};

// ---------------------------------------------------------------------------
// Defaults aligned with distribution/ecnu.json
// ---------------------------------------------------------------------------

#[test]
fn defaults_match_ecnu_distribution() {
    let cfg = ExvConfig::default();

    assert_eq!(cfg.server, "vpn-cn.ecnu.edu.cn");
    assert_eq!(cfg.username, "");
    assert_eq!(cfg.password, "");
    assert!(!cfg.remember_password);
    assert_eq!(cfg.user_agent, "AnyConnect Win_x86_64 4.10.05095");
    assert_eq!(cfg.mtu, 1290);

    let expected_routes = [
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
    assert_eq!(cfg.routes, expected_routes);
    // C1: server control-plane bypass defaults to none (config opt-in).
    assert!(cfg.server_bypass_ips.is_empty());
    // C1: auto-reconnect off by default, unlimited attempts (0 = unlimited).
    assert!(!cfg.auto_reconnect);
    assert_eq!(cfg.auto_reconnect_max_attempts, 0);
}

// ---------------------------------------------------------------------------
// Load/save round-trip
// ---------------------------------------------------------------------------

#[test]
fn save_then_load_roundtrips() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = ExvConfig {
        server: "vpn-ct.ecnu.edu.cn".to_string(),
        username: "student".to_string(),
        mtu: 1400,
        server_bypass_ips: vec!["10.10.10.1".to_string(), "10.20.30.40".to_string()],
        ..ExvConfig::default()
    };

    cfg.save_to_dir(dir.path()).expect("save");

    // Files created in the right layout.
    assert!(config_path(dir.path()).exists());
    assert!(dir.path().join("config.json").exists());

    let loaded = ExvConfig::load_from_dir(dir.path()).expect("load");
    assert_eq!(loaded, cfg);
}

#[test]
fn load_missing_config_yields_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = ExvConfig::load_from_dir(dir.path()).expect("load missing");
    assert_eq!(cfg, ExvConfig::default());
}

#[test]
fn load_invalid_config_yields_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(config_path(dir.path()), "not json{").expect("write invalid");
    let cfg = ExvConfig::load_from_dir(dir.path()).expect("load invalid");
    assert_eq!(cfg, ExvConfig::default());
}

#[test]
fn load_unknown_fields_ignored_and_partial_defaulted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let json = r#"{
        "server": "vpn-lt.ecnu.edu.cn",
        "username": "student",
        "some_future_field": 42
    }"#;
    std::fs::write(config_path(dir.path()), json).expect("write partial");

    let cfg = ExvConfig::load_from_dir(dir.path()).expect("load partial");
    assert_eq!(cfg.server, "vpn-lt.ecnu.edu.cn");
    assert_eq!(cfg.username, "student");
    // Missing fields fall back to defaults.
    assert_eq!(cfg.mtu, 1290);
    assert_eq!(cfg.user_agent, "AnyConnect Win_x86_64 4.10.05095");
    assert_eq!(cfg.routes.len(), 9);
    assert!(cfg.server_bypass_ips.is_empty());
    assert!(!cfg.remember_password);
}

#[test]
fn load_old_config_without_auto_reconnect_fields_yields_defaults() {
    // 旧 config.json（新字段未写入）→ 结构体级 `#[serde(default)]` 用 Default 补齐。
    let dir = tempfile::tempdir().expect("tempdir");
    let json = r#"{
        "server": "vpn-cn.ecnu.edu.cn",
        "username": "student",
        "mtu": 1290
    }"#;
    std::fs::write(config_path(dir.path()), json).expect("write old config");

    let cfg = ExvConfig::load_from_dir(dir.path()).expect("load old config");
    assert_eq!(cfg.server, "vpn-cn.ecnu.edu.cn");
    // 缺省字段回退默认：auto_reconnect=false，auto_reconnect_max_attempts=0。
    assert!(!cfg.auto_reconnect);
    assert_eq!(cfg.auto_reconnect_max_attempts, 0);
}

#[test]
fn auto_reconnect_fields_save_load_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = ExvConfig {
        auto_reconnect: true,
        auto_reconnect_max_attempts: 5,
        ..ExvConfig::default()
    };

    cfg.save_to_dir(dir.path()).expect("save");
    let loaded = ExvConfig::load_from_dir(dir.path()).expect("load");
    assert_eq!(loaded, cfg);
    assert!(loaded.auto_reconnect);
    assert_eq!(loaded.auto_reconnect_max_attempts, 5);
}

// ---------------------------------------------------------------------------
// Password encrypt/decrypt round-trip via key.bin
// ---------------------------------------------------------------------------

#[test]
fn password_roundtrip_via_key_file() {
    let dir = tempfile::tempdir().expect("tempdir");

    let key = ExvConfig::ensure_key(dir.path()).expect("ensure key");
    assert_eq!(key.len(), 32);
    assert!(key_path(dir.path()).exists());

    let mut cfg = ExvConfig::default();
    cfg.set_password_encrypted("s3cret!", &key).expect("encrypt");
    assert!(cfg.remember_password);
    assert_ne!(cfg.password, "s3cret!");
    assert!(!cfg.password.is_empty());

    let decrypted = cfg.decrypt_password(&key).expect("decrypt");
    assert_eq!(decrypted, "s3cret!");
}

#[test]
fn password_roundtrip_after_save_load() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = ExvConfig::ensure_key(dir.path()).expect("ensure key");

    let mut cfg = ExvConfig {
        username: "student".to_string(),
        ..ExvConfig::default()
    };
    cfg.set_password_encrypted("hunter2", &key).expect("encrypt");
    cfg.save_to_dir(dir.path()).expect("save");

    // Simulate a fresh load: ciphertext persists, key file persists.
    let loaded = ExvConfig::load_from_dir(dir.path()).expect("load");
    assert_ne!(loaded.password, "hunter2");
    let loaded_key = ExvConfig::load_key(dir.path())
        .expect("load key")
        .expect("key present");
    assert_eq!(loaded_key, key);
    assert_eq!(loaded.decrypt_password(&loaded_key).expect("decrypt"), "hunter2");
}

#[test]
fn password_decrypt_wrong_key_fails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = ExvConfig::ensure_key(dir.path()).expect("ensure key");

    let mut cfg = ExvConfig::default();
    cfg.set_password_encrypted("secret", &key).expect("encrypt");

    let wrong_key = [7u8; 32];
    let result = cfg.decrypt_password(&wrong_key);
    assert!(matches!(result, Err(ConfigError::Crypto(_))));
}

#[test]
fn ensure_key_preserves_existing_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = ExvConfig::ensure_key(dir.path()).expect("first");
    let again = ExvConfig::ensure_key(dir.path()).expect("second");
    assert_eq!(key, again);
}

#[test]
fn load_key_rejects_wrong_length() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(key_path(dir.path()), [1u8; 16]).expect("write short key");
    let result = ExvConfig::load_key(dir.path());
    assert!(matches!(result, Err(ConfigError::Malformed(_))));
}

// ---------------------------------------------------------------------------
// config_dir resolution
// ---------------------------------------------------------------------------

#[test]
fn config_dir_defaults_to_dot_exv() {
    // EXV_CONFIG_DIR override is not set in CI; the default path must end in
    // `.exv` (via USERPROFILE or HOME) rather than be empty.
    let dir = config_dir();
    assert!(!dir.as_os_str().is_empty());
    assert!(dir.file_name().is_some_and(|n| n == ".exv"));
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
