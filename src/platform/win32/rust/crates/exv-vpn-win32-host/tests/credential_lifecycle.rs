// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! P3-a 凭据生命周期集成测试：真实 config 目录 → 解密 → 组装 `secret_payload` →
//! hand-off → 发送后零化，端到端断言凭据卫生。
//!
//! 验证契约：
//! 1. 明文密码只在 RAII guard 中短暂存活，组装后**确定性零化**（内存级断言）；
//! 2. `Debug` 对密码恒 `<redacted>`（不泄漏）；
//! 3. `secret` 不落盘（`config.json` 只含密文）、不上线（无任何可序列化产物含明文）。

use exv_vpn_win32_config::ExvConfig;
use exv_core::credential::{
    build_connect_request, load_credentials, parse_secret_payload, zeroize_connect_secret,
};
use exv_core::grpc_control::hand_off_request;
use exv_core::kernel_control::ClearableSecret;
use exv_vpn_wire::generated::ConnectIntent;

/// 测试明文密码（21 字节）与其字节长度（`windows` 断言用）。
const PASSWORD: &[u8] = b"hunter2-correct-horse";
const PASSWORD_LEN: usize = PASSWORD.len();

/// 写入一个携带 AES 密封密码 + 独立 key.bin 的临时 config 目录。
fn seeded_config_dir(plaintext: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let key = ExvConfig::ensure_key(dir.path()).expect("ensure key");
    let mut cfg = ExvConfig {
        server: "vpn-cn.ecnu.edu.cn".to_string(),
        username: "student".to_string(),
        routes: vec!["202.120.80.0/20".to_string()],
        ..ExvConfig::default()
    };
    cfg.set_password_encrypted(plaintext, &key).expect("encrypt");
    cfg.save_to_dir(dir.path()).expect("save config");
    dir
}

/// 完整产品流程：config（密文）+ key.bin → 解密 → 组装 payload → 放入
/// `ConnectRequest.secret_payload` → hand-off（move + 零化 one-shot 源）→
/// 发送后零化 wire 副本。全链路断言凭据卫生。
#[test]
fn credential_lifecycle_decrypt_assemble_send_zeroize() {
    let dir = seeded_config_dir("hunter2-correct-horse");
    let mut bundle = load_credentials(dir.path()).expect("load credentials");

    // 解密正确、明文仅在 guard 中。
    assert_eq!(bundle.config.username, "student");
    assert_eq!(bundle.password.as_str(), "hunter2-correct-horse");
    assert!(!bundle.password.is_zeroed(), "组装前 guard 仍持有明文");

    // 组装一次性 secret_payload → 明文密码中间态确定性零化。
    let payload = bundle.assemble_secret_payload().expect("assemble");
    assert!(bundle.password.is_zeroed(), "组装后明文密码必须已零化");
    let parsed = parse_secret_payload(&payload).expect("parse payload");
    assert_eq!(parsed.username, "student");
    assert_eq!(parsed.password, "hunter2-correct-horse");

    // 放入 ConnectRequest.secret_payload，走 hand_off（P1-c send_owned 语义）。
    let intent = ConnectIntent {
        lookup_key: None,
        request_digest: vec![0u8; 32],
        profile: None,
    };
    let mut secret = ClearableSecret::new(&payload);
    let mut request = build_connect_request(intent, payload);
    assert!(
        request
            .secret_payload
            .windows(PASSWORD_LEN)
            .any(|w| w == PASSWORD),
        "wire 副本在发送前持有明文"
    );

    let mut wire_request = hand_off_request(&mut request, &mut secret);
    assert!(request.secret_payload.is_empty(), "调用方请求被 Default 化");
    assert!(
        secret.as_bytes().iter().all(|&b| b == 0),
        "one-shot 源已零化"
    );

    // 发送完成后：确定性零化 wire 副本。
    zeroize_connect_secret(&mut wire_request);
    assert!(
        wire_request.secret_payload.iter().all(|&b| b == 0),
        "发送后 wire 副本已零化"
    );

    // Debug 全程不泄漏明文。
    assert!(!format!("{bundle:?}").contains("hunter2"), "bundle Debug 不得泄漏");
    assert!(!format!("{parsed:?}").contains("hunter2"), "package Debug 不得泄漏");
    assert!(
        !format!("{wire_request:?}").contains("hunter2"),
        "请求 Debug 不得泄漏"
    );

    // secret 不落盘：config.json 只含密文，绝无明文。
    let on_disk = std::fs::read_to_string(exv_vpn_win32_config::config_path(dir.path()))
        .expect("read config.json");
    assert!(!on_disk.contains("hunter2"), "明文不得落盘");
    assert!(bundle.config.password != "hunter2-correct-horse", "密文字段");
}

/// 失败路径 fail closed：`key.bin` 缺失时拒绝解密，无明文产生。
#[test]
fn credential_lifecycle_missing_key_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = ExvConfig {
        username: "student".to_string(),
        ..ExvConfig::default()
    };
    cfg.save_to_dir(dir.path()).expect("save config");

    let err = load_credentials(dir.path()).expect_err("must fail");
    assert_eq!(
        err,
        exv_core::credential::CredentialError::KeyMissing
    );
}
