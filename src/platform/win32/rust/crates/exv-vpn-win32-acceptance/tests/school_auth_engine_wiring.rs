// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV CS-AUTH-05-T: acceptance wiring + evidence integration tests (RED phase).
//
// These tests define the acceptance-side contract that CS-AUTH-05-I must
// implement in the win32 acceptance crate
// (docs/superpowers/plans/2026-08-15-cstp-authentication-rebuild-plan.md leaf
// CS-AUTH-05, L123):
//   * `scenarios/school.rs`'s hand-rolled `open_school_data_connection`
//     (CONNECT <host> + X-AnyConnect-* + Authorization: Basic, rejected by the
//     real gateway) is REPLACED by the committed engine calls
//     (`webvpn::WebvpnLogin::perform_login` -> `session::CstpSession::open`);
//   * `evidence.rs` gains the three additive fields `login_status: Option<String>`
//     / `saml_required: bool` / `cookie_present: bool` (appended at struct end,
//     serialization stable) and `is_dynamic_complete()` adds the login
//     obligation (`login_status == Some("webvpn-login-ok")`);
//   * `scenarios/controlled.rs`'s `is_cisco_cstp_connect_request` is aligned to
//     the engine CONNECT shape (fake and real behave alike).
//
// These tests are expected to be RED (compile errors for the not-yet-existing
// evidence fields `login_status` / `saml_required` / `cookie_present`) until
// CS-AUTH-05-I implements the wiring. The mechanism tests (loopback fake
// gateway, non-elevated) drive the committed engine (`exv-vpn-cstp`) through
// the acceptance-crate test harness, reusing the loopback TLS patterns of the
// cstp crate's webvpn_login.rs with THIS file's own embedded test PKI; the
// real-gateway parts are elevation-gated per the existing school_scenario.rs
// pattern (require_admin: never fake RED/GREEN, `not_run` rules unchanged).
//
// Mutants this suite must kill (plan L123):
//   M1 手搓 CONNECT 复活（fake 拒绝）      -> hand_rolled_connect_with_authorization_revived_is_rejected,
//                                            engine_login_connect_session_flow_proceeds_over_loopback_fake
//   M2 cookie 值进证据（扫描失败）         -> cookie_value_never_enters_evidence
//   M3 SAML 时 saml_required=false         -> saml_required_is_never_false_when_saml
//   M4 login 失败仍 completed              -> login_failure_is_never_recorded_as_completed,
//                                            school_evidence_new_auth_fields_are_honest
//   M5 无 Authorization 断言在 fake 侧     -> aligned_fake_accepts (rejects any Authorization)

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use exv_vpn_cstp::codec::{Codec, CstpFrame};
use exv_vpn_cstp::connector::{BootstrapConfig, TrustPolicy};
use exv_vpn_cstp::session::CstpSession;
use exv_vpn_cstp::webvpn::{WebvpnLogin, build_connect_request};
use exv_vpn_win32_acceptance::evidence::SchoolScenarioEvidence;
use exv_vpn_win32_acceptance::scenarios::school::run_school_scenario;
use exv_vpn_win32_acceptance::wintun_facts::resolve_dll_path;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// 冻结契约常量（测试拥有；production `evidence.rs` / `scenarios/school.rs` /
// `scenarios/controlled.rs` 在 CS-AUTH-05-I 必须满足，不可漂移）。
// ---------------------------------------------------------------------------

/// `environment_state` 取值契约（计划 §6.1）：完整学校 flow 唯一值。
const ENV_STATE_COMPLETED: &str = "completed";
/// 环境无效标记前缀（后随精确 predicate）。
const ENV_INVALID_PREFIX: &str = "WIN_ACCEPTANCE_ENV_INVALID:";
/// 环境无效的另一合法标记。
const NOT_RUN_BLOCKED_PREFIX: &str = "not_run/blocked_by_environment";
/// login 成功时 `login_status` 的取值（计划 §5.1：`is_dynamic_complete` 的 login
/// obligation——`login_status == Some("webvpn-login-ok")`）。
const LOGIN_STATUS_OK: &str = "webvpn-login-ok";
/// SAML 要求的诚实 blocked 标记（计划 §6.3：MVP 不支持 SAML，如实标记，不冒充
/// 失败/成功）。
const SAML_BLOCKED_MARKER: &str = "school-saml-required";

/// 对齐后的 fake 应答的真实 Cisco 头式 offer（与 school.rs `REAL_CISCO_OFFER`
/// 同族：HTTP 包装头 + `X-CSTP-*` 必填字段 + 真实 gateway 额外字段）。
const FAKE_OFFER: &str = "HTTP/1.1 200 OK\r\n\
    Transfer-Encoding: chunked\r\n\
    X-CSTP-Server-Name: vpn.example.test\r\n\
    X-CSTP-Address: 10.1.0.2\r\n\
    X-CSTP-Netmask: 255.255.255.255\r\n\
    X-CSTP-MTU: 1406\r\n\
    X-CSTP-Lease-Duration: 28800\r\n\
    X-CSTP-Session-Id: 0123456789abcdef\r\n\
    X-CSTP-Split-Include: 0.0.0.0/0 172.16.0.0/12\r\n\
    X-CSTP-DNS: 10.1.0.1 10.1.0.2\r\n\
    \r\n";

/// 证据 JSON 中禁止出现的 raw secret/cookie/private key/certificate/group 标记
/// （独立于 production 自报的序列化扫描；扩展守卫到 cookie 值标记 `Set-Cookie` /
/// `webvpn=`——kills cookie 值进证据 mutant）。
const FORBIDDEN_EVIDENCE_MARKERS: [&str; 9] = [
    "PRIVATE KEY",
    "BEGIN CERTIFICATE",
    "Cookie:",
    "Set-Cookie",
    "webvpn=",
    "Authorization:",
    "password=",
    "group=",
    "username=",
];

// ---------------------------------------------------------------------------
// 嵌入测试 PKI（与 exv-vpn-cstp 测试同款确定性材料族：自签名 ECDSA P-256
// 证书，SAN DNS:vpn.example.test；自身即信任根。本文件自行内嵌——不复用/不
// 移动任何冻结测试文件的私有常量）。
// ---------------------------------------------------------------------------

const VPN_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBqTCCAU6gAwIBAgIUCz2E6EXN/6S3gIxuRBEAK/doSI8wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQdnBuLmV4YW1wbGUudGVzdDAeFw0yNjA4MTIyMDQxNTBaFw0z
NjA4MDkyMDQxNTBaMBsxGTAXBgNVBAMMEHZwbi5leGFtcGxlLnRlc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ621WzgT+Rp6MR+st4LY1gxps9HzBSlIIFbbHW
M3PjUe5vJXzSuEaBQ+t6kBsHEc9FoX5oPA6ivQ7eryJYMrL4o3AwbjAdBgNVHQ4E
FgQU0IZcqxbwuE5X5GGdjRl/4XLJEqkwHwYDVR0jBBgwFoAU0IZcqxbwuE5X5GGd
jRl/4XLJEqkwDwYDVR0TAQH/BAUwAwEB/zAbBgNVHREEFDASghB2cG4uZXhhbXBs
ZS50ZXN0MAoGCCqGSM49BAMCA0kAMEYCIQDQ+3+bij4pa2x1Z5ErL29zX1aXHRE/
8j8r2YsJ2fkeegIhAOBH6bDzde1JgeRR/IuiTm29PrNb3DbM7ksLb5mNTzUt
-----END CERTIFICATE-----
"#;

const VPN_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn1Ra5jnCNjCWeCfF
x0h7BnT9tvnlrqAdc+0xZphBfZWhRANCAAQ621WzgT+Rp6MR+st4LY1gxps9HzBS
lIIFbbHWM3PjUe5vJXzSuEaBQ+t6kBsHEc9FoX5oPA6ivQ7eryJYMrL4
-----END PRIVATE KEY-----
"#;

/// 嵌入的服务器私钥（`PrivateKeyDer` 不实现 `Clone`——需要第二份时重新解析 PEM）。
fn material_key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(VPN_KEY_PEM.as_bytes()).expect("parse embedded PEM private key")
}

fn material() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    (
        CertificateDer::from_pem_slice(VPN_CERT_PEM.as_bytes())
            .expect("parse embedded PEM certificate"),
        material_key(),
    )
}

/// 只信任 `cert` 的根存储（注入测试根）。
fn root_store_with(cert: &CertificateDer<'static>) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("add injected test root");
    roots
}

// ---------------------------------------------------------------------------
// 对齐后的 Cisco fake 判定（CS-AUTH-05 契约；kills 手搓 CONNECT 复活 +
// 无 Authorization 断言在 fake 侧）。
//
// CS-AUTH-05-I 必须把 `controlled.rs::is_cisco_cstp_connect_request` 对齐到本
// 判定：接受引擎 CONNECT 形状（计划 §3.2 逐字块——`CONNECT /CSCOSSLC/tunnel
// HTTP/1.1` + `Host:` + `Cookie: webvpn=` + `X-CSTP-Version: 1` +
// `X-CSTP-Hostname:` + `X-CSTP-Protocol:` shibboleth，空行终结；无
// `Authorization`、无 `X-AnyConnect-*`），拒绝任何 Authorization 复活。fake 与
// 真实 behave alike：格式不被识别即关闭连接、不答 offer。
// ---------------------------------------------------------------------------

fn aligned_fake_accepts(req: &[u8]) -> bool {
    let text = String::from_utf8_lossy(req);
    let mut lines = text.split("\r\n");
    let Some(first) = lines.next() else {
        return false;
    };
    let mut parts = first.split_whitespace();
    let (verb, target, version) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    if verb != "CONNECT" || target != "/CSCOSSLC/tunnel" || version != "HTTP/1.1" {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    lower.contains("\r\nhost:")
        && lower.contains("\r\ncookie: webvpn=")
        && lower.contains("\r\nx-cstp-version: 1")
        && lower.contains("\r\nx-cstp-hostname:")
        && lower.contains("\r\nx-cstp-protocol:")
        && !lower.contains("authorization:")
        && !lower.contains("x-anyconnect-")
        && text.ends_with("\r\n\r\n")
}

// ---------------------------------------------------------------------------
// loopback fake gateway（webvpn_login.rs 模式，适配到 acceptance crate）：
// login server（`POST /+CSCOE+/logon` -> `Set-Cookie: webvpn=<value>`）+
// connect server（对齐判定 -> offer -> DATA 回显循环）。
// ---------------------------------------------------------------------------

/// fake connect server 从客户端观测到的 CONNECT 请求。
struct CapturedConnect {
    /// 请求是否通过对齐后的 Cisco 判定。
    accepted: bool,
    /// 原始请求字节（`\r\n\r\n` 终结前）。
    request: Vec<u8>,
}

/// 运行 loopback TLS login gateway：服务 `POST /+CSCOE+/logon`，应答
/// `Set-Cookie: webvpn=<cookie>`（成功登录）。返回 gateway 地址。
async fn run_login_server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    cookie: &'static str,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind login server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let (tcp, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => return,
        };
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("build login server config");
        let acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_cfg)));
        let Ok(mut stream) = acceptor.accept(tcp).await else {
            return; // 客户端在握手期拒绝——接下一个。
        };
        // 消费 login POST（head + body）。
        let mut request = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    request.extend_from_slice(&buf[..n]);
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if request.len() > 8192 {
                        break;
                    }
                }
            }
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: webvpn={cookie}; path=/; secure\r\n\r\n"
        );
        let _ = stream.write_all(response.as_bytes()).await;
    });
    addr
}

/// 运行 loopback TLS connect gateway：读 CONNECT 请求 -> 对齐判定 -> 被接受则写
/// offer（`\r\n\r\n` 终结）并进入 DATA 回显循环（解码 Data 帧原样写回）；被拒则
/// 关闭连接不答 offer（client 读到 EOF——与真实 gateway 行为对齐）。
async fn run_connect_server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (SocketAddr, oneshot::Receiver<CapturedConnect>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind connect server");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => {
                let _ = tx.send(CapturedConnect {
                    accepted: false,
                    request: Vec::new(),
                });
                return;
            }
        };
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("build connect server config");
        let acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_cfg)));
        let Ok(mut stream) = acceptor.accept(tcp).await else {
            let _ = tx.send(CapturedConnect {
                accepted: false,
                request: Vec::new(),
            });
            return;
        };
        // 读 CONNECT 请求（`\r\n\r\n` 终结；上限防失控）。
        let mut request = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    request.extend_from_slice(&buf[..n]);
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                    if request.len() > 4096 {
                        break;
                    }
                }
            }
        }
        let accepted = aligned_fake_accepts(&request);
        let _ = tx.send(CapturedConnect {
            accepted,
            request: request.clone(),
        });
        if !accepted {
            return; // fake 拒绝：不答 offer（client 读到 EOF，失败可见）。
        }
        // 写 offer（`\r\n\r\n` 终结）。
        if stream.write_all(FAKE_OFFER.as_bytes()).await.is_err() {
            return;
        }
        // DATA 回显循环：解码收到的 Data 帧并原样写回（session flow 双向证明）。
        let mut codec = Codec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    codec.feed(&chunk[..n]);
                    loop {
                        match codec.decode() {
                            Ok(Some(CstpFrame::Data(payload))) => {
                                let Ok(echo) = Codec::new().encode(&CstpFrame::Data(payload))
                                else {
                                    return;
                                };
                                if stream.write_all(&echo).await.is_err() {
                                    return;
                                }
                            }
                            Ok(Some(CstpFrame::Control { .. })) => {}
                            Ok(None) => break,
                            Err(_) => return,
                        }
                    }
                }
            }
        }
    });
    (addr, rx)
}

// ---------------------------------------------------------------------------
// 机制测试（非 elevated；loopback fake gateway 驱动已提交的引擎）。
// ---------------------------------------------------------------------------

/// 引擎 CONNECT 请求形状 vs 对齐后的 Cisco fake 判定：`build_connect_request`
/// 必须产出计划 §3.2 的逐字字节（`CONNECT /CSCOSSLC/tunnel HTTP/1.1`、`Host`、
/// `Cookie: webvpn=<value>`、`X-CSTP-Version: 1`、`X-CSTP-Hostname`、
/// `X-CSTP-Protocol` shibboleth，空行终结；**无 Authorization**、**无
/// `X-AnyConnect-*`**）；对齐后的 fake 必须接受该形状；cookie 值绝不进入任何
/// Debug/证据面（kills cookie 值进证据 + 无 Authorization 断言在 fake 侧）。
#[tokio::test]
async fn engine_connect_request_matches_cisco_fake_shape() {
    let (cert, key) = material();
    let login_addr = run_login_server(cert.clone(), key, "wiring-cookie-7f3k").await;
    let login = WebvpnLogin::perform_login(
        "vpn.example.test",
        login_addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"p@ss",
    )
    .await
    .expect("fake gateway accepts the login POST");

    let request = build_connect_request("vpn.example.test", &login);
    assert!(
        request.ends_with(b"\r\n\r\n"),
        "CONNECT 请求必须以空行终结"
    );
    let head_text = String::from_utf8_lossy(&request);
    let lines: Vec<&str> = head_text.split("\r\n").collect();
    assert_eq!(
        lines[0], "CONNECT /CSCOSSLC/tunnel HTTP/1.1",
        "CONNECT 目标必须是 /CSCOSSLC/tunnel（不是裸 CONNECT <host>）"
    );
    assert!(
        lines.iter().any(|l| *l == "Host: vpn.example.test"),
        "必须携带 Host 头"
    );
    assert!(
        lines.iter().any(|l| *l == "Cookie: webvpn=wiring-cookie-7f3k"),
        "webvpn cookie 值必须原样进入 CONNECT 请求（会话凭据）"
    );
    assert!(
        lines.iter().any(|l| *l == "X-CSTP-Version: 1"),
        "必须携带 X-CSTP-Version: 1"
    );
    assert!(
        lines.iter().any(|l| *l == "X-CSTP-Hostname: vpn.example.test"),
        "必须携带 X-CSTP-Hostname"
    );
    assert!(
        lines.iter().any(|l| *l == "X-CSTP-Protocol: \"Copyright (c) 2004 Cisco Systems, Inc.\""),
        "必须携带 X-CSTP-Protocol shibboleth 头"
    );
    let lower = head_text.to_ascii_lowercase();
    assert!(
        !lower.contains("authorization"),
        "CONNECT 不得携带 Authorization（webvpn cookie 是认证凭据）"
    );
    assert!(
        !lower.contains("x-anyconnect-"),
        "桌面客户端 CONNECT 不得携带 X-AnyConnect-* 头"
    );
    // 对齐：post-alignment fake 判定必须接受引擎请求形状。
    assert!(
        aligned_fake_accepts(&request),
        "引擎 CONNECT 形状必须被对齐后的 Cisco fake 接受"
    );
    // cookie 值绝不出现在任何 Debug/证据面。
    let login_debug = format!("{login:?}");
    assert!(
        !login_debug.contains("wiring-cookie-7f3k"),
        "LoginSession Debug 不得泄漏 cookie 值"
    );
    let cookie_debug = format!("{:?}", login.cookie);
    assert!(
        !cookie_debug.contains("wiring-cookie-7f3k"),
        "WebvpnCookie Debug 必须脱敏"
    );
}

/// 手搓 CONNECT 复活（school.rs 旧格式）必须被对齐后的 fake 拒绝：旧格式
/// `CONNECT <host>` + `X-AnyConnect-*` + `Authorization: Basic` 曾在真实 gateway
/// 被拒；即使在正确路径 `/CSCOSSLC/tunnel` 上复活 `Authorization` 也必须被拒
/// （kills 手搓 CONNECT 复活 + 无 Authorization 断言在 fake 侧 mutant）。
#[test]
fn hand_rolled_connect_with_authorization_revived_is_rejected() {
    let old_school_shape = b"CONNECT vpn.example.test HTTP/1.1\r\n\
        Host: vpn.example.test\r\n\
        X-AnyConnect-Platform: win\r\n\
        X-AnyConnect-Client-Version: 4.10.03153\r\n\
        X-AnyConnect-Device-Type: AnyConnect\r\n\
        X-AnyConnect-Device-Version: 1.0\r\n\
        Authorization: Basic Y29udHJvbGxlZDp0ZXN0\r\n\
        \r\n";
    assert!(
        !aligned_fake_accepts(old_school_shape),
        "旧的 CONNECT <host> + X-AnyConnect-* + Authorization: Basic 形状必须被拒绝"
    );

    let authorization_revival = b"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n\
        Host: vpn.example.test\r\n\
        Cookie: webvpn=any-value\r\n\
        X-CSTP-Version: 1\r\n\
        X-CSTP-Hostname: vpn.example.test\r\n\
        X-CSTP-Protocol: \"Copyright (c) 2004 Cisco Systems, Inc.\"\r\n\
        Authorization: Basic Y29udHJvbGxlZDp0ZXN0\r\n\
        \r\n";
    assert!(
        !aligned_fake_accepts(authorization_revival),
        "Authorization 复活必须被 fake 拒绝"
    );

    // 基线：引擎完整形状必须被接受（对齐目标）。
    let engine_shape = b"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n\
        Host: vpn.example.test\r\n\
        Cookie: webvpn=wiring-cookie-7f3k\r\n\
        X-CSTP-Version: 1\r\n\
        X-CSTP-Hostname: vpn.example.test\r\n\
        X-CSTP-Protocol: \"Copyright (c) 2004 Cisco Systems, Inc.\"\r\n\
        \r\n";
    assert!(
        aligned_fake_accepts(engine_shape),
        "引擎 CONNECT 形状必须被接受"
    );
}

/// 引擎全链（login -> CONNECT -> offer -> DATA 双向）经 loopback fake gateway
/// 真实前进：`WebvpnLogin::perform_login` 成功捕获 cookie ->
/// `CstpSession::open`（对齐判定接受引擎 CONNECT）-> `TunnelOffer` 校验 -> data
/// 通道双向（写 Data 帧被 fake 回显）。login 成功即 `cookie_present` 语义的机制
/// 面（证据面见 evidence 测试）。
#[tokio::test]
async fn engine_login_connect_session_flow_proceeds_over_loopback_fake() {
    let (cert, key) = material();
    // `PrivateKeyDer` 不实现 Clone：login server 与 connect server 各持一份
    // 重新解析的私钥（同一确定性材料）。
    let login_addr = run_login_server(cert.clone(), material_key(), "wiring-cookie-7f3k").await;
    let (connect_addr, captured) = run_connect_server(cert.clone(), key).await;

    let login = WebvpnLogin::perform_login(
        "vpn.example.test",
        login_addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"p@ss",
    )
    .await
    .expect("login 成功");

    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: connect_addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };
    let mut session = CstpSession::open(cfg, Some(&login))
        .await
        .expect("对齐后的 fake 必须接受引擎 CONNECT 并完成会话");

    let observed = captured.await.expect("fake 观测到 CONNECT 请求");
    assert!(
        observed.accepted,
        "引擎 CONNECT 必须被对齐后的 fake 接受"
    );
    let observed_head = String::from_utf8_lossy(&observed.request);
    assert!(
        observed_head.starts_with("CONNECT /CSCOSSLC/tunnel HTTP/1.1"),
        "fake 侧必须观测到引擎 CONNECT 形状"
    );
    assert!(
        !observed_head.to_ascii_lowercase().contains("authorization"),
        "fake 侧必须无 Authorization（无 Authorization 断言在 fake 侧）"
    );

    // offer plan 解析（引擎 TunnelOffer）。
    assert_eq!(session.offer_plan.ipv4_address, Ipv4Addr::new(10, 1, 0, 2));
    assert_eq!(session.offer_plan.prefix, 32);
    assert_eq!(session.offer_plan.mtu, 1406);
    assert_eq!(
        session.offer_plan.dns_servers,
        vec![Ipv4Addr::new(10, 1, 0, 1), Ipv4Addr::new(10, 1, 0, 2)]
    );
    assert_eq!(
        session.offer_plan.routes,
        vec!["0.0.0.0/0".to_string(), "172.16.0.0/12".to_string()]
    );
    assert!(
        session.peer_fingerprint.is_some(),
        "会话必须记录对端证书 SHA-256 指纹（非 raw 证书）"
    );

    // data 通道双向：写 Data 帧 -> fake 回显 -> read_channel 收到（session flow
    // 前进，不是只到 offer 为止）。
    let frame = Codec::new()
        .encode(&CstpFrame::Data(vec![0x45, 0x00, 0x00, 0x01]))
        .expect("encode data frame");
    session
        .write_channel
        .send(frame)
        .expect("write channel 接受帧");
    let echoed = tokio::time::timeout(Duration::from_secs(5), session.read_channel.recv())
        .await
        .expect("回显帧必须在超时内到达")
        .expect("data 通道不得提前关闭");
    assert_eq!(
        echoed,
        vec![0x45, 0x00, 0x00, 0x01],
        "DATA 帧必须原样回显（双向 flow）"
    );
}

// ---------------------------------------------------------------------------
// school scenario 证据（elevation-gated，school_scenario.rs require_admin
// pattern）：新字段 `login_status` / `saml_required` / `cookie_present` 必须存在
// 且诚实。以下测试在 CS-AUTH-05-I 落地前以编译错误形式 RED。
// ---------------------------------------------------------------------------

/// 学校 flow 只跑一次，各项证据断言共享同一份观测（确定性；不向证据目录发布——
/// 证据发布是 `school_scenario` oracle 的职责，本 wiring 测试不覆盖其输出）。
fn school() -> &'static SchoolScenarioEvidence {
    static EVIDENCE: OnceLock<SchoolScenarioEvidence> = OnceLock::new();
    EVIDENCE.get_or_init(|| {
        let dll = resolve_dll_path(None);
        run_school_scenario(&dll)
    })
}

/// elevation/学校服务/完整性门禁（require_admin pattern）：环境有效（elevated 且
/// 学校服务可达且动态事实完整）返回 `true`；否则验证环境无效标记的诚实性并返回
/// `false`（not_run，不伪造——新认证字段不得在 not_run 状态下自报成功）。
fn school_env_complete_or_honest_not_run(ev: &SchoolScenarioEvidence) -> bool {
    if ev.env_elevated && ev.school_service_available && ev.is_dynamic_complete() {
        assert_eq!(
            ev.environment_state, ENV_STATE_COMPLETED,
            "完整学校 flow 必须标记 environment_state=completed"
        );
        true
    } else {
        assert!(
            ev.environment_state.starts_with(ENV_INVALID_PREFIX)
                || ev.environment_state.starts_with(NOT_RUN_BLOCKED_PREFIX),
            "环境无效必须产生 {ENV_INVALID_PREFIX}<predicate> 或 {NOT_RUN_BLOCKED_PREFIX}:<predicate>（不得冒充 RED/GREEN），got {:?}",
            ev.environment_state
        );
        // not_run：新认证字段的诚实一致性（不伪造）。
        if ev.cookie_present {
            assert_eq!(
                ev.login_status.as_deref(),
                Some(LOGIN_STATUS_OK),
                "cookie_present=true 必须伴随 login 成功"
            );
        }
        if ev.saml_required {
            assert_ne!(
                ev.login_status.as_deref(),
                Some(LOGIN_STATUS_OK),
                "SAML 要求不得记录为 login 成功"
            );
        }
        false
    }
}

/// login 失败绝不得标记 completed（kills login 失败仍 completed mutant）：
/// `login_status` 失败态或 `school_data_connection_error` 的 `login:` 前缀必须
/// 伴随非 completed 状态、非完整动态事实、无 cookie_present。
#[test]
fn login_failure_is_never_recorded_as_completed() {
    let ev = school();
    let login_failed = ev
        .login_status
        .as_deref()
        .is_some_and(|s| s != LOGIN_STATUS_OK);
    let login_error_recorded = ev
        .school_data_connection_error
        .as_deref()
        .is_some_and(|e| e.starts_with("login:"));
    if login_failed || login_error_recorded {
        assert_ne!(
            ev.environment_state, ENV_STATE_COMPLETED,
            "login 失败时不得标记 completed"
        );
        assert!(
            !ev.is_dynamic_complete(),
            "login 失败时动态事实不得完整"
        );
        assert!(
            !ev.cookie_present,
            "login 失败时不得声称 cookie_present"
        );
    }
    if login_error_recorded {
        assert!(
            login_failed,
            "school_data_connection_error=login:<..> 必须伴随 login_status 失败态"
        );
    }
}

/// SAML 要求时 `saml_required` 绝不为 false（kills SAML 时 saml_required=false
/// mutant）：`saml_required=true` 不得与 login 成功/完成并存，且必须诚实标记
/// `not_run/blocked_by_environment:school-saml-required`（计划 §6.3——MVP 不支持
/// SAML，如实标记，不冒充失败/成功）；反向：blocked 标记出现则 `saml_required`
/// 必须为 true。
#[test]
fn saml_required_is_never_false_when_saml() {
    let ev = school();
    if ev.saml_required {
        assert_ne!(
            ev.login_status.as_deref(),
            Some(LOGIN_STATUS_OK),
            "SAML 要求不得记录为 login 成功"
        );
        assert!(
            !ev.cookie_present,
            "SAML 要求时不得声称 cookie_present"
        );
        assert_ne!(
            ev.environment_state, ENV_STATE_COMPLETED,
            "SAML 要求时不得标记 completed"
        );
        assert!(
            ev.environment_state.contains(SAML_BLOCKED_MARKER),
            "SAML 要求必须诚实标记 not_run/blocked_by_environment:school-saml-required，got {:?}",
            ev.environment_state
        );
    }
    if ev.environment_state.contains(SAML_BLOCKED_MARKER) {
        assert!(
            ev.saml_required,
            "school-saml-required 标记必须伴随 saml_required=true"
        );
    }
}

/// login 成功 -> `cookie_present=true`：引擎登录成功（`login_status` =
/// "webvpn-login-ok"）必须伴随 `cookie_present=true`（webvpn cookie 是 CONNECT
/// 凭据）；反向：`cookie_present=true` 必须伴随 login 成功。
#[test]
fn login_success_records_cookie_present() {
    let ev = school();
    if ev.login_status.as_deref() == Some(LOGIN_STATUS_OK) {
        assert!(
            ev.cookie_present,
            "login 成功必须 cookie_present=true（webvpn cookie 是 CONNECT 凭据）"
        );
        assert!(
            !ev.saml_required,
            "login 成功不得 saml_required"
        );
    }
    if ev.cookie_present {
        assert_eq!(
            ev.login_status.as_deref(),
            Some(LOGIN_STATUS_OK),
            "cookie_present=true 必须伴随 login 成功"
        );
    }
}

/// cookie 值绝不进入证据（kills cookie 值进证据 mutant）：`scan_evidence` 的
/// `"Cookie:"` 守卫必须在新增 `login_status` / `saml_required` / `cookie_present`
/// 字段后仍通过；独立于 production 自报的第二次序列化扫描把守卫扩展到
/// `Set-Cookie` / `webvpn=` 值标记。
#[test]
fn cookie_value_never_enters_evidence() {
    let ev = school();
    assert!(
        ev.no_raw_secret_in_evidence,
        "scan_evidence 守卫必须在新字段（login_status/saml_required/cookie_present）下仍通过"
    );
    let json = serde_json::to_string(ev).unwrap_or_else(|e| format!("evidence-serialize-error:{e}"));
    for marker in FORBIDDEN_EVIDENCE_MARKERS {
        assert!(
            !json.contains(marker),
            "school evidence JSON 不得包含 {marker:?}"
        );
    }
}

/// school scenario 证据的新字段存在且诚实：`is_dynamic_complete` 必须以 login 成功
/// 为前提（kills login 失败仍 completed mutant——完整 flow 必须记录
/// `login_status=webvpn-login-ok`）；完成态下三态字段齐全（cookie_present=true、
/// saml_required=false）、无连接错误残留、offer 只记 SHA-256 digest。
#[test]
fn school_evidence_new_auth_fields_are_honest() {
    let ev = school();
    // is_dynamic_complete 的 login obligation（计划 §5.1）：完整动态事实必须以
    // login 成功为前提。
    if ev.is_dynamic_complete() {
        assert_eq!(
            ev.login_status.as_deref(),
            Some(LOGIN_STATUS_OK),
            "is_dynamic_complete 必须以 login 成功为前提（login 失败仍 completed 的 mutant）"
        );
    }
    if !school_env_complete_or_honest_not_run(ev) {
        return; // not_run / blocked_by_environment
    }
    // 完成态：引擎登录三态证据齐全且诚实。
    assert_eq!(
        ev.login_status.as_deref(),
        Some(LOGIN_STATUS_OK),
        "完成态必须记录 login_status=webvpn-login-ok"
    );
    assert!(
        ev.cookie_present,
        "完成态必须 cookie_present=true"
    );
    assert!(
        !ev.saml_required,
        "完成态不得 saml_required"
    );
    assert!(
        ev.school_data_connection_error.is_none(),
        "完成态不得残留 school_data_connection_error"
    );
    assert!(
        ev.school_offer_digest
            .as_deref()
            .is_some_and(|d| d.len() == 64),
        "完成态必须记录 offer SHA-256 digest（非 raw offer）"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
