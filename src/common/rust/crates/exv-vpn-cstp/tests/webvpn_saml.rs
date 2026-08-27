// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV CS-AUTH-04-T: SAML detection in the WebVPN login phase. Integration tests
// for exv-vpn-cstp, pinning the SAML branches of the CS-AUTH-01 API
// `exv_vpn_cstp::webvpn::{WebvpnLogin, LoginSession, LoginError}` (driven through
// the same loopback TLS fake gateway pattern as tests/webvpn_login.rs — the
// two-step measured flow: GET `/+CSCOE+/logon.html` -> POST the form ACTION
// `/+webvpn+/index.html` — with the embedded test PKI copied in per the plan
// rule — frozen tls_bootstrap.rs constants are never reused or moved).
//
// The SAML branches live in the RESPONSE handling of `WebvpnLogin::perform_login`
// (plan §3.1, openconnect auth.c handle_saml_redirect()):
//
//   * The credential POST is answered with a 302 + `Location` containing the
//     marker `+CSCOE+/saml` -> the login is steered to a SAML identity
//     provider: `Err(LoginError::SamlRequired)`. A redirect is NEVER login
//     success, even when the response also carries a webvpn cookie, and the
//     client NEVER follows it (exactly one GET + one POST is observed on the
//     wire).
//   * Body variant: a 200 page whose `<meta http-equiv="refresh">` steers to
//     the SAML ACS (same `+CSCOE+/saml` marker in the target URL) -> likewise
//     `Err(LoginError::SamlRequired)`. An HTML page is NEVER login success,
//     even when it also carries a webvpn cookie.
//   * Plain 200 + `Set-Cookie: webvpn=` -> `Ok(LoginSession)` with
//     `saml_detected == false`.
//   * Non-SAML redirects and gateway error pages stay typed errors
//     (`LoginRejected`), never success and never `SamlRequired`.
//
// `saml_detected` is observable only on the Ok path, so the plan §3.1 contract
// ("`saml_detected=true` + `LoginError::SamlRequired`") is pinned as: the Ok
// path must carry `saml_detected == false` for plain form logins, and every
// detection path must return `Err(LoginError::SamlRequired)` — a mutant that
// fabricates an Ok session out of a redirect/HTML page (with `saml_detected`
// true or false) fails these tests.
//
// Mutants this suite must kill (plan leaf CS-AUTH-04 row):
//   M1 SAML redirect treated as login success (login_status=ok)
//       -> saml_302_redirect_is_saml_required_never_success,
//          saml_302_with_webvpn_cookie_still_not_success
//   M2 the redirect is followed and the final page treated as success
//       -> saml_302_redirect_is_saml_required_never_success (the client must
//          not issue any THIRD connection: exactly the GET on connection #1
//          and the credential POST on connection #2 are observed — a
//          follow-the-redirect mutant needs a third connection this server
//          never accepts)
//   M3 HTTP 302 without a webvpn cookie still returns Ok
//       -> non_saml_302_is_typed_error_not_success
//   M4 an HTML page (meta-refresh to ACS / error page) treated as success
//       -> meta_refresh_html_page_never_treated_as_login_success,
//          meta_refresh_to_acs_is_saml_required
//   M5 SAML over-reach: a plain error page mis-classified as SamlRequired
//       -> html_login_error_page_is_login_rejected_not_saml_required

use exv_vpn_cstp::connector::TrustPolicy;
use exv_vpn_cstp::webvpn::{LoginError, LoginSession, WebvpnLogin};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncRead;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Embedded test PKI. The same deterministic material family as the P41-T suite
// (self-signed ECDSA P-256 leaf certs that are their own roots) is embedded
// HERE per the plan's rule — the frozen tls_bootstrap.rs private constants are
// never reused or moved, and an integration-test crate cannot import the
// constants of another test crate:
//   VPN_CERT  -> SAN DNS:vpn.example.test   (the fake login gateway)
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

fn parse_cert(pem: &str) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem.as_bytes()).expect("parse embedded PEM certificate")
}

fn parse_key(pem: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).expect("parse embedded PEM private key")
}

/// The fake login-gateway material: a self-signed cert for `vpn.example.test`.
fn vpn_material() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    (parse_cert(VPN_CERT_PEM), parse_key(VPN_KEY_PEM))
}

/// A root store that trusts exactly `cert` (used as an injected test root).
fn root_store_with(cert: &CertificateDer<'static>) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("add injected test root");
    roots
}

/// The byte offset just past the `\r\n\r\n` header terminator, if present.
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

// ---------------------------------------------------------------------------
// The fake login gateway (loopback TLS server with the embedded cert).
// ---------------------------------------------------------------------------

/// What the fake login gateway observes from the client.
struct CapturedLogin {
    /// The SNI the client sent (None if the handshake never completed).
    sni: Option<String>,
    /// The raw GET `/+CSCOE+/logon.html` request head bytes.
    get_request: Vec<u8>,
    /// The csrf_token embedded in the served logon.html form (dynamic per
    /// request), so tests can assert the client echoes it into the POST.
    csrf_token: String,
    /// The raw credential POST request bytes (head plus the declared form
    /// body; the ONLY request on the fresh connection #2 — the SAML redirect
    /// must never be followed).
    post_request: Vec<u8>,
}

/// The counter backing the dynamic csrf_token (measured gateway: the token
/// changes on every GET of logon.html).
static CSRF_TOKEN_COUNTER: AtomicU64 = AtomicU64::new(0x7788_a917_b493_948c);

/// Build the measured-shape logon.html form (vpn-ct.ecnu.edu.cn, 2026-08-15:
/// hidden tgroup/next/tgcookieset/csrf_token fields, action
/// `/+webvpn+/index.html`) and return it together with the csrf_token it
/// embeds.
fn logon_html() -> (String, String) {
    let n = CSRF_TOKEN_COUNTER.fetch_add(1, Ordering::SeqCst);
    let csrf_token = format!("{n:032x}");
    let html = format!(
        "<html><head><script>document.location.replace(\"/+CSCOE+/logon.html\");</script></head>\n\
         <body><form action=\"/+webvpn+/index.html\" method=\"post\">\n\
         <input type=\"hidden\" name=\"tgroup\" value=\"\"/>\n\
         <input type=\"hidden\" name=\"next\" value=\"\"/>\n\
         <input type=\"hidden\" name=\"tgcookieset\" value=\"\"/>\n\
         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_token}\"/>\n\
         <input type=\"text\" name=\"username\"/>\n\
         <input type=\"password\" name=\"password\"/>\n\
         <input type=\"submit\" name=\"Login\" value=\"Logon\"/>\n\
         </form></body></html>"
    );
    (html, csrf_token)
}

/// Read an HTTP request head (up to `\r\n\r\n`; the logon GET has no body).
async fn read_request_head<R: AsyncRead + Unpin>(read: &mut R) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match tokio::io::AsyncReadExt::read(read, &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                request.extend_from_slice(&buf[..n]);
                if find_header_end(&request).is_some() || request.len() > 8192 {
                    break;
                }
            }
        }
    }
    request
}

/// Read an HTTP request head plus the Content-Length-declared body (never less
/// than the full form, so the shape assertions see the exact bytes).
async fn read_request_with_body<R: AsyncRead + Unpin>(read: &mut R) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buf = [0u8; 512];
    let mut expected_len: Option<usize> = None;
    loop {
        match tokio::io::AsyncReadExt::read(read, &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                request.extend_from_slice(&buf[..n]);
                if let Some(end) = find_header_end(&request) {
                    if expected_len.is_none() {
                        let head = String::from_utf8_lossy(&request[..end]);
                        expected_len = head
                            .lines()
                            .skip(1)
                            .find_map(|line| {
                                let (key, value) = line.split_once(':')?;
                                if key.trim().eq_ignore_ascii_case("content-length") {
                                    Some(value.trim().parse::<usize>().ok()?)
                                } else {
                                    None
                                }
                            });
                    }
                    let body_len = request.len().saturating_sub(end);
                    if expected_len.is_some_and(|want| body_len >= want) {
                        break;
                    }
                }
                if request.len() > 8192 {
                    break;
                }
            }
        }
    }
    request
}

/// The configurable response the fake login gateway serves for the credential
/// POST (the second exchange of the two-step flow).
enum LoginReply {
    /// `HTTP/1.1 302` with exactly this `Location`, plus optional `Set-Cookie`
    /// headers (SAML steering / non-SAML redirect variants).
    Redirect {
        location: &'static str,
        cookies: &'static [&'static str],
    },
    /// `HTTP/1.1 200` with this HTML body, plus optional `Set-Cookie` headers
    /// (meta-refresh-to-ACS steering page / gateway error page variants).
    OkPage {
        body: &'static str,
        cookies: &'static [&'static str],
    },
    /// `HTTP/1.1 200` with exactly these `Set-Cookie` headers and an empty body
    /// (the plain form-login success variant).
    OkCookies(&'static [&'static str]),
}

/// Run a real local TLS login gateway (loopback) that serves the two-step
/// measured flow — GET `/+CSCOE+/logon.html` (standard form, dynamic
/// csrf_token) on connection #1 (served WITHOUT Content-Length/Transfer-
/// Encoding, and the connection then CLOSED: the measured implicit-close
/// transport), then the configured `reply` for the credential POST on a FRESH
/// connection #2 (served chunked: the measured POST transport) — and report
/// the captured requests. The client (under test) connects with
/// `TrustPolicy::TestRoots` so the TLS handshake is verified for real.
async fn run_login_server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    reply: LoginReply,
) -> (SocketAddr, oneshot::Receiver<CapturedLogin>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind login server");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("build server config from embedded cert");
        let acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_cfg)));
        let (logon_html, csrf_token) = logon_html();
        let mut get_request: Vec<u8> = Vec::new();
        // Connection #1: the aggregate-auth XML channel probe (`POST /` with
        // config-auth XML + X-Aggregate-Auth) — the PRIMARY channel, which a
        // FORM-ONLY gateway answers 404 (the measured "XML channel disabled"
        // signature), sending the login to the form flow. A client that skips
        // the XML channel sends the logon GET here instead.
        let (tcp, _peer) = listener.accept().await.expect("accept login connection");
        let stream = acceptor
            .accept(tcp)
            .await
            .expect("complete the TLS handshake");
        let sni = stream.get_ref().1.server_name().map(|s| s.to_string());
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let first_request = read_request_head(&mut read_half).await;
        let first_head = String::from_utf8_lossy(&first_request);
        let is_xml_probe = first_head.starts_with("POST / HTTP/1.1")
            && first_head.to_ascii_lowercase().contains("application/xml");
        if is_xml_probe {
            let out = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
            drop(write_half);
            drop(read_half);
            // Connection #2: the client GETs /+CSCOE+/logon.html after the
            // XML-channel 404. The gateway serves the logon form with a
            // PER-REQUEST dynamic csrf_token (measured), delimited by the
            // CONNECTION CLOSE — no Content-Length, no Transfer-Encoding —
            // and then closes the connection (the measured implicit-close
            // transport). The credential POST therefore MUST come on a new
            // connection.
            let (tcp, _peer) = listener.accept().await.expect("accept GET connection");
            let stream = acceptor
                .accept(tcp)
                .await
                .expect("complete the GET TLS handshake");
            let (mut read_half, mut write_half) = tokio::io::split(stream);
            get_request = read_request_head(&mut read_half).await;
            let out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nKeep-Alive: timeout=5, max=100\r\nConnection: keep-alive\r\n\r\n{logon_html}"
            );
            let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
            drop(write_half);
            drop(read_half);
        } else {
            // The logon GET arrives on this connection: serve the logon form
            // (dynamic csrf_token) delimited by the CONNECTION CLOSE — no
            // Content-Length, no Transfer-Encoding — and then close the
            // connection (measured implicit-close transport). The credential
            // POST therefore MUST come on a new connection.
            get_request = first_request;
            let out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nKeep-Alive: timeout=5, max=100\r\nConnection: keep-alive\r\n\r\n{logon_html}"
            );
            let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
            drop(write_half);
            drop(read_half);
        }
        // Connection #2 (FRESH): the credential POST (head + declared body).
        // This is the ONLY request on this connection the client may ever send
        // — a mutant that follows the SAML redirect would need a THIRD
        // connection this server never accepts.
        let (tcp, _peer) = listener.accept().await.expect("accept POST connection");
        let stream = acceptor
            .accept(tcp)
            .await
            .expect("complete the POST TLS handshake");
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let post_request = read_request_with_body(&mut read_half).await;
        // The csrf_token is served once on connection #1; the POST must echo it
        // (a hardcoded / foreign token is a rejected login on the real gateway).
        let post_body =
            String::from_utf8_lossy(&post_request[find_header_end(&post_request).unwrap_or(0)..]);
        let token_matches = post_body
            .split("csrf_token=")
            .nth(1)
            .and_then(|t| t.split('&').next())
            .is_some_and(|echoed| echoed == csrf_token);
        let _ = tx.send(CapturedLogin {
            sni,
            get_request,
            csrf_token,
            post_request,
        });
        if !token_matches {
            let out = "HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
            return;
        }

        let mut out = String::new();
        match reply {
            LoginReply::Redirect { location, cookies } => {
                out.push_str("HTTP/1.1 302 Found\r\nLocation: ");
                out.push_str(location);
                for cookie in cookies {
                    out.push_str("\r\nSet-Cookie: ");
                    out.push_str(cookie);
                }
                out.push_str("\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
            }
            LoginReply::OkPage { body, cookies } => {
                out.push_str(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n",
                );
                for cookie in cookies {
                    out.push_str("Set-Cookie: ");
                    out.push_str(cookie);
                    out.push_str("\r\n");
                }
                out.push_str("\r\n");
                let chunk_size = format!("{:x}", body.len());
                out.push_str(&chunk_size);
                out.push_str("\r\n");
                out.push_str(body);
                out.push_str("\r\n0\r\n\r\n");
            }
            LoginReply::OkCookies(cookies) => {
                out.push_str("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n");
                for cookie in cookies {
                    out.push_str("Set-Cookie: ");
                    out.push_str(cookie);
                    out.push_str("\r\n");
                }
                out.push_str("\r\n0\r\n\r\n");
            }
        }
        let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
    });
    (addr, rx)
}

// ---------------------------------------------------------------------------
// The 7 fixed tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn saml_302_redirect_is_saml_required_never_success() {
    // A 302 whose Location carries the Cisco SAML marker `+CSCOE+/saml`
    // (openconnect auth.c handle_saml_redirect()) is a SAML steering redirect:
    // it must surface as `Err(LoginError::SamlRequired)` — NEVER as login
    // success (kills M1), and the client must NOT follow it: exactly the GET
    // logon.html on connection #1 + the credential POST on connection #2 is
    // observed on the wire (kills M2 — a follow-the-redirect mutant needs a
    // THIRD connection this server never accepts).
    let (cert, key) = vpn_material();
    let (addr, captured) = run_login_server(
        cert.clone(),
        key,
        LoginReply::Redirect {
            location: "/+CSCOE+/saml/acs/start?token=abc123",
            cookies: &[],
        },
    )
    .await;

    let err = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"s3cret",
    )
    .await
    .expect_err("a SAML redirect must never be login success");

    assert!(
        matches!(err, LoginError::SamlRequired),
        "a SAML redirect surfaces as the typed SamlRequired"
    );

    let captured = captured.await.expect("the fake gateway observed the login");
    assert_eq!(
        captured.sni.as_deref(),
        Some("vpn.example.test"),
        "SNI must be the configured hostname"
    );
    let get_request = String::from_utf8_lossy(&captured.get_request);
    assert!(
        get_request.starts_with("GET /+CSCOE+/logon.html HTTP/1.1"),
        "exactly one logon-form GET is sent (the measured form endpoint)"
    );
    let post_request = String::from_utf8_lossy(&captured.post_request);
    let body = post_request.splitn(2, "\r\n\r\n").nth(1).unwrap_or_default();
    assert!(
        post_request.starts_with("POST /+webvpn+/index.html HTTP/1.1"),
        "exactly one credential POST to the form ACTION is sent; the SAML redirect is never followed"
    );
    assert!(
        body.contains(&format!("csrf_token={}", captured.csrf_token)),
        "the credential POST echoes the served csrf_token verbatim"
    );
}

#[tokio::test]
async fn saml_302_with_webvpn_cookie_still_not_success() {
    // Even when the SAML redirect response ALSO carries a `webvpn` cookie, it
    // must NOT be treated as a successful login: the redirect means the form
    // login was steered to SAML, whatever else the response contains (kills M1
    // hardening — a mutant that returns Ok whenever a cookie is present fails
    // here).
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LoginReply::Redirect {
            location: "/+CSCOE+/saml/start",
            cookies: &["webvpn=redirect-cookie-must-not-matter; path=/"],
        },
    )
    .await;

    let err = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"s3cret",
    )
    .await
    .expect_err("a SAML redirect carrying a webvpn cookie is still not login success");

    assert!(
        matches!(err, LoginError::SamlRequired),
        "SAML detection wins over cookie capture: still typed SamlRequired"
    );
}

#[tokio::test]
async fn meta_refresh_to_acs_is_saml_required() {
    // Body variant of handle_saml_redirect(): a 200 page whose meta-refresh
    // steers to the SAML ACS (target carries the same `+CSCOE+/saml` marker) is
    // a SAML steering page and must surface as `Err(LoginError::SamlRequired)` —
    // NOT as a protocol violation and NOT as success. This is the CS-AUTH-04-I
    // behavior the current CS-AUTH-01 code lacks: it must be RED until the body
    // check exists.
    const META_REFRESH_ACS: &str = "<html><head><meta http-equiv=\"refresh\" \
        content=\"0; url=https://vpn.example.test/+CSCOE+/saml/acs/start\">\
        </head><body>Redirecting to single sign-on...</body></html>";
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LoginReply::OkPage {
            body: META_REFRESH_ACS,
            cookies: &[],
        },
    )
    .await;

    let err = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"s3cret",
    )
    .await
    .expect_err("a meta-refresh steering page to the SAML ACS is never login success");

    assert!(
        matches!(err, LoginError::SamlRequired),
        "a meta-refresh to the ACS surfaces as the typed SamlRequired"
    );
}

#[tokio::test]
async fn meta_refresh_html_page_never_treated_as_login_success() {
    // The hardest mutant: the SAML steering HTML page ALSO carries a webvpn
    // cookie. The HTML page must NEVER be login success (plan §3.1 "绝不把重定向/
    // HTML 页当作登录成功"): SAML detection wins over cookie capture, and
    // `Err(LoginError::SamlRequired)` is returned. A mutant (or the current
    // CS-AUTH-01 code, which returns `Ok(LoginSession { saml_detected: false })`
    // for any 200 + cookie) that treats the page as success must fail here.
    const META_REFRESH_ACS: &str = "<html><head><meta http-equiv=\"refresh\" \
        content=\"0; url=https://vpn.example.test/+CSCOE+/saml/acs/start\">\
        </head><body>Redirecting to single sign-on...</body></html>";
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LoginReply::OkPage {
            body: META_REFRESH_ACS,
            cookies: &["webvpn=html-page-cookie-must-not-matter; path=/"],
        },
    )
    .await;

    let err = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"s3cret",
    )
    .await
    .expect_err("an HTML page is never login success, even when it carries a webvpn cookie");

    assert!(
        matches!(err, LoginError::SamlRequired),
        "a meta-refresh page with a cookie still surfaces as the typed SamlRequired"
    );
}

#[tokio::test]
async fn plain_200_with_cookie_is_saml_detected_false() {
    // A plain 200 + `Set-Cookie: webvpn=` is a REAL login success (CS-AUTH-01
    // behavior preserved): the session is Ok, the cookie is captured, and
    // `saml_detected` is false — the absence of a SAML steering response must
    // never flip the flag.
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LoginReply::OkCookies(&["webvpn=abc123xyz; path=/; secure"]),
    )
    .await;

    let login: LoginSession = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"s3cret",
    )
    .await
    .expect("a plain 200 + webvpn cookie is login success");

    assert_eq!(
        login.cookie.as_str(),
        "abc123xyz",
        "the webvpn cookie value is captured"
    );
    assert!(
        !login.saml_detected,
        "a plain form login is never a SAML login: saml_detected must be false"
    );
}

#[tokio::test]
async fn non_saml_302_is_typed_error_not_success() {
    // A 302 WITHOUT the `+CSCOE+/saml` marker is not SAML, and — with no webvpn
    // cookie — it must NEVER be `Ok` (kills M3: "HTTP 302 无 cookie 仍 Ok"). It
    // surfaces as the typed `LoginRejected`, not as `SamlRequired` (no SAML
    // marker, no SamlRequired).
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LoginReply::Redirect {
            location: "/+CSCOE+/logon?retry=1",
            cookies: &[],
        },
    )
    .await;

    let err = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"s3cret",
    )
    .await
    .expect_err("a 302 without a webvpn cookie must never be login success");

    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "a non-SAML 302 surfaces as the typed LoginRejected"
    );
}

#[tokio::test]
async fn html_login_error_page_is_login_rejected_not_saml_required() {
    // The gateway error page stays `LoginRejected` (CS-AUTH-01 behavior): SAML
    // detection must not over-reach and classify a plain error page as
    // `SamlRequired` (kills M5), and the page is never success.
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LoginReply::OkPage {
            body: "<html><body><a href=\"/+CSCOE+/error\">login failed</a></body></html>",
            cookies: &[],
        },
    )
    .await;

    let err = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"wrong-password",
    )
    .await
    .expect_err("a gateway error page is a rejected login");

    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "an error page surfaces as the typed LoginRejected, never SamlRequired"
    );
    let err_debug = format!("{err:?}");
    assert!(
        !err_debug.contains("wrong-password"),
        "LoginError Debug output must never leak the password"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
