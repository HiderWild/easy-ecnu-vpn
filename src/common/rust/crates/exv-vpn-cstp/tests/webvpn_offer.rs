// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV CS-AUTH-03-T: CSTP offer parsing alignment contract tests for
// exv-vpn-cstp.
//
// The engine's `CstpSession::open` (committed CS-AUTH-02 surface) reads the
// offer head up to its `\r\n\r\n` terminator and validates it into a
// `TunnelOffer` plan. These tests pin the plan §3.3 offer-validation semantics
// (engine version of the school `validate_school_offer`, school.rs L1334-1409,
// controlled alignment), driven end-to-end through the real loopback TLS
// gateway pattern: login -> CONNECT -> configurable offer body -> typed
// outcome. They are expected to be RED against the CS-AUTH-02 provisional
// parse wherever the alignment gap lives (currently: the legacy line-style
// branch — school splits `key value` on whitespace, the provisional engine
// parse only splits on `:`), and CS-AUTH-03-I must align `session.rs`
// `parse_offer` (the only production file this leaf may touch) until the
// whole matrix is GREEN.
//
// Contract (docs/superpowers/plans/2026-08-15-cstp-authentication-rebuild-plan.md
// leaf CS-AUTH-03, §3.3; openconnect cstp.c offer semantics):
//   * HTTP-header-style real offer — `HTTP/1.1 200` + `X-CSTP-Address` /
//     `X-CSTP-Netmask` / `X-CSTP-MTU` / `X-CSTP-DNS` (whitespace-separated) /
//     `X-CSTP-Split-Include` (whitespace-separated CIDR), plus the wrapper
//     headers `Transfer-Encoding: chunked`, `Session-Id`, `DPD`, `Keepalive` —
//     parses into `TunnelOffer { ipv4_address, prefix, mtu, dns_servers,
//     routes }`.
//   * Legacy line-style offer (`key value` on whitespace, the school-retained
//     legacy form) — parses into the SAME plan (controlled alignment
//     retained).
//   * Missing required field (`CSTP_NETMASK`, `CSTP_ADDRESS`, `CSTP_MTU`) is a
//     typed `SessionError::OfferParseFailed`, never a plan.
//   * Unknown `X-CSTP-*` / wrapper keys are ignored (real-gateway extra
//     fields); the offer still parses.
//   * Any `dtls` appearance (e.g. `X-CSTP-Protocol: dtls`) rejects the offer.
//   * HTML error pages (bare, or served under a 200 status) are rejected, NOT
//     parsed into a plan.
//   * HTTP error status (non-2xx) is rejected even when X-CSTP-* fields are
//     present.
//   * Contiguous netmask -> prefix length (0..=32); a non-contiguous mask is
//     rejected.
//
// Mutants this suite must kill (plan leaf row):
//   M1 HTML page parsed into a plan        -> html_error_page_*_rejected...
//   M2 DTLS offer accepted                 -> dtls_offer_is_rejected
//   M3 missing CSTP_NETMASK accepted       -> missing_required_offer_fields_are_rejected
// plus the alignment pin:
//   M4 legacy line style dropped/ignored   -> legacy_line_style_offer_parses_like_header_style
//     (the school `validate_school_offer` whitespace split branch must be
//     retained under control: the same plan as the header style)

use exv_vpn_cstp::connector::{BootstrapConfig, TrustPolicy};
use exv_vpn_cstp::session::{CstpSession, SessionError, TunnelOffer};
use exv_vpn_cstp::webvpn::{LoginSession, WebvpnLogin, build_connect_request};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::AsyncRead;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Embedded test PKI. Same deterministic material family as the CS-AUTH-01/02
// suites (self-signed ECDSA P-256 leaf cert that is its own root) is embedded
// HERE per the plan's rule — frozen constants are never reused or moved:
//   VPN_CERT -> SAN DNS:vpn.example.test (the "valid" gateway)
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

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn parse_cert(pem: &str) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem.as_bytes()).expect("parse embedded PEM certificate")
}

fn parse_key(pem: &str) -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).expect("parse embedded PEM private key")
}

/// The "valid" gateway material: a self-signed cert for `vpn.example.test`.
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
// The fake login gateway (minimal: serves the two-step measured login flow
// and exactly the webvpn cookie).
//
// `LoginSession` is only obtainable through the committed CS-AUTH-01
// `WebvpnLogin::perform_login` (the `WebvpnCookie` value is opaque and
// privately constructed), so every test that needs a login session runs a real
// loopback login first (GET logon.html -> POST the form ACTION).
// ---------------------------------------------------------------------------

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
/// than the full form, so the login POST completes before the response is
/// written).
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

/// Run a local TLS login gateway that serves the two-step measured flow — the
/// client's connections are dispatched by request: the aggregate-auth XML
/// channel probe (`POST /` + config-auth init XML) on the FIRST connection is
/// answered 404 (the measured "XML channel disabled" signature) so the login
/// falls back to the form flow, then `GET /+CSCOE+/logon.html` (standard form,
/// dynamic csrf_token; served WITHOUT Content-Length/Transfer-Encoding, and
/// the connection then CLOSED: the measured implicit-close transport), then
/// the credential POST on a FRESH connection — answered `200 OK` (chunked,
/// the measured POST transport) with exactly
/// `Set-Cookie: webvpn=<value>; path=/; secure`.
async fn run_login_ok_server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    cookie_value: &'static str,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind login server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("build server config from embedded cert");
        let acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_cfg)));
        let (logon_html, csrf_token) = logon_html();
        let mut served_logon = false;

        // Connection #1: the aggregate-auth XML channel probe (`POST /` with
        // config-auth XML + X-Aggregate-Auth) — the PRIMARY channel, which a
        // FORM-ONLY gateway answers 404 (the measured "XML channel disabled"
        // signature), sending the login to the form flow. A client that skips
        // the XML channel sends the logon GET here instead.
        let (tcp, _peer) = listener.accept().await.expect("login server accept");
        let stream = acceptor.accept(tcp).await.expect("login TLS accept");
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let first_request = read_request_head(&mut read_half).await;
        let first_head = String::from_utf8_lossy(&first_request);
        let is_xml_probe = first_head.starts_with("POST / HTTP/1.1")
            && first_head.to_ascii_lowercase().contains("application/xml");
        if is_xml_probe {
            let out = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
        } else {
            // The logon GET arrives on this connection: serve the measured
            // login form (dynamic csrf_token) delimited by the CONNECTION
            // CLOSE — no Content-Length, no Transfer-Encoding — and then
            // close the connection (measured implicit-close transport), so
            // the credential POST must come on a new connection.
            let out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nKeep-Alive: timeout=5, max=100\r\nConnection: keep-alive\r\n\r\n{logon_html}"
            );
            let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
            served_logon = true;
        }
        drop(write_half);
        drop(read_half);

        if !served_logon {
            // Connection #2: the client GETs /+CSCOE+/logon.html after the
            // XML-channel 404; serve the logon form (implicit close), so the
            // credential POST must come on yet another connection.
            let (tcp, _peer) = listener.accept().await.expect("login server accept");
            let stream = acceptor.accept(tcp).await.expect("login TLS accept");
            let (mut read_half, mut write_half) = tokio::io::split(stream);
            let _get_request = read_request_head(&mut read_half).await;
            let out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nKeep-Alive: timeout=5, max=100\r\nConnection: keep-alive\r\n\r\n{logon_html}"
            );
            let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
            drop(write_half);
            drop(read_half);
        }

        // The credential POST (FRESH): read the head plus declared form body,
        // so the login POST completes before the response is written. The
        // POST must echo the served csrf_token.
        let (tcp, _peer) = listener.accept().await.expect("login server accept");
        let stream = acceptor.accept(tcp).await.expect("login TLS accept");
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let post_request = read_request_with_body(&mut read_half).await;
        let post_body =
            String::from_utf8_lossy(&post_request[find_header_end(&post_request).unwrap_or(0)..]);
        let echoed_token = post_body
            .split("csrf_token=")
            .nth(1)
            .and_then(|t| t.split('&').next())
            .unwrap_or_default();
        if echoed_token != csrf_token {
            let out = "HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
            let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
            return;
        }
        let out = format!(
            "HTTP/1.1 200 OK\r\nSet-Cookie: webvpn={cookie_value}; path=/; secure\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        );
        let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
    });
    addr
}

/// Perform a real CS-AUTH-01 login against a loopback fake gateway and return
/// the resulting `LoginSession` together with the gateway cert/key material
/// (for the CONNECT fake gateway and the injected roots).
async fn login_session(
    host: &str,
    cookie_value: &'static str,
) -> (
    LoginSession,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let (cert, key) = vpn_material();
    // `PrivateKeyDer` is not `Clone`; `clone_key` re-derives a 'static copy.
    let addr = run_login_ok_server(cert.clone(), key.clone_key(), cookie_value).await;
    let login = WebvpnLogin::perform_login(
        host,
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"s3cret",
    )
    .await
    .expect("the fake gateway accepts the login POST");
    (login, cert, key)
}

// ---------------------------------------------------------------------------
// The fake CONNECT gateway (loopback TLS server with the embedded certs):
// reads the client's CONNECT request, serves a CONFIGURABLE offer body plus
// the `\r\n\r\n` terminator, and reports the captured request.
// ---------------------------------------------------------------------------

/// What the fake CONNECT gateway observed from the client.
struct CapturedConnect {
    /// The raw CONNECT request bytes (head incl. the `\r\n\r\n` terminator).
    request: Vec<u8>,
}

/// Run a local TLS CONNECT gateway (loopback) that reads the client's CONNECT
/// request, serves `body` followed by the `\r\n\r\n` offer terminator (the
/// stream is closed after the reply — these tests pin the offer-parse matrix,
/// not the data phase), and reports the captured request. The client (under
/// test) connects with `TrustPolicy::TestRoots` so the TLS handshake is
/// verified for real.
async fn run_offer_server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    body: &'static str,
) -> (SocketAddr, oneshot::Receiver<CapturedConnect>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind connect server");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _peer) = listener.accept().await.expect("connect server accept");
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("build server config from embedded cert");
        let acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_cfg)));
        let stream = acceptor.accept(tcp).await.expect("connect TLS accept");
        let (mut read_half, mut write_half) = tokio::io::split(stream);

        // Read the CONNECT request head (no body; ends at `\r\n\r\n`).
        let mut request = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            match tokio::io::AsyncReadExt::read(&mut read_half, &mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    request.extend_from_slice(&buf[..n]);
                    if find_header_end(&request).is_some() {
                        break;
                    }
                    if request.len() > 8192 {
                        break;
                    }
                }
            }
        }

        // Serve the configured offer body, terminated by `\r\n\r\n`.
        let mut out = String::from(body);
        out.push_str("\r\n\r\n");
        let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
        let _ = tx.send(CapturedConnect { request });
    });
    (addr, rx)
}

/// A `BootstrapConfig` for the fake gateway (loopback, injected roots).
fn connect_cfg(addr: SocketAddr, cert: &CertificateDer<'static>) -> BootstrapConfig {
    BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    }
}

/// Drive `CstpSession::open` against a fake gateway serving `body` (via a real
/// login + CONNECT over the embedded PKI). Returns the typed outcome.
async fn open_with_offer_body(body: &'static str) -> Result<CstpSession, SessionError> {
    let (login, cert, key) = login_session("vpn.example.test", "offer-alignment").await;
    let (addr, _captured) = run_offer_server(cert.clone(), key, body).await;
    CstpSession::open(connect_cfg(addr, &cert), Some(&login)).await
}

// ---------------------------------------------------------------------------
// The offer bodies served by the fake gateway.
// ---------------------------------------------------------------------------

/// The canonical real-Cisco HTTP-header-style offer (plan §3.3): the wrapper
/// headers `Transfer-Encoding: chunked` / `Session-Id` / `DPD` / `Keepalive`
/// plus the `X-CSTP-*` offer keys.
const OFFER_HEAD: &str = "HTTP/1.1 200 OK\r\n\
    Date: Thu, 01 Jan 2026 00:00:00 GMT\r\n\
    Server: Cisco AnyConnect\r\n\
    Transfer-Encoding: chunked\r\n\
    Session-Id: 0123456789abcdef\r\n\
    DPD: 30\r\n\
    Keepalive: 60\r\n\
    X-CSTP-Address: 10.88.88.1\r\n\
    X-CSTP-Netmask: 255.255.255.0\r\n\
    X-CSTP-MTU: 1406\r\n\
    X-CSTP-DNS: 10.88.88.2 8.8.8.8\r\n\
    X-CSTP-Split-Include: 10.0.0.0/8 192.168.0.0/16\r\n\
    X-CSTP-Lease-Duration: 86400";

/// The legacy line-style offer (school `validate_school_offer` whitespace
/// branch, school.rs L1345-1352 — "legacy 行式（受控对齐保留）"): the same
/// fields as [`OFFER_HEAD`], but `key value` pairs separated by whitespace
/// with the legacy `CSTP_*` keys, under the same 200 wrapper.
const LEGACY_OFFER_HEAD: &str = "HTTP/1.1 200 OK\r\n\
    CSTP_MTU 1406\r\n\
    CSTP_ADDRESS 10.88.88.1\r\n\
    CSTP_NETMASK 255.255.255.0\r\n\
    CSTP_DNS 10.88.88.2 8.8.8.8\r\n\
    CSTP_SPLIT_INCLUDE 10.0.0.0/8 192.168.0.0/16";

/// The offer with the netmask missing (kills the M3 mutant).
const OFFER_NO_NETMASK: &str = "HTTP/1.1 200 OK\r\n\
    X-CSTP-Address: 10.88.88.1\r\n\
    X-CSTP-MTU: 1406";

/// The offer with the address missing.
const OFFER_NO_ADDRESS: &str = "HTTP/1.1 200 OK\r\n\
    X-CSTP-Netmask: 255.255.255.0\r\n\
    X-CSTP-MTU: 1406";

/// The offer with the MTU missing.
const OFFER_NO_MTU: &str = "HTTP/1.1 200 OK\r\n\
    X-CSTP-Address: 10.88.88.1\r\n\
    X-CSTP-Netmask: 255.255.255.0";

/// The full offer plus unknown `X-CSTP-*` extra fields and additional wrapper
/// keys (real gateways send more than the required set): every unknown key
/// must be ignored, not misread and not fatal.
const OFFER_WITH_UNKNOWN_KEYS: &str = "HTTP/1.1 200 OK\r\n\
    Transfer-Encoding: chunked\r\n\
    X-CSTP-Address: 10.88.88.1\r\n\
    X-CSTP-Netmask: 255.255.255.0\r\n\
    X-CSTP-MTU: 1406\r\n\
    X-CSTP-DNS: 10.88.88.2 8.8.8.8\r\n\
    X-CSTP-Split-Include: 10.0.0.0/8 192.168.0.0/16\r\n\
    X-CSTP-Lease-Duration: 86400\r\n\
    X-CSTP-Session-Id: 0123456789abcdef\r\n\
    X-CSTP-Keepalive: 60\r\n\
    X-CSTP-DPD: 30\r\n\
    X-CSTP-Quote-Of-The-Day: \"authenticate or die\"";

/// A DTLS offer: all required fields present, but the protocol is `dtls` —
/// any `dtls` appearance rejects the offer (plan §3.3; kills the M2 mutant).
const OFFER_DTLS: &str = "HTTP/1.1 200 OK\r\n\
    X-CSTP-Address: 10.88.88.1\r\n\
    X-CSTP-Netmask: 255.255.255.0\r\n\
    X-CSTP-MTU: 1406\r\n\
    X-CSTP-Protocol: dtls";

/// A bare HTML error page (no HTTP status line): non-CSTP content.
const HTML_ERROR_PAGE: &str = "<!DOCTYPE html>\r\n\
    <html><head><title>Error</title></head>\r\n\
    <body><h1>Forbidden</h1><p>Login required.</p></body></html>";

/// An HTML page served under a 200 status (the gateway's login/rejection page
/// on the tunnel path): must still be rejected — the HTML must never parse
/// into a plan (kills the M1 mutant).
const HTML_ERROR_PAGE_UNDER_200: &str = "HTTP/1.1 200 OK\r\n\
    Content-Type: text/html\r\n\
    Content-Length: 78\r\n\
    <html><head><title>Login</title></head>\r\n\
    <body><h1>Login</h1><p>Authentication required.</p></body></html>";

/// An HTTP error status WITH all required X-CSTP-* fields present: the
/// non-2xx status must reject regardless of the fields.
const OFFER_403_WITH_FIELDS: &str = "HTTP/1.1 403 Forbidden\r\n\
    Content-Length: 0\r\n\
    X-CSTP-Address: 10.88.88.1\r\n\
    X-CSTP-Netmask: 255.255.255.0\r\n\
    X-CSTP-MTU: 1406";

/// Netmask -> prefix variants: 255.255.255.0 -> 24, 255.0.0.0 -> 8,
/// 255.255.255.255 -> 32, and the non-contiguous 255.0.255.0 -> rejected.
const OFFER_MASK_24: &str = "HTTP/1.1 200 OK\r\n\
    X-CSTP-Address: 10.88.88.1\r\n\
    X-CSTP-Netmask: 255.255.255.0\r\n\
    X-CSTP-MTU: 1406";
const OFFER_MASK_8: &str = "HTTP/1.1 200 OK\r\n\
    X-CSTP-Address: 10.88.88.1\r\n\
    X-CSTP-Netmask: 255.0.0.0\r\n\
    X-CSTP-MTU: 1406";
const OFFER_MASK_32: &str = "HTTP/1.1 200 OK\r\n\
    X-CSTP-Address: 10.88.88.1\r\n\
    X-CSTP-Netmask: 255.255.255.255\r\n\
    X-CSTP-MTU: 1406";
const OFFER_MASK_NON_CONTIGUOUS: &str = "HTTP/1.1 200 OK\r\n\
    X-CSTP-Address: 10.88.88.1\r\n\
    X-CSTP-Netmask: 255.0.255.0\r\n\
    X-CSTP-MTU: 1406";

/// The plan the canonical offers must produce (address 10.88.88.1, prefix 24,
/// mtu 1406, dns 10.88.88.2+8.8.8.8, routes 10.0.0.0/8 + 192.168.0.0/16).
fn assert_canonical_plan(offer: &TunnelOffer) {
    assert_eq!(offer.ipv4_address, Ipv4Addr::new(10, 88, 88, 1));
    assert_eq!(offer.prefix, 24);
    assert_eq!(offer.mtu, 1406);
    assert_eq!(
        offer.dns_servers,
        vec![Ipv4Addr::new(10, 88, 88, 2), Ipv4Addr::new(8, 8, 8, 8)]
    );
    assert_eq!(offer.routes, vec!["10.0.0.0/8", "192.168.0.0/16"]);
}

// ---------------------------------------------------------------------------
// The 8 fixed tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_header_style_offer_parses_into_tunnel_offer() {
    // The real-Cisco HTTP-header-style offer (plan §3.3): the wrapper headers
    // `Transfer-Encoding: chunked` / `Session-Id` / `DPD` / `Keepalive` must be
    // ignored, the `X-CSTP-*` keys normalize to `CSTP_*` and produce the full
    // plan `TunnelOffer{ipv4_address,prefix,mtu,dns_servers,routes}`. A mutant
    // that misreads a wrapper header, drops a field, or fails to normalize
    // `X-CSTP-*` fails here.
    let (login, cert, key) = login_session("vpn.example.test", "offer-alignment").await;
    let (addr, captured) = run_offer_server(cert.clone(), key, OFFER_HEAD).await;

    let session = CstpSession::open(connect_cfg(addr, &cert), Some(&login))
        .await
        .expect("the real header-style offer must parse into a tunnel plan");

    let captured = captured.await.expect("the fake gateway observed the CONNECT");
    assert_eq!(
        captured.request,
        build_connect_request("vpn.example.test", &login),
        "the bytes written on the wire must be exactly build_connect_request's bytes"
    );

    assert_canonical_plan(&session.offer_plan);
}

#[tokio::test]
async fn legacy_line_style_offer_parses_like_header_style() {
    // The legacy line-style offer — `key value` pairs separated by whitespace
    // with the legacy `CSTP_*` keys (school `validate_school_offer` whitespace
    // branch, school.rs L1345-1352; plan leaf row "legacy 行式（受控对齐保
    // 留）→ 同样解析") — must produce EXACTLY the same plan as the
    // HTTP-header-style offer. The CS-AUTH-02 provisional parse only splits on
    // `:` and drops every whitespace-separated line, so this test is the
    // alignment pin for CS-AUTH-03-I: legacy lines must be split on whitespace
    // (and the HTTP wrapper/status lines skipped), never silently dropped.
    let session = open_with_offer_body(LEGACY_OFFER_HEAD)
        .await
        .expect("the legacy line-style offer must parse into the same tunnel plan");

    assert_canonical_plan(&session.offer_plan);
}

#[tokio::test]
async fn missing_required_offer_fields_are_rejected() {
    // A missing required field must be a typed `OfferParseFailed`, never a
    // plan. The killer mutant is "缺 CSTP_NETMASK 被接受" — the netmask is the
    // gateway's prefix authority, so `CSTP_NETMASK` missing must reject even
    // when address and MTU are present. Address and MTU missing are pinned the
    // same way.
    for (body, missing) in [
        (OFFER_NO_NETMASK, "CSTP_NETMASK"),
        (OFFER_NO_ADDRESS, "CSTP_ADDRESS"),
        (OFFER_NO_MTU, "CSTP_MTU"),
    ] {
        let err = open_with_offer_body(body)
            .await
            .expect_err("an offer missing a required field must be a typed error");
        assert!(
            matches!(err, SessionError::OfferParseFailed),
            "missing {missing} surfaces as typed OfferParseFailed, got {err:?}"
        );
    }
}

#[tokio::test]
async fn unknown_x_cstp_and_extra_wrapper_headers_are_ignored() {
    // Real gateways send more than the required set (`X-CSTP-Lease-Duration`,
    // `X-CSTP-Session-Id`, `X-CSTP-Keepalive`, `X-CSTP-DPD`, plus unknown
    // vendor keys): every unknown `X-CSTP-*` / wrapper key must be ignored —
    // neither fatal nor misread into the plan. A mutant that treats unknown
    // keys as required, or misreads one as a known key, fails here.
    let session = open_with_offer_body(OFFER_WITH_UNKNOWN_KEYS)
        .await
        .expect("unknown X-CSTP-* and wrapper headers must be ignored, not fatal");

    assert_canonical_plan(&session.offer_plan);
}

#[tokio::test]
async fn dtls_offer_is_rejected() {
    // Any `dtls` appearance rejects the offer (plan §3.3: the MVP is
    // TLS/CSTP only; kills the "DTLS offer accepted" mutant). All required
    // fields are present here — the protocol line alone must reject.
    let err = open_with_offer_body(OFFER_DTLS)
        .await
        .expect_err("a DTLS offer must be a typed error");
    assert!(
        matches!(err, SessionError::OfferParseFailed),
        "a DTLS offer surfaces as typed OfferParseFailed, got {err:?}"
    );
}

#[tokio::test]
async fn html_error_page_is_rejected_not_parsed_into_a_plan() {
    // Non-CSTP content must never become a tunnel plan (kills the "HTML 页解
    // 析成 plan" mutant). Two shapes: a bare HTML error page (no HTTP status
    // line — the gateway's raw rejection page) and an HTML page served under a
    // 200 status (the login/rejection page on the tunnel path). Both are
    // rejected as typed `OfferParseFailed`.
    for (body, shape) in [
        (HTML_ERROR_PAGE, "bare HTML error page"),
        (HTML_ERROR_PAGE_UNDER_200, "HTML page under 200"),
    ] {
        let err = open_with_offer_body(body)
            .await
            .expect_err("non-CSTP content must be a typed error");
        assert!(
            matches!(err, SessionError::OfferParseFailed),
            "a {shape} surfaces as typed OfferParseFailed, got {err:?}"
        );
    }
}

#[tokio::test]
async fn http_error_status_offer_is_rejected() {
    // An HTTP error status is non-CSTP offer content and never becomes a data
    // session — even when all required X-CSTP-* fields are present (a mutant
    // that validates fields before the status line, or skips the status check,
    // would accept this and must die here).
    let err = open_with_offer_body(OFFER_403_WITH_FIELDS)
        .await
        .expect_err("an HTTP error status offer must be a typed error");
    assert!(
        matches!(err, SessionError::OfferParseFailed),
        "an HTTP error status surfaces as typed OfferParseFailed, got {err:?}"
    );
}

#[tokio::test]
async fn netmask_converts_to_prefix() {
    // Contiguous netmask -> prefix length (0..=32, school `netmask_to_prefix`
    // pattern); a non-contiguous mask is rejected, never clamped or wrapped.
    for (body, expected_prefix) in [
        (OFFER_MASK_24, 24u8),
        (OFFER_MASK_8, 8u8),
        (OFFER_MASK_32, 32u8),
    ] {
        let session = open_with_offer_body(body)
            .await
            .expect("a contiguous netmask offer must parse");
        assert_eq!(
            session.offer_plan.prefix, expected_prefix,
            "the contiguous netmask must convert to its prefix length"
        );
    }

    let err = open_with_offer_body(OFFER_MASK_NON_CONTIGUOUS)
        .await
        .expect_err("a non-contiguous netmask must be a typed error");
    assert!(
        matches!(err, SessionError::OfferParseFailed),
        "a non-contiguous netmask surfaces as typed OfferParseFailed, got {err:?}"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
