// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV CS-AUTH-02-T: CSTP CONNECT phase (`CONNECT /CSCOSSLC/tunnel` + webvpn
// cookie) integration tests for exv-vpn-cstp.
//
// These tests define the exact public API that CS-AUTH-02-I must implement:
// `build_connect_request` in `exv_vpn_cstp::webvpn` and `CstpSession` /
// `SessionError` / `TunnelOffer` in the currently-empty `exv_vpn_cstp::session`
// module. They are expected to be RED (compile error: the items do not exist)
// until CS-AUTH-02-I fills in that production code. The CONNECT runs over a
// REAL TLS connection established by the P41 Bootstrap with an injected trust
// policy (`TrustPolicy::TestRoots`, loopback), reproduces the openconnect
// `cstp.c start_cstp_connection()` request byte-for-byte (plan §3.2), reads the
// offer up to its `\r\n\r\n` terminator, and hands the stream to two data
// tasks so the returned session carries working CSTP data channels.
//
// Contract (docs/superpowers/plans/2026-08-15-cstp-authentication-rebuild-plan.md
// leaf CS-AUTH-02, §3.2/§3.3, openconnect cstp.c start_cstp_connection()):
//   * Byte-exact CONNECT request (plan §3.2 verbatim block, `\r\n\r\n`-terminated):
//       CONNECT /CSCOSSLC/tunnel HTTP/1.1
//       Host: <host>[:<port>]                    (the host string as given)
//       Cookie: webvpn=<cookie>                  (raw value, never percent-encoded)
//       X-CSTP-Version: 1
//       X-CSTP-Hostname: <host>
//       X-CSTP-Protocol: "Copyright (c) 2004 Cisco Systems, Inc."
//     with NO `Authorization` header and NO `X-AnyConnect-Identifier-*` (or any
//     other X-AnyConnect-*) headers on desktop.
//   * `build_connect_request(host, session)` consumes a `LoginSession` from the
//     committed CS-AUTH-01 phase: the cookie captured by the login flows into
//     the CONNECT request verbatim.
//   * `CstpSession::open` without a login session is `SessionError::MissingSession`
//     BEFORE any network activity (kills the "cookie missing still CONNECTs"
//     mutant).
//   * Full chain: Bootstrap(TestRoots) loopback -> CONNECT -> offer read
//     (terminated by `\r\n\r\n`) -> data session with two live tasks.
//   * EOF before the offer terminator is the typed `SessionError::EofBeforeTerminator`
//     (the gateway closed the connection = format rejected; never a success).
//   * A non-CSTP offer (HTTP error status) is `SessionError::OfferParseFailed`;
//     it never becomes a data session. (The field-level offer matrix is the
//     CS-AUTH-03 contract; this leaf pins the typed failure.)
//
// The API CS-AUTH-02-I must implement:
//
//   // exv_vpn_cstp::webvpn (additive to the committed CS-AUTH-01 module):
//   pub fn build_connect_request(host: &str, session: &LoginSession) -> Vec<u8>;
//
//   // exv_vpn_cstp::session (fills the currently-empty module):
//   pub struct CstpSession {
//       pub offer_plan: TunnelOffer,
//       pub peer_fingerprint: Option<String>,   // SHA-256 hex of the peer cert
//       pub write_channel: mpsc::UnboundedSender<Vec<u8>>, // raw on-wire CSTP frames (Codec-encoded)
//       pub read_channel: mpsc::UnboundedReceiver<Vec<u8>>, // decoded CstpFrame::Data payloads
//   }
//   impl CstpSession {
//       pub async fn open(
//           cfg: BootstrapConfig,
//           login: Option<&LoginSession>,   // None -> SessionError::MissingSession
//       ) -> Result<CstpSession, SessionError>;
//   }
//   pub struct TunnelOffer {
//       pub ipv4_address: Ipv4Addr,
//       pub prefix: u8,
//       pub mtu: u16,
//       pub dns_servers: Vec<Ipv4Addr>,
//       pub routes: Vec<String>,            // "net/prefix" CIDR strings (school-aligned)
//   }
//   pub enum SessionError {
//       TlsFailed(BootstrapError),
//       WriteFailed,
//       EofBeforeTerminator,                // EOF before the offer \r\n\r\n
//       OfferParseFailed,                   // non-CSTP offer content
//       MissingSession,                     // CONNECT without a login session
//   }
//
//   (`open` takes `Option<&LoginSession>` so the `MissingSession` variant is
//   reachable at all; plan §2.2's terse `&LoginSession` would make it dead.)
//
// Mutants this suite must kill:
//   M1 CONNECT path wrong (not /CSCOSSLC/tunnel)
//       -> connect_request_is_byte_exact
//   M2 cookie missing from the request / missing login session still CONNECTs
//       -> connect_request_is_byte_exact, connect_request_carries_the_cookie,
//          open_without_login_session_is_missing_session,
//          cookie_roundtrips_from_login_session_into_connect_request
//   M3 Authorization: Basic resurrects
//       -> connect_request_forbids_authorization_and_anyconnect_headers
//   M4 missing X-CSTP-Version (or Hostname / shibboleth)
//       -> connect_request_is_byte_exact
//   M5 X-AnyConnect-Identifier-* (mobile-only) headers leak into the desktop request
//       -> connect_request_forbids_authorization_and_anyconnect_headers
//   M6 EOF before the offer terminator swallowed as success / partial offer accepted
//       -> open_eof_before_offer_terminator_is_typed_error
//   M7 non-CSTP offer accepted as a data session
//       -> open_rejects_error_status_offer
//   M8 data tasks never wired (session channels dead) / framing bytes mangled
//       -> open_data_channels_carry_cstp_frames

use exv_vpn_cstp::codec::{CstpFrame, Codec};
use exv_vpn_cstp::connector::{BootstrapConfig, TrustPolicy};
use exv_vpn_cstp::session::{CstpSession, SessionError};
use exv_vpn_cstp::webvpn::{
    LoginSession, WebvpnLogin, build_connect_request, build_connect_request_with_user_agent,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Embedded test PKI. The same deterministic material family as the CS-AUTH-01-T
// suite (self-signed ECDSA P-256 leaf cert that is its own root) is embedded
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

/// The value of the first header named `name` in an HTTP head (case-insensitive).
fn header_value(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

// ---------------------------------------------------------------------------
// The fake login gateway (minimal: serves the two-step measured login flow
// and exactly the webvpn cookie).
//
// `LoginSession` is only obtainable through the committed CS-AUTH-01
// `WebvpnLogin::perform_login` (the `WebvpnCookie` value is opaque and
// privately constructed), so every test that needs a login session runs a real
// loopback login first (GET logon.html -> POST the form ACTION) — which also
// makes the cookie roundtrip intrinsic.
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
                        expected_len = header_value(&head, "content-length")
                            .and_then(|v| v.parse::<usize>().ok());
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
            && header_value(&first_head, "content-type")
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("application/xml"));
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
// The fake CONNECT gateway (loopback TLS server with the embedded certs).
// ---------------------------------------------------------------------------

/// What the fake CONNECT gateway observes from the client.
struct CapturedConnect {
    /// The raw CONNECT request bytes (head incl. the `\r\n\r\n` terminator).
    request: Vec<u8>,
    /// The first complete CSTP frame the client sent after the offer (only the
    /// data-channel test drives one).
    client_frame: Option<Vec<u8>>,
}

/// The configurable response the fake CONNECT gateway serves after reading the
/// CONNECT request.
enum ConnectReply {
    /// A proper CSTP offer head (HTTP/1.1 200 + `X-CSTP-*` headers, without the
    /// trailing `\r\n\r\n`, which the server appends). With `then_data`, the
    /// server keeps the stream open for one CSTP frame exchange.
    Offer {
        offer_head: &'static str,
        then_data: bool,
    },
    /// An HTTP error status + empty body: non-CSTP offer content.
    ErrorStatus(&'static str),
    /// Close the TLS stream right after the CONNECT request: EOF before the
    /// offer terminator.
    Eof,
}

/// Run a local TLS CONNECT gateway (loopback) that reads the client's CONNECT
/// request, serves the configured reply, and reports the captured request. The
/// client (under test) connects with `TrustPolicy::TestRoots` so the TLS
/// handshake is verified for real.
async fn run_connect_server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    reply: ConnectReply,
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

        match reply {
            ConnectReply::Eof => {
                // Close without writing a single byte: the offer never starts.
                let _ = tx.send(CapturedConnect {
                    request,
                    client_frame: None,
                });
            }
            ConnectReply::ErrorStatus(status_line) => {
                let out = format!("HTTP/1.1 {status_line}\r\nContent-Length: 0\r\n\r\n");
                let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
                let _ = tx.send(CapturedConnect {
                    request,
                    client_frame: None,
                });
            }
            ConnectReply::Offer { offer_head, then_data } => {
                let mut out = String::from(offer_head);
                out.push_str("\r\n\r\n");
                let _ = tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
                if !then_data {
                    let _ = tx.send(CapturedConnect {
                        request,
                        client_frame: None,
                    });
                    return;
                }
                // Data phase. Ordering is deterministic: the client sends its
                // frame FIRST (its `open` has returned by then), the server
                // captures it, and only then does the server write its own
                // frame — so no server bytes can be stranded in the client's
                // offer reader and no client bytes before the offer.
                let mut frame = Vec::new();
                let mut declared: Option<usize> = None;
                loop {
                    match tokio::io::AsyncReadExt::read(&mut read_half, &mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            frame.extend_from_slice(&buf[..n]);
                            if declared.is_none() && frame.len() >= 3 {
                                // STF header: len is the be16 at [4..5]; full frame = 8 + len.
                                declared = Some(((frame[4] as usize) << 8) | frame[5] as usize);
                            }
                            if declared.is_some_and(|len| frame.len() >= 8 + len) {
                                break;
                            }
                            if frame.len() > 8192 {
                                break;
                            }
                        }
                    }
                }
                let _ = tx.send(CapturedConnect {
                    request,
                    client_frame: Some(frame),
                });
                // One CSTP data frame with payload "ping!" (raw wire bytes; the
                // client's data task decodes them with the frozen P40 Codec).
                let _ = tokio::io::AsyncWriteExt::write_all(
                    &mut write_half,
                    &[0x53, 0x54, 0x46, 0x01, 0x00, 0x05, 0x00, 0x00, b'p', b'i', b'n', b'g', b'!'],
                )
                .await;
            }
        }
    });
    (addr, rx)
}

// ---------------------------------------------------------------------------
// The canonical offer head served by the fake gateway in the success tests
// (HTTP-header style, real-Cisco shape: wrapper headers + X-CSTP-* offer keys).
// ---------------------------------------------------------------------------

const OFFER_HEAD: &str = "HTTP/1.1 200 OK\r\n\
    Date: Thu, 01 Jan 2026 00:00:00 GMT\r\n\
    Server: Cisco AnyConnect\r\n\
    Transfer-Encoding: chunked\r\n\
    X-CSTP-Address: 10.88.88.1\r\n\
    X-CSTP-Netmask: 255.255.255.0\r\n\
    X-CSTP-MTU: 1406\r\n\
    X-CSTP-DNS: 10.88.88.2 8.8.8.8\r\n\
    X-CSTP-Split-Include: 10.0.0.0/8 192.168.0.0/16\r\n\
    X-CSTP-Lease-Duration: 86400\r\n\
    X-CSTP-Session-Id: 0123456789abcdef\r\n\
    X-CSTP-Keepalive: 60\r\n\
    X-CSTP-DPD: 30";

/// A `BootstrapConfig` for the fake gateway (loopback, injected roots).
fn connect_cfg(
    addr: SocketAddr,
    cert: &CertificateDer<'static>,
) -> BootstrapConfig {
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

// ---------------------------------------------------------------------------
// The 8 fixed tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn connect_request_is_byte_exact() {
    // The CONNECT request must reproduce openconnect cstp.c
    // start_cstp_connection() byte-for-byte (plan §3.2 verbatim block): the
    // `/CSCOSSLC/tunnel` path (NOT a bare `CONNECT <host>`), `Host`,
    // `Cookie: webvpn=<value>`, `X-CSTP-Version: 1`, `X-CSTP-Hostname` and the
    // `X-CSTP-Protocol` shibboleth, terminated by `\r\n\r\n`. Mutants that use
    // the wrong path, drop the cookie, drop `X-CSTP-Version`, drop the
    // hostname, or drop the shibboleth all fail the exact equality.
    let (login, _cert, _key) = login_session("vpn.example.test", "abc123xyz").await;
    let request = build_connect_request("vpn.example.test", &login);

    let expected = concat!(
        "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n",
        "Host: vpn.example.test\r\n",
        "Cookie: webvpn=abc123xyz\r\n",
        "X-CSTP-Version: 1\r\n",
        "X-CSTP-Hostname: vpn.example.test\r\n",
        "X-CSTP-Protocol: \"Copyright (c) 2004 Cisco Systems, Inc.\"\r\n",
        "\r\n",
    );
    assert_eq!(
        request,
        expected.as_bytes(),
        "the CONNECT request must be byte-exact (plan §3.2)"
    );

    // The mutant guards, made explicit (the equality above already kills them):
    let head = String::from_utf8_lossy(&request);
    assert!(
        head.lines().next() == Some("CONNECT /CSCOSSLC/tunnel HTTP/1.1"),
        "the CONNECT target must be exactly /CSCOSSLC/tunnel"
    );
    assert!(
        header_value(&head, "cookie").as_deref() == Some("webvpn=abc123xyz"),
        "the request must carry Cookie: webvpn=<value>"
    );
    assert!(
        head.contains("X-CSTP-Version: 1"),
        "the request must carry X-CSTP-Version: 1"
    );
    assert!(
        head.contains("X-CSTP-Hostname: vpn.example.test"),
        "the request must carry X-CSTP-Hostname"
    );
    assert!(
        head.contains("X-CSTP-Protocol: \"Copyright (c) 2004 Cisco Systems, Inc.\""),
        "the request must carry the X-CSTP-Protocol shibboleth"
    );
}

#[tokio::test]
async fn connect_request_with_user_agent_is_additive_and_carries_the_ua() {
    // The additive UA variant of the CONNECT builder (the C++
    // make_cstp_connect_request shape: `User-Agent:` right after `Host`) —
    // the client name the caller passes per connection (a config/settings
    // layer feeds its override through CstpSession::open_with_user_agent).
    // The legacy UA-less CONNECT (connect_request_is_byte_exact) stays
    // byte-identical — the cookie remains the credential, no Authorization
    // and no X-AnyConnect-* header appears.
    let (login, _cert, _key) = login_session("vpn.example.test", "abc123xyz").await;
    let request = build_connect_request_with_user_agent(
        "vpn.example.test",
        &login,
        "AnyConnect Win_x86_64 4.10.05095",
    );

    let expected = concat!(
        "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n",
        "Host: vpn.example.test\r\n",
        "User-Agent: AnyConnect Win_x86_64 4.10.05095\r\n",
        "Cookie: webvpn=abc123xyz\r\n",
        "X-CSTP-Version: 1\r\n",
        "X-CSTP-Hostname: vpn.example.test\r\n",
        "X-CSTP-Protocol: \"Copyright (c) 2004 Cisco Systems, Inc.\"\r\n",
        "\r\n",
    );
    assert_eq!(
        request,
        expected.as_bytes(),
        "the UA variant is the byte-exact CONNECT request plus the User-Agent header"
    );
    let head = String::from_utf8_lossy(&request);
    assert!(
        !head.to_ascii_lowercase().contains("authorization"),
        "the UA variant must not carry an Authorization header"
    );
    assert!(
        !head.to_ascii_lowercase().contains("x-anyconnect-"),
        "the UA variant must not carry any X-AnyConnect-* header"
    );
}

#[tokio::test]
async fn connect_request_forbids_authorization_and_anyconnect_headers() {
    // The WebVPN cookie IS the credential for the CONNECT phase: no
    // `Authorization` header may appear (the `Authorization: Basic` mutant of
    // the old school.rs flow must not resurrect), and no `X-AnyConnect-*`
    // header (including the mobile-only `X-AnyConnect-Identifier-*` family)
    // belongs in the desktop client's request (openconnect cstp.c
    // start_cstp_connection() sends neither).
    let (login, _cert, _key) = login_session("vpn.example.test", "authorization-mutant").await;
    let request = build_connect_request("vpn.example.test", &login);
    let head = String::from_utf8_lossy(&request);

    assert!(
        header_value(&head, "authorization").is_none(),
        "no Authorization header may appear in the CONNECT request"
    );
    assert!(
        !head.to_ascii_lowercase().contains("anyconnect"),
        "no X-AnyConnect-* header may appear in the desktop CONNECT request"
    );
    assert!(
        !head.to_ascii_lowercase().contains("x-anyconnect-identifier"),
        "the mobile-only X-AnyConnect-Identifier-* headers must not appear"
    );
}

#[tokio::test]
async fn connect_request_carries_the_cookie() {
    // A distinct cookie value must appear in the request verbatim (raw, not
    // percent-encoded and not truncated): a mutant that hardcodes a fixed
    // cookie, truncates the value, or re-encodes it fails here.
    let distinctive = "round-trip+V4lue_9";
    let (login, _cert, _key) = login_session("vpn.example.test", distinctive).await;
    let request = build_connect_request("vpn.example.test", &login);
    let head = String::from_utf8_lossy(&request);

    assert_eq!(
        header_value(&head, "cookie").as_deref(),
        Some("webvpn=round-trip+V4lue_9"),
        "the cookie must be passed through verbatim, exactly as captured"
    );
    assert_eq!(
        login.cookie.as_str(),
        distinctive,
        "the login session holds the captured cookie value"
    );
}

#[tokio::test]
async fn open_without_login_session_is_missing_session() {
    // CONNECTing without a login session is a typed error BEFORE any network
    // activity (kills the "cookie missing still CONNECTs" mutant). The gateway
    // address deliberately points at a closed port, so a connect-first mutant
    // dies on a real connect failure instead of ever succeeding.
    let (cert, _key) = vpn_material();
    let err = CstpSession::open(
        BootstrapConfig {
            hostname: "vpn.example.test".to_string(),
            gateway_addr: "127.0.0.1:1".parse().expect("closed loopback port"),
            trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
            dtls_offered: false,
            deadline: None,
            socket_binder: None,
            gateway_resolver: None,
        },
        None,
    )
    .await
    .expect_err("CONNECT without a login session must be a typed error");
    assert!(
        matches!(err, SessionError::MissingSession),
        "no login session surfaces as typed MissingSession, got {err:?}"
    );
}

#[tokio::test]
async fn open_full_chain_parses_offer_and_reports_fingerprint() {
    // The full chain over a REAL TLS connection (Bootstrap with TestRoots,
    // loopback): CONNECT -> offer read (terminated by `\r\n\r\n`) -> a
    // validated `TunnelOffer` plan + the peer fingerprint. The wire request
    // must be exactly the builder's bytes. This is the leaf's central
    // end-to-end test; a mutant that skips TLS verification, writes a different
    // request, fails to read the offer, or drops the fingerprint fails here.
    let (login, cert, key) = login_session("vpn.example.test", "abc123xyz").await;
    let (addr, captured) = run_connect_server(
        cert.clone(),
        key,
        ConnectReply::Offer {
            offer_head: OFFER_HEAD,
            then_data: false,
        },
    )
    .await;

    let session = CstpSession::open(connect_cfg(addr, &cert), Some(&login))
        .await
        .expect("the fake gateway accepts the CONNECT and serves a valid offer");

    let captured = captured.await.expect("the fake gateway observed the CONNECT");
    assert_eq!(
        captured.request,
        build_connect_request("vpn.example.test", &login),
        "the bytes written on the wire must be exactly build_connect_request's bytes"
    );

    let offer = session.offer_plan;
    assert_eq!(offer.ipv4_address, Ipv4Addr::new(10, 88, 88, 1));
    assert_eq!(offer.prefix, 24);
    assert_eq!(offer.mtu, 1406);
    assert_eq!(
        offer.dns_servers,
        vec![Ipv4Addr::new(10, 88, 88, 2), Ipv4Addr::new(8, 8, 8, 8)]
    );
    assert_eq!(offer.routes, vec!["10.0.0.0/8", "192.168.0.0/16"]);

    let fingerprint = session
        .peer_fingerprint
        .as_ref()
        .expect("the TLS peer fingerprint must be reported");
    assert!(!fingerprint.is_empty(), "the fingerprint must not be empty");
    assert!(
        fingerprint.chars().all(|c| c.is_ascii_hexdigit()),
        "the fingerprint must be hex (school tls_peer_fingerprint pattern)"
    );
}

#[tokio::test]
async fn open_data_channels_carry_cstp_frames() {
    // After the offer, the same byte stream switches to CSTP binary framing
    // (frozen P40 Codec). `CstpSession::open` must have split the stream and
    // started the two data tasks: a frame sent on `write_channel` must reach
    // the gateway byte-for-byte, and a gateway frame must arrive as a decoded
    // `CstpFrame::Data` payload on `read_channel`. A mutant that never spawns
    // the tasks (dead channels) or mangles the framing fails here.
    let (login, cert, key) = login_session("vpn.example.test", "abc123xyz").await;
    let (addr, captured) = run_connect_server(
        cert.clone(),
        key,
        ConnectReply::Offer {
            offer_head: OFFER_HEAD,
            then_data: true,
        },
    )
    .await;

    let mut session = CstpSession::open(connect_cfg(addr, &cert), Some(&login))
        .await
        .expect("the fake gateway accepts the CONNECT and serves a valid offer");

    // client -> gateway: one IPv4 data frame, encoded by the frozen Codec.
    let wire = Codec::new()
        .encode(&CstpFrame::Data(vec![0x45, 0x01, 0x02, 0x03]))
        .expect("encode a CSTP data frame");
    session
        .write_channel
        .send(wire.clone())
        .expect("the write channel is live");

    let captured = tokio::time::timeout(Duration::from_secs(5), captured)
        .await
        .expect("the fake gateway captures the client frame")
        .expect("the fake gateway completed");
    let observed = captured
        .client_frame
        .expect("the fake gateway observed exactly one CSTP frame");
    assert_eq!(
        observed, wire,
        "the data task must write the exact CSTP frame bytes"
    );

    // gateway -> client: the server's "ping!" data frame decodes to its payload.
    let delivered = tokio::time::timeout(Duration::from_secs(5), session.read_channel.recv())
        .await
        .expect("the read channel delivers the gateway frame")
        .expect("the read channel is live");
    assert_eq!(
        delivered,
        b"ping!".to_vec(),
        "the data task must deliver the decoded CSTP data payload"
    );
}

#[tokio::test]
async fn open_eof_before_offer_terminator_is_typed_error() {
    // The gateway closed the connection right after the CONNECT (the real
    // Cisco gateway's rejection signature): EOF before the offer's `\r\n\r\n`
    // terminator must surface as the typed `EofBeforeTerminator` — never a
    // partial-offer success. A mutant that swallows the EOF or treats a
    // partial offer as a data session fails here.
    let (login, cert, key) = login_session("vpn.example.test", "abc123xyz").await;
    let (addr, captured) = run_connect_server(cert.clone(), key, ConnectReply::Eof).await;

    let err = CstpSession::open(connect_cfg(addr, &cert), Some(&login))
        .await
        .expect_err("EOF before the offer terminator must be a typed error");
    assert!(
        matches!(err, SessionError::EofBeforeTerminator),
        "EOF before the offer terminator surfaces as typed EofBeforeTerminator, got {err:?}"
    );

    let captured = captured.await.expect("the fake gateway observed the CONNECT");
    assert_eq!(
        captured.request,
        build_connect_request("vpn.example.test", &login),
        "the CONNECT request was sent before the gateway closed"
    );
}

#[tokio::test]
async fn open_rejects_error_status_offer() {
    // A non-CSTP offer (an HTTP error status, e.g. the gateway's rejection
    // page) must never become a data session: `open` fails with the typed
    // `OfferParseFailed`. (The field-level offer-validation matrix is the
    // CS-AUTH-03 contract; this leaf pins the typed failure at the session
    // boundary.)
    let (login, cert, key) = login_session("vpn.example.test", "abc123xyz").await;
    let (addr, _captured) = run_connect_server(
        cert.clone(),
        key,
        ConnectReply::ErrorStatus("500 Internal Server Error"),
    )
    .await;

    let err = CstpSession::open(connect_cfg(addr, &cert), Some(&login))
        .await
        .expect_err("an HTTP error status offer must not become a data session");
    assert!(
        matches!(err, SessionError::OfferParseFailed),
        "a non-CSTP offer surfaces as typed OfferParseFailed, got {err:?}"
    );
}

#[tokio::test]
async fn cookie_roundtrips_from_login_session_into_connect_request() {
    // The cookie captured by the committed CS-AUTH-01 login flows verbatim
    // into the CONNECT request: the request's `Cookie` header must equal
    // `webvpn=<login.cookie.as_str()>` for a distinctive, mixed-character
    // value. This is the end-to-end cookie roundtrip the CONNECT phase exists
    // for; a mutant that invents its own cookie (or drops it) fails here.
    let distinctive = "s3ss10n!V4lue_9+=";
    let (login, cert, key) = login_session("vpn.example.test", distinctive).await;
    let (addr, captured) = run_connect_server(
        cert.clone(),
        key,
        ConnectReply::Offer {
            offer_head: OFFER_HEAD,
            then_data: false,
        },
    )
    .await;

    let session = CstpSession::open(connect_cfg(addr, &cert), Some(&login))
        .await
        .expect("the fake gateway accepts the CONNECT");

    let captured = captured.await.expect("the fake gateway observed the CONNECT");
    let head = String::from_utf8_lossy(&captured.request);
    assert_eq!(
        header_value(&head, "cookie").as_deref(),
        Some("webvpn=s3ss10n!V4lue_9+=".into()),
        "the wire CONNECT must carry Cookie: webvpn=<captured value>"
    );
    assert_eq!(
        login.cookie.as_str(),
        distinctive,
        "the login session holds the captured cookie value"
    );
    assert!(
        !format!("{session:?}").contains(distinctive),
        "CstpSession Debug must not leak the cookie value"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
