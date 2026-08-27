// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV CS-AUTH-01-T (aggregate-auth): the PRIMARY XML login channel tests for
// exv-vpn-cstp.
//
// These tests pin the aggregate-auth XML flow that
// `WebvpnLogin::perform_login` / `WebvpnLogin::perform_login_with_user_agent`
// run FIRST (the FORM channel of tests/webvpn_login.rs is the FALLBACK):
//
//   * `POST /` (one keep-alive connection) with the init XML (`<config-auth
//     client="vpn" type="init" aggregate-auth-version="2">` + `<version
//     who="vpn">` = the UA + `<device-id>` + `<group-access>` +
//     `<capabilities>`) and the `User-Agent` + `Content-Type: application/xml;
//     charset=utf-8` + `X-Transcend-Version: 1` + `X-Aggregate-Auth: 1` +
//     `Connection: keep-alive` headers -> 200 + `config-auth
//     type="auth-request"` (the MEASURED vpn-ct.ecnu.edu.cn shape, 2026-08-15
//     probe: `<opaque>` + username/password form + `group_list` select).
//   * `POST /` on the SAME connection with the auth-reply XML: the `<opaque>`
//     echoed VERBATIM + `<auth><username>` + `<password>` (XML-escaped) +
//     `<group-select>` (the parsed group value).
//   * Success = `auth_id="success"` or a `<session-token>`/`<session-id>`
//     (the credential IS `webvpn=<token>`), falling back to the reply's
//     `Set-Cookie: webvpn=`; rejection = `auth_id="error"` / `<error>` node /
//     non-2xx status / non-XML reply; SAML steering = `SamlRequired`.
//
// The UA gate (MEASURED probe matrix, 2026-08-15): the XML channel opens ONLY
// for the exact AnyConnect platform `User-Agent` names — any other UA (a
// product UA, a platform-less `AnyConnect`, a lowercased prefix) gets HTTP 404
// on `POST /`, which sends the login to the FORM fallback. The fake gateway
// below implements that gate: `accepted_ua` decides whether the init is
// answered 200 (XML channel open) or 404 (channel closed -> form fallback).
//
// Mutants this suite must kill:
//   M1 the XML channel is skipped (the login goes straight to the form flow)
//       -> every test (the fake's first exchange IS the XML init probe)
//   M2 the init is sent without the platform UA / X-Aggregate-Auth /
//      X-Transcend-Version / XML content type / init body shape
//       -> aggregate_auth_init_and_reply_success_round_trip
//   M3 the `<opaque>` is not echoed verbatim (dropped / re-escaped / altered)
//       -> aggregate_auth_init_and_reply_success_round_trip
//   M4 the credentials are not XML-escaped on the wire, or retained after the
//      login (Debug leakage)
//       -> password_is_xml_escaped_on_the_wire_and_never_leaks
//   M5 a session-token / success id without a webvpn cookie is not accepted
//       -> aggregate_auth_success_via_session_token
//   M6 an `auth_id="error"` / `<error>` node is swallowed as success
//       -> aggregate_auth_rejection_error_node_is_login_rejected,
//          aggregate_auth_init_error_is_login_rejected
//   M7 a SAML redirect / steering page is treated as login success
//       -> aggregate_auth_saml_redirect_is_saml_required
//   M8 a non-XML reply (HTML) is treated as login success
//       -> aggregate_auth_reply_non_xml_is_login_rejected
//   M9 the 404 init (UA rejected / XML channel disabled) does NOT fall back
//      to the form flow
//       -> aggregate_auth_init_404_falls_back_to_form,
//          wrong_ua_closes_xml_channel_and_falls_back_to_form
//   M10 a non-404 init failure is silently swallowed into the form fallback
//       (only 404 is the "channel disabled" signature)
//       -> aggregate_auth_non_2xx_init_is_login_rejected
//   M11 the auth-reply is sent on a NEW connection instead of reusing the
//       init's keep-alive connection
//       -> every success test (the fake reads the reply on the SAME
//          connection as the init; a new connection dies on the empty read)
//   M12 the UA default is hardcoded / not platform-adaptive
//       -> default_user_agent_is_the_platform_anyconnect_identity
//   M13 the caller cannot override the UA per connection
//       -> wrong_ua_closes_xml_channel_and_falls_back_to_form,
//          exact_platform_ua_opens_the_xml_channel

use exv_vpn_cstp::connector::TrustPolicy;
use exv_vpn_cstp::webvpn::{LoginError, WebvpnLogin, default_user_agent};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Embedded test PKI. The same deterministic material family as the P41-T suite
// (self-signed ECDSA P-256 leaf certs that are their own roots) is embedded
// HERE per the plan's rule — the frozen tls_bootstrap.rs private constants are
// never reused or moved:
//   VPN_CERT -> SAN DNS:vpn.example.test (the "valid" aggregate gateway)
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

fn vpn_material() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    (parse_cert(VPN_CERT_PEM), parse_key(VPN_KEY_PEM))
}

fn root_store_with(cert: &CertificateDer<'static>) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).expect("add injected test root");
    roots
}

// ---------------------------------------------------------------------------
// The measured aggregate-auth documents (vpn-ct.ecnu.edu.cn probe, 2026-08-15)
// ---------------------------------------------------------------------------

/// The MEASURED init response shape (2026-08-15 probe, HTTP 200): an
/// `auth-request` carrying the `<opaque>` block (VERBATIM-echoed into the
/// auth-reply), the username/password form and the `group_list` select with
/// `ECNU` selected.
const MEASURED_AUTH_REQUEST_XML: &str = r#"<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<opaque is-for="sg">
<tunnel-group>vpn-ct</tunnel-group>
<aggauth-handle>7661108704527115802</aggauth-handle>
<auth-method>single-sign-on-v2</auth-method>
<group-alias>ECNU</group-alias>
<config-hash>1786440667230</config-hash>
</opaque>
<auth id="main">
<form>
<input type="text" name="username"/>
<input type="password" name="password"/>
<select name="group_list"><option selected="true">ECNU</option></select>
</form>
</auth>
</config-auth>"#;

/// The success reply: `auth_id="success"` + a `<session-token>` (the
/// aggregate-auth v2 success credential).
const SUCCESS_SESSION_TOKEN_XML: &str = r#"<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="success">
<session-token>sess-tok-42</session-token>
</auth>
</config-auth>"#;

/// The success reply: `auth_id="success"` with NO session token (the cookie
/// then comes from the response's `Set-Cookie: webvpn=`).
const SUCCESS_AUTH_ID_XML: &str = r#"<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="success">
</auth>
</config-auth>"#;

/// The rejection reply: `auth_id="error"` + an `<error>` node (the rejection
/// detail text).
const ERROR_XML: &str = r#"<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="error">
<message>Login denied</message>
</auth>
<error>auth_rejected</error>
</config-auth>"#;

/// A challenge auth-request: the username/password form plus a
/// `secondary_password` field (the second-password / OTP interaction the MVP
/// honestly does not support).
const CHALLENGE_XML: &str = r#"<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="main">
<form>
<input type="text" name="username"/>
<input type="password" name="password"/>
<input type="password" name="secondary_password"/>
</form>
</auth>
</config-auth>"#;

/// A group-select-only auth-request (no credentials): the interaction the
/// XML channel cannot serve in the MVP — the form channel takes over.
const GROUP_SELECT_ONLY_XML: &str = r#"<config-auth client="vpn" type="auth-request" aggregate-auth-version="2">
<auth id="main">
<form>
<select name="group_list"><option selected="true">ECNU</option></select>
</form>
</auth>
</config-auth>"#;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

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

/// The request head (up to `\r\n\r\n`) of a captured request.
fn request_head(request: &[u8]) -> String {
    let end = find_header_end(request).unwrap_or(request.len());
    String::from_utf8_lossy(&request[..end]).into_owned()
}

/// The request body of a captured request (after `\r\n\r\n`).
fn request_body(request: &[u8]) -> String {
    let end = find_header_end(request).unwrap_or(request.len());
    String::from_utf8_lossy(&request[end..]).into_owned()
}

/// Read an HTTP request head (up to `\r\n\r\n`).
async fn read_request_head<R: AsyncRead + Unpin>(read: &mut R) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match tokio::io::AsyncReadExt::read(read, &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                request.extend_from_slice(&buf[..n]);
                if find_header_end(&request).is_some() || request.len() > 16 * 1024 {
                    break;
                }
            }
        }
    }
    request
}

/// Read an HTTP request head plus the Content-Length-declared body (the
/// aggregate-auth POSTs and the form POST carry a body; the logon GET has
/// none, so a body-less request must NOT block the read).
async fn read_request_with_body<R: AsyncRead + Unpin>(read: &mut R) -> Vec<u8> {
    let mut request = read_request_head(read).await;
    let head = request_head(&request);
    let Some(want) = header_value(&head, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
    else {
        return request;
    };
    let head_end = find_header_end(&request).unwrap_or(request.len());
    let mut buf = [0u8; 512];
    while request.len().saturating_sub(head_end) < want {
        match tokio::io::AsyncReadExt::read(read, &mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                request.extend_from_slice(&buf[..n]);
                if request.len() > 16 * 1024 {
                    break;
                }
            }
        }
    }
    request
}

/// Write a full XML response with an exact `Content-Length` and
/// `Connection: keep-alive` — the aggregate-auth transport (the measured 200
/// is NOT chunked).
async fn write_xml_response<S: AsyncWrite + Unpin>(
    write: &mut S,
    status: &str,
    body: &str,
) {
    let out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{body}",
        body.len()
    );
    let _ = tokio::io::AsyncWriteExt::write_all(write, out.as_bytes()).await;
}

/// Write the plain 404 the UA gate serves: the MEASURED "XML channel
/// disabled" signature (wrong UA / xmlpost unsupported).
async fn write_plain_404<S: AsyncWrite + Unpin>(write: &mut S) {
    let out = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    let _ = tokio::io::AsyncWriteExt::write_all(write, out.as_bytes()).await;
}

/// Write a full HTML response with NO Content-Length and NO
/// Transfer-Encoding, then let the caller close — the MEASURED logon.html GET
/// transport (implicit close).
async fn write_implicit_close_response<S: AsyncWrite + Unpin>(
    write: &mut S,
    status: &str,
    set_cookies: &[&str],
    body: &str,
) {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nKeep-Alive: timeout=5, max=100\r\nConnection: keep-alive\r\n"
    );
    for cookie in set_cookies {
        out.push_str("Set-Cookie: ");
        out.push_str(cookie);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.push_str(body);
    let _ = tokio::io::AsyncWriteExt::write_all(write, out.as_bytes()).await;
}

/// Write the form-flow credential-POST reply (chunked, the measured POST
/// transport) carrying the webvpn cookie.
async fn write_form_reply<S: AsyncWrite + Unpin>(write: &mut S, cookie: &str) {
    let out = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: webvpn={cookie}; path=/; secure\r\n\r\n0\r\n\r\n"
    );
    let _ = tokio::io::AsyncWriteExt::write_all(write, out.as_bytes()).await;
}

/// The measured-shape logon.html form for the FALLBACK channel.
fn logon_html(csrf_token: &str) -> String {
    format!(
        "<html><body><form action=\"/+webvpn+/index.html\" method=\"post\">\n\
         <input type=\"hidden\" name=\"tgroup\" value=\"\"/>\n\
         <input type=\"hidden\" name=\"next\" value=\"\"/>\n\
         <input type=\"hidden\" name=\"tgcookieset\" value=\"\"/>\n\
         <input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_token}\"/>\n\
         <input type=\"text\" name=\"username\"/>\n\
         <input type=\"password\" name=\"password\"/>\n\
         <select name=\"group_list\">\n\
         <option selected=\"selected\" value=\"vpn-ct\">vpn-ct</option>\n\
         </select>\n\
         <input type=\"submit\" name=\"Login\" value=\"Logon\"/>\n\
         </form></body></html>"
    )
}

// ---------------------------------------------------------------------------
// The fake aggregate gateway (loopback TLS server with the embedded certs)
// ---------------------------------------------------------------------------

/// What the fake aggregate gateway observes from the client.
struct CapturedAggregate {
    /// The raw aggregate-auth init POST (head + body).
    init_request: Vec<u8>,
    /// The `User-Agent` the init POST carried.
    init_ua: Option<String>,
    /// The HTTP status the gateway answered to the init.
    init_status: u16,
    /// The raw aggregate-auth auth-reply POST (head + body; empty when the
    /// exchange never reached the reply — e.g. the fallback path).
    reply_request: Vec<u8>,
    /// The auth-reply XML body (head-stripped) — the opaque-echo / credential
    /// assertion surface.
    reply_body: String,
    /// The raw fallback-channel logon GET (empty when the XML channel was
    /// used end-to-end).
    form_get_request: Vec<u8>,
    /// The raw fallback-channel form POST (empty when the XML channel was
    /// used end-to-end).
    form_post_request: Vec<u8>,
}

/// The configured reply to the aggregate-auth INIT probe.
#[derive(Clone, Copy, Debug)]
enum InitReply {
    /// The MEASURED auth-request shape (opaque + username/password +
    /// group_list) — the normal school-gateway reply.
    AuthRequest,
    /// An auth-request WITHOUT credentials (group-select-only): the XML
    /// channel cannot serve it — the form channel takes over.
    GroupSelectOnly,
    /// An auth-request with a challenge/secondary field (2FA, unsupported).
    Challenge,
    /// A session-token in the init (the gateway logged the init in directly).
    InstantSuccess,
    /// `auth_id="error"` + `<error>` node (the constant `ERROR_XML`).
    Error,
    /// A 200 HTML page — the "channel disabled" shape.
    HtmlPage,
    /// A non-2xx status (only 404 is the fallback signature).
    Status(&'static str, &'static str),
}

/// The configured outcome of the aggregate-auth AUTH-REPLY.
#[derive(Clone, Copy, Debug)]
enum ReplyOutcome {
    /// `auth_id="success"` + `Set-Cookie: webvpn=<v>`.
    SuccessCookie(&'static str),
    /// `auth_id="success"` + `<session-token>` (no Set-Cookie).
    SuccessSessionToken,
    /// `auth_id="error"` + `<error>` node (the constant `ERROR_XML`).
    Error,
    /// A 3xx redirect to the SAML ACS.
    SamlRedirect,
    /// A 200 HTML meta-refresh page steering to the SAML ACS.
    SamlMetaRefresh,
    /// A 200 HTML (non-XML) body.
    HtmlBody,
    /// A 200 auth-request re-ask (credentials not accepted in one round).
    ReAsk,
    /// A non-2xx status.
    Status(&'static str, &'static str),
}

/// The configured gateway behavior: the UA gate (which UA opens the XML
/// channel), the init reply, the auth-reply outcome, and whether the form
/// channel exists (the fallback path).
struct AggregateGateway {
    /// The `User-Agent` that opens the XML channel; any other UA gets 404 on
    /// the init (the MEASURED UA gate). `None` -> the XML channel is closed
    /// for EVERY UA.
    accepted_ua: Option<&'static str>,
    /// The reply to the aggregate-auth init probe.
    init_reply: InitReply,
    /// The outcome of the aggregate-auth auth-reply exchange.
    reply_outcome: ReplyOutcome,
    /// Whether the form-channel endpoints (`/+CSCOE+/logon.html` GET /
    /// `/+webvpn+/index.html` POST) are served — the fallback path.
    serve_form: bool,
}

/// Write the configured init reply and return the status it was served with.
async fn serve_init_reply<S: AsyncWrite + Unpin>(
    reply: InitReply,
    write: &mut S,
) -> u16 {
    match reply {
        InitReply::AuthRequest => {
            write_xml_response(write, "200 OK", MEASURED_AUTH_REQUEST_XML).await;
            200
        }
        InitReply::GroupSelectOnly => {
            write_xml_response(write, "200 OK", GROUP_SELECT_ONLY_XML).await;
            200
        }
        InitReply::Challenge => {
            write_xml_response(write, "200 OK", CHALLENGE_XML).await;
            200
        }
        InitReply::InstantSuccess => {
            write_xml_response(write, "200 OK", SUCCESS_SESSION_TOKEN_XML).await;
            200
        }
        InitReply::Error => {
            write_xml_response(write, "200 OK", ERROR_XML).await;
            200
        }
        InitReply::HtmlPage => {
            let body = "<html><body>login</body></html>";
            let out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = tokio::io::AsyncWriteExt::write_all(write, out.as_bytes()).await;
            200
        }
        InitReply::Status(status_line, body) => {
            write_xml_response(write, status_line, body).await;
            status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(200)
        }
    }
}

/// Write the configured auth-reply outcome.
async fn serve_reply_outcome<S: AsyncWrite + Unpin>(
    outcome: ReplyOutcome,
    write: &mut S,
) {
    match outcome {
        ReplyOutcome::SuccessCookie(cookie) => {
            let out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nSet-Cookie: webvpn={cookie}; path=/; secure\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{SUCCESS_AUTH_ID_XML}",
                SUCCESS_AUTH_ID_XML.len()
            );
            let _ = tokio::io::AsyncWriteExt::write_all(write, out.as_bytes()).await;
        }
        ReplyOutcome::SuccessSessionToken => {
            write_xml_response(write, "200 OK", SUCCESS_SESSION_TOKEN_XML).await;
        }
        ReplyOutcome::Error => {
            write_xml_response(write, "200 OK", ERROR_XML).await;
        }
        ReplyOutcome::SamlRedirect => {
            let out = "HTTP/1.1 302 Found\r\nLocation: https://idp.example.test/+CSCOE+/saml/acs/start?tgname=vpn-ct\r\nContent-Length: 0\r\n\r\n";
            let _ = tokio::io::AsyncWriteExt::write_all(write, out.as_bytes()).await;
        }
        ReplyOutcome::SamlMetaRefresh => {
            let body = "<html><head><meta http-equiv=\"refresh\" content=\"0; url=https://idp.example.test/+CSCOE+/saml/acs/start\"></head><body>saml</body></html>";
            let out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = tokio::io::AsyncWriteExt::write_all(write, out.as_bytes()).await;
        }
        ReplyOutcome::HtmlBody => {
            let body = "<html><body>login</body></html>";
            let out = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = tokio::io::AsyncWriteExt::write_all(write, out.as_bytes()).await;
        }
        ReplyOutcome::ReAsk => {
            write_xml_response(write, "200 OK", MEASURED_AUTH_REQUEST_XML).await;
        }
        ReplyOutcome::Status(status_line, body) => {
            write_xml_response(write, status_line, body).await;
        }
    }
}

/// Run a real local TLS aggregate gateway (loopback) that implements the
/// measured UA gate and serves BOTH channels:
///
/// * the aggregate-auth XML channel on `POST /` — the init (checked against
///   `accepted_ua`; a rejected UA gets the measured 404) and, when the init
///   opens the channel, the auth-reply on the SAME keep-alive connection;
/// * the form channel on `GET /+CSCOE+/logon.html` +
///   `POST /+webvpn+/index.html` when `serve_form` is set (the fallback).
///
/// The captured exchanges are reported through the oneshot channel. The
/// client connects with `TrustPolicy::TestRoots` so the handshake is verified
/// for real.
#[allow(
    clippy::too_many_lines,
    reason = "one coherent fake gateway: the UA gate, the init/reply exchanges on one keep-alive connection, the fallback form exchanges, the capture channel, and every reply variant"
)]
async fn run_aggregate_gateway(
    gateway: AggregateGateway,
) -> (SocketAddr, oneshot::Receiver<CapturedAggregate>) {
    const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
    let (cert, key) = vpn_material();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind aggregate gateway");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("build server config from embedded cert");
        let acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_cfg)));
        let mut capture = CapturedAggregate {
            init_request: Vec::new(),
            init_ua: None,
            init_status: 0,
            reply_request: Vec::new(),
            reply_body: String::new(),
            form_get_request: Vec::new(),
            form_post_request: Vec::new(),
        };

        // Accept the client's connections and dispatch by request. The
        // aggregate-auth XML channel runs init + auth-reply on ONE keep-alive
        // connection (the C++ production behavior); the form fallback runs
        // its two exchanges on fresh connections.
        loop {
            let (tcp, _peer) =
                match tokio::time::timeout(CONNECTION_TIMEOUT, listener.accept()).await {
                    Ok(Ok(x)) => x,
                    _ => {
                        let _ = tx.send(capture);
                        return;
                    }
                };
            let stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(_) => {
                    let _ = tx.send(capture);
                    return;
                }
            };
            let (mut read_half, mut write_half) = tokio::io::split(stream);
            let request = read_request_with_body(&mut read_half).await;
            let head = request_head(&request);
            let body = request_body(&request);

            if head.starts_with("POST / HTTP/1.1")
                && header_value(&head, "content-type")
                    .is_some_and(|ct| ct.to_ascii_lowercase().contains("application/xml"))
            {
                if body.contains("type=\"init\"") {
                    // The aggregate-auth init probe.
                    capture.init_request = request;
                    capture.init_ua = header_value(&head, "user-agent");
                    // `accepted_ua: None` closes the XML channel for EVERY
                    // UA (the measured 404 signature).
                    let ua_opens_channel = gateway
                        .accepted_ua
                        .is_some_and(|accepted| capture.init_ua.as_deref() == Some(accepted));
                    if !ua_opens_channel {
                        // The MEASURED UA gate: any non-AnyConnect-platform UA
                        // is refused with 404 — the login falls back to the
                        // form flow on fresh connections.
                        capture.init_status = 404;
                        write_plain_404(&mut write_half).await;
                        continue;
                    }
                    capture.init_status = serve_init_reply(gateway.init_reply, &mut write_half)
                        .await;
                    match gateway.init_reply {
                        // The client sends the auth-reply on the SAME
                        // connection (keep-alive): a client that opens a NEW
                        // connection for the reply dies on the empty read
                        // below.
                        InitReply::AuthRequest => {}
                        // The engine cannot serve these interactions on the
                        // XML channel (no username/password form / the
                        // channel is not actually open): it FALLS BACK to the
                        // form flow on fresh connections.
                        InitReply::GroupSelectOnly | InitReply::HtmlPage => continue,
                        // The flow ends with the init exchange (error /
                        // challenge / instant success / non-2xx): the engine
                        // returns without another request.
                        InitReply::Challenge
                        | InitReply::InstantSuccess
                        | InitReply::Error
                        | InitReply::Status(_, _) => {
                            let _ = tx.send(capture);
                            return;
                        }
                    }
                    let reply_request = read_request_with_body(&mut read_half).await;
                    capture.reply_request = reply_request;
                    capture.reply_body = request_body(&capture.reply_request);
                    serve_reply_outcome(gateway.reply_outcome, &mut write_half).await;
                    let _ = tx.send(capture);
                    return;
                }
                // A standalone auth-reply without a captured init.
                capture.reply_request = request;
                capture.reply_body = body;
                serve_reply_outcome(gateway.reply_outcome, &mut write_half).await;
                let _ = tx.send(capture);
                return;
            }

            if head.starts_with("GET /+CSCOE+/logon.html HTTP/1.1") {
                // The form fallback channel.
                if !gateway.serve_form {
                    write_plain_404(&mut write_half).await;
                    let _ = tx.send(capture);
                    return;
                }
                capture.form_get_request = request;
                let csrf_token = "7788a917b493948c9c787348e6549d";
                write_implicit_close_response(
                    &mut write_half,
                    "200 OK",
                    &[
                        "webvpnlogin=1; path=/; secure",
                        "webvpnLang=en; path=/; secure",
                    ],
                    &logon_html(csrf_token),
                )
                .await;
                continue;
            }

            if head.starts_with("POST /+webvpn+/index.html HTTP/1.1") {
                // The form fallback credential POST.
                capture.form_post_request = request;
                write_form_reply(&mut write_half, "form-cookie-123").await;
                let _ = tx.send(capture);
                return;
            }

            let _ = tx.send(capture);
            return;
        }
    });
    (addr, rx)
}

// ---------------------------------------------------------------------------
// The fixed tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn aggregate_auth_init_and_reply_success_round_trip() {
    // The PRIMARY channel end-to-end: init POST / (init XML + the platform
    // AnyConnect UA + X-Aggregate-Auth + X-Transcend-Version + keep-alive) ->
    // the MEASURED auth-request -> auth-reply POST / on the SAME connection
    // (the opaque echoed VERBATIM + the XML-escaped credentials +
    // group-select ECNU) -> success via `Set-Cookie: webvpn=`. A mutant that
    // skips the XML channel, sends the init without the UA/aggregate headers,
    // drops or alters the opaque echo, or opens a NEW connection for the
    // auth-reply dies here.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::SuccessCookie("abc123xyz"),
        serve_form: false,
    })
    .await;

    let login = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"p@ss:w1rd!",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect("the aggregate-auth XML flow succeeds");

    let captured = captured.await.expect("the fake gateway observed the login");
    assert_eq!(
        captured.init_status, 200,
        "the exact AnyConnect platform UA opens the XML channel (HTTP 200)"
    );
    assert!(
        captured.form_get_request.is_empty() && captured.form_post_request.is_empty(),
        "a successful XML-channel login never touches the form channel"
    );

    // The init request shape.
    let init_head = request_head(&captured.init_request);
    let init_body = request_body(&captured.init_request);
    assert_eq!(
        init_head.lines().next(),
        Some("POST / HTTP/1.1"),
        "the init is a POST to / (the aggregate-auth endpoint)"
    );
    assert_eq!(
        header_value(&init_head, "host")
            .as_deref()
            .map(|h| h.split(':').next().unwrap_or_default()),
        Some("vpn.example.test"),
        "Host must be the configured hostname"
    );
    assert_eq!(
        captured.init_ua.as_deref(),
        Some("AnyConnect Win_x86_64 4.10.05095"),
        "the caller-passed User-Agent is the client name on the wire"
    );
    assert_eq!(
        header_value(&init_head, "x-aggregate-auth").as_deref(),
        Some("1"),
        "the init carries X-Aggregate-Auth: 1"
    );
    assert_eq!(
        header_value(&init_head, "x-transcend-version").as_deref(),
        Some("1"),
        "the init carries X-Transcend-Version: 1"
    );
    assert_eq!(
        header_value(&init_head, "content-type").as_deref(),
        Some("application/xml; charset=utf-8"),
        "the init body is XML"
    );
    assert_eq!(
        header_value(&init_head, "connection").as_deref(),
        Some("keep-alive"),
        "the init requests a keep-alive connection (init + reply on one connection)"
    );
    assert!(
        header_value(&init_head, "content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|len| len == init_body.len()),
        "Content-Length must match the init body length"
    );
    assert!(
        init_body.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
            && init_body.contains(
                "<config-auth client=\"vpn\" type=\"init\" aggregate-auth-version=\"2\">"
            ),
        "the init body is the aggregate-auth init XML"
    );
    assert!(
        init_body.contains("<version who=\"vpn\">AnyConnect Win_x86_64 4.10.05095</version>"),
        "the init carries the client name in <version who=\"vpn\">"
    );
    assert!(
        init_body.contains("<device-id>exv-native</device-id>"),
        "the init carries a stable device-id"
    );
    assert!(
        init_body.contains("<group-access>https://vpn.example.test/</group-access>"),
        "the init carries the gateway group-access URL"
    );
    assert!(
        init_body.contains("<auth-method>single-sign-on-v2</auth-method>"),
        "the init advertises the single-sign-on-v2 capability"
    );

    // The auth-reply request shape (same connection, same UA).
    let reply_head = request_head(&captured.reply_request);
    let reply_body = &captured.reply_body;
    assert_eq!(
        reply_head.lines().next(),
        Some("POST / HTTP/1.1"),
        "the auth-reply is a POST to / (the same aggregate-auth endpoint)"
    );
    assert_eq!(
        header_value(&reply_head, "user-agent").as_deref(),
        Some("AnyConnect Win_x86_64 4.10.05095"),
        "the auth-reply carries the same client name"
    );
    assert_eq!(
        header_value(&reply_head, "x-aggregate-auth").as_deref(),
        Some("1"),
        "the auth-reply carries X-Aggregate-Auth: 1"
    );
    assert!(
        reply_body.contains(
            "<config-auth client=\"vpn\" type=\"auth-reply\" aggregate-auth-version=\"2\">"
        ),
        "the auth-reply body is the aggregate-auth auth-reply XML"
    );
    assert!(
        reply_body.contains("<opaque is-for=\"sg\">"),
        "the opaque element is echoed into the auth-reply"
    );
    assert!(
        reply_body.contains("<aggauth-handle>7661108704527115802</aggauth-handle>")
            && reply_body.contains("<tunnel-group>vpn-ct</tunnel-group>")
            && reply_body.contains("<config-hash>1786440667230</config-hash>"),
        "the opaque inner content round-trips VERBATIM"
    );
    assert!(
        reply_body.contains("<username>alice</username>"),
        "the username lands in <auth><username>"
    );
    assert!(
        reply_body.contains("<password>p@ss:w1rd!</password>"),
        "the password lands in <auth><password>"
    );
    assert!(
        reply_body.contains("<group-select>ECNU</group-select>"),
        "the parsed group_list selected value (ECNU) is echoed as <group-select>"
    );

    assert_eq!(
        login.cookie.as_str(),
        "abc123xyz",
        "the webvpn cookie from the reply's Set-Cookie is captured"
    );
    assert!(
        !login.saml_detected,
        "a plain success is not a SAML login"
    );
}

#[tokio::test]
async fn aggregate_auth_success_via_session_token() {
    // `auth_id="success"` + `<session-token>` WITHOUT any Set-Cookie: the
    // session token IS the credential (`webvpn=<token>`), mirroring the C++
    // `auth_cookie_ = "webvpn=" + token` construction. A mutant that requires
    // a Set-Cookie webvpn — or drops the token — dies here.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::SuccessSessionToken,
        serve_form: false,
    })
    .await;

    let login = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect("a session-token success is a login success");

    let captured = captured.await.expect("the fake gateway observed the login");
    assert_eq!(
        login.cookie.as_str(),
        "sess-tok-42",
        "the <session-token> value is the webvpn credential"
    );
    assert_eq!(captured.init_status, 200);
    assert!(
        captured.form_get_request.is_empty() && captured.form_post_request.is_empty(),
        "the XML channel succeeded — no form fallback"
    );
}

#[tokio::test]
async fn aggregate_auth_rejection_error_node_is_login_rejected() {
    // `auth_id="error"` + `<error>` node: a typed LoginRejected carrying the
    // error text as diagnostic detail — never login success. A mutant that
    // swallows the rejection as success dies here.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::Error,
        serve_form: false,
    })
    .await;

    let err = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"wrong-password",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect_err("an aggregate-auth error response must not be login success");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "the XML-channel rejection surfaces as typed LoginRejected"
    );
    assert_eq!(
        err.a0_result(),
        Some("auth_rejected"),
        "the <error> node text is the diagnostic detail"
    );
    let _ = captured.await;
    let err_debug = format!("{err:?}");
    assert!(
        !err_debug.contains("wrong-password"),
        "LoginError Debug output must never leak the password"
    );
}

#[tokio::test]
async fn aggregate_auth_saml_redirect_is_saml_required() {
    // A 3xx `Location` pointing at `+CSCOE+/saml` is SAML steering
    // (CS-AUTH-04) — never login success, never a cookie capture.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::SamlRedirect,
        serve_form: false,
    })
    .await;

    let err = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect_err("a SAML redirect must not be login success");
    assert!(
        matches!(err, LoginError::SamlRequired),
        "a 3xx to +CSCOE+/saml surfaces as typed SamlRequired"
    );
    let _ = captured.await;
}

#[tokio::test]
async fn aggregate_auth_saml_meta_refresh_is_saml_required() {
    // The body variant: a meta-refresh page steering to the SAML ACS is SAML
    // detection even when the reply body is not XML.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::SamlMetaRefresh,
        serve_form: false,
    })
    .await;

    let err = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect_err("a SAML meta-refresh page must not be login success");
    assert!(
        matches!(err, LoginError::SamlRequired),
        "the SAML steering page surfaces as typed SamlRequired"
    );
    let _ = captured.await;
}

#[tokio::test]
async fn aggregate_auth_reply_non_xml_is_login_rejected() {
    // The channel was open for the init but the auth-reply came back as HTML
    // (not config-auth XML): the submission was not accepted — typed
    // LoginRejected, never success.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::HtmlBody,
        serve_form: false,
    })
    .await;

    let err = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect_err("a non-XML auth-reply must not be login success");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "a non-XML reply surfaces as typed LoginRejected"
    );
    let _ = captured.await;
}

#[tokio::test]
async fn aggregate_auth_re_ask_is_login_rejected() {
    // The reply is an auth-request AGAIN (a re-ask): the one-shot submission
    // was not accepted in a single round — typed LoginRejected, never a
    // success and never a silent second attempt with the same credentials.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::ReAsk,
        serve_form: false,
    })
    .await;

    let err = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect_err("a re-ask must not be login success");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "an auth-request re-ask surfaces as typed LoginRejected"
    );
    let _ = captured.await;
}

#[tokio::test]
async fn aggregate_auth_non_2xx_reply_is_login_rejected() {
    // A non-2xx auth-reply status is a rejected login with the status as
    // diagnostic detail — never a success.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::Status("500 Internal Server Error", "boom"),
        serve_form: false,
    })
    .await;

    let err = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect_err("a non-2xx auth-reply must not be login success");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "a non-2xx auth-reply surfaces as typed LoginRejected"
    );
    assert_eq!(
        err.a0_result(),
        Some("500"),
        "the rejected HTTP status is the diagnostic detail"
    );
    let _ = captured.await;
}

#[tokio::test]
async fn aggregate_auth_init_error_is_login_rejected() {
    // The init itself answers `auth_id="error"`: a typed LoginRejected with
    // the error text — the XML channel is open, the gateway rejected the
    // exchange; NOT a form-channel fallback.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::Error,
        reply_outcome: ReplyOutcome::SuccessCookie("unused"),
        serve_form: false,
    })
    .await;

    let err = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect_err("an error init must not be login success");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "the init rejection surfaces as typed LoginRejected"
    );
    assert_eq!(
        err.a0_result(),
        Some("auth_rejected"),
        "the <error> node text is the diagnostic detail"
    );
    let _ = captured.await;
}

#[tokio::test]
async fn aggregate_auth_init_html_page_falls_back_to_form() {
    // The init probe answers 200 with an HTML page (not config-auth XML): the
    // XML channel is not actually open — the login falls back to the form
    // channel, which succeeds.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::HtmlPage,
        reply_outcome: ReplyOutcome::SuccessCookie("unused"),
        serve_form: true,
    })
    .await;

    let login = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect("a non-XML init probe falls back to the form channel");

    let captured = captured.await.expect("the fake gateway observed the login");
    assert_eq!(
        login.cookie.as_str(),
        "form-cookie-123",
        "the form channel's webvpn cookie is captured on the fallback path"
    );
    assert_eq!(captured.init_status, 200);
    assert!(
        !captured.form_get_request.is_empty() && !captured.form_post_request.is_empty(),
        "the form channel ran after the non-XML init probe"
    );
}

#[tokio::test]
async fn aggregate_auth_group_select_only_init_falls_back_to_form() {
    // The init is an auth-request WITHOUT credentials (a group-selection-only
    // form): the XML channel cannot serve it in the MVP — the login falls
    // back to the form channel (which carries the group_list select too).
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::GroupSelectOnly,
        reply_outcome: ReplyOutcome::SuccessCookie("unused"),
        serve_form: true,
    })
    .await;

    let login = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect("a group-select-only init falls back to the form channel");

    let captured = captured.await.expect("the fake gateway observed the login");
    assert_eq!(
        login.cookie.as_str(),
        "form-cookie-123",
        "the form channel's webvpn cookie is captured on the fallback path"
    );
    assert!(
        captured.reply_request.is_empty() && captured.reply_body.is_empty(),
        "no auth-reply is sent for a form the XML channel cannot serve"
    );
    assert!(
        !captured.form_get_request.is_empty() && !captured.form_post_request.is_empty(),
        "the form flow ran after the group-select-only init"
    );
}

#[tokio::test]
async fn aggregate_auth_init_session_token_is_instant_success() {
    // The init itself returns a `<session-token>` (the gateway logged the
    // init in directly — e.g. a resumed session): the token IS the webvpn
    // credential, and no auth-reply round-trip happens.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::InstantSuccess,
        reply_outcome: ReplyOutcome::SuccessCookie("unused"),
        serve_form: false,
    })
    .await;

    let login = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect("an init session-token is a login success");

    let captured = captured.await.expect("the fake gateway observed the login");
    assert_eq!(
        login.cookie.as_str(),
        "sess-tok-42",
        "the init <session-token> is the webvpn credential"
    );
    assert!(
        captured.reply_request.is_empty() && captured.reply_body.is_empty(),
        "no auth-reply round-trip happens after an init success"
    );
}

#[tokio::test]
async fn aggregate_auth_init_404_falls_back_to_form() {
    // The MEASURED "XML channel disabled" signature: the init probe answers
    // 404 for every UA — the login FALLS BACK to the form flow on fresh
    // connections and succeeds there.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: None,
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::SuccessCookie("unused"),
        serve_form: true,
    })
    .await;

    let login = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect("a 404 init probe falls back to the form channel");

    let captured = captured.await.expect("the fake gateway observed the login");
    assert_eq!(
        captured.init_status, 404,
        "the XML channel was refused with the measured 404"
    );
    assert_eq!(
        login.cookie.as_str(),
        "form-cookie-123",
        "the form channel's webvpn cookie is captured on the fallback path"
    );
    assert!(
        !captured.form_get_request.is_empty() && !captured.form_post_request.is_empty(),
        "the form flow ran after the 404"
    );
    assert!(
        captured.reply_request.is_empty() && captured.reply_body.is_empty(),
        "no auth-reply is sent when the init is refused"
    );
}

#[tokio::test]
async fn wrong_ua_closes_xml_channel_and_falls_back_to_form() {
    // The MEASURED UA gate (probe matrix 2026-08-15): the XML channel opens
    // ONLY for the exact AnyConnect platform UAs — a platform-less
    // `AnyConnect 4.10.03153` is refused with 404 and the login falls back to
    // the form flow. This pins that the caller can PASS a UA per connection
    // (the override parameter) and that a wrong one costs the XML channel.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::SuccessCookie("unused"),
        serve_form: true,
    })
    .await;

    let login = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect 4.10.03153",
    )
    .await
    .expect("a refused UA falls back to the form channel");

    let captured = captured.await.expect("the fake gateway observed the login");
    assert_eq!(
        captured.init_status, 404,
        "the platform-less UA is refused with the measured 404"
    );
    assert_eq!(
        captured.init_ua.as_deref(),
        Some("AnyConnect 4.10.03153"),
        "the caller-passed UA is what went on the wire"
    );
    assert_eq!(
        login.cookie.as_str(),
        "form-cookie-123",
        "the form channel's webvpn cookie is captured on the fallback path"
    );
    assert!(
        !captured.form_get_request.is_empty() && !captured.form_post_request.is_empty(),
        "the form flow ran after the UA-refused 404"
    );
}

#[tokio::test]
async fn exact_platform_ua_opens_the_xml_channel() {
    // The SAME gateway, the SAME credentials, the exact AnyConnect platform
    // UA: the XML channel opens (init 200, auth-reply exchanged) — the
    // inverse of wrong_ua_closes_xml_channel_and_falls_back_to_form, pinning
    // the gate both ways.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::SuccessCookie("abc123xyz"),
        serve_form: true,
    })
    .await;

    let login = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect("the exact AnyConnect platform UA opens the XML channel");

    let captured = captured.await.expect("the fake gateway observed the login");
    assert_eq!(
        captured.init_status, 200,
        "the exact platform UA opens the XML channel"
    );
    assert_eq!(
        login.cookie.as_str(),
        "abc123xyz",
        "the XML channel's webvpn cookie is captured"
    );
    assert!(
        !captured.reply_body.is_empty() && captured.reply_body.contains("type=\"auth-reply\""),
        "the auth-reply was exchanged on the XML channel"
    );
    assert!(
        captured.form_get_request.is_empty() && captured.form_post_request.is_empty(),
        "the form channel was never touched when the XML channel is open"
    );
}

#[tokio::test]
async fn aggregate_auth_challenge_is_two_factor_required() {
    // A challenge/secondary field in the auth-request form (2FA/OTP): honestly
    // unsupported in the MVP — typed TwoFactorRequired, never a login.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::Challenge,
        reply_outcome: ReplyOutcome::SuccessCookie("unused"),
        serve_form: false,
    })
    .await;

    let err = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect_err("a challenge form must not log in");
    assert!(
        matches!(err, LoginError::TwoFactorRequired),
        "a second-password/challenge interaction surfaces as typed TwoFactorRequired"
    );
    let _ = captured.await;
}

#[tokio::test]
async fn aggregate_auth_non_2xx_init_is_login_rejected() {
    // ONLY the 404 is the "XML channel disabled" fallback signature: a 500 on
    // the init probe is a real rejection (the channel answered) — typed
    // LoginRejected with the status detail, NEVER a silent form fallback.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::Status("500 Internal Server Error", "boom"),
        reply_outcome: ReplyOutcome::SuccessCookie("unused"),
        serve_form: true,
    })
    .await;

    let err = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        b"alice",
        b"s3cret",
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect_err("a non-404 init failure must not silently fall back");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "a non-404 init failure surfaces as typed LoginRejected"
    );
    assert_eq!(
        err.a0_result(),
        Some("500"),
        "the rejected HTTP status is the diagnostic detail"
    );
    let captured = captured.await.expect("the fake gateway observed the login");
    assert!(
        captured.form_get_request.is_empty() && captured.form_post_request.is_empty(),
        "the form channel must not run after a non-404 init failure"
    );
}

#[tokio::test]
async fn password_is_xml_escaped_on_the_wire_and_never_leaks() {
    // The credentials are XML-escaped in the auth-reply body (`& < > " '`),
    // never emitted raw — and the engine retains nothing: Debug output of the
    // session and of the typed errors never contains the password.
    let (addr, captured) = run_aggregate_gateway(AggregateGateway {
        accepted_ua: Some("AnyConnect Win_x86_64 4.10.05095"),
        init_reply: InitReply::AuthRequest,
        reply_outcome: ReplyOutcome::SuccessCookie("abc123xyz"),
        serve_form: false,
    })
    .await;

    let username = "al<b&c>d\"e'f";
    let password = "p@ss:w1rd!<&>\"'";
    let login = WebvpnLogin::perform_login_with_user_agent(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&parse_cert(VPN_CERT_PEM)))),
        None,
        username.as_bytes(),
        password.as_bytes(),
        "AnyConnect Win_x86_64 4.10.05095",
    )
    .await
    .expect("login succeeds; the XML-escaped credentials are accepted");

    let captured = captured.await.expect("the fake gateway observed the login");
    assert!(
        captured
            .reply_body
            .contains("<username>al&lt;b&amp;c&gt;d&quot;e&apos;f</username>"),
        "the username is XML-escaped on the wire"
    );
    assert!(
        captured
            .reply_body
            .contains("<password>p@ss:w1rd!&lt;&amp;&gt;&quot;&apos;</password>"),
        "the password is XML-escaped on the wire, never raw"
    );
    assert!(
        !captured.reply_body.contains(password),
        "the raw password must never appear in the auth-reply body"
    );

    let session_debug = format!("{login:?}");
    assert!(
        !session_debug.contains(password),
        "LoginSession Debug output must not retain the password"
    );
    let cookie_debug = format!("{:?}", login.cookie);
    assert!(
        !cookie_debug.contains("abc123xyz"),
        "WebvpnCookie Debug output must be redacted"
    );
}

#[test]
fn default_user_agent_is_the_platform_anyconnect_identity() {
    // The settings default: the platform-appropriate AnyConnect identity with
    // the runtime-adapted architecture (the gateway's UA gate is
    // arch-insensitive — measured probe matrix 2026-08-15).
    let ua = default_user_agent();
    assert!(
        ua.starts_with("AnyConnect "),
        "the default UA is an AnyConnect identity"
    );
    assert!(
        ua.contains(" 4.10.05095"),
        "the default UA carries the pinned AnyConnect version"
    );
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        other => other,
    };
    #[cfg(target_os = "windows")]
    assert_eq!(ua, format!("AnyConnect Win_{arch} 4.10.05095"));
    #[cfg(target_os = "macos")]
    assert_eq!(ua, format!("AnyConnect Darwin_{arch} 4.10.05095"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    assert_eq!(ua, format!("AnyConnect Linux_{arch} 4.10.05095"));
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
