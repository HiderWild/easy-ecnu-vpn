// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV CS-AUTH-01-T: WebVPN login phase (measured form flow: GET
// `/+CSCOE+/logon.html` -> parse -> POST the form ACTION `/+webvpn+/index.html`)
// integration tests for exv-vpn-cstp.
//
// These tests define the exact public API that CS-AUTH-01-I implements in
// `exv_vpn_cstp::webvpn`. The login runs over a REAL TLS connection
// established by the P41 Bootstrap with an injected trust policy
// (`TrustPolicy::TestRoots`, loopback), reproduces the MEASURED gateway flow
// (vpn-ct.ecnu.edu.cn, TLS 222.66.117.109:443, SNI vpn-ct.ecnu.edu.cn,
// 2026-08-15), captures the `Set-Cookie: webvpn=` value into
// `LoginSession.cookie`, and rejects bad credentials / error pages / protocol
// violations as typed errors. The password bytes live only during POST
// construction (one-shot: the caller zeroizes its own plaintext after the
// call, SchoolSecrets pattern) and never appear in Debug output.
//
// Measured gateway facts driving this contract (2026-08-15 probes):
//   * `GET /` -> 200 HTML with `document.location.replace("/+CSCOE+/logon.html")`.
//   * `GET /+CSCOE+/logon.html` -> 200, body delimited by the CONNECTION CLOSE
//     (no Content-Length, no Transfer-Encoding — the gateway CLOSES the
//     connection after this response, implicit close despite a Keep-Alive
//     header), 10KB form; hidden fields
//     `tgroup`(empty)/`next`(empty)/`tgcookieset`(empty)/`csrf_token`
//     (dynamic per request)/`username`/`password`, the `group_list` select
//     (selected value `vpn-ct`, submitted by a browser)/`Login`; form ACTION
//     `/+webvpn+/index.html`.
//   * `POST /+webvpn+/index.html` on a FRESH connection (the GET connection is
//     already closed) with the urlencoded fields -> 200,
//     `Transfer-Encoding: chunked` (the login reader must decode the chunks);
//     on BAD credentials the gateway CLEARS the webvpn cookie
//     (`Set-Cookie: webvpn=; expires=1970`) and the body JS-redirects back to
//     logon.html.
//   * The credential POST carries the cookie jar the gateway's CSRF precheck
//     requires — `Cookie: webvpnlogin=1; CSRFtoken=<csrf_token>;
//     webvpnLang=en` — mirroring the browser: logon.html JS does
//     `document.cookie="CSRFtoken="+csrf_token+"; path=/; secure"` and the
//     server Set-Cookies `webvpnlogin=1` and `webvpnLang=en` on the GET (a
//     browser echoes both). A POST WITHOUT the jar is rejected with the
//     gateway result code `a0=8` — the request NEVER reaches credential
//     evaluation (the real password is never checked; probed 2026-08-15:
//     `a0=8` no cookie, `a0=114` CSRFtoken cookie missing, `a0=115` fields
//     missing, `a0=15` real credential rejection, `a0=16` empty user or
//     password field).
//   * `POST /+CSCOE+/logon` -> 404 (the WRONG endpoint).
//   * The aggregate-auth XML channel (`POST /` + config-auth init XML +
//     `X-Aggregate-Auth`) is the PRIMARY: it opens only for the exact
//     AnyConnect platform UAs. This FORM-ONLY fake answers the probe with 404
//     (the measured "XML channel disabled" signature — wrong UA / xmlpost
//     unsupported) so the login FALLS BACK to the form flow below; the
//     aggregate-auth channel itself is exercised in tests/webvpn_aggregate.rs.
//
// Contract (docs/superpowers/plans/2026-08-15-cstp-authentication-rebuild-plan.md
// leaf CS-AUTH-01, §3.1, refined by the real-gateway measurement above):
//   * The XML channel is probed FIRST on its own connection: `POST /` with
//     the config-auth init XML + the platform default AnyConnect
//     `User-Agent` (the settings default) + `X-Aggregate-Auth: 1` +
//     `X-Transcend-Version: 1`. A FORM-ONLY gateway answers 404 — the
//     measured "XML channel disabled" signature — and the login then runs the
//     two-step form flow on FRESH connections (the pinned shape below).
//   * Two-step form request shape on TWO further connections (measured): GET
//     `/+CSCOE+/logon.html` (Host + SNI = configured hostname) on connection
//     #2, which the gateway CLOSES after the response (implicit close) and
//     which Set-Cookies `webvpnlogin=1` and `webvpnLang=en`, then POST to the
//     parsed form ACTION (`/+webvpn+/index.html`) on a FRESH connection #3
//     with `Host: <hostname>`, the CSRF-precheck cookie jar
//     `Cookie: webvpnlogin=1; CSRFtoken=<csrf_token>; webvpnLang=en` (a POST
//     without it is rejected `a0=8` — measured probe matrix), `Content-Type:
//     application/x-www-form-urlencoded`, a correct Content-Length, the
//     served csrf_token echoed VERBATIM (dynamic per request),
//     `tgroup`/`next`/`tgcookieset` echoed, the percent-encoded
//     `username`/`password`, the `group_list` select's selected value
//     (`vpn-ct` — a browser submits it), and the fixed `Login=Logon` submit
//     value. No `Authorization` header (the form IS the credential exchange).
//   * Cookie capture: `Set-Cookie: webvpn=<value>` (ONLY the webvpn cookie) is
//     captured into `LoginSession.cookie`; a 2xx response WITHOUT it — or with
//     it CLEARED (empty value, the measured bad-credential response) — is NOT
//     login success.
//   * csrf_token REQUIRED: a logon form without the hidden csrf_token field is
//     `LoginError::ProtocolViolation` and NO credential POST is sent.
//   * Implicit-close GET + fresh-connection POST (measured): the fake gateway
//     serves the logon form WITHOUT Content-Length/Transfer-Encoding and
//     CLOSES the connection — the login reader must treat the close (EOF /
//     unexpected-EOF) as the body delimiter, and the credential POST can only
//     go out on a NEW connection (a mutant that reuses the GET connection dies
//     on the EOF write). The credential-POST replies are served
//     `Transfer-Encoding: chunked` (the measured POST transport) so the chunk
//     decoder stays covered.
//   * Rejections: a 2xx page carrying `+CSCOE+/error` or `login error`, and any
//     non-2xx status, surface as `LoginError::LoginRejected` (typed, never
//     swallowed into success). When the rejected response body carries the
//     gateway result code `a0=N`, the code is attached to the rejection's
//     `detail` (read back through `LoginError::a0_result()`) so the acceptance
//     evidence can distinguish `a0=15` (credentials wrong) from `a0=8`/`114`/
//     `115`/`16` (request malformed).
//   * TLS: the login TLS connection is a real Bootstrap connection under the
//     injected trust policy; an untrusted CA and a hostname mismatch are rejected
//     BEFORE any HTTP byte is sent.
//   * Deadline: measured on the injected clock; the login must not roll back
//     before the deadline and must surface a real `LoginError::DeadlineExceeded`
//     after it.
//   * Secrets: the password is one-shot (SchoolSecrets pattern: caller-side
//     plaintext zeroized after the call, `AuthInteraction::send_secret` wipes the
//     vault copy) and Debug output of `LoginSession` / `WebvpnCookie` /
//     `LoginError` never contains the password or the cookie value.
//
// The API CS-AUTH-01-I implements in `exv_vpn_cstp::webvpn`:
//
//   pub struct WebvpnLogin;   // unit type, static entry point
//   impl WebvpnLogin {
//       pub async fn perform_login(
//           host: &str,
//           gateway_addr: SocketAddr,
//           trust: TrustPolicy,
//           deadline: Option<Deadline>,
//           username: &[u8],
//           password: &[u8],
//       ) -> Result<LoginSession, LoginError>;
//   }
//   pub struct LoginSession {
//       pub cookie: WebvpnCookie,
//       pub saml_detected: bool,
//   }
//   pub struct WebvpnCookie { /* opaque */ }
//   impl WebvpnCookie {
//       pub fn as_str(&self) -> &str;   // the raw webvpn cookie value
//   }
//   // WebvpnCookie Debug is redacted (finish_non_exhaustive), like BootstrapSession.
//   pub enum LoginError {
//       TlsFailed(BootstrapError),   // the TLS bootstrap failed (trust/name/etc.)
//       HttpFailed,                  // the HTTP exchange itself failed
//       LoginRejected { detail: Option<String> }, // error page / non-2xx status / cleared
//                                   // or missing webvpn cookie; `detail` = the gateway
//                                   // `a0` result code from the rejected body when it
//                                   // carried one (additive field, diagnostic only)
//       SamlRequired,                // SAML redirect detected (CS-AUTH-04)
//       TwoFactorRequired,           // 2FA/OTP requested (honest unsupported)
//       ProtocolViolation,           // logon form without the REQUIRED csrf_token / form ACTION
//       DeadlineExceeded,            // the injected deadline expired
//   }
//   impl LoginError {
//       pub fn a0_result(&self) -> Option<&str>;   // additive accessor: the gateway
//                                                  // `a0` code on a LoginRejected
//       pub fn login_rejected_with_detail(detail: Option<String>) -> Self; // additive constructor
//   }
//
// Mutants this suite must kill:
//   M1 the webvpn cookie is missing yet login still returns Ok
//       -> success_without_webvpn_cookie_is_not_ok
//   M2 a login error page is swallowed as success
//       -> error_page_csco_e_marker_is_login_rejected,
//          error_page_login_error_marker_is_login_rejected,
//          non_2xx_status_is_login_rejected
//   M3 wrong endpoint path (the legacy `POST /+CSCOE+/logon` instead of the
//      measured GET logon.html -> POST action flow) / raw (unencoded) body /
//      wrong Host / missing form type / hardcoded csrf_token / tgroup fields
//      dropped
//       -> login_gets_logon_form_then_posts_measured_shape
//   M4 password bytes retained or leaked (Debug/trace/error)
//       -> password_secret_zeroized_after_login_vault_pattern
//   M5 TLS verification skipped (always-true verifier)
//       -> untrusted_ca_is_tls_failed, wrong_hostname_is_tls_failed
//   M6 deadline ignored / false rollback
//       -> deadline_is_respected_without_false_rollback
//   M7 a 200 that CLEARS the webvpn cookie (the measured bad-credential
//      signature) treated as success
//       -> cleared_webvpn_cookie_is_login_rejected
//   M8 a logon form without the REQUIRED csrf_token still POSTs / logs in
//       -> logon_form_without_csrf_token_is_protocol_violation
//   M9 a relative form ACTION not resolved against the gateway origin
//       -> relative_form_action_is_resolved_against_gateway_origin
//   M10 a credential POST without the CSRF-precheck cookie jar
//       -> the fake rejects it with the measured a0=8 body (CSRF-precheck
//          semantics), and login_post_without_cookie_jar_is_csrf_rejected
//          pins the typed LoginRejected mapping AND the `a0=8` landing in
//          the error detail (a0_result())

use exv_vpn_cstp::auth::{
    AuthClock, AuthInteraction, AuthProgress, AuthResponse, Secret,
};
use exv_vpn_cstp::connector::{BootstrapError, Deadline, TrustPolicy, VerifyClock};
use exv_vpn_cstp::webvpn::{LoginError, WebvpnLogin};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Embedded test PKI. The same deterministic material family as the P41-T suite
// (self-signed ECDSA P-256 leaf certs that are their own roots) is embedded HERE
// per the plan's rule — the frozen tls_bootstrap.rs private constants are never
// reused or moved:
//   VPN_CERT  -> SAN DNS:vpn.example.test   (the "valid" login gateway)
//   OTHER_CERT-> SAN DNS:other.example.test (hostname-mismatch / untrusted peer)
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

const OTHER_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBrTCCAVSgAwIBAgIUbaSXY9kWbAD4xiB/bvajvDR9wJowCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSb3RoZXIuZXhhbXBsZS50ZXN0MB4XDTI2MDgxMjIwNDE1MFoX
DTM2MDgwOTIwNDE1MFowHTEbMBkGA1UEAwwSb3RoZXIuZXhhbXBsZS50ZXN0MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeFJh2xv2A/nlbBjPMH8JQMb/4zlrqX/2
yjHV78/4sGxngq/yUE+dfa5dkMAQr2GnAIF2L1dWGtpNTWxj8BTWJ6NyMHAwHQYD
VR0OBBYEFAFPe3M6QRGx0b/4vs7mFbYDg8YdMB8GA1UdIwQYMBaAFAFPe3M6QRGx
0b/4vs7mFbYDg8YdMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0RBBYwFIISb3RoZXIu
ZXhhbXBsZS50ZXN0MAoGCCqGSM49BAMCA0cAMEQCIHQ0oDw0g09HCTivuUomKmqo
7OuLuUgHwsXd/WAPP/mFAiBhjMWRWOik9RYsA0bLk/WxS/AarJBp3g+FgiC0V0F5
EA==
-----END CERTIFICATE-----
"#;

const OTHER_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgr/t/WmuPezs4Ze7X
lN7SpJpid5kHNBcp4VT5M50iyjihRANCAAR4UmHbG/YD+eVsGM8wfwlAxv/jOWup
f/bKMdXvz/iwbGeCr/JQT519rl2QwBCvYacAgXYvV1Ya2k1NbGPwFNYn
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

/// The "valid" login-gateway material: a self-signed cert for `vpn.example.test`.
fn vpn_material() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    (parse_cert(VPN_CERT_PEM), parse_key(VPN_KEY_PEM))
}

/// A second peer material: a self-signed cert for `other.example.test`.
fn other_material() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    (parse_cert(OTHER_CERT_PEM), parse_key(OTHER_KEY_PEM))
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

/// An injected, paused monotonic clock (not wall-clock) so the deadline test is
/// deterministic and never sleeps on the wall clock. Serves both the connector
/// `VerifyClock` and the auth `AuthClock` seams.
struct FakeClock {
    now: AtomicU64,
}

impl FakeClock {
    fn at(t: u64) -> Self {
        Self {
            now: AtomicU64::new(t),
        }
    }

    fn advance(&self, by: u64) {
        self.now.fetch_add(by, Ordering::SeqCst);
    }
}

impl VerifyClock for FakeClock {
    fn now_millis(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

impl AuthClock for FakeClock {
    fn now_millis(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// The fake login gateway (loopback TLS server with the embedded certs).
// ---------------------------------------------------------------------------

/// What the fake login gateway observes from the client.
struct CapturedLogin {
    /// The SNI the client sent (None if the handshake never completed).
    sni: Option<String>,
    /// The raw aggregate-auth XML channel probe (`POST /` with config-auth
    /// init XML + `X-Aggregate-Auth`) the client sends FIRST — the PRIMARY
    /// channel, which this FORM-ONLY fake answers 404 (the measured
    /// "XML channel disabled" signature) so the login falls back to the form
    /// flow. Empty when the client skipped the XML channel entirely.
    probe_request: Vec<u8>,
    /// The raw GET `/+CSCOE+/logon.html` request head bytes (empty when the
    /// client aborted before sending anything).
    get_request: Vec<u8>,
    /// The csrf_token the fake gateway embedded in the served logon.html form
    /// (dynamic per request, served once on connection #2), so tests can assert
    /// the client echoes it verbatim into the POST on connection #3.
    csrf_token: String,
    /// The raw POST request bytes, head plus the declared form body (empty
    /// when the client aborted before sending the credential POST).
    post_request: Vec<u8>,
    /// The POST body's `username` field, decoded with the standard
    /// form-urlencoded rules (`+` -> space, `%XX` -> byte) — the round-trip
    /// oracle for the percent-encoding matrix test.
    decoded_username: String,
    /// The POST body's `password` field, decoded with the standard
    /// form-urlencoded rules.
    decoded_password: String,
}

/// The configurable logon.html form the fake gateway serves for the initial
/// GET (probes of the client's form parsing).
enum LogonPage {
    /// The measured login form (2026-08-15 probe): hidden
    /// tgroup/next/tgcookieset/csrf_token, the group_list select (selected
    /// value `vpn-ct` — a browser submits it), action
    /// `/+webvpn+/index.html`, csrf_token dynamic per request.
    Standard,
    /// The same form WITHOUT the hidden csrf_token field (protocol-violation
    /// probe: a front end that issues no CSRF token).
    NoCsrfToken,
    /// The same form with a RELATIVE action (origin-relative resolution
    /// probe).
    RelativeAction,
}

/// The counter backing the dynamic csrf_token (measured gateway: the token
/// changes on every GET of logon.html).
static CSRF_TOKEN_COUNTER: AtomicU64 = AtomicU64::new(0x7788_a917_b493_948c);

/// Build the measured-shape logon.html form for `logon` and return it together
/// with the csrf_token it embeds.
fn logon_html_for(logon: &LogonPage) -> (String, String) {
    let n = CSRF_TOKEN_COUNTER.fetch_add(1, Ordering::SeqCst);
    let csrf_token = format!("{n:032x}");
    let csrf_input = match logon {
        LogonPage::NoCsrfToken => String::new(),
        _ => format!(
            "<input type=\"hidden\" name=\"csrf_token\" value=\"{csrf_token}\"/>\n"
        ),
    };
    let action = match logon {
        LogonPage::RelativeAction => "webvpn/index.html",
        _ => "/+webvpn+/index.html",
    };
    let html = format!(
        "<html><head><script>document.location.replace(\"/+CSCOE+/logon.html\");</script></head>\n\
         <body><form action=\"{action}\" method=\"post\">\n\
         <input type=\"hidden\" name=\"tgroup\" value=\"\"/>\n\
         <input type=\"hidden\" name=\"next\" value=\"\"/>\n\
         <input type=\"hidden\" name=\"tgcookieset\" value=\"\"/>\n\
         {csrf_input}\
         <input type=\"text\" name=\"username\"/>\n\
         <input type=\"password\" name=\"password\"/>\n\
         <select name=\"group_list\">\n\
         <option selected=\"selected\" value=\"vpn-ct\">vpn-ct</option>\n\
         </select>\n\
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

/// Write a full HTML response with NO Content-Length and NO
/// Transfer-Encoding, then CLOSE the connection — the MEASURED logon.html GET
/// transport (2026-08-15): the gateway answers the GET with a body delimited
/// by the connection close (implicit close despite a Keep-Alive header) and
/// Set-Cookies `webvpnlogin=1` (the CSRF-precheck jar the POST must echo). A
/// login reader that waits for a Content-Length or chunked frames must fail
/// here, and the credential POST can only go out on a FRESH connection (the
/// caller closes this one).
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

/// Whether the raw `Cookie:` header value `cookie_header` contains the
/// `name=value` pair among its `;`-separated members (the name matched
/// case-insensitively, the value exactly).
fn cookie_has_pair(cookie_header: &str, name: &str, value: &str) -> bool {
    cookie_header.split(';').any(|part| {
        let Some((cookie_name, cookie_value)) = part.trim().split_once('=') else {
            return false;
        };
        cookie_name.trim().eq_ignore_ascii_case(name) && cookie_value.trim() == value
    })
}

/// The value of the form field `name` in a urlencoded POST body, decoded with
/// the standard form-urlencoded rules — the fake gateway's round-trip oracle
/// for the percent-encoding matrix test.
fn form_field(body: &str, name: &str) -> String {
    for pair in body.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        if key == name {
            return form_url_decode(value);
        }
    }
    String::new()
}

/// Decode a form-urlencoded value with the WHATWG
/// `application/x-www-form-urlencoded` rules: `+` decodes to a space, `%XX`
/// (either hex case) to the byte, everything else passes through verbatim.
fn form_url_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                    out.push(hi * 16 + lo);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8(out).expect("decoded form value must be UTF-8")
}

/// The value of a single hexadecimal digit, or `None`.
fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Write a full HTML response as a single chunked transfer-encoding frame —
/// the MEASURED credential-POST transport (200, `Transfer-Encoding: chunked`):
/// the login reader must decode the chunks (a mutant that reads to EOF hangs
/// and times out into `LoginError::HttpFailed`).
async fn write_chunked_response<S: AsyncWrite + Unpin>(
    write: &mut S,
    status: &str,
    body: &str,
) {
    let out = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        body.len(),
        body
    );
    let _ = tokio::io::AsyncWriteExt::write_all(write, out.as_bytes()).await;
}

/// The configurable response the fake login gateway serves for the credential
/// POST (the second exchange of the two-step flow).
enum LoginReply {
    /// HTTP/1.1 200 with exactly these `Set-Cookie` headers and an empty body.
    OkCookies(Vec<String>),
    /// HTTP/1.1 200 with this body (e.g. a gateway error page).
    OkBody(&'static str),
    /// HTTP/1.1 200 with the MEASURED CSRF-precheck rejection: the body
    /// JS-redirects back to logon.html carrying the gateway result code
    /// `a0=8` (the request never reaches credential evaluation), and the
    /// Set-Cookie CLEARS the webvpn cookie — what a credential POST WITHOUT
    /// the cookie jar receives.
    CsrfReject,
    /// HTTP/1.1 200 with the MEASURED bad-credential rejection: the body
    /// JS-redirects back to logon.html carrying the gateway result code
    /// `a0=15` (real credential rejection — evaluated and rejected), and the
    /// Set-Cookie CLEARS the webvpn cookie.
    BadCredentials,
    /// A non-2xx status line with this body.
    Status(&'static str, &'static str),
    /// Accept the TCP connection but never start the TLS handshake (stall).
    StallHandshake,
}

/// Whether a request head is the aggregate-auth XML channel probe: `POST /`
/// with an XML content type — the PRIMARY channel the client probes first,
/// which this FORM-ONLY gateway answers 404 (the measured "XML channel
/// disabled" signature: wrong UA / xmlpost unsupported).
fn is_aggregate_auth_probe(head: &str) -> bool {
    head.starts_with("POST / HTTP/1.1")
        && header_value(head, "content-type")
            .is_some_and(|ct| ct.to_ascii_lowercase().contains("application/xml"))
}

/// Run a real local TLS login gateway (loopback) that serves the measured
/// FORM flow — the client's connections are dispatched by request:
///
/// * the aggregate-auth XML channel probe (`POST /` + config-auth init XML) on
///   the FIRST connection is answered 404 (the measured "XML channel
///   disabled" signature) so the client falls back to the form flow on FRESH
///   connections;
/// * `GET /+CSCOE+/logon.html` with the configured `logon` form (served
///   WITHOUT Content-Length/Transfer-Encoding, and the connection is then
///   CLOSED: the measured implicit-close transport);
/// * the configured `reply` for the credential POST (the POST must never
///   reuse the GET connection).
///
/// The captured requests are reported through the oneshot channel. The client
/// (under test) connects with `TrustPolicy::TestRoots` so the handshake is
/// verified for real.
#[allow(
    clippy::too_many_lines,
    reason = "one coherent fake-gateway flow: the XML-channel 404 probe, both measured form exchanges over their TLS connections, the capture channel, and every reply variant"
)]
async fn run_login_server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    logon: LogonPage,
    reply: LoginReply,
) -> (SocketAddr, oneshot::Receiver<CapturedLogin>) {
    // Only a client that never POSTs (e.g. a protocol violation: no csrf_token
    // to echo) leaves the final connection unaccepted; bound each accept so
    // the capture still arrives.
    const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind login server");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let empty_capture = || CapturedLogin {
            sni: None,
            probe_request: Vec::new(),
            get_request: Vec::new(),
            csrf_token: String::new(),
            post_request: Vec::new(),
            decoded_username: String::new(),
            decoded_password: String::new(),
        };
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("build server config from embedded cert");
        let acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_cfg)));

        let mut sni: Option<String> = None;
        let mut probe_request: Vec<u8> = Vec::new();
        let mut get_request: Vec<u8> = Vec::new();
        let mut csrf_token = String::new();

        // Accept the client's connections in order and dispatch by request:
        // the XML-channel probe (404), the logon GET, then the credential
        // POST (the two-step measured flow).
        loop {
            let (tcp, _peer) =
                match tokio::time::timeout(CONNECTION_TIMEOUT, listener.accept()).await {
                    Ok(Ok(x)) => x,
                    _ => {
                        // No further connection (e.g. the protocol-violation
                        // path never POSTs): report what was observed.
                        let _ = tx.send(CapturedLogin {
                            sni: sni.clone(),
                            probe_request: probe_request.clone(),
                            get_request: get_request.clone(),
                            csrf_token: csrf_token.clone(),
                            post_request: Vec::new(),
                            decoded_username: String::new(),
                            decoded_password: String::new(),
                        });
                        return;
                    }
                };
            if matches!(reply, LoginReply::StallHandshake) {
                // Hold the connection open without ever sending a ServerHello:
                // the client's TLS handshake stays pending until its injected
                // deadline. `pending()` never resolves, so the branch diverges
                // and `tx` is only used once.
                let _ = tx.send(empty_capture());
                std::future::pending::<()>().await;
                unreachable!("the stall server never resolves");
            }
            let stream = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(_) => {
                    // The client rejected the handshake (untrusted CA /
                    // hostname mismatch): capture that no HTTP bytes ever
                    // flowed.
                    let _ = tx.send(empty_capture());
                    return;
                }
            };
            if sni.is_none() {
                sni = stream.get_ref().1.server_name().map(|s| s.to_string());
            }
            let (mut read_half, mut write_half) = tokio::io::split(stream);
            let request = read_request_head(&mut read_half).await;
            let request_head = String::from_utf8_lossy(&request);

            if is_aggregate_auth_probe(&request_head) {
                // The aggregate-auth XML channel probe: a FORM-ONLY gateway
                // answers 404 (the measured wrong-UA / disabled-channel
                // signature), which sends the client to the form flow.
                probe_request = request;
                let out = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                let _ =
                    tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
                continue;
            }

            if request_head.starts_with("GET /+CSCOE+/logon.html HTTP/1.1") {
                // Exchange 1: the logon GET. The gateway serves the logon form
                // with a PER-REQUEST dynamic csrf_token (measured), delimited
                // by the CONNECTION CLOSE — no Content-Length, no
                // Transfer-Encoding — and then closes the connection (the
                // measured implicit-close transport; no TLS close_notify, so
                // the login reader must treat the unexpected-EOF close as the
                // body delimiter). The credential POST therefore MUST come on
                // a NEW connection.
                get_request = request;
                let (logon_html, token) = logon_html_for(&logon);
                csrf_token = token;
                // The GET Set-Cookies `webvpnlogin=1` and `webvpnLang=en`
                // (measured gateway: the server plants them on the logon GET;
                // logon.html JS plants `CSRFtoken` client-side, so the POST
                // echoes all three).
                write_implicit_close_response(
                    &mut write_half,
                    "200 OK",
                    &[
                        "webvpnlogin=1; path=/; secure",
                        "webvpnLang=en; path=/; secure",
                    ],
                    &logon_html,
                )
                .await;
                continue;
            }

            // Exchange 2 (a FRESH connection): the credential POST. Read the
            // rest of the declared body so the shape assertions see the exact
            // bytes.
            let mut post_request = request;
            let post_head_end = find_header_end(&post_request).unwrap_or(0);
            let head = String::from_utf8_lossy(&post_request[..post_head_end]);
            let want: Option<usize> =
                header_value(&head, "content-length").and_then(|v| v.parse::<usize>().ok());
            let mut buf = [0u8; 512];
            while want.is_some_and(|w| post_request.len().saturating_sub(post_head_end) < w) {
                match tokio::io::AsyncReadExt::read(&mut read_half, &mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        post_request.extend_from_slice(&buf[..n]);
                        if post_request.len() > 8192 {
                            break;
                        }
                    }
                }
            }
            let post_head_end = find_header_end(&post_request).unwrap_or(0);
            let post_head = String::from_utf8_lossy(&post_request[..post_head_end]);
            let post_body = String::from_utf8_lossy(&post_request[post_head_end..]);
            // The gateway's CSRF precheck (MEASURED probe matrix 2026-08-15): a
            // credential POST WITHOUT the cookie jar — `webvpnlogin` (the GET
            // Set-Cookie'd it) plus `CSRFtoken` (logon.html's
            // `document.cookie`) — is rejected with the result code `a0=8` /
            // `a0=114` BEFORE the credentials are evaluated. The fake accepts
            // the jar (then evaluates the csrf echo and the configured reply),
            // so a mutant that skips the jar dies here.
            let cookie_header = header_value(&post_head, "cookie");
            let has_webvpnlogin = cookie_header
                .as_deref()
                .is_some_and(|c| cookie_has_pair(c, "webvpnlogin", "1"));
            let has_csrftoken = cookie_header
                .as_deref()
                .is_some_and(|c| cookie_has_pair(c, "CSRFtoken", &csrf_token));
            // The csrf_token is served once on the logon GET; the POST must
            // echo it (a hardcoded / foreign token is a rejected login on the
            // real gateway).
            let token_matches = post_body
                .split("csrf_token=")
                .nth(1)
                .and_then(|t| t.split('&').next())
                .is_some_and(|echoed| echoed == csrf_token);
            // The credential fields, decoded with the STANDARD form-urlencoded
            // rules (`+` -> space, `%XX` -> byte): the round-trip oracle for
            // the percent-encoding matrix test (a mutant that leaves a special
            // character raw — or encodes space as `+` — still decodes, so the
            // exact-bytes assertions in the matrix test pin the encoding).
            let decoded_username = form_field(&post_body, "username");
            let decoded_password = form_field(&post_body, "password");
            let _ = tx.send(CapturedLogin {
                sni,
                probe_request,
                get_request,
                csrf_token,
                post_request,
                decoded_username,
                decoded_password,
            });
            if !has_webvpnlogin {
                // a0=8: CSRF precheck failed — the request never reaches
                // credential evaluation.
                write_chunked_response(
                    &mut write_half,
                    "200 OK",
                    "<html><body>Login failed - CSRF precheck (a0=8)</body></html>",
                )
                .await;
                return;
            }
            if !has_csrftoken {
                // a0=114: the CSRFtoken cookie is missing from the jar.
                write_chunked_response(
                    &mut write_half,
                    "200 OK",
                    "<html><body>Login failed - missing CSRFtoken cookie (a0=114)</body></html>",
                )
                .await;
                return;
            }
            if !token_matches {
                write_chunked_response(&mut write_half, "403 Forbidden", "csrf_token mismatch")
                    .await;
                return;
            }
            match reply {
                LoginReply::StallHandshake => unreachable!("handled before the first TLS accept"),
                LoginReply::OkCookies(cookies) => {
                    let mut out = String::from("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n");
                    for cookie in cookies {
                        out.push_str("Set-Cookie: ");
                        out.push_str(&cookie);
                        out.push_str("\r\n");
                    }
                    out.push_str("\r\n0\r\n\r\n");
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
                }
                LoginReply::OkBody(body) => {
                    write_chunked_response(&mut write_half, "200 OK", body).await;
                }
                LoginReply::CsrfReject => {
                    // The MEASURED CSRF-precheck rejection (probe matrix
                    // 2026-08-15): HTTP 200, chunked, whose body JS-redirects
                    // back to logon.html with the gateway result code `a0=8`
                    // embedded in the redirect string —
                    // `document.location.replace("/+CSCOE+/logon.html?"+"a0=8"+...)`
                    // — and whose Set-Cookie CLEARS the webvpn cookie: what a
                    // credential POST WITHOUT the cookie jar receives. The
                    // client must map this to LoginRejected (with `a0=8` in
                    // the error detail), never success.
                    let body = "<html><head><script>document.location.replace(\"/+CSCOE+/logon.html?\"+\"a0=8\"+\"\");</script></head><body><h1>Login failed</h1><p>CSRF precheck (a0=8)</p></body></html>";
                    let out = format!(
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: webvpn=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                        body.len(),
                        body
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
                }
                LoginReply::BadCredentials => {
                    // The MEASURED bad-credential rejection (probe matrix
                    // 2026-08-15): HTTP 200, chunked, whose body JS-redirects
                    // back to logon.html with the gateway result code `a0=15`
                    // (real credential rejection — evaluated and rejected)
                    // embedded in the redirect string, and whose Set-Cookie
                    // CLEARS the webvpn cookie. The client must map this to
                    // LoginRejected (with `a0=15` in the error detail), never
                    // success.
                    let body = "<html><head><script>document.location.replace(\"/+CSCOE+/logon.html?\"+\"a0=15\"+\"\");</script></head><body><h1>Login failed</h1><p>Invalid username or password (a0=15)</p></body></html>";
                    let out = format!(
                        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nSet-Cookie: webvpn=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                        body.len(),
                        body
                    );
                    let _ =
                        tokio::io::AsyncWriteExt::write_all(&mut write_half, out.as_bytes()).await;
                }
                LoginReply::Status(status_line, body) => {
                    write_chunked_response(&mut write_half, status_line, body).await;
                }
            }
            return;
        }
    });
    (addr, rx)
}

// ---------------------------------------------------------------------------
// The fixed tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_gets_logon_form_then_posts_measured_shape() {
    // The login phase must reproduce the MEASURED gateway flow
    // (vpn-ct.ecnu.edu.cn, 2026-08-15): first GET `/+CSCOE+/logon.html` (the
    // xmlpost channel and the legacy `POST /+CSCOE+/logon` are both 404 on
    // this gateway), then POST the urlencoded form to the parsed form ACTION
    // `/+webvpn+/index.html` over TLS with SNI = configured hostname,
    // carrying `Host: <hostname>`,
    // `Content-Type: application/x-www-form-urlencoded`, a correct
    // Content-Length, the served csrf_token echoed VERBATIM (dynamic per
    // request — a hardcoded-token mutant fails here), `tgroup`/`next`/
    // `tgcookieset` echoed (empty on the measured gateway), the percent-encoded
    // `username`/`password`, the `group_list` select's selected value
    // (`vpn-ct` — a browser submits it), the fixed `Login=Logon` submit value,
    // and the browser cookie jar `Cookie: webvpnlogin=1; CSRFtoken=<token>;
    // webvpnLang=en` (webvpnlogin + webvpnLang Set-Cookie'd by the logon GET).
    // No Authorization header (the login form IS the credential exchange). A
    // mutant that uses the wrong endpoint path (the legacy /+CSCOE+/logon
    // POST), a raw (unencoded) body, the wrong Host, skips the form content
    // type, drops the group_list field, or drops the webvpnLang cookie must
    // fail here.
    let (cert, key) = vpn_material();
    let (addr, captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::Standard,
        LoginReply::OkCookies(vec![
            "webvpn=abc123xyz; path=/; secure".to_string(),
            "sessionid=ignore-me".to_string(),
        ]),
    )
    .await;

    let login = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"p@ss:w1rd!",
    )
    .await
    .expect("the fake gateway accepts the login POST");

    let captured = captured.await.expect("the fake gateway observed the login");
    assert_eq!(
        captured.sni.as_deref(),
        Some("vpn.example.test"),
        "SNI must be the configured hostname"
    );

    // The PRIMARY channel is probed FIRST: the aggregate-auth XML init POST
    // (`POST /` with the config-auth init XML + the platform default
    // AnyConnect User-Agent + X-Aggregate-Auth / X-Transcend-Version), which
    // this FORM-ONLY fake answers 404 — the measured "XML channel disabled"
    // signature (wrong UA / xmlpost unsupported) — so the login falls back to
    // the form flow.
    let probe = String::from_utf8_lossy(&captured.probe_request);
    assert_eq!(
        probe.lines().next(),
        Some("POST / HTTP/1.1"),
        "the aggregate-auth XML channel is probed first (POST /, the init endpoint)"
    );
    let probe_lower = probe.to_ascii_lowercase();
    assert!(
        probe_lower.contains("<config-auth") && probe_lower.contains("type=\"init\""),
        "the probe body is the aggregate-auth init XML"
    );
    assert_eq!(
        header_value(&probe, "user-agent").as_deref(),
        Some(exv_vpn_cstp::webvpn::default_user_agent().as_str()),
        "the XML probe carries the platform default AnyConnect User-Agent (the settings default)"
    );
    assert_eq!(
        header_value(&probe, "x-aggregate-auth").as_deref(),
        Some("1"),
        "the XML probe carries X-Aggregate-Auth: 1"
    );
    assert_eq!(
        header_value(&probe, "x-transcend-version").as_deref(),
        Some("1"),
        "the XML probe carries X-Transcend-Version: 1"
    );
    assert_eq!(
        header_value(&probe, "content-type").as_deref(),
        Some("application/xml; charset=utf-8"),
        "the XML probe carries the XML content type"
    );

    let get_request = String::from_utf8_lossy(&captured.get_request);
    assert_eq!(
        get_request.lines().next(),
        Some("GET /+CSCOE+/logon.html HTTP/1.1"),
        "the login starts with GET /+CSCOE+/logon.html (the measured form endpoint)"
    );
    assert_eq!(
        header_value(&get_request, "host")
            .as_deref()
            .map(|h| h.split(':').next().unwrap_or_default()),
        Some("vpn.example.test"),
        "Host must be the configured hostname on the logon GET too"
    );

    let request = String::from_utf8_lossy(&captured.post_request);
    let mut parts = request.splitn(2, "\r\n\r\n");
    let head = parts.next().expect("request head");
    let body = parts.next().unwrap_or_default();
    assert_eq!(
        head.lines().next(),
        Some("POST /+webvpn+/index.html HTTP/1.1"),
        "the login POST must target the measured form ACTION /+webvpn+/index.html"
    );
    assert_eq!(
        header_value(head, "host")
            .as_deref()
            .map(|h| h.split(':').next().unwrap_or_default()),
        Some("vpn.example.test"),
        "Host must be the configured hostname"
    );
    assert_eq!(
        header_value(head, "content-type").as_deref(),
        Some("application/x-www-form-urlencoded"),
        "the form body must be urlencoded"
    );
    assert_eq!(
        header_value(head, "content-length").and_then(|v| v.parse::<usize>().ok()),
        Some(body.len()),
        "Content-Length must match the body length"
    );
    let expected_cookie = format!(
        "webvpnlogin=1; CSRFtoken={}; webvpnLang=en",
        captured.csrf_token
    );
    assert_eq!(
        header_value(head, "cookie").as_deref(),
        Some(expected_cookie.as_str()),
        "the login POST must carry the browser cookie jar: webvpnlogin + webvpnLang (Set-Cookie'd by the logon GET) + CSRFtoken = the served csrf_token (logon.html's document.cookie)"
    );
    assert!(
        header_value(head, "cookie").is_some_and(|c| cookie_has_pair(&c, "webvpnLang", "en")),
        "the cookie jar must contain webvpnLang=en — the logon GET Set-Cookie'd it and a browser echoes it"
    );
    assert_eq!(
        body,
        format!(
            "tgroup=&next=&tgcookieset=&csrf_token={}&username=alice&password=p%40ss%3Aw1rd%21&group_list=vpn-ct&Login=Logon",
            captured.csrf_token
        ),
        "the POST body must echo the served csrf_token verbatim, then username + percent-encoded password, then the group_list select's selected value (vpn-ct), then Login=Logon"
    );
    assert!(
        body.contains("&group_list=vpn-ct&Login=Logon"),
        "the measured group_list select value vpn-ct must be submitted, in the browser's field order between password and Login"
    );
    assert!(
        body.contains("tgroup=&next=&tgcookieset="),
        "the measured empty hidden fields are echoed as empty values"
    );
    assert!(
        header_value(head, "authorization").is_none(),
        "the login POST must not carry an Authorization header"
    );

    assert_eq!(
        login.cookie.as_str(),
        "abc123xyz",
        "the webvpn cookie value is captured"
    );
    assert!(
        !login.saml_detected,
        "a plain 200 + cookie is not a SAML login"
    );
}

#[tokio::test]
async fn captures_only_webvpn_cookie() {
    // Among several Set-Cookie headers only `webvpn=` is captured into
    // `LoginSession.cookie`; every other cookie is ignored (openconnect auth.c
    // do_login() behavior). A mutant that captures the wrong cookie (or the whole
    // header line) must fail here.
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::Standard,
        LoginReply::OkCookies(vec![
            "sessionid=ignored".to_string(),
            "webvpn=cap-tured-v4lue".to_string(),
            "other=irrelevant".to_string(),
        ]),
    )
    .await;

    let login = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"s3cret",
    )
    .await
    .expect("login succeeds when a webvpn cookie is present");

    assert_eq!(
        login.cookie.as_str(),
        "cap-tured-v4lue",
        "only the webvpn cookie value is captured"
    );
    assert!(!login.saml_detected);
}

#[tokio::test]
async fn success_without_webvpn_cookie_is_not_ok() {
    // A 200 response WITHOUT `Set-Cookie: webvpn=` must NOT be treated as login
    // success: the webvpn cookie is the session credential that the CONNECT phase
    // (CS-AUTH-02) depends on, and on the measured gateway a 2xx without a real
    // (non-empty) webvpn cookie is a rejected login (bad credentials) — never a
    // success. A mutant that returns Ok even when the cookie is missing must
    // fail here.
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::Standard,
        LoginReply::OkCookies(vec!["sessionid=only-this-one".to_string()]),
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
    .expect_err("a 200 without the webvpn cookie must not be login success");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "a 2xx without a real webvpn cookie surfaces as typed LoginRejected, never a success"
    );
}

#[tokio::test]
async fn cleared_webvpn_cookie_is_login_rejected() {
    // MEASURED failure semantics (vpn-ct.ecnu.edu.cn, 2026-08-15): on bad
    // credentials the gateway answers the credential POST with HTTP 200 but
    // CLEARS the webvpn cookie (`Set-Cookie: webvpn=; expires=...1970`) and
    // JS-redirects back to logon.html. That 200-with-cleared-cookie is a
    // rejected login, never a success — the mutant that treats any 200 as
    // login success dies here.
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::Standard,
        LoginReply::OkCookies(vec![
            "webvpn=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/".to_string(),
        ]),
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
    .expect_err("a cleared webvpn cookie must not be login success");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "the measured cleared-cookie signature surfaces as typed LoginRejected"
    );
    let err_debug = format!("{err:?}");
    assert!(
        !err_debug.contains("wrong-password"),
        "LoginError Debug output must never leak the password"
    );
}

#[tokio::test]
async fn logon_form_without_csrf_token_is_protocol_violation() {
    // The csrf_token is REQUIRED on the measured gateway (dynamic per
    // request): a logon page without the hidden csrf_token field is not a
    // usable login form -> typed ProtocolViolation, and NO credential POST may
    // be sent (the password never leaves the process for a form the engine
    // cannot post).
    let (cert, key) = vpn_material();
    let (addr, captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::NoCsrfToken,
        LoginReply::OkCookies(vec!["webvpn=abc123xyz".to_string()]),
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
    .expect_err("a logon form without csrf_token must not log in");
    assert!(
        matches!(err, LoginError::ProtocolViolation),
        "a missing csrf_token is a typed ProtocolViolation"
    );

    let captured = captured.await.expect("the fake gateway observed the logon GET");
    assert!(
        captured.post_request.is_empty(),
        "no credential POST is sent for a form without a csrf_token"
    );
}

#[tokio::test]
async fn relative_form_action_is_resolved_against_gateway_origin() {
    // The form ACTION may be relative: it is resolved against the gateway
    // origin (the TLS peer, carried by the Host header) into an
    // absolute-path request-target for the POST.
    let (cert, key) = vpn_material();
    let (addr, captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::RelativeAction,
        LoginReply::OkCookies(vec!["webvpn=abc123xyz".to_string()]),
    )
    .await;

    let login = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        b"alice",
        b"s3cret",
    )
    .await
    .expect("a relative action resolves against the gateway origin");

    let captured = captured.await.expect("the fake gateway observed the login");
    let request = String::from_utf8_lossy(&captured.post_request);
    assert_eq!(
        request.lines().next(),
        Some("POST /webvpn/index.html HTTP/1.1"),
        "a relative form action must resolve against the gateway origin"
    );
    assert_eq!(
        login.cookie.as_str(),
        "abc123xyz",
        "the login still succeeds with the resolved action"
    );
}

#[tokio::test]
async fn login_post_without_cookie_jar_is_csrf_rejected() {
    // MEASURED gateway semantics (vpn-ct.ecnu.edu.cn, 2026-08-15 probe
    // matrix): the gateway's CSRF precheck rejects a credential POST WITHOUT
    // the cookie jar (`webvpnlogin` + `CSRFtoken`) with the result code
    // `a0=8` — the request NEVER reaches credential evaluation (the real
    // password is never checked). The engine mirrors the browser by sending
    // the jar (asserted in login_gets_logon_form_then_posts_measured_shape,
    // and the fake rejects a jar-less POST with this exact body), so a gateway
    // answering the measured `a0=8` rejection must surface as typed
    // `LoginRejected`, never login success. A mutant that swallows the CSRF
    // rejection as success must fail here.
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(cert.clone(), key, LogonPage::Standard, LoginReply::CsrfReject)
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
    .expect_err("a CSRF-precheck rejection must not be login success");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "the a0=8 CSRF rejection surfaces as typed LoginRejected"
    );
    assert_eq!(
        err.a0_result(),
        Some("8"),
        "the gateway's a0=8 result code (embedded in the JS redirect text) must land in the rejected-login error detail"
    );
    let err_debug = format!("{err:?}");
    assert!(
        !err_debug.contains("wrong-password"),
        "LoginError Debug output must never leak the password"
    );
}

#[tokio::test]
async fn bad_credentials_a0_15_lands_in_error_detail() {
    // MEASURED gateway semantics (vpn-ct.ecnu.edu.cn, 2026-08-15 probe
    // matrix): a REAL credential rejection answers the POST with HTTP 200,
    // CLEARS the webvpn cookie (`webvpn=; expires=1970`) and JS-redirects
    // back to logon.html carrying the gateway result code `a0=15` embedded
    // in the redirect string. The typed error is LoginRejected, and the
    // `a0=15` must be readable from the error detail — that is what lets the
    // acceptance evidence distinguish "credentials wrong" (`a0=15`) from
    // "request malformed" (`a0=8`/`114`/`115`/`16`). A mutant that swallows
    // the rejection as success — or drops the a0 code — must fail here.
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(cert.clone(), key, LogonPage::Standard, LoginReply::BadCredentials)
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
    .expect_err("bad credentials must not be login success");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "the a0=15 bad-credential rejection surfaces as typed LoginRejected"
    );
    assert_eq!(
        err.a0_result(),
        Some("15"),
        "the gateway's a0=15 result code (embedded in the JS redirect text) must land in the rejected-login error detail"
    );
    let err_debug = format!("{err:?}");
    assert!(
        !err_debug.contains("wrong-password"),
        "LoginError Debug output must never leak the password"
    );
}

#[tokio::test]
async fn special_character_matrix_round_trips_through_percent_encoding() {
    // The credential POST percent-encodes EVERY byte outside RFC 3986
    // unreserved (`-._~` + ASCII alphanumerics) as `%XX`: `@ & + % = ? #`,
    // space, `' " / \`, newline, and multi-byte UTF-8 (Chinese, emoji) must
    // never appear raw on the wire, and must decode back to the originals
    // with the STANDARD form-urlencoded rules (`+` -> space, `%XX` -> byte).
    // Space is pinned as `%20` here — the alternate form-urlencoded spelling
    // `+` (which the gateway also decodes) must NOT be emitted, so a mutant
    // that encodes space as `+` (or leaves any special character raw) dies
    // on the exact-bytes assertions below.
    let (cert, key) = vpn_material();
    let (addr, captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::Standard,
        LoginReply::OkCookies(vec!["webvpn=abc123xyz; path=/; secure".to_string()]),
    )
    .await;

    let username = "a@b&c+d%e=f?g#h i'j\"k/l\\m\n中🚀";
    let password = "p@s&w+o%r=d?q#r s't\"u/v\\w\n密🚀";
    let login = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        username.as_bytes(),
        password.as_bytes(),
    )
    .await
    .expect("login succeeds; the percent-encoded credentials are accepted");
    assert_eq!(login.cookie.as_str(), "abc123xyz");

    let captured = captured.await.expect("the fake gateway observed the login");
    let request = String::from_utf8_lossy(&captured.post_request);
    let mut parts = request.splitn(2, "\r\n\r\n");
    let head = parts.next().expect("request head");
    let body = parts.next().unwrap_or_default();

    // The exact encoded bytes are PINNED (space -> `%20`, never `+`;
    // multi-byte UTF-8 -> one `%XX` per byte), so an encoding mutant dies
    // here even though the standard decode below would still round-trip.
    let username_enc = body
        .split("&username=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap_or_default();
    let password_enc = body
        .split("&password=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .unwrap_or_default();
    assert_eq!(
        username_enc,
        "a%40b%26c%2Bd%25e%3Df%3Fg%23h%20i%27j%22k%2Fl%5Cm%0A%E4%B8%AD%F0%9F%9A%80",
        "every non-unreserved byte in the username is percent-encoded (space as %20)"
    );
    assert_eq!(
        password_enc,
        "p%40s%26w%2Bo%25r%3Dd%3Fq%23r%20s%27t%22u%2Fv%5Cw%0A%E5%AF%86%F0%9F%9A%80",
        "every non-unreserved byte in the password is percent-encoded (space as %20)"
    );
    assert_eq!(
        header_value(head, "content-length").and_then(|v| v.parse::<usize>().ok()),
        Some(body.len()),
        "Content-Length still matches the percent-encoded body length"
    );

    // Round-trip: the fake gateway decodes the form with the STANDARD rules
    // and recovers the ORIGINAL username/password byte-for-byte.
    assert_eq!(
        captured.decoded_username, username,
        "the standard form-urlencoded decode of the POST body must recover the original username"
    );
    assert_eq!(
        captured.decoded_password, password,
        "the standard form-urlencoded decode of the POST body must recover the original password"
    );
}

#[tokio::test]
async fn error_page_csco_e_marker_is_login_rejected() {
    // A 2xx page carrying the `+CSCOE+/error` marker is a login failure page: the
    // gateway rejected the credentials. A mutant that swallows login errors as
    // success must fail here.
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::Standard,
        LoginReply::OkBody("<html><body><a href=\"/+CSCOE+/error\">login failed</a></body></html>"),
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
    .expect_err("a +CSCOE+/error page must be a rejected login");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "the gateway error page surfaces as typed LoginRejected"
    );
    let err_debug = format!("{err:?}");
    assert!(
        !err_debug.contains("wrong-password"),
        "LoginError Debug output must never leak the password"
    );
}

#[tokio::test]
async fn error_page_login_error_marker_is_login_rejected() {
    // A 2xx page carrying the `login error` marker is likewise a rejection
    // (openconnect auth.c checks both markers). A mutant that only detects one of
    // the two markers must fail here.
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::Standard,
        LoginReply::OkBody("<html>Authentication failed: login error, try again.</html>"),
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
    .expect_err("a login error marker page must be a rejected login");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "the login error marker surfaces as typed LoginRejected"
    );
}

#[tokio::test]
async fn non_2xx_status_is_login_rejected() {
    // An HTTP status outside 2xx is a rejected login even without any marker in
    // the body. A mutant that only inspects the body (or treats any response as
    // success) must fail here.
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::Standard,
        LoginReply::Status("401 Unauthorized", "Authentication required"),
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
    .expect_err("a non-2xx status must be a rejected login");
    assert!(
        matches!(err, LoginError::LoginRejected { .. }),
        "a non-2xx status surfaces as typed LoginRejected"
    );
}

#[tokio::test]
async fn untrusted_ca_is_tls_failed() {
    // The login TLS connection must REALLY verify the chain against the injected
    // roots: a gateway served by a CA that is NOT in the injected store is
    // rejected before any HTTP bytes are exchanged. A mutant that skips TLS
    // verification (always-true verifier) must fail here.
    let (other_cert, other_key) = other_material();
    let (vpn_cert, _vpn_key) = vpn_material();
    let (addr, captured) = run_login_server(
        other_cert,
        other_key,
        LogonPage::Standard,
        LoginReply::OkCookies(vec!["webvpn=evil-cookie".to_string()]),
    )
    .await;

    let err = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&vpn_cert))),
        None,
        b"alice",
        b"s3cret",
    )
    .await
    .expect_err("a gateway with an untrusted CA must be rejected");
    assert!(
        matches!(
            err,
            LoginError::TlsFailed(BootstrapError::UntrustedChain)
        ),
        "an untrusted chain surfaces as LoginError::TlsFailed(UntrustedChain)"
    );
    let captured = captured.await.expect("the server observed the failed handshake");
    assert!(
        captured.get_request.is_empty() && captured.post_request.is_empty(),
        "no HTTP byte may flow over an unverified TLS connection"
    );
}

#[tokio::test]
async fn wrong_hostname_is_tls_failed() {
    // A gateway presenting a cert trusted by the injected root but for a DIFFERENT
    // hostname must be rejected: the TLS peer must match the configured hostname.
    // A verifier mutant that ignores the name must fail here.
    let (vpn_cert, vpn_key) = vpn_material();
    let (addr, _captured) = run_login_server(
        vpn_cert.clone(),
        vpn_key,
        LogonPage::Standard,
        LoginReply::OkCookies(vec!["webvpn=leaked-cookie".to_string()]),
    )
    .await;

    let err = WebvpnLogin::perform_login(
        "other.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&vpn_cert))),
        None,
        b"alice",
        b"s3cret",
    )
    .await
    .expect_err("a cert for the wrong hostname must be rejected");
    assert!(
        matches!(
            err,
            LoginError::TlsFailed(BootstrapError::HostnameMismatch)
        ),
        "a hostname mismatch surfaces as LoginError::TlsFailed(HostnameMismatch)"
    );
}

#[tokio::test]
async fn deadline_is_respected_without_false_rollback() {
    // The login deadline is measured on the INJECTED clock, exactly like the P41
    // bootstrap. While the injected clock is before the deadline the login must
    // stay pending (no false rollback even as real time elapses), and once the
    // clock passes the deadline a REAL `LoginError::DeadlineExceeded` must
    // surface. A mutant that never consults the deadline (or rolls back early)
    // must fail here.
    let clock = Arc::new(FakeClock::at(0));
    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::Standard,
        LoginReply::StallHandshake,
    )
    .await;

    let login = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        Some(Deadline::at(clock.clone(), 1_000)),
        b"alice",
        b"s3cret",
    );
    tokio::pin!(login);

    // (a) Injected clock (t=0) is before the deadline (t=1000): the login must
    //     remain pending and must NOT roll back while real time elapses.
    let before = tokio::time::timeout(Duration::from_millis(80), &mut login).await;
    assert!(
        before.is_err(),
        "no false rollback while the injected clock is before the deadline"
    );

    // (b) Advance the injected clock past the deadline -> a real rollback.
    clock.advance(5_000);
    let settled = tokio::time::timeout(Duration::from_secs(5), login)
        .await
        .expect("the login re-polls the injected clock and settles once the deadline passes");
    let err = settled.expect_err("a deadline expiry is a failure, never a success");
    assert!(
        matches!(err, LoginError::DeadlineExceeded),
        "passing the injected deadline surfaces a typed DeadlineExceeded"
    );
}

#[tokio::test]
async fn password_secret_zeroized_after_login_vault_pattern() {
    // SchoolSecrets pattern (school.rs): the password lives in caller-side
    // one-shot plaintext buffers; it is deposited in the AuthInteraction vault,
    // the login POST consumes it, and afterwards `vault.send_secret()` wipes the
    // vault copy and the caller zeroizes its own plaintext. The engine must
    // retain nothing: Debug output of LoginSession and WebvpnCookie must never
    // contain the password or the cookie value. A mutant that retains the
    // password bytes (or leaks them in Debug) must fail here.
    let clock = Arc::new(FakeClock::at(0));
    let mut vault = AuthInteraction::new(clock, Duration::from_secs(30));

    // Drive the vault to Established with the school password (school.rs pattern:
    // group/username challenges advance the protocol; the password is the only
    // real credential).
    let group = vault.begin();
    let username = vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id.clone(),
            secret: Secret::new(b"vpn-group"),
        })
        .expect("group advances the flow");
    let AuthProgress::Challenge(username) = username else {
        panic!("group step must return the username challenge");
    };
    let password = vault
        .respond(AuthResponse {
            interaction_id: username.interaction_id.clone(),
            secret: Secret::new(b"alice"),
        })
        .expect("username advances the flow");
    let AuthProgress::Challenge(password) = password else {
        panic!("username step must return the password challenge");
    };
    let secret = Secret::new(b"p@ss:w1rd!");
    let secret_handle = secret.clone();
    let done = vault
        .respond(AuthResponse {
            interaction_id: password.interaction_id.clone(),
            secret,
        })
        .expect("deposit the password");
    assert!(matches!(done, AuthProgress::Established));

    // Caller-side one-shot plaintext buffers (SchoolSecrets analog).
    let mut username_bytes: Vec<u8> = b"alice".to_vec();
    let mut password_bytes: Vec<u8> = b"p@ss:w1rd!".to_vec();

    let (cert, key) = vpn_material();
    let (addr, _captured) = run_login_server(
        cert.clone(),
        key,
        LogonPage::Standard,
        LoginReply::OkCookies(vec!["webvpn=abc123xyz; path=/; secure".to_string()]),
    )
    .await;
    let login = WebvpnLogin::perform_login(
        "vpn.example.test",
        addr,
        TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        None,
        &username_bytes,
        &password_bytes,
    )
    .await
    .expect("login succeeds against the fake gateway");

    // One-shot lifecycle: caller zeroizes its plaintext and the vault wipes its
    // copy (school.rs open_school_data_connection pattern).
    username_bytes.fill(0);
    password_bytes.fill(0);
    vault.send_secret();
    assert!(
        secret_handle.is_zeroed(),
        "the vault copy of the password must be wiped after send_secret"
    );

    // The engine must retain nothing observable: no password or cookie value in
    // Debug output.
    let session_debug = format!("{login:?}");
    assert!(
        !session_debug.contains("p@ss:w1rd!"),
        "LoginSession Debug output must not retain the password"
    );
    let cookie_debug = format!("{:?}", login.cookie);
    assert!(
        !cookie_debug.contains("abc123xyz"),
        "WebvpnCookie Debug output must be redacted"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
