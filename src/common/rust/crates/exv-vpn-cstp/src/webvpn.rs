// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! `WebVPN` login phase (CS-AUTH-01-I): the AnyConnect `WebVPN` login flow.
//!
//! The flow is driven by MEASURED gateway evidence (vpn-ct.ecnu.edu.cn, TLS
//! to 222.66.117.109:443, SNI vpn-ct.ecnu.edu.cn, 2026-08-15). The gateway
//! runs TWO login channels, and which one opens depends on the `User-Agent`:
//!
//! * The aggregate-auth XML channel (`POST /` with config-auth XML +
//!   `X-Aggregate-Auth: 1` + `X-Transcend-Version: 1`) is the PRIMARY: it
//!   opens ONLY for the exact AnyConnect platform `User-Agent` names
//!   (`AnyConnect Win_x86_64 4.10.05095` and the platform/arch/version
//!   variants of it) — any other UA (a product UA like `EXV Native`, or an
//!   AnyConnect string without the platform part, or a lowercased
//!   `anyconnect` prefix) is refused with HTTP 404 (measured probe matrix,
//!   2026-08-15). With the exact UA the init POST returns HTTP 200 +
//!   `config-auth type="auth-request"` carrying an `<opaque>` block, a
//!   username/password form and a `group_list` select.
//! * The FORM channel (GET `/+CSCOE+/logon.html` -> POST the form ACTION) is
//!   the FALLBACK: [`WebvpnLogin::perform_login`] probes the XML channel
//!   first and falls back to the form flow when the gateway refuses it (the
//!   404 signature) or answers the probe with a non-XML page. The legacy
//!   `POST /+CSCOE+/logon` endpoint is 404 on this gateway (the WRONG
//!   endpoint).
//!
//! [`WebvpnLogin::perform_login`] / [`WebvpnLogin::perform_login_with_user_agent`]
//! reproduce the measured flows over real
//! [`Bootstrap`](crate::connector::Bootstrap) TLS connections under the
//! injected trust policy. The XML channel (mirrors the stable C++ v3.3.7
//! `aggregate_auth.cpp` + `production_transport.cpp`):
//!
//! 1. `POST /` (connection #1, keep-alive) with the init XML (`<config-auth
//!    client="vpn" type="init" aggregate-auth-version="2">` + `<version
//!    who="vpn">` = the UA + `<device-id>` + `<group-access>` +
//!    `<capabilities>`), the `User-Agent`, `X-Aggregate-Auth: 1` and
//!    `X-Transcend-Version: 1` headers -> 200 + `auth-request` XML. Parse the
//!    `<opaque>` element(s) VERBATIM (for echo), the form fields
//!    (username/password presence), the `group_list` select's selected value,
//!    and any `<session-token>`/`<session-id>`.
//! 2. `POST /` on the SAME connection (keep-alive) with the auth-reply XML:
//!    the `<opaque>` echoed verbatim, `<auth><username>..</username>
//!    <password>..</password></auth>` (XML-escaped) and
//!    `<group-select>` (the parsed group value). If the gateway closed the
//!    connection after the init response, the reply is retried ONCE on a
//!    FRESH connection.
//! 3. Success = `auth_id="success"` (or a `<session-token>`/`<session-id>`,
//!    which IS the credential: `webvpn=<token>`), falling back to the
//!    `Set-Cookie: webvpn=` value of the reply; rejection = `auth_id="error"`
//!    or an `<error>` node (its text is attached to
//!    [`LoginError::LoginRejected`] as diagnostic detail), a non-2xx status,
//!    or a non-XML reply; SAML steering (a 3xx `Location` to
//!    `+CSCOE+/saml`, or a meta-refresh page) is [`LoginError::SamlRequired`].
//!
//! The FORM channel (the measured fallback):
//!
//! 1. `GET /+CSCOE+/logon.html` -> 200, body delimited by the CONNECTION
//!    CLOSE: no `Content-Length`, no `Transfer-Encoding` — the gateway CLOSES
//!    the connection after this response (implicit close despite a Keep-Alive
//!    header, measured 2026-08-15), so the login reader stops at the
//!    close/EOF and the credential POST MUST run over a FRESH connection;
//!    10KB form; hidden fields `tgroup`(empty) / `next`(empty) /
//!    `tgcookieset`(empty) / `csrf_token` (DYNAMIC per request) / `username` /
//!    `password`, the `group_list` select (selected value `vpn-ct` — a
//!    browser submits it) / `Login`; form ACTION `/+webvpn+/index.html`.
//! 2. `POST /+webvpn+/index.html` on a NEW connection with the urlencoded
//!    fields -> 200 (`Transfer-Encoding: chunked`, so the login reader
//!    decodes the chunks); on bad credentials the gateway CLEARS the webvpn
//!    cookie (`Set-Cookie: webvpn=; expires=1970`) and the body JS-redirects
//!    back to logon.html (login-failed semantics). The POST carries the
//!    CSRF-precheck cookie jar a browser would echo — `Cookie: webvpnlogin=1;
//!    CSRFtoken=<csrf_token>; webvpnLang=en` (the GET Set-Cookies
//!    `webvpnlogin=1` and `webvpnLang=en`; logon.html JS does
//!    `document.cookie="CSRFtoken="+csrf_token+"; path=/; secure"`): a POST
//!    WITHOUT the jar is rejected with the gateway result code `a0=8`
//!    before the credentials are ever evaluated (measured probe matrix,
//!    2026-08-15).
//! 3. `/+CSCOE+/saml/sp/acs?tgname=` -> 400 (not SAML; no IdP redirect).
//!
//! The `User-Agent` is a SETTINGS DEFAULT, never a hardcoded constant in the
//! flow: [`default_user_agent`] computes the platform-appropriate AnyConnect
//! identity (Windows -> `AnyConnect Win_x86_64 4.10.05095`, Darwin ->
//! `AnyConnect Darwin_x86_64 4.10.05095`, Linux -> `AnyConnect Linux_x86_64
//! 4.10.05095`, arch-adapted at runtime from `x86_64`/`arm64` — the gateway
//! is arch-insensitive per the measured matrix), and the caller may override
//! it per connection through
//! [`WebvpnLogin::perform_login_with_user_agent`] (a future config/settings
//! layer feeds its override into that parameter).
//!
//! Secret discipline (auth.rs vault pattern): the password bytes live only in
//! the caller's one-shot plaintext buffer and in the POST body during
//! construction; the request buffer is zeroized immediately after the POST is
//! sent, and the password never appears in Debug output (`WebvpnCookie` is
//! Debug-redacted with the same `finish_non_exhaustive` pattern as
//! `BootstrapSession`).

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroize;

// 【单侧宿主豁免(R1c/P3-1,2026-08-19)】此变更由 win32 单侧宿主发起并驱动:
// 目的=让 WebVPN 登录的 bootstrap TLS 连接与 CSTP 控制面一致地钉在物理网卡出口
// (IP_UNICAST_IF,绕过 Mihomo TUN 默认路由;否则登录流量走 Mihomo 代理路径)。
// 必要性=exv-vpn-cstp 是 common 域共享 crate,登录 socket 绑定只能在 common 层
// 提供穿参入口(win32 engine 的 production_socket_binder 闭包就是
// `BootstrapConfig.socket_binder` 的产地,类型在 connector.rs)。其它宿主(linux/
// darwin)不传 binder 时保持 None=原行为,零语义变化。位置=本文件公开入口 + 内部
// 两通道(aggregate_auth_login/form_channel_login)的 BootstrapConfig 穿参。
use crate::connector::{
    Bootstrap, BootstrapConfig, BootstrapError, Deadline, SocketBinder, TrustPolicy,
};

/// The static entry point of the `WebVPN` login phase.
#[allow(
    clippy::module_name_repetitions,
    reason = "API fixed verbatim by the CS-AUTH-01-T test contract (tests/webvpn_login.rs)"
)]
pub struct WebvpnLogin;

/// The outcome of a successful `WebVPN` login.
///
/// The cookie is the session credential the CONNECT phase (CS-AUTH-02) depends
/// on. It is engine session state, never serialized and never logged (plan
/// §5.2 rule 1).
pub struct LoginSession {
    /// The captured `webvpn` cookie value (opaque; Debug is redacted).
    pub cookie: WebvpnCookie,
    /// Whether the gateway steered the login toward a SAML identity provider
    /// (CS-AUTH-04; always false for a plain form login).
    pub saml_detected: bool,
}

impl fmt::Debug for LoginSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginSession")
            .field("cookie", &self.cookie)
            .field("saml_detected", &self.saml_detected)
            .finish_non_exhaustive()
    }
}

/// An opaque `WebVPN` session cookie.
///
/// Debug output is redacted (`finish_non_exhaustive`, the same pattern as
/// `BootstrapSession`): the value never appears in logs or traces.
#[allow(
    clippy::module_name_repetitions,
    reason = "API fixed verbatim by the CS-AUTH-01-T test contract (tests/webvpn_login.rs)"
)]
pub struct WebvpnCookie {
    value: String,
}

impl WebvpnCookie {
    /// The raw `webvpn` cookie value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for WebvpnCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebvpnCookie").finish_non_exhaustive()
    }
}

/// Typed failure of the `WebVPN` login phase (plan §2.2).
#[derive(Debug)]
pub enum LoginError {
    /// The TLS bootstrap failed (untrusted chain / hostname mismatch /
    /// handshake / connect / IPv6 target / DTLS offer).
    TlsFailed(BootstrapError),
    /// The HTTP exchange itself failed (write / read / response parsing).
    HttpFailed,
    /// The gateway rejected the credentials: an error page, a non-2xx status,
    /// or the measured bad-credential signature — a 200 that CLEARS the
    /// `webvpn` cookie (`Set-Cookie: webvpn=; expires=1970`) or a 200 without
    /// a real (non-empty) webvpn cookie. Never swallowed into success.
    ///
    /// The additive `detail` field carries the gateway's rejection detail:
    /// for the FORM channel the `a0` result code extracted from the rejected
    /// response body (measured: `a0=8` CSRF precheck failed, `a0=15` real
    /// credential rejection, ...); for the aggregate-auth XML channel the
    /// `<error>` node text or the rejected HTTP status — DIAGNOSTIC only, read
    /// back through [`LoginError::a0_result`], never part of the typed
    /// contract. The CS-AUTH-01-T contract pins the variant names; this field
    /// is the additive extension the acceptance evidence consumes.
    LoginRejected {
        /// The gateway rejection detail from the rejected response (the
        /// form channel's `a0` result code — e.g. `"15"` for a real
        /// credential rejection, `"8"` for a CSRF-precheck failure — or the
        /// aggregate-auth XML channel's `<error>` node text / HTTP status),
        /// if the response carried one. Diagnostic only.
        detail: Option<String>,
    },
    /// The gateway redirected the login to a SAML identity provider (CS-AUTH-04).
    SamlRequired,
    /// The gateway requested a second password / OTP: honestly unsupported in
    /// the MVP.
    TwoFactorRequired,
    /// A protocol violation: the logon form (`/+CSCOE+/logon.html`) without
    /// its REQUIRED hidden `csrf_token` field (or without a form ACTION to
    /// POST to).
    ProtocolViolation,
    /// The injected login deadline expired.
    DeadlineExceeded,
}

impl LoginError {
    /// The gateway rejection detail attached to a rejected login, if the
    /// rejected response carried one: the form channel's `a0` result code
    /// (extracted from the body's JS redirect text — measured: `a0=8` CSRF
    /// precheck failed, `a0=114`/`115` CSRFtoken cookie / form-field
    /// mismatch, `a0=15` real credential rejection, `a0=16` empty user or
    /// password field) or the aggregate-auth XML channel's `<error>` node
    /// text / rejected HTTP status. Diagnostic only — never part of the
    /// typed contract; `None` for every other variant.
    #[must_use]
    pub fn a0_result(&self) -> Option<&str> {
        match self {
            LoginError::LoginRejected { detail } => detail.as_deref(),
            _ => None,
        }
    }

    /// Additive constructor: a rejected login carrying the gateway `a0`
    /// result code (`Some`) — or no detail (`None`) — as diagnostic detail.
    #[must_use]
    pub fn login_rejected_with_detail(detail: Option<String>) -> Self {
        Self::LoginRejected { detail }
    }
}

impl WebvpnLogin {
    /// Perform the `WebVPN` login phase against the gateway with the platform
    /// default `User-Agent` — the settings default
    /// ([`default_user_agent`]: Windows -> `AnyConnect Win_x86_64 4.10.05095`,
    /// Darwin -> `AnyConnect Darwin_x86_64 4.10.05095`, Linux ->
    /// `AnyConnect Linux_x86_64 4.10.05095`, arch-adapted at runtime). To
    /// override the client name per connection (a config/settings layer feeds
    /// its override through the parameter), use
    /// [`WebvpnLogin::perform_login_with_user_agent`].
    ///
    /// The PRIMARY channel is the aggregate-auth XML flow (measured
    /// vpn-ct.ecnu.edu.cn, 2026-08-15: the gateway opens it only for the exact
    /// AnyConnect platform UAs): `POST /` (keep-alive) with the init XML +
    /// `User-Agent` + `X-Aggregate-Auth: 1` + `X-Transcend-Version: 1` ->
    /// 200 + `config-auth type="auth-request"` -> `POST /` (same connection)
    /// with the auth-reply XML (the `<opaque>` echoed verbatim + `<auth>
    /// <username>` + `<password>` + `<group-select>`) -> success
    /// (`auth_id="success"`, or `<session-token>`/`<session-id>` = the
    /// `webvpn` credential, or the reply's `Set-Cookie: webvpn=`) / rejection
    /// (`auth_id="error"` / `<error>` node / non-2xx status / non-XML reply) /
    /// SAML steering. When the gateway REFUSES the XML channel (the init
    /// probe answers 404 — the measured wrong-UA / disabled-channel
    /// signature — or a non-XML page, or an auth-request without a
    /// username/password form), the login FALLS BACK to the measured FORM
    /// channel: `GET /+CSCOE+/logon.html` -> parse the hidden fields
    /// (`csrf_token` REQUIRED) + `group_list` + form ACTION -> `POST` the
    /// ACTION on a fresh connection with the percent-encoded fields and the
    /// CSRF-precheck cookie jar (`webvpnlogin`/`CSRFtoken`/`webvpnLang`),
    /// capturing only the `Set-Cookie: webvpn=` value.
    ///
    /// Response classification (measured semantics): success is a 2xx with a
    /// real credential — the XML channel's session token or webvpn cookie, or
    /// the form channel's non-empty `Set-Cookie: webvpn=` value — captured
    /// into [`LoginSession::cookie`]; a cleared/missing webvpn cookie, error
    /// pages, `auth_id="error"`, and non-2xx statuses are all
    /// [`LoginError::LoginRejected`]; a 3xx `Location` carrying
    /// `+CSCOE+/saml` or a meta-refresh page steering to the SAML ACS
    /// (CS-AUTH-04) is [`LoginError::SamlRequired`]. When a rejected response
    /// carries a gateway detail (the form channel's `a0` result code, or the
    /// XML channel's `<error>` text / status), it is attached to the
    /// [`LoginError::LoginRejected`] `detail` (additive field; read back
    /// through [`LoginError::a0_result`]) so the acceptance evidence can
    /// distinguish "credentials wrong" from "request malformed".
    ///
    /// The password bytes are consumed one-shot (`SchoolSecrets` pattern): they
    /// exist only in the caller's plaintext buffer and in the POST body during
    /// construction, which is zeroized immediately after the request is sent.
    ///
    /// # Errors
    ///
    /// * [`LoginError::TlsFailed`] — the bootstrap rejected the peer (untrusted
    ///   chain, hostname mismatch, handshake, connect).
    /// * [`LoginError::DeadlineExceeded`] — the injected deadline expired.
    /// * [`LoginError::HttpFailed`] — the HTTP exchange failed.
    /// * [`LoginError::LoginRejected`] — error page / non-2xx status / cleared
    ///   or missing webvpn cookie on a 2xx / XML `auth_id="error"`; carries
    ///   the gateway detail in its `detail` field
    ///   ([`LoginError::a0_result`]) when the response had one.
    /// * [`LoginError::SamlRequired`] — SAML steering detected: a 3xx
    ///   `Location` carrying `+CSCOE+/saml`, or a meta-refresh page steering to
    ///   the SAML ACS (CS-AUTH-04).
    /// * [`LoginError::TwoFactorRequired`] — second password / OTP requested
    ///   (the XML channel's challenge/secondary form).
    /// * [`LoginError::ProtocolViolation`] — the logon form without its
    ///   REQUIRED `csrf_token` (or without a form ACTION).
    pub async fn perform_login(
        host: &str,
        gateway_addr: SocketAddr,
        trust: TrustPolicy,
        deadline: Option<Deadline>,
        username: &[u8],
        password: &[u8],
    ) -> Result<LoginSession, LoginError> {
        Self::perform_login_with_user_agent(
            host,
            gateway_addr,
            trust,
            deadline,
            username,
            password,
            &default_user_agent(),
        )
        .await
    }

    /// Perform the `WebVPN` login phase against the gateway with an explicit
    /// `User-Agent` — the per-connection override of the settings default
    /// ([`default_user_agent`]). The client name is never hardcoded into the
    /// flow: the caller passes it here, and a config/settings layer may
    /// substitute its own platform default.
    ///
    /// The channel selection is driven by the measured UA gate
    /// (vpn-ct.ecnu.edu.cn, 2026-08-15 probe matrix): the aggregate-auth XML
    /// channel (`POST /` + config-auth XML) opens ONLY for the exact
    /// AnyConnect platform `User-Agent` names (`AnyConnect Win_x86_64
    /// 4.10.05095`, any platform/arch/version variant) — any other UA is
    /// refused with HTTP 404. So `user_agent` decides whether the login runs
    /// the XML flow (PRIMARY) or falls back to the measured FORM flow
    /// (GET `/+CSCOE+/logon.html` -> POST the form ACTION).
    ///
    /// See [`WebvpnLogin::perform_login`] for the full flow and
    /// classification semantics.
    ///
    /// # Errors
    ///
    /// Same as [`WebvpnLogin::perform_login`]: [`LoginError::TlsFailed`],
    /// [`LoginError::DeadlineExceeded`], [`LoginError::HttpFailed`],
    /// [`LoginError::LoginRejected`], [`LoginError::SamlRequired`],
    /// [`LoginError::TwoFactorRequired`], [`LoginError::ProtocolViolation`].
    pub async fn perform_login_with_user_agent(
        host: &str,
        gateway_addr: SocketAddr,
        trust: TrustPolicy,
        deadline: Option<Deadline>,
        username: &[u8],
        password: &[u8],
        user_agent: &str,
    ) -> Result<LoginSession, LoginError> {
        Self::perform_login_with_socket_binder(
            host,
            gateway_addr,
            trust,
            deadline,
            username,
            password,
            user_agent,
            None,
        )
        .await
    }

    /// Perform the `WebVPN` login phase with the login's bootstrap TLS
    /// connections threaded through an explicit [`SocketBinder`] — the same
    /// egress discipline as the CSTP control plane (`BootstrapConfig.
    /// socket_binder`, connector.rs): on the win32 host the binder pins the
    /// socket's source interface to the physical NIC via `IP_UNICAST_IF`,
    /// bypassing a Mihomo TUN default route so the login egress does not
    /// traverse the proxy path. Pass `None` (the `perform_login` /
    /// `perform_login_with_user_agent` behavior) for the platform default.
    ///
    /// See [`WebvpnLogin::perform_login`] for the full flow and
    /// classification semantics; the `socket_binder` is applied to every
    /// bootstrap connection the login opens (aggregate-auth XML channel AND
    /// the form-channel fallback — both the logon GET and the credential
    /// POST run over fresh binder-bound connections).
    ///
    /// # Errors
    ///
    /// Same as [`WebvpnLogin::perform_login`]: [`LoginError::TlsFailed`],
    /// [`LoginError::DeadlineExceeded`], [`LoginError::HttpFailed`],
    /// [`LoginError::LoginRejected`], [`LoginError::SamlRequired`],
    /// [`LoginError::TwoFactorRequired`], [`LoginError::ProtocolViolation`].
    pub async fn perform_login_with_socket_binder(
        host: &str,
        gateway_addr: SocketAddr,
        trust: TrustPolicy,
        deadline: Option<Deadline>,
        username: &[u8],
        password: &[u8],
        user_agent: &str,
        socket_binder: Option<Arc<SocketBinder>>,
    ) -> Result<LoginSession, LoginError> {
        // PRIMARY: the aggregate-auth XML channel (measured: the school
        // gateway opens it only for the exact AnyConnect platform UA; the
        // init probe returned HTTP 200 + auth-request XML with
        // `AnyConnect Win_x86_64 4.10.05095`).
        match aggregate_auth_login(
            host,
            gateway_addr,
            trust.clone(),
            deadline.clone(),
            username,
            password,
            user_agent,
            socket_binder.clone(),
        )
        .await
        {
            Ok(Some(session)) => return Ok(session),
            Ok(None) => {
                tracing::info!(
                    "webvpn: aggregate-auth XML channel unavailable (UA refused / disabled); falling back to the form channel"
                );
            }
            Err(err) => return Err(err),
        }
        // FALLBACK: the measured form flow (the XML channel is the primary;
        // the form flow stays the fallback for gateways that refuse it).
        form_channel_login(
            host,
            gateway_addr,
            trust,
            deadline,
            username,
            password,
            socket_binder,
        )
        .await
    }
}

/// The platform-appropriate AnyConnect `User-Agent` — the SETTINGS DEFAULT
/// the login flow consults when the caller does not override it
/// ([`WebvpnLogin::perform_login`] uses it;
/// [`WebvpnLogin::perform_login_with_user_agent`] overrides it per
/// connection). The client name is never hardcoded into the flow itself.
///
/// Mirrors `src/generated/distribution_config.hpp`
/// (`kDefaultWindowsUserAgent` / `kDefaultMacosUserAgent` /
/// `kDefaultLinuxUserAgent`): Windows -> `AnyConnect Win_<arch> 4.10.05095`,
/// Darwin -> `AnyConnect Darwin_<arch> 4.10.05095`, Linux ->
/// `AnyConnect Linux_<arch> 4.10.05095`, with the architecture adapted at
/// RUNTIME from `std::env::consts::ARCH` (`aarch64` -> `arm64`, `x86_64` ->
/// `x86_64`, anything else passes through). The gateway's UA gate is
/// arch-insensitive (measured probe matrix 2026-08-15: any
/// `AnyConnect <platform>_<arch> <version>` variant is accepted; only the
/// AnyConnect prefix — case-sensitive, first letter capital — is required).
#[must_use]
pub fn default_user_agent() -> String {
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        other => other,
    };
    match std::env::consts::OS {
        "windows" => format!("AnyConnect Win_{arch} 4.10.05095"),
        "macos" => format!("AnyConnect Darwin_{arch} 4.10.05095"),
        _ => format!("AnyConnect Linux_{arch} 4.10.05095"),
    }
}

/// The measured FORM channel of the `WebVPN` login (the FALLBACK; the
/// aggregate-auth XML channel is the primary). Runs over its own fresh
/// bootstrap connections:
///
/// 1. `GET /+CSCOE+/logon.html` on connection #1 (Host: `<host>`); a
///    non-2xx response is already a rejected login. The MEASURED gateway
///    CLOSES this connection after the response (no Content-Length, no
///    chunked — implicit close despite a Keep-Alive header), so the POST
///    MUST use a fresh connection. The response's `Set-Cookie:
///    webvpnlogin=` value (fallback `"1"`, the page-JS constant) is
///    captured for the POST's cookie jar.
/// 2. Parse the form's hidden fields — `tgroup` / `next` / `tgcookieset` /
///    `csrf_token` — the `group_list` select's submitted value (`vpn-ct`
///    on the measured gateway; a browser submits it), and the form ACTION
///    (`/+webvpn+/index.html` on the measured gateway; a relative action is
///    resolved against the gateway origin). The `csrf_token` is REQUIRED
///    (measured: dynamic per request); a form without it is
///    [`LoginError::ProtocolViolation`].
/// 3. `POST` the ACTION on connection #2 (a FRESH bootstrap connection —
///    the gateway closed connection #1 after the GET) with the
///    percent-encoded urlencoded fields: `tgroup`/`next`/`tgcookieset`
///    echoed, `csrf_token` echoed verbatim, `username`, `password`, the
///    `group_list` select's value, and the fixed `Login=Logon` submit
///    value — `Host: <host>`, `Content-Type:
///    application/x-www-form-urlencoded`, a correct `Content-Length`, no
///    `Authorization` header (the form IS the credential exchange), and
///    the CSRF-precheck cookie jar the browser would echo — `Cookie:
///    webvpnlogin=<captured, "1" by default>;
///    CSRFtoken=<the served csrf_token>; webvpnLang=<captured, "en" by
///    default>` (measured 2026-08-15: a POST without the jar is rejected
///    `a0=8` before the credentials are evaluated). The POST response IS
///    `Transfer-Encoding: chunked` (measured), decoded by the login
///    reader.
///
/// Response classification (measured semantics): a 200 is login success
/// ONLY when it carries a real (non-empty) `Set-Cookie: webvpn=` value,
/// captured into [`LoginSession::cookie`]. A 200 that CLEARS the webvpn
/// cookie (`webvpn=; expires=1970` — the measured bad-credential
/// response), a 200 without a webvpn cookie at all, gateway error pages
/// (`+CSCOE+/error`, `login error` markers), and non-2xx statuses are all
/// [`LoginError::LoginRejected`]; a 3xx `Location` carrying
/// `+CSCOE+/saml`, or a meta-refresh page steering to the SAML ACS
/// (CS-AUTH-04), is [`LoginError::SamlRequired`]. When a rejected
/// response body carries the gateway's `a0` result code, it is attached
/// to the [`LoginError::LoginRejected`] `detail` (additive field; read
/// back through [`LoginError::a0_result`]) so the acceptance evidence can
/// distinguish "credentials wrong" (`a0=15`) from "request malformed"
/// (`a0=8`/`114`/`115`/`16`).
///
/// The password bytes are consumed one-shot (`SchoolSecrets` pattern): they
/// exist only in the caller's plaintext buffer and in the POST body during
/// construction, which is zeroized immediately after the request is sent.
async fn form_channel_login(
    host: &str,
    gateway_addr: SocketAddr,
    trust: TrustPolicy,
    deadline: Option<Deadline>,
    username: &[u8],
    password: &[u8],
    socket_binder: Option<Arc<SocketBinder>>,
) -> Result<LoginSession, LoginError> {
        // The login TLS connections are real Bootstrap connections under the
        // injected trust policy (openconnect auth.c do_login() runs the form
        // POST as the credential exchange). Measured 2026-08-15: the gateway
        // CLOSES the connection after the logon.html GET response — no
        // Content-Length, no chunked on the GET, implicit close despite a
        // Keep-Alive header — so the credential POST MUST run over a FRESH
        // connection (a POST on the GET connection dies on the EOF write). A
        // deadline expiry surfaces here as a real rollback.
        let session = Bootstrap::system()
            .connect(BootstrapConfig {
                hostname: host.to_string(),
                gateway_addr,
                trust: trust.clone(),
                dtls_offered: false,
                deadline: deadline.clone(),
                socket_binder: socket_binder.clone(),
                gateway_resolver: None,
            })
            .await
            .map_err(|failure| match failure.error {
                BootstrapError::DeadlineExceeded => LoginError::DeadlineExceeded,
                other => LoginError::TlsFailed(other),
            })?;

        // The frozen bootstrap stays opaque: the TLS stream is handed over
        // through the additive `into_stream` accessor (connector.rs, §7
        // governance record).
        let mut stream = session.into_stream();

        // --- Step 1: GET the login form (connection #1). Measured 2026-08-15:
        // this gateway serves the 10KB form at `/+CSCOE+/logon.html` (`GET /`
        // only JS-redirects there); the xmlpost probe (`POST /` with
        // config-auth XML + X-Aggregate-Auth) is 404, so the form flow IS the
        // channel. The response has no Content-Length and no
        // Transfer-Encoding: the body is delimited by the connection close,
        // which the reader consumes up to (EOF / unexpected-EOF close).
        let get_head = format!("GET /+CSCOE+/logon.html HTTP/1.1\r\nHost: {host}\r\n\r\n");
        stream
            .write_all(get_head.as_bytes())
            .await
            .map_err(|_| LoginError::HttpFailed)?;
        stream.flush().await.map_err(|_| LoginError::HttpFailed)?;

        let logon_page = read_login_response(&mut stream).await?;
        if !(200..=299).contains(&logon_page.status) {
            // The logon-GET rejection predates the credential POST, so no
            // `a0` result code exists to attach.
            return Err(LoginError::login_rejected_with_detail(None));
        }
        let page_text = String::from_utf8_lossy(&logon_page.body);

        // The gateway's CSRF precheck (measured 2026-08-15 probe matrix: a
        // credential POST WITHOUT the cookie jar is rejected with the result
        // code `a0=8` — the request never reaches credential evaluation)
        // requires the POST to carry the jar a browser would echo:
        // `webvpnlogin` (the server Set-Cookies it on this logon GET) and
        // `CSRFtoken` (logon.html JS:
        // `document.cookie="CSRFtoken="+csrf_token+"; path=/; secure"`).
        // Capture the `webvpnlogin` value the GET served (fallback `"1"` —
        // the page-JS constant) and skip the cookies the GET CLEARS (empty
        // values, e.g. the `webvpn=; expires=1970` of a previous session).
        let webvpnlogin = logon_page
            .headers
            .iter()
            .filter(|(name, _)| name == "set-cookie")
            .find_map(|(_, value)| cookie_value_named(value, "webvpnlogin"))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "1".to_string());
        // The GET also Set-Cookies `webvpnLang=en` on the measured gateway
        // (the post-login UI language cookie); a browser echoes it. Captured
        // like `webvpnlogin`, with the same page-constant fallback precedent
        // (`"en"`, the measured value) — so the POST always carries it.
        let webvpnlang = logon_page
            .headers
            .iter()
            .filter(|(name, _)| name == "set-cookie")
            .find_map(|(_, value)| cookie_value_named(value, "webvpnLang"))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "en".to_string());

        // --- Step 2: parse the form. `csrf_token` is REQUIRED (measured:
        // dynamic per request — `7788a917b493948c9c787348e6549d`-shaped); a
        // form without it (or without a form ACTION) is a protocol violation,
        // never a login.
        let form = parse_login_form(&page_text);
        let csrf_token = form
            .csrf_token
            .as_deref()
            .ok_or(LoginError::ProtocolViolation)?;
        let action = resolve_form_action(form.action.as_deref().ok_or(LoginError::ProtocolViolation)?);

        // The gateway already closed connection #1 after the logon.html
        // response; the credential POST goes out on a FRESH connection
        // (measured 2026-08-15: the POST write on the same stream fails with
        // an EOF/closed-connection error -> HttpFailed).
        drop(stream);

        let session = Bootstrap::system()
            .connect(BootstrapConfig {
                hostname: host.to_string(),
                gateway_addr,
                trust,
                dtls_offered: false,
                deadline,
                socket_binder: socket_binder.clone(),
                gateway_resolver: None,
            })
            .await
            .map_err(|failure| match failure.error {
                BootstrapError::DeadlineExceeded => LoginError::DeadlineExceeded,
                other => LoginError::TlsFailed(other),
            })?;
        let mut stream = session.into_stream();

        // --- Step 3: POST construction (connection #2): password bytes live
        // only here, one-shot. The browser's field order:
        // tgroup/next/tgcookieset/csrf_token (echoed), username, password,
        // group_list (the select's selected value — `vpn-ct` on the measured
        // gateway), Login=Logon.
        let mut body = Vec::with_capacity(username.len() + password.len() + csrf_token.len() + 128);
        body.extend_from_slice(b"tgroup=");
        percent_encode_into(
            form.tgroup.as_deref().unwrap_or_default().as_bytes(),
            &mut body,
        );
        body.extend_from_slice(b"&next=");
        percent_encode_into(
            form.next.as_deref().unwrap_or_default().as_bytes(),
            &mut body,
        );
        body.extend_from_slice(b"&tgcookieset=");
        percent_encode_into(
            form.tgcookieset.as_deref().unwrap_or_default().as_bytes(),
            &mut body,
        );
        body.extend_from_slice(b"&csrf_token=");
        percent_encode_into(csrf_token.as_bytes(), &mut body);
        body.extend_from_slice(b"&username=");
        percent_encode_into(username, &mut body);
        body.extend_from_slice(b"&password=");
        percent_encode_into(password, &mut body);
        // The group_list select is submitted by a browser (its selected value
        // `vpn-ct` on the measured gateway); a form WITHOUT the select sends
        // no group_list field at all.
        if let Some(group) = form.group_list.as_deref() {
            body.extend_from_slice(b"&group_list=");
            percent_encode_into(group.as_bytes(), &mut body);
        }
        body.extend_from_slice(b"&Login=Logon");

        let content_length = body.len();
        // The browser jar the POST echoes: `webvpnlogin` (the GET Set-Cookie'd
        // it), `CSRFtoken` (= the served token; logon.html JS plants it) and
        // `webvpnLang` (the GET Set-Cookies it; `"en"` fallback).
        let cookie_header =
            format!("webvpnlogin={webvpnlogin}; CSRFtoken={csrf_token}; webvpnLang={webvpnlang}");
        let head = format!(
            "POST {action} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Cookie: {cookie_header}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {content_length}\r\n\
             \r\n"
        );
        let mut request = head.into_bytes();
        request.extend_from_slice(&body);
        body.zeroize();

        // Send, then wipe the password-bearing request buffer immediately: the
        // engine retains nothing after the POST leaves the process.
        let write_result = stream.write_all(&request).await;
        request.zeroize();
        write_result.map_err(|_| LoginError::HttpFailed)?;
        stream.flush().await.map_err(|_| LoginError::HttpFailed)?;

        // --- Response classification (measured semantics + openconnect auth.c
        // do_login()) ---
        let response = read_login_response(&mut stream).await?;

        // SAML redirect (auth.c handle_saml_redirect(); CS-AUTH-04): a 3xx
        // Location pointing at `+CSCOE+/saml` is never treated as login success.
        if (300..=399).contains(&response.status)
            && response
                .headers
                .iter()
                .any(|(name, value)| name == "location" && value.contains("+CSCOE+/saml"))
        {
            return Err(LoginError::SamlRequired);
        }

        let body_text = String::from_utf8_lossy(&response.body);
        // The gateway's `a0` result code (measured 2026-08-15 probe matrix:
        // `a0=8` CSRF precheck failed — the request never reached credential
        // evaluation; `a0=114`/`115` CSRFtoken cookie / form-field mismatch;
        // `a0=15` real credential rejection; `a0=16` empty user or password
        // field). The code is NOT part of the typed contract: it is attached
        // as DIAGNOSTIC detail to the rejected-login error (the additive
        // `LoginRejected.detail` field, read back through
        // [`LoginError::a0_result`]) and mirrored into the log line — so the
        // acceptance evidence can tell "credentials wrong" (`a0=15`) from
        // "request malformed" (`a0=8`/`114`/`115`/`16`) while the typed
        // variants keep their pinned names.
        let a0 = a0_code(&body_text);
        let a0_diag = a0
            .as_deref()
            .map(|code| format!(" (a0={code})"))
            .unwrap_or_default();

        // Any non-2xx status is a rejected login, even without a body marker.
        if !(200..=299).contains(&response.status) {
            tracing::warn!("webvpn login rejected: HTTP {}{a0_diag}", response.status);
            return Err(LoginError::login_rejected_with_detail(a0.clone()));
        }
        // Gateway error pages: auth.c checks both markers.
        if body_text.contains("+CSCOE+/error") || body_text.contains("login error") {
            tracing::warn!("webvpn login rejected: gateway error page{a0_diag}");
            return Err(LoginError::login_rejected_with_detail(a0.clone()));
        }
        // Body variant of handle_saml_redirect() (plan §3.1, CS-AUTH-04): a
        // meta-refresh steering page to the SAML ACS is SAML detection — it is
        // NEVER login success, even when the page also carries a webvpn cookie.
        if meta_refresh_steers_to_saml_acs(&body_text) {
            return Err(LoginError::SamlRequired);
        }
        // Second password / OTP request: honestly unsupported in the MVP
        // (plan §3.1).
        if body_text.contains("second password") {
            return Err(LoginError::TwoFactorRequired);
        }

        // ONLY the `webvpn` cookie is captured (openconnect http.c
        // openconnect_obtain_cookie() cookie selection). A 2xx with NO webvpn
        // cookie — or with it CLEARED (`webvpn=; expires=1970`, the MEASURED
        // bad-credential response: the gateway clears the cookie on failed
        // credentials and JS-redirects back to logon.html) — is NOT login
        // success, never a success.
        let cookie_value = response
            .headers
            .iter()
            .filter(|(name, _)| name == "set-cookie")
            .find_map(|(_, value)| cookie_value_named(value, "webvpn"))
            .filter(|value| !value.is_empty());
        let Some(cookie_value) = cookie_value else {
            tracing::warn!("webvpn login rejected: no usable webvpn cookie{a0_diag}");
            return Err(LoginError::login_rejected_with_detail(a0));
        };

        Ok(LoginSession {
            cookie: WebvpnCookie {
                value: cookie_value,
            },
            saml_detected: false,
        })
    }

/// The aggregate-auth XML login channel (the PRIMARY — measured
/// vpn-ct.ecnu.edu.cn, 2026-08-15: the gateway opens it only for the exact
/// AnyConnect platform `User-Agent` names; with `AnyConnect Win_x86_64
/// 4.10.05095` the init `POST /` returned HTTP 200 + `config-auth
/// type="auth-request"`). Mirrors the stable C++ v3.3.7
/// `aggregate_auth.cpp` + `production_transport.cpp` flow:
///
/// 1. `POST /` (one keep-alive connection) with the init XML — `<config-auth
///    client="vpn" type="init" aggregate-auth-version="2">` + `<version
///    who="vpn">` (= the UA) + `<device-id>` + `<group-access>` +
///    `<capabilities>` — and the `User-Agent`, `Content-Type: application/xml;
///    charset=utf-8`, `X-Transcend-Version: 1`, `X-Aggregate-Auth: 1`
///    headers -> 200 + `auth-request` XML. Parse the `<opaque>` element(s)
///    VERBATIM (echoed into the reply), the form fields (username/password
///    presence), the `group_list` select's selected value, and any
///    `<session-token>`/`<session-id>`.
/// 2. `POST /` on the SAME connection (keep-alive, the C++ behavior) with
///    the auth-reply XML: the `<opaque>` echoed verbatim + `<auth>
///    <username>` + `<password>` (XML-escaped) + `<group-select>`. If the
///    gateway closed the connection after the init response, the reply is
///    retried ONCE on a FRESH connection (the measured probe showed
///    `Connection: close` also works for the init — the reply carries the
///    credentials and must not be lost to a dead connection).
/// 3. Success = `auth_id="success"` (or a `<session-token>`/`<session-id>`,
///    which IS the credential — `webvpn=<token>`), falling back to the
///    reply's `Set-Cookie: webvpn=`/`webvpn_session=` value; rejection =
///    `auth_id="error"` / `<error>` node (its text is the diagnostic detail)
///    / non-2xx status / non-XML reply; SAML steering is
///    [`LoginError::SamlRequired`].
///
/// Returns `Ok(None)` when the XML channel is UNAVAILABLE — the gateway
/// refused the init probe with 404 (the measured wrong-UA / disabled-channel
/// signature), answered it with a non-XML page, or asked for an interaction
/// without a username/password form — so the caller falls back to the form
/// channel.
async fn aggregate_auth_login(
    host: &str,
    gateway_addr: SocketAddr,
    trust: TrustPolicy,
    deadline: Option<Deadline>,
    username: &[u8],
    password: &[u8],
    user_agent: &str,
    socket_binder: Option<Arc<SocketBinder>>,
) -> Result<Option<LoginSession>, LoginError> {
    // --- Step 1: POST the aggregate-auth init XML (`POST /`, connection #1,
    // keep-alive). ---
    let mut stream =
        connect_bootstrap(host, gateway_addr, trust.clone(), deadline.clone(), socket_binder.clone())
            .await?;
    let init_response = post_aggregate_auth_xml(
        &mut stream,
        host,
        user_agent,
        build_aggregate_auth_init_xml(host, user_agent),
    )
    .await?;

    // SAML steering on the probe (a 3xx Location to `+CSCOE+/saml`) is SAML
    // detection (CS-AUTH-04) — checked before any rejection mapping.
    if (300..=399).contains(&init_response.status) && is_saml_location(&init_response) {
        return Err(LoginError::SamlRequired);
    }
    // The 404 is the MEASURED "XML channel disabled" signature (wrong UA /
    // xmlpost unsupported, e.g. other gateways): the form channel is the
    // fallback.
    if init_response.status == 404 {
        return Ok(None);
    }
    if !(200..=299).contains(&init_response.status) {
        tracing::warn!(
            "webvpn aggregate-auth init rejected: HTTP {}",
            init_response.status
        );
        return Err(LoginError::login_rejected_with_detail(Some(
            init_response.status.to_string(),
        )));
    }

    let init_text = String::from_utf8_lossy(&init_response.body);
    let Some(auth_request) = parse_aggregate_auth_response(&init_text) else {
        // 200 but NOT a config-auth XML document (e.g. the gateway answered
        // the probe with its HTML login page): the XML channel is not open.
        // A SAML steering page is the exception — SAML, never a fallback.
        if meta_refresh_steers_to_saml_acs(&init_text) {
            return Err(LoginError::SamlRequired);
        }
        return Ok(None);
    };

    match auth_request.classify() {
        // The gateway logged the init in directly (a session-token is the
        // credential) — accept it like a reply success.
        AggregateAuthType::Success => {
            return Ok(Some(session_from_aggregate(auth_request, &init_response)?));
        }
        AggregateAuthType::Error => {
            tracing::warn!(
                "webvpn aggregate-auth init rejected: {}",
                auth_request.error_text.as_deref().unwrap_or("auth-rejected")
            );
            return Err(LoginError::login_rejected_with_detail(
                auth_request.error_text,
            ));
        }
        AggregateAuthType::Challenge => return Err(LoginError::TwoFactorRequired),
        AggregateAuthType::HostScan => {
            return Err(LoginError::login_rejected_with_detail(Some(
                "host-scan-required".to_string(),
            )));
        }
        AggregateAuthType::GroupSelect | AggregateAuthType::AuthRequest => {}
    }
    // The XML channel only supports the plain username/password interaction
    // (the measured school shape); any other form is handed to the form
    // channel.
    if !auth_request.has_field("username") || !auth_request.has_field("password") {
        return Ok(None);
    }
    let group = auth_request.field_value("group_list").unwrap_or_default();

    // --- Step 2: POST the auth-reply (the `<opaque>` echoed verbatim; the
    // credentials XML-escaped; the group-select echoed). One keep-alive
    // connection; if the gateway closed it after the init response, retry
    // the reply ONCE on a FRESH connection (the reply carries the
    // credentials and must not be lost to a dead connection). ---
    let reply_response = match post_aggregate_auth_xml(
        &mut stream,
        host,
        user_agent,
        build_aggregate_auth_reply_xml(
            user_agent,
            &auth_request.opaque_xml,
            username,
            password,
            group,
        ),
    )
    .await
    {
        Ok(response) => response,
        Err(_) => {
            // The gateway may have closed the connection after the init
            // response (the measured probe showed `Connection: close` also
            // works for the init): the auth-reply — which carries the
            // credentials — is retried ONCE on a FRESH connection.
            let mut fresh =
                connect_bootstrap(host, gateway_addr, trust, deadline, socket_binder.clone()).await?;
            post_aggregate_auth_xml(
                &mut fresh,
                host,
                user_agent,
                build_aggregate_auth_reply_xml(
                    user_agent,
                    &auth_request.opaque_xml,
                    username,
                    password,
                    group,
                ),
            )
            .await?
        }
    };

    // --- Step 3: classify the reply. ---
    if (300..=399).contains(&reply_response.status) && is_saml_location(&reply_response) {
        return Err(LoginError::SamlRequired);
    }
    if !(200..=299).contains(&reply_response.status) {
        tracing::warn!(
            "webvpn aggregate-auth reply rejected: HTTP {}",
            reply_response.status
        );
        return Err(LoginError::login_rejected_with_detail(Some(
            reply_response.status.to_string(),
        )));
    }
    let reply_text = String::from_utf8_lossy(&reply_response.body);
    if meta_refresh_steers_to_saml_acs(&reply_text) {
        return Err(LoginError::SamlRequired);
    }
    let Some(submitted) = parse_aggregate_auth_response(&reply_text) else {
        // The channel was open for the init but the reply is not
        // aggregate-auth XML: the submission was not accepted.
        tracing::warn!("webvpn aggregate-auth reply was not config-auth XML");
        return Err(LoginError::login_rejected_with_detail(None));
    };
    match submitted.classify() {
        AggregateAuthType::Success => {
            Ok(Some(session_from_aggregate(submitted, &reply_response)?))
        }
        AggregateAuthType::Error => {
            tracing::warn!(
                "webvpn aggregate-auth rejected credentials: {}",
                submitted.error_text.as_deref().unwrap_or("auth-rejected")
            );
            Err(LoginError::login_rejected_with_detail(
                submitted.error_text,
            ))
        }
        AggregateAuthType::Challenge => Err(LoginError::TwoFactorRequired),
        AggregateAuthType::HostScan => Err(LoginError::login_rejected_with_detail(
            Some("host-scan-required".to_string()),
        )),
        // The gateway re-asked (auth-request / group-select): the one-shot
        // submission was not accepted in a single round.
        AggregateAuthType::GroupSelect | AggregateAuthType::AuthRequest => {
            tracing::warn!("webvpn aggregate-auth re-asked for credentials after the auth-reply");
            Err(LoginError::login_rejected_with_detail(None))
        }
    }
}

/// Establish a bootstrap TLS connection to the gateway, mapping bootstrap
/// failures to the typed [`LoginError`] values.
async fn connect_bootstrap(
    host: &str,
    gateway_addr: SocketAddr,
    trust: TrustPolicy,
    deadline: Option<Deadline>,
    socket_binder: Option<Arc<SocketBinder>>,
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, LoginError> {
    let session = Bootstrap::system()
        .connect(BootstrapConfig {
            hostname: host.to_string(),
            gateway_addr,
            trust,
            dtls_offered: false,
            deadline,
            socket_binder,
            gateway_resolver: None,
        })
        .await
        .map_err(|failure| match failure.error {
            BootstrapError::DeadlineExceeded => LoginError::DeadlineExceeded,
            other => LoginError::TlsFailed(other),
        })?;
    Ok(session.into_stream())
}

/// Frame, send and read one aggregate-auth `POST /` exchange: the
/// `User-Agent` + `Content-Type: application/xml; charset=utf-8` +
/// `Accept-Encoding: identity` + `X-Transcend-Version: 1` +
/// `X-Aggregate-Auth: 1` + `Connection: keep-alive` headers (the C++
/// `make_aggregate_auth_post_request` shape), a correct `Content-Length`, and
/// the XML body. The body buffer is zeroized immediately after the POST
/// leaves the process (the auth-reply body carries the password).
async fn post_aggregate_auth_xml<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    host: &str,
    user_agent: &str,
    mut body: String,
) -> Result<LoginResponse, LoginError> {
    let head = format!(
        "POST / HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {user_agent}\r\n\
         Content-Type: application/xml; charset=utf-8\r\n\
         Accept-Encoding: identity\r\n\
         X-Transcend-Version: 1\r\n\
         X-Aggregate-Auth: 1\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n",
        body.len()
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(body.as_bytes());
    body.zeroize();
    let write_result = stream.write_all(&request).await;
    request.zeroize();
    write_result.map_err(|_| LoginError::HttpFailed)?;
    stream.flush().await.map_err(|_| LoginError::HttpFailed)?;
    read_login_response(stream).await
}

/// The init/auth-reply XML construction for the aggregate-auth channel
/// (mirrors `aggregate_auth.cpp` `build_aggregate_auth_init_xml` /
/// `build_aggregate_auth_reply_xml`; the `version who="vpn"` element carries
/// the client name — the UA — and `<device-id>` is a stable client
/// identifier).
fn build_aggregate_auth_init_xml(host: &str, user_agent: &str) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<config-auth client=\"vpn\" type=\"init\" aggregate-auth-version=\"2\">\n");
    out.push_str("  <version who=\"vpn\">");
    xml_escape_into(&mut out, user_agent);
    out.push_str("</version>\n");
    out.push_str("  <device-id>exv-native</device-id>\n");
    out.push_str("  <group-access>https://");
    xml_escape_into(&mut out, host);
    out.push_str("/</group-access>\n");
    out.push_str("  <capabilities>\n");
    out.push_str("    <auth-method>single-sign-on-v2</auth-method>\n");
    out.push_str("  </capabilities>\n");
    out.push_str("</config-auth>");
    out
}

/// Build the aggregate-auth auth-reply XML: the `<opaque>` element(s) from
/// the auth-request echoed VERBATIM (they carry the `aggauth-handle`), the
/// credentials as `<auth><username>` + `<password>` (XML-escaped; empty
/// values are omitted, the C++ `append_text_node` semantics), and the
/// `<group-select>` (the parsed `group_list` value, omitted when empty).
fn build_aggregate_auth_reply_xml(
    user_agent: &str,
    opaque_xml: &[String],
    username: &[u8],
    password: &[u8],
    group: &str,
) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<config-auth client=\"vpn\" type=\"auth-reply\" aggregate-auth-version=\"2\">\n",
    );
    out.push_str("  <version who=\"vpn\">");
    xml_escape_into(&mut out, user_agent);
    out.push_str("</version>\n");
    out.push_str("  <device-id>exv-native</device-id>\n");
    out.push_str("  <capabilities>\n");
    out.push_str("    <auth-method>single-sign-on-v2</auth-method>\n");
    out.push_str("  </capabilities>\n");
    for opaque in opaque_xml {
        out.push_str("  ");
        out.push_str(opaque);
        out.push('\n');
    }
    out.push_str("  <auth>\n");
    if !username.is_empty() {
        out.push_str("    <username>");
        xml_escape_into(&mut out, &String::from_utf8_lossy(username));
        out.push_str("</username>\n");
    }
    if !password.is_empty() {
        out.push_str("    <password>");
        xml_escape_into(&mut out, &String::from_utf8_lossy(password));
        out.push_str("</password>\n");
    }
    out.push_str("  </auth>\n");
    if !group.is_empty() {
        out.push_str("  <group-select>");
        xml_escape_into(&mut out, group);
        out.push_str("</group-select>\n");
    }
    out.push_str("</config-auth>");
    out
}

/// XML-escape `value` into `out` (the five predefined entities `& < > " '`).
fn xml_escape_into(out: &mut String, value: &str) {
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
}

/// Unescape the five XML predefined entities (`&quot; &apos; &lt; &gt;
/// &amp;`), `&amp;` LAST so an escaped `&amp;lt;` never double-unescapes
/// (the C++ `xml_unescape` order).
fn xml_unescape(value: &str) -> String {
    let mut out = value.to_string();
    for (from, to) in [
        ("&quot;", "\""),
        ("&apos;", "'"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&amp;", "&"),
    ] {
        out = out.replace(from, to);
    }
    out
}

/// A parsed aggregate-auth `config-auth` document (the
/// `parse_aggregate_auth_response` semantics of `aggregate_auth.cpp`).
struct AggregateAuthResponse {
    /// The `id` attribute of the `<auth>` element (`"main"` on an
    /// auth-request, `"success"` on success, `"error"` on rejection).
    auth_id: Option<String>,
    /// The `type` attribute of the `<config-auth>` root (`"complete"` is a
    /// success signature).
    root_type: Option<String>,
    /// Whether the document carries a `<host-scan>` element (the AnyConnect
    /// host scanner is required — unsupported in the MVP).
    has_host_scan: bool,
    /// The `<opaque>` elements' raw markup, VERBATIM (echoed into the
    /// auth-reply).
    opaque_xml: Vec<String>,
    /// The `<input>` / `<select>` form fields of an auth-request.
    fields: Vec<AggregateAuthField>,
    /// The `<session-token>` value (the aggregate-auth v2 success credential).
    session_token: Option<String>,
    /// The `<session-id>` value (an alternate success credential).
    session_id: Option<String>,
    /// The text of the first `<error>` node (rejection detail).
    error_text: Option<String>,
}

impl AggregateAuthResponse {
    /// Whether the form carries a field named `name` (the C++
    /// `has_field` semantics).
    fn has_field(&self, name: &str) -> bool {
        self.fields.iter().any(|field| field.name == name)
    }

    /// The value of the field named `name` (`None` when absent).
    fn field_value(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|field| field.name == name)
            .map(|field| field.value.as_str())
    }

    /// Classify the document (the C++
    /// `parse_aggregate_auth_response` ordering): a session token / id is a
    /// SUCCESS; `auth_id="error"` or an `<error>` node is an ERROR; a
    /// challenge/secondary form field is a CHALLENGE; a `group_list`-only
    /// form is GROUP_SELECT; `auth_id="success"` or root
    /// `type="complete"` is a SUCCESS; anything else is an AUTH_REQUEST.
    fn classify(&self) -> AggregateAuthType {
        if self.session_token.is_some() || self.session_id.is_some() {
            return AggregateAuthType::Success;
        }
        if self.has_host_scan {
            return AggregateAuthType::HostScan;
        }
        if self.auth_id.as_deref() == Some("error") || self.error_text.is_some() {
            return AggregateAuthType::Error;
        }
        if self.fields.iter().any(is_challenge_field) {
            return AggregateAuthType::Challenge;
        }
        let has_username = self.has_field("username");
        let has_password = self.has_field("password");
        if self.has_field("group_list") && !has_username && !has_password {
            return AggregateAuthType::GroupSelect;
        }
        if self.auth_id.as_deref() == Some("success")
            || self.root_type.as_deref() == Some("complete")
        {
            return AggregateAuthType::Success;
        }
        AggregateAuthType::AuthRequest
    }
}

/// The classified outcome of an aggregate-auth `config-auth` document
/// (aggregate_auth.cpp `AggregateAuthResponseType`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AggregateAuthType {
    /// The gateway asked for credentials (username/password form).
    AuthRequest,
    /// The gateway asked for a group selection first (no credentials yet).
    GroupSelect,
    /// The gateway asked for a second password / OTP / challenge.
    Challenge,
    /// The gateway requires the AnyConnect host scanner.
    HostScan,
    /// The gateway rejected the exchange.
    Error,
    /// The exchange succeeded (a session token / id, or `auth_id="success"`).
    Success,
}

/// One parsed aggregate-auth form field (`<input>` or `<select>`): the
/// select's value is its SELECTED option's value (what the client submits).
struct AggregateAuthField {
    name: String,
    value: String,
}

/// Whether a form field name marks a second-password / OTP challenge (the
/// C++ `has_challenge_field` keyword set).
fn is_challenge_field(field: &AggregateAuthField) -> bool {
    let name = field.name.to_ascii_lowercase();
    name.contains("secondary")
        || name.contains("challenge")
        || name.contains("token")
        || name.contains("passcode")
}

/// Parse an aggregate-auth response body into its structured form, or `None`
/// when the body is not a `config-auth` XML document (empty, an HTML page —
/// the C++ `auth_protocol_mismatch` — or a different root).
fn parse_aggregate_auth_response(xml: &str) -> Option<AggregateAuthResponse> {
    let trimmed = xml.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("<html") || !lower.contains("<config-auth") {
        return None;
    }
    let root_type = first_tag(trimmed, "config-auth")
        .as_deref()
        .and_then(|tag| attr_value_ci(tag, "type"))
        .map(str::to_string);
    let auth_id = first_tag(trimmed, "auth")
        .as_deref()
        .and_then(|tag| attr_value_ci(tag, "id"))
        .map(str::to_string);
    let mut fields = input_fields(trimmed);
    fields.extend(select_fields(trimmed));
    Some(AggregateAuthResponse {
        auth_id,
        root_type,
        has_host_scan: lower.contains("<host-scan"),
        opaque_xml: opaque_nodes(trimmed),
        fields,
        session_token: node_text(trimmed, "session-token"),
        session_id: node_text(trimmed, "session-id"),
        error_text: node_text(trimmed, "error"),
    })
}

/// The first `<name ...>` opening tag of `xml` (attributes included), at an
/// element-name boundary (`<auth` never matches `<auth-method>`). `None` when
/// the element is absent.
fn first_tag(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}");
    let mut search_from = 0;
    while let Some(rel) = xml[search_from..].find(&open) {
        let start = search_from + rel;
        let boundary_ok = xml[start + open.len()..]
            .chars()
            .next()
            .is_none_or(|c| c == '>' || c == '/' || c.is_whitespace());
        if boundary_ok {
            let tag_end = xml[start..].find('>')?;
            return Some(xml[start..start + tag_end + 1].to_string());
        }
        search_from = start + open.len();
    }
    None
}

/// The trimmed, entity-unescaped text content of the FIRST `<name>` element
/// (`None` when absent).
fn node_text(xml: &str, name: &str) -> Option<String> {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let mut search_from = 0;
    while let Some(rel) = xml[search_from..].find(&open) {
        let start = search_from + rel;
        let boundary_ok = xml[start + open.len()..]
            .chars()
            .next()
            .is_none_or(|c| c == '>' || c == '/' || c.is_whitespace());
        if !boundary_ok {
            search_from = start + open.len();
            continue;
        }
        let open_end = xml[start..].find('>')?;
        let inner_start = start + open_end + 1;
        let close_rel = xml[inner_start..].find(&close)?;
        return Some(xml_unescape(xml[inner_start..inner_start + close_rel].trim()));
    }
    None
}

/// The `<input>` fields of an aggregate-auth form (the C++
/// `input_fields` semantics: name/type/value attributes; a non-self-closing
/// `<input>` takes its text content as the value).
fn input_fields(xml: &str) -> Vec<AggregateAuthField> {
    let mut fields = Vec::new();
    let mut pos = 0;
    while let Some(rel) = xml[pos..].find("<input") {
        let start = pos + rel;
        let Some(tag_end) = xml[start..].find('>') else {
            break;
        };
        let tag = &xml[start..start + tag_end + 1];
        let Some(name) = attr_value_ci(tag, "name") else {
            pos = start + tag_end + 1;
            continue;
        };
        let mut value = attr_value_ci(tag, "value").unwrap_or_default().to_string();
        if !tag.trim_end().ends_with('/') && value.is_empty() {
            // `<input>text</input>` (rare): the text content is the value.
            let inner_start = start + tag_end + 1;
            if let Some(close_rel) = xml[inner_start..].find("</input>") {
                value = xml_unescape(xml[inner_start..inner_start + close_rel].trim());
            }
        }
        fields.push(AggregateAuthField {
            name: name.trim().to_string(),
            value,
        });
        pos = start + tag_end + 1;
    }
    fields
}

/// The `<select>` fields of an aggregate-auth form (the C++
/// `select_fields` semantics): the field value is the SELECTED option's
/// value — or the first option's when none is selected — exactly what a
/// client submits.
fn select_fields(xml: &str) -> Vec<AggregateAuthField> {
    let mut fields = Vec::new();
    let mut pos = 0;
    while let Some(rel) = xml[pos..].find("<select") {
        let start = pos + rel;
        let Some(tag_end) = xml[start..].find('>') else {
            break;
        };
        let tag = &xml[start..start + tag_end + 1];
        let inner_start = start + tag_end + 1;
        let Some(close_rel) = xml[inner_start..].find("</select>") else {
            break;
        };
        let inner = &xml[inner_start..inner_start + close_rel];
        if let Some(name) = attr_value_ci(tag, "name") {
            if let Some(value) = selected_option_value(inner) {
                fields.push(AggregateAuthField {
                    name: name.trim().to_string(),
                    value,
                });
            }
        }
        pos = inner_start + close_rel;
    }
    fields
}

/// The `<opaque>` elements' raw markup, VERBATIM (the C++ `opaque_nodes`
/// semantics): collected for echo into the auth-reply — the gateway's
/// `aggauth-handle` must round-trip byte-for-byte.
fn opaque_nodes(xml: &str) -> Vec<String> {
    let mut nodes = Vec::new();
    let mut pos = 0;
    while let Some(rel) = xml[pos..].find("<opaque") {
        let start = pos + rel;
        let Some(close_rel) = xml[start..].find("</opaque>") else {
            break;
        };
        let end = start + close_rel + "</opaque>".len();
        nodes.push(xml[start..end].to_string());
        pos = end;
    }
    nodes
}

/// Whether an HTTP response is a SAML steering redirect: a 3xx whose
/// `Location` points at the `+CSCOE+/saml` ACS (openconnect `auth.c
/// handle_saml_redirect()`, CS-AUTH-04).
fn is_saml_location(response: &LoginResponse) -> bool {
    response
        .headers
        .iter()
        .any(|(name, value)| name == "location" && value.contains("+CSCOE+/saml"))
}

/// Build the login session from an aggregate-auth SUCCESS response: the
/// `<session-token>` (or `<session-id>`) from the XML IS the credential
/// (`webvpn=<token>`, the C++ `auth_cookie_` construction); without one, the
/// `Set-Cookie: webvpn=` (or `webvpn_session=`) value from the response. A
/// success WITHOUT either is a rejected login (the C++ `missing session
/// token` gate) — never a success.
fn session_from_aggregate(
    response: AggregateAuthResponse,
    http: &LoginResponse,
) -> Result<LoginSession, LoginError> {
    let token = response.session_token.or(response.session_id);
    let cookie = if let Some(token) = token {
        token
    } else {
        let Some(cookie) = http
            .headers
            .iter()
            .filter(|(name, _)| name == "set-cookie")
            .find_map(|(_, value)| {
                cookie_value_named(value, "webvpn")
                    .or_else(|| cookie_value_named(value, "webvpn_session"))
            })
            .filter(|value| !value.is_empty())
        else {
            return Err(LoginError::login_rejected_with_detail(None));
        };
        cookie
    };
    Ok(LoginSession {
        cookie: WebvpnCookie { value: cookie },
        saml_detected: false,
    })
}

/// Build the byte-exact CSTP CONNECT request bytes for the session phase
/// (CS-AUTH-02, plan §3.2 verbatim block; openconnect `cstp.c`
/// `start_cstp_connection()` anchors — the tag pin and per-line verification
/// are recorded at the leaf commit, per plan §3 provenance discipline).
///
/// The request is `\r\n\r\n`-terminated: `CONNECT /CSCOSSLC/tunnel HTTP/1.1`,
/// `Host: <host>`, `Cookie: webvpn=<cookie>` (the captured value verbatim,
/// never percent-encoded), `X-CSTP-Version: 1`, `X-CSTP-Hostname: <host>` and
/// the `X-CSTP-Protocol` shibboleth. The webvpn cookie IS the credential: no
/// `Authorization` header and no `X-AnyConnect-*` header belong in the desktop
/// client's request.
#[must_use]
pub fn build_connect_request(host: &str, session: &LoginSession) -> Vec<u8> {
    let cookie = session.cookie.as_str();
    format!(
        "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n\
         Host: {host}\r\n\
         Cookie: webvpn={cookie}\r\n\
         X-CSTP-Version: 1\r\n\
         X-CSTP-Hostname: {host}\r\n\
         X-CSTP-Protocol: \"Copyright (c) 2004 Cisco Systems, Inc.\"\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Build the byte-exact CSTP CONNECT request bytes carrying the client
/// `User-Agent` — the additive UA variant of [`build_connect_request`] (the
/// C++ `make_cstp_connect_request` shape: `User-Agent` right after `Host`).
/// The webvpn cookie remains the credential; the UA is the client identity
/// the gateway logs. The legacy UA-less CONNECT ([`build_connect_request`])
/// stays verified working on the school gateway; a config/settings layer
/// feeds its client-name override into this builder through the session-phase
/// entry point [`CstpSession::open_with_user_agent`](crate::session::CstpSession::open_with_user_agent).
#[must_use]
pub fn build_connect_request_with_user_agent(
    host: &str,
    session: &LoginSession,
    user_agent: &str,
) -> Vec<u8> {
    let cookie = session.cookie.as_str();
    format!(
        "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: {user_agent}\r\n\
         Cookie: webvpn={cookie}\r\n\
         X-CSTP-Version: 1\r\n\
         X-CSTP-Hostname: {host}\r\n\
         X-CSTP-Protocol: \"Copyright (c) 2004 Cisco Systems, Inc.\"\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Percent-encode `input` (RFC 3986: unreserved characters pass through,
/// everything else is `%XX` with uppercase hex) and append the result to `out`.
fn percent_encode_into(input: &[u8], out: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in input {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte);
        } else {
            out.push(b'%');
            out.push(HEX[(byte >> 4) as usize]);
            out.push(HEX[(byte & 0x0f) as usize]);
        }
    }
}

/// The hidden-field values and POST target parsed from the gateway's
/// `/+CSCOE+/logon.html` login form.
struct LoginForm {
    /// The `tgroup` hidden-field value (echoed back into the POST; empty on
    /// the measured gateway).
    tgroup: Option<String>,
    /// The `next` hidden-field value (echoed back into the POST; empty on the
    /// measured gateway).
    next: Option<String>,
    /// The `tgcookieset` hidden-field value (echoed back into the POST; empty
    /// on the measured gateway).
    tgcookieset: Option<String>,
    /// The `csrf_token` hidden-field value (REQUIRED; dynamic per request on
    /// the measured gateway).
    csrf_token: Option<String>,
    /// The `group_list` select's submitted value — the SELECTED option's
    /// `value` (`vpn-ct` on the measured gateway; a browser submits it).
    /// `None` when the form has no `group_list` select — then no
    /// `group_list` field goes on the wire.
    group_list: Option<String>,
    /// The form's `action` attribute — the POST target (measured
    /// `/+webvpn+/index.html`).
    action: Option<String>,
}

/// Parse the login form out of a `/+CSCOE+/logon.html` page body.
///
/// Real-gateway shape (measured 2026-08-15): a
/// `<form action="/+webvpn+/index.html" method="post">` containing hidden
/// `<input type="hidden" name=... value=...>` fields for `tgroup` / `next` /
/// `tgcookieset` / `csrf_token`, plus the `username` / `password` text fields,
/// the `group_list` select (selected value `vpn-ct`) and the `Login` submit
/// button. Attribute-name matching is case-insensitive and
/// attribute-order-agnostic; values are taken verbatim (no HTML-entity
/// decoding — the fields are plain on the measured gateway).
fn parse_login_form(body_text: &str) -> LoginForm {
    let mut form = LoginForm {
        tgroup: None,
        next: None,
        tgcookieset: None,
        csrf_token: None,
        group_list: None,
        action: None,
    };
    let mut rest = body_text;
    while let Some(start) = rest.find("<input") {
        let tail = &rest[start + "<input".len()..];
        let Some(tag_len) = tail.find('>') else {
            break;
        };
        let tag = &rest[start..start + "<input".len() + tag_len + 1];
        if let Some(name) = attr_value_ci(tag, "name") {
            let value = attr_value_ci(tag, "value").unwrap_or_default();
            match name.trim() {
                "tgroup" => form.tgroup = Some(value.to_string()),
                "next" => form.next = Some(value.to_string()),
                "tgcookieset" => form.tgcookieset = Some(value.to_string()),
                "csrf_token" => form.csrf_token = Some(value.to_string()),
                _ => {}
            }
        }
        rest = &rest[start + "<input".len()..];
    }
    // The form ACTION: the first `<form ... action=...>` tag wins.
    rest = body_text;
    while let Some(start) = rest.find("<form") {
        let tail = &rest[start + "<form".len()..];
        let Some(tag_len) = tail.find('>') else {
            break;
        };
        let tag = &rest[start..start + "<form".len() + tag_len + 1];
        if let Some(action) = attr_value_ci(tag, "action") {
            form.action = Some(action.trim().to_string());
            break;
        }
        rest = &rest[start + "<form".len()..];
    }
    // The group_list select is a `<select>` element (not an `<input>`, so the
    // input scan above skips it); a browser submits its selected value.
    form.group_list = parse_group_list(body_text);
    form
}

/// The submitted value of the `group_list` select in a logon form, if the
/// form has one: the `value` of the SELECTED `<option>` — or, when no option
/// is marked selected, of the FIRST option (what a browser submits). The
/// measured gateway (vpn-ct.ecnu.edu.cn, 2026-08-15) serves a `group_list`
/// select with `vpn-ct` selected, so a browser's POST carries
/// `group_list=vpn-ct` — the field the diagnosis probe had dropped.
fn parse_group_list(body_text: &str) -> Option<String> {
    let mut rest = body_text;
    while let Some(start) = rest.find("<select") {
        let tail = &rest[start + "<select".len()..];
        let Some(tag_len) = tail.find('>') else {
            break;
        };
        let tag = &rest[start..start + "<select".len() + tag_len + 1];
        if attr_value_ci(tag, "name").is_some_and(|n| n.trim().eq_ignore_ascii_case("group_list")) {
            let inner_start = start + "<select".len() + tag_len + 1;
            let inner = &rest[inner_start..];
            let Some(close) = inner.find("</select") else {
                break;
            };
            return selected_option_value(&inner[..close]);
        }
        rest = &rest[start + "<select".len()..];
    }
    None
}

/// The value a browser submits for a `<select>` whose option markup is
/// `options`: the `value` of the first `<option>` carrying a `selected`
/// attribute, else of the first option overall (HTML default-selection
/// semantics). An option without a `value` attribute submits its text
/// content.
fn selected_option_value(options: &str) -> Option<String> {
    let mut rest = options;
    let mut first: Option<String> = None;
    while let Some(start) = rest.find("<option") {
        let tail = &rest[start + "<option".len()..];
        let Some(tag_len) = tail.find('>') else {
            break;
        };
        let tag = &rest[start..start + "<option".len() + tag_len + 1];
        let value = attr_value_ci(tag, "value")
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                // No value attribute: the browser submits the option's text.
                rest[start + "<option".len() + tag_len + 1..]
                    .split("</option")
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            });
        if first.is_none() {
            first = Some(value.clone());
        }
        if has_attr_ci(tag, "selected") {
            return Some(value);
        }
        rest = &rest[start + "<option".len()..];
    }
    first
}

/// Whether an HTML tag carries the attribute `name` — matched at an
/// attribute-name boundary (like [`attr_value_ci`]) but without requiring a
/// value, for value-less attributes such as `selected`.
fn has_attr_ci(tag: &str, name: &str) -> bool {
    let lower = tag.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(rel) = lower[search_from..].find(name) {
        let idx = search_from + rel;
        let preceded_by_word_char = idx.checked_sub(1).is_some_and(|i| {
            lower.as_bytes()[i].is_ascii_alphanumeric()
                || lower.as_bytes()[i] == b'-'
                || lower.as_bytes()[i] == b'_'
        });
        if !preceded_by_word_char
            && lower
                .as_bytes()
                .get(idx + name.len())
                .is_some_and(|c| *c == b'=' || c.is_ascii_whitespace() || *c == b'>' || *c == b'/')
        {
            return true;
        }
        search_from = idx + name.len();
    }
    false
}

/// Resolve the login form's `action` attribute into a POST request-target
/// path.
///
/// The measured gateway action is the absolute path `/+webvpn+/index.html`
/// (2026-08-15 probe). An absolute URL is reduced to its path, and a relative
/// action is resolved against the gateway origin — the TLS peer this
/// connection was established with, so only the path is needed on the wire
/// (`Host:` already carries the authority).
fn resolve_form_action(action: &str) -> String {
    if let Some(rest) = action
        .strip_prefix("https://")
        .or_else(|| action.strip_prefix("http://"))
    {
        return rest
            .find('/')
            .map(|i| rest[i..].to_string())
            .unwrap_or_else(|| "/".to_string());
    }
    if action.starts_with('/') {
        action.to_string()
    } else {
        format!("/{action}")
    }
}

/// The value of attribute `name` in an HTML tag string, matching the attribute
/// name case-insensitively and handling single-quoted, double-quoted and
/// unquoted values. The value is returned verbatim (HTML attribute names are
/// case-insensitive; values are not). The name must start at an
/// attribute-name boundary (not mid-word, e.g. inside another attribute's
/// value).
fn attr_value_ci<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let lower = tag.to_ascii_lowercase();
    let mut search_from = 0;
    while let Some(rel) = lower[search_from..].find(name) {
        let idx = search_from + rel;
        let preceded_by_word_char = idx
            .checked_sub(1)
            .is_some_and(|i| lower.as_bytes()[i].is_ascii_alphanumeric() || lower.as_bytes()[i] == b'-' || lower.as_bytes()[i] == b'_');
        if !preceded_by_word_char && lower.as_bytes().get(idx + name.len()) == Some(&b'=') {
            let after = &tag[idx + name.len() + 1..];
            if let Some(value) = after.strip_prefix('"') {
                return value.split('"').next();
            }
            if let Some(value) = after.strip_prefix('\'') {
                return value.split('\'').next();
            }
            return Some(
                after
                    .split(|c: char| c.is_whitespace() || c == '>')
                    .next()
                    .unwrap_or_default(),
            );
        }
        search_from = idx + name.len();
    }
    None
}

/// A parsed HTTP response: status code, headers (lower-cased names) and body.
struct LoginResponse {
    /// The HTTP status code.
    status: u16,
    /// The response headers, name lower-cased, in wire order.
    headers: Vec<(String, String)>,
    /// The response body (Content-Length-declared, chunked
    /// transfer-encoding-decoded, or the rest of the stream).
    body: Vec<u8>,
}

/// Read a full HTTP response from `stream`: the head up to the `\r\n\r\n`
/// terminator, then the body — the Content-Length-declared body, the chunked
/// transfer-encoding body (the MEASURED credential-POST transport: the gateway
/// answers the POST `Transfer-Encoding: chunked`, so the chunks must be
/// decoded), or, defensively, the rest of the stream when neither is declared
/// (the MEASURED logon.html GET transport: the gateway CLOSES the connection
/// after the response — implicit close despite a Keep-Alive header — so the
/// close/EOF IS the body delimiter).
async fn read_login_response<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<LoginResponse, LoginError> {
    const MAX_HEAD: usize = 16 * 1024;
    const MAX_BODY: usize = 256 * 1024;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];

    // Head: read until the `\r\n\r\n` terminator.
    let head_end = loop {
        if let Some(end) = find_header_end(&buf) {
            break end;
        }
        if buf.len() >= MAX_HEAD {
            return Err(LoginError::HttpFailed);
        }
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|_| LoginError::HttpFailed)?;
        if n == 0 {
            return Err(LoginError::HttpFailed);
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let head = String::from_utf8_lossy(&buf[..head_end]);
    let status = parse_status(&head).ok_or(LoginError::HttpFailed)?;
    let headers = parse_headers(&head);
    let declared = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok());
    let chunked = headers.iter().any(|(name, value)| {
        name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked")
    });

    let pending = buf.split_off(head_end);
    let body = if chunked {
        // Transfer-Encoding takes precedence over Content-Length (RFC 9112
        // §6.1): decode the chunked body to its full length. Reading to EOF is
        // NOT an option here — the measured gateway answers the credential
        // POST chunked, so the chunks themselves delimit the body.
        decode_chunked_body(stream, pending, MAX_BODY).await?
    } else if let Some(want) = declared {
        let mut body = pending;
        while body.len() < want {
            read_more(stream, &mut body, &mut tmp).await?;
            if body.len() > MAX_BODY {
                return Err(LoginError::HttpFailed);
            }
        }
        body.truncate(want);
        body
    } else {
        // No Content-Length and no Transfer-Encoding: the body is delimited by
        // the connection close (the MEASURED logon.html GET transport).
        let mut body = pending;
        loop {
            match stream.read(&mut tmp).await {
                Ok(0) => break,
                Ok(n) => {
                    body.extend_from_slice(&tmp[..n]);
                    if body.len() > MAX_BODY {
                        return Err(LoginError::HttpFailed);
                    }
                }
                // The measured gateway closes the GET connection WITHOUT a TLS
                // close_notify; rustls surfaces that close as an
                // unexpected-EOF io error. For an implicit-close body that IS
                // the end of the response — not a transport failure.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(_) => return Err(LoginError::HttpFailed),
            }
        }
        body
    };

    Ok(LoginResponse {
        status,
        headers,
        body,
    })
}

/// Read more bytes from `stream` into `pending`, failing on EOF (a response
/// truncated mid-body) with [`LoginError::HttpFailed`].
async fn read_more<S: AsyncRead + Unpin>(
    stream: &mut S,
    pending: &mut Vec<u8>,
    tmp: &mut [u8],
) -> Result<(), LoginError> {
    let n = stream
        .read(tmp)
        .await
        .map_err(|_| LoginError::HttpFailed)?;
    if n == 0 {
        return Err(LoginError::HttpFailed);
    }
    pending.extend_from_slice(&tmp[..n]);
    Ok(())
}

/// Decode a chunked transfer-encoding body (RFC 9112 §7.1.2) from `pending`
/// (bytes already read after the head) plus `stream`: each chunk is a hex size
/// line, the chunk bytes, and a CRLF; a zero-size chunk ends the body,
/// optionally followed by trailer lines up to the terminating blank line.
///
/// This is the transport the MEASURED gateway uses for the credential-POST
/// response (200, `Transfer-Encoding: chunked`): EOF never arrives before the
/// final zero-size chunk, so the chunks themselves delimit the body. Any
/// malformed size line, truncated chunk, or size overflow is
/// [`LoginError::HttpFailed`], the same mapping as every other read/parse
/// failure.
async fn decode_chunked_body<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut pending: Vec<u8>,
    max_body: usize,
) -> Result<Vec<u8>, LoginError> {
    let mut body = Vec::new();
    let mut tmp = [0u8; 1024];

    loop {
        // The chunk size line ends at its CRLF.
        let line_end = loop {
            if let Some(end) = pending.windows(2).position(|w| w == b"\r\n") {
                break end;
            }
            read_more(stream, &mut pending, &mut tmp).await?;
        };
        // Chunk extensions after `;` are ignored; the size is hexadecimal.
        let size_str = std::str::from_utf8(&pending[..line_end])
            .ok()
            .and_then(|s| s.split(';').next())
            .map(str::trim);
        let chunk_size = size_str
            .and_then(|s| usize::from_str_radix(s, 16).ok())
            .ok_or(LoginError::HttpFailed)?;
        pending.drain(..line_end + 2);

        if chunk_size == 0 {
            // Last chunk: consume the optional trailer lines up to the
            // terminating blank line (a compliant server always sends it).
            loop {
                let trailer_end = loop {
                    if let Some(end) = pending.windows(2).position(|w| w == b"\r\n") {
                        break end;
                    }
                    read_more(stream, &mut pending, &mut tmp).await?;
                };
                let done = trailer_end == 0;
                pending.drain(..trailer_end + 2);
                if done {
                    break;
                }
            }
            break;
        }

        // The chunk bytes plus their trailing CRLF.
        let want = chunk_size.checked_add(2).ok_or(LoginError::HttpFailed)?;
        while pending.len() < want {
            read_more(stream, &mut pending, &mut tmp).await?;
        }
        body.extend_from_slice(&pending[..chunk_size]);
        pending.drain(..want);
        if body.len() > max_body {
            return Err(LoginError::HttpFailed);
        }
    }

    Ok(body)
}

/// The byte offset just past the `\r\n\r\n` header terminator, if present.
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

/// The HTTP status code of a response head, if it parses.
fn parse_status(head: &str) -> Option<u16> {
    let status = head.lines().next()?.split_whitespace().nth(1)?;
    status.parse::<u16>().ok()
}

/// Parse the headers of a response head, lower-casing header names.
fn parse_headers(head: &str) -> Vec<(String, String)> {
    head.lines()
        .skip(1)
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((
                name.trim().to_ascii_lowercase(),
                value.trim().to_string(),
            ))
        })
        .collect()
}

/// The value of the cookie named `name` in a `Set-Cookie` header value,
/// ignoring any attribute chain and matching the cookie name
/// case-insensitively. A CLEARED cookie (`webvpn=; expires=1970`, the measured
/// bad-credential signature) yields `Some("")`.
fn cookie_value_named(set_cookie: &str, name: &str) -> Option<String> {
    let first = set_cookie.split(';').next()?.trim();
    let (cookie_name, value) = first.split_once('=')?;
    if cookie_name.trim().eq_ignore_ascii_case(name) {
        Some(value.trim().to_string())
    } else {
        None
    }
}

/// The gateway's `a0` result code embedded in a credential-POST response body.
///
/// Measured vpn-ct.ecnu.edu.cn semantics (2026-08-15 probe matrix): `a0=8`
/// CSRF precheck failed — the request never reached credential evaluation;
/// `a0=114`/`115` CSRFtoken cookie / form-field mismatch; `a0=15` real
/// credential rejection; `a0=16` empty user or password field. The code is
/// DIAGNOSTIC only: it is attached to the rejected-login error through the
/// additive `LoginRejected.detail` field (read back through
/// [`LoginError::a0_result`]) and mirrored into the log line — the typed
/// [`LoginError`] variants themselves keep their pinned CS-AUTH-01-T shape.
fn a0_code(body_text: &str) -> Option<String> {
    let mut rest = body_text;
    while let Some(start) = rest.find("a0=") {
        // Boundary check: `a0=` must not sit mid-token (e.g. `ra0=`).
        let boundary_ok = start == 0
            || !(rest.as_bytes()[start - 1].is_ascii_alphanumeric()
                || rest.as_bytes()[start - 1] == b'_'
                || rest.as_bytes()[start - 1] == b'-');
        let digits = &rest[start + 3..];
        let end = digits
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(digits.len());
        if boundary_ok && end > 0 {
            return Some(digits[..end].to_string());
        }
        rest = &digits[end..];
    }
    None
}

/// Whether `body_text` is a SAML steering page: a `<meta http-equiv="refresh">`
/// tag whose refresh target points at the SAML ACS (the target carries the
/// `+CSCOE+/saml` marker or an `/acs` path). This is the body variant of
/// openconnect `auth.c handle_saml_redirect()` (plan §3.1, CS-AUTH-04): such a
/// page is never login success, even when the response also carries a `webvpn`
/// cookie.
fn meta_refresh_steers_to_saml_acs(body_text: &str) -> bool {
    // Attribute names/values are matched case-insensitively (real-world pages
    // vary; the marker itself is always the same Cisco constant).
    let lower = body_text.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(start) = rest.find("<meta") {
        let tag_tail = &rest[start + "<meta".len()..];
        let Some(tag_len) = tag_tail.find('>') else {
            break;
        };
        let tag = &rest[start..start + "<meta".len() + tag_len + 1];
        if attr_value_ci(tag, "http-equiv")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("refresh"))
        {
            // `content="0; url=https://.../+CSCOE+/saml/acs/start"`: the target
            // is the part after the first `url=` (anything after a later `url=`
            // belongs to the target itself and is kept).
            let target = attr_value_ci(tag, "content")
                .unwrap_or_default()
                .to_ascii_lowercase();
            let acs_url = target.split("url=").skip(1).collect::<String>();
            if acs_url.contains("+cscoe+/saml") || acs_url.contains("/acs") {
                return true;
            }
        }
        rest = &rest[start + "<meta".len()..];
    }
    false
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
