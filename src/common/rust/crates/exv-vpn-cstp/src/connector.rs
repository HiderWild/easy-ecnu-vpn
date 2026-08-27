// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! EXV P41-I: TLS bootstrap for the VPN control channel (AnyConnect/CSTP).
//!
//! The bootstrap connects to the configured gateway over the SYSTEM TCP stack, performs a
//! TLS (1.2/1.3) handshake with SNI set to the CONFIGURED hostname, and applies a trust
//! policy: production uses the platform verifier, tests may inject explicit test roots.
//! It rejects untrusted chains, hostname mismatches, IPv6 gateway targets and DTLS offers,
//! and a connect failure yields an ephemeral (cheap, non-durable) cleanup token.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{WebPkiServerVerifier, verify_server_name};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpStream;

/// The TCP transport the bootstrap uses to reach the gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// The operating-system TCP stack (a real socket). The only production transport.
    SystemTcp,
    /// A user-space TCP/IP stack. Forbidden for the MVP.
    UserSpace,
}

/// Where the trust anchors come from for a bootstrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifierSource {
    /// The platform trust store (OS CA store).
    Platform,
    /// Explicitly injected test roots.
    InjectedRoots,
}

/// The trust policy applied during the TLS handshake.
#[derive(Clone)]
pub enum TrustPolicy {
    /// Use the platform verifier (rustls-platform-verifier) against the OS trust store.
    Production,
    /// Trust exactly the given root store (used by tests to inject test roots).
    TestRoots(Arc<rustls::RootCertStore>),
}

impl TrustPolicy {
    /// Which verifier source this policy selects.
    pub fn verifier_source(&self) -> VerifierSource {
        match self {
            TrustPolicy::Production => VerifierSource::Platform,
            TrustPolicy::TestRoots(_) => VerifierSource::InjectedRoots,
        }
    }
}

/// The typed failure modes of the TLS bootstrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    /// The TCP connect to the gateway failed.
    ConnectFailed,
    /// An IPv6 gateway target was offered; the MVP is IPv4-only.
    Ipv6EndpointsRejected,
    /// The peer offered DTLS; the MVP is TLS/CSTP only.
    DtlsOffered,
    /// The peer's certificate chain had no trusted anchor.
    UntrustedChain,
    /// The certificate did not match the configured hostname.
    HostnameMismatch,
    /// The TLS handshake failed for another reason.
    HandshakeFailed,
    /// The injected connect deadline expired.
    DeadlineExceeded,
}

/// An ephemeral (cheap, non-durable) cleanup token. A connect failure yields one so late
/// callbacks / partially-created resources can be cleaned without journal debt.
#[derive(Debug, Clone, Copy)]
pub struct EphemeralCleanupToken;

impl EphemeralCleanupToken {
    /// Always ephemeral: cheap and non-durable.
    pub fn is_ephemeral(&self) -> bool {
        true
    }

    /// Consume/dispose the token. For the ephemeral token this is a local no-op success.
    pub fn finish(self) {}
}

/// A typed connect failure carrying an ephemeral cleanup token.
#[derive(Debug)]
pub struct ConnectFailure {
    pub error: BootstrapError,
    pub cleanup_token: EphemeralCleanupToken,
}

impl ConnectFailure {
    fn new(error: BootstrapError) -> Self {
        Self {
            error,
            cleanup_token: EphemeralCleanupToken,
        }
    }
}

/// An injected, monotonic clock seam so deadlines are deterministic and independent of the
/// wall clock.
pub trait VerifyClock: Send + Sync {
    /// Current time in milliseconds.
    fn now_millis(&self) -> u64;
}

/// A connect deadline measured on an injected clock. A deadline expiry is a REAL failure
/// (a rollback), never a false one.
///
/// `Clone` is additive (the clock is shared): a login phase that needs the
/// same injected deadline across several bootstrap connections (e.g. the
/// `WebVPN` GET and POST connections) reuses it without re-constructing it.
#[derive(Clone)]
pub struct Deadline {
    clock: Arc<dyn VerifyClock>,
    at_millis: u64,
}

impl Deadline {
    /// A deadline `after_millis` from the clock's current reading.
    pub fn at(clock: Arc<dyn VerifyClock>, after_millis: u64) -> Self {
        let base = clock.now_millis();
        Self {
            clock,
            at_millis: base.wrapping_add(after_millis),
        }
    }

    fn is_expired(&self) -> bool {
        self.clock.now_millis() >= self.at_millis
    }
}

/// An injected callback that applies platform socket options to the TCP socket
/// BEFORE the gateway connection is established. The canonical production use is
/// Windows `IP_UNICAST_IF` outbound-interface pinning to the physical NIC so the
/// control plane cannot leak into a proxy TUN default route (PRD G-④).
///
/// The callback receives the not-yet-connected [`tokio::net::TcpSocket`] so the
/// option (e.g. the interface index in network byte order) takes effect before
/// the TCP handshake. The implementation is supplied by the platform side
/// (win32), keeping this Common crate free of platform socket APIs.
pub type SocketBinder = dyn Fn(&tokio::net::TcpSocket) -> std::io::Result<()> + Send + Sync;

/// A boxed future resolving the gateway hostname to a connectable address.
pub type ResolverFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<SocketAddr, String>> + Send>>;

/// An injected callback that resolves the gateway **hostname** to a connectable
/// address BEFORE the TLS bootstrap connects. The canonical production use is
/// the VGDC dual-line DNS (DoH direct + bound-NIC UDP/53 fallback) so the
/// gateway resolves outside Mihomo fake-ip pollution (PRD G-⑤). A failure
/// (e.g. all dual-line layers failed) aborts the connect as
/// [`BootstrapError::ConnectFailed`].
///
/// The callback is `async`-shaped (returns a boxed future) so the DoH line can
/// be awaited on the caller's tokio context rather than blocking it. The
/// implementation is supplied by the platform side (win32), keeping this Common
/// crate free of platform DNS/network APIs.
pub type GatewayResolver = dyn Fn(&str) -> ResolverFuture + Send + Sync;

/// Configuration for a single TLS bootstrap.
pub struct BootstrapConfig {
    pub hostname: String,
    pub gateway_addr: SocketAddr,
    pub trust: TrustPolicy,
    pub dtls_offered: bool,
    pub deadline: Option<Deadline>,
    /// Optional outbound-interface pin applied before the TCP connect.
    /// `None` = system default route (existing behavior, fully backward
    /// compatible).
    pub socket_binder: Option<Arc<SocketBinder>>,
    /// Optional VGDC dual-line DNS resolver that maps the configured hostname to
    /// a connectable gateway address before the TCP connect. `None` = use the
    /// pre-resolved `gateway_addr` unchanged (existing behavior, fully backward
    /// compatible).
    pub gateway_resolver: Option<Arc<GatewayResolver>>,
}

/// An established TLS session to the gateway (opaque to callers).
pub struct BootstrapSession {
    #[allow(dead_code)]
    stream: tokio_rustls::client::TlsStream<TcpStream>,
}

impl std::fmt::Debug for BootstrapSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapSession").finish_non_exhaustive()
    }
}

impl BootstrapSession {
    /// Consume this session and hand over the underlying TLS stream to a later
    /// engine phase (`WebVPN` login / CSTP CONNECT).
    ///
    /// Governance record (CSTP authentication rebuild plan §7.1, leaf
    /// CS-AUTH-01): the TLS stream established by the frozen P41 bootstrap is
    /// the necessary handoff between the bootstrap and the engine-owned
    /// authentication phases — the opaque surface offers no other delivery
    /// seam, and an equivalent host-side implementation would duplicate the
    /// rustls wiring the rebuild is replacing (the exact structure the real
    /// gateway rejected). Additive only: no fields, no derives, and no
    /// existing-method semantics change; the P41-T oracle stays green.
    pub fn into_stream(self) -> tokio_rustls::client::TlsStream<TcpStream> {
        self.stream
    }
}

/// The TLS bootstrap for the VPN control channel.
pub struct Bootstrap {
    transport: Transport,
}

impl Bootstrap {
    /// A bootstrap over the SYSTEM TCP stack.
    pub fn system() -> Self {
        Self {
            transport: Transport::SystemTcp,
        }
    }

    /// The transport this bootstrap uses.
    pub fn transport(&self) -> Transport {
        self.transport
    }

    /// Connect and perform the TLS handshake against `cfg.hostname` at `cfg.gateway_addr`.
    ///
    /// Takes `self` by value (the transport is cheaply `Copy`) so callers may build a
    /// temporary `Bootstrap` and hold the returned future independently.
    pub async fn connect(self, cfg: BootstrapConfig) -> Result<BootstrapSession, ConnectFailure> {
        // Reject unsupported targets before any network mutation.
        if cfg.dtls_offered {
            return Err(ConnectFailure::new(BootstrapError::DtlsOffered));
        }

        // Resolve the configured hostname through the injected VGDC dual-line DNS
        // resolver when present (PRD G-⑤); otherwise keep the pre-resolved
        // `gateway_addr`. The resolution failure aborts the connect before any TCP
        // traffic (typed ConnectFailed).
        let gateway_addr = if let Some(resolver) = &cfg.gateway_resolver {
            let addr = resolver(&cfg.hostname)
                .await
                .map_err(|_err| ConnectFailure::new(BootstrapError::ConnectFailed))?;
            if addr.is_ipv6() {
                return Err(ConnectFailure::new(BootstrapError::Ipv6EndpointsRejected));
            }
            addr
        } else {
            cfg.gateway_addr
        };
        if gateway_addr.is_ipv6() {
            return Err(ConnectFailure::new(BootstrapError::Ipv6EndpointsRejected));
        }

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config_error = |_err| ConnectFailure::new(BootstrapError::HandshakeFailed);
        let client_cfg = match &cfg.trust {
            TrustPolicy::Production => {
                let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
                    .map_err(config_error)?;
                rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .map_err(config_error)?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_no_client_auth()
            }
            TrustPolicy::TestRoots(roots) => {
                let inner =
                    WebPkiServerVerifier::builder_with_provider(roots.clone(), provider.clone())
                        .build()
                        .map_err(|_err| ConnectFailure::new(BootstrapError::HandshakeFailed))?;
                let verifier = TestRootsVerifier {
                    inner,
                    roots: roots.clone(),
                };
                rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .map_err(config_error)?
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(verifier))
                    .with_no_client_auth()
            }
        };

        // SNI is the CONFIGURED hostname, never a parsed gateway IP.
        let server_name = rustls::pki_types::ServerName::try_from(cfg.hostname)
            .map_err(|_err| ConnectFailure::new(BootstrapError::HandshakeFailed))?;

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));

        // Connect over the SYSTEM TCP stack to the resolved gateway address. When an
        // outbound-interface binder is injected, apply it to a not-yet-connected socket
        // BEFORE the TCP handshake so the option (e.g. IP_UNICAST_IF) governs route
        // selection; otherwise keep the legacy eager-connect path byte-for-byte
        // unchanged.
        let tcp = if let Some(binder) = &cfg.socket_binder {
            let socket = tokio::net::TcpSocket::new_v4()
                .map_err(|_err| ConnectFailure::new(BootstrapError::ConnectFailed))?;
            binder(&socket)
                .map_err(|_err| ConnectFailure::new(BootstrapError::ConnectFailed))?;
            socket
                .connect(gateway_addr)
                .await
                .map_err(|_err| ConnectFailure::new(BootstrapError::ConnectFailed))?
        } else {
            TcpStream::connect(gateway_addr)
                .await
                .map_err(|_err| ConnectFailure::new(BootstrapError::ConnectFailed))?
        };

        let handshake = connector.connect(server_name, tcp);
        let stream = connect_with_deadline(handshake, cfg.deadline)
            .await
            .map_err(ConnectFailure::new)?;

        Ok(BootstrapSession { stream })
    }
}

/// A test-roots certificate verifier.
///
/// It delegates to the standard `WebPkiServerVerifier` built from the injected root store.
/// The strict rustls-webpki path rejects a CA-coded end-entity (`CaUsedAsEndEntity`), which
/// is exactly the shape of a self-signed test root used as its own end-entity. In that case
/// the end-entity is accepted only when it is itself one of the injected roots AND its name
/// matches the hostname, so an always-true verifier mutant still fails the untrusted-chain
/// and hostname-mismatch tests.
struct TestRootsVerifier {
    inner: Arc<WebPkiServerVerifier>,
    roots: Arc<rustls::RootCertStore>,
}

impl std::fmt::Debug for TestRootsVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestRootsVerifier").finish_non_exhaustive()
    }
}

impl TestRootsVerifier {
    /// Whether the end-entity is one of the injected trust anchors (matched by public key).
    ///
    /// `ParsedCertificate::subject_public_key_info()` returns the full DER SPKI including
    /// the enclosing `SEQUENCE`, whereas a `TrustAnchor` stores the `subjectPublicKeyInfo`
    /// content (the `AlgorithmIdentifier` + `BIT STRING`) without that outer tag. Strip the
    /// leading `SEQUENCE` header from the end-entity SPKI before comparing.
    fn end_entity_is_injected_root(&self, end_entity: &CertificateDer<'_>) -> bool {
        let Ok(cert) = ParsedCertificate::try_from(end_entity) else {
            return false;
        };
        let spki = cert.subject_public_key_info();
        let Some(spki_content) = strip_sequence_header(spki.as_ref()) else {
            return false;
        };
        self.roots
            .roots
            .iter()
            .any(|anchor| anchor.subject_public_key_info.as_ref() == spki_content)
    }
}

/// Strip the DER `SEQUENCE` tag + length header from `bytes`, returning the content.
fn strip_sequence_header(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.first() != Some(&0x30) {
        return None;
    }
    let first_len = *bytes.get(1)?;
    if first_len & 0x80 == 0 {
        let content_len = first_len as usize;
        return bytes.get(2..2 + content_len);
    }
    let len_bytes = first_len & 0x7f;
    if len_bytes == 0 || len_bytes > 4 {
        return None;
    }
    let n = len_bytes as usize;
    let len_bytes_slice = bytes.get(2..2 + n)?;
    let content_len = len_bytes_slice
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | *b as usize);
    bytes.get(2 + n..2 + n + content_len)
}

impl ServerCertVerifier for TestRootsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(rustls::Error::InvalidCertificate(CertificateError::Other(_))) => {
                // The strict webpki path rejected a CA-coded end-entity
                // (`CaUsedAsEndEntity`). Accept a self-signed injected root used as its
                // own end-entity only if it is a trusted injected root and its name
                // matches the hostname.
                if self.end_entity_is_injected_root(end_entity) {
                    let cert = ParsedCertificate::try_from(end_entity).map_err(|_e| {
                        rustls::Error::InvalidCertificate(CertificateError::BadEncoding)
                    })?;
                    verify_server_name(&cert, server_name).map_err(|_e| {
                        rustls::Error::InvalidCertificate(CertificateError::NotValidForName)
                    })?;
                    return Ok(ServerCertVerified::assertion());
                }
                Err(rustls::Error::InvalidCertificate(
                    CertificateError::UnknownIssuer,
                ))
            }
            Err(err) => Err(err),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Drive the TLS handshake to completion, re-checking an injected deadline on each poll so
/// that a deadline expiry is a real failure and an un-expired deadline never causes a false
/// rollback.
async fn connect_with_deadline(
    handshake: impl Future<Output = Result<tokio_rustls::client::TlsStream<TcpStream>, std::io::Error>>,
    deadline: Option<Deadline>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BootstrapError> {
    tokio::pin!(handshake);
    loop {
        if let Some(deadline) = &deadline {
            if deadline.is_expired() {
                return Err(BootstrapError::DeadlineExceeded);
            }
        }
        tokio::select! {
            biased;
            result = &mut handshake => {
                return result.map_err(classify_handshake_error);
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(1)) => {}
        }
    }
}

/// Map a TLS handshake `io::Error` to a typed bootstrap error, distinguishing an untrusted
/// chain from a hostname mismatch.
fn classify_handshake_error(err: std::io::Error) -> BootstrapError {
    if let Some(rustls_err) = err
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    {
        return match rustls_err {
            rustls::Error::InvalidCertificate(CertificateError::NotValidForName) => {
                BootstrapError::HostnameMismatch
            }
            rustls::Error::InvalidCertificate(_) => BootstrapError::UntrustedChain,
            _ => BootstrapError::HandshakeFailed,
        };
    }
    BootstrapError::HandshakeFailed
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
