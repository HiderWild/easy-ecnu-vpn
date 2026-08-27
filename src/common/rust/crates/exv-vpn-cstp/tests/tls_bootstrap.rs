// EXV P41-T: TCP + rustls verification + AnyConnect bootstrap integration tests for
// exv-vpn-cstp.
//
// These tests define the exact public API that P41-I must implement in
// `exv_vpn_cstp::connector`. They are expected to be RED (compile error) until P41-I
// implements that bootstrap. The bootstrap performs the TLS handshake against a
// configured hostname using the SYSTEM TCP stack (never a user-space IP stack), sets
// SNI to the configured hostname, and uses a trust policy: production uses the platform
// verifier; tests can inject test roots. It must reject untrusted chains, hostname
// mismatches, IPv6 targets and DTLS offers, and a deadline must not cause a false
// rollback. A connect failure yields an ephemeral cleanup token.
//
// Contract (RNRM-005/006/008, TG-04):
//   * System TCP: the bootstrap connects with the OS TCP socket (tokio TcpStream), not a
//     user-space TCP/IP stack.
//   * SNI: the ClientHello SNI is the CONFIGURED hostname, never a parsed gateway IP.
//   * Trust: `TrustPolicy::Production` selects the platform verifier
//     (rustls-platform-verifier); `TrustPolicy::TestRoots` injects explicit test roots.
//   * Rejects: untrusted chains, hostname mismatches, IPv6 gateway targets, DTLS offers.
//   * Deadline: measured on an injected/paused clock; it must not cause a false rollback.
//   * A connect failure yields an EPHEMERAL cleanup token (cheap, non-durable).
//
// The API P41-I must implement in `exv_vpn_cstp::connector`:
//
//   pub enum Transport { SystemTcp, UserSpace }
//   pub enum TrustPolicy { Production, TestRoots(Arc<rustls::RootCertStore>) }
//   pub enum VerifierSource { Platform, InjectedRoots }
//   pub enum BootstrapError {
//       ConnectFailed, Ipv6EndpointsRejected, DtlsOffered,
//       UntrustedChain, HostnameMismatch, HandshakeFailed, DeadlineExceeded,
//   }
//   pub struct EphemeralCleanupToken { /* opaque */ }
//   pub struct ConnectFailure { pub error: BootstrapError, pub cleanup_token: EphemeralCleanupToken }
//   pub struct BootstrapSession { /* opaque */ }
//   pub trait VerifyClock: Send + Sync { fn now_millis(&self) -> u64; }
//   pub struct Deadline { /* opaque */ }
//   pub struct BootstrapConfig {
//       pub hostname: String,
//       pub gateway_addr: SocketAddr,
//       pub trust: TrustPolicy,
//       pub dtls_offered: bool,
//       pub deadline: Option<Deadline>,
//       pub socket_binder: Option<Arc<SocketBinder>>,  // None = default route (unchanged)
//   }
//   pub struct Bootstrap { /* opaque */ }
//   impl Bootstrap {
//       pub fn system() -> Self;                       // system TCP transport
//       pub fn transport(&self) -> Transport;
//       pub async fn connect(&self, cfg: BootstrapConfig)
//           -> Result<BootstrapSession, ConnectFailure>;
//   }
//   impl TrustPolicy { pub fn verifier_source(&self) -> VerifierSource; }
//   impl Deadline { pub fn at(clock: Arc<dyn VerifyClock>, after_millis: u64) -> Self; }
//   impl EphemeralCleanupToken {
//       pub fn is_ephemeral(&self) -> bool;           // true: cheap, non-durable
//       pub fn finish(self);                          // consume/dispose the token
//   }

use exv_vpn_cstp::connector::{
    Bootstrap, BootstrapConfig, BootstrapError, ConnectFailure, Deadline, EphemeralCleanupToken,
    Transport, TrustPolicy, VerifyClock, VerifierSource,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Embedded test PKI. Two self-signed ECDSA P-256 leaf certs (their own roots):
//   VPN_CERT  -> SAN DNS:vpn.example.test   (the "valid" peer)
//   OTHER_CERT-> SAN DNS:other.example.test (used for hostname-mismatch / untrusted)
// Generated once with OpenSSL; embedded so the tests are deterministic and touch no
// host trust store and no network except the loopback TLS peer.
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

/// The "valid" peer material: a self-signed cert for `vpn.example.test`.
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

/// A closed local port (bound then dropped): connecting fails at the TCP layer.
async fn unused_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

/// A local TCP peer that accepts a connection but then stalls: it never sends any TLS
/// handshake bytes, so the client's handshake stays pending (no ServerHello).
async fn run_stalled_tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind stall server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        if let Ok((_tcp, _peer)) = listener.accept().await {
            // Hold the connection open without performing a TLS handshake.
            std::future::pending::<()>().await;
        }
    });
    addr
}

/// Run a real local TLS server (loopback) and report the ClientHello SNI it observed.
async fn run_tls_server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (SocketAddr, oneshot::Receiver<Option<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tls server");
    let addr = listener.local_addr().expect("local addr");
    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("build server config from embedded cert");
    let acceptor = Arc::new(TlsAcceptor::from(Arc::new(server_cfg)));
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => {
                let _ = tx.send(None);
                return;
            }
        };
        let stream = match acceptor.accept(tcp).await {
            Ok(s) => s,
            Err(_) => {
                let _ = tx.send(None);
                return;
            }
        };
        let server_conn = stream.get_ref().1;
        let _ = tx.send(server_conn.server_name().map(|s| s.to_string()));
    });
    (addr, rx)
}

/// An injected, paused monotonic clock (not wall-clock) so the deadline test is
/// deterministic and does not sleep on the wall clock.
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

// ---------------------------------------------------------------------------
// The 9 fixed tests
// ---------------------------------------------------------------------------

#[test]
fn uses_system_tcp_not_user_stack() {
    // The bootstrap connects over the SYSTEM TCP stack (OS socket), never a user-space
    // TCP/IP stack. A mutant that substitutes a user-space stack must fail here.
    let bootstrap = Bootstrap::system();
    assert_eq!(
        bootstrap.transport(),
        Transport::SystemTcp,
        "the bootstrap must use the system TCP stack"
    );
    assert_ne!(
        bootstrap.transport(),
        Transport::UserSpace,
        "a user-space TCP/IP stack is forbidden"
    );
}

#[tokio::test]
async fn sets_sni_to_configured_hostname() {
    // The ClientHello SNI must be the CONFIGURED hostname, not the parsed gateway IP
    // (the loopback peer is 127.0.0.1). A mutant that sends SNI = parsed IP must fail.
    let (cert, key) = vpn_material();
    let (addr, observed_sni) = run_tls_server(cert.clone(), key).await;
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };

    let _session = Bootstrap::system()
        .connect(cfg)
        .await
        .expect("client trusts the injected root and matches the hostname");

    let sni = observed_sni.await.expect("server observed a handshake");
    assert_eq!(
        sni.as_deref(),
        Some("vpn.example.test"),
        "SNI must be the configured hostname, never the parsed gateway IP"
    );
}

#[tokio::test]
async fn rejects_untrusted_chain() {
    // Serve a cert the client does NOT trust (different injected root). The bootstrap
    // must reject the handshake as an untrusted chain. A dangerous "always-true"
    // verifier mutant must fail here.
    let (vpn_cert, vpn_key) = vpn_material();
    let (other_cert, _other_key) = other_material();
    let (addr, _observed_sni) = run_tls_server(vpn_cert, vpn_key).await;
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&other_cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };

    let failure = Bootstrap::system()
        .connect(cfg)
        .await
        .expect_err("a chain with no trusted root must be rejected");
    assert!(
        matches!(failure.error, BootstrapError::UntrustedChain),
        "untrusted chain surfaces as a typed UntrustedChain error"
    );
}

#[tokio::test]
async fn rejects_hostname_mismatch() {
    // Serve a trusted cert for `other.example.test` while the client connects to
    // hostname `vpn.example.test`. The chain is trusted but the name does not match, so
    // the bootstrap must reject with HostnameMismatch. An always-true verifier mutant
    // must fail here.
    let (other_cert, other_key) = other_material();
    let (addr, _observed_sni) = run_tls_server(other_cert.clone(), other_key).await;
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&other_cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };

    let failure = Bootstrap::system()
        .connect(cfg)
        .await
        .expect_err("a trusted chain for the wrong name must be rejected");
    assert!(
        matches!(failure.error, BootstrapError::HostnameMismatch),
        "hostname mismatch surfaces as a typed HostnameMismatch error"
    );
}

#[tokio::test]
async fn accepts_valid_peer_with_injected_test_roots() {
    // A peer signed by an explicitly injected test root is accepted: the test-roots
    // trust policy is a first-class, non-production path that does not touch the host
    // platform trust store.
    let (cert, key) = vpn_material();
    let (addr, _observed_sni) = run_tls_server(cert.clone(), key).await;
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };

    let session = Bootstrap::system().connect(cfg).await;
    assert!(
        session.is_ok(),
        "a peer signed by an injected test root must be accepted"
    );
}

#[test]
fn production_policy_selects_platform_verifier() {
    // Production trust must select the platform verifier, never injected test roots. A
    // mutant that makes the production policy select test roots must fail here.
    let production = TrustPolicy::Production;
    assert_eq!(
        production.verifier_source(),
        VerifierSource::Platform,
        "the production trust policy must use the platform verifier"
    );
    assert_ne!(
        production.verifier_source(),
        VerifierSource::InjectedRoots,
        "production must never select injected test roots"
    );
}

#[tokio::test]
async fn deadline_returns_no_false_rollback() {
    // The deadline is measured on an INJECTED/paused clock, not the wall clock. While the
    // injected clock is still before the deadline the connect must NOT roll back just
    // because real wall-clock time passed; once the injected clock passes the deadline a
    // REAL rollback (DeadlineExceeded) must occur. A mutant that guesses the timeout has
    // no effect (never rolls back) must fail on the second half; a mutant that always
    // rolls back must fail on the first half.
    let clock = Arc::new(FakeClock::at(0));
    let (cert, _key) = vpn_material();
    let addr = run_stalled_tcp_server().await; // handshake never completes on its own
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        dtls_offered: false,
        deadline: Some(Deadline::at(clock.clone(), 1_000)),
        socket_binder: None,
        gateway_resolver: None,
    };

    let connect = Bootstrap::system().connect(cfg);
    tokio::pin!(connect);

    // (a) Injected clock (t=0) is before the deadline (t=1000). The connect must remain
    //     pending and must NOT roll back, even though real time elapses.
    let before = tokio::time::timeout(std::time::Duration::from_millis(80), &mut connect).await;
    assert!(
        before.is_err(),
        "no false rollback while the injected clock is before the deadline"
    );

    // (b) Advance the injected clock past the deadline -> a real rollback must occur.
    clock.advance(5_000);
    let res = tokio::time::timeout(std::time::Duration::from_secs(5), connect)
        .await
        .expect("the connect re-polls the injected clock and settles once the deadline passes");
    let failure = res.expect_err("deadline exceeded is a failure, not a success");
    assert!(
        matches!(failure.error, BootstrapError::DeadlineExceeded),
        "passing the injected deadline causes a real DeadlineExceeded rollback"
    );
}

#[tokio::test]
async fn bootstrap_rejects_ipv6_or_dtls_offer() {
    // The MVP is IPv4 + TLS/CSTP only. An IPv6 gateway target and a DTLS offer must both
    // be rejected by the bootstrap before any network mutation.
    //
    // (1) IPv6 gateway target is rejected outright.
    let ipv6 = BootstrapConfig {
        hostname: "gateway6.example.test".to_string(),
        gateway_addr: "[::1]:1".parse().expect("valid ipv6 socket address"),
        trust: TrustPolicy::Production,
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };
    let f6 = Bootstrap::system()
        .connect(ipv6)
        .await
        .expect_err("an IPv6 gateway target must be rejected");
    assert!(
        matches!(f6.error, BootstrapError::Ipv6EndpointsRejected),
        "IPv6 gateway target surfaces as a typed rejection"
    );

    // (2) A DTLS offer is rejected even against a closed address: the rejection must not
    //     depend on the peer, i.e. it happens before any connect (no DTLS in the MVP).
    let dtls_addr = unused_addr().await;
    let dtls = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: dtls_addr,
        trust: TrustPolicy::Production,
        dtls_offered: true,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };
    let fd = Bootstrap::system()
        .connect(dtls)
        .await
        .expect_err("a DTLS offer must be rejected");
    assert!(
        matches!(fd.error, BootstrapError::DtlsOffered),
        "a DTLS offer surfaces as a typed rejection"
    );
}

#[tokio::test]
async fn connect_failure_yields_ephemeral_cleanup_token() {
    // A TCP connect failure is a typed failure that yields an EPHEMERAL cleanup token: a
    // cheap, non-durable handle so late callbacks / partially-created resources can be
    // cleaned without journal debt. A mutant that drops the token (or makes it durable)
    // must fail here.
    let addr = unused_addr().await; // closed port: TCP connect fails
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::Production,
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };

    let failure = Bootstrap::system()
        .connect(cfg)
        .await
        .expect_err("a closed port fails the connect");
    assert!(
        matches!(failure.error, BootstrapError::ConnectFailed),
        "a TCP connect failure is typed as ConnectFailed"
    );
    assert!(
        failure.cleanup_token.is_ephemeral(),
        "a connect failure yields an EPHEMERAL cleanup token, not a durable/journaled resource"
    );
    // Consuming the ephemeral token is a local no-op success.
    failure.cleanup_token.finish();
}

// ---------------------------------------------------------------------------
// Socket egress binding (PRD G-④): an injected `SocketBinder` runs against the
// not-yet-connected TCP socket BEFORE the TCP handshake, so the control plane
// can be pinned to the physical NIC (IP_UNICAST_IF) and cannot leak into a
// proxy TUN default route. `None` keeps the legacy eager-connect path.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn injected_binder_runs_before_connect_and_success_path_works() {
    // A binder that records invocation and returns Ok must run BEFORE the gateway
    // connection is established, and the connect must still complete. A mutant that
    // ignores the binder (or runs it after connect) must fail on the flag.
    let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let binder_arc = Arc::clone(&invoked);
    let binder: Arc<exv_vpn_cstp::connector::SocketBinder> =
        Arc::new(move |_socket: &tokio::net::TcpSocket| -> std::io::Result<()> {
            binder_arc.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        });

    let (cert, key) = vpn_material();
    let (addr, _observed_sni) = run_tls_server(cert.clone(), key).await;
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: Some(binder),
        gateway_resolver: None,
    };

    let session = Bootstrap::system().connect(cfg).await;
    assert!(session.is_ok(), "binder Ok must not block the TLS handshake");
    assert!(
        invoked.load(std::sync::atomic::Ordering::SeqCst),
        "the injected binder must run before the gateway connect"
    );
}

#[tokio::test]
async fn injected_binder_error_aborts_connect_as_connect_failed() {
    // A binder that fails must abort the connect BEFORE any TCP traffic, surfacing as
    // the typed ConnectFailed failure (the socket option could not be applied). A mutant
    // that swallows the binder error (or ignores it) must fail here.
    let binder: Arc<exv_vpn_cstp::connector::SocketBinder> = Arc::new(|_socket| {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ip-unicast-if refused",
        ))
    });

    let (cert, _key) = vpn_material();
    let addr = unused_addr().await; // would fail the connect anyway; binder must fail first
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: Some(binder),
        gateway_resolver: None,
    };

    let failure = Bootstrap::system()
        .connect(cfg)
        .await
        .expect_err("a failing binder must abort the connect");
    assert!(
        matches!(failure.error, BootstrapError::ConnectFailed),
        "a binder failure surfaces as the typed ConnectFailed failure"
    );
}

#[tokio::test]
async fn none_binder_keeps_legacy_connect_path() {
    // `socket_binder: None` must keep the existing eager-connect behavior: a successful
    // handshake against a loopback TLS peer, exactly as before the binder seam existed.
    let (cert, key) = vpn_material();
    let (addr, _observed_sni) = run_tls_server(cert.clone(), key).await;
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };

    let session = Bootstrap::system().connect(cfg).await;
    assert!(
        session.is_ok(),
        "None binder keeps the legacy eager-connect path working"
    );
}

// ---------------------------------------------------------------------------
// Gateway hostname resolution (PRD G-⑤ / C4): an injected `GatewayResolver`
// maps the configured HOSTNAME to a connectable address BEFORE the TCP connect,
// so the gateway resolves through the VGDC dual-line DNS (DoH direct +
// bound-NIC UDP/53) and never through Mihomo fake-ip pollution. `None` keeps
// the pre-resolved `gateway_addr` unchanged.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn injected_resolver_overrides_gateway_addr_and_runs_before_connect() {
    // A resolver that records invocation and maps the hostname to the loopback TLS
    // server must run BEFORE the TCP connect, and the connect must target the
    // RESOLVED address (a mutant that ignores the resolver and keeps the literal
    // `gateway_addr` would connect to an unused port and fail).
    let invoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (cert, key) = vpn_material();
    let (addr, _observed_sni) = run_tls_server(cert.clone(), key).await;
    let invoked_arc = Arc::clone(&invoked);
    let server_addr = addr;
    let resolver: Arc<exv_vpn_cstp::connector::GatewayResolver> = Arc::new(
        move |host: &str| -> exv_vpn_cstp::connector::ResolverFuture {
            assert_eq!(host, "vpn.example.test", "resolver receives the configured hostname");
            invoked_arc.store(true, std::sync::atomic::Ordering::SeqCst);
            let target = server_addr;
            Box::pin(async move { Ok(target) })
        },
    );

    // A deliberately wrong literal gateway_addr: the resolver must override it.
    let wrong_addr = unused_addr().await;
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: wrong_addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: Some(resolver),
    };

    let session = Bootstrap::system().connect(cfg).await;
    assert!(session.is_ok(), "resolved addr must win over the literal gateway_addr");
    assert!(
        invoked.load(std::sync::atomic::Ordering::SeqCst),
        "the injected resolver must run before the gateway connect"
    );
}

#[tokio::test]
async fn injected_resolver_error_aborts_connect_as_connect_failed() {
    // A resolver that fails must abort the connect BEFORE any TCP traffic, surfacing as
    // the typed ConnectFailed failure (the gateway could not be resolved). A mutant
    // that swallows the resolver error (or ignores it) must fail here.
    let resolver: Arc<exv_vpn_cstp::connector::GatewayResolver> = Arc::new(|_host| {
        Box::pin(async move { Err("vgdc: both layers failed".to_string()) })
    });

    let (cert, _key) = vpn_material();
    let addr = unused_addr().await; // would fail the connect anyway; resolver must fail first
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: Some(resolver),
    };

    let failure = Bootstrap::system()
        .connect(cfg)
        .await
        .expect_err("a failing resolver must abort the connect");
    assert!(
        matches!(failure.error, BootstrapError::ConnectFailed),
        "a resolver failure surfaces as the typed ConnectFailed failure"
    );
}

#[tokio::test]
async fn none_resolver_keeps_legacy_gateway_addr() {
    // `gateway_resolver: None` must keep the existing behavior: the connect targets the
    // pre-resolved `gateway_addr`, exactly as before the resolver seam existed.
    let (cert, key) = vpn_material();
    let (addr, _observed_sni) = run_tls_server(cert.clone(), key).await;
    let cfg = BootstrapConfig {
        hostname: "vpn.example.test".to_string(),
        gateway_addr: addr,
        trust: TrustPolicy::TestRoots(Arc::new(root_store_with(&cert))),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };

    let session = Bootstrap::system().connect(cfg).await;
    assert!(
        session.is_ok(),
        "None resolver keeps the legacy gateway_addr connect path working"
    );
}