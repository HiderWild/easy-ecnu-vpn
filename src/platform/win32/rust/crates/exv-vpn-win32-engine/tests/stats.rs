// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// P5-a integration contract for `HelperControl.StreamStats` over the REAL named-pipe
// transport:
//
//   1. `stream_stats` is transport-gated (unauthenticated peer is refused).
//   2. Over the pipe, opening `stream_stats` attaches the engine stats publisher;
//      counters recorded on the shared registry stream out as `StatsEvent` samples
//      with the accumulated cumulative shape.
//   3. The mutation boundary transitions phase: `ApplyTunnel` → Connected,
//      `StopTunnel` → Idle, and the pushed samples reflect it.
//
// Mirrors the harness in tests/grpc_server.rs (same test-only named-pipe connector).

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use exv_engine::grpc_server::HelperControlService;
use exv_engine::grpc_transport::serve_named_pipe;
use exv_vpn_win32_ipc::peer_auth::current_user_sid;
use exv_vpn_wire::generated;
use generated::helper_control_client::HelperControlClient;
use generated::helper_control_server::{HelperControl, HelperControlServer};
use hyper_util::rt::TokioIo;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::mpsc;
use tonic::codegen::http::Uri;
use tonic::codegen::{Service, tokio_stream};
use tonic::Request;

// ---------------------------------------------------------------------------
// Helpers (mirror tests/grpc_server.rs)
// ---------------------------------------------------------------------------

fn unique_pipe_name(tag: &str) -> String {
    format!(r"\\.\pipe\exv-grpc-stats-{tag}-{}", std::process::id())
}

/// A 16-byte non-nil uuid for the wire epoch / operation id.
fn uuid16(n: u8) -> Vec<u8> {
    let mut bytes = [0u8; 16];
    bytes[0] = n;
    bytes[1] = 0x42;
    bytes.to_vec()
}

/// A 32-byte request digest.
fn digest32(n: u8) -> Vec<u8> {
    vec![n; 32]
}

/// SHA-256 of `bytes` (mirrors the engine's principal derivation).
fn sha256(bytes: impl AsRef<[u8]>) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes.as_ref()).to_vec()
}

/// A wire lookup key with the given method discriminant and a distinct identity per `n`.
fn wire_key(method: i32, n: u8) -> generated::OperationLookupKey {
    generated::OperationLookupKey {
        principal_digest: digest32(0x10),
        method,
        runtime_epoch: uuid16(n),
        operation_id: uuid16(n + 1),
    }
}

/// A valid wire tunnel plan.
fn wire_plan() -> generated::TunnelPlan {
    generated::TunnelPlan {
        ipv4_address: vec![10, 0, 0, 1],
        ipv4_prefix_len: 24,
        mtu: 1400,
        ipv4_routes: vec![],
        dns_servers: vec![],
        control_bypass: vec![],
        opaque_intent: Some(generated::TunnelIntentRef {
            identity_digest: digest32(0x33),
        }),
    }
}

// ---------------------------------------------------------------------------
// Transport gate (no pipe needed)
// ---------------------------------------------------------------------------

/// StreamStats is gated by the transport peer: an unverified request is refused.
#[tokio::test]
async fn stream_stats_requires_verified_peer() {
    let service = HelperControlService::new();
    let request = Request::new(generated::StreamStatsRequest {
        sample_interval_ms: 0,
    });
    let status = service.stream_stats(request).await.expect_err("must fail");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// Opening StreamStats without a transport peer never spawns a sampler (fail closed
/// before any push side-effect).
#[tokio::test]
async fn stream_stats_unverified_leaves_no_sampler() {
    let service = HelperControlService::new();
    let publisher = service.stats_publisher();
    let request = Request::new(generated::StreamStatsRequest {
        sample_interval_ms: 0,
    });
    let status = service.stream_stats(request).await.expect_err("must fail");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert!(
        !publisher.is_push_attached(),
        "rejected stream must not attach a push channel"
    );
}

// ---------------------------------------------------------------------------
// End-to-end: StreamStats over the real named pipe
// ---------------------------------------------------------------------------

/// A minimal test-only named-pipe connector (mirrors the product connector in win32-host).
#[derive(Default)]
struct TestPipeConnector {
    pipe: Option<NamedPipeClient>,
}

impl Service<Uri> for TestPipeConnector {
    type Response = TokioIo<NamedPipeClient>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let pipe = self.pipe.take().expect("single test connection");
        Box::pin(async move { Ok(TokioIo::new(pipe)) })
    }
}

/// Dial the pipe with bounded retry (engine startup race).
async fn dial_with_retry(name: &str) -> NamedPipeClient {
    for _ in 0..50 {
        match ClientOptions::new().open(name) {
            Ok(pipe) => return pipe,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("dial {name} exhausted retries");
}

/// StreamStats over the named pipe: the engine's data-plane registry counters stream
/// out as `StatsEvent` samples with the accumulated cumulative shape, and the mutation
/// boundaries drive the phase (ApplyTunnel → Connected, StopTunnel → Idle).
#[tokio::test]
async fn stream_stats_pushes_accumulated_samples_over_named_pipe() {
    // The service owns a fresh stats publisher; reach its shared registry through the
    // accessor. The returned `Arc<StatsRegistry>` outlives the service, so the data
    // plane can keep writing after the service moves into the server task.
    let service = HelperControlService::new();
    let registry = service.stats_publisher().registry().clone();

    let name = unique_pipe_name("push");
    let sid = current_user_sid().expect("current user sid");
    let pid = std::process::id();
    let server_task = tokio::spawn({
        let name = name.clone();
        let sid = sid.clone();
        async move {
            let server = HelperControlServer::new(service);
            serve_named_pipe(&name, &sid, pid, server).await
        }
    });

    let pipe = dial_with_retry(&name).await;
    let connector = TestPipeConnector { pipe: Some(pipe) };
    let channel = tonic::transport::Endpoint::from_static("http://engine.local")
        .connect_with_connector(connector)
        .await
        .expect("connect channel");
    let mut client = HelperControlClient::new(channel);

    // 1. Open the StreamStats channel with a short sample interval for a fast test.
    let mut stats_stream = client
        .stream_stats(generated::StreamStatsRequest {
            sample_interval_ms: 20,
        })
        .await
        .expect("stream_stats opens")
        .into_inner();

    // 2. Record counters on the shared registry (the data-plane seam).
    registry.record_rx(1000);
    registry.record_tx(500);
    registry.record_latency(7);

    // 3. The first sample carries the accumulated cumulative shape and phase.
    let first = tokio::time::timeout(Duration::from_secs(2), stats_stream.message())
        .await
        .expect("first sample within timeout")
        .expect("stream alive")
        .expect("event ok");
    assert_eq!(first.rx_bytes, 1000);
    assert_eq!(first.tx_bytes, 500);
    assert_eq!(first.latency_ms, 7);
    assert_eq!(first.phase, generated::StatsPhase::Idle as i32);
    assert_eq!(first.rx_rate, 0, "first sample has no prior rate");
    assert_eq!(first.tx_rate, 0);

    // 4. Drive the owner handshake + ApplyTunnel: the engine phase becomes Connected.
    let principal_digest = sha256(format!("sid:{sid}"));
    let (req_tx, req_rx) = mpsc::channel::<generated::HostLeaseMessage>(8);
    let stream_request = Request::new(tokio_stream::wrappers::ReceiverStream::new(req_rx));
    let mut lease_stream = client
        .maintain_owner_lease(stream_request)
        .await
        .expect("open lease stream")
        .into_inner();
    req_tx
        .send(generated::HostLeaseMessage {
            owner_lease_id: vec![0u8; 16],
            runtime_epoch: vec![0u8; 16],
            message: Some(generated::host_lease_message::Message::Handshake(
                generated::LeaseHandshake {
                    principal_digest: principal_digest.clone(),
                    capability_digest: digest32(0x20),
                    channel_identity_digest: digest32(0x30),
                },
            )),
        })
        .await
        .expect("send handshake");
    let accepted = lease_stream
        .message()
        .await
        .expect("stream alive")
        .expect("handshake accepted");
    assert!(
        matches!(
            accepted.message,
            Some(generated::helper_lease_message::Message::HandshakeAccepted(_))
        ),
        "handshake must be accepted"
    );

    // AcquireLease first: the W15 mutation gate requires a held owner lease.
    let acquire_key = wire_key(5, 1);
    let acquire = client
        .acquire_lease(generated::AcquireLeaseRequest {
            lookup_key: Some(acquire_key.clone()),
            platform_ownership: None,
            request_digest: digest32(1),
        })
        .await
        .expect("acquire succeeds");
    assert!(
        matches!(
            acquire.into_inner().result,
            Some(generated::acquire_lease_reply::Result::Acquired(_))
        ),
        "acquire accepted"
    );

    let apply_key = wire_key(6, 2);
    let apply = client
        .apply_tunnel(generated::ApplyTunnelRequest {
            lookup_key: Some(apply_key.clone()),
            plan: Some(wire_plan()),
            request_digest: digest32(2),
            secret_payload: b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}"
                .to_vec(),
        })
        .await
        .expect("apply succeeds");
    // R1w: ApplyTunnel is async — the reply is the `pending` ApplyAccepted; the terminal
    // flows on the independent StreamConnectStatus channel (never merged into stats).
    assert!(
        matches!(
            apply.into_inner().result,
            Some(generated::apply_tunnel_reply::Result::Pending(_))
        ),
        "apply returns the async pending acceptance"
    );

    // 5. A later sample reflects the Connected phase (mutation boundary transition).
    let mut saw_connected = false;
    for _ in 0..20 {
        let item = tokio::time::timeout(Duration::from_secs(2), stats_stream.message())
            .await
            .expect("stream stays open and delivers")
            .expect("stream alive")
            .expect("event ok");
        if item.phase == generated::StatsPhase::Connected as i32 {
            saw_connected = true;
            break;
        }
    }
    assert!(saw_connected, "ApplyTunnel drives phase to Connected");

    // 6. StopTunnel → the phase returns to Idle.
    let stop_key = wire_key(7, 3);
    let stop = client
        .stop_tunnel(generated::StopTunnelRequest {
            lookup_key: Some(stop_key.clone()),
            request_digest: digest32(3),
        })
        .await
        .expect("stop succeeds");
    assert!(
        matches!(
            stop.into_inner().result,
            Some(generated::stop_tunnel_reply::Result::Stopped(_))
        ),
        "stop accepted"
    );
    let mut saw_idle_after_stop = false;
    for _ in 0..20 {
        let item = tokio::time::timeout(Duration::from_secs(2), stats_stream.message())
            .await
            .expect("stream stays open and delivers")
            .expect("stream alive")
            .expect("event ok");
        if item.phase == generated::StatsPhase::Idle as i32 {
            saw_idle_after_stop = true;
            break;
        }
    }
    assert!(saw_idle_after_stop, "StopTunnel drives phase back to Idle");

    drop(req_tx);
    drop(client);
    server_task.abort();
}
