// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// P1-b RED→GREEN tests for the engine HelperControl tonic gRPC server:
//
//   1. Unit tests (no transport): the `HelperControl` trait handlers fail closed
//      (unauthenticated without the transport-verified peer; refused without an
//      established owner lease), observe/get_operation/stream_logs answer, and
//      the dispatch interceptor rejects unverified requests.
//   2. End-to-end test over a REAL local Named Pipe: `serve_named_pipe` creates
//      the DACL'd pipe, authenticates the core peer (same process → pid/SID pass),
//      and a tonic client drives the full lifecycle — MaintainOwnerLease handshake
//      + keepalive, AcquireLease, GetOperation, ApplyTunnel, StopTunnel,
//      ReleaseLease.
//   3. R1w wire contract over the same real pipe: ApplyTunnel returns the async
//      `pending` ApplyAccepted, and the INDEPENDENT StreamConnectStatus channel
//      pushes the correlated phase progression (operation_id + ConnectPhase +
//      coarse StatsPhase + err), distinct from StreamStats.
//
// The client connector below is a TEST-ONLY minimal named-pipe connector (mirrors
// the proven pattern in exv-core::grpc_transport; the product client is
// P1-c's).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use exv_vpn_domain::identity::{ConnectionBindingDigest, PrincipalDigest};
use exv_engine::grpc_server::HelperControlService;
use exv_engine::grpc_transport::{
    NamedPipeConnectInfo, TransportPeerInfo, require_verified_peer, serve_named_pipe,
};
use exv_engine::log_sink::{LogSink, RawLogDumper};
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
// Helpers
// ---------------------------------------------------------------------------

fn unique_pipe_name(tag: &str) -> String {
    format!(r"\\.\pipe\exv-grpc-server-{tag}-{}", std::process::id())
}

/// A transport-verified peer extension (simulates the named-pipe transport after auth).
fn test_peer() -> NamedPipeConnectInfo {
    NamedPipeConnectInfo(TransportPeerInfo {
        verified: true,
        process_id: 42,
        user_sid: "S-1-5-21-exv-test".to_string(),
        account_name: "exv-test".to_string(),
        principal: PrincipalDigest::try_from([1u8; 32]).expect("principal"),
        connection_digest: ConnectionBindingDigest::try_from([2u8; 32]).expect("connection"),
    })
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

fn with_peer<T>(msg: T, peer: &NamedPipeConnectInfo) -> Request<T> {
    let mut request = Request::new(msg);
    request.extensions_mut().insert(peer.clone());
    request
}

// ---------------------------------------------------------------------------
// Unit tests: fail-closed semantics (no transport needed)
// ---------------------------------------------------------------------------

/// The transport gate: a request without the verified-peer extension is refused.
#[test]
fn interceptor_rejects_unverified_peer() {
    let err = require_verified_peer(Request::new(())).expect_err("must fail closed");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

/// The transport gate: a verified peer passes.
#[test]
fn interceptor_accepts_verified_peer() {
    let mut request = Request::new(());
    request.extensions_mut().insert(test_peer());
    require_verified_peer(request).expect("verified peer passes");
}

/// Every mutation handler fails closed when the transport peer is absent.
#[tokio::test]
async fn mutation_without_verified_peer_rejected() {
    let service = HelperControlService::new();
    let request = Request::new(generated::AcquireLeaseRequest {
        lookup_key: Some(wire_key(5, 1)),
        platform_ownership: None,
        request_digest: digest32(1),
    });
    let status = service.acquire_lease(request).await.expect_err("must fail");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// A mutation requires an established owner lease (MaintainOwnerLease handshake first).
#[tokio::test]
async fn mutation_without_owner_lease_rejected() {
    let service = HelperControlService::new();
    let request = with_peer(
        generated::AcquireLeaseRequest {
            lookup_key: Some(wire_key(5, 1)),
            platform_ownership: None,
            request_digest: digest32(1),
        },
        &test_peer(),
    );
    let status = service.acquire_lease(request).await.expect_err("must fail");
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
}

/// Observe returns the identity-free Idle snapshot for the pure composition phase.
#[tokio::test]
async fn observe_owned_state_returns_idle() {
    let service = HelperControlService::new();
    let request = with_peer(
        generated::ObserveOwnedStateRequest {
            lookup_key: Some(wire_key(1, 1)),
        },
        &test_peer(),
    );
    let reply = service
        .observe_owned_state(request)
        .await
        .expect("observe succeeds");
    let snapshot = reply.into_inner().snapshot.expect("snapshot");
    assert!(
        matches!(
            snapshot.state,
            Some(generated::runtime_snapshot::State::Idle(_))
        ),
        "pure composition observes Idle"
    );
}

/// GetOperation answers Unknown for a never-seen operation.
#[tokio::test]
async fn get_operation_unknown_for_absent() {
    let service = HelperControlService::new();
    let request = with_peer(
        generated::GetOperationRequest {
            lookup_key: Some(wire_key(5, 9)),
        },
        &test_peer(),
    );
    let reply = service.get_operation(request).await.expect("get operation");
    let state = reply.into_inner().state.expect("state");
    assert!(
        matches!(state.state, Some(generated::operation_state::State::Unknown(_))),
        "absent operation is Unknown"
    );
}

/// StreamLogs is gated by the transport peer and returns an empty stream (P2 replaces).
#[tokio::test]
async fn stream_logs_requires_verified_peer() {
    let service = HelperControlService::new();
    let request = Request::new(generated::StreamLogsRequest { resume_tick: 0 });
    let status = service.stream_logs(request).await.expect_err("must fail");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// StreamLogs opens for a verified peer and stays open, delivering real business events
/// pushed through the service's log sink — over the real named-pipe transport (P2-b real
/// push; replaces the P1-b empty stream). The pipe multiplexes StreamLogs + the lease
/// stream + unary RPCs over one gRPC connection, exactly like the product.
#[tokio::test]
async fn stream_logs_pushes_business_events() {
    use std::sync::Arc;
    use tonic::codegen::tokio_stream::StreamExt;

    // A temp-dir log sink so the test is hermetic (no files on the machine log dir).
    let temp = tempfile::tempdir().expect("temp dir");
    let sink = Arc::new(LogSink::new(RawLogDumper::new(temp.path().join("logs"))));
    let service = HelperControlServer::new(HelperControlService::with_log_sink(sink));

    let name = unique_pipe_name("logs");
    let sid = current_user_sid().expect("current user sid");
    let pid = std::process::id();
    let server_task = tokio::spawn({
        let name = name.clone();
        let sid = sid.clone();
        async move { serve_named_pipe(&name, &sid, pid, service).await }
    });

    let pipe = dial_with_retry(&name).await;
    let connector = TestPipeConnector { pipe: Some(pipe) };
    let channel = tonic::transport::Endpoint::from_static("http://engine.local")
        .connect_with_connector(connector)
        .await
        .expect("connect channel");
    let mut client = HelperControlClient::new(channel);

    // 1. Open the StreamLogs channel (first pushed event is the channel-opened confirmation).
    let mut log_stream = client
        .stream_logs(generated::StreamLogsRequest { resume_tick: 0 })
        .await
        .expect("stream_logs opens")
        .into_inner();

    // 2. Drive the owner lease handshake, then a mutation, so business points emit events.
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

    // 3. The pushed stream carries the events, in emit order: channel-opened, handshake
    //    accepted, acquire accepted.
    let mut codes = Vec::new();
    for _ in 0..3 {
        let item = tokio::time::timeout(Duration::from_secs(2), log_stream.message())
            .await
            .expect("stream stays open and delivers")
            .expect("stream alive")
            .expect("event ok");
        codes.push(item.code);
    }
    assert_eq!(
        codes,
        vec![
            "logs.stream.opened".to_string(),
            "lease.handshake.accepted".to_string(),
            "mutation.acquire.accepted".to_string(),
        ],
        "business events pushed in order"
    );

    // The stream does NOT complete on its own: it stays open for live push (idle between
    // events = the 150ms timeout fires; EOF or an extra event would be a contract break).
    let drained = tokio::time::timeout(Duration::from_millis(150), log_stream.message()).await;
    assert!(
        matches!(drained, Err(_)),
        "stream idle between events (stays open, no EOF or extra event): {drained:?}"
    );

    drop(req_tx);
    drop(client);
    server_task.abort();
}

// ---------------------------------------------------------------------------
// End-to-end test: real local named pipe + tonic client
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

/// Full lifecycle over the real named-pipe transport:
/// handshake → keepalive → acquire → get_operation → apply → stop → release.
#[tokio::test]
async fn full_control_plane_round_trip_over_named_pipe() {
    let name = unique_pipe_name("e2e");
    let sid = current_user_sid().expect("current user sid");
    let pid = std::process::id();

    let server = HelperControlServer::new(HelperControlService::new());
    let serve = {
        let name = name.clone();
        let sid = sid.clone();
        async move { serve_named_pipe(&name, &sid, pid, server).await }
    };
    let server_task = tokio::spawn(serve);

    let client = dial_with_retry(&name).await;
    let connector = TestPipeConnector { pipe: Some(client) };
    let channel = tonic::transport::Endpoint::from_static("http://engine.local")
        .connect_with_connector(connector)
        .await
        .expect("connect channel");
    let mut client = HelperControlClient::new(channel);

    // ---- MaintainOwnerLease: handshake -> accepted. ----
    // The handshake's self-reported principal digest must equal the transport-derived
    // principal (SHA-256 of "sid:<user SID>"), mirroring the engine's derivation.
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
        .expect("handshake accepted message");
    assert!(
        matches!(
            accepted.message,
            Some(generated::helper_lease_message::Message::HandshakeAccepted(_))
        ),
        "expected handshake accepted"
    );
    // The server establishes the runtime epoch; the host echoes it on subsequent messages.
    let established_epoch = accepted.runtime_epoch.clone();

    // ---- Keepalive -> ack. ----
    req_tx
        .send(generated::HostLeaseMessage {
            owner_lease_id: vec![0u8; 16],
            runtime_epoch: established_epoch.clone(),
            message: Some(generated::host_lease_message::Message::Keepalive(
                generated::LeaseKeepalive { monotonic_tick: 7 },
            )),
        })
        .await
        .expect("send keepalive");

    let ack = lease_stream
        .message()
        .await
        .expect("stream alive")
        .expect("keepalive ack message");
    assert!(
        matches!(
            ack.message,
            Some(generated::helper_lease_message::Message::KeepaliveAck(_))
        ),
        "expected keepalive ack"
    );

    // ---- AcquireLease -> Acquired receipt. ----
    let acquire_key = wire_key(5, 1);
    let acquire = client
        .acquire_lease(generated::AcquireLeaseRequest {
            lookup_key: Some(acquire_key.clone()),
            platform_ownership: None,
            request_digest: digest32(1),
        })
        .await
        .expect("acquire rpc succeeds");
    let acquire_result = acquire.into_inner().result.expect("acquire result");
    let receipt = match acquire_result {
        generated::acquire_lease_reply::Result::Acquired(receipt) => receipt,
        generated::acquire_lease_reply::Result::Failed(failed) => {
            panic!("acquire failed: {failed:?}")
        }
    };
    assert_eq!(receipt.ownership_version, 1);
    assert_eq!(receipt.certainty, 2); // EffectCertainty::Applied

    // ---- GetOperation -> Terminal(Succeeded). ----
    let get = client
        .get_operation(generated::GetOperationRequest {
            lookup_key: Some(acquire_key.clone()),
        })
        .await
        .expect("get_operation rpc succeeds");
    let state = get.into_inner().state.expect("state");
    assert!(
        matches!(
            state.state,
            Some(generated::operation_state::State::Terminal(
                generated::OperationTerminal {
                    result: Some(generated::operation_terminal::Result::Succeeded(_))
                }
            ))
        ),
        "acquired operation is terminal-succeeded"
    );

    // ---- ApplyTunnel -> Pending (R1w async). ----
    // R1w: ApplyTunnel returns the async `pending` ApplyAccepted; the terminal outcome
    // flows on the independent StreamConnectStatus channel. The pending reply carries
    // the operation_id of the in-flight operation.
    let apply_key = wire_key(6, 2);
    let apply = client
        .apply_tunnel(generated::ApplyTunnelRequest {
            lookup_key: Some(apply_key.clone()),
            plan: Some(wire_plan()),
            request_digest: digest32(2),
            // P3-b1: one-shot CSTP credentials (serde JSON, version=1, same shape as the
            // host's CredentialPackage). The engine parses them for the CSTP auth seam.
            secret_payload: b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}"
                .to_vec(),
        })
        .await
        .expect("apply rpc succeeds");
    let accepted = match apply.into_inner().result.expect("apply result") {
        generated::apply_tunnel_reply::Result::Pending(accepted) => accepted,
        generated::apply_tunnel_reply::Result::Applied(_) => {
            panic!("R1w: apply must return pending, not a terminal applied")
        }
        generated::apply_tunnel_reply::Result::Failed(failed) => {
            panic!("apply failed: {failed:?}")
        }
    };
    assert_eq!(
        accepted.operation_id, apply_key.operation_id,
        "pending ApplyAccepted carries the operation_id"
    );

    // ---- StopTunnel -> Stopped. ----
    let stop_key = wire_key(7, 3);
    let stop = client
        .stop_tunnel(generated::StopTunnelRequest {
            lookup_key: Some(stop_key.clone()),
            request_digest: digest32(3),
        })
        .await
        .expect("stop rpc succeeds");
    match stop.into_inner().result.expect("stop result") {
        generated::stop_tunnel_reply::Result::Stopped(_) => {}
        generated::stop_tunnel_reply::Result::Failed(failed) => {
            panic!("stop failed: {failed:?}")
        }
    }

    // ---- ApplyTunnel with a MALFORMED secret_payload fails closed. ----
    // The engine parses `secret_payload` before admission (J51), so a truncated
    // one-shot payload is rejected with InvalidArgument; no mutation effect is
    // produced and the wire copy is zeroized (P3-b1 fail-closed over the RPC
    // boundary, not just at the parse unit).
    let apply_bad = client
        .apply_tunnel(generated::ApplyTunnelRequest {
            lookup_key: Some(wire_key(6, 5)),
            plan: Some(wire_plan()),
            request_digest: digest32(5),
            // Truncated JSON (missing closing brace) with the password substring intact.
            secret_payload: b"{\"version\":1,\"username\":\"student\",\"password\":\"hunter2\""
                .to_vec(),
        })
        .await
        .expect_err("malformed secret_payload must fail closed");
    assert_eq!(
        apply_bad.code(),
        tonic::Code::InvalidArgument,
        "malformed one-shot payload rejected as InvalidArgument"
    );
    assert!(
        !apply_bad.to_string().contains("hunter2"),
        "RPC error must not carry plaintext"
    );

    // ---- ReleaseLease -> Released. ----
    let release_key = wire_key(8, 4);
    let release = client
        .release_lease(generated::ReleaseLeaseRequest {
            lookup_key: Some(release_key.clone()),
            request_digest: digest32(4),
        })
        .await
        .expect("release rpc succeeds");
    match release.into_inner().result.expect("release result") {
        generated::release_lease_reply::Result::Released(_) => {}
        generated::release_lease_reply::Result::Failed(failed) => {
            panic!("release failed: {failed:?}")
        }
    }

    // End the request stream and shut the server down.
    drop(req_tx);
    drop(client);
    server_task.abort();
}

/// R1w wire contract over the REAL local Named Pipe (bidirectional auth): the engine's
/// independent connect-status channel.
///
///   1. `StreamConnectStatus` is transport-gated (unauthenticated peer refused).
///   2. Over the pipe: open the status stream, drive the lease handshake + acquire +
///      apply, and verify the status channel pushes the phase progression —
///      ApplyingPlatformTunnel → StartingDataPlane → Connected — every event carrying
///      the SAME operation_id as the `pending` ApplyAccepted reply (correlation).
///   3. The pending branch is returnable and the stream stays open (no EOF).
///   4. `StopTunnel` pushes the coarse-Idle terminal for the stop operation.
///
/// This is the R1w acceptance seam: the status stream is INDEPENDENT from StreamStats.
#[tokio::test]
async fn stream_connect_status_pushes_correlated_phases_over_named_pipe() {
    let name = unique_pipe_name("status");
    let sid = current_user_sid().expect("current user sid");
    let pid = std::process::id();

    let server = HelperControlServer::new(HelperControlService::new());
    let serve = {
        let name = name.clone();
        let sid = sid.clone();
        async move { serve_named_pipe(&name, &sid, pid, server).await }
    };
    let server_task = tokio::spawn(serve);

    let pipe = dial_with_retry(&name).await;
    let connector = TestPipeConnector { pipe: Some(pipe) };
    let channel = tonic::transport::Endpoint::from_static("http://engine.local")
        .connect_with_connector(connector)
        .await
        .expect("connect channel");
    let mut client = HelperControlClient::new(channel);

    // ---- 1. Open the independent status stream FIRST (attaches the push slot). ----
    let mut status_stream = client
        .stream_connect_status(generated::StreamConnectStatusRequest {})
        .await
        .expect("stream_connect_status opens")
        .into_inner();

    // ---- 2. Lease handshake (bidirectional auth; principal = sha256("sid:<sid>")). ----
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
    let established_epoch = accepted.runtime_epoch.clone();

    // ---- 3. AcquireLease (owner lease for the mutation gate). ----
    let acquire_key = wire_key(5, 1);
    client
        .acquire_lease(generated::AcquireLeaseRequest {
            lookup_key: Some(acquire_key.clone()),
            platform_ownership: None,
            request_digest: digest32(1),
        })
        .await
        .expect("acquire succeeds");

    // ---- 4. ApplyTunnel returns the async `pending` ApplyAccepted (R1w). ----
    let apply_key = wire_key(6, 2);
    let expected_operation_id = apply_key.operation_id.clone();
    let apply = client
        .apply_tunnel(generated::ApplyTunnelRequest {
            lookup_key: Some(apply_key.clone()),
            plan: Some(wire_plan()),
            request_digest: digest32(2),
            secret_payload: b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}"
                .to_vec(),
        })
        .await
        .expect("apply rpc succeeds");
    let accepted = match apply.into_inner().result.expect("apply result") {
        generated::apply_tunnel_reply::Result::Pending(accepted) => accepted,
        other => panic!("R1w: apply must return pending, got {other:?}"),
    };
    assert_eq!(
        accepted.operation_id, expected_operation_id,
        "pending ApplyAccepted carries the operation_id"
    );

    // ---- 5. The status channel pushes the phase progression, all correlated. ----
    // (ApplyingPlatformTunnel -> StartingDataPlane -> Connected), each with the SAME
    // operation_id as the pending reply.
    let mut saw_apply_start = false;
    let mut saw_data_plane = false;
    let mut saw_connected = false;
    for _ in 0..6 {
        let item = tokio::time::timeout(Duration::from_secs(2), status_stream.message())
            .await
            .expect("status stream delivers")
            .expect("stream alive")
            .expect("event ok");
        assert_eq!(
            item.operation_id, expected_operation_id,
            "every status event is correlated to the apply operation"
        );
        if item.connect_phase == generated::ConnectPhase::ApplyingPlatformTunnel as i32 {
            saw_apply_start = true;
        }
        if item.connect_phase == generated::ConnectPhase::StartingDataPlane as i32
            && item.coarse_phase == generated::StatsPhase::Connecting as i32
        {
            saw_data_plane = true;
        }
        if item.coarse_phase == generated::StatsPhase::Connected as i32 {
            saw_connected = true;
            break;
        }
    }
    assert!(saw_apply_start, "saw ApplyingPlatformTunnel phase event");
    assert!(saw_data_plane, "saw StartingDataPlane/Connecting phase event");
    assert!(saw_connected, "saw the Connected terminal event");

    // ---- 5.5 R2/P2-1: GetOperation(apply) resolves to the real terminal (Succeeded)
    // ---- instead of lying Pending forever — the runtime Connected was recorded into
    // ---- core.terminals via the internal terminal observer. ----
    let op = client
        .get_operation(generated::GetOperationRequest {
            lookup_key: Some(apply_key.clone()),
        })
        .await
        .expect("get_operation rpc succeeds")
        .into_inner();
    let apply_terminal = match op
        .state
        .expect("operation state")
        .state
        .expect("state oneof")
    {
        generated::operation_state::State::Terminal(terminal) => terminal,
        other => panic!("R2/P2-1: apply must be terminal after Connected, got {other:?}"),
    };
    assert!(
        matches!(
            apply_terminal.result,
            Some(generated::operation_terminal::Result::Succeeded(_))
        ),
        "R2/P2-1: apply terminal must be Succeeded after Connected"
    );

    // ---- 6. The stream does NOT complete on its own (idle stays open). ----
    let drained = tokio::time::timeout(Duration::from_millis(150), status_stream.message()).await;
    assert!(
        matches!(drained, Err(_)),
        "status stream idle between events (stays open, no EOF): {drained:?}"
    );

    // ---- 7. StopTunnel pushes the coarse-Idle terminal for the stop operation. ----
    let stop_key = wire_key(7, 3);
    client
        .stop_tunnel(generated::StopTunnelRequest {
            lookup_key: Some(stop_key.clone()),
            request_digest: digest32(3),
        })
        .await
        .expect("stop rpc succeeds");
    let idle = tokio::time::timeout(Duration::from_secs(2), status_stream.message())
        .await
        .expect("stop idle event within timeout")
        .expect("stream alive")
        .expect("event ok");
    assert_eq!(
        idle.coarse_phase,
        generated::StatsPhase::Idle as i32,
        "StopTunnel pushes the coarse-Idle terminal"
    );
    assert_eq!(
        idle.operation_id, stop_key.operation_id,
        "stop idle event carries the stop operation_id"
    );

    // End the request stream and shut the server down.
    drop(req_tx);
    drop(client);
    server_task.abort();
}

/// StreamConnectStatus is gated by the transport peer: an unverified request is refused.
#[tokio::test]
async fn stream_connect_status_requires_verified_peer() {
    let service = HelperControlService::new();
    let request = Request::new(generated::StreamConnectStatusRequest {});
    let status = service
        .stream_connect_status(request)
        .await
        .expect_err("must fail closed");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// P2 KeepAlive is gated by the transport peer: an unverified request must NOT refresh
/// the heartbeat — a heartbeat from an imposter would defeat the bounded-retention hard
/// time bound.
#[tokio::test]
async fn keep_alive_requires_verified_peer() {
    let service = HelperControlService::new();
    let request = Request::new(generated::KeepAliveRequest { monotonic_tick: 7 });
    let status = service
        .keep_alive(request)
        .await
        .expect_err("unverified keepalive must fail closed");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// P2 KeepAlive wire contract over the REAL Named Pipe (bidirectional auth): the
/// verified core's unary heartbeat refreshes the engine's last-heartbeat timestamp and
/// the engine echoes the core's monotonic tick. This is the bounded-retention heartbeat
/// that keeps the engine alive past the 15s timeout while the core is healthy.
#[tokio::test]
async fn keep_alive_echoes_tick_and_refreshes_heartbeat_over_named_pipe() {
    let name = unique_pipe_name("keepalive");
    let sid = current_user_sid().expect("current user sid");
    let pid = std::process::id();

    // Grab the heartbeat watch BEFORE the service moves into the server: the E2E assert
    // reads the refreshed timestamp (last heartbeat reset near engine start).
    let service = HelperControlService::new();
    let heartbeat = service.heartbeat_watch();
    let server = HelperControlServer::new(service);
    let serve = {
        let name = name.clone();
        let sid = sid.clone();
        async move { serve_named_pipe(&name, &sid, pid, server).await }
    };
    let server_task = tokio::spawn(serve);

    let pipe = dial_with_retry(&name).await;
    let connector = TestPipeConnector { pipe: Some(pipe) };
    let channel = tonic::transport::Endpoint::from_static("http://engine.local")
        .connect_with_connector(connector)
        .await
        .expect("connect channel");
    let mut client = HelperControlClient::new(channel);

    // The engine just started; the heartbeat watch counts from launch (elapsed small).
    let reply = client
        .keep_alive(generated::KeepAliveRequest { monotonic_tick: 42 })
        .await
        .expect("keepalive rpc succeeds")
        .into_inner();
    assert_eq!(reply.monotonic_tick, 42, "engine echoes the core's heartbeat tick");

    // The heartbeat watch was refreshed: elapsed since the last heartbeat is ~0 (not the
    // engine-runtime elapsed since launch). A heartbeat that did NOT touch the watch would
    // leave elapsed equal to the whole boot time and fail this bound.
    assert!(
        heartbeat.elapsed_ms() < 1000,
        "keepalive must refresh the engine heartbeat watch (elapsed {} ms)",
        heartbeat.elapsed_ms()
    );

    drop(client);
    server_task.abort();
}

/// S3/Tier 2: `ServiceManage` is gated by the transport peer — an unverified
/// request is refused (must NOT leak the engine's deep self-report to an
/// unauthenticated peer).
#[tokio::test]
async fn service_manage_requires_verified_peer() {
    let service = HelperControlService::new();
    let request = Request::new(generated::ServiceManageRequest {
        action: Some(generated::service_manage_request::Action::Query(
            generated::ServiceSelfQuery::default(),
        )),
    });
    let status = service
        .service_manage(request)
        .await
        .expect_err("must fail closed");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
}

/// S3/Tier 2 `ServiceManage.query` wire contract over the REAL Named Pipe: the
/// verified core receives the engine's deep self-report, and the report's
/// mode/ready/psk match the construction (with_service_self injection).
#[tokio::test]
async fn service_manage_query_over_named_pipe() {
    let name = unique_pipe_name("servicemanage");
    let sid = current_user_sid().expect("current user sid");
    let pid = std::process::id();

    // Inject a service-self seam whose psk_present=true and control_plane_ready
    // mirrors a shared AtomicBool (the accept-loop's store(true) path sets it in
    // production; here the test pre-sets it to exercise the report read).
    let control_plane_ready = Arc::new(AtomicBool::new(true));
    let service = HelperControlService::new().with_service_self(Arc::clone(&control_plane_ready), true);
    let server = HelperControlServer::new(service);
    let serve = {
        let name = name.clone();
        let sid = sid.clone();
        async move { serve_named_pipe(&name, &sid, pid, server).await }
    };
    let server_task = tokio::spawn(serve);

    let pipe = dial_with_retry(&name).await;
    let connector = TestPipeConnector { pipe: Some(pipe) };
    let channel = tonic::transport::Endpoint::from_static("http://engine.local")
        .connect_with_connector(connector)
        .await
        .expect("connect channel");
    let mut client = HelperControlClient::new(channel);

    let reply = client
        .service_manage(generated::ServiceManageRequest {
            action: Some(generated::service_manage_request::Action::Query(
                generated::ServiceSelfQuery::default(),
            )),
        })
        .await
        .expect("service_manage rpc succeeds")
        .into_inner();
    let report = reply.self_report.expect("self_report present");
    assert_eq!(report.connection_mode, "oneshot", "mode matches construction");
    assert!(
        report.control_plane_ready,
        "control_plane_ready reflects the shared AtomicBool"
    );
    assert!(report.psk_present, "psk_present matches with_service_self(true)");
    assert_eq!(report.runtime_epoch.len(), 16, "runtime_epoch is 16 bytes");
    assert!(
        report.authority_fence.is_some(),
        "authority fence present in the report"
    );

    // The report reads the SAME shared AtomicBool the accept-loop writes: flipping
    // it makes the next query report not-ready (production store(true) is idempotent).
    control_plane_ready.store(false, Ordering::SeqCst);
    let reply = client
        .service_manage(generated::ServiceManageRequest {
            action: Some(generated::service_manage_request::Action::Query(
                generated::ServiceSelfQuery::default(),
            )),
        })
        .await
        .expect("second query succeeds")
        .into_inner();
    let report = reply.self_report.expect("self_report present");
    assert!(
        !report.control_plane_ready,
        "report must reflect the shared AtomicBool flip"
    );

    drop(client);
    server_task.abort();
}

// ---------------------------------------------------------------------------
// D4 状态权威跨连接保留（engine 持久化生命周期，P1）：P1 测试清单钉死——
//  (a) 二次 connect 过 gate（同 peer 新 connect 操作，gate 命中首次 lease）；
//  (b) 新连接不能借用旧 owner 授权（bind_mutation 的 peer 校验生效）；
//  (c) 异常断线（token 未 ACK）后 acquire 可恢复（owner_lease.rs 单测，见下）。
// ---------------------------------------------------------------------------

/// D4(a)：二次 connect 过 gate，gate 命中首次 lease。
///
/// 状态权威跨连接保留（D4）：acquire 建立的 J52 lease 在 StopTunnel 后**不 release**
///（grpc_server `stop_tunnel` 注释契约——lease 随 ReleaseLease 才退役）。engine 常驻
/// （D1 解耦），二次 ApplyTunnel（新 connect 操作、同 peer 同 owner 会话）经
/// `admit_and_gate` 用 owner.connection 命中首次 lease → gate 通过（返回 pending 而非
/// `failed_precondition("no owner lease for gate")`）。热启动路径由此成立。
#[tokio::test]
async fn second_connect_passes_gate_hitting_first_lease() {
    let name = unique_pipe_name("d4a");
    let sid = current_user_sid().expect("current user sid");
    let pid = std::process::id();

    let server = HelperControlServer::new(HelperControlService::new());
    let serve = {
        let name = name.clone();
        let sid = sid.clone();
        async move { serve_named_pipe(&name, &sid, pid, server).await }
    };
    let server_task = tokio::spawn(serve);

    let client = dial_with_retry(&name).await;
    let connector = TestPipeConnector { pipe: Some(client) };
    let channel = tonic::transport::Endpoint::from_static("http://engine.local")
        .connect_with_connector(connector)
        .await
        .expect("connect channel");
    let mut client = HelperControlClient::new(channel);

    // ---- owner 授权握手（同 peer；一次握手，跨 connect/stop 保持）。 ----
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

    // ---- 首次 acquire：issue 首次 lease（slot 持 token；测试不 ACK，镜像"gate 命中
    // ---- 首次 lease"的前置——lease 保持存活）。 ----
    let acquire = client
        .acquire_lease(generated::AcquireLeaseRequest {
            lookup_key: Some(wire_key(5, 1)),
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
        "first acquire accepted"
    );

    // ---- 首次 connect：ApplyTunnel 过 gate（lease 存活）→ pending。 ----
    let apply1 = client
        .apply_tunnel(generated::ApplyTunnelRequest {
            lookup_key: Some(wire_key(6, 2)),
            plan: Some(wire_plan()),
            request_digest: digest32(2),
            secret_payload: b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}"
                .to_vec(),
        })
        .await
        .expect("first connect apply accepted");
    assert!(
        matches!(
            apply1.into_inner().result,
            Some(generated::apply_tunnel_reply::Result::Pending(_))
        ),
        "first connect passes the gate (pending)"
    );

    // ---- 停机：StopTunnel → Stopped；lease 不 release（D4 契约）。 ----
    let stop = client
        .stop_tunnel(generated::StopTunnelRequest {
            lookup_key: Some(wire_key(7, 3)),
            request_digest: digest32(3),
        })
        .await
        .expect("stop succeeds");
    assert!(
        matches!(
            stop.into_inner().result,
            Some(generated::stop_tunnel_reply::Result::Stopped(_))
        ),
        "stop returns Stopped (engine stays resident, lease kept)"
    );

    // ---- 二次 connect：新 connect 操作（新 operation_id/key）过 gate——命中首次 lease，
    // ---- 返回 pending，不得 `failed_precondition("no owner lease for gate")`。 ----
    let apply2 = client
        .apply_tunnel(generated::ApplyTunnelRequest {
            lookup_key: Some(wire_key(6, 6)),
            plan: Some(wire_plan()),
            request_digest: digest32(6),
            secret_payload: b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}"
                .to_vec(),
        })
        .await
        .expect("second connect apply accepted");
    assert!(
        matches!(
            apply2.into_inner().result,
            Some(generated::apply_tunnel_reply::Result::Pending(_))
        ),
        "second connect must pass the gate hitting the first lease (D4(a))"
    );

    drop(req_tx);
    drop(client);
    server_task.abort();
}

/// 把一条 prost 消息编码为 gRPC 单帧字节（无压缩标志 + 4 字节 BE 长度 + payload）——
/// 供单测构造 `Streaming` 请求体（镜像 tonic 客户端编码）。
fn framed_grpc_bytes<T: prost::Message>(msg: &T) -> Vec<u8> {
    let payload = msg.encode_to_vec();
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0u8); // 无压缩。
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap_or_default().to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

/// 构造一条 `maintain_owner_lease` 的请求（已编码 handshake + 给定 transport peer
/// 扩展）——单测直接建立 owner 会话，无需真实管道。
fn lease_handshake_request(
    peer: &NamedPipeConnectInfo,
    principal_digest: Vec<u8>,
) -> Request<tonic::Streaming<generated::HostLeaseMessage>> {
    use http_body_util::Full;
    let handshake = generated::HostLeaseMessage {
        owner_lease_id: vec![0u8; 16],
        runtime_epoch: vec![0u8; 16],
        message: Some(generated::host_lease_message::Message::Handshake(
            generated::LeaseHandshake {
                principal_digest,
                capability_digest: digest32(0x20),
                channel_identity_digest: digest32(0x30),
            },
        )),
    };
    let body = Full::new(bytes::Bytes::from(framed_grpc_bytes(&handshake)));
    let decoder = tonic_prost::ProstDecoder::<generated::HostLeaseMessage>::default();
    let streaming = tonic::Streaming::new_request(decoder, body, None, None);
    let mut request = Request::new(streaming);
    request.extensions_mut().insert(peer.clone());
    request
}

/// 一个与 [`test_peer`] 不同 principal / connection 的 transport peer（模拟"新连接"——
/// 每 accept 一个独立 nonce → 不同 connection binding；此处还换 principal 以示"别的
/// 主体"）。
fn other_peer() -> NamedPipeConnectInfo {
    NamedPipeConnectInfo(TransportPeerInfo {
        verified: true,
        process_id: 99,
        user_sid: "S-1-5-21-exv-other".to_string(),
        account_name: "exv-other".to_string(),
        principal: PrincipalDigest::try_from([3u8; 32]).expect("principal"),
        connection_digest: ConnectionBindingDigest::try_from([4u8; 32]).expect("connection"),
    })
}

/// D4(b)：新连接不能借用旧 owner 授权——bind_mutation 的 peer 校验生效。
///
/// owner 会话由 peer A（[`test_peer`]）建立；随后一个**不同 peer**（[`other_peer`]，
/// 模拟新连接/新主体）发起 mutation（acquire_lease）→ `bind_mutation` 的
/// `owner.peer != peer` 检查拒绝 → `unauthenticated("owner peer mismatch")`。旧 owner
/// 的授权绝不跨连接外借。
#[tokio::test]
async fn new_connection_cannot_borrow_old_owner_authorization() {
    use tonic::codegen::tokio_stream::StreamExt as _;

    let service = HelperControlService::new();
    let owner_peer = test_peer();

    // 1. 建立 owner（peer A）：maintain_owner_lease 握手 → HandshakeAccepted。
    //    握手 principal_digest 必须等于 transport peer A 的 principal（[1u8; 32]，
    //    与 [`test_peer`] 一致）。
    let lease_request = lease_handshake_request(&owner_peer, vec![1u8; 32]);
    let lease_response = service
        .maintain_owner_lease(lease_request)
        .await
        .expect("open lease stream");
    let mut lease_stream = lease_response.into_inner();
    let first = tokio::time::timeout(Duration::from_secs(2), lease_stream.next())
        .await
        .expect("handshake reply within timeout")
        .expect("stream alive")
        .expect("message ok");
    assert!(
        matches!(
            first.message,
            Some(generated::helper_lease_message::Message::HandshakeAccepted(_))
        ),
        "owner handshake accepted for peer A"
    );

    // 2. 新连接（peer B ≠ owner peer）发起 acquire → bind_mutation peer 校验拒绝。
    let other = other_peer();
    let request = with_peer(
        generated::AcquireLeaseRequest {
            lookup_key: Some(wire_key(5, 1)),
            platform_ownership: None,
            request_digest: digest32(1),
        },
        &other,
    );
    let status = service
        .acquire_lease(request)
        .await
        .expect_err("new connection must not borrow old owner authorization");
    assert_eq!(
        status.code(),
        tonic::Code::Unauthenticated,
        "bind_mutation must reject a peer that differs from the owner (D4(b))"
    );
    assert!(
        status.message().contains("owner peer mismatch"),
        "rejection must name the owner peer mismatch, got: {}",
        status.message()
    );
}
