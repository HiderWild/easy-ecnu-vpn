// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! P3-b2 集成测试：host 的 `KernelControl` 写路径 engine 派发 ⇄ 真实 in-process engine
//! （`exv-engine` 的 `HelperControlService`，P1-b）经真实 Named Pipe。
//!
//! 验证 P3-b1 契约的 host 侧闭合：`apply_connect`（`KernelEngineControl` 真实实现）把
//! 一次性 `secret_payload` 移入 `ApplyTunnelRequest.secret_payload`（tag=4）随 wire 走，
//! engine 解析同形状（`CredentialPackage`，version=1）——有效载荷被接受（引擎存为
//! `pending_credentials`），**畸形载荷被 engine 拒绝**（`invalid_argument`，证明秘密确实
//! 到达 engine 的解析器），且每次派发后 host 的 one-shot 槽确定性零化。
//!
//! 复用 grpc_interop 的同进程手法：engine 侧服务 + host 侧 `EngineControlGrpcClient` 在
//! 同一进程内经真实 local Named Pipe 连通，双向 peer 认证（server 验 core pid+SID；
//! client 验 engine pid+SID）。mutation 前置 owner lease 握手（MaintainOwnerLease 首条
//! 消息为授权握手，principal digest = SHA-256("sid:<SID>")，镜像 engine 的派生）。

use exv_core::grpc_control::{EngineControlGrpcClient, KernelEngineControl};
use exv_core::kernel_control::ClearableSecret;
use exv_engine::grpc_server::HelperControlService;
use exv_engine::grpc_transport::serve_named_pipe;
use exv_vpn_win32_ipc::peer_auth::current_user_sid;
use exv_vpn_wire::generated::helper_control_server::HelperControlServer;
use exv_vpn_wire::generated::{
    self as wire, ApplyTunnelRequest, HostLeaseMessage, OperationLookupKey,
};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tonic::{Code, Request};
use tokio_stream::wrappers::ReceiverStream;

fn unique_pipe_name(tag: &str) -> String {
    format!(r"\\.\pipe\exv-kernel-engine-{tag}-{}", std::process::id())
}

/// SHA-256 of `bytes`（镜像 engine 的 principal 派生）。
fn sha256(bytes: impl AsRef<[u8]>) -> Vec<u8> {
    Sha256::digest(bytes.as_ref()).to_vec()
}

/// 16 字节非 nil uuid（wire epoch / operation id）。
fn uuid16(n: u8) -> Vec<u8> {
    let mut bytes = [0u8; 16];
    bytes[0] = n;
    bytes[1] = 0x42;
    bytes.to_vec()
}

/// 32 字节 digest。
fn digest32(n: u8) -> Vec<u8> {
    vec![n; 32]
}

/// 合法 wire lookup key（method 为给定判别值；每 `n` 一个独立身份）。
fn wire_key(method: i32, n: u8) -> OperationLookupKey {
    OperationLookupKey {
        principal_digest: digest32(0x10),
        method,
        runtime_epoch: uuid16(n),
        operation_id: uuid16(n + 1),
    }
}

/// 合法 wire tunnel plan。
fn wire_plan() -> wire::TunnelPlan {
    wire::TunnelPlan {
        ipv4_address: vec![10, 0, 0, 1],
        ipv4_prefix_len: 24,
        mtu: 1400,
        ipv4_routes: vec![],
        dns_servers: vec![],
        control_bypass: vec![],
        opaque_intent: Some(wire::TunnelIntentRef {
            identity_digest: digest32(0x33),
        }),
    }
}

/// host 的 `apply_connect`（`KernelEngineControl` 真实实现）把一次性秘密移入
/// `ApplyTunnelRequest.secret_payload` 随 wire 走，engine 解析后接受；畸形载荷被
/// engine 拒绝；每次派发后 one-shot 槽确定性零化。
#[tokio::test]
async fn connect_secret_reaches_engine_and_zeroizes_slot() {
    let name = unique_pipe_name("connect");
    let pid = std::process::id();
    let sid = current_user_sid().expect("current user sid");

    // engine 侧：建 pipe → accept → 验 core → serve HelperControl。
    let server = HelperControlServer::new(HelperControlService::new());
    let serve_pipe = name.clone();
    let serve_sid = sid.clone();
    let serve_pid = pid;
    let serve_task = tokio::spawn(async move {
        serve_named_pipe(&serve_pipe, &serve_sid, serve_pid, server)
            .await
            .expect("engine serve");
    });

    // host 侧：拨号 + 双向 peer 认证 + gRPC channel。
    let mut client = EngineControlGrpcClient::connect(&name, pid, &sid)
        .await
        .expect("host connect");

    // ---- MaintainOwnerLease 授权握手：handshake -> accepted。----
    let principal_digest = sha256(format!("sid:{sid}"));
    let (req_tx, req_rx) = mpsc::channel::<HostLeaseMessage>(8);
    let stream_request = Request::new(ReceiverStream::new(req_rx));
    let mut lease_stream = client
        .maintain_owner_lease(stream_request)
        .await
        .expect("open lease stream");
    req_tx
        .send(HostLeaseMessage {
            owner_lease_id: vec![0u8; 16],
            runtime_epoch: vec![0u8; 16],
            message: Some(wire::host_lease_message::Message::Handshake(
                wire::LeaseHandshake {
                    principal_digest,
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
            Some(wire::helper_lease_message::Message::HandshakeAccepted(_))
        ),
        "handshake must be accepted"
    );

    // ---- AcquireLease：建立 J52 lease 槽（W15 admit gate 需要；apply 前置）。----
    let acquire = client
        .acquire_lease(wire::AcquireLeaseRequest {
            lookup_key: Some(wire_key(5, 1)),
            platform_ownership: None,
            request_digest: digest32(1),
        })
        .await
        .expect("acquire succeeds");
    assert!(
        matches!(
            acquire.result,
            Some(wire::acquire_lease_reply::Result::Acquired(_))
        ),
        "owner lease must be acquired before apply"
    );

    // ---- 有效 secret_payload：engine 接受 apply（秘密解析成功）。----
    let valid = b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}";
    let mut slot = ClearableSecret::new(valid);
    let apply = ApplyTunnelRequest {
        lookup_key: Some(wire_key(6, 2)),
        plan: Some(wire_plan()),
        request_digest: digest32(1),
        secret_payload: vec![],
    };
    let reply = client.apply_connect(apply, &mut slot).await.expect("apply accepted");
    // R1w: ApplyTunnel is async — the engine returns the `pending` ApplyAccepted;
    // the terminal outcome flows on the independent StreamConnectStatus channel.
    assert!(
        matches!(
            reply.result,
            Some(wire::apply_tunnel_reply::Result::Pending(_))
        ),
        "engine must accept a well-formed secret payload (async pending)"
    );
    // 真实实现契约：派发后 one-shot 槽确定性零化。
    assert!(
        slot.as_bytes().iter().all(|&b| b == 0),
        "one-shot slot must be zeroized after send"
    );

    // ---- 畸形 secret_payload：engine 拒绝（证明秘密确实到达 engine 的解析器）。----
    let mut bad_slot = ClearableSecret::new(b"not a credential package");
    let bad_apply = ApplyTunnelRequest {
        lookup_key: Some(wire_key(6, 4)),
        plan: Some(wire_plan()),
        request_digest: digest32(1),
        secret_payload: vec![],
    };
    let err = client
        .apply_connect(bad_apply, &mut bad_slot)
        .await
        .expect_err("malformed payload must be rejected");
    match err {
        exv_core::grpc_control::GrpcClientError::Rpc(Code::InvalidArgument, _) => {}
        other => panic!("expected InvalidArgument, got {other:?}"),
    }
    // 失败路径同样零化槽（无明文残留）。
    assert!(
        bad_slot.as_bytes().iter().all(|&b| b == 0),
        "one-shot slot must be zeroized on the failure path too"
    );

    // 显式关闭连接 → engine serve future 结束（req_tx 随作用域 drop）。
    drop(client);
    drop(req_tx);
    serve_task.await.expect("engine serve task joins");
}

/// Bug D 回归：core 的 `establish_owner_lease`（MaintainOwnerLease 授权握手）先建立
/// engine 侧 `core.owner`，随后 `apply_connect` 才能通过 `bind_mutation` gate。
///
/// 修复前 core 的 connect 直接派发 `apply_connect` 而不建 lease → engine 返回
/// `failed_precondition("no owner lease established")`。本测试走真实 engine（in-process
/// Named Pipe）验证：`establish_owner_lease` 成功（HandshakeAccepted），随后 apply 被
/// 接受（无 FAILED_PRECONDITION）。
#[tokio::test]
async fn owner_lease_client_method_establishes_lease_before_apply() {
    let name = unique_pipe_name("lease-before-apply");
    let pid = std::process::id();
    let sid = current_user_sid().expect("current user sid");

    // engine 侧：建 pipe → accept → 验 core → serve HelperControl。
    let server = HelperControlServer::new(HelperControlService::new());
    let serve_pipe = name.clone();
    let serve_sid = sid.clone();
    let serve_pid = pid;
    let serve_task = tokio::spawn(async move {
        serve_named_pipe(&serve_pipe, &serve_sid, serve_pid, server)
            .await
            .expect("engine serve");
    });

    // host 侧：拨号 + 双向 peer 认证 + gRPC channel。
    let mut client = EngineControlGrpcClient::connect(&name, pid, &sid)
        .await
        .expect("host connect");

    // 关键修复路径：establish_owner_lease（内部 MaintainOwnerLease 握手 → core.owner）。
    client
        .establish_owner_lease()
        .await
        .expect("owner lease handshake accepted");

    // 无 lease 前置时 engine 会 failed_precondition("no owner lease established")——
    // 现在 lease 已建立，apply 必须被接受。
    let mut slot = ClearableSecret::new(b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}");
    let apply = ApplyTunnelRequest {
        lookup_key: Some(wire_key(6, 9)),
        plan: Some(wire_plan()),
        request_digest: digest32(1),
        secret_payload: vec![],
    };
    let reply = client
        .apply_connect(apply, &mut slot)
        .await
        .expect("apply accepted after owner lease established");
    // R1w: ApplyTunnel is async — the engine returns the `pending` ApplyAccepted.
    assert!(
        matches!(reply.result, Some(wire::apply_tunnel_reply::Result::Pending(_))),
        "apply must be accepted once the owner lease is established (Bug D; R1w async pending)"
    );
    // 派发后 one-shot 槽零化。
    assert!(
        slot.as_bytes().iter().all(|&b| b == 0),
        "one-shot slot must be zeroized after send"
    );

    drop(client);
    serve_task.await.expect("engine serve task joins");
}

/// Bug E 回归（engine 边界）：engine `apply_tunnel` 期待 `wire_key.method == ApplyTunnel`。
///
/// 修复前 core 把 UI Connect 意图（method=Connect）原样派发 ApplyTunnel → engine
/// `kernel_request_to_operation` 判 `method != expected_method` → `"kernel: operation:
/// out of scope"`（用户实测：`Internal("...operation binding: kernel: operation: out of
/// scope")`）。本测试锁定两个方向：
/// 1. **错法（Connect method）必须被 engine 拒绝**（`InvalidArgument` "out of scope"，
///    无副作用）——反假绿护栏；
/// 2. **对法（ApplyTunnel method，修复后 core 的转换）必须被接受**（`Applied`）。
#[tokio::test]
async fn apply_tunnel_requires_apply_tunnel_method_not_connect() {
    let name = unique_pipe_name("method-conversion");
    let pid = std::process::id();
    let sid = current_user_sid().expect("current user sid");

    let server = HelperControlServer::new(HelperControlService::new());
    let serve_pipe = name.clone();
    let serve_sid = sid.clone();
    let serve_pid = pid;
    let serve_task = tokio::spawn(async move {
        serve_named_pipe(&serve_pipe, &serve_sid, serve_pid, server)
            .await
            .expect("engine serve");
    });

    let mut client = EngineControlGrpcClient::connect(&name, pid, &sid)
        .await
        .expect("host connect");
    client
        .establish_owner_lease()
        .await
        .expect("owner lease established");

    // 反假绿：Connect method 的 apply 必须被 engine 拒绝（"out of scope"）。
    let mut wrong_slot = ClearableSecret::new(b"{}");
    let wrong_apply = ApplyTunnelRequest {
        lookup_key: Some(wire_key(wire::OperationMethod::Connect as i32, 9)),
        plan: Some(wire_plan()),
        request_digest: digest32(1),
        secret_payload: vec![],
    };
    let err = client
        .apply_connect(wrong_apply, &mut wrong_slot)
        .await
        .expect_err("Connect-method apply must be rejected by the engine");
    match err {
        exv_core::grpc_control::GrpcClientError::Rpc(Code::InvalidArgument, msg) => {
            assert!(
                msg.contains("out of scope"),
                "engine must report 'out of scope' for method mismatch, got: {msg}"
            );
        }
        other => panic!("expected InvalidArgument(out of scope), got {other:?}"),
    }

    // 对法：ApplyTunnel method 的 apply 必须被接受（修复后 core 的转换目标）。
    let mut good_slot = ClearableSecret::new(b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}");
    let good_apply = ApplyTunnelRequest {
        lookup_key: Some(wire_key(wire::OperationMethod::ApplyTunnel as i32, 9)),
        plan: Some(wire_plan()),
        request_digest: digest32(1),
        secret_payload: vec![],
    };
    let reply = client
        .apply_connect(good_apply, &mut good_slot)
        .await
        .expect("ApplyTunnel-method apply must be accepted");
    // R1w: ApplyTunnel is async — the engine returns the `pending` ApplyAccepted.
    assert!(
        matches!(reply.result, Some(wire::apply_tunnel_reply::Result::Pending(_))),
        "ApplyTunnel-method apply must be applied (Bug E; R1w async pending)"
    );

    drop(client);
    serve_task.await.expect("engine serve task joins");
}
