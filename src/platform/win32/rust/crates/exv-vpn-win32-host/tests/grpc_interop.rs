// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! P1 互操作冒烟测试：core 的 tonic gRPC 客户端 ⇄ engine 的 HelperControl gRPC 服务，
//! 均承载于同一双向认证 Tokio Windows Named Pipe（spec §9.4）。
//!
//! 本测试把 engine 侧服务（`exv-engine` 的 `HelperControlService`，P1-b）与
//! core 侧客户端（`exv-core` 的 `EngineControlGrpcClient`，P1-c）在**同一进程**
//! 内经真实 local Named Pipe 连通，验证产品 wire 端到端可用：
//!
//! 1. 拨号 + 双向 peer 认证（server 侧验 core pid+SID；client 侧验 engine pid+SID）都通过；
//! 2. gRPC 往返（`ping`）成功；
//! 3. server-streaming（`stream_logs`）可建立（P2 填充真实推送）。
//!
//! 同进程互操作意味着 server pid == client 进程 pid、SID == 当前用户 SID，二者期望
//! 值相同——与 legacy `control_client` 的单测同一手法。

use exv_core::grpc_control::EngineControlGrpcClient;
use exv_vpn_win32_ipc::peer_auth::current_user_sid;
use exv_engine::grpc_server::HelperControlService;
use exv_engine::grpc_transport::serve_named_pipe;
use exv_vpn_wire::generated::helper_control_server::HelperControlServer;

fn unique_pipe_name(tag: &str) -> String {
    format!(r"\\.\pipe\exv-grpc-interop-{tag}-{}", std::process::id())
}

/// core⇄engine gRPC 互操作：拨号 + 双向 peer 认证 + 往返 + server-streaming 建立。
#[tokio::test]
async fn core_engine_grpc_interop_over_named_pipe() {
    let name = unique_pipe_name("smoke");
    let pid = std::process::id();
    let sid = current_user_sid().expect("current user sid");

    // engine 侧：建 pipe（DACL + first-instance + reject-remote）→ accept → 验 core →
    // serve HelperControl。单连接；client drop 后连接关闭，serve future 结束。
    let server = HelperControlServer::new(HelperControlService::new());
    let serve_pipe = name.clone();
    let serve_sid = sid.clone();
    let serve_pid = pid;
    let serve_task = tokio::spawn(async move {
        serve_named_pipe(&serve_pipe, &serve_sid, serve_pid, server)
            .await
            .expect("engine serve");
    });

    // core 侧：拨号（有界重试）→ 验 engine pid+SID → 构建 gRPC channel。
    let mut client = EngineControlGrpcClient::connect(&name, pid, &sid).await.expect("core connect");

    // client 侧记录到的 engine peer 必须是本进程 pid + 当前用户 SID。
    assert_eq!(client.engine_peer.process_id, pid, "engine peer pid");
    assert_eq!(client.engine_peer.user_sid, sid, "engine peer SID");

    // gRPC 往返：engine 侧 transport gate 已放行（连接已验），往返成功或返回业务
    // 状态都证明连接可用；`ping` 只把 transport 类失败视为掉线。
    client.ping().await.expect("gRPC round-trip ping");

    // server-streaming 可建立（P2 填充真实日志推送）。
    let _stream = client.stream_logs(0).await.expect("stream_logs channel opens");

    // P5-a/P5-b：`StreamStats` 统计推送可订阅——engine 默认间隔 1000 ms，等首个样本
    // （累计字节 authority + 阶段）；验证 host client 对真实 HelperControlService 的
    // 统计通道端到端可用。
    use tokio_stream::StreamExt;
    let mut stats = client
        .stream_stats(0)
        .await
        .expect("stream_stats channel opens");
    let sample = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stats.next(),
    )
    .await
    .expect("first stats sample within timeout")
    .expect("stats stream alive")
    .expect("stats event ok");
    assert!(sample.sequence >= 1, "engine sample sequence monotonic");
    assert_eq!(
        sample.phase,
        exv_vpn_wire::generated::StatsPhase::Idle as i32,
        "engine 初始阶段 Idle（无隧道）"
    );
    assert_eq!(sample.rx_bytes, 0, "无隧道累计字节 0");
    // 首个样本速率 = 0（engine 尚无前一样本）。
    assert_eq!(sample.rx_rate, 0);

    // 显式关闭连接 → engine serve future 结束。
    drop(client);
    serve_task.await.expect("engine serve task joins");
}

// 注：engine 掉线的集成级测试需要强制关闭 engine 侧连接（tonic `serve_with_incoming`
// 会把连接处理 detach，abort serve future 不关闭 pipe）；该 close 钩子属 P1-b 领地。
// 掉线映射由单元测试 `grpc_control::map_status_classifies_codes`（Unavailable→
// ConnectionLost）覆盖；liveness 监视器设计见 `grpc_control.rs`。
