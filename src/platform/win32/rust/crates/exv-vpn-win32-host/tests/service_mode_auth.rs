// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! S3/D2 + D7 契约测试：service 模式 PSK-HMAC 双向认证 + owner 断线释放（真实 Named
//! Pipe，engine service accept-loop ⇄ host service-mode client）。
//!
//! 覆盖：
//! 1. **完整握手双向 fail-closed（S6 自报身份 + D2 PSK）**：匹配身份 + PSK → 双方成功；
//!    client 持错 PSK → server 拒绝（fail closed）；server 持错 PSK → client 拒绝
//!    （fail closed）——两方向都验证；自报身份（PID/SID）不符或缺失 → client 拒绝。
//! 2. **旧 core 断线 → 新 core 握手接管**（D7）：core A 连接并建立 lease → drop（流
//!    EOF）→ engine 释放 connection-bound owner + ownership_version++ → core B 连接，
//!    握手接管成功。
//! 3. **PSK 轮换（M14）**：写 key A 的服务接受 key A；重装写 key B 后，持 key A 的
//!    client 挑战失败（旧 key 断开即失效）。

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use exv_engine::grpc_server::HelperControlService;
use exv_engine::grpc_transport::{psk_challenge_server, serve_named_pipe_loop};
use exv_core::grpc_control::{
    query_service_self, EngineControlGrpcClient, KernelEngineControl,
};
use exv_core::grpc_transport::{
    dial_control_pipe_with_retry, service_peer_handshake,
};
use exv_core::service_status::{query_service_status, RealServiceStatusSource, ServiceState};
use exv_engine::service::{SERVICE_CONTROL_PIPE, SERVICE_NAME};
use exv_vpn_win32_ipc::peer_auth::{current_process_identity, current_user_sid, ProcessIdentity, SYSTEM_SID};
use exv_vpn_win32_ipc::service_key::read_service_psk;
use exv_vpn_wire::generated::helper_control_server::HelperControlServer;

fn unique_pipe_name(tag: &str) -> String {
    format!(r"\\.\pipe\exv-psk-{tag}-{}", std::process::id())
}

/// 引擎 service 侧 accept-loop + PSK 的建连任务（真实管道；`serve_named_pipe_loop`）。
fn spawn_service_loop(name: &str, sid: &str, psk: [u8; 32]) -> tokio::sync::watch::Sender<bool> {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let server = HelperControlServer::new(HelperControlService::new().in_service_mode());
    // S3/Tier 2: the accept-loop writes control-plane readiness to this shared
    // AtomicBool (query reads it); this test only exercises auth, not the report.
    let control_plane_ready = Arc::new(AtomicBool::new(false));
    let name = name.to_string();
    let sid = sid.to_string();
    tokio::spawn(async move {
        let _outcome =
            serve_named_pipe_loop(&name, &sid, psk, server, stop_rx, None, control_plane_ready)
                .await;
    });
    stop_tx
}

/// 引擎 service 侧 accept-loop + PSK + **深度自述 seam**（真实管道）：`with_service_self`
/// 注入 `psk_present`，`control_plane_ready` 与 accept-loop 共享同一 `Arc<AtomicBool>`
/// （预置 true 模拟控制面已就绪——`serve_named_pipe_loop` 的 `ready: None` 不会覆写）。
/// 返回停止发送端 + 循环任务句柄（供 stop-await 的有序停机，rotation 用例复启同名管道）。
fn spawn_service_loop_with_report(
    name: &str,
    sid: &str,
    psk: [u8; 32],
    psk_present: bool,
) -> (tokio::sync::watch::Sender<bool>, tokio::task::JoinHandle<()>) {
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let control_plane_ready = Arc::new(AtomicBool::new(true));
    let server = HelperControlServer::new(
        HelperControlService::new()
            .in_service_mode()
            .with_service_self(Arc::clone(&control_plane_ready), psk_present),
    );
    let name = name.to_string();
    let sid = sid.to_string();
    let handle = tokio::spawn(async move {
        let _outcome =
            serve_named_pipe_loop(&name, &sid, psk, server, stop_rx, None, control_plane_ready)
                .await;
    });
    (stop_tx, handle)
}

/// 1a. 匹配身份 + PSK → `psk_challenge_server`（engine）与 host 侧完整握手互认成功
/// （engine 自报身份验证通过 + 双向证明共享秘密）。
#[tokio::test]
async fn psk_challenge_mutual_accept_with_matching_key() {
    let name = unique_pipe_name("mutual");
    let sid = current_user_sid().expect("current user sid");
    let psk = [0x42; 32];
    let identity = current_process_identity().expect("current process identity");

    let server = exv_engine::grpc_transport::create_control_pipe_server(&name, &sid)
        .expect("create control pipe");
    let server_task = tokio::spawn(async move {
        let mut server = server;
        server.connect().await.expect("accept");
        psk_challenge_server(&mut server, &psk, &identity).await
    });

    let mut client = dial_control_pipe_with_retry(&name).await.expect("dial");
    let peer = service_peer_handshake(&mut client, &sid, &psk)
        .await
        .expect("client side handshake succeeds");
    assert_eq!(peer.user_sid, sid, "自报 SID 验证通过");
    assert_eq!(peer.process_id, std::process::id(), "自报 PID 交叉核验通过");

    server_task
        .await
        .expect("server task joins")
        .expect("server side handshake succeeds");
}

/// 1b. client 持错 PSK → server 挑战失败（fail closed，client 应答不匹配）。身份帧先通过
/// （server 自报真实身份），PSK 是主认证——错 key 在挑战层被拒。
#[tokio::test]
async fn psk_challenge_rejects_wrong_client_key() {
    let name = unique_pipe_name("wrong-client");
    let sid = current_user_sid().expect("current user sid");
    let identity = current_process_identity().expect("current process identity");
    let server_psk = [0x11; 32];
    let client_psk = [0x22; 32];

    let server = exv_engine::grpc_transport::create_control_pipe_server(&name, &sid)
        .expect("create control pipe");
    let server_task = tokio::spawn(async move {
        let mut server = server;
        server.connect().await.expect("accept");
        psk_challenge_server(&mut server, &server_psk, &identity).await
    });

    let mut client = dial_control_pipe_with_retry(&name).await.expect("dial");
    let client_err = service_peer_handshake(&mut client, &sid, &client_psk)
        .await
        .expect_err("client with wrong key must fail closed");
    assert!(
        matches!(client_err, exv_core::grpc_transport::GrpcPipeError::Auth(_)),
        "wrong client key → Auth error, got {client_err:?}"
    );
    // server 侧同步失败（读到错误应答 → 拒绝连接）。
    let server_err = server_task.await.expect("server task joins").expect_err(
        "server must reject wrong client response",
    );
    assert!(
        server_err.contains("psk challenge"),
        "server rejects challenge, got {server_err}"
    );
}

/// 1c. server 持错 PSK（client 持对「自己以为」的 key）→ client 验证 server 应答失败
/// （fail closed，防伪 server / 中间人）。
#[tokio::test]
async fn psk_challenge_rejects_wrong_server_key() {
    let name = unique_pipe_name("wrong-server");
    let sid = current_user_sid().expect("current user sid");
    let identity = current_process_identity().expect("current process identity");
    let server_psk = [0x33; 32];
    let client_psk = [0x44; 32];

    let server = exv_engine::grpc_transport::create_control_pipe_server(&name, &sid)
        .expect("create control pipe");
    let server_task = tokio::spawn(async move {
        let mut server = server;
        server.connect().await.expect("accept");
        psk_challenge_server(&mut server, &server_psk, &identity).await
    });

    let mut client = dial_control_pipe_with_retry(&name).await.expect("dial");
    // client 用「自己持有的 key」挑战——server 用不同 key 应答 → client 恒时比较失败。
    let client_err = service_peer_handshake(&mut client, &sid, &client_psk)
        .await
        .expect_err("client must reject wrong server reply (fail closed)");
    assert!(
        matches!(client_err, exv_core::grpc_transport::GrpcPipeError::Auth(_)),
        "wrong server key → Auth error, got {client_err:?}"
    );
    // server 侧：client 的应答（用 client_psk 计算）同样不匹配 → server 也失败。
    let server_err = server_task.await.expect("server task joins").expect_err(
        "server must reject client response (both directions fail closed)",
    );
    assert!(
        server_err.contains("psk challenge"),
        "server rejects challenge, got {server_err}"
    );
}

/// 2. 旧 core 断线 → 新 core 握手接管（D7：owner 断线释放 + ownership_version++）。
///
/// core A（service-mode client）连接 + 建立 owner lease → drop A（流 EOF）→ engine
/// 释放 connection-bound owner → core B 连接 + 握手接管成功。
#[tokio::test]
async fn service_owner_released_on_eof_and_new_core_takes_over() {
    let name = unique_pipe_name("takeover");
    let sid = current_user_sid().expect("current user sid");
    let psk = [0x51; 32];
    let _stop_tx = spawn_service_loop(&name, &sid, psk);

    // core A：service-mode client（SID-only + PSK 挑战）→ 建立 owner lease。
    let mut core_a = EngineControlGrpcClient::connect_service(&name, &sid, &psk)
        .await
        .expect("core A connects (PSK accepted)");
    core_a
        .ensure_owner_lease()
        .await
        .expect("core A establishes owner lease");
    assert_eq!(core_a.engine_peer.user_sid, sid, "service engine peer SID");

    // 优雅关闭 core A 连接：lease 流关闭 + liveness 监视中止 → 连接立即关闭 →
    // MaintainOwnerLease 流 EOF → engine 释放 connection-bound owner + accept-loop 释放
    // （生产等价于 core 进程退出关闭连接）。
    core_a.close_engine_connection();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // core B：重连 + 握手接管（引擎已释放旧 owner + 连接已关闭 → 新握手不再被拒）。
    let mut core_b = None;
    let mut last_err = String::new();
    for attempt in 0..20 {
        match EngineControlGrpcClient::connect_service(&name, &sid, &psk).await {
            Ok(mut client) => match client.ensure_owner_lease().await {
                Ok(()) => {
                    core_b = Some(client);
                    break;
                }
                Err(e) => {
                    last_err = format!("handshake: {e:?}");
                    tracing::warn!(attempt, ?e, "core B handshake not yet admitted, retrying");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            },
            Err(e) => {
                last_err = format!("connect: {e:?}");
                tracing::warn!(attempt, ?e, "core B connect retrying");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    }
    assert!(
        core_b.is_some(),
        "core B must take over the ownership after core A disconnects (D7); last: {last_err}"
    );
    drop(core_b);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let _ = _stop_tx;
}

/// 2b. 服务 engine SID 验证 fail-closed：expected SID（SYSTEM——真实 LocalSystem 服务）
/// ≠ 实际 server SID（测试进程 = 当前用户）→ 连接被拒（D2：服务 engine 必须是特权
/// 系统服务，而非用户态冒名进程）。
#[tokio::test]
async fn service_engine_sid_mismatch_fails_closed() {
    let name = unique_pipe_name("sid-mismatch");
    let sid = current_user_sid().expect("current user sid");
    let psk = [0x61; 32];
    let _stop_tx = spawn_service_loop(&name, &sid, psk);

    // 期望 SYSTEM（真实 LocalSystem 服务 engine）；测试 server 是当前用户进程 → SID 不符。
    // （EngineControlGrpcClient 无 Debug——不用 expect_err 的 Ok 分支格式化，显式 match。）
    let err = match EngineControlGrpcClient::connect_service(&name, SYSTEM_SID, &psk).await {
        Ok(_client) => panic!("service engine SID mismatch must fail closed"),
        Err(e) => e,
    };
    assert!(
        matches!(
            err,
            exv_core::grpc_control::GrpcClientError::Transport(
                exv_core::grpc_transport::GrpcPipeError::Auth(_)
            )
        ),
        "SID mismatch → Auth transport error, got {err:?}"
    );
}

/// 3. PSK 轮换（M14）：服务重装生成新 key → 持旧 key 的 client 挑战失败（fail closed）。
#[tokio::test]
async fn service_psk_rotation_invalidates_old_key() {
    let name = unique_pipe_name("rotation");
    let sid = current_user_sid().expect("current user sid");
    let identity = current_process_identity().expect("current process identity");
    let old_psk = [0x71; 32];
    let new_psk = [0x72; 32];

    // 服务用「新 key」（重装后 engine 重启读入）accept；client 仍持旧 key → 挑战失败。
    let server = exv_engine::grpc_transport::create_control_pipe_server(&name, &sid)
        .expect("create control pipe");
    let server_task = tokio::spawn(async move {
        let mut server = server;
        server.connect().await.expect("accept");
        psk_challenge_server(&mut server, &new_psk, &identity).await
    });

    let mut client = dial_control_pipe_with_retry(&name).await.expect("dial");
    let client_err = service_peer_handshake(&mut client, &sid, &old_psk)
        .await
        .expect_err("old key must fail against rotated service key (M14)");
    assert!(
        matches!(client_err, exv_core::grpc_transport::GrpcPipeError::Auth(_)),
        "old key → Auth error, got {client_err:?}"
    );
    let _ = server_task.await;
}

// ---------------------------------------------------------------------------
// S3-C（阶段 3 Tier 2 集成测试）：host 侧 `ServiceManage.query` 真管道成功路径
// + PSK 轮换报告 + env-gated 真机自述。S3-B 已覆盖失败保守 + 纯函数映射，本节补
// host 经真实 Named Pipe + 真 PSK 服务端调 `query_service_self()` 的成功路径。
// ---------------------------------------------------------------------------

/// S3-C 真管道集成（成功路径）：engine service accept-loop（`serve_named_pipe_loop`，
/// `in_service_mode` + `with_service_self(psk_present=true)`）建真管道 + 真 PSK 服务端；
/// host 端 `query_service_self()` 拨号 + PSK 握手 + `ServiceManage.query` → 报告字段与
/// engine 构造一致（覆盖 S3-B 未测的成功路径）。
#[tokio::test]
async fn query_service_self_answers_real_service_report() {
    let name = unique_pipe_name("query-self");
    let sid = current_user_sid().expect("current user sid");
    let psk = [0x5a; 32];
    let (stop_tx, loop_task) = spawn_service_loop_with_report(&name, &sid, psk, true);

    let report = query_service_self(&name, &sid, &psk, Duration::from_secs(3))
        .await
        .expect("host 经真管道 + PSK 拨号调 ServiceManage.query 必须成功（S3-B 成功路径）");
    assert_eq!(
        report.connection_mode, "service",
        "in_service_mode → 报告 connection_mode=service"
    );
    assert!(
        report.control_plane_ready,
        "control_plane_ready 与 engine 共享 AtomicBool 构造一致"
    );
    assert!(
        report.psk_present,
        "psk_present 与 with_service_self(true) 构造一致"
    );
    assert_eq!(report.runtime_epoch.len(), 16, "runtime_epoch 为 16 字节");
    assert!(report.authority_fence.is_some(), "authority_fence 在场");

    stop_tx.send(true).expect("stop service loop");
    let _ = tokio::time::timeout(Duration::from_secs(2), loop_task).await;
}

/// S3-C + M14：PSK 轮换（真管道）——重装后 engine 读入新 key（新引擎以新 key accept）；
/// 旧 key 挑战失败（fail closed，旧 key 断开即失效）；host 用新 key query，报告反映轮换后
/// 的 key 状态（`psk_present=true`、mode=service、控制面就绪）。
#[tokio::test]
async fn service_psk_rotation_report_reflects_rotated_key_state() {
    let name = unique_pipe_name("rotation-report");
    let sid = current_user_sid().expect("current user sid");
    let old_psk = [0x91; 32];
    let new_psk = [0x92; 32];

    // 轮换前：engine 持旧 key（启动读入 → psk_present=true）。旧 key query 成功。
    let (stop_tx, loop_task) = spawn_service_loop_with_report(&name, &sid, old_psk, true);
    let before = query_service_self(&name, &sid, &old_psk, Duration::from_secs(3))
        .await
        .expect("轮换前旧 key 拨号必须成功");
    assert_eq!(before.connection_mode, "service");
    assert!(before.psk_present, "轮换前 report 反映启动读入的旧 key");

    // 轮换 = 重装：停旧服务（有序停机 → 释放管道名）→ 新引擎读入新 key 再 accept。
    stop_tx.send(true).expect("stop old service");
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task)
        .await
        .expect("old service loop stops")
        .expect("task ok");
    tokio::time::sleep(Duration::from_millis(200)).await; // 释放管道名（SCM 停机语义）
    let (stop_tx, loop_task) = spawn_service_loop_with_report(&name, &sid, new_psk, true);

    // 旧 key 在新服务上挑战失败（M14：旧 key 断开即失效）。
    let stale = query_service_self(&name, &sid, &old_psk, Duration::from_secs(2)).await;
    assert!(stale.is_none(), "轮换后旧 key 必须无法拨号（M14 fail-closed）");

    // 新 key query → 报告反映轮换后的 key 状态。
    let after = query_service_self(&name, &sid, &new_psk, Duration::from_secs(3))
        .await
        .expect("轮换后新 key 拨号必须成功");
    assert_eq!(after.connection_mode, "service");
    assert!(after.psk_present, "轮换后 report 反映新 key（psk_present=true）");
    assert!(after.control_plane_ready, "轮换后控制面就绪");

    stop_tx.send(true).expect("stop rotated service");
    let _ = tokio::time::timeout(Duration::from_secs(2), loop_task).await;
}

/// 测试进程是否 elevated（OpenProcessToken + TokenElevation；fail closed）。供 env-gated
/// 真机自述测试的提权门控（镜像 engine `tests/service_lifecycle.rs` 的 `is_elevated`）。
fn is_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let process = unsafe { GetCurrentProcess() };
    let mut token = windows::Win32::Foundation::HANDLE::default();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        return false;
    }
    let mut elevated = false;
    let mut size = 0u32;
    unsafe {
        let _ = GetTokenInformation(token, TokenElevation, None, 0, &raw mut size);
    }
    if size != 0 {
        let mut buffer = vec![0u8; size as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some(buffer.as_mut_ptr().cast()),
                size,
                &raw mut size,
            )
        };
        if ok.is_ok() && buffer.len() >= 4 {
            elevated = u32::from_ne_bytes(buffer[0..4].try_into().unwrap_or([0u8; 4])) != 0;
        }
    }
    unsafe {
        let _ = CloseHandle(token);
    }
    elevated
}

/// S3-C env-gated 真机（scope §5.3，S5 业务验收 opt-in）：`#[ignore]` +
/// `EXV_SCM_INTEGRATION=1` + 提权。对**已安装并运行**的 engine 服务，经
/// `SERVICE_CONTROL_PIPE` + 真实 PSK 拨号调 `ServiceManage.query` →
/// `control_plane_ready=true`、`psk_present=true`、`connection_mode="service"`。
///
/// 注：本测试**不自装**服务——`install_service` 用 `current_exe` 注册可执行（测试进程
/// 是测试二进制，不是 engine），自装无法得到能应答 RPC 的真 engine 服务。真机前置由打包
/// 完成（S5 部署环境）；SCM 非 Running 时打印原因并跳过。
#[tokio::test]
#[ignore = "SCM 真机：需已安装并运行的 engine 服务 + admin；S5 业务验收 opt-in"]
async fn real_service_mode_self_report_over_service_control_pipe() {
    if std::env::var("EXV_SCM_INTEGRATION").as_deref() != Ok("1") {
        eprintln!("S3 env-gated: EXV_SCM_INTEGRATION=1 未置位，跳过");
        return;
    }
    if !is_elevated() {
        eprintln!("S3 env-gated: 测试进程非提权，跳过（需 admin）");
        return;
    }
    let snap = query_service_status(&RealServiceStatusSource, SERVICE_NAME)
        .expect("SCM 服务状态查询（非提权）");
    if snap.state != ServiceState::Running {
        eprintln!(
            "S3 env-gated: engine 服务未 Running（{:?}），跳过——需打包先安装并启动（测试进程 current_exe 是测试二进制，不能自装 engine 服务）",
            snap.state
        );
        return;
    }
    let psk = read_service_psk().expect("engine 服务 PSK 必须可读（已安装）");
    // 有界轮询：SCM Running 与 accept-loop bind 之间仍有竞窗（`query_service_self` 的
    // 拨号重试 30×100ms 之外再加外层轮询覆盖真实服务启动）。
    let mut report = None;
    for attempt in 0..20 {
        let r = query_service_self(SERVICE_CONTROL_PIPE, SYSTEM_SID, &psk, Duration::from_secs(2))
            .await;
        if r.is_some() {
            report = r;
            break;
        }
        eprintln!("S3 env-gated: ServiceManage.query 未就绪（attempt {attempt}），重试");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let report = report.expect("ServiceManage.query 必须能对运行中的 engine 服务应答");
    assert_eq!(
        report.connection_mode, "service",
        "真机 service 模式自述 connection_mode=service"
    );
    assert!(report.control_plane_ready, "真机服务控制面必须 ready");
    assert!(report.psk_present, "真机服务 PSK 必须 present");
}

/// 4a. engine 自报 PID 与管道对端真实进程（`GetNamedPipeServerProcessId`）不符 → client
/// 拒绝（fail closed）——防伪装进程谎报身份。
#[tokio::test]
async fn service_engine_pid_self_report_mismatch_fails_closed() {
    let name = unique_pipe_name("pid-mismatch");
    let sid = current_user_sid().expect("current user sid");
    let psk = [0x81; 32];
    // 自报一个与管道对端真实 PID 不符的假 PID（模拟伪装进程谎报）。
    let bogus_identity = ProcessIdentity {
        process_id: 0xDEAD_BEEF,
        user_sid: sid.clone(),
    };

    let server = exv_engine::grpc_transport::create_control_pipe_server(&name, &sid)
        .expect("create control pipe");
    let server_task = tokio::spawn(async move {
        let mut server = server;
        server.connect().await.expect("accept");
        psk_challenge_server(&mut server, &psk, &bogus_identity).await
    });

    let mut client = dial_control_pipe_with_retry(&name).await.expect("dial");
    let err = service_peer_handshake(&mut client, &sid, &psk)
        .await
        .expect_err("自报 PID 与管道对端不符必须 fail closed");
    assert!(
        matches!(err, exv_core::grpc_transport::GrpcPipeError::Auth(_)),
        "PID mismatch → Auth error, got {err:?}"
    );
    // client 在身份层拒绝（未发 PSK 应答）——须先关闭 client 句柄，server 侧阻塞的
    // read_exact 才会读到 EOF 并结束（避免任务悬挂）。
    drop(client);
    let _ = server_task.await;
}

/// 4b. engine 自报 SID 与期望不符（伪装 SYSTEM 但管道对端是用户进程）→ client 拒绝
/// （fail closed）。
#[tokio::test]
async fn service_engine_sid_self_report_mismatch_fails_closed() {
    let name = unique_pipe_name("self-sid-mismatch");
    let sid = current_user_sid().expect("current user sid");
    let psk = [0x82; 32];
    // 自报 SYSTEM SID（伪装）——PID 用真实值（交叉核验可通过），SID 比对必须拒绝。
    let bogus_identity = ProcessIdentity {
        process_id: std::process::id(),
        user_sid: SYSTEM_SID.to_string(),
    };

    let server = exv_engine::grpc_transport::create_control_pipe_server(&name, &sid)
        .expect("create control pipe");
    let server_task = tokio::spawn(async move {
        let mut server = server;
        server.connect().await.expect("accept");
        psk_challenge_server(&mut server, &psk, &bogus_identity).await
    });

    let mut client = dial_control_pipe_with_retry(&name).await.expect("dial");
    // client 期望「当前用户 SID」，server 自报 SYSTEM → 拒绝。
    let err = service_peer_handshake(&mut client, &sid, &psk)
        .await
        .expect_err("自报 SID 与期望不符必须 fail closed");
    assert!(
        matches!(err, exv_core::grpc_transport::GrpcPipeError::Auth(_)),
        "SID mismatch → Auth error, got {err:?}"
    );
    // client 在身份层拒绝（未发 PSK 应答）——先关闭 client 句柄避免 server 侧任务悬挂。
    drop(client);
    let _ = server_task.await;
}

/// 4c. server 接受连接后不发送身份帧直接关闭 → client 读身份帧失败（fail closed）。
#[tokio::test]
async fn service_engine_missing_identity_frame_fails_closed() {
    let name = unique_pipe_name("no-identity");
    let sid = current_user_sid().expect("current user sid");
    let psk = [0x83; 32];

    let server = exv_engine::grpc_transport::create_control_pipe_server(&name, &sid)
        .expect("create control pipe");
    let server_task = tokio::spawn(async move {
        server.connect().await.expect("accept");
        // server 不发送身份帧，直接结束任务（连接关闭）。
    });

    let mut client = dial_control_pipe_with_retry(&name).await.expect("dial");
    let err = service_peer_handshake(&mut client, &sid, &psk)
        .await
        .expect_err("缺失身份帧必须 fail closed");
    assert!(
        matches!(err, exv_core::grpc_transport::GrpcPipeError::Auth(_)),
        "missing identity frame → Auth error, got {err:?}"
    );
    let _ = server_task.await;
}

/// 4d. **标准用户场景模拟（S6 核心验收）**：server 自报 SYSTEM SID（真实 LocalSystem
/// 服务自报形态）+ 真实管道对端 PID，client 期望 `SYSTEM_SID` → 验证通过。全程仅依赖
/// 自报身份 + `GetNamedPipeServerProcessId` 交叉核验，**不调用 `OpenProcess` 读 SYSTEM
/// 进程**——S5 真机实测该 OpenProcess 路径在标准用户下必失败（err=5），此测试证明自报
/// 替代成立。
#[tokio::test]
async fn service_engine_self_reports_system_sid_accepted() {
    let name = unique_pipe_name("self-system");
    let sid = current_user_sid().expect("current user sid");
    let psk = [0x84; 32];
    let system_identity = ProcessIdentity {
        process_id: std::process::id(),
        user_sid: SYSTEM_SID.to_string(),
    };

    let server = exv_engine::grpc_transport::create_control_pipe_server(&name, &sid)
        .expect("create control pipe");
    let server_task = tokio::spawn(async move {
        let mut server = server;
        server.connect().await.expect("accept");
        psk_challenge_server(&mut server, &psk, &system_identity).await
    });

    let mut client = dial_control_pipe_with_retry(&name).await.expect("dial");
    let peer = service_peer_handshake(&mut client, SYSTEM_SID, &psk)
        .await
        .expect("SYSTEM 自报身份验证通过（免 OpenProcess）");
    assert_eq!(peer.user_sid, SYSTEM_SID, "自报 SYSTEM SID 被采纳为已验证身份");
    assert_eq!(peer.process_id, std::process::id(), "PID 交叉核验通过");

    server_task
        .await
        .expect("server task joins")
        .expect("server side handshake succeeds");
}

/// 4. oneshot path+SID 不回归：`connect`（oneshot，无 PSK）仍以 pid+SID 认证建立 ——
/// 复用既有 `grpc_interop` 的核心断言（拨号 + 双向认证 + gRPC 往返）。
#[tokio::test]
async fn oneshot_connect_without_psk_still_works() {
    let name = unique_pipe_name("oneshot");
    let pid = std::process::id();
    let sid = current_user_sid().expect("current user sid");

    let server = HelperControlServer::new(HelperControlService::new());
    let serve_name = name.clone();
    let serve_sid = sid.clone();
    let serve_task = tokio::spawn(async move {
        exv_engine::grpc_transport::serve_named_pipe(&serve_name, &serve_sid, pid, server)
            .await
            .expect("oneshot engine serve");
    });

    // oneshot client：pid+SID 认证（无 PSK）。
    let mut client = EngineControlGrpcClient::connect(&name, pid, &sid)
        .await
        .expect("oneshot core connect (path+SID, no PSK)");
    client.ping().await.expect("gRPC round-trip ping");
    drop(client);
    serve_task.await.expect("oneshot serve task joins");
}
