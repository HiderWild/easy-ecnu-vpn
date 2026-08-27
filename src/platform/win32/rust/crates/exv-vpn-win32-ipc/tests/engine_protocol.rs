// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! 阶段 3a 控制面协议集成测试：帧 I/O 与双向 peer 认证在真实 local Named Pipe 上往返。
//!
//! 覆盖 core↔engine 控制面管道的 wire 契约：u32 BE 长度前缀 + JSON 帧（`write_json_frame`/
//! `read_json_frame`），以及 client 侧验 engine（`verify_engine_server`，反 fake-engine）。

use exv_vpn_win32_ipc::engine_protocol::{
    read_json_frame, verify_engine_server, write_json_frame, ConnectRequest, CoreToEngine,
    Credentials, EngineHelloReply, EngineHelloReq, EngineState, EngineToCore, ServerVerifyError,
};
use exv_vpn_win32_ipc::named_pipe_io::NamedPipeByteStream;
use exv_vpn_win32_ipc::peer_auth::current_user_sid;

fn unique_pipe_name(tag: &str) -> String {
    format!(r"\\.\pipe\exv-engine-protocol-it-{tag}-{}", std::process::id())
}

fn sample_connect_request() -> ConnectRequest {
    ConnectRequest {
        server: "vpn-cn.ecnu.edu.cn".to_string(),
        real_ip: "10.88.88.1".to_string(),
        prefix: 24,
        credentials: Credentials::new("student", "s3cret"),
        user_agent: "AnyConnect Win_x86_64 4.10.05095".to_string(),
        mtu: 1420,
        dns: vec!["10.88.88.53".to_string()],
        routes: vec!["10.99.99.0/24".to_string()],
        campus_routes: Vec::new(),
    }
}

/// 握手 + 命令 + 事件在真实 pipe 上双向帧往返（engine 侧写入，core 侧读取）。
#[test]
fn handshake_and_commands_round_trip_over_real_pipe() {
    let name = unique_pipe_name("handshake");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server");
    let client = NamedPipeByteStream::connect_client(&name).expect("connect");
    server.connect().expect("server accept");
    let mut server = server;
    let mut client = client;

    // core → engine：HelloReq；engine → core：HelloReply。
    write_json_frame(&mut client, &EngineHelloReq { host_pid: 4242 }).expect("write hello");
    let hello_req: EngineHelloReq = read_json_frame(&mut server).expect("read hello");
    assert_eq!(hello_req.host_pid, 4242);

    write_json_frame(&mut server, &EngineHelloReply {
        ok: true,
        error: None,
        engine_pid: std::process::id(),
        engine_sid: current_user_sid().expect("sid"),
        engine_account: "local".to_string(),
        engine_elevated: false,
    })
    .expect("write hello reply");
    let back: EngineHelloReply = read_json_frame(&mut client).expect("read hello reply");
    assert!(back.ok);
    assert_eq!(back.engine_pid, std::process::id());

    // core → engine：Connect；engine → core：StatusChanged + RouteApplied 批。
    write_json_frame(&mut client, &CoreToEngine::Connect(sample_connect_request())).expect("write connect");
    let cmd: CoreToEngine = read_json_frame(&mut server).expect("read connect");
    match cmd {
        CoreToEngine::Connect(req) => {
            assert_eq!(req.real_ip, "10.88.88.1");
            assert_eq!(req.credentials.username(), "student");
            assert_eq!(req.credentials.password(), "s3cret");
        }
        other => panic!("expected Connect, got {other:?}"),
    }
    write_json_frame(&mut server, &EngineToCore::StatusChanged {
        state: EngineState::Connected,
        reason: None,
    })
    .expect("write status");
    write_json_frame(
        &mut server,
        &EngineToCore::RouteApplied {
            ok: true,
            conflict: false,
        },
    )
    .expect("write route");
    let first: EngineToCore = read_json_frame(&mut client).expect("read status");
    let second: EngineToCore = read_json_frame(&mut client).expect("read route");
    assert_eq!(first, EngineToCore::StatusChanged { state: EngineState::Connected, reason: None });
    assert_eq!(second, EngineToCore::RouteApplied { ok: true, conflict: false });
}

/// client 侧验 engine：同进程本地 server 通过；错误 PID/SID fail closed（反 fake-engine）。
#[test]
fn verify_engine_server_accepts_local_and_rejects_impostor() {
    let name = unique_pipe_name("server-verify");
    let server = NamedPipeByteStream::create_server(&name, 1).expect("create server");
    let client = NamedPipeByteStream::connect_client(&name).expect("connect");
    server.connect().expect("server accept");

    let sid = current_user_sid().expect("current user sid");
    let peer = verify_engine_server(&client, std::process::id(), &sid)
        .expect("a same-process local server must verify");
    assert_eq!(peer.process_id, std::process::id());
    assert_eq!(peer.user_sid, sid);

    assert_eq!(
        verify_engine_server(&client, std::process::id() + 1, &sid),
        Err(ServerVerifyError::NotAuthorized),
        "wrong engine PID must fail closed"
    );
    assert_eq!(
        verify_engine_server(&client, std::process::id(), "S-1-0-0"),
        Err(ServerVerifyError::NotAuthorized),
        "wrong engine SID must fail closed"
    );
}
