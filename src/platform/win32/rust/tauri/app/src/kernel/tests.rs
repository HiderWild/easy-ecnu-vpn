//! P4-b 集成测试：CoreClient 真实 tonic 调用 ↔ 进程内 mock `KernelControl` server。
//!
//! 用 localhost TCP 的 tonic server（mock 实现 `kernel_control_server::KernelControl`
//! trait，复用 Root workspace 的生成类型）验证 CoreClient 的 unary + streaming
//! 端到端：请求组装 → 发送 → 响应 wire→UI 映射。named-pipe transport 的真实拨号
//! 由 [`super::core_transport`] 的单测覆盖（同进程 local pipe）；core 二进制缺失
//! （P5 落 host main）使进程级 smoke 受环境阻塞——本文件提供语义层的最强可行验证。

#![cfg(test)]

use std::pin::Pin;
use std::sync::Arc;

use exv_vpn_wire::generated::kernel_control_server::{KernelControl, KernelControlServer};
use exv_vpn_wire::generated::{self as wire};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::{Channel, Endpoint, Server};
use tonic::{Request, Response, Status};

use super::client::{ConnectIntent, CoreClient, CoreHandle, CoreState};
use super::core_transport::CorePeer;
use super::state::{OperationResult, RuntimeState};

/// mock `KernelControl` server：观测请求并回确定性响应（watch_events 用 mpsc 流）。
#[derive(Clone)]
struct MockKernel {
    /// watch_events 的待发事件流（测试注入 `mpsc::Receiver`；None = 立即 EOF）。
    watch_rx: Arc<tokio::sync::Mutex<Option<mpsc::Receiver<wire::RuntimeEvent>>>>,
    /// 收到的 connect 请求（断言用）。
    connects: Arc<tokio::sync::Mutex<Vec<wire::ConnectRequest>>>,
    /// 收到的 stop 请求。
    stops: Arc<tokio::sync::Mutex<Vec<wire::StopRequest>>>,
    /// 收到的 interaction 应答。
    interactions: Arc<tokio::sync::Mutex<Vec<wire::InteractionResponse>>>,
    /// `get_snapshot` 的注入回复（`None` = 默认 Idle 快照；stats-wire 方案 A 测试
    /// 注入带统计的快照）。
    snapshot_reply: Arc<tokio::sync::Mutex<Option<wire::RuntimeSnapshot>>>,
}

impl MockKernel {
    fn new() -> Self {
        Self {
            watch_rx: Arc::new(tokio::sync::Mutex::new(None)),
            connects: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            stops: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            interactions: Arc::new(tokio::sync::Mutex::new(Vec::new())),
            snapshot_reply: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
}

type WatchStream = Pin<Box<dyn Stream<Item = Result<wire::RuntimeEvent, Status>> + Send>>;

#[tonic::async_trait]
impl KernelControl for MockKernel {
    type WatchEventsStream = WatchStream;

    async fn connect(
        &self,
        request: Request<wire::ConnectRequest>,
    ) -> Result<Response<wire::OperationReply>, Status> {
        let req = request.into_inner();
        self.connects.lock().await.push(req);
        Ok(Response::new(succeeded_reply()))
    }

    async fn logs_list(
        &self,
        _r: Request<wire::LogsListRequest>,
    ) -> Result<Response<wire::LogsListReply>, Status> {
        Ok(Response::new(wire::LogsListReply {
            entries: Vec::new(),
            next_seq: 0,
        }))
    }

    async fn logs_clear(
        &self,
        _r: Request<wire::LogsClearRequest>,
    ) -> Result<Response<wire::LogsClearReply>, Status> {
        Ok(Response::new(wire::LogsClearReply {
            cleared: true,
            removed_entries: 0,
        }))
    }

    async fn config_get(
        &self,
        _r: Request<wire::ConfigGetRequest>,
    ) -> Result<Response<wire::ConfigPayload>, Status> {
        Ok(Response::new(wire::ConfigPayload { items: Vec::new() }))
    }

    async fn config_set(
        &self,
        _r: Request<wire::ConfigSetRequest>,
    ) -> Result<Response<wire::ConfigReply>, Status> {
        Ok(Response::new(wire::ConfigReply { ok: true }))
    }

    async fn respond_interaction(
        &self,
        request: Request<wire::InteractionResponse>,
    ) -> Result<Response<wire::OperationReply>, Status> {
        self.interactions.lock().await.push(request.into_inner());
        Ok(Response::new(succeeded_reply()))
    }

    async fn stop(
        &self,
        request: Request<wire::StopRequest>,
    ) -> Result<Response<wire::OperationReply>, Status> {
        self.stops.lock().await.push(request.into_inner());
        Ok(Response::new(succeeded_reply()))
    }

    async fn reconcile(
        &self,
        _request: Request<wire::ReconcileRequest>,
    ) -> Result<Response<wire::OperationReply>, Status> {
        Ok(Response::new(succeeded_reply()))
    }

    async fn get_operation(
        &self,
        _request: Request<wire::GetKernelOperationRequest>,
    ) -> Result<Response<wire::KernelOperationReply>, Status> {
        Ok(Response::new(wire::KernelOperationReply { state: None }))
    }

    async fn get_snapshot(
        &self,
        _request: Request<wire::SnapshotRequest>,
    ) -> Result<Response<wire::RuntimeSnapshot>, Status> {
        let injected = self.snapshot_reply.lock().await.clone();
        Ok(Response::new(injected.unwrap_or(wire::RuntimeSnapshot {
            state: Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
                last_cleanup: None,
            })),
            stats: None,
            proxy_tun: None,
            system_proxy: None,
            reconnect: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
        })))
    }

    async fn watch_events(
        &self,
        _request: Request<wire::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        let rx = self.watch_rx.lock().await.take();
        match rx {
            // `ReceiverStream` 产出 `RuntimeEvent`；服务契约要求 `Result<_, Status>`——
            // map 到 Ok 满足 tonic server-streaming 签名。
            Some(rx) => Ok(Response::new(Box::pin(ReceiverStream::new(rx).map(Ok)))),
            None => {
                // 无事件源 → 立即 EOF（空流；测试可自行塞源）。
                Ok(Response::new(Box::pin(tokio_stream::iter(Vec::<
                    Result<wire::RuntimeEvent, Status>,
                >::new(
                )))))
            }
        }
    }

    async fn service_control(
        &self,
        _request: Request<wire::ServiceControlRequest>,
    ) -> Result<Response<wire::ServiceControlReply>, Status> {
        Ok(Response::new(wire::ServiceControlReply {
            service_status: None,
            ok: true,
            message: "mock service_control".to_string(),
        }))
    }
}

/// 确定性 succeeded `OperationReply`（receipt 带 effect_id + ownership_version）。
fn succeeded_reply() -> wire::OperationReply {
    wire::OperationReply {
        terminal: Some(wire::OperationTerminal {
            result: Some(wire::operation_terminal::Result::Succeeded(
                wire::MutationReceipt {
                    effect_id: vec![0x11; 16],
                    ownership_version: 5,
                    ..Default::default()
                },
            )),
        }),
    }
}

/// 起一个进程内 mock server，返回 (mock 句柄, channel)。
async fn serve_mock(mock: MockKernel) -> (MockKernel, Channel, tokio::task::JoinHandle<()>) {
    let addr = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("local addr")
    };
    let server = Server::builder().add_service(KernelControlServer::new(mock.clone()));
    let handle = tokio::spawn(async move {
        let _ = server.serve(addr).await;
    });
    // `Endpoint::from_static` 需 `'static` 字面量；动态地址用 `Endpoint::new(Uri)`
    // （tonic 0.14 `new` 返回 `Result<Endpoint, _>`，unwrap 后再 connect）。
    let uri = format!("http://{addr}")
        .parse::<http::Uri>()
        .expect("valid uri");
    let channel = Endpoint::new(uri)
        .expect("endpoint")
        .connect()
        .await
        .expect("connect to mock server");
    (mock, channel, handle)
}

/// 构造一个已拨号（Dialed）的 CoreState（测试注入 fake peer）。
fn dialed_state(channel: Channel) -> CoreState {
    CoreState {
        handle: std::sync::RwLock::new(CoreHandle::Dialed {
            channel,
            core_peer: CorePeer {
                process_id: 4242,
                user_sid: "S-1-5-21-0000000000-0000000000-0000000000-1001".to_string(),
            },
        }),
        last_snapshot: Default::default(),
        last_stats: Default::default(),
    }
}

/// Core 的控制通道不是启动期一次性常量：确认旧 core 已退出并重拉后，UI 必须能切换到
/// 新的已验证通道；常规刷新则只读取该状态，不扫描进程表。
#[tokio::test]
async fn core_state_replaces_dialed_handle_after_confirmed_recovery() {
    let (_mock, channel, server_task) = serve_mock(MockKernel::new()).await;
    let state = CoreState::default();

    assert!(state.channel().is_none(), "初始 core 状态应为已停止");
    state.replace_handle(CoreHandle::Dialed {
        channel,
        core_peer: CorePeer {
            process_id: 4343,
            user_sid: "S-1-5-21-0000000000-0000000000-0000000000-1001".to_string(),
        },
    });

    assert!(state.channel().is_some(), "恢复成功后应使用新的控制管道");
    state.mark_stopped();
    assert!(state.channel().is_none(), "管道断开后 UI 状态应为已停止");

    server_task.abort();
}

/// connect：真实 tonic 往返 → wire→UI 映射（succeeded + effect_id/epoch）。
#[tokio::test]
async fn core_client_connect_roundtrips_to_mock_server() {
    let (mock, channel, server_task) = serve_mock(MockKernel::new()).await;
    let state = dialed_state(channel);
    let client = CoreClient;

    let reply = client
        .connect(
            &state,
            ConnectIntent {
                profile_ref: "ecnu".to_string(),
                secret_payload: Some("ui-secret".to_string()),
            },
        )
        .await
        .expect("connect succeeds");

    let OperationResult::Succeeded {
        effect_id,
        authority_epoch,
    } = reply.result
    else {
        panic!("expected succeeded");
    };
    assert_eq!(effect_id, Some("11".repeat(16)));
    assert_eq!(authority_epoch, Some(5));

    // mock 观测到请求：well-formed intent（method=CONNECT、digest 32 字节、secret 透传）。
    let req = mock.connects.lock().await.pop().expect("connect observed");
    let intent = req.intent.expect("intent");
    let key = intent.lookup_key.as_ref().expect("key");
    assert_eq!(key.method, wire::OperationMethod::Connect as i32);
    assert_eq!(intent.request_digest.len(), 32);
    assert_eq!(req.secret_payload, b"ui-secret");

    // R4 事件关联：connect 命令必须回传 operation_id（hex16 = 32 字符），且与发给
    // host 的 wire 意图 lookup_key.operation_id 一致——前端据此只让「当前用户操作」
    // 的事件驱动 UI。
    let op_id = reply
        .operation_id
        .expect("connect reply carries operation_id");
    assert_eq!(op_id.len(), 32, "operation_id 是 16 字节 UUID 的 hex 编码");
    assert!(
        op_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "operation_id 必须是小写 hex：{op_id}"
    );
    assert_eq!(
        key.operation_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        op_id,
        "wire 意图的 operation_id 与回传前端的一致"
    );

    server_task.abort();
}

/// stop：真实 tonic 往返（method=STOP）。
#[tokio::test]
async fn core_client_stop_roundtrips_to_mock_server() {
    let (mock, channel, server_task) = serve_mock(MockKernel::new()).await;
    let state = dialed_state(channel);

    let reply = CoreClient.stop(&state).await.expect("stop succeeds");
    assert!(matches!(reply.result, OperationResult::Succeeded { .. }));

    let req = mock.stops.lock().await.pop().expect("stop observed");
    let intent = req.intent.expect("intent");
    assert_eq!(
        intent.lookup_key.as_ref().expect("key").method,
        wire::OperationMethod::Stop as i32
    );
    assert_eq!(intent.request_digest.len(), 32);

    server_task.abort();
}

/// snapshot：真实 tonic 往返 → wire Idle → UI Idle，并更新缓存。
#[tokio::test]
async fn core_client_snapshot_roundtrips_and_caches() {
    let (_mock, channel, server_task) = serve_mock(MockKernel::new()).await;
    let state = dialed_state(channel);

    let snap = CoreClient
        .snapshot(&state)
        .await
        .expect("snapshot succeeds");
    assert!(matches!(snap.runtime, RuntimeState::Idle { .. }));
    // 缓存已更新。
    assert!(state.cached_snapshot().is_some());

    server_task.abort();
}

/// stats-wire 方案 A：GetSnapshot 携带统计 → snapshot 命令映射 `stats` 并更新缓存；
/// `stats` 命令从缓存读取（unary 拉取路径）。
#[tokio::test]
async fn core_client_snapshot_carries_stats_and_stats_command_reads_cache() {
    let (mock, channel, server_task) = serve_mock(MockKernel::new()).await;
    // 注入带统计的 Idle 快照（host `GetSnapshot` 从 EventBus 统计 lane 附加）。
    *mock.snapshot_reply.lock().await = Some(wire::RuntimeSnapshot {
        state: Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
            last_cleanup: None,
        })),
        stats: Some(wire::RuntimeStats {
            rx_bytes: 1000,
            tx_bytes: 500,
            rx_rate_bps: 200,
            tx_rate_bps: 100,
            latency_ms: 7,
            phase: wire::StatsPhase::Connected as i32,
            engine_sequence: 3,
            sample_tick: 9,
        }),
        proxy_tun: None,
            system_proxy: None,
            reconnect: None,
        operation_id: vec![],

        service_status: None,
        mode: String::new(),
    });
    let state = dialed_state(channel);

    // snapshot 命令：wire stats → UI stats 镜像（字段映射 + phase 判别）。
    let snap = CoreClient
        .snapshot(&state)
        .await
        .expect("snapshot succeeds");
    let ui_stats = snap.stats.expect("snapshot carries stats");
    assert_eq!(ui_stats.rx_bytes, 1000);
    assert_eq!(ui_stats.tx_bytes, 500);
    assert_eq!(ui_stats.rx_rate_bps, 200);
    assert_eq!(ui_stats.tx_rate_bps, 100);
    assert_eq!(ui_stats.latency_ms, 7);
    assert_eq!(ui_stats.phase, super::stats::StatsPhase::Connected);
    assert_eq!(ui_stats.engine_sequence, 3);
    assert_eq!(ui_stats.sample_tick, 9);

    // stats 命令：从缓存读取同一份统计（无独立 RPC）。
    let cached = CoreClient.stats(&state).await.expect("stats from cache");
    assert_eq!(cached, ui_stats, "stats 命令读 snapshot 写入的缓存");

    server_task.abort();
}

/// respond_interaction：真实 tonic 往返（interaction_id + payload 透传）。
#[tokio::test]
async fn core_client_respond_interaction_roundtrips() {
    let (mock, channel, server_task) = serve_mock(MockKernel::new()).await;
    let state = dialed_state(channel);

    let reply = CoreClient
        .respond_interaction(&state, vec![0xAA; 16], b"answer".to_vec())
        .await
        .expect("respond succeeds");
    assert!(matches!(reply.result, OperationResult::Succeeded { .. }));

    let received = mock
        .interactions
        .lock()
        .await
        .pop()
        .expect("interaction observed");
    assert_eq!(received.interaction_id, vec![0xAA; 16]);
    assert_eq!(received.response_payload, b"answer");
    assert_eq!(
        received.runtime_epoch.len(),
        16,
        "epoch 必须 16 字节（core 校验）"
    );

    server_task.abort();
}

/// watch_events：真实 server-streaming → 事件映射（tick/kind/snapshot）。
#[tokio::test]
async fn core_client_watch_stream_maps_live_events() {
    use tokio_stream::StreamExt;

    let (mock, channel, server_task) = serve_mock(MockKernel::new()).await;
    let (tx, rx) = mpsc::channel::<wire::RuntimeEvent>(8);
    *mock.watch_rx.lock().await = Some(rx);

    let mut stream = CoreClient
        .open_watch_stream(&channel, 0)
        .await
        .expect("watch stream opens");

    // 向流中推一个 TRANSITION Connected 事件（必须 `.await` 使发送生效；裸 `let _ = send`
    // 会 drop future 而不发送）→ 真实 server-streaming 送达 → UI 映射。
    let sent = tx
        .send(wire::RuntimeEvent {
            monotonic_tick: 9,
            kind: wire::RuntimeEventKind::Transition as i32,
            snapshot: Some(wire::RuntimeSnapshot {
                state: Some(wire::runtime_snapshot::State::Connected(
                    wire::ConnectedState {
                        session: None,
                        session_established_at_ms: 0,
                    },
                )),
                stats: None,
                proxy_tun: None,
            system_proxy: None,
            reconnect: None,
                operation_id: vec![0x11; 16],

                service_status: None,
                mode: String::new(),
            }),
            operation_id: vec![0x11; 16],
        })
        .await;
    assert!(
        sent.is_ok(),
        "事件发送必须成功（receiver 在 server 流中存活）"
    );
    drop(tx);

    let ev = tokio::time::timeout(std::time::Duration::from_secs(3), stream.next())
        .await
        .expect("event arrives")
        .expect("stream yields")
        .expect("event ok");
    // 流携带 wire 事件 → 经 wire→UI 映射断言 UI 视图。
    let ui = super::wire::event_from_wire(&ev);
    assert_eq!(ui.monotonic_tick, 9);
    assert_eq!(ui.kind, super::state::RuntimeEventKind::Transition);
    assert!(matches!(
        ui.snapshot.runtime,
        RuntimeState::Connected { .. }
    ));
    assert_eq!(ui.snapshot.monotonic_tick, 9, "UI snapshot 内嵌同一 tick");

    server_task.abort();
}

/// 未拨号（NotWired）时命令必须 fail closed（CoreUnreachable，不 panic）。
#[tokio::test]
async fn core_client_fails_closed_when_not_dialed() {
    let state = CoreState::default();
    assert!(state.channel().is_none());

    let err = CoreClient
        .connect(
            &state,
            ConnectIntent {
                profile_ref: String::new(),
                secret_payload: None,
            },
        )
        .await
        .expect_err("must fail closed");
    assert!(matches!(err, super::error::AppError::CoreUnreachable(_)));
}

/// 未拨号时 logs/config 返回 CoreUnreachable（已真实接线，需 core 通道）；
/// stats 缓存无样本仍返回 typed NotWired（前端「暂无统计」，不视为失败）。
#[tokio::test]
async fn core_client_logs_config_require_dialed_stats_gap_not_wired() {
    let state = CoreState::default();
    let err = CoreClient
        .logs_list(&state, 0, 100)
        .await
        .expect_err("logs_list requires dialed core");
    assert!(matches!(err, super::error::AppError::CoreUnreachable(_)));

    let err = CoreClient
        .logs_clear(&state)
        .await
        .expect_err("logs_clear requires dialed core");
    assert!(matches!(err, super::error::AppError::CoreUnreachable(_)));

    let err = CoreClient
        .config_get(&state)
        .await
        .expect_err("config_get requires dialed core");
    assert!(matches!(err, super::error::AppError::CoreUnreachable(_)));

    let err = CoreClient
        .config_set(&state, Vec::new())
        .await
        .expect_err("config_set requires dialed core");
    assert!(matches!(err, super::error::AppError::CoreUnreachable(_)));

    // stats-wire 方案 A：stats 随 RuntimeSnapshot 携带（不再独立 RPC）；缓存尚无
    // 样本（未连接）→ typed NotWired 占位（前端「暂无统计」，不视为失败）。
    let err = CoreClient.stats(&state).await.expect_err("no stats yet");
    assert!(matches!(err, super::error::AppError::NotWired(_)));

    // NotWired 是 serde 序列化的（随 invoke 返回前端）——形状必须稳定。
    let json = serde_json::to_value(err).expect("serialize");
    assert_eq!(json["kind"], "not_wired");
}

/// RPC 拒绝（mock 返回 Unauthorized）→ 非 transport 类错误映射为 Internal。
#[tokio::test]
async fn core_client_maps_business_rejection_to_internal() {
    struct Rejecting;
    #[tonic::async_trait]
    impl KernelControl for Rejecting {
        type WatchEventsStream = WatchStream;
        async fn connect(
            &self,
            _r: Request<wire::ConnectRequest>,
        ) -> Result<Response<wire::OperationReply>, Status> {
            Err(Status::unauthenticated("not authorized"))
        }
        async fn logs_list(
            &self,
            _r: Request<wire::LogsListRequest>,
        ) -> Result<Response<wire::LogsListReply>, Status> {
            Err(Status::unauthenticated("not authorized"))
        }
        async fn logs_clear(
            &self,
            _r: Request<wire::LogsClearRequest>,
        ) -> Result<Response<wire::LogsClearReply>, Status> {
            Err(Status::unauthenticated("not authorized"))
        }
        async fn config_get(
            &self,
            _r: Request<wire::ConfigGetRequest>,
        ) -> Result<Response<wire::ConfigPayload>, Status> {
            Err(Status::unauthenticated("not authorized"))
        }
        async fn config_set(
            &self,
            _r: Request<wire::ConfigSetRequest>,
        ) -> Result<Response<wire::ConfigReply>, Status> {
            Err(Status::unauthenticated("not authorized"))
        }
        async fn respond_interaction(
            &self,
            _r: Request<wire::InteractionResponse>,
        ) -> Result<Response<wire::OperationReply>, Status> {
            unreachable!()
        }
        async fn stop(
            &self,
            _r: Request<wire::StopRequest>,
        ) -> Result<Response<wire::OperationReply>, Status> {
            unreachable!()
        }
        async fn reconcile(
            &self,
            _r: Request<wire::ReconcileRequest>,
        ) -> Result<Response<wire::OperationReply>, Status> {
            unreachable!()
        }
        async fn get_operation(
            &self,
            _r: Request<wire::GetKernelOperationRequest>,
        ) -> Result<Response<wire::KernelOperationReply>, Status> {
            unreachable!()
        }
        async fn get_snapshot(
            &self,
            _r: Request<wire::SnapshotRequest>,
        ) -> Result<Response<wire::RuntimeSnapshot>, Status> {
            unreachable!()
        }
        async fn watch_events(
            &self,
            _r: Request<wire::WatchEventsRequest>,
        ) -> Result<Response<Self::WatchEventsStream>, Status> {
            unreachable!()
        }
        async fn service_control(
            &self,
            _r: Request<wire::ServiceControlRequest>,
        ) -> Result<Response<wire::ServiceControlReply>, Status> {
            unreachable!()
        }
    }

    let (_mock, _channel, server_task) = serve_mock(MockKernel::new()).await;
    // 换成拒绝 server：直接 serve Rejecting。
    server_task.abort();
    let addr = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("local addr")
    };
    let server = Server::builder().add_service(KernelControlServer::new(Rejecting));
    let handle = tokio::spawn(async move {
        let _ = server.serve(addr).await;
    });
    let uri = format!("http://{addr}")
        .parse::<http::Uri>()
        .expect("valid uri");
    let channel = Endpoint::new(uri)
        .expect("endpoint")
        .connect()
        .await
        .expect("connect");
    let state = dialed_state(channel);

    let err = CoreClient
        .connect(
            &state,
            ConnectIntent {
                profile_ref: String::new(),
                secret_payload: None,
            },
        )
        .await
        .expect_err("business rejection");
    assert!(
        matches!(err, super::error::AppError::Internal(_)),
        "非 transport 拒绝必须映射为 Internal（core 语义拒绝 ≠ 掉线），got {err:?}"
    );
    handle.abort();
}
