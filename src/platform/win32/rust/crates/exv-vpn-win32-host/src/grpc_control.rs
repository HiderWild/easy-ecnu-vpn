// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core 侧 gRPC 控制面客户端（P1-c：自研 JSON frame → tonic `HelperControlClient`）。
//!
//! 本模块是产品 wire 的 core 侧入口（P1 决策：proto gRPC 是唯一 wire 权威）。经
//! [`grpc_transport::connect_engine_channel`] 建立承载于双向认证 Named Pipe 的 HTTP/2
//! channel，再构造 [`HelperControlClient<Channel>`]。保留 legacy `control_client.rs`
//! 的既有能力在 gRPC 世界中的对应：
//!
//! - **连接管理**：`connect` 有界重试拨号 + 构建 channel；`Channel` 自身处理重连。
//! - **peer 认证（双向 pid+SID）**：client 侧在拨号后验证 engine server 的 pid+SID
//!   （`verify_engine_server_pipe`，fail closed）；engine 侧验证 core 由 server 完成
//!   （P1-b）。gRPC 无 hello 字段自报身份（spec §9.4：peer 身份只来自连接元数据）。
//! - **凭据一次性 + zeroize**：legacy `send_owned` 语义由 [`hand_off_request`] 保留——
//!   请求按 move 交给 wire（`std::mem::take`，不复制其中的一次性 secret），本地
//!   one-shot 源（[`crate::kernel_control::ClearableSecret`]）立即零化，调用方的请求
//!   副本被 Default 化。注意：当前 HelperControl wire 尚无凭据字段（P1 基线 proto），
//!   凭据落点由 P3 语义网关决策；本工具已就绪。
//! - **事件/掉线感知**：engine→core 日志事件经 `stream_logs`（server-streaming）；
//!   掉线由后台 liveness 监视器（周期性 `observe_owned_state` 探测）上报，调用方可经
//!   [`EngineControlGrpcClient::liveness`] 观察或 `ping` 主动探测。

use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::Stream;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};

use exv_vpn_wire::generated::helper_control_client::HelperControlClient;
use exv_vpn_wire::generated::{
    acquire_lease_reply, helper_lease_message, host_lease_message, service_manage_request,
    AcquireLeaseReply, AcquireLeaseRequest, ApplyTunnelReply, ApplyTunnelRequest, ConnectPhase,
    ConnectStatusEvent, GetOperationReply, GetOperationRequest, HelperLeaseMessage,
    HostLeaseMessage, InteractionResponse, KeepAliveReply, KeepAliveRequest, LeaseHandshake,
    LogEvent, ObserveOwnedStateReply, ObserveOwnedStateRequest, OperationLookupKey,
    OperationMethod, OperationReply, ReconcileRequest, ReleaseLeaseReply, ReleaseLeaseRequest,
    ServiceManageReply, ServiceManageRequest, ServiceSelfQuery, ServiceSelfReport, StatsEvent,
    StatsPhase, StopTunnelReply, StopTunnelRequest, StreamLogsRequest, StreamStatsRequest,
    StreamConnectStatusRequest, VpnError,
};
use exv_vpn_win32_ipc::peer_auth::{current_user_sid, VerifiedPipePeer};

use crate::engine_lifecycle::EngineSlot;
use crate::grpc_transport::{
    connect_engine_channel, connect_engine_service_channel, GrpcPipeError,
};
use crate::kernel_control::ClearableSecret;

/// 掉线感知探测周期。
const LIVENESS_PERIOD: Duration = Duration::from_secs(5);
/// 单次探测超时。
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(3);
/// P2 core 侧心跳发送周期（默认 10s，可调——`spawn_keepalive_ticker` 参数；engine 侧
/// 超时上界 15s 见 `exv_engine::heartbeat::HEARTBEAT_TIMEOUT_MS`）。
pub const KEEPALIVE_PERIOD: Duration = Duration::from_secs(10);

/// 当前 core 维护的 engine 类型：KeepAlive 只对 oneshot 有效。
pub const ENGINE_KIND_AUTO: u8 = 0;
pub const ENGINE_KIND_SERVICE: u8 = 1;
pub const ENGINE_KIND_ONESHOT: u8 = 2;

/// 从已认证的 core 用户 SID 派生 owner lease principal。
///
/// 这是客户端自己的身份，不是控制面服务端（engine）的身份；service engine
/// 以 LocalSystem 运行时两者必然不同。C3a 自动重连意图的 `principal_digest` 与
/// UI 同源派生（复用本函数）。
#[must_use]
pub(crate) fn owner_principal_digest(core_user_sid: &str) -> Vec<u8> {
    Sha256::digest(format!("sid:{core_user_sid}").as_bytes()).to_vec()
}

/// gRPC 控制面客户端错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrpcClientError {
    /// 传输层失败（拨号/peer 认证/channel 构建）。
    Transport(GrpcPipeError),
    /// RPC 被 engine 拒绝（携带 gRPC code 与 message）。
    Rpc(Code, String),
    /// engine 已断开（transport Unavailable/Canceled/Unknown 或探测超时）。
    ConnectionLost,
    /// 等待 engine 回复超时。
    Timeout,
}

/// 把 tonic `Status` 映射为客户端错误：transport 类 code → `ConnectionLost`；
/// `DeadlineExceeded` → `Timeout`；其余 → `Rpc`。
fn map_status(s: Status) -> GrpcClientError {
    match s.code() {
        Code::Unavailable | Code::Cancelled | Code::Unknown => GrpcClientError::ConnectionLost,
        Code::DeadlineExceeded => GrpcClientError::Timeout,
        _ => GrpcClientError::Rpc(s.code(), s.message().to_string()),
    }
}

/// transport 类失败（掉线）判据。
fn is_lost_status(s: &Status) -> bool {
    matches!(s.code(), Code::Unavailable | Code::Cancelled | Code::Unknown)
}

/// core→engine 的 gRPC 控制面客户端。
///
/// 持有已验证的 engine peer（`engine_peer`）与 liveness 观察端（`liveness`）。所有
/// RPC 方法为 async 且 borrow `&mut self`（tonic client 方法签名）。engine 掉线后，
/// 调用方应重建（再次 `connect` / `connect_service`）。
pub struct EngineControlGrpcClient {
    client: HelperControlClient<Channel>,
    /// 已验证的 engine（server）身份。
    pub engine_peer: VerifiedPipePeer,
    /// engine 存活观察端：`true` 表示最近一次 liveness 探测成功。
    liveness: watch::Receiver<bool>,
    /// liveness 监视器任务。
    _monitor: tokio::task::JoinHandle<()>,
    /// 是否已向 engine 建立 owner lease（MaintainOwnerLease 握手；P1-b `core.owner`
    /// 前置）。幂等 guard：同一 client 已握手后 `ensure_owner_lease` 直接返回。
    owner_lease_established: bool,
    /// S3/D7：service-mode 连接时持有 `MaintainOwnerLease` bidi 流（engine 侧以此感知
    /// 连接存活；连接 EOF → engine 释放 connection-bound owner）。oneshot 为 `None`
    /// （一次性握手后关流，owner 跨 stream 保持）。
    service_lease: Option<ServiceLease>,
    /// S3/D7：本 client 是否连接 service-mode engine（`connect_service`）。service 模式
    /// 建立 lease 后须保持 bidi 流开放；oneshot 一次性握手后关流。
    service_mode: bool,
}

/// 服务模式的 `MaintainOwnerLease` bidi 流持有者（D7）。
///
/// core 连接 service-mode engine 后，握手完成即把流保持在本句柄中；本句柄 drop →
/// 流关闭 → engine 侧 `maintain_owner_lease` 读到 EOF → 释放 connection-bound owner +
/// terminate_connection + ownership_version++（旧 core 断线后新 core 可握手接管）。
struct ServiceLease {
    /// 保留发送端（向 engine 发 OwnershipTokenReceived 等消息的通道；当前未使用——
    /// token 经 AcquireLease RPC 交付，发送端存活保证流不因 sender drop 而关）。
    _req_tx: mpsc::Sender<HostLeaseMessage>,
    /// 后台 drain 任务（消费 engine→core 的 lease 消息；流 EOF → 任务结束）。
    _task: tokio::task::JoinHandle<()>,
}

impl EngineControlGrpcClient {
    /// 连接 engine 控制面（有界重试拨号 + client 侧 peer 认证），并启动掉线监视。
    ///
    /// `expected_engine_pid` 是 engine 进程 pid（core 侧核对）；`expected_user_sid`
    /// 是当前用户 SID（engine 与 core 同用户）。engine 侧验证 core 的 pid+SID 由
    /// server 完成（P1-b）。
    ///
    /// # Errors
    /// 拨号失败 → `GrpcClientError::Transport(GrpcPipeError::Dial)`；身份不匹配 →
    /// `Transport(GrpcPipeError::Auth)`；channel 构建失败 →
    /// `Transport(GrpcPipeError::Transport)`。
    pub async fn connect(
        pipe_name: &str,
        expected_engine_pid: u32,
        expected_user_sid: &str,
    ) -> Result<Self, GrpcClientError> {
        let (channel, peer) =
            connect_engine_channel(pipe_name, expected_engine_pid, expected_user_sid)
                .await
                .map_err(GrpcClientError::Transport)?;
        let client = HelperControlClient::new(channel.clone());
        let (liveness_tx, liveness) = watch::channel(true);
        let monitor = tokio::spawn(engine_liveness_monitor(channel, liveness_tx));
        Ok(Self {
            client,
            engine_peer: peer,
            liveness,
            _monitor: monitor,
            owner_lease_established: false,
            service_lease: None,
            // oneshot：一次性握手后关流，engine 侧 owner 跨 stream 保持（不持有 bidi 流）。
            service_mode: false,
        })
    }

    /// 连接 **service-mode** engine 控制面（S3/D2/D7/S6）：拨号稳定服务管道 →
    /// engine 自报身份验证（PID 交叉核验 + SID 比对）→ PSK-HMAC 双向挑战 → 构建 channel。
    /// 与 oneshot（[`Self::connect`]）的差异：PID 不固定（SCM 常驻 engine 跨 core），
    /// PSK 是主认证机制，自报身份是 server 身份确认。
    ///
    /// `psk` 是服务共享秘密（core 从 `%ProgramData%\exv\service.key` 读入，安装用户可读）。
    /// `expected_user_sid` 是**服务 engine（server）进程**的期望用户 SID——服务以
    /// LocalSystem 运行，调用方应传
    /// [`SYSTEM_SID`](exv_vpn_win32_ipc::peer_auth::SYSTEM_SID)（`S-1-5-18`）；
    /// 自报 SID 不符 → fail closed（服务 engine 必须是特权系统服务，而非用户态冒名进程）。
    ///
    /// # Errors
    /// 拨号失败 → `GrpcClientError::Transport`；身份/PSK 不匹配 →
    /// `Transport(GrpcPipeError::Auth)`；channel 构建失败 → `Transport`。
    pub async fn connect_service(
        pipe_name: &str,
        expected_user_sid: &str,
        psk: &[u8],
    ) -> Result<Self, GrpcClientError> {
        let (channel, peer) =
            connect_engine_service_channel(pipe_name, expected_user_sid, psk)
                .await
                .map_err(GrpcClientError::Transport)?;
        let client = HelperControlClient::new(channel.clone());
        let (liveness_tx, liveness) = watch::channel(true);
        let monitor = tokio::spawn(engine_liveness_monitor(channel, liveness_tx));
        Ok(Self {
            client,
            engine_peer: peer,
            liveness,
            _monitor: monitor,
            owner_lease_established: false,
            service_lease: None,
            // service：握手完成后保持 bidi 流开放（D7）——engine 以流 EOF 判连接断线，
            // 旧 core 断线 → 释放 connection-bound owner，新 core 可握手接管。
            service_mode: true,
        })
    }

    /// 当前 engine 存活状态（最近一次 liveness 探测结果）。
    #[must_use]
    pub fn is_engine_alive(&self) -> bool {
        *self.liveness.borrow()
    }

    /// engine 掉线 liveness 接收端（P3-c2：`EngineSupervisor::attach_client` 用同一
    /// 接收端驱动运行期 `on_helper_link_terminal`）。
    #[must_use]
    pub fn liveness(&self) -> watch::Receiver<bool> {
        self.liveness.clone()
    }

    /// 主动探测 engine 存活（有界超时）。仅 transport 类失败视为掉线；收到任意
    /// gRPC 状态（即使业务错误）都证明连接往返成功。
    ///
    /// # Errors
    /// engine 掉线 → `GrpcClientError::ConnectionLost`；探测超时 →
    /// `GrpcClientError::Timeout`。
    pub async fn ping(&mut self) -> Result<(), GrpcClientError> {
        let probe = ObserveOwnedStateRequest { lookup_key: None };
        let outcome = tokio::time::timeout(LIVENESS_TIMEOUT, self.client.observe_owned_state(probe))
            .await;
        match outcome {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(s)) if is_lost_status(&s) => Err(GrpcClientError::ConnectionLost),
            Ok(Err(_)) => Ok(()),
            Err(_) => Err(GrpcClientError::Timeout),
        }
    }

    // -----------------------------------------------------------------------
    // HelperControl unary RPC（直通）
    // -----------------------------------------------------------------------

    /// 观察当前 owned runtime 状态（只读）。
    ///
    /// # Errors
    /// engine 掉线 → `GrpcClientError::ConnectionLost`；超时 → `Timeout`；其余拒绝 →
    /// `Rpc`。
    pub async fn observe_owned_state(
        &mut self,
        request: ObserveOwnedStateRequest,
    ) -> Result<ObserveOwnedStateReply, GrpcClientError> {
        let resp = self
            .client
            .observe_owned_state(request)
            .await
            .map_err(map_status)?;
        Ok(resp.into_inner())
    }

    /// 获取（或重选）平台 ownership lease。映射 domain `AcquireOwnership`。
    ///
    /// # Errors
    /// 同 [`EngineControlGrpcClient::observe_owned_state`]。
    pub async fn acquire_lease(
        &mut self,
        request: AcquireLeaseRequest,
    ) -> Result<AcquireLeaseReply, GrpcClientError> {
        let resp = self.client.acquire_lease(request).await.map_err(map_status)?;
        Ok(resp.into_inner())
    }

    /// 应用协商好的 tunnel plan 到平台。
    ///
    /// # Errors
    /// 同 [`EngineControlGrpcClient::observe_owned_state`]。
    pub async fn apply_tunnel(
        &mut self,
        request: ApplyTunnelRequest,
    ) -> Result<ApplyTunnelReply, GrpcClientError> {
        let resp = self.client.apply_tunnel(request).await.map_err(map_status)?;
        Ok(resp.into_inner())
    }

    /// 拆除当前已应用的 tunnel。
    ///
    /// # Errors
    /// 同 [`EngineControlGrpcClient::observe_owned_state`]。
    pub async fn stop_tunnel(
        &mut self,
        request: StopTunnelRequest,
    ) -> Result<StopTunnelReply, GrpcClientError> {
        let resp = self.client.stop_tunnel(request).await.map_err(map_status)?;
        Ok(resp.into_inner())
    }

    /// 查询先前提交操作的 disposition。
    ///
    /// # Errors
    /// 同 [`EngineControlGrpcClient::observe_owned_state`]。
    pub async fn get_operation(
        &mut self,
        request: GetOperationRequest,
    ) -> Result<GetOperationReply, GrpcClientError> {
        let resp = self.client.get_operation(request).await.map_err(map_status)?;
        Ok(resp.into_inner())
    }

    /// 退役（释放）当前 ownership lease。
    ///
    /// # Errors
    /// 同 [`EngineControlGrpcClient::observe_owned_state`]。
    pub async fn release_lease(
        &mut self,
        request: ReleaseLeaseRequest,
    ) -> Result<ReleaseLeaseReply, GrpcClientError> {
        let resp = self.client.release_lease(request).await.map_err(map_status)?;
        Ok(resp.into_inner())
    }

    // -----------------------------------------------------------------------
    // HelperControl streaming RPC（engine→core 推送）
    // -----------------------------------------------------------------------

    /// 订阅 engine→core 的结构化日志流（产品日志通道，P2 聚合服务消费）。
    /// `resume_tick == 0` 表示从当前流位置开始。返回的流由调用方驱动；流 EOF 即
    /// engine 断开（掉线感知）。
    ///
    /// # Errors
    /// engine 掉线 → `GrpcClientError::ConnectionLost`；其余拒绝 → `Rpc`。
    pub async fn stream_logs(
        &mut self,
        resume_tick: u64,
    ) -> Result<tonic::codec::Streaming<LogEvent>, GrpcClientError> {
        let request = StreamLogsRequest { resume_tick };
        let resp = self.client.stream_logs(request).await.map_err(map_status)?;
        Ok(resp.into_inner())
    }

    /// 订阅 engine 统计推送流（P5-a：`HelperControl.StreamStats`）。
    /// `sample_interval_ms == 0` 用 engine 默认间隔（1000 ms）；流从当前累计计数开始，
    /// 持续到客户端断开。返回的流由调用方驱动；流 EOF 即 engine 断开（掉线感知）。
    ///
    /// # Errors
    /// 同 [`EngineControlGrpcClient::stream_logs`]。
    pub async fn stream_stats(
        &mut self,
        sample_interval_ms: u32,
    ) -> Result<tonic::codec::Streaming<StatsEvent>, GrpcClientError> {
        let request = StreamStatsRequest { sample_interval_ms };
        let resp = self.client.stream_stats(request).await.map_err(map_status)?;
        Ok(resp.into_inner())
    }

    /// 建立（或维持）lease 维护 bidi 流（首条消息为授权握手）。
    ///
    /// # Errors
    /// 同 [`EngineControlGrpcClient::stream_logs`]。
    pub async fn maintain_owner_lease(
        &mut self,
        request: impl tonic::IntoStreamingRequest<Message = HostLeaseMessage>,
    ) -> Result<tonic::codec::Streaming<HelperLeaseMessage>, GrpcClientError> {
        let resp = self
            .client
            .maintain_owner_lease(request)
            .await
            .map_err(map_status)?;
        Ok(resp.into_inner())
    }

    /// 建立（或确认已建立）engine 侧 owner lease（`ApplyTunnel`/`StopTunnel` 的完整
    /// 前置，P1-b）：
    ///
    /// 1. **MaintainOwnerLease 授权握手**——首条消息为 `LeaseHandshake`
    ///    （`principal_digest = SHA-256("sid:<core_user_sid>")`，镜像 engine
    ///    `verify_service_peer`/`verify_core_peer` 的 principal 派生；capability/channel
    ///    digest 各 32 字节占位——engine 只校验长度）。收到 `HandshakeAccepted` 即
    ///    `core.owner` 已建立
    ///    （engine 侧 `core.owner` 在 `release_lease` 前保持——一次性握手、stream 关闭
    ///    不影响已建立的 owner）。
    /// 2. **AcquireLease**——建立 J52 lease 槽（`core.leases.lease(&owner.connection)`）：
    ///    `ApplyTunnel`/`StopTunnel` 的 W15 admit gate（`admit_and_gate`）要求该槽存在，
    ///    缺失时返回 `failed_precondition("no owner lease for gate")`。
    ///
    /// 幂等：同一 client 已建立后直接返回。任一步失败（流断开 / 非 accepted / acquire
    /// 拒绝）→ typed `GrpcClientError`。
    ///
    /// # Errors
    /// 见 [`KernelEngineControl::ensure_owner_lease`]。
    pub async fn establish_owner_lease(&mut self) -> Result<(), GrpcClientError> {
        if self.owner_lease_established {
            return Ok(());
        }
        // 1. MaintainOwnerLease 授权握手（首条消息 = 授权握手）。
        let (req_tx, req_rx) = mpsc::channel::<HostLeaseMessage>(8);
        let stream_request = Request::new(ReceiverStream::new(req_rx));
        let mut lease_stream = self
            .client
            .maintain_owner_lease(stream_request)
            .await
            .map_err(map_status)?
            .into_inner();
        // `engine_peer` 是**服务端**身份。service 模式下服务以 LocalSystem 运行，
        // 因而这里不能再拿 `self.engine_peer.user_sid`（S-1-5-18）声明 owner；
        // engine 侧会把 handshake principal 与已认证的**客户端 core** SID 比较。
        // oneshot 中两者通常恰好相同，所以旧实现只在 service 真机路径暴露为
        // `lease.handshake.refused / identity_mismatch`。
        let core_user_sid = current_user_sid().ok_or_else(|| {
            GrpcClientError::Transport(GrpcPipeError::Auth(
                "cannot resolve core user SID for owner lease".to_string(),
            ))
        })?;
        let principal_digest = owner_principal_digest(&core_user_sid);
        req_tx
            .send(HostLeaseMessage {
                owner_lease_id: vec![0u8; 16],
                runtime_epoch: vec![0u8; 16],
                message: Some(host_lease_message::Message::Handshake(LeaseHandshake {
                    principal_digest,
                    capability_digest: vec![0x20; 32],
                    channel_identity_digest: vec![0x30; 32],
                })),
            })
            .await
            .map_err(|_| GrpcClientError::ConnectionLost)?;
        // 等待 engine 确认：core.owner 已建立（HandshakeAccepted）。
        let accepted = lease_stream
            .message()
            .await
            .map_err(map_status)?
            .ok_or(GrpcClientError::ConnectionLost)?;
        if !matches!(
            accepted.message,
            Some(helper_lease_message::Message::HandshakeAccepted(_))
        ) {
            return Err(GrpcClientError::Rpc(
                Code::FailedPrecondition,
                "owner lease handshake not accepted".to_string(),
            ));
        }
        // S3/D7：service 模式——握手完成后**保持** bidi 流开放（后台 drain engine→core
        // 消息；持有 `req_tx` 发送端）。engine 侧以流 EOF 判连接断线：core 退出 / 本
        // client drop → 流关 → engine 释放 connection-bound owner（新 core 可接管）。
        // oneshot 保持原语义：一次性握手后关流，engine 侧 owner 跨 stream 保持。
        if self.service_mode {
            let task = tokio::spawn(async move {
                while let Ok(Some(_msg)) = lease_stream.message().await {
                    // drain：消费 engine→core lease 消息（握手后主要为 keepalive-ack /
                    // owner-lost 等）；流 EOF（engine 断开）即结束本任务。
                }
            });
            self.service_lease = Some(ServiceLease {
                _req_tx: req_tx,
                _task: task,
            });
        }

        // 2. AcquireLease：建立 J52 lease 槽（W15 admit gate 需要；key 的 principal 由
        // engine `kernel_request_to_operation` 以认证 peer 覆盖，确定性合成 key 足够——
        // 镜像 P1-b 集成测试的 acquire 构造）。
        let acquire = AcquireLeaseRequest {
            lookup_key: Some(lease_acquire_wire_key()),
            platform_ownership: None,
            request_digest: vec![0x11; 32],
        };
        let reply = self
            .client
            .acquire_lease(acquire)
            .await
            .map_err(map_status)?
            .into_inner();
        if !matches!(
            reply.result,
            Some(acquire_lease_reply::Result::Acquired(_))
        ) {
            return Err(GrpcClientError::Rpc(
                Code::FailedPrecondition,
                "owner lease acquire rejected".to_string(),
            ));
        }
        self.owner_lease_established = true;
        Ok(())
    }

    /// 优雅关闭与 engine 的控制连接（S3/D7 + 停机路径）：丢弃 service lease（
    /// `MaintainOwnerLease` 流关闭）并中止 liveness 监视任务 → 所有 channel 引用 drop →
    /// 连接关闭 → engine 侧（service 模式）释放 connection-bound owner（新 core 可接管）。
    /// 调用后本 client 不可再用（terminal）。oneshot 下同样中止监视任务（连接释放）。
    ///
    /// 生产语义：core 停机 / 换 engine 前调用，连接立即关闭而非等 liveness 周期自然退出。
    pub fn close_engine_connection(mut self) {
        self.service_lease.take();
        self._monitor.abort();
    }
}

/// 确定性 lease-acquire 操作 key（`OperationMethod::AcquireLease`；principal digest 由
/// engine 以认证 peer 覆盖，method/runtime_epoch/operation_id 为合法 wire 形状）。
fn lease_acquire_wire_key() -> OperationLookupKey {
    OperationLookupKey {
        principal_digest: vec![0x10; 32],
        method: OperationMethod::AcquireLease as i32,
        runtime_epoch: vec![0x42; 16],
        operation_id: vec![0x43; 16],
    }
}

/// 凭据一次性 + zeroize（legacy `send_owned` 语义）。
///
/// 把 `request` 按 move 交给 wire（`std::mem::take`，不复制其中的一次性 secret），
/// 并**立即**零化本地 one-shot 源 `secret`；调用方的 `request` 被 Default 化——发送后
/// 本地无明文（无需等待 RPC 返回，更不等待 `Drop`）。返回的请求交由 gRPC 发送；
/// 其 wire 副本随请求 drop（P3 将补 generated message 发送后清零）。
///
/// 当前 HelperControl wire 尚无凭据字段（P1 基线 proto）；当 P3 语义网关为某条
/// mutation 引入一次性 secret（如 `secret_payload`）时，把该请求的 `&mut` 与本函数
/// 配对，即获得与 legacy 一致的发送后零化保证。
///
/// # Examples
/// ```ignore
/// let mut secret = ClearableSecret::new(&decrypted);
/// let wire_req = hand_off_request(&mut req, &mut secret);
/// client.apply_tunnel(wire_req).await?; // secret 已在 hand-off 时零化
/// ```
#[must_use]
pub fn hand_off_request<R: Default>(request: &mut R, secret: &mut ClearableSecret) -> R {
    let wire_request = std::mem::take(request);
    secret.clear();
    wire_request
}

// ---------------------------------------------------------------------------
// KernelControl 写路径的 engine 控制面 seam（P3-b2）
// ---------------------------------------------------------------------------

/// 归一化的 engine connect-status 事件（R1：`WatchEvents` 真实订阅的源事件模型）。
///
/// 状态只从 engine 独立 `StreamConnectStatus` 通道来（R1w 契约，载 operation_id +
/// 8 级 ConnectPhase + coarse StatsPhase + 可选 err）。**日志已退役为纯输出**（D3
/// 铁律：日志绝不回流状态）；host 侧状态转发器
/// （`kernel_control_service::spawn_status_forwarder`）把 [`EngineStatusEvent`]
/// 归一化为 `WatchEvents` 的 `RuntimeEvent` 并驱动 composition 状态机。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineStatusEvent {
    /// 连接阶段推进（coarse = Connecting；携带细粒度 ConnectPhase）。
    Progress { operation_id: Vec<u8>, connect_phase: ConnectPhase },
    /// 连接成功（coarse = Connected）——`set_phase(Connected)` 的唯一驱动；时间来自
    /// engine 确认数据面可用的 wall-clock，0 表示上游尚不能提供。
    Connected {
        operation_id: Vec<u8>,
        session_established_at_ms: Option<i64>,
    },
    /// 连接失败（coarse = Failed；携带结构化错误）。
    Failed { operation_id: Vec<u8>, error: VpnError },
    /// 已停止 / 回 idle（coarse = Idle；停止收敛）。
    Stopped { operation_id: Vec<u8> },
}

/// `WatchEvents` 的 engine connect-status 事件流类型（host 侧归一化后；由调用方驱动）。
pub type EngineStatusEventStream = Pin<Box<dyn Stream<Item = EngineStatusEvent> + Send>>;

/// engine 统计推送流类型（P5-b：host 侧消费 `StreamStats` 后；由调用方驱动）。
/// 元素为 wire `StatsEvent`（累计权威字节 + engine 采样 convenience），host 侧
/// [`crate::stats`] 归一化层再算权威速度。
pub type StatsEventStream = Pin<Box<dyn Stream<Item = StatsEvent> + Send>>;

/// engine 日志推送流类型（R3：host 侧消费 `StreamLogs` 后；由调用方驱动）。
/// 元素为 `Result<LogEvent, Status>`（transport 错误项已被过滤，仅保留成功项——
/// 聚合-only 消费，见 [`crate::log_aggregator::ingest_engine_stream`]）。
pub type LogEventStream = Pin<Box<dyn Stream<Item = Result<LogEvent, Status>> + Send>>;

/// 把 engine 的 `ConnectStatusEvent`（wire）归一化为 [`EngineStatusEvent`]。
///
/// 按 coarse `StatsPhase` 分支：Connecting → Progress（带细粒度 ConnectPhase）；
/// Connected → Connected；Failed → Failed（携带 err）；Idle → Stopped。其余 coarse
/// （Unspecified/Stopping——R1w 状态流不产生）或空 operation_id → `None`。
#[must_use]
pub fn connect_status_from_wire(event: ConnectStatusEvent) -> Option<EngineStatusEvent> {
    let operation_id = event.operation_id;
    if operation_id.is_empty() {
        return None;
    }
    let connect_phase = ConnectPhase::try_from(event.connect_phase)
        .unwrap_or(ConnectPhase::Unspecified);
    match StatsPhase::try_from(event.coarse_phase).unwrap_or(StatsPhase::Unspecified) {
        StatsPhase::Connecting => Some(EngineStatusEvent::Progress {
            operation_id,
            connect_phase,
        }),
        StatsPhase::Connected => Some(EngineStatusEvent::Connected {
            operation_id,
            session_established_at_ms: (event.session_established_at_ms > 0)
                .then_some(event.session_established_at_ms),
        }),
        StatsPhase::Failed => Some(EngineStatusEvent::Failed {
            operation_id,
            error: event.error?,
        }),
        StatsPhase::Idle => Some(EngineStatusEvent::Stopped { operation_id }),
        _ => None,
    }
}

/// `KernelControl` 写路径派发所需的 engine 控制面 seam（P3-b2）。
///
/// 由 [`EngineControlGrpcClient`] 实现（真实 wire）；测试注入 fake，使写路径语义
/// （Connect 秘密零化、Stop/Reconcile 意图组装）可在无真实 engine 时单测。所有方法
/// 都是 `&mut self`（tonic client 方法签名），故服务内以
/// `tokio::sync::Mutex<dyn KernelEngineControl>` 串行化派发。
#[tonic::async_trait]
pub trait KernelEngineControl: Send + Sync {
    /// 应用协商好的 tunnel plan，携带一次性连接秘密（`KernelControl.Connect` 的
    /// engine 派发）。
    ///
    /// `secret_payload` 是 [`crate::credential::assemble_secret_payload`] 产出的一次性
    /// 登录凭据字节（zeroable 槽）。P3-b1 已落地 `ApplyTunnelRequest.secret_payload`
    /// （tag=4，engine 侧解析 `CredentialPackage` 形状）：真实实现把槽内字节移入请求
    /// 字段（秘密随 wire 走），RPC 后零化槽——任何路径都不留明文。
    async fn apply_connect(
        &mut self,
        request: ApplyTunnelRequest,
        secret_payload: &mut ClearableSecret,
    ) -> Result<ApplyTunnelReply, GrpcClientError>;

    /// 拆除当前已应用的 tunnel（`KernelControl.Stop` 的 engine 派发）。
    async fn stop_tunnel(
        &mut self,
        request: StopTunnelRequest,
    ) -> Result<StopTunnelReply, GrpcClientError>;

    /// 查询先前提交操作的 disposition（`KernelControl.Reconcile` 的义务观察；
    /// HelperControl 无 Reconcile RPC，重试落在 P3-b1/P3-c engine 义务模型）。
    async fn get_operation(
        &mut self,
        request: GetOperationRequest,
    ) -> Result<GetOperationReply, GrpcClientError>;

    /// 观察当前 owned runtime 状态（P3-c1：`GetSnapshot` 源化 —— 经 engine 拉真实快照）。
    async fn observe_owned_state(
        &mut self,
        request: ObserveOwnedStateRequest,
    ) -> Result<ObserveOwnedStateReply, GrpcClientError>;

    /// 发送一个 KeepAlive 心跳到 engine（P2 有界存留：engine 侧刷新 `last_heartbeat`
    /// 单调计时；15s 未收到 → 自清理+自退出，hung-core / 进程句柄路径故障兜底）。
    ///
    /// 由 [`spawn_keepalive_ticker`] 的独立 tick 任务按固定周期（默认 10s）调用；传输类
    /// 失败（engine 掉线）best-effort——liveness 监视与状态转发器驱动链接终止路径。
    async fn keep_alive(
        &mut self,
        request: KeepAliveRequest,
    ) -> Result<KeepAliveReply, GrpcClientError>;

    /// 确保 engine 侧 owner lease 已建立（MaintainOwnerLease 授权握手；P1-b `core.owner`
    /// 前置）。
    ///
    /// engine 的 `ApplyTunnel`/`StopTunnel` 经 `bind_mutation` 要求 `core.owner` 存在，
    /// 否则返回 `failed_precondition("no owner lease established")`。本方法幂等：同一
    /// client 已握手后直接返回。engine 侧 `core.owner` 在 `release_lease` 前保持，故
    /// 一次性握手（stream 随后关闭）足以让后续 mutation 通过 gate。
    ///
    /// # Errors
    /// 握手流建立/发送/确认失败或 engine 拒绝 → `GrpcClientError`（transport 掉线 /
    /// RPC 拒绝）。
    async fn ensure_owner_lease(&mut self) -> Result<(), GrpcClientError>;

    /// 订阅 engine connect-status 事件流（R1：`WatchEvents` 真实订阅的源）。
    ///
    /// 真实实现包装 `stream_connect_status`（`HelperControl.StreamConnectStatus`，
    /// R1w 独立 status 通道）并把 wire `ConnectStatusEvent` 归一化为
    /// [`ConnectStatusEvent`]；流 EOF = engine 断开（掉线感知，host 侧断线重放
    /// 语义的判据）。**必须先挂接本流再 ApplyTunnel/StopTunnel**（attach-before-apply
    /// 硬约束——status 发布器无快照，open 前事件丢弃）。
    async fn stream_connect_status(
        &mut self,
    ) -> Result<EngineStatusEventStream, GrpcClientError>;

    /// 订阅 engine 统计推送流（P5-b：core 统计归一化的源）。
    ///
    /// `sample_interval_ms == 0` 用 engine 默认间隔（1000 ms）。真实实现包装
    /// `stream_stats`（`HelperControl.StreamStats`，P5-a 契约）；流 EOF = engine 断开
    /// （host 侧统计转发器退避重连的判据）。`StatsEvent.rx_bytes`/`tx_bytes` 为累计
    /// 权威字节，host 侧 [`crate::stats::TrafficSample`] 以增量归一化速度。
    async fn stream_stats(
        &mut self,
        sample_interval_ms: u32,
    ) -> Result<StatsEventStream, GrpcClientError>;

    /// 订阅 engine 结构化日志推送流（R3：core 日志聚合-only 消费的源）。
    ///
    /// `resume_tick == 0` 从当前流位置开始（不补拉——断线缺口由 engine raw 文件
    /// 离线对账，O4）。真实实现包装 `stream_logs`（`HelperControl.StreamLogs`）并丢弃
    /// transport 错误项；流 EOF = engine 断开（host 侧日志转发器退避重连的判据）。
    /// **纯单向输出**（D3 铁律）：日志只流向聚合落盘，绝不回流状态机。
    async fn stream_logs(
        &mut self,
        resume_tick: u64,
    ) -> Result<LogEventStream, GrpcClientError>;

    /// 查询 engine 内部深度自述（S3-B：Tier 2 零 UAC 通道）。
    ///
    /// 真实实现直通 `HelperControl.ServiceManage`（`query` action）——只读自述，**无
    /// owner lease 要求**（transport peer gate only）：服务刚启动、尚未建立 owner 时 host
    /// 也要能问健康。报告只做健康/展示输入，**绝不作为授权材料**。
    async fn service_manage(
        &mut self,
        request: ServiceManageRequest,
    ) -> Result<ServiceManageReply, GrpcClientError>;

    /// 应答一个待决交互提示（P3-c1：`KernelControl.RespondInteraction` 转发 seam）。
    ///
    /// engine 冻结 wire 无 interaction RPC（P5 补 wire 后替换）；真实实现返回 typed
    /// `Unimplemented`，host 侧保留完整校验 + 转发语义，wire 缺口已标注。
    async fn respond_interaction(
        &mut self,
        response: InteractionResponse,
    ) -> Result<OperationReply, GrpcClientError>;

    /// 重试一个未终局的义务（P3-c1：`KernelControl.Reconcile` 的真实重试 seam）。
    ///
    /// engine 义务模型未在冻结 wire 上（HelperControl 无 Reconcile RPC）；真实实现
    /// 返回 typed `Unimplemented`——host 保留观测 disposition 作为回执并标注，重试
    /// seam 由 engine 义务模型落地（P3-c2）后接线。
    async fn retry_obligation(
        &mut self,
        request: ReconcileRequest,
    ) -> Result<GetOperationReply, GrpcClientError>;
}

#[tonic::async_trait]
impl KernelEngineControl for EngineControlGrpcClient {
    async fn apply_connect(
        &mut self,
        mut request: ApplyTunnelRequest,
        secret_payload: &mut ClearableSecret,
    ) -> Result<ApplyTunnelReply, GrpcClientError> {
        // P3-b1：把一次性秘密字节移入 `ApplyTunnelRequest.secret_payload`（tag=4），
        // 秘密随 wire 走；RPC 完成后零化槽（成败两路径都不留明文）。engine 侧解析
        // 同形状（`CredentialPackage`，version=1）并就地零化 wire 副本。
        request.secret_payload = secret_payload.as_bytes().to_vec();
        let outcome = self.client.apply_tunnel(request).await.map_err(map_status);
        secret_payload.clear();
        outcome.map(tonic::Response::into_inner)
    }

    async fn stop_tunnel(
        &mut self,
        request: StopTunnelRequest,
    ) -> Result<StopTunnelReply, GrpcClientError> {
        let resp = self.client.stop_tunnel(request).await.map_err(map_status)?;
        Ok(resp.into_inner())
    }

    async fn get_operation(
        &mut self,
        request: GetOperationRequest,
    ) -> Result<GetOperationReply, GrpcClientError> {
        let resp = self.client.get_operation(request).await.map_err(map_status)?;
        Ok(resp.into_inner())
    }

    async fn observe_owned_state(
        &mut self,
        request: ObserveOwnedStateRequest,
    ) -> Result<ObserveOwnedStateReply, GrpcClientError> {
        let resp = self
            .client
            .observe_owned_state(request)
            .await
            .map_err(map_status)?;
        Ok(resp.into_inner())
    }

    async fn keep_alive(
        &mut self,
        request: KeepAliveRequest,
    ) -> Result<KeepAliveReply, GrpcClientError> {
        let resp = self.client.keep_alive(request).await.map_err(map_status)?;
        Ok(resp.into_inner())
    }

    async fn ensure_owner_lease(&mut self) -> Result<(), GrpcClientError> {
        self.establish_owner_lease().await
    }

    async fn stream_connect_status(
        &mut self,
    ) -> Result<EngineStatusEventStream, GrpcClientError> {
        use tokio_stream::StreamExt;
        // 真实通道 = StreamConnectStatus（R1w 独立 status 通道，非 StreamLogs——日志
        // 已退役为纯输出，绝不回流状态）。丢弃无法归一化的事件（空 operation_id /
        // 未覆盖的 coarse 分支），EOF 即断线（调用方判据）。
        let stream = self
            .client
            .stream_connect_status(StreamConnectStatusRequest {})
            .await
            .map_err(map_status)?
            .into_inner();
        let normalized = stream.filter_map(|ev| ev.ok().and_then(connect_status_from_wire));
        Ok(Box::pin(normalized))
    }

    async fn stream_stats(
        &mut self,
        sample_interval_ms: u32,
    ) -> Result<StatsEventStream, GrpcClientError> {
        use tokio_stream::StreamExt;
        // 真实通道 = StreamStats（P5-a 契约）；丢弃 transport 错误项，EOF 即断线。
        // 注意：inherent `stream_stats` 在此优先于 trait 方法解析（具体类型方法
        // 遮蔽 trait 方法），取到的是 client passthrough（raw `Streaming<StatsEvent>`）。
        let stream = self.stream_stats(sample_interval_ms).await?;
        let normalized = stream.filter_map(|ev| ev.ok());
        Ok(Box::pin(normalized))
    }

    async fn stream_logs(
        &mut self,
        resume_tick: u64,
    ) -> Result<LogEventStream, GrpcClientError> {
        // 真实通道 = StreamLogs（产品日志通道）；元素为 `Result<LogEvent, Status>`
        // （transport 错误项由下游 [`crate::log_aggregator::ingest_engine_stream`]
        // 判为 `StreamError` → 转发器退避重连）。聚合-only 消费：下游 ingest 只落盘，
        // 绝不回流状态（D3 铁律——R1 已把日志→状态归一化退役）。
        let stream = self.stream_logs(resume_tick).await?;
        Ok(Box::pin(stream))
    }

    async fn service_manage(
        &mut self,
        request: ServiceManageRequest,
    ) -> Result<ServiceManageReply, GrpcClientError> {
        let resp = self.client.service_manage(request).await.map_err(map_status)?;
        Ok(resp.into_inner())
    }

    async fn respond_interaction(
        &mut self,
        _response: InteractionResponse,
    ) -> Result<OperationReply, GrpcClientError> {
        // engine 冻结 wire 无 interaction RPC（HostLeaseMessage/HelperControl 均无交互
        // 变体）；显式 typed 拒绝而非静默丢弃——P5 补 wire（InteractionResponse 落点）
        // 后替换为真实转发。
        Err(GrpcClientError::Rpc(
            Code::Unimplemented,
            "engine has no interaction RPC on frozen wire (P5)".to_string(),
        ))
    }

    async fn retry_obligation(
        &mut self,
        _request: ReconcileRequest,
    ) -> Result<GetOperationReply, GrpcClientError> {
        // engine 冻结 wire 无 Reconcile RPC / 义务模型；显式 typed 拒绝——host 保留
        // 观测 disposition 作为回执，义务模型落地（P3-c2）后替换为真实重试派发。
        Err(GrpcClientError::Rpc(
            Code::Unimplemented,
            "engine obligation model not on frozen wire (P3-c2 seam)".to_string(),
        ))
    }
}

/// 后台掉线监视：周期性探测 engine（`observe_owned_state`），把存活状态推给
/// `liveness_tx`。任何 gRPC 响应（含业务错误）视为存活；仅 transport 类失败或超时
/// 视为掉线。
async fn engine_liveness_monitor(channel: Channel, liveness_tx: watch::Sender<bool>) {
    let mut ticker = tokio::time::interval(LIVENESS_PERIOD);
    loop {
        ticker.tick().await;
        let mut probe = HelperControlClient::new(channel.clone());
        let request = ObserveOwnedStateRequest { lookup_key: None };
        let outcome =
            tokio::time::timeout(LIVENESS_TIMEOUT, probe.observe_owned_state(request)).await;
        let healthy = match outcome {
            Ok(Ok(_)) => true,
            Ok(Err(s)) => !is_lost_status(&s),
            Err(_) => false,
        };
        // 所有 Receiver 被丢弃（client 已 drop）→ 退出监视，避免任务泄漏。
        if liveness_tx.send(healthy).is_err() {
            return;
        }
    }
}

/// R2 keepalive 就绪探活：拨号稳定服务管道 → 发送一条 `KeepAlive` RPC → 丢弃 client。
///
/// 用于判定服务 engine 是否已具备**业务响应能力**（不依赖 SCM running；keepalive 在
/// service 态只做探活返回，无业务语义）。`connect_engine_service_channel` 内部的有界重试
/// （`dial_control_pipe_with_retry`，30×100ms）已覆盖服务刚启动未绑管道的竞窗；
/// 返回 `Ok(())` = keepalive 已回复（engine gRPC 服务实际响应）。
///
/// 与 [`EngineControlGrpcClient::connect_service`] 的差异：不建立 owner lease、不持有
/// bidi 流（无 `service_mode`/`ServiceLease`）、不起 liveness 监视——探活是一次性拨号 +
/// 一条 RPC 即丢弃。
///
/// # Errors
/// 拨号 / 身份 / PSK / channel 构建失败 → `GrpcClientError::Transport`；RPC 超时 →
/// `Timeout`；engine 掉线 / 拒绝 → `ConnectionLost` / `Rpc`。
pub async fn probe_service_engine(
    pipe_name: &str,
    expected_user_sid: &str,
    psk: &[u8],
    per_attempt_timeout: Duration,
) -> Result<(), GrpcClientError> {
    let (channel, _peer) = connect_engine_service_channel(pipe_name, expected_user_sid, psk)
        .await
        .map_err(GrpcClientError::Transport)?;
    let mut client = HelperControlClient::new(channel);
    // 探活 tick：keepalive 在 service 态只做探活返回（monotonic_tick 仅回显）。
    let request = KeepAliveRequest { monotonic_tick: 0 };
    tokio::time::timeout(per_attempt_timeout, client.keep_alive(request))
        .await
        .map_err(|_| GrpcClientError::Timeout)?
        .map_err(map_status)?;
    Ok(())
}

/// 构造 `HelperControl.ServiceManage` 的 `query` 请求（纯函数；S3-B）。
///
/// Tier 2 v1 只落 `query` action（未来 action 由 proto oneof 演化承接）。
#[must_use]
pub fn service_manage_query_request() -> ServiceManageRequest {
    ServiceManageRequest {
        action: Some(service_manage_request::Action::Query(ServiceSelfQuery {})),
    }
}

/// 从 `ServiceManageReply` 提取 engine 深度自述（`self_report` 字段；reply 缺 report → None）。
#[must_use]
pub fn service_report_from_reply(reply: ServiceManageReply) -> Option<ServiceSelfReport> {
    reply.self_report
}

/// S3-B：查询 engine 内部深度自述（Tier 2 零 UAC 通道，健康加深的探针）。
///
/// 复用 [`probe_service_engine`] 的拨号 + PSK 握手通道
/// （[`connect_engine_service_channel`]：`dial_control_pipe_with_retry` +
/// `service_peer_handshake`），调 `HelperControl.ServiceManage`（`query` action），返回
/// engine 自述报告。
///
/// **探针失败保守**：拨号 / 身份 / PSK / channel 构建 / RPC 拒绝 / 超时 → 一律返回
/// `None`，**不抛错**——调用方保留 SCM 派生结果（不把探针失败当引擎失败）。
#[must_use]
pub async fn query_service_self(
    pipe_name: &str,
    expected_user_sid: &str,
    psk: &[u8],
    per_attempt_timeout: Duration,
) -> Option<ServiceSelfReport> {
    let (channel, _peer) = connect_engine_service_channel(pipe_name, expected_user_sid, psk)
        .await
        .ok()?;
    let mut client = HelperControlClient::new(channel);
    let request = service_manage_query_request();
    let reply = tokio::time::timeout(per_attempt_timeout, client.service_manage(request))
        .await
        .ok()?
        .ok()?;
    service_report_from_reply(reply.into_inner())
}

/// 拉起 core 侧 KeepAlive 心跳 tick 任务（P2 有界存留）：按 `period`（默认
/// [`KEEPALIVE_PERIOD`] = 10s）周期发 `KeepAlive` 到 engine——engine 侧刷新
/// `last_heartbeat`，15s 未收到即自清理+自退出（hung-core / 进程句柄路径故障兜底）。
///
/// 持共享 [`EngineSlot`]（P3 崩溃自愈换点：respawn 换入新 engine 后，本任务下一 tick
/// 即从槽取新 engine 续心跳，无需重拉任务）。服务路由换入 service engine 后，当前
/// service engine 不收 KeepAlive；若初始 oneshot 仍被槽保留以支持卸载后的恢复，则
/// ticker 继续维护这个隐藏的 oneshot，避免它自己的 watchdog 误判 Core 已失联并关闭
/// admission。调用方（`serve_kernel_control_pipe` 拉起，`CoreRuntime` 停机先中止）须在
/// `shutdown_core` 前中止本任务，释放 engine client
/// 引用。传输类失败（engine 掉线）best-effort：继续 tick，engine 恢复后自动续心跳——
/// 链接终止由 liveness 监视/状态转发器驱动（本任务不改变业务状态）。
#[must_use]
pub fn spawn_keepalive_ticker(
    slot: EngineSlot,
    engine_kind: Arc<AtomicU8>,
    period: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        let mut tick: u64 = 0;
        loop {
            ticker.tick().await;
            let kind = engine_kind.load(Ordering::Relaxed);
            if !matches!(
                kind,
                ENGINE_KIND_AUTO | ENGINE_KIND_SERVICE | ENGINE_KIND_ONESHOT
            ) {
                continue;
            }
            tick = tick.saturating_add(1);
            let request = KeepAliveRequest { monotonic_tick: tick };
            let current = slot.current().await;
            let initial = slot.initial();
            // service engine 的业务生命周期不依赖 core KeepAlive；但当前架构为了
            // 卸载后无重启地恢复 oneshot，仍保留初始 oneshot client。服务/auto 路由下
            // 若当前已换成 service，就维护这个保留 client；当前仍是初始 oneshot 时
            // 直接维护当前 client。切回 oneshot 后维护槽内当前 engine（包括 crash
            // recovery 换入的新 oneshot）。
            let engine = if kind == ENGINE_KIND_ONESHOT {
                current
            } else if Arc::ptr_eq(&current, &initial) {
                current
            } else {
                initial
            };
            let mut guard = engine.lock().await;
            // best-effort：失败（engine 掉线/超时）不 panic、不重试风暴——下一个周期
            // 再发；engine 存活时下一个 KeepAlive 刷新心跳计时。
            let _ = guard.keep_alive(request).await;
        }
    })
}

// ---------------------------------------------------------------------------
// 单元测试：hand_off_request 的 move + zeroize 语义、map_status 分类、
// spawn_keepalive_ticker 周期发送。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// `hand_off_request` 必须把请求 move 交给 wire（调用方 `request` 被 Default 化，
    /// secret 不再驻留），并零化 one-shot 源。
    #[test]
    fn hand_off_moves_request_and_zeroizes_secret() {
        let mut secret = ClearableSecret::new(b"one-shot-credential");
        let mut request = ApplyTunnelRequest {
            lookup_key: None,
            plan: None,
            request_digest: b"secret-on-wire".to_vec(),
            // P3-b1: proto added one-shot secret_payload (tag=4); the host's real
            // credential hand-off lands in P3-b2. Keep the literal compile-valid here.
            secret_payload: Vec::new(),
        };

        let wire_request = hand_off_request(&mut request, &mut secret);

        // wire 请求拿到完整 secret（move，非空）。
        assert_eq!(wire_request.request_digest, b"secret-on-wire");
        // 调用方 request 已被 Default 化（secret 移出）。
        assert!(request.request_digest.is_empty(), "request 必须被清空");
        // one-shot 源已零化。
        assert!(
            secret.as_bytes().iter().all(|&b| b == 0),
            "secret 必须已零化"
        );
    }

    /// `map_status`：transport 类 code → ConnectionLost；DeadlineExceeded → Timeout。
    #[test]
    fn map_status_classifies_codes() {
        assert_eq!(
            map_status(Status::unavailable("engine gone")),
            GrpcClientError::ConnectionLost
        );
        assert_eq!(
            map_status(Status::deadline_exceeded("slow engine")),
            GrpcClientError::Timeout
        );
        assert!(matches!(
            map_status(Status::invalid_argument("bad req")),
            GrpcClientError::Rpc(Code::InvalidArgument, _)
        ));
    }

    /// S3-B：`service_manage_query_request` 构造 `ServiceManage.query` action（Tier 2 v1
    /// 只落 query；请求无其它字段）。
    #[test]
    fn service_manage_query_request_builds_query_action() {
        let request = service_manage_query_request();
        assert!(
            matches!(
                request.action,
                Some(service_manage_request::Action::Query(ServiceSelfQuery {}))
            ),
            "Tier 2 v1 只落 query action"
        );
    }

    /// S3-B：`service_report_from_reply` 映射——reply 带 report → Some；缺 report → None。
    #[test]
    fn service_report_from_reply_maps_some_and_none() {
        let report = ServiceSelfReport {
            control_plane_ready: true,
            psk_present: true,
            connection_mode: "service".to_string(),
            runtime_epoch: vec![0u8; 16],
            authority_fence: None,
        };
        let reply = ServiceManageReply {
            self_report: Some(report.clone()),
        };
        assert_eq!(
            service_report_from_reply(reply),
            Some(report),
            "reply 带 report → Some"
        );
        assert_eq!(
            service_report_from_reply(ServiceManageReply { self_report: None }),
            None,
            "reply 缺 report → None"
        );
    }

    /// S3-B：`query_service_self` 失败保守——拨号不到（无 server）→ `None`（不抛错，
    /// 调用方保留 SCM 派生）。镜像 `dial_fails_closed_when_no_server` 的 absent-pipe
    /// 探测方式。
    #[tokio::test]
    async fn query_service_self_returns_none_when_dial_fails() {
        let pipe = format!(r"\\.\pipe\exv-query-self-absent-{}", std::process::id());
        let report = query_service_self(
            &pipe,
            "S-1-5-18",
            &[0u8; 32],
            Duration::from_millis(200),
        )
        .await;
        assert!(
            report.is_none(),
            "拨号失败必须保守返回 None（探针失败 ≠ 引擎失败）"
        );
    }

    /// service engine 以 LocalSystem 运行时，owner principal 必须仍由 core 用户 SID
    /// 派生，不能误用服务端的 SYSTEM SID。
    #[test]
    fn owner_principal_is_bound_to_core_sid_not_service_sid() {
        let core = owner_principal_digest("S-1-5-21-core");
        let system = owner_principal_digest("S-1-5-18");
        assert_ne!(core, system);
        assert_eq!(core.len(), 32);
    }

    /// 16-byte 测试 operation id。
    fn uuid16(n: u8) -> Vec<u8> {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        bytes[1] = 0x42;
        bytes.to_vec()
    }

    fn wire_status_event(
        operation_id: Vec<u8>,
        connect_phase: ConnectPhase,
        coarse_phase: StatsPhase,
        error: Option<VpnError>,
    ) -> ConnectStatusEvent {
        ConnectStatusEvent {
            operation_id,
            connect_phase: connect_phase as i32,
            coarse_phase: coarse_phase as i32,
            error,
            session_established_at_ms: 1_700_000_000_123,
        }
    }

    /// `connect_status_from_wire`（R1）：按 coarse 分支归一化——Connecting →
    /// Progress（带细粒度 ConnectPhase）；Connected → Connected；Failed → Failed
    /// （携带 err）；Idle → Stopped；空 operation_id / 未覆盖 coarse → `None`。
    #[test]
    fn connect_status_from_wire_maps_coarse_branches() {
        let id = uuid16(3);
        assert_eq!(
            connect_status_from_wire(wire_status_event(
                id.clone(),
                ConnectPhase::ApplyingPlatformTunnel,
                StatsPhase::Connecting,
                None,
            )),
            Some(EngineStatusEvent::Progress {
                operation_id: id.clone(),
                connect_phase: ConnectPhase::ApplyingPlatformTunnel,
            })
        );
        assert_eq!(
            connect_status_from_wire(wire_status_event(
                id.clone(),
                ConnectPhase::StartingDataPlane,
                StatsPhase::Connected,
                None,
            )),
            Some(EngineStatusEvent::Connected {
                operation_id: id.clone(),
                session_established_at_ms: Some(1_700_000_000_123),
            })
        );
        let error = VpnError {
            code: 1,
            stage: 8,
            certainty: 0,
            retry: 1,
            subject: None,
            resource: None,
            native: None,
        };
        assert_eq!(
            connect_status_from_wire(wire_status_event(
                id.clone(),
                ConnectPhase::ApplyingPlatformTunnel,
                StatsPhase::Failed,
                Some(error.clone()),
            )),
            Some(EngineStatusEvent::Failed {
                operation_id: id.clone(),
                error,
            })
        );
        assert_eq!(
            connect_status_from_wire(wire_status_event(
                id.clone(),
                ConnectPhase::Unspecified,
                StatsPhase::Idle,
                None,
            )),
            Some(EngineStatusEvent::Stopped {
                operation_id: id.clone()
            })
        );
        // 空 operation_id / 未覆盖 coarse → None（无关联操作或非 R1w 状态分支）。
        assert_eq!(
            connect_status_from_wire(wire_status_event(
                vec![],
                ConnectPhase::Unspecified,
                StatsPhase::Connected,
                None,
            )),
            None
        );
        assert_eq!(
            connect_status_from_wire(wire_status_event(
                id,
                ConnectPhase::Unspecified,
                StatsPhase::Stopping,
                None,
            )),
            None
        );
    }

    /// 记录 `keep_alive` 调用的 fake engine（ticker 周期发送的观测点）。
    #[derive(Default)]
    struct TickerEngine {
        /// 收到的心跳序号（monotonic_tick）。
        keeps: std::sync::Mutex<Vec<u64>>,
    }

    #[tonic::async_trait]
    impl KernelEngineControl for TickerEngine {
        async fn keep_alive(
            &mut self,
            request: KeepAliveRequest,
        ) -> Result<KeepAliveReply, GrpcClientError> {
            self.keeps.lock().unwrap().push(request.monotonic_tick);
            Ok(KeepAliveReply {
                monotonic_tick: request.monotonic_tick,
            })
        }

        async fn ensure_owner_lease(&mut self) -> Result<(), GrpcClientError> {
            Ok(())
        }

        async fn service_manage(
            &mut self,
            _request: ServiceManageRequest,
        ) -> Result<ServiceManageReply, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in ticker test".to_string(),
            ))
        }

        async fn apply_connect(
            &mut self,
            _request: ApplyTunnelRequest,
            secret_payload: &mut ClearableSecret,
        ) -> Result<ApplyTunnelReply, GrpcClientError> {
            secret_payload.clear();
            Ok(ApplyTunnelReply { result: None })
        }

        async fn stop_tunnel(
            &mut self,
            _request: StopTunnelRequest,
        ) -> Result<StopTunnelReply, GrpcClientError> {
            Ok(StopTunnelReply { result: None })
        }

        async fn get_operation(
            &mut self,
            _request: GetOperationRequest,
        ) -> Result<GetOperationReply, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in ticker test".to_string(),
            ))
        }

        async fn observe_owned_state(
            &mut self,
            _request: ObserveOwnedStateRequest,
        ) -> Result<ObserveOwnedStateReply, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in ticker test".to_string(),
            ))
        }

        async fn stream_connect_status(
            &mut self,
        ) -> Result<EngineStatusEventStream, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in ticker test".to_string(),
            ))
        }

        async fn stream_stats(
            &mut self,
            _sample_interval_ms: u32,
        ) -> Result<StatsEventStream, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in ticker test".to_string(),
            ))
        }

        async fn stream_logs(
            &mut self,
            _resume_tick: u64,
        ) -> Result<LogEventStream, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in ticker test".to_string(),
            ))
        }

        async fn respond_interaction(
            &mut self,
            _response: InteractionResponse,
        ) -> Result<OperationReply, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in ticker test".to_string(),
            ))
        }

        async fn retry_obligation(
            &mut self,
            _request: ReconcileRequest,
        ) -> Result<GetOperationReply, GrpcClientError> {
            Err(GrpcClientError::Rpc(
                tonic::Code::Unimplemented,
                "not in ticker test".to_string(),
            ))
        }
    }

    /// 让 paused 时间下的被唤醒任务运行若干次（advance 后 ticker 需要被 poll 才能 send）。
    async fn pump() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    /// `spawn_keepalive_ticker`（P2）：按周期（默认 10s）发 KeepAlive，序号严格递增。
    #[tokio::test(start_paused = true)]
    async fn keepalive_ticker_sends_every_period() {
        // 持有具体类型 Arc（断言读取）与 trait 对象 Arc（ticker 调用）——两者共享同一
        // Mutex（`Arc<Mutex<T>>` → `Arc<Mutex<dyn KernelEngineControl>>` unsizing）。
        let typed = Arc::new(tokio::sync::Mutex::new(TickerEngine::default()));
        let engine: Arc<tokio::sync::Mutex<dyn KernelEngineControl>> = typed.clone();
        let slot = EngineSlot::new(engine);
        let kind = Arc::new(AtomicU8::new(ENGINE_KIND_ONESHOT));
        let handle = spawn_keepalive_ticker(slot, kind, Duration::from_secs(10));
        // interval 首 tick 立即发送（t=0 即 1 次心跳）。
        pump().await;
        assert_eq!(
            typed.lock().await.keeps.lock().unwrap().len(),
            1,
            "interval 首 tick 立即发送一次心跳"
        );
        // 推进一个周期 → 第 2 次心跳；再推进 → 第 3 次。
        tokio::time::advance(Duration::from_secs(10)).await;
        pump().await;
        assert_eq!(
            typed.lock().await.keeps.lock().unwrap().len(),
            2,
            "推进 10s → 第 2 次心跳"
        );
        tokio::time::advance(Duration::from_secs(10)).await;
        pump().await;
        assert_eq!(
            typed.lock().await.keeps.lock().unwrap().len(),
            3,
            "推进 20s → 第 3 次心跳"
        );
        // 序号严格递增（1,2,3）——engine 侧据此刷新单调计时。
        let ticks = typed.lock().await.keeps.lock().unwrap().clone();
        assert_eq!(ticks, vec![1, 2, 3], "心跳序号必须严格递增");
        handle.abort();
    }

    /// 服务 engine 不依赖 core KeepAlive；服务路由切换后只维护保留的初始 oneshot，
    /// 切回 oneshot 后 ticker 恢复向当前 oneshot 发送。
    #[tokio::test(start_paused = true)]
    async fn keepalive_ticker_skips_service_engine() {
        let original_typed = Arc::new(tokio::sync::Mutex::new(TickerEngine::default()));
        let original: Arc<tokio::sync::Mutex<dyn KernelEngineControl>> = original_typed.clone();
        let service_typed = Arc::new(tokio::sync::Mutex::new(TickerEngine::default()));
        let service_engine: Arc<tokio::sync::Mutex<dyn KernelEngineControl>> = service_typed.clone();
        let slot = EngineSlot::new(original);
        slot.swap(service_engine).await;
        let kind = Arc::new(std::sync::atomic::AtomicU8::new(ENGINE_KIND_SERVICE));
        let handle = spawn_keepalive_ticker(slot.clone(), kind.clone(), Duration::from_secs(10));

        pump().await;
        tokio::time::advance(Duration::from_secs(20)).await;
        pump().await;
        assert!(
            service_typed.lock().await.keeps.lock().unwrap().is_empty(),
            "service engine 不应收到周期性 KeepAlive"
        );
        assert_eq!(
            original_typed.lock().await.keeps.lock().unwrap().len(),
            3,
            "服务路由仍需维护保留的初始 oneshot，避免其心跳 watchdog 误杀 Core admission"
        );

        // 真实卸载路径会在记录 oneshot 类型前先把 EngineSlot 切回初始 oneshot；
        // 测试也复现这一顺序，确保切回后心跳目标不是已经停止的 service client。
        let initial = slot.initial();
        slot.swap(initial).await;
        kind.store(ENGINE_KIND_ONESHOT, std::sync::atomic::Ordering::Relaxed);
        // 切换恰好发生在 interval 边界时，先推进一个完整周期再多推进一拍，
        // 避免把 Tokio 的 paused-clock 唤醒顺序误判成业务行为。
        tokio::time::advance(Duration::from_secs(11)).await;
        pump().await;
        let ticks = original_typed.lock().await.keeps.lock().unwrap().clone();
        assert!(
            ticks.len() >= 4,
            "切回 oneshot 后下一拍恢复 KeepAlive，序号继续单调递增：{ticks:?}"
        );
        assert_eq!(&ticks[..3], &[1, 2, 3]);
        assert_eq!(ticks[3], 4);
        handle.abort();
    }
}
