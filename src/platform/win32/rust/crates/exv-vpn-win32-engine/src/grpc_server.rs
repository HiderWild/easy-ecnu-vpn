// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// P1-b: the engine's HelperControl tonic gRPC server — the PRODUCT control plane
// (WIRE DECISION: proto gRPC is the sole wire authority; engine_protocol.rs JSON
// frame is legacy/acceptance-only). This module implements the generated
// `helper_control_server::HelperControl` trait, replacing the self-developed
// engine_protocol command loop as the product channel while REUSING the existing
// win32-engine business logic:
//   * `owner_lease::OwnerLeaseManager` — J52 per-connection ownership-token slot;
//   * `mutation_ingress::MutationIngress` — W15 sync-before-reply admission gate;
//   * `exv_vpn_resource::operation::AdmissionIndex` — J51 durable admission sequencer;
//   * `exv_vpn_resource::authority` — PeerContext / PeerCapability / ConnectionBinding;
//   * `exv_vpn_local_rpc::kernel::kernel_request_to_operation` — wire→domain binding
//     anchored to the AUTHENTICATED peer principal only.
//
// Transport-layer peer authentication (peer_auth/pipe_security) is a separate
// concern in `crate::grpc_transport`; every handler here FAILS CLOSED when a
// request does not carry the transport-verified peer extension, so no mutation
// ever dispatches for an unverified connection.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use exv_vpn_domain::identity::{
    canonical_lookup_digest, EffectId, OperationLookupKey, OperationLookupKeyDigest,
    OperationMethod, OwnershipVersion, PrincipalDigest, RequestDigest, ResourceIdentityDigest,
    RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, JournalRevision, MonotonicTick,
    PlatformAuthorityInstanceId,
};
use exv_vpn_local_rpc::kernel::{kernel_request_to_operation, KernelRequest};
use exv_vpn_resource::admission::{
    AppliedFingerprint, AuthorizationSubject, MutationAdmitted, MutationKind, ObligationSeed,
};
use exv_vpn_resource::authority::{ConnectionBinding, PeerContext};
use exv_vpn_resource::delivery::AckOutcome;
use exv_vpn_resource::operation::{AdmissionIndex, AdmissionOutcome, MutationAdmissionInput};
use exv_vpn_wire::convert;
use exv_vpn_wire::generated;
use generated::helper_control_server::HelperControl;
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tonic::codegen::http::Extensions;
use tonic::codegen::{async_trait, tokio_stream};
use tonic::{Request, Response, Status, Streaming};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::grpc_transport::NamedPipeConnectInfo;
use crate::heartbeat::HeartbeatWatch;
use crate::log_sink::{LogLevel, LogSink};
use crate::mutation_ingress::MutationIngress;
use crate::owner_lease::{LeaseIssue, OwnerLeaseManager};
use crate::stats::StatsPublisher;
use crate::status::{StatusEvent, StatusPublisher};
use crate::secret_payload::{
    EngineCredentials, SecretPayloadError, SECRET_PAYLOAD_VERSION,
};
use crate::tunnel_runtime::{ApplyContext, FakeTunnelRuntime, TunnelRuntime};

/// The capability lifetime for a freshly bound operation capability (monotonic ms).
const CAPABILITY_TTL_MS: u64 = 30_000;

/// The engine's connection-handling mode (S3/D7). Decides whether the engine releases
/// the connection-bound owner when the `MaintainOwnerLease` stream EOFs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    /// oneshot（默认）：core 生命周期。Owner 一次性握手后跨 stream 保持，直到显式
    /// `ReleaseLease`——stream EOF **不**释放 owner（host 侧一次性握手后随即关流）。
    Oneshot,
    /// service（SCM 常驻）：连续 accept，每次连接独立 owner。连接 EOF → 释放
    /// connection-bound owner + terminate_connection + ownership_version++（D7——旧 core
    /// 断线后新 core 可握手接管；仅隧道/admission 持久状态保留）。
    Service,
}

/// The wire `EffectCertainty::Applied` discriminant (common.proto).
const EFFECT_CERTAINTY_APPLIED: i32 = 2;
/// The wire `ErrorCode::Unauthorized` discriminant (common.proto).
const ERROR_CODE_UNAUTHORIZED: i32 = 15;
/// The wire `ErrorStage::Ingress` discriminant (common.proto).
const ERROR_STAGE_INGRESS: i32 = 1;
/// The wire `RetryAdvice::DoNotRetry` discriminant (common.proto).
const RETRY_ADVICE_DO_NOT_RETRY: i32 = 1;

/// A monotonic clock (P1-b minimal; P3 binds to the domain `Clock` port).
#[derive(Clone)]
pub struct MonotonicClock {
    start: std::time::Instant,
}

impl MonotonicClock {
    /// A clock started at construction; `now()` is the elapsed milliseconds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }

    /// The current monotonic tick (elapsed milliseconds since construction).
    #[must_use]
    pub fn now(&self) -> MonotonicTick {
        let ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        MonotonicTick::try_from(ms).expect("monotonic tick mints")
    }

    /// A tick `ms` milliseconds in the future (capability expiry deadline).
    #[must_use]
    pub fn later_by(&self, ms: u64) -> MonotonicTick {
        let now = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        MonotonicTick::try_from(now.saturating_add(ms)).expect("monotonic deadline mints")
    }
}

/// The authenticated owner session established by the MaintainOwnerLease handshake.
struct OwnerSession {
    /// The authenticated peer context (principal + connection binding).
    peer: PeerContext,
    /// The verified connection binding anchoring the lease.
    connection: ConnectionBinding,
}

/// The mutating state of the HelperControl endpoint.
struct HelperControlCore {
    /// J52 per-connection ownership-token delivery slot manager (reused business logic).
    leases: OwnerLeaseManager,
    /// W15 sync-before-reply mutation ingress gate (reused business logic).
    ingress: MutationIngress,
    /// J51 durable admission sequencer (reused; mints watermarks + operation state).
    admissions: AdmissionIndex,
    /// The authority epoch of this helper instance (raw, for the wire fence).
    authority_epoch: u64,
    /// The platform authority instance id (16-byte uuid, minted once per helper).
    authority_instance: [u8; 16],
    /// The admission watermark counter (mirrors the J51 sequencer; wire fence only).
    watermark: u64,
    /// The journal revision counter (no real journal in this phase; wire fence only).
    journal_revision: u64,
    /// The current ownership version (boot = 1; a release advances it).
    ownership_version: u64,
    /// The authenticated owner session, once the handshake establishes it.
    owner: Option<OwnerSession>,
    /// The currently applied tunnel plan, if any.
    applied_tunnel: Option<exv_vpn_domain::ports::TunnelPlan>,
    /// In-flight async apply operations keyed by 16-byte operation_id (R2/P2-1): the
    /// runtime terminal (Connected/Failed) is delivered out-of-band on the status
    /// channel; the internal terminal observer consumes it and records the terminal in
    /// `terminals` so GetOperation(apply) resolves instead of lying Pending forever.
    /// Cleared on StopTunnel / ReleaseLease / next ApplyTunnel.
    pending_apply: HashMap<Vec<u8>, PendingApply>,
    /// Terminal operation outcomes for completed mutations, keyed by canonical lookup digest.
    terminals: HashMap<OperationLookupKeyDigest, generated::OperationTerminal>,
}

/// Bookkeeping for one in-flight async apply (R2/P2-1): enough to synthesize the
/// `OperationTerminal` from the runtime's Connected/Failed status event.
struct PendingApply {
    /// The bound external operation key (domain; canonical digest keys `terminals`).
    key: OperationLookupKey,
    /// The wire lookup key (receipt journal identity / error subject).
    wire_key: generated::OperationLookupKey,
    /// The canonical input digest (mints the wire receipt).
    canonical_input_digest: [u8; 32],
    /// The apply's effect uuid (mints the wire receipt).
    effect_uuid: Uuid,
}

/// The engine's internal deep self-report seam (S3/Tier 2): facts the engine knows
/// that the host cannot observe from SCM alone. `ServiceManage.query` reads it.
/// Health/display input only — NEVER authorization material.
pub struct ServiceSelfState {
    /// service 模式：accept-loop 建管 + 报告 ready 时置 true（oneshot 缺省 true——
    /// 能答 RPC 即控制面在）。
    pub control_plane_ready: Arc<AtomicBool>,
    /// service 模式：启动时 PSK 文件读入（main.rs 注入）；oneshot 缺省 false。
    pub psk_present: bool,
}

/// The engine's HelperControl gRPC endpoint (the product control plane).
pub struct HelperControlService {
    core: Arc<Mutex<HelperControlCore>>,
    /// The authority epoch minted at boot (matches the composed helper's authority).
    authority_epoch: u64,
    /// The runtime epoch minted at boot (identity of this helper instance).
    runtime_epoch: RuntimeEpoch,
    /// The runtime epoch as wire bytes (16 bytes).
    runtime_epoch_bytes: [u8; 16],
    /// The monotonic clock for capability expiry.
    clock: MonotonicClock,
    /// The engine's structured log sink: StreamLogs push + raw-dump fallback (P2-b).
    log: Arc<LogSink>,
    /// The engine's statistics publisher: StreamStats push + data-plane registry (P5-a).
    stats: Arc<StatsPublisher>,
    /// The engine's connect-status publisher: StreamConnectStatus push (R1w). An
    /// independent status channel — NEVER merged into StreamStats (stats stays pure
    /// counters); real data-plane status is driven by the tunnel runtime (R1b).
    status: Arc<StatusPublisher>,
    /// The real data-plane assembly runtime (R1b): ApplyTunnel runs the real
    /// login/CSTP/apply/data-plane assembly through it; StopTunnel tears it down.
    /// Injected seam — production wires [`crate::tunnel_runtime::RealTunnelRuntime`];
    /// tests inject [`crate::tunnel_runtime::FakeTunnelRuntime`].
    runtime: Arc<dyn TunnelRuntime>,
    /// P2 bounded-retention heartbeat watch: `KeepAlive` refreshes it; the engine
    /// bin's watchdog self-cleans + self-exits when it times out (hung-core /
    /// process-handle-failure backstop). Oneshot only — the service engine is
    /// unaffected (SCM lifecycle self-managed).
    heartbeat: Arc<HeartbeatWatch>,
    /// S3/D7: connection-handling mode. Service mode releases the connection-bound
    /// owner when the `MaintainOwnerLease` stream EOFs; oneshot keeps the one-shot
    /// owner across the stream close (host handshake-then-close flow).
    connection_mode: ConnectionMode,
    /// S3/Tier 2: the engine's internal deep self-report seam (`ServiceManage.query`
    /// reads it). Injected in service mode by `main.rs` (`with_service_self`); the
    /// oneshot/test default answers a trivially-ready report.
    service_self: Arc<ServiceSelfState>,
}

/// A 32-byte SHA-256 digest of `bytes`.
pub(crate) fn digest32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(bytes));
    out
}

/// A domain-tagged copy of `body` (`tag || body`), so distinct digest domains never collide.
fn tagged(tag: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + body.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(body);
    out
}

/// The wire fence for this helper, built from the core's current counters.
fn wire_fence(core: &HelperControlCore) -> generated::AuthorityFence {
    generated::AuthorityFence {
        authority_epoch: core.authority_epoch,
        platform_authority_instance_id: core.authority_instance.to_vec(),
        admission_watermark: core.watermark,
        journal_revision: core.journal_revision,
    }
}

/// A wire error with no external subject (owner-lost / lease-stream failures). These are
/// runtime-causal, not external-operation-causal (spec §10: 不得为 owner lost 伪造外部 OperationId).
fn wire_error_no_subject(detail: &str) -> generated::VpnError {
    tracing::warn!(detail, "helper control lease-stream error");
    generated::VpnError {
        code: ERROR_CODE_UNAUTHORIZED,
        stage: ERROR_STAGE_INGRESS,
        certainty: 0,
        retry: RETRY_ADVICE_DO_NOT_RETRY,
        subject: None,
        resource: None,
        native: None,
    }
}

/// The wire error for a failed mutation under an external lookup key.
///
/// Free-text diagnostic detail is logged locally but never placed on the wire
/// (spec §10: wire errors carry structured fields only; free-text stacks never travel).
fn wire_error(key: &generated::OperationLookupKey, code: i32, detail: &str) -> generated::VpnError {
    tracing::warn!(code, detail, "helper control operation failed");
    generated::VpnError {
        code,
        stage: ERROR_STAGE_INGRESS,
        certainty: 0,
        retry: RETRY_ADVICE_DO_NOT_RETRY,
        subject: Some(generated::ErrorSubject {
            subject: Some(generated::error_subject::Subject::External(key.clone())),
        }),
        resource: None,
        native: None,
    }
}

/// Run the W15 sync-before-reply gate + J51 admission for a mutation.
///
/// Returns the durable `MutationAdmitted` record. The W15 gate is NOT bypassed: the
/// `encode_record`/`decode_record` codec round-trip must recover an
/// `AdmissionRecord::Admitted` and the external key is registered for future `admit` calls.
/// (P3 wires the host-driven durable journal persistence; the gate semantics are real here.)
#[allow(clippy::too_many_arguments)]
fn admit_and_gate(
    core: &mut HelperControlCore,
    peer: &PeerContext,
    wire_key_bytes: &[u8],
    request_digest_raw: &[u8],
    key: &OperationLookupKey,
    request_digest: &RequestDigest,
    method: OperationMethod,
    subject: AuthorizationSubject,
    effect_id: EffectId,
) -> Result<MutationAdmitted, Status> {
    let canonical_input_digest =
        exv_vpn_domain::ports::CanonicalInputDigest::try_from(digest32(request_digest_raw))
            .expect("canonical input digest mints");
    let resource_identity = ResourceIdentityDigest::try_from(digest32(&tagged(
        b"resource",
        wire_key_bytes,
    )))
    .expect("resource identity mints");
    let precondition =
        AppliedFingerprint::try_from(digest32(&tagged(b"pre", wire_key_bytes)))
            .expect("precondition fingerprint mints");
    let desired = AppliedFingerprint::try_from(digest32(&tagged(b"post", wire_key_bytes)))
        .expect("desired fingerprint mints");
    let seed = ObligationSeed::try_from(digest32(&tagged(b"obligation", wire_key_bytes)))
        .expect("obligation seed mints");

    let input = MutationAdmissionInput {
        key: key.clone(),
        request_digest: request_digest.clone(),
        effect_id,
        initiator_identity_digest: peer.principal().clone(),
        canonical_input_digest,
        mutation_kind: MutationKind::External(method),
        ownership_version: OwnershipVersion::try_from(core.ownership_version)
            .expect("ownership version mints"),
        authorization_subject: subject,
        resource_identity,
        precondition_fingerprint: precondition,
        desired_applied_fingerprint: desired,
        canonical_obligation_seed: seed,
    };

    let record = match core.admissions.admit(input) {
        AdmissionOutcome::Admitted { record } => record,
        AdmissionOutcome::RejectedNoEffect { .. } => {
            return Err(Status::failed_precondition("mutation previously rejected"));
        }
        AdmissionOutcome::ClosedByAbsenceProof => {
            return Err(Status::failed_precondition("mutation closed by absence proof"));
        }
        AdmissionOutcome::IdempotencyConflict => {
            return Err(Status::failed_precondition("idempotency conflict"));
        }
    };

    // W15 sync-before-reply: the durable record must round-trip the codec and register
    // the external key before the reply is admitted.
    if !core.ingress.durable_before_reply(&record) {
        return Err(Status::internal("mutation admission not durable"));
    }
    let gate = core
        .owner
        .as_ref()
        .and_then(|owner| core.leases.lease(&owner.connection))
        .ok_or_else(|| Status::failed_precondition("no owner lease for gate"))?;
    core.ingress
        .admit(gate, key.clone(), request_digest.clone())
        .map_err(|e| Status::internal(format!("mutation ingress: {e}")))?;

    core.watermark = core.watermark.saturating_add(1);
    Ok(record)
}

impl HelperControlService {
    /// Build an endpoint with fresh boot identity (authority epoch 1, fresh runtime epoch,
    /// ownership version 1). The engine-startup slice threads the composed helper's epochs
    /// through the equivalent constructor once composition wiring lands.
    ///
    /// The default uses a null log sink (raw-dump disabled — test-safe, no files on disk)
    /// and a [`FakeTunnelRuntime`] (test double: emits the phase progression without real
    /// work). The PRODUCT composition wires the machine-dir sink AND the real runtime via
    /// [`Self::with_real_tunnel`] — the fake is a test-only default, never production.
    #[must_use]
    pub fn new() -> Self {
        Self::with_log_sink(Arc::new(LogSink::null()))
    }

    /// Build the endpoint with an explicit log sink (the engine's real log destination)
    /// and the **test** tunnel runtime (fake phase progression, no real work). Use for
    /// tests / back-compat; production MUST use [`Self::with_real_tunnel`].
    ///
    /// # Panics
    /// Panics if the boot identity epochs cannot be minted (infallible domain conversions).
    #[must_use]
    pub fn with_log_sink(log: Arc<LogSink>) -> Self {
        Self::with_tunnel_runtime(log, Arc::new(FakeTunnelRuntime::new()))
    }

    /// Build the endpoint with the real data-plane runtime (R1b): ApplyTunnel performs the
    /// real login/CSTP/apply/data-plane assembly in the engine process.
    ///
    /// `wintun_dll` / `adapter_name` / `config_dir` come from the engine startup args
    /// (`--dll`, `--adapter-name`, `--config-dir`). The machine-dir log sink is wired by
    /// the caller.
    #[must_use]
    pub fn with_real_tunnel(
        log: Arc<LogSink>,
        wintun_dll: PathBuf,
        adapter_name: String,
        config_dir: PathBuf,
        core_user_sid: Option<String>,
    ) -> Self {
        Self::with_tunnel_runtime(
            log,
            Arc::new(
                crate::tunnel_runtime::RealTunnelRuntime::new_with_config_dir_and_sid(
                    wintun_dll,
                    adapter_name,
                    config_dir,
                    core_user_sid,
                ),
            ),
        )
    }

    /// Build the endpoint with an explicit log sink AND an explicit tunnel runtime seam.
    ///
    /// # Panics
    /// Panics if the boot identity epochs cannot be minted (infallible domain conversions).
    #[must_use]
    pub fn with_tunnel_runtime(log: Arc<LogSink>, runtime: Arc<dyn TunnelRuntime>) -> Self {
        let authority_epoch = 1u64;
        let authority_instance = Uuid::new_v4();
        let runtime_uuid = Uuid::new_v4();
        let runtime_epoch = RuntimeEpoch::try_from(runtime_uuid).expect("runtime epoch mints");
        let fence = AuthorityFence {
            authority_epoch: AuthorityEpoch::try_from(authority_epoch).expect("epoch mints"),
            platform_authority_instance_id: PlatformAuthorityInstanceId::try_from(authority_instance)
                .expect("instance mints"),
            admission_watermark: AdmissionWatermark::try_from(0).expect("watermark mints"),
            journal_revision: JournalRevision::try_from(0).expect("revision mints"),
        };
        let core = Arc::new(Mutex::new(HelperControlCore {
            leases: OwnerLeaseManager::new(),
            ingress: MutationIngress::new(),
            admissions: AdmissionIndex::new(fence),
            authority_epoch,
            authority_instance: *authority_instance.as_bytes(),
            watermark: 0,
            journal_revision: 0,
            ownership_version: 1,
            owner: None,
            applied_tunnel: None,
            pending_apply: HashMap::new(),
            terminals: HashMap::new(),
        }));
        let status = Arc::new(StatusPublisher::new());
        // R2/P2-1：注册内部终态观察者——异步 apply 的运行时终态（Connected/Failed）
        // 经 status 通道发布时，把它写回 `core.terminals`（`GetOperation(apply)` 能答
        // 真实终态）。观察者与外部推送通道互不影响（推送仍由 core 唯一消费）。
        let observer_core = Arc::clone(&core);
        let terminal_observer = Arc::new(move |event: &StatusEvent| {
            use generated::StatsPhase;
            match event.coarse_phase {
                StatsPhase::Connected | StatsPhase::Failed => {
                    let mut core = observer_core.lock().expect("helper core lock");
                    let Some(pending) = core.pending_apply.remove(&event.operation_id) else {
                        return; // 未知/已清理的操作（stop 已接管）→ no-op。
                    };
                    let receipt = build_wire_receipt(
                        &core,
                        &pending.wire_key,
                        pending.canonical_input_digest,
                        pending.effect_uuid,
                    );
                    let terminal = if event.coarse_phase == StatsPhase::Connected {
                        generated::OperationTerminal {
                            result: Some(generated::operation_terminal::Result::Succeeded(
                                receipt,
                            )),
                        }
                    } else {
                        let error = event.error.clone().unwrap_or_else(|| {
                            wire_error(&pending.wire_key, ERROR_CODE_UNAUTHORIZED, "apply failed")
                        });
                        generated::OperationTerminal {
                            result: Some(generated::operation_terminal::Result::Failed(
                                generated::OperationFailed {
                                    receipt: Some(receipt),
                                    error: Some(error),
                                },
                            )),
                        }
                    };
                    Self::record_terminal(&mut core, &pending.key, terminal);
                }
                _ => {}
            }
        });
        status.set_terminal_observer(terminal_observer);
        Self {
            core,
            authority_epoch,
            runtime_epoch,
            runtime_epoch_bytes: *runtime_uuid.as_bytes(),
            clock: MonotonicClock::new(),
            log,
            stats: Arc::new(StatsPublisher::new()),
            status,
            runtime,
            heartbeat: Arc::new(HeartbeatWatch::new()),
            connection_mode: ConnectionMode::Oneshot,
            // Oneshot / test default: a runnable control plane answers RPCs, so
            // control_plane_ready starts true; psk_present is a service-mode fact.
            service_self: Arc::new(ServiceSelfState {
                control_plane_ready: Arc::new(AtomicBool::new(true)),
                psk_present: false,
            }),
        }
    }

    /// Switch this endpoint to **service** connection handling (S3/D7): the
    /// `MaintainOwnerLease` stream EOF releases the connection-bound owner +
    /// terminate_connection + ownership_version++. The service accept-loop
    /// (SCM 常驻) must construct the service this way; oneshot keeps the default.
    #[must_use]
    pub fn in_service_mode(mut self) -> Self {
        self.connection_mode = ConnectionMode::Service;
        self
    }

    /// Inject the service self-report seam (S3/Tier 2). Service mode shares one
    /// `Arc<AtomicBool>` between the accept-loop (`ServiceAcceptor` sets it true
    /// after the control pipe is created + `report_ready`) and this endpoint
    /// (`ServiceManage.query` reads it). `psk_present` is the service-mode PSK
    /// loaded at startup. Oneshot keeps the default (ready, no PSK).
    #[must_use]
    pub fn with_service_self(mut self, control_plane_ready: Arc<AtomicBool>, psk_present: bool) -> Self {
        self.service_self = Arc::new(ServiceSelfState {
            control_plane_ready,
            psk_present,
        });
        self
    }

    /// The engine's structured log sink (business points emit through it).
    #[must_use]
    pub fn log_sink(&self) -> &Arc<LogSink> {
        &self.log
    }

    /// The engine's statistics publisher (data plane writes counters through it;
    /// `StreamStats` opens the push channel). The data plane / composition wiring
    /// reaches the shared registry via [`StatsPublisher::registry`].
    #[must_use]
    pub fn stats_publisher(&self) -> Arc<StatsPublisher> {
        Arc::clone(&self.stats)
    }

    /// The engine's connect-status publisher (R1w): apply/stop (and later the R1b
    /// data plane) publish connect-status events through it; `StreamConnectStatus`
    /// opens the push channel. Independent from the stats publisher.
    #[must_use]
    pub fn status_publisher(&self) -> Arc<StatusPublisher> {
        Arc::clone(&self.status)
    }

    /// The P2 heartbeat watch: `KeepAlive` refreshes it; the engine bin's watchdog
    /// self-cleans + self-exits when it times out (hung-core / process-handle
    /// failure backstop).
    #[must_use]
    pub fn heartbeat_watch(&self) -> Arc<HeartbeatWatch> {
        Arc::clone(&self.heartbeat)
    }

    /// The data-plane tunnel runtime (the engine bin's heartbeat self-exit reuses
    /// its teardown path: cancel → teardown → post Idle → flush → exit).
    #[must_use]
    pub fn runtime_handle(&self) -> Arc<dyn TunnelRuntime> {
        Arc::clone(&self.runtime)
    }

    /// The authenticated transport peer for this request, or `Err(Status)` fail-closed.
    ///
    /// The peer context is derived ONLY from verified transport metadata (the
    /// `NamedPipeConnectInfo` attached by `crate::grpc_transport` after
    /// `peer_auth::PeerAuthenticator` succeeded); no client-supplied field can
    /// fabricate identity.
    fn transport_peer(&self, extensions: &Extensions) -> Result<(PeerContext, ConnectionBinding), Status> {
        let info = extensions
            .get::<NamedPipeConnectInfo>()
            .ok_or_else(|| Status::unauthenticated("transport peer not verified"))?;
        if !info.0.verified {
            return Err(Status::unauthenticated("transport peer not verified"));
        }
        let metadata = exv_vpn_resource::authority::VerifiedConnectionMetadata::try_from((
            info.0.principal.clone(),
            info.0.connection_digest.clone(),
        ))
        .map_err(|_| Status::unauthenticated("invalid transport identity"))?;
        let peer = PeerContext::try_from(metadata)
            .map_err(|_| Status::unauthenticated("invalid peer context"))?;
        let connection = ConnectionBinding::try_from(info.0.connection_digest.clone())
            .map_err(|_| Status::unauthenticated("invalid connection binding"))?;
        Ok((peer, connection))
    }

    /// Bind a mutation RPC to a domain operation under the owner's authenticated peer.
    ///
    /// Requires an established owner session whose peer matches the transport peer, binds a
    /// fresh one-shot capability for `method`, and delegates the wire→domain binding to
    /// `kernel_request_to_operation` (identity from the authenticated principal only).
    fn bind_mutation(
        &self,
        extensions: &Extensions,
        core: &HelperControlCore,
        wire_key: &generated::OperationLookupKey,
        request_digest: &[u8],
        method: OperationMethod,
    ) -> Result<(PeerContext, OperationLookupKey, RequestDigest), Status> {
        let (peer, _connection) = self.transport_peer(extensions)?;
        let owner = core
            .owner
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("no owner lease established"))?;
        if owner.peer != peer {
            return Err(Status::unauthenticated("owner peer mismatch"));
        }
        let capability = peer
            .bind_capability(method, self.authority(), self.clock.later_by(CAPABILITY_TTL_MS))
            .map_err(|e| Status::invalid_argument(format!("capability: {e}")))?;
        let bound = kernel_request_to_operation(
            &KernelRequest::new(wire_key.clone(), request_digest.to_vec(), method),
            &peer,
            &capability,
            self.authority(),
            self.clock.now(),
        )
        .map_err(|e| Status::invalid_argument(format!("operation binding: {e}")))?;
        Ok((peer, bound.lookup_key, bound.request_digest))
    }

    /// The authority epoch of this helper instance (minted into domain form on demand).
    #[must_use]
    fn authority(&self) -> AuthorityEpoch {
        AuthorityEpoch::try_from(self.authority_epoch).expect("authority epoch mints")
    }

    /// Record a terminal outcome for a completed mutation so GetOperation can answer.
    fn record_terminal(
        core: &mut HelperControlCore,
        key: &OperationLookupKey,
        terminal: generated::OperationTerminal,
    ) {
        let digest = canonical_lookup_digest(key);
        core.terminals.insert(digest, terminal);
    }

    /// The owned-token authorization subject for an established owner, falling back to a
    /// request-derived digest when no lease is held yet (used by apply/stop/release).
    fn owned_token_subject(core: &HelperControlCore, fallback_raw: &[u8]) -> AuthorizationSubject {
        let digest = core
            .owner
            .as_ref()
            .and_then(|owner| core.leases.lease(&owner.connection))
            .map(|lease| lease.token_digest().clone())
            .unwrap_or_else(|| {
                TokenDigest::try_from(digest32(fallback_raw)).expect("token digest mints")
            });
        AuthorizationSubject::LiveOwnershipTokenDigest(digest)
    }

    /// Parse the one-shot `secret_payload` bytes into engine-side credentials, then
    /// zeroize the wire copy immediately (P3-b1). An absent/empty payload yields
    /// `Ok(None)` — no credentials provided is a valid caller choice.
    ///
    /// The returned [`EngineCredentials`] is a zeroizing type: it is never persisted,
    /// never logged, and `Drop` clears the plaintext. R1b: the credentials are consumed
    /// directly by the tunnel runtime at apply time (parsed and moved into
    /// [`ApplyContext`]); no pending-credentials slot is retained.
    ///
    /// # Errors
    /// Malformed or unsupported-version payload → `Err(Status)`, and the wire copy is
    /// still zeroized before returning (fail closed, no plaintext lingers).
    fn parse_secret_payload(
        payload_bytes: &mut Vec<u8>,
    ) -> Result<Option<EngineCredentials>, Status> {
        if payload_bytes.is_empty() {
            return Ok(None);
        }
        let parsed = crate::secret_payload::parse_secret_payload(payload_bytes).map_err(|e| {
            let msg = match e {
                SecretPayloadError::UnsupportedVersion(v) => {
                    format!("secret payload unsupported version {v} (expected {SECRET_PAYLOAD_VERSION})")
                }
                SecretPayloadError::Decode(d) => format!("secret payload decode failed: {d}"),
            };
            // Fail closed: no plaintext may linger even on a malformed payload.
            payload_bytes.zeroize();
            Status::invalid_argument(msg)
        });
        match parsed {
            Ok(package) => {
                payload_bytes.zeroize();
                Ok(Some(EngineCredentials::from_package(package)))
            }
            Err(status) => Err(status),
        }
    }
}

/// Build the wire `MutationReceipt` for an admitted external mutation (free function
/// so the R2/P2-1 terminal observer can mint it without a `&HelperControlService`).
fn build_wire_receipt(
    core: &HelperControlCore,
    wire_key: &generated::OperationLookupKey,
    canonical_input_digest: [u8; 32],
    effect_id: Uuid,
) -> generated::MutationReceipt {
    generated::MutationReceipt {
        journal_operation_identity: Some(generated::JournalOperationIdentity {
            identity: Some(
                generated::journal_operation_identity::Identity::External(wire_key.clone()),
            ),
        }),
        canonical_input_digest: canonical_input_digest.to_vec(),
        effect_id: effect_id.as_bytes().to_vec(),
        authority_fence: Some(wire_fence(core)),
        ownership_version: core.ownership_version,
        certainty: EFFECT_CERTAINTY_APPLIED,
    }
}

impl Default for HelperControlService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HelperControl for HelperControlService {
    type MaintainOwnerLeaseStream =
        tokio_stream::wrappers::ReceiverStream<Result<generated::HelperLeaseMessage, tonic::Status>>;
    type StreamLogsStream =
        tokio_stream::wrappers::ReceiverStream<Result<generated::LogEvent, tonic::Status>>;
    type StreamStatsStream =
        tokio_stream::wrappers::ReceiverStream<Result<generated::StatsEvent, tonic::Status>>;
    type StreamConnectStatusStream = tokio_stream::wrappers::ReceiverStream<
        Result<generated::ConnectStatusEvent, tonic::Status>,
    >;

    async fn maintain_owner_lease(
        &self,
        request: Request<Streaming<generated::HostLeaseMessage>>,
    ) -> Result<Response<Self::MaintainOwnerLeaseStream>, Status> {
        let (peer, connection) = self.transport_peer(request.extensions())?;
        let mut inbound = request.into_inner();

        let (tx, rx) = mpsc::channel::<Result<generated::HelperLeaseMessage, Status>>(16);
        let core = self.core.clone();
        let runtime_epoch = self.runtime_epoch.clone();
        let runtime_epoch_bytes = self.runtime_epoch_bytes;
        let log = self.log.clone();
        // S3/D7: service mode releases the connection-bound owner when this stream EOFs.
        let connection_mode = self.connection_mode;

        tokio::spawn(async move {
            let mut lease_established = false;
            let mut owner_lease_id = Uuid::nil();

            while let Ok(Some(message)) = inbound.message().await {
                let is_handshake =
                    matches!(message.message, Some(generated::host_lease_message::Message::Handshake(_)));
                // The FIRST host message must be the authorization handshake; a stream that
                // sends anything else before it is refused (fail closed).
                if !lease_established && !is_handshake {
                    break;
                }
                // Once the lease is established, the host must echo the server's runtime
                // epoch on every subsequent message; a mismatch fails closed. The handshake
                // itself establishes the epoch, so it is exempt (the client cannot know it
                // before the handshake-accepted reply).
                if lease_established && !is_handshake {
                    let epoch_ok = Uuid::from_slice(&message.runtime_epoch)
                        .ok()
                        .and_then(|uuid| RuntimeEpoch::try_from(uuid).ok())
                        .map(|epoch| epoch == runtime_epoch)
                        .unwrap_or(false);
                    if !epoch_ok {
                        break;
                    }
                }
                match message.message {
                    Some(generated::host_lease_message::Message::Handshake(handshake)) => {
                        // The handshake's self-reported principal must match the AUTHENTICATED
                        // transport principal; it can never upgrade identity.
                        let declared = <[u8; 32]>::try_from(handshake.principal_digest.as_slice())
                            .map(|d| PrincipalDigest::try_from(d).map(|p| p == *peer.principal()));
                        let declared_matches = matches!(declared, Ok(Ok(true)));
                        let capability_ok = handshake.capability_digest.len() == 32;
                        let channel_ok = handshake.channel_identity_digest.len() == 32;
                        if !declared_matches || !capability_ok || !channel_ok {
                            log.emit(
                                LogLevel::Warn,
                                "auth",
                                "lease.handshake.refused",
                                "owner handshake refused (identity mismatch)",
                                &[("reason", "identity_mismatch")],
                            );
                            let refused = tx
                                .send(Ok(generated::HelperLeaseMessage {
                                    owner_lease_id: owner_lease_id.as_bytes().to_vec(),
                                    runtime_epoch: runtime_epoch_bytes.to_vec(),
                                    message: Some(
                                        generated::helper_lease_message::Message::OwnerLost(
                                            generated::OwnerLost {
                                                error: Some(wire_error_no_subject(
                                                    "handshake rejected",
                                                )),
                                            },
                                        ),
                                    ),
                                }))
                                .await;
                            if refused.is_err() {
                                break;
                            }
                            break;
                        }
                        {
                            let mut core = core.lock().expect("helper core lock");
                            if let Some(existing) = &core.owner {
                                if existing.peer != peer {
                                    log.emit(
                                        LogLevel::Warn,
                                        "auth",
                                        "lease.handshake.refused",
                                        "owner handshake refused (peer already owns)",
                                        &[],
                                    );
                                    break;
                                }
                            }
                            owner_lease_id = Uuid::new_v4();
                            core.owner = Some(OwnerSession {
                                peer: peer.clone(),
                                connection: connection.clone(),
                            });
                            lease_established = true;
                        }
                        log.emit(
                            LogLevel::Info,
                            "auth",
                            "lease.handshake.accepted",
                            "owner lease established",
                            &[],
                        );
                        let fence = {
                            let core = core.lock().expect("helper core lock");
                            wire_fence(&core)
                        };
                        let accepted = tx
                            .send(Ok(generated::HelperLeaseMessage {
                                owner_lease_id: owner_lease_id.as_bytes().to_vec(),
                                runtime_epoch: runtime_epoch_bytes.to_vec(),
                                message: Some(
                                    generated::helper_lease_message::Message::HandshakeAccepted(
                                        generated::LeaseHandshakeAccepted {
                                            authority_fence: Some(fence),
                                        },
                                    ),
                                ),
                            }))
                            .await;
                        if accepted.is_err() {
                            break;
                        }
                    }
                    Some(generated::host_lease_message::Message::Keepalive(keepalive)) => {
                        if !lease_established {
                            break;
                        }
                        let ack = tx
                            .send(Ok(generated::HelperLeaseMessage {
                                owner_lease_id: owner_lease_id.as_bytes().to_vec(),
                                runtime_epoch: runtime_epoch_bytes.to_vec(),
                                message: Some(
                                    generated::helper_lease_message::Message::KeepaliveAck(
                                        generated::LeaseKeepaliveAck {
                                            monotonic_tick: keepalive.monotonic_tick,
                                        },
                                    ),
                                ),
                            }))
                            .await;
                        if ack.is_err() {
                            break;
                        }
                    }
                    Some(generated::host_lease_message::Message::OwnershipTokenReceived(otr)) => {
                        // One-shot token bytes: never stored; cleared immediately after the ack.
                        let mut token_bytes = otr.ownership_token;
                        let mut token_digest = otr.ownership_token_digest;
                        let outcome = {
                            let mut core = core.lock().expect("helper core lock");
                            // Clone the ack inputs (releasing the immutable lease borrow before
                            // the mutable ack call below).
                            let ack_input = match (
                                core.owner.as_ref(),
                                <[u8; 32]>::try_from(token_digest.as_slice()),
                            ) {
                                (Some(owner), Ok(digest)) => {
                                    core.leases.lease(&owner.connection).and_then(|lease| {
                                        TokenDigest::try_from(digest).ok().map(|token| {
                                            (
                                                owner.connection.clone(),
                                                lease.key().clone(),
                                                lease.request_digest().clone(),
                                                lease.ownership_version(),
                                                token,
                                            )
                                        })
                                    })
                                }
                                _ => None,
                            };
                            match ack_input {
                                Some((connection, key, request_digest, version, token)) => {
                                    core.leases.ack(&connection, key, request_digest, version, token)
                                }
                                None => AckOutcome::NoSlot,
                            }
                        };
                        token_bytes.zeroize();
                        token_digest.zeroize();
                        let _ = outcome;
                    }
                    None => {
                        // A message with no oneof payload carries no lease semantics; ignore.
                    }
                }
            }
            // S3/D7: service mode — the owner connection dropped (stream EOF). Release the
            // connection-bound owner + terminate the J52 lease + advance the ownership
            // version so a NEW core can handshake-take-over. Tunnel/admission persistent
            // state is RETAINED (D7: 仅隧道/admission 持久状态保留) — the service keeps
            // the applied tunnel / admission watermarks across core disconnects.
            if connection_mode == ConnectionMode::Service {
                let mut core = core.lock().expect("helper core lock");
                // Clone the binding out of the borrow before the mutable terminate call.
                let release = core
                    .owner
                    .as_ref()
                    .filter(|owner| owner.connection == connection)
                    .map(|owner| owner.connection.clone());
                if let Some(conn) = release {
                    let _ = core.leases.terminate_connection(&conn);
                    core.owner = None;
                    core.ownership_version = core.ownership_version.saturating_add(1);
                    log.emit(
                        LogLevel::Info,
                        "auth",
                        "lease.owner.released-on-eof",
                        "service owner released on connection EOF (new core may take over)",
                        &[],
                    );
                }
            }
            drop(tx);
        });

        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn observe_owned_state(
        &self,
        request: Request<generated::ObserveOwnedStateRequest>,
    ) -> Result<Response<generated::ObserveOwnedStateReply>, Status> {
        let (peer, _connection) = self.transport_peer(request.extensions())?;
        let wire_key = request
            .get_ref()
            .lookup_key
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("observe: missing lookup key"))?;
        let _key = convert::lookup_key_from_wire(wire_key, peer.principal().clone())
            .map_err(|e| Status::invalid_argument(format!("observe: {e}")))?;
        let core = self.core.lock().expect("helper core lock");
        Ok(Response::new(generated::ObserveOwnedStateReply {
            // The pure composition phase owns no native runtime state; a real snapshot is a P3
            // semantic-gateway concern. The Idle branch is the only identity-free snapshot shape.
            snapshot: Some(generated::RuntimeSnapshot {
                state: Some(generated::runtime_snapshot::State::Idle(generated::IdleState {
                    last_cleanup: None,
                })),
                // stats-wire 方案 A：helper 的 Idle 占位快照无统计样本（core 负责填）。
                ..Default::default()
            }),
            authority_fence: Some(wire_fence(&core)),
        }))
    }

    async fn acquire_lease(
        &self,
        request: Request<generated::AcquireLeaseRequest>,
    ) -> Result<Response<generated::AcquireLeaseReply>, Status> {
        let wire_key = request
            .get_ref()
            .lookup_key
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("acquire: missing lookup key"))?;
        let wire_key_bytes = wire_key.encode_to_vec();
        let request_digest = request.get_ref().request_digest.clone();
        let mut core = self.core.lock().expect("helper core lock");
        let (peer, key, digest) = self.bind_mutation(
            request.extensions(),
            &core,
            wire_key,
            &request_digest,
            OperationMethod::AcquireLease,
        )?;

        // Mint the candidate ownership token (one-shot secret; only the digest is retained and
        // the raw bytes never travel — P3 delivers the raw token to the host on the lease stream).
        let candidate = TokenDigest::try_from(digest32(&request_digest)).expect("token mints");
        let subject = AuthorizationSubject::LiveOwnershipTokenDigest(candidate.clone());

        let connection = core
            .owner
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("no owner lease"))?
            .connection
            .clone();
        let effect_uuid = Uuid::new_v4();
        let effect_id = EffectId::try_from(effect_uuid).expect("effect id mints");

        // Spec §7.2 order: install the connection-owned re-acquirable token slot FIRST
        // (J52), THEN run the durable admission + W15 sync-before-reply gate (the gate
        // needs the held lease), and only then reply.
        let version = OwnershipVersion::try_from(core.ownership_version)
            .expect("ownership version mints");
        let issue = core
            .leases
            .issue(&connection, key.clone(), digest.clone(), version, candidate.clone());

        let canonical_input_digest = digest32(&request_digest);
        match issue {
            LeaseIssue::Issued { token_digest } | LeaseIssue::SameTokenReplayed { token_digest } => {
                let _ = token_digest;
                admit_and_gate(
                    &mut core,
                    &peer,
                    &wire_key_bytes,
                    &request_digest,
                    &key,
                    &digest,
                    OperationMethod::AcquireLease,
                    subject,
                    effect_id,
                )?;
                let receipt = build_wire_receipt(&core, wire_key, canonical_input_digest, effect_uuid);
                let terminal = generated::OperationTerminal {
                    result: Some(generated::operation_terminal::Result::Succeeded(receipt.clone())),
                };
                Self::record_terminal(&mut core, &key, terminal);
                self.log.emit(
                    LogLevel::Info,
                    "auth",
                    "mutation.acquire.accepted",
                    "ownership lease acquired",
                    &[],
                );
                Ok(Response::new(generated::AcquireLeaseReply {
                    result: Some(generated::acquire_lease_reply::Result::Acquired(receipt)),
                }))
            }
            LeaseIssue::Refused => {
                self.log.emit(
                    LogLevel::Warn,
                    "auth",
                    "mutation.acquire.refused",
                    "ownership lease refused",
                    &[],
                );
                let error = wire_error(wire_key, ERROR_CODE_UNAUTHORIZED, "lease refused");
                let receipt = build_wire_receipt(&core, wire_key, canonical_input_digest, effect_uuid);
                let failed = generated::OperationFailed {
                    receipt: Some(receipt),
                    error: Some(error),
                };
                let terminal = generated::OperationTerminal {
                    result: Some(generated::operation_terminal::Result::Failed(failed.clone())),
                };
                Self::record_terminal(&mut core, &key, terminal);
                Ok(Response::new(generated::AcquireLeaseReply {
                    result: Some(generated::acquire_lease_reply::Result::Failed(failed)),
                }))
            }
        }
    }

    async fn apply_tunnel(
        &self,
        request: Request<generated::ApplyTunnelRequest>,
    ) -> Result<Response<generated::ApplyTunnelReply>, Status> {
        // Take the request apart up front: the owned message is destructured so no borrow of
        // `request` outlives the extraction (the extensions handle stays alive for the peer).
        let extensions = request.extensions().clone();
        let generated::ApplyTunnelRequest {
            lookup_key,
            plan,
            request_digest,
            // P3-b1: the one-shot secret_payload moves out of the wire message; it is parsed
            // and zeroized below. No plaintext stays in the request carrier.
            mut secret_payload,
        } = request.into_inner();
        let wire_key = lookup_key
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("apply: missing lookup key"))?;
        let wire_key_bytes = wire_key.encode_to_vec();
        let wire_plan = plan
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("apply: missing tunnel plan"))?;
        // All core-guarded admission work runs in a scope block so the `MutexGuard`
        // is dropped structurally BEFORE the runtime's async-start (`start_apply` 受理即回，
        // 不需要跨 await 持锁；`operation_id`/`ctx` 为 owned 值，可存活）。
        let (operation_id, ctx) = {
            let mut core = self.core.lock().expect("helper core lock");
            let (_peer, key, digest) = self.bind_mutation(
                &extensions,
                &core,
                wire_key,
                &request_digest,
                OperationMethod::ApplyTunnel,
            )?;

            let plan = convert::tunnel_plan_from_wire(wire_plan)
                .map_err(|e| Status::invalid_argument(format!("apply: {e}")))?;

            // P3-b1: parse the one-shot secret_payload into engine credentials and zeroize
            // the wire copy immediately. R1b: the credentials are consumed by the tunnel
            // runtime at apply time (never parked in a pending slot).
            let credentials = Self::parse_secret_payload(&mut secret_payload)?;

            let subject = Self::owned_token_subject(&core, &request_digest);
            let effect_uuid = Uuid::new_v4();
            let effect_id = EffectId::try_from(effect_uuid).expect("effect id mints");
            admit_and_gate(
                &mut core,
                &_peer,
                &wire_key_bytes,
                &request_digest,
                &key,
                &digest,
                OperationMethod::ApplyTunnel,
                subject,
                effect_id,
            )?;

            // The admitted operation is recorded; the REAL assembly (login/CSTP/apply/
            // data plane) runs through the injected tunnel runtime below. The wire plan
            // is the config approximation — the CSTP offer (real negotiation) is
            // authoritative for address/prefix/mtu/dns/routes (R1b; same semantics as
            // the acceptance engine).
            core.applied_tunnel = Some(plan.clone());
            let operation_id = wire_key.operation_id.clone();
            // R2/P2-1：登记在途 apply——运行时终态（Connected/Failed）经 status 通道
            // 发布时，内部终态观察者据此合成 `OperationTerminal` 写回 `terminals`
            // （`GetOperation(apply)` 可答真实终态而非恒 Pending）。
            core.pending_apply.insert(
                operation_id.clone(),
                PendingApply {
                    key: key.clone(),
                    wire_key: wire_key.clone(),
                    canonical_input_digest: digest32(&request_digest),
                    effect_uuid,
                },
            );
            // Build the apply context: one-shot credentials (parsed + zeroized wire
            // copy), the shared status publisher, and the log sink. The runtime emits
            // real status milestones (ConnectingControl -> ApplyingPlatformTunnel ->
            // StartingDataPlane -> Connected) — the bookkeeping placeholder signals
            // are RETIRED (R1b).
            let ctx = ApplyContext {
                plan,
                credentials,
                operation_id: operation_id.clone(),
                status: Arc::clone(&self.status),
                stats: Arc::clone(&self.stats),
                log: Arc::clone(&self.log),
            };
            (operation_id, ctx)
        };
        // A1b: the real assembly is async-start — `start_apply` 受理即回，组装在后台
        // thread 内逐段执行，终态（Connected/Failed）由后台 thread 经 status 通道
        // 发布（handler 不等待、不记账——记账式假连接已退役）。The reply is the
        // `pending` ApplyAccepted; the terminal never rides on the ApplyTunnel reply
        // (R1w).
        let runtime = Arc::clone(&self.runtime);
        let outcome = runtime.start_apply(ctx);
        // 组装受理失败（duplicate connect 等）→ 以 Failed 终态上报（不静默），仍回
        // pending（host 经 status 通道关联 Failed）。
        if let Err(err) = outcome {
            self.stats.registry().set_phase(generated::StatsPhase::Failed);
            self.status.publish(StatusEvent::failed(
                operation_id.clone(),
                err.connect_phase,
                crate::tunnel_runtime::tunnel_error_to_wire(&err),
            ));
            self.log.emit(
                LogLevel::Warn,
                "platform",
                "mutation.apply.refused",
                "tunnel assembly refused (diagnostic; state on StreamConnectStatus)",
                &[("detail", &err.detail)],
            );
        }
        let core = self.core.lock().expect("helper core lock");
        // R1: this log code is PURE DIAGNOSTIC — it no longer carries any state
        // semantics. Status flows ONLY on StreamConnectStatus; the core derives no
        // phase from log codes (D3: logs never feed back into state).
        self.log.emit(
            LogLevel::Info,
            "platform",
            "mutation.apply.accepted",
            "tunnel assembly started (diagnostic; state on StreamConnectStatus)",
            &[],
        );
        // The async reply: admitted and in-flight, not yet terminal. The core correlates
        // the operation via operation_id against the StreamConnectStatus events.
        Ok(Response::new(generated::ApplyTunnelReply {
            result: Some(generated::apply_tunnel_reply::Result::Pending(
                generated::ApplyAccepted {
                    operation_id,
                    authority_fence: Some(wire_fence(&core)),
                },
            )),
        }))
    }

    async fn stop_tunnel(
        &self,
        request: Request<generated::StopTunnelRequest>,
    ) -> Result<Response<generated::StopTunnelReply>, Status> {
        let wire_key = request
            .get_ref()
            .lookup_key
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("stop: missing lookup key"))?;
        let wire_key_bytes = wire_key.encode_to_vec();
        let request_digest = request.get_ref().request_digest.clone();
        // Core-guarded admission runs in a scope block so the `MutexGuard` drops
        // structurally BEFORE the spawn_blocking await (a `MutexGuard` is not Send
        // across an await).
        let (key, effect_uuid) = {
            let mut core = self.core.lock().expect("helper core lock");
            let (peer, key, digest) = self.bind_mutation(
                request.extensions(),
                &core,
                wire_key,
                &request_digest,
                OperationMethod::StopTunnel,
            )?;

            let subject = Self::owned_token_subject(&core, &request_digest);
            let effect_uuid = Uuid::new_v4();
            let effect_id = EffectId::try_from(effect_uuid).expect("effect id mints");
            admit_and_gate(
                &mut core,
                &peer,
                &wire_key_bytes,
                &request_digest,
                &key,
                &digest,
                OperationMethod::StopTunnel,
                subject,
                effect_id,
            )?;
            (key, effect_uuid)
        };

        // Tear down the real tunnel (R1b + A1b cancel + S1.5 D13 减负断开): first
        // `cancel()` 触发取消令牌中止在途组装（后台组装在段边界自清理），等待其退出
        // （有界），再 `disconnect()`——session owner 断 VPN 连接 + route owner 清路由
        // （含地址/on-link）+ Paused 标记；**NIC owner 保留 adapter**（D12 网卡惰性
        // 存续，退出清理阶段才 close）。The J52 ownership token slot is NOT invalidated
        // here — the ownership lease outlives the tunnel and is retired by ReleaseLease.
        let runtime = Arc::clone(&self.runtime);
        let disconnect = tokio::task::spawn_blocking(move || {
            // A1b：置位取消令牌 → 有界等待在途组装在段边界取消并自清理（5s 上限）。
            runtime.cancel();
            for _ in 0..100 {
                if !runtime.is_assembling() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            runtime.disconnect()
        })
        .await
        .map_err(|e| Status::internal(format!("stop: disconnect join: {e}")))?;
        let mut core = self.core.lock().expect("helper core lock");
        core.applied_tunnel = None;
        core.pending_apply.clear();
        if let Err(e) = disconnect {
            // Disconnect failure: report it on the status channel as a typed failure, but
            // still return the stop receipt (the caller must not retry stop forever).
            // The adapter is retained (D12); exit cleanup still closes it.
            self.log.emit(
                LogLevel::Warn,
                "platform",
                "mutation.stop.disconnect-failed",
                "tunnel disconnect failed (diagnostic; adapter retained for exit cleanup)",
                &[("detail", &e)],
            );
        }
        // P5-a: the tunnel is torn down — the engine returns to idle.
        self.stats.registry().set_phase(generated::StatsPhase::Idle);
        let canonical_input_digest = digest32(&request_digest);
        let receipt = build_wire_receipt(&core, wire_key, canonical_input_digest, effect_uuid);
        let terminal = generated::OperationTerminal {
            result: Some(generated::operation_terminal::Result::Succeeded(receipt.clone())),
        };
        Self::record_terminal(&mut core, &key, terminal);
        // R1w: publish the stop terminal on the independent status channel (coarse Idle).
        // The stop operation carries its OWN operation_id; R2 wires the full
        // teardown/convergence (core-synthesized Idle + engine-first Idle) behind it.
        self.status.publish(StatusEvent::idle(wire_key.operation_id.clone()));
        // R1: PURE DIAGNOSTIC — no state semantics ride on this log code; state
        // flows only on StreamConnectStatus (the Idle event published above).
        self.log.emit(
            LogLevel::Info,
            "platform",
            "mutation.stop.stopped",
            "tunnel stopped (diagnostic; state on StreamConnectStatus)",
            &[],
        );
        // D1 (engine persistent lifecycle): StopTunnel 只做业务停机——拆隧道 + publish
        // Idle + 回 Stopped 回复；engine 回 Idle **常驻**,本 RPC 不再触发进程退出
        // （进程退出仅由 engine bin 的 core 进程句柄等待驱动）。core 停机链 = 发本退出包
        // → core 自身进程退出 → engine 随行。
        Ok(Response::new(generated::StopTunnelReply {
            result: Some(generated::stop_tunnel_reply::Result::Stopped(receipt)),
        }))
    }

    async fn get_operation(
        &self,
        request: Request<generated::GetOperationRequest>,
    ) -> Result<Response<generated::GetOperationReply>, Status> {
        let (peer, _connection) = self.transport_peer(request.extensions())?;
        let wire_key = request
            .get_ref()
            .lookup_key
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("get_operation: missing lookup key"))?;
        let key = convert::lookup_key_from_wire(wire_key, peer.principal().clone())
            .map_err(|e| Status::invalid_argument(format!("get_operation: {e}")))?;
        let core = self.core.lock().expect("helper core lock");

        let state = if let Some(terminal) = core.terminals.get(&canonical_lookup_digest(&key)) {
            generated::OperationState {
                state: Some(generated::operation_state::State::Terminal(terminal.clone())),
            }
        } else {
            // The J51 sequencer answers Pending / Rejected / Absent / Unknown. A placeholder
            // digest is passed: `AdmissionIndex::get_operation` does not read it.
            let digest = RequestDigest::try_from([0u8; 32]).expect("placeholder digest mints");
            match core.admissions.get_operation(&key, &digest) {
                exv_vpn_domain::ports::OperationState::Pending => generated::OperationState {
                    state: Some(generated::operation_state::State::Pending(
                        generated::EmptyOperationState {},
                    )),
                },
                exv_vpn_domain::ports::OperationState::Unknown => generated::OperationState {
                    state: Some(generated::operation_state::State::Unknown(
                        generated::EmptyOperationState {},
                    )),
                },
                exv_vpn_domain::ports::OperationState::AbsentNoEffect {
                    lookup_key_digest: _,
                    ..
                } => generated::OperationState {
                    state: Some(generated::operation_state::State::Absent(
                        generated::AbsentNoEffect {
                            lookup_key_digest: digest32(&wire_key.operation_id).to_vec(),
                            authority_epoch: core.authority_epoch,
                            admission_watermark: core.watermark,
                        },
                    )),
                },
                exv_vpn_domain::ports::OperationState::RejectedNoEffect { .. } => {
                    generated::OperationState {
                        state: Some(generated::operation_state::State::Rejected(
                            generated::RejectedNoEffect {
                                error: Some(wire_error(
                                    wire_key,
                                    ERROR_CODE_UNAUTHORIZED,
                                    "mutation rejected",
                                )),
                                authority_fence: Some(wire_fence(&core)),
                            },
                        )),
                    }
                }
                exv_vpn_domain::ports::OperationState::Terminal(_) => {
                    // Unreachable: terminals are answered from `core.terminals` above.
                    generated::OperationState {
                        state: Some(generated::operation_state::State::Unknown(
                            generated::EmptyOperationState {},
                        )),
                    }
                }
            }
        };

        Ok(Response::new(generated::GetOperationReply { state: Some(state) }))
    }

    async fn release_lease(
        &self,
        request: Request<generated::ReleaseLeaseRequest>,
    ) -> Result<Response<generated::ReleaseLeaseReply>, Status> {
        let wire_key = request
            .get_ref()
            .lookup_key
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("release: missing lookup key"))?;
        let wire_key_bytes = wire_key.encode_to_vec();
        let request_digest = request.get_ref().request_digest.clone();
        let mut core = self.core.lock().expect("helper core lock");
        let (peer, key, digest) = self.bind_mutation(
            request.extensions(),
            &core,
            wire_key,
            &request_digest,
            OperationMethod::ReleaseLease,
        )?;

        let subject = Self::owned_token_subject(&core, &request_digest);
        let effect_uuid = Uuid::new_v4();
        let effect_id = EffectId::try_from(effect_uuid).expect("effect id mints");
        admit_and_gate(
            &mut core,
            &peer,
            &wire_key_bytes,
            &request_digest,
            &key,
            &digest,
            OperationMethod::ReleaseLease,
            subject,
            effect_id,
        )?;

        // Retire the ownership: invalidate the J52 slot, clear the tunnel and the owner
        // session, and advance the ownership version for the next owner.
        let connection = core
            .owner
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("no owner lease"))?
            .connection
            .clone();
        let _ = core.leases.terminate_connection(&connection);
        core.applied_tunnel = None;
        core.pending_apply.clear();
        core.owner = None;
        core.ownership_version = core.ownership_version.saturating_add(1);
        // P5-a: ownership retired — the engine returns to idle.
        self.stats.registry().set_phase(generated::StatsPhase::Idle);

        let canonical_input_digest = digest32(&request_digest);
        let receipt = build_wire_receipt(&core, wire_key, canonical_input_digest, effect_uuid);
        let terminal = generated::OperationTerminal {
            result: Some(generated::operation_terminal::Result::Succeeded(receipt.clone())),
        };
        Self::record_terminal(&mut core, &key, terminal);
        self.log.emit(
            LogLevel::Info,
            "auth",
            "mutation.release.released",
            "ownership lease released",
            &[],
        );
        Ok(Response::new(generated::ReleaseLeaseReply {
            result: Some(generated::release_lease_reply::Result::Released(receipt)),
        }))
    }

    async fn stream_logs(
        &self,
        request: Request<generated::StreamLogsRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        // Transport gate applies to log streaming too: only verified connections may open a
        // log channel (the engine→core log channel must not leak to unauthenticated peers).
        let (_peer, _connection) = self.transport_peer(request.extensions())?;
        // P2-b: attach the shared log sink to this client. `open_stream` backfills buffered
        // events after `resume_tick` (bounded history ring) and then streams live events; a
        // `resume_tick == 0` stream starts at the current position (no backfill). The sink
        // falls back to the raw dump when no stream is attached or the push channel closes.
        let resume_tick = request.get_ref().resume_tick;
        let rx = self.log.open_stream(resume_tick);
        self.log.emit(
            LogLevel::Info,
            "engine",
            "logs.stream.opened",
            "stream logs channel opened",
            &[("resume_tick", &resume_tick.to_string())],
        );
        tracing::debug!(resume_tick, "stream_logs: real log push attached (P2-b)");
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn stream_stats(
        &self,
        request: Request<generated::StreamStatsRequest>,
    ) -> Result<Response<Self::StreamStatsStream>, Status> {
        // Transport gate applies to stats streaming too: only verified connections may
        // open a stats channel (the engine→core stats channel must not leak to
        // unauthenticated peers).
        let (_peer, _connection) = self.transport_peer(request.extensions())?;
        // P5-a: attach the shared stats publisher to this client. `open_stream`
        // registers the push channel and spawns the sampler task; cumulative counters
        // are the resume point (no resume tick needed). `sample_interval_ms == 0`
        // selects the engine default (1000 ms).
        let sample_interval_ms = request.get_ref().sample_interval_ms;
        let rx = self.stats.open_stream(sample_interval_ms);
        self.log.emit(
            LogLevel::Info,
            "engine",
            "stats.stream.opened",
            "stream stats channel opened",
            &[("sample_interval_ms", &sample_interval_ms.to_string())],
        );
        tracing::debug!(sample_interval_ms, "stream_stats: real stats push attached (P5-a)");
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn stream_connect_status(
        &self,
        request: Request<generated::StreamConnectStatusRequest>,
    ) -> Result<Response<Self::StreamConnectStatusStream>, Status> {
        // Transport gate applies to the status channel too: only verified connections
        // may open it (the engine→core status channel must not leak to unauthenticated
        // peers). The status channel is INDEPENDENT from StreamStats (R1w).
        let (_peer, _connection) = self.transport_peer(request.extensions())?;
        // R1w: attach the shared status publisher to this client. `open_stream`
        // registers the push channel; the engine (apply/stop now, real data plane in
        // R1b) publishes connect-status events carrying operation_id + ConnectPhase +
        // coarse StatsPhase + optional err. The stream stays open until the client
        // disconnects.
        let rx = self.status.open_stream();
        self.log.emit(
            LogLevel::Info,
            "engine",
            "status.stream.opened",
            "stream connect-status channel opened",
            &[],
        );
        tracing::debug!("stream_connect_status: real status push attached (R1w)");
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(rx)))
    }

    async fn keep_alive(
        &self,
        request: Request<generated::KeepAliveRequest>,
    ) -> Result<Response<generated::KeepAliveReply>, Status> {
        // P2 bounded retention: only the transport-verified core may keep the
        // engine alive — an unverified peer's heartbeat must never refresh the
        // last-heartbeat timestamp (a heartbeat from an imposter would defeat the
        // hard time bound). The transport interceptor already gates every RPC;
        // this is the handler's fail-closed defense in depth.
        self.transport_peer(request.extensions())?;
        // Refresh the monotonic last-heartbeat timestamp (the engine bin's
        // watchdog self-cleans + self-exits when this stalls past the timeout).
        // 心跳高频（~1s）打日志太重，逻辑保留、日志摘除（用户 2026-08-23）。
        self.heartbeat.touch();
        Ok(Response::new(generated::KeepAliveReply {
            monotonic_tick: request.get_ref().monotonic_tick,
        }))
    }

    async fn service_manage(
        &self,
        request: Request<generated::ServiceManageRequest>,
    ) -> Result<Response<generated::ServiceManageReply>, Status> {
        // S3/Tier 2: only the transport-verified core may read the deep self-report
        // (fail closed — an unverified peer must never learn engine internals). The
        // dispatch interceptor already gates every RPC; this is the handler's
        // fail-closed defense in depth (same idiom as keep_alive). No owner-lease
        // requirement: any authenticated connection may ask (health probe works
        // before an owner is established).
        self.transport_peer(request.extensions())?;
        // Tier 2 v1 lands ONLY the `query` action; a default/absent or unknown action
        // is an invalid argument (future actions evolve via the oneof).
        let Some(generated::service_manage_request::Action::Query(_query)) = request.into_inner().action
        else {
            return Err(Status::invalid_argument(
                "ServiceManage: only the query action is supported",
            ));
        };
        // Assemble the deep self-report: facts ONLY the engine knows. NO SCM-derived
        // fields (installed/state/binary_path/health_state), NO stats/connect status
        // (host already has those via RuntimeSnapshot / StreamStats).
        let connection_mode = match self.connection_mode {
            ConnectionMode::Service => "service",
            ConnectionMode::Oneshot => "oneshot",
        };
        let report = generated::ServiceSelfReport {
            control_plane_ready: self
                .service_self
                .control_plane_ready
                .load(Ordering::SeqCst),
            psk_present: self.service_self.psk_present,
            connection_mode: connection_mode.to_string(),
            runtime_epoch: self.runtime_epoch_bytes.to_vec(),
            authority_fence: Some(wire_fence(
                &self.core.lock().expect("helper core lock"),
            )),
        };
        self.log.emit(
            LogLevel::Info,
            "engine",
            "service.query.answered",
            "service self-report answered (diagnostic)",
            &[("connection_mode", connection_mode)],
        );
        Ok(Response::new(generated::ServiceManageReply {
            self_report: Some(report),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty payload → `Ok(None)` — no credentials is a valid caller choice.
    #[test]
    fn parse_secret_payload_empty_is_ok_none() {
        let mut bytes = Vec::new();
        let parsed = HelperControlService::parse_secret_payload(&mut bytes).expect("ok");
        assert!(parsed.is_none());
    }

    /// Valid payload → `Ok(Some(creds))` with correct plaintext, and the wire copy is
    /// zeroized immediately after parsing (no plaintext stays in the caller's carrier).
    #[test]
    fn parse_secret_payload_valid_consumes_and_zeroizes_wire_copy() {
        let mut bytes = b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}"
            .to_vec();
        let creds = HelperControlService::parse_secret_payload(&mut bytes)
            .expect("parse")
            .expect("some");
        assert_eq!(creds.username, "student");
        assert_eq!(creds.password, "s3cret");
        // The wire copy is deterministically zeroized (fail-closed hygiene even on success).
        assert!(bytes.iter().all(|&b| b == 0), "wire copy must be zeroized");
    }

    /// Malformed payload → fail closed with `InvalidArgument`, and the wire copy is still
    /// zeroized before returning — no plaintext lingers even on a rejected payload.
    #[test]
    fn parse_secret_payload_malformed_fails_closed_and_zeroizes() {
        let mut bytes = b"{\"version\":1,\"username\":\"student\",\"password\":\"hunter2\"}"
            .to_vec();
        // Corrupt the shape (drop the closing brace) while keeping the password substring.
        bytes.pop();
        let status = HelperControlService::parse_secret_payload(&mut bytes).expect_err("must fail");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(bytes.iter().all(|&b| b == 0), "wire copy must be zeroized");
        assert!(
            !status.to_string().contains("hunter2"),
            "error must not carry plaintext"
        );
    }

    /// Unsupported version → fail closed with `InvalidArgument` (forward-compat guard).
    #[test]
    fn parse_secret_payload_unsupported_version_rejected() {
        let mut bytes = b"{\"version\":99,\"username\":\"student\",\"password\":\"s3cret\"}"
            .to_vec();
        let status = HelperControlService::parse_secret_payload(&mut bytes).expect_err("must fail");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(status.to_string().contains("unsupported version"));
    }

    // -----------------------------------------------------------------------
    // S3/Tier 2: ServiceManage unit tests (no transport needed)
    // -----------------------------------------------------------------------

    use exv_vpn_domain::identity::ConnectionBindingDigest;

    /// A transport-verified peer extension (simulates the named-pipe transport after auth).
    fn test_peer() -> NamedPipeConnectInfo {
        NamedPipeConnectInfo(crate::grpc_transport::TransportPeerInfo {
            verified: true,
            process_id: 42,
            user_sid: "S-1-5-21-exv-test".to_string(),
            account_name: "exv-test".to_string(),
            principal: PrincipalDigest::try_from([1u8; 32]).expect("principal"),
            connection_digest: ConnectionBindingDigest::try_from([2u8; 32]).expect("connection"),
        })
    }

    /// A verified-peer `ServiceManageRequest` with the given action.
    fn service_manage_request(
        action: Option<generated::service_manage_request::Action>,
    ) -> Request<generated::ServiceManageRequest> {
        let mut request = Request::new(generated::ServiceManageRequest { action });
        request.extensions_mut().insert(test_peer());
        request
    }

    /// `ServiceManage` without a transport-verified peer fails closed
    /// (unauthenticated) — an unverified peer must never read the deep self-report.
    #[tokio::test]
    async fn service_manage_without_verified_peer_rejected() {
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

    /// A default/absent action is `InvalidArgument` — Tier 2 v1 lands ONLY `query`.
    #[tokio::test]
    async fn service_manage_rejects_missing_action() {
        let service = HelperControlService::new();
        let request = service_manage_request(None);
        let status = service
            .service_manage(request)
            .await
            .expect_err("missing action must fail");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    /// Oneshot default report: mode="oneshot", psk_present=false,
    /// control_plane_ready=true (default seam: a runnable control plane answers
    /// RPCs), runtime_epoch is 16 bytes, and the authority fence is populated.
    #[tokio::test]
    async fn service_manage_oneshot_default_report() {
        let service = HelperControlService::new();
        let request = service_manage_request(Some(
            generated::service_manage_request::Action::Query(
                generated::ServiceSelfQuery::default(),
            ),
        ));
        let reply = service
            .service_manage(request)
            .await
            .expect("query succeeds")
            .into_inner();
        let report = reply.self_report.expect("self_report present");
        assert_eq!(report.connection_mode, "oneshot");
        assert!(!report.psk_present, "oneshot default has no service PSK");
        assert!(report.control_plane_ready, "oneshot default control plane is ready");
        assert_eq!(report.runtime_epoch.len(), 16, "runtime_epoch is 16 bytes");
        let fence = report.authority_fence.expect("authority fence present");
        assert_ne!(fence.authority_epoch, 0, "authority epoch is set");
        assert!(
            !fence.platform_authority_instance_id.is_empty(),
            "instance id set"
        );
    }

    /// `with_service_self` injection is reflected: psk_present=true and
    /// control_plane_ready mirrors the shared AtomicBool (the report reads the
    /// SAME carrier the accept-loop writes).
    #[tokio::test]
    async fn service_manage_with_service_self_injection() {
        let control_plane_ready = Arc::new(AtomicBool::new(true));
        let service =
            HelperControlService::new().with_service_self(Arc::clone(&control_plane_ready), true);
        let request = service_manage_request(Some(
            generated::service_manage_request::Action::Query(
                generated::ServiceSelfQuery::default(),
            ),
        ));
        let reply = service
            .service_manage(request)
            .await
            .expect("query succeeds")
            .into_inner();
        let report = reply.self_report.expect("self_report present");
        assert!(report.psk_present, "injected psk_present must be true");
        assert!(report.control_plane_ready, "injected ready must be true");
        // The report reads the SAME shared AtomicBool: flip it and the next query
        // reflects the change (the accept-loop store(true) path is mirrored here).
        control_plane_ready.store(false, Ordering::SeqCst);
        let request = service_manage_request(Some(
            generated::service_manage_request::Action::Query(
                generated::ServiceSelfQuery::default(),
            ),
        ));
        let reply = service
            .service_manage(request)
            .await
            .expect("second query succeeds")
            .into_inner();
        let report = reply.self_report.expect("self_report present");
        assert!(
            !report.control_plane_ready,
            "report must reflect the shared AtomicBool"
        );
    }
}
