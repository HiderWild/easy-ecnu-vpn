//! wire ↔ UI 镜像类型的机械映射（P4-b）。
//!
//! core 是唯一语义网关，UI 不直连 engine（计划 §1）。本模块把
//! [`exv_vpn_wire::generated`]（复用 Root workspace 的 proto 生成代码）的
//! `KernelControl` 消息映射到 UI 侧镜像类型（[`super::state`] / [`super::logs`]），
//! 并把 UI 意图组装为 wire 请求（Connect/Stop/RespondInteraction）。
//!
//! 政策（common.proto）：snapshots/events 永不携带口令、cookie、原始证书或自由文本
//! 诊断栈——UI 侧 RuntimeState 是 redacted 精简视图（无 attempt/lease/proof 内部
//! refs），本模块负责裁剪。

use exv_vpn_wire::generated::{self as wire};
use sha2::{Digest, Sha256};

use super::logs::LogEvent;
use super::state::{
    ConnectPhase, OperationReply, OperationResult, ProxyTunAdapter, ProxyTunDetection,
    ReconnectStatus, RuntimeEvent, RuntimeEventKind, RuntimeSnapshot, RuntimeState,
    ServiceControlAction, ServiceControlReply, ServiceStatus, SystemProxyDetection, VpnError,
};
use super::stats::{RuntimeStats, StatsPhase};

// ---------------------------------------------------------------------------
// 请求组装（UI 意图 → wire 请求）
// ---------------------------------------------------------------------------

/// 当前进程用户 SID（wire 身份 ref 派生源；与 host `verify_ui_peer` 的
/// `principal = sha256("sid:{sid}")` 同源）。解析失败 → `None`（fail closed，
/// 调用方拒绝组装）。
#[must_use]
pub fn current_principal_digest() -> Option<[u8; 32]> {
    let sid = super::core_transport::current_user_sid()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(format!("sid:{sid}").as_bytes()));
    Some(out)
}

/// 组装 `KernelControl.Connect` 请求：UI `ConnectIntent` → 完整 wire `ConnectIntent`
/// （lookup_key：principal_digest = 当前用户 SID 派生、method=CONNECT、随机
/// runtime_epoch；`operation_id` 由调用方（命令层）生成并传入——**同一 id 必须用于
/// 请求与回传**，host 以 lookup_key.operation_id 关联状态事件；request_digest 32
/// 字节；profile 从 UI 引用）。
///
/// UI 提交的一次性 `secret_payload` 原样进入 wire（core 侧会零化其副本；UI 侧
/// 请求 move 后随 drop 释放）。
///
/// # Errors
/// 当前用户 SID 无法解析（无法派生 principal digest）→ `AppError::Internal`。
pub fn connect_request(
    intent: &super::client::ConnectIntent,
    operation_id: Vec<u8>,
) -> Result<wire::ConnectRequest, super::error::AppError> {
    let principal_digest = current_principal_digest().ok_or_else(|| {
        super::error::AppError::Internal(
            "connect: cannot derive principal digest (user SID)".to_string(),
        )
    })?;
    let runtime_epoch = uuid::Uuid::new_v4().as_bytes().to_vec();
    // request_digest 契约 = 32 字节；Uuid 是 16 字节，经 SHA-256 派生为 32 字节。
    let request_digest = sha256(uuid::Uuid::new_v4().as_bytes());
    let profile = (!intent.profile_ref.is_empty()).then(|| wire::ConnectionProfileRef {
        identity_digest: sha256(intent.profile_ref.as_bytes()),
    });
    Ok(wire::ConnectRequest {
        intent: Some(wire::ConnectIntent {
            lookup_key: Some(wire::OperationLookupKey {
                principal_digest: principal_digest.to_vec(),
                method: wire::OperationMethod::Connect as i32,
                runtime_epoch,
                operation_id,
            }),
            request_digest,
            profile,
        }),
        secret_payload: intent
            .secret_payload
            .clone()
            .unwrap_or_default()
            .into_bytes(),
    })
}

/// 组装 `KernelControl.Stop` 请求（method=STOP 的完整意图；principal 派生同
/// Connect；`operation_id` 由调用方生成并传入——同 connect 关联契约）。
///
/// # Errors
/// 当前用户 SID 无法解析 → `AppError::Internal`。
pub fn stop_request(operation_id: Vec<u8>) -> Result<wire::StopRequest, super::error::AppError> {
    let principal_digest = current_principal_digest().ok_or_else(|| {
        super::error::AppError::Internal(
            "stop: cannot derive principal digest (user SID)".to_string(),
        )
    })?;
    Ok(wire::StopRequest {
        intent: Some(wire::StopIntent {
            lookup_key: Some(wire::OperationLookupKey {
                principal_digest: principal_digest.to_vec(),
                method: wire::OperationMethod::Stop as i32,
                runtime_epoch: uuid::Uuid::new_v4().as_bytes().to_vec(),
                operation_id,
            }),
            // request_digest 契约 = 32 字节（SHA-256 派生）。
            request_digest: sha256(uuid::Uuid::new_v4().as_bytes()),
        }),
    })
}

/// 组装 `KernelControl.RespondInteraction` 请求。
///
/// `runtime_epoch` 应来自交互提示事件；P4-b 期间 UI 尚未透传该字段（命令签名
/// 只有 interaction_id + response_payload），此处用确定性占位（16 字节 0）——core
/// 校验仅要求 16 字节长度，engine 侧 seam 当前返回 typed `Unimplemented`（P5 补
/// 真实交互流后由事件携带真 epoch）。
#[must_use]
pub fn interaction_response(
    interaction_id: Vec<u8>,
    response_payload: Vec<u8>,
) -> wire::InteractionResponse {
    wire::InteractionResponse {
        interaction_id,
        runtime_epoch: vec![0u8; 16],
        response_payload,
    }
}

/// 32 字节 SHA-256（wire 身份 ref 的确定性派生）。
fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

// ---------------------------------------------------------------------------
// wire → UI：快照 / 事件 / 回复 / 日志
// ---------------------------------------------------------------------------

/// wire `RuntimeSnapshot` → UI `RuntimeSnapshot`（redacted：无内部 refs；
/// stats-wire 方案 A：`stats` 随快照携带，`None` = 尚无样本；C5-wire：`proxy_tun`
/// 随快照携带，`None` = 未探测/探测失败；R1：`operation_id` 随快照携带，hex16，
/// 空 = 无在途操作；S2：`system_proxy` 随快照携带，`None` = 未检测/检测失败；
/// S4：`reconnect` 随快照携带，`None` = 重连不适用）。
#[must_use]
pub fn snapshot_from_wire(
    wire_snap: &wire::RuntimeSnapshot,
    monotonic_tick: u64,
) -> RuntimeSnapshot {
    RuntimeSnapshot {
        runtime: runtime_state_from_wire(wire_snap.state.as_ref()),
        monotonic_tick,
        stats: wire_snap.stats.as_ref().map(stats_from_wire),
        proxy_tun: wire_snap
            .proxy_tun
            .as_ref()
            .map(proxy_tun_detection_from_wire),
        operation_id: opt_hex(&wire_snap.operation_id),
        service_status: wire_snap
            .service_status
            .as_ref()
            .map(service_status_from_wire),
        mode: wire_snap.mode.clone(),
        system_proxy: wire_snap
            .system_proxy
            .as_ref()
            .map(system_proxy_detection_from_wire),
        reconnect: wire_snap
            .reconnect
            .as_ref()
            .map(reconnect_status_from_wire),
    }
}

/// wire `RuntimeEvent` → UI `RuntimeEvent`（UI snapshot 内嵌同一 monotonic_tick；
/// 事件级 operation_id 与快照内嵌的保持一致，前端二选一即可）。
#[must_use]
pub fn event_from_wire(ev: &wire::RuntimeEvent) -> RuntimeEvent {
    let operation_id = opt_hex(&ev.operation_id);
    let snapshot = ev
        .snapshot
        .as_ref()
        .map(|s| snapshot_from_wire(s, ev.monotonic_tick))
        .unwrap_or_else(|| RuntimeSnapshot {
            runtime: RuntimeState::Idle {
                last_cleanup_at_ms: None,
            },
            monotonic_tick: ev.monotonic_tick,
            stats: None,
            proxy_tun: None,
            operation_id: operation_id.clone(),
            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        });
    RuntimeEvent {
        monotonic_tick: ev.monotonic_tick,
        kind: if ev.kind == wire::RuntimeEventKind::Snapshot as i32 {
            RuntimeEventKind::Snapshot
        } else {
            RuntimeEventKind::Transition
        },
        snapshot,
        operation_id,
    }
}

/// wire `OperationReply` → UI `OperationReply`（terminal oneof → pending /
/// succeeded / failed；`terminal: None` = **pending**（R1w 异步受理，终态走 status
/// 通道），不是失败——修复前端「pending 误报失败」）。`operation_id` 由调用方
/// （命令层）回填其生成的那个 id。
#[must_use]
pub fn operation_reply_from_wire(reply: &wire::OperationReply) -> OperationReply {
    let result = match reply.terminal.as_ref().and_then(|t| t.result.as_ref()) {
        Some(wire::operation_terminal::Result::Succeeded(receipt)) => OperationResult::Succeeded {
            effect_id: receipt
                .effect_id
                .iter()
                .map(hex8)
                .collect::<String>()
                .into(),
            authority_epoch: receipt
                .authority_fence
                .as_ref()
                .and_then(|f| (f.authority_epoch != 0).then_some(f.authority_epoch))
                .or(Some(receipt.ownership_version)),
        },
        Some(wire::operation_terminal::Result::Failed(failed)) => OperationResult::Failed {
            error: failed.error.as_ref().map(vpn_error_from_wire),
        },
        // terminal: None = 尚无终局（R1w pending：core 已受理，终态走 status 通道）。
        None => OperationResult::Pending,
    };
    OperationReply {
        result,
        operation_id: None,
    }
}

/// wire `LogEvent` → UI `LogEvent`（字段一一对应；fields 为无 secret 的键值元数据）。
///
/// P4-b 日志 wire 缺口 seam：core `KernelControl` 服务未向 UI 暴露 StreamLogs，
/// 此映射在日志订阅接线（proto 变更后）时启用。
#[must_use]
#[allow(dead_code)]
pub fn log_event_from_wire(ev: &wire::LogEvent) -> LogEvent {
    LogEvent {
        level: ev.level.clone(),
        component: ev.component.clone(),
        code: ev.code.clone(),
        message: ev.message.clone(),
        // wire fields 是 HashMap；UI 用 BTreeMap（确定性序列化顺序）。
        fields: ev
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        timestamp_ms: ev.timestamp_ms,
    }
}

/// wire `RuntimeStats` → UI `RuntimeStats`（stats-wire 方案 A；字段一一对应）。
#[must_use]
fn stats_from_wire(w: &wire::RuntimeStats) -> RuntimeStats {
    RuntimeStats {
        rx_bytes: w.rx_bytes,
        tx_bytes: w.tx_bytes,
        rx_rate_bps: w.rx_rate_bps,
        tx_rate_bps: w.tx_rate_bps,
        latency_ms: w.latency_ms,
        phase: stats_phase_from_wire(w.phase),
        engine_sequence: w.engine_sequence,
        sample_tick: w.sample_tick,
    }
}

/// wire `StatsPhase` int → UI `StatsPhase`（未知/未指定 → `Unspecified`）。
#[must_use]
fn stats_phase_from_wire(phase: i32) -> StatsPhase {
    match phase {
        1 => StatsPhase::Idle,
        2 => StatsPhase::Connecting,
        3 => StatsPhase::Connected,
        4 => StatsPhase::Stopping,
        5 => StatsPhase::Failed,
        _ => StatsPhase::Unspecified,
    }
}

/// wire `ProxyTunDetection` → UI `ProxyTunDetection`（C5-wire；字段一一对应）。
#[must_use]
fn proxy_tun_detection_from_wire(w: &wire::ProxyTunDetection) -> ProxyTunDetection {
    ProxyTunDetection {
        detected: w.detected,
        adapters: w
            .adapters
            .iter()
            .map(|a| ProxyTunAdapter {
                name: a.name.clone(),
                description: a.description.clone(),
                if_index: a.if_index,
                kind: a.kind.clone(),
            })
            .collect(),
        route_policy: w.route_policy.clone(),
    }
}

/// wire `SystemProxyDetection` → UI `SystemProxyDetection`（S2；字段一一对应）。
#[must_use]
fn system_proxy_detection_from_wire(w: &wire::SystemProxyDetection) -> SystemProxyDetection {
    SystemProxyDetection {
        mode: w.mode.clone(),
        endpoint_count: w.endpoint_count,
        bypass_merged: w.bypass_merged,
        topology: w.topology.clone(),
    }
}

/// wire `ReconnectStatus` → UI `ReconnectStatus`（S4；字段一一对应）。
#[must_use]
fn reconnect_status_from_wire(w: &wire::ReconnectStatus) -> ReconnectStatus {
    ReconnectStatus {
        auto_reconnect: w.auto_reconnect,
        max_attempts: w.max_attempts,
        current_attempt: w.current_attempt,
        active: w.active,
    }
}

/// wire `ServiceStatus` → UI `ServiceStatus`（S3/D5 字段一一对应 + R3 `health_state`，
/// 仅展示）。
#[must_use]
fn service_status_from_wire(w: &wire::ServiceStatus) -> ServiceStatus {
    ServiceStatus {
        installed: w.installed,
        state: w.state.clone(),
        binary_path: (!w.binary_path.is_empty()).then(|| w.binary_path.clone()),
        health_state: (!w.health_state.is_empty()).then(|| w.health_state.clone()),
    }
}

/// 组装 `KernelControl.ServiceControl` 请求：UI action → wire action（S3/D5）。
///
/// query 为非提权读；install/uninstall/start 为变更 action，host 侧走 write path
/// gate + engine 子命令 runas 提权 seam（D4）。
#[must_use]
pub fn service_control_request(action: ServiceControlAction) -> wire::ServiceControlRequest {
    use wire::service_control_request::Action as WireAction;
    let action = match action {
        ServiceControlAction::Query => WireAction::Query(wire::ServiceStatusQuery {}),
        ServiceControlAction::Install => WireAction::Install(wire::ServiceInstall {}),
        ServiceControlAction::Uninstall => WireAction::Uninstall(wire::ServiceUninstall {}),
        ServiceControlAction::Start => WireAction::Start(wire::ServiceStart {}),
    };
    wire::ServiceControlRequest {
        action: Some(action),
    }
}

/// wire `ServiceControlReply` → UI `ServiceControlReply`（S3/D5；post-action 状态 + 结果）。
#[must_use]
pub fn service_control_reply_from_wire(reply: &wire::ServiceControlReply) -> ServiceControlReply {
    ServiceControlReply {
        service_status: reply.service_status.as_ref().map(service_status_from_wire),
        ok: reply.ok,
        message: reply.message.clone(),
    }
}

/// wire `VpnError` → UI `VpnError`（redacted：仅稳定 code 字符串；自由文本诊断栈
/// 永不进 UI——wire 的 native 字段是 redacted 类别，不展开）。
#[must_use]
fn vpn_error_from_wire(err: &wire::VpnError) -> VpnError {
    VpnError {
        code: wire::ErrorCode::try_from(err.code)
            .map(|c| c.as_str_name().to_string())
            .unwrap_or_else(|_| "ERROR_CODE_UNSPECIFIED".to_string()),
        message: String::new(),
    }
}

/// wire `runtime_snapshot::State` → UI `RuntimeState`（redacted 精简视图）。
#[must_use]
fn runtime_state_from_wire(state: Option<&wire::runtime_snapshot::State>) -> RuntimeState {
    use wire::runtime_snapshot::State as S;
    match state {
        Some(S::Idle(_)) => RuntimeState::Idle {
            last_cleanup_at_ms: None,
        },
        Some(S::Connecting(s)) => {
            let attempt_id = s
                .attempt
                .as_ref()
                .and_then(|a| (!a.attempt_id.is_empty()).then(|| hex(&a.attempt_id)));
            RuntimeState::Connecting {
                phase: connect_phase_from_wire(s.phase),
                attempt_id,
                phase_index: connect_phase_index(s.phase),
            }
        }
        Some(S::AwaitingInteraction(s)) => RuntimeState::AwaitingInteraction {
            attempt_id: s
                .attempt
                .as_ref()
                .and_then(|a| (!a.attempt_id.is_empty()).then(|| hex(&a.attempt_id))),
            prompt_deadline_ms: s
                .prompt
                .as_ref()
                .and_then(|p| (p.deadline != 0).then_some(p.deadline)),
        },
        Some(S::Connected(connected)) => RuntimeState::Connected {
            session_established_at_ms: (connected.session_established_at_ms > 0)
                .then_some(connected.session_established_at_ms),
            summary: None,
        },
        Some(S::Stopping(_)) => RuntimeState::Stopping { reason: None },
        Some(S::Reconciling(s)) => RuntimeState::Reconciling {
            blocking_error: s
                .obligation
                .as_ref()
                .and_then(|o| o.blocking_error.as_ref())
                .map(vpn_error_from_wire),
        },
        Some(S::FailedClean(s)) => RuntimeState::FailedClean {
            error: s.last_error.as_ref().map(vpn_error_from_wire),
        },
        Some(S::FailedDirty(s)) => RuntimeState::FailedDirty {
            error: s.last_error.as_ref().map(vpn_error_from_wire),
            has_obligation: s.obligation.is_some(),
        },
        None => RuntimeState::Idle {
            last_cleanup_at_ms: None,
        },
    }
}

/// wire `ConnectPhase` int → UI `ConnectPhase`（未知/未指定回落 `ConnectingControl`）。
#[must_use]
fn connect_phase_from_wire(phase: i32) -> ConnectPhase {
    match phase {
        1 => ConnectPhase::ObservingOwnedState,
        2 => ConnectPhase::AcquiringPlatformLease,
        3 => ConnectPhase::ConnectingControl,
        4 => ConnectPhase::AwaitingInteraction,
        5 => ConnectPhase::NegotiatingTunnel,
        6 => ConnectPhase::ApplyingPlatformTunnel,
        7 => ConnectPhase::AttachingPacketBoundary,
        8 => ConnectPhase::StartingDataPlane,
        _ => ConnectPhase::ConnectingControl,
    }
}

/// wire `ConnectPhase` int → UI 进度序号（0..=7；未指定回落 ConnectingControl=2）。
#[must_use]
fn connect_phase_index(phase: i32) -> u8 {
    connect_phase_from_wire(phase).index()
}

/// 小写 hex 编码（UI attempt_id / effect_id / operation_id 的字符串展示）。
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 非空字节的 hex 编码（`Some`），空/缺省 → `None`（R1 operation_id：空 = 无在途
/// 操作）。
fn opt_hex(bytes: &[u8]) -> Option<String> {
    (!bytes.is_empty()).then(|| hex(bytes))
}

/// 单字节 hex（effect_id 展示复用）。
fn hex8(b: &u8) -> String {
    format!("{b:02x}")
}

// ---------------------------------------------------------------------------
// 单元测试：wire → UI 映射 + 请求组装。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// wire Idle 快照 → UI Idle。
    #[test]
    fn snapshot_idle_maps_to_ui_idle() {
        let w = wire::RuntimeSnapshot {
            state: Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
                last_cleanup: None,
            })),
            stats: None,
            proxy_tun: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        };
        let ui = snapshot_from_wire(&w, 7);
        assert_eq!(ui.monotonic_tick, 7);
        assert!(matches!(ui.runtime, RuntimeState::Idle { .. }));
    }

    /// wire Connecting（phase=STARTING_DATA_PLANE，携带 attempt_id）→ UI Connecting。
    #[test]
    fn snapshot_connecting_maps_phase_and_attempt() {
        let w = wire::RuntimeSnapshot {
            state: Some(wire::runtime_snapshot::State::Connecting(
                wire::ConnectingState {
                    attempt: Some(wire::Attempt {
                        runtime_epoch: vec![0xEE; 16],
                        attempt_id: vec![0xAB; 16],
                        intent: None,
                        prior_error: None,
                    }),
                    phase: wire::ConnectPhase::StartingDataPlane as i32,
                },
            )),
            stats: None,
            proxy_tun: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        };
        let ui = snapshot_from_wire(&w, 1);
        let RuntimeState::Connecting {
            phase,
            attempt_id,
            phase_index,
        } = ui.runtime
        else {
            panic!("expected connecting");
        };
        assert_eq!(phase, ConnectPhase::StartingDataPlane);
        assert_eq!(phase_index, 7);
        assert_eq!(
            attempt_id,
            Some("ab".repeat(16)),
            "attempt_id 必须小写 hex 展示"
        );
    }

    /// wire Connected（内部 refs 不泄漏）→ UI Connected（redacted：无 summary）。
    #[test]
    fn snapshot_connected_is_redacted() {
        let w = wire::RuntimeSnapshot {
            state: Some(wire::runtime_snapshot::State::Connected(
                wire::ConnectedState {
                    session: Some(wire::ConnectedSession {
                        attempt: Some(wire::Attempt::default()),
                        protocol_session: Some(wire::ProtocolSessionRef {
                            identity_digest: vec![1; 32],
                        }),
                        platform_ownership: None,
                        packet_lease: None,
                        platform_ready: None,
                        data_running: None,
                    }),
                    session_established_at_ms: 1_700_000_000_123,
                },
            )),
            stats: None,
            proxy_tun: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        };
        let ui = snapshot_from_wire(&w, 2);
        assert!(matches!(
            ui.runtime,
            RuntimeState::Connected {
                session_established_at_ms: Some(1_700_000_000_123),
                summary: None,
            }
        ));
    }

    /// wire FailedDirty（带 obligation）→ UI FailedDirty has_obligation=true + error code。
    #[test]
    fn snapshot_failed_dirty_maps_obligation_and_error() {
        let w = wire::RuntimeSnapshot {
            state: Some(wire::runtime_snapshot::State::FailedDirty(
                wire::FailedDirtyState {
                    last_error: Some(wire::VpnError {
                        code: wire::ErrorCode::Unauthorized as i32,
                        ..Default::default()
                    }),
                    context: None,
                    obligation: Some(wire::RecoveryObligation::default()),
                },
            )),
            stats: None,
            proxy_tun: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        };
        let ui = snapshot_from_wire(&w, 3);
        let RuntimeState::FailedDirty {
            error,
            has_obligation,
        } = ui.runtime
        else {
            panic!("expected failed_dirty");
        };
        assert!(has_obligation);
        assert_eq!(error.unwrap().code, "ERROR_CODE_UNAUTHORIZED");
    }

    /// wire `RuntimeSnapshot.stats`（stats-wire 方案 A）→ UI `RuntimeStats`：字段
    /// 一一对应、phase 判别映射。
    #[test]
    fn snapshot_stats_map_to_ui_mirror() {
        let w = wire::RuntimeSnapshot {
            state: Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
                last_cleanup: None,
            })),
            stats: Some(wire::RuntimeStats {
                rx_bytes: 42,
                tx_bytes: 24,
                rx_rate_bps: 1000,
                tx_rate_bps: 500,
                latency_ms: 9,
                phase: wire::StatsPhase::Stopping as i32,
                engine_sequence: 6,
                sample_tick: 11,
            }),
            proxy_tun: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        };
        let ui = snapshot_from_wire(&w, 1);
        let stats = ui.stats.expect("stats mapped");
        assert_eq!(stats.rx_bytes, 42);
        assert_eq!(stats.tx_bytes, 24);
        assert_eq!(stats.rx_rate_bps, 1000);
        assert_eq!(stats.tx_rate_bps, 500);
        assert_eq!(stats.latency_ms, 9);
        assert_eq!(stats.phase, StatsPhase::Stopping);
        assert_eq!(stats.engine_sequence, 6);
        assert_eq!(stats.sample_tick, 11);
    }

    /// wire `RuntimeSnapshot.proxy_tun`（C5-wire）→ UI `ProxyTunDetection`：字段一一
    /// 对应（detected/adapters/route_policy）；缺省（None）→ UI `proxy_tun` 为空。
    #[test]
    fn snapshot_proxy_tun_maps_to_ui_mirror() {
        let w = wire::RuntimeSnapshot {
            state: Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
                last_cleanup: None,
            })),
            stats: None,
            proxy_tun: Some(wire::ProxyTunDetection {
                detected: true,
                adapters: vec![wire::ProxyTunAdapter {
                    name: "Mihomo".to_string(),
                    description: "Wintun Userspace Tunnel".to_string(),
                    if_index: 42,
                    kind: "proxy_tun".to_string(),
                }],
                route_policy: "exv-before-proxy-tun".to_string(),
            }),
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        };
        let ui = snapshot_from_wire(&w, 1);
        let detection = ui.proxy_tun.expect("proxy_tun mapped");
        assert!(detection.detected);
        assert_eq!(detection.route_policy, "exv-before-proxy-tun");
        assert_eq!(detection.adapters.len(), 1);
        assert_eq!(detection.adapters[0].name, "Mihomo");
        assert_eq!(detection.adapters[0].description, "Wintun Userspace Tunnel");
        assert_eq!(detection.adapters[0].if_index, 42);
        assert_eq!(detection.adapters[0].kind, "proxy_tun");

        // None → UI proxy_tun 为空（未探测/探测失败）。
        let empty = wire::RuntimeSnapshot {
            state: None,
            stats: None,
            proxy_tun: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        };
        assert!(snapshot_from_wire(&empty, 2).proxy_tun.is_none());
    }

    /// wire `RuntimeSnapshot.system_proxy`（S2）→ UI `SystemProxyDetection`：字段一一
    /// 对应（mode/endpoint_count/bypass_merged/topology）；缺省（None）→ UI `system_proxy`
    /// 为空。
    #[test]
    fn snapshot_system_proxy_maps_to_ui_mirror() {
        let w = wire::RuntimeSnapshot {
            state: Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
                last_cleanup: None,
            })),
            stats: None,
            proxy_tun: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: Some(wire::SystemProxyDetection {
                mode: "automatic".to_string(),
                endpoint_count: 3,
                bypass_merged: true,
                topology: "t2".to_string(),
            }),
            reconnect: None,
        };
        let ui = snapshot_from_wire(&w, 1);
        let detection = ui.system_proxy.expect("system_proxy mapped");
        assert_eq!(detection.mode, "automatic");
        assert_eq!(detection.endpoint_count, 3);
        assert!(detection.bypass_merged);
        assert_eq!(detection.topology, "t2");

        // None → UI system_proxy 为空（未检测/检测失败）。
        let empty = wire::RuntimeSnapshot {
            state: None,
            stats: None,
            proxy_tun: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        };
        assert!(snapshot_from_wire(&empty, 2).system_proxy.is_none());
    }

    /// wire `RuntimeSnapshot.reconnect`（S4）→ UI `ReconnectStatus`：字段一一对应
    /// （auto_reconnect/max_attempts/current_attempt/active）；缺省（None）→ UI
    /// `reconnect` 为空（重连不适用）。
    #[test]
    fn snapshot_reconnect_maps_to_ui_mirror() {
        let w = wire::RuntimeSnapshot {
            state: Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
                last_cleanup: None,
            })),
            stats: None,
            proxy_tun: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: Some(wire::ReconnectStatus {
                auto_reconnect: true,
                max_attempts: 5,
                current_attempt: 2,
                active: true,
            }),
        };
        let ui = snapshot_from_wire(&w, 1);
        let status = ui.reconnect.expect("reconnect mapped");
        assert!(status.auto_reconnect);
        assert_eq!(status.max_attempts, 5);
        assert_eq!(status.current_attempt, 2);
        assert!(status.active);

        // None → UI reconnect 为空（重连不适用/从未建立连接）。
        let empty = wire::RuntimeSnapshot {
            state: None,
            stats: None,
            proxy_tun: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        };
        assert!(snapshot_from_wire(&empty, 2).reconnect.is_none());
    }

    /// `stats_phase_from_wire`：已知判别往返，未知/未指定 → `Unspecified`。
    #[test]
    fn stats_phase_from_wire_round_trips_and_falls_back() {
        for (phase, want) in [
            (1, StatsPhase::Idle),
            (2, StatsPhase::Connecting),
            (3, StatsPhase::Connected),
            (4, StatsPhase::Stopping),
            (5, StatsPhase::Failed),
        ] {
            assert_eq!(stats_phase_from_wire(phase), want, "phase {phase}");
        }
        assert_eq!(stats_phase_from_wire(0), StatsPhase::Unspecified);
        assert_eq!(stats_phase_from_wire(99), StatsPhase::Unspecified);
    }

    /// wire RuntimeEvent（kind=TRANSITION + Connected）→ UI event（tick 内嵌 snapshot）。
    #[test]
    fn event_maps_kind_and_embeds_tick() {
        let w = wire::RuntimeEvent {
            monotonic_tick: 42,
            kind: wire::RuntimeEventKind::Transition as i32,
            snapshot: Some(wire::RuntimeSnapshot {
                state: Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
                    last_cleanup: None,
                })),
                stats: None,
                proxy_tun: None,
                operation_id: vec![],

                service_status: None,
                mode: String::new(),
                system_proxy: None,
                reconnect: None,
            }),
            operation_id: vec![],
        };
        let ui = event_from_wire(&w);
        assert_eq!(ui.monotonic_tick, 42);
        assert_eq!(ui.kind, RuntimeEventKind::Transition);
        assert_eq!(ui.snapshot.monotonic_tick, 42);
    }

    /// wire OperationReply succeeded（receipt 带 effect_id + ownership_version）→ UI。
    #[test]
    fn operation_reply_succeeded_maps_effect_and_epoch() {
        let w = wire::OperationReply {
            terminal: Some(wire::OperationTerminal {
                result: Some(wire::operation_terminal::Result::Succeeded(
                    wire::MutationReceipt {
                        effect_id: vec![0x11; 16],
                        ownership_version: 5,
                        ..Default::default()
                    },
                )),
            }),
        };
        let ui = operation_reply_from_wire(&w);
        let OperationResult::Succeeded {
            effect_id,
            authority_epoch,
        } = ui.result
        else {
            panic!("expected succeeded");
        };
        assert_eq!(effect_id, Some("11".repeat(16)));
        assert_eq!(authority_epoch, Some(5));
    }

    /// wire OperationReply failed（error）→ UI failed with error code。
    #[test]
    fn operation_reply_failed_maps_error() {
        let w = wire::OperationReply {
            terminal: Some(wire::OperationTerminal {
                result: Some(wire::operation_terminal::Result::Failed(
                    wire::OperationFailed {
                        receipt: Some(wire::MutationReceipt::default()),
                        error: Some(wire::VpnError {
                            code: wire::ErrorCode::SessionBusy as i32,
                            ..Default::default()
                        }),
                    },
                )),
            }),
        };
        let ui = operation_reply_from_wire(&w);
        let OperationResult::Failed { error } = ui.result else {
            panic!("expected failed");
        };
        assert_eq!(error.unwrap().code, "ERROR_CODE_SESSION_BUSY");
    }

    /// wire OperationReply（terminal: None = R1w pending）→ UI `Pending`（不是失败——
    /// 前端「pending 误报失败」回归测试）。
    #[test]
    fn operation_reply_pending_when_no_terminal() {
        let w = wire::OperationReply { terminal: None };
        let ui = operation_reply_from_wire(&w);
        assert!(
            matches!(ui.result, OperationResult::Pending),
            "terminal: None 必须映射为 Pending（异步受理），而非 Failed；got {:?}",
            ui.result
        );
        assert_eq!(ui.operation_id, None, "operation_id 由调用方回填");
    }

    /// wire snapshot/event 的 operation_id（非空 → hex16；空 → None）映射 + 事件级与
    /// 快照内嵌一致。
    #[test]
    fn operation_id_maps_hex_and_empty_to_none() {
        let w = wire::RuntimeSnapshot {
            state: Some(wire::runtime_snapshot::State::Idle(wire::IdleState {
                last_cleanup: None,
            })),
            stats: None,
            proxy_tun: None,
            operation_id: vec![0xAB; 16],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        };
        let ui = snapshot_from_wire(&w, 1);
        assert_eq!(
            ui.operation_id,
            Some("ab".repeat(16)),
            "operation_id 小写 hex"
        );

        let empty = wire::RuntimeSnapshot {
            state: None,
            stats: None,
            proxy_tun: None,
            operation_id: vec![],

            service_status: None,
            mode: String::new(),
            system_proxy: None,
            reconnect: None,
        };
        assert_eq!(
            snapshot_from_wire(&empty, 2).operation_id,
            None,
            "空 → None"
        );

        let ev = wire::RuntimeEvent {
            monotonic_tick: 3,
            kind: wire::RuntimeEventKind::Snapshot as i32,
            snapshot: Some(w.clone()),
            operation_id: vec![0xAB; 16],
        };
        let ui_ev = event_from_wire(&ev);
        assert_eq!(ui_ev.operation_id, Some("ab".repeat(16)));
        assert_eq!(
            ui_ev.snapshot.operation_id, ui_ev.operation_id,
            "事件级与快照内嵌 operation_id 一致"
        );
    }

    /// connect_request 组装完整意图：lookup_key method=CONNECT、digest 32 字节、
    /// profile 从 UI 引用派生、secret_payload 透传、operation_id 透传调用方 id。
    #[test]
    fn connect_request_builds_well_formed_intent() {
        let intent = super::super::client::ConnectIntent {
            profile_ref: "ecnu".to_string(),
            secret_payload: Some("ui-secret".to_string()),
        };
        let op_id = vec![0xCD; 16];
        let req = connect_request(&intent, op_id.clone()).expect("connect request builds");
        let w_intent = req.intent.expect("intent");
        let key = w_intent.lookup_key.expect("lookup key");
        assert_eq!(key.method, wire::OperationMethod::Connect as i32);
        assert_eq!(w_intent.request_digest.len(), 32);
        assert_eq!(key.runtime_epoch.len(), 16);
        assert_eq!(
            key.operation_id, op_id,
            "operation_id 必须透传调用方 id（事件关联契约）"
        );
        let profile = w_intent.profile.expect("profile");
        assert_eq!(profile.identity_digest.len(), 32);
        assert_eq!(req.secret_payload, b"ui-secret");
    }

    /// stop_request 组装完整 STOP 意图（method=STOP、digest 32 字节、operation_id 透传）。
    #[test]
    fn stop_request_builds_well_formed_intent() {
        let op_id = vec![0xCD; 16];
        let req = stop_request(op_id.clone()).expect("stop request builds");
        let intent = req.intent.expect("intent");
        assert_eq!(
            intent.lookup_key.as_ref().expect("key").method,
            wire::OperationMethod::Stop as i32
        );
        assert_eq!(
            intent.lookup_key.as_ref().expect("key").operation_id,
            op_id,
            "operation_id 必须透传调用方 id（事件关联契约）"
        );
        assert_eq!(intent.request_digest.len(), 32);
    }
}
