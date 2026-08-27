// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Non-privileged host composition (W27-I): binds the verified helper identity
//! (WSP1 §6, anti fake-helper), observes the real process token elevation
//! fact, wraps exactly one portable runtime actor (H80) and one
//! [`KernelControlGate`](crate::kernel_control::KernelControlGate), and
//! composes the W23A packet channel + W23B packet relay WITHOUT re-implementing
//! them. Pure composition: no real pipe or session I/O happens here — the
//! host's `main.rs` establishes the helper pipe connection after this
//! composition is built.

// The portable H80 host types are re-exported through this seam so the win32
// tests never import the portable crate directly.
pub use exv_vpn_host::composition::{HostEffect, HostEvent, HostPhase};

use std::ffi::c_void;

use exv_vpn_data_plane::budget::DataPlaneDirection;
use exv_vpn_data_plane::teardown::TeardownSide;
use exv_vpn_domain::error::VpnError;
use exv_vpn_domain::identity::{ResourceIdentityDigest, RuntimeEpoch};
use exv_vpn_domain::model::PacketLeaseRef;
use exv_vpn_resource::authority::{PeerCapability, PeerContext};
use exv_engine::packet_relay::{
    AttachedPacketRelay, RelayDirection, RelayTerminalSource,
};
use exv_vpn_win32_ipc::packet_channel::PacketChannel;
use exv_vpn_win32_ipc::packet_limits::PacketLimits;
use exv_vpn_win32_ipc::peer_auth::VerifiedPipePeer;
use exv_vpn_win32_resource::packet_capability::PacketCapability;
use uuid::Uuid;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::kernel_control::KernelControlGate;

/// The portable H80 host composition: the single runtime actor of this host.
type RuntimeActor = exv_vpn_host::composition::HostComposition;

/// The deterministic connection id the pure composition's packet leg attaches
/// with (the real flow binds the winning relay stream's connection id).
const PACKET_LEG_CONNECTION_ID: u64 = 1;

/// The non-privileged host composition (frozen seam, W27-I).
///
/// Wraps exactly one runtime actor — the portable H80 composition, owned as an
/// array of exactly one slot so a second business state machine cannot hide —
/// and one [`KernelControlGate`]. `KernelControl` only routes commands through
/// the gate; it never owns a second business state machine.
pub struct HostComposition {
    /// The verified helper identity the host is bound to (WSP1 §6).
    helper: VerifiedPipePeer,
    /// The observed process token elevation fact (read at compose time, never
    /// hardcoded).
    token_elevated: bool,
    /// The runtime actors this composition owns: exactly one.
    actors: [RuntimeActor; 1],
    /// The `KernelControl` gate (routes commands; owns no state machine).
    gate: KernelControlGate,
    /// The W23A channel + W23B relay packet leg (attached at compose time,
    /// pure construction; the send legs start with [`HostEvent::ProtocolEstablished`]).
    relay: AttachedPacketRelay,
    /// Cancelled RPC waiter record: RPC cancel ≠ business Stop.
    rpc_waiter_cancellations: u64,
    /// Whether a bounded complete teardown has started.
    teardown_started: bool,
    /// Business Stop requests emitted (the only business cancel is
    /// KernelControl.Stop / an explicit disconnect).
    stop_requests: u64,
    /// Whether the host exit path already ran (idempotent Stop).
    exited: bool,
    /// R1: the 16-byte operation id of the in-flight connect/stop operation
    /// (host-side correlation register; set at dispatch, cleared on terminal).
    operation_id: Option<[u8; 16]>,
    /// R1: the latest connect-failure's wire error (snapshot source for the
    /// `Failed` state; the portable actor holds the domain error for the state
    /// machine). None = no failure observed since the last connect.
    last_wire_error: Option<exv_vpn_wire::generated::VpnError>,
    /// 当前已连接会话由 engine 确认的起点（Unix epoch ms）。这是状态事件携带的
    /// 权威事实；后续 GetSnapshot/统计刷新必须复用，不能因重新组装快照而回退为 0。
    session_established_at_ms: Option<i64>,
}

/// Compose the non-privileged host from the verified helper identity.
///
/// Pure composition (no pipe/session I/O): binds the verified helper PID+SID,
/// records the real process token elevation observation, wraps exactly one
/// portable runtime actor and one [`KernelControlGate`], and composes the W23A
/// channel + W23B relay packet leg. The real helper pipe connection is
/// established by `main.rs` after this composition is built.
///
/// # Errors
///
/// Returns [`VpnError`] when the W23A packet channel cannot be built from the
/// frozen MVP limits or the W23B atomic attach refuses (both pure and
/// deterministic; the MVP knobs are valid, so the error path exists only for
/// typed symmetry with the composed seams).
pub fn compose_nonprivileged_host(helper: &VerifiedPipePeer) -> Result<HostComposition, VpnError> {
    // W23A: the packet channel is built from the frozen MVP limits (pure, no
    // I/O); the primary queue direction is the transport->packet leg.
    let channel = PacketChannel::new(&PacketLimits::mvp(), DataPlaneDirection::ProtocolToPacket)?;
    // W23B: the relay is attached atomically from a single-use capability. The
    // lease/epoch are deterministic stand-ins — the runtime (R31-I) issues the
    // real lease at protocol establishment.
    let mut capability =
        PacketCapability::issue(deterministic_packet_lease(), deterministic_runtime_epoch());
    let attachment = AttachedPacketRelay::attach(&mut capability, PACKET_LEG_CONNECTION_ID)?;
    let relay = AttachedPacketRelay::new(attachment, channel, PacketLimits::mvp());

    Ok(HostComposition {
        helper: helper.clone(),
        token_elevated: observe_process_token_elevation(),
        actors: [RuntimeActor::new()],
        gate: KernelControlGate::new(),
        relay,
        rpc_waiter_cancellations: 0,
        teardown_started: false,
        stop_requests: 0,
        exited: false,
        operation_id: None,
        last_wire_error: None,
        session_established_at_ms: None,
    })
}

impl HostComposition {
    /// The observed process token elevation fact (real observation, never
    /// hardcoded). The non-privileged host premise: elevation is the helper's
    /// job, not the host's.
    #[must_use]
    pub fn process_token_is_elevated(&self) -> bool {
        self.token_elevated
    }

    /// The verified helper PID this host is bound to (WSP1 §6 anti
    /// fake-helper).
    #[must_use]
    pub fn helper_process_id(&self) -> u32 {
        self.helper.process_id
    }

    /// The verified helper user SID this host is bound to (an endpoint name
    /// alone is not a capability).
    #[must_use]
    pub fn helper_user_sid(&self) -> &str {
        &self.helper.user_sid
    }

    /// The number of runtime actors: exactly one. The portable H80
    /// composition is the only business state machine; a second state machine
    /// anywhere in the composition is the killer mutant this pins.
    #[must_use]
    pub fn runtime_actor_count(&self) -> usize {
        self.actors.len()
    }

    /// `KernelControl` never owns the business state machine: it only routes
    /// commands through the gate.
    #[must_use]
    pub fn kernel_control_owns_state_machine(&self) -> bool {
        false
    }

    /// The `KernelControl` gate this composition routes commands through.
    pub fn kernel_gate(&mut self) -> &mut KernelControlGate {
        &mut self.gate
    }

    /// Bind the authorized acceptance controller (the `KernelControl` transport
    /// peer) to the single runtime actor.
    pub fn bind_controller(&mut self, peer: PeerContext, capability: PeerCapability) {
        self.actors[0].bind_peer(peer, capability);
    }

    /// Apply an event to the single runtime actor and return its effect
    /// (portable H80 deterministic semantics).
    ///
    /// The packet leg follows the actor's lifecycle: both relay legs start
    /// when the protocol establishes and stop when the business stops.
    pub fn apply(&mut self, event: HostEvent) -> HostEffect {
        match event {
            HostEvent::Connect
            | HostEvent::HelperLinkLost
            | HostEvent::StopNewAdmission
            | HostEvent::TeardownSideJoined(_)
            // R1: failure and fine-phase progress only drive the actor's state
            // machine — no packet-leg side effects (relay starts only on
            // ProtocolEstablished, stops on Disconnect/terminal).
            | HostEvent::ConnectFailed(_)
            | HostEvent::ConnectPhaseProgress(_)
            // S1: ReopenAdmission is the portable actor's migration back to Idle
            // after Stopped — no packet-leg side effect here; the relay re-arms
            // when the next ProtocolEstablished starts the legs.
            | HostEvent::ReopenAdmission => self.actors[0].apply(event),
            HostEvent::ProtocolEstablished => {
                let effect = self.actors[0].apply(HostEvent::ProtocolEstablished);
                if effect == HostEffect::Connected {
                    // S1: re-arm the packet leg before starting it for THIS
                    // connection — a relay stopped by a previous disconnect
                    // stays Terminal and would otherwise never return to Running
                    // (packet_attachment_active() stays false forever).
                    // `reset_legs` is a no-op on a fresh/never-stopped relay.
                    self.relay.reset_legs();
                    self.relay.start_leg(RelayDirection::Receive);
                    self.relay.start_leg(RelayDirection::Send);
                }
                effect
            }
            HostEvent::Disconnect => {
                let effect = self.actors[0].apply(HostEvent::Disconnect);
                self.stop_requests += 1;
                self.teardown_started = true;
                self.relay.stop();
                effect
            }
        }
    }

    /// The current lifecycle phase (delegates to the runtime actor).
    #[must_use]
    pub fn phase(&self) -> HostPhase {
        self.actors[0].phase()
    }

    /// Whether new connections are still admitted (delegates to the runtime
    /// actor; a terminal helper link / business Stop closes admission).
    #[must_use]
    pub fn admission_open(&self) -> bool {
        self.actors[0].admission_open()
    }

    /// Whether the packet leg is live: true only while the W23B relay's
    /// running proof holds (both legs Running after
    /// [`HostEvent::ProtocolEstablished`]). Any terminal (helper link lost,
    /// business Stop, host exit) revokes it — 'helper link lost 仍 Connected'
    /// is the mutant this kills.
    #[must_use]
    pub fn packet_attachment_active(&self) -> bool {
        self.relay.running_proof()
    }

    /// The deterministic runtime epoch bytes this composition's capability is
    /// issued for (the pure composition's stand-in; real epoch from engine
    /// negotiation replaces it in P3-c wire snapshots).
    #[must_use]
    pub fn runtime_epoch_bytes(&self) -> [u8; 16] {
        deterministic_runtime_epoch_bytes()
    }

    /// The deterministic packet lease ref bytes the W23B packet leg attaches
    /// with (the pure composition's stand-in lease; real lease from R31-I).
    #[must_use]
    pub fn packet_lease_ref_bytes(&self) -> [u8; 32] {
        deterministic_packet_lease_digest()
    }

    /// Cancel the RPC waiter: records the cancellation and stops nothing else.
    ///
    /// RPC cancel ≠ business Stop (spec §8.3/§9.1): the wait is cancelled but
    /// no business state changes — admission, packet leg and Stop count are
    /// untouched. The pure composition tracks no live waiter; the recorded
    /// count is the observable fact of the cancellation.
    pub fn on_rpc_waiter_cancel(&mut self) {
        self.rpc_waiter_cancellations += 1;
    }

    /// The number of RPC waiter cancellations recorded.
    #[must_use]
    pub fn rpc_waiter_cancellations(&self) -> u64 {
        self.rpc_waiter_cancellations
    }

    /// The business Stop requests emitted (the only business cancel is
    /// KernelControl.Stop / an explicit disconnect / host exit).
    #[must_use]
    pub fn stop_requests(&self) -> u64 {
        self.stop_requests
    }

    /// R1: the 16-byte operation id of the in-flight connect/stop operation
    /// (host-side correlation register; set at dispatch, cleared on terminal).
    #[must_use]
    pub fn operation_id(&self) -> Option<[u8; 16]> {
        self.operation_id
    }

    /// R1: register the operation id of a dispatched connect/stop (the engine
    /// status events for it carry the same id; snapshots/events surface it).
    pub fn set_operation_id(&mut self, operation_id: [u8; 16]) {
        self.operation_id = Some(operation_id);
        // 新操作开启：清掉上一个失败的 wire error（成败由状态流再报）。
        self.last_wire_error = None;
        // 新连接/停止操作不能沿用上一会话的在线时长起点。
        self.session_established_at_ms = None;
    }

    /// 当前已确认连接会话的起点（Unix epoch ms）。`None` 表示 engine 尚未确认。
    #[must_use]
    pub fn session_established_at_ms(&self) -> Option<i64> {
        self.session_established_at_ms
    }

    /// 记录 engine 在数据面真正可用时铸造的会话起点。
    ///
    /// 仅接受正值；同一会话的后续缺失/无效状态事件不得清空已经确认的事实。
    pub fn set_session_established_at_ms(&mut self, established_at_ms: Option<i64>) {
        if let Some(established_at_ms) = established_at_ms.filter(|value| *value > 0) {
            self.session_established_at_ms = Some(established_at_ms);
        }
    }

    /// R1: the latest connect-failure's wire error (snapshot source for the
    /// `Failed` state). None = no failure observed since the last connect.
    #[must_use]
    pub fn last_wire_error(&self) -> Option<&exv_vpn_wire::generated::VpnError> {
        self.last_wire_error.as_ref()
    }

    /// R1: record a connect-failure's wire error (the status forwarder drives
    /// this alongside `HostEvent::ConnectFailed` on the actor).
    pub fn set_last_wire_error(&mut self, error: exv_vpn_wire::generated::VpnError) {
        self.last_wire_error = Some(error);
    }

    /// The current fine connect phase of the single runtime actor (R1).
    #[must_use]
    pub fn connect_phase(&self) -> Option<exv_vpn_domain::model::ConnectPhase> {
        self.actors[0].connect_phase()
    }

    /// The error reported by the last `ConnectFailed` on the single runtime
    /// actor (R1).
    #[must_use]
    pub fn last_error(&self) -> Option<&exv_vpn_domain::error::VpnError> {
        self.actors[0].last_error()
    }

    /// A helper pipe link terminal: revoke admission, revoke the packet leg,
    /// and start a bounded complete teardown (spec §8.3).
    ///
    /// Connected must not survive a lost helper link: the runtime actor is
    /// driven into reconciliation and admission is closed regardless of the
    /// phase it was in when the link died.
    pub fn on_helper_link_terminal(&mut self) {
        self.teardown_started = true;
        self.relay.on_terminal(RelayTerminalSource::StreamEof);
        let effect = self.actors[0].apply(HostEvent::HelperLinkLost);
        if effect == HostEffect::AdmissionStopped {
            // The actor only closes admission when the link was live; force it
            // closed regardless so a terminal link never leaves admission open.
            self.actors[0].apply(HostEvent::StopNewAdmission);
        }
    }

    /// Whether a bounded complete teardown has started.
    #[must_use]
    pub fn teardown_started(&self) -> bool {
        self.teardown_started
    }

    /// R2 (a) 收敛双保险：core 合成数据面侧加入。
    ///
    /// 当 engine 已确认离开（干净退出 / 状态流断开）而本机仍停在停机收敛
    /// （[`HostPhase::Stopping`]，host 控制面侧已加入 teardown 屏障）时，补发数据面
    /// 侧（PacketData）加入——engine 侧的 Idle 终态事件可能随断线丢失。双侧齐 →
    /// [`HostPhase::Stopped`]（回落 Idle 终态），UI 不再卡 Reconciling。
    ///
    /// 幂等：仅在 `Stopping` 时生效（[`TeardownBarrier`] 未释放才 join 生效；Idle /
    /// Connected / 已 Stopped 等其余相位 no-op，不制造虚假相位）。
    pub fn synthesize_data_plane_join(&mut self) {
        if self.phase() == HostPhase::Stopping {
            self.apply(HostEvent::TeardownSideJoined(TeardownSide::PacketData));
        }
    }

    /// The host process exit path: emit exactly one business Stop (idempotent),
    /// close admission, and revoke the packet leg. Connected must not survive
    /// host exit.
    pub fn exit(&mut self) {
        if self.exited {
            return;
        }
        self.exited = true;
        self.teardown_started = true;
        self.stop_requests += 1;
        self.relay.stop();
        self.actors[0].apply(HostEvent::Disconnect);
    }
}

/// The deterministic packet lease digest bytes for the pure composition's attach
/// (`'L' 'W'` marker + zero fill). The single source the domain ref and the wire
/// snapshot ref both derive from (P3-b2 `GetSnapshot` exposes the same bytes).
fn deterministic_packet_lease_digest() -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest[0] = 0x4C; // 'L' — lease stand-in marker.
    digest[1] = 0x57; // 'W' — host packet leg.
    digest
}

/// The deterministic packet lease for the pure composition's attach.
///
/// In the real flow the runtime (R31-I) issues the lease from the admitted
/// connection; the pure composition uses a fixed non-nil stand-in so the
/// W23A/W23B pieces are composed without live runtime I/O (same construction
/// pattern as the W23B-T contract tests).
fn deterministic_packet_lease() -> PacketLeaseRef {
    PacketLeaseRef::try_from(
        ResourceIdentityDigest::try_from(deterministic_packet_lease_digest()).expect("valid digest"),
    )
    .expect("valid lease")
}

/// The deterministic runtime epoch bytes the pure composition's capability is
/// issued for (`Uuid::from_u128(1)`, 16 bytes). Single source for the domain
/// epoch and the wire snapshot's runtime epoch bytes (P3-b2 `GetSnapshot`).
fn deterministic_runtime_epoch_bytes() -> [u8; 16] {
    *Uuid::from_u128(1).as_bytes()
}

/// The deterministic runtime epoch the pure composition's capability is
/// issued for (non-nil, fixed — matching the `exv_vpn_data_plane` pattern).
fn deterministic_runtime_epoch() -> RuntimeEpoch {
    RuntimeEpoch::try_from(Uuid::from_u128(1)).expect("non-nil runtime epoch")
}

/// Reads the current process token elevation fact (`TokenElevation`), fail
/// closed: any token query failure records `false`. This is the only native
/// read in the composition, taken at compose time so the recorded fact is a
/// real observation — mirroring the contract test's own probe.
fn observe_process_token_elevation() -> bool {
    // SAFETY: GetCurrentProcess returns the current process pseudo-handle; it
    // must not be closed.
    let process = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken writes the token handle on success; it must be
    // closed below.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        return false;
    }
    let mut elevated = false;
    let mut size = 0u32;
    // SAFETY: the size-only query cannot write; `size` receives the required
    // buffer size.
    unsafe {
        let _ = GetTokenInformation(token, TokenElevation, None, 0, &raw mut size);
    }
    if size != 0 {
        let capacity = usize::try_from(size).unwrap_or_default();
        let mut buffer = vec![0u8; capacity];
        let len = u32::try_from(buffer.len()).unwrap_or_default();
        // SAFETY: `buffer` is a live buffer of at least `size` bytes;
        // TokenElevation writes a TOKEN_ELEVATION struct and reports the same
        // length back.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                len,
                &raw mut size,
            )
        };
        if ok.is_ok() && buffer.len() >= 4 {
            elevated = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) != 0;
        }
    }
    // SAFETY: `token` was opened above and is not closed elsewhere; release it
    // now that every query is complete.
    unsafe {
        let _ = CloseHandle(token);
    }
    elevated
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
