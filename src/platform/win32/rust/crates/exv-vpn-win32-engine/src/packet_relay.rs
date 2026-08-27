// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Packet-boundary relay legs: atomic attach + running proof (W23B-I).
//!
//! [`AttachedPacketRelay`] is the `W23B-T` frozen seam of the helper crate.
//! It composes, WITHOUT re-implementing:
//! - the resource crate's single-use [`PacketCapability`] /
//!   [`PacketAttachment`] (the atomic `Pending(capability) ->
//!   Attached(connection_id)` transition, spec §5.5; the capability owner
//!   lives in the resource crate and `attach` executes its consume exactly
//!   once);
//! - the W23A [`PacketChannel`] (X71H ownership-version sequence and queue
//!   budget — the relay never re-implements budget/sequence);
//! - the W17 [`WintunSession`] ring (receive/send/read-wait event), injected
//!   by the host for the send leg's writes.
//!
//! The relay itself is a pure per-leg state machine per direction
//! (`Attached -> Running -> Terminal`); it never spawns threads. Frozen WSP3
//! facts honored here: `pump_send_frame` uses the fixed lock order (relay
//! lock -> session lock), and the `EndSession` safety order (packet workers
//! JOIN before `WintunEndSession`) is owned by [`WintunSession`]'s `Drop` —
//! the relay only writes the send ring, it never ends the session.

use std::sync::{Arc, Mutex};

use exv_vpn_domain::error::VpnError;
use exv_vpn_win32_ipc::packet_channel::{ChannelVerdict, PacketChannel};
use exv_vpn_win32_ipc::packet_limits::PacketLimits;
use exv_vpn_win32_resource::native_error::NativeError;
use exv_vpn_win32_resource::packet_attachment::PacketAttachment;
use exv_vpn_win32_resource::packet_capability::PacketCapability;
use exv_vpn_win32_resource::wintun_session::WintunSession;

/// The relay-level 64 KiB message ceiling rejection (spec §8.5 transport
/// max-message, WSP1 facts §7). The channel per-batch caps alone
/// (262144 bytes) would admit a 70 KiB frame, so the relay enforces the
/// ceiling at its own boundary, refusing without consuming a sequence.
const MAX_MESSAGE_CEILING: &str = "message exceeds 64 KiB ceiling";

/// The two relay legs (spec §5.5: running proof requires BOTH).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayDirection {
    /// The receive leg: ring packets admitted into the channel.
    Receive,
    /// The send leg: transport frames pumped to the send ring.
    Send,
}

/// The per-leg relay state (the state machine the contract test exercises).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayLegState {
    /// Attached (created) but the leg's worker has not started.
    Attached,
    /// The leg's worker is running.
    Running,
    /// The leg reached a terminal state (EOF/panic/native terminal/Stop).
    Terminal,
}

/// The sources that terminate the relay (spec §6.6: ANY of them invalidates
/// the running proof).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayTerminalSource {
    /// The transport stream reached EOF.
    StreamEof,
    /// A relay task panicked.
    TaskPanic,
    /// The native read reported a terminal condition.
    NativeReadTerminal,
    /// The relay was explicitly stopped.
    Stop,
}

/// Typed send-side failure of [`AttachedPacketRelay::pump_send_frame`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelaySendError {
    /// The frame was refused by the relay or the channel: message ceiling,
    /// stale X71H frame, full budget, or no session attached.
    Rejected(&'static str),
    /// The Wintun send ring rejected the write (typed native error).
    Native(NativeError),
}

/// The attached packet relay: one atomic attach plus two composable legs.
pub struct AttachedPacketRelay {
    /// The attachment this relay carries (the winning stream's identity).
    attachment: PacketAttachment,
    /// The W23A channel (sequence/budget; never re-implemented here).
    channel: PacketChannel,
    /// The limits the relay enforces at its own boundary (64 KiB ceiling).
    limits: PacketLimits,
    /// The W17 session the send leg writes to (optional until injected).
    session: Option<Arc<Mutex<WintunSession>>>,
    /// The receive leg state.
    receive_leg: RelayLegState,
    /// The send leg state.
    send_leg: RelayLegState,
}

impl AttachedPacketRelay {
    /// Atomically consume `capability` exactly once and produce the
    /// attachment binding `connection_id`.
    ///
    /// The single-use transition (spec §5.5: `Pending(capability) ->
    /// Attached(connection_id)`) is owned by the resource crate's
    /// [`PacketCapability`]; this seam executes it. Concurrent streams
    /// serialized by the caller's lock race exactly once: the first attach
    /// wins, every later attempt is refused (kills 'capability consumed
    /// twice' / 'attach not atomic').
    ///
    /// # Errors
    ///
    /// Returns `VpnError` with `PacketLeaseAlreadyAttached` when the
    /// capability is already consumed (reuse, or a concurrent loser).
    pub fn attach(
        capability: &mut PacketCapability,
        connection_id: u64,
    ) -> Result<PacketAttachment, VpnError> {
        capability.attach(connection_id)
    }

    /// Build the pure per-leg state machine from the won attachment, the
    /// W23A channel, and the limits the relay enforces at its own boundary.
    ///
    /// Pure logic: constructing the relay performs no Win32 call, so the
    /// state machine is testable without elevation.
    #[must_use]
    pub const fn new(
        attachment: PacketAttachment,
        channel: PacketChannel,
        limits: PacketLimits,
    ) -> Self {
        Self {
            attachment,
            channel,
            limits,
            session: None,
            receive_leg: RelayLegState::Attached,
            send_leg: RelayLegState::Attached,
        }
    }

    /// The attachment this relay carries (the winning stream's identity).
    #[must_use]
    pub const fn attachment(&self) -> &PacketAttachment {
        &self.attachment
    }

    /// Inject the W17 session the send leg writes to.
    ///
    /// Pure bookkeeping: the relay never ends the session; the caller owns
    /// the frozen WSP3 safety order (join packet workers before
    /// `WintunEndSession`). Not `const`: replacing the session slot drops
    /// the previous `Arc`, whose destructor is not compile-time.
    pub fn attach_session(&mut self, session: Arc<Mutex<WintunSession>>) {
        self.session = Some(session);
    }

    /// Start the given leg's worker: `Attached -> Running`.
    ///
    /// Starting an already-Running or Terminal leg is a no-op.
    pub fn start_leg(&mut self, direction: RelayDirection) {
        let state = match direction {
            RelayDirection::Receive => &mut self.receive_leg,
            RelayDirection::Send => &mut self.send_leg,
        };
        if *state == RelayLegState::Attached {
            *state = RelayLegState::Running;
        }
    }

    /// The current state of the given leg.
    #[must_use]
    pub const fn leg_state(&self, direction: RelayDirection) -> RelayLegState {
        match direction {
            RelayDirection::Receive => self.receive_leg,
            RelayDirection::Send => self.send_leg,
        }
    }

    /// The running proof (spec §5.5/§8.5): true ONLY when both legs are
    /// `Running`. Any terminal (EOF/panic/native terminal/Stop) invalidates
    /// it (spec §6.6) — a single-direction proof or optimistic `Connected`
    /// is the mutant this gates.
    #[must_use]
    pub fn running_proof(&self) -> bool {
        self.receive_leg == RelayLegState::Running && self.send_leg == RelayLegState::Running
    }

    /// Record a relay terminal: BOTH legs transition to `Terminal`, so the
    /// running proof fails regardless of which source fired.
    ///
    /// Any source (stream EOF, task panic, native read terminal) must
    /// invalidate `Connected` — 'EOF only stops task' is the mutant this
    /// kills.
    pub const fn on_terminal(&mut self, _source: RelayTerminalSource) {
        self.receive_leg = RelayLegState::Terminal;
        self.send_leg = RelayLegState::Terminal;
    }

    /// Stop BOTH legs (`Terminal`), never one — partial stop is the mutant.
    pub const fn stop(&mut self) {
        self.receive_leg = RelayLegState::Terminal;
        self.send_leg = RelayLegState::Terminal;
    }

    /// Re-arm a stopped relay for a subsequent connection (S1).
    ///
    /// Resets both legs from [`RelayLegState::Terminal`] back to
    /// [`RelayLegState::Attached`], so a later [`Self::start_leg`] can bring the
    /// running proof back up. Legs that are not `Terminal` (a fresh `Attached`
    /// or an already-`Running` relay) are left untouched — re-arm is a data-path
    /// reset for the next connection, NOT a capability re-consume (the single-use
    /// attachment is preserved).
    pub fn reset_legs(&mut self) {
        if self.receive_leg == RelayLegState::Terminal {
            self.receive_leg = RelayLegState::Attached;
        }
        if self.send_leg == RelayLegState::Terminal {
            self.send_leg = RelayLegState::Attached;
        }
    }

    /// Admit one received ring packet into the channel (receive side).
    ///
    /// Returns the strictly monotonic sequence stamped on the batch. A
    /// message over the 64 KiB ceiling is refused WITHOUT consuming a
    /// sequence (the next admit still gets the same sequence) — a consumed
    /// sequence on rejection would break monotonicity (double-consume
    /// mutant).
    ///
    /// # Errors
    ///
    /// Returns `Err("message exceeds 64 KiB ceiling")` for oversized
    /// messages, or `Err("budget full")` when the directional queue budget
    /// refuses the batch.
    pub fn admit_receive_packet(&mut self, packet: &[u8]) -> Result<u64, &'static str> {
        if packet.len() > self.limits.max_message_bytes {
            return Err(MAX_MESSAGE_CEILING);
        }
        match self.channel.admit(1, packet.len()) {
            ChannelVerdict::Admitted { sequence } => Ok(sequence),
            ChannelVerdict::Rejected => Err("budget full"),
        }
    }

    /// Admit a transport send frame into the channel (send side, X71H).
    ///
    /// `frame_sequence` must equal the channel's current sequence: a stale
    /// (already-consumed) frame is refused with `Err("old frame")` without
    /// consuming a sequence — killing the channel-level double-consume
    /// mutant. The 64 KiB message ceiling is enforced before admission.
    ///
    /// # Errors
    ///
    /// Returns `Err("message exceeds 64 KiB ceiling")` for oversized
    /// batches, `Err("old frame")` for a consumed sequence, or
    /// `Err("budget full")` when the queue budget refuses the batch.
    pub fn admit_send_frame(
        &mut self,
        packets: usize,
        bytes: usize,
        frame_sequence: u64,
    ) -> Result<(), &'static str> {
        if bytes > self.limits.max_message_bytes {
            return Err(MAX_MESSAGE_CEILING);
        }
        self.channel.admit_owned_frame(packets, bytes, frame_sequence)
    }

    /// Pump one frame through the send side and into the Wintun send ring.
    ///
    /// Single entry point for the send leg: relay ceiling check, then X71H +
    /// budget admission on the channel, then the native write under the
    /// fixed lock order (relay lock -> session lock). The frame's admission
    /// consumes exactly one sequence whether or not the native write
    /// succeeds; a native failure is reported typed, never a panic.
    ///
    /// # Errors
    ///
    /// Returns [`RelaySendError::Rejected`] when the frame is oversized, its
    /// `frame_sequence` is stale, the budget refuses it, or no session is
    /// attached; [`RelaySendError::Native`] when the Wintun send ring
    /// rejects the write.
    ///
    /// # Panics
    ///
    /// Panics if the attached session's mutex is poisoned (a worker panicked
    /// while holding the session lock).
    pub fn pump_send_frame(
        &mut self,
        frame: &[u8],
        frame_sequence: u64,
    ) -> Result<(), RelaySendError> {
        if frame.len() > self.limits.max_message_bytes {
            return Err(RelaySendError::Rejected(MAX_MESSAGE_CEILING));
        }
        self.channel
            .admit_owned_frame(1, frame.len(), frame_sequence)
            .map_err(RelaySendError::Rejected)?;
        let Some(session) = self.session.as_ref() else {
            return Err(RelaySendError::Rejected("no session attached"));
        };
        let mut guard = session.lock().expect("session 锁（仅 worker panic 时 poisoned）");
        guard.send(frame).map_err(RelaySendError::Native)
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
