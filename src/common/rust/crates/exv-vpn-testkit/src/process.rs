// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Fake-process driver for the E89 portable-process E2E (spec TG-07 L1451, L1598).
//!
//! Composes the deterministic slices: the H80 host composition owns the lifecycle authority,
//! while the packet attach/budget/pump and the durable retirement saga hold the auxiliary state.

use exv_vpn_cstp::codec::{Codec, CstpFrame};
use exv_vpn_data_plane::attachment::PacketAttachGuard;
use exv_vpn_data_plane::budget::{AdmissionVerdict, DataPlaneDirection, PacketBudget};
use exv_vpn_data_plane::pump::{DirectionReadiness, PollDecision, PumpScheduler};
use exv_vpn_data_plane::teardown::{JoinOutcome, TeardownSide};
use exv_vpn_domain::error::ErrorSubject;
use exv_vpn_domain::identity::{
    EvidenceDigest, InventoryDigest, OwnerLeaseId, OwnershipVersion, ResourceIdentityDigest,
    RetirementOperationId, RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::limits::MvpLimits;
use exv_vpn_domain::model::PlatformOwnershipRef;
use exv_vpn_domain::ports::{
    AuthorityFence, CleanupTrigger, CleanupTriggerDigest, ExternalOperationDigest,
    JournalRootDigest, VersionedPlatformEvidence,
};
use exv_vpn_host::composition::{HostComposition, HostEffect, HostEvent, HostPhase};
use exv_vpn_resource::authority::{PeerCapability, PeerContext};
use exv_vpn_resource::retirement::{InventoryPredicate, ProveCleanInput, RetirementSaga};
use uuid::Uuid;

/// The fake process's own lifecycle phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessPhase {
    /// No connection; the host is idle.
    Idle,
    /// A connect was admitted but the protocol has not established.
    Connecting,
    /// The protocol is established but the packet boundary is not yet attached.
    Connected,
    /// The packet boundary is attached and the data plane is live.
    DataPlaneLive,
    /// Teardown initiated; awaiting both sides to join.
    Stopping,
    /// Both teardown sides joined; the aggregate is released.
    Stopped,
    /// Ownership durably retired at the next ownership version.
    Retired,
}

/// The portable fake-process driver composing the deterministic slices.
pub struct FakeProcessDriver {
    host: HostComposition,
    attach: PacketAttachGuard,
    budget: PacketBudget,
    pump: PumpScheduler,
    retirement: RetirementSaga,
    codec: Codec,
    phase: ProcessPhase,
}

impl FakeProcessDriver {
    /// Compose a fresh driver under the given limits, runtime epoch, authority fence, and prior
    /// ownership version.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the packet budget cannot be built from the given limits.
    pub fn new(
        limits: &MvpLimits,
        runtime_epoch: RuntimeEpoch,
        authority: AuthorityFence,
        prior_ownership_version: OwnershipVersion,
    ) -> Result<Self, &'static str> {
        let budget =
            PacketBudget::from_limits(limits).map_err(|_| "new: invalid packet limits")?;
        Ok(Self {
            host: HostComposition::new(),
            attach: PacketAttachGuard::new(runtime_epoch),
            budget,
            pump: PumpScheduler::new(),
            retirement: RetirementSaga::new(authority, prior_ownership_version),
            codec: Codec::new(),
            phase: ProcessPhase::Idle,
        })
    }

    /// Bind the authenticated peer and its capability to the host composition.
    pub fn bind_peer(&mut self, peer: PeerContext, capability: PeerCapability) {
        self.host.bind_peer(peer, capability);
    }

    /// Request a connection over the bound peer.
    pub fn connect(&mut self) -> HostEffect {
        let effect = self.host.apply(HostEvent::Connect);
        if effect == HostEffect::ConnectAdmitted {
            self.phase = ProcessPhase::Connecting;
        }
        effect
    }

    /// Signal that the protocol established over the admitted peer.
    pub fn protocol_established(&mut self) -> HostEffect {
        let effect = self.host.apply(HostEvent::ProtocolEstablished);
        if effect == HostEffect::Connected {
            self.phase = ProcessPhase::Connected;
        }
        effect
    }

    /// Attach the single packet-boundary slot.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the process is not Connected, or the slot is already attached.
    pub fn attach_packet(&mut self) -> Result<(), &'static str> {
        if self.phase != ProcessPhase::Connected {
            return Err("attach: not connected");
        }
        self.attach.try_attach().map_err(|_| "attach: already attached")?;
        self.phase = ProcessPhase::DataPlaneLive;
        Ok(())
    }

    /// Request admission for a data-plane batch.
    pub fn admit_packet(
        &mut self,
        d: DataPlaneDirection,
        packets: usize,
        bytes: usize,
    ) -> AdmissionVerdict {
        self.budget.try_admit(d, packets, bytes)
    }

    /// Decide which data-plane direction to poll this round.
    pub fn pump(&mut self, p2p: DirectionReadiness, p2x: DirectionReadiness) -> PollDecision {
        self.pump.next(p2p, p2x)
    }

    /// Encode a CSTP frame into its on-wire bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the frame cannot be encoded (e.g. malformed or IPv6).
    pub fn encode_packet(&self, frame: &CstpFrame) -> Result<Vec<u8>, &'static str> {
        self.codec.encode(frame).map_err(|_| "encode: invalid frame")
    }

    /// Request a disconnect.
    pub fn disconnect(&mut self) -> HostEffect {
        let effect = self.host.apply(HostEvent::Disconnect);
        if effect == HostEffect::TeardownInitiated {
            self.phase = ProcessPhase::Stopping;
            self.attach.detach();
        }
        effect
    }

    /// Join one side of the two-sided teardown barrier.
    pub fn join_teardown(&mut self, side: TeardownSide) -> JoinOutcome {
        let effect = self.host.apply(HostEvent::TeardownSideJoined(side));
        if effect == HostEffect::Stopped {
            self.phase = ProcessPhase::Stopped;
            JoinOutcome::Released
        } else if effect == HostEffect::TeardownPending {
            JoinOutcome::Pending
        } else {
            JoinOutcome::Rejected
        }
    }

    /// Durably begin a retirement over the expected obligation inventory.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the process is not Stopped, or the saga cannot be durably started.
    pub fn begin_retirement(
        &mut self,
        id: RetirementOperationId,
        expected_obligations: Vec<u8>,
        canonical_inventory_digest: InventoryDigest,
    ) -> Result<(), &'static str> {
        if self.phase != ProcessPhase::Stopped {
            return Err("retire: not stopped");
        }
        self.retirement
            .begin(
                id,
                synthetic_trigger(),
                synthetic_origin(),
                synthetic_ownership(),
                expected_obligations,
                canonical_inventory_digest,
            )
            .map_err(|_| "retire: begin")
    }

    /// Observe and re-verify the complete cleanup inventory.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the observed inventory is incomplete or contains an unverified predicate.
    pub fn observe_cleanup(&mut self, observed: &[InventoryPredicate]) -> Result<(), &'static str> {
        self.retirement
            .observe_cleanup(observed)
            .map_err(|_| "retire: observe")
    }

    /// Issue a `CleanProof` over the complete observed inventory.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the cleanup inventory has not been observed.
    pub fn prove_clean(&mut self) -> Result<(), &'static str> {
        self.retirement
            .prove_clean(synthetic_prove_input())
            .map_err(|_| "retire: prove")?;
        Ok(())
    }

    /// Durably retire ownership at the next ownership version.
    ///
    /// # Errors
    ///
    /// Returns `Err` unless the retirement is proved and ownership is not already retired.
    pub fn retire_ownership(&mut self, next: OwnershipVersion) -> Result<(), &'static str> {
        self.retirement
            .retire_ownership(next)
            .map_err(|_| "retire: retire")?;
        self.phase = ProcessPhase::Retired;
        Ok(())
    }

    /// The current fake-process phase.
    #[must_use]
    pub fn phase(&self) -> ProcessPhase {
        self.phase
    }

    /// The underlying host composition phase.
    #[must_use]
    pub fn host_phase(&self) -> HostPhase {
        self.host.phase()
    }

    /// Whether the process has reached a terminal phase (Stopped or Retired).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.phase == ProcessPhase::Stopped || self.phase == ProcessPhase::Retired
    }
}

/// A deterministic external-stop cleanup trigger (frozen id 0x11).
fn synthetic_trigger() -> CleanupTrigger {
    CleanupTrigger::OwnerLost(
        OwnerLeaseId::try_from(Uuid::from_u128(0x11)).expect("non-nil owner lease id"),
    )
}

/// A deterministic origin subject (runtime epoch 0xB0).
fn synthetic_origin() -> ErrorSubject {
    ErrorSubject::Runtime(RuntimeEpoch::try_from(Uuid::from_u128(0xB0)).expect("non-nil epoch"))
}

/// A deterministic prior platform ownership ref (identity 0xE6, version 1, token 0xE7).
fn synthetic_ownership() -> PlatformOwnershipRef {
    PlatformOwnershipRef::try_from((
        ResourceIdentityDigest::try_from([0xE6; 32]).expect("resource identity digest"),
        OwnershipVersion::try_from(1).expect("non-zero ownership version"),
        TokenDigest::try_from([0xE7; 32]).expect("token digest"),
    ))
    .expect("platform ownership ref")
}

/// A deterministic, fully-bound `ProveCleanInput` mirroring the H81 composition's synthetic input.
fn synthetic_prove_input() -> ProveCleanInput {
    ProveCleanInput {
        runtime_epoch: RuntimeEpoch::try_from(Uuid::from_u128(0xB0)).expect("non-nil epoch"),
        cleanup_trigger_digest: CleanupTriggerDigest::try_from([0xE1; 32])
            .expect("cleanup trigger digest"),
        external_trigger_operation_identity_digest_if_present: Some(
            ExternalOperationDigest::try_from([0xE2; 32]).expect("external operation digest"),
        ),
        journal_root_or_projection_digest: JournalRootDigest::try_from([0xE3; 32])
            .expect("journal root digest"),
        platform_evidence: VersionedPlatformEvidence {
            kind_version: 1,
            digest: EvidenceDigest::try_from([0xE4; 32]).expect("evidence digest"),
        },
        prior_platform_ownership_token_digest_if_issued: Some(
            TokenDigest::try_from([0xE5; 32]).expect("token digest"),
        ),
    }
}