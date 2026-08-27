// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

use crate::error::VpnError;
use crate::identity::{
    AttemptId, EvidenceDigest, InteractionId, InventoryDigest, OperationLookupKey, OwnerLeaseId,
    OwnershipVersion, RecoveryId, RequestDigest, ResourceIdentityDigest, RetirementOperationId,
    RuntimeEpoch, TokenDigest,
};
use crate::ports::{MonotonicTick, ReconcileRequest};
use serde::Serialize;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum ConnectPhase {
    ObservingOwnedState,
    AcquiringPlatformLease,
    ConnectingControl,
    AwaitingInteraction,
    NegotiatingTunnel,
    ApplyingPlatformTunnel,
    AttachingPacketBoundary,
    StartingDataPlane,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct PromptDeadline(u64);

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ConnectionProfileRef(ResourceIdentityDigest);

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ConnectIntent {
    lookup_key: OperationLookupKey,
    request_digest: RequestDigest,
    profile: ConnectionProfileRef,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct Attempt {
    runtime_epoch: RuntimeEpoch,
    attempt_id: AttemptId,
    intent: ConnectIntent,
    prior_error: Option<VpnError>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct StopIntent {
    lookup_key: OperationLookupKey,
    request_digest: RequestDigest,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct InteractionPrompt {
    interaction_id: InteractionId,
    runtime_epoch: RuntimeEpoch,
    attempt_id: AttemptId,
    deadline: PromptDeadline,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ProtocolSessionRef(ResourceIdentityDigest);

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PlatformOwnershipRef {
    identity_digest: ResourceIdentityDigest,
    ownership_version: OwnershipVersion,
    token_digest: TokenDigest,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PacketLeaseRef(ResourceIdentityDigest);

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CleanupProofRef {
    canonical_inventory_digest: InventoryDigest,
    platform_evidence_digest: EvidenceDigest,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PlatformReadyProof {
    platform_ownership: PlatformOwnershipRef,
    evidence_digest: EvidenceDigest,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct DataRunningProof {
    protocol_session: ProtocolSessionRef,
    platform_ownership: PlatformOwnershipRef,
    packet_lease: PacketLeaseRef,
    evidence_digest: EvidenceDigest,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ConnectedSession {
    attempt: Attempt,
    protocol_session: ProtocolSessionRef,
    platform_ownership: PlatformOwnershipRef,
    packet_lease: PacketLeaseRef,
    platform_ready: PlatformReadyProof,
    data_running: DataRunningProof,
}

pub type ConnectedSessionConstructor = fn(
    Attempt,
    ProtocolSessionRef,
    PlatformOwnershipRef,
    PacketLeaseRef,
    PlatformReadyProof,
    DataRunningProof,
) -> ConnectedSession;

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum RecoveryContext {
    Startup {
        runtime_epoch: RuntimeEpoch,
        recovery_id: RecoveryId,
    },
    AttemptTeardown {
        attempt: Attempt,
    },
    OwnerLost {
        owner_lease_id: OwnerLeaseId,
        attempt: Attempt,
    },
    PacketBoundaryLost {
        attempt: Attempt,
        packet_lease: PacketLeaseRef,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryObligation {
    owner_runtime_epoch: RuntimeEpoch,
    retirement_operation_id: Option<RetirementOperationId>,
    blocking_error: VpnError,
    platform_ownership: Option<PlatformOwnershipRef>,
    packet_lease: Option<PacketLeaseRef>,
    canonical_inventory_digest: InventoryDigest,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum RuntimeState {
    Idle {
        last_cleanup: Option<CleanupProofRef>,
    },
    Connecting {
        attempt: Attempt,
        phase: ConnectPhase,
    },
    AwaitingInteraction {
        attempt: Attempt,
        prompt: InteractionPrompt,
    },
    Connected {
        session: ConnectedSession,
    },
    Stopping {
        attempt: Attempt,
        stop: StopIntent,
        queued_connect: Option<ConnectIntent>,
    },
    Reconciling {
        context: RecoveryContext,
        obligation: RecoveryObligation,
    },
    FailedClean {
        last_error: VpnError,
        proof: CleanupProofRef,
    },
    FailedDirty {
        last_error: VpnError,
        context: RecoveryContext,
        obligation: RecoveryObligation,
    },
}

// ---- D10-T construction seams (model) ----

impl TryFrom<(MonotonicTick, Duration)> for PromptDeadline {
    type Error = &'static str;
    fn try_from((tick, budget): (MonotonicTick, Duration)) -> Result<Self, Self::Error> {
        if budget == Duration::ZERO {
            return Err("prompt deadline: zero budget");
        }
        if budget > Duration::from_secs(300) {
            return Err("prompt deadline: budget over ceiling");
        }
        let nanos = budget.as_nanos() as u64;
        let deadline = tick
            .as_inner()
            .checked_add(nanos)
            .ok_or("prompt deadline: tick overflow")?;
        Ok(PromptDeadline(deadline))
    }
}

impl TryFrom<ResourceIdentityDigest> for ProtocolSessionRef {
    type Error = &'static str;
    fn try_from(identity_digest: ResourceIdentityDigest) -> Result<Self, Self::Error> {
        if identity_digest.is_nil() {
            return Err("protocol session ref: nil identity");
        }
        Ok(ProtocolSessionRef(identity_digest))
    }
}

impl TryFrom<ResourceIdentityDigest> for PacketLeaseRef {
    type Error = &'static str;
    fn try_from(identity_digest: ResourceIdentityDigest) -> Result<Self, Self::Error> {
        if identity_digest.is_nil() {
            return Err("packet lease ref: nil identity");
        }
        Ok(PacketLeaseRef(identity_digest))
    }
}

impl TryFrom<(ResourceIdentityDigest, OwnershipVersion, TokenDigest)> for PlatformOwnershipRef {
    type Error = &'static str;
    fn try_from(
        (identity_digest, ownership_version, token_digest): (
            ResourceIdentityDigest,
            OwnershipVersion,
            TokenDigest,
        ),
    ) -> Result<Self, Self::Error> {
        if identity_digest.is_nil() {
            return Err("platform ownership ref: nil identity");
        }
        Ok(PlatformOwnershipRef {
            identity_digest,
            ownership_version,
            token_digest,
        })
    }
}

impl TryFrom<(InventoryDigest, EvidenceDigest)> for CleanupProofRef {
    type Error = &'static str;
    fn try_from(
        (canonical_inventory_digest, platform_evidence_digest): (InventoryDigest, EvidenceDigest),
    ) -> Result<Self, Self::Error> {
        if canonical_inventory_digest.is_nil() {
            return Err("cleanup proof: unresolved obligations");
        }
        Ok(CleanupProofRef {
            canonical_inventory_digest,
            platform_evidence_digest,
        })
    }
}

impl TryFrom<(PlatformOwnershipRef, EvidenceDigest)> for PlatformReadyProof {
    type Error = &'static str;
    fn try_from(
        (platform_ownership, evidence_digest): (PlatformOwnershipRef, EvidenceDigest),
    ) -> Result<Self, Self::Error> {
        if evidence_digest.is_nil() {
            return Err("platform ready proof: nil evidence");
        }
        Ok(PlatformReadyProof {
            platform_ownership,
            evidence_digest,
        })
    }
}

impl
    TryFrom<(
        ProtocolSessionRef,
        PlatformOwnershipRef,
        PacketLeaseRef,
        EvidenceDigest,
    )> for DataRunningProof
{
    type Error = &'static str;
    fn try_from(
        (protocol_session, platform_ownership, packet_lease, evidence_digest): (
            ProtocolSessionRef,
            PlatformOwnershipRef,
            PacketLeaseRef,
            EvidenceDigest,
        ),
    ) -> Result<Self, Self::Error> {
        if evidence_digest.is_nil() {
            return Err("data running proof: nil evidence");
        }
        Ok(DataRunningProof {
            protocol_session,
            platform_ownership,
            packet_lease,
            evidence_digest,
        })
    }
}

impl
    TryFrom<(
        RuntimeEpoch,
        Option<RetirementOperationId>,
        VpnError,
        Option<PlatformOwnershipRef>,
        Option<PacketLeaseRef>,
        InventoryDigest,
    )> for RecoveryObligation
{
    type Error = &'static str;
    fn try_from(
        (
            owner_runtime_epoch,
            retirement_operation_id,
            blocking_error,
            platform_ownership,
            packet_lease,
            canonical_inventory_digest,
        ): (
            RuntimeEpoch,
            Option<RetirementOperationId>,
            VpnError,
            Option<PlatformOwnershipRef>,
            Option<PacketLeaseRef>,
            InventoryDigest,
        ),
    ) -> Result<Self, Self::Error> {
        Ok(RecoveryObligation {
            owner_runtime_epoch,
            retirement_operation_id,
            blocking_error,
            platform_ownership,
            packet_lease,
            canonical_inventory_digest,
        })
    }
}

// ReconcileRequest retirement cross-link: the request's retirement_operation_id MUST match the
// obligation's recorded retirement id (D10-M3); a mismatched id is rejected.
impl TryFrom<(RetirementOperationId, RecoveryObligation)> for ReconcileRequest {
    type Error = &'static str;
    fn try_from(
        (retirement_operation_id, obligation): (RetirementOperationId, RecoveryObligation),
    ) -> Result<Self, Self::Error> {
        if obligation.retirement_operation_id != Some(retirement_operation_id.clone()) {
            return Err("reconcile: retirement id mismatch");
        }
        Ok(ReconcileRequest {
            context: RecoveryContext::Startup {
                runtime_epoch: obligation.owner_runtime_epoch.clone(),
                recovery_id: RecoveryId::try_from(Uuid::new_v4()).expect("non-nil uuid"),
            },
            retirement_operation_id,
            obligation,
        })
    }
}

// ---- D11-I construction + access seams (model) ----

impl TryFrom<ResourceIdentityDigest> for ConnectionProfileRef {
    type Error = &'static str;
    fn try_from(identity_digest: ResourceIdentityDigest) -> Result<Self, Self::Error> {
        if identity_digest.is_nil() {
            return Err("connection profile ref: nil identity");
        }
        Ok(ConnectionProfileRef(identity_digest))
    }
}

impl ConnectIntent {
    pub fn new(
        lookup_key: OperationLookupKey,
        request_digest: RequestDigest,
        profile: ConnectionProfileRef,
    ) -> Self {
        ConnectIntent {
            lookup_key,
            request_digest,
            profile,
        }
    }

    pub(crate) fn lookup_key(&self) -> &OperationLookupKey {
        &self.lookup_key
    }

    pub(crate) fn request_digest(&self) -> &RequestDigest {
        &self.request_digest
    }

    pub(crate) fn runtime_epoch(&self) -> RuntimeEpoch {
        self.lookup_key.runtime_epoch()
    }
}

impl StopIntent {
    pub fn new(lookup_key: OperationLookupKey, request_digest: RequestDigest) -> Self {
        StopIntent {
            lookup_key,
            request_digest,
        }
    }

    pub(crate) fn lookup_key(&self) -> &OperationLookupKey {
        &self.lookup_key
    }

    pub(crate) fn request_digest(&self) -> &RequestDigest {
        &self.request_digest
    }
}

impl Attempt {
    pub fn new(
        runtime_epoch: RuntimeEpoch,
        attempt_id: AttemptId,
        intent: ConnectIntent,
        prior_error: Option<VpnError>,
    ) -> Self {
        Attempt {
            runtime_epoch,
            attempt_id,
            intent,
            prior_error,
        }
    }

    pub(crate) fn runtime_epoch(&self) -> RuntimeEpoch {
        self.runtime_epoch.clone()
    }

    pub(crate) fn attempt_id(&self) -> AttemptId {
        self.attempt_id.clone()
    }

    pub(crate) fn intent(&self) -> &ConnectIntent {
        &self.intent
    }

    pub(crate) fn prior_error(&self) -> &Option<VpnError> {
        &self.prior_error
    }
}

impl InteractionPrompt {
    pub fn new(
        interaction_id: InteractionId,
        runtime_epoch: RuntimeEpoch,
        attempt_id: AttemptId,
        deadline: PromptDeadline,
    ) -> Self {
        InteractionPrompt {
            interaction_id,
            runtime_epoch,
            attempt_id,
            deadline,
        }
    }

    pub(crate) fn interaction_id(&self) -> InteractionId {
        self.interaction_id.clone()
    }

    pub(crate) fn runtime_epoch(&self) -> RuntimeEpoch {
        self.runtime_epoch.clone()
    }

    pub(crate) fn attempt_id(&self) -> AttemptId {
        self.attempt_id.clone()
    }

    pub(crate) fn deadline(&self) -> PromptDeadline {
        self.deadline
    }
}

impl ConnectedSession {
    pub fn new(
        attempt: Attempt,
        protocol_session: ProtocolSessionRef,
        platform_ownership: PlatformOwnershipRef,
        packet_lease: PacketLeaseRef,
        platform_ready: PlatformReadyProof,
        data_running: DataRunningProof,
    ) -> Self {
        ConnectedSession {
            attempt,
            protocol_session,
            platform_ownership,
            packet_lease,
            platform_ready,
            data_running,
        }
    }

    pub(crate) fn attempt(&self) -> &Attempt {
        &self.attempt
    }

    pub(crate) fn protocol_session(&self) -> &ProtocolSessionRef {
        &self.protocol_session
    }

    pub(crate) fn platform_ownership(&self) -> &PlatformOwnershipRef {
        &self.platform_ownership
    }

    pub(crate) fn packet_lease(&self) -> &PacketLeaseRef {
        &self.packet_lease
    }

    pub(crate) fn platform_ready(&self) -> &PlatformReadyProof {
        &self.platform_ready
    }

    pub(crate) fn data_running(&self) -> &DataRunningProof {
        &self.data_running
    }
}

impl RecoveryContext {
    pub fn startup(runtime_epoch: RuntimeEpoch, recovery_id: RecoveryId) -> Self {
        RecoveryContext::Startup {
            runtime_epoch,
            recovery_id,
        }
    }

    pub fn attempt_teardown(attempt: Attempt) -> Self {
        RecoveryContext::AttemptTeardown { attempt }
    }

    pub fn owner_lost(owner_lease_id: OwnerLeaseId, attempt: Attempt) -> Self {
        RecoveryContext::OwnerLost {
            owner_lease_id,
            attempt,
        }
    }

    pub fn packet_boundary_lost(attempt: Attempt, packet_lease: PacketLeaseRef) -> Self {
        RecoveryContext::PacketBoundaryLost {
            attempt,
            packet_lease,
        }
    }
}

impl RecoveryObligation {
    pub fn new(
        owner_runtime_epoch: RuntimeEpoch,
        retirement_operation_id: Option<RetirementOperationId>,
        blocking_error: VpnError,
        platform_ownership: Option<PlatformOwnershipRef>,
        packet_lease: Option<PacketLeaseRef>,
        canonical_inventory_digest: InventoryDigest,
    ) -> Self {
        RecoveryObligation {
            owner_runtime_epoch,
            retirement_operation_id,
            blocking_error,
            platform_ownership,
            packet_lease,
            canonical_inventory_digest,
        }
    }
}

impl RuntimeState {
    pub fn idle() -> Self {
        RuntimeState::Idle { last_cleanup: None }
    }

    pub fn connecting(attempt: Attempt, phase: ConnectPhase) -> Self {
        RuntimeState::Connecting { attempt, phase }
    }

    pub fn awaiting_interaction(attempt: Attempt, prompt: InteractionPrompt) -> Self {
        RuntimeState::AwaitingInteraction { attempt, prompt }
    }

    pub fn connected(session: ConnectedSession) -> Self {
        RuntimeState::Connected { session }
    }

    pub fn stopping(
        attempt: Attempt,
        stop: StopIntent,
        queued_connect: Option<ConnectIntent>,
    ) -> Self {
        RuntimeState::Stopping {
            attempt,
            stop,
            queued_connect,
        }
    }

    pub fn reconciling(context: RecoveryContext, obligation: RecoveryObligation) -> Self {
        RuntimeState::Reconciling {
            context,
            obligation,
        }
    }

    pub fn failed_clean(last_error: VpnError, proof: CleanupProofRef) -> Self {
        RuntimeState::FailedClean { last_error, proof }
    }

    pub fn failed_dirty(
        last_error: VpnError,
        context: RecoveryContext,
        obligation: RecoveryObligation,
    ) -> Self {
        RuntimeState::FailedDirty {
            last_error,
            context,
            obligation,
        }
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
