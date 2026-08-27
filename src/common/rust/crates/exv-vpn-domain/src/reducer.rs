// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

use crate::error::{EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError};
use crate::identity::{
    AttemptId, EffectId, InteractionId, OperationLookupKey, OwnerLeaseId, RecoveryId,
    RequestDigest, RetirementOperationId, RuntimeEpoch,
};
use crate::model::{
    Attempt, CleanupProofRef, ConnectIntent, ConnectPhase, ConnectedSession, DataRunningProof,
    InteractionPrompt, PacketLeaseRef, PlatformOwnershipRef, PlatformReadyProof, PromptDeadline,
    ProtocolSessionRef, RecoveryContext, RecoveryObligation, RuntimeState, StopIntent,
};
use crate::ports::{
    AcquireOwnershipRequest, ApplyTunnelRequest, AttemptEffectFence, BeginRecoveryStopRequest,
    BeginStopRequest, CleanupOutcome, CleanupTrigger, GetOperationRequest, InteractionEffectFence,
    MutationReceipt, ObserveOwnedStateRequest, OperationState, OwnedAttemptEffectFence,
    OwnedStateObservation, OwnershipRetired, PacketStopFence, PacketTerminal, PlatformApplied,
    ProtocolTerminal, ReconcileRequest, ReleaseOwnershipRequest, RetirementStarted, TunnelPlan,
};
use serde::Serialize;

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum RuntimeCommand {
    Connect(ConnectIntent),
    RespondInteraction(RespondInteractionCommand),
    Stop(StopIntent),
    Reconcile(ReconcileCommand),
    HostLost { runtime_epoch: RuntimeEpoch },
    PlatformOwnerLost(PlatformOwnerLostCommand),
    PacketRelayLost(PacketRelayTerminal),
    EffectCompleted(EffectCompletion),
}

pub const MAX_EFFECTS_PER_DECISION: usize = 3;

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ReducerInputs {
    pub next_attempt_id: AttemptId,
    pub next_effect_ids: [EffectId; MAX_EFFECTS_PER_DECISION],
    pub next_interaction_id: InteractionId,
    pub next_prompt_deadline: PromptDeadline,
    /// Current teardown saga's not-yet-completed effect IDs (initial batch
    /// {StopProtocol, StopPacket, BeginPlatformStop} plus later saga effects
    /// {Reconcile, ReleaseOwnership}, added on emission; includes
    /// `RevokeQueuedConnect` when a queued connect is revoked). MUST include the
    /// currently-completing EffectId (D3 settle). Set-empty is necessary-not-sufficient
    /// to leave Stopping: exit requires set-empty AND `OwnershipRetired`.
    pub outstanding_teardown_effects: Vec<EffectId>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RespondInteractionCommand {
    pub lookup_key: OperationLookupKey,
    pub request_digest: RequestDigest,
    pub interaction_id: InteractionId,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ReconcileCommand {
    pub lookup_key: OperationLookupKey,
    pub request_digest: RequestDigest,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum RecoveryOwnershipFence {
    Owned {
        runtime_epoch: RuntimeEpoch,
        recovery_id: RecoveryId,
        platform_ownership: PlatformOwnershipRef,
    },
    Retirement {
        runtime_epoch: RuntimeEpoch,
        recovery_id: RecoveryId,
        retirement_operation_id: RetirementOperationId,
        platform_ownership: PlatformOwnershipRef,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum PlatformOwnerLossFence {
    Active {
        runtime_epoch: RuntimeEpoch,
        attempt_id: AttemptId,
        platform_ownership: PlatformOwnershipRef,
    },
    Recovery(RecoveryOwnershipFence),
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PlatformOwnerLostCommand {
    pub owner_lease_id: OwnerLeaseId,
    pub fence: PlatformOwnerLossFence,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum PacketRelayFence {
    Active {
        runtime_epoch: RuntimeEpoch,
        attempt_id: AttemptId,
        platform_ownership: PlatformOwnershipRef,
    },
    Recovery(RecoveryOwnershipFence),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PacketTerminalCause {
    PeerEof,
    NativeReadTerminal,
    TaskPanicked,
    ProviderTerminal,
    Backpressure,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct PacketRelayTerminal {
    pub fence: PacketRelayFence,
    pub packet_lease: PacketLeaseRef,
    pub cause: PacketTerminalCause,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ExternalEffectFence {
    pub runtime_epoch: RuntimeEpoch,
    pub effect_id: EffectId,
    pub lookup_key: OperationLookupKey,
    pub request_digest: RequestDigest,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum RecoveryEffectFence {
    Observe {
        runtime_epoch: RuntimeEpoch,
        recovery_id: RecoveryId,
        effect_id: EffectId,
    },
    Owned {
        runtime_epoch: RuntimeEpoch,
        recovery_id: RecoveryId,
        effect_id: EffectId,
        platform_ownership: PlatformOwnershipRef,
    },
    Retirement {
        runtime_epoch: RuntimeEpoch,
        recovery_id: RecoveryId,
        effect_id: EffectId,
        retirement_operation_id: RetirementOperationId,
        platform_ownership: PlatformOwnershipRef,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum CompletionFence {
    External(ExternalEffectFence),
    Attempt(AttemptEffectFence),
    Owned(OwnedAttemptEffectFence),
    Interaction(InteractionEffectFence),
    Recovery(RecoveryEffectFence),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum EphemeralResourceKind {
    PlatformOwnershipToken,
    ProtocolLateHandle,
    PacketLateHandle,
    DataPlaneTask,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct EphemeralCleanupRef {
    pub effect_id: EffectId,
    pub kind: EphemeralResourceKind,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum JournalOperationRef {
    External {
        lookup_key: OperationLookupKey,
        request_digest: RequestDigest,
    },
    Retirement(RetirementOperationId),
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum StaleDisposition {
    ProvenNoEffect,
    AcquiredEphemeralResource(EphemeralCleanupRef),
    JournaledExternalEffect(JournalOperationRef),
    UnknownResourceAcquisition(RecoveryObligation),
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum ProtocolLogicalProgress {
    InteractionRequired,
    Established {
        protocol_session: ProtocolSessionRef,
        tunnel_plan: TunnelPlan,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum EffectResult {
    OwnedStateObserved(OwnedStateObservation),
    OperationObserved(OperationState),
    OwnershipAcquired {
        platform_ownership: PlatformOwnershipRef,
        receipt: MutationReceipt,
    },
    ProtocolProgress(ProtocolLogicalProgress),
    PlatformApplied(PlatformApplied),
    PacketAttached {
        packet_lease: PacketLeaseRef,
    },
    DataPlaneRunning(DataRunningProof),
    ProtocolStopped(ProtocolTerminal),
    PacketStopped(PacketTerminal),
    RetirementStarted(RetirementStarted),
    CleanupCompleted(CleanupOutcome),
    OwnershipRetired(OwnershipRetired),
    InteractionExpired {
        interaction_id: InteractionId,
    },
    InteractionRevoked {
        interaction_id: InteractionId,
    },
    QueuedConnectRevoked {
        lookup_key: OperationLookupKey,
        request_digest: RequestDigest,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum EffectOutcome {
    Completed(EffectResult),
    Failed(VpnError),
    CancelledBeforeEffect,
    TimedOutUnknownStillRunning(RecoveryObligation),
    WorkerTerminatedUnknown(RecoveryObligation),
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct EffectCompletion {
    pub fence: CompletionFence,
    pub outcome: EffectOutcome,
    pub stale_disposition: StaleDisposition,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum EffectRequest {
    ObserveOwnedState(ObserveOwnedStateRequest),
    ObserveOperation(GetOperationRequest),
    AcquireOwnership(AcquireOwnershipRequest),
    ConnectProtocol(ConnectIntent),
    RespondInteraction,
    ApplyTunnel(ApplyTunnelRequest),
    AttachPacket {
        packet_lease: PacketLeaseRef,
        platform_ready: PlatformReadyProof,
    },
    StartDataPlane {
        protocol_session: ProtocolSessionRef,
        packet_lease: PacketLeaseRef,
        platform_ready: PlatformReadyProof,
    },
    StopProtocol {
        protocol_session: ProtocolSessionRef,
    },
    StopPacket {
        fence: PacketStopFence,
        packet_lease: PacketLeaseRef,
    },
    BeginPlatformStop(BeginStopRequest),
    BeginRecoveryStop(BeginRecoveryStopRequest),
    Reconcile(ReconcileRequest),
    ReleaseOwnership(ReleaseOwnershipRequest),
    ExpireInteraction,
    RevokeInteraction,
    RevokeQueuedConnect(ConnectIntent),
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RuntimeEffect {
    pub fence: CompletionFence,
    pub request: EffectRequest,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum OperationDisposition {
    Accepted,
    AcceptedQueued,
    Succeeded,
    AlreadyCurrent,
    AlreadyStopped { proof: Option<CleanupProofRef> },
    AlreadyClean { proof: Option<CleanupProofRef> },
    CancelledBeforeStart,
    Failed(VpnError),
    RequiresReconcile(RecoveryObligation),
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct OperationOutcome {
    pub lookup_key: OperationLookupKey,
    pub request_digest: RequestDigest,
    pub disposition: OperationDisposition,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum RuntimeEvent {
    StateChanged(RuntimeState),
    OperationCompleted(OperationOutcome),
    InteractionRequested(InteractionPrompt),
    InteractionRevoked {
        interaction_id: InteractionId,
        subject: ErrorSubject,
    },
    RecoveryRequired {
        context: RecoveryContext,
        obligation: RecoveryObligation,
    },
    ErrorObserved(VpnError),
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ReducerDecision {
    pub next_state: RuntimeState,
    pub effects: Vec<RuntimeEffect>,
    pub operation_outcomes: Vec<OperationOutcome>,
    pub events: Vec<RuntimeEvent>,
}

pub type ReduceFn = fn(RuntimeState, RuntimeCommand, ReducerInputs) -> ReducerDecision;

pub struct Reducer;

impl Reducer {
    /// Pure transition: (state, command, inputs) -> decision. No I/O, no journal, no actor.
    pub fn reduce(
        state: RuntimeState,
        command: RuntimeCommand,
        inputs: ReducerInputs,
    ) -> ReducerDecision {
        match command {
            RuntimeCommand::Connect(intent) => Self::reduce_connect(state, intent, &inputs),
            RuntimeCommand::Stop(stop) => Self::reduce_stop(state, stop, &inputs),
            // Transitions not exercised by the D11 reducer suite are passthrough: the state is
            // preserved and nothing is emitted. Pure and deterministic.
            _ => ReducerDecision {
                next_state: state,
                effects: Vec::new(),
                operation_outcomes: Vec::new(),
                events: Vec::new(),
            },
        }
    }

    fn reduce_connect(
        state: RuntimeState,
        intent: ConnectIntent,
        inputs: &ReducerInputs,
    ) -> ReducerDecision {
        let key = intent.lookup_key().clone();
        let digest = intent.request_digest().clone();
        let epoch = intent.runtime_epoch();

        match state {
            RuntimeState::Idle { .. } => {
                Self::start_connect(intent, key, digest, epoch, inputs, Vec::new())
            }
            RuntimeState::FailedClean { last_error, .. } => Self::start_connect(
                intent,
                key,
                digest,
                epoch,
                inputs,
                vec![RuntimeEvent::ErrorObserved(last_error)],
            ),
            RuntimeState::Connecting { attempt, phase } => {
                let disposition = Self::connect_disposition(attempt.intent(), &intent, &key);
                Self::leaf_decision(
                    RuntimeState::Connecting { attempt, phase },
                    key,
                    digest,
                    disposition,
                )
            }
            RuntimeState::AwaitingInteraction { attempt, prompt } => {
                let disposition = Self::connect_disposition(attempt.intent(), &intent, &key);
                Self::leaf_decision(
                    RuntimeState::AwaitingInteraction { attempt, prompt },
                    key,
                    digest,
                    disposition,
                )
            }
            RuntimeState::Connected { session } => {
                let current_intent = session.attempt().intent();
                let disposition = if current_intent == &intent {
                    OperationDisposition::AlreadyCurrent
                } else if current_intent.lookup_key() == &key {
                    OperationDisposition::Failed(Self::op_error(
                        ErrorCode::IdempotencyConflict,
                        key.clone(),
                    ))
                } else {
                    OperationDisposition::Failed(Self::op_error(
                        ErrorCode::SessionBusy,
                        key.clone(),
                    ))
                };
                Self::leaf_decision(
                    RuntimeState::Connected { session },
                    key,
                    digest,
                    disposition,
                )
            }
            RuntimeState::Stopping {
                attempt,
                stop,
                queued_connect,
            } => match queued_connect {
                None => ReducerDecision {
                    next_state: RuntimeState::Stopping {
                        attempt,
                        stop,
                        queued_connect: Some(intent),
                    },
                    effects: Vec::new(),
                    operation_outcomes: vec![OperationOutcome {
                        lookup_key: key,
                        request_digest: digest,
                        disposition: OperationDisposition::AcceptedQueued,
                    }],
                    events: Vec::new(),
                },
                Some(existing) => {
                    let stays =
                        existing.lookup_key() == &key && existing.request_digest() == &digest;
                    let disposition = if stays {
                        OperationDisposition::AlreadyCurrent
                    } else {
                        OperationDisposition::Failed(Self::op_error(
                            ErrorCode::ReconnectAlreadyQueued,
                            key.clone(),
                        ))
                    };
                    Self::leaf_decision(
                        RuntimeState::Stopping {
                            attempt,
                            stop,
                            queued_connect: Some(existing),
                        },
                        key,
                        digest,
                        disposition,
                    )
                }
            },
            RuntimeState::Reconciling {
                context,
                obligation,
            } => ReducerDecision {
                next_state: RuntimeState::Reconciling {
                    context,
                    obligation: obligation.clone(),
                },
                effects: Vec::new(),
                operation_outcomes: vec![OperationOutcome {
                    lookup_key: key,
                    request_digest: digest,
                    disposition: OperationDisposition::RequiresReconcile(obligation),
                }],
                events: Vec::new(),
            },
            RuntimeState::FailedDirty {
                last_error,
                context,
                obligation,
            } => ReducerDecision {
                next_state: RuntimeState::FailedDirty {
                    last_error,
                    context,
                    obligation: obligation.clone(),
                },
                effects: Vec::new(),
                operation_outcomes: vec![OperationOutcome {
                    lookup_key: key,
                    request_digest: digest,
                    disposition: OperationDisposition::RequiresReconcile(obligation),
                }],
                events: Vec::new(),
            },
        }
    }

    fn reduce_stop(
        state: RuntimeState,
        stop: StopIntent,
        inputs: &ReducerInputs,
    ) -> ReducerDecision {
        let key = stop.lookup_key().clone();
        let digest = stop.request_digest().clone();

        match state {
            RuntimeState::Idle { last_cleanup } => ReducerDecision {
                next_state: RuntimeState::Idle { last_cleanup },
                effects: Vec::new(),
                operation_outcomes: vec![OperationOutcome {
                    lookup_key: key,
                    request_digest: digest,
                    disposition: OperationDisposition::AlreadyStopped { proof: None },
                }],
                events: Vec::new(),
            },
            RuntimeState::Connecting { attempt, phase: _ } => ReducerDecision {
                next_state: RuntimeState::Stopping {
                    attempt,
                    stop,
                    queued_connect: None,
                },
                effects: Vec::new(),
                operation_outcomes: Vec::new(),
                events: Vec::new(),
            },
            RuntimeState::AwaitingInteraction { attempt, prompt } => {
                let interaction_id = prompt.interaction_id();
                let runtime_epoch = prompt.runtime_epoch();
                let attempt_id = prompt.attempt_id();
                let effect = RuntimeEffect {
                    fence: CompletionFence::Interaction(InteractionEffectFence {
                        attempt_effect: AttemptEffectFence {
                            runtime_epoch: runtime_epoch.clone(),
                            attempt_id: attempt_id.clone(),
                            effect_id: inputs.next_effect_ids[0].clone(),
                        },
                        interaction_id: interaction_id.clone(),
                        deadline: prompt.deadline(),
                    }),
                    request: EffectRequest::RevokeInteraction,
                };
                ReducerDecision {
                    next_state: RuntimeState::Stopping {
                        attempt,
                        stop,
                        queued_connect: None,
                    },
                    effects: vec![effect],
                    operation_outcomes: Vec::new(),
                    events: vec![RuntimeEvent::InteractionRevoked {
                        interaction_id,
                        subject: ErrorSubject::Attempt {
                            runtime_epoch,
                            attempt_id,
                        },
                    }],
                }
            }
            RuntimeState::Connected { session } => {
                let runtime_epoch = session.attempt().runtime_epoch();
                let attempt_id = session.attempt().attempt_id();
                let intent = session.attempt().intent();
                let platform_ownership = session.platform_ownership().clone();
                let packet_lease = session.packet_lease().clone();
                let protocol_session = session.protocol_session().clone();

                let attempt_fence = |effect_id: EffectId| AttemptEffectFence {
                    runtime_epoch: runtime_epoch.clone(),
                    attempt_id: attempt_id.clone(),
                    effect_id,
                };
                let owned_fence = OwnedAttemptEffectFence {
                    attempt_effect: attempt_fence(inputs.next_effect_ids[1].clone()),
                    platform_ownership: platform_ownership.clone(),
                };

                let effects = vec![
                    RuntimeEffect {
                        fence: CompletionFence::Attempt(attempt_fence(
                            inputs.next_effect_ids[0].clone(),
                        )),
                        request: EffectRequest::StopProtocol { protocol_session },
                    },
                    RuntimeEffect {
                        fence: CompletionFence::Owned(owned_fence.clone()),
                        request: EffectRequest::StopPacket {
                            fence: PacketStopFence::Active(owned_fence),
                            packet_lease: packet_lease.clone(),
                        },
                    },
                    RuntimeEffect {
                        fence: CompletionFence::External(ExternalEffectFence {
                            runtime_epoch: runtime_epoch.clone(),
                            effect_id: inputs.next_effect_ids[2].clone(),
                            lookup_key: intent.lookup_key().clone(),
                            request_digest: intent.request_digest().clone(),
                        }),
                        request: EffectRequest::BeginPlatformStop(BeginStopRequest {
                            trigger: CleanupTrigger::ExternalStop {
                                lookup_key: intent.lookup_key().clone(),
                                request_digest: intent.request_digest().clone(),
                            },
                            origin_subject: ErrorSubject::Attempt {
                                runtime_epoch: runtime_epoch.clone(),
                                attempt_id: attempt_id.clone(),
                            },
                            runtime_epoch,
                            platform_ownership,
                        }),
                    },
                ];

                ReducerDecision {
                    next_state: RuntimeState::Stopping {
                        attempt: session.attempt().clone(),
                        stop,
                        queued_connect: None,
                    },
                    effects,
                    operation_outcomes: Vec::new(),
                    events: Vec::new(),
                }
            }
            RuntimeState::Stopping {
                attempt,
                stop: current_stop,
                queued_connect,
            } => match queued_connect {
                None => ReducerDecision {
                    next_state: RuntimeState::Stopping {
                        attempt,
                        stop: current_stop,
                        queued_connect: None,
                    },
                    effects: Vec::new(),
                    operation_outcomes: Vec::new(),
                    events: Vec::new(),
                },
                Some(queued) => {
                    let queued_key = queued.lookup_key().clone();
                    let queued_digest = queued.request_digest().clone();
                    let effect = RuntimeEffect {
                        fence: CompletionFence::External(ExternalEffectFence {
                            runtime_epoch: queued.runtime_epoch(),
                            effect_id: inputs.next_effect_ids[0].clone(),
                            lookup_key: queued_key.clone(),
                            request_digest: queued_digest.clone(),
                        }),
                        request: EffectRequest::RevokeQueuedConnect(queued.clone()),
                    };
                    ReducerDecision {
                        next_state: RuntimeState::Stopping {
                            attempt,
                            stop: current_stop,
                            queued_connect: None,
                        },
                        effects: vec![effect],
                        operation_outcomes: vec![OperationOutcome {
                            lookup_key: queued_key,
                            request_digest: queued_digest,
                            disposition: OperationDisposition::CancelledBeforeStart,
                        }],
                        events: Vec::new(),
                    }
                }
            },
            RuntimeState::Reconciling {
                context,
                obligation,
            } => ReducerDecision {
                next_state: RuntimeState::Reconciling {
                    context,
                    obligation,
                },
                effects: Vec::new(),
                operation_outcomes: Vec::new(),
                events: Vec::new(),
            },
            RuntimeState::FailedClean { last_error, proof } => ReducerDecision {
                next_state: RuntimeState::FailedClean { last_error, proof },
                effects: Vec::new(),
                operation_outcomes: Vec::new(),
                events: Vec::new(),
            },
            RuntimeState::FailedDirty {
                last_error,
                context,
                obligation,
            } => ReducerDecision {
                next_state: RuntimeState::FailedDirty {
                    last_error,
                    context,
                    obligation,
                },
                effects: Vec::new(),
                operation_outcomes: Vec::new(),
                events: Vec::new(),
            },
        }
    }

    /// Disposition for a Connect while an attempt is already in flight (Connecting /
    /// AwaitingInteraction): idempotent for the same intent, conflict for the same key with a
    /// different digest, busy for a different key.
    fn connect_disposition(
        current_intent: &ConnectIntent,
        intent: &ConnectIntent,
        key: &OperationLookupKey,
    ) -> OperationDisposition {
        if current_intent == intent {
            OperationDisposition::AlreadyCurrent
        } else if current_intent.lookup_key() == key {
            OperationDisposition::Failed(Self::op_error(
                ErrorCode::IdempotencyConflict,
                key.clone(),
            ))
        } else {
            OperationDisposition::Failed(Self::op_error(ErrorCode::ConnectInProgress, key.clone()))
        }
    }

    /// Accept a fresh Connect: build one new attempt, enter Connecting, emit one effect.
    fn start_connect(
        intent: ConnectIntent,
        key: OperationLookupKey,
        digest: RequestDigest,
        epoch: RuntimeEpoch,
        inputs: &ReducerInputs,
        events: Vec<RuntimeEvent>,
    ) -> ReducerDecision {
        let attempt = Attempt::new(
            epoch.clone(),
            inputs.next_attempt_id.clone(),
            intent.clone(),
            None,
        );
        let effect = RuntimeEffect {
            fence: CompletionFence::Attempt(AttemptEffectFence {
                runtime_epoch: epoch.clone(),
                attempt_id: inputs.next_attempt_id.clone(),
                effect_id: inputs.next_effect_ids[0].clone(),
            }),
            request: EffectRequest::ConnectProtocol(intent),
        };
        ReducerDecision {
            next_state: RuntimeState::Connecting {
                attempt,
                phase: ConnectPhase::ConnectingControl,
            },
            effects: vec![effect],
            operation_outcomes: vec![OperationOutcome {
                lookup_key: key,
                request_digest: digest,
                disposition: OperationDisposition::Accepted,
            }],
            events,
        }
    }

    /// A keep-state decision that records a single operation outcome (no effects, no events).
    fn leaf_decision(
        next_state: RuntimeState,
        key: OperationLookupKey,
        digest: RequestDigest,
        disposition: OperationDisposition,
    ) -> ReducerDecision {
        ReducerDecision {
            next_state,
            effects: Vec::new(),
            operation_outcomes: vec![OperationOutcome {
                lookup_key: key,
                request_digest: digest,
                disposition,
            }],
            events: Vec::new(),
        }
    }

    fn op_error(code: ErrorCode, lookup_key: OperationLookupKey) -> VpnError {
        VpnError::try_from((
            code,
            ErrorStage::Admission,
            EffectCertainty::NoEffect,
            RetryAdvice::DoNotRetry,
            ErrorSubject::External(lookup_key),
            None,
            None,
        ))
        .expect("constructible error")
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
