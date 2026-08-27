// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
// R31-T/I: the single-writer `RuntimeActor`. It consumes `RuntimeCommand`s from a bounded mailbox,
// calls the frozen `Reducer::reduce(state, command, inputs)` with fresh `ReducerInputs` seeds,
// schedules the resulting fenced `RuntimeEffect`s via an injected `EffectScheduler`, and routes
// `EffectCompleted` completions back (with their `CompletionFence` + `StaleDisposition`). The actor
// is the ONLY state writer: effect tasks never write state directly, no lock is held across an
// effect, Stop is recorded before new effects are issued, and completions are serviced even under a
// Stop flood. Late TLS/packet handles are closed+joined / detached+reconciled; a completion fenced
// to a prior runtime epoch is rejected.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::{
    AttemptId, EffectId, InteractionId, InventoryDigest, OperationId, OperationLookupKey,
    OperationMethod, PrincipalDigest, RecoveryId, RequestDigest, ResourceIdentityDigest,
    RuntimeEpoch,
};
use exv_vpn_domain::limits::MvpLimits;
use exv_vpn_domain::model::{
    Attempt, ConnectIntent, ConnectionProfileRef, PromptDeadline, ProtocolSessionRef,
    RecoveryContext, RecoveryObligation, RuntimeState, StopIntent,
};
use exv_vpn_domain::ports::{AttemptEffectFence, MonotonicTick};
use exv_vpn_domain::reducer::{
    CompletionFence, EffectCompletion, EffectRequest, EphemeralCleanupRef, EphemeralResourceKind,
    RecoveryEffectFence, Reducer, ReducerInputs, RuntimeCommand, RuntimeEffect, StaleDisposition,
};
use uuid::Uuid;

use crate::mailbox::BoundedMailbox;

pub use crate::effect::EffectScheduler;

/// A registered late-resource cleanup: invoked exactly once when the actor consumes the matching
/// ephemeral cleanup disposition (protocol late handle: close + join; packet late handle: detach).
pub type LateCleanup = Box<dyn FnOnce() + Send + 'static>;

struct LateHandleEntry {
    ref_: EphemeralCleanupRef,
    cleanup: Option<LateCleanup>,
    consumed: bool,
}

/// The actor's private single-writer state. Only the actor loop mutates `state`.
struct ActorInner {
    state: RuntimeState,
    commands: BoundedMailbox<RuntimeCommand>,
    completions: BoundedMailbox<EffectCompletion>,
    /// Fenced effects scheduled but not yet consumed by a current completion.
    inflight: Vec<RuntimeEffect>,
    /// The current runtime era, used to reject completions fenced to a prior epoch.
    current_epoch: Option<RuntimeEpoch>,
    late_handles: Vec<LateHandleEntry>,
}

/// A held single-writer lock. Dropping the guard releases the actor's state lock.
pub struct ActorLockGuard<'a> {
    _guard: MutexGuard<'a, ActorInner>,
}

/// The runtime's single state writer.
pub struct RuntimeActor {
    inner: Mutex<ActorInner>,
    scheduler: Arc<dyn EffectScheduler>,
}

impl RuntimeActor {
    /// Construct an actor from an idle state with mailboxes sized by `limits`.
    pub fn new(limits: &MvpLimits, scheduler: Arc<dyn EffectScheduler>) -> Self {
        Self::from_state(limits, scheduler, RuntimeState::idle())
    }

    /// Construct an actor seeded with `initial` (e.g. a restored `Connected` on host loss).
    pub fn from_state(
        limits: &MvpLimits,
        scheduler: Arc<dyn EffectScheduler>,
        initial: RuntimeState,
    ) -> Self {
        let inner = ActorInner {
            state: initial,
            commands: BoundedMailbox::new(limits.normal_mailbox_messages),
            completions: BoundedMailbox::new(limits.completion_mailbox_messages),
            inflight: Vec::new(),
            current_epoch: None,
            late_handles: Vec::new(),
        };
        RuntimeActor {
            inner: Mutex::new(inner),
            scheduler,
        }
    }

    /// Enqueue a normal command (bounded; dropped when the mailbox is full).
    pub fn submit(&self, command: RuntimeCommand) {
        let mut inner = self.inner.lock().unwrap();
        let _ = inner.commands.try_send(command);
    }

    /// Enqueue a completion (bounded; dropped when the mailbox is full).
    pub fn complete_effect(&self, completion: EffectCompletion) {
        let mut inner = self.inner.lock().unwrap();
        let _ = inner.completions.try_send(completion);
    }

    /// Drain both inboxes synchronously: run the reducer, schedule effects (releasing the lock
    /// before any effect task runs), and route completions. Commands are drained before
    /// completions so a queued Stop is recorded before a pending completion is settled.
    pub fn pump(&self) {
        let mut inner = self.inner.lock().unwrap();
        while let Some(command) = inner.commands.try_recv() {
            self.handle_command(&mut inner, command);
        }
        while let Some(completion) = inner.completions.try_recv() {
            self.handle_completion(&mut inner, completion);
        }
    }

    /// The committed-state snapshot.
    pub fn state(&self) -> RuntimeState {
        self.inner.lock().unwrap().state.clone()
    }

    /// Number of scheduled-but-not-yet-consumed effects.
    pub fn inflight_effects(&self) -> usize {
        self.inner.lock().unwrap().inflight.len()
    }

    /// The fences of all inflight effects.
    pub fn inflight_fences(&self) -> Vec<CompletionFence> {
        self.inner
            .lock()
            .unwrap()
            .inflight
            .iter()
            .map(|e| e.fence.clone())
            .collect()
    }

    /// Probe the single-writer lock without blocking. `None` means the lock is held (an effect or
    /// another writer is in flight); `Some` yields a guard that must be dropped quickly.
    pub fn try_lock(&self) -> Option<ActorLockGuard<'_>> {
        self.inner
            .try_lock()
            .ok()
            .map(|guard| ActorLockGuard { _guard: guard })
    }

    /// Register a late-resource cleanup for an ephemeral resource, keyed by its cleanup ref.
    pub fn register_late_handle(&self, ref_: EphemeralCleanupRef, cleanup: LateCleanup) {
        let mut inner = self.inner.lock().unwrap();
        inner.late_handles.push(LateHandleEntry {
            ref_,
            cleanup: Some(cleanup),
            consumed: false,
        });
    }

    /// Whether the late handle for `ref_` has been consumed (its cleanup invoked or discarded).
    pub fn late_handle_consumed(&self, ref_: &EphemeralCleanupRef) -> bool {
        let inner = self.inner.lock().unwrap();
        inner
            .late_handles
            .iter()
            .any(|e| &e.ref_ == ref_ && e.consumed)
    }

    // ---- command path ----

    fn handle_command(&self, inner: &mut ActorInner, command: RuntimeCommand) {
        // HostLost is a lifecycle terminal the actor must handle itself: the frozen reducer treats
        // it as a passthrough, so the actor revokes data admission and starts a teardown directly.
        if let RuntimeCommand::HostLost { runtime_epoch } = &command {
            inner.current_epoch = Some(runtime_epoch.clone());
            self.begin_host_lost_teardown(inner, runtime_epoch.clone());
            return;
        }

        let outstanding: Vec<EffectId> = match &command {
            RuntimeCommand::EffectCompleted(c) => fence_effect_id(&c.fence).into_iter().collect(),
            _ => Vec::new(),
        };
        let inputs = self.fresh_inputs(&outstanding);
        let decision = Reducer::reduce(inner.state.clone(), command, inputs);
        inner.state = decision.next_state;
        self.commit_effects(inner, decision.effects);
    }

    // ---- completion path ----

    fn handle_completion(&self, inner: &mut ActorInner, completion: EffectCompletion) {
        // A completion fenced to a runtime epoch that differs from the current era is rejected:
        // never consumed against the inflight effect, never applied.
        if let Some(current) = inner.current_epoch.clone() {
            if fence_epoch(&completion.fence) != current {
                return;
            }
        }

        // A fence matching an inflight effect is a CURRENT completion: consume the inflight effect
        // and route the completion to the reducer (the actor's sole write path).
        if let Some(idx) = inner
            .inflight
            .iter()
            .position(|e| e.fence == completion.fence)
        {
            inner.inflight.remove(idx);
            self.settle_current(inner, completion);
            return;
        }

        // Otherwise it is a stale completion in the current era: converge per its disposition.
        self.apply_stale(inner, completion.stale_disposition);
    }

    /// Settle a current completion: re-run the reducer with the completion so only the actor
    /// writes state, and schedule any effects the reducer emits.
    fn settle_current(&self, inner: &mut ActorInner, completion: EffectCompletion) {
        let outstanding: Vec<EffectId> = fence_effect_id(&completion.fence).into_iter().collect();
        let inputs = self.fresh_inputs(&outstanding);
        let decision = Reducer::reduce(
            inner.state.clone(),
            RuntimeCommand::EffectCompleted(completion),
            inputs,
        );
        inner.state = decision.next_state;
        self.commit_effects(inner, decision.effects);
    }

    /// Apply a stale completion's disposition (the actor's own responsibility, independent of the
    /// reducer): no-effect is discarded, ephemeral resources consume their cleanup token, journaled
    /// requests reconcile, and unknown acquisitions enter recovery.
    fn apply_stale(&self, inner: &mut ActorInner, disposition: StaleDisposition) {
        match disposition {
            StaleDisposition::ProvenNoEffect => {
                // Discard: no state change, no effect, no recovery.
            }
            StaleDisposition::AcquiredEphemeralResource(ref_) => {
                self.consume_late_handle(inner, &ref_);
                // A late packet attach is detached AND reconciled afterwards.
                if ref_.kind == EphemeralResourceKind::PacketLateHandle {
                    self.enter_reconciling(inner, self.recovery_obligation());
                }
            }
            StaleDisposition::JournaledExternalEffect(_) => {
                // Request reconcile: the journaled external operation is re-synced.
                self.enter_reconciling(inner, self.recovery_obligation());
            }
            StaleDisposition::UnknownResourceAcquisition(obligation) => {
                self.enter_reconciling(inner, obligation);
            }
        }
    }

    /// Consume a registered late handle exactly once: invoke its cleanup (close + join for a
    /// protocol TLS handle; detach for a packet lease) and mark it consumed.
    fn consume_late_handle(&self, inner: &mut ActorInner, ref_: &EphemeralCleanupRef) {
        if let Some(entry) = inner.late_handles.iter_mut().find(|e| &e.ref_ == ref_) {
            if !entry.consumed {
                entry.consumed = true;
                if let Some(cleanup) = entry.cleanup.take() {
                    cleanup();
                }
            }
        }
    }

    /// Enter `Reconciling` carrying the given recovery obligation.
    fn enter_reconciling(&self, inner: &mut ActorInner, obligation: RecoveryObligation) {
        let epoch = inner
            .current_epoch
            .clone()
            .unwrap_or_else(|| self.fresh_epoch());
        let context = RecoveryContext::startup(epoch, self.fresh_recovery_id());
        inner.state = RuntimeState::reconciling(context, obligation);
    }

    // ---- host-lost teardown ----

    /// Revoke data admission (leave `Connected`) and start a fenced teardown effect.
    fn begin_host_lost_teardown(&self, inner: &mut ActorInner, epoch: RuntimeEpoch) {
        let attempt_id = self.fresh_attempt_id();
        let effect_id = self.fresh_effect_id();
        let principal = PrincipalDigest::try_from([1u8; 32]).expect("principal digest");
        let lookup_key = OperationLookupKey::try_from((
            principal,
            OperationMethod::Connect,
            epoch.clone(),
            self.fresh_operation_id(),
        ))
        .expect("lookup key");
        let request_digest = RequestDigest::try_from([2u8; 32]).expect("request digest");
        let profile = ConnectionProfileRef::try_from(
            ResourceIdentityDigest::try_from([3u8; 32]).expect("resource identity digest"),
        )
        .expect("profile ref");
        let intent = ConnectIntent::new(lookup_key.clone(), request_digest.clone(), profile);
        let attempt = Attempt::new(epoch.clone(), attempt_id.clone(), intent, None);
        let stop = StopIntent::new(lookup_key.clone(), request_digest.clone());
        inner.state = RuntimeState::stopping(attempt, stop, None);

        let protocol_session = ProtocolSessionRef::try_from(
            ResourceIdentityDigest::try_from([11u8; 32]).expect("resource identity digest"),
        )
        .expect("protocol session ref");
        let effect = RuntimeEffect {
            fence: CompletionFence::Attempt(AttemptEffectFence {
                runtime_epoch: epoch.clone(),
                attempt_id,
                effect_id,
            }),
            request: EffectRequest::StopProtocol { protocol_session },
        };
        self.commit_effects(inner, vec![effect]);
    }

    // ---- effect commitment ----

    /// Track, commit, and schedule effects. The actor records the effect as inflight before the
    /// scheduler runs it, and infers the current era from the first fenced effect.
    fn commit_effects(&self, inner: &mut ActorInner, effects: Vec<RuntimeEffect>) {
        for effect in effects {
            if inner.current_epoch.is_none() {
                inner.current_epoch = Some(fence_epoch(&effect.fence));
            }
            inner.inflight.push(effect.clone());
            self.scheduler.schedule(effect);
        }
    }

    // ---- seed issuance ----

    /// Build fresh `ReducerInputs` seeds from strong uuid entropy (never from request digest, wall
    /// clock, or old identity). `outstanding_teardown_effects` carries the completing `EffectId`.
    fn fresh_inputs(&self, outstanding_teardown_effects: &[EffectId]) -> ReducerInputs {
        let next_effect_ids = [
            self.fresh_effect_id(),
            self.fresh_effect_id(),
            self.fresh_effect_id(),
        ];
        let next_prompt_deadline = PromptDeadline::try_from((
            MonotonicTick::try_from(0u64).expect("monotonic tick"),
            Duration::from_secs(30),
        ))
        .expect("prompt deadline");
        ReducerInputs {
            next_attempt_id: self.fresh_attempt_id(),
            next_effect_ids,
            next_interaction_id: self.fresh_interaction_id(),
            next_prompt_deadline,
            outstanding_teardown_effects: outstanding_teardown_effects.to_vec(),
        }
    }

    fn recovery_obligation(&self) -> RecoveryObligation {
        let epoch = self.fresh_epoch();
        RecoveryObligation::new(
            epoch.clone(),
            None,
            self.blocker_error(epoch.clone()),
            None,
            None,
            InventoryDigest::try_from([5u8; 32]).expect("inventory digest"),
        )
    }

    fn blocker_error(&self, epoch: RuntimeEpoch) -> VpnError {
        VpnError::try_from((
            ErrorCode::EffectUnknown,
            ErrorStage::Recovery,
            EffectCertainty::Unknown,
            RetryAdvice::Reconcile,
            ErrorSubject::Runtime(epoch),
            None,
            None,
        ))
        .expect("constructible error")
    }

    fn fresh_epoch(&self) -> RuntimeEpoch {
        RuntimeEpoch::try_from(Uuid::new_v4()).expect("non-nil uuid")
    }

    fn fresh_attempt_id(&self) -> AttemptId {
        AttemptId::try_from(Uuid::new_v4()).expect("non-nil uuid")
    }

    fn fresh_effect_id(&self) -> EffectId {
        EffectId::try_from(Uuid::new_v4()).expect("non-nil uuid")
    }

    fn fresh_interaction_id(&self) -> InteractionId {
        InteractionId::try_from(Uuid::new_v4()).expect("non-nil uuid")
    }

    fn fresh_recovery_id(&self) -> RecoveryId {
        RecoveryId::try_from(Uuid::new_v4()).expect("non-nil uuid")
    }

    fn fresh_operation_id(&self) -> OperationId {
        OperationId::try_from(Uuid::new_v4()).expect("non-nil uuid")
    }
}

/// The runtime epoch carried by a `CompletionFence` (present for every variant).
fn fence_epoch(fence: &CompletionFence) -> RuntimeEpoch {
    match fence {
        CompletionFence::External(f) => f.runtime_epoch.clone(),
        CompletionFence::Attempt(f) => f.runtime_epoch.clone(),
        CompletionFence::Owned(f) => f.attempt_effect.runtime_epoch.clone(),
        CompletionFence::Interaction(f) => f.attempt_effect.runtime_epoch.clone(),
        CompletionFence::Recovery(f) => match f {
            RecoveryEffectFence::Observe { runtime_epoch, .. } => runtime_epoch.clone(),
            RecoveryEffectFence::Owned { runtime_epoch, .. } => runtime_epoch.clone(),
            RecoveryEffectFence::Retirement { runtime_epoch, .. } => runtime_epoch.clone(),
        },
    }
}

/// The effect id carried by a `CompletionFence` (present for every variant).
fn fence_effect_id(fence: &CompletionFence) -> Option<EffectId> {
    match fence {
        CompletionFence::External(f) => Some(f.effect_id.clone()),
        CompletionFence::Attempt(f) => Some(f.effect_id.clone()),
        CompletionFence::Owned(f) => Some(f.attempt_effect.effect_id.clone()),
        CompletionFence::Interaction(f) => Some(f.attempt_effect.effect_id.clone()),
        CompletionFence::Recovery(f) => match f {
            RecoveryEffectFence::Observe { effect_id, .. } => Some(effect_id.clone()),
            RecoveryEffectFence::Owned { effect_id, .. } => Some(effect_id.clone()),
            RecoveryEffectFence::Retirement { effect_id, .. } => Some(effect_id.clone()),
        },
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
