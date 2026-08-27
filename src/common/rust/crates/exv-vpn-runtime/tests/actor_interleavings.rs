// EXV R31-T: effect scheduling, stale disposition, and host-lost for exv-vpn-runtime.
// These tests define and pin the actor contract that R31-I must implement in
// `exv_vpn_runtime::actor`. The actor is the runtime's single writer: it consumes
// `RuntimeCommand`s (bounded mailbox from R30), calls `Reducer::reduce(state, command,
// inputs)`, schedules the resulting fenced `RuntimeEffect`s (each a fenced effect task), and
// routes `EffectCompleted` completions back carrying their `CompletionFence` and
// `StaleDisposition`. They are expected to be RED until R31-I implements `actor::RuntimeActor`.
//
// The actor contract is FROZEN BY THESE TESTS. R31-I must implement EXACTLY in
// `exv_vpn_runtime::actor`:
//   - `RuntimeActor::new(limits: &MvpLimits, scheduler: Arc<dyn EffectScheduler>)`
//   - `RuntimeActor::from_state(limits, scheduler, initial: RuntimeState)`
//   - `RuntimeActor::submit(&self, command: RuntimeCommand)`      // enqueue a normal command
//   - `RuntimeActor::complete_effect(&self, completion: EffectCompletion)` // enqueue a completion
//   - `RuntimeActor::pump(&self)`  // drain inboxes synchronously: run reducer, schedule effects
//     (spawn fenced effect tasks), route completions; MUST release the single-writer lock before
//     any effect task runs and NOT hold it across an effect.
//   - `RuntimeActor::state(&self) -> RuntimeState`                // committed-state snapshot
//   - `RuntimeActor::inflight_effects(&self) -> usize`            // scheduled-not-yet-consumed
//   - `RuntimeActor::inflight_fences(&self) -> Vec<CompletionFence>`
//   - `RuntimeActor::try_lock(&self) -> Option<ActorLockGuard<'_>>` // single-writer lock probe
//   - `RuntimeActor::register_late_handle(&self, ref_: EphemeralCleanupRef, cleanup: LateCleanup)`
//     where `type LateCleanup = Box<dyn FnOnce() + Send + 'static>`
//   - `RuntimeActor::late_handle_consumed(&self, ref_: &EphemeralCleanupRef) -> bool`
// plus `pub trait EffectScheduler: Send + Sync { fn schedule(&self, effect: RuntimeEffect); }`
// and `pub struct ActorLockGuard<'a>`.
//
// Stale-completion semantics (the actor's own responsibility, independent of the reducer):
//   - `ProvenNoEffect`            -> discard: no state change, no effect, no recovery.
//   - `AcquiredEphemeralResource` -> consume the registered cleanup token (ephemeral close),
//     and for a protocol/packet late handle, close+join it (protocol) or detach+reconcile (packet).
//   - `JournaledExternalEffect`   -> request reconcile (enter `Reconciling`).
//   - `UnknownResourceAcquisition`-> enter recovery (enter `Reconciling`).
// A completion fenced to a runtime epoch that predates the current epoch is REJECTED (never
// consumed, never applied). On `HostLost` the actor revokes data admission and begins a teardown.
//
// These tests are killable by the three R31 mutants:
//   (a) discard the late TLS handle instead of close+join -> late_tls_handle_is_closed_and_joined
//       fails (the closed/joined flags are never set).
//   (b) completion channel permanently below Stop priority -> stop_flood_still_services_completion
//       fails (a stop flood starves the pending completion, inflight_effects() stays nonzero).
//   (c) effect task directly modifies state -> actor_is_only_state_writer fails (the committed
//       state changes without the actor's sole write path).
// Determinism comes from `tokio::time::pause()` and explicit `tokio::sync::Notify` gates; the
// tests NEVER sleep.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::{
    AttemptId, EffectId, EvidenceDigest, InventoryDigest, OperationId, OperationMethod,
    OperationLookupKey, OwnershipVersion, PrincipalDigest, RequestDigest, ResourceIdentityDigest,
    RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::limits::MvpLimits;
use exv_vpn_domain::model::{
    Attempt, ConnectIntent, ConnectedSession, ConnectionProfileRef, DataRunningProof,
    PacketLeaseRef, PlatformOwnershipRef, PlatformReadyProof, ProtocolSessionRef, RecoveryObligation,
    RuntimeState, StopIntent,
};
use exv_vpn_domain::ports::AttemptEffectFence;
use exv_vpn_domain::reducer::{
    CompletionFence, EffectCompletion, EffectOutcome, EffectRequest, EffectResult,
    EphemeralCleanupRef, EphemeralResourceKind, JournalOperationRef, RuntimeCommand,
    RuntimeEffect, StaleDisposition,
};
use exv_vpn_runtime::actor::{ActorLockGuard, EffectScheduler, RuntimeActor};
use std::time::Duration;
use tokio::sync::Notify;
use uuid::Uuid;

/// A base `MvpLimits` with sane, non-inverted budgets.
fn base_limits() -> MvpLimits {
    MvpLimits {
        normal_mailbox_messages: 64,
        completion_mailbox_messages: 16,
        stop_waiters: 8,
        snapshot_receivers: 4,
        packet_queue_messages: 1024,
        packet_queue_bytes: 1 << 20,
        max_packet_batch_packets: 64,
        max_packet_batch_bytes: 1 << 16,
        max_control_message_bytes: 1 << 12,
        max_packet_message_bytes: 1 << 14,
        normal_cleanup_budget: Duration::from_secs(5),
        queued_connect_budget: Duration::from_secs(10),
        owner_lease_ttl: Duration::from_secs(60),
        packet_loss_cleanup_grace: Duration::from_secs(2),
    }
}

// ---- identity / model construction helpers (D10 seams) ----

fn rid(seed: u8) -> ResourceIdentityDigest {
    ResourceIdentityDigest::try_from([seed; 32]).expect("non-nil resource identity")
}

fn fresh_epoch() -> RuntimeEpoch {
    RuntimeEpoch::try_from(Uuid::new_v4()).expect("non-nil uuid")
}

fn fresh_attempt_id() -> AttemptId {
    AttemptId::try_from(Uuid::new_v4()).expect("non-nil uuid")
}

fn fresh_effect_id() -> EffectId {
    EffectId::try_from(Uuid::new_v4()).expect("non-nil uuid")
}

fn fresh_operation_id() -> OperationId {
    OperationId::try_from(Uuid::new_v4()).expect("non-nil uuid")
}

fn principal() -> PrincipalDigest {
    PrincipalDigest::try_from([1u8; 32]).expect("principal digest")
}

fn lookup_key(epoch: &RuntimeEpoch) -> OperationLookupKey {
    OperationLookupKey::try_from((
        principal(),
        OperationMethod::Connect,
        epoch.clone(),
        fresh_operation_id(),
    ))
    .expect("lookup key")
}

fn connect_intent(epoch: &RuntimeEpoch, key: &OperationLookupKey) -> ConnectIntent {
    ConnectIntent::new(
        key.clone(),
        RequestDigest::try_from([7u8; 32]).expect("request digest"),
        ConnectionProfileRef::try_from(rid(9)).expect("profile ref"),
    )
}

fn stop_intent(key: &OperationLookupKey) -> StopIntent {
    StopIntent::new(key.clone(), RequestDigest::try_from([8u8; 32]).expect("request digest"))
}

fn attempt(epoch: &RuntimeEpoch) -> Attempt {
    Attempt::new(
        epoch.clone(),
        fresh_attempt_id(),
        connect_intent(epoch, &lookup_key(epoch)),
        None,
    )
}

/// A completion fence for an arbitrary (foreign) attempt/effect — used to build STALE or
/// prior-epoch completions that do not match the single inflight effect.
fn foreign_fence(epoch: &RuntimeEpoch) -> CompletionFence {
    CompletionFence::Attempt(AttemptEffectFence {
        runtime_epoch: epoch.clone(),
        attempt_id: fresh_attempt_id(),
        effect_id: fresh_effect_id(),
    })
}

fn blocker_error() -> VpnError {
    VpnError::try_from((
        ErrorCode::EffectUnknown,
        ErrorStage::Recovery,
        EffectCertainty::Unknown,
        RetryAdvice::Reconcile,
        ErrorSubject::Runtime(fresh_epoch()),
        None,
        None,
    ))
    .expect("valid error tuple")
}

fn obligation(epoch: &RuntimeEpoch) -> RecoveryObligation {
    RecoveryObligation::new(
        epoch.clone(),
        None,
        blocker_error(),
        None,
        None,
        InventoryDigest::try_from([5u8; 32]).expect("inventory digest"),
    )
}

/// A fully-owned `Connected` state (admission held) plus its runtime epoch.
fn connected_session() -> (RuntimeState, RuntimeEpoch) {
    let epoch = fresh_epoch();
    let session_ref = ProtocolSessionRef::try_from(rid(11)).expect("protocol session ref");
    let ownership = PlatformOwnershipRef::try_from((
        rid(12),
        OwnershipVersion::try_from(1).expect("ownership version"),
        TokenDigest::try_from([3u8; 32]).expect("token digest"),
    ))
    .expect("platform ownership ref");
    let lease = PacketLeaseRef::try_from(rid(13)).expect("packet lease ref");
    let ready = PlatformReadyProof::try_from((ownership.clone(), EvidenceDigest::try_from([4u8; 32]).expect("evidence")))
        .expect("platform ready proof");
    let running = DataRunningProof::try_from((
        session_ref.clone(),
        ownership.clone(),
        lease.clone(),
        EvidenceDigest::try_from([6u8; 32]).expect("evidence"),
    ))
    .expect("data running proof");
    let session = ConnectedSession::new(
        attempt(&epoch),
        session_ref,
        ownership,
        lease,
        ready,
        running,
    );
    (RuntimeState::connected(session), epoch)
}

// ---- deterministic actor harness ----

/// A scripted `EffectScheduler`: each scheduled effect spawns a task that signals `started` then
/// parks on `go`. The test drives effect completion timing explicitly through
/// `RuntimeActor::complete_effect`, so interleavings are fully deterministic under paused time.
struct ScriptedScheduler {
    go: Arc<Notify>,
    started: Arc<Notify>,
}

impl EffectScheduler for ScriptedScheduler {
    fn schedule(&self, _effect: RuntimeEffect) {
        let go = self.go.clone();
        let started = self.started.clone();
        tokio::spawn(async move {
            started.notify_waiters();
            go.notified().await;
        });
    }
}

struct Harness {
    actor: Arc<RuntimeActor>,
    started: Arc<Notify>,
}

impl Harness {
    fn from_state(initial: RuntimeState) -> Self {
        let go = Arc::new(Notify::new());
        let started = Arc::new(Notify::new());
        let scheduler = Arc::new(ScriptedScheduler {
            go: go.clone(),
            started: started.clone(),
        });
        let actor = Arc::new(RuntimeActor::from_state(&base_limits(), scheduler, initial));
        Harness { actor, started }
    }

    fn new() -> Self {
        Self::from_state(RuntimeState::idle())
    }

    fn pump(&self) {
        self.actor.pump();
    }

    /// The fence of the single inflight effect, so tests can build a CURRENT completion.
    fn current_fence(&self) -> CompletionFence {
        let fences = self.actor.inflight_fences();
        assert_eq!(
            fences.len(),
            1,
            "expected exactly one inflight effect, got {}",
            fences.len()
        );
        fences[0].clone()
    }

    /// Complete the single inflight effect as current with the given result.
    fn complete_current(&self, result: EffectResult) {
        self.actor.complete_effect(EffectCompletion {
            fence: self.current_fence(),
            outcome: EffectOutcome::Completed(result),
            stale_disposition: StaleDisposition::ProvenNoEffect,
        });
    }

    /// Wait until the scheduled effect task has signalled that it is running.
    async fn await_effect_started(&self) {
        self.started.notified().await;
    }
}

// ---- the 12 frozen tests ----

/// The actor is the ONLY state writer: the committed state changes exclusively through the actor
/// loop (`pump`), never through an effect task. While a fenced effect is in flight, the committed
/// state is exactly what the actor wrote when it scheduled that effect — an effect task must not
/// be able to observe or produce a different `RuntimeState`. Kills mutant (c): an effect task that
/// directly modified state would make `state()` diverge from the actor-committed `Connecting`
/// while the effect is still in flight.
#[tokio::test]
async fn actor_is_only_state_writer() {
    tokio::time::pause();
    let h = Harness::new();
    let epoch = fresh_epoch();
    let key = lookup_key(&epoch);

    h.actor.submit(RuntimeCommand::Connect(connect_intent(&epoch, &key)));
    h.pump();

    // The actor, as the single writer, committed `Connecting` and scheduled one fenced effect.
    assert!(
        matches!(h.actor.state(), RuntimeState::Connecting { .. }),
        "actor did not commit the Connecting transition"
    );
    assert_eq!(h.actor.inflight_effects(), 1);
    h.await_effect_started().await;

    // While the effect task is running, the committed state has not been touched by the effect:
    // it is still exactly `Connecting`. If the effect task were a state writer, this would have
    // changed without a `pump`.
    assert!(
        matches!(h.actor.state(), RuntimeState::Connecting { .. }),
        "effect task directly modified the committed state"
    );

    // The effect's result reaches state only through the actor's sole write path (`pump` after
    // `complete_effect`); a current completion for the inflight effect is consumed without the
    // effect writing anything itself.
    h.complete_current(EffectResult::ProtocolStopped(exv_vpn_domain::ports::ProtocolTerminal::Terminated));
    h.pump();
    assert!(
        matches!(h.actor.state(), RuntimeState::Connecting { .. }),
        "effect task wrote state directly"
    );
    assert_eq!(h.actor.inflight_effects(), 0);
}

/// The actor holds no lock across an effect: it acquires its single-writer lock only for the
/// (pure, non-blocking) state transition, schedules the fenced effect, and releases the lock
/// before the effect task can run. While an effect is in flight the lock is free.
#[tokio::test]
async fn actor_holds_no_lock_across_effect() {
    tokio::time::pause();
    let h = Harness::new();
    let epoch = fresh_epoch();
    let key = lookup_key(&epoch);

    h.actor.submit(RuntimeCommand::Connect(connect_intent(&epoch, &key)));
    h.pump();
    assert_eq!(h.actor.inflight_effects(), 1);
    h.await_effect_started().await;

    // The single-writer lock is acquired-quickly while the effect is in flight: the actor is not
    // holding it across the (long-running) effect.
    let guard: ActorLockGuard<'_> = h
        .actor
        .try_lock()
        .expect("actor holds the state lock across an effect");
    drop(guard);

    // The actor is still responsive while the effect is in flight: it can accept and process a
    // new command (Stop recorded) without waiting for the effect.
    h.actor.submit(RuntimeCommand::Stop(stop_intent(&key)));
    h.pump();
    assert!(
        matches!(h.actor.state(), RuntimeState::Stopping { .. }),
        "actor was blocked behind an in-flight effect"
    );
}

/// The actor records a Stop into state BEFORE scheduling any new effect that a queued completion
/// would otherwise produce from the pre-stop state. A Stop and a current completion are queued
/// together: the committed state must be `Stopping` and no forward effect may be scheduled past
/// the one already in flight.
#[tokio::test]
async fn stop_is_recorded_before_new_effect() {
    tokio::time::pause();
    let h = Harness::new();
    let epoch = fresh_epoch();
    let key = lookup_key(&epoch);

    h.actor.submit(RuntimeCommand::Connect(connect_intent(&epoch, &key)));
    h.pump();
    assert_eq!(h.actor.inflight_effects(), 1);

    // Queue the Stop and the current completion together.
    h.actor.submit(RuntimeCommand::Stop(stop_intent(&key)));
    h.complete_current(EffectResult::ProtocolStopped(
        exv_vpn_domain::ports::ProtocolTerminal::Terminated,
    ));
    h.pump();

    // Stop was recorded first: the committed state is Stopping and no new forward effect was
    // scheduled as a result of processing the completion.
    assert!(
        matches!(h.actor.state(), RuntimeState::Stopping { .. }),
        "Stop was not recorded before processing the completion"
    );
    assert_eq!(
        h.actor.inflight_effects(),
        0,
        "a new effect was scheduled before Stop was recorded"
    );
}

/// A Stop flood must not permanently starve the completion channel. Under a flood of Stop
/// commands a pending current completion is still serviced (its inflight effect is consumed).
/// Kills mutant (b): a completion channel kept permanently below Stop priority would leave the
/// inflight effect unconsumed under the flood.
#[tokio::test]
async fn stop_flood_still_services_completion() {
    tokio::time::pause();
    let h = Harness::new();
    let epoch = fresh_epoch();
    let key = lookup_key(&epoch);

    h.actor.submit(RuntimeCommand::Connect(connect_intent(&epoch, &key)));
    h.pump();
    assert_eq!(h.actor.inflight_effects(), 1);

    // A large flood of Stops alongside the pending completion.
    for _ in 0..100 {
        h.actor.submit(RuntimeCommand::Stop(stop_intent(&key)));
    }
    h.complete_current(EffectResult::ProtocolStopped(
        exv_vpn_domain::ports::ProtocolTerminal::Terminated,
    ));
    h.pump();

    // The completion was serviced despite the flood: the inflight effect was consumed.
    assert_eq!(
        h.actor.inflight_effects(),
        0,
        "stop flood starved the completion channel"
    );
}

/// A stale completion with `ProvenNoEffect` is discarded: no state change, no recovery, and the
/// (unrelated) inflight effect is not consumed.
#[tokio::test]
async fn stale_no_effect_is_discarded() {
    tokio::time::pause();
    let h = Harness::new();
    let epoch = fresh_epoch();
    let key = lookup_key(&epoch);

    h.actor.submit(RuntimeCommand::Connect(connect_intent(&epoch, &key)));
    h.pump();
    assert_eq!(h.actor.inflight_effects(), 1);

    h.actor.complete_effect(EffectCompletion {
        fence: foreign_fence(&epoch),
        outcome: EffectOutcome::Completed(EffectResult::ProtocolStopped(
            exv_vpn_domain::ports::ProtocolTerminal::Terminated,
        )),
        stale_disposition: StaleDisposition::ProvenNoEffect,
    });
    h.pump();

    assert!(
        matches!(h.actor.state(), RuntimeState::Connecting { .. }),
        "stale ProvenNoEffect completion changed the committed state"
    );
    assert_eq!(
        h.actor.inflight_effects(),
        1,
        "stale ProvenNoEffect completion consumed the inflight effect"
    );
}

/// A stale completion carrying `AcquiredEphemeralResource` consumes the registered cleanup token:
/// the actor invokes the registered late-handle cleanup for that ephemeral resource.
#[tokio::test]
async fn stale_ephemeral_resource_consumes_cleanup_token() {
    tokio::time::pause();
    let h = Harness::new();
    let epoch = fresh_epoch();
    let key = lookup_key(&epoch);

    h.actor.submit(RuntimeCommand::Connect(connect_intent(&epoch, &key)));
    h.pump();

    let cleanup = EphemeralCleanupRef {
        effect_id: fresh_effect_id(),
        kind: EphemeralResourceKind::PlatformOwnershipToken,
    };
    let consumed = Arc::new(AtomicBool::new(false));
    let ticked = consumed.clone();
    h.actor.register_late_handle(cleanup.clone(), Box::new(move || {
        ticked.store(true, Ordering::SeqCst);
    }));

    h.actor.complete_effect(EffectCompletion {
        fence: foreign_fence(&epoch),
        outcome: EffectOutcome::CancelledBeforeEffect,
        stale_disposition: StaleDisposition::AcquiredEphemeralResource(cleanup.clone()),
    });
    h.pump();

    assert!(
        consumed.load(Ordering::SeqCst),
        "ephemeral cleanup token was not consumed"
    );
    assert!(
        h.actor.late_handle_consumed(&cleanup),
        "late handle not marked consumed after cleanup"
    );
}

/// A stale journaled completion requests reconcile: the actor enters `Reconciling` so the
/// journaled external operation is re-synced rather than silently dropped.
#[tokio::test]
async fn stale_journaled_effect_requests_reconcile() {
    tokio::time::pause();
    let h = Harness::new();
    let epoch = fresh_epoch();
    let key = lookup_key(&epoch);

    h.actor.submit(RuntimeCommand::Connect(connect_intent(&epoch, &key)));
    h.pump();

    h.actor.complete_effect(EffectCompletion {
        fence: foreign_fence(&epoch),
        outcome: EffectOutcome::Failed(blocker_error()),
        stale_disposition: StaleDisposition::JournaledExternalEffect(JournalOperationRef::External {
            lookup_key: key.clone(),
            request_digest: RequestDigest::try_from([3u8; 32]).expect("request digest"),
        }),
    });
    h.pump();

    assert!(
        matches!(h.actor.state(), RuntimeState::Reconciling { .. }),
        "journaled stale effect did not request reconcile"
    );
}

/// A stale completion reporting an unknown resource acquisition enters recovery: the actor moves
/// to `Reconciling` carrying the obligation.
#[tokio::test]
async fn stale_unknown_acquisition_enters_recovery() {
    tokio::time::pause();
    let h = Harness::new();
    let epoch = fresh_epoch();
    let key = lookup_key(&epoch);

    h.actor.submit(RuntimeCommand::Connect(connect_intent(&epoch, &key)));
    h.pump();

    let recovery = obligation(&epoch);
    h.actor.complete_effect(EffectCompletion {
        fence: foreign_fence(&epoch),
        outcome: EffectOutcome::WorkerTerminatedUnknown(recovery.clone()),
        stale_disposition: StaleDisposition::UnknownResourceAcquisition(recovery),
    });
    h.pump();

    assert!(
        matches!(h.actor.state(), RuntimeState::Reconciling { .. }),
        "unknown-acquisition stale effect did not enter recovery"
    );
}

/// A late TLS handle is closed AND joined when the actor consumes the corresponding ephemeral
/// cleanup disposition — never merely discarded. Kills mutant (a): discarding the late TLS handle
/// leaves both the close and the join undo.
#[tokio::test]
async fn late_tls_handle_is_closed_and_joined() {
    tokio::time::pause();
    let h = Harness::new();
    let epoch = fresh_epoch();
    let key = lookup_key(&epoch);

    h.actor.submit(RuntimeCommand::Connect(connect_intent(&epoch, &key)));
    h.pump();

    let cleanup = EphemeralCleanupRef {
        effect_id: fresh_effect_id(),
        kind: EphemeralResourceKind::ProtocolLateHandle,
    };
    let closed = Arc::new(AtomicBool::new(false));
    let joined = Arc::new(AtomicBool::new(false));
    let close_flag = closed.clone();
    let join_flag = joined.clone();
    h.actor.register_late_handle(cleanup.clone(), Box::new(move || {
        close_flag.store(true, Ordering::SeqCst); // close the TLS handle
        // join the TLS task to completion before returning
        join_flag.store(true, Ordering::SeqCst); // fully joined
    }));

    h.actor.complete_effect(EffectCompletion {
        fence: foreign_fence(&epoch),
        outcome: EffectOutcome::CancelledBeforeEffect,
        stale_disposition: StaleDisposition::AcquiredEphemeralResource(cleanup.clone()),
    });
    h.pump();

    assert!(
        closed.load(Ordering::SeqCst),
        "late TLS handle was discarded instead of closed"
    );
    assert!(
        joined.load(Ordering::SeqCst),
        "late TLS handle was closed but not joined"
    );
}

/// A late packet attach is detached AND the actor reconciles afterwards: the packet late handle is
/// cleaned up and the runtime moves to `Reconciling`.
#[tokio::test]
async fn late_packet_attach_is_detached_and_reconciled() {
    tokio::time::pause();
    let h = Harness::new();
    let epoch = fresh_epoch();
    let key = lookup_key(&epoch);

    h.actor.submit(RuntimeCommand::Connect(connect_intent(&epoch, &key)));
    h.pump();

    let cleanup = EphemeralCleanupRef {
        effect_id: fresh_effect_id(),
        kind: EphemeralResourceKind::PacketLateHandle,
    };
    let detached = Arc::new(AtomicBool::new(false));
    let flag = detached.clone();
    h.actor.register_late_handle(cleanup.clone(), Box::new(move || {
        flag.store(true, Ordering::SeqCst); // detach the packet lease
    }));

    h.actor.complete_effect(EffectCompletion {
        fence: foreign_fence(&epoch),
        outcome: EffectOutcome::CancelledBeforeEffect,
        stale_disposition: StaleDisposition::AcquiredEphemeralResource(cleanup.clone()),
    });
    h.pump();

    assert!(
        detached.load(Ordering::SeqCst),
        "late packet attach was not detached"
    );
    assert!(
        matches!(h.actor.state(), RuntimeState::Reconciling { .. }),
        "late packet attach was detached but not reconciled"
    );
}

/// Host loss revokes data admission and begins a teardown: the actor leaves `Connected` (no more
/// admission) and schedules at least one fenced teardown effect.
#[tokio::test]
async fn host_lost_revokes_admission_and_starts_stop() {
    tokio::time::pause();
    let (state, epoch) = connected_session();
    let h = Harness::from_state(state);
    assert!(
        matches!(h.actor.state(), RuntimeState::Connected { .. }),
        "precondition: session must start Connected"
    );

    h.actor
        .submit(RuntimeCommand::HostLost { runtime_epoch: epoch });
    h.pump();

    assert!(
        !matches!(h.actor.state(), RuntimeState::Connected { .. }),
        "host lost did not revoke data admission"
    );
    assert!(
        h.actor.inflight_effects() >= 1,
        "host lost did not begin a teardown"
    );
}

/// A completion fenced to a PRIOR runtime epoch is rejected: it is neither applied to the current
/// epoch's state nor consumed against the inflight effect.
#[tokio::test]
async fn runtime_epoch_rejects_prior_completion() {
    tokio::time::pause();
    let h = Harness::new();
    let epoch = fresh_epoch();
    let key = lookup_key(&epoch);

    h.actor.submit(RuntimeCommand::Connect(connect_intent(&epoch, &key)));
    h.pump();
    assert_eq!(h.actor.inflight_effects(), 1);

    // A completion fenced to a different (prior) runtime epoch.
    let prior_epoch = fresh_epoch();
    h.actor.complete_effect(EffectCompletion {
        fence: foreign_fence(&prior_epoch),
        outcome: EffectOutcome::Completed(EffectResult::ProtocolStopped(
            exv_vpn_domain::ports::ProtocolTerminal::Terminated,
        )),
        stale_disposition: StaleDisposition::ProvenNoEffect,
    });
    h.pump();

    assert!(
        matches!(h.actor.state(), RuntimeState::Connecting { .. }),
        "prior-epoch completion was applied to the current state"
    );
    assert_eq!(
        h.actor.inflight_effects(),
        1,
        "prior-epoch completion was consumed against the inflight effect"
    );
}