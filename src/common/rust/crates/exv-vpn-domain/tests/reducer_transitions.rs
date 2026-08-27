// EXV D11-T: reducer transition integration tests for exv-vpn-domain.
//
// These tests drive the pure `Reducer::reduce(state, command, inputs) -> ReducerDecision` and
// assert on the returned decision (next_state, effects, operation_outcomes, events). They
// reference the D11-I construction seams (inherent `pub fn` constructors on the private-field
// model types) and the D10-I value/ref TryFrom seams. They are expected to be RED (compile error)
// until D11-I implements `Reducer::reduce` and those constructors.
//
// The 18 tests are pinned by the D11-T/I plan (§4.5 command-transition table, §6.2 teardown saga,
// H00 D3 bounded multi-effect batch). They must be killable by:
//   - D11-M1  reducer does not clear the queued connect on Stop            -> tests 11, 12
//   - D11-M2  promotion races actor-order / promotes before Stop           -> tests 12, 13
//   - D11-M3  reducer reaches Connected without all five proofs            -> test 7
//
// No assertion depends on the exact EffectId values (those come from `ReducerInputs`).

use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::{
    AttemptId, EffectId, EvidenceDigest, InteractionId, InventoryDigest, OperationId,
    OperationLookupKey, OperationMethod, OwnershipVersion, PrincipalDigest, RecoveryId,
    RequestDigest, ResourceIdentityDigest, RetirementOperationId, RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::model::{
    Attempt, CleanupProofRef, ConnectIntent, ConnectPhase, ConnectedSession, ConnectionProfileRef,
    DataRunningProof, InteractionPrompt, PacketLeaseRef, PlatformOwnershipRef, PlatformReadyProof,
    PromptDeadline, ProtocolSessionRef, RecoveryContext, RecoveryObligation, RuntimeState,
    StopIntent,
};
use exv_vpn_domain::ports::MonotonicTick;
use exv_vpn_domain::reducer::{
    EffectRequest, MAX_EFFECTS_PER_DECISION, OperationDisposition, OperationOutcome, Reducer,
    ReducerDecision, ReducerInputs, RuntimeCommand, RuntimeEvent,
};
use std::time::Duration;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Seam helpers (D10-I value/ref TryFrom + D11-I inherent constructors)
// ---------------------------------------------------------------------------

fn make_key(method: OperationMethod) -> OperationLookupKey {
    OperationLookupKey::try_from((
        PrincipalDigest::try_from([0x11; 32]).unwrap(),
        method,
        RuntimeEpoch::try_from(Uuid::new_v4()).unwrap(),
        OperationId::try_from(Uuid::new_v4()).unwrap(),
    ))
    .unwrap()
}

fn make_digest(byte: u8) -> RequestDigest {
    RequestDigest::try_from([byte; 32]).unwrap()
}

fn make_profile() -> ConnectionProfileRef {
    ConnectionProfileRef::try_from(ResourceIdentityDigest::try_from([0x22; 32]).unwrap()).unwrap()
}

fn make_intent(key: OperationLookupKey, req: RequestDigest) -> ConnectIntent {
    ConnectIntent::new(key, req, make_profile())
}

fn make_stop(key: OperationLookupKey, req: RequestDigest) -> StopIntent {
    StopIntent::new(key, req)
}

fn make_attempt(intent: ConnectIntent) -> Attempt {
    Attempt::new(
        RuntimeEpoch::try_from(Uuid::new_v4()).unwrap(),
        AttemptId::try_from(Uuid::new_v4()).unwrap(),
        intent,
        None, // prior_error
    )
}

fn make_error(code: ErrorCode) -> VpnError {
    VpnError::try_from((
        code,
        ErrorStage::Admission,
        EffectCertainty::NoEffect,
        RetryAdvice::DoNotRetry,
        ErrorSubject::Runtime(RuntimeEpoch::try_from(Uuid::new_v4()).unwrap()),
        None,
        None,
    ))
    .unwrap()
}

fn make_proof() -> CleanupProofRef {
    CleanupProofRef::try_from((
        InventoryDigest::try_from([0x11; 32]).unwrap(),
        EvidenceDigest::try_from([0x22; 32]).unwrap(),
    ))
    .unwrap()
}

fn make_context() -> RecoveryContext {
    RecoveryContext::startup(
        RuntimeEpoch::try_from(Uuid::new_v4()).unwrap(),
        RecoveryId::try_from(Uuid::new_v4()).unwrap(),
    )
}

fn make_obligation(ctx: &RecoveryContext) -> RecoveryObligation {
    RecoveryObligation::new(
        RuntimeEpoch::try_from(Uuid::new_v4()).unwrap(),
        Some(RetirementOperationId::try_from(Uuid::new_v4()).unwrap()),
        make_error(ErrorCode::EffectUnknown),
        None, // platform_ownership
        None, // packet_lease
        InventoryDigest::try_from([0x33; 32]).unwrap(),
    )
}

// A ConnectedSession carries all five proofs: protocol_session, platform_ownership, packet_lease,
// platform_ready, data_running. The D11-I constructor requires all five arguments.
fn connected_session(intent: ConnectIntent) -> ConnectedSession {
    let attempt = make_attempt(intent);
    let protocol_session =
        ProtocolSessionRef::try_from(ResourceIdentityDigest::try_from([0xAA; 32]).unwrap())
            .unwrap();
    let platform_ownership = PlatformOwnershipRef::try_from((
        ResourceIdentityDigest::try_from([0xBB; 32]).unwrap(),
        OwnershipVersion::try_from(1u64).unwrap(),
        TokenDigest::try_from([0xCC; 32]).unwrap(),
    ))
    .unwrap();
    let packet_lease =
        PacketLeaseRef::try_from(ResourceIdentityDigest::try_from([0xDD; 32]).unwrap()).unwrap();
    let platform_ready = PlatformReadyProof::try_from((
        platform_ownership.clone(),
        EvidenceDigest::try_from([0xEE; 32]).unwrap(),
    ))
    .unwrap();
    let data_running = DataRunningProof::try_from((
        protocol_session.clone(),
        platform_ownership.clone(),
        packet_lease.clone(),
        EvidenceDigest::try_from([0xFF; 32]).unwrap(),
    ))
    .unwrap();
    ConnectedSession::new(
        attempt,
        protocol_session,
        platform_ownership,
        packet_lease,
        platform_ready,
        data_running,
    )
}

fn inputs() -> ReducerInputs {
    ReducerInputs {
        next_attempt_id: AttemptId::try_from(Uuid::new_v4()).unwrap(),
        next_effect_ids: [
            EffectId::try_from(Uuid::new_v4()).unwrap(),
            EffectId::try_from(Uuid::new_v4()).unwrap(),
            EffectId::try_from(Uuid::new_v4()).unwrap(),
        ],
        next_interaction_id: InteractionId::try_from(Uuid::new_v4()).unwrap(),
        next_prompt_deadline: PromptDeadline::try_from((
            MonotonicTick::try_from(1_000u64).unwrap(),
            Duration::from_secs(30),
        ))
        .unwrap(),
        outstanding_teardown_effects: Vec::new(),
    }
}

// Locate the disposition recorded for a given operation lookup key.
fn outcome<'a>(
    decision: &'a ReducerDecision,
    key: &OperationLookupKey,
) -> &'a OperationDisposition {
    decision
        .operation_outcomes
        .iter()
        .find(|o| &o.lookup_key == key)
        .map(|o: &OperationOutcome| &o.disposition)
        .expect("no operation outcome for lookup key")
}

fn assert_equals(
    decision: &ReducerDecision,
    key: &OperationLookupKey,
    expected: OperationDisposition,
) {
    // OperationDisposition does not derive Debug, so compare by value rather than assert_eq!.
    assert!(
        outcome(decision, key) == &expected,
        "unexpected operation disposition for lookup key"
    );
}

fn assert_failed_code(decision: &ReducerDecision, key: &OperationLookupKey, code: ErrorCode) {
    match outcome(decision, key) {
        OperationDisposition::Failed(err) => {
            let rendered = format!("{err:?}");
            let want = format!("{code:?}");
            assert!(
                rendered.contains(&want),
                "expected {want} in rendered error {rendered}"
            );
        }
        other => panic!("expected Failed({code:?})"),
    }
}

fn has_effect(decision: &ReducerDecision, want: &EffectRequest) -> bool {
    decision.effects.iter().any(|e| &e.request == want)
}

// ---------------------------------------------------------------------------
// 1. idle_connect_creates_one_attempt
// ---------------------------------------------------------------------------
#[test]
fn idle_connect_creates_one_attempt() {
    let key = make_key(OperationMethod::Connect);
    let req = make_digest(0x11);
    let intent = make_intent(key.clone(), req.clone());

    let decision = Reducer::reduce(
        RuntimeState::idle(),
        RuntimeCommand::Connect(intent),
        inputs(),
    );

    // Exactly one new attempt is created: a single Accepted operation outcome and the reducer
    // enters Connecting carrying that new attempt.
    assert_equals(&decision, &key, OperationDisposition::Accepted);
    assert!(matches!(
        decision.next_state,
        RuntimeState::Connecting { .. }
    ));
    assert_eq!(decision.operation_outcomes.len(), 1);
}

// ---------------------------------------------------------------------------
// 2. idle_stop_is_already_stopped
// ---------------------------------------------------------------------------
#[test]
fn idle_stop_is_already_stopped() {
    let key = make_key(OperationMethod::Stop);
    let req = make_digest(0x11);
    let stop = make_stop(key.clone(), req.clone());

    let decision = Reducer::reduce(RuntimeState::idle(), RuntimeCommand::Stop(stop), inputs());

    // Idle has no cleanup proof, so Stop is AlreadyStopped with no proof.
    assert_equals(
        &decision,
        &key,
        OperationDisposition::AlreadyStopped { proof: None },
    );
    assert!(matches!(decision.next_state, RuntimeState::Idle { .. }));
}

// ---------------------------------------------------------------------------
// 3. failed_clean_connect_preserves_last_error_observation
// ---------------------------------------------------------------------------
#[test]
fn failed_clean_connect_preserves_last_error_observation() {
    let last_error = make_error(ErrorCode::ConnectInProgress);
    let proof = make_proof();
    let key = make_key(OperationMethod::Connect);
    let req = make_digest(0x11);
    let intent = make_intent(key.clone(), req.clone());

    let decision = Reducer::reduce(
        RuntimeState::failed_clean(last_error.clone(), proof),
        RuntimeCommand::Connect(intent),
        inputs(),
    );

    // FailedClean accepts a new Connect (new attempt) while preserving the last error as an
    // observation emitted to callers.
    assert_equals(&decision, &key, OperationDisposition::Accepted);
    assert!(matches!(
        decision.next_state,
        RuntimeState::Connecting { .. }
    ));
    assert!(
        decision
            .events
            .iter()
            .any(|e| matches!(e, RuntimeEvent::ErrorObserved(er) if er == &last_error)),
        "expected the last error to be preserved as an ErrorObserved observation"
    );
}

// ---------------------------------------------------------------------------
// 4. connecting_same_intent_is_idempotent
// ---------------------------------------------------------------------------
#[test]
fn connecting_same_intent_is_idempotent() {
    let key = make_key(OperationMethod::Connect);
    let req = make_digest(0x11);
    let intent = make_intent(key.clone(), req.clone());
    let attempt = make_attempt(intent.clone());
    let state = RuntimeState::connecting(attempt, ConnectPhase::ConnectingControl);

    let decision = Reducer::reduce(state, RuntimeCommand::Connect(intent), inputs());

    // The same intent over the same operation key is the current in-flight fact: AlreadyCurrent,
    // no new attempt.
    assert_equals(&decision, &key, OperationDisposition::AlreadyCurrent);
    assert!(matches!(
        decision.next_state,
        RuntimeState::Connecting { .. }
    ));
}

// ---------------------------------------------------------------------------
// 5. connecting_different_intent_is_busy
// ---------------------------------------------------------------------------
#[test]
fn connecting_different_intent_is_busy() {
    let key_a = make_key(OperationMethod::Connect);
    let req_a = make_digest(0x11);
    let attempt = make_attempt(make_intent(key_a.clone(), req_a.clone()));
    let state = RuntimeState::connecting(attempt, ConnectPhase::AcquiringPlatformLease);

    let key_b = make_key(OperationMethod::Connect);
    let req_b = make_digest(0x22);
    let other = make_intent(key_b.clone(), req_b.clone());

    let decision = Reducer::reduce(state, RuntimeCommand::Connect(other), inputs());

    // A different intent while Connecting is busy: ConnectInProgress, no new attempt.
    assert_failed_code(&decision, &key_b, ErrorCode::ConnectInProgress);
    assert!(matches!(
        decision.next_state,
        RuntimeState::Connecting { .. }
    ));
}

// ---------------------------------------------------------------------------
// 6. awaiting_interaction_stop_revokes_prompt
// ---------------------------------------------------------------------------
#[test]
fn awaiting_interaction_stop_revokes_prompt() {
    let epoch = RuntimeEpoch::try_from(Uuid::new_v4()).unwrap();
    let attempt_id = AttemptId::try_from(Uuid::new_v4()).unwrap();
    let intent = make_intent(make_key(OperationMethod::Connect), make_digest(0x11));
    let attempt = Attempt::new(epoch.clone(), attempt_id.clone(), intent, None);
    let interaction_id = InteractionId::try_from(Uuid::new_v4()).unwrap();
    let deadline = PromptDeadline::try_from((
        MonotonicTick::try_from(500u64).unwrap(),
        Duration::from_secs(30),
    ))
    .unwrap();
    let prompt = InteractionPrompt::new(interaction_id.clone(), epoch, attempt_id, deadline);
    let state = RuntimeState::awaiting_interaction(attempt, prompt);

    let stop = make_stop(make_key(OperationMethod::Stop), make_digest(0x22));
    let decision = Reducer::reduce(state, RuntimeCommand::Stop(stop), inputs());

    // Stop enters Stopping and revokes the outstanding interaction prompt.
    assert!(matches!(decision.next_state, RuntimeState::Stopping { .. }));
    assert!(
        has_effect(&decision, &EffectRequest::RevokeInteraction),
        "expected a RevokeInteraction effect on Stop while awaiting interaction"
    );
    assert!(
        decision.events.iter().any(
            |e| matches!(e, RuntimeEvent::InteractionRevoked { interaction_id: id, subject: _ } if id == &interaction_id)
        ),
        "expected InteractionRevoked event for the revoked prompt"
    );
}

// ---------------------------------------------------------------------------
// 7. connected_requires_all_five_proofs
// ---------------------------------------------------------------------------
#[test]
fn connected_requires_all_five_proofs() {
    // A ConnectedSession is only constructible with all five proofs (protocol_session,
    // platform_ownership, packet_lease, platform_ready, data_running); the D11-I constructor
    // requires all five arguments. The reducer must treat a Connected state as carrying that
    // complete proof set and preserve it exactly across an idempotent Connect. This kills
    // D11-M3: a reducer that reached Connected without all five proofs would not hold the
    // canonical full session.
    let key = make_key(OperationMethod::Connect);
    let req = make_digest(0x11);
    let intent = make_intent(key.clone(), req.clone());
    let session = connected_session(intent.clone());
    let state = RuntimeState::connected(session.clone());

    let decision = Reducer::reduce(state, RuntimeCommand::Connect(intent), inputs());

    assert_equals(&decision, &key, OperationDisposition::AlreadyCurrent);
    match &decision.next_state {
        RuntimeState::Connected { session: s } => {
            // ConnectedSession does not derive Debug; compare by value.
            assert!(
                s == &session,
                "Connected must preserve the full five-proof session"
            );
        }
        other => panic!("expected Connected state"),
    }
}

// ---------------------------------------------------------------------------
// 8. connected_different_connect_is_session_busy
// ---------------------------------------------------------------------------
#[test]
fn connected_different_connect_is_session_busy() {
    let key_a = make_key(OperationMethod::Connect);
    let req_a = make_digest(0x11);
    let session = connected_session(make_intent(key_a.clone(), req_a.clone()));
    let state = RuntimeState::connected(session);

    let key_b = make_key(OperationMethod::Connect);
    let req_b = make_digest(0x22);
    let other = make_intent(key_b.clone(), req_b.clone());

    let decision = Reducer::reduce(state, RuntimeCommand::Connect(other), inputs());

    // A different connect while a session is live is SessionBusy; the live session is untouched.
    assert_failed_code(&decision, &key_b, ErrorCode::SessionBusy);
    assert!(matches!(
        decision.next_state,
        RuntimeState::Connected { .. }
    ));
}

// ---------------------------------------------------------------------------
// 9. stopping_accepts_one_queued_connect_without_resources
// ---------------------------------------------------------------------------
#[test]
fn stopping_accepts_one_queued_connect_without_resources() {
    let attempt = make_attempt(make_intent(
        make_key(OperationMethod::Connect),
        make_digest(0x11),
    ));
    let stop = make_stop(make_key(OperationMethod::Stop), make_digest(0x22));
    let state = RuntimeState::stopping(attempt, stop, None);

    let queued_key = make_key(OperationMethod::Connect);
    let queued_req = make_digest(0x33);
    let queued = make_intent(queued_key.clone(), queued_req.clone());

    let decision = Reducer::reduce(state, RuntimeCommand::Connect(queued.clone()), inputs());

    // The single queue slot accepts the connect as queued, stored without acquiring resources.
    assert_equals(&decision, &queued_key, OperationDisposition::AcceptedQueued);
    match &decision.next_state {
        RuntimeState::Stopping { queued_connect, .. } => {
            // ConnectIntent does not derive Debug; compare by value.
            assert!(queued_connect == &Some(queued));
        }
        other => panic!("expected Stopping state"),
    }
    // A queued connect must not acquire any platform resource or start any protocol lane.
    assert!(
        decision.effects.iter().all(|e| !matches!(
            e.request,
            EffectRequest::AcquireOwnership(_)
                | EffectRequest::ConnectProtocol(_)
                | EffectRequest::ApplyTunnel(_)
                | EffectRequest::AttachPacket { .. }
                | EffectRequest::StartDataPlane { .. }
        )),
        "a queued connect must not acquire platform resources"
    );
}

// ---------------------------------------------------------------------------
// 10. stopping_rejects_second_different_queue
// ---------------------------------------------------------------------------
#[test]
fn stopping_rejects_second_different_queue() {
    let attempt = make_attempt(make_intent(
        make_key(OperationMethod::Connect),
        make_digest(0x11),
    ));
    let stop = make_stop(make_key(OperationMethod::Stop), make_digest(0x22));
    let queued_key = make_key(OperationMethod::Connect);
    let queued_req = make_digest(0x33);
    let queued = make_intent(queued_key.clone(), queued_req.clone());
    let state = RuntimeState::stopping(attempt, stop, Some(queued.clone()));

    let second_key = make_key(OperationMethod::Connect);
    let second_req = make_digest(0x44);
    let second = make_intent(second_key.clone(), second_req.clone());

    let decision = Reducer::reduce(state, RuntimeCommand::Connect(second), inputs());

    // The single queue slot already holds a different intent: ReconnectAlreadyQueued.
    assert_failed_code(&decision, &second_key, ErrorCode::ReconnectAlreadyQueued);
    match &decision.next_state {
        RuntimeState::Stopping { queued_connect, .. } => {
            // ConnectIntent does not derive Debug; compare by value.
            assert!(
                queued_connect == &Some(queued),
                "original queued connect must be preserved"
            );
        }
        other => panic!("expected Stopping state"),
    }
}

// ---------------------------------------------------------------------------
// 11. explicit_stop_cancels_queued_connect
// ---------------------------------------------------------------------------
#[test]
fn explicit_stop_cancels_queued_connect() {
    let attempt = make_attempt(make_intent(
        make_key(OperationMethod::Connect),
        make_digest(0x11),
    ));
    let stop = make_stop(make_key(OperationMethod::Stop), make_digest(0x22));
    let queued_key = make_key(OperationMethod::Connect);
    let queued_req = make_digest(0x33);
    let queued = make_intent(queued_key.clone(), queued_req.clone());
    let state = RuntimeState::stopping(attempt, stop.clone(), Some(queued));

    let decision = Reducer::reduce(state, RuntimeCommand::Stop(stop), inputs());

    // Any explicit Stop while Stopping atomically clears the queued connect (kills D11-M1).
    match &decision.next_state {
        RuntimeState::Stopping { queued_connect, .. } => {
            assert!(
                queued_connect.is_none(),
                "Stop must clear the queued connect"
            );
        }
        other => panic!("expected Stopping state"),
    }
    assert!(
        has_effect(
            &decision,
            &EffectRequest::RevokeQueuedConnect(make_intent(
                queued_key.clone(),
                queued_req.clone()
            ))
        ),
        "expected a RevokeQueuedConnect effect for the cancelled queued connect"
    );
}

// ---------------------------------------------------------------------------
// 12. stop_before_promotion_cancels_queue
// ---------------------------------------------------------------------------
#[test]
fn stop_before_promotion_cancels_queue() {
    // Stop arrives before any promotion of the queued connect: the queue is cancelled rather than
    // promoted (kills D11-M2 if the reducer promotes ahead of the actor's receive order).
    let attempt = make_attempt(make_intent(
        make_key(OperationMethod::Connect),
        make_digest(0x11),
    ));
    let stop = make_stop(make_key(OperationMethod::Stop), make_digest(0x22));
    let queued_key = make_key(OperationMethod::Connect);
    let queued_req = make_digest(0x33);
    let queued = make_intent(queued_key.clone(), queued_req.clone());
    let state = RuntimeState::stopping(attempt, stop.clone(), Some(queued));

    let decision = Reducer::reduce(state, RuntimeCommand::Stop(stop), inputs());

    // The queued operation is cancelled before start, not promoted.
    assert!(
        decision
            .operation_outcomes
            .iter()
            .any(|o| o.lookup_key == queued_key
                && matches!(o.disposition, OperationDisposition::CancelledBeforeStart)),
        "Stop before promotion must end the queued connect in CancelledBeforeStart"
    );
    match &decision.next_state {
        RuntimeState::Stopping { queued_connect, .. } => {
            assert!(
                queued_connect.is_none(),
                "queue must be cancelled before promotion"
            );
        }
        other => panic!("expected Stopping state"),
    }
}

// ---------------------------------------------------------------------------
// 13. promotion_before_stop_stops_new_attempt
// ---------------------------------------------------------------------------
#[test]
fn promotion_before_stop_stops_new_attempt() {
    // Promotion has already happened: the queued connect became a live Connecting attempt. A Stop
    // that arrives after promotion must target that new attempt, not a stale queue (kills D11-M2
    // if the reducer cancels a queue that no longer holds the promoted attempt).
    let key = make_key(OperationMethod::Connect);
    let req = make_digest(0x11);
    let intent = make_intent(key.clone(), req.clone());
    let attempt = make_attempt(intent);
    let state = RuntimeState::connecting(attempt.clone(), ConnectPhase::StartingDataPlane);

    let stop = make_stop(make_key(OperationMethod::Stop), make_digest(0x22));
    let decision = Reducer::reduce(state, RuntimeCommand::Stop(stop), inputs());

    // Match by value so the bindings are unambiguous regardless of match ergonomics.
    match decision.next_state {
        RuntimeState::Stopping {
            attempt: stopped_attempt,
            queued_connect,
            ..
        } => {
            // Attempt does not derive Debug; compare by value.
            assert!(
                stopped_attempt == attempt,
                "Stop must apply to the promoted attempt"
            );
            assert!(
                queued_connect.is_none(),
                "nothing is queued after promotion"
            );
        }
        other => panic!("expected Stopping state"),
    }
    assert!(
        !decision
            .effects
            .iter()
            .any(|e| matches!(e.request, EffectRequest::RevokeQueuedConnect(_))),
        "no queued connect should be revoked now that promotion has already occurred"
    );
}

// ---------------------------------------------------------------------------
// 14. failed_dirty_connect_requires_reconcile
// ---------------------------------------------------------------------------
#[test]
fn failed_dirty_connect_requires_reconcile() {
    let last_error = make_error(ErrorCode::EffectUnknown);
    let ctx = make_context();
    let obligation = make_obligation(&ctx);
    let state = RuntimeState::failed_dirty(last_error, ctx, obligation);

    let key = make_key(OperationMethod::Connect);
    let req = make_digest(0x11);
    let intent = make_intent(key.clone(), req.clone());

    let decision = Reducer::reduce(state, RuntimeCommand::Connect(intent), inputs());

    // FailedDirty does not accept a new connect; it returns the current typed obligation and
    // requires reconcile, leaving the state untouched.
    assert!(
        matches!(
            outcome(&decision, &key),
            OperationDisposition::RequiresReconcile(_)
        ),
        "expected RequiresReconcile for a Connect while FailedDirty"
    );
    assert!(matches!(
        decision.next_state,
        RuntimeState::FailedDirty { .. }
    ));
}

// ---------------------------------------------------------------------------
// 15. reconciling_stop_subscribes_same_saga
// ---------------------------------------------------------------------------
#[test]
fn reconciling_stop_subscribes_same_saga() {
    let ctx = make_context();
    let obligation = make_obligation(&ctx);
    let state = RuntimeState::reconciling(ctx.clone(), obligation.clone());

    let stop = make_stop(make_key(OperationMethod::Stop), make_digest(0x11));
    let decision = Reducer::reduce(state, RuntimeCommand::Stop(stop), inputs());

    // Stop while Reconciling is an idempotent subscribe to the same recovery/teardown saga: the
    // state is unchanged and no new recovery saga is started.
    // RuntimeState does not derive Debug; compare by value.
    assert!(
        decision.next_state == RuntimeState::reconciling(ctx, obligation),
        "Stop must subscribe to the existing reconcile, not fork a new saga"
    );
    assert!(
        !decision
            .effects
            .iter()
            .any(|e| matches!(e.request, EffectRequest::BeginRecoveryStop(_))),
        "no new recovery saga should be started by a Stop while already Reconciling"
    );
}

// ---------------------------------------------------------------------------
// 16. same_operation_key_different_digest_conflicts
// ---------------------------------------------------------------------------
#[test]
fn same_operation_key_different_digest_conflicts() {
    let key = make_key(OperationMethod::Connect);
    let req_a = make_digest(0x11);
    let attempt = make_attempt(make_intent(key.clone(), req_a.clone()));
    let state = RuntimeState::connecting(attempt, ConnectPhase::NegotiatingTunnel);

    // Same operation key, different request digest: an idempotency conflict, not a duplicate
    // success and not a busy signal.
    let req_b = make_digest(0x22);
    let replay = make_intent(key.clone(), req_b.clone());

    let decision = Reducer::reduce(state, RuntimeCommand::Connect(replay), inputs());

    assert_failed_code(&decision, &key, ErrorCode::IdempotencyConflict);
}

// ---------------------------------------------------------------------------
// 17. decision_emits_at_most_bounded_effects  (H00 D3)
// ---------------------------------------------------------------------------
#[test]
fn decision_emits_at_most_bounded_effects() {
    let cap = MAX_EFFECTS_PER_DECISION;
    let inp = || inputs();

    // Idle -> Connect (start a new attempt).
    let d = Reducer::reduce(
        RuntimeState::idle(),
        RuntimeCommand::Connect(make_intent(
            make_key(OperationMethod::Connect),
            make_digest(0x01),
        )),
        inp(),
    );
    assert!(
        d.effects.len() <= cap,
        "Idle+Connect emitted {} effects",
        d.effects.len()
    );

    // Connecting -> Stop (enter teardown).
    let d = Reducer::reduce(
        RuntimeState::connecting(
            make_attempt(make_intent(
                make_key(OperationMethod::Connect),
                make_digest(0x02),
            )),
            ConnectPhase::ConnectingControl,
        ),
        RuntimeCommand::Stop(make_stop(
            make_key(OperationMethod::Stop),
            make_digest(0x03),
        )),
        inp(),
    );
    assert!(
        d.effects.len() <= cap,
        "Connecting+Stop emitted {} effects",
        d.effects.len()
    );

    // Connected -> Stop (teardown of a live session).
    let d = Reducer::reduce(
        RuntimeState::connected(connected_session(make_intent(
            make_key(OperationMethod::Connect),
            make_digest(0x04),
        ))),
        RuntimeCommand::Stop(make_stop(
            make_key(OperationMethod::Stop),
            make_digest(0x05),
        )),
        inp(),
    );
    assert!(
        d.effects.len() <= cap,
        "Connected+Stop emitted {} effects",
        d.effects.len()
    );

    // Stopping -> Connect (single-slot queue).
    let d = Reducer::reduce(
        RuntimeState::stopping(
            make_attempt(make_intent(
                make_key(OperationMethod::Connect),
                make_digest(0x06),
            )),
            make_stop(make_key(OperationMethod::Stop), make_digest(0x07)),
            None,
        ),
        RuntimeCommand::Connect(make_intent(
            make_key(OperationMethod::Connect),
            make_digest(0x08),
        )),
        inp(),
    );
    assert!(
        d.effects.len() <= cap,
        "Stopping+Connect emitted {} effects",
        d.effects.len()
    );
}

// ---------------------------------------------------------------------------
// 18. teardown_issues_beginstop_and_protocol_close  (H00 D3 / §6.2 step 1)
// ---------------------------------------------------------------------------
#[test]
fn teardown_issues_beginstop_and_protocol_close() {
    let session = connected_session(make_intent(
        make_key(OperationMethod::Connect),
        make_digest(0x11),
    ));
    let state = RuntimeState::connected(session);

    let stop = make_stop(make_key(OperationMethod::Stop), make_digest(0x22));
    let decision = Reducer::reduce(state, RuntimeCommand::Stop(stop), inputs());

    // A Connected teardown decision may emit StopProtocol + BeginPlatformStop together in the
    // same transition (bounded multi-effect batch, §6.2 step 1).
    assert!(matches!(decision.next_state, RuntimeState::Stopping { .. }));
    assert!(
        decision
            .effects
            .iter()
            .any(|e| matches!(e.request, EffectRequest::StopProtocol { .. })),
        "teardown must issue StopProtocol (best-effort CSTP close)"
    );
    assert!(
        decision
            .effects
            .iter()
            .any(|e| matches!(e.request, EffectRequest::BeginPlatformStop(_))),
        "teardown must issue BeginPlatformStop to the platform resource owner"
    );
    assert!(
        decision.effects.len() <= MAX_EFFECTS_PER_DECISION,
        "teardown exceeded the bounded effect batch"
    );
}
