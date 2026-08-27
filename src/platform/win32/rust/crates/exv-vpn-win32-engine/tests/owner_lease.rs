// RED tests for W15-T/I: the Win32 per-connection ownership lease + sync-before-reply ingress
// (vpn-rust-native-runtime-mvp win32 phase, helper crate `exv-engine`).
// PURE, deterministic: no I/O, no filesystem, no sleep, no randomness — identifiers come only from
// fixed byte arrays and Uuid::from_u128 literals.
//
// The production seams `exv_engine::owner_lease`, `exv_engine::token_slot` and
// `exv_engine::mutation_ingress` do not exist yet; W15-I implements them. Until then this
// file FAILS TO COMPILE (unresolved imports of OwnerLease, OwnerLeaseManager, LeaseIssue,
// MutationIngress) — that is the intended RED.
//
// The owner lease wires the J52 per-connection single-unacknowledged ownership-token delivery slot
// (`exv_vpn_resource::delivery`) and the J51 durable admission sequencer
// (`exv_vpn_resource::operation`/`admission`) to the Windows owner lease/token slot.
//
// NOTE: TokenDigest and OperationLookupKey have NO Debug, so outcomes are asserted with `matches!`
// (with token binding) and equality via PartialEq (==/!=) — never assert_eq!.

use exv_vpn_domain::identity::{
    ConnectionBindingDigest, EffectId, OperationId, OperationLookupKey, OperationMethod,
    OwnershipVersion, PrincipalDigest, RequestDigest, ResourceIdentityDigest, RuntimeEpoch,
    TokenDigest,
};
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CanonicalInputDigest, JournalRevision,
    MonotonicTick, PlatformAuthorityInstanceId,
};
use exv_vpn_resource::admission::{
    AdmissionRecord, AppliedFingerprint, AuthorizationSubject, MutationKind, ObligationSeed,
    decode_record, encode_record,
};
use exv_vpn_resource::authority::ConnectionBinding;
use exv_vpn_resource::delivery::{AckOutcome, TerminateOutcome};
use exv_vpn_resource::operation::{AdmissionIndex, AdmissionOutcome, MutationAdmissionInput};
use exv_engine::mutation_ingress::MutationIngress;
use exv_engine::owner_lease::{LeaseIssue, OwnerLease, OwnerLeaseManager};
use uuid::Uuid;

/// Deterministic 32-byte identity digest that differs across `n`.
fn digest(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = n;
    b
}

/// Deterministic principal digest that differs across `n`.
fn principal(n: u8) -> PrincipalDigest {
    PrincipalDigest::try_from(digest(n)).expect("digest")
}

/// Deterministic request digest that differs across `n`.
fn request_digest(n: u8) -> RequestDigest {
    RequestDigest::try_from(digest(n)).expect("digest")
}

/// Deterministic candidate/held token digest that differs across `n`.
fn token(n: u8) -> TokenDigest {
    TokenDigest::try_from(digest(n)).expect("digest")
}

/// Deterministic connection binding that differs across `n`.
fn binding(n: u8) -> ConnectionBinding {
    let connection_digest = ConnectionBindingDigest::try_from(digest(n)).expect("digest");
    ConnectionBinding::try_from(connection_digest).expect("binding")
}

/// Deterministic non-zero ownership version for the given `n`.
fn version(n: u64) -> OwnershipVersion {
    OwnershipVersion::try_from(n).expect("version")
}

/// Deterministic non-nil runtime epoch for the given `n`.
fn epoch(n: u128) -> RuntimeEpoch {
    RuntimeEpoch::try_from(Uuid::from_u128(n)).expect("epoch")
}

/// Deterministic non-nil operation id for the given `n`.
fn operation(n: u128) -> OperationId {
    OperationId::try_from(Uuid::from_u128(n)).expect("operation")
}

/// Deterministic lookup key anchored to the given principal and method (fixed epoch/op).
fn lookup_key(principal_n: u8, method: OperationMethod) -> OperationLookupKey {
    OperationLookupKey::try_from((principal(principal_n), method, epoch(1), operation(1)))
        .expect("lookup key")
}

/// Deterministic authority fence minted at epoch 1, instance 1, watermark 0, revision 0.
fn fence() -> AuthorityFence {
    AuthorityFence {
        authority_epoch: AuthorityEpoch::try_from(1).expect("epoch 1"),
        platform_authority_instance_id: PlatformAuthorityInstanceId::try_from(Uuid::from_u128(1))
            .expect("non-nil instance"),
        admission_watermark: AdmissionWatermark::try_from(0).expect("watermark 0"),
        journal_revision: JournalRevision::try_from(0).expect("revision 0"),
    }
}

/// A canonical J51 mutation admission input for the given key/digest/ownership version.
fn admission_input(
    key: &OperationLookupKey,
    request_digest: &RequestDigest,
    ownership_version: OwnershipVersion,
) -> MutationAdmissionInput {
    MutationAdmissionInput {
        key: key.clone(),
        request_digest: request_digest.clone(),
        effect_id: EffectId::try_from(Uuid::from_u128(1000)).expect("non-nil effect"),
        initiator_identity_digest: principal(9),
        canonical_input_digest: CanonicalInputDigest::try_from([0x11; 32]).expect("digest"),
        mutation_kind: MutationKind::External(OperationMethod::Connect),
        ownership_version,
        authorization_subject: AuthorizationSubject::LiveOwnershipTokenDigest(token(7)),
        resource_identity: ResourceIdentityDigest::try_from([0x33; 32]).expect("digest"),
        precondition_fingerprint: AppliedFingerprint::try_from([0x44; 32]).expect("digest"),
        desired_applied_fingerprint: AppliedFingerprint::try_from([0x55; 32]).expect("digest"),
        canonical_obligation_seed: ObligationSeed::try_from([0x66; 32]).expect("digest"),
    }
}

/// A lost unary reply retried on the same key+digest+version must replay the SAME held token,
/// never a fresh candidate. Kills: 'lost unary reply reissues a NEW token'.
#[test]
fn same_key_digest_retry_returns_same_token() {
    let mut manager = OwnerLeaseManager::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);
    let cand_b = token(21);

    let issued = manager.issue(&conn, key.clone(), d1.clone(), v1, cand_a.clone());
    assert!(
        matches!(issued, LeaseIssue::Issued { ref token_digest } if *token_digest == cand_a),
        "the first issue must mint the candidate token"
    );

    let replayed = manager.issue(&conn, key.clone(), d1.clone(), v1, cand_b.clone());
    assert!(
        matches!(replayed, LeaseIssue::SameTokenReplayed { ref token_digest } if *token_digest == cand_a && *token_digest != cand_b),
        "a same-key/digest/version retry must replay the SAME held token, never a new one"
    );
}

/// A different acquire key must NOT get a token while the slot is held.
/// Kills: 'other acquire key gets a token while a slot is held'.
#[test]
fn different_key_rejected_while_slot_held() {
    let mut manager = OwnerLeaseManager::new();
    let conn = binding(3);
    let k1 = lookup_key(1, OperationMethod::Connect);
    let k2 = lookup_key(2, OperationMethod::Connect);
    let d1 = request_digest(10);
    let d2 = request_digest(11);
    let v1 = version(1);
    let cand_a = token(20);
    let cand_b = token(21);

    assert!(matches!(
        manager.issue(&conn, k1.clone(), d1.clone(), v1, cand_a.clone()),
        LeaseIssue::Issued { .. }
    ));

    assert!(
        matches!(
            manager.issue(&conn, k2.clone(), d2.clone(), v1, cand_b.clone()),
            LeaseIssue::Refused
        ),
        "a different acquire key must be refused while the slot is held"
    );
}

/// An ACK verifies connection/version/digest/token before clearing: every mismatched ACK is
/// `Mismatch` and leaves the slot held; only the fully matching ACK clears it.
/// Kills: 'ACK does not verify connection/version/digest/token'.
#[test]
fn ack_verifies_then_clears_slot() {
    let mut manager = OwnerLeaseManager::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let d2 = request_digest(11);
    let v1 = version(1);
    let v2 = version(2);
    let cand_a = token(20);

    assert!(matches!(
        manager.issue(&conn, key.clone(), d1.clone(), v1, cand_a.clone()),
        LeaseIssue::Issued { .. }
    ));

    // Wrong ownership version: mismatch, slot retained.
    assert!(matches!(
        manager.ack(&conn, key.clone(), d1.clone(), v2, cand_a.clone()),
        AckOutcome::Mismatch
    ));
    assert!(matches!(
        manager.issue(&conn, key.clone(), d1.clone(), v1, token(21)),
        LeaseIssue::SameTokenReplayed { ref token_digest } if *token_digest == cand_a
    ));

    // Wrong request digest: mismatch, slot retained.
    assert!(matches!(
        manager.ack(&conn, key.clone(), d2.clone(), v1, cand_a.clone()),
        AckOutcome::Mismatch
    ));
    assert!(matches!(
        manager.issue(&conn, key.clone(), d1.clone(), v1, token(22)),
        LeaseIssue::SameTokenReplayed { ref token_digest } if *token_digest == cand_a
    ));

    // Wrong token: mismatch, slot retained.
    assert!(matches!(
        manager.ack(&conn, key.clone(), d1.clone(), v1, token(30)),
        AckOutcome::Mismatch
    ));
    assert!(matches!(
        manager.issue(&conn, key.clone(), d1.clone(), v1, token(23)),
        LeaseIssue::SameTokenReplayed { ref token_digest } if *token_digest == cand_a
    ));

    // Only the fully matching ACK clears the slot.
    assert!(matches!(
        manager.ack(&conn, key.clone(), d1.clone(), v1, cand_a.clone()),
        AckOutcome::Cleared
    ));
}

/// After a matching ACK the slot is resolved and the token is never re-sent.
/// Kills: 'token re-sent after ACK'.
#[test]
fn no_token_resent_after_ack() {
    let mut manager = OwnerLeaseManager::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);

    assert!(matches!(
        manager.issue(&conn, key.clone(), d1.clone(), v1, cand_a.clone()),
        LeaseIssue::Issued { .. }
    ));
    assert!(matches!(
        manager.ack(&conn, key.clone(), d1.clone(), v1, cand_a.clone()),
        AckOutcome::Cleared
    ));

    assert!(
        matches!(
            manager.issue(&conn, key.clone(), d1.clone(), v1, token(21)),
            LeaseIssue::Refused
        ),
        "the token must never be re-sent after a matching ACK"
    );
}

/// Connection termination immediately invalidates the held token; it is never re-issued.
/// Kills: 'connection termination does not invalidate the token'.
#[test]
fn terminate_invalidates_token_immediately() {
    let mut manager = OwnerLeaseManager::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);

    assert!(matches!(
        manager.issue(&conn, key.clone(), d1.clone(), v1, cand_a.clone()),
        LeaseIssue::Issued { .. }
    ));

    let terminated = manager.terminate_connection(&conn);
    assert!(
        matches!(
            terminated,
            TerminateOutcome::Invalidated { ref token, ref ownership_version }
                if *token == cand_a && *ownership_version == v1
        ),
        "termination must immediately invalidate the held token and its ownership version"
    );

    assert!(
        matches!(
            manager.issue(&conn, key.clone(), d1.clone(), v1, token(21)),
            LeaseIssue::Refused
        ),
        "the token must never be re-issued after the connection is terminated"
    );
}

/// The ingress RPC is only accepted once the J51 admission is durable: `admit` refuses before any
/// durable `MutationAdmitted` exists, and the durability gate is the codec round-trip of the
/// admission record. Kills: 'RPC accepted before a durable MutationAdmitted'.
#[test]
fn ingress_sync_before_reply() {
    // A lease is live, but no J51 admission has been made durable yet.
    let mut manager = OwnerLeaseManager::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    assert!(matches!(
        manager.issue(&conn, key.clone(), d1.clone(), v1, token(20)),
        LeaseIssue::Issued { .. }
    ));
    // The manager exposes the per-connection lease handle it holds (W15-I contract).
    let lease: &OwnerLease = manager.lease(&conn).expect("a live lease for the connection");

    let mut ingress = MutationIngress::new();
    // Before the J51 admission is durable, the ingress refuses the RPC.
    assert!(
        ingress.admit(lease, key.clone(), d1.clone()).is_err(),
        "the RPC must not be accepted before a durable MutationAdmitted exists"
    );

    // A J51 admission becomes durable when its MutationAdmitted round-trips the codec.
    let mut index = AdmissionIndex::new(fence());
    let admitted = match index.admit(admission_input(&key, &d1, v1)) {
        AdmissionOutcome::Admitted { record } => record,
        _ => panic!("expected a durable admission"),
    };
    let payload = encode_record(&AdmissionRecord::Admitted(admitted.clone()));
    assert!(
        matches!(
            decode_record(&payload).expect("durable admission decodes"),
            AdmissionRecord::Admitted(_)
        ),
        "a durable MutationAdmitted must round-trip encode_record/decode_record"
    );

    // The ingress acknowledges the reply only once the admission is durable.
    assert!(
        ingress.durable_before_reply(&admitted),
        "the ingress must sync the reply on the durable MutationAdmitted"
    );
}

/// The lease expiry is a monotonic tick (not a wall clock), comparable via `exceeded_by`, and only
/// exists for a held lease. Kills: 'lease expiry is a wall clock / no deadline'.
#[test]
fn expiry_is_a_monotonic_deadline() {
    let mut manager = OwnerLeaseManager::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);

    assert!(matches!(
        manager.issue(&conn, key.clone(), d1.clone(), v1, token(20)),
        LeaseIssue::Issued { .. }
    ));

    // A held lease exposes a monotonic expiry deadline: a tick, not a wall clock.
    let deadline = manager
        .expiry_deadline(&conn)
        .expect("a held lease has an expiry deadline");
    let tick_0 = MonotonicTick::try_from(0).expect("tick 0");
    let later = MonotonicTick::try_from(2u64.pow(60)).expect("later tick");
    assert!(
        deadline.exceeded_by(later),
        "the expiry deadline is a monotonic tick: a later tick exceeds it"
    );
    assert!(
        !deadline.exceeded_by(tick_0),
        "an earlier tick does not exceed the expiry deadline (same clock domain)"
    );

    // A connection with no lease exposes no deadline.
    assert!(
        manager.expiry_deadline(&binding(4)).is_none(),
        "no lease means no expiry deadline"
    );
}

/// D4(c)（engine 持久化生命周期，P1）：异常断线（token 未 ACK）后 acquire 可恢复。
///
/// J52 单槽语义：token 发出未 ACK 即异常断线 → 连接终止（`terminate_connection`）立即
/// 无效化槽内 token → **新连接**（重新连到常驻 engine 的 transport，新 connection
/// binding）可重新 acquire（`Issued`，新 token）——恢复不卡死、不残留旧 token。旧连接
/// 本身不可再 issue（槽已 resolved），符合 "token 永不重发"。
#[test]
fn acquire_recovers_after_abnormal_disconnect_without_ack() {
    let mut manager = OwnerLeaseManager::new();
    // 首次连接（异常断线；token 从未 ACK）。
    let conn_a = binding(3);
    // 重连后的新连接（新 transport connection binding）。
    let conn_b = binding(4);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);

    // 首次 acquire：token 发出、未 ACK。
    assert!(matches!(
        manager.issue(&conn_a, key.clone(), d1.clone(), v1, token(20)),
        LeaseIssue::Issued { .. }
    ));

    // 异常断线：token 未 ACK，连接终止 → 槽立即无效化（旧 token 作废）。
    assert!(matches!(
        manager.terminate_connection(&conn_a),
        TerminateOutcome::Invalidated { token: ref invalidated, ref ownership_version }
            if *invalidated == token(20) && *ownership_version == v1
    ));

    // 旧连接（已终止）不再接受 issue（token 永不重发）。
    assert!(matches!(
        manager.issue(&conn_a, key.clone(), d1.clone(), v1, token(30)),
        LeaseIssue::Refused
    ));

    // 新连接 acquire 可恢复：同 key/digest/version 重新铸造新 token（Issued，非 Refused）。
    assert!(matches!(
        manager.issue(&conn_b, key.clone(), d1.clone(), v1, token(21)),
        LeaseIssue::Issued { ref token_digest } if *token_digest == token(21)
    ));
}

/// After a connection terminates, a NEW manager instance (restart) does NOT accept the prior token
/// digest as authorization: a fresh issue requires a fresh auth path and mints a fresh token.
/// Kills: 'restart re-authorizes via prior token digest'.
#[test]
fn restart_does_not_authenticate_by_digest() {
    // First lifetime: issue a token, then terminate the connection (token invalidated).
    let mut first = OwnerLeaseManager::new();
    let conn = binding(3);
    let key = lookup_key(1, OperationMethod::Connect);
    let d1 = request_digest(10);
    let v1 = version(1);
    let cand_a = token(20);

    assert!(matches!(
        first.issue(&conn, key.clone(), d1.clone(), v1, cand_a.clone()),
        LeaseIssue::Issued { .. }
    ));
    assert!(matches!(
        first.terminate_connection(&conn),
        TerminateOutcome::Invalidated { ref token, ref ownership_version }
            if *token == cand_a && *ownership_version == v1
    ));

    // Restart: a brand-new manager instance has NO memory of the prior token digest. Presenting the
    // prior token as a candidate must NOT be accepted as a replay/authorization; a fresh issue
    // requires a fresh auth path and mints a fresh token.
    let mut restarted = OwnerLeaseManager::new();
    let issued = restarted.issue(&conn, key, d1, v1, cand_a.clone());
    assert!(
        matches!(issued, LeaseIssue::Issued { ref token_digest } if *token_digest == cand_a),
        "restart must not re-authorize via the prior token digest; a fresh issue needs a fresh auth path"
    );
}
