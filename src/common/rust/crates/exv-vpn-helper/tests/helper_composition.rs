// RED tests for the helper control-plane composition (spec L1012/L1052/L1054/L1056/L1057/
// L1079/L1099/L1120, vpn-rust-native-runtime-mvp).
// PURE, deterministic: no I/O, no filesystem, no sleep, no randomness —
// identifiers and digests come only from Uuid::from_u128 and fixed byte literals.
//
// The composition seam `exv_vpn_helper::composition` is an empty stub; H81-I implements it.
// Until then this file FAILS TO COMPILE (unresolved imports) — that is the intended RED.

use exv_vpn_data_plane::teardown::{JoinOutcome, TeardownSide};
use exv_vpn_domain::error::ErrorSubject;
use exv_vpn_domain::identity::{
    EvidenceDigest, InventoryDigest, OperationId, OperationLookupKey, OperationMethod,
    OwnershipVersion, PrincipalDigest, RequestDigest, ResourceIdentityDigest,
    RetirementOperationId, RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::model::PlatformOwnershipRef;
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CleanupTrigger, CleanupTriggerDigest,
    ExternalOperationDigest, JournalRootDigest, JournalRevision, PlatformAuthorityInstanceId,
    VersionedPlatformEvidence,
};
use exv_vpn_helper::composition::{HelperComposition, HelperEffect, HelperPhase};
use exv_vpn_resource::retirement::ProveCleanInput;
use uuid::Uuid;

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

/// Deterministic 32-byte digest whose first byte differs across `n` (non-nil).
fn digest32(n: u8) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0] = n;
    b
}

/// Deterministic durable retirement id that differs across `n`.
fn retirement_id(n: u128) -> RetirementOperationId {
    RetirementOperationId::try_from(Uuid::from_u128(n)).expect("non-nil retirement id")
}

/// Deterministic runtime epoch across `n`.
fn runtime_epoch(n: u128) -> RuntimeEpoch {
    RuntimeEpoch::try_from(Uuid::from_u128(n)).expect("non-nil epoch")
}

/// Deterministic non-zero ownership version across `n`.
fn ownership_version(n: u64) -> OwnershipVersion {
    OwnershipVersion::try_from(n).expect("non-zero version")
}

/// Deterministic canonical inventory digest across `n`.
fn inventory_digest(n: u8) -> InventoryDigest {
    InventoryDigest::try_from(digest32(n)).expect("digest")
}

/// A deterministic platform ownership ref (non-nil identity digest).
fn platform_ownership() -> PlatformOwnershipRef {
    PlatformOwnershipRef::try_from((
        ResourceIdentityDigest::try_from(digest32(0x31)).expect("digest"),
        ownership_version(1),
        TokenDigest::try_from(digest32(0x32)).expect("digest"),
    ))
    .expect("ownership ref")
}

/// A deterministic external-stop cleanup trigger.
fn cleanup_trigger() -> CleanupTrigger {
    CleanupTrigger::ExternalStop {
        lookup_key: OperationLookupKey::try_from((
            PrincipalDigest::try_from(digest32(0x41)).expect("digest"),
            OperationMethod::Stop,
            runtime_epoch(1),
            OperationId::try_from(Uuid::from_u128(3)).expect("non-nil op"),
        ))
        .expect("key"),
        request_digest: RequestDigest::try_from(digest32(0x42)).expect("digest"),
    }
}

/// A deterministic origin subject (runtime epoch).
fn origin_subject() -> ErrorSubject {
    ErrorSubject::Runtime(runtime_epoch(1))
}

/// A canonical, fully-bound ProveCleanInput (all distinct nominal digest types).
fn prove_input() -> ProveCleanInput {
    ProveCleanInput {
        runtime_epoch: runtime_epoch(1),
        cleanup_trigger_digest: CleanupTriggerDigest::try_from(digest32(0x0a)).expect("digest"),
        external_trigger_operation_identity_digest_if_present: Some(
            ExternalOperationDigest::try_from(digest32(0x0b)).expect("digest"),
        ),
        journal_root_or_projection_digest: JournalRootDigest::try_from(digest32(0x0c))
            .expect("digest"),
        platform_evidence: VersionedPlatformEvidence {
            kind_version: 1,
            digest: EvidenceDigest::try_from(digest32(0x0d)).expect("digest"),
        },
        prior_platform_ownership_token_digest_if_issued: Some(
            TokenDigest::try_from(digest32(0x0e)).expect("digest"),
        ),
    }
}

/// Drive a fresh composition deterministically into the Active phase (ownership acquired, packet
/// attached, current frame admitted).
fn to_active(comp: &mut HelperComposition) {
    assert!(comp.acquire_ownership(ownership_version(1)).is_ok(), "acquire reaches Acquired");
    assert!(comp.attach_packet().is_ok(), "attach reaches Active");
    assert!(comp.admit_owned_frame(ownership_version(1)).is_ok(), "admit current frame");
    assert!(comp.ownership_version() == Some(&ownership_version(1)), "version pinned");
    assert!(comp.is_attached(), "attached");
}

/// Drive a fresh composition deterministically into the Retiring phase with the given obligations.
fn to_retiring(comp: &mut HelperComposition, id: u128, obligations: Vec<u8>) {
    to_active(comp);
    assert!(
        comp.begin_retirement(
            fence(),
            ownership_version(1),
            retirement_id(id),
            cleanup_trigger(),
            origin_subject(),
            platform_ownership(),
            obligations,
            inventory_digest(1),
        )
        .is_ok(),
        "begin_retirement reaches Retiring"
    );
    assert!(matches!(comp.phase(), HelperPhase::Retiring), "phase is Retiring");
}

/// Packet attach is refused before ownership is held (L1052). Kills: "packet attach
/// before ownership acquisition".
#[test]
fn attach_packet_before_ownership_is_refused() {
    let mut comp = HelperComposition::new();
    assert!(matches!(comp.phase(), HelperPhase::Idle), "fresh composition is Idle");
    assert!(comp.attach_packet().is_err(), "attach must be refused without ownership");
    assert!(matches!(comp.phase(), HelperPhase::Idle), "phase stays Idle on refusal");
    assert!(!comp.is_attached(), "never attached");
}

/// Retirement is only released once BOTH teardown sides have joined (L1056). Kills: "retirement
/// released before teardown barrier completes both sides".
#[test]
fn release_waits_for_both_teardown_sides() {
    let mut comp = HelperComposition::new();
    to_retiring(&mut comp, 1, vec![1]);
    assert!(comp.retire_saga(ownership_version(2)).is_ok(), "saga can reach Retired");

    assert!(matches!(
        comp.join_teardown(TeardownSide::ProtocolControl),
        JoinOutcome::Pending
    ));
    assert!(!comp.teardown_released(), "barrier still fenced after one side");
    assert!(comp.release_ownership().is_err(), "release refused while barrier fenced");
    assert!(matches!(comp.phase(), HelperPhase::Retiring), "phase stays Retiring");

    assert!(matches!(
        comp.join_teardown(TeardownSide::PacketData),
        JoinOutcome::Released
    ));
    assert!(comp.teardown_released(), "barrier released on final side");
    assert!(comp.release_ownership().is_ok(), "release succeeds once both sides joined");
    assert!(matches!(comp.phase(), HelperPhase::Retired), "phase reaches Retired");
}

/// A new ownership must not be issued while a retirement is in progress (L1012). Kills: "a new
/// ownership issued during retirement".
#[test]
fn acquire_ownership_refused_during_retirement() {
    let mut comp = HelperComposition::new();
    to_retiring(&mut comp, 1, vec![1]);
    assert!(
        comp.acquire_ownership(ownership_version(3)).is_err(),
        "acquire must be refused during retirement"
    );
    assert!(matches!(comp.phase(), HelperPhase::Retiring), "phase stays Retiring");
}

/// Only the current ownership version frame is admitted; older/foreign epochs are refused
/// (L1054). Kills: "stale/old-epoch packet accepted".
#[test]
fn stale_epoch_frame_refused() {
    let mut comp = HelperComposition::new();
    to_active(&mut comp);
    assert!(comp.admit_owned_frame(ownership_version(1)).is_ok(), "current frame admitted");
    assert!(
        comp.admit_owned_frame(ownership_version(2)).is_err(),
        "newer frame is stale w.r.t. the held version"
    );
    assert!(
        comp.admit_owned_frame(OwnershipVersion::try_from(0xFFFF).expect("max version")).is_err(),
        "foreign max frame refused"
    );
}

/// A second retirement cannot start while one is already in progress (L1099). Kills: "a second
/// retirement started while one is in progress".
#[test]
fn second_retirement_refused_while_in_progress() {
    let mut comp = HelperComposition::new();
    to_retiring(&mut comp, 1, vec![1]);
    assert!(
        comp.begin_retirement(
            fence(),
            ownership_version(1),
            retirement_id(2),
            cleanup_trigger(),
            origin_subject(),
            platform_ownership(),
            vec![1],
            inventory_digest(1),
        )
        .is_err(),
        "second retirement must be refused"
    );
    assert!(matches!(comp.phase(), HelperPhase::Retiring), "phase stays Retiring");
}

/// Release requires the retirement saga to have reached Retired even when the teardown barrier is
/// already released (L1057). Kills: "release while saga not Retired even with teardown barrier
/// released".
#[test]
fn release_waits_for_retirement_saga_retired() {
    let mut comp = HelperComposition::new();
    to_retiring(&mut comp, 1, vec![1]);
    assert!(matches!(
        comp.join_teardown(TeardownSide::ProtocolControl),
        JoinOutcome::Pending
    ));
    assert!(matches!(
        comp.join_teardown(TeardownSide::PacketData),
        JoinOutcome::Released
    ));
    assert!(comp.teardown_released(), "barrier fully released");
    assert!(
        comp.release_ownership().is_err(),
        "release must wait for the saga to be Retired"
    );
    assert!(matches!(comp.phase(), HelperPhase::Retiring), "phase stays Retiring");
}

/// Packet attach is refused once teardown has begun (L1056/L1120). Kills: "packet attach during
/// retirement".
#[test]
fn packet_attach_refused_after_teardown_begins() {
    let mut comp = HelperComposition::new();
    assert!(comp.acquire_ownership(ownership_version(1)).is_ok(), "acquire reaches Acquired");
    assert!(
        comp.begin_retirement(
            fence(),
            ownership_version(1),
            retirement_id(1),
            cleanup_trigger(),
            origin_subject(),
            platform_ownership(),
            vec![1],
            inventory_digest(1),
        )
        .is_ok(),
        "begin_retirement reaches Retiring"
    );
    assert!(comp.attach_packet().is_err(), "attach must be refused during retirement");
    assert!(matches!(comp.phase(), HelperPhase::Retiring), "phase stays Retiring");
}

/// The full clean retirement flow must be admitted end-to-end (L1079/L1099/L1120). Kills:
/// "over-strict guard refuses a valid clean retirement".
#[test]
fn full_clean_retirement_flow() {
    let mut comp = HelperComposition::new();
    assert!(matches!(comp.phase(), HelperPhase::Idle), "starts Idle");

    assert!(comp.acquire_ownership(ownership_version(1)).is_ok(), "acquire reaches Acquired");
    assert_eq!(comp.phase(), HelperPhase::Acquired);
    assert!(comp.ownership_version() == Some(&ownership_version(1)), "version held");

    assert!(comp.attach_packet().is_ok(), "attach reaches Active");
    assert_eq!(comp.phase(), HelperPhase::Active);
    assert!(comp.is_attached(), "attached");

    assert!(comp.admit_owned_frame(ownership_version(1)).is_ok(), "admit current frame");

    // Empty obligations: observe_cleanup sees a complete (trivially so) inventory.
    assert!(
        comp.begin_retirement(
            fence(),
            ownership_version(1),
            retirement_id(1),
            cleanup_trigger(),
            origin_subject(),
            platform_ownership(),
            vec![],
            inventory_digest(1),
        )
        .is_ok(),
        "begin_retirement reaches Retiring"
    );
    assert_eq!(comp.phase(), HelperPhase::Retiring);

    assert!(matches!(
        comp.join_teardown(TeardownSide::ProtocolControl),
        JoinOutcome::Pending
    ));
    assert!(matches!(
        comp.join_teardown(TeardownSide::PacketData),
        JoinOutcome::Released
    ));
    assert!(comp.teardown_released(), "barrier released");

    assert!(comp.observe_and_prove(prove_input()).is_ok(), "observe_and_prove succeeds");
    assert!(comp.retire_saga(ownership_version(2)).is_ok(), "saga reaches Retired");

    assert!(comp.release_ownership().is_ok(), "release succeeds on clean retirement");
    assert_eq!(comp.phase(), HelperPhase::Retired);
    assert!(!comp.is_attached(), "no longer attached after retirement");
}