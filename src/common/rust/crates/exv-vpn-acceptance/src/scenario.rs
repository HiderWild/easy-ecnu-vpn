// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Deterministic retirement-gate agreement probe (spec §8.5 L1300). Pure + deterministic: no I/O,
//! no filesystem, no sleep, no randomness — identifiers come only from fixed byte literals and
//! `Uuid::from_u128`.
//!
//! Drives BOTH the host composition (H80) and the helper composition (H81) and reports whether
//! each releases its terminal ONLY after both teardown sides join (and, for the helper, after the
//! retirement saga reaches Retired).

use exv_vpn_data_plane::teardown::{JoinOutcome, TeardownSide};
use exv_vpn_domain::error::ErrorSubject;
use exv_vpn_domain::identity::{
    EvidenceDigest, InventoryDigest, OwnerLeaseId, OwnershipVersion, ResourceIdentityDigest,
    RetirementOperationId, RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::model::PlatformOwnershipRef;
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CleanupTrigger, CleanupTriggerDigest,
    ExternalOperationDigest, JournalRootDigest, JournalRevision, PlatformAuthorityInstanceId,
    VersionedPlatformEvidence,
};
use exv_vpn_helper::composition::{HelperComposition, HelperPhase};
use exv_vpn_host::composition::{HostComposition, HostEffect, HostEvent, HostPhase};
use exv_vpn_resource::retirement::ProveCleanInput;
use uuid::Uuid;

/// Whether the host and helper control-plane compositions both gate their terminal release on
/// BOTH teardown sides joining (and, for the helper, on the retirement saga reaching Retired).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetirementGateProbe {
    /// The host releases Stopped only after both teardown sides join.
    pub host_releases_only_after_both_sides: bool,
    /// The helper releases ownership only after both sides join and the saga is Retired.
    pub helper_releases_only_after_both_sides: bool,
}

/// Drive the host and helper compositions and report whether each honors the two-sided retirement
/// gate.
///
/// # Panics
///
/// Panics if a deterministic construction invariant is violated: the fixed byte literals and
/// `Uuid::from_u128` identifiers must always be valid (non-nil, non-zero), and the helper's
/// acquire/attach/begin-retirement sequence must always succeed on a fresh composition. These
/// hold by construction for the fixed inputs used here.
#[must_use]
pub fn retirement_gate_agreement() -> RetirementGateProbe {
    // HOST: disconnect, then join one side (must stay Stopping/fenced), then the other side
    // (must release to Stopped).
    let mut host = HostComposition::new();
    host.apply(HostEvent::Disconnect);
    let one = host.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl));
    let host_still_stopping = one == HostEffect::TeardownPending && host.phase() == HostPhase::Stopping;
    let host_stopped = host.apply(HostEvent::TeardownSideJoined(TeardownSide::PacketData))
        == HostEffect::Stopped
        && host.phase() == HostPhase::Stopped;

    // HELPER: acquire ownership, attach the packet data plane, then begin a clean retirement.
    let v1 = OwnershipVersion::try_from(1).expect("non-zero v1");
    let v2 = OwnershipVersion::try_from(2).expect("non-zero v2");
    let mut helper = HelperComposition::new();
    assert!(helper.acquire_ownership(v1).is_ok(), "acquire reaches Acquired");
    assert!(helper.attach_packet().is_ok(), "attach reaches Active");
    assert!(
        helper
            .begin_retirement(
                crate_authority_fence(),
                v1,
                RetirementOperationId::try_from(Uuid::from_u128(0xB1)).expect("non-nil retirement id"),
                CleanupTrigger::OwnerLost(
                    OwnerLeaseId::try_from(Uuid::from_u128(0x11)).expect("non-nil lease"),
                ),
                ErrorSubject::Runtime(
                    RuntimeEpoch::try_from(Uuid::from_u128(0xB0)).expect("non-nil epoch"),
                ),
                PlatformOwnershipRef::try_from((
                    ResourceIdentityDigest::try_from([0xE6; 32]).expect("identity digest"),
                    v1,
                    TokenDigest::try_from([0xE7; 32]).expect("token digest"),
                ))
                .expect("ownership ref"),
                vec![0xAA],
                InventoryDigest::try_from([0xE8; 32]).expect("inventory digest"),
            )
            .is_ok(),
        "begin_retirement reaches Retiring"
    );

    // Join one teardown side: the barrier stays fenced and release is refused.
    let one_side = helper.join_teardown(TeardownSide::ProtocolControl);
    let refused_one_side =
        matches!(one_side, JoinOutcome::Pending) && helper.release_ownership().is_err();

    // Join the second side, observe + prove clean, retire the saga, then release.
    let both_joined =
        matches!(helper.join_teardown(TeardownSide::PacketData), JoinOutcome::Released);
    let released_after_both = both_joined
        && helper.observe_and_prove(synthetic_clean_input()).is_ok()
        && helper.retire_saga(v2).is_ok()
        && helper.release_ownership().is_ok()
        && helper.phase() == HelperPhase::Retired;

    RetirementGateProbe {
        host_releases_only_after_both_sides: host_still_stopping && host_stopped,
        helper_releases_only_after_both_sides: refused_one_side && released_after_both,
    }
}

/// A deterministic authority fence minted at epoch 1, instance 1, watermark 1, revision 1.
fn crate_authority_fence() -> AuthorityFence {
    AuthorityFence {
        authority_epoch: AuthorityEpoch::try_from(1).expect("epoch 1"),
        platform_authority_instance_id: PlatformAuthorityInstanceId::try_from(Uuid::from_u128(1))
            .expect("non-nil instance"),
        admission_watermark: AdmissionWatermark::try_from(1).expect("watermark 1"),
        journal_revision: JournalRevision::try_from(1).expect("revision 1"),
    }
}

/// A canonical, fully-bound `ProveCleanInput` (all distinct nominal digest types).
fn synthetic_clean_input() -> ProveCleanInput {
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

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。