// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// Deterministic fixture builders for tests (TK80-83).

//! Deterministic fixture builders for tests (TK80-83).

use exv_vpn_domain::identity::{ConnectionBindingDigest, OperationMethod, PrincipalDigest};
use exv_vpn_domain::limits::MvpLimits;
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, JournalRevision, MonotonicTick,
    PlatformAuthorityInstanceId,
};
use exv_vpn_resource::authority::{PeerCapability, PeerContext, VerifiedConnectionMetadata};
use std::time::Duration;
use uuid::Uuid;

/// Build a [`PeerContext`] authenticated as `principal` over `connection`.
pub fn peer_context(principal: [u8; 32], connection: [u8; 32]) -> PeerContext {
    let principal = PrincipalDigest::try_from(principal).expect("valid principal digest");
    let connection =
        ConnectionBindingDigest::try_from(connection).expect("valid connection digest");
    let metadata =
        VerifiedConnectionMetadata::try_from((principal, connection)).expect("valid metadata");
    PeerContext::try_from(metadata).expect("valid peer context")
}

/// Bind a time-limited capability for `operation` under `authority`, expiring at `expires_at`.
pub fn peer_capability(
    context: &PeerContext,
    operation: OperationMethod,
    authority: u64,
    expires_at: MonotonicTick,
) -> PeerCapability {
    let authority = AuthorityEpoch::try_from(authority).expect("valid authority epoch");
    context
        .bind_capability(operation, authority, expires_at)
        .expect("bindable capability")
}

/// The canonical MVP limits fixture; passes [`exv_vpn_domain::limits::validate_limits`].
pub fn mvp_limits() -> MvpLimits {
    MvpLimits {
        normal_mailbox_messages: 64,
        completion_mailbox_messages: 64,
        stop_waiters: 8,
        snapshot_receivers: 8,
        packet_queue_messages: 1024,
        packet_queue_bytes: 1 << 20,
        max_packet_batch_packets: 64,
        max_packet_batch_bytes: 256 * 1024,
        max_control_message_bytes: 64 * 1024,
        max_packet_message_bytes: 64 * 1024,
        normal_cleanup_budget: Duration::from_secs(30),
        queued_connect_budget: Duration::from_secs(60),
        owner_lease_ttl: Duration::from_secs(300),
        packet_loss_cleanup_grace: Duration::from_secs(5),
    }
}

/// Build an [`AuthorityFence`] minting the canonical non-nil test platform instance (Uuid 1).
pub fn authority_fence(epoch: u64, watermark: u64, revision: u64) -> AuthorityFence {
    AuthorityFence {
        authority_epoch: AuthorityEpoch::try_from(epoch).expect("valid authority epoch"),
        platform_authority_instance_id: PlatformAuthorityInstanceId::try_from(Uuid::from_u128(1))
            .expect("non-nil platform instance"),
        admission_watermark: AdmissionWatermark::try_from(watermark).expect("valid admission watermark"),
        journal_revision: JournalRevision::try_from(revision).expect("valid journal revision"),
    }
}