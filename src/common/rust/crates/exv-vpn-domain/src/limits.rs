// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

use crate::error::{EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, RetryAdvice, VpnError};
use crate::identity::RuntimeEpoch;
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MvpLimits {
    pub normal_mailbox_messages: usize,
    pub completion_mailbox_messages: usize,
    pub stop_waiters: usize,
    pub snapshot_receivers: usize,
    pub packet_queue_messages: usize,
    pub packet_queue_bytes: usize,
    pub max_packet_batch_packets: usize,
    pub max_packet_batch_bytes: usize,
    pub max_control_message_bytes: usize,
    pub max_packet_message_bytes: usize,
    pub normal_cleanup_budget: Duration,
    pub queued_connect_budget: Duration,
    pub owner_lease_ttl: Duration,
    pub packet_loss_cleanup_grace: Duration,
}

pub type ValidateLimitsFn = fn(&MvpLimits) -> Result<(), VpnError>;

/// Rejects zero budgets and inverted budget ordering (queued connect budget shorter than the
/// cleanup budget). Returns a generic `InvalidInput` admission error on failure.
pub fn validate_limits(limits: &MvpLimits) -> Result<(), VpnError> {
    let invalid = || {
        VpnError::try_from((
            ErrorCode::InvalidInput,
            ErrorStage::Admission,
            EffectCertainty::NoEffect,
            RetryAdvice::DoNotRetry,
            ErrorSubject::Runtime(RuntimeEpoch::try_from(Uuid::new_v4()).expect("non-nil uuid")),
            None,
            None,
        ))
        .expect("valid error tuple")
    };

    if limits.normal_cleanup_budget == Duration::ZERO
        || limits.queued_connect_budget == Duration::ZERO
        || limits.owner_lease_ttl == Duration::ZERO
        || limits.packet_loss_cleanup_grace == Duration::ZERO
    {
        return Err(invalid());
    }
    if limits.queued_connect_budget < limits.normal_cleanup_budget {
        return Err(invalid());
    }
    Ok(())
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
