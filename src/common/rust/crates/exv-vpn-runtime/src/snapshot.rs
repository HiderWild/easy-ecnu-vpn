// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
// R31-T/I: a bounded snapshot/observer path. The single-writer actor publishes the latest committed
// `RuntimeState`; a slow observer that has not drained between revisions drops the oldest revision
// (latest-wins) instead of stalling, per R30 bounded-mailbox semantics.

use exv_vpn_domain::model::RuntimeState;

use crate::mailbox::BoundedMailbox;

/// A bounded snapshot/observer path. Publishing is latest-wins: when the buffer is full, the oldest
/// unobserved revision is dropped so a slow reader never stalls on stale revisions.
pub struct SnapshotObserver {
    revisions: BoundedMailbox<RuntimeState>,
}

impl SnapshotObserver {
    /// Create an observer with a bounded revision buffer of at most `capacity` entries.
    pub fn new(capacity: usize) -> Self {
        Self {
            revisions: BoundedMailbox::new(capacity),
        }
    }

    /// Publish the latest committed state. If the buffer is full, the oldest revision is dropped.
    pub fn publish(&mut self, state: RuntimeState) {
        self.revisions.try_send_drop_oldest(state);
    }

    /// Observe the next available revision, if any.
    pub fn observe(&mut self) -> Option<RuntimeState> {
        self.revisions.try_recv()
    }

    /// Number of unobserved revisions currently buffered.
    pub fn len(&self) -> usize {
        self.revisions.len()
    }

    /// Whether there are no unobserved revisions buffered.
    pub fn is_empty(&self) -> bool {
        self.revisions.is_empty()
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
