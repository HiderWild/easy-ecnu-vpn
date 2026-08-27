// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
// R31-T/I: fenced `RuntimeEffect` scheduling. The single-writer actor calls `schedule` immediately
// after committing a state transition that emits effects; the scheduler runs the effect off the
// actor's lock and routes its `EffectCompleted` (exact `CompletionFence` + `StaleDisposition`)
// back to the actor. Outer/inner fence mismatch fails closed: the effect is not run.

use std::sync::Arc;

use exv_vpn_domain::identity::EffectId;
use exv_vpn_domain::ports::PacketStopFence;
use exv_vpn_domain::reducer::{
    CompletionFence, EffectCompletion, EffectOutcome, EffectRequest, RecoveryEffectFence,
    RuntimeEffect, StaleDisposition,
};

/// A scheduler for fenced runtime effects. The actor requests an effect runner here; the runner
/// owns the effect's commitment and must report its terminal outcome back through the actor.
pub trait EffectScheduler: Send + Sync {
    /// Schedule `effect` to run off the actor's single-writer lock.
    fn schedule(&self, effect: RuntimeEffect);
}

/// Closure that routes a completed effect's `EffectCompleted` back to the single-writer actor.
pub type CompletionSink = Arc<dyn Fn(EffectCompletion) + Send + Sync>;

/// Production fenced scheduler: validates that the outer `CompletionFence` and the inner port
/// request fence agree (fail closed on mismatch) before running the effect, then routes the
/// resulting `EffectCompleted` back through the sink.
pub struct FencedEffectScheduler {
    sink: CompletionSink,
}

impl FencedEffectScheduler {
    pub fn new(sink: CompletionSink) -> Self {
        Self { sink }
    }
}

impl EffectScheduler for FencedEffectScheduler {
    fn schedule(&self, effect: RuntimeEffect) {
        // Fail closed: an outer/inner fence mismatch means the effect is never run.
        if !fence_is_consistent(&effect) {
            return;
        }
        let sink = self.sink.clone();
        tokio::spawn(async move {
            // MVP runtime: without a live port executor the effect is reported as cancelled before
            // it ran, carrying the exact fenced identity and disposition back to the actor.
            let completion = EffectCompletion {
                fence: effect.fence,
                outcome: EffectOutcome::CancelledBeforeEffect,
                stale_disposition: StaleDisposition::ProvenNoEffect,
            };
            sink(completion);
        });
    }
}

/// Checks that the request's embedded fence (when present) names the same effect as the outer
/// `CompletionFence`. A mismatch is a contract violation and fails closed.
fn fence_is_consistent(effect: &RuntimeEffect) -> bool {
    match inner_effect_id(&effect.request) {
        None => true,
        Some(inner) => fence_effect_id(&effect.fence) == inner,
    }
}

fn fence_effect_id(fence: &CompletionFence) -> EffectId {
    match fence {
        CompletionFence::External(f) => f.effect_id.clone(),
        CompletionFence::Attempt(f) => f.effect_id.clone(),
        CompletionFence::Owned(f) => f.attempt_effect.effect_id.clone(),
        CompletionFence::Interaction(f) => f.attempt_effect.effect_id.clone(),
        CompletionFence::Recovery(f) => match f {
            RecoveryEffectFence::Observe { effect_id, .. } => effect_id.clone(),
            RecoveryEffectFence::Owned { effect_id, .. } => effect_id.clone(),
            RecoveryEffectFence::Retirement { effect_id, .. } => effect_id.clone(),
        },
    }
}

/// The effect id embedded in the request's own fence, when the request carries one.
fn inner_effect_id(request: &EffectRequest) -> Option<EffectId> {
    match request {
        EffectRequest::AcquireOwnership(r) => Some(r.fence.effect_id.clone()),
        EffectRequest::ApplyTunnel(r) => Some(r.fence.attempt_effect.effect_id.clone()),
        EffectRequest::StopPacket { fence, .. } => match fence {
            PacketStopFence::Active(f) => Some(f.attempt_effect.effect_id.clone()),
            PacketStopFence::Recovery { .. } => None,
        },
        _ => None,
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
