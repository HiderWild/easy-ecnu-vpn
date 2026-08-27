// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Orderly shutdown of the privileged helper composition (W26-I).
//!
//! [`shutdown_composition`] tears the composition down in the exact reverse of the
//! composition order (W17/W24 join-before-final 的进程级投影): the native workers
//! the helper started are JOINED first — never detached — and the authority/final
//! handle is released only after every join completed (架构 §6.2/§6.3: 不允许 detach
//! 未知 worker)。

use exv_vpn_win32_resource::native_error::NativeError;

use crate::composition::HelperComposition;

/// The outcome of an orderly helper shutdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// Every native worker the helper started was joined before the authority
    /// was released (detach mutant 死于此).
    Joined { workers_joined: usize },
}

/// Tear down `composition` in reverse composition order.
///
/// 1. join every native worker the helper started — `ChildJoin` strictly before
///    the final handle (W17 SAFETY-ORDER / W24 plan order);
/// 2. end the session / restore settings / finalize the journal — nothing pending
///    in this pure composition phase (no real Wintun session was started, nothing
///    was applied, and the journal store was transient at recovery);
/// 3. release the authority last: dropping the recovery engine closes the W13
///    singleton authority handle, so a fresh helper on the same name composes
///    immediately (WSP2 §1: mutex_reusable_after_release).
///
/// # Errors
///
/// Returns a typed [`NativeError`] if a teardown stage fails; in this pure
/// composition phase no stage can fail, so `Ok` is the only observable outcome.
pub fn shutdown_composition(
    mut composition: HelperComposition,
) -> Result<ShutdownOutcome, NativeError> {
    // 1. join-before-final: the helper's native workers join FIRST (detach
    //    mutant——不 join 直接返回——死于此)。
    let workers_joined = composition.join_workers();
    // 2. session end / settings restore / journal finalize: none pending in this
    //    pure composition phase (the W22/W24 machinery joins real workers with
    //    the W28 vertical slice).
    // 3. release the authority LAST: the engine is the W13 authority holder;
    //    dropping it releases the singleton mutex after every worker joined.
    drop(composition.recovery);
    Ok(ShutdownOutcome::Joined { workers_joined })
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
