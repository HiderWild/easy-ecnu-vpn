// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Deterministic scripted [`Clock`] for tests (TK80-83).

use exv_vpn_domain::ports::{Clock, MonotonicTick};
use std::collections::VecDeque;
use std::sync::Mutex;

/// A deterministic clock that yields ticks from a fixed script, then repeats the final tick.
#[derive(Debug)]
pub struct ScriptedClock {
    inner: Mutex<ScriptedClockState>,
}

#[derive(Debug)]
struct ScriptedClockState {
    script: VecDeque<MonotonicTick>,
    last: Option<MonotonicTick>,
}

impl ScriptedClock {
    /// The script must be non-empty; the final tick is repeated forever after it is exhausted.
    pub fn from_script(ticks: Vec<MonotonicTick>) -> Self {
        assert!(!ticks.is_empty(), "script must be non-empty");
        Self {
            inner: Mutex::new(ScriptedClockState {
                script: ticks.into(),
                last: None,
            }),
        }
    }

    /// A clock that always reports the same tick.
    pub fn constant(tick: MonotonicTick) -> Self {
        Self::from_script(vec![tick])
    }
}

impl Clock for ScriptedClock {
    fn monotonic_now(&self) -> MonotonicTick {
        let mut state = self
            .inner
            .lock()
            .expect("scripted clock mutex poisoned");
        if let Some(tick) = state.script.pop_front() {
            state.last = Some(tick);
            tick
        } else {
            state.last.expect("script non-empty invariant")
        }
    }
}