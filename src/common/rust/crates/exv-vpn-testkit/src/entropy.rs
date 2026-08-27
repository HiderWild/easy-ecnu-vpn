// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// Deterministic scripted EntropySource for tests (TK80-83).

//! Deterministic scripted [`EntropySource`] for tests (TK80-83).

use exv_vpn_domain::ports::EntropySource;
use std::collections::VecDeque;
use std::sync::Mutex;
use uuid::Uuid;

/// A deterministic entropy source that yields UUIDs from a fixed script, then `Uuid::nil()`.
#[derive(Debug)]
pub struct ScriptedEntropy {
    script: Mutex<VecDeque<Uuid>>,
}

impl ScriptedEntropy {
    /// The script may be empty; exhausted scripts yield `Uuid::nil()`.
    pub fn from_script(uuids: Vec<Uuid>) -> Self {
        Self {
            script: Mutex::new(uuids.into()),
        }
    }
}

impl EntropySource for ScriptedEntropy {
    fn next_uuid(&self) -> Uuid {
        self.script
            .lock()
            .expect("scripted entropy mutex poisoned")
            .pop_front()
            .unwrap_or_else(Uuid::nil)
    }
}