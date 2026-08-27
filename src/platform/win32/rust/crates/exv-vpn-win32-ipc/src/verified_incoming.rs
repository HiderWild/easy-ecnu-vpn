// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W11-I: the dispatch seam verdict. `IncomingVerdict` is produced by W12's dispatch path and is
// pinned here so the acceptance import resolves; authentication failures never dispatch (WSP1 §7).

use crate::peer_auth::PeerAuthError;

/// The disposition of an incoming connection at the dispatch seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncomingVerdict {
    /// The connection passed authentication and was dispatched.
    Dispatched,
    /// Authentication failed; the peer must not be dispatched.
    AuthFailed(PeerAuthError),
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
