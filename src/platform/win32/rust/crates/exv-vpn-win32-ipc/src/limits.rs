// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W12-I: the pre-auth resource limits frozen by WSP1 (native-pipe-facts.md §7). These are the
// bounds enforced before a connection passes authentication: at most one concurrent stream, at
// most one 64 KiB message, and at most 64 KiB of buffered data per peer plane.

/// The pre-authentication resource limits for one peer plane (WSP1 §7, frozen).
///
/// These values are measured on the Win32 acceptance host and must not drift from the frozen
/// facts: `stream=1`, `message=64 KiB (65536 B)`, `buffer=64 KiB (65536 B)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaneLimits {
    /// Maximum number of concurrent streams a plane may dispatch before authentication.
    pub preauth_max_streams: usize,
    /// Maximum size of a single message/frame admitted before authentication (64 KiB).
    pub preauth_max_message_bytes: usize,
    /// Maximum cumulative buffered bytes a plane may hold before authentication (64 KiB).
    pub preauth_max_buffer_bytes: usize,
    /// Maximum size of a packet-message carried by the data plane.
    pub max_packet_message_bytes: usize,
}

impl PlaneLimits {
    /// The MVP's pre-auth limits, pinned to the frozen WSP1 values.
    #[must_use]
    pub const fn mvp() -> Self {
        Self {
            preauth_max_streams: 1,
            preauth_max_message_bytes: 65536,
            preauth_max_buffer_bytes: 65536,
            max_packet_message_bytes: 65536,
        }
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
