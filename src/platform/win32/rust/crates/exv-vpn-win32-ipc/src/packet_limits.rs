// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! MVP packet-channel limits (W23A-I): the 64 KiB message ceiling and the derived per-batch
//! admission caps for the post-auth packet plane (WSP1 facts §7).

/// Admission caps for the packet channel, pinned to the frozen WSP1 facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketLimits {
    /// Ceiling for a single data-plane message, in bytes (65536).
    pub max_message_bytes: usize,
    /// Maximum number of packets in a single admitted batch.
    pub max_batch_packets: usize,
    /// Maximum total bytes in a single admitted batch.
    pub max_batch_bytes: usize,
    /// The MVP data plane must never negotiate compression on the packet channel.
    pub no_compression: bool,
}

impl PacketLimits {
    /// The MVP defaults: 65536-byte message ceiling, 64 packets / 262144 bytes per batch,
    /// compression pinned off.
    #[must_use]
    pub const fn mvp() -> Self {
        Self {
            max_message_bytes: 65_536,
            max_batch_packets: 64,
            max_batch_bytes: 262_144,
            no_compression: true,
        }
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
