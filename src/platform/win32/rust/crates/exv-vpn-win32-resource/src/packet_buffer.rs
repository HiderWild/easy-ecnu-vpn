// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! A received Wintun packet buffer (W17).
//!
//! `WintunReceivePacket` returns a pointer into the session's receive ring;
//! that outstanding receive must be released with `WintunReleaseReceivePacket`
//! (frozen fact `receive.outstanding_released`, native-wintun-facts.md §2).
//! [`WintunPacket`] owns the outstanding receive and releases it in `Drop`, so
//! dropping a packet *is* the release — a receive ring of ~1024 slots is never
//! exhausted by callers that drop what they receive (kills the
//! 'received packet buffer never released' mutant).

use windows::Win32::Foundation::HANDLE;

use crate::wintun_api::WintunReleaseReceivePacketFn;

impl WintunPacket {
    /// Wrap a just-received ring buffer (crate-internal; called by
    /// [`WintunSession::receive`](crate::wintun_session::WintunSession::receive)).
    ///
    /// `buffer` must be a non-NULL outstanding receive of exactly `size`
    /// bytes from `session`.
    pub(crate) fn from_receive(
        session: HANDLE,
        release: WintunReleaseReceivePacketFn,
        buffer: *mut u8,
        size: u32,
    ) -> Self {
        Self {
            session,
            release,
            buffer,
            size,
        }
    }
}

/// A packet received from the session receive ring.
///
/// Wraps the raw receive-buffer pointer plus its size; the outstanding receive
/// is released with `WintunReleaseReceivePacket` when the packet is dropped
/// (the frozen release contract). Constructed only by
/// [`WintunSession::receive`](crate::wintun_session::WintunSession::receive);
/// the caller must not use the bytes after the packet is dropped.
pub struct WintunPacket {
    /// The session handle the buffer belongs to (required to release it).
    session: HANDLE,
    /// `WintunReleaseReceivePacket` export, kept for `Drop`.
    release: WintunReleaseReceivePacketFn,
    /// Pointer to the received packet bytes inside the session ring.
    buffer: *mut u8,
    /// The received packet size in bytes (written by `WintunReceivePacket`).
    size: u32,
}

impl WintunPacket {
    /// The received packet bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `buffer` is a live, un-released receive buffer of exactly
        // `size` bytes (the value `WintunReceivePacket` wrote); the session
        // handle stays open because the outstanding receive keeps this packet
        // alive until `Drop`. Reading `size` bytes is therefore in-bounds.
        unsafe { std::slice::from_raw_parts(self.buffer, self.size as usize) }
    }

    /// The received packet bytes (alias of [`Self::as_slice`]).
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Drop for WintunPacket {
    fn drop(&mut self) {
        // SAFETY: `self.session` is the session this packet was received from
        // and `self.buffer` is the still-outstanding receive pointer; this is
        // the only place the outstanding receive is released (frozen fact
        // `receive.outstanding_released`). `Drop` is the last use of both.
        unsafe { (self.release)(self.session, self.buffer) };
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
