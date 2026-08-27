// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Wintun packet session: `WintunStartSession` handle + ring access (W17).
//!
//! Frozen facts (native-wintun-facts.md §2, WSP3 elevated measurements) pin the
//! contract:
//! - ring capacity is power-of-two within `[131072, 67108864]` (wintun.h
//!   bounds); `WintunStartSession` rejects other values, and so does `start`
//!   (validation happens before the FFI call);
//! - an empty receive ring returns `ERROR_NO_MORE_ITEMS` (259), mapped to
//!   `Ok(None)` by [`WintunSession::receive`];
//! - a full send ring makes `WintunAllocateSendPacket` return NULL
//!   (`ERROR_BUFFER_OVERFLOW`, 111); [`WintunSession::send`] maps that to
//!   `Err`, never a panic;
//! - the read-wait event is session-managed: callers must not close it
//!   (`WintunEndSession` closes it on drop);
//! - outstanding receives are released by dropping the
//!   [`WintunPacket`](crate::packet_buffer::WintunPacket);
//! - a packet worker MUST be joined **before** `WintunEndSession` (`EndSession`
//!   destroys the session object; any receive after end is a use-after-free).
//!
//! Each `unsafe` block carries a reviewed `// SAFETY:` comment (workspace
//! enforces `unsafe_op_in_unsafe_fn = deny`).

use windows::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, ERROR_NO_MORE_ITEMS, GetLastError, HANDLE,
};

use crate::native_error::NativeError;
use crate::packet_worker::PacketWorker;
use crate::wintun_adapter::WintunAdapter;
use crate::wintun_api::{WintunExports, WintunLibrary};

/// Re-export of the receive-buffer wrapper (the W17 pinned seam exposes it
/// through this module; the contract test imports it as
/// `exv_vpn_win32_resource::wintun_session::WintunPacket`). The `pub use`
/// doubles as the module-local import for [`WintunSession::receive`].
pub use crate::packet_buffer::WintunPacket;

/// Wintun ring capacity minimum (wintun.h 0.14.1, frozen facts §1: 0x20000).
const RING_CAPACITY_MIN: u32 = 131_072;
/// Wintun ring capacity maximum (wintun.h 0.14.1, frozen facts §1: 0x4000000).
const RING_CAPACITY_MAX: u32 = 67_108_864;

/// An open Wintun packet session (single owner of the session handle).
///
/// Wraps the `WintunStartSession` handle of an adapter. All ring access
/// (`receive`/`send`) requires `&mut self`; the read-wait event handle is
/// session-managed (callers must not close it). Dropping the session joins any
/// attached [`PacketWorker`] first and then calls `WintunEndSession` — the
/// frozen SAFETY-ORDER.
///
/// A copy of the session exports is kept so the session can be ended even
/// after the [`WintunLibrary`] that started it was dropped (same pattern as
/// [`WintunAdapter`]).
pub struct WintunSession {
    /// The session handle from `WintunStartSession`.
    session: HANDLE,
    /// The resolved exports of the library that started the session (kept for
    /// `Drop` and all ring calls).
    exports: WintunExports,
    /// The ring capacity this session was started with (power-of-two).
    ring_capacity: u32,
    /// An attached packet worker, joined in `Drop` **before** `WintunEndSession`.
    worker: Option<PacketWorker>,
}

impl std::fmt::Debug for WintunSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque: raw handles and function pointers add no
        // debuggable value; the contract test only needs the type to be
        // `Debug` (its `.expect()` on `Arc<Mutex<WintunSession>>` requires it).
        f.debug_struct("WintunSession")
            .field("ring_capacity", &self.ring_capacity)
            .field("worker_attached", &self.worker.is_some())
            .finish_non_exhaustive()
    }
}

impl WintunSession {
    /// Start a Wintun session on `adapter` with a ring of `ring_capacity`
    /// bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if `ring_capacity` is not a power of two
    /// within `[131072, 67108864]` (validation happens before the FFI call,
    /// killing 'any ring capacity accepted' / 'ring bounds not enforced'), or
    /// if `WintunStartSession` fails (e.g. non-elevated hosts).
    pub fn start(
        lib: &WintunLibrary,
        adapter: &WintunAdapter,
        ring_capacity: u32,
    ) -> Result<Self, NativeError> {
        let _t = crate::timing::Timed::new("resource.wintun_session.start");
        if !ring_capacity.is_power_of_two()
            || !(RING_CAPACITY_MIN..=RING_CAPACITY_MAX).contains(&ring_capacity)
        {
            return Err(NativeError::from_win32(
                ERROR_INVALID_PARAMETER.0,
                "ring capacity not power of two within bounds",
            ));
        }
        let exports = *lib.exports();
        // SAFETY: `adapter.handle()` is a live open adapter handle and the
        // capacity was validated above; a NULL return means failure
        // (wintun.h contract, GetLastError carries the code).
        let session = unsafe { (exports.start_session)(adapter.handle(), ring_capacity) };
        if session.0.is_null() {
            // SAFETY: no intervening Windows API call between the NULL return
            // and this read, so GetLastError still holds the error code.
            let code = unsafe { GetLastError().0 };
            return Err(NativeError::from_win32(code, "WintunStartSession 失败"));
        }
        Ok(Self {
            session,
            exports,
            ring_capacity,
            worker: None,
        })
    }

    /// Receive one packet from the ring.
    ///
    /// An empty ring (`ERROR_NO_MORE_ITEMS`, 259) maps to `Ok(None)` — frozen
    /// fact; any other failure is an `Err`. A non-NULL result owns an
    /// outstanding receive that is released when the [`WintunPacket`] is
    /// dropped.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if `WintunReceivePacket` fails for a reason
    /// other than the empty ring.
    pub fn receive(&mut self) -> Result<Option<WintunPacket>, NativeError> {
        let mut size = 0u32;
        // SAFETY: `self.session` is a live session handle; `size` is a valid
        // out-parameter written by the DLL. Returns NULL when the ring is
        // empty (GetLastError = ERROR_NO_MORE_ITEMS) or on failure.
        // `&raw mut size` avoids clippy's implicit-borrow-as-raw-pointer.
        let buffer = unsafe { (self.exports.receive_packet)(self.session, &raw mut size) };
        if buffer.is_null() {
            // SAFETY: no intervening Windows API call between the NULL return
            // and this read, so GetLastError still holds the error code.
            let code = unsafe { GetLastError().0 };
            if code == ERROR_NO_MORE_ITEMS.0 {
                return Ok(None); // empty ring -> Ok(None), never Err/panic
            }
            return Err(NativeError::from_win32(code, "WintunReceivePacket 失败"));
        }
        Ok(Some(WintunPacket::from_receive(
            self.session,
            self.exports.release_receive_packet,
            buffer,
            size,
        )))
    }

    /// Send one packet: `WintunAllocateSendPacket` + copy + `WintunSendPacket`.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeError`] if `WintunAllocateSendPacket` returns NULL —
    /// a full send ring gives `ERROR_BUFFER_OVERFLOW` (111), an oversized
    /// packet (> `WINTUN_MAX_IP_PACKET_SIZE`) is rejected by the DLL; the NULL
    /// is mapped to `Err`, never a panic.
    pub fn send(&mut self, packet: &[u8]) -> Result<(), NativeError> {
        let size = u32::try_from(packet.len())
            .map_err(|_| NativeError::from_win32(ERROR_INVALID_PARAMETER.0, "packet 长度超限"))?;
        // SAFETY: `self.session` is a live session handle; `size` is the
        // requested packet size. Returns NULL when the ring is full or the
        // size is invalid (GetLastError carries the reason).
        let buffer = unsafe { (self.exports.allocate_send_packet)(self.session, size) };
        if buffer.is_null() {
            // SAFETY: no intervening Windows API call between the NULL return
            // and this read, so GetLastError still holds the error code.
            let code = unsafe { GetLastError().0 };
            return Err(NativeError::from_win32(code, "WintunAllocateSendPacket 失败"));
        }
        // SAFETY: a non-NULL return grants a writable buffer of exactly `size`
        // bytes owned by the session ring; copying the caller's packet fills
        // that buffer exactly.
        unsafe { std::ptr::copy_nonoverlapping(packet.as_ptr(), buffer, packet.len()) };
        // SAFETY: `buffer` was allocated from `self.session` and is fully
        // written; `WintunSendPacket` consumes it (the pointer must not be
        // used again).
        unsafe { (self.exports.send_packet)(self.session, buffer) };
        Ok(())
    }

    /// The session-managed read-wait event (`WintunGetReadWaitEvent`).
    ///
    /// The caller must NOT close this handle: the session owns the event and
    /// `WintunEndSession` closes it when the session is dropped (frozen fact
    /// `readwait.*`, native-wintun-facts.md §2).
    #[must_use]
    pub fn read_wait_event(&self) -> HANDLE {
        // SAFETY: `self.session` is a live session handle; the returned event
        // belongs to the session and is closed by `WintunEndSession` (never by
        // this wrapper or its callers).
        unsafe { (self.exports.get_read_wait_event)(self.session) }
    }

    /// The ring capacity this session was started with.
    #[must_use]
    pub fn ring_capacity(&self) -> u32 {
        self.ring_capacity
    }

    /// Attach a packet worker to this session.
    ///
    /// The worker's thread is joined in [`Drop`](Self) **before**
    /// `WintunEndSession` — the frozen SAFETY-ORDER (`EndSession` destroys the
    /// session object, so receive after end is a use-after-free mutant).
    pub fn attach_worker(&mut self, worker: PacketWorker) {
        self.worker = Some(worker);
    }
}

// SAFETY: The session handle is only ever accessed through `&mut self` methods
// (`receive`/`send` — the ring accesses) or read by value (`read_wait_event`
// returns the handle without dereferencing it). `Drop` performs
// `WintunEndSession` exactly once, under exclusive ownership: any attached
// worker is joined before the end call, so no other thread can be inside a
// session call during teardown; a moved session (e.g. `Arc<Mutex<WintunSession>>`
// shared with a worker thread, as in the W17 worker test) serializes
// cross-thread access through the mutex. This mirrors the WSP3 RawSession
// pattern: the wrapper guarantees the handle's lifetime, and `EndSession`
// never races with concurrent ring access.
unsafe impl Send for WintunSession {}

impl Drop for WintunSession {
    fn drop(&mut self) {
        // SAFETY-ORDER (frozen, native-wintun-facts.md §2): the packet worker
        // MUST join FIRST — `WintunEndSession` destroys the session object
        // (DeleteCriticalSection + free, wintun-0.14.1), so any
        // `WintunReceivePacket` after end is a use-after-free (measured ntdll
        // AV). Joining here makes the end of concurrent receive observable
        // before the end call.
        if let Some(worker) = self.worker.take() {
            worker.join();
        }
        // SAFETY: `self.session` is a live session handle and no other thread
        // can be inside a session call (the worker was just joined); this is
        // the last use of the handle (paired with the `WintunStartSession`).
        unsafe { (self.exports.end_session)(self.session) };
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
