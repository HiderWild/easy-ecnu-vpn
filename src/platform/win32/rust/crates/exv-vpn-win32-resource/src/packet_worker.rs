// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! A joinable packet worker thread (W17).
//!
//! The packet worker is the helper abstraction a session uses to poll
//! `WintunReceivePacket` on a dedicated thread. The frozen safety order
//! (native-wintun-facts.md §2 `child.joined_before_session_end`) requires the
//! worker to be joined **before** `WintunEndSession`: 0.14.1's `WintunEndSession`
//! destroys the session object, so any `WintunReceivePacket` after end is a
//! use-after-free (measured ntdll AV). [`PacketWorker`] guarantees the join by
//! doing it both on explicit [`PacketWorker::join`] and in `Drop`, so a session
//! that holds a worker cannot end before the worker thread has stopped.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A worker thread that repeatedly runs a user closure until joined.
///
/// Dropping the worker (or calling [`PacketWorker::join`]) signals the thread
/// to stop and joins it, so a dropped worker never leaks its thread and a
/// session ending after a joined worker is never racing `receive`.
pub struct PacketWorker {
    /// Set by `join`/`Drop` to ask the worker thread to stop.
    stop: Arc<AtomicBool>,
    /// The spawned worker thread (taken during join to consume the handle).
    handle: Option<std::thread::JoinHandle<()>>,
}

/// The worker closure, boxed to a concrete type so the worker thread's auto
/// traits never depend on the caller's closure type.
///
/// # SAFETY
///
/// [`PacketWorker::spawn`] moves the boxed closure into a single dedicated
/// worker thread and never exposes it again: the carrier is consumed by the
/// thread's loop, the closure is only ever called on that one thread, and
/// [`PacketWorker::join`] / `Drop` block until the thread has stopped before
/// the worker (and thus the carrier) is dropped. The caller must therefore
/// ensure the closure's captures are not concurrently shared with other
/// threads for the worker's lifetime — the frozen WSP3 receive-poller pattern
/// (e.g. a session-managed event handle held for the worker's lifetime, with
/// the join-before-session-end order guaranteeing the handle stays valid).
/// This mirrors the reviewed `unsafe impl Send` of `crate::wintun_session::WintunSession`:
/// the wrapped state is only ever touched from one thread at a time under the
/// wrapper's own lifetime rules.
struct SpawnClosure(Box<dyn FnMut() + 'static>);

impl SpawnClosure {
    /// Run one iteration of the worker closure.
    ///
    /// Exists so the worker thread's closure calls it as a method: the
    /// method-call receiver borrows the **whole** carrier (a `&mut
    /// SpawnClosure`, `Send` via the reviewed impl below), instead of
    /// precision-capturing the inner `Box<dyn FnMut()>` field (which is not
    /// `Send` and would make the thread closure non-`Send`).
    fn call(&mut self) {
        (self.0)();
    }
}

// SAFETY: the closure is confined to the single worker thread for its whole
// lifetime (see the struct-level SAFETY comment); moving the owned carrier
// into that thread is safe exactly when the caller honours the confinement
// contract documented on `spawn`.
unsafe impl Send for SpawnClosure {}

impl PacketWorker {
    /// Spawn a worker thread that calls `f` repeatedly until the worker is
    /// joined.
    ///
    /// The closure runs on a dedicated thread. It should be responsive to
    /// termination (e.g. a receive-poller should sleep briefly when the ring is
    /// empty) so that [`PacketWorker::join`] returns promptly; `join` waits for
    /// the current `f()` call to return. The closure may capture raw native
    /// state (e.g. a session-managed event handle — WSP3 pattern); the caller
    /// is responsible for its thread confinement (see [`SpawnClosure`]).
    #[must_use]
    pub fn spawn<F: FnMut() + 'static>(f: F) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let mut f = SpawnClosure(Box::new(f));
        let handle = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                f.call();
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    /// Signal the worker to stop and join its thread (blocks until the current
    /// `f()` call returns).
    ///
    /// MUST be called before `WintunEndSession` when the worker calls
    /// `WintunReceivePacket` (frozen safety order — end-before-join is the
    /// use-after-free mutant, native-wintun-facts.md §2). `Drop` performs the
    /// same join, so forgetting the explicit join cannot leak the thread.
    pub fn join(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            // A panicked closure ends the thread; join returns Err, which is
            // fine here — the goal (no thread still running) is achieved.
            drop(handle.join());
        }
    }
}

impl Drop for PacketWorker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            drop(handle.join());
        }
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
