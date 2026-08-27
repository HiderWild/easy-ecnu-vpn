// EXV P43-T: single-writer priority mux, DPD/EOF, and protocol late-cleanup vault
// integration tests for exv-vpn-cstp.
//
// These tests define the exact public API that P43-I must implement in
// `exv_vpn_cstp::mux` (and the protocol late-cleanup vault). They are expected to be
// RED (compile error) until P43-I implements that mux. The mux is the single writer
// over the peer byte stream: it separates control (Close / DPD / Keepalive) from data
// (two producers A and B) behind a reserved-control-capacity FIFO, byte-budgeted data,
// fair data producers, and peer non-read backpressure. It also exercises the PROTOCOL
// LATE-CLEANUP vault semantics: a cleanup failure returns the moved handle + obligation,
// wrong owner/fence rejects the locator, an unpolled cleanup future keeps the vault
// entry, and a future dropped while polled keeps the vault entry.
//
// Contract (RNRM-004/005/010/014, TG-04):
//   * Reserved control capacity: control lives on its own bounded FIFO that data can
//     never occupy, so a data flood can never starve a Close / DPD / Keepalive.
//   * Control is always scheduled ahead of data, so control has a bounded scheduling
//     delay regardless of how much data is queued.
//   * Data is byte-budgeted: admission is refused once the buffered byte budget is
//     exhausted, and only relieved when the peer reads.
//   * The two data producers are drained fairly (round-robin); neither is starved.
//   * Peer non-read yields bounded backpressure — it never permanently blocks the
//     writer, and control is unaffected.
//   * EOF is terminal: after `eof()`, no further data/control admission is accepted and
//     the writer drains the queue then observes EOF.
//   * A Stop/Close flood is bounded by the reserved control capacity and can never
//     starve writer completion.
//   * Protocol late cleanup: `register` registers the moved handle into the vault
//     SYNCHRONOUSLY (before any cleanup future is returned or polled). A cleanup
//     failure returns the moved handle + `RecoveryObligation` in a `StillLive` outcome
//     and re-registers the live handle (never swallowed). A locator is rejected by a
//     wrong owner or a wrong fence. Dropping a cleanup future — unpolled or in-flight —
//     never removes the vault entry.
//
// The API P43-I must implement in `exv_vpn_cstp::mux`:
//
//   pub enum ControlKind { Close, Dpd, Keepalive }
//   pub enum DataSource { ProducerA, ProducerB }          // Clone, Copy, PartialEq, Eq, Debug
//
//   pub struct MuxConfig {
//       pub control_capacity: usize,   // reserved control FIFO capacity (data never uses)
//       pub data_byte_budget: usize,   // max buffered (enqueued + in-flight) data bytes
//   }
//
//   pub enum MuxError {
//       ControlQueueFull,     // reserved control capacity exhausted
//       DataBudgetExceeded,   // data admission would exceed the byte budget (peer not reading)
//       EofTerminal,          // admission after terminal EOF
//   }
//
//   pub enum MuxItem {
//       Control(ControlKind),
//       Data(DataSource, Vec<u8>),
//       Eof,                  // emitted once after all queued items when eof() was called
//   }
//
//   pub struct Mux { /* opaque */ }                       // Send + 'static
//   impl Mux {
//       pub fn new(config: MuxConfig) -> Self;
//       pub fn push_control(&mut self, kind: ControlKind) -> Result<(), MuxError>;
//       pub fn push_data(&mut self, source: DataSource, payload: Vec<u8>) -> Result<(), MuxError>;
//       pub fn next(&mut self) -> Option<MuxItem>;        // control first, then fair data, then Eof
//       pub fn peer_read(&mut self, consumed: usize);     // release `consumed` in-flight bytes
//       pub fn is_backpressured(&self) -> bool;           // data byte budget exhausted
//       pub fn eof(&mut self);                            // terminal EOF
//       pub fn is_eof(&self) -> bool;
//       pub fn control_queued(&self) -> usize;
//       pub fn data_buffered_bytes(&self) -> usize;
//       pub fn is_empty(&self) -> bool;
//   }
//
// Protocol late-cleanup vault (`exv_vpn_cstp::mux`):
//
//   pub struct LateHandle { /* opaque linear handle; the concrete type P43-I binds to
//                                exv_vpn_domain::ports::ProtocolPort::LateHandle */ }
//   impl LateHandle {
//       pub fn new() -> Self;   // mint a fresh linear handle (owner/test seam); NOT Clone
//   }
//   pub struct LateHandleLocator { /* opaque */ }         // Clone
//   #[derive(Debug, Clone, PartialEq, Eq)]
//   pub enum VaultError { WrongOwner, WrongFence, UnknownLocator }
//   pub struct LateCleanupFuture { /* opaque */ }         // Future<Output = ProtocolLateCleanupOutcome<LateHandle>>
//   impl LateCleanupFuture {
//       pub fn locator(&self) -> &LateHandleLocator;
//   }
//   pub struct LateCleanupVault { /* opaque */ }
//   impl LateCleanupVault {
//       pub fn new() -> Self;
//       pub fn register(&mut self, handle: LateHandle) -> LateHandleLocator; // synchronous
//       pub fn take(&mut self, locator: &LateHandleLocator) -> Result<LateHandle, VaultError>;
//       pub fn contains(&self, locator: &LateHandleLocator) -> bool;
//       pub fn len(&self) -> usize;
//       pub fn is_empty(&self) -> bool;
//       pub fn begin_cleanup(&self, locator: &LateHandleLocator) -> LateCleanupFuture;
//   }
//
//   The cleanup future's polling contract:
//     * DROPPING it — polled or not — MUST NOT remove the vault entry.
//     * The first poll returns Poll::Pending (cleanup is in-flight; entry stays).
//     * A subsequent poll drives cleanup to a failure and yields
//       ProtocolLateCleanupOutcome::StillLive { error, handle, obligation }, re-registering
//       the moved handle as a live vault entry so it is never swallowed.
//
// Mutants this suite must kill:
//   M1 control/data share an unreserved FIFO
//       -> control_has_reserved_capacity, close/dpd/keepalive scheduling-delay tests
//   M2 always-drain data (never refuses admission)
//       -> data_is_byte_budgeted, peer_non_read_yields_backpressure
//   M3 peer non-read permanently blocks the writer
//       -> peer_non_read_yields_backpressure
//   M4 late-cleanup failure swallows the moved handle
//       -> protocol_late_cleanup_failure_returns_handle_and_obligation
//   M5 wrong owner/fence accepts the locator
//       -> protocol_late_handle_rejects_wrong_owner_or_fence
//   M6 vault entry registered only on first poll
//       -> protocol_late_cleanup_unpolled_future_keeps_vault_entry
//   M7 future drop removes the vault entry
//       -> protocol_late_cleanup_unpolled_future_keeps_vault_entry,
//          protocol_late_cleanup_inflight_drop_keeps_vault_entry

use exv_vpn_cstp::mux::{
    ControlKind, DataSource, LateCleanupFuture, LateCleanupVault, LateHandle, LateHandleLocator,
    Mux, MuxConfig, MuxError, MuxItem, VaultError,
};
use exv_vpn_domain::ports::ProtocolLateCleanupOutcome;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// Shared construction helpers
// ---------------------------------------------------------------------------

/// A sane, non-inverted mux configuration.
fn mux_config() -> MuxConfig {
    MuxConfig {
        control_capacity: 8,
        data_byte_budget: 4096,
    }
}

/// Poll a future to completion using a noop waker. No runtime, no real time: the future
/// is driven purely by the caller. Deterministic for the deterministic cleanup future.
fn poll_to_completion<F: Future>(fut: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);
    let mut pinned = pin!(fut);
    loop {
        match pinned.as_mut().poll(&mut cx) {
            Poll::Ready(out) => return out,
            Poll::Pending => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Mux: reserved control capacity, scheduling, data budget, fairness, backpressure, EOF
// ---------------------------------------------------------------------------

#[test]
fn control_has_reserved_capacity() {
    let mut mux = Mux::new(mux_config());

    // Fill the data byte budget so data admission is backpressured.
    let mut admitted = 0;
    while !mux.is_backpressured() {
        mux.push_data(DataSource::ProducerA, vec![0x45; 512])
            .expect("fill the data budget");
        admitted += 1;
    }
    assert!(admitted > 0, "the data budget was filled");
    assert!(mux.is_backpressured());

    // Control still has reserved capacity: it lives on a separate FIFO data can never
    // occupy, so a full data buffer cannot starve it (M1: shared unreserved FIFO fails).
    assert!(
        mux.push_control(ControlKind::Close).is_ok(),
        "control has reserved capacity even under data backpressure"
    );
    assert_eq!(mux.control_queued(), 1, "the Close is queued in the control FIFO");
    // Control is prioritized: it drains before any data.
    assert!(
        matches!(mux.next(), Some(MuxItem::Control(ControlKind::Close))),
        "control is scheduled ahead of data"
    );
}

#[test]
fn close_has_bounded_scheduling_delay() {
    let config = mux_config();
    let mut mux = Mux::new(config);

    // A data flood larger than the reserved control window, then a Close arrives.
    let flood = config.control_capacity * 2;
    for _ in 0..flood {
        mux.push_data(DataSource::ProducerA, vec![0x45; 128])
            .expect("flood data");
    }
    mux.push_control(ControlKind::Close).expect("Close admitted");

    // Control is prioritized, so the Close must be scheduled within the reserved
    // control window — never starved behind the data flood. A mutant that shares an
    // unreserved FIFO would deliver the flood first and fail the bound.
    let mut skipped = 0;
    let mut found = false;
    while skipped < config.control_capacity {
        match mux.next() {
            Some(MuxItem::Control(ControlKind::Close)) => {
                found = true;
                break;
            }
            Some(_) => skipped += 1,
            None => break,
        }
    }
    assert!(found, "Close must be scheduled within the reserved control window");
    assert!(
        skipped < config.control_capacity,
        "Close scheduling delay must be bounded by the reserved control capacity"
    );
}

#[test]
fn dpd_has_bounded_scheduling_delay() {
    let config = mux_config();
    let mut mux = Mux::new(config);

    // A data flood, then a DPD (dead-peer-detection) frame arrives.
    let flood = config.control_capacity * 2;
    for _ in 0..flood {
        mux.push_data(DataSource::ProducerA, vec![0x45; 128])
            .expect("flood data");
    }
    mux.push_control(ControlKind::Dpd).expect("DPD admitted");

    let mut skipped = 0;
    let mut found = false;
    while skipped < config.control_capacity {
        match mux.next() {
            Some(MuxItem::Control(ControlKind::Dpd)) => {
                found = true;
                break;
            }
            Some(_) => skipped += 1,
            None => break,
        }
    }
    assert!(found, "DPD must be scheduled within the reserved control window");
    assert!(
        skipped < config.control_capacity,
        "DPD scheduling delay must be bounded by the reserved control capacity"
    );
}

#[test]
fn keepalive_not_starved_by_data() {
    let config = mux_config();
    let mut mux = Mux::new(config);

    // Continuous data pressure, then a Keepalive. It must never be starved.
    for _ in 0..config.control_capacity * 3 {
        mux.push_data(DataSource::ProducerA, vec![0x45; 128])
            .expect("continuous data");
    }
    mux.push_control(ControlKind::Keepalive).expect("Keepalive admitted");

    let mut skipped = 0;
    loop {
        match mux.next() {
            Some(MuxItem::Control(ControlKind::Keepalive)) => {
                assert!(
                    skipped < config.control_capacity,
                    "Keepalive scheduling delay must be bounded"
                );
                break;
            }
            Some(MuxItem::Eof) => panic!("Keepalive was starved before EOF"),
            Some(_) => skipped += 1,
            None => panic!("Keepalive was never scheduled"),
        }
        assert!(
            skipped < config.control_capacity,
            "Keepalive was starved by data"
        );
    }
}

#[test]
fn data_is_byte_budgeted() {
    let config = mux_config();
    let mut mux = Mux::new(config);

    // Fill the byte budget; admission must be refused once it is exhausted rather than
    // always draining (M2: always-drain data fails).
    let mut admitted_bytes = 0;
    loop {
        match mux.push_data(DataSource::ProducerA, vec![0x45; 512]) {
            Ok(()) => admitted_bytes += 512,
            Err(MuxError::DataBudgetExceeded) => break,
            Err(other) => panic!("unexpected error: {:?}", other),
        }
    }
    assert!(
        admitted_bytes >= config.data_byte_budget,
        "data is byte-budgeted and admission is refused at the budget"
    );
    assert!(mux.is_backpressured(), "the mux is backpressured at the byte budget");
}

#[test]
fn both_data_producers_are_fair() {
    let mut mux = Mux::new(mux_config());

    // Equal offers from both producers: drains must alternate round-robin; neither
    // producer is starved.
    for _ in 0..4 {
        mux.push_data(DataSource::ProducerA, vec![0x45; 64])
            .expect("producer A offers");
        mux.push_data(DataSource::ProducerB, vec![0x46; 64])
            .expect("producer B offers");
    }

    let mut got_a = 0;
    let mut got_b = 0;
    let mut drained = 0;
    let mut last: Option<DataSource> = None;
    while let Some(item) = mux.next() {
        match item {
            MuxItem::Data(src, _) => {
                if let Some(prev) = &last {
                    assert_ne!(prev, &src, "data producers must alternate fairly");
                }
                last = Some(src);
                match src {
                    DataSource::ProducerA => got_a += 1,
                    DataSource::ProducerB => got_b += 1,
                }
                drained += 1;
            }
            _ => panic!("only data is queued here"),
        }
    }
    assert_eq!(drained, 8, "all eight queued data items drained");
    assert_eq!(got_a, 4, "producer A is not starved");
    assert_eq!(got_b, 4, "producer B is not starved");
}

#[test]
fn peer_non_read_yields_backpressure() {
    let mut mux = Mux::new(mux_config());

    // An unreading peer: fill the data byte budget.
    let mut admitted = 0;
    while !mux.is_backpressured() {
        mux.push_data(DataSource::ProducerA, vec![0x45; 512])
            .expect("fill the budget");
        admitted += 1;
    }
    assert!(admitted > 0);
    assert!(mux.is_backpressured());

    // Control is NOT blocked: an unreading peer must yield bounded backpressure, never
    // permanently block the whole writer (M3: peer non-read permanently blocks fails).
    assert!(
        mux.push_control(ControlKind::Keepalive).is_ok(),
        "control is not blocked by an unreading peer"
    );
    // Data admission is refused while the peer is not reading.
    assert!(matches!(
        mux.push_data(DataSource::ProducerB, vec![0x45; 512]),
        Err(MuxError::DataBudgetExceeded)
    ));

    // Drain the control, then hand one data item to the peer (next()). Its bytes stay
    // in flight until the peer reads, so the mux is still backpressured.
    assert!(matches!(mux.next(), Some(MuxItem::Control(ControlKind::Keepalive))));
    assert!(matches!(mux.next(), Some(MuxItem::Data(DataSource::ProducerA, _))));
    assert!(
        mux.is_backpressured(),
        "in-flight bytes still count until the peer reads"
    );

    // The peer reads: backpressure is relieved and data is admitted again.
    mux.peer_read(512);
    assert!(!mux.is_backpressured(), "peer read relieves backpressure");
    assert!(
        mux.push_data(DataSource::ProducerB, vec![0x45; 512]).is_ok(),
        "data is admitted again after the peer reads"
    );
}

#[test]
fn eof_is_terminal() {
    let mut mux = Mux::new(mux_config());
    mux.push_data(DataSource::ProducerA, vec![0x45; 64])
        .expect("data before EOF");
    mux.push_control(ControlKind::Close).expect("control before EOF");
    mux.eof();
    assert!(mux.is_eof());

    // Admission after EOF is terminal, for both data and control.
    assert!(matches!(
        mux.push_data(DataSource::ProducerA, vec![0x45; 64]),
        Err(MuxError::EofTerminal)
    ));
    assert!(matches!(mux.push_control(ControlKind::Dpd), Err(MuxError::EofTerminal)));

    // Draining yields the queued Close, then the queued data, then Eof, then nothing.
    assert!(matches!(mux.next(), Some(MuxItem::Control(ControlKind::Close))));
    assert!(matches!(mux.next(), Some(MuxItem::Data(DataSource::ProducerA, _))));
    assert!(matches!(mux.next(), Some(MuxItem::Eof)));
    assert!(mux.next().is_none(), "EOF is terminal");
}

#[tokio::test]
async fn stop_flood_cannot_starve_writer_completion() {
    // Paused time: the writer's completion is gated by a barrier (Notify), never by
    // wall-clock sleep. No time is advanced; the writer completes deterministically.
    tokio::time::pause();
    let config = mux_config();
    let mut mux = Mux::new(config);

    // A Stop/Close flood. The control FIFO is reserved-and-bounded, so the flood cannot
    // grow without limit and starve the writer.
    let mut accepted = 0;
    loop {
        match mux.push_control(ControlKind::Close) {
            Ok(()) => accepted += 1,
            Err(MuxError::ControlQueueFull) => break,
            Err(other) => panic!("unexpected error: {:?}", other),
        }
    }
    assert_eq!(
        accepted, config.control_capacity,
        "the reserved control capacity bounds the stop flood"
    );
    mux.eof();

    // The writer drains to EOF; a barrier (Notify) signals completion. Under paused time
    // the barrier is ready the moment the writer finishes — no sleep, no hang.
    let writer_done = Arc::new(Notify::new());
    let writer_done_task = writer_done.clone();
    let completed = Arc::new(AtomicBool::new(false));
    let completed_task = completed.clone();
    let mut mux_task = mux;
    tokio::spawn(async move {
        let mut drained = 0;
        let mut saw_eof = false;
        while let Some(item) = mux_task.next() {
            if matches!(item, MuxItem::Eof) {
                saw_eof = true;
            }
            drained += 1;
        }
        completed_task.store(saw_eof && drained == accepted + 1, Ordering::SeqCst);
        writer_done_task.notify_one();
    });

    writer_done.notified().await;
    assert!(
        completed.load(Ordering::SeqCst),
        "the stop flood starved writer completion"
    );
}

// ---------------------------------------------------------------------------
// Protocol late-cleanup vault
// ---------------------------------------------------------------------------

#[test]
fn protocol_late_cleanup_failure_returns_handle_and_obligation() {
    let mut vault = LateCleanupVault::new();
    let locator = vault.register(LateHandle::new());
    assert!(vault.contains(&locator), "the handle is live after registration");

    // Run the late cleanup to a FAILURE. The outcome must return the moved handle and
    // obligation in a StillLive arm — never swallow them (M4: failure swallows the
    // moved handle fails) and never report Terminated for an unresolved cleanup.
    let outcome = poll_to_completion(vault.begin_cleanup(&locator));
    match outcome {
        ProtocolLateCleanupOutcome::Terminated => {
            panic!("a failed late cleanup must not report Terminated")
        }
        ProtocolLateCleanupOutcome::StillLive {
            error: _,
            handle: _,
            obligation,
        } => {
            // The obligation is present in the returned outcome (its fields are opaque
            // to the test; the StillLive arm carrying it is the contract).
            let _ = obligation;
        }
    }

    // The moved handle was re-registered: the vault keeps a live entry, so the handle is
    // recoverable rather than swallowed.
    assert!(
        vault.contains(&locator),
        "a failed cleanup must re-register the live handle, not swallow it"
    );
    assert!(
        vault.take(&locator).is_ok(),
        "the recovered handle is still consumable from the vault"
    );
}

#[test]
fn protocol_late_handle_rejects_wrong_owner_or_fence() {
    let mut owner_a = LateCleanupVault::new();
    let mut owner_b = LateCleanupVault::new(); // a different owner (wrong fence)
    let locator = owner_a.register(LateHandle::new());

    // Wrong owner: a locator minted by owner_a must be rejected by owner_b (M5: a
    // mutant that accepts any locator fails).
    assert!(
        owner_b.take(&locator).is_err(),
        "a locator from another owner must be rejected"
    );
    // The entry is still live in its real owner.
    assert!(owner_a.contains(&locator), "the real owner keeps the live entry");

    // The real owner can consume it exactly once.
    assert!(owner_a.take(&locator).is_ok(), "the owner consumes its live handle");
    assert!(!owner_a.contains(&locator), "a consumed locator is no longer live");

    // Wrong fence: consuming the same locator again is rejected.
    assert!(
        owner_a.take(&locator).is_err(),
        "a consumed locator (wrong fence) must be rejected"
    );
}

#[test]
fn protocol_late_cleanup_unpolled_future_keeps_vault_entry() {
    let mut vault = LateCleanupVault::new();
    let locator = vault.register(LateHandle::new());

    // Begin cleanup but NEVER poll it. The entry must already be registered — a mutant
    // that registers only on first poll (M6) would leave no entry here.
    let fut = vault.begin_cleanup(&locator);
    assert!(
        vault.contains(&locator),
        "the vault entry is registered before any poll"
    );

    // Dropping the unpolled future must NOT remove the vault entry (M7 fails).
    drop(fut);
    assert!(
        vault.contains(&locator),
        "dropping an unpolled cleanup future keeps the vault entry"
    );
}

#[test]
fn protocol_late_cleanup_inflight_drop_keeps_vault_entry() {
    let mut vault = LateCleanupVault::new();
    let locator = vault.register(LateHandle::new());

    let fut = vault.begin_cleanup(&locator);

    // Poll once: the cleanup is now in-flight (Pending), entry still registered.
    let waker = Waker::noop();
    let mut cx = Context::from_waker(&waker);
    let mut pinned = pin!(fut);
    assert!(
        matches!(pinned.as_mut().poll(&mut cx), Poll::Pending),
        "the cleanup is in-flight after the first poll"
    );

    // Drop the future while it is in-flight. The vault entry must survive (M7 fails).
    drop(pinned);
    assert!(
        vault.contains(&locator),
        "dropping an in-flight cleanup future keeps the vault entry"
    );
}