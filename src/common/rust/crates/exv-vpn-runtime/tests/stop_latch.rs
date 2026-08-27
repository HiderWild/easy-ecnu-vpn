// EXV R30-T: bounded mailboxes and the single-slot Stop latch for exv-vpn-runtime.
// These tests reference the R30 construction seams (BoundedMailbox in `mailbox`, StopLatch in
// `handle`). They are expected to be RED until R30-I implements those types.
//
// The mailbox/latch contract is FROZEN BY THESE TESTS. R30-I must implement EXACTLY:
//   - `exv_vpn_runtime::mailbox::BoundedMailbox<T>` with `new(capacity)`, `try_send`,
//     `try_send_drop_oldest`, `try_recv`, `len`, `is_full`, and `MailboxFull<T>`.
//   - `exv_vpn_runtime::handle::StopLatch` with `new`, `with_limits(&MvpLimits)`,
//     `latch_stop(&AttemptId)`, `latched_attempt`, `token_count`, `coalesced_count`,
//     `try_add_waiter`, `register_rpc_waiter`, `rpc_waiter_drop`, and `WaiterLimitExceeded`.
//
// These tests are killable by the three R30 mutants:
//   (a) unbounded channel       -> normal_mailbox_is_bounded / completion_mailbox_is_bounded /
//                                  snapshot_slow_reader_drops_old_revision fail.
//   (b) every Stop a fresh token -> stop_latch_has_single_token / repeated_stop_coalesces_same_attempt /
//                                  stop_flood_does_not_allocate_unboundedly fail.
//   (c) RPC future drop auto-Stop -> rpc_waiter_drop_does_not_emit_stop fails.

use exv_vpn_domain::identity::AttemptId;
use exv_vpn_domain::limits::MvpLimits;
use exv_vpn_runtime::handle::{StopLatch, WaiterLimitExceeded};
use exv_vpn_runtime::mailbox::{BoundedMailbox, MailboxFull};
use std::time::Duration;
use uuid::Uuid;

/// A base MvpLimits with sane, non-inverted budgets so `with_limits`/`validate_limits`-style
/// consumers get a well-formed configuration.
fn base_limits() -> MvpLimits {
    MvpLimits {
        normal_mailbox_messages: 64,
        completion_mailbox_messages: 16,
        stop_waiters: 8,
        snapshot_receivers: 4,
        packet_queue_messages: 1024,
        packet_queue_bytes: 1 << 20,
        max_packet_batch_packets: 64,
        max_packet_batch_bytes: 1 << 16,
        max_control_message_bytes: 1 << 12,
        max_packet_message_bytes: 1 << 14,
        normal_cleanup_budget: Duration::from_secs(5),
        queued_connect_budget: Duration::from_secs(10),
        owner_lease_ttl: Duration::from_secs(60),
        packet_loss_cleanup_grace: Duration::from_secs(2),
    }
}

fn fresh_attempt() -> AttemptId {
    AttemptId::try_from(Uuid::new_v4()).expect("non-nil uuid")
}

/// A snapshot message carrying a monotonically increasing revision number; a slow reader is one
/// that has not drained between revisions.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    revision: u64,
}

#[test]
fn normal_mailbox_is_bounded() {
    // The normal-op mailbox is bounded by `normal_mailbox_messages`: it rejects with
    // `MailboxFull` once filled to capacity instead of accepting every message (kills mutant (a)
    // — an unbounded mailbox never rejects).
    let capacity = base_limits().normal_mailbox_messages;
    let mut mb: BoundedMailbox<u64> = BoundedMailbox::new(capacity);

    for i in 0..capacity {
        assert!(mb.try_send(i as u64).is_ok(), "should accept up to capacity");
    }
    assert!(mb.is_full());
    assert_eq!(mb.len(), capacity);

    match mb.try_send(capacity as u64) {
        Err(MailboxFull(rejected)) => assert_eq!(rejected, capacity as u64),
        Ok(_) => panic!("normal mailbox accepted a message past its bound"),
    }
    // The rejected message must not have been buffered.
    assert_eq!(mb.len(), capacity);
}

#[test]
fn completion_mailbox_is_bounded() {
    // The completion-op mailbox is bounded by `completion_mailbox_messages` (kills mutant (a)).
    let capacity = base_limits().completion_mailbox_messages;
    let mut mb: BoundedMailbox<u64> = BoundedMailbox::new(capacity);

    for i in 0..capacity {
        assert!(mb.try_send(i as u64).is_ok(), "should accept up to capacity");
    }
    assert!(mb.try_send(capacity as u64).is_err(), "must reject when full");
    assert_eq!(mb.len(), capacity);
}

#[test]
fn stop_latch_has_single_token() {
    // The latch is a single-slot token: it holds at most one latched stop, on the current attempt.
    let attempt = fresh_attempt();
    let mut latch = StopLatch::new();

    // A fresh latch has no stop token latched.
    assert_eq!(latch.token_count(), 0);
    assert_eq!(latch.latched_attempt(), None);

    // The first Stop latches the single token onto the current attempt.
    let latched = latch.latch_stop(&attempt);
    assert_eq!(latched, attempt);
    assert_eq!(latch.token_count(), 1, "single-slot latch exceeds one token");
    assert_eq!(latch.latched_attempt(), Some(&attempt));
}

#[test]
fn repeated_stop_coalesces_same_attempt() {
    // A flood of Stops on the same attempt coalesce onto the one single-slot token (kills
    // mutant (b) — every Stop delivering a fresh token would mint new tokens and grow the slot).
    let attempt = fresh_attempt();
    let mut latch = StopLatch::new();

    latch.latch_stop(&attempt);
    latch.latch_stop(&attempt);
    latch.latch_stop(&attempt);

    // Still exactly one token slot, still latched onto the original attempt.
    assert_eq!(latch.token_count(), 1, "repeated stops must not mint new tokens");
    assert_eq!(latch.latched_attempt(), Some(&attempt));
    // But every Stop was observed by the coalescing counter.
    assert_eq!(latch.coalesced_count(), 3);
}

#[test]
fn stop_waiters_are_bounded() {
    // Concurrent stop waiters are bounded by `stop_waiters`: registering past the bound is
    // rejected rather than growing without limit.
    let mut limits = base_limits();
    limits.stop_waiters = 3;
    let mut latch = StopLatch::with_limits(&limits);

    for _ in 0..3 {
        assert!(latch.try_add_waiter().is_ok(), "should admit up to stop_waiters");
    }
    match latch.try_add_waiter() {
        Err(WaiterLimitExceeded) => {}
        Ok(()) => panic!("stop waiter admitted past the stop_waiters bound"),
    }
}

#[test]
fn stop_flood_does_not_allocate_unboundedly() {
    // A large flood of Stops must not grow the latch's live state unboundedly: it stays a single
    // slot while every stop is coalesced (kills mutant (b) — fresh-token-per-stop allocation).
    let attempt = fresh_attempt();
    let mut latch = StopLatch::new();

    // Bounded flood: 10_000 coalesced stops are well beyond any legit single-stop scenario.
    let flood = 10_000usize;
    for _ in 0..flood {
        latch.latch_stop(&attempt);
    }

    // Fixed O(1) state: still a single token, never a per-stop allocation.
    assert_eq!(latch.token_count(), 1, "flood allocated per-stop state");
    assert_eq!(latch.coalesced_count(), flood as u64);
    assert_eq!(latch.latched_attempt(), Some(&attempt));
}

#[test]
fn snapshot_slow_reader_drops_old_revision() {
    // A slow snapshot reader (one that never drains between revisions) must not stall on stale
    // revisions: a latest-wins snapshot buffer drops the oldest revision when full (kills
    // mutant (a) — an unbounded buffer would retain every stale revision).
    let mut snap = BoundedMailbox::new(2);

    snap.try_send(Snapshot { revision: 1 }).unwrap();
    snap.try_send(Snapshot { revision: 2 }).unwrap();
    assert!(snap.is_full());

    // The slow reader has consumed nothing; a new revision evicts the oldest one.
    let dropped = snap.try_send_drop_oldest(Snapshot { revision: 3 });
    assert_eq!(dropped.map(|s| s.revision), Some(1), "oldest revision not dropped");

    // The buffer now holds only the newest revisions, never the stale one.
    let drained: Vec<u64> = std::iter::from_fn(|| snap.try_recv())
        .map(|s| s.revision)
        .collect();
    assert_eq!(drained, vec![2, 3]);
}

#[test]
fn rpc_waiter_drop_does_not_emit_stop() {
    // Dropping an RPC future/waiter must NOT emit a Stop on its own (kills mutant (c) — an
    // auto-Stop on RPC drop would latch a stop token here). Cancellation of an RPC waiter is not
    // a Stop request.
    let mut latch = StopLatch::new();

    latch.register_rpc_waiter();
    latch.register_rpc_waiter();
    // The runtime drops both RPC waiters below.
    latch.rpc_waiter_drop();
    latch.rpc_waiter_drop();

    // No Stop was emitted by the drops.
    assert_eq!(latch.latched_attempt(), None, "RPC waiter drop emitted a Stop");
    assert_eq!(latch.token_count(), 0);
}