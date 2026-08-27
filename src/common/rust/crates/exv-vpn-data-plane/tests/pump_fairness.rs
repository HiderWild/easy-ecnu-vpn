// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// 规格：docs/superpowers/specs/vpn-rust-native-runtime-mvp.md；cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// Terra (test writer) — leaf Q61: fair directional pump scheduler. RED tests ONLY.
// The production seam (pump.rs) is an empty stub and is NOT implemented here. This file references
// the pinned seam and must fail to compile until Q61-I lands.
//
// Pure + deterministic: no I/O, no filesystem, no sleep, no randomness. All counts are fixed
// integer literals and the sustained-full budget is driven with fixed batches.

use exv_vpn_data_plane::budget::{DataPlaneDirection, PacketBudget};
use exv_vpn_data_plane::pump::{DirectionReadiness, PollDecision, PumpScheduler};
use exv_vpn_domain::limits::MvpLimits;

/// Default limits: small packet knobs, real durations (mirrors attachment_budget.rs).
/// packet queue 4 msgs / 1024 B; per-batch cap 2 pkts / 512 B.
fn base_limits() -> MvpLimits {
    MvpLimits {
        normal_mailbox_messages: 16,
        completion_mailbox_messages: 16,
        stop_waiters: 4,
        snapshot_receivers: 4,
        packet_queue_messages: 4,
        packet_queue_bytes: 1024,
        max_packet_batch_packets: 2,
        max_packet_batch_bytes: 512,
        max_control_message_bytes: 256,
        max_packet_message_bytes: 256,
        normal_cleanup_budget: std::time::Duration::from_secs(30),
        queued_connect_budget: std::time::Duration::from_secs(60),
        owner_lease_ttl: std::time::Duration::from_secs(120),
        packet_loss_cleanup_grace: std::time::Duration::from_secs(5),
    }
}

/// Tight budget: a single batch exactly fills the whole queue to capacity, so repeated
/// admits drive the counter past the sustained-full threshold quickly (>= 4 increments).
fn sustained_full_limits() -> MvpLimits {
    let mut limits = base_limits();
    limits.packet_queue_messages = 2;
    limits.packet_queue_bytes = 512;
    limits.max_packet_batch_packets = 2;
    limits.max_packet_batch_bytes = 512;
    limits
}

/// Repeatedly admit a full-capacity batch on `direction` until `budget.is_sustained_full()`
/// reports true. Deterministic: fixed batch size, bounded loop with a hard cap.
fn drive_to_sustained_full(mut budget: PacketBudget, direction: DataPlaneDirection) -> PacketBudget {
    let mut rounds = 0;
    while !budget.is_sustained_full() {
        let _ = budget.try_admit(direction, 2, 512);
        rounds += 1;
        assert!(rounds < 16, "budget never reached sustained-full");
    }
    budget
}

// ---- fair directional pump scheduler ----

#[test]
fn new_tries_protocol_to_packet_first() {
    assert_eq!(
        PumpScheduler::new().next_direction(),
        DataPlaneDirection::ProtocolToPacket
    );
}

#[test]
fn both_ready_alternate_fairly_over_rounds() {
    let mut scheduler = PumpScheduler::new();
    let ready = DirectionReadiness {
        has_data: true,
        backed_up: false,
    };
    let mut polls = Vec::new();
    for _ in 0..8 {
        polls.push(scheduler.next(ready, ready));
    }
    let expected = vec![
        PollDecision::Poll(DataPlaneDirection::ProtocolToPacket),
        PollDecision::Poll(DataPlaneDirection::PacketToProtocol),
        PollDecision::Poll(DataPlaneDirection::ProtocolToPacket),
        PollDecision::Poll(DataPlaneDirection::PacketToProtocol),
        PollDecision::Poll(DataPlaneDirection::ProtocolToPacket),
        PollDecision::Poll(DataPlaneDirection::PacketToProtocol),
        PollDecision::Poll(DataPlaneDirection::ProtocolToPacket),
        PollDecision::Poll(DataPlaneDirection::PacketToProtocol),
    ];
    assert_eq!(polls, expected);
}

#[test]
fn never_drains_one_direction_before_the_other() {
    let mut scheduler = PumpScheduler::new();
    let ready = DirectionReadiness {
        has_data: true,
        backed_up: false,
    };
    let mut prev: Option<DataPlaneDirection> = None;
    for _ in 0..8 {
        let poll = scheduler.next(ready, ready);
        let direction = match poll {
            PollDecision::Poll(d) => d,
            PollDecision::Idle => panic!("expected a poll, got Idle"),
        };
        if let Some(prev) = prev {
            assert_ne!(direction, prev, "a direction was polled twice consecutively");
        }
        prev = Some(direction);
    }
}

#[test]
fn backed_up_direction_yields_to_healthy_other() {
    let mut scheduler = PumpScheduler::new();
    assert_eq!(
        scheduler.next(
            DirectionReadiness {
                has_data: true,
                backed_up: true,
            },
            DirectionReadiness {
                has_data: true,
                backed_up: false,
            },
        ),
        PollDecision::Poll(DataPlaneDirection::PacketToProtocol)
    );
}

#[test]
fn backed_up_direction_does_not_block_healthy() {
    // Drive ProtocolToPacket into true sustained-full via the Q60 budget composition.
    let p2p_budget = drive_to_sustained_full(
        PacketBudget::from_limits(&sustained_full_limits()).expect("valid limits"),
        DataPlaneDirection::ProtocolToPacket,
    );
    let p2p_backed_up = p2p_budget.is_sustained_full();
    // Keep PacketToProtocol truly healthy: a fresh budget that is never admitted is not full.
    let healthy_budget = PacketBudget::from_limits(&sustained_full_limits()).expect("valid limits");
    let healthy_backed_up = healthy_budget.is_sustained_full();
    assert!(p2p_backed_up, "backed-up direction must report sustained-full");
    assert!(!healthy_backed_up, "healthy direction must not report sustained-full");

    let mut scheduler = PumpScheduler::new();
    for _ in 0..4 {
        assert_eq!(
            scheduler.next(
                DirectionReadiness {
                    has_data: true,
                    backed_up: p2p_backed_up,
                },
                DirectionReadiness {
                    has_data: true,
                    backed_up: healthy_backed_up,
                },
            ),
            PollDecision::Poll(DataPlaneDirection::PacketToProtocol)
        );
    }
}

#[test]
fn both_backed_up_returns_idle() {
    let mut scheduler = PumpScheduler::new();
    let backed_up = DirectionReadiness {
        has_data: true,
        backed_up: true,
    };
    assert_eq!(scheduler.next(backed_up, backed_up), PollDecision::Idle);
}

#[test]
fn deterministic_poll_order_for_same_readiness() {
    let sequence = [
        (
            DirectionReadiness {
                has_data: true,
                backed_up: false,
            },
            DirectionReadiness {
                has_data: true,
                backed_up: false,
            },
        ),
        (
            DirectionReadiness {
                has_data: true,
                backed_up: true,
            },
            DirectionReadiness {
                has_data: true,
                backed_up: false,
            },
        ),
        (
            DirectionReadiness {
                has_data: false,
                backed_up: false,
            },
            DirectionReadiness {
                has_data: true,
                backed_up: false,
            },
        ),
        (
            DirectionReadiness {
                has_data: true,
                backed_up: false,
            },
            DirectionReadiness {
                has_data: true,
                backed_up: true,
            },
        ),
        (
            DirectionReadiness {
                has_data: true,
                backed_up: true,
            },
            DirectionReadiness {
                has_data: true,
                backed_up: true,
            },
        ),
    ];
    let mut scheduler_a = PumpScheduler::new();
    let mut scheduler_b = PumpScheduler::new();
    let mut polls_a = Vec::new();
    let mut polls_b = Vec::new();
    for (p2p, p2prot) in sequence {
        polls_a.push(scheduler_a.next(p2p, p2prot));
        polls_b.push(scheduler_b.next(p2p, p2prot));
    }
    assert_eq!(polls_a, polls_b);
}

#[test]
fn direction_without_data_yields_to_available() {
    let mut scheduler = PumpScheduler::new();
    assert_eq!(
        scheduler.next(
            DirectionReadiness {
                has_data: false,
                backed_up: false,
            },
            DirectionReadiness {
                has_data: true,
                backed_up: false,
            },
        ),
        PollDecision::Poll(DataPlaneDirection::PacketToProtocol)
    );
}