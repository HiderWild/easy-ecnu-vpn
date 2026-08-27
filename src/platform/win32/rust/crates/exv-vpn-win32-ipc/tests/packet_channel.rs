// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W23A-T terra: the Win32 packet channel. These tests pin the packet_limits / packet_channel
// API that W23A-I implements in exv_vpn_win32_ipc::{packet_limits, packet_channel}. The frozen
// WSP1 facts (docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-pipe-facts.md
// §7) extend to the post-auth packet plane: a 64 KiB message ceiling (65536 B). The channel's
// admission budget is Q60 `exv_vpn_data_plane::budget::PacketBudget` built from those limits
// (per-batch caps max_batch_packets=64 / max_batch_bytes=262144, queue byte budget derived from
// the same limits), its fairness is Q61 `exv_vpn_data_plane::pump::PumpScheduler` (strict
// alternation so neither data-plane leg starves, spec §8.5), and its owned-frame admission
// carries the X71H ownership-version semantics: a frame bearing a stale sequence (older than
// `next_sequence`) is refused, only the current sequence is admitted.
//
// This file is RED / test-only: it references the empty `packet_limits` / `packet_channel`
// modules and must fail to compile until W23A-I implements the seam. PURE + deterministic: no
// I/O, no pipes, no sleep, no randomness; fixed integer literals only.

use exv_vpn_win32_ipc::packet_channel::{ChannelVerdict, PacketChannel};
use exv_vpn_win32_ipc::packet_limits::PacketLimits;

use exv_vpn_data_plane::budget::DataPlaneDirection;
use exv_vpn_data_plane::pump::{DirectionReadiness, PollDecision};

/// Kills 'sequence not monotonic / reused'. Two admitted batches must receive strictly
/// increasing sequence numbers 0, 1, and `next_sequence` must advance to 2 — a reused or
/// non-monotonic counter would break the X71H ownership-version ordering.
#[test]
fn sequence_strictly_increases() {
    let mut channel = PacketChannel::new(&PacketLimits::mvp(), DataPlaneDirection::ProtocolToPacket)
        .expect("mvp limits construct a valid channel");

    let first = channel.admit(1, 100);
    let second = channel.admit(1, 100);

    assert!(matches!(first, ChannelVerdict::Admitted { sequence: 0 }));
    assert!(matches!(second, ChannelVerdict::Admitted { sequence: 1 }));
    assert_eq!(
        channel.next_sequence(),
        2,
        "each admitted batch must consume exactly one, strictly increasing sequence"
    );
}

/// Kills 'per-batch packet cap ignored'. A batch of `max_batch_packets + 1` packets must be
/// rejected even though its byte count is trivially within every byte budget.
#[test]
fn batch_over_max_packets_rejected() {
    let limits = PacketLimits::mvp();
    let mut channel = PacketChannel::new(&limits, DataPlaneDirection::ProtocolToPacket)
        .expect("mvp limits construct a valid channel");

    let verdict = channel.admit(limits.max_batch_packets + 1, 1);
    assert!(
        matches!(verdict, ChannelVerdict::Rejected),
        "a batch over max_batch_packets ({} + 1) must be rejected",
        limits.max_batch_packets
    );
}

/// Kills 'per-batch byte cap ignored'. A batch of `max_batch_bytes + 1` bytes must be rejected
/// even though it carries a single packet.
#[test]
fn batch_over_max_bytes_rejected() {
    let limits = PacketLimits::mvp();
    let mut channel = PacketChannel::new(&limits, DataPlaneDirection::ProtocolToPacket)
        .expect("mvp limits construct a valid channel");

    let verdict = channel.admit(1, limits.max_batch_bytes + 1);
    assert!(
        matches!(verdict, ChannelVerdict::Rejected),
        "a batch over max_batch_bytes ({} + 1) must be rejected",
        limits.max_batch_bytes
    );
}

/// Kills 'queue byte budget ignored (count-only budget)'. Two admits each within the per-batch
/// caps but whose CUMULATIVE bytes exceed the queue byte budget (derived from the limits, i.e.
/// max_batch_bytes = 262144) must have the second one rejected. A count-only budget would track
/// only packets (2 of 64) and wrongly admit it.
#[test]
fn cumulative_over_queue_bytes_rejected() {
    let limits = PacketLimits::mvp();
    let mut channel = PacketChannel::new(&limits, DataPlaneDirection::ProtocolToPacket)
        .expect("mvp limits construct a valid channel");

    // Each single batch (1 packet, 200000 bytes) is under the per-batch caps (64 / 262144)...
    assert!(matches!(channel.admit(1, 200_000), ChannelVerdict::Admitted { sequence: 0 }));
    // ...but the two batches together push cumulative queue usage to 400000 bytes, past the
    // queue byte budget (262144), so the second admit must be refused.
    assert!(
        matches!(channel.admit(1, 200_000), ChannelVerdict::Rejected),
        "cumulative bytes over the queue byte budget must be rejected, not merely counted packets"
    );
}

/// Kills 'old ownership frame accepted' (X71H ownership-version semantics). After a frame is
/// admitted as sequence 0, an owned frame bearing the STALE sequence 0 (now less than
/// `next_sequence` == 1) must be refused, and the refusal must not consume a sequence number.
#[test]
fn old_frame_rejected() {
    let limits = PacketLimits::mvp();
    let mut channel = PacketChannel::new(&limits, DataPlaneDirection::ProtocolToPacket)
        .expect("mvp limits construct a valid channel");

    channel.admit(1, 100);
    assert_eq!(channel.next_sequence(), 1);

    assert!(
        channel.admit_owned_frame(1, 100, 0).is_err(),
        "an owned frame with a stale sequence (0 < next_sequence 1) must be rejected"
    );
    assert_eq!(
        channel.next_sequence(),
        1,
        "a rejected old frame must not consume a sequence number"
    );
}

/// Kills 'current frame wrongly rejected'. An owned frame carrying the CURRENT sequence (equal
/// to `next_sequence`, 0 on a fresh channel) must be admitted, advancing the sequence.
#[test]
fn current_frame_admitted() {
    let limits = PacketLimits::mvp();
    let mut channel = PacketChannel::new(&limits, DataPlaneDirection::ProtocolToPacket)
        .expect("mvp limits construct a valid channel");

    assert_eq!(channel.next_sequence(), 0);
    assert!(
        channel.admit_owned_frame(1, 100, 0).is_ok(),
        "an owned frame with the current sequence must be admitted"
    );
    assert_eq!(channel.next_sequence(), 1);
}

/// Kills 'compression allowed'. The MVP data plane must never negotiate compression on the
/// packet channel.
#[test]
fn no_compression_flagged() {
    assert!(
        PacketLimits::mvp().no_compression,
        "the MVP packet channel must be pinned to no compression"
    );
}

/// Kills 'one direction starved' (Q61 fairness). With both data-plane directions ready, two
/// consecutive `pump_decision` rounds must poll DIFFERENT directions — strict alternation so
/// neither leg is starved in front of the other (spec §8.5).
#[test]
fn pump_alternates_fairly() {
    let limits = PacketLimits::mvp();
    let mut channel = PacketChannel::new(&limits, DataPlaneDirection::ProtocolToPacket)
        .expect("mvp limits construct a valid channel");

    let ready = DirectionReadiness { has_data: true, backed_up: false };
    let first = channel.pump_decision(ready, ready);
    let second = channel.pump_decision(ready, ready);

    let (first_dir, second_dir) = match (first, second) {
        (PollDecision::Poll(a), PollDecision::Poll(b)) => (a, b),
        _ => panic!("with both directions ready the scheduler must poll, not idle"),
    };
    assert_ne!(
        first_dir, second_dir,
        "the two data-plane legs must alternate across rounds so neither starves"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
