// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// 规格：docs/superpowers/specs/vpn-rust-native-runtime-mvp.md；cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// Terra (test writer) — leaf Q60: bounded byte-budget admission + single-slot packet attach guard.
// RED tests ONLY. The production seams (budget.rs / attachment.rs) are empty stubs and are NOT
// implemented here. This file references the pinned seam and must fail to compile until Q60-I lands.
//
// Pure + deterministic: no I/O, no filesystem, no sleep, no randomness. All counts are fixed
// integer literals and a fixed, non-nil RuntimeEpoch (Uuid::from_u128(1)).

use std::time::Duration;

use uuid::Uuid;

use exv_vpn_data_plane::attachment::PacketAttachGuard;
use exv_vpn_data_plane::budget::{AdmissionVerdict, DataPlaneDirection, PacketBudget};
use exv_vpn_domain::error::ErrorCode;
use exv_vpn_domain::error::VpnError;
use exv_vpn_domain::identity::RuntimeEpoch;
use exv_vpn_domain::limits::MvpLimits;

/// Default limits: small packet knobs, real durations.
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
        normal_cleanup_budget: Duration::from_secs(30),
        queued_connect_budget: Duration::from_secs(60),
        owner_lease_ttl: Duration::from_secs(120),
        packet_loss_cleanup_grace: Duration::from_secs(5),
    }
}

/// Deterministic, non-nil epoch derived from a fixed UUID (never new_v4).
fn epoch() -> RuntimeEpoch {
    RuntimeEpoch::try_from(Uuid::from_u128(1)).expect("non-nil runtime epoch")
}

// ---- budget: bounded byte-budget admission ----

#[test]
fn from_limits_zero_queue_bytes_is_err() {
    let mut limits = base_limits();
    limits.packet_queue_bytes = 0;
    assert!(PacketBudget::from_limits(&limits).is_err());
}

#[test]
fn admit_within_batch_and_queue_is_admitted() {
    let mut budget = PacketBudget::from_limits(&base_limits()).expect("valid limits");
    assert_eq!(
        budget.try_admit(DataPlaneDirection::PacketToProtocol, 1, 100),
        AdmissionVerdict::Admitted
    );
}

#[test]
fn batch_over_max_batch_is_overmax_though_queue_free() {
    let mut budget = PacketBudget::from_limits(&base_limits()).expect("valid limits");
    // 600 B single batch > 512 B per-batch cap, even though the 1024 B queue is still free.
    assert_eq!(
        budget.try_admit(DataPlaneDirection::PacketToProtocol, 1, 600),
        AdmissionVerdict::OverMaxBatch
    );
}

#[test]
fn cumulative_over_queue_bytes_is_overbudget() {
    let mut limits = base_limits();
    limits.packet_queue_bytes = 600; // two 400 B batches exceed it; each batch stays < 512 B cap
    let mut budget = PacketBudget::from_limits(&limits).expect("valid limits");
    assert_eq!(
        budget.try_admit(DataPlaneDirection::PacketToProtocol, 1, 400),
        AdmissionVerdict::Admitted
    );
    assert_eq!(
        budget.try_admit(DataPlaneDirection::PacketToProtocol, 1, 400),
        AdmissionVerdict::OverBudget
    );
}

#[test]
fn over_queue_messages_is_overbudget() {
    let mut limits = base_limits();
    limits.packet_queue_messages = 1; // 2 pkts within batch cap (2), but > message-count budget
    let mut budget = PacketBudget::from_limits(&limits).expect("valid limits");
    assert_eq!(
        budget.try_admit(DataPlaneDirection::PacketToProtocol, 2, 100),
        AdmissionVerdict::OverBudget
    );
}

#[test]
fn release_then_admit_again() {
    let mut budget = PacketBudget::from_limits(&base_limits()).expect("valid limits");
    assert_eq!(
        budget.try_admit(DataPlaneDirection::PacketToProtocol, 1, 400),
        AdmissionVerdict::Admitted
    );
    assert_eq!(
        budget.try_admit(DataPlaneDirection::PacketToProtocol, 1, 400),
        AdmissionVerdict::Admitted
    );
    assert_eq!(
        budget.try_admit(DataPlaneDirection::PacketToProtocol, 1, 400),
        AdmissionVerdict::OverBudget // queue now full
    );
    budget.release(DataPlaneDirection::PacketToProtocol, 2, 800);
    assert_eq!(
        budget.try_admit(DataPlaneDirection::PacketToProtocol, 1, 400),
        AdmissionVerdict::Admitted // budget freed by release
    );
}

#[test]
fn sustained_full_returns_backpressure() {
    let mut limits = base_limits();
    // Tight budget: a single batch exactly fills the whole queue to capacity.
    limits.packet_queue_messages = 2;
    limits.packet_queue_bytes = 512;
    limits.max_packet_batch_packets = 2;
    limits.max_packet_batch_bytes = 512;
    let mut budget = PacketBudget::from_limits(&limits).expect("valid limits");
    // Drive well past any reasonable sustained-full threshold (>= 3).
    let mut verdict = AdmissionVerdict::Admitted;
    for _ in 0..8 {
        verdict = budget.try_admit(DataPlaneDirection::PacketToProtocol, 2, 512);
    }
    assert_eq!(verdict, AdmissionVerdict::Backpressure);
}

#[test]
fn below_threshold_stays_not_sustained_full() {
    let mut budget = PacketBudget::from_limits(&base_limits()).expect("valid limits");
    for _ in 0..5 {
        assert_eq!(
            budget.try_admit(DataPlaneDirection::PacketToProtocol, 1, 100),
            AdmissionVerdict::Admitted
        );
    }
    assert!(!budget.is_sustained_full());
    assert_eq!(
        budget.in_flight(DataPlaneDirection::PacketToProtocol),
        (5, 500)
    );
}

// ---- attachment: single-slot packet attach guard ----

#[test]
fn attach_twice_rejects_second() {
    let mut guard = PacketAttachGuard::new(epoch());
    assert!(guard.try_attach().is_ok());
    let err: VpnError = guard.try_attach().expect_err("second attach must be rejected");
    assert_eq!(*err.code(), ErrorCode::PacketLeaseAlreadyAttached);
}

#[test]
fn detach_then_reattach() {
    let mut guard = PacketAttachGuard::new(epoch());
    assert!(guard.try_attach().is_ok());
    guard.detach();
    assert!(!guard.is_attached());
    assert!(guard.try_attach().is_ok());
}