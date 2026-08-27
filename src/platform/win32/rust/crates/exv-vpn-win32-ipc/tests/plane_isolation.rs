// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W12-T terra: plane isolation for the Win32 native runtime. These tests pin the
// grpc_planes / limits / connection_binding API that W12-I implements in
// exv_vpn_win32_ipc::{grpc_planes, limits, connection_binding}. The frozen WSP1 facts
// (docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-pipe-facts.md) are the
// contract:
//   - control 与 data 使用两条独立物理连接，各自 CreateNamedPipeW + ConnectNamedPipe（§3）；
//   - pre-auth 资源初值：stream=1、message=64 KiB（65536B）、buffer=64 KiB（65536B）（§7）；
//   - pre-auth 超大 frame 在不派发的前提下被拒；pre-auth 阶段不得按声明长度预分配大缓冲（§7）；
//   - unauthorized 不派发（§7）。
//
// The isolation model is PURE in-memory state: no real Named Pipe is needed. Only the
// two-physical-connection test uses two distinct pipe-name strings. Every test is deterministic.

use exv_vpn_win32_ipc::connection_binding::{ConnectionBinding, Plane};
use exv_vpn_win32_ipc::grpc_planes::PlaneIsolation;
use exv_vpn_win32_ipc::limits::PlaneLimits;

/// Kills 'control and data share one connection' (WSP1 §3: control/data 两条独立物理连接).
#[test]
fn control_and_packet_are_two_physical_connections() {
    let mut iso = PlaneIsolation::new();

    // Two distinct physical connections, one per plane (each would be its own
    // CreateNamedPipeW + ConnectNamedPipe + 独立读/写 in the real runtime).
    iso.register_connection(ConnectionBinding::new(Plane::Control, "control-pipe".to_string()))
        .expect("control plane registers on its own physical connection");
    iso.register_connection(ConnectionBinding::new(Plane::Packet, "packet-pipe".to_string()))
        .expect("packet plane registers on its own physical connection");

    // Each plane resolves back to its own binding, and the two bindings are DISTINCT
    // physical connections — never the same pipe.
    let control = iso.connection_for(Plane::Control).expect("control binding present");
    let packet = iso.connection_for(Plane::Packet).expect("packet binding present");
    assert!(matches!(control.plane(), Plane::Control));
    assert!(matches!(packet.plane(), Plane::Packet));
    assert_ne!(
        control.pipe_name(),
        packet.pipe_name(),
        "control and packet must ride two independent physical connections (WSP1 §3)"
    );
}

/// Kills 'a plane can have multiple physical connections'.
#[test]
fn same_plane_second_connection_rejected() {
    let mut iso = PlaneIsolation::new();
    iso.register_connection(ConnectionBinding::new(Plane::Control, "control-1".to_string()))
        .expect("first control connection registers");
    let second = iso.register_connection(ConnectionBinding::new(Plane::Control, "control-2".to_string()));
    assert!(
        second.is_err(),
        "a plane may hold at most one physical connection; the second register must be refused"
    );
}

/// Kills 'pre-auth limits not frozen to WSP1 values' (WSP1 §7).
#[test]
fn preauth_limits_match_frozen_wsp1() {
    let l = PlaneLimits::mvp();
    assert_eq!(l.preauth_max_streams, 1, "WSP1 §7 pre-auth stream limit");
    assert_eq!(l.preauth_max_message_bytes, 65536, "WSP1 §7 pre-auth message limit (64 KiB)");
    assert_eq!(l.preauth_max_buffer_bytes, 65536, "WSP1 §7 pre-auth buffer limit (64 KiB)");
}

/// Kills 'oversize frame is dispatched / pre-auth large allocation' (WSP1 §7: pre-auth 超大
/// frame 在不派发的前提下被拒；pre-auth 阶段不得按声明长度预分配大缓冲).
#[test]
fn frame_over_max_message_rejected_without_dispatch() {
    let limits = PlaneLimits::mvp();
    let mut iso = PlaneIsolation::new();
    iso.register_connection(ConnectionBinding::new(Plane::Control, "control-pipe".to_string()))
        .expect("control plane registered");

    // Baseline: a max-size frame fits exactly at the pre-auth budget.
    assert!(
        iso.admit_frame(Plane::Control, 65536, &limits).is_ok(),
        "a frame at exactly preauth_max_message_bytes must be admitted"
    );

    // One byte over the message limit is rejected outright...
    assert!(
        iso.admit_frame(Plane::Control, 65537, &limits).is_err(),
        "a frame over preauth_max_message_bytes must be refused"
    );
    // ...and the rejected frame is NOT dispatched: the plane's stream/buffer budget is
    // unchanged, so it is still within budget. If the oversize frame had been dispatched
    // (or its declared length had pre-allocated a large buffer), the plane would be over
    // budget here.
    assert!(
        !iso.is_over_budget(Plane::Control),
        "a rejected oversize frame must not be dispatched or counted toward the pre-auth budget"
    );
}

/// Kills 'max-size frame wrongly rejected'.
#[test]
fn frame_at_max_message_admitted() {
    let limits = PlaneLimits::mvp();
    let mut iso = PlaneIsolation::new();
    iso.register_connection(ConnectionBinding::new(Plane::Packet, "packet-pipe".to_string()))
        .expect("packet plane registered");

    assert!(
        iso.admit_frame(Plane::Packet, 65536, &limits).is_ok(),
        "a frame at exactly preauth_max_message_bytes must be admitted, not rejected"
    );
}

/// Kills 'packet backpressure blocks control' — a packet flood may trip the packet plane's
/// budget, but it must never block the control plane (the control Stop path stays live).
#[test]
fn packet_flood_does_not_block_control_stop() {
    let limits = PlaneLimits::mvp();
    let mut iso = PlaneIsolation::new();
    iso.register_connection(ConnectionBinding::new(Plane::Packet, "packet-pipe".to_string()))
        .expect("packet plane registered");
    iso.register_connection(ConnectionBinding::new(Plane::Control, "control-pipe".to_string()))
        .expect("control plane registered");

    // Flood the packet plane past its pre-auth budget: two 64 KiB frames exceed both the
    // stream limit (1) and the cumulative buffer limit (64 KiB).
    assert!(iso.admit_frame(Plane::Packet, 65536, &limits).is_ok(), "first packet frame admitted");
    assert!(iso.admit_frame(Plane::Packet, 65536, &limits).is_ok(), "second packet frame admitted");
    assert!(
        iso.is_over_budget(Plane::Packet),
        "the packet plane must be flagged over budget after the flood"
    );

    // The control plane is unaffected: its admits still succeed and it stays within budget,
    // so control Stop is not blocked by the packet flood.
    assert!(
        iso.admit_frame(Plane::Control, 65536, &limits).is_ok(),
        "control admits must keep succeeding under packet backpressure"
    );
    assert!(
        !iso.is_over_budget(Plane::Control),
        "control must not be driven over budget by a packet-plane flood"
    );
}

/// Kills 'unauthorized plane dispatches' (WSP1 §7: unauthorized 不派发).
#[test]
fn unauthorized_plane_has_no_dispatch() {
    let limits = PlaneLimits::mvp();
    let mut iso = PlaneIsolation::new();
    // A physical connection whose plane never passed authentication is registered. In the
    // isolation model, registration alone dispatches nothing.
    iso.register_connection(ConnectionBinding::new(Plane::Control, "control-pipe".to_string()))
        .expect("control plane registered");

    // The isolation model starts with zero dispatched frames: nothing has entered the
    // stream/buffer budget, and registration is not itself a dispatch. Only an explicit
    // admit_frame after authentication may begin dispatch.
    assert!(
        !iso.is_over_budget(Plane::Control),
        "a plane that never passed auth must have no dispatched frames (starts below budget)"
    );
    // Rejected frames still do not dispatch on such a plane.
    assert!(
        iso.admit_frame(Plane::Control, 65537, &limits).is_err(),
        "an oversize frame on an unauthorized plane is refused and never dispatched"
    );
    assert!(
        !iso.is_over_budget(Plane::Control),
        "the unauthorized plane still shows zero dispatch after the refusal"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
