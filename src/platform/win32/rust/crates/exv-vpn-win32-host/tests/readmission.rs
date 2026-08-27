// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// S1 admission 重开 + relay 重武装（win32 host 组合层）：断开收敛 → Stopped →
// controller 显式 ReopenAdmission → Idle/admission_open → 二次 Connect admitted →
// 二次 ProtocolEstablished → packet_attachment_active()==true（数据面证明重新成立）。
// 纯逻辑 + 确定性：只驱动 win32 host 组合（`compose_nonprivileged_host`，纯构造，
// 唯一 native 读是进程 token elevation 事实）与 relay 每腿状态机，无真实 pipe/session
// I/O、无需提权。独立文件（不并入 W27-T 冻结集 `process_boundary.rs`）。

use exv_vpn_data_plane::teardown::TeardownSide;
use exv_vpn_domain::identity::{ConnectionBindingDigest, OperationMethod, PrincipalDigest};
use exv_vpn_domain::ports::{AuthorityEpoch, MonotonicTick};
use exv_vpn_resource::authority::{
    ConnectionBinding, PeerCapability, PeerContext, VerifiedConnectionMetadata,
};
use exv_core::composition::{
    compose_nonprivileged_host, HostComposition, HostEffect, HostEvent, HostPhase,
};
use exv_vpn_win32_ipc::peer_auth::VerifiedPipePeer;

/// 确定性已验 helper peer（WSP1 §6：host 只对已验 helper 的 PID+SID 组合）。
fn helper_peer() -> VerifiedPipePeer {
    VerifiedPipePeer {
        process_id: 4242,
        user_sid: "S-1-5-21-3980489076-1253412212-3874560562-1002".to_string(),
        logon_sid: Some("S-1-5-5-0-323470".to_string()),
        account_name: "EXV VPN Helper".to_string(),
    }
}

/// 确定性 controller peer + capability（portable H80 测试同款构造，固定字面量）。
fn controller_peer_and_capability() -> (PeerContext, PeerCapability) {
    let principal = PrincipalDigest::try_from([0u8; 32]).unwrap();
    let binding = ConnectionBindingDigest::try_from([1u8; 32]).unwrap();
    let metadata =
        VerifiedConnectionMetadata::try_from((principal.clone(), binding.clone())).unwrap();
    let peer = PeerContext::try_from(metadata).unwrap();
    let connection = ConnectionBinding::try_from(binding).unwrap();
    let capability = PeerCapability::try_from((
        connection,
        principal,
        AuthorityEpoch::try_from(7u64).unwrap(),
        OperationMethod::Connect,
        MonotonicTick::try_from(42u64).unwrap(),
    ))
    .unwrap();
    (peer, capability)
}

/// 构造已绑定 controller peer/capability 并推进到 Connected 的组合。
fn connected_composition() -> (HostComposition, HostEffect) {
    let mut composition =
        compose_nonprivileged_host(&helper_peer()).expect("compose_nonprivileged_host");
    let (peer, capability) = controller_peer_and_capability();
    composition.bind_controller(peer, capability);
    let _ = composition.apply(HostEvent::Connect);
    let effect = composition.apply(HostEvent::ProtocolEstablished);
    (composition, effect)
}

// Kills '二次连接 packet_attachment_active() 恒 false'（问题 A relay 一次性闩锁）。
// 完整序列：stop → Stopped（teardown 拒绝 pin 保持）→ ReopenAdmission → Idle/
// admission_open → 二次 Connect admitted → 二次 ProtocolEstablished →
// packet_attachment_active()==true。
#[test]
fn reconnect_after_stopped_reopens_admission_and_revives_packet_attachment() {
    let (mut composition, effect) = connected_composition();
    assert_eq!(effect, HostEffect::Connected);
    assert!(
        composition.packet_attachment_active(),
        "首次连接后数据面证明成立"
    );

    // 断开：Stopping，admission 关闭，packet leg 撤销。
    assert_eq!(
        composition.apply(HostEvent::Disconnect),
        HostEffect::TeardownInitiated
    );
    assert_eq!(composition.phase(), HostPhase::Stopping);
    assert!(!composition.admission_open(), "断开即关闭 admission（pin）");
    assert!(
        !composition.packet_attachment_active(),
        "断开即撤销 packet leg"
    );

    // 双侧齐 → Stopped（Stopped pin 保持：admission 仍关闭）。
    let _ = composition.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl));
    assert_eq!(
        composition.apply(HostEvent::TeardownSideJoined(TeardownSide::PacketData)),
        HostEffect::Stopped
    );
    assert_eq!(composition.phase(), HostPhase::Stopped);
    assert!(!composition.admission_open(), "Stopped 下 admission 保持关闭");

    // controller 显式 ReopenAdmission → Idle + admission open。
    assert_eq!(
        composition.apply(HostEvent::ReopenAdmission),
        HostEffect::AdmissionReopened
    );
    assert_eq!(composition.phase(), HostPhase::Idle);
    assert!(composition.admission_open(), "admission 重开");

    // 二次连接：admitted（无重新绑定——D4 owner/lease 跨连接保持）→
    // ProtocolEstablished → packet_attachment_active()==true（relay 重武装）。
    assert_eq!(composition.apply(HostEvent::Connect), HostEffect::ConnectAdmitted);
    assert_eq!(composition.phase(), HostPhase::Connecting);
    assert_eq!(
        composition.apply(HostEvent::ProtocolEstablished),
        HostEffect::Connected
    );
    assert!(
        composition.packet_attachment_active(),
        "二次连接数据面证明必须重新成立（relay 重武装）"
    );
}

// Kills 'teardown 拒绝语义在 reopen 后丢失'（既存 pin 保留：ReopenAdmission 前拒绝，
// 之后 admitted；无重新绑定）。
#[test]
fn connect_refused_through_teardown_then_admitted_after_reopen() {
    let (mut composition, _) = connected_composition();

    // 断开进行中（Stopping）：Connect 拒绝。
    let _ = composition.apply(HostEvent::Disconnect);
    let _ = composition.apply(HostEvent::TeardownSideJoined(TeardownSide::ProtocolControl));
    assert_eq!(composition.phase(), HostPhase::Stopping);
    assert!(matches!(
        composition.apply(HostEvent::Connect),
        HostEffect::ConnectRefused(_)
    ));

    // 双侧齐 → Stopped：仍拒绝（admission 未重开）。
    let _ = composition.apply(HostEvent::TeardownSideJoined(TeardownSide::PacketData));
    assert_eq!(composition.phase(), HostPhase::Stopped);
    assert!(matches!(
        composition.apply(HostEvent::Connect),
        HostEffect::ConnectRefused(_)
    ));

    // ReopenAdmission 后：admitted（无重新绑定 controller —— D4）。
    let _ = composition.apply(HostEvent::ReopenAdmission);
    assert_eq!(composition.apply(HostEvent::Connect), HostEffect::ConnectAdmitted);
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
