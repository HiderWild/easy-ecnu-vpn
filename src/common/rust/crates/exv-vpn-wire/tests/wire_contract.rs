// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// V20-T terra：strict wire<->domain conversion contract. These tests pin the
// conversion API that V20-I implements in `exv_vpn_wire::convert` (and the
// redaction seam in `exv_vpn_wire::redact`). Every test is written so the
// declared mutants are killed:
//   * accept enum 0                      -> rejects_unspecified_enum
//   * protobuf self-reported principal   -> operation_lookup_uses_authenticated_principal
//   * snapshot leaks password            -> snapshot_omits_secret_native_handle_and_raw_cert
//
// Deterministic only: no I/O, no sleep, no randomness.

use exv_vpn_domain::identity::canonical_lookup_digest;
use exv_vpn_domain::identity::{OperationMethod, PrincipalDigest};
use exv_vpn_domain::model::RuntimeState;
use exv_vpn_wire::convert;
use exv_vpn_wire::descriptor::FILE_DESCRIPTOR_SET;
use exv_vpn_wire::generated;
use exv_vpn_wire::redact;
use prost::Message;

#[test]
fn descriptor_has_exact_namespace_and_services() {
    let fds =
        prost_types::FileDescriptorSet::decode(FILE_DESCRIPTOR_SET).expect("descriptor set decodes");

    let services: Vec<&str> = fds
        .file
        .iter()
        .flat_map(|f| f.service.iter())
        .filter_map(|s| s.name.as_deref())
        .collect();

    assert!(
        fds.file.iter().any(|f| f.package.as_deref() == Some("exv.vpn.v1")),
        "descriptor must define the exv.vpn.v1 namespace"
    );
    assert!(services.contains(&"KernelControl"));
    assert!(services.contains(&"HelperControl"));
    assert!(services.contains(&"PacketRelay"));
    assert_eq!(services.len(), 3, "exactly the three canonical services");
}

#[test]
fn rejects_unspecified_enum() {
    assert!(
        convert::operation_method_from_wire(generated::OperationMethod::Unspecified as i32).is_err(),
        "UNSPECIFIED (=0) must be rejected by the strict converter"
    );
    assert_eq!(
        convert::operation_method_from_wire(generated::OperationMethod::Connect as i32),
        Ok(OperationMethod::Connect)
    );
}

#[test]
fn rejects_empty_identity() {
    let auth = PrincipalDigest::try_from([7u8; 32]).unwrap();
    let wire = generated::OperationLookupKey {
        principal_digest: Vec::new(), // empty principal identity
        method: generated::OperationMethod::Connect as i32,
        runtime_epoch: vec![1u8; 16],
        operation_id: vec![2u8; 16],
    };
    assert!(
        convert::lookup_key_from_wire(&wire, auth).is_err(),
        "empty identity must be rejected"
    );
}

#[test]
fn rejects_wrong_digest_size() {
    let auth = PrincipalDigest::try_from([7u8; 32]).unwrap();
    let wire = generated::OperationLookupKey {
        principal_digest: vec![9u8; 31], // 31 bytes, not the exact 32
        method: generated::OperationMethod::Connect as i32,
        runtime_epoch: vec![1u8; 16],
        operation_id: vec![2u8; 16],
    };
    assert!(
        convert::lookup_key_from_wire(&wire, auth).is_err(),
        "wrong principal digest size must be rejected"
    );
}

#[test]
fn rejects_ipv6_tunnel_offer() {
    let mut wire = generated::TunnelPlan::default();
    wire.ipv4_address = vec![0xfd; 16]; // 16-byte IPv6, not the 4-byte IPv4
    assert!(convert::tunnel_plan_from_wire(&wire).is_err(), "IPv6 tunnel offer rejected");
}

#[test]
fn rejects_out_of_range_mtu_and_prefix() {
    let mut low_mtu = generated::TunnelPlan::default();
    low_mtu.ipv4_address = vec![10, 0, 0, 1];
    low_mtu.mtu = 500; // below the 576 minimum
    assert!(
        convert::tunnel_plan_from_wire(&low_mtu).is_err(),
        "sub-minimum MTU must be rejected"
    );

    let mut wide_prefix = generated::TunnelPlan::default();
    wide_prefix.ipv4_address = vec![10, 0, 0, 1];
    wide_prefix.ipv4_prefix_len = 40; // > 32
    assert!(
        convert::tunnel_plan_from_wire(&wide_prefix).is_err(),
        "IPv4 prefix over 32 must be rejected"
    );
}

#[test]
fn operation_lookup_uses_authenticated_principal() {
    let auth = PrincipalDigest::try_from([7u8; 32]).unwrap();
    let epoch = vec![1u8; 16];
    let operation = vec![2u8; 16];

    // Two wire keys that differ ONLY in their self-reported principal field.
    let mk = |self_reported: u8| generated::OperationLookupKey {
        principal_digest: vec![self_reported; 32],
        method: generated::OperationMethod::Connect as i32,
        runtime_epoch: epoch.clone(),
        operation_id: operation.clone(),
    };

    let a = convert::lookup_key_from_wire(&mk(9), auth.clone()).unwrap();
    let b = convert::lookup_key_from_wire(&mk(10), auth.clone()).unwrap();

    // Identity is a function of the AUTHENTICATED principal + method + epoch,
    // never of a client-supplied (self-reported) principal field.
    assert_eq!(
        canonical_lookup_digest(&a),
        canonical_lookup_digest(&b),
        "lookup identity must derive from the authenticated principal, not a client field"
    );
}

#[test]
fn snapshot_omits_secret_native_handle_and_raw_cert() {
    // A snapshot converts to a domain state that carries no secret-bearing fields.
    let mut snap = generated::RuntimeSnapshot::default();
    snap.state = Some(generated::runtime_snapshot::State::Idle(generated::IdleState::default()));
    let state = convert::snapshot_from_wire(&snap).expect("valid snapshot converts");
    assert!(matches!(state, RuntimeState::Idle { last_cleanup: None }));

    // Redaction must never leak secret / native-handle / raw-cert material
    // into a snapshot/event rendering.
    let secret = b"hunter2 SECRET native-handle=0xfd12 raw-cert";
    let rendered = redact::redact_secret(secret);
    assert!(!rendered.contains("hunter2"), "snapshot must not leak a password/secret");
    assert!(!rendered.contains("native-handle"), "snapshot must not leak a native handle");
    assert!(!rendered.contains("raw-cert"), "snapshot must not leak a raw certificate");
}

#[test]
fn generated_secret_is_zeroized_after_conversion() {
    let mut req = generated::ConnectRequest {
        intent: None,
        secret_payload: vec![0xABu8; 16],
    };

    let admitted = convert::admit_secret_from_wire(&mut req.secret_payload);
    assert_eq!(admitted, vec![0xABu8; 16], "secret is moved into a buffer");
    assert!(
        req.secret_payload.iter().all(|&b| b == 0),
        "source generated secret must be zeroized after conversion"
    );
}

#[test]
fn transport_cancel_is_not_encoded_as_stop() {
    let encoded = convert::cancel_to_operation(true);
    assert!(
        encoded.is_none(),
        "a transport/future cancel is not represented as an in-connection operation"
    );
    assert_ne!(encoded, Some(OperationMethod::Stop));
}