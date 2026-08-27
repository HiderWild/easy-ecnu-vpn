// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// V20-I strict wire<->domain conversion. Every converter enforces the exact
// byte lengths of identity/digest fields and rejects any enum that decodes to
// its UNSPECIFIED=0 sentinel. Peer identity is ALWAYS the authenticated
// transport principal, never a client-supplied (self-reported) field. Secrets
// are moved into a buffer and the source is zeroized immediately. A transport
// / future cancel is never an in-connection business operation.

use crate::generated;
use exv_vpn_domain::identity::{
    EvidenceDigest, InventoryDigest, OperationId, OperationLookupKey, OperationMethod,
    PrincipalDigest, ResourceIdentityDigest, RuntimeEpoch,
};
use exv_vpn_domain::model::{CleanupProofRef, RuntimeState};
use exv_vpn_domain::ports::{Ipv4Route, TunnelIntentRef, TunnelPlan};
use std::net::Ipv4Addr;
use uuid::Uuid;
use zeroize::Zeroize;

// ---------------------------------------------------------------------------
// Operation method
// ---------------------------------------------------------------------------

/// Map a wire `OperationMethod` enum discriminant to the domain method.
/// UNSPECIFIED (=0) and any unknown discriminant are rejected.
pub fn operation_method_from_wire(method: i32) -> Result<OperationMethod, &'static str> {
    match method {
        1 => Ok(OperationMethod::Connect),
        2 => Ok(OperationMethod::RespondInteraction),
        3 => Ok(OperationMethod::Stop),
        4 => Ok(OperationMethod::Reconcile),
        5 => Ok(OperationMethod::AcquireLease),
        6 => Ok(OperationMethod::ApplyTunnel),
        7 => Ok(OperationMethod::StopTunnel),
        8 => Ok(OperationMethod::ReleaseLease),
        _ => Err("operation method: UNSPECIFIED or unknown"),
    }
}

// ---------------------------------------------------------------------------
// Operation lookup key
// ---------------------------------------------------------------------------

/// Build a domain `OperationLookupKey` from a wire key. The client-supplied
/// `principal_digest` field is validated for strictness (present, exact 32
/// bytes) but is NEVER used for identity: the lookup key's principal is the
/// authenticated transport principal passed in.
pub fn lookup_key_from_wire(
    wire: &generated::OperationLookupKey,
    authenticated_principal: PrincipalDigest,
) -> Result<OperationLookupKey, &'static str> {
    // Enforce the strict wire contract on the self-reported field ...
    let _self_reported = principal_digest_from_wire(&wire.principal_digest)?;
    // ... but derive identity solely from the authenticated principal.
    let method = operation_method_from_wire(wire.method)?;
    let runtime_epoch = runtime_epoch_from_wire(&wire.runtime_epoch)?;
    let operation_id = operation_id_from_wire(&wire.operation_id)?;

    OperationLookupKey::try_from((authenticated_principal, method, runtime_epoch, operation_id))
        .map_err(|_| "lookup key: invalid")
}

// ---------------------------------------------------------------------------
// Tunnel plan
// ---------------------------------------------------------------------------

/// Build a domain `TunnelPlan` from a wire plan. Rejects an IPv6 (non-4-byte)
/// tunnel offer, an MTU below the 576 minimum, and an IPv4 prefix over 32.
pub fn tunnel_plan_from_wire(plan: &generated::TunnelPlan) -> Result<TunnelPlan, &'static str> {
    let ipv4_address = ipv4_from_wire_bytes(&plan.ipv4_address)?;
    let ipv4_prefix_len =
        u8::try_from(plan.ipv4_prefix_len).map_err(|_| "tunnel plan: ipv4 prefix out of range")?;
    let mtu = u16::try_from(plan.mtu).map_err(|_| "tunnel plan: mtu out of range")?;

    if ipv4_prefix_len > 32 {
        return Err("tunnel plan: ipv4 prefix over 32");
    }
    if mtu < 576 {
        return Err("tunnel plan: mtu below minimum");
    }

    let ipv4_routes: Vec<Ipv4Route> = plan
        .ipv4_routes
        .iter()
        .map(ipv4_route_from_wire)
        .collect::<Result<_, _>>()?;
    let dns_servers: Vec<Ipv4Addr> = plan
        .dns_servers
        .iter()
        .map(|s| ipv4_from_wire_bytes(s))
        .collect::<Result<_, _>>()?;
    let control_bypass: Vec<Ipv4Addr> = plan
        .control_bypass
        .iter()
        .map(|s| ipv4_from_wire_bytes(s))
        .collect::<Result<_, _>>()?;

    let opaque_intent = match &plan.opaque_intent {
        Some(intent) => tunnel_intent_from_wire(intent)?,
        None => return Err("tunnel plan: missing opaque intent"),
    };

    TunnelPlan::try_from((
        ipv4_address,
        ipv4_prefix_len,
        mtu,
        ipv4_routes,
        dns_servers,
        control_bypass,
        opaque_intent,
    ))
    .map_err(|_| "tunnel plan: invalid")
}

// ---------------------------------------------------------------------------
// Runtime snapshot
// ---------------------------------------------------------------------------

/// Build a domain `RuntimeState` from a wire snapshot. Snapshots never carry
/// secret / native-handle / raw-cert material into the domain. The strict
/// converter rebuilds identity-bearing state only from an authenticated
/// principal; a bare snapshot carries none, so only the identity-free `Idle`
/// branch is convertible here.
pub fn snapshot_from_wire(snap: &generated::RuntimeSnapshot) -> Result<RuntimeState, &'static str> {
    match &snap.state {
        Some(generated::runtime_snapshot::State::Idle(idle)) => {
            let last_cleanup = match &idle.last_cleanup {
                Some(proof) => Some(cleanup_proof_ref_from_wire(proof)?),
                None => None,
            };
            Ok(RuntimeState::Idle { last_cleanup })
        }
        Some(generated::runtime_snapshot::State::Connecting(_)) => {
            Err("snapshot: connecting requires authenticated-principal context")
        }
        Some(generated::runtime_snapshot::State::AwaitingInteraction(_)) => {
            Err("snapshot: awaiting_interaction requires authenticated-principal context")
        }
        Some(generated::runtime_snapshot::State::Connected(_)) => {
            Err("snapshot: connected requires authenticated-principal context")
        }
        Some(generated::runtime_snapshot::State::Stopping(_)) => {
            Err("snapshot: stopping requires authenticated-principal context")
        }
        Some(generated::runtime_snapshot::State::Reconciling(_)) => {
            Err("snapshot: reconciling requires authenticated-principal context")
        }
        Some(generated::runtime_snapshot::State::FailedClean(_)) => {
            Err("snapshot: failed_clean requires authenticated-principal context")
        }
        Some(generated::runtime_snapshot::State::FailedDirty(_)) => {
            Err("snapshot: failed_dirty requires authenticated-principal context")
        }
        None => Err("snapshot: missing state"),
    }
}

// ---------------------------------------------------------------------------
// Secret admission
// ---------------------------------------------------------------------------

/// Admit a one-shot secret from a generated message: move the bytes into a
/// returned buffer and zeroize the source in place so the generated message
/// holds no secret residue.
pub fn admit_secret_from_wire(secret: &mut Vec<u8>) -> Vec<u8> {
    let admitted = secret.clone();
    secret.zeroize();
    admitted
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

/// A transport/future cancellation is never an in-connection business
/// operation; Stop is the only in-connection cancellation and future
/// cancellation must not be encoded as it, so this maps to `None`.
pub fn cancel_to_operation(_future_cancel: bool) -> Option<OperationMethod> {
    None
}

// ---------------------------------------------------------------------------
// Wire primitive helpers
// ---------------------------------------------------------------------------

fn uuid16(bytes: &[u8]) -> Result<Uuid, &'static str> {
    if bytes.len() != 16 {
        return Err("wire: expected 16-byte uuid");
    }
    Uuid::from_slice(bytes).map_err(|_| "wire: invalid uuid")
}

fn digest32(bytes: &[u8]) -> Result<[u8; 32], &'static str> {
    <[u8; 32]>::try_from(bytes).map_err(|_| "wire: expected 32-byte digest")
}

fn principal_digest_from_wire(bytes: &[u8]) -> Result<PrincipalDigest, &'static str> {
    PrincipalDigest::try_from(digest32(bytes)?).map_err(|_| "wire: invalid principal digest")
}

fn resource_identity_digest_from_wire(
    bytes: &[u8],
) -> Result<ResourceIdentityDigest, &'static str> {
    ResourceIdentityDigest::try_from(digest32(bytes)?)
        .map_err(|_| "wire: invalid resource identity digest")
}

fn inventory_digest_from_wire(bytes: &[u8]) -> Result<InventoryDigest, &'static str> {
    InventoryDigest::try_from(digest32(bytes)?).map_err(|_| "wire: invalid inventory digest")
}

fn evidence_digest_from_wire(bytes: &[u8]) -> Result<EvidenceDigest, &'static str> {
    EvidenceDigest::try_from(digest32(bytes)?).map_err(|_| "wire: invalid evidence digest")
}

fn runtime_epoch_from_wire(bytes: &[u8]) -> Result<RuntimeEpoch, &'static str> {
    RuntimeEpoch::try_from(uuid16(bytes)?).map_err(|_| "wire: nil runtime epoch")
}

fn operation_id_from_wire(bytes: &[u8]) -> Result<OperationId, &'static str> {
    OperationId::try_from(uuid16(bytes)?).map_err(|_| "wire: nil operation id")
}

fn cleanup_proof_ref_from_wire(w: &generated::CleanupProofRef) -> Result<CleanupProofRef, &'static str> {
    let canonical_inventory_digest = inventory_digest_from_wire(&w.canonical_inventory_digest)?;
    let platform_evidence_digest = evidence_digest_from_wire(&w.platform_evidence_digest)?;
    CleanupProofRef::try_from((canonical_inventory_digest, platform_evidence_digest))
        .map_err(|_| "wire: invalid cleanup proof ref")
}

fn ipv4_from_wire_bytes(bytes: &[u8]) -> Result<Ipv4Addr, &'static str> {
    let arr: [u8; 4] =
        <[u8; 4]>::try_from(bytes).map_err(|_| "wire: expected 4-byte IPv4 address")?;
    Ok(Ipv4Addr::from(arr))
}

fn ipv4_route_from_wire(w: &generated::Ipv4Route) -> Result<Ipv4Route, &'static str> {
    let network = ipv4_from_wire_bytes(&w.network)?;
    let prefix_len = u8::try_from(w.prefix_len).map_err(|_| "route: prefix out of range")?;
    if prefix_len > 32 {
        return Err("route: prefix over 32");
    }
    Ok(Ipv4Route { network, prefix_len })
}

fn tunnel_intent_from_wire(w: &generated::TunnelIntentRef) -> Result<TunnelIntentRef, &'static str> {
    TunnelIntentRef::try_from(resource_identity_digest_from_wire(&w.identity_digest)?)
        .map_err(|_| "wire: invalid tunnel intent ref")
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。