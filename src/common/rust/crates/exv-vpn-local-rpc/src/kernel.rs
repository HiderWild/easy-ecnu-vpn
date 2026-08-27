// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

use exv_vpn_domain::identity::{OperationLookupKey, OperationMethod, RequestDigest};
use exv_vpn_domain::ports::{AuthorityEpoch, MonotonicTick};
use exv_vpn_resource::authority::{PeerCapability, PeerContext};
use exv_vpn_wire::convert;
use exv_vpn_wire::generated;

/// A wire kernel request awaiting binding to a domain operation.
///
/// The request carries the self-reported wire lookup key plus the caller's
/// expected domain method. Identity is never derived from the self-reported
/// wire principal; it is a function of the authenticated peer principal only.
pub struct KernelRequest {
    wire_key: generated::OperationLookupKey,
    request_digest: Vec<u8>,
    expected_method: OperationMethod,
}

impl KernelRequest {
    /// Construct a kernel request from its wire key, caller-supplied digest, and expected method.
    #[must_use]
    pub fn new(
        wire_key: generated::OperationLookupKey,
        request_digest: Vec<u8>,
        expected_method: OperationMethod,
    ) -> Self {
        Self {
            wire_key,
            request_digest,
            expected_method,
        }
    }
}

/// A kernel request bound to a domain operation.
///
/// `lookup_key` carries the operation identity anchored to the authenticated
/// peer principal; `request_digest` is the caller-supplied bound digest.
#[derive(Clone, PartialEq, Eq)]
pub struct BoundKernelOperation {
    pub lookup_key: OperationLookupKey,
    pub request_digest: RequestDigest,
}

/// Bind a wire kernel request to a domain operation under the given authority.
///
/// The operation identity derives from the AUTHENTICATED peer principal only:
/// the self-reported wire principal is validated for strictness by the wire
/// converter but never used for identity. Out-of-scope methods, capabilities
/// that do not authorize the request, authority-epoch mismatches, and expired
/// capabilities are all rejected.
///
/// # Errors
///
/// Returns an error if the digest is malformed, the wire method/lookup key is
/// invalid, the operation is out of scope, or the capability does not
/// authorize the request.
pub fn kernel_request_to_operation(
    request: &KernelRequest,
    peer: &PeerContext,
    capability: &PeerCapability,
    authority: AuthorityEpoch,
    now: MonotonicTick,
) -> Result<BoundKernelOperation, &'static str> {
    // 1. Strict request digest: exactly 32 bytes, then a valid domain digest.
    let digest_bytes =
        <[u8; 32]>::try_from(request.request_digest.as_slice())
            .map_err(|_| "kernel: request digest: expected 32 bytes")?;
    let request_digest =
        RequestDigest::try_from(digest_bytes).map_err(|_| "kernel: request digest: invalid")?;

    // 2. Operation identity from the AUTHENTICATED peer principal only.
    let method = convert::operation_method_from_wire(request.wire_key.method)
        .map_err(|_| "kernel: operation method: invalid")?;
    let lookup_key = convert::lookup_key_from_wire(&request.wire_key, peer.principal().clone())
        .map_err(|_| "kernel: lookup key: invalid")?;

    // 3. Out-of-scope: the wire method must match the expected domain method.
    if method != request.expected_method {
        return Err("kernel: operation: out of scope");
    }

    // 4. Capability admission: the peer must be authorized for this operation.
    if !capability.authorizes(
        peer.principal(),
        peer.connection(),
        method,
        authority,
        now,
    ) {
        return Err("kernel: not authorized by peer capability");
    }

    // 5. Bound operation.
    Ok(BoundKernelOperation {
        lookup_key,
        request_digest,
    })
}