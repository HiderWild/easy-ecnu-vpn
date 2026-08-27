// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Per-connection single-unacknowledged ownership-token delivery slot (J52, W15).
//!
//! A thin Win32 seam over `exv_vpn_resource::delivery::OwnershipTokenDelivery`: it exposes the
//! deliver/ack/terminate lifecycle without leaking the J52 model. Each connection holds at most one
//! unacknowledged token; after the token is acknowledged or the connection terminates, the slot
//! resolves and no token is ever re-sent.

use exv_vpn_domain::identity::{OperationLookupKey, OwnershipVersion, RequestDigest, TokenDigest};
use exv_vpn_resource::authority::ConnectionBinding;
use exv_vpn_resource::delivery::{
    AckOutcome, DeliveryOutcome, OwnershipTokenAck, OwnershipTokenDelivery, TerminateOutcome,
    TokenDeliveryRequest,
};

/// The per-connection ownership-token delivery slot.
#[derive(Default)]
pub struct TokenSlot {
    /// The J52 single-unacknowledged-token delivery registry backing this slot.
    inner: OwnershipTokenDelivery,
}

impl TokenSlot {
    /// Build an empty delivery slot.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: OwnershipTokenDelivery::new(),
        }
    }

    /// Attempt to deliver a candidate ownership token to the connection slot.
    ///
    /// Delegates to the J52 `OwnershipTokenDelivery::deliver`: an empty slot issues the candidate
    /// exactly once; a same key+digest+version retry replays the SAME held token; a different key,
    /// version, or digest, or a resolved slot, refuses the delivery.
    pub fn put(
        &mut self,
        connection: ConnectionBinding,
        key: OperationLookupKey,
        request_digest: RequestDigest,
        ownership_version: OwnershipVersion,
        token: TokenDigest,
    ) -> DeliveryOutcome<'_> {
        self.inner.deliver(TokenDeliveryRequest {
            connection,
            key,
            request_digest,
            ownership_version,
            candidate_token: token,
        })
    }

    /// Acknowledge a held ownership token; only a fully matching ACK clears the slot.
    pub fn ack(
        &mut self,
        connection: ConnectionBinding,
        key: OperationLookupKey,
        request_digest: RequestDigest,
        ownership_version: OwnershipVersion,
        token: TokenDigest,
    ) -> AckOutcome {
        self.inner.ack(OwnershipTokenAck {
            connection,
            key,
            request_digest,
            ownership_version,
            token,
        })
    }

    /// Terminate the connection's slot, immediately invalidating any held token.
    pub fn clear(&mut self, connection: &ConnectionBinding) -> TerminateOutcome {
        self.inner.terminate_connection(connection)
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
