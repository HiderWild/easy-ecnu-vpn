// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Per-connection ownership lease manager (W15).
//!
//! Owns a J52 delivery slot plus the live per-connection lease handles. A lease is held from the
//! moment a token is issued until the token is acknowledged or the connection terminates; a held
//! lease exposes a monotonic expiry deadline, and an absent/resolved lease exposes none. A
//! restarted manager has no memory of prior tokens: a fresh issue requires a fresh auth path and
//! mints a fresh token.

use std::collections::HashMap;

use exv_vpn_domain::identity::{OperationLookupKey, OwnershipVersion, RequestDigest, TokenDigest};
use exv_vpn_domain::ports::MonotonicTick;
use exv_vpn_resource::authority::ConnectionBinding;
use exv_vpn_resource::delivery::{AckOutcome, DeliveryOutcome, TerminateOutcome};

use crate::token_slot::TokenSlot;

/// The per-connection ownership lease handle held while a token is live.
pub struct OwnerLease {
    /// The connection the lease anchors.
    connection: ConnectionBinding,
    /// The acquire lookup key the lease was minted under.
    key: OperationLookupKey,
    /// The request digest of the acquire that minted the lease.
    request_digest: RequestDigest,
    /// The ownership version the lease was issued at.
    ownership_version: OwnershipVersion,
    /// The held ownership token digest.
    token_digest: TokenDigest,
    /// The monotonic tick at which the lease expires.
    expiry_deadline: MonotonicTick,
}

/// Outcome of a lease issue attempt.
pub enum LeaseIssue {
    /// The slot was empty and the candidate token was issued exactly once.
    Issued { token_digest: TokenDigest },
    /// A same key+digest+version retry replayed the SAME held token, never a new one.
    SameTokenReplayed { token_digest: TokenDigest },
    /// The issue was refused: a different key, a pending version, a digest conflict, or a
    /// resolved/terminated slot.
    Refused,
}

/// The default lease lifetime in monotonic ticks, chosen well below `2^60` so any later production
/// tick exceeds it while an earlier tick never does.
const LEASE_EXPIRY_TICK: u64 = 1_000_000;

/// The default per-lease expiry deadline.
///
/// `TryFrom<u64>` for `MonotonicTick` is infallible, so the `expect` cannot fire.
fn default_deadline() -> MonotonicTick {
    MonotonicTick::try_from(LEASE_EXPIRY_TICK).expect("monotonic deadline tick mints")
}

/// Manages per-connection ownership leases over a shared J52 delivery slot.
#[derive(Default)]
pub struct OwnerLeaseManager {
    /// The J52 token delivery slot shared by all managed connections.
    slot: TokenSlot,
    /// The live lease handles keyed by connection binding.
    leases: HashMap<ConnectionBinding, OwnerLease>,
}

impl OwnerLeaseManager {
    /// Build a lease manager with an empty slot and no live leases.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slot: TokenSlot::new(),
            leases: HashMap::new(),
        }
    }

    /// Attempt to issue an ownership lease for the connection.
    ///
    /// An empty slot issues the candidate token once and records a monotonic expiry deadline. A
    /// same key+digest+version retry replays the SAME held token. Every other refusal maps to
    /// [`LeaseIssue::Refused`].
    pub fn issue(
        &mut self,
        connection: &ConnectionBinding,
        key: OperationLookupKey,
        request_digest: RequestDigest,
        ownership_version: OwnershipVersion,
        candidate: TokenDigest,
    ) -> LeaseIssue {
        let outcome = self.slot.put(
            connection.clone(),
            key.clone(),
            request_digest.clone(),
            ownership_version,
            candidate,
        );
        match outcome {
            DeliveryOutcome::Issued { token } => {
                self.leases.insert(
                    connection.clone(),
                    OwnerLease {
                        connection: connection.clone(),
                        key,
                        request_digest,
                        ownership_version,
                        token_digest: token.clone(),
                        expiry_deadline: default_deadline(),
                    },
                );
                LeaseIssue::Issued {
                    token_digest: token,
                }
            }
            DeliveryOutcome::Replayed { token } => LeaseIssue::SameTokenReplayed {
                token_digest: (*token).clone(),
            },
            _ => LeaseIssue::Refused,
        }
    }

    /// Acknowledge a held ownership token; only a fully matching ACK clears the slot.
    pub fn ack(
        &mut self,
        connection: &ConnectionBinding,
        key: OperationLookupKey,
        request_digest: RequestDigest,
        ownership_version: OwnershipVersion,
        token: TokenDigest,
    ) -> AckOutcome {
        let outcome =
            self.slot
                .ack(connection.clone(), key, request_digest, ownership_version, token);
        if outcome == AckOutcome::Cleared {
            self.leases.remove(connection);
        }
        outcome
    }

    /// Terminate the connection, immediately invalidating any held token and retiring the lease.
    pub fn terminate_connection(&mut self, connection: &ConnectionBinding) -> TerminateOutcome {
        let outcome = self.slot.clear(connection);
        if matches!(outcome, TerminateOutcome::Invalidated { .. }) {
            self.leases.remove(connection);
        }
        outcome
    }

    /// The live lease handle for the connection, if one is held.
    #[must_use]
    pub fn lease(&self, connection: &ConnectionBinding) -> Option<&OwnerLease> {
        self.leases.get(connection)
    }

    /// The monotonic expiry deadline of a held lease, or none for an absent lease.
    #[must_use]
    pub fn expiry_deadline(&self, connection: &ConnectionBinding) -> Option<MonotonicTick> {
        self.leases
            .get(connection)
            .map(|lease| lease.expiry_deadline)
    }
}

impl OwnerLease {
    /// The connection the lease anchors.
    #[must_use]
    pub fn connection(&self) -> &ConnectionBinding {
        &self.connection
    }

    /// The acquire lookup key the lease was minted under.
    #[must_use]
    pub fn key(&self) -> &OperationLookupKey {
        &self.key
    }

    /// The request digest of the acquire that minted the lease.
    #[must_use]
    pub fn request_digest(&self) -> &RequestDigest {
        &self.request_digest
    }

    /// The ownership version the lease was issued at.
    #[must_use]
    pub fn ownership_version(&self) -> OwnershipVersion {
        self.ownership_version
    }

    /// The held ownership token digest.
    #[must_use]
    pub fn token_digest(&self) -> &TokenDigest {
        &self.token_digest
    }

    /// The monotonic tick at which the lease expires.
    #[must_use]
    pub fn expiry_deadline(&self) -> MonotonicTick {
        self.expiry_deadline
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
