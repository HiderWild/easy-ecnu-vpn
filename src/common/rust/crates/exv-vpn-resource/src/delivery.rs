// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// §7.4 (L1210-1213): per-connection single-unacknowledged ownership-token delivery slot.
// Each connection holds at most one unacknowledged ownership token at a time. After that token is
// ACKed or the connection is terminated, the slot resolves and no token is ever re-sent.

use std::collections::HashMap;
use std::ops::Deref;

use exv_vpn_domain::identity::{
    OperationLookupKey, OwnershipVersion, RequestDigest, TokenDigest,
};

use crate::authority::ConnectionBinding;

/// A borrowed held token.
///
/// Wraps `&TokenDigest` so a `Replayed` outcome can present the SAME held token (never a fresh
/// mint) while both dereferencing to the underlying digest (`**token`) and comparing equal to an
/// owned `TokenDigest` (`*token == digest`), which the delivery-seam test contract exercises.
/// `&TokenDigest` cannot compare equal to `TokenDigest` directly, and `TokenDigest` (frozen in the
/// domain crate) has no `Deref`; a local wrapper is the only Rust-legal way to satisfy both.
/// It must be `pub` because it appears in the public `DeliveryOutcome::Replayed` variant.
#[derive(Clone)]
pub struct HeldToken<'a>(&'a TokenDigest);

impl PartialEq for HeldToken<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for HeldToken<'_> {}

impl PartialEq<TokenDigest> for HeldToken<'_> {
    fn eq(&self, other: &TokenDigest) -> bool {
        self.0 == other
    }
}

impl Deref for HeldToken<'_> {
    type Target = TokenDigest;

    fn deref(&self) -> &TokenDigest {
        self.0
    }
}

impl<'a> HeldToken<'a> {
    #[must_use]
    fn new(token: &'a TokenDigest) -> Self {
        HeldToken(token)
    }
}

/// Outcome of attempting to deliver an ownership token to a connection slot.
///
/// NOTE: `TokenDigest`/`OperationLookupKey` have no `Debug`, so this enum derives only
/// `Clone, PartialEq, Eq`.
#[derive(Clone, PartialEq, Eq)]
pub enum DeliveryOutcome<'a> {
    /// The slot was empty; the candidate token is now held and issued once.
    Issued { token: TokenDigest },
    /// A same key+digest+version retry replays the SAME held token, never a new one.
    Replayed { token: HeldToken<'a> },
    /// A different acquire key is rejected while the slot is held.
    OtherKeyHeld,
    /// A new ownership version while one is pending must not mint a parallel token.
    VersionPending,
    /// A same-version retry with a different request digest is rejected.
    IdempotencyConflict,
    /// The slot is already resolved (ACKed/terminated); the token is never re-sent.
    AlreadyDelivered,
}

/// Outcome of acknowledging a held ownership token.
#[derive(Clone, PartialEq, Eq)]
pub enum AckOutcome {
    /// A fully matching ACK cleared the slot (now resolved).
    Cleared,
    /// The ACK carried mismatched credentials; the slot is retained.
    Mismatch,
    /// No holding slot exists for this connection.
    NoSlot,
}

/// Outcome of terminating a connection's delivery slot.
#[derive(Clone, PartialEq, Eq)]
pub enum TerminateOutcome {
    /// A held token was invalidated; it is never re-sent afterward.
    Invalidated {
        token: TokenDigest,
        ownership_version: OwnershipVersion,
    },
    /// Neither a holding nor a resolved slot was present.
    NothingHeld,
}

/// A single unacknowledged ownership token held for a connection.
#[derive(Clone, PartialEq, Eq)]
struct OwnershipTokenSlot {
    key: OperationLookupKey,
    request_digest: RequestDigest,
    ownership_version: OwnershipVersion,
    token: TokenDigest,
}

/// Per-connection delivery slot state.
#[derive(Clone, PartialEq, Eq)]
enum ConnectionSlot {
    /// A token is held and awaiting ACK.
    Holding(OwnershipTokenSlot),
    /// The token was `ACK`ed or the connection terminated; nothing is re-sent.
    Resolved {
        key: OperationLookupKey,
        ownership_version: OwnershipVersion,
    },
}

/// Per-connection single-unacknowledged ownership-token delivery (§7.4).
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipTokenDelivery {
    slots: HashMap<ConnectionBinding, ConnectionSlot>,
}

/// Request to deliver a candidate ownership token to a connection slot.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenDeliveryRequest {
    pub connection: ConnectionBinding,
    pub key: OperationLookupKey,
    pub request_digest: RequestDigest,
    pub ownership_version: OwnershipVersion,
    pub candidate_token: TokenDigest,
}

/// Request to acknowledge a held ownership token for a connection slot.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnershipTokenAck {
    pub connection: ConnectionBinding,
    pub key: OperationLookupKey,
    pub request_digest: RequestDigest,
    pub ownership_version: OwnershipVersion,
    pub token: TokenDigest,
}

impl OwnershipTokenDelivery {
    /// Create an empty delivery registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
        }
    }

    /// Attempt to deliver an ownership token to the connection's slot.
    ///
    /// Semantics:
    /// - No slot: insert a `Holding` slot and issue the candidate token once.
    /// - `Holding`: a same key+digest+version retry replays the SAME held token; a different
    ///   version is `VersionPending`; a different key is `OtherKeyHeld`; a different digest is
    ///   `IdempotencyConflict`.
    /// - `Resolved`: the token is never re-sent (`AlreadyDelivered`), subject to version/key guards.
    pub fn deliver(&mut self, request: TokenDeliveryRequest) -> DeliveryOutcome<'_> {
        // Empty slot: insert a new `Holding` slot and issue the candidate token exactly once.
        if !self.slots.contains_key(&request.connection) {
            let connection = request.connection;
            let candidate_token = request.candidate_token;
            self.slots.insert(
                connection,
                ConnectionSlot::Holding(OwnershipTokenSlot {
                    key: request.key,
                    request_digest: request.request_digest,
                    ownership_version: request.ownership_version,
                    token: candidate_token.clone(),
                }),
            );
            return DeliveryOutcome::Issued {
                token: candidate_token,
            };
        }

        // A slot already exists: the decision is purely read-only.
        match self.slots.get(&request.connection) {
            Some(ConnectionSlot::Holding(slot)) => {
                if slot.ownership_version != request.ownership_version {
                    DeliveryOutcome::VersionPending
                } else if slot.key != request.key {
                    DeliveryOutcome::OtherKeyHeld
                } else if slot.request_digest != request.request_digest {
                    DeliveryOutcome::IdempotencyConflict
                } else {
                    DeliveryOutcome::Replayed {
                        token: HeldToken::new(&slot.token),
                    }
                }
            }
            Some(ConnectionSlot::Resolved {
                key: rk,
                ownership_version: rv,
            }) => {
                if *rv != request.ownership_version {
                    DeliveryOutcome::VersionPending
                } else if *rk != request.key {
                    DeliveryOutcome::OtherKeyHeld
                } else {
                    DeliveryOutcome::AlreadyDelivered
                }
            }
            None => unreachable!("contains_key confirmed the slot exists"),
        }
    }

    /// Acknowledge a held ownership token.
    ///
    /// A fully matching ACK (connection + key + digest + version + token) clears the slot and
    /// returns `Cleared`. Any mismatch retains the slot and returns `Mismatch`. No holding slot
    /// yields `NoSlot`.
    pub fn ack(&mut self, request: OwnershipTokenAck) -> AckOutcome {
        let OwnershipTokenAck {
            connection,
            key,
            request_digest,
            ownership_version,
            token,
        } = request;
        match self.slots.get_mut(&connection) {
            None | Some(ConnectionSlot::Resolved { .. }) => AckOutcome::NoSlot,
            Some(slot_ref) => {
                let ConnectionSlot::Holding(slot) = slot_ref else {
                    unreachable!("Resolved handled above");
                };
                let matches = slot.ownership_version == ownership_version
                    && slot.key == key
                    && slot.request_digest == request_digest
                    && slot.token == token;
                if matches {
                    let key = slot.key.clone();
                    let ownership_version = slot.ownership_version;
                    *slot_ref = ConnectionSlot::Resolved {
                        key,
                        ownership_version,
                    };
                    AckOutcome::Cleared
                } else {
                    AckOutcome::Mismatch
                }
            }
        }
    }

    /// Terminate a connection's delivery slot.
    ///
    /// A `Holding` slot is transitioned to `Resolved` and its token invalidated (`Invalidated`).
    /// A `Resolved` slot or an absent slot yields `NothingHeld`.
    pub fn terminate_connection(&mut self, connection: &ConnectionBinding) -> TerminateOutcome {
        match self.slots.get_mut(connection) {
            None | Some(ConnectionSlot::Resolved { .. }) => TerminateOutcome::NothingHeld,
            Some(slot_ref) => {
                let ConnectionSlot::Holding(slot) = slot_ref else {
                    unreachable!("Resolved handled above");
                };
                let token = slot.token.clone();
                let ownership_version = slot.ownership_version;
                let key = slot.key.clone();
                *slot_ref = ConnectionSlot::Resolved {
                    key,
                    ownership_version,
                };
                TerminateOutcome::Invalidated {
                    token,
                    ownership_version,
                }
            }
        }
    }
}

impl Default for OwnershipTokenDelivery {
    fn default() -> Self {
        Self::new()
    }
}