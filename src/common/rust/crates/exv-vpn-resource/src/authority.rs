// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

use exv_vpn_domain::identity::{ConnectionBindingDigest, OperationMethod, PrincipalDigest};
use exv_vpn_domain::ports::{AuthorityEpoch, MonotonicTick};
use serde::Serialize;
use std::fmt;

/// A verified transport-layer connection binding, anchored to the connection digest only.
/// The endpoint name/path is never a capability (§9.4).
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ConnectionBinding(ConnectionBindingDigest);

impl fmt::Debug for ConnectionBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionBinding").finish_non_exhaustive()
    }
}

impl TryFrom<ConnectionBindingDigest> for ConnectionBinding {
    type Error = &'static str;

    fn try_from(digest: ConnectionBindingDigest) -> Result<Self, Self::Error> {
        Ok(ConnectionBinding(digest))
    }
}

/// Authenticated transport metadata: the verified principal plus its connection binding.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct VerifiedConnectionMetadata {
    principal: PrincipalDigest,
    connection: ConnectionBinding,
}

impl fmt::Debug for VerifiedConnectionMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedConnectionMetadata")
            .finish_non_exhaustive()
    }
}

impl TryFrom<(PrincipalDigest, ConnectionBindingDigest)> for VerifiedConnectionMetadata {
    type Error = &'static str;

    fn try_from((principal, connection): (PrincipalDigest, ConnectionBindingDigest)) -> Result<Self, Self::Error> {
        let connection = ConnectionBinding::try_from(connection)?;
        Ok(VerifiedConnectionMetadata {
            principal,
            connection,
        })
    }
}

/// A peer context carrying the authenticated principal and its connection binding.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PeerContext {
    principal: PrincipalDigest,
    connection: ConnectionBinding,
}

impl fmt::Debug for PeerContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerContext").finish_non_exhaustive()
    }
}

impl TryFrom<VerifiedConnectionMetadata> for PeerContext {
    type Error = &'static str;

    fn try_from(metadata: VerifiedConnectionMetadata) -> Result<Self, Self::Error> {
        Ok(PeerContext {
            principal: metadata.principal,
            connection: metadata.connection,
        })
    }
}

impl PeerContext {
    /// The authenticated principal surfacing from this peer context.
    #[must_use]
    pub fn principal(&self) -> &PrincipalDigest {
        &self.principal
    }

    /// The verified connection binding anchoring this peer context.
    #[must_use]
    pub fn connection(&self) -> &ConnectionBinding {
        &self.connection
    }

    /// A peer-provided principal verifies only if it matches the authenticated one.
    #[must_use]
    pub fn verify_declared_principal(&self, declared: &PrincipalDigest) -> bool {
        self.principal == *declared
    }

    /// Bind a time-limited capability for the given operation under the given authority epoch.
    ///
    /// # Errors
    ///
    /// Returns an error if the capability cannot be bound from this peer context.
    pub fn bind_capability(
        &self,
        operation: OperationMethod,
        authority: AuthorityEpoch,
        expires_at: MonotonicTick,
    ) -> Result<PeerCapability, &'static str> {
        PeerCapability::try_from((
            self.connection.clone(),
            self.principal.clone(),
            authority,
            operation,
            expires_at,
        ))
    }
}

/// A time-limited, operation-scoped capability the peer may exercise on its connection.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PeerCapability {
    connection: ConnectionBinding,
    principal: PrincipalDigest,
    authority: AuthorityEpoch,
    operation: OperationMethod,
    expires_at: MonotonicTick,
}

impl fmt::Debug for PeerCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerCapability").finish_non_exhaustive()
    }
}

impl TryFrom<(ConnectionBinding, PrincipalDigest, AuthorityEpoch, OperationMethod, MonotonicTick)>
    for PeerCapability
{
    type Error = &'static str;

    fn try_from(
        (connection, principal, authority, operation, expires_at): (
            ConnectionBinding,
            PrincipalDigest,
            AuthorityEpoch,
            OperationMethod,
            MonotonicTick,
        ),
    ) -> Result<Self, Self::Error> {
        Ok(PeerCapability {
            connection,
            principal,
            authority,
            operation,
            expires_at,
        })
    }
}

impl PeerCapability {
    /// The connection binding this capability is anchored to.
    #[must_use]
    pub fn connection(&self) -> &ConnectionBinding {
        &self.connection
    }

    /// A capability forwards only to its own connection binding.
    #[must_use]
    pub fn can_forward_to(&self, other: &ConnectionBinding) -> bool {
        self.connection == *other
    }

    /// Whether the clock is strictly past the capability's expiry.
    #[must_use]
    pub fn is_expired_at(&self, now: MonotonicTick) -> bool {
        self.expires_at.exceeded_by(now)
    }

    /// Whether this capability authorizes the given request at the current tick.
    #[must_use]
    pub fn authorizes(
        &self,
        principal: &PrincipalDigest,
        connection: &ConnectionBinding,
        operation: OperationMethod,
        authority: AuthorityEpoch,
        now: MonotonicTick,
    ) -> bool {
        self.principal == *principal
            && self.connection == *connection
            && self.operation == operation
            && self.authority == authority
            && !self.is_expired_at(now)
    }
}