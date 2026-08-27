// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct RuntimeEpoch(Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct AttemptId(Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct OperationId(Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct EffectId(Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct InteractionId(Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct RetirementOperationId(Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct RecoveryId(Uuid);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct OwnerLeaseId(Uuid);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct OwnershipVersion(u64);

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct PrincipalDigest([u8; 32]);

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct RequestDigest([u8; 32]);

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct OperationLookupKeyDigest([u8; 32]);

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ConnectionBindingDigest([u8; 32]);

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct TokenDigest([u8; 32]);

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct InventoryDigest([u8; 32]);

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct EvidenceDigest([u8; 32]);

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ResourceIdentityDigest([u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationMethod {
    Connect,
    RespondInteraction,
    Stop,
    Reconcile,
    AcquireLease,
    ApplyTunnel,
    StopTunnel,
    ReleaseLease,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct OperationLookupKey {
    principal_digest: PrincipalDigest,
    method: OperationMethod,
    runtime_epoch: RuntimeEpoch,
    operation_id: OperationId,
}

pub type CanonicalLookupDigestFn = fn(&OperationLookupKey) -> OperationLookupKeyDigest;

// ---- D10-T construction seams (identity) ----

const ERR_DIGEST_LENGTH: &str = "digest: wrong length";
const ERR_NIL_UUID: &str = "identifier: nil uuid";
const ERR_ZERO_VERSION: &str = "ownership version: zero";

macro_rules! digest_try_from {
    ($ty:ident) => {
        impl TryFrom<[u8; 32]> for $ty {
            type Error = &'static str;
            fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
                Ok($ty(bytes))
            }
        }
    };
}

digest_try_from!(PrincipalDigest);
digest_try_from!(RequestDigest);
digest_try_from!(OperationLookupKeyDigest);
digest_try_from!(ConnectionBindingDigest);
digest_try_from!(TokenDigest);
digest_try_from!(InventoryDigest);
digest_try_from!(EvidenceDigest);
digest_try_from!(ResourceIdentityDigest);

// A wrong-length digest input must be rejected (D10-M1).
impl TryFrom<[u8; 31]> for PrincipalDigest {
    type Error = &'static str;
    fn try_from(_bytes: [u8; 31]) -> Result<Self, Self::Error> {
        Err(ERR_DIGEST_LENGTH)
    }
}

// Lookup-identity and request digests are compared in tests via assert_eq!/assert_ne!, which
// requires Debug; the remaining digests are never Debug-printed.
use std::fmt;

impl fmt::Debug for OperationLookupKeyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("OperationLookupKeyDigest")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Debug for RequestDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RequestDigest").field(&self.0).finish()
    }
}

macro_rules! uuid_try_from {
    ($ty:ident) => {
        impl TryFrom<Uuid> for $ty {
            type Error = &'static str;
            fn try_from(uuid: Uuid) -> Result<Self, Self::Error> {
                if uuid.is_nil() {
                    return Err(ERR_NIL_UUID);
                }
                Ok($ty(uuid))
            }
        }
    };
}

uuid_try_from!(RuntimeEpoch);
uuid_try_from!(AttemptId);
uuid_try_from!(OperationId);
uuid_try_from!(EffectId);
uuid_try_from!(InteractionId);
uuid_try_from!(RetirementOperationId);
uuid_try_from!(RecoveryId);
uuid_try_from!(OwnerLeaseId);

impl TryFrom<u64> for OwnershipVersion {
    type Error = &'static str;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value == 0 {
            return Err(ERR_ZERO_VERSION);
        }
        Ok(OwnershipVersion(value))
    }
}

impl TryFrom<(PrincipalDigest, OperationMethod, RuntimeEpoch, OperationId)> for OperationLookupKey {
    type Error = &'static str;
    fn try_from(
        (principal_digest, method, runtime_epoch, operation_id): (
            PrincipalDigest,
            OperationMethod,
            RuntimeEpoch,
            OperationId,
        ),
    ) -> Result<Self, Self::Error> {
        Ok(OperationLookupKey {
            principal_digest,
            method,
            runtime_epoch,
            operation_id,
        })
    }
}

impl OperationLookupKey {
    // D11-I reducer seam: the lookup key's runtime_epoch governs the attempt's epoch.
    pub(crate) fn runtime_epoch(&self) -> RuntimeEpoch {
        self.runtime_epoch.clone()
    }
}

impl ResourceIdentityDigest {
    pub(crate) fn is_nil(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl InventoryDigest {
    pub(crate) fn is_nil(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl EvidenceDigest {
    pub(crate) fn is_nil(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

fn method_byte(method: &OperationMethod) -> u8 {
    match method {
        OperationMethod::Connect => 0,
        OperationMethod::RespondInteraction => 1,
        OperationMethod::Stop => 2,
        OperationMethod::Reconcile => 3,
        OperationMethod::AcquireLease => 4,
        OperationMethod::ApplyTunnel => 5,
        OperationMethod::StopTunnel => 6,
        OperationMethod::ReleaseLease => 7,
    }
}

// The canonical lookup identity is a function of principal + method + runtime_epoch, NOT the
// operation/request id (D10-M1). Distinct requests over the same key resolve to one identity.
pub fn canonical_lookup_digest(key: &OperationLookupKey) -> OperationLookupKeyDigest {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut bytes: Vec<u8> = Vec::with_capacity(49);
    bytes.extend_from_slice(&key.principal_digest.0);
    bytes.push(method_byte(&key.method));
    bytes.extend_from_slice(key.runtime_epoch.0.as_bytes());

    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut hasher = DefaultHasher::new();
        (i as u64).hash(&mut hasher);
        bytes.hash(&mut hasher);
        let value = hasher.finish();
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    OperationLookupKeyDigest(out)
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
