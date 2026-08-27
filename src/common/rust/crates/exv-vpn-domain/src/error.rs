// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

use crate::identity::{
    AttemptId, EffectId, OperationLookupKey, RecoveryId, ResourceIdentityDigest,
    RetirementOperationId, RuntimeEpoch,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    InvalidInput,
    IdempotencyConflict,
    ConnectInProgress,
    SessionBusy,
    ReconnectAlreadyQueued,
    CancelledBeforeStart,
    AuthorityAlreadyHeld,
    OwnershipAcquisitionPending,
    ObservedConflict,
    JournalCorrupt,
    DataPlaneBackpressure,
    PacketLeaseAlreadyAttached,
    EffectUnknown,
    ObservationFailed,
    Unauthorized,
    DeadlineExceeded,
    ActiveAttemptCannotReconcile,
    ActiveSessionCannotReconcile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorStage {
    Ingress,
    Admission,
    ObservingOwnedState,
    AcquiringPlatformLease,
    ConnectingControl,
    AwaitingInteraction,
    NegotiatingTunnel,
    ApplyingPlatformTunnel,
    AttachingPacketBoundary,
    StartingDataPlane,
    ProtocolSession,
    DataPlane,
    Teardown,
    Recovery,
    Journal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EffectCertainty {
    NoEffect,
    Applied,
    Partial,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RetryAdvice {
    DoNotRetry,
    RetrySameOperation,
    UseNewOperation,
    Reconcile,
    RestartProcess,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum ErrorSubject {
    External(OperationLookupKey),
    Attempt {
        runtime_epoch: RuntimeEpoch,
        attempt_id: AttemptId,
    },
    Effect {
        runtime_epoch: RuntimeEpoch,
        attempt_id: AttemptId,
        effect_id: EffectId,
    },
    Retirement(RetirementOperationId),
    Recovery(RecoveryId),
    Runtime(RuntimeEpoch),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceKind {
    Runtime,
    ProtocolSession,
    PlatformOwnership,
    PacketDevice,
    NetworkAddress,
    Mtu,
    RouteSet,
    Dns,
    ControlBypass,
    NetworkSettings,
    PacketLease,
    Journal,
    CleanupProof,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct OpaqueResourceRef {
    kind: ResourceKind,
    identity_digest: ResourceIdentityDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NativeErrorCategory {
    Permission,
    Transport,
    Protocol,
    Resource,
    Storage,
    Observation,
    Unsupported,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NativeErrorNamespace {
    Win32,
    HResult,
    NtStatus,
    PosixErrno,
    AppleOsStatus,
    AppleMach,
    AppleNetworkExtension,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NativeErrorCode(i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RedactedNativeError {
    category: NativeErrorCategory,
    namespace: NativeErrorNamespace,
    code: NativeErrorCode,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct VpnError {
    code: ErrorCode,
    stage: ErrorStage,
    certainty: EffectCertainty,
    retry: RetryAdvice,
    subject: ErrorSubject,
    resource: Option<OpaqueResourceRef>,
    native: Option<RedactedNativeError>,
}

pub type VpnErrorAccessorFn = for<'a> fn(
    &'a VpnError,
) -> (
    &'a ErrorCode,
    &'a ErrorStage,
    &'a EffectCertainty,
    &'a RetryAdvice,
    &'a ErrorSubject,
    Option<&'a OpaqueResourceRef>,
    Option<&'a RedactedNativeError>,
);

// ---- D10-T construction seams (error) ----

use std::fmt;

impl TryFrom<(ResourceKind, ResourceIdentityDigest)> for OpaqueResourceRef {
    type Error = &'static str;
    fn try_from(
        (kind, identity_digest): (ResourceKind, ResourceIdentityDigest),
    ) -> Result<Self, Self::Error> {
        if identity_digest.is_nil() {
            return Err("opaque resource ref: nil identity");
        }
        Ok(OpaqueResourceRef {
            kind,
            identity_digest,
        })
    }
}

impl TryFrom<(NativeErrorCategory, NativeErrorNamespace, NativeErrorCode)> for RedactedNativeError {
    type Error = &'static str;
    fn try_from(
        (category, namespace, code): (NativeErrorCategory, NativeErrorNamespace, NativeErrorCode),
    ) -> Result<Self, Self::Error> {
        Ok(RedactedNativeError {
            category,
            namespace,
            code,
        })
    }
}

impl
    TryFrom<(
        ErrorCode,
        ErrorStage,
        EffectCertainty,
        RetryAdvice,
        ErrorSubject,
        Option<OpaqueResourceRef>,
        Option<RedactedNativeError>,
    )> for VpnError
{
    type Error = &'static str;
    fn try_from(
        (code, stage, certainty, retry, subject, resource, native): (
            ErrorCode,
            ErrorStage,
            EffectCertainty,
            RetryAdvice,
            ErrorSubject,
            Option<OpaqueResourceRef>,
            Option<RedactedNativeError>,
        ),
    ) -> Result<Self, Self::Error> {
        Ok(VpnError {
            code,
            stage,
            certainty,
            retry,
            subject,
            resource,
            native,
        })
    }
}

impl VpnError {
    /// The typed error code, for match-based classification. Exposes only the code — never
    /// secret, native, or resource payloads.
    pub fn code(&self) -> &ErrorCode {
        &self.code
    }
}

// A Debug wrapper that renders sensitive payloads as opaque "<redacted>" so that native/secret
// text (uuids, resource identity digests, native error details) never leaks into Debug output
// (D10-M2).
struct Redacted<T>(T);

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl fmt::Debug for VpnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VpnError")
            .field("code", &self.code)
            .field("stage", &self.stage)
            .field("certainty", &self.certainty)
            .field("retry", &self.retry)
            .field("subject", &Redacted(&self.subject))
            .field("resource", &Redacted(&self.resource))
            .field("native", &Redacted(&self.native))
            .finish()
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
