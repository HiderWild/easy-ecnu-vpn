// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Durable admission records + codec (Architecture spec §7.2).
//!
//! An admission is a single self-contained durable record that seals the mutation kind, the
//! journal operation identity, the effect, the canonical input digest, the admission watermark,
//! the ownership version, the authorization subject, and the pre/post condition fingerprints under
//! a fixed on-disk version. `encode_record`/`decode_record` round-trip these records through the
//! journal's payload channel.
//!
//! The domain types embedded by these records are Serialize-only by design (spec §7.4 derive
//! inventory), so `decode_record` reconstructs them manually from a `serde_json::Value` via their
//! existing `TryFrom` construction seams rather than deriving `Deserialize` on them.

use exv_vpn_domain::error::{
    EffectCertainty, ErrorCode, ErrorStage, ErrorSubject, OpaqueResourceRef, RedactedNativeError,
    ResourceKind, RetryAdvice, VpnError,
};
use exv_vpn_domain::identity::{
    AttemptId, EffectId, OperationId, OperationLookupKey, OperationMethod, OwnershipVersion,
    PrincipalDigest, RecoveryId, RequestDigest, ResourceIdentityDigest, RetirementOperationId,
    RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CanonicalInputDigest,
    JournalOperationIdentity, JournalRevision, PlatformAuthorityInstanceId, RejectionReason,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The kind of mutation being admitted.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MutationKind {
    /// An externally initiated mutation (e.g. Connect/Stop/Reconcile).
    External(OperationMethod),
    /// A retirement-driven mutation.
    Retirement,
}

/// Who authorizes this admission.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub enum AuthorizationSubject {
    /// The live ownership token presented by the current owner.
    LiveOwnershipTokenDigest(TokenDigest),
    /// A recovery authority tied to a retirement operation.
    RecoveryAuthority(RetirementOperationId),
}

/// The applied fingerprint of the resource at the precondition (pre-image) of the mutation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppliedFingerprint([u8; 32]);

impl TryFrom<[u8; 32]> for AppliedFingerprint {
    type Error = &'static str;
    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        Ok(AppliedFingerprint(bytes))
    }
}

/// The canonical obligation seed that the mutation binds to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObligationSeed([u8; 32]);

impl TryFrom<[u8; 32]> for ObligationSeed {
    type Error = &'static str;
    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        Ok(ObligationSeed(bytes))
    }
}

/// A mutation that was admitted and sealed as a single durable record.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct MutationAdmitted {
    pub mutation_kind: MutationKind,
    pub journal_operation_identity: JournalOperationIdentity,
    pub effect_id: EffectId,
    pub canonical_input_digest: CanonicalInputDigest,
    pub initiator_identity_digest: PrincipalDigest,
    pub authority_epoch: AuthorityEpoch,
    pub platform_authority_instance_id: PlatformAuthorityInstanceId,
    pub admission_watermark: AdmissionWatermark,
    pub ownership_version: OwnershipVersion,
    pub authorization_subject: AuthorizationSubject,
    pub resource_identity: ResourceIdentityDigest,
    pub precondition_fingerprint: AppliedFingerprint,
    pub desired_applied_fingerprint: AppliedFingerprint,
    pub canonical_obligation_seed: ObligationSeed,
}

/// A mutation that was rejected without effect.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct OperationRejected {
    pub lookup_key: OperationLookupKey,
    pub request_digest: RequestDigest,
    pub authority_epoch: AuthorityEpoch,
    pub rejection_reason: RejectionReason,
    pub admission_watermark: AdmissionWatermark,
}

/// An absence proof fence over a key that was observed with no owned state.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct OperationAbsentFence {
    pub lookup_key: OperationLookupKey,
    pub request_digest: RequestDigest,
    pub authority_epoch: AuthorityEpoch,
    pub admission_watermark: AdmissionWatermark,
}

/// A durable admission record variant.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub enum AdmissionRecord {
    Admitted(MutationAdmitted),
    Rejected(OperationRejected),
    AbsentFence(OperationAbsentFence),
}

/// Error reported by [`decode_record`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionCodecError {
    /// The leading version byte is not the supported admission record version.
    UnsupportedVersion,
    /// The payload is empty or does not deserialize to an admission record.
    Corrupt,
}

/// On-disk format version for admission records.
pub const ADMISSION_RECORD_VERSION: u8 = 1;

/// Encode an admission record: version byte then the JSON payload.
///
/// # Panics
///
/// Panics if the record fails to serialize. Every admission record type is infallibly
/// serializable, so this never fires in practice.
#[must_use]
pub fn encode_record(record: &AdmissionRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(1);
    out.push(ADMISSION_RECORD_VERSION);
    let json = serde_json::to_vec(record).expect("admission record serializes");
    out.extend_from_slice(&json);
    out
}

/// Decode an admission record from an [`encode_record`] payload.
///
/// # Errors
///
/// Returns [`AdmissionCodecError::UnsupportedVersion`] if the leading version byte is not the
/// supported admission record version, or [`AdmissionCodecError::Corrupt`] if the payload is empty
/// or fails to deserialize as an admission record.
pub fn decode_record(payload: &[u8]) -> Result<AdmissionRecord, AdmissionCodecError> {
    let Some((&version, rest)) = payload.split_first() else {
        return Err(AdmissionCodecError::Corrupt);
    };
    if version != ADMISSION_RECORD_VERSION {
        return Err(AdmissionCodecError::UnsupportedVersion);
    }
    let v: serde_json::Value =
        serde_json::from_slice(rest).map_err(|_| AdmissionCodecError::Corrupt)?;
    let obj = v.as_object().ok_or(AdmissionCodecError::Corrupt)?;
    if let Some(x) = obj.get("Admitted") {
        Ok(AdmissionRecord::Admitted(re_mutation_admitted(x)?))
    } else if let Some(x) = obj.get("Rejected") {
        Ok(AdmissionRecord::Rejected(re_operation_rejected(x)?))
    } else if let Some(x) = obj.get("AbsentFence") {
        Ok(AdmissionRecord::AbsentFence(re_operation_absent_fence(x)?))
    } else {
        Err(AdmissionCodecError::Corrupt)
    }
}

// ---- Value primitives ----

fn v_u64(v: &serde_json::Value) -> Result<u64, AdmissionCodecError> {
    v.as_u64().ok_or(AdmissionCodecError::Corrupt)
}

fn v_u8arr32(v: &serde_json::Value) -> Result<[u8; 32], AdmissionCodecError> {
    let arr = v.as_array().ok_or(AdmissionCodecError::Corrupt)?;
    let mut out = [0u8; 32];
    for (slot, item) in out.iter_mut().zip(arr.iter()) {
        *slot = item.as_u64().ok_or(AdmissionCodecError::Corrupt)? as u8;
    }
    Ok(out)
}

fn v_uuid(v: &serde_json::Value) -> Result<Uuid, AdmissionCodecError> {
    let s = v.as_str().ok_or(AdmissionCodecError::Corrupt)?;
    Uuid::parse_str(s).map_err(|_| AdmissionCodecError::Corrupt)
}

fn v_opt<'a>(
    v: &'a serde_json::Value,
    key: &str,
) -> Result<Option<&'a serde_json::Value>, AdmissionCodecError> {
    match v.get(key) {
        Some(serde_json::Value::Null) | None => Ok(None),
        Some(val) => Ok(Some(val)),
    }
}

// ---- Domain-type reconstructors (via existing TryFrom seams) ----

fn re_authority_epoch(v: &serde_json::Value) -> Result<AuthorityEpoch, AdmissionCodecError> {
    AuthorityEpoch::try_from(v_u64(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_platform_instance(
    v: &serde_json::Value,
) -> Result<PlatformAuthorityInstanceId, AdmissionCodecError> {
    PlatformAuthorityInstanceId::try_from(v_uuid(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_admission_watermark(v: &serde_json::Value) -> Result<AdmissionWatermark, AdmissionCodecError> {
    AdmissionWatermark::try_from(v_u64(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_journal_revision(v: &serde_json::Value) -> Result<JournalRevision, AdmissionCodecError> {
    JournalRevision::try_from(v_u64(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_ownership_version(v: &serde_json::Value) -> Result<OwnershipVersion, AdmissionCodecError> {
    OwnershipVersion::try_from(v_u64(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_digest<T: TryFrom<[u8; 32]>>(v: &serde_json::Value) -> Result<T, AdmissionCodecError> {
    T::try_from(v_u8arr32(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_effect_id(v: &serde_json::Value) -> Result<EffectId, AdmissionCodecError> {
    EffectId::try_from(v_uuid(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_retirement_id(v: &serde_json::Value) -> Result<RetirementOperationId, AdmissionCodecError> {
    RetirementOperationId::try_from(v_uuid(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_runtime_epoch(v: &serde_json::Value) -> Result<RuntimeEpoch, AdmissionCodecError> {
    RuntimeEpoch::try_from(v_uuid(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_operation_id(v: &serde_json::Value) -> Result<OperationId, AdmissionCodecError> {
    OperationId::try_from(v_uuid(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_attempt_id(v: &serde_json::Value) -> Result<AttemptId, AdmissionCodecError> {
    AttemptId::try_from(v_uuid(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_recovery_id(v: &serde_json::Value) -> Result<RecoveryId, AdmissionCodecError> {
    RecoveryId::try_from(v_uuid(v)?).map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_operation_lookup_key(v: &serde_json::Value) -> Result<OperationLookupKey, AdmissionCodecError> {
    let principal_digest = {
        let pd = v.get("principal_digest").ok_or(AdmissionCodecError::Corrupt)?;
        re_digest::<PrincipalDigest>(pd)?
    };
    let method: OperationMethod = {
        let m = v.get("method").ok_or(AdmissionCodecError::Corrupt)?;
        serde_json::from_value(m.clone()).map_err(|_| AdmissionCodecError::Corrupt)?
    };
    let runtime_epoch = {
        let re = v.get("runtime_epoch").ok_or(AdmissionCodecError::Corrupt)?;
        re_runtime_epoch(re)?
    };
    let operation_id = {
        let oi = v.get("operation_id").ok_or(AdmissionCodecError::Corrupt)?;
        re_operation_id(oi)?
    };
    OperationLookupKey::try_from((principal_digest, method, runtime_epoch, operation_id))
        .map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_journal_op_identity(
    v: &serde_json::Value,
) -> Result<JournalOperationIdentity, AdmissionCodecError> {
    let obj = v.as_object().ok_or(AdmissionCodecError::Corrupt)?;
    if let Some(ext) = obj.get("External") {
        Ok(JournalOperationIdentity::External(re_operation_lookup_key(ext)?))
    } else if let Some(ret) = obj.get("Retirement") {
        Ok(JournalOperationIdentity::Retirement(re_retirement_id(ret)?))
    } else {
        Err(AdmissionCodecError::Corrupt)
    }
}

fn re_opaque_resource_ref(
    v: &serde_json::Value,
) -> Result<OpaqueResourceRef, AdmissionCodecError> {
    let kind: ResourceKind = serde_json::from_value(
        v.get("kind")
            .ok_or(AdmissionCodecError::Corrupt)?
            .clone(),
    )
    .map_err(|_| AdmissionCodecError::Corrupt)?;
    let identity_digest = {
        let id = v.get("identity_digest").ok_or(AdmissionCodecError::Corrupt)?;
        re_digest::<ResourceIdentityDigest>(id)?
    };
    OpaqueResourceRef::try_from((kind, identity_digest))
        .map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_redacted_native_error(
    v: &serde_json::Value,
) -> Result<RedactedNativeError, AdmissionCodecError> {
    let category = serde_json::from_value(
        v.get("category")
            .ok_or(AdmissionCodecError::Corrupt)?
            .clone(),
    )
    .map_err(|_| AdmissionCodecError::Corrupt)?;
    let namespace = serde_json::from_value(
        v.get("namespace")
            .ok_or(AdmissionCodecError::Corrupt)?
            .clone(),
    )
    .map_err(|_| AdmissionCodecError::Corrupt)?;
    let code = serde_json::from_value(
        v.get("code").ok_or(AdmissionCodecError::Corrupt)?.clone(),
    )
    .map_err(|_| AdmissionCodecError::Corrupt)?;
    RedactedNativeError::try_from((category, namespace, code))
        .map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_error_subject(v: &serde_json::Value) -> Result<ErrorSubject, AdmissionCodecError> {
    let obj = v.as_object().ok_or(AdmissionCodecError::Corrupt)?;
    if let Some(ext) = obj.get("External") {
        Ok(ErrorSubject::External(re_operation_lookup_key(ext)?))
    } else if let Some(attempt) = obj.get("Attempt") {
        let ao = attempt.as_object().ok_or(AdmissionCodecError::Corrupt)?;
        let runtime_epoch =
            re_runtime_epoch(ao.get("runtime_epoch").ok_or(AdmissionCodecError::Corrupt)?)?;
        let attempt_id =
            re_attempt_id(ao.get("attempt_id").ok_or(AdmissionCodecError::Corrupt)?)?;
        Ok(ErrorSubject::Attempt {
            runtime_epoch,
            attempt_id,
        })
    } else if let Some(effect) = obj.get("Effect") {
        let eo = effect.as_object().ok_or(AdmissionCodecError::Corrupt)?;
        let runtime_epoch =
            re_runtime_epoch(eo.get("runtime_epoch").ok_or(AdmissionCodecError::Corrupt)?)?;
        let attempt_id =
            re_attempt_id(eo.get("attempt_id").ok_or(AdmissionCodecError::Corrupt)?)?;
        let effect_id = re_effect_id(eo.get("effect_id").ok_or(AdmissionCodecError::Corrupt)?)?;
        Ok(ErrorSubject::Effect {
            runtime_epoch,
            attempt_id,
            effect_id,
        })
    } else if let Some(ret) = obj.get("Retirement") {
        Ok(ErrorSubject::Retirement(re_retirement_id(ret)?))
    } else if let Some(rec) = obj.get("Recovery") {
        Ok(ErrorSubject::Recovery(re_recovery_id(rec)?))
    } else if let Some(runtime) = obj.get("Runtime") {
        Ok(ErrorSubject::Runtime(re_runtime_epoch(runtime)?))
    } else {
        Err(AdmissionCodecError::Corrupt)
    }
}

fn re_vpn_error(v: &serde_json::Value) -> Result<VpnError, AdmissionCodecError> {
    let code: ErrorCode = serde_json::from_value(
        v.get("code").ok_or(AdmissionCodecError::Corrupt)?.clone(),
    )
    .map_err(|_| AdmissionCodecError::Corrupt)?;
    let stage: ErrorStage = serde_json::from_value(
        v.get("stage").ok_or(AdmissionCodecError::Corrupt)?.clone(),
    )
    .map_err(|_| AdmissionCodecError::Corrupt)?;
    let certainty: EffectCertainty = serde_json::from_value(
        v.get("certainty")
            .ok_or(AdmissionCodecError::Corrupt)?
            .clone(),
    )
    .map_err(|_| AdmissionCodecError::Corrupt)?;
    let retry: RetryAdvice = serde_json::from_value(
        v.get("retry").ok_or(AdmissionCodecError::Corrupt)?.clone(),
    )
    .map_err(|_| AdmissionCodecError::Corrupt)?;
    let subject = re_error_subject(v.get("subject").ok_or(AdmissionCodecError::Corrupt)?)?;
    let resource = match v_opt(v, "resource")? {
        Some(r) => Some(re_opaque_resource_ref(r)?),
        None => None,
    };
    let native = match v_opt(v, "native")? {
        Some(n) => Some(re_redacted_native_error(n)?),
        None => None,
    };
    VpnError::try_from((code, stage, certainty, retry, subject, resource, native))
        .map_err(|_| AdmissionCodecError::Corrupt)
}

fn re_authority_fence(v: &serde_json::Value) -> Result<AuthorityFence, AdmissionCodecError> {
    Ok(AuthorityFence {
        authority_epoch: re_authority_epoch(
            v.get("authority_epoch")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        platform_authority_instance_id: re_platform_instance(
            v.get("platform_authority_instance_id")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        admission_watermark: re_admission_watermark(
            v.get("admission_watermark")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        journal_revision: re_journal_revision(
            v.get("journal_revision")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
    })
}

fn re_rejection_reason(v: &serde_json::Value) -> Result<RejectionReason, AdmissionCodecError> {
    Ok(RejectionReason {
        error: re_vpn_error(v.get("error").ok_or(AdmissionCodecError::Corrupt)?)?,
        authority_fence: re_authority_fence(
            v.get("authority_fence")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
    })
}

fn re_authorization_subject(
    v: &serde_json::Value,
) -> Result<AuthorizationSubject, AdmissionCodecError> {
    let obj = v.as_object().ok_or(AdmissionCodecError::Corrupt)?;
    if let Some(t) = obj.get("LiveOwnershipTokenDigest") {
        Ok(AuthorizationSubject::LiveOwnershipTokenDigest(re_digest::<
            TokenDigest,
        >(t)?))
    } else if let Some(r) = obj.get("RecoveryAuthority") {
        Ok(AuthorizationSubject::RecoveryAuthority(re_retirement_id(r)?))
    } else {
        Err(AdmissionCodecError::Corrupt)
    }
}

fn re_mutation_admitted(v: &serde_json::Value) -> Result<MutationAdmitted, AdmissionCodecError> {
    Ok(MutationAdmitted {
        mutation_kind: serde_json::from_value(
            v.get("mutation_kind")
                .ok_or(AdmissionCodecError::Corrupt)?
                .clone(),
        )
        .map_err(|_| AdmissionCodecError::Corrupt)?,
        journal_operation_identity: re_journal_op_identity(
            v.get("journal_operation_identity")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        effect_id: re_effect_id(v.get("effect_id").ok_or(AdmissionCodecError::Corrupt)?)?,
        canonical_input_digest: re_digest::<CanonicalInputDigest>(
            v.get("canonical_input_digest")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        initiator_identity_digest: re_digest::<PrincipalDigest>(
            v.get("initiator_identity_digest")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        authority_epoch: re_authority_epoch(
            v.get("authority_epoch")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        platform_authority_instance_id: re_platform_instance(
            v.get("platform_authority_instance_id")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        admission_watermark: re_admission_watermark(
            v.get("admission_watermark")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        ownership_version: re_ownership_version(
            v.get("ownership_version")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        authorization_subject: re_authorization_subject(
            v.get("authorization_subject")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        resource_identity: re_digest::<ResourceIdentityDigest>(
            v.get("resource_identity")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        precondition_fingerprint: serde_json::from_value(
            v.get("precondition_fingerprint")
                .ok_or(AdmissionCodecError::Corrupt)?
                .clone(),
        )
        .map_err(|_| AdmissionCodecError::Corrupt)?,
        desired_applied_fingerprint: serde_json::from_value(
            v.get("desired_applied_fingerprint")
                .ok_or(AdmissionCodecError::Corrupt)?
                .clone(),
        )
        .map_err(|_| AdmissionCodecError::Corrupt)?,
        canonical_obligation_seed: serde_json::from_value(
            v.get("canonical_obligation_seed")
                .ok_or(AdmissionCodecError::Corrupt)?
                .clone(),
        )
        .map_err(|_| AdmissionCodecError::Corrupt)?,
    })
}

fn re_operation_rejected(v: &serde_json::Value) -> Result<OperationRejected, AdmissionCodecError> {
    Ok(OperationRejected {
        lookup_key: re_operation_lookup_key(
            v.get("lookup_key").ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        request_digest: re_digest::<RequestDigest>(
            v.get("request_digest")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        authority_epoch: re_authority_epoch(
            v.get("authority_epoch")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        rejection_reason: re_rejection_reason(
            v.get("rejection_reason")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        admission_watermark: re_admission_watermark(
            v.get("admission_watermark")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
    })
}

fn re_operation_absent_fence(
    v: &serde_json::Value,
) -> Result<OperationAbsentFence, AdmissionCodecError> {
    Ok(OperationAbsentFence {
        lookup_key: re_operation_lookup_key(
            v.get("lookup_key").ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        request_digest: re_digest::<RequestDigest>(
            v.get("request_digest")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        authority_epoch: re_authority_epoch(
            v.get("authority_epoch")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
        admission_watermark: re_admission_watermark(
            v.get("admission_watermark")
                .ok_or(AdmissionCodecError::Corrupt)?,
        )?,
    })
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。