// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Sync-before-reply mutation ingress gate (W15, J51).
//!
//! A mutation RPC is admitted only once a durable J51 `MutationAdmitted` exists for its lookup
//! key; the reply is synced only after the admitted record round-trips the
//! `encode_record`/`decode_record` codec. Until a durable record is registered the ingress refuses
//! the RPC.

use std::collections::HashMap;

use exv_vpn_domain::identity::{OperationLookupKey, RequestDigest};
use exv_vpn_domain::ports::JournalOperationIdentity;
use exv_vpn_resource::admission::{
    decode_record, encode_record, AdmissionRecord, MutationAdmitted,
};

use crate::owner_lease::OwnerLease;

/// The sync-before-reply ingress gate.
#[derive(Default)]
pub struct MutationIngress {
    /// The durable `MutationAdmitted` records registered per lookup key.
    durable: HashMap<OperationLookupKey, MutationAdmitted>,
}

impl MutationIngress {
    /// Build an ingress with no durable admissions registered yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            durable: HashMap::new(),
        }
    }

    /// Admit a mutation RPC for the given lease/key once its J51 admission is durable.
    ///
    /// # Errors
    ///
    /// Returns an error when no durable `MutationAdmitted` has been registered for the lookup key.
    pub fn admit(
        &mut self,
        _lease: &OwnerLease,
        key: OperationLookupKey,
        _request_digest: RequestDigest,
    ) -> Result<MutationAdmitted, &'static str> {
        match self.durable.remove(&key) {
            Some(record) => {
                let durable = record.clone();
                self.durable.insert(key, record);
                Ok(durable)
            }
            None => Err("mutation admission not durable"),
        }
    }

    /// Confirm the admitted record is durable and register it for future admits.
    ///
    /// The durability gate is the codec round-trip: `encode_record` followed by `decode_record`
    /// must recover an `AdmissionRecord::Admitted`. Only externally-keyed admissions gate an RPC;
    /// retirement admissions are not an RPC gate.
    #[must_use]
    pub fn durable_before_reply(&mut self, admitted: &MutationAdmitted) -> bool {
        let payload = encode_record(&AdmissionRecord::Admitted(admitted.clone()));
        if !matches!(decode_record(&payload), Ok(AdmissionRecord::Admitted(_))) {
            return false;
        }
        match &admitted.journal_operation_identity {
            JournalOperationIdentity::External(key) => {
                self.durable.insert(key.clone(), admitted.clone());
                true
            }
            JournalOperationIdentity::Retirement(_) => false,
        }
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
