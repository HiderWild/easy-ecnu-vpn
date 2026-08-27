// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Per-resource cleanup evidence and proof verification (W24-I).
//!
//! A cleanup proof is only issued over the complete 9-item canonical inventory,
//! with one verified per-resource predicate per item — a missing, unverified or
//! unknown predicate is `Err` (API success is not proof). Verification composes
//! the J53 `RetirementSaga`: the predicates are observed (`observe_cleanup`,
//! same `u8` label mapping as `WindowsTeardown::begin`'s expected obligations)
//! and a `CleanProof` is signed via `prove_clean` only when every gate passed —
//! a saga that fails to observe or prove signs nothing ('failure signs proof'
//! mutant). Pure logic: no Win32 calls, no I/O.

use exv_vpn_domain::identity::InventoryDigest;
use exv_vpn_domain::ports::CleanProof;
use exv_vpn_resource::retirement::{InventoryPredicate, ProveCleanInput, RetirementSaga};

use crate::inventory::{is_complete, InventoryItem};

/// Per-resource no-leftover predicate: one canonical obligation item and the
/// observed verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupPredicate {
    /// The canonical obligation this predicate covers.
    pub item: InventoryItem,
    /// Whether a native observation confirmed no leftover for the item.
    pub verified: bool,
    /// The evidence text of the observation.
    pub evidence: &'static str,
}

/// Collected cleanup evidence: the J53-signed `CleanProof`, the bound canonical
/// inventory digest and the per-resource predicates.
#[derive(Clone, PartialEq, Eq)]
pub struct CleanupProof {
    /// The J53-signed `CleanProof` (exv-vpn-domain port type — composition).
    pub clean: CleanProof,
    /// The canonical inventory digest this proof binds to.
    pub inventory_digest: InventoryDigest,
    /// The per-resource predicates that were verified.
    pub predicates: Vec<CleanupPredicate>,
}

impl std::fmt::Debug for CleanupProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `CleanProof` / `InventoryDigest` carry no `Debug` (J53 同款) — keep
        // the signed evidence opaque and surface only the predicate count.
        f.debug_struct("CleanupProof")
            .field("predicate_count", &self.predicates.len())
            .finish_non_exhaustive()
    }
}

/// Verify the cleanup proof over the complete inventory.
///
/// Gates (all must pass, nothing is signed on any failure):
/// 1. the inventory must be complete (all 9 canonical obligations);
/// 2. the predicates must cover the inventory exactly — one `verified` predicate
///    per item; a missing, unverified, unknown or duplicate predicate is `Err`;
/// 3. the evidence is observed on the saga (`saga.observe_cleanup`, labels =
///    `InventoryItem` as `u8` — the same mapping as
///    `WindowsTeardown::begin`'s expected obligations);
/// 4. `saga.prove_clean` signs the `CleanProof` bound to the canonical digest.
///
/// # Errors
///
/// Returns a `&'static str` describing the failing gate; no proof is issued.
pub fn verify_cleanup_proof(
    inventory: &[InventoryItem],
    predicates: &[CleanupPredicate],
    canonical_inventory_digest: InventoryDigest,
    saga: &mut RetirementSaga,
    input: ProveCleanInput,
) -> Result<CleanupProof, &'static str> {
    if !is_complete(inventory) {
        return Err("cleanup proof: inventory must be the complete 9-item canonical list");
    }
    let mut observed = Vec::with_capacity(inventory.len());
    for item in inventory {
        let predicate = predicates
            .iter()
            .find(|p| p.item == *item)
            .ok_or("cleanup proof: predicate missing for inventory item")?;
        if !predicate.verified {
            return Err("cleanup proof: unverified inventory predicate");
        }
        observed.push(InventoryPredicate {
            label: *item as u8,
            verified: predicate.verified,
        });
    }
    if observed.len() != predicates.len() {
        return Err("cleanup proof: predicates must cover the inventory exactly");
    }
    saga.observe_cleanup(&observed)?;
    let clean = saga.prove_clean(input)?;
    Ok(CleanupProof {
        clean,
        inventory_digest: canonical_inventory_digest,
        predicates: predicates.to_vec(),
    })
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
