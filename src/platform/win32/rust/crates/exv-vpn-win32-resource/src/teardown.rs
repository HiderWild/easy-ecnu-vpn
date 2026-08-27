// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Journaled reverse-order teardown of the aggregate (W24-I).
//!
//! Frozen facts (`docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-wintun-facts.md`
//! WSP3 §2, `native-network-settings-facts.md` WSP4 §3/§6): the packet worker MUST be
//! joined **before** `WintunEndSession` (0.14.1's `WintunEndSession` destroys the session
//! object — any receive after end is a use-after-free); a creator's `WintunCloseAdapter`
//! removes the adapter and cascades away all of its address/MTU/route/DNS; cleanup runs
//! in **reverse** install order — the last-applied family restores first, the tunnel
//! routes before the bypass; every destructive step must be durably journaled
//! (`RetirementStarted`) before it may run.
//!
//! [`build_teardown_plan`] fixes the stage order (pure logic — the W24 killer-mutant
//! seam): `PureCancel` → (`JournaledUnblock` → `ChildJoin`, only when packet children
//! exist) → `ReverseRestore` → `FinalHandle` → `Proof`, and composes
//! [`crate::apply_tunnel::build_restore_plan`] for the reverse-family restore steps —
//! never a reimplementation. [`WindowsTeardown`] executes the plan on the committed
//! pieces (W22 `Aggregate` + `apply_tunnel::restore`, J53 `RetirementSaga`, W17
//! `PacketWorker`) without re-implementing them: a `join`/`restore` failure poisons
//! the teardown (remaining stages still run, but no proof is ever signed — the
//! benign pre-journal `unblock` and final-handle ordering guards are correctable
//! rejections and do not poison), a repeated `begin` merges into the same saga, and
//! `Drop` preserves the W17 SAFETY-ORDER (children joined before the aggregate's
//! session end).

use exv_vpn_domain::error::ErrorSubject;
use exv_vpn_domain::identity::{InventoryDigest, RetirementOperationId};
use exv_vpn_domain::model::PlatformOwnershipRef;
use exv_vpn_domain::ports::CleanupTrigger;
use exv_vpn_resource::retirement::{ProveCleanInput, RetirementSaga};

use crate::aggregate::Aggregate;
use crate::apply_tunnel::{build_restore_plan, restore, ApplyPlan, FamilyStep};
use crate::cleanup_proof::{verify_cleanup_proof, CleanupPredicate, CleanupProof};
use crate::inventory::COMPLETE_INVENTORY;
use crate::packet_worker::PacketWorker;

/// One teardown stage (architecture §6.2: the six canonical step kinds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownStage {
    /// Pure cancel/wakeup — no journal, no ownership change, not completion.
    PureCancel,
    /// Journaled unblock of the native read (the session end needs the durable
    /// `RetirementStarted` record first).
    JournaledUnblock,
    /// Join all packet children (strictly before the final handle).
    ChildJoin,
    /// Reverse-family compare-and-restore of the owned resources.
    ReverseRestore,
    /// Destroy the aggregate/final handle (session end, then adapter close).
    FinalHandle,
    /// Sign the cleanup proof (only after every stage completed without failure).
    Proof,
}

/// The full teardown plan: stage order + reverse restore steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeardownPlan {
    /// The fixed execution order of the stages.
    pub stages: Vec<TeardownStage>,
    /// The reverse-family restore steps (composed from
    /// [`build_restore_plan`], never reimplemented).
    pub restore_steps: Vec<FamilyStep>,
}

/// Typed teardown errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownError {
    /// A destructive step ran before the journaled `begin`.
    DestructiveBeforeJournal,
    /// A step ran in the wrong order relative to the plan.
    StageOutOfOrder,
    /// The cleanup proof is unavailable (teardown incomplete or poisoned).
    ProofUnavailable,
}

/// Build the teardown plan (pure logic; the stage order is the W24 mutant seam).
///
/// Stages are always `[PureCancel]` + (`[JournaledUnblock, ChildJoin]` only when
/// packet children exist) + `[ReverseRestore, FinalHandle, Proof]` — the reverse of
/// the setup order per the frozen facts (worker join before session end,
/// reverse-family restore, adapter removal by creator close last; `ChildJoin` is
/// strictly before `FinalHandle`). `restore_steps` is exactly
/// [`build_restore_plan`] of the apply plan — the last-applied family restores
/// first, the tunnel routes before the bypass.
#[must_use]
pub fn build_teardown_plan(apply: &ApplyPlan, has_packet_children: bool) -> TeardownPlan {
    let mut stages = vec![TeardownStage::PureCancel];
    if has_packet_children {
        stages.push(TeardownStage::JournaledUnblock);
        stages.push(TeardownStage::ChildJoin);
    }
    stages.push(TeardownStage::ReverseRestore);
    stages.push(TeardownStage::FinalHandle);
    stages.push(TeardownStage::Proof);
    TeardownPlan {
        stages,
        restore_steps: build_restore_plan(apply),
    }
}

/// The internal linear completion of the core stages (`cancel → journal →
/// restore → final handle → proof`). The conditional child stages (unblock/join)
/// are tracked by the two dedicated bools, so the enum stays linear while the
/// plan decides whether those stages apply.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CorePhase {
    /// Nothing has happened yet.
    Pending,
    /// `pure_cancel` has been sent (cancel precedes journal, spec §5.6).
    Canceled,
    /// The journaled `begin` has sealed the saga.
    Journaled,
    /// The reverse-family compare-and-restore has run.
    Restored,
    /// The aggregate/final handle has been destroyed.
    FinalDropped,
    /// The cleanup proof has been issued (the only true completion).
    Proved,
}

/// The frozen-seam teardown executor (composes W22 `Aggregate`/`apply_tunnel`,
/// J53 `RetirementSaga` and W17 `PacketWorker` — never reimplements a piece).
///
/// Pure state machinery over the committed pieces: `None` aggregate = no real
/// state (no-op teardown). Error priority (contract): a journaled step before
/// `begin` is `DestructiveBeforeJournal` (checked before the ordering check);
/// begun-but-out-of-order is `StageOutOfOrder`. A `join`/`restore` failure is
/// sticky and poisons the proof; the `unblock` wakeup guard and the final-handle
/// ordering guard are correctable rejections that do not poison.
pub struct WindowsTeardown {
    /// The aggregate under teardown; `None` = no real state (no-op teardown).
    aggregate: Option<Aggregate>,
    /// The durable retirement saga (J53 composition).
    saga: RetirementSaga,
    /// The plan this teardown executes.
    plan: TeardownPlan,
    /// The packet children, joined before the final handle (W17).
    children: Vec<PacketWorker>,
    /// The linear completion of the core stages.
    phase: CorePhase,
    /// The journaled unblock has run (only meaningful when the plan has children).
    unblocked: bool,
    /// All packet children have been joined.
    children_joined: bool,
    /// A `join`/`restore` stage failure — sticky, poisons the proof ('failure
    /// signs proof' mutant): a child that did not join is a live UAF hazard and
    /// owned config that did not restore is a leftover, so no clean proof may
    /// ever be signed. The benign guards — the pre-journal `unblock` wakeup
    /// rejection and the final-handle ordering rejection (both correctable,
    /// exercised by the contract tests) — do not poison.
    failed: bool,
    /// The canonical inventory digest sealed at `begin` (bound by the proof).
    canonical_inventory_digest: Option<InventoryDigest>,
}

impl WindowsTeardown {
    /// Construct the teardown (pure state machinery — testable non-elevated).
    #[must_use]
    pub fn new(
        aggregate: Option<Aggregate>,
        saga: RetirementSaga,
        plan: TeardownPlan,
        children: Vec<PacketWorker>,
    ) -> Self {
        Self {
            aggregate,
            saga,
            plan,
            children,
            phase: CorePhase::Pending,
            unblocked: false,
            children_joined: false,
            failed: false,
            canonical_inventory_digest: None,
        }
    }

    /// Pure cancel/wakeup (spec §6.2 step 2): no journal, no ownership change,
    /// no child join (join is a later stage) and **not** a cleanup completion.
    ///
    /// # Errors
    ///
    /// Never fails: this is a pure state marker.
    pub fn pure_cancel(&mut self) -> Result<(), TeardownError> {
        if self.phase < CorePhase::Canceled {
            self.phase = CorePhase::Canceled;
        }
        Ok(())
    }

    /// Journaled start: seals the retirement via `saga.begin` with the 9
    /// canonical obligations (the same `u8` discriminant mapping as
    /// [`verify_cleanup_proof`] uses for `observe_cleanup`). Must follow
    /// `pure_cancel` (cancel precedes journal, spec §5.6). Idempotent: a second
    /// Stop intent merges into the same saga and returns `Ok` — never a second
    /// destructive cleanup (spec §6.1).
    ///
    /// # Errors
    ///
    /// `StageOutOfOrder` when the cancel has not been sent first.
    pub fn begin(
        &mut self,
        retirement_operation_id: RetirementOperationId,
        trigger: CleanupTrigger,
        origin_subject: ErrorSubject,
        prior_platform_ownership: PlatformOwnershipRef,
        canonical_inventory_digest: InventoryDigest,
    ) -> Result<(), TeardownError> {
        if self.phase < CorePhase::Canceled {
            self.failed = true;
            return Err(TeardownError::StageOutOfOrder);
        }
        if self.phase >= CorePhase::Journaled {
            return Ok(()); // 相同/不同 Stop 意图合并到同一 saga（spec §6.1）
        }
        let expected_obligations: Vec<u8> =
            COMPLETE_INVENTORY.iter().map(|item| *item as u8).collect();
        if self
            .saga
            .begin(
                retirement_operation_id,
                trigger,
                origin_subject,
                prior_platform_ownership,
                expected_obligations,
                canonical_inventory_digest.clone(),
            )
            .is_err()
        {
            // Unreachable in practice: the idempotency guard above covers the
            // saga's only failure mode ('already started'). The journal did not
            // durably start, so any later destructive step would be
            // destructive-before-journal.
            self.failed = true;
            return Err(TeardownError::DestructiveBeforeJournal);
        }
        self.phase = CorePhase::Journaled;
        self.canonical_inventory_digest = Some(canonical_inventory_digest);
        Ok(())
    }

    /// Journaled unblock of the native read (spec §6.2 steps 4/5: the cancel
    /// signal precedes the join; `RetirementStarted` must already be durable).
    ///
    /// The pre-journal rejection is a benign wakeup guard (a journaled-state
    /// transition only) and does **not** poison the proof: the contract test
    /// exercises exactly this rejection and still expects a clean proof after
    /// the journaled run.
    ///
    /// # Errors
    ///
    /// `DestructiveBeforeJournal` when the journaled `begin` has not run.
    pub fn unblock_native_read(&mut self) -> Result<(), TeardownError> {
        if self.phase < CorePhase::Journaled {
            return Err(TeardownError::DestructiveBeforeJournal);
        }
        self.unblocked = true;
        Ok(())
    }

    /// Join all packet children (spec §6.2 step 4: join strictly before the
    /// final handle — `EndSession` destroys the session object).
    ///
    /// A join failure poisons the proof (sticky): a child that did not join
    /// may still be live inside the session — ending the session would be the
    /// end-before-join use-after-free mutant — so no clean proof can follow.
    ///
    /// # Errors
    ///
    /// `DestructiveBeforeJournal` when the journaled `begin` has not run.
    pub fn join_children(&mut self) -> Result<(), TeardownError> {
        if self.phase < CorePhase::Journaled {
            self.failed = true;
            return Err(TeardownError::DestructiveBeforeJournal);
        }
        for worker in self.children.drain(..) {
            worker.join();
        }
        self.children_joined = true;
        Ok(())
    }

    /// Reverse-family compare-and-restore, delegating to `apply_tunnel::restore`
    /// (never reimplemented): the last-applied family restores first; a
    /// third-party change is a typed skip.
    ///
    /// A restore failure poisons the proof (sticky): owned config may still be
    /// applied, so no clean proof can follow.
    ///
    /// # Errors
    ///
    /// `DestructiveBeforeJournal` when the journaled `begin` has not run.
    pub fn restore_owned_resources(&mut self) -> Result<(), TeardownError> {
        if self.phase < CorePhase::Journaled {
            self.failed = true;
            return Err(TeardownError::DestructiveBeforeJournal);
        }
        if let Some(aggregate) = self.aggregate.as_mut()
            && restore(aggregate).is_err()
        {
            // A native failure poisons the teardown. The contract-pinned
            // `TeardownError` variants cannot carry the NativeError payload,
            // so the failure surfaces as proof-unavailable: the teardown
            // must never sign proof over unknown state.
            self.failed = true;
            return Err(TeardownError::ProofUnavailable);
        }
        self.phase = CorePhase::Restored;
        Ok(())
    }

    /// Destroy the aggregate/final handle: session end first, adapter close
    /// after (W17 SAFETY-ORDER, `Aggregate::drop`; a creator close removes the
    /// adapter with all of its config). Must follow the reverse restore and
    /// every child join.
    ///
    /// Both rejections are correctable ordering guards and do **not** poison
    /// the proof: the contract test rejects the final handle before the join
    /// and still expects a clean proof after the children have joined.
    ///
    /// # Errors
    ///
    /// `DestructiveBeforeJournal` when the journaled `begin` has not run;
    /// `StageOutOfOrder` before the restore, or when packet children exist
    /// but have not joined.
    pub fn drop_final_handle(&mut self) -> Result<(), TeardownError> {
        if self.phase < CorePhase::Journaled {
            return Err(TeardownError::DestructiveBeforeJournal);
        }
        if self.phase < CorePhase::Restored {
            return Err(TeardownError::StageOutOfOrder);
        }
        if self.plan.stages.contains(&TeardownStage::ChildJoin) && !self.children_joined {
            return Err(TeardownError::StageOutOfOrder);
        }
        // The aggregate's Drop runs EndSession then the creator close (which
        // removes the adapter and cascades its address/MTU/route/DNS away).
        self.aggregate = None;
        self.phase = CorePhase::FinalDropped;
        Ok(())
    }

    /// The live aggregate (readable until the final handle drops).
    #[must_use]
    pub fn aggregate(&self) -> Option<&Aggregate> {
        self.aggregate.as_ref()
    }

    /// Whether every stage — including the proof — has completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.phase >= CorePhase::Proved && self.cleanup_stage_completed()
    }

    /// Issue the cleanup proof over the complete inventory (delegates to
    /// [`verify_cleanup_proof`]; binds the digest sealed at `begin`).
    ///
    /// # Errors
    ///
    /// `ProofUnavailable` when a `join`/`restore` stage failed earlier
    /// ('failure signs proof' mutant), the teardown is not yet complete, or
    /// the delegated verification refuses (incomplete inventory / missing or
    /// unverified predicate).
    pub fn cleanup_proof(
        &mut self,
        input: ProveCleanInput,
        predicates: &[CleanupPredicate],
    ) -> Result<CleanupProof, TeardownError> {
        if self.failed {
            return Err(TeardownError::ProofUnavailable);
        }
        if !self.cleanup_stage_completed() {
            return Err(TeardownError::ProofUnavailable);
        }
        let digest = self
            .canonical_inventory_digest
            .clone()
            .ok_or(TeardownError::ProofUnavailable)?;
        let proof = verify_cleanup_proof(COMPLETE_INVENTORY, predicates, digest, &mut self.saga, input)
            .map_err(|_| TeardownError::ProofUnavailable)?;
        self.phase = CorePhase::Proved;
        Ok(proof)
    }

    /// All stages before the proof are complete (the completion gate).
    #[must_use]
    fn cleanup_stage_completed(&self) -> bool {
        self.phase >= CorePhase::FinalDropped
            && (!self.plan.stages.contains(&TeardownStage::ChildJoin)
                || (self.unblocked && self.children_joined))
    }
}

impl Drop for WindowsTeardown {
    fn drop(&mut self) {
        // W17 SAFETY-ORDER (frozen, native-wintun-facts.md §2): the children
        // join FIRST — `WintunEndSession` destroys the session object, so any
        // receive after end is a use-after-free. Then the aggregate drops
        // (session end before adapter close inside `Aggregate::drop`). Panic
        // early-exit self-cleanup: no half state, no residue.
        for worker in self.children.drain(..) {
            worker.join();
        }
        self.aggregate = None;
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
