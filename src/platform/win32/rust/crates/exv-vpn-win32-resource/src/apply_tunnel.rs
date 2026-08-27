// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Cross-family tunnel apply / restore orchestration (W22-I).
//!
//! Frozen facts (`docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md`
//! WSP4 §3/§6, W20-W21 frozen): the bypass family must be installed **before**
//! the tunnel-routes family (otherwise control traffic is hijacked by the
//! tunnel route); cleanup runs in **reverse** install order (tunnel routes are
//! removed first, the bypass last); apply is admission-first — the whole plan
//! is validated before any effect, so an invalid family (e.g. MTU=1 -> 87)
//! leaves **zero** effect, never half state; restore is compare-and-restore —
//! the current state is compared against the applied fingerprint and a
//! third-party change is a typed skip, never an unconditional overwrite.
//!
//! Every effect delegates to the committed leaf seams (W18 `ip_address` /
//! W19 `mtu` / W20 `routes`+`bypass_route` / W21 `dns`); the plan and snapshot
//! types are the leaves' types — composition, never reimplementation.

use windows::core::GUID;

use crate::aggregate::{luid_to_guid, Aggregate};
use crate::dns::{DnsApplier, DnsCapture};
use crate::dns_types::{DnsFingerprint, DnsSettings};
use crate::ip_address::{plan_addresses, restore_owned_addresses, IpAddressController};
use crate::ip_helper_types::IpAddressRow;
use crate::mtu::{validate_mtu_value, MtuController, MtuFamily, MtuSnapshot};
use crate::native_error::NativeError;
use crate::routes::{build_cleanup_order, install, install_plan, remove, RouteRow};
use crate::system_proxy::RawInternetSettings;
use crate::system_proxy_family_exec::{
    apply_from_prestate, plan_restore, SystemProxyApplyOutcome, SystemProxyRestoreOutcome,
};
use crate::wintun_adapter::WintunAdapter;

/// `ERROR_INVALID_PARAMETER`（非法 MTU / 路由 / 地址前缀的冻结拒绝码，87）。
const ERROR_INVALID_PARAMETER: u32 = 87;
/// `ERROR_NOT_FOUND`（LUID -> GUID 转换失败等，1168）。
const ERROR_NOT_FOUND: u32 = 1168;
/// IPv4 前缀长度上限（facts §3 / W18：33 -> 87）。
const MAX_PREFIX_LEN: u8 = 32;

/// A cross-family apply step (canonical family order: address -> MTU -> bypass
/// -> tunnel routes -> DNS). `build_apply_plan` emits the steps in this order
/// and `build_restore_plan` emits their **exact reverse**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyStep {
    /// IPv4 unicast addresses (W18 leaf).
    Address,
    /// Interface MTU, IPv4 + IPv6 rows (W19 leaf).
    Mtu,
    /// Bypass route — installed before the tunnel routes (W20 leaf).
    Bypass,
    /// System proxy exemption merge (design §5.3; TK1b) — after bypass, before
    /// tunnel routes. `EXV_PAC_FAMILY_PENDING`: PAC wrap wiring is a separate task.
    SystemProxy,
    /// Tunnel routes — installed after the bypass (W20 leaf).
    Routes,
    /// Interface DNS settings (W21 leaf).
    Dns,
}

/// A full cross-family apply plan: family order + per-family configuration.
///
/// All configuration fields are the committed leaf types — the aggregate
/// composes, it never re-implements a family or its types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPlan {
    /// The cross-family apply order (`FamilyStep::Bypass` always precedes
    /// `FamilyStep::Routes`).
    pub steps: Vec<FamilyStep>,
    /// W18 类型：本次 apply 期望的地址行。
    pub addresses: Vec<IpAddressRow>,
    /// W19 类型：IPv4 接口 MTU 值。
    pub mtu_v4: u32,
    /// W19 类型：IPv6 接口 MTU 值（`None` = 不触碰 V6 行）。
    pub mtu_v6: Option<u32>,
    /// W20 类型：bypass 路由（隧道路由之前安装；`control_bypass` 是矢量，
    /// 每个控制目的地一条 `/32` 行——空矢量 = 不安装）。
    pub bypass: Vec<RouteRow>,
    /// W20 类型：隧道路由。
    pub tunnel_routes: Vec<RouteRow>,
    /// W21 类型：接口 DNS 设置。
    pub dns: DnsSettings,
    /// 系统代理豁免条目（设计 §5.4；v1 由 host `plan_from_config` 从
    /// server_bypass_ips + routes 派生）。空矢量 = family 零动作候选（仍会
    /// capture+classify，Disabled 时零动作零账本，拍板结论 4）。
    pub proxy_exempt_entries: Vec<String>,
    /// 发起用户 SID（系统代理写入必须落在该用户 HKU；空串 = 不执行该 family）。
    pub originating_sid: String,
}

/// Applied state recorded by [`apply`] — the compare-and-restore inputs of
/// [`restore`]. Owned by the aggregate; fields are private to this module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppliedState {
    /// The applied plan (its `steps` derive the restore order).
    plan: ApplyPlan,
    /// Address rows this apply created (owned — restore deletes exactly these;
    /// pre-existing rows are never owned, never deleted).
    owned_addresses: Vec<IpAddressRow>,
    /// MTU `(applied, original)` snapshot pairs in apply order (V4 then V6).
    mtu: Vec<(MtuSnapshot, MtuSnapshot)>,
    /// Tunnel routes in install order (cleanup runs in reverse).
    installed_tunnel: Vec<RouteRow>,
    /// The installed bypass rows (removed last — after the tunnel routes;
    /// cleanup runs in reverse install order).
    bypass_rows: Vec<RouteRow>,
    /// DNS applied fingerprint + original settings (GUID-keyed).
    dns: Option<DnsAppliedState>,
    /// 系统代理 family 的 compare-and-restore 输入（TK1b）：prestate + 写入后
    /// 指纹。`None` = 该 family 未产生效果（SkipNoOp / PacDetectedSkip / SID 空）。
    system_proxy: Option<SystemProxyApplied>,
}

/// 系统代理 family 的已生效状态（compare-and-restore 输入；TK1b）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SystemProxyApplied {
    /// 连接前五值原始快照（精确还原的唯一依据）。
    pub prestate: RawInternetSettings,
    /// 发起用户 SID（还原写回同一用户的 HKU）。
    pub sid: String,
    /// 写入后立即重读的指纹基准。
    pub written_fingerprint: Vec<u8>,
}

impl AppliedState {
    /// An empty applied state for a plan (no family effect yet).
    fn empty(plan: ApplyPlan) -> Self {
        Self {
            plan,
            owned_addresses: Vec::new(),
            mtu: Vec::new(),
            installed_tunnel: Vec::new(),
            bypass_rows: Vec::new(),
            dns: None,
            system_proxy: None,
        }
    }

    /// Whether any family effect was recorded (nothing to restore).
    #[must_use]
    fn is_empty(&self) -> bool {
        self.owned_addresses.is_empty()
            && self.mtu.is_empty()
            && self.installed_tunnel.is_empty()
            && self.bypass_rows.is_empty()
            && self.dns.is_none()
            && self.system_proxy.is_none()
    }
}

/// DNS compare-and-restore inputs, keyed by interface GUID.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsAppliedState {
    /// The interface GUID the settings were applied to.
    guid: GUID,
    /// The applied fingerprint from the leaf's independent read-back.
    applied: DnsFingerprint,
    /// The original settings captured before the apply.
    original: DnsSettings,
}

/// Build the apply plan: the family steps are the canonical fixed order with
/// `Bypass` strictly before `Routes` (pure logic — bypass is installed before
/// the tunnel routes, otherwise control traffic would be hijacked; WSP4 §3
/// frozen).
#[must_use]
pub fn build_apply_plan(
    addresses: Vec<IpAddressRow>,
    mtu_v4: u32,
    mtu_v6: Option<u32>,
    bypass: Vec<RouteRow>,
    tunnel_routes: Vec<RouteRow>,
    dns: DnsSettings,
    proxy_exempt_entries: Vec<String>,
    originating_sid: String,
) -> ApplyPlan {
    ApplyPlan {
        // canonical 顺序（设计 §5.3）：address → MTU → bypass → **system_proxy**
        // → tunnel routes → DNS；cleanup 逆序自动获得（DNS 先撤、system_proxy
        // 在 bypass 之前撤）。
        steps: vec![
            FamilyStep::Address,
            FamilyStep::Mtu,
            FamilyStep::Bypass,
            FamilyStep::SystemProxy,
            FamilyStep::Routes,
            FamilyStep::Dns,
        ],
        addresses,
        mtu_v4,
        mtu_v6,
        bypass,
        tunnel_routes,
        dns,
        proxy_exempt_entries,
        originating_sid,
    }
}

/// Build the restore plan: the **exact reverse** of the apply steps (the
/// last-applied family is restored first; pure logic).
#[must_use]
pub fn build_restore_plan(apply: &ApplyPlan) -> Vec<FamilyStep> {
    apply.steps.iter().rev().copied().collect()
}

/// Execute the cross-family apply: admission before effect.
///
/// The whole plan is validated first — any invalid family (e.g. `mtu_v4 = 1`,
/// below the IPv4 minimum 68 -> 87) returns `Err` with **zero effect**, never
/// half state. Only then are the families effected in `plan.steps` order, each
/// family delegating to its committed leaf seam. On success the applied state
/// (owned address rows, MTU applied/original pairs, installed routes, DNS
/// applied fingerprint) is recorded on the aggregate for [`restore`].
///
/// # Errors
///
/// Returns a typed [`NativeError`] when any family fails admission (code 87,
/// zero effect) or when a leaf effect call fails; families already effected
/// before the failure are still recorded, so a later `restore` can clean them
/// up in reverse order.
pub fn apply(aggregate: &mut Aggregate, plan: &ApplyPlan) -> Result<(), NativeError> {
    let (state, result) = run_apply(aggregate.adapter().luid(), plan);
    // 保留已生效部分（若有）：restore 仍能逆序清理，不留不可恢复的半状态。成功时
    // 恒记录（空状态也记录——compare-and-restore 输入恒来自本次 apply）。
    if result.is_ok() || !state.is_empty() {
        aggregate.applied = Some(state);
    }
    result
}

/// The shared cross-family apply runner (the [`apply`]/[`apply_privileged`]
/// common core): admission first, then effect in `plan.steps` order. Always
/// returns the applied state — a family already effected before a failure is
/// still recorded, so a later restore cleans it up in reverse order.
fn run_apply(luid: u64, plan: &ApplyPlan) -> (AppliedState, Result<(), NativeError>) {
    let _t = crate::timing::Timed::new("resource.apply_tunnel.run_apply");
    if let Err(e) = admit(plan) {
        return (AppliedState::empty(plan.clone()), Err(e));
    }
    let mut state = AppliedState::empty(plan.clone());
    for step in &plan.steps {
        if let Err(e) = apply_step(*step, plan, &mut state, luid) {
            return (state, Err(e));
        }
    }
    (state, Ok(()))
}

/// Apply over an already-created adapter (no `WintunSession` — the caller owns
/// the adapter handle; the helper does privileged init only, DP-01, and the
/// data-plane session is opened later by the engine).
///
/// The [`PrivilegedAppliedState`] returned is the compare-and-restore input of
/// [`restore_privileged`]; on a partial failure the returned `Err` still leaves
/// already-effected families on the interface — the caller must either call
/// `restore_privileged` (when it can recover the state) or drop the creator
/// adapter handle, whose close removes the adapter with all of its config.
///
/// # Errors
///
/// Returns a typed [`NativeError`] when admission fails (zero effect) or any
/// leaf effect call fails.
pub fn apply_privileged(
    adapter: &WintunAdapter,
    plan: &ApplyPlan,
) -> Result<PrivilegedAppliedState, NativeError> {
    let (state, result) = run_apply(adapter.luid(), plan);
    let applied = PrivilegedAppliedState { state };
    match result {
        Ok(()) => Ok(applied),
        Err(e) => Err(e),
    }
}

/// The applied state of [`apply_privileged`] — the compare-and-restore input
/// of [`restore_privileged`]. Opaque to callers; the reverse restore needs the
/// recorded owned rows / applied fingerprints, never re-captures them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedAppliedState {
    state: AppliedState,
}

impl PrivilegedAppliedState {
    /// Whether any family effect was recorded (nothing to restore).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }
}

/// Reverse-family-order compare-and-restore.
///
/// Restores along [`build_restore_plan`] (the exact reverse of the apply
/// steps), every family delegating to its leaf's compare-and-restore: MTU via
/// `MtuController::compare_and_restore`, DNS via `DnsApplier::restore`, routes
/// via `routes::remove` (already-absent is an idempotent skip; a filled row
/// the leaf refuses to delete — a third-party modification — is a typed skip),
/// addresses via `restore_owned_addresses` + exact-row delete. A third-party
/// change is always a typed skip, never an overwrite. On success the applied
/// state is cleared; on failure it is kept — a retry is safe, already-restored
/// families naturally skip.
///
/// # Errors
///
/// Returns a typed [`NativeError`] when a leaf restore reports a hard failure.
pub fn restore(aggregate: &mut Aggregate) -> Result<(), NativeError> {
    let Some(state) = aggregate.applied.clone() else {
        return Ok(());
    };
    let luid = aggregate.adapter().luid();
    run_restore(luid, &state)?;
    aggregate.applied = None;
    Ok(())
}

/// Reverse-family-order compare-and-restore over an already-created adapter
/// (the counterpart of [`apply_privileged`]; same discipline as [`restore`] —
/// typed skips for third-party changes, never an unconditional overwrite).
/// On success the state is consumed; on failure it is kept — a retry is safe,
/// already-restored families naturally skip.
///
/// # Errors
///
/// Returns a typed [`NativeError`] when a leaf restore reports a hard failure.
pub fn restore_privileged(
    adapter: &WintunAdapter,
    state: PrivilegedAppliedState,
) -> Result<(), NativeError> {
    run_restore(adapter.luid(), &state.state)
}

/// The shared reverse compare-and-restore runner ([`restore`] /
/// [`restore_privileged`] common core).
fn run_restore(luid: u64, state: &AppliedState) -> Result<(), NativeError> {
    let _t = crate::timing::Timed::new("resource.apply_tunnel.run_restore");
    for step in build_restore_plan(&state.plan) {
        restore_step(step, state, luid)?;
    }
    Ok(())
}

/// Admission: validate the whole plan before any effect (zero effect on
/// rejection — 'effect before admission' mutant dies here).
fn admit(plan: &ApplyPlan) -> Result<(), NativeError> {
    validate_mtu_value(plan.mtu_v4)?;
    if let Some(v6) = plan.mtu_v6 {
        validate_mtu_value(v6)?;
    }
    for row in &plan.bypass {
        admit_route(row)?;
    }
    for row in &plan.tunnel_routes {
        admit_route(row)?;
    }
    if plan
        .addresses
        .iter()
        .any(|row| row.on_link_prefix_length > MAX_PREFIX_LEN)
    {
        return Err(NativeError::from_win32(
            ERROR_INVALID_PARAMETER,
            "aggregate: 非法地址前缀（IPv4 前缀上限 32）",
        ));
    }
    Ok(())
}

/// Validate a route row's prefix (IPv4 max 32 -> 87, the WSP4-frozen reject
/// code of the routes leaf).
fn admit_route(row: &RouteRow) -> Result<(), NativeError> {
    if row.prefix_len > MAX_PREFIX_LEN {
        return Err(NativeError::from_win32(
            ERROR_INVALID_PARAMETER,
            "aggregate: 非法路由前缀（IPv4 前缀上限 32）",
        ));
    }
    Ok(())
}

/// Effect one family step (delegates to the committed leaf seams; failures
/// propagate after recording whatever already took effect).
fn apply_step(
    step: FamilyStep,
    plan: &ApplyPlan,
    state: &mut AppliedState,
    luid: u64,
) -> Result<(), NativeError> {
    match step {
        FamilyStep::Address => {
            // Admission split first: pre-existing rows (same identity) are
            // never owned; only to-add rows are created and recorded as owned.
            let controller = IpAddressController::new(luid);
            let captured = controller.capture()?;
            let admission_plan = plan_addresses(&captured, &plan.addresses);
            for row in &admission_plan.to_add {
                controller.apply(row)?;
                state.owned_addresses.push(row.clone());
            }
        }
        FamilyStep::Mtu => {
            // Original snapshots are captured BEFORE the Set (restore inputs).
            let v4 = MtuController::new(luid, MtuFamily::V4);
            let original_v4 = v4.capture()?;
            v4.apply(plan.mtu_v4)?;
            state.mtu.push((
                MtuSnapshot::new(luid, MtuFamily::V4, plan.mtu_v4),
                original_v4,
            ));
            if let Some(v6_value) = plan.mtu_v6 {
                let v6 = MtuController::new(luid, MtuFamily::V6);
                let original_v6 = v6.capture()?;
                v6.apply(v6_value)?;
                state.mtu.push((
                    MtuSnapshot::new(luid, MtuFamily::V6, v6_value),
                    original_v6,
                ));
            }
        }
        FamilyStep::Bypass => {
            // Bypass first (family order): installing it before the tunnel
            // routes keeps control traffic from being hijacked (WSP4 §3).
            // Multiple bypass rows are installed in order; cleanup runs reverse.
            for bypass in &plan.bypass {
                install(bypass)?;
                state.bypass_rows.push(bypass.clone());
            }
        }
        FamilyStep::SystemProxy => {
            // 系统代理豁免（设计 §5.3；TK1b）：SID 空 = 调用方未提供每用户语义，
            // family 零动作（fail-closed 交给上层 admission 决定是否报错——v1 由
            // host 保证 SID 在握，此处防御性跳过）。capture/解析失败向上传播 =
            // 整计划零效果（admission-first）。Disabled 零动作零账本（拍板结论 4）；
            // PacDetectedSkip 是 typed skip（EXV_PAC_FAMILY_PENDING）。
            if plan.originating_sid.is_empty() {
                return Ok(());
            }
            match apply_from_prestate(
                &plan.originating_sid,
                &plan.proxy_exempt_entries,
                crate::system_proxy::capture_for_user(&plan.originating_sid)?,
            )? {
                SystemProxyApplyOutcome::SkippedNoProxy => {}
                SystemProxyApplyOutcome::PacDetectedSkip => {}
                SystemProxyApplyOutcome::Applied {
                    step,
                    written_fingerprint,
                } => {
                    state.system_proxy = Some(SystemProxyApplied {
                        prestate: step.prestate.clone(),
                        sid: step.originating_sid.clone(),
                        written_fingerprint,
                    });
                }
            }
        }
        FamilyStep::Routes => {
            // install_plan is atomic within the family (pre-validate + reverse
            // rollback on failure — no half state).
            install_plan(&plan.tunnel_routes)?;
            state.installed_tunnel.extend(plan.tunnel_routes.clone());
        }
        FamilyStep::Dns => {
            let guid = luid_to_guid(luid).ok_or_else(|| {
                NativeError::from_win32(
                    ERROR_NOT_FOUND,
                    "aggregate: 接口 LUID 无法转换为 GUID（DNS 族）",
                )
            })?;
            let original = DnsCapture::capture(&guid)?;
            let applied = DnsApplier::apply(&guid, &plan.dns)?;
            state.dns = Some(DnsAppliedState {
                guid,
                applied,
                original,
            });
        }
    }
    Ok(())
}

/// Restore one family step in reverse order (compare-and-restore, typed skips).
fn restore_step(step: FamilyStep, state: &AppliedState, luid: u64) -> Result<(), NativeError> {
    match step {
        FamilyStep::Dns => {
            if let Some(dns) = &state.dns {
                // Compare first against the applied fingerprint:
                // `SkipThirdPartyChange` is a typed skip (never overwrite).
                DnsApplier::restore(&dns.guid, &dns.applied, &dns.original)?;
            }
        }
        FamilyStep::Routes => {
            // Reverse install order: last-installed tunnel route removed first.
            for row in build_cleanup_order(&state.installed_tunnel) {
                match remove(&row) {
                    // Removed / AlreadyAbsent: both are success (idempotent skip).
                    Ok(_) => {}
                    // Leaf refused (filled row != request): a third party
                    // modified the route — typed skip, never delete, never
                    // fail the whole restore.
                    Err(e) if e.code == ERROR_INVALID_PARAMETER => {}
                    Err(e) => return Err(e),
                }
            }
        }
        FamilyStep::SystemProxy => {
            // 系统代理 compare-and-restore（逆序中先于 bypass 撤除；设计 §5.3）。
            // 第三方改动 = typed skip（记 restore_failures 的职责在调用方聚合层，
            // 此处不失败不覆盖）；指纹相等 → 精确还原操作（五值写回/删除直调层
            // EXV_TK1C_PENDING，桩拒绝半还原）。
            if let Some(applied) = &state.system_proxy {
                let current =
                    crate::system_proxy::capture_for_user(&applied.sid)?;
                match plan_restore(&applied.prestate, &current, &applied.written_fingerprint) {
                    SystemProxyRestoreOutcome::TypedSkip => {}
                    SystemProxyRestoreOutcome::Restored { .. } => {
                        return Err(NativeError {
                            kind: crate::native_error::NativeErrorKind::Unsupported,
                            code: ERROR_INVALID_PARAMETER,
                            message: "EXV_TK1C_PENDING: 五值写回直调层未接入".to_owned(),
                        });
                    }
                }
            }
        }
        FamilyStep::Bypass => {
            // The bypass rows are removed LAST (after the tunnel routes),
            // in reverse install order.
            for row in state.bypass_rows.iter().rev() {
                match remove(row) {
                    Ok(_) => {}
                    Err(e) if e.code == ERROR_INVALID_PARAMETER => {}
                    Err(e) => return Err(e),
                }
            }
        }
        FamilyStep::Mtu => {
            // Reverse apply order (V6 before V4 when both applied);
            // `SkippedThirdPartyChanged` is a typed skip, never overwrite.
            for (applied, original) in state.mtu.iter().rev() {
                let controller = MtuController::new(applied.luid, applied.family);
                controller.compare_and_restore(applied, original)?;
            }
        }
        FamilyStep::Address => {
            // Compare-delete: only owned rows whose fingerprint is unchanged
            // are deleted; pre-existing rows are never in the owned set, and a
            // third-party-modified row is left alone.
            let controller = IpAddressController::new(luid);
            let current = controller.capture()?;
            let to_delete = restore_owned_addresses(&state.owned_addresses, &current);
            for row in to_delete {
                controller.delete(&row)?;
            }
        }
    }
    Ok(())
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
