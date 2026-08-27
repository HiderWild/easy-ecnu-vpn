// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! 系统代理 family 的执行层（TK1b；设计 §5.3）。
//!
//! [`crate::system_proxy_family`] 提供纯决策（`decide`/`compute_restore`），
//! 本模块把决策接到副作用边界上：
//!
//! - [`apply_from_prestate`]：快照 → `decide` 三分派——Disabled 零动作零账本
//!   （拍板结论 4）；Manual/Mixed 合并写入 + 广播；Automatic typed skip
//!   （`EXV_PAC_FAMILY_PENDING`: engine 侧 PAC 包装接线另立任务）。
//! - [`restore_from_current`]：compare-and-restore——当前指纹 == 写入指纹才
//!   产出精确还原操作序列（存在 → 字节级写回；原不存在 → 删除该值）；第三方
//!   改动是 [`SystemProxyRestoreOutcome::TypedSkip`]，绝不强写。
//!
//! Win32 注册表写回/删除的直调层见 [`EXV_TK1C_PENDING`]（`write_registry_value`
//! 桩）：apply 侧写入走 [`crate::system_proxy_override::write_override_for_user`]
//! 既有实现，restore 侧五值泛化写回在下一增量补齐。journal 落盘由 engine 接线
//! 在 apply 成功前以 `SystemProxyFamilyStep::to_payload` 经
//! `journal_store::append_synced` 完成——本模块只产出步骤记录与指纹。

use crate::native_error::{NativeError, NativeErrorKind};
use crate::system_proxy::{capture_for_user, snapshot_from_raw, RawInternetSettings, RawValue};
use crate::system_proxy_family::{
    compute_restore, decide, RestoreDecision, RestoreOp, SystemProxyFamilyStep,
};

/// 五值的注册表指纹（compare-and-restore 的比较输入）：按固定顺序拼接各值的
/// tag + 内容字节。任何第三方对五值任一的改动都会改变指纹。
#[must_use]
pub fn fingerprint_prestate(raw: &RawInternetSettings) -> Vec<u8> {
    let mut buf = Vec::new();
    for value in [
        &raw.proxy_enable,
        &raw.proxy_server,
        &raw.proxy_override,
        &raw.auto_config_url,
        &raw.auto_detect,
    ] {
        match value {
            RawValue::Absent => buf.push(0),
            RawValue::Dword(v) => {
                buf.push(1);
                buf.extend_from_slice(&v.to_le_bytes());
            }
            RawValue::Other { r#type, data } => {
                buf.push(2);
                buf.extend_from_slice(&r#type.to_le_bytes());
                buf.extend_from_slice(data);
            }
            // REG_SZ 的指纹取其 UTF-16 单元字节（与 capture 的去尾 NUL 语义一致，
            // 同一文本恒得同一指纹）。
            RawValue::Sz(s) => {
                buf.push(3);
                let units: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                buf.extend_from_slice(&units);
            }
        }
    }
    buf
}

/// apply 阶段系统代理 family 步骤的执行结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemProxyApplyOutcome {
    /// Disabled：零动作零账本（拍板结论 4）。
    SkippedNoProxy,
    /// Automatic / WPAD：typed skip（v1 不接线 PAC）。
    PacDetectedSkip,
    /// Manual/Mixed：已合并写入 + 广播。携带 journal 落盘所需的步骤记录与
    /// 「写入后」指纹（还原时的 compare 基准）。
    Applied {
        /// apply 成功前由调用方落盘的步骤记录。
        step: SystemProxyFamilyStep,
        /// 写入后立即重读五值得到的指纹（= 我们写入状态的基准指纹）。
        written_fingerprint: Vec<u8>,
    },
}

/// 执行 apply 阶段的系统代理 family 步骤（真机入口；含 PAC 开环包装）。
///
/// admission-first：`capture_for_user` 或解析失败直接返回 `Err`——此时零效果，
/// 调用方的整计划 admission 语义（W22-I）据此放弃整个 plan。
///
/// # Errors
///
/// 注册表不可读、快照自洽性破坏、或写入/广播失败时传播类型化 [`NativeError`]。
pub fn apply_system_proxy_step(
    originating_sid: &str,
    desired_entries: &[String],
) -> Result<SystemProxyApplyOutcome, NativeError> {
    let prestate = capture_for_user(originating_sid)?;
    apply_from_prestate(originating_sid, desired_entries, prestate)
}

/// apply 的**带 PAC 开环包装**入口（设计 §7-3 二次修订；engine 侧使用）：
/// Automatic（有 `AutoConfigURL`）时，一次性下载原文 → 文本包装 → 起 loopback
/// 端点 → 把 `AutoConfigURL` 改指端点 → 广播。任一步失败 **fail-closed** 回退为
/// 「仅提示」（[`SystemProxyApplyResult::Pac`] 且 `endpoint: None`），绝不静默
/// 半改写注册表。开环语义：注入后不跟踪，代理软件改写即失效、重连刷新。
///
/// 零扰动纪律（设计 §5.6）：端点先可服务 → 再改注册表 → 再广播。
pub fn apply_system_proxy_with_pac(
    originating_sid: &str,
    desired_entries: &[String],
) -> Result<SystemProxyApplyResult, NativeError> {
    let prestate = capture_for_user(originating_sid)?;
    let snapshot = snapshot_from_raw(&prestate)?;
    match decide(&snapshot, desired_entries)? {
        crate::system_proxy_family::FamilyAction::SkipNoOp => {
            Ok(SystemProxyApplyResult::SkippedNoProxy)
        }
        crate::system_proxy_family::FamilyAction::MergeAndWrite { .. } => {
            let step = SystemProxyFamilyStep {
                prestate: prestate.clone(),
                desired_entries: desired_entries.to_vec(),
                originating_sid: originating_sid.to_owned(),
                pac_detected: false,
            };
            let merged = decide_merged(&snapshot, desired_entries)?;
            let _broadcasted =
                crate::system_proxy_override::write_override_for_user(originating_sid, &merged)?;
            let written = capture_for_user(originating_sid)?;
            Ok(SystemProxyApplyResult::Applied {
                step,
                written_fingerprint: fingerprint_prestate(&written),
            })
        }
        crate::system_proxy_family::FamilyAction::PacDetectedSkip => {
            let step = SystemProxyFamilyStep {
                prestate: prestate.clone(),
                desired_entries: desired_entries.to_vec(),
                originating_sid: originating_sid.to_owned(),
                pac_detected: true,
            };
            // 取 AutoConfigURL 原文（缺失/非文本 → 无包装对象，fail-closed 提示）。
            let url = match &prestate.auto_config_url {
                RawValue::Sz(u) if !u.is_empty() => u.clone(),
                _ => {
                    return Ok(SystemProxyApplyResult::Pac {
                        step,
                        written_fingerprint: fingerprint_prestate(&prestate),
                        endpoint: None,
                    });
                }
            };
            // 一次性开环包装：任一步失败 → 回退仅提示（endpoint None），不报错
            // 不阻断隧道（与 Manual 分支 best-effort 一致）。
            let endpoint = match try_pac_wrap(originating_sid, &url, desired_entries) {
                Ok(endpoint) => Some(endpoint),
                Err(e) => {
                    tracing::warn!(?e, "system-proxy pac wrap degraded (best-effort)");
                    None
                }
            };
            let written = capture_for_user(originating_sid)?;
            Ok(SystemProxyApplyResult::Pac {
                step,
                written_fingerprint: fingerprint_prestate(&written),
                endpoint,
            })
        }
    }
}

/// 一次性 PAC 开环包装：下载 → 包装 → 起端点 → 改指 `AutoConfigURL` → 广播。
///
/// 零扰动顺序（§5.6）：端点先可服务 → 写注册表 → 广播刷新。任何一步失败返回
/// `Err`——调用方已按 fail-closed 回退，端点若已起则随返回值丢弃（Drop 即关）。
fn try_pac_wrap(
    sid: &str,
    pac_url: &str,
    desired_entries: &[String],
) -> Result<crate::system_proxy_pac::PacEndpoint, NativeError> {
    use std::sync::Arc;
    let original = crate::system_proxy_pac::fetch_pac_script(pac_url)?;
    let wrapped = crate::system_proxy_pac::wrap_pac_script(&original, desired_entries)?;
    let endpoint = crate::system_proxy_pac::PacEndpoint::spawn(Arc::new(wrapped))
        .map_err(|e| NativeError::from_win32(87, &format!("pac-endpoint-spawn:{e}")))?;
    let served_url = format!("http://127.0.0.1:{}/proxy.pac", endpoint.port());
    crate::system_proxy_override::write_back_value_for_user(
        sid,
        crate::system_proxy_family::ValueName::AutoConfigUrl,
        &RawValue::Sz(served_url),
    )?;
    crate::system_proxy_override::broadcast_wininet_refresh();
    Ok(endpoint)
}

/// apply 结果（含 PAC 端点持有，供 teardown 关闭；不复用 [`SystemProxyApplyOutcome`]
/// 的 Clone/Eq 派生——端点持有线程句柄不可克隆）。
#[derive(Debug)]
pub enum SystemProxyApplyResult {
    /// Disabled：零动作零账本（拍板结论 4）。
    SkippedNoProxy,
    /// Manual/Mixed：已合并写入 + 广播。
    Applied {
        /// journal 落盘所需的步骤记录。
        step: SystemProxyFamilyStep,
        /// 写入后指纹（还原 compare 基准）。
        written_fingerprint: Vec<u8>,
    },
    /// Automatic：PAC 开环包装（成功 `endpoint: Some`；失败回退提示 `None`）。
    Pac {
        /// journal 落盘所需的步骤记录。
        step: SystemProxyFamilyStep,
        /// 改指后指纹（还原 compare 基准）。
        written_fingerprint: Vec<u8>,
        /// loopback 包装端点（Drop 即关；teardown 还原注册表后再 drop）。
        endpoint: Option<crate::system_proxy_pac::PacEndpoint>,
    },
}

/// [`apply_system_proxy_step`] 的可注入内核：prestate 由调用方给定（单测不触真机）。
pub fn apply_from_prestate(
    originating_sid: &str,
    desired_entries: &[String],
    prestate: RawInternetSettings,
) -> Result<SystemProxyApplyOutcome, NativeError> {
    let snapshot = snapshot_from_raw(&prestate)?;
    match decide(&snapshot, desired_entries)? {
        crate::system_proxy_family::FamilyAction::SkipNoOp => Ok(SystemProxyApplyOutcome::SkippedNoProxy),
        crate::system_proxy_family::FamilyAction::PacDetectedSkip => {
            Ok(SystemProxyApplyOutcome::PacDetectedSkip)
        }
        crate::system_proxy_family::FamilyAction::MergeAndWrite { .. } => {
            let step = SystemProxyFamilyStep {
                prestate: prestate.clone(),
                desired_entries: desired_entries.to_vec(),
                originating_sid: originating_sid.to_owned(),
                pac_detected: false,
            };
            // decide 已算出 merged；此处经真机 leaf 写入 + 广播。广播 skip
            // （wininet 缺失，Ok(false)）仍是成功写入，设置重启后生效，不阻断。
            let merged = decide_merged(&snapshot, desired_entries)?;
            let _broadcasted =
                crate::system_proxy_override::write_override_for_user(originating_sid, &merged)?;
            let written = capture_for_user(originating_sid)?;
            Ok(SystemProxyApplyOutcome::Applied {
                step,
                written_fingerprint: fingerprint_prestate(&written),
            })
        }
    }
}

/// 取出合并结果（`decide` 的 MergeAndWrite 变体重放；避免 FamilyAction 携带
/// String 导致的 match 借用纠缠——纯读函数，成本可忽略）。
fn decide_merged(
    snapshot: &crate::system_proxy::SystemProxySnapshot,
    desired: &[String],
) -> Result<String, NativeError> {
    match decide(snapshot, desired)? {
        crate::system_proxy_family::FamilyAction::MergeAndWrite { merged } => Ok(merged),
        _ => Err(NativeError {
            kind: NativeErrorKind::Protocol,
            code: 87,
            message: "system_proxy_family_exec: 决策重放变体不符".to_owned(),
        }),
    }
}

/// restore 阶段的结果（teardown/recovery 共用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemProxyRestoreOutcome {
    /// 指纹相等：还原操作序列就绪/已执行（写回 N 个 + 删除 M 个）。
    Restored {
        /// 字节级写回的原存在值个数。
        write_backs: usize,
        /// 删除的原本不存在值个数。
        deletes: usize,
    },
    /// 指纹不等：第三方中途改动，typed skip（调用方记 restore_failures）。
    TypedSkip,
}

/// 执行 restore 阶段系统代理 family 步骤的比较内核（可注入，单测不触真机）。
///
/// `current` 为 teardown 时重读的五值；`written_fingerprint` 为 apply 后记录的
/// 基准指纹。相等 → [`compute_restore`] 的精确还原操作序列；不等 → typed skip。
#[must_use]
pub fn plan_restore(
    prestate: &RawInternetSettings,
    current: &RawInternetSettings,
    written_fingerprint: &[u8],
) -> SystemProxyRestoreOutcome {
    let current_fp = fingerprint_prestate(current);
    match compute_restore(prestate, &current_fp, written_fingerprint) {
        RestoreDecision::TypedSkip => SystemProxyRestoreOutcome::TypedSkip,
        RestoreDecision::Restore { ops } => SystemProxyRestoreOutcome::Restored {
            write_backs: ops
                .iter()
                .filter(|op| matches!(op, RestoreOp::WriteBack { .. }))
                .count(),
            deletes: ops
                .iter()
                .filter(|op| matches!(op, RestoreOp::DeleteValue { .. }))
                .count(),
        },
    }
}

/// teardown 便捷入口：从 journal 步骤记录 + 当前真机状态还原（真机入口）。
///
/// compare-and-restore：当前值指纹 == 写入后指纹才执行精确还原（存在 → 字节级
/// 写回；原不存在 → 删除该值）；第三方改动是 [`SystemProxyRestoreOutcome::TypedSkip`]，
/// 绝不强写（设计 §5.3 / 拍板结论 3）。
///
/// # Errors
///
/// 注册表操作失败传播；第三方改动不是错误（typed skip）。
pub fn restore_system_proxy_step(
    sid: &str,
    step: &SystemProxyFamilyStep,
    written_fingerprint: &[u8],
) -> Result<SystemProxyRestoreOutcome, NativeError> {
    let current = capture_for_user(sid)?;
    let current_fp = fingerprint_prestate(&current);
    match compute_restore(&step.prestate, &current_fp, written_fingerprint) {
        RestoreDecision::TypedSkip => Ok(SystemProxyRestoreOutcome::TypedSkip),
        RestoreDecision::Restore { ops } => {
            let mut write_backs = 0usize;
            let mut deletes = 0usize;
            for op in ops {
                match op {
                    RestoreOp::WriteBack { value_name, value } => {
                        crate::system_proxy_override::write_back_value_for_user(
                            sid,
                            value_name,
                            &value,
                        )?;
                        write_backs += 1;
                    }
                    RestoreOp::DeleteValue { value_name } => {
                        crate::system_proxy_override::delete_value_for_user(sid, value_name)?;
                        deletes += 1;
                    }
                }
            }
            crate::system_proxy_override::broadcast_wininet_refresh();
            Ok(SystemProxyRestoreOutcome::Restored { write_backs, deletes })
        }
    }
}

/// 广播刷新（供 apply 侧合并写入后调用；wininet 缺失是 typed skip 不是错误）。
#[allow(dead_code)]
pub fn broadcast_after_write() {
    crate::system_proxy_override::broadcast_wininet_refresh();
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_proxy::SystemProxyMode;

    fn manual_prestate(override_entries: &str) -> RawInternetSettings {
        RawInternetSettings {
            proxy_enable: RawValue::Dword(1),
            proxy_server: RawValue::Sz("127.0.0.1:7890".to_owned()),
            proxy_override: RawValue::Sz(override_entries.to_owned()),
            auto_config_url: RawValue::Absent,
            auto_detect: RawValue::Absent,
        }
    }

    fn disabled_prestate() -> RawInternetSettings {
        RawInternetSettings {
            proxy_enable: RawValue::Dword(0),
            proxy_server: RawValue::Absent,
            proxy_override: RawValue::Absent,
            auto_config_url: RawValue::Absent,
            auto_detect: RawValue::Absent,
        }
    }

    fn pac_prestate() -> RawInternetSettings {
        RawInternetSettings {
            proxy_enable: RawValue::Dword(1),
            proxy_server: RawValue::Absent,
            proxy_override: RawValue::Absent,
            auto_config_url: RawValue::Sz("http://proxy.example.com/proxy.pac".to_owned()),
            auto_detect: RawValue::Absent,
        }
    }

    #[test]
    fn fingerprint_is_order_sensitive_and_content_sensitive() {
        let a = manual_prestate("a.com;b.com");
        let b = manual_prestate("b.com;a.com");
        let c = manual_prestate("a.com;b.com ");
        assert_eq!(fingerprint_prestate(&a), fingerprint_prestate(&manual_prestate("a.com;b.com")));
        assert_ne!(fingerprint_prestate(&a), fingerprint_prestate(&b), "顺序敏感");
        assert_ne!(fingerprint_prestate(&a), fingerprint_prestate(&c), "内容敏感");
    }

    #[test]
    fn fingerprint_absent_vs_present_differ() {
        assert_ne!(
            fingerprint_prestate(&disabled_prestate()),
            fingerprint_prestate(&manual_prestate(""))
        );
    }

    #[test]
    fn apply_disabled_yields_skip_noop() {
        let out = apply_from_prestate("S-1-5-21-1", &["10.0.0.1".to_owned()], disabled_prestate())
            .expect("决策必成功");
        assert_eq!(out, SystemProxyApplyOutcome::SkippedNoProxy);
    }

    #[test]
    fn apply_pac_yields_typed_skip() {
        let out = apply_from_prestate("S-1-5-21-1", &["10.0.0.1".to_owned()], pac_prestate())
            .expect("决策必成功");
        assert_eq!(out, SystemProxyApplyOutcome::PacDetectedSkip);
    }

    #[test]
    fn apply_enable_without_endpoints_is_disabled_noop() {
        // ProxyEnable=true 但无端点无 PAC → snapshot_from_raw 判 Disabled
        //（mode 判定以端点/PAC 存在性为准）→ 零动作，不是错误。
        let broken = RawInternetSettings {
            proxy_enable: RawValue::Dword(1),
            proxy_server: RawValue::Absent,
            proxy_override: RawValue::Absent,
            auto_config_url: RawValue::Absent,
            auto_detect: RawValue::Absent,
        };
        let out = apply_from_prestate("S-1-5-21-1", &[], broken).expect("决策必成功");
        assert_eq!(out, SystemProxyApplyOutcome::SkippedNoProxy);
    }

    #[test]
    fn apply_enable_false_with_endpoints_propagates_malformed() {
        // 自洽性破坏（fail-closed）：ProxyEnable=false 却有端点 → malformed 传播。
        let broken = RawInternetSettings {
            proxy_enable: RawValue::Dword(0),
            proxy_server: RawValue::Sz("127.0.0.1:7890".to_owned()),
            proxy_override: RawValue::Absent,
            auto_config_url: RawValue::Absent,
            auto_detect: RawValue::Absent,
        };
        assert!(apply_from_prestate("S-1-5-21-1", &[], broken).is_err());
    }

    #[test]
    fn restore_equal_fingerprints_plans_exact_restore() {
        let prestate = manual_prestate("localhost");
        let outcome = plan_restore(&prestate, &prestate.clone(), &fingerprint_prestate(&prestate));
        match outcome {
            SystemProxyRestoreOutcome::Restored { write_backs, deletes } => {
                // prestate 五值中 3 个存在（enable/server/override）→ 写回 3；
                // 2 个不存在（pac_url/auto_detect）→ 删除 2。
                assert_eq!(write_backs, 3);
                assert_eq!(deletes, 2);
            }
            other => panic!("期望 Restored，得到 {other:?}"),
        }
    }

    #[test]
    fn restore_third_party_change_is_typed_skip() {
        let prestate = manual_prestate("localhost");
        let current = manual_prestate("localhost;someone-else");
        let outcome = plan_restore(&prestate, &current, &fingerprint_prestate(&prestate));
        assert_eq!(outcome, SystemProxyRestoreOutcome::TypedSkip);
    }

    #[test]
    fn restore_absent_values_plan_delete_branch() {
        // 五值中 Absent 的项走删除分支、存在的项字节级写回——与 RawValue 存在性
        // 一一对应。
        let mut prestate = disabled_prestate();
        prestate.proxy_enable = RawValue::Absent;
        let outcome = plan_restore(&prestate, &prestate.clone(), &fingerprint_prestate(&prestate));
        match outcome {
            SystemProxyRestoreOutcome::Restored { write_backs, deletes } => {
                assert_eq!(write_backs, 0, "全 Absent 无写回");
                assert_eq!(deletes, 5, "原全不存在 → 全删除分支");
            }
            other => panic!("期望 Restored，得到 {other:?}"),
        }
    }

    #[test]
    fn step_helpers_report_effect_and_fingerprint() {
        use crate::system_proxy_family::SystemProxyFamilyStep;
        let step = SystemProxyFamilyStep {
            prestate: manual_prestate("localhost"),
            desired_entries: vec!["10.0.0.1".to_owned()],
            originating_sid: "S-1-5-21-1".to_owned(),
            pac_detected: false,
        };
        assert!(step.prestate_has_effect());
        assert!(!step.written_fingerprint_bytes().is_empty());

        let noop = SystemProxyFamilyStep {
            prestate: disabled_prestate(),
            desired_entries: vec![],
            originating_sid: "S-1-5-21-1".to_owned(),
            pac_detected: false,
        };
        assert!(!noop.prestate_has_effect());
    }

    #[test]
    fn snapshot_mode_matches_decide_dispatch() {
        // 与 system_proxy.rs 的 mode 判定联动：Manual 快照喂 decide 得 MergeAndWrite。
        let snapshot = crate::system_proxy::snapshot_from_raw(&manual_prestate("localhost"))
            .expect("解析成功");
        assert_eq!(snapshot.mode, SystemProxyMode::Manual);
        match decide(&snapshot, &["10.99.99.1".to_owned()]).expect("decide") {
            crate::system_proxy_family::FamilyAction::MergeAndWrite { merged } => {
                assert!(merged.contains("10.99.99.1"));
                assert!(merged.contains("localhost"), "原条目无损");
            }
            other => panic!("期望 MergeAndWrite，得到 {other:?}"),
        }
    }
}
