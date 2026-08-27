// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! WSP4-A native spike binary：address / MTU / route / DNS 网络设置观测。
//!
//! 在真实 Windows 宿主（需管理员，本文件会短暂修改并**恢复**地址/MTU/路由/DNS）上
//! 运行 `run_network_settings_fact_probe()`，把观测到的事实写成 stdout 的 `FACT:` 行 +
//! JSON evidence 文件。非 elevated 时动态部分记为 `not_run_blocked_by_environment`。
//!
//! ```
//! cargo run --manifest-path src/platform/win32/rust/Cargo.toml --locked \
//!   -p exv-vpn-win32-acceptance --bin exv-win32-network-settings-spike -- \
//!   --evidence-dir docs/superpowers/evidence/vpn-rust-native-runtime-mvp/win32/WSP4
//! ```
//!
//! 提权运行（WSP3 验证过的模式）：写 `.ps1` 到 `%TEMP%`，spike 自写 `--log-file`，
//! 父 shell 零管道；`Start-Process powershell -Verb RunAs -Wait -File <script>`。
//!
//! 事实权威文件：
//! `docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-network-settings-facts.md`。

use std::io::Write;
use std::path::{Path, PathBuf};

use exv_vpn_win32_acceptance::network_settings_facts::{
    run_network_settings_fact_probe, NetworkSettingsFacts,
};

/// 日志文件（--log-file 时打开）：所有输出同时写 stdout 与日志，保证提权
/// 运行（父 shell 管道会杀子进程 / 编码混乱）也能拿到完整证据。
static LOG_FILE: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

fn log_line(s: &str) {
    println!("{s}");
    let _ = std::io::stdout().flush();
    if let Ok(mut g) = LOG_FILE.lock()
        && let Some(f) = g.as_mut()
    {
        let _ = writeln!(f, "{s}");
        let _ = f.flush();
    }
}

/// 把事实写成 `FACT: <key> = <value>` 行，供人类与脚本读取。
fn emit_fact_lines(f: &NetworkSettingsFacts) {
    macro_rules! fact {
        ($key:literal, $value:expr) => {
            log_line(&format!("FACT: {} = {}", $key, $value));
        };
    }
    macro_rules! fact_opt {
        ($key:literal, $value:expr) => {
            log_line(&format!("FACT: {} = {}", $key, opt(&$value)));
        };
    }
    fact!("host.os", f.host_os);
    fact!("host.hostname", f.hostname);
    fact!("env.elevated", f.env_elevated);
    fact!("test_if.blocked_reason", opt(&f.test_if_blocked_reason));
    fact!("test_if.name", opt(&f.test_if_name));
    fact!("test_if.luid", opt(&f.test_if_luid_value));
    fact!("test_if.ifindex", opt(&f.test_if_ifindex));
    fact!("test_if.guid", opt(&f.test_if_guid));
    fact!("test_if.alias", opt(&f.test_if_alias));
    // Address
    fact!("address.precondition_clean", f.address_precondition_clean);
    fact!("address.prep_no_effect", f.address_prep_no_effect);
    fact!("address.created", f.address_created);
    fact_opt!("address.create_error", f.address_create_error);
    fact_opt!("address.readback.addr", f.address_readback_addr);
    fact_opt!("address.readback.onlink_prefix", f.address_readback_onlink_prefix);
    fact_opt!("address.readback.prefix_origin", f.address_readback_prefix_origin);
    fact_opt!("address.readback.suffix_origin", f.address_readback_suffix_origin);
    fact_opt!("address.readback.dad_state", f.address_readback_dad_state);
    fact_opt!("address.readback.skip_as_source", f.address_readback_skip_as_source);
    fact_opt!("address.readback.valid_lifetime", f.address_readback_valid_lifetime);
    fact_opt!("address.readback.preferred_lifetime", f.address_readback_preferred_lifetime);
    fact_opt!("address.readback.creation_ts", f.address_readback_creation_ts);
    fact!("address.third_party_deleted_detected", f.address_third_party_deleted_detected);
    fact_opt!("address.already_exists_error", f.address_already_exists_error);
    fact_opt!("address.partial.invalid_prefix_error", f.address_partial_invalid_prefix_error);
    fact_opt!("address.partial.bogus_interface_error", f.address_partial_bogus_interface_error);
    fact!("address.restore_verified", f.address_restore_verified);
    // MTU
    fact_opt!("mtu.before", f.mtu_before);
    fact_opt!("mtu.v6_before", f.mtu_v6_before);
    fact!("mtu.prep_no_effect", f.mtu_prep_no_effect);
    fact!("mtu.set_attempts", fmt_mtu_attempts(&f.mtu_set_attempts));
    fact!("mtu.applied", f.mtu_applied);
    fact_opt!("mtu.apply_error", f.mtu_apply_error);
    fact_opt!("mtu.after", f.mtu_after);
    fact!("mtu.third_party_detected", f.mtu_third_party_detected);
    fact!("mtu.same_value_idempotent", f.mtu_same_value_idempotent);
    fact_opt!("mtu.illegal_value_error", f.mtu_illegal_value_error);
    fact!("mtu.restore_verified", f.mtu_restore_verified);
    // Route
    fact_opt!("route.bypass_before.dest", f.route_bypass_before_dest);
    fact_opt!("route.bypass_before.nexthop", f.route_bypass_before_nexthop);
    fact_opt!("route.bypass_before.metric", f.route_bypass_before_metric);
    fact_opt!("route.bypass_before.protocol", f.route_bypass_before_protocol);
    fact_opt!("route.bypass_before.interface_alias", f.route_bypass_before_interface_alias);
    fact_opt!("route.bypass_before.luid", f.route_bypass_before_luid);
    fact!("route.prep_no_effect", f.route_prep_no_effect);
    fact!("route.create_variants", fmt_route_variants(&f.route_create_variants));
    fact_opt!("route.control_on_bypass_rc", f.route_control_on_bypass_rc);
    fact_opt!("route.control_cleanup_rc", f.route_control_cleanup_rc);
    fact_opt!("route.create_success_variant", f.route_create_success_variant);
    fact!("route.created", f.route_created);
    fact_opt!("route.create_error", f.route_create_error);
    fact_opt!("route.readback.metric", f.route_readback_metric);
    fact_opt!("route.readback.protocol", f.route_readback_protocol);
    fact_opt!("route.readback.nexthop", f.route_readback_nexthop);
    fact!("route.readback.luid_matches", f.route_readback_luid_matches);
    fact_opt!("route.best_after.nexthop", f.route_best_after_nexthop);
    fact!("route.best_after.luid_matches", f.route_best_after_luid_matches);
    fact!("route.superseded_bypass", f.route_superseded_bypass);
    fact!("route.third_party_delete_detected", f.route_third_party_delete_detected);
    fact_opt!("route.already_exists_error", f.route_already_exists_error);
    fact_opt!("route.partial.invalid_prefix_error", f.route_partial_invalid_prefix_error);
    fact_opt!("route.mutant.delete_by_cidr_only_error", f.route_mutant_delete_by_cidr_only_error);
    fact!("route.delete_full_row_succeeded", f.route_delete_full_row_succeeded);
    fact!("route.restore_verified", f.route_restore_verified);
    // DNS
    fact_opt!("dns.before.version", f.dns_before_version);
    fact_opt!("dns.before.flags", f.dns_before_flags);
    fact!("dns.before.nameservers", opt_list(&f.dns_before_nameservers));
    fact!("dns.before.search_list", opt_list(&f.dns_before_search_list));
    fact!("dns.prep_no_effect", f.dns_prep_no_effect);
    fact!("dns.applied", f.dns_applied);
    fact_opt!("dns.apply_error", f.dns_apply_error);
    fact_opt!("dns.set_version_used", f.dns_set_version_used);
    fact!("dns.readback.nameservers", opt_list(&f.dns_readback_nameservers));
    fact!("dns.readback.search_list", opt_list(&f.dns_readback_search_list));
    fact_opt!("dns.readback.flags", f.dns_readback_flags);
    fact_opt!("dns.readback.version", f.dns_readback_version);
    fact!("dns.third_party_detected", f.dns_third_party_detected);
    fact!("dns.same_value_idempotent", f.dns_same_value_idempotent);
    fact_opt!("dns.partial_unknown_error", f.dns_partial_unknown_error);
    fact!("dns.restore_skipped_third_party", f.dns_restore_skipped_third_party);
    fact!("dns.mutant_unconditional_restore_would_clobber", f.dns_mutant_unconditional_restore_would_clobber);
    fact!("dns.final_state_equals_original", f.dns_final_state_equals_original);
    // cleanup / restore
    fact!("adapter.removed_by_close", f.adapter_removed_by_close);
    fact!("restore.failures", f.restore_failures.join(" | "));
    fact!("restore.ok", f.restore_ok);
    fact!("probe.notes", f.probe_notes.join(" | "));
}

fn opt<T: std::fmt::Display>(v: &Option<T>) -> String {
    match v {
        Some(x) => x.to_string(),
        None => "not_run/none".to_string(),
    }
}

fn opt_list(v: &[String]) -> String {
    if v.is_empty() {
        "(empty)".to_string()
    } else {
        v.join(",")
    }
}

fn fmt_mtu_attempts(
    v: &[exv_vpn_win32_acceptance::network_settings_facts::MtuAttempt],
) -> String {
    if v.is_empty() {
        "(none)".to_string()
    } else {
        v.iter()
            .map(|a| format!("{}:rc={}:rb={}", a.value, a.rc, opt(&a.readback)))
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

fn fmt_route_variants(
    v: &[exv_vpn_win32_acceptance::network_settings_facts::RouteVariantResult],
) -> String {
    if v.is_empty() {
        "(none)".to_string()
    } else {
        v.iter()
            .map(|a| format!("{}:rc={}", a.label, a.rc))
            .collect::<Vec<_>>()
            .join(" | ")
    }
}

fn main() {
    let args = parse_args();
    if let Some(lp) = &args.log_file
        && let Ok(f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(lp)
        && let Ok(mut g) = LOG_FILE.lock()
    {
        *g = Some(f);
    }

    let dll = resolve_wintun_dll(args.dll.as_deref());
    log_line("== EXV WSP4 address/MTU/route/DNS network-settings spike ==");
    log_line(&format!("wintun_dll = {}", dll.display()));

    // 探针 panic 时仍写出 JSON + FACT 行（诊断不丢证据），panic 信息记入 notes。
    let facts = std::panic::catch_unwind(|| run_network_settings_fact_probe(&dll))
        .unwrap_or_else(|p| {
            let msg = if let Some(s) = p.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = p.downcast_ref::<String>() {
                s.clone()
            } else {
                "unknown panic payload".to_string()
            };
            let mut f = exv_vpn_win32_acceptance::network_settings_facts::default_facts();
            f.host_os = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
            f.hostname = std::env::var("COMPUTERNAME").unwrap_or_default();
            f.env_elevated =
                exv_vpn_win32_acceptance::network_settings_facts::is_elevated_exported();
            f.wintun_dll_path = dll.display().to_string();
            f.probe_notes.push(format!("probe panicked: {msg}"));
            f
        });
    emit_fact_lines(&facts);
    log_line(&format!(
        "== dynamic_complete = {} ==",
        facts.is_dynamic_complete()
    ));

    if let Some(dir) = args.evidence_dir {
        let path = dir.as_path().join("wsp4-network-settings-facts.json");
        match serde_json::to_string_pretty(&facts) {
            Ok(json) => {
                if std::fs::create_dir_all(&dir)
                    .and_then(|_| std::fs::write(&path, json))
                    .is_ok()
                {
                    log_line(&format!("EVIDENCE: {}", path.display()));
                } else {
                    log_line(&format!("WARN: 无法写入 evidence 文件 {}", path.display()));
                }
            }
            Err(e) => log_line(&format!("WARN: 无法序列化 facts: {e}")),
        }
    }

    log_line("== spike done ==");
}

fn parse_args() -> Args {
    let mut a = Args {
        evidence_dir: None,
        dll: None,
        log_file: None,
    };
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--evidence-dir" {
            if let Some(v) = args.get(i + 1) {
                a.evidence_dir = Some(PathBuf::from(v));
            }
        } else if args[i] == "--dll" {
            if let Some(v) = args.get(i + 1) {
                a.dll = Some(PathBuf::from(v));
            }
        } else if args[i] == "--log-file"
            && let Some(v) = args.get(i + 1)
        {
            a.log_file = Some(PathBuf::from(v));
        }
        i += 1;
    }
    a
}

fn resolve_wintun_dll(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    exv_vpn_win32_acceptance::network_settings_facts::resolve_wintun_dll_path(None)
}

struct Args {
    evidence_dir: Option<PathBuf>,
    dll: Option<PathBuf>,
    log_file: Option<PathBuf>,
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
