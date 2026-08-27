// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! WSP2-A native spike binary：singleton authority + durable Windows storage。
//!
//! 在真实 Windows 宿主（无需管理员）上运行 `run_authority_storage_fact_probe()`，
//! 把观测到的事实写成 stdout 的 `FACT:` 行 + JSON evidence 文件。本二进制同时是
//! 双进程 authority case 的子进程执行体（`EXV_WSP2_CHILD_MODE` 环境变量驱动，
//! 见 `run_child_mode`）。
//!
//! ```
//! cargo run --manifest-path src/platform/win32/rust/Cargo.toml --locked \
//!   -p exv-vpn-win32-acceptance --bin exv-win32-authority-storage-spike -- \
//!   --evidence-dir docs/superpowers/evidence/vpn-rust-native-runtime-mvp/win32/WSP2
//! ```
//!
//! 事实权威文件：
//! `docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-authority-storage-facts.md`。

use std::path::PathBuf;

use exv_vpn_win32_acceptance::authority_storage_facts::{
    run_authority_storage_fact_probe, run_child_mode, AuthorityStorageFacts,
};

/// 把事实写成 `FACT: <key> = <value>` 行，供人类与脚本读取。
fn emit_fact_lines(f: &AuthorityStorageFacts) {
    macro_rules! fact {
        ($key:literal, $value:expr) => {
            println!("FACT: {} = {}", $key, $value);
        };
    }
    fact!("host.os", f.host_os);
    fact!("host.hostname", f.hostname);
    fact!("env.elevated", f.env_elevated);
    fact!("authority.primitive_choice", f.primitive_choice);
    fact!("authority.mutex_namespace", f.mutex_namespace);
    fact!("authority.global_namespace_probe", f.global_namespace_probe);
    fact!("authority.mutex_dacl_sddl", f.mutex_dacl_sddl);
    fact!("authority.mutex_race_loser_result", f.mutex_two_process_race_winner_is_loser);
    fact!("authority.mutex_loser_wait_code", f.mutex_loser_wait_code);
    fact!("authority.mutex_loser_exited_before_scan_observe_publish", f.mutex_loser_exited_before_scan_observe_publish);
    fact!("authority.mutex_reusable_after_release", f.mutex_reusable_after_release);
    fact!("authority.mutex_abandoned_owner_killed_without_release", f.mutex_abandoned_owner_killed_without_release);
    fact!("authority.mutex_abandoned_wait_code", f.mutex_abandoned_wait_code);
    fact!("authority.mutex_abandoned_granted", f.mutex_abandoned_granted);
    fact!("authority.lockfile_second_locker_fails", f.lockfile_second_locker_fails);
    fact!("authority.lockfile_second_locker_error_code", f.lockfile_second_locker_error_code);
    fact!("authority.lockfile_reacquirable_after_release", f.lockfile_reacquirable_after_release);
    fact!("authority.lockfile_has_abandoned_notification", f.lockfile_has_abandoned_notification);
    fact!("journal.base_programdata", f.journal_base_programdata);
    fact!("journal.programdata_creatable_non_admin", f.programdata_creatable_non_admin);
    fact!("journal.programdata_create_error", opt(&f.programdata_create_error));
    fact!("journal.path_chosen", f.journal_path_chosen);
    fact!("journal.dir_acl_sddl", f.journal_dir_acl_sddl);
    fact!("journal.create_file_access", f.create_file_access);
    fact!("journal.create_file_share_mode", f.create_file_share_mode);
    fact!("journal.append_only_write_ok", f.append_only_write_ok);
    fact!("journal.append_after_seek_lands_at_eof", f.append_after_seek_lands_at_eof);
    fact!("journal.second_writer_share_violation_observed", f.second_writer_share_violation_observed);
    fact!("journal.second_writer_share_violation_error_code", f.second_writer_share_violation_error_code);
    fact!("journal.flush_file_buffers_succeeds", f.flush_file_buffers_succeeds);
    fact!("journal.append_visible_to_second_handle", f.append_visible_to_second_handle);
    fact!("journal.rust_std_flush_is_not_durable_sync", f.rust_std_flush_is_not_durable_sync);
    fact!("journal.movefile_replace_succeeds", f.movefile_replace_succeeds);
    fact!("journal.dir_flush_succeeds", f.dir_flush_succeeds);
    fact!("journal.j50_clean_roundtrip", f.j50_clean_roundtrip);
    fact!("journal.torn_tail_recovers_to_last_complete", f.torn_tail_recovers_to_last_complete);
    fact!("journal.torn_tail_recovered_count", f.torn_tail_recovered_count);
    fact!("journal.corrupt_middle_no_skip", f.corrupt_middle_no_skip);
    fact!("journal.corrupt_middle_recovered_count", f.corrupt_middle_recovered_count);
    fact!("acl.deny_open_fails", f.acl_deny_open_fails);
    fact!("acl.deny_error_code", f.acl_deny_error_code);
    fact!("acl.restore_succeeds", f.acl_restore_succeeds);
    fact!("acl.test_original_sddl", f.acl_test_original_sddl);
    fact!("acl.test_deny_sddl", f.acl_test_deny_sddl);
}

fn opt<T: std::fmt::Display>(v: &Option<T>) -> String {
    match v {
        Some(x) => x.to_string(),
        None => "not_run/none".to_string(),
    }
}

fn main() {
    // 双进程 authority case 的子进程执行体：检测到子模式立即执行并退出，
    // 不进入正常探针路径。
    if std::env::var_os("EXV_WSP2_CHILD_MODE").is_some() {
        run_child_mode();
    }

    let evidence_dir = parse_evidence_dir();
    // 子进程执行体与本二进制相同：用 current_exe 再生成子进程。
    let self_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("exv-win32-authority-storage-spike.exe"));
    let facts = run_authority_storage_fact_probe(&self_exe);

    println!("== EXV WSP2 authority + durable storage spike ==");
    emit_fact_lines(&facts);
    println!("== facts.complete = {}", facts.is_complete());

    if let Some(dir) = evidence_dir {
        let path = dir.as_path().join("wsp2-authority-storage-facts.json");
        // 写 JSON evidence。失败仅打印警告，不伪造成功。
        match serde_json::to_string_pretty(&facts) {
            Ok(json) => {
                if std::fs::create_dir_all(&dir).and_then(|_| std::fs::write(&path, json)).is_ok() {
                    println!("EVIDENCE: {}", path.display());
                } else {
                    eprintln!("WARN: 无法写入 evidence 文件 {}", path.display());
                }
            }
            Err(e) => eprintln!("WARN: 无法序列化 facts: {e}"),
        }
    }
}

fn parse_evidence_dir() -> Option<PathBuf> {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--evidence-dir" && let Some(v) = args.get(i + 1) {
            return Some(PathBuf::from(v));
        }
        i += 1;
    }
    None
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
