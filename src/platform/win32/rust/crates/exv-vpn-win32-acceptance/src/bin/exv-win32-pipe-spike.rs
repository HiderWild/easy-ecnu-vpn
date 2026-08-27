// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! WSP1-A native spike binary：Named Pipe + HTTP/2 + 双向身份。
//!
//! 在真实 Windows 宿主上运行 `run_named_pipe_fact_probe()`，把观测到的事实写成
//! stdout 的 `FACT:` 行 + JSON evidence 文件。
//!
//! ```
//! cargo run --manifest-path src/platform/win32/rust/Cargo.toml --locked \
//!   -p exv-vpn-win32-acceptance --bin exv-win32-pipe-spike -- \
//!   --evidence-dir docs/superpowers/evidence/vpn-rust-native-runtime-mvp/win32/WSP1
//! ```
//!
//! 事实权威文件：`docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-pipe-facts.md`。

use std::path::PathBuf;

use exv_vpn_win32_acceptance::named_pipe_facts::{run_named_pipe_fact_probe, NamedPipeFacts};

/// 把事实写成 `FACT: <key> = <value>` 行，供人类与脚本读取。
fn emit_fact_lines(f: &NamedPipeFacts) {
    macro_rules! fact {
        ($key:literal, $value:expr) => {
            println!("FACT: {} = {}", $key, $value);
        };
    }
    fact!("host.os", f.os);
    fact!("host.hostname", f.hostname);
    fact!("pipe.mode_selected", f.pipe_mode_selected);
    fact!("pipe.type_observed", f.pipe_type_observed);
    fact!("h2.preface_carried_over_byte_pipe", f.h2_preface_carried_over_byte_pipe);
    fact!("h2.preface_bytes", f.h2_preface_bytes);
    fact!("security.reject_remote_clients_flag_set", f.reject_remote_clients_flag_set);
    fact!("security.reject_remote_plus_first_instance_compatible", f.reject_remote_plus_first_instance_compatible);
    fact!("security.second_instance_squatting_rejected", f.second_instance_squatting_rejected);
    fact!("security.second_instance_error_code", opt(&f.second_instance_error_code));
    fact!("security.remote_client_rejection", f.remote_client_rejection);
    fact!("peer.client_pid", opt(&f.client_pid));
    fact!("peer.client_pid_matches_self", f.client_pid_matches_self);
    fact!("peer.client_computer_name", opt(&f.client_computer_name));
    fact!("peer.client_user_sid", opt(&f.client_user_sid));
    fact!("peer.client_logon_sid", opt(&f.client_logon_sid));
    fact!("peer.client_account", opt(&f.client_account));
    fact!("peer.wrong_client_sid_rejected", opt(&f.wrong_client_sid_rejected));
    fact!("peer.token_query_failure_fails_closed", opt(&f.token_query_failure_fails_closed));
    fact!("peer.fake_helper_server_rejected", opt(&f.fake_helper_server_rejected));
    fact!("preauth.oversize_rejected_without_dispatch", opt(&f.preauth_oversize_rejected_without_dispatch));
    fact!("preauth.unauthorized_no_dispatch", opt(&f.unauthorized_no_dispatch));
    fact!("preauth.dispatch_count_observed", f.dispatch_count_observed);
    fact!("security.endpoint_name_alone_grants_authority", f.endpoint_name_alone_grants_authority);
    fact!("security.dacl_sddl", f.dacl_sddl);
    fact!("preauth.stream_limit", f.preauth_stream_limit);
    fact!("preauth.message_limit", f.preauth_message_limit);
    fact!("preauth.buffer_limit", f.preauth_buffer_limit);
    fact!("topology.control_data_separate_connections", f.control_data_separate_connections);
}

fn opt<T: std::fmt::Display>(v: &Option<T>) -> String {
    match v {
        Some(x) => x.to_string(),
        None => "not_run/none".to_string(),
    }
}

fn main() {
    let evidence_dir = parse_evidence_dir();
    let facts = run_named_pipe_fact_probe();

    println!("== EXV WSP1 Named Pipe + HTTP/2 + bidirectional auth spike ==");
    emit_fact_lines(&facts);
    println!("== facts.complete = {}", facts.is_complete());

    if let Some(dir) = evidence_dir {
        let path = dir.as_path().join("wsp1-named-pipe-facts.json");
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