// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! WSP1-T Terra oracle：Named Pipe + HTTP/2 + 双向身份。
//!
//! 本测试在**真实 Windows 宿主**上运行原生 spike seam `run_named_pipe_fact_probe`，
//! 并断言探针观测到的事实（把它们冻结为契约）。若未来实现破坏某个冻结事实
//! （例如改用 message-mode、去掉 PIPE_REJECT_REMOTE_CLIENTS、把端点名当 authority），
//! 对应测试必然失败。
//!
//! GREEN 固定为 6 passed; 0 failed; 0 ignored。
//! 远端 client 拒绝无法在本机（无网络 client）真实触发，记为
//! `remote_client_rejection = not_run_blocked_by_environment`，不伪装成 pass/fail。

use exv_vpn_win32_acceptance::named_pipe_facts::{run_named_pipe_fact_probe, NamedPipeFacts};
use std::sync::OnceLock;

/// 探针只跑一次，六项断言共享同一份观测（保持确定性、避免重复建 pipe）。
fn facts() -> &'static NamedPipeFacts {
    static FACTS: OnceLock<NamedPipeFacts> = OnceLock::new();
    FACTS.get_or_init(run_named_pipe_fact_probe)
}

/// byte 流承载 h2 preface，且跨 partial read/write 重组正确。
#[test]
fn byte_stream_carries_h2_preface_across_partial_io() {
    let f = facts();
    assert_eq!(f.pipe_mode_selected, "byte", "spike 必须选 byte 模式承接 h2 preface");
    assert_ne!(f.pipe_type_observed, "message", "message 模式会破坏 h2 字节流 framing");
    assert!(
        f.h2_preface_carried_over_byte_pipe,
        "h2 preface 必须在 byte 流上跨 partial I/O 完整搬运"
    );
    assert_eq!(f.h2_preface_bytes, 24, "RFC 9113 §3.5 preface 固定 24 字节");
}

/// 远端 client 拒绝标志与 second-instance squatting 检测。
///
/// 真实远端 client 拒绝需要另一台宿主，本机记为 not_run；本测试断言本机可观测的
/// 那一半：`PIPE_REJECT_REMOTE_CLIENTS` 已置位、与 `FILE_FLAG_FIRST_PIPE_INSTANCE`
/// 共存、同名第二实例被拒。
#[test]
fn remote_and_second_pipe_instance_are_rejected() {
    let f = facts();
    assert!(
        f.reject_remote_clients_flag_set,
        "server pipe 必须带 PIPE_REJECT_REMOTE_CLIENTS"
    );
    assert!(
        f.reject_remote_plus_first_instance_compatible,
        "PIPE_REJECT_REMOTE_CLIENTS + FILE_FLAG_FIRST_PIPE_INSTANCE 必须能共存"
    );
    assert!(
        f.second_instance_squatting_rejected,
        "同名第二 listener 必须被 FIRST_INSTANCE 拒绝（anti-squatting）"
    );
    assert_eq!(f.remote_client_rejection, "not_run_blocked_by_environment");
}

/// server 能查询 client 的 PID/token/user-SID/logon-SID，且错误谓词全部 fail closed。
#[test]
fn wrong_sid_logon_sid_or_token_query_failure_is_rejected() {
    let f = facts();
    assert!(f.client_pid.is_some(), "GetNamedPipeClientProcessId 必须取到 client PID");
    assert!(f.client_pid_matches_self, "本地 client 的 PID 应等于本进程");
    assert!(f.client_user_sid.is_some(), "必须取到 client user SID");
    assert!(f.client_logon_sid.is_some(), "必须取到 client logon SID");
    assert_eq!(
        f.wrong_client_sid_rejected,
        Some(true),
        "client user SID 不匹配期望值必须被拒绝"
    );
    assert_eq!(
        f.token_query_failure_fails_closed,
        Some(true),
        "token/SID 查询失败必须 fail closed（拒绝）"
    );
}

/// host 必须验证 elevated helper 的 PID/token/identity；fake helper server 被拒。
#[test]
fn host_rejects_fake_helper_server() {
    let f = facts();
    assert_eq!(
        f.fake_helper_server_rejected,
        Some(true),
        "伪造 helper server（PID/SID 与期望不符）必须被 host 拒绝"
    );
}

/// pre-auth 超大 frame 在 dispatch 前被拒；未经授权的连接不派发任何东西。
#[test]
fn preauth_oversize_fails_without_dispatch() {
    let f = facts();
    assert_eq!(
        f.preauth_oversize_rejected_without_dispatch,
        Some(true),
        "超过 pre-auth message 上限的 frame 必须在不派发的前提下被拒"
    );
    assert_eq!(
        f.unauthorized_no_dispatch,
        Some(true),
        "未通过身份验证的连接不得派发"
    );
    assert_eq!(f.dispatch_count_observed, 0, "oversize/未授权路径不得派发");
    assert_eq!(f.preauth_stream_limit, 1, "pre-auth stream 初值冻结为 1");
    assert_eq!(f.preauth_message_limit, 64 * 1024, "pre-auth message 初值冻结为 64KiB");
    assert_eq!(f.preauth_buffer_limit, 64 * 1024, "pre-auth buffer 初值冻结为 64KiB");
}

/// 反假绿：端点名/pipe 路径本身**不是** authority。若把端点名当 capability，
/// 该 mutant 会被本测试杀死。
#[test]
fn oracle_kills_endpoint_name_as_authority_mutant() {
    let f = facts();
    assert!(
        !f.endpoint_name_alone_grants_authority,
        "端点名/pipe 路径不是 capability；不能仅凭连接到了正确名字就授予 authority"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。