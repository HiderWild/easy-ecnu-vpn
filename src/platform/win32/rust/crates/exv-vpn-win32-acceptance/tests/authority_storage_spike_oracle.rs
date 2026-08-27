// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! WSP2-T Terra oracle：singleton authority + durable Windows storage。
//!
//! 本测试在**真实 Windows 宿主**上运行原生 spike seam `run_authority_storage_fact_probe`
//! （双进程 case 用 `CARGO_BIN_EXE_*` 指向的 spike 二进制作子进程），并断言探针观测
//! 到的事实（把它们冻结为契约）。若未来实现破坏某个冻结事实（例如改用 LockFileEx
//! 当 authority、scan 后才 lock、把 Rust `flush` 当 durable sync、跳过 corrupt 记录、
//! 用宽泛 IU DACL、用 plain-JSON journal），对应测试必然失败。
//!
//! 双进程 authority case（race / abandoned）在本宿主可确定性复现：Named Mutex 让
//! winner 持有、loser 超时退出且不 scan/observe/publish；owner 被 `TerminateProcess`
//! 杀死且未释放时，下一个 waiter 收到 `WAIT_ABANDONED_0=128` 并被授予所有权。
//! 这些不是 `not_run`——它们在本机真实发生。

use std::path::Path;
use std::sync::OnceLock;

use exv_vpn_win32_acceptance::authority_storage_facts::{
    run_authority_storage_fact_probe, AuthorityStorageFacts, StorageErrorKind, classify_win32,
};

/// spike 二进制路径（Cargo 为 integration test 注入），作为双进程 case 的子进程执行体。
const CHILD_EXE: &str = env!("CARGO_BIN_EXE_exv-win32-authority-storage-spike");

/// 探针只跑一次，各项断言共享同一份观测（保持确定性、避免重复跨进程竞态）。
fn facts() -> &'static AuthorityStorageFacts {
    static FACTS: OnceLock<AuthorityStorageFacts> = OnceLock::new();
    FACTS.get_or_init(|| run_authority_storage_fact_probe(Path::new(CHILD_EXE)))
}

/// 双进程 authority 竞争：Named Mutex 是唯一选择，loser 在 scan/observe/publish 前退出。
#[test]
fn mutex_is_authority_and_loser_exits_before_scan_observe_publish() {
    let f = facts();
    assert_eq!(
        f.primitive_choice, "named_mutex_local",
        "authority 原语必须冻结为 Local\\ Named Mutex（LockFileEx 无 abandoned 通知）"
    );
    assert_eq!(f.mutex_namespace, "Local", "用户态 singleton 用 Local\\ 命名空间");
    assert_eq!(
        f.mutex_loser_wait_code, 258,
        "loser 必须 WaitForSingleObject 超时（WAIT_TIMEOUT=258）"
    );
    assert!(
        f.mutex_loser_exited_before_scan_observe_publish,
        "loser 必须在 scan/observe/publish 之前退出（mutant：scan 后才 lock 会被杀）"
    );
    assert!(
        f.mutex_reusable_after_release,
        "owner 释放后 mutex 必须可重新获取"
    );
}

/// Abandoned semantics：owner 被 TerminateProcess 杀死且未释放 → 下一个 waiter 收到
/// WAIT_ABANDONED_0 并被授予所有权（可检测的"前任 owner 死亡"信号）。
#[test]
fn abandoned_owner_kill_grants_mutex_with_abandoned_flag() {
    let f = facts();
    assert!(
        f.mutex_abandoned_owner_killed_without_release,
        "owner 必须真的被 TerminateProcess 杀死且未释放"
    );
    assert_eq!(
        f.mutex_abandoned_wait_code, 128,
        "owner 死亡后下一个 waiter 必须收到 WAIT_ABANDONED_0=128"
    );
    assert!(
        f.mutex_abandoned_granted,
        "WAIT_ABANDONED_0 必须伴随所有权授予（新 owner 可继续使用）"
    );
}

/// LockFileEx 是错误选择：第二个 locker 得 ERROR_LOCK_VIOLATION，且 owner 死后锁被
/// OS 静默释放（无 abandoned 通知）。这一对比冻结"为什么 authority 不用文件锁"。
#[test]
fn lockfile_is_not_authority_primitive() {
    let f = facts();
    assert!(f.lockfile_second_locker_fails, "第二个 locker 必须失败");
    assert_eq!(
        f.lockfile_second_locker_error_code, 33,
        "LockFileEx 冲突必须 ERROR_LOCK_VIOLATION=33"
    );
    assert!(
        f.lockfile_reacquirable_after_release,
        "owner 释放后 LockFileEx 可重新获得"
    );
    assert!(
        !f.lockfile_has_abandoned_notification,
        "LockFileEx 没有 abandoned 通知：owner 死后锁被静默释放，无法检测前任死亡"
    );
}

/// machine-level journal 路径 + ACL：`%ProgramData%\ExvVpn\journal\` 非提权可创建，
/// 目录带受限 DACL（当前用户 + SYSTEM），不是宽泛 IU DACL。
#[test]
fn journal_path_is_programdata_with_restricted_dacl() {
    let f = facts();
    assert!(
        f.programdata_creatable_non_admin,
        "machine-level journal 基路径 %ProgramData%\\ExvVpn\\journal\\ 必须非提权可创建；\
         失败时应记录 programdata_create_error，不伪造"
    );
    assert!(
        f.journal_path_chosen.contains("ExvVpn")
            && (f.journal_path_chosen.contains("ProgramData")
                || f.journal_path_chosen.contains("LocalAppData")),
        "journal 路径必须落在 %ProgramData%\\ExvVpn\\journal\\ 或用户 ExvVpn 目录"
    );
    assert!(
        !f.journal_dir_acl_sddl.is_empty(),
        "必须记录 journal 目录 ACL"
    );
    assert!(
        f.journal_dir_acl_sddl.contains("SY")
            || f.journal_dir_acl_sddl.contains("S-1-5-18"),
        "journal 目录 ACL 必须显式允许 SYSTEM，不是空 ACL/宽泛 Everyone"
    );
}

/// CreateFileW flags：FILE_APPEND_DATA（无 FILE_WRITE_DATA）强制 append-only；
/// FILE_SHARE_READ 禁并发写（第二写者 ERROR_SHARING_VIOLATION）。
#[test]
fn journal_file_is_append_only_single_writer() {
    let f = facts();
    assert!(
        f.create_file_access.contains("FILE_APPEND_DATA")
            && f.create_file_access.contains("no FILE_WRITE_DATA"),
        "journal 文件必须以 FILE_APPEND_DATA 打开且无 FILE_WRITE_DATA"
    );
    assert!(
        f.create_file_share_mode.contains("FILE_SHARE_READ"),
        "journal 文件 share mode 必须冻结为 FILE_SHARE_READ（禁并发写）"
    );
    assert!(f.append_only_write_ok, "append 写入必须成功");
    assert!(
        f.append_after_seek_lands_at_eof,
        "FILE_APPEND_DATA（无 FILE_WRITE_DATA）必须强制写入到文件末尾：\
         seek 到 0 后再写，数据仍落在 EOF，不允许中段改写"
    );
    assert!(
        f.second_writer_share_violation_observed,
        "第二个写者必须被拒"
    );
    assert_eq!(
        f.second_writer_share_violation_error_code, 32,
        "并发写必须 ERROR_SHARING_VIOLATION=32"
    );
}

/// 持久化：FlushFileBuffers 是 durability 原语；Rust `std::fs::flush` 不是（no-op 契约）。
#[test]
fn flush_file_buffers_is_durability_not_rust_flush() {
    let f = facts();
    assert!(f.flush_file_buffers_succeeds, "FlushFileBuffers 必须成功");
    assert!(
        f.append_visible_to_second_handle,
        "append 后第二个只读句柄必须能看到数据（OS 缓存可见性）"
    );
    assert!(
        f.rust_std_flush_is_not_durable_sync,
        "冻结 API 契约：Rust std::fs::File::flush 不调用 FlushFileBuffers，不保证落盘；\
         必须显式调用 FlushFileBuffers（mutant：flush 当 durable 会被杀）"
    );
    assert!(
        f.movefile_replace_succeeds && f.dir_flush_succeeds,
        "compaction 替换必须用 MoveFileExW(REPLACE|WRITE_THROUGH) + 父目录句柄 FlushFileBuffers"
    );
}

/// 崩溃语义（J50 在真实文件上往返）：torn final tail 恢复到最后一个完整记录。
#[test]
fn torn_final_tail_recovers_to_last_complete_record() {
    let f = facts();
    assert!(f.j50_clean_roundtrip, "J50 三记录完整往返必须 Clean");
    assert_eq!(
        f.torn_tail_recovered_count, 2,
        "截断最后一个记录后必须恢复到前 2 个完整记录"
    );
    assert!(
        f.torn_tail_recovers_to_last_complete,
        "torn final tail 必须恢复到最后一个完整记录，不报 corruption"
    );
}

/// 崩溃语义：corrupt middle record → JournalCorrupt，不跳过（never skip）。
#[test]
fn corrupt_middle_record_is_corrupt_not_skipped() {
    let f = facts();
    assert!(
        f.corrupt_middle_no_skip,
        "middle 记录损坏必须报 corrupt 且不跳过（mutant：skip corruption 会被杀）"
    );
    assert_eq!(
        f.corrupt_middle_recovered_count, 1,
        "corrupt 记录及其之后的所有记录都不返回（recovered 只含 corrupt 之前的记录）"
    );
}

/// ACL tamper/deny：把 DACL 改成仅 SYSTEM → 打开/追加得 ERROR_ACCESS_DENIED
/// （typed error），改回原 DACL 可恢复。
#[test]
fn acl_deny_fails_with_typed_access_denied_and_restores() {
    let f = facts();
    assert!(
        f.acl_deny_open_fails,
        "ACL 拒绝后重新打开/追加必须失败"
    );
    assert_eq!(
        f.acl_deny_error_code, 5,
        "ACL deny 必须 ERROR_ACCESS_DENIED=5"
    );
    assert_eq!(
        classify_win32(f.acl_deny_error_code),
        StorageErrorKind::AccessDenied,
        "ACL deny 必须映射为 typed error AccessDenied（W14 journal_store.rs 使用）"
    );
    assert!(
        f.acl_restore_succeeds,
        "恢复原 DACL 后必须能再次打开（探针可清理，不留残留）"
    );
    assert!(
        !f.acl_test_original_sddl.is_empty() && !f.acl_test_deny_sddl.is_empty(),
        "必须记录原始与 deny 的 DACL SDDL"
    );
}

/// 反假绿：facts.is_complete() 必须为真（所有关键事实都真实观测到，不是 not_run）。
#[test]
fn oracle_facts_are_complete() {
    let f = facts();
    assert!(f.is_complete(), "所有关键 authority/storage 事实必须真实观测");
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
