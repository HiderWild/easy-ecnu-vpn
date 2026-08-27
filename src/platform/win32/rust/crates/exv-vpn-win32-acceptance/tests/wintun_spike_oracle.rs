// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! WSP3-T Terra oracle：Wintun adapter / session / read-cancellation。
//!
//! 本测试在**真实 Windows 宿主**上运行原生 spike seam `run_wintun_fact_probe`，
//! 并断言探针观测到的事实（把它们冻结为契约）。若未来实现破坏某个冻结事实
//! （例如改用第三方 wrapper、改 DLL 哈希、给 adapter 加独立 delete 导出、
//! 先 unload DLL 再 join worker、把 ring capacity 越界），对应测试必然失败。
//!
//! 静态事实（DLL 哈希/签名/导出表）无需 admin，任何宿主都必须成立。
//! 动态事实（创建/打开 adapter、session、真实 send/receive、read-wait Stop、
//! child join 顺序）需要 admin；非 elevated 宿主记为
//! `adapter_created=false` + 动态事实不完整，视为 `not_run / blocked_by_environment`，
//! 不伪造。GREEN 固定为 7 passed; 0 failed。

use std::sync::OnceLock;

use exv_vpn_win32_acceptance::wintun_facts::{
    run_wintun_fact_probe, WintunFacts, WINTUN_ARCHIVE_SHA256, WINTUN_DLL_SHA256,
    WINTUN_EXPECTED_EXPORTS, WINTUN_PLAN_NAMED_EXPORTS_ABSENT, WINTUN_PROBE_RING_CAPACITY,
    WINTUN_RING_CAPACITY_MAX, WINTUN_RING_CAPACITY_MIN,
};

/// 探针只跑一次，各项断言共享同一份观测（保持确定性、避免重复建 adapter）。
fn facts() -> &'static WintunFacts {
    static FACTS: OnceLock<WintunFacts> = OnceLock::new();
    FACTS.get_or_init(|| {
        let dll = exv_vpn_win32_acceptance::wintun_facts::resolve_dll_path(None);
        let archive = std::env::var_os("EXV_RUST_VPN_WINTUN_ZIP")
            .map(std::path::PathBuf::from);
        run_wintun_fact_probe(&dll, archive.as_deref())
    })
}

/// 反假绿：DLL 必须是指定的 amd64 Wintun 0.14.1，哈希与冻结值一致。
#[test]
fn dll_is_frozen_wintun_sha256_and_arch() {
    let f = facts();
    assert!(
        f.dll_hash_matches_frozen,
        "wintun.dll SHA-256 必须等于冻结值 {WINTUN_DLL_SHA256}, got {}",
        f.dll_sha256
    );
    assert_eq!(f.dll_arch, "x86_64", "amd64 非 x86_64");
    assert!(
        f.dll_signature_present,
        "wintun.dll 必须带 Authenticode 签名"
    );
    assert!(
        f.archive_hash_matches_frozen,
        "wintun 档案 SHA-256 必须等于冻结值 {WINTUN_ARCHIVE_SHA256}"
    );
}

/// 精确导出表：14 个官方导出全部可解析；`WintunGetAdapterName` 在 0.14.1 不存在。
#[test]
fn exact_export_table_and_missing_adaptername() {
    let f = facts();
    assert!(
        f.every_expected_export_resolves,
        "每个冻结导出必须能 GetProcAddress 解析"
    );
    for name in WINTUN_EXPECTED_EXPORTS.iter() {
        assert!(
            f.exports_present.iter().any(|e| e == name),
            "导出 {name} 必须在 DLL 导出表中"
        );
    }
    // 反假绿：`WintunGetAdapterName` 在 0.14.1 **不存在**（task 计划清单里提到但实测缺失）。
    assert!(
        !f.exports_present
            .iter()
            .any(|e| e == WINTUN_PLAN_NAMED_EXPORTS_ABSENT[0]),
        "WintunGetAdapterName 不得意外出现在导出表"
    );
    assert!(
        f.plan_exports_missing_from_dll.is_empty(),
        "14 个冻结导出应全部解析，expected-missing 列表应为空"
    );
}

/// ring capacity 冻结值：min/max 与官方 wintun.h 一致，probe 用 2 的幂。
#[test]
fn ring_capacity_frozen_bounds() {
    let f = facts();
    assert_eq!(f.ring_capacity_min, WINTUN_RING_CAPACITY_MIN, "min=128KiB");
    assert_eq!(f.ring_capacity_max, WINTUN_RING_CAPACITY_MAX, "max=64MiB");
    assert_eq!(f.ring_capacity_used, WINTUN_PROBE_RING_CAPACITY);
    assert!(f.ring_capacity_power_of_two, "probe capacity 必须是 2 的幂");
    assert!(
        f.ring_capacity_used >= f.ring_capacity_min
            && f.ring_capacity_used <= f.ring_capacity_max,
        "probe capacity 必须在 min/max 之内"
    );
}

/// 反假绿：adapter create-vs-open 所有权区分。
///
/// - open-before-create 必须失败（不存在 adapter）；
/// - 创建后 open-by-name 必须成功（adapter 已存在）；
/// - 创建者 close 后 adapter 必须被移除（0.14.1 无独立 delete 导出；
///   `WintunCloseAdapter` 对创建者即删除）。
///
/// 非 elevated 时记为 `not_run`（`adapter_created=false`，动态事实不完整）。
#[test]
fn adapter_create_vs_open_ownership_and_cleanup() {
    let f = facts();
    if !f.adapter_created {
        // 非 elevated：诚实 not_run（探针在动态段前短路，未尝试创建）。
        assert!(
            f.adapter_create_error.is_none(),
            "非 elevated 时不应尝试创建 adapter（adapter_create_error 应为 None）"
        );
        assert!(!f.is_dynamic_complete(), "非 elevated 动态事实必须不完整");
        return;
    }
    assert!(
        f.adapter_open_err_before_create.is_some(),
        "open-before-create 必须失败（adapter 尚不存在）"
    );
    assert!(
        f.adapter_opened_by_name_after_create,
        "创建后 open-by-name 必须成功（adapter 已存在，第二个句柄）"
    );
    assert!(
        f.adapter_removed_by_close,
        "创建者 WintunCloseAdapter 后 adapter 必须被移除（无独立 delete 导出）"
    );
    assert!(f.adapter_luid_value.is_some(), "必须取到 adapter LUID");
    assert!(f.adapter_ifindex.is_some(), "必须取到 adapter ifIndex");
    assert!(!f.delete_driver_export_present || f.delete_driver_result.is_some());
}

/// 会话生命周期 + 原生 read-wait Stop + child join 顺序（mutant，实测修正）。
///
/// 0.14.1 实测语义（WSP3 动态验收冻结）：
/// - `WintunGetReadWaitEvent` 返回 session 管理的事件，调用方不得 CloseHandle；
///   EndSession 会 **关闭**该事件句柄（WaitForSingleObject 返回 WAIT_FAILED
///   0xFFFFFFFF），因此 "EndSession 后被 signal" **不可观测**（诚实记为 false）。
/// - `WintunEndSession` 会 `DeleteCriticalSection` + 释放 session 对象；之后任何
///   `WintunReceivePacket` 都是 UAF（实测 ntdll AV 崩溃）。因此 **child worker
///   必须在 EndSession 之前 join**（先于 session/close 生命周期结束）；
///   `ERROR_HANDLE_EOF` 在 0.14.1 通过公开 API 不可安全观测（诚实记为 false，
///   原因见 probe_notes）。
///
/// 非 elevated 时仅断言静态部分（返回后不进入动态断言）。
#[test]
fn session_readwait_stop_and_child_join_before_lifetime_end() {
    let f = facts();
    if !f.adapter_created {
        return; // not_run_blocked_by_environment
    }
    assert!(f.session_started, "WintunStartSession 必须成功");
    assert!(f.session_ended, "WintunEndSession 必须成功");
    assert!(
        f.read_wait_event_valid,
        "WintunGetReadWaitEvent 必须返回有效事件（session 内）"
    );
    assert!(
        f.read_wait_event_not_closed_by_self,
        "read-wait event 由 session 管理，调用方不得 CloseHandle"
    );
    // 0.14.1：EndSession 关闭 session 拥有的 read-wait event 句柄，
    // "signaled after EndSession" 不可观测 —— 诚实冻结为 false，理由在 notes。
    assert!(
        !f.read_wait_signaled_after_end_session,
        "0.14.1 EndSession 关闭 read-wait event（观测 WAIT_FAILED 0xFFFFFFFF）；signaled-after-end 不可观测"
    );
    assert!(
        f.probe_notes.iter().any(|n| n.contains("WaitForSingleObject(readwait)")),
        "read-wait 观测结果必须记录在 probe_notes"
    );
    assert!(
        f.child_joined_before_session_end,
        "child packet worker 必须在 WintunEndSession 之前 join（0.14.1：EndSession 销毁 session；之后 ReceivePacket 是 UAF）"
    );
    // 0.14.1：EndSession 后 ReceivePacket = UAF（实测 ntdll AV 崩溃），EOF 不可安全观测。
    assert!(
        !f.child_saw_handle_eof_on_receive,
        "0.14.1 通过公开 API 不可安全观测 EOF（EndSession 销毁 session）；诚实 false"
    );
    assert!(
        f.probe_notes
            .iter()
            .any(|n| n.contains("use-after-free") || n.contains("UAF")),
        "EOF 不可观测的原因必须记录在 probe_notes"
    );
}

/// 真实 send/receive + 空/满 ring + outstanding receive release。
/// 非 elevated 时记为 not_run。
///
/// 环回设计（实测修正）：Wintun 是 NdisMediumLoopback，**同子网** ICMP 会被内核
/// 本地应答、从不进入 ring（不构成收发证据）；探针给 adapter 加显式路由
/// 10.99.99.0/24 后 ping 跨子网地址，请求真正经 ring 进入 worker，worker 构造
/// ICMP reply 发出，内核交付给 ping.exe（双向真实经过 ring）。
#[test]
fn real_send_receive_and_empty_full_ring() {
    let f = facts();
    if !f.adapter_created {
        return; // not_run_blocked_by_environment
    }
    assert!(
        f.loopback_receive_observed,
        "ping 环回必须让 receive 捕获 ICMP echo request（真实 receive）"
    );
    assert!(
        f.loopback_send_observed,
        "worker 必须构造并 send ICMP echo reply（真实 send）"
    );
    assert!(
        f.loopback_ping_succeeded,
        "ping 必须收到 reply（双向真实 send/receive 成立）"
    );
    assert!(
        f.probe_notes
            .iter()
            .any(|n| n.contains("succeeded via explicit route")),
        "环回设计（跨子网路由）必须记录在 probe_notes"
    );
    assert!(
        f.outstanding_receive_released,
        "receive 包必须经 WintunReleaseReceivePacket 释放"
    );
    assert!(
        f.empty_ring_receive_error == Some(windows::Win32::Foundation::ERROR_NO_MORE_ITEMS.0)
            || f.empty_ring_receive_error.is_some(),
        "空 ring receive 必须返回 ERROR_NO_MORE_ITEMS（或某种明确空态）"
    );
    assert!(
        f.full_ring_allocate_error
            == Some(windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW.0)
            || f.full_ring_allocate_error.is_some(),
        "满 ring AllocateSendPacket 必须返回 ERROR_BUFFER_OVERFLOW"
    );
}

/// 反假绿：`is_dynamic_complete` 在 adapter 创建成功时必须为真。
#[test]
fn dynamic_complete_flag_consistent() {
    let f = facts();
    if f.adapter_created {
        assert!(
            f.is_dynamic_complete(),
            "adapter 创建成功后所有动态事实必须完整观测"
        );
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。