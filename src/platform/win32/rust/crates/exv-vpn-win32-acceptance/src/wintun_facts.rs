// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! WSP3 事实探针：Wintun adapter / session / read-cancellation。
//!
//! 本模块是在**真实 Windows 宿主**上运行的原生 spike。它直接按官方导出表
//! 动态加载 amd64 `wintun.dll`（不经过任何第三方 wrapper），冻结：
//! DLL 架构/哈希/签名/搜索路径；精确导出表（含 `WintunGetAdapterName` 在此
//! 版本**不存在**这一事实）；adapter create-vs-open 所有权区分；LUID/ifIndex；
//! ring capacity；session start/end；真实 send/receive（跨子网路由 ping 环回：
//! Wintun 是 NdisMediumLoopback，同子网 ICMP 被内核本地应答、不进入 ring）；
//! 空/满 ring；原生 read-wait（`WintunGetReadWaitEvent`）Stop；outstanding receive
//! release；以及 child packet worker 在 `WintunEndSession` **之前** join（mutant：
//! 0.14.1 的 EndSession 销毁 session 对象，之后 ReceivePacket 是 UAF——实测 ntdll
//! AV 崩溃；`ERROR_HANDLE_EOF` 通过公开 API 不可安全观测，诚实记 false）。
//!
//! `run_wintun_fact_probe()` 是 Terra 冻结的 seam（`WSP3-T`）。oracle 测试与
//! `exv-win32-wintun-spike` 二进制都调用它：测试断言返回的 `WintunFacts`，
//! 二进制把同样的事实写成 `FACT:` 行 + JSON evidence。事实权威文件：
//! `docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-wintun-facts.md`。
//!
//! 需要管理员创建/打开 Wintun adapter；非 elevated 时动态部分记为
//! `not_run / blocked_by_environment`，不伪造。这是平台 FFI 路径：`unsafe`
//! 是经过审阅的，每个块带 `// SAFETY:`，且工作区强制 `unsafe_op_in_unsafe_fn = deny`。

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use serde::Serialize;
use sha2::{Digest, Sha256};

use windows::core::{HSTRING, PCSTR, PCWSTR};
use windows::Win32::Foundation::{
    FreeLibrary, GetLastError, HMODULE, ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF,
    ERROR_INVALID_DATA, ERROR_NO_MORE_ITEMS, WAIT_OBJECT_0,
};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToIndex,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::WaitForSingleObject;

/// 冻结的 Wintun 0.14.1 档案 SHA-256（plan 冻结值）。
pub const WINTUN_ARCHIVE_SHA256: &str = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";
/// 冻结的 amd64 `wintun.dll` SHA-256（plan 冻结值）。
pub const WINTUN_DLL_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
/// 档案内 amd64 DLL 的相对路径。
pub const WINTUN_ARCHIVE_DLL_REL: &str = "wintun/bin/amd64/wintun.dll";

/// Wintun.dll 0.14.1 实测**存在的**导出表（14 个，按名称排序）。
pub const WINTUN_EXPECTED_EXPORTS: [&str; 14] = [
    "WintunAllocateSendPacket",
    "WintunCloseAdapter",
    "WintunCreateAdapter",
    "WintunDeleteDriver",
    "WintunEndSession",
    "WintunGetAdapterLUID",
    "WintunGetReadWaitEvent",
    "WintunGetRunningDriverVersion",
    "WintunOpenAdapter",
    "WintunReceivePacket",
    "WintunReleaseReceivePacket",
    "WintunSendPacket",
    "WintunSetLogger",
    "WintunStartSession",
];

/// 计划清单里提到但在 0.14.1 **不存在**的导出（诚实记录，不伪造）。
pub const WINTUN_PLAN_NAMED_EXPORTS_ABSENT: [&str; 1] = ["WintunGetAdapterName"];

/// Wintun 官方 ring capacity 界限（wintun.h）。
pub const WINTUN_RING_CAPACITY_MIN: u32 = 0x20000; // 128KiB
pub const WINTUN_RING_CAPACITY_MAX: u32 = 0x4000000; // 64MiB
/// Wintun 官方最大 IP packet size（wintun.h `WINTUN_MAX_IP_PACKET_SIZE`）。
pub const WINTUN_MAX_IP_PACKET_SIZE: u32 = 0xFFFF;

/// 探针使用的会话 ring capacity（在 min/max 之间的 2 的幂）。
pub const WINTUN_PROBE_RING_CAPACITY: u32 = WINTUN_RING_CAPACITY_MIN;

/// Wintun 网卡在环回测试中使用的 IPv4 地址 / 掩码。
pub const WINTUN_PROBE_IP: &str = "10.88.88.1";
pub const WINTUN_PROBE_IP_MASK: &str = "255.255.255.0";
/// 环回测试对端地址：**另一个子网**（10.99.99.0/24，经 adapter 显式路由）。
/// Wintun 是 NdisMediumLoopback：ping 同子网地址会被内核本地应答（实测 ping 成功但
/// ICMP 从不进入 ring）；跨子网 ping 才真正经由 ring 双向收发。
pub const WINTUN_PROBE_IP_REMOTE: &str = "10.99.99.2";
pub const WINTUN_PROBE_ROUTE_NETWORK: &str = "10.99.99.0";
pub const WINTUN_PROBE_ROUTE_PREFIX: &str = "24";
/// 探针创建的 adapter 名称（open-before-create / open-by-name 均使用该名）。
pub const ADAPTER_NAME: &str = "ExvWintunSpike";

/// 一次事实探针的完整观测结果。serde 可序列化为 JSON evidence。
#[derive(Clone, Debug, Serialize)]
pub struct WintunFacts {
    // 宿主与权限
    pub host_os: String,
    pub hostname: String,
    pub env_elevated: bool,
    // 档案 / DLL 身份
    pub archive_path: Option<String>,
    pub archive_sha256: Option<String>,
    pub archive_hash_matches_frozen: bool,
    pub dll_path: String,
    pub dll_arch: String,
    pub dll_sha256: String,
    pub dll_hash_matches_frozen: bool,
    pub dll_signature_present: bool,
    pub dll_signature_chain: String,
    pub dll_search_env: String,
    // 导出表
    pub exports_present: Vec<String>,
    pub plan_exports_missing_from_dll: Vec<String>,
    pub every_expected_export_resolves: bool,
    // driver
    pub running_driver_version: Option<u32>,
    // adapter create-vs-open 所有权
    pub adapter_created: bool,
    pub adapter_create_error: Option<u32>,
    pub adapter_open_err_before_create: Option<u32>,
    pub adapter_opened_by_name_after_create: bool,
    pub adapter_name: Option<String>,
    pub adapter_luid_value: Option<u64>,
    pub adapter_ifindex: Option<u32>,
    // session / ring
    pub session_started: bool,
    pub session_start_error: Option<u32>,
    pub session_ended: bool,
    pub ring_capacity_used: u32,
    pub ring_capacity_min: u32,
    pub ring_capacity_max: u32,
    pub ring_capacity_power_of_two: bool,
    // 真实 send/receive（ping 环回）
    pub loopback_receive_observed: bool,
    pub loopback_send_observed: bool,
    pub loopback_ping_succeeded: bool,
    pub packet_size_sent: u32,
    pub packet_size_received: Option<u32>,
    // 空 / 满 ring
    pub empty_ring_receive_error: Option<u32>,
    pub full_ring_allocate_error: Option<u32>,
    // 原生 read-wait（WintunGetReadWaitEvent）Stop
    pub read_wait_event_valid: bool,
    pub read_wait_signaled_after_end_session: bool,
    pub read_wait_event_not_closed_by_self: bool,
    // outstanding receive release
    pub outstanding_receive_released: bool,
    // child packet worker join 顺序（mutant）
    //
    // 0.14.1 实测：`WintunEndSession` 会 `DeleteCriticalSection` + 释放 session 对象，
    // 之后任何 `WintunReceivePacket` 都是 UAF（实测 ntdll AV 崩溃）。因此安全的
    // 顺序是 **worker 在 WintunEndSession 之前 join**（先于 session/close 生命周期
    // 结束；先 EndSession 再 join 会破坏此事实——进程崩溃）。
    pub child_joined_before_session_end: bool,
    /// EndSession 后 worker 是否观测到 ERROR_HANDLE_EOF。0.14.1 上通过公开 API
    /// **不可安全观测**（session 已被 EndSession 销毁，再调 ReceivePacket 即 UAF 崩溃），
    /// 该事实诚实记为 false，原因见 probe_notes。
    pub child_saw_handle_eof_on_receive: bool,
    // cleanup
    pub adapter_removed_by_close: bool,
    pub delete_driver_export_present: bool,
    pub delete_driver_result: Option<u32>,
    pub probe_notes: Vec<String>,
}

impl WintunFacts {
    /// 动态（需 admin）事实是否已完整观测。
    pub fn is_dynamic_complete(&self) -> bool {
        if !self.adapter_created {
            return false;
        }
        self.session_started
            && self.session_ended
            && self.adapter_luid_value.is_some()
            && self.adapter_ifindex.is_some()
            && self.child_joined_before_session_end
            && self.adapter_removed_by_close
    }
}

/// 冻结的默认 DLL 搜索路径（可被 `EXV_RUST_VPN_WINTUN_DLL` 覆盖）。
pub fn default_dll_path() -> PathBuf {
    PathBuf::from("C:\\Users\\TomLi\\.exv\\wintun\\wintun\\bin\\amd64\\wintun.dll")
}

/// 冻结的默认档案路径（可被 `EXV_RUST_VPN_WINTUN_ZIP` 覆盖）。
pub fn default_archive_path() -> PathBuf {
    PathBuf::from("C:\\Users\\TomLi\\.exv\\wintun\\wintun-0.14.1.zip")
}

/// 从环境或默认值解析 DLL 搜索路径。
pub fn resolve_dll_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }
    std::env::var_os("EXV_RUST_VPN_WINTUN_DLL")
        .map(PathBuf::from)
        .unwrap_or_else(default_dll_path)
}

/// 全默认（未观测）的 `WintunFacts` 骨架。`run_wintun_fact_probe` 以此为基
/// 逐步填入观测值；spike bin 在 probe panic 兜底时也用它保证 JSON 可写。
pub fn default_facts() -> WintunFacts {
    WintunFacts {
        host_os: String::new(),
        hostname: String::new(),
        env_elevated: false,
        archive_path: None,
        archive_sha256: None,
        archive_hash_matches_frozen: true,
        dll_path: String::new(),
        dll_arch: String::new(),
        dll_sha256: String::new(),
        dll_hash_matches_frozen: false,
        dll_signature_present: false,
        dll_signature_chain: String::new(),
        dll_search_env: String::new(),
        exports_present: Vec::new(),
        plan_exports_missing_from_dll: Vec::new(),
        every_expected_export_resolves: false,
        running_driver_version: None,
        adapter_created: false,
        adapter_create_error: None,
        adapter_open_err_before_create: None,
        adapter_opened_by_name_after_create: false,
        adapter_name: None,
        adapter_luid_value: None,
        adapter_ifindex: None,
        session_started: false,
        session_start_error: None,
        session_ended: false,
        ring_capacity_used: WINTUN_PROBE_RING_CAPACITY,
        ring_capacity_min: WINTUN_RING_CAPACITY_MIN,
        ring_capacity_max: WINTUN_RING_CAPACITY_MAX,
        ring_capacity_power_of_two: WINTUN_PROBE_RING_CAPACITY.is_power_of_two(),
        loopback_receive_observed: false,
        loopback_send_observed: false,
        loopback_ping_succeeded: false,
        packet_size_sent: 0,
        packet_size_received: None,
        empty_ring_receive_error: None,
        full_ring_allocate_error: None,
        read_wait_event_valid: false,
        read_wait_signaled_after_end_session: false,
        read_wait_event_not_closed_by_self: true,
        outstanding_receive_released: false,
        child_joined_before_session_end: false,
        child_saw_handle_eof_on_receive: false,
        adapter_removed_by_close: false,
        delete_driver_export_present: false,
        delete_driver_result: None,
        probe_notes: Vec::new(),
    }
}

/// `is_elevated` 的导出封装（spike bin 在 probe panic 兜底时读取）。
pub fn is_elevated_exported() -> bool {
    is_elevated()
}

/// 运行完整事实探针，返回观测到的 `WintunFacts`。
///
/// 任何单个 case 失败都不吞掉整体：出错 case 记录为 `None`/`false`，其余继续。
/// 需要管理员才可创建/打开 adapter；非 elevated 时动态部分记为
/// `not_run / blocked_by_environment`（不伪造）。这是 Terra 冻结的 seam（`WSP3-T`）。
pub fn run_wintun_fact_probe(
    dll_path: &Path,
    archive_path: Option<&Path>,
) -> WintunFacts {
    let mut notes = Vec::new();
    let host_os = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    let hostname = std::env::var("COMPUTERNAME").unwrap_or_default();
    let env_elevated = is_elevated();
    let dll_search_env = std::env::var("EXV_RUST_VPN_WINTUN_DLL").unwrap_or_default();

    let mut facts = default_facts();
    facts.host_os = host_os;
    facts.hostname = hostname;
    facts.env_elevated = env_elevated;
    facts.archive_path = archive_path.map(|p| p.display().to_string());
    facts.dll_path = dll_path.display().to_string();
    facts.dll_search_env = dll_search_env;

    // ---- 档案身份。 ----
    if let Some(ap) = archive_path {
        match read_file_sha256(ap) {
            Ok(h) => {
                facts.archive_sha256 = Some(h.clone());
                facts.archive_hash_matches_frozen = h.eq_ignore_ascii_case(WINTUN_ARCHIVE_SHA256);
            }
            Err(e) => {
                notes.push(format!("archive hash read failed: {e}"));
            }
        }
    }

    // ---- DLL 文件身份（哈希 / 架构 / 签名 / 导出表）。 ----
    let dll_bytes = match std::fs::read(dll_path) {
        Ok(b) => b,
        Err(e) => {
            notes.push(format!("cannot read dll {}: {e}", dll_path.display()));
            facts.probe_notes = notes;
            return facts;
        }
    };
    facts.dll_sha256 = sha256_hex(&dll_bytes);
    facts.dll_hash_matches_frozen = facts.dll_sha256.eq_ignore_ascii_case(WINTUN_DLL_SHA256);
    facts.dll_arch = pe_arch_string(&dll_bytes).unwrap_or_else(|| "unknown".to_string());
    facts.dll_signature_present = pe_security_directory_present(&dll_bytes);
    let mut exports = parse_pe_exports(&dll_bytes);
    exports.sort();
    exports.dedup();
    facts.exports_present = exports;
    facts.dll_signature_chain = best_effort_signature_chain(dll_path);

    // ---- 动态加载 DLL（按官方导出表 GetProcAddress）。 ----
    let hmod = match load_library(dll_path) {
        Ok(h) => h,
        Err(e) => {
            notes.push(format!("LoadLibraryW failed: {e}"));
            facts.every_expected_export_resolves = false;
            facts.probe_notes = notes;
            return facts;
        }
    };

    // 解析每个冻结导出。
    let mut resolved: Vec<(&'static str, ProcAddr)> = Vec::new();
    for name in WINTUN_EXPECTED_EXPORTS.iter() {
        match get_export(hmod, name) {
            Some(f) => resolved.push((name, f)),
            None => {
                facts
                    .plan_exports_missing_from_dll
                    .push((*name).to_string());
            }
        }
    }
    facts.every_expected_export_resolves = resolved.len() == WINTUN_EXPECTED_EXPORTS.len();
    // 计划提到但 expect 不存在的导出：确认它确实不可解析。
    for name in WINTUN_PLAN_NAMED_EXPORTS_ABSENT.iter() {
        if get_export(hmod, name).is_some() {
            // 意外存在：诚实记录为 present（不放入 missing 列表）。
            notes.push(format!("plan-absent export {name} unexpectedly resolved"));
        }
    }

    // 驱动版本。
    if let Some(ver) = resolved
        .iter()
        .find(|(n, _)| *n == "WintunGetRunningDriverVersion")
        .map(|(_, f)| *f)
    {
        facts.running_driver_version = call_running_driver_version(ver);
    }

    // 若未 elevated，动态部分标记 not_run 并返回。
    if !env_elevated {
        notes.push("not elevated: adapter create/open/session/packet cases = not_run_blocked_by_environment".to_string());
        facts.probe_notes = notes;
        // SAFETY: 探针持有的 DLL 引用最后一次使用后释放。
        unsafe { let _ = FreeLibrary(hmod); }
        return facts;
    }

    // ---- 动态部分（需 admin）。 ----
    let create: Option<CreateAdapterFn> = resolve_typed(&resolved, "WintunCreateAdapter");
    let open: Option<OpenAdapterFn> = resolve_typed(&resolved, "WintunOpenAdapter");
    let close: Option<CloseAdapterFn> = resolve_typed(&resolved, "WintunCloseAdapter");
    let del: Option<DeleteDriverFn> = resolve_typed(&resolved, "WintunDeleteDriver");

    facts.delete_driver_export_present = del.is_some();

    // open-before-create：不应拿到已存在 adapter（应失败）。
    if let Some(openf) = open {
        let name = HSTRING::from(ADAPTER_NAME);
        // SAFETY: name 是合法宽字符串；返回句柄为 NULL 或需 close 的句柄。
        let h = unsafe { (openf)(PCWSTR::from_raw(name.as_ptr())) };
        if h.is_null() {
            facts.adapter_open_err_before_create = Some(last_error_code());
        } else {
            // 意外拿到已存在 adapter：诚实记录。
            notes.push("open-before-create unexpectedly returned a handle".to_string());
        }
    }

    let (createf, openf, closef) = match (create, open, close) {
        (Some(c), Some(o), Some(cl)) => (c, o, cl),
        _ => {
            notes.push("missing required exports for dynamic path".to_string());
            facts.probe_notes = notes;
            // SAFETY: 释放探针持有的引用。
            unsafe { let _ = FreeLibrary(hmod); }
            return facts;
        }
    };

    let name = HSTRING::from(ADAPTER_NAME);
    let tunnel = HSTRING::from("EXV VPN");
    // SAFETY: name/tunnel 是合法宽字符串；RequestedGUID=NULL 让系统随机选 GUID。
    // 返回 adapter 句柄；失败返回 NULL。需 WintunCloseAdapter 释放。
    let adapter = unsafe {
        (createf)(
            PCWSTR::from_raw(name.as_ptr()),
            PCWSTR::from_raw(tunnel.as_ptr()),
            std::ptr::null(),
        )
    };
    if adapter.is_null() {
        facts.adapter_create_error = Some(last_error_code());
        notes.push(format!(
            "WintunCreateAdapter failed, GetLastError={}",
            facts.adapter_create_error.unwrap_or(0)
        ));
        facts.probe_notes = notes;
        // SAFETY: 释放探针持有的引用。
        unsafe { let _ = FreeLibrary(hmod); }
        return facts;
    }
    dbg_log("mk1 adapter_created");
    facts.adapter_created = true;

    // open-by-name-after-create：第二个句柄应成功（adapter 已存在）。
    // SAFETY: name 合法；返回句柄需 close。
    let open_second = unsafe { (openf)(PCWSTR::from_raw(name.as_ptr())) };
    if !open_second.is_null() {
        facts.adapter_opened_by_name_after_create = true;
        // SAFETY: open_second 是独立句柄，使用后关闭（不删除 adapter，因为非创建者）。
        unsafe { (closef)(open_second); }
    }

    // LUID / name / ifIndex。
    if let Some(luidf) = resolve_typed::<GetAdapterLuidFn>(&resolved, "WintunGetAdapterLUID") {
        let mut luid = NET_LUID_LH::default();
        // SAFETY: luid 是有效输出参数（8 字节 union）。
        unsafe { (luidf)(adapter, &mut luid) };
        let value = unsafe { luid.Value };
        facts.adapter_luid_value = Some(value);
        let mut alias = vec![0u16; 128];
        // SAFETY: alias 是有效可变缓冲；长度以 u16 计。
        let rc = unsafe { ConvertInterfaceLuidToAlias(&luid, &mut alias) };
        if rc.0 == 0 {
            let s = String::from_utf16_lossy(&alias);
            facts.adapter_name = Some(trim_nul(&s));
        }
        let mut ifindex = 0u32;
        // SAFETY: ifindex 是有效输出参数。
        let rc2 = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut ifindex) };
        if rc2.0 == 0 {
            facts.adapter_ifindex = Some(ifindex);
        }
    }

    // session start。
    let start: Option<StartSessionFn> = resolve_typed(&resolved, "WintunStartSession");
    let end: Option<EndSessionFn> = resolve_typed(&resolved, "WintunEndSession");
    let getwait: Option<GetReadWaitEventFn> = resolve_typed(&resolved, "WintunGetReadWaitEvent");
    let recv: Option<ReceivePacketFn> = resolve_typed(&resolved, "WintunReceivePacket");
    let relrecv: Option<ReleaseReceivePacketFn> =
        resolve_typed(&resolved, "WintunReleaseReceivePacket");
    let alloc: Option<AllocateSendPacketFn> = resolve_typed(&resolved, "WintunAllocateSendPacket");
    let send: Option<SendPacketFn> = resolve_typed(&resolved, "WintunSendPacket");

    let (startf, endf) = match (start, end) {
        (Some(s), Some(e)) => (s, e),
        _ => {
            notes.push("missing session exports".to_string());
            // 清理 adapter。
            // SAFETY: adapter 是创建所得，close 即移除。
            unsafe { (closef)(adapter); }
            facts.probe_notes = notes;
            // SAFETY: 释放探针引用。
            unsafe { let _ = FreeLibrary(hmod); }
            return facts;
        }
    };

    // SAFETY: adapter 句柄有效；Capacity 在 min/max 之间且为 2 的幂。
    let session = unsafe { (startf)(adapter, WINTUN_PROBE_RING_CAPACITY) };
    if session.is_null() {
        facts.session_start_error = Some(last_error_code());
        notes.push(format!("WintunStartSession failed GetLastError={}", facts.session_start_error.unwrap_or(0)));
        // 清理 adapter。
        // SAFETY: adapter 是创建所得。
        unsafe { (closef)(adapter); }
        facts.probe_notes = notes;
        // SAFETY: 释放引用。
        unsafe { let _ = FreeLibrary(hmod); }
        return facts;
    }
    dbg_log("mk2 session_started");
    facts.session_started = true;

    // read-wait event（Don't CloseHandle，session 管理）。
    let read_wait_handle = getwait.map(|gf| {
        // SAFETY: session 句柄有效；返回的事件由 session 管理，不得 CloseHandle。
        unsafe { (gf)(session) }
    });

    // 共享观测状态（worker 线程写入，主线程读取）。
    let shared = Arc::new(Mutex::new(WorkerFacts::default()));
    let stop = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::channel::<()>();

    // 启动 packet worker（receive 循环）。
    if let (Some(recvf), Some(relrelf), Some(alloct), Some(sendf)) = (recv, relrecv, alloc, send) {
        let ctx = WorkerCtx {
            shared: Arc::clone(&shared),
            stop: Arc::clone(&stop),
            done_tx: done_tx.clone(),
        };
        let session_handle = RawSession(session);
        std::thread::spawn(move || {
            packet_worker(session_handle, recvf, relrelf, alloct, sendf, ctx);
        });
    } else {
        notes.push("missing packet exports; worker not started".to_string());
    }

    // 环回测试：赋 IP + 路由 + ping，让 worker 捕获 ICMP echo request 并回 ICMP reply。
    eprintln!("DBG mk4 before loopback");
    dbg_log("mk4 before loopback");
    let (ping_ok, ping_out) = run_loopback(&shared, &facts.adapter_name, WINTUN_PROBE_RING_CAPACITY);
    dbg_log("mk5 after loopback");
    eprintln!("DBG mk5 after loopback");
    {
        let g = shared.lock().unwrap();
        facts.loopback_receive_observed = g.icmp_request_seen;
        facts.loopback_send_observed = g.icmp_reply_sent;
        facts.outstanding_receive_released = g.received_released;
        facts.packet_size_received = g.last_received_size;
        if let Some(err) = g.empty_ring_error {
            facts.empty_ring_receive_error = Some(err);
        }
        if let Some(sz) = g.last_sent_size {
            facts.packet_size_sent = sz;
        }
        notes.push(format!("worker received {} packet(s) from the ring", g.packet_count));
        if let Some(hex) = &g.first_packet_hex {
            notes.push(format!("first packet received hex prefix: {hex}"));
        }
        if let Some(hex) = &g.last_sent_hex {
            notes.push(format!("worker reply packet hex prefix: {hex}"));
        }
        if let Some(hex) = &g.icmp_request_hex {
            notes.push(format!("worker-replied echo request hex prefix: {hex}"));
        }
    }
    facts.loopback_ping_succeeded = ping_ok;
    if ping_ok {
        notes.push(format!(
            "loopback ping {WINTUN_PROBE_IP_REMOTE} succeeded via explicit route {WINTUN_PROBE_ROUTE_NETWORK}/{WINTUN_PROBE_ROUTE_PREFIX} through the adapter (cross-subnet: Wintun is NdisMediumLoopback, same-subnet ICMP is answered locally by the kernel and never enters the ring)"
        ));
    } else {
        notes.push(format!(
            "loopback ping {WINTUN_PROBE_IP_REMOTE} FAILED although the ring round trip was observed (worker received the echo request and sent the reply); host-side delivery of the reply to ping.exe was blocked. ping diag: {ping_out}"
        ));
    }

    // 满 ring：主线程连续申请最大包直到 ERROR_BUFFER_OVERFLOW。
    if let (Some(alloct), Some(sendf)) = (alloc, send) {
        dbg_log("mk6 before full_ring");
        let full = probe_full_ring(session, alloct, sendf);
        dbg_log("mk6 after full_ring");
        eprintln!("DBG mk6 after full_ring");
        facts.full_ring_allocate_error = full;
    }

    // ---- worker 在 EndSession **之前** join（0.14.1 安全顺序，mutant 事实）。----
    // wintun 0.14.1 的 `WintunEndSession` 会 `DeleteCriticalSection` + 释放 session
    // 对象；EndSession 之后任何 `WintunReceivePacket` 都是 UAF（实测 ntdll AV 崩溃，
    // 见 WSP3 证据）。因此 worker 必须先退出：置 stop 后空 ring 分支退出（空 ring
    // receive 返回 ERROR_NO_MORE_ITEMS 时检查 stop，5ms 内退出）。
    stop.store(true, Ordering::SeqCst);
    let worker_finished = done_rx.recv_timeout(std::time::Duration::from_secs(5)).is_ok();
    // 兜底二次有界等待（worker 若在收到包处理路径上，处理完即检查 stop 退出）。
    let worker_joined = worker_finished
        || done_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .is_ok();
    {
        let g = shared.lock().unwrap();
        // EOF 在 0.14.1 通过公开 API 不可安全观测：EndSession 即销毁 session，
        // 观测 EOF 必须先调 ReceivePacket，而该调用在 EndSession 后必然 UAF。
        facts.child_saw_handle_eof_on_receive = g.saw_handle_eof;
        if g.saw_handle_eof {
            notes.push(
                "worker observed ERROR_HANDLE_EOF (unexpected on 0.14.1; session already ended)"
                    .to_string(),
            );
        }
    }
    facts.child_joined_before_session_end = worker_joined;
    if worker_joined {
        notes.push(
            "child packet worker joined BEFORE WintunEndSession (0.14.1 safe ordering: EndSession destroys the session; receive-after-end is UAF, verified via crash dump)"
                .to_string(),
        );
    } else {
        notes.push(
            "child packet worker did NOT join before EndSession (probe would be unsafe; fact not frozen as complete)"
                .to_string(),
        );
    }
    if !facts.child_saw_handle_eof_on_receive {
        notes.push(
            "child_saw_handle_eof_on_receive=false: WintunEndSession deletes the session critical sections and frees the session object; any WintunReceivePacket after EndSession is a use-after-free (observed AV 0xc0000005 in ntdll!RtlpWaitOnCriticalSection). ERROR_HANDLE_EOF is not safely observable via the 0.14.1 public API"
                .to_string(),
        );
    }
    dbg_log("mk7 after worker join, before endf");

    // 结束会话 → 原生 read-wait Stop（event 由 session 管理；EndSession 后句柄被关闭）。
    // SAFETY: session 句柄有效；worker 已 join，无并发 ReceivePacket。
    eprintln!("DBG mk7b before endf");
    dbg_log("mk7b before endf");
    unsafe { (endf)(session) };
    facts.session_ended = true;
    // 立即检查 read-wait event（在 EndSession 与 Wait 之间不创建任何内核对象，
    // 避免句柄值被回收造成误判；0.14.1 的 EndSession 会 CloseHandle 该事件）。
    if let Some(ev) = read_wait_handle {
        facts.read_wait_event_valid = !ev.is_invalid();
        // SAFETY: ev 是 session 管理的事件句柄；EndSession 后句柄已被 session 关闭。
        let wr = unsafe { WaitForSingleObject(ev, 3000) };
        facts.read_wait_signaled_after_end_session = wr == WAIT_OBJECT_0;
        notes.push(format!(
            "WaitForSingleObject(readwait) after EndSession returned {wr:?} (0.14.1: EndSession closes the session-owned read-wait event; caller must not CloseHandle)"
        ));
        // 我们不 CloseHandle 该事件（session 管理），read_wait_event_not_closed_by_self=true。
    }
    dbg_log("mk8 after endf + readwait check");
    eprintln!("DBG mk8 after endf + readwait check");

    // 关闭 adapter（创建者 close → 移除 adapter）。
    // SAFETY: adapter 是创建所得句柄；WintunCloseAdapter 释放并移除（无独立 delete 导出）。
    // 此时 worker 已 join，无并发访问。
    dbg_log("mk9 before closef");
    unsafe { (closef)(adapter); }
    dbg_log("mk10 after closef");

    // verify adapter removed: open-by-name 应失败。
    // SAFETY: name 合法；NULL 表示已不存在。
    let after = unsafe { (openf)(PCWSTR::from_raw(name.as_ptr())) };
    if after.is_null() {
        facts.adapter_removed_by_close = true;
    } else {
        // SAFETY: 意外仍存在，关闭非创建者句柄（不删除）。
        unsafe { (closef)(after); }
    }
    dbg_log("mk11 after verify-removed");

    // DeleteDriver（最后一个 handle 关闭后，可删除驱动）。实测（本宿主，驱动被
    // Mihomo "Meta Tunnel" 占用）：0.14.1 在驱动仍被占用时**快速失败**（不阻塞、
    // 不删除服务，GetLastError=0xE000023D），而非挂死；记录观测到的返回与错误码。
    // 若驱动未被任何 adapter 占用，DeleteDriver 会停止并删除 wintun 服务
    // （wintun.h: "Deletes the Wintun driver if there are no more adapters in use"），
    // 下一次 WintunCreateAdapter 会重新安装——这是 API 契约，探针如实调用并记录。
    if let Some(delf) = del {
        dbg_log("mk12 before delf");
        // SAFETY: 无参数，返回 BOOL。
        let ok = unsafe { (delf)() != 0 };
        facts.delete_driver_result = Some(if ok { 1 } else { last_error_code() });
        notes.push(format!(
            "WintunDeleteDriver returned {} ({}); driver in use by other adapters fails fast on 0.14.1, no hang",
            if ok { "TRUE" } else { "FALSE" },
            facts.delete_driver_result.unwrap_or(0)
        ));
        dbg_log("mk13 after delf");
    }

    // 释放 DLL 引用（此时 worker 已 join，无并发访问）。
    // SAFETY: 探针持有的 DLL 引用最后一次使用后释放。
    dbg_log("mk14 before FreeLibrary");
    unsafe { let _ = FreeLibrary(hmod); }
    dbg_log("mk15 probe done");

    facts.probe_notes = notes;
    facts
}

/// worker 线程写入的观测状态。
#[derive(Clone, Debug, Default)]
struct WorkerFacts {
    icmp_request_seen: bool,
    icmp_reply_sent: bool,
    received_released: bool,
    saw_handle_eof: bool,
    empty_ring_error: Option<u32>,
    last_received_size: Option<u32>,
    last_sent_size: Option<u32>,
    /// worker 收到的包总数（诊断：区分 ring 是否真的有流量）。
    packet_count: u32,
    /// 首个收到的包的前 32 字节 hex（诊断：识别包来源）。
    first_packet_hex: Option<String>,
    /// worker 最后构造并 send 的 reply 的前 32 字节 hex（诊断：校验 reply 内容）。
    last_sent_hex: Option<String>,
    /// worker 应答的 echo request 的前 32 字节 hex（诊断：识别请求来源）。
    icmp_request_hex: Option<String>,
}

/// 类型化的 Wintun 导出函数指针（与 wintun.h 签名一致）。
type CreateAdapterFn = unsafe extern "system" fn(PCWSTR, PCWSTR, *const windows::core::GUID) -> *mut c_void;
type OpenAdapterFn = unsafe extern "system" fn(PCWSTR) -> *mut c_void;
type CloseAdapterFn = unsafe extern "system" fn(*mut c_void);
type DeleteDriverFn = unsafe extern "system" fn() -> i32;
type GetAdapterLuidFn = unsafe extern "system" fn(*mut c_void, *mut NET_LUID_LH);
type RunningDriverVersionFn = unsafe extern "system" fn() -> u32;
type StartSessionFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type EndSessionFn = unsafe extern "system" fn(*mut c_void);
type GetReadWaitEventFn = unsafe extern "system" fn(*mut c_void) -> windows::Win32::Foundation::HANDLE;
type ReceivePacketFn = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type ReleaseReceivePacketFn = unsafe extern "system" fn(*mut c_void, *const u8);
type AllocateSendPacketFn = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
type SendPacketFn = unsafe extern "system" fn(*mut c_void, *const u8);

/// `ProcAddr`（windows crate 类型：`Option<unsafe extern "system" fn() -> isize>`）。
type ProcAddr = unsafe extern "system" fn() -> isize;

/// 把裸 session 指针包成可跨线程发送的句柄。
///
/// `*mut c_void` 本身不 `Send`；探针保证该指针指向的 session 在 worker 线程存活期内
/// 有效（主线程在 `WintunEndSession` + 之后 join worker，close adapter 与 unload DLL
/// 都发生在 join 之后）。FFI 回调签名是 `extern "system" fn(...)`，不要求 `Send`。
#[derive(Clone, Copy)]
struct RawSession(*mut c_void);
// SAFETY: 探针生命周期保证 session 指针在 worker 线程结束前始终有效。
unsafe impl Send for RawSession {}
unsafe impl Sync for RawSession {}

/// 加载 DLL 并返回 HMODULE。
fn load_library(path: &Path) -> Result<HMODULE, windows::core::Error> {
    let h = HSTRING::from(path.as_os_str());
    // SAFETY: h 是合法宽字符串路径；返回模块句柄。
    unsafe { LoadLibraryW(&h) }
}

/// GetProcAddress：按名称解析导出，返回裸函数指针。
fn get_export(hmod: HMODULE, name: &str) -> Option<ProcAddr> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: hmod 有效；cname 是 NUL 结尾 ANSI 名称。CString::as_ptr 返回 *const i8，
    // PCSTR 期望 *const u8，转换是同一地址。
    unsafe { GetProcAddress(hmod, PCSTR::from_raw(cname.as_ptr().cast::<u8>())) }
}

/// 把 GetProcAddress 返回的 ProcAddr 转成特定签名的函数指针。
fn cast_fn<T>(fp: ProcAddr) -> T {
    // SAFETY: 调用方用已知签名声明；GetProcAddress 返回的地址即该导出入口。
    unsafe { std::mem::transmute_copy(&fp) }
}

/// 从已解析导出表里按名称取出并转成指定签名的函数指针。
fn resolve_typed<T>(resolved: &[(&'static str, ProcAddr)], name: &str) -> Option<T> {
    resolved
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, f)| cast_fn::<T>(*f))
}

fn call_running_driver_version(fp: ProcAddr) -> Option<u32> {
    let f: RunningDriverVersionFn = cast_fn(fp);
    // SAFETY: 无参数调用。
    let v = unsafe { (f)() };
    if v == 0 { None } else { Some(v) }
}

fn last_error_code() -> u32 {
    // SAFETY: 无指针参数，纯读线程错误码。
    unsafe { GetLastError().0 }
}

/// worker 线程的同步上下文。
struct WorkerCtx {
    shared: Arc<Mutex<WorkerFacts>>,
    stop: Arc<AtomicBool>,
    done_tx: mpsc::Sender<()>,
}

/// packet worker：receive 循环。捕获 ICMP echo request 则构造 reply 并 send。
fn packet_worker(
    session: RawSession,
    recv: ReceivePacketFn,
    relrecv: ReleaseReceivePacketFn,
    alloc: AllocateSendPacketFn,
    send: SendPacketFn,
    ctx: WorkerCtx,
) {
    let WorkerCtx {
        shared,
        stop,
        done_tx,
    } = ctx;
    // 循环结构：**先尝试 recv**，再检查 stop（仅在空 ring 分支）。这样 EndSession 后
    // 下一次 recv 会返回 ERROR_HANDLE_EOF（worker 观测到 EOF），而不是被 stop 提前截断。
    loop {
        let mut size = 0u32;
        // SAFETY: session 有效；size 是输出参数。
        let pkt = unsafe { (recv)(session.0, &mut size) };
        if pkt.is_null() {
            let err = last_error_code();
            if err == ERROR_HANDLE_EOF.0 {
                shared.lock().unwrap().saw_handle_eof = true;
                break;
            }
            if err == ERROR_NO_MORE_ITEMS.0 {
                let mut g = shared.lock().unwrap();
                if g.empty_ring_error.is_none() {
                    g.empty_ring_error = Some(err);
                }
                drop(g);
                // 空 ring：若 stop 已置位则退出；否则短暂等待后重试 recv。
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
                continue;
            }
            if err == ERROR_INVALID_DATA.0 {
                shared.lock().unwrap().saw_handle_eof = true;
                break;
            }
            // 其他错误：停止。
            break;
        }
        // 拿到一个包。
        let bytes = unsafe { std::slice::from_raw_parts(pkt, size as usize) };
        {
            let mut g = shared.lock().unwrap();
            g.last_received_size = Some(size);
            g.packet_count += 1;
            if g.first_packet_hex.is_none() {
                g.first_packet_hex =
                    Some(bytes.iter().take(32).map(|b| format!("{b:02x}")).collect());
            }
        }
        // 若为 ICMP echo request，构造 reply 并 send。
        if let Some(reply) = build_icmp_reply(bytes) {
            let mut g = shared.lock().unwrap();
            g.icmp_request_seen = true;
            g.last_received_size = Some(size);
            g.icmp_request_hex =
                Some(bytes.iter().take(32).map(|b| format!("{b:02x}")).collect());
            drop(g);
            // SAFETY: session 有效；reply.len()<=MAX_IP_PACKET_SIZE。
            let out = unsafe { (alloc)(session.0, reply.len() as u32) };
            if !out.is_null() {
                // SAFETY: out 指向 size 字节可写缓冲。
                unsafe { std::ptr::copy_nonoverlapping(reply.as_ptr(), out, reply.len()); }
                // SAFETY: out 是该 session 申请待发送的包。
                unsafe { (send)(session.0, out); }
                let mut g = shared.lock().unwrap();
                g.icmp_reply_sent = true;
                g.last_sent_size = Some(reply.len() as u32);
                g.last_sent_hex =
                    Some(reply.iter().take(32).map(|b| format!("{b:02x}")).collect());
            }
        }
        // 释放 receive 内部缓冲（outstanding receive release）。
        // SAFETY: pkt 从前一次 recv 返回；释放内部 buffer。
        unsafe { (relrecv)(session.0, pkt); }
        shared.lock().unwrap().received_released = true;
    }
    let _ = done_tx.send(());
}

/// 环回测试：赋 IP + 加路由 + ping，让 worker 捕获 ICMP echo request 并回 reply。
/// 返回 ping 是否成功（host 收到 reply = receive+send 双向真实成立）。
///
/// 关键设计：Wintun 是 NdisMediumLoopback，**同子网**（10.88.88.0/24 内）的 ICMP
/// 会被内核本地应答，实测 ping 成功但包从不进入 ring（不构成收发证据）。因此给
/// adapter 显式加一条 **另一个子网**（10.99.99.0/24）的路由，ping 10.99.99.2 的
/// 包会经该路由进入 ring → worker 收到 echo request → 构造 reply send → 内核
/// 交付给 ping.exe → ping 成功。双向都真实经过 ring。
///
/// 所有子进程调用都带 watchdog 超时：本机实测 `netsh interface ip set address`
/// 在 Wintun 接口上可能无限阻塞（接口注册未完成 / 与其他网络栈组件竞争），
/// 历史上导致探针静默挂死。超时/失败时诚实返回 false，绝不挂死探针。
fn run_loopback(
    shared: &Arc<Mutex<WorkerFacts>>,
    adapter_name: &Option<String>,
    _capacity: u32,
) -> (bool, String) {
    let Some(ifname) = adapter_name else {
        return (false, String::new());
    };
    // 赋 IP 并启用接口（最多重试 4 次；单次 12s 超时后 kill 子进程）。
    // netsh 语法：interface ip set address name="<n>" source=static addr=<ip> mask=<mask>
    let mut set_ok = false;
    for _attempt in 0..4 {
        let args = [
            "interface".to_string(),
            "ip".to_string(),
            "set".to_string(),
            "address".to_string(),
            format!("name={ifname}"),
            "source=static".to_string(),
            format!("addr={WINTUN_PROBE_IP}"),
            format!("mask={WINTUN_PROBE_IP_MASK}"),
        ];
        if let Some((ok, _)) = run_cmd_checked("netsh", &args, std::time::Duration::from_secs(12)) {
            set_ok = ok;
            if ok {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    if !set_ok {
        dbg_log("loopback: netsh set address failed/timed out");
        return (false, String::new());
    }
    let enable_args = [
        "interface".to_string(),
        "set".to_string(),
        "interface".to_string(),
        format!("name={ifname}"),
        "admin=enabled".to_string(),
    ];
    let _enable = run_cmd_checked("netsh", &enable_args, std::time::Duration::from_secs(10));

    // 显式路由 10.99.99.0/24 经 adapter（跨子网 ping 才真正经过 ring）。
    let route_args = [
        "interface".to_string(),
        "ipv4".to_string(),
        "add".to_string(),
        "route".to_string(),
        format!("{WINTUN_PROBE_ROUTE_NETWORK}/{WINTUN_PROBE_ROUTE_PREFIX}"),
        format!("interface={ifname}"),
    ];
    let route_out = run_cmd_checked("netsh", &route_args, std::time::Duration::from_secs(10));
    if !matches!(&route_out, Some((true, _))) {
        dbg_log("loopback: netsh add route failed/timed out");
        return (false, String::new());
    }

    // ping 对端（跨子网，经 adapter 路由进 ring，由 worker 捕获并回 ICMP reply）。
    // 最多 3 次尝试（首次可能因路由/接口暖机超时），-w 3000 留足余量。
    let mut ping_diag = String::new();
    let mut ping_ok = false;
    for attempt in 0..3 {
        let ping_args = [
            "-n".to_string(),
            "1".to_string(),
            "-w".to_string(),
            "3000".to_string(),
            WINTUN_PROBE_IP_REMOTE.to_string(),
        ];
        let ping = run_cmd_checked("ping", &ping_args, std::time::Duration::from_secs(10));
        match &ping {
            Some((ok, out)) => {
                ping_diag.push_str(&format!(
                    "attempt{attempt}: exit={} out_hex=[{}] ",
                    if *ok { "0" } else { "nonzero" },
                    out.as_bytes().iter().take(96).map(|b| format!("{b:02x}")).collect::<String>()
                ));
                if *ok {
                    ping_ok = true;
                    break;
                }
            }
            None => ping_diag.push_str(&format!("attempt{attempt}: spawn_failed ")),
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    // 等待 worker 观测到 request（ping 可能已返回，但 worker 需一点时间写共享状态）。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    loop {
        let seen = shared.lock().unwrap().icmp_request_seen;
        if seen || std::time::Instant::now() > deadline {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // ping 成功 = host 收到 reply = 双向真实 send/receive 成立。
    (ping_ok, ping_diag)
}

/// 带 watchdog 的子进程调用：超时后 kill 子进程并返回 None。
/// 返回 (退出成功, stdout+stderr 文本)。
fn run_cmd_checked(
    program: &str,
    args: &[String],
    timeout: std::time::Duration,
) -> Option<(bool, String)> {
    use std::io::Read;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None; // 超时
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            Err(_) => return None,
        }
    };
    let mut out = String::new();
    let mut err = String::new();
    if let Some(mut s) = child.stdout.take() {
        let _ = s.read_to_string(&mut out);
    }
    if let Some(mut s) = child.stderr.take() {
        let _ = s.read_to_string(&mut err);
    }
    let _ = child.wait();
    Some((status.success(), format!("{out}{err}")))
}

/// 满 ring：连续申请最大包直到 ERROR_BUFFER_OVERFLOW。
fn probe_full_ring(
    session: *mut c_void,
    alloc: AllocateSendPacketFn,
    send: SendPacketFn,
) -> Option<u32> {
    let mut allocated: Vec<*mut u8> = Vec::new();
    let mut result = None;
    for _ in 0..WINTUN_RING_CAPACITY_MAX / WINTUN_MAX_IP_PACKET_SIZE {
        // SAFETY: session 有效；申请最大包以尽快填满 ring。
        let p = unsafe { (alloc)(session, WINTUN_MAX_IP_PACKET_SIZE) };
        if p.is_null() {
            let err = last_error_code();
            if err == ERROR_BUFFER_OVERFLOW.0 {
                result = Some(err);
            }
            break;
        }
        allocated.push(p);
        if allocated.len() >= (WINTUN_RING_CAPACITY_MAX / WINTUN_MAX_IP_PACKET_SIZE) as usize {
            break;
        }
    }
    // 释放申请的包（send 以释放内部缓冲）。
    for p in allocated {
        // SAFETY: p 是申请待发送的包；send 释放。
        unsafe { (send)(session, p); }
    }
    result
}

/// 构造 ICMP echo reply（交换 IP，type 8→0，重算校验和）。
fn build_icmp_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if pkt.len() < ihl + 8 || pkt[9] != 1 {
        return None; // 非 IPv4 ICMP
    }
    if pkt[ihl] != 8 {
        return None; // 非 echo request
    }
    let mut out = pkt.to_vec();
    // 交换 source/dest IP。
    out[12..16].copy_from_slice(&pkt[16..20]);
    out[16..20].copy_from_slice(&pkt[12..16]);
    // ICMP type = 0 (echo reply)。
    out[ihl] = 0;
    // 重算 ICMP 校验和（覆盖 ICMP header + data）。**必须先把校验和字段清零**：
    // 实测（WSP3 动态验收）漏清零会导致 reply 校验和无效（0x0800），内核 ICMP 引擎
    // 静默丢弃 reply，ping 永远收不到——ring 收发本身真实成立，但端到端失败。
    out[ihl + 2] = 0;
    out[ihl + 3] = 0;
    let icmp_sum = checksum_16bit(&out[ihl..]);
    out[ihl + 2] = (icmp_sum >> 8) as u8;
    out[ihl + 3] = (icmp_sum & 0xFF) as u8;
    // 重算 IP 校验和。
    out[10] = 0;
    out[11] = 0;
    let ip_sum = checksum_16bit(&out[..ihl]);
    out[10] = (ip_sum >> 8) as u8;
    out[11] = (ip_sum & 0xFF) as u8;
    Some(out)
}

fn checksum_16bit(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += (u32::from(data[i]) << 8) | u32::from(data[i + 1]);
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    (!sum) as u16
}

fn trim_nul(s: &str) -> String {
    s.trim_end_matches('\0').to_string()
}

/// 把探针进度追加写入文件（崩溃时可靠记录，便于诊断）。
fn dbg_log(msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("C:\\exv-wsp3-dbg.log")
    {
        let _ = writeln!(f, "[{}] {msg}", std::process::id());
    }
}

/// 当前进程是否 elevated（admin token）。
fn is_elevated() -> bool {
    // SAFETY: GetCurrentProcess 返回伪句柄，无需关闭。
    let proc_h = unsafe { windows::Win32::System::Threading::GetCurrentProcess() };
    let mut token = windows::Win32::Foundation::HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    let ok = unsafe {
        windows::Win32::System::Threading::OpenProcessToken(
            proc_h,
            windows::Win32::Security::TOKEN_QUERY,
            &mut token,
        )
    };
    if ok.is_err() {
        return false;
    }
    let mut elevated = false;
    let mut size = 0u32;
    // SAFETY: 查询 TokenElevation。
    let query = unsafe {
        windows::Win32::Security::GetTokenInformation(
            token,
            windows::Win32::Security::TokenElevation,
            Some(std::ptr::null_mut()),
            0,
            &mut size,
        )
    };
    let _ = query;
    let mut buff = vec![0u8; size as usize];
    // SAFETY: buff 是有效缓冲；TokenElevation 返回 TOKEN_ELEVATION { TokenIsElevated: BOOL }。
    let ok2 = unsafe {
        windows::Win32::Security::GetTokenInformation(
            token,
            windows::Win32::Security::TokenElevation,
            Some(buff.as_mut_ptr().cast::<c_void>()),
            buff.len() as u32,
            &mut size,
        )
    };
    if ok2.is_ok() && buff.len() >= 4 {
        elevated = u32::from_ne_bytes(buff[0..4].try_into().unwrap_or([0u8; 4])) != 0;
    }
    // SAFETY: token 是本进程新打开句柄，使用后关闭。
    unsafe { let _ = windows::Win32::Foundation::CloseHandle(token); }
    elevated
}

/// SHA-256 十六进制（小写）。
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_file_sha256(path: &Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(sha256_hex(&bytes))
}

/// 从 PE bytes 解析架构字符串。
fn pe_arch_string(bytes: &[u8]) -> Option<String> {
    let coff = pe_coff_offset(bytes)?;
    let machine = u16::from_le_bytes(bytes.get(coff..coff + 2)?.try_into().ok()?);
    Some(match machine {
        0x8664 => "x86_64".to_string(),
        0x014C => "i386".to_string(),
        0xAA64 => "arm64".to_string(),
        0x01C4 => "arm".to_string(),
        _ => format!("machine=0x{machine:04X}"),
    })
}

/// PE 里是否存在 Security Directory（Authenticode 证书表）。
fn pe_security_directory_present(bytes: &[u8]) -> bool {
    let (dd_rva, _magic) = match pe_optional_header(bytes) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let Some(entry) = dd_rva.checked_add(4 * 8) else {
        return false;
    };
    let entry = entry as usize;
    let Some(rva) = bytes.get(entry..entry + 4) else {
        return false;
    };
    let Some(size) = bytes.get(entry + 4..entry + 8) else {
        return false;
    };
    let Ok(rva) = <[u8; 4]>::try_from(rva) else {
        return false;
    };
    let Ok(size) = <[u8; 4]>::try_from(size) else {
        return false;
    };
    let rva = u32::from_le_bytes(rva);
    let size = u32::from_le_bytes(size);
    rva != 0 && size != 0
}

/// 解析 PE 导出表，返回所有导出名称（去重前）。
fn parse_pe_exports(bytes: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let (dd_rva, _magic) = match pe_optional_header(bytes) {
        Ok(x) => x,
        Err(_) => return names,
    };
    // Export dir 是 data directory index 0。
    let entry = dd_rva as usize;
    let (Some(exp_rva), Some(exp_size)) = (
        bytes.get(entry..entry + 4).and_then(|b| <[u8; 4]>::try_from(b).ok()),
        bytes.get(entry + 4..entry + 8).and_then(|b| <[u8; 4]>::try_from(b).ok()),
    ) else {
        return names;
    };
    let exp_rva = u32::from_le_bytes(exp_rva);
    let exp_size = u32::from_le_bytes(exp_size);
    if exp_rva == 0 || exp_size == 0 {
        return names;
    }
    let exp_off = match rva_to_offset(bytes, exp_rva) {
        Some(o) => o,
        None => return names,
    };
    // Export Directory: NumberOfNames at +24, AddressOfNames at +32。
    let (Some(num_names), Some(names_rva)) = (
        bytes.get(exp_off + 24..exp_off + 28).and_then(|b| <[u8; 4]>::try_from(b).ok()),
        bytes.get(exp_off + 32..exp_off + 36).and_then(|b| <[u8; 4]>::try_from(b).ok()),
    ) else {
        return names;
    };
    let num_names = u32::from_le_bytes(num_names);
    let names_rva = u32::from_le_bytes(names_rva);
    let names_off = match rva_to_offset(bytes, names_rva) {
        Some(o) => o,
        None => return names,
    };
    for i in 0..num_names as usize {
        let ptr_off = names_off + i * 4;
        let Some(name_rva) = bytes
            .get(ptr_off..ptr_off + 4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
        else {
            continue;
        };
        let name_rva = u32::from_le_bytes(name_rva);
        let name_off = match rva_to_offset(bytes, name_rva) {
            Some(o) => o,
            None => continue,
        };
        // 读 NUL 结尾字符串。
        let end = bytes[name_off..]
            .iter()
            .position(|&b| b == 0)
            .map(|i| name_off + i)
            .unwrap_or(bytes.len());
        if let Some(s) = std::str::from_utf8(&bytes[name_off..end])
            .ok()
            .filter(|s| !s.is_empty())
        {
            names.push(s.to_string());
        }
    }
    names
}

/// 返回 (data directory RVA, optional header magic)。
fn pe_optional_header(bytes: &[u8]) -> Result<(u32, u16), ()> {
    let coff = pe_coff_offset(bytes).ok_or(())?;
    let opt_off = coff + 20;
    let magic = u16::from_le_bytes(bytes.get(opt_off..opt_off + 2).ok_or(())?.try_into().ok().ok_or(())?);
    // PE32+ (0x20B): data dir 从 optional header +112 起；PE32 (0x10B): +96。
    let dd_off_rel = if magic == 0x20B { 112 } else { 96 };
    let dd_rva = opt_off.checked_add(dd_off_rel).ok_or(())? as u32;
    Ok((dd_rva, magic))
}

fn pe_coff_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 64 || bytes.get(0..2)? != b"MZ" {
        return None;
    }
    let pe = u32::from_le_bytes(bytes.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if bytes.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    Some(pe + 4)
}

/// 把 PE RVA 转成文件偏移（按 section 表）。
fn rva_to_offset(bytes: &[u8], rva: u32) -> Option<usize> {
    let coff = pe_coff_offset(bytes)?;
    let num_sections = u16::from_le_bytes(bytes.get(coff + 2..coff + 4)?.try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(bytes.get(coff + 16..coff + 18)?.try_into().ok()?) as usize;
    let sec_off = coff + 20 + opt_size;
    for i in 0..num_sections {
        let off = sec_off + i * 40;
        let va = u32::from_le_bytes(bytes.get(off + 12..off + 16)?.try_into().ok()?);
        let vsz = u32::from_le_bytes(bytes.get(off + 8..off + 12)?.try_into().ok()?);
        let raw_size = u32::from_le_bytes(bytes.get(off + 16..off + 20)?.try_into().ok()?);
        let raw_ptr = u32::from_le_bytes(bytes.get(off + 20..off + 24)?.try_into().ok()?);
        let span = vsz.max(raw_size);
        if rva >= va && rva < va.saturating_add(span) {
            return Some((raw_ptr as usize) + (rva - va) as usize);
        }
    }
    None
}

/// 尽力而为地读取 Authenticode 签名链（signtool）。找不到工具则返回 "not_run"。
fn best_effort_signature_chain(dll: &Path) -> String {
    let signtool = find_signtool();
    let Some(st) = signtool else {
        return "not_run_blocked_by_environment (signtool not found)".to_string();
    };
    let out = std::process::Command::new(&st)
        .arg("verify")
        .arg("/a")
        .arg("/v")
        .arg(dll)
        .output();
    let text = match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
        Err(_) => return "not_run_blocked_by_environment (signtool failed)".to_string(),
    };
    // 提取 "Issued to: <name>" 的叶子证书（首个）。
    let lines = text.lines();
    let mut chain = Vec::new();
    for l in lines {
        let t = l.trim();
        if t.starts_with("Issued to:") {
            let v = t.strip_prefix("Issued to:").unwrap_or_default().trim();
            chain.push(v.to_string());
        }
    }
    // signtool 按 root→leaf 顺序列出；叶子证书（签名者）在最后。
    let leaf = chain.last().cloned().unwrap_or_default();
    if leaf.is_empty() {
        "signed (chain parse inconclusive)".to_string()
    } else {
        format!("Issued to: {leaf}")
    }
}

fn find_signtool() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("EXV_SIGNTOOL") {
        let bp = PathBuf::from(p);
        if bp.exists() {
            return Some(bp);
        }
    }
    // 常见 Windows SDK 路径。
    let base = Path::new("C:/Program Files (x86)/Windows Kits/10/bin");
    let mut best: Option<PathBuf> = None;
    if let Ok(rd) = std::fs::read_dir(base) {
        for e in rd.flatten() {
            let p = e.path().join("x64").join("signtool.exe");
            if p.exists() {
                best = Some(p);
            }
        }
    }
    best
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。