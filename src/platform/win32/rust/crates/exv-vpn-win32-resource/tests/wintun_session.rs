// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W17-T Terra: Wintun session（WintunSession / WintunPacket）契约测试。这些测试钉住
// W17-I 在 exv_vpn_win32_resource::wintun_session 实现的 seam。冻结事实
// （docs/superpowers/platforms/win32/vpn-rust-native-runtime-mvp/native-wintun-facts.md，
// WSP3 提权实测）是契约：
//   - ring capacity 131072（2^17；min 131072 / max 67108864，power_of_two）；WintunStartSession
//     拒绝非 2 幂 / 越界容量（seam start 必须 Err）；
//   - 空 ring receive -> ERROR_NO_MORE_ITEMS(259)，seam 映射为 Ok(None)；
//   - 满 ring allocate -> ERROR_BUFFER_OVERFLOW(111)，seam send 映射为 Err（不得 panic）；
//   - child packet worker 必须**先 join 再 WintunEndSession**（0.14.1 的 EndSession 销毁
//     session 对象，之后任何 WintunReceivePacket 都是 UAF——实测 ntdll AV 崩溃）；
//   - read-wait 事件由 session 管理：调用方不得 CloseHandle（EndSession 关闭之）；
//   - outstanding receive 必须经 WintunReleaseReceivePacket 释放；
//   - 真实收发：Wintun 是 NdisMediumLoopback——同子网 ICMP 被内核本地应答、不进入 ring；
//     只有跨子网（10.99.99.0/24 经 adapter 显式路由）的包才真实经过 ring；ICMP 校验和
//     必须先把字段清零再重算（WSP3 实测 bug：漏清零导致 reply 校验和无效被内核丢弃）。
//
// W17-I pinned seam（src/wintun_session.rs）：
//   pub struct WintunSession（包装 WintunStartSession 句柄）；pub struct WintunPacket（receive 缓冲 + 大小，drop 时释放）
//   WintunSession::start(&WintunLibrary, &WintunAdapter, u32) -> Result<Self, NativeError>
//   WintunSession::receive(&mut self) -> Result<Option<WintunPacket>, NativeError>   // 空 -> Ok(None)；满 -> Err
//   WintunSession::send(&mut self, &[u8]) -> Result<(), NativeError>                 // AllocateSendPacket + SendPacket
//   WintunSession::read_wait_event(&self) -> HANDLE                                    // 调用方不得 CloseHandle
//   WintunSession::ring_capacity(&self) -> u32
//   Drop -> WintunEndSession（必须在 packet worker join 之后）
// 本测试对 seam 追加的契约（W17-I 必须满足，否则 GREEN 编译失败）：
//   - WintunPacket::as_slice() -> &[u8]：receive 缓冲的内容访问（缓冲由 drop 释放）；
//   - WintunSession: Send：worker 线程经 Arc<Mutex<WintunSession>> 共享。windows::HANDLE
//     不是 Send（裸指针），W17-I 须提供有审阅 SAFETY 注释的 Send 实现（同 WSP3 spike 的
//     RawSession 模式：句柄生命周期由实现保证，跨线程期间 session 不被 EndSession）。
//
// 本测试在真实 Windows 宿主（admin）上创建真实的 Wintun adapter + session。每个测试
// 结束时按安全顺序清理：worker join -> drop session（EndSession）-> drop adapter
// （创建者 close = 移除 adapter，无残留；adapter 上的 IP/路由随之消失）。非 elevated
// 宿主上动态断言短路为 `not_run / blocked_by_environment`（明确输出，不伪造假绿）。

use std::ffi::c_void;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use exv_vpn_win32_resource::native_error::NativeError;
use exv_vpn_win32_resource::wintun_adapter::{AdapterOpen, WintunAdapter};
use exv_vpn_win32_resource::wintun_api::WintunLibrary;
use exv_vpn_win32_resource::wintun_session::{WintunPacket, WintunSession};

use windows::Win32::Foundation::{CloseHandle, ERROR_BUFFER_OVERFLOW, HANDLE, WAIT_FAILED};
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, WaitForSingleObject,
};

/// 冻结的 amd64 wintun-0.14.1 DLL 精确路径（PATH DLL 是 mutant；哈希由 WintunLibrary::load 校验）。
const FROZEN_DLL_PATH: &str = "C:\\Users\\TomLi\\.exv\\wintun\\wintun\\bin\\amd64\\wintun.dll";
/// Wintun ring capacity 官方界限（wintun.h / native-wintun-facts.md §1：min 0x20000 / max 0x4000000）。
const RING_CAPACITY_MIN: u32 = 131072;
const RING_CAPACITY_MAX: u32 = 67108864;
/// 测试使用的环容量（与 WSP3 探针一致：2^17）。
const RING_CAPACITY: u32 = RING_CAPACITY_MIN;
/// 与 WSP3 探针一致的 tunnel type。
const TUNNEL_TYPE: &str = "EXV VPN";
/// 环回测试常量（WSP3 冻结：Wintun 是 NdisMediumLoopback，跨子网经 adapter 显式路由才真实经过 ring）。
const PROBE_IP: &str = "10.88.88.1";
const PROBE_IP_MASK: &str = "255.255.255.0";
const ROUTE_NETWORK: &str = "10.99.99.0/24";
/// 环回请求目的地址的字符串形式（ping.exe 参数）。
const ROUTE_DST_STR: &str = "10.99.99.2";
/// 环回请求源地址（非本机地址，避免内核反欺骗过滤）。
const PROBE_SRC: [u8; 4] = [10, 99, 99, 1];
/// 不可路由测试地址（TEST-NET-1，本机无路由 -> 内核不会把包送回 ring）。
const UNROUTABLE_DST: [u8; 4] = [192, 0, 2, 123];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 取 Err 并 panic 掉意外 Ok（不给 T 强加 Debug bound）。
fn expect_native_error<T>(r: Result<T, NativeError>, ctx: &str) -> NativeError {
    match r {
        Err(e) => e,
        Ok(_) => panic!("{ctx}: 必须返回 Err(NativeError)"),
    }
}

/// 取 Ok 并 panic 掉意外 Err（不给 T 强加 Debug bound）。
fn expect_ok<T>(r: Result<T, NativeError>, ctx: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{ctx}: 失败 {e:?}"),
    }
}

/// 当前进程是否 elevated（admin token）——模式与 W16-T / WSP3 spike 一致。
fn is_elevated() -> bool {
    // SAFETY: GetCurrentProcess 返回伪句柄，无需关闭。
    let proc_h = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    let ok = unsafe { OpenProcessToken(proc_h, TOKEN_QUERY, &mut token) };
    if ok.is_err() {
        return false;
    }
    let mut elevated = false;
    let mut size = 0u32;
    // SAFETY: 首次查询请求所需缓冲区大小（输出为 size）。
    unsafe {
        let _ = GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::null_mut()),
            0,
            &mut size,
        );
    }
    let mut buff = vec![0u8; size as usize];
    // SAFETY: buff 是有效缓冲；TokenElevation 返回 TOKEN_ELEVATION { TokenIsElevated: BOOL }。
    let ok2 = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(buff.as_mut_ptr().cast::<c_void>()),
            buff.len() as u32,
            &mut size,
        )
    };
    if ok2.is_ok() && buff.len() >= 4 {
        elevated = u32::from_ne_bytes(buff[0..4].try_into().unwrap_or([0u8; 4])) != 0;
    }
    // SAFETY: token 是本进程新打开句柄，使用后关闭。
    unsafe { let _ = CloseHandle(token); }
    elevated
}

/// 动态断言的前置：非 elevated 时输出显式 `not_run / blocked_by_environment` 并短路。
fn require_admin(test: &str) -> bool {
    if is_elevated() {
        return true;
    }
    eprintln!(
        "[not_run/blocked_by_environment] {test}: 创建/启动 Wintun adapter/session 需要提权 \
         （elevated admin token）；当前进程非 elevated，跳过动态断言"
    );
    false
}

/// 唯一 adapter 名（按测试用途分前缀，pid 防并行/残留碰撞）。
fn unique_name(prefix: &str) -> String {
    format!("{prefix}-{}", std::process::id())
}

/// 加载冻结 DLL 的便捷入口（各测试独立加载，LoadLibraryW 引用计数安全）。
fn load_frozen() -> WintunLibrary {
    expect_ok(
        WintunLibrary::load(Path::new(FROZEN_DLL_PATH)),
        "load 冻结 wintun.dll",
    )
}

/// 创建真实 adapter（创建者 owned；drop 即移除 adapter）。
fn create_adapter(lib: &WintunLibrary, prefix: &str) -> WintunAdapter {
    let name = unique_name(prefix);
    let (adapter, opened) =
        expect_ok(WintunAdapter::create(lib, &name, TUNNEL_TYPE), "create adapter");
    assert!(
        matches!(opened, AdapterOpen::Created),
        "create 必须返回 AdapterOpen::Created"
    );
    adapter
}

/// 在真实 adapter 上以冻结容量启动 session。
fn start_session(lib: &WintunLibrary, adapter: &WintunAdapter) -> WintunSession {
    expect_ok(
        WintunSession::start(lib, adapter, RING_CAPACITY),
        "start session",
    )
}

/// 带 watchdog 的子进程调用：超时后 kill 子进程并返回 None（WSP3 spike 同款；
/// 本机实测 netsh 在 Wintun 接口上可能无限阻塞，必须 watchdog）。
/// 返回 (退出成功, stdout+stderr 文本)。
fn run_cmd_checked(
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Option<(bool, String)> {
    use std::io::Read;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None; // 超时
                }
                std::thread::sleep(Duration::from_millis(150));
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

/// 环回配置（WSP3 spike 同款，全部带 watchdog）：赋 IP -> 启用接口 -> 加跨子网路由。
/// Wintun 是 NdisMediumLoopback：同子网 ICMP 被内核本地应答、不进入 ring；显式路由
/// 10.99.99.0/24 经 adapter 后，目的 10.99.99.2 的包才真实经过 ring。
///
/// 出站触发（W17-T 提权实测修正，记录在案）：本测试改为触发内核**出站**流量
/// （ping/UDP 经显式路由进 ring——WSP3 冻结机制）。把包**注入** send ring 不会回来：
/// 注入包以"从接口收到"的姿态进入内核，Windows 默认不转发、注入包被内核直接丢弃
/// （roundtrip 收不到匹配包；pump 只能收到接口刚拉起时的 ~100 个 IPv6 组播杂包）；
/// 开接口转发（`netsh ... set subinterface forwarding=enabled`）实测也不生效。
/// 因此正向流量一律走内核出站路径（ping.exe / UdpSocket），见各测试。
fn configure_loopback_route(ifname: &str) -> Result<(), String> {
    configure_loopback_route_for(ifname, PROBE_IP, PROBE_IP_MASK, ROUTE_NETWORK)
}

/// 环回配置的通用形态：`probe_ip`/`probe_mask`/`route_network` 可自定义——并行测试用
/// **唯一**子网避免多条同网络路由抢接口（DP-02 的 9 号测试与既有 W17 环回测试共享
/// 10.99.99.0/24 时，Windows 会把 ping 路由到竞争接口、收不到 echo——23s 超时。
/// 换用 10.99.98.0/24 后确定性回归）。机制与 `configure_loopback_route` 相同（WSP3：
/// NdisMediumLoopback 同子网 ICMP 被内核本地应答、不进 ring；显式**跨子网**路由才让
/// 包真实经过 ring；正向流量走内核出站路径）。
fn configure_loopback_route_for(
    ifname: &str,
    probe_ip: &str,
    probe_mask: &str,
    route_network: &str,
) -> Result<(), String> {
    // 赋 IP 并启用接口（最多重试 4 次；单次 12s 超时后 kill 子进程——接口注册可能未完成）。
    let mut set_ok = false;
    for _attempt in 0..4 {
        let args = [
            "interface".to_string(),
            "ip".to_string(),
            "set".to_string(),
            "address".to_string(),
            format!("name={ifname}"),
            "source=static".to_string(),
            format!("addr={probe_ip}"),
            format!("mask={probe_mask}"),
        ];
        if let Some((true, _)) = run_cmd_checked("netsh", &args, Duration::from_secs(12)) {
            set_ok = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    if !set_ok {
        return Err("netsh set address 失败/超时（watchdog 已 kill）".to_string());
    }
    let enable_args = [
        "interface".to_string(),
        "set".to_string(),
        "interface".to_string(),
        format!("name={ifname}"),
        "admin=enabled".to_string(),
    ];
    let _enable = run_cmd_checked("netsh", &enable_args, Duration::from_secs(10));
    // 显式路由 {route_network} 经 adapter（跨子网包才真正经过 ring）。
    let route_args = [
        "interface".to_string(),
        "ipv4".to_string(),
        "add".to_string(),
        "route".to_string(),
        route_network.to_string(),
        format!("interface={ifname}"),
    ];
    match run_cmd_checked("netsh", &route_args, Duration::from_secs(10)) {
        Some((true, _)) => Ok(()),
        _ => Err("netsh add route 失败/超时（watchdog 已 kill）".to_string()),
    }
}

/// 16 位校验和（网络字节序求和取反；WSP3 冻结：计算前必须清零字段）。
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

/// 构造 IPv4 ICMP echo request（合法校验和：先清零再计算——WSP3 实测 bug 的继承点）。
fn build_icmp_echo_request(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::new();
    // IPv4 header（20B：v4/ihl5, tos, total len, id, flags, ttl, proto ICMP, csum, src, dst）。
    pkt.push(0x45);
    pkt.push(0);
    let total_len = 20 + 8 + payload.len();
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0x1757u16.to_be_bytes()); // identification
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // flags/frag
    pkt.push(64); // TTL
    pkt.push(1); // ICMP
    pkt.push(0);
    pkt.push(0); // IP checksum 占位
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    // ICMP echo header（8B）+ payload。
    pkt.push(8); // type echo request
    pkt.push(0); // code
    pkt.push(0);
    pkt.push(0); // ICMP checksum 占位
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(payload);
    // 校验和：先清零字段再计算（WSP3 实测：漏清零导致校验和无效被内核丢弃）。
    pkt[10] = 0;
    pkt[11] = 0;
    let ip_sum = checksum_16bit(&pkt[..20]);
    pkt[10] = (ip_sum >> 8) as u8;
    pkt[11] = (ip_sum & 0xFF) as u8;
    pkt[22] = 0;
    pkt[23] = 0;
    let icmp_sum = checksum_16bit(&pkt[20..]);
    pkt[22] = (icmp_sum >> 8) as u8;
    pkt[23] = (icmp_sum & 0xFF) as u8;
    pkt
}

/// 是否为 IPv4 ICMP echo request（type=8；忽略 TTL/校验和——内核转发会递减 TTL 并重算
/// 校验和，其余字节原样转发）。
/// 实测修正（W17-T）：正向流量由 ping.exe 触发（内核出站经路由进 ring，WSP3 冻结机制），
/// ping 的 id/seq/payload 不可预知，故匹配"任一 echo request"而非固定 identity；反
/// fake 性质不变——fake 内存环回（send 存/recv 取）返回的正是 echo request，负向断言
/// 仍能捕获（本机 ring 杂包为 IPv6 组播/IGMP/UDP，无 IPv4 echo request，无假阳性）。
fn is_icmp_echo_request(pkt: &[u8]) -> bool {
    if pkt.len() < 28 || (pkt[0] >> 4) != 4 {
        return false;
    }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    pkt.len() >= ihl + 8 && pkt[9] == 1 && pkt[ihl] == 8
}

/// 有界等待：直到收到一个 IPv4 ICMP echo request（杂包排空并释放）。事件等待基于
/// session 管理的 read-wait event（调用方不 CloseHandle）。超时返回 None。
fn wait_for_echo_request(session: &mut WintunSession, timeout: Duration) -> Option<WintunPacket> {
    let ev = session.read_wait_event();
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        // SAFETY: ev 是 session 管理的有效事件句柄（本测试不 CloseHandle 它）。
        let wr = unsafe { WaitForSingleObject(ev, 100) };
        assert_ne!(
            wr, WAIT_FAILED,
            "read-wait event 无效（WAIT_FAILED）：impl 可能已 CloseHandle session 管理的事件"
        );
        loop {
            match session.receive() {
                Ok(Some(pkt)) => {
                    if is_icmp_echo_request(pkt.as_slice()) {
                        return Some(pkt);
                    }
                    drop(pkt); // 杂包：释放并继续
                }
                Ok(None) => break,
                Err(e) => panic!("receive 意外 Err: {e:?}"),
            }
        }
    }
}

/// 有界等待：直到收到任意一个包（泵用；drop 即释放）。
fn wait_for_any_packet(session: &mut WintunSession, deadline: Instant) -> Option<WintunPacket> {
    let ev = session.read_wait_event();
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        // SAFETY: ev 是 session 管理的有效事件句柄。
        let wr = unsafe { WaitForSingleObject(ev, 50) };
        assert_ne!(wr, WAIT_FAILED, "read-wait event 无效（WAIT_FAILED）");
        match session.receive() {
            Ok(Some(pkt)) => return Some(pkt),
            Ok(None) => continue,
            Err(e) => panic!("receive 意外 Err: {e:?}"),
        }
    }
}

/// 在时间窗内观测是否收到 IPv4 ICMP echo request（负向断言用：应不匹配）。
fn observe_echo_request_in_window(session: &mut WintunSession, window: Duration) -> bool {
    let ev = session.read_wait_event();
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        // SAFETY: ev 是 session 管理的有效事件句柄。
        let wr = unsafe { WaitForSingleObject(ev, 50) };
        assert_ne!(wr, WAIT_FAILED, "read-wait event 无效（WAIT_FAILED）");
        loop {
            match session.receive() {
                Ok(Some(pkt)) => {
                    if is_icmp_echo_request(pkt.as_slice()) {
                        return true;
                    }
                    drop(pkt);
                }
                Ok(None) => break,
                Err(e) => panic!("receive 意外 Err: {e:?}"),
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Session 契约（需要 admin；非 elevated 记为 not_run）
// ---------------------------------------------------------------------------

/// ring capacity 必须是 2 的幂（100000 不是 -> Err；131072 是 -> Ok）。
/// 杀死 'any ring capacity accepted'。
#[test]
fn start_rejects_non_power_of_two_ring() {
    if !require_admin("start_rejects_non_power_of_two_ring") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW17NotPow2");
    // 100000 不是 2 的幂：start 必须 Err（seam 在调用 WintunStartSession 前校验）。
    let err = expect_native_error(
        WintunSession::start(&lib, &adapter, 100_000),
        "start ring=100000",
    );
    assert_ne!(err.code, 0, "非 2 幂容量必须 Err（code 非 0）");
    // 131072（2^17）是冻结容量：start 必须 Ok。
    let session = expect_ok(
        WintunSession::start(&lib, &adapter, RING_CAPACITY),
        "start ring=131072",
    );
    assert_eq!(
        session.ring_capacity(),
        RING_CAPACITY,
        "ring_capacity() 必须回显实际容量 131072"
    );
    // 安全清理顺序：drop session（EndSession）先于 drop adapter（创建者 close 移除）。
    drop(session);
    drop(adapter);
}

/// ring capacity 越界（<131072 或 >67108864 -> Err；边界值 131072 -> Ok）。
/// 杀死 'ring bounds not enforced'。
#[test]
fn start_rejects_out_of_bounds_ring() {
    if !require_admin("start_rejects_out_of_bounds_ring") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW17Bounds");
    for (cap, ctx) in [
        (RING_CAPACITY_MIN - 1, "start ring=131071（低于 min）"),
        (RING_CAPACITY_MAX + 1, "start ring=67108865（高于 max）"),
    ] {
        let err = expect_native_error(WintunSession::start(&lib, &adapter, cap), ctx);
        assert_ne!(err.code, 0, "{ctx}: 越界容量必须 Err（code 非 0）");
    }
    // min 边界值必须 Ok（证明拒绝是因越界，而非容量本身）。
    let session = expect_ok(
        WintunSession::start(&lib, &adapter, RING_CAPACITY_MIN),
        "start ring=131072（min 边界）",
    );
    drop(session);
    drop(adapter);
}

/// 空 ring receive -> Ok(None)（空 ring 错误 259 映射为 None，不得 Err/panic）。
/// 杀死 'empty ring receive treated as an error/panic'。
#[test]
fn empty_ring_receive_returns_none() {
    if !require_admin("empty_ring_receive_returns_none") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW17EmptyRing");
    let mut session = start_session(&lib, &adapter);
    // 排空：真实宿主上 Wintun 接口可能送来 IPv6 组播杂包（WSP3 实测观测到）；
    // 全部接收并 drop（drop 即释放），直到 Ok(None)。任何 Err 或 panic 都杀死 mutant。
    let mut drained = 0u32;
    loop {
        match session.receive() {
            Ok(Some(pkt)) => {
                drained += 1;
                drop(pkt);
                assert!(
                    drained < 512,
                    "ring 持续有包（{drained} 个仍未空）——宿主异常，避免无限循环"
                );
            }
            Ok(None) => break, // 空 ring -> Ok(None)：契约成立
            Err(e) => panic!("空 ring receive 必须映射为 Ok(None)，得到 Err({e:?})"),
        }
    }
    // 排空后立即 receive：仍必须 Ok（None 或个别杂包均可，绝不 Err/panic）。
    match session.receive() {
        Ok(Some(pkt)) => drop(pkt),
        Ok(None) => {}
        Err(e) => panic!("排空后 receive 必须 Ok（None/Some 均可），得到 Err({e:?})"),
    }
    drop(session);
    drop(adapter);
}

/// 真实收发：ping.exe 跨子网 10.99.99.2（经显式路由 10.99.99.0/24 由内核**出站**送进
/// ring，WSP3 冻结机制），receive 必须观测到该 echo request；再 send 不可路由目的地址
/// -> 内核不送回（任何内存 fake 环回都会在负向断言处返回存储的包）。
/// 实测修正（W17-T）：注入 send ring 的包被内核丢弃、不返回（本机不开转发且转发命令
/// 实测无效），故正向触发改为 ping.exe 出站流量。
/// 杀死 'send/receive not real (fake loopback)'。
#[test]
fn send_receive_roundtrip_real_packet() {
    if !require_admin("send_receive_roundtrip_real_packet") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW17Roundtrip");
    let mut session = start_session(&lib, &adapter);
    if let Err(msg) = configure_loopback_route(adapter.alias()) {
        panic!("环回路由配置失败（无法验证真实收发）：{msg}");
    }
    // 正向：ping 出站请求经路由进 ring（重试容忍接口暖机丢包；ping 无回复会超时退出，
    // watchdog 兜底；不依赖 ping 的退出码——ring 观测才是断言）。
    let mut matched = false;
    for attempt in 0..3 {
        let args = [
            "-n".to_string(),
            "1".to_string(),
            "-w".to_string(),
            "3000".to_string(),
            ROUTE_DST_STR.to_string(),
        ];
        let _ping = run_cmd_checked("ping", &args, Duration::from_secs(10));
        if wait_for_echo_request(&mut session, Duration::from_secs(2)).is_some() {
            matched = true;
            break;
        }
        if attempt < 2 {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    assert!(
        matched,
        "未收到 ping 出站的 echo request：send/receive 未真实经过 ring，或路由未生效"
    );
    // 正向收尾：排空 ring（避免迟到的 ping 请求污染负向窗口）。
    loop {
        match session.receive() {
            Ok(Some(pkt)) => drop(pkt),
            Ok(None) => break,
            Err(e) => panic!("排空 receive 意外 Err: {e:?}"),
        }
    }
    // 负向：不可路由目的地址 -> 内核不送回；fake 内存环回（send 存/recv 取）必在此暴露。
    let pkt2 = build_icmp_echo_request(PROBE_SRC, UNROUTABLE_DST, 0x1758, 2, b"W17-NEG");
    session.send(&pkt2).expect("send 不可路由包必须 Ok");
    let observed = observe_echo_request_in_window(&mut session, Duration::from_millis(1500));
    assert!(
        !observed,
        "不可路由包被'环回'收到——send/receive 是 fake 内存环回（无内核路由参与）"
    );
    drop(session);
    drop(adapter);
}

/// read-wait event 有效且由 session 管理：有效句柄、使用中不得 WAIT_FAILED、调用方不
/// CloseHandle（drop session -> EndSession 关闭之，旧句柄值随后无效）。
/// 杀死 'caller closes the session-managed event'。
#[test]
fn read_wait_event_is_valid_and_session_managed() {
    if !require_admin("read_wait_event_is_valid_and_session_managed") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW17ReadWait");
    let session = start_session(&lib, &adapter);
    let ev = session.read_wait_event();
    assert!(
        !ev.0.is_null() && !ev.is_invalid(),
        "read_wait_event() 必须返回有效事件句柄"
    );
    // 事件必须可用（非 WAIT_FAILED；TIME_OUT/OBJECT_0 均可——ring 此刻可能空也可能有杂包）。
    // SAFETY: ev 是 session 管理的有效事件句柄。
    let wr0 = unsafe { WaitForSingleObject(ev, 0) };
    assert_ne!(
        wr0, WAIT_FAILED,
        "read-wait event 无效（WAIT_FAILED）：impl 可能在返回句柄前已 CloseHandle（session 管理事件不得被调用方关闭）"
    );
    // 本测试从不 CloseHandle 该事件；drop session -> EndSession 关闭 session 拥有的事件。
    drop(session);
    // SAFETY: 传递旧句柄值本身安全；EndSession 已关闭该事件，内核返回 WAIT_FAILED。
    let wr1 = unsafe { WaitForSingleObject(ev, 0) };
    assert_eq!(
        wr1, WAIT_FAILED,
        "drop session 后事件句柄必须已由 EndSession 关闭（WAIT_FAILED）——事件未被 session 管理或 session 未正确 EndSession"
    );
    drop(adapter);
}

/// outstanding receive 释放：泵 1100 个 UDP 环回包（每个 receive 后立即 drop）。receive
/// ring 容量 ~1024 槽：若 WintunPacket drop 不释放内部缓冲（mutant），驱动在 ~1024 个
/// 未释放槽后丢弃新包 -> 计数停在 ~1024 -> 断言失败。
/// 实测修正（W17-T）：注入 send ring 的包被内核丢弃不返回，故泵改由 UdpSocket 经内核
/// **出站**路径向 10.99.99.2 发 UDP（提权实测 20/20 进入 ring，WSP3 出站机制）。
/// 杀死 'received packet buffer never released'。
#[test]
fn outstanding_receive_is_released() {
    if !require_admin("outstanding_receive_is_released") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW17Outstanding");
    let mut session = start_session(&lib, &adapter);
    if let Err(msg) = configure_loopback_route(adapter.alias()) {
        panic!("环回路由配置失败：{msg}");
    }
    // UDP 出站触发（内核经显式路由 10.99.99.0/24 把包送进 ring）。
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind UDP socket 失败");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut received = 0u32;
    for i in 0..1100u32 {
        let payload = format!("W17-PUMP-{i}");
        if let Err(e) = sock.send_to(payload.as_bytes(), (ROUTE_DST_STR, 9u16)) {
            // 个别发送失败（路由暖机等）不 panic：计数不足会诚实失败。
            eprintln!("[info] UDP send_to 失败（继续）：{e}");
            std::thread::sleep(Duration::from_millis(5));
        }
        match wait_for_any_packet(&mut session, deadline) {
            Some(p) => {
                received += 1;
                drop(p); // drop 必须释放 receive buffer
            }
            None => break,
        }
    }
    assert!(
        received >= 1080,
        "1100 个环回包仅收到 {received} 个：超过 receive ring 容量——WintunPacket drop 未释放 receive buffer（mutant）"
    );
    drop(session);
    drop(adapter);
}

/// 安全顺序：packet worker 先 join，再 drop session（EndSession）。0.14.1 的 EndSession
/// 销毁 session 对象，先 EndSession 再让 worker receive = UAF 崩溃（WSP3 实测 AV）。
/// 杀死 'end/unload before child join (UAF)'。
#[test]
fn session_end_after_worker_join_is_safe() {
    if !require_admin("session_end_after_worker_join_is_safe") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW17JoinOrder");
    let session = Arc::new(Mutex::new(start_session(&lib, &adapter)));
    let stop = Arc::new(AtomicBool::new(false));
    let worker_session = Arc::clone(&session);
    let worker_stop = Arc::clone(&stop);
    let worker = std::thread::spawn(move || {
        // packet worker：轮询 receive（空 ring 时短暂等待，与 WSP3 spike 同款）。
        let mut drained = 0u32;
        loop {
            if worker_stop.load(Ordering::SeqCst) {
                break;
            }
            match worker_session.lock().expect("session 锁").receive() {
                Ok(Some(pkt)) => {
                    drained += 1;
                    drop(pkt);
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => {
                    eprintln!("[info] worker receive Err: {e:?}");
                    break;
                }
            }
        }
        drained
    });
    // 让 worker 实际运行片刻（可能收到 IPv6 组播杂包；不依赖其数量）。
    std::thread::sleep(Duration::from_millis(150));
    stop.store(true, Ordering::SeqCst);
    // 安全顺序：**worker 先 join**，再 drop session（Drop -> WintunEndSession）。
    // 若 impl 在 EndSession 后仍有 receive 并发/被 EndSession 提前销毁 session，
    // 本进程会崩溃（UAF AV）或 join 失败——测试即失败。
    let drained = worker.join().expect("worker join 失败（receive panic？）");
    let _ = drained;
    let session = Arc::try_unwrap(session)
        .expect("Arc 必须唯一持有")
        .into_inner()
        .expect("Mutex 无竞争持有");
    drop(session); // Drop -> WintunEndSession；此时无并发 receive
    drop(adapter);
}

/// 满 ring allocate -> Err(ERROR_BUFFER_OVERFLOW 111)，不得 panic。
/// 杀死 'full-ring allocate panics'。
#[test]
fn full_ring_allocate_returns_error_not_panic() {
    if !require_admin("full_ring_allocate_returns_error_not_panic") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW17FullRing");
    let mut session = start_session(&lib, &adapter);
    // 1) 超长包：size > ring capacity（131072）时 DLL 拒绝分配（NULL）。实测修正
    //    （W17-T 提权）：0.14.1 的 WintunAllocateSendPacket 只拒绝大于 ring capacity
    //    的大小——70000（>0xFFFF 但 <131072）反而被接受并成功入队；改用 200000
    //    （>131072）才稳定触发 allocate-NULL。send() 必须返回 Err 而非 panic（任何
    //    NULL 解引用/expect 类 mutant 在此暴露——与满 ring 相同的 allocate-NULL 路径）。
    let oversized = vec![0x45u8; 200_000];
    let err = expect_native_error(session.send(&oversized), "send 超长包");
    assert_eq!(
        err.code, ERROR_BUFFER_OVERFLOW.0,
        "越界包长 send 必须 Err(ERROR_BUFFER_OVERFLOW 111), got {}",
        err.code
    );
    // 2) 满 ring：64KB（0xFFFF，< 容量 131072 被接受）包连发。实测修正（W17-T 提权）：
    //    每次 allocate 按 PacketSize+8 保留 ring 槽；131072 只容纳 1-2 个 64KB 保留，
    //    连发远快于驱动投递 -> 第 2-3 次即 allocate-NULL，DLL 返回 111；session 保持
    //    健康（旧的"无内核流量驱动不消费 send ring"假设在本宿主不成立——驱动及时
    //    投递入内核，小包连发永不填满）。
    let big = vec![0x45u8; 65_535];
    let mut ok_count = 0u32;
    let mut full_err = None;
    for _ in 0..8u32 {
        match session.send(&big) {
            Ok(()) => ok_count += 1,
            Err(e) => {
                full_err = Some(e);
                break;
            }
        }
    }
    let e = full_err.unwrap_or_else(|| {
        panic!(
            "8 次 64KB send 从未失败：send ring 未被填满（驱动持续消费？），无法验证满 ring 语义（ok_count={ok_count}）"
        )
    });
    assert_eq!(
        e.code, ERROR_BUFFER_OVERFLOW.0,
        "满 ring 失败必须 ERROR_BUFFER_OVERFLOW(111), got {}",
        e.code
    );
    assert!(
        ok_count >= 1,
        "满 ring 前必须已成功发送至少一个 64KB 包（证明 ring 确实被填满）"
    );
    // 3) 满 ring 后 session 仍健康：receive 必须 Ok（None/杂包均可），不得 Err/panic。
    match session.receive() {
        Ok(Some(pkt)) => drop(pkt),
        Ok(None) => {}
        Err(e) => panic!("满 ring 后 receive 必须仍可用: {e:?}"),
    }
    drop(session);
    drop(adapter);
}

// ---------------------------------------------------------------------------
// DP-02（W30 数据面修复）：引擎 host 侧 open_by_name + 引擎 session
// ---------------------------------------------------------------------------

/// DP-02（C++-faithful）：引擎按 **create 名** open helper 创建的 adapter（第二句柄
/// `AdapterOpen::Opened`，`owned=false`）并在此打开的句柄上启动引擎自己的 session
/// （`WintunSession::start`，不特权）——镜像 C++ `RealWintunPacketSession::start`
/// （`open_adapter` + `start_session`）。本测试在同一进程内模拟 helper+engine 拆分：
/// 创建者句柄 = helper（drop 时 creator close 移除 adapter）；打开句柄 = 引擎。
///
/// 断言（kills DP-02 mutants）：
///   - open-by-name 返回 `Opened`（非 `Created`——'host 用 create 而非 open' mutant）；
///   - 打开句柄 `owned()==false`（非创建者 close 不删 adapter）；
///   - session 在打开的句柄上启动成功；
///   - ring I/O 真实工作：跨子网 ping 出站经显式路由进 ring，receive 在打开的句柄
///     session 上观测到 echo request（'fake loopback' mutant 被杀）。
///
/// 清理顺序（W17 SAFETY-ORDER）：drop session（`WintunEndSession`）→ drop 打开的
/// 句柄（非创建者 close 不删 adapter）→ drop 创建者句柄（creator close 移除 adapter）。
/// 非 elevated 宿主短路为 `not_run / blocked_by_environment`（require_admin pattern）。
///
/// 本测试的环回子网**唯一**（10.99.98.0/24 + 10.88.89.1，与既有 W17 环回测试的
/// 10.99.99.0/24 + 10.88.88.1 隔离）：Rust 测试并行运行时，多个 adapter 共享同一
/// 网络路由会让 Windows 把 ping 路由到竞争接口而收不到 echo（23s 超时）——换唯一
/// 子网后确定性回归，同时仍满足 WSP3 跨子网显式路由要求（NdisMediumLoopback 同子网
/// ping 被内核本地应答、不进 ring）。
const DP02_PROBE_IP: &str = "10.88.89.1";
const DP02_PROBE_IP_MASK: &str = "255.255.255.0";
const DP02_ROUTE_NETWORK: &str = "10.99.98.0/24";
const DP02_ROUTE_DST_STR: &str = "10.99.98.2";

#[test]
fn engine_opens_adapter_by_name_and_starts_session_roundtrip() {
    if !require_admin("engine_opens_adapter_by_name_and_starts_session_roundtrip") {
        return;
    }
    let lib = load_frozen();
    let name = unique_name("ExvW30EngineDataPlane");
    // helper 角色：create adapter（创建者句柄；drop 即移除 adapter）。
    let (creator, created) =
        expect_ok(WintunAdapter::create(&lib, &name, TUNNEL_TYPE), "create adapter");
    assert!(
        matches!(created, AdapterOpen::Created),
        "create 必须返回 AdapterOpen::Created"
    );
    // 引擎角色：open-by-name（第二句柄；`Opened`/`owned=false`——非创建者）。
    let (engine_adapter, opened) =
        expect_ok(WintunAdapter::open(&lib, &name), "open adapter by name");
    assert!(
        matches!(opened, AdapterOpen::Opened),
        "open 已有 adapter 必须返回 AdapterOpen::Opened（不是 Created——重复创建 mutant）"
    );
    assert!(!engine_adapter.owned(), "引擎打开的句柄必须非 owned");
    assert_eq!(
        engine_adapter.alias(),
        name,
        "open-by-name 的 alias 必须等于 create 名（host 用 create 名而非 alias 打开的契约）"
    );
    // 引擎角色：在打开的（非创建者）adapter 句柄上启动自己的 session。
    let mut session = expect_ok(
        WintunSession::start(&lib, &engine_adapter, RING_CAPACITY),
        "start session on opened adapter",
    );
    assert_eq!(
        session.ring_capacity(),
        RING_CAPACITY,
        "引擎 session ring capacity 必须回显 131072"
    );
    if let Err(msg) = configure_loopback_route_for(
        engine_adapter.alias(),
        DP02_PROBE_IP,
        DP02_PROBE_IP_MASK,
        DP02_ROUTE_NETWORK,
    ) {
        panic!("环回路由配置失败（无法验证真实收发）：{msg}");
    }
    // ring I/O：跨子网 ping 出站经路由进 ring，receive 在打开的句柄 session 上观测。
    let mut matched = false;
    for attempt in 0..3 {
        let args = [
            "-n".to_string(),
            "1".to_string(),
            "-w".to_string(),
            "3000".to_string(),
            DP02_ROUTE_DST_STR.to_string(),
        ];
        let _ping = run_cmd_checked("ping", &args, Duration::from_secs(10));
        if wait_for_echo_request(&mut session, Duration::from_secs(2)).is_some() {
            matched = true;
            break;
        }
        if attempt < 2 {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    assert!(
        matched,
        "未收到 ping 出站的 echo request：引擎在打开的（非创建者）adapter 句柄上的 \
         session 未真实收发（send/receive 非真实 ring，或 open-by-name 句柄不可用）"
    );
    // 清理顺序（W17 SAFETY-ORDER）：session 先 drop（EndSession），再 drop 打开的句柄
    // （非创建者 close 不删 adapter），最后 drop 创建者句柄（creator close 移除 adapter）。
    drop(session);
    drop(engine_adapter);
    drop(creator);
}
