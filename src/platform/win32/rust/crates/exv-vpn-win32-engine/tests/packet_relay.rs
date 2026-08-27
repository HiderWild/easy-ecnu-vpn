// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// W23B-T Terra: packet relay（AttachedPacketRelay）契约测试。test names 是
// docs/superpowers/plans/2026-08-12-vpn-rust-native-runtime-mvp-terra-oracle-plan.md §6.1
// `W23B-T` 行的**完整且精确**集合（Terra 不得改名/增删/合并）；frozen seam 是
// `AttachedPacketRelay`（exv-engine crate 的 packet_relay 模块）。Win32 子计划
// §7 `W23B-T/I` 行的必测行为：atomic single attach、two-stream race、running proof、
// EOF/panic/native terminal；killer mutants：**double consume**、**EOF only stops task**
// （以及 partial stop，见 oracle 测试）。
//
// 本测试对 seam 追加的契约（W23B-I 必须满足，否则 GREEN 编译失败）：
//   exv_vpn_win32_resource::packet_capability::PacketCapability（capability owner 在 resource crate）
//     PacketCapability::issue(lease: PacketLeaseRef, epoch: RuntimeEpoch) -> Self
//     PacketCapability::lease(&self) -> PacketLeaseRef
//     PacketCapability::is_consumed(&self) -> bool
//     （消费动作经 AttachedPacketRelay::attach 原子执行——spec §5.5：
//       Pending(capability) -> Attached(connection_id)，并发/重复 -> PacketLeaseAlreadyAttached）
//   exv_vpn_win32_resource::packet_attachment::PacketAttachment（Clone/Debug/PartialEq/Eq）
//     PacketAttachment::connection_id(&self) -> u64
//     PacketAttachment::lease(&self) -> PacketLeaseRef
//   exv_engine::packet_relay::AttachedPacketRelay（frozen seam）
//     AttachedPacketRelay::attach(&mut PacketCapability, connection_id: u64) -> Result<PacketAttachment, VpnError>
//     AttachedPacketRelay::new(attachment, channel: PacketChannel, limits: PacketLimits) -> Self
//       —— 纯状态机构造（非提权可测）；relay 组合 W23A 的 PacketChannel，不重新实现预算/序列
//     AttachedPacketRelay::attach_session(&mut self, Arc<Mutex<WintunSession>>)   // 真实环回测试注入 W17 session
//     AttachedPacketRelay::start_leg(&mut self, RelayDirection)                   // 该方向 worker 开始运行
//     AttachedPacketRelay::leg_state(&self, RelayDirection) -> RelayLegState
//     AttachedPacketRelay::running_proof(&self) -> bool   // 两个方向都必须 Running（spec §5.5/§8.5）
//     AttachedPacketRelay::on_terminal(&mut self, RelayTerminalSource)
//       —— 任一 terminal（EOF/panic/native read terminal/Stop）都使 running proof 失效（spec §6.6）
//     AttachedPacketRelay::admit_receive_packet(&mut self, &[u8]) -> Result<u64, &'static str>
//       —— receive 侧：ring 包 admit 进 channel，返回单调 sequence；> 64KiB 消息上限拒绝且不消耗 sequence
//     AttachedPacketRelay::admit_send_frame(&mut self, packets, bytes, frame_sequence) -> Result<(), &'static str>
//       —— send 侧 X71H：frame_sequence 必须等于 channel 当前 sequence（旧帧/超限拒绝）
//     AttachedPacketRelay::pump_send_frame(&mut self, &[u8], frame_sequence) -> Result<(), RelaySendError>
//       —— send 侧单帧入口：X71H + 预算 + 写入 Wintun send ring（relay 锁 -> session 锁，锁序固定）
//     AttachedPacketRelay::stop(&mut self)   // 两个方向都停（partial stop 是 mutant）
//   RelayDirection { Receive, Send } / RelayLegState { Attached, Running, Terminal }
//   RelayTerminalSource { StreamEof, TaskPanic, NativeReadTerminal, Stop }
//   RelaySendError { Rejected(&'static str), Native(NativeError) }
//
// 本测试组合 W17（wintun_session.rs 的 WintunSession/WintunPacket）与 W23A
// （packet_channel.rs 的 PacketChannel / packet_limits.rs 的 PacketLimits），不重新实现它们。
// 纯逻辑断言（capability 单次消费、attach 原子性、two-stream race、running proof 决策、
// terminal 失效、序列/admission 记账、通道上限）非提权即可运行；真实 ring 流量断言
// （跨子网 10.99.99.0/24 环回）提权运行，全部 netsh/ping 子进程带 watchdog。
//
// 冻结事实（native-wintun-facts.md §2，WSP3 提权实测）继承：
//   - Wintun 是 NdisMediumLoopback：同子网 ICMP 被内核本地应答、不进入 ring；只有跨子网
//     （10.99.99.0/24 经 adapter 显式路由）的包才真实经过 ring；
//   - ICMP reply 校验和必须先清零再重算（实测 bug：漏清零 -> 0x0800 无效，内核静默丢弃）；
//   - child worker 必须**先 join 再 WintunEndSession**（0.14.1 EndSession 销毁 session 对象，
//     之后任何 receive 都是 UAF——实测 ntdll AV）；
//   - read-wait 事件由 session 管理，调用方不得 CloseHandle；
//   - outstanding receive 经 WintunReleaseReceivePacket 释放（drop WintunPacket 即是）。

use std::ffi::c_void;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use exv_vpn_data_plane::budget::DataPlaneDirection;
use exv_vpn_domain::error::{ErrorCode, VpnError};
use exv_vpn_domain::identity::{ResourceIdentityDigest, RuntimeEpoch};
use exv_vpn_domain::model::PacketLeaseRef;
use exv_engine::packet_relay::{
    AttachedPacketRelay, RelayDirection, RelayLegState, RelaySendError, RelayTerminalSource,
};
use exv_vpn_win32_ipc::packet_channel::PacketChannel;
use exv_vpn_win32_ipc::packet_limits::PacketLimits;
use exv_vpn_win32_resource::packet_attachment::PacketAttachment;
use exv_vpn_win32_resource::packet_capability::PacketCapability;
use exv_vpn_win32_resource::wintun_adapter::{AdapterOpen, WintunAdapter};
use exv_vpn_win32_resource::wintun_api::WintunLibrary;
use exv_vpn_win32_resource::wintun_session::WintunSession;

use uuid::Uuid;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_FAILED};
use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, WaitForSingleObject};

/// 冻结的 amd64 wintun-0.14.1 DLL 精确路径（PATH DLL 是 mutant；哈希由 WintunLibrary::load 校验）。
const FROZEN_DLL_PATH: &str = "C:\\Users\\TomLi\\.exv\\wintun\\wintun\\bin\\amd64\\wintun.dll";
/// 测试使用的环容量（与 WSP3 探针一致：2^17，wintun.h 下界）。
const RING_CAPACITY: u32 = 131072;
/// 与 WSP3 探针一致的 tunnel type。
const TUNNEL_TYPE: &str = "EXV VPN";
/// 环回测试常量（WSP3 冻结：Wintun 是 NdisMediumLoopback，跨子网经 adapter 显式路由才真实经过 ring）。
const PROBE_IP: &str = "10.88.88.1";
const PROBE_IP_MASK: &str = "255.255.255.0";
const ROUTE_NETWORK: &str = "10.99.99.0/24";
/// 环回请求目的地址的字符串形式（ping.exe 参数）。
const ROUTE_DST_STR: &str = "10.99.99.2";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// 取 Ok 并 panic 掉意外 Err（不给 T 强加 Debug bound）。
fn expect_ok<T>(r: Result<T, impl std::fmt::Debug>, ctx: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("{ctx}: 失败 {e:?}"),
    }
}

/// 确定性非 nil lease（digest 以 'L' 前缀 + 序号填充，跨测试互不冲突）。
fn lease(n: u8) -> PacketLeaseRef {
    let mut digest = [0u8; 32];
    digest[0] = 0x4C; // 'L'
    digest[1] = n;
    PacketLeaseRef::try_from(ResourceIdentityDigest::try_from(digest).expect("digest"))
        .expect("lease")
}

/// 确定性非 nil runtime epoch（owner_lease 同款构造）。
fn epoch(n: u128) -> RuntimeEpoch {
    RuntimeEpoch::try_from(Uuid::from_u128(n)).expect("epoch")
}

/// 签发确定性一次性 packet capability（绑定 lease(n) + epoch(n)）。
fn issue_capability(n: u8) -> PacketCapability {
    PacketCapability::issue(lease(n), epoch(u128::from(n)))
}

/// 构造一个已 attach 的 relay（connection_id = `conn`）及其 attachment。
/// 组合 W23A：channel 由 PacketLimits::mvp() 构造，relay 不自己实现预算/序列。
fn attach_relay(conn: u64) -> (AttachedPacketRelay, PacketAttachment) {
    let mut capability = issue_capability(7);
    let attachment = AttachedPacketRelay::attach(&mut capability, conn)
        .expect("fresh capability 首次 attach 必须成功");
    let channel = PacketChannel::new(&PacketLimits::mvp(), DataPlaneDirection::ProtocolToPacket)
        .expect("mvp limits 构造 channel");
    (
        AttachedPacketRelay::new(attachment.clone(), channel, PacketLimits::mvp()),
        attachment,
    )
}

/// attach 失败断言：重复/旧 capability attach 必须返回 PacketLeaseAlreadyAttached。
fn expect_attach_conflict(r: Result<PacketAttachment, VpnError>, ctx: &str) {
    match r {
        Ok(_) => panic!("{ctx}: 重复 attach 必须失败"),
        Err(e) => assert_eq!(
            *e.code(),
            ErrorCode::PacketLeaseAlreadyAttached,
            "{ctx}: 必须返回 PacketLeaseAlreadyAttached, got {e:?}"
        ),
    }
}

/// 当前进程是否 elevated（admin token）——模式与 W17-T / WSP3 spike 一致。
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
fn configure_loopback_route(ifname: &str) -> Result<(), String> {
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
            format!("addr={PROBE_IP}"),
            format!("mask={PROBE_IP_MASK}"),
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
    // 显式路由 10.99.99.0/24 经 adapter（跨子网包才真正经过 ring）。
    let route_args = [
        "interface".to_string(),
        "ipv4".to_string(),
        "add".to_string(),
        "route".to_string(),
        ROUTE_NETWORK.to_string(),
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

/// 是否为 IPv4 ICMP echo request（type=8；忽略 TTL/校验和——内核转发会递减 TTL 并重算
/// 校验和，其余字节原样转发）。实测修正（W17-T）：正向流量由 ping.exe 触发，ping 的
/// id/seq/payload 不可预知，故匹配"任一 echo request"而非固定 identity。
fn is_icmp_echo_request(pkt: &[u8]) -> bool {
    if pkt.len() < 28 || (pkt[0] >> 4) != 4 {
        return false;
    }
    let ihl = usize::from(pkt[0] & 0x0F) * 4;
    pkt.len() >= ihl + 8 && pkt[9] == 1 && pkt[ihl] == 8
}

/// 从 IPv4 ICMP echo request 构造 reply：交换 src/dst、type 8 -> 0，TTL 重置 64；
/// IP 与 ICMP 校验和都**先清零字段再重算**——WSP3 实测 bug 的继承点：ICMP 校验和漏清零
/// 导致 reply 校验和无效（观测值 0x0800），内核 ICMP 引擎静默丢弃 reply，ping 永远不成功。
fn build_icmp_reply(request: &[u8]) -> Vec<u8> {
    assert!(request.len() >= 28 && (request[0] >> 4) == 4, "必须是 IPv4 包");
    let ihl = usize::from(request[0] & 0x0F) * 4;
    assert!(
        request.len() >= ihl + 8 && request[9] == 1 && request[ihl] == 8,
        "必须是 IPv4 ICMP echo request"
    );
    let mut reply = request.to_vec();
    // IP header：src/dst 交换（IPv4：src @12-15、dst @16-19——WSP3 spike 同款偏移，
    // 曾误用 8-11 导致 reply 协议字段/地址错乱、内核静默丢弃，ping 端到端必失败）、
    // TTL 重置，校验和清零待重算。
    reply[12..16].copy_from_slice(&request[16..20]); // 新 src = 旧 dst
    reply[16..20].copy_from_slice(&request[12..16]); // 新 dst = 旧 src
    reply[8] = 64;
    reply[10] = 0;
    reply[11] = 0; // IP 校验和清零
    // ICMP：type 8 -> 0（echo reply），校验和**先清零**再重算（WSP3 实测继承）。
    reply[ihl] = 0;
    reply[ihl + 1] = 0;
    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    let ip_sum = checksum_16bit(&reply[..ihl]);
    reply[10] = (ip_sum >> 8) as u8;
    reply[11] = (ip_sum & 0xFF) as u8;
    let icmp_sum = checksum_16bit(&reply[ihl..]);
    reply[ihl + 2] = (icmp_sum >> 8) as u8;
    reply[ihl + 3] = (icmp_sum & 0xFF) as u8;
    reply
}

// ---------------------------------------------------------------------------
// 1. attach 原子性与单次消费（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// 一次性 capability 的 attach 必须原子且单次：首次 Ok 并绑定 connection_id；同一
/// capability 的第二次 attach 必须返回 PacketLeaseAlreadyAttached（spec §5.5：
/// 并发或重复使用 -> PacketLeaseAlreadyAttached；capability 不复用——§9.2）。
/// 杀死 'capability consumed twice / attach not atomic'。
#[test]
fn packet_attach_is_single_use_and_atomic() {
    let mut capability = issue_capability(1);
    assert!(
        !capability.is_consumed(),
        "新签 capability 必须未消费"
    );
    assert!(
        capability.lease() == lease(1),
        "capability 必须绑定其 lease"
    );

    let attachment = AttachedPacketRelay::attach(&mut capability, 7)
        .expect("首次 attach 必须成功");
    assert_eq!(
        attachment.connection_id(),
        7,
        "attach 必须绑定发起 stream 的 connection_id"
    );
    assert!(
        attachment.lease() == lease(1),
        "attachment 必须携带 lease"
    );
    assert!(
        capability.is_consumed(),
        "attach 成功即原子消费 capability（单次）"
    );

    expect_attach_conflict(
        AttachedPacketRelay::attach(&mut capability, 8),
        "同一 capability 第二次 attach",
    );
}

// ---------------------------------------------------------------------------
// 2. two-stream race（纯逻辑并发，非提权）
// ---------------------------------------------------------------------------

/// 两个并发 stream 竞争同一个一次性 capability 的 attach：恰好一个 winner，loser 得到
/// PacketLeaseAlreadyAttached——并发第二 stream 不得成为第二 packet reader/writer
/// （spec §8.5）。断言的是竞争结果（每轮恰好一胜），不依赖时序。
/// 杀死 'both streams become packet readers/writers'。
#[test]
fn two_stream_race_has_one_winner() {
    for round in 0..8u64 {
        let capability = Arc::new(Mutex::new(issue_capability((round as u8) + 1)));
        let stream_a = Arc::clone(&capability);
        let stream_b = Arc::clone(&capability);
        let a_conn = 1000 + round;
        let b_conn = 2000 + round;
        let racer_a = std::thread::spawn(move || {
            AttachedPacketRelay::attach(&mut stream_a.lock().expect("capability 锁"), a_conn)
        });
        let racer_b = std::thread::spawn(move || {
            AttachedPacketRelay::attach(&mut stream_b.lock().expect("capability 锁"), b_conn)
        });
        let results: Vec<Result<PacketAttachment, VpnError>> = [racer_a, racer_b]
            .into_iter()
            .map(|h| h.join().expect("stream 线程 join"))
            .collect();
        let winners = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            winners, 1,
            "round {round}: 两个并发 stream 必须恰好一个 attach 成功"
        );
        let loser = results.iter().find(|r| r.is_err()).expect("必有 loser");
        assert_eq!(
            *loser.as_ref().expect_err("loser 是 Err").code(),
            ErrorCode::PacketLeaseAlreadyAttached,
            "round {round}: loser 必须得到 PacketLeaseAlreadyAttached"
        );
        let winner_conn = results
            .iter()
            .find_map(|r| r.as_ref().ok().map(|a| a.connection_id()))
            .expect("必有 winner");
        assert!(
            winner_conn == a_conn || winner_conn == b_conn,
            "round {round}: winner 必须是两个竞争 stream 之一"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. running proof（纯逻辑，非提权）+ 真实双向往返（提权）
// ---------------------------------------------------------------------------

/// running proof 必须等两个方向都运行：仅 attach、只有 receive 侧都不构成 proof；
/// 两腿都 start 才成立；任一 terminal（此处 StreamEof）立即失效（spec §5.5/§6.6——
/// Connected 不能只靠一个方向）。
/// 杀死 'running proof from a single direction / optimistic connected'。
///
/// 提权段：真实环回端到端——ping 10.99.99.2 的 echo request 经 ring 进 relay receive 侧
/// （read-wait event 驱动轮询）admit 进 channel（sequence 单调），reply worker 构造 ICMP
/// reply（校验和先清零再重算，WSP3 继承）经 relay send 侧 pump 回 send ring，内核送达
/// ping.exe（端到端）。Stop 先 join 两个 worker，再 drop session（EndSession）——安全顺序，
/// UAF 是 mutant。清理：adapter drop（创建者 close 即移除），路由随 adapter 消失。
#[test]
fn running_proof_waits_for_both_directions() {
    // ---- 纯逻辑部分（非提权） ----
    let (mut relay, attachment) = attach_relay(30);
    assert_eq!(attachment.connection_id(), 30, "attach 绑定 connection 30");
    assert!(
        !relay.running_proof(),
        "仅 attach（两腿 Attached）不构成 running proof"
    );
    assert_eq!(
        relay.leg_state(RelayDirection::Receive),
        RelayLegState::Attached,
        "start 前 receive 腿处于 Attached"
    );
    assert_eq!(
        relay.leg_state(RelayDirection::Send),
        RelayLegState::Attached,
        "start 前 send 腿处于 Attached"
    );
    relay.start_leg(RelayDirection::Receive);
    assert!(
        !relay.running_proof(),
        "只有 receive 侧运行不构成 running proof——两个方向都必须运行"
    );
    relay.start_leg(RelayDirection::Send);
    assert!(
        relay.running_proof(),
        "两个方向都运行 -> running proof 成立"
    );
    relay.on_terminal(RelayTerminalSource::StreamEof);
    assert!(
        !relay.running_proof(),
        "EOF 必须失效 running proof（§6.6）"
    );

    // ---- 真实环回部分（提权；非提权记为 not_run） ----
    if !require_admin("running_proof_waits_for_both_directions") {
        return;
    }
    let lib = load_frozen();
    let adapter = create_adapter(&lib, "ExvW23BRelay");
    let session = Arc::new(Mutex::new(start_session(&lib, &adapter)));
    if let Err(msg) = configure_loopback_route(adapter.alias()) {
        panic!("环回路由配置失败（无法验证真实 relay 收发）：{msg}");
    }
    // relay：注入真实 session（W17 组合），两腿启动。
    let mut real_relay = attach_relay(30).0;
    real_relay.attach_session(Arc::clone(&session));
    real_relay.start_leg(RelayDirection::Receive);
    real_relay.start_leg(RelayDirection::Send);
    assert!(real_relay.running_proof(), "两腿启动后 running proof 成立");
    let relay = Arc::new(Mutex::new(real_relay));
    let stop = Arc::new(AtomicBool::new(false));
    let admitted_seqs = Arc::new(Mutex::new(Vec::<u64>::new()));
    let (reply_tx, reply_rx) = std::sync::mpsc::channel::<(u64, Vec<u8>)>();

    // receive worker：read-wait event 驱动轮询 WintunSession::receive；echo request 经
    // relay.admit_receive_packet 进 channel（杂包排空但不 admit——host 环境杂包不确定，
    // 只对真实 echo request 记账保证确定性；ring 缓冲一律 drop 释放）。
    let w_stop = Arc::clone(&stop);
    let w_session = Arc::clone(&session);
    let w_relay = Arc::clone(&relay);
    let w_seqs = Arc::clone(&admitted_seqs);
    let receive_worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !w_stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            // 事件等待基于 session 管理的 read-wait event（调用方不 CloseHandle）。
            let ev = w_session.lock().expect("session 锁").read_wait_event();
            // SAFETY: ev 是 session 管理的有效事件句柄（本 worker 不 CloseHandle）。
            let wr = unsafe { WaitForSingleObject(ev, 100) };
            assert_ne!(wr, WAIT_FAILED, "read-wait event 无效（WAIT_FAILED）");
            loop {
                let received = {
                    let mut sess = w_session.lock().expect("session 锁");
                    match sess.receive() {
                        Ok(Some(pkt)) => Some(pkt.as_slice().to_vec()),
                        // drop(pkt) 即释放 outstanding receive（W17 冻结契约）
                        Ok(None) => None,
                        Err(e) => {
                            eprintln!("[info] worker receive Err: {e:?}");
                            None
                        }
                    }
                };
                let Some(bytes) = received else { break };
                if !is_icmp_echo_request(&bytes) {
                    continue; // 杂包排空（不 admit，保持 sequence 记账确定）
                }
                let seq = w_relay
                    .lock()
                    .expect("relay 锁")
                    .admit_receive_packet(&bytes)
                    .expect("admit echo request 必须成功");
                w_seqs.lock().expect("seqs 锁").push(seq);
                let _ = reply_tx.send((seq, bytes));
            }
        }
    });

    // reply worker：构造 ICMP reply（校验和先清零再重算）并经 relay send 侧 pump 回 send ring。
    // pump_send_frame 单次取 relay 锁完成 X71H 校验 + 写入（锁序固定：relay 锁 -> session 锁）。
    let r_stop = Arc::clone(&stop);
    let r_relay = Arc::clone(&relay);
    let reply_worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !r_stop.load(Ordering::SeqCst) && Instant::now() < deadline {
            match reply_rx.recv_timeout(Duration::from_millis(100)) {
                Ok((seq, request)) => {
                    let reply = build_icmp_reply(&request);
                    // X71H：reply 帧必须携带 channel 当前 sequence（request 的下一帧）。
                    r_relay
                        .lock()
                        .expect("relay 锁")
                        .pump_send_frame(&reply, seq + 1)
                        .expect("reply 帧必须被 admit 并写入 Wintun send ring");
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });

    // 正向触发：ping 跨子网 10.99.99.2（watchdog 兜底；端到端成功证明 reply 经 relay
    // send 侧真实回到 ring 并被内核送达 ping.exe）。
    let mut ping_ok = false;
    for _attempt in 0..3 {
        let args = [
            "-n".to_string(),
            "1".to_string(),
            "-w".to_string(),
            "3000".to_string(),
            ROUTE_DST_STR.to_string(),
        ];
        match run_cmd_checked("ping", &args, Duration::from_secs(10)) {
            Some((true, _)) => {
                ping_ok = true;
                break;
            }
            Some((false, _)) | None => {
                std::thread::sleep(Duration::from_millis(300));
            }
        }
    }
    assert!(
        ping_ok,
        "ping 10.99.99.2 必须端到端成功（request 经 relay receive 侧、reply 经 relay send 侧）"
    );
    let seq_list = admitted_seqs.lock().expect("seqs 锁").clone();
    assert!(
        !seq_list.is_empty(),
        "receive 侧必须 admit 到至少一个 echo request"
    );
    assert!(
        seq_list.windows(2).all(|w| w[1] > w[0]),
        "admit sequence 必须严格单调: {seq_list:?}（double consume 会复用 sequence）"
    );
    assert!(
        relay.lock().expect("relay 锁").running_proof(),
        "真实流量期间 running proof 必须成立"
    );

    // 安全顺序（冻结）：先 stop 两个 worker 并 join，再 drop session（EndSession）——
    // 先 EndSession 再让 worker receive 是 UAF（WSP3 实测 ntdll AV）。partial stop 在此
    // 同样暴露：任一 worker 仍在轮询即崩溃或 join 失败。
    stop.store(true, Ordering::SeqCst);
    receive_worker.join().expect("receive worker join");
    reply_worker.join().expect("reply worker join");
    relay.lock().expect("relay 锁").stop();
    assert_eq!(
        relay.lock().expect("relay 锁").leg_state(RelayDirection::Receive),
        RelayLegState::Terminal,
        "Stop 后 receive 腿必须 Terminal"
    );
    assert_eq!(
        relay.lock().expect("relay 锁").leg_state(RelayDirection::Send),
        RelayLegState::Terminal,
        "Stop 后 send 腿必须 Terminal"
    );
    assert!(
        !relay.lock().expect("relay 锁").running_proof(),
        "Stop 后 running proof 必须失效"
    );
    // worker 已 join：session 仍健康（无并发 receive；receive 不得 Err/panic）。
    match session.lock().expect("session 锁").receive() {
        Ok(_) => {}
        Err(e) => panic!("join 后 receive 必须仍可用: {e:?}"),
    }
    drop(relay);
    drop(session); // EndSession —— 此时所有 packet worker 已 join
    drop(adapter); // 创建者 close = 移除 adapter（无残留；路由随 adapter 消失）
}

// ---------------------------------------------------------------------------
// 4. EOF / panic / native terminal（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// 三种 terminal 来源（stream EOF、relay task panic、native read terminal）都必须使
/// Connected（running proof）失效（spec §6.6：EOF/panic/native terminal 原子撤销 lease
/// 与 capability 并发送 PacketRelayLost）。
/// 杀死 'EOF only stops task'（EOF 只停自己的任务、Connected 保持真 = mutant）。
#[test]
fn eof_panic_and_native_terminal_invalidate_connected() {
    let cases: [(RelayTerminalSource, u64, &str); 3] = [
        (RelayTerminalSource::StreamEof, 41, "stream EOF"),
        (RelayTerminalSource::TaskPanic, 42, "relay task panic"),
        (RelayTerminalSource::NativeReadTerminal, 43, "native read terminal"),
    ];
    for (source, conn, label) in cases {
        let (mut relay, _attachment) = attach_relay(conn);
        relay.start_leg(RelayDirection::Receive);
        relay.start_leg(RelayDirection::Send);
        assert!(
            relay.running_proof(),
            "{label} 前两腿运行 -> running proof 成立"
        );
        relay.on_terminal(source);
        assert!(
            !relay.running_proof(),
            "{label} 必须使 Connected 失效（§6.6）——EOF only stops task 是 mutant"
        );
        assert_eq!(
            relay.leg_state(RelayDirection::Receive),
            RelayLegState::Terminal,
            "{label} 后 receive 腿必须 Terminal"
        );
        assert_eq!(
            relay.leg_state(RelayDirection::Send),
            RelayLegState::Terminal,
            "{label} 后 send 腿必须 Terminal"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. old capability（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// 已消费的 capability（old）不能再次 attach——即使换 connection 重试也不行；
/// 已 attached 的单槽不接受第二次 attach（spec §5.5 单槽、§9.2 capability 不复用）。
/// 杀死 'old/consumed capability accepted'。
#[test]
fn old_capability_cannot_attach() {
    // 同一 capability：第一次 attach 消费后，第二次（换 connection）必须拒绝。
    let mut capability = issue_capability(2);
    let first = AttachedPacketRelay::attach(&mut capability, 21)
        .expect("首次 attach 必须成功");
    assert_eq!(first.connection_id(), 21);
    expect_attach_conflict(
        AttachedPacketRelay::attach(&mut capability, 22),
        "old（已消费）capability 换 connection 再 attach",
    );

    // 独立 capability 也只允许一次 attach（单槽语义独立于实例）。
    let mut capability2 = issue_capability(3);
    let attached = AttachedPacketRelay::attach(&mut capability2, 31)
        .expect("新 capability 首次 attach 必须成功");
    assert_eq!(attached.connection_id(), 31);
    expect_attach_conflict(
        AttachedPacketRelay::attach(&mut capability2, 32),
        "同一 capability 第二次 attach（即使 connection 不同）",
    );
}

// ---------------------------------------------------------------------------
// 6. oracle：double consume / partial stop（纯逻辑，非提权）
// ---------------------------------------------------------------------------

/// killer mutant oracle（Terra plan §6.1 `oracle_kills_*` 必须杀死 Win32 子计划 §7
/// W23B 的 mutant：double consume；EOF only stops task）：
///   (a) capability 级 double consume：同一 capability attach 两次，第二次必须
///       PacketLeaseAlreadyAttached；
///   (b) channel 级 double consume：同一 frame_sequence 经 admit_send_frame 消费两次，
///       第二次必须 Err("old frame")（X71H：旧帧拒绝、sequence 不复用——W23A 组合）；
///   (c) 超过 64 KiB 消息上限的 batch（receive 侧与 send 侧）必须拒绝，且拒绝不得消耗
///       sequence（下一 admit 仍从 0 开始）；
///   (d) partial stop：stop() 必须两个方向都停（任一腿仍 Running = mutant）。
#[test]
fn oracle_kills_double_consume_or_partial_stop_mutant() {
    // (a) capability 级 double consume。
    let mut capability = issue_capability(5);
    assert!(AttachedPacketRelay::attach(&mut capability, 51).is_ok());
    expect_attach_conflict(
        AttachedPacketRelay::attach(&mut capability, 52),
        "capability double consume",
    );
    assert!(
        capability.is_consumed(),
        "attach 后 capability 必须保持 consumed"
    );

    // (b) channel 级 double consume：一个 frame_sequence 只能被消费一次。
    let (mut relay, _attachment) = attach_relay(61);
    let seq = relay
        .admit_receive_packet(b"pkt-a")
        .expect("receive 侧 admit 必须成功");
    assert_eq!(seq, 0, "首个 admit 得到 sequence 0");
    let frame = [0x45u8; 40];
    relay
        .admit_send_frame(1, frame.len(), seq + 1)
        .expect("当前 sequence 的 send 帧必须被接受");
    let err = relay
        .admit_send_frame(1, frame.len(), seq + 1)
        .expect_err("同一 sequence 第二次消费必须拒绝");
    assert_eq!(
        err, "old frame",
        "X71H：已消费的 sequence 是 old frame——double consume mutant"
    );
    relay
        .admit_send_frame(1, frame.len(), seq + 2)
        .expect("下一 sequence 的 send 帧必须被接受");

    // (c) 超过 64 KiB 消息上限（WSP1 facts §7 / spec §8.5 transport max-message）必须拒绝，
    //     且拒绝不消耗 sequence。
    let (mut relay, _attachment) = attach_relay(62);
    let oversized = vec![0x45u8; 70_000]; // > max_message_bytes (65536)
    assert!(
        relay.admit_receive_packet(&oversized).is_err(),
        "receive 侧超 64 KiB 消息上限必须拒绝"
    );
    assert!(
        relay.admit_send_frame(1, oversized.len(), 0).is_err(),
        "send 侧超 64 KiB 消息上限必须拒绝"
    );
    let next = relay
        .admit_receive_packet(b"ok")
        .expect("拒绝后 admit 必须仍成功");
    assert_eq!(
        next, 0,
        "被拒 batch 不得消耗 sequence——oversized 拒绝若消耗 sequence 会打破单调"
    );

    // (d) partial stop：Stop 必须两个方向都停。
    let (mut relay, _attachment) = attach_relay(63);
    relay.start_leg(RelayDirection::Receive);
    relay.start_leg(RelayDirection::Send);
    assert!(relay.running_proof(), "两腿运行 -> running proof");
    relay.stop();
    assert_eq!(
        relay.leg_state(RelayDirection::Receive),
        RelayLegState::Terminal,
        "Stop 必须停 receive 侧（partial stop 是 mutant）"
    );
    assert_eq!(
        relay.leg_state(RelayDirection::Send),
        RelayLegState::Terminal,
        "Stop 必须停 send 侧（partial stop 是 mutant）"
    );
    assert!(
        !relay.running_proof(),
        "Stop 后 running proof 必须失效"
    );
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
