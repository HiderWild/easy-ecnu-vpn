// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! engine 特权进程内的 Wintun 数据面（R1b）：ring→CSTP→TLS reader + TLS→CSTP→ring
//! writer，**全在 engine 进程内零跨进程**。
//!
//! 本模块是 acceptance `engine_data_plane`（阶段 3b 真实组装）的产品移植——复用同一组
//! 产品资源 seam（`exv-vpn-win32-resource` wintun adapter/session/api + `exv-vpn-cstp`
//! codec），不依赖 acceptance crate（test-only）。R0 归因：数据面空转 sleep 不在 apply
//! 关键路径（零贡献），移植保持原有 50ms 事件等待 / 1ms 空转语义不变。
//!
//! - [`EngineDataPlane::start`]：在**已创建**的 adapter 上启动 engine session
//!   （adapter/lib 由调用方持有——`crate::platform_tunnel` 创建 adapter 并持有到
//!   Stop；本结构只持有 `Arc<Mutex<WintunSession>>` 供 reader/writer 线程共享）。
//! - [`EngineDataPlane::spawn_data_plane`]：spawn 两条数据面线程——
//!   **reader**（ring → `session.receive()` → `Codec::encode(CstpFrame::Data)` →
//!   CSTP `write_channel` → TLS → 学校）与 **writer**（CSTP `read_channel`（TLS
//!   解码帧，IP 包）→ `session.send()` → ring）。
//! - [`EngineDataPlaneThreads::stop_and_join`]：置位 stop → join 两线程 → 返回
//!   `(ring_received_bytes, ring_sent_bytes)`（engine 数据面计数器）。
//!
//! **W17 SAFETY-ORDER（冻结）**：[`EngineDataPlaneThreads`] 在 `stop_and_join`/`Drop`
//! 时**先 join 两个线程，再放掉线程持有的 session Arc 克隆**——`WintunEndSession`
//! 之前 worker 必已 join（0.14.1 的 EndSession 销毁 session 对象，之后 receive 是
//! UAF）。线程的 read-wait event 是 session 管理的（调用方不 CloseHandle），50ms
//! 等待保持 stop 标志可及时观察（可中断 join）。

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use exv_vpn_cstp::codec::{Codec, CstpFrame};
use exv_vpn_cstp::session::{CSTP_PACKET_TYPE_DPD_REQUEST, CstpControlEvent};
use exv_vpn_win32_resource::wintun_adapter::WintunAdapter;
use exv_vpn_win32_resource::wintun_api::WintunLibrary;
use exv_vpn_win32_resource::wintun_session::WintunSession;
use exv_vpn_wire::generated;
use generated::ConnectPhase;
use tokio::sync::mpsc;
use windows::Win32::Foundation::WAIT_FAILED;
use windows::Win32::System::Threading::WaitForSingleObject;

use crate::stats::StatsRegistry;
use crate::status::{StatusEvent, StatusPublisher};

/// Wintun ring capacity for the engine data plane（同 acceptance `WINTUN_PROBE_RING_CAPACITY`）。
pub const WINTUN_RING_CAPACITY: u32 = 1 << 20;

/// engine 数据面（DP-03 结构）：持有共享的 Wintun session 供 reader/writer 数据面
/// 线程直连。
///
/// 本结构只持有 `Arc<Mutex<WintunSession>>`——**不持有 adapter / WintunLibrary**。
/// 调用方（engine 的 `tunnel_runtime`，经 `platform_tunnel`）持有创建者 adapter 与
/// WintunLibrary 并保证其存活覆盖本结构：teardown 顺序是 `stop_and_join` →
/// drop `EngineDataPlane`（`WintunEndSession`）→ `platform_tunnel::restore`
/// （adapter creator close 移除 adapter、释放 lib）。session 的 `Drop` 用内嵌的
/// exports 副本调用 `WintunEndSession`，不依赖 lib 存活；但 lib 保持 DLL 加载，
/// lib 必须先于 session 存活（调用方 teardown 顺序保证）。
pub struct EngineDataPlane {
    /// engine session（在已创建的 adapter 上启动；最后一个 `Arc` drop 即
    /// `WintunEndSession`）。
    pub session: Arc<Mutex<WintunSession>>,
}

/// 数据面辅助接线（T1：统计注册表 + 延迟探测输入；C2：掉线状态上报）。
///
/// 单一入口避免 `spawn_data_plane` 参数爆炸；`Option` 字段不接线时行为与 T1 之前
/// 一致（只做 ring 计数器诊断，不写 registry、不探测延迟、不发布状态）。
///
/// 注：不 derive `Debug`——`StatusPublisher` 无 `Debug` 实现（内部持 `dyn Fn`）。
#[derive(Clone)]
pub struct DataPlaneAux {
    /// 共享统计注册表（数据面计数 + 延迟写入；`None` = 不接线）。
    pub stats: Option<Arc<StatsRegistry>>,
    /// 延迟探测配置（`None` = 关闭延迟探测）。
    pub latency: Option<LatencyProbeConfig>,
    /// CSTP 控制面事件接收端（DPD response 等；来自 cstp session；`None` = 无）。
    pub control_rx: Option<Arc<Mutex<mpsc::UnboundedReceiver<CstpControlEvent>>>>,
    /// 状态发布端点（C2：数据面掉线等运行时状态上报；`None` = 不接线——不发布状态）。
    pub status: Option<Arc<StatusPublisher>>,
    /// 关联的 apply operation_id（掉线状态事件携带；未接线时为空）。
    pub operation_id: Vec<u8>,
}

impl Default for DataPlaneAux {
    fn default() -> Self {
        Self {
            stats: None,
            latency: None,
            control_rx: None,
            status: None,
            operation_id: Vec::new(),
        }
    }
}

/// 方向映射（T1 核对结论）：reader 消费 ring 里的**出站**包（本地应用上传 →
/// CSTP/TLS → 学校）= 上传 = `tx`；writer 把 TLS 解码的**入站**包（学校 → 本地
/// 下载）送进 ring = 下载 = `rx`。与 tunnel_runtime 诊断注释（ring_received 增长 =
/// 出站被 reader 消费；ring_sent 增长 = TLS 回包被 writer 送进 ring）及前端
/// 「下载/上传」标签（rx=下载，tx=上传）一致。
fn count_reader_upload(counter: &AtomicU64, stats: Option<&StatsRegistry>, len: u64) {
    counter.fetch_add(len, Ordering::SeqCst);
    if let Some(stats) = stats {
        stats.record_tx(len);
    }
}

/// 方向映射（见 [`count_reader_upload`]）：writer 送进 ring 的是入站/下载 → `rx`。
fn count_writer_download(counter: &AtomicU64, stats: Option<&StatsRegistry>, len: u64) {
    counter.fetch_add(len, Ordering::SeqCst);
    if let Some(stats) = stats {
        stats.record_rx(len);
    }
}

// ---------------------------------------------------------------------------
// T1 latency design v2：隧道内延迟探测（DPD RTT 探索性优先 → ping fallback）。
// ---------------------------------------------------------------------------
//
// 探测循环跑在 writer 数据面线程（入站包必经 read_channel，DPD response 经
// control_rx 到达）：
//   * DPD（探索性，feature 开关 `dpd_enabled`，默认关）：每 ~5s 经 write_channel
//     发 DPD request（CSTP control 帧 0x03），收到 response（0x04）算 RTT →
//     `registry.record_latency`。学校 ASA 是否应答未验证——连续超时则**永久回退**
//     ping（真实机器验证属 S5）。
//   * ping fallback：每 `ping_interval`（默认 3 分钟）经隧道发 ICMP echo request
//     到学校网关隧道内网地址，匹配 echo reply 计时 → `record_latency`。
//   * 手动立即刷新：前端写 `refresh_marker` 文件（内容 = epoch 毫秒），探测循环
//     每秒轮询一次，发现新值立即执行一次探测。
//
// wire/UI 零变更：延迟最终经既有 `StatsRegistry.latency_ms` → `StatsEvent` →
// `RuntimeSnapshot.stats` 到达前端。

/// DPD 探测间隔（探索性；task T1 约定 ~5s）。
const DPD_PROBE_INTERVAL: Duration = Duration::from_secs(5);
/// DPD 应答超时（超过即认为无应答）。
const DPD_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// DPD 连续超时次数达到此值 → 永久回退 ping（学校 ASA 大概率不支持 DPD）。
const DPD_MAX_TIMEOUTS: u32 = 3;
/// ping 探测超时（无 echo reply 则本次探测无结果，不记录）。
const PING_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// 手动刷新标记文件的轮询间隔。
const MARKER_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// 延迟探测配置（由 `tunnel_runtime` 在拿到 CSTP offer 后构建）。
#[derive(Debug, Clone)]
pub struct LatencyProbeConfig {
    /// 隧道内网探测目标地址（默认 = 客户端子网网络基地址；真实学校网关应答 S5 验证）。
    pub target: Ipv4Addr,
    /// 本地隧道分配地址（ICMP echo request 源地址）。
    pub source: Ipv4Addr,
    /// 是否启用 DPD 探测（探索性；默认关——ASA 应答未验证）。
    pub dpd_enabled: bool,
    /// ping 探测周期（默认 3 分钟）。
    pub ping_interval: Duration,
    /// 手动刷新标记文件（`None` = 不轮询；前端「立即刷新」经此触发即时 ping）。
    pub refresh_marker: Option<PathBuf>,
}

/// 探测状态机（writer 线程内；`Instant` 计时经 `tick` 注入便于测试）。
///
/// 注：不 derive `Debug`——持有的 `Codec` 无 `Debug` 实现。
struct ProbeState {
    cfg: LatencyProbeConfig,
    kind: ProbeKind,
    dpd_timeouts: u32,
    last_dpd_sent: Instant,
    last_ping_sent: Instant,
    last_marker_check: Instant,
    last_marker_seen: u64,
    pending_dpd: Option<Instant>,
    pending_ping: Option<PendingPing>,
    next_ident: u16,
    codec: Codec,
}

/// 当前探测通道（DPD 优先，无应答回退 ping）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeKind {
    Dpd,
    Ping,
}

/// 一次在途 ping 的状态。
#[derive(Debug, Clone, Copy)]
struct PendingPing {
    sent_at: Instant,
    ident: u16,
}

impl ProbeState {
    /// 建一个探测状态机：`dpd_enabled` 时从 DPD 通道开始，否则直接用 ping。
    fn new(cfg: LatencyProbeConfig) -> Self {
        let kind = if cfg.dpd_enabled {
            ProbeKind::Dpd
        } else {
            ProbeKind::Ping
        };
        Self {
            cfg,
            kind,
            dpd_timeouts: 0,
            last_dpd_sent: Instant::now(),
            last_ping_sent: Instant::now(),
            last_marker_check: Instant::now(),
            last_marker_seen: 0,
            pending_dpd: None,
            pending_ping: None,
            next_ident: 0,
            codec: Codec::new(),
        }
    }

    /// 收到 DPD response：若有在途 DPD 请求 → 返回 RTT（ms）并清除请求。
    fn on_dpd_response(&mut self, now: Instant) -> Option<u64> {
        let sent_at = self.pending_dpd.take()?;
        self.dpd_timeouts = 0;
        Some(rtt_ms(sent_at, now))
    }

    /// 收到一个入站包：若匹配在途 ping 的 echo reply → 返回 RTT（ms）并清除请求。
    fn on_icmp_echo_reply(&mut self, pkt: &[u8], now: Instant) -> Option<u64> {
        let pending = self.pending_ping.take()?;
        if is_icmp_echo_reply(
            pkt,
            self.cfg.target,
            self.cfg.source,
            pending.ident,
        ) {
            Some(rtt_ms(pending.sent_at, now))
        } else {
            self.pending_ping = Some(pending);
            None
        }
    }

    /// 探测循环节拍：超时处理 → 手动标记 → 周期触发。`send` 接收已编码的 CSTP
    /// 帧（writer 线程经 write_channel 发出；测试注入记录闭包）。
    fn tick(&mut self, now: Instant, send: &mut dyn FnMut(Vec<u8>)) {
        // 1. 超时：DPD 无应答累计 → 回退 ping；ping 无应答清空。
        if let Some(sent_at) = self.pending_dpd {
            if now.duration_since(sent_at) >= DPD_PROBE_TIMEOUT {
                self.pending_dpd = None;
                self.dpd_timeouts += 1;
                if self.dpd_timeouts >= DPD_MAX_TIMEOUTS {
                    // 学校网关不应答 DPD → 永久回退 ping（真实验证 S5）。
                    self.kind = ProbeKind::Ping;
                }
            }
        }
        if let Some(pending) = self.pending_ping {
            if now.duration_since(pending.sent_at) >= PING_PROBE_TIMEOUT {
                self.pending_ping = None;
            }
        }

        // 2. 手动刷新标记（前端「立即刷新延迟」）：轮询本地标记文件，发现新值立即探测。
        if now.duration_since(self.last_marker_check) >= MARKER_POLL_INTERVAL {
            self.last_marker_check = now;
            if let Some(marker) = &self.cfg.refresh_marker {
                if let Some(ts) = read_refresh_marker(marker) {
                    if ts > self.last_marker_seen {
                        self.last_marker_seen = ts;
                        self.fire(now, send);
                        return;
                    }
                }
            }
        }

        // 3. 周期触发：DPD ~5s / ping `ping_interval`。
        match self.kind {
            ProbeKind::Dpd => {
                if now.duration_since(self.last_dpd_sent) >= DPD_PROBE_INTERVAL {
                    self.fire(now, send);
                }
            }
            ProbeKind::Ping => {
                if now.duration_since(self.last_ping_sent) >= self.cfg.ping_interval {
                    self.fire(now, send);
                }
            }
        }
    }

    /// 按当前通道发一次探测。
    fn fire(&mut self, now: Instant, send: &mut dyn FnMut(Vec<u8>)) {
        match self.kind {
            ProbeKind::Dpd => self.fire_dpd(now, send),
            ProbeKind::Ping => self.fire_ping(now, send),
        }
    }

    /// 发 DPD request（CSTP control 帧 0x03）并记录在途请求。
    fn fire_dpd(&mut self, now: Instant, send: &mut dyn FnMut(Vec<u8>)) {
        self.last_dpd_sent = now;
        self.pending_dpd = Some(now);
        let frame = build_dpd_request_frame();
        send(frame);
    }

    /// 发 ICMP echo request（经隧道）并记录在途 ping。
    fn fire_ping(&mut self, now: Instant, send: &mut dyn FnMut(Vec<u8>)) {
        self.last_ping_sent = now;
        let ident = self.next_ident;
        self.next_ident = self.next_ident.wrapping_add(1);
        let pkt = build_icmp_echo_request(self.cfg.source, self.cfg.target, ident, 0);
        if let Ok(frame) = self.codec.encode(&CstpFrame::Data(pkt)) {
            self.pending_ping = Some(PendingPing { sent_at: now, ident });
            send(frame);
        }
    }
}

/// 两次 Instant 的往返毫秒（饱和下取）。
fn rtt_ms(sent_at: Instant, now: Instant) -> u64 {
    u64::try_from(now.duration_since(sent_at).as_millis()).unwrap_or(u64::MAX)
}

/// 读手动刷新标记文件：内容为 epoch 毫秒；不存在/解析失败 → `None`。
fn read_refresh_marker(path: &PathBuf) -> Option<u64> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
}

/// 构建 DPD request 的 CSTP 帧字节（control kind 0x03，body = 4 字节 BE unix 时间，
/// openconnect `cstp.c` DPD 形态）。
#[must_use]
fn build_dpd_request_frame() -> Vec<u8> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(0));
    Codec::encode_raw(CSTP_PACKET_TYPE_DPD_REQUEST, &stamp.to_be_bytes())
        .expect("DPD request frame encodes within bounds")
}

/// 构建一个 IPv4 ICMP echo request 包（源/目标/标识/序号）。
#[must_use]
fn build_icmp_echo_request(source: Ipv4Addr, target: Ipv4Addr, ident: u16, seq: u16) -> Vec<u8> {
    let payload = [b'E', b'X', b'V', 0x01, (ident >> 8) as u8, (ident & 0xFF) as u8];
    let payload_len = payload.len();
    let total_len = 20 + 8 + payload_len;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[2] = ((total_len >> 8) & 0xFF) as u8;
    pkt[3] = (total_len & 0xFF) as u8;
    pkt[8] = 64; // TTL
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&source.octets());
    pkt[16..20].copy_from_slice(&target.octets());
    pkt[20] = 8; // ICMP echo request
    pkt[24..26].copy_from_slice(&ident.to_be_bytes());
    pkt[26..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..28 + payload_len].copy_from_slice(&payload);
    // IP 头校验和 + ICMP 校验和都必须正确：探测包经 CSTP Data 帧上传，网关解封装后
    // 在校园网内路由——校验和为零的 IP 头会被网关丢弃（无回包）。
    let ip_sum = internet_checksum(&pkt[0..20]);
    pkt[10] = (ip_sum >> 8) as u8;
    pkt[11] = (ip_sum & 0xFF) as u8;
    let icmp_sum = internet_checksum(&pkt[20..]);
    pkt[22] = (icmp_sum >> 8) as u8;
    pkt[23] = (icmp_sum & 0xFF) as u8;
    pkt
}

/// `pkt` 是否为匹配本探测的 ICMP echo reply（IPv4/ICMP 类型 0/源=请求目标/
/// 目标=请求源/标识匹配）。IP 头布局：字节 12-16 = 源地址，16-20 = 目标地址；
/// echo reply 的源 = 被 ping 的 `target`，目标 = 原始发送方 `source`。
#[must_use]
fn is_icmp_echo_reply(pkt: &[u8], target: Ipv4Addr, source: Ipv4Addr, ident: u16) -> bool {
    if pkt.len() < 28 {
        return false;
    }
    if pkt[0] >> 4 != 4 {
        return false; // IPv4 only
    }
    if pkt[9] != 1 {
        return false; // ICMP
    }
    if pkt[12..16] != target.octets() {
        return false; // reply 源 = 被 ping 的目标
    }
    if pkt[16..20] != source.octets() {
        return false; // reply 目标 = 请求源
    }
    if pkt[20] != 0 {
        return false; // echo reply
    }
    pkt[24..26] == ident.to_be_bytes()
}

/// 标准 Internet checksum（one's complement，按 BE 16 位字）。
#[must_use]
fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        let word = u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
        sum = sum.wrapping_add(u32::from(word));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

impl EngineDataPlane {
    /// 在**已创建**的 adapter 上启动 engine session（engine 特权进程自己建
    /// adapter——`platform_tunnel::apply` 的 `WintunAdapter::create` 已完成；本调用
    /// 直接在该创建句柄上 `WintunSession::start`，**不再 open-by-name**）。
    ///
    /// # Errors
    ///
    /// `WintunSession::start` 失败（ring 容量非法 → 87；`WintunStartSession` 失败，
    /// 如非特权）→ typed `String`（绝不 panic）。
    pub fn start(
        lib: &WintunLibrary,
        adapter: &WintunAdapter,
        ring_capacity: u32,
    ) -> Result<Self, String> {
        let session =
            WintunSession::start(lib, adapter, ring_capacity).map_err(|e| format!("{e:?}"))?;
        Ok(Self {
            session: Arc::new(Mutex::new(session)),
        })
    }

    /// 启动引擎数据面线程（ring→CSTP reader + CSTP→ring writer），直连引擎 session。
    ///
    /// - **reader 线程**：`read_wait_event`（WaitForSingleObject 50ms，可中断 join）→
    ///   `session.receive()` → `is_ipv4_packet` → ring 字节计数（上传/tx）→
    ///   `Codec::encode(CstpFrame::Data)` → engine `write_channel`（TLS）→ 学校。
    /// - **writer 线程**：engine `read_channel`（TLS 解码帧，IP 包）→ ring 字节计数
    ///   （下载/rx）→ `session.send()` → ring。
    ///
    /// `aux`（[`DataPlaneAux`]）携带统计注册表（T1 Part A：方向映射见
    /// [`count_reader_upload`]/[`count_writer_download`]）与延迟探测输入（T1 Part B：
    /// DPD→ping fallback 探测循环 + 手动刷新标记）；C2 起另携带状态发布端点与
    /// operation_id——writer 线程检测到 read_channel 关闭（TLS 掉线）时发布数据面
    /// 掉线 Failed 事件（见 [`on_read_channel_closed`]）。
    ///
    /// W17 SAFETY-ORDER：返回的 [`EngineDataPlaneThreads`] 在 `stop_and_join`/`Drop`
    /// 时先 join 两个线程，再放掉持有的 session Arc 克隆——`WintunEndSession` 之前
    /// worker 必已 join。
    #[must_use]
    pub fn spawn_data_plane(
        &self,
        write_channel: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        read_channel: &Arc<Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>>,
        log: Option<Arc<crate::log_sink::LogSink>>,
        aux: DataPlaneAux,
    ) -> EngineDataPlaneThreads {
        let reader_stop = Arc::new(AtomicBool::new(false));
        let writer_stop = Arc::new(AtomicBool::new(false));
        let ring_received_bytes = Arc::new(AtomicU64::new(0));
        let ring_sent_bytes = Arc::new(AtomicU64::new(0));

        // ---- reader 线程：ring → ring 计数 → STF Data 帧 → write_channel（TLS）。 ----
        let reader_session = Arc::clone(&self.session);
        let reader_tx = write_channel.clone();
        let reader_stop_flag = Arc::clone(&reader_stop);
        let ring_recv_counter = Arc::clone(&ring_received_bytes);
        let reader_stats = aux.stats.clone();
        let reader_log = log.clone();
        let reader = std::thread::spawn(move || {
            while !reader_stop_flag.load(Ordering::SeqCst) {
                // 事件等待基于 session 管理的 read-wait event（调用方不 CloseHandle），
                // 50ms 超时保持 stop 标志可及时观察（可中断 join）。
                let ev = reader_session.lock().expect("session 锁").read_wait_event();
                // SAFETY: ev 是 session 管理的有效事件句柄（本线程不 CloseHandle）。
                let wr = unsafe { WaitForSingleObject(ev, 50) };
                if wr == WAIT_FAILED {
                    break; // 事件句柄无效（session 已结束等）：停止线程，绝不 panic
                }
                // 排空 ring（read-wait 只保证"至少一个"；内部循环直到空）。
                loop {
                    let received = {
                        let mut sess = reader_session.lock().expect("session 锁");
                        match sess.receive() {
                            Ok(Some(pkt)) => Some(pkt.as_slice().to_vec()),
                            // drop(pkt) 即释放 outstanding receive（W17 冻结契约）
                            Ok(None) => None,
                            Err(e) => {
                                eprintln!("[info] engine data-plane receive Err: {e:?}");
                                None
                            }
                        }
                    };
                    let Some(pkt) = received else { break };
                    count_reader_upload(
                        &ring_recv_counter,
                        reader_stats.as_deref(),
                        pkt.len() as u64,
                    );
                    if is_ipv4_packet(&pkt) {
                        let Ok(frame) = Codec::new().encode(&CstpFrame::Data(pkt)) else {
                            continue;
                        };
                        // 发送失败 = TLS-write 任务已退出（write_rx drop）→ 诊断。
                        if reader_tx.send(frame).is_err() {
                            if let Some(log) = &reader_log {
                                log.emit(
                                    crate::log_sink::LogLevel::Warn,
                                    "engine",
                                    "tunnel.dataplane.write-channel-closed",
                                    "CSTP write channel closed (TLS task exited)",
                                    &[],
                                );
                            }
                            break;
                        }
                    }
                }
            }
        });

        // ---- writer 线程：read_channel（TLS）→ ring 计数 → session.send（ring）。 ----
        let writer_session = Arc::clone(&self.session);
        let tls_reader = Arc::clone(read_channel);
        let writer_stop_flag = Arc::clone(&writer_stop);
        let ring_sent_counter = Arc::clone(&ring_sent_bytes);
        let writer_stats = aux.stats.clone();
        let writer_latency = aux.latency.clone();
        let writer_control_rx = aux.control_rx.clone();
        let probe_tx = write_channel.clone();
        let writer_log = log.clone();
        // C2：掉线状态上报端点与关联 operation_id（read_channel 关闭时发布
        // Failed 事件；`None` 发布端 = 不接线，行为与 C2 之前一致）。
        let writer_status = aux.status.clone();
        let writer_operation_id = aux.operation_id.clone();
        let writer = std::thread::spawn(move || {
            // T1 latency probe：状态机（DPD→ping fallback + 手动刷新标记）。
            let mut probe = writer_latency.map(ProbeState::new);
            // 引擎 data 通道是 tokio unbounded receiver：轮询 `try_recv`（空则短睡，
            // 保持 stop 标志的可达性），收到解码后的 IP 包 → session.send。
            while !writer_stop_flag.load(Ordering::SeqCst) {
                // T1：轮询 CSTP 控制面事件（DPD response）→ 算 RTT 写 registry。
                if let Some(ctrl) = &writer_control_rx {
                    let mut guard = ctrl.lock().expect("control rx 锁");
                    if let Ok(event) = guard.try_recv() {
                        if matches!(event, CstpControlEvent::DpdResponse) {
                            if let Some(probe) = probe.as_mut() {
                                if let Some(stats) = &writer_stats {
                                    if let Some(rtt) = probe.on_dpd_response(Instant::now()) {
                                        stats.record_latency(rtt);
                                    }
                                }
                            }
                        }
                    }
                }
                // T1：探测节拍（周期 ping / 手动标记 / 超时回退）。
                if let Some(probe) = probe.as_mut() {
                    probe.tick(Instant::now(), &mut |frame: Vec<u8>| {
                        // 发送失败 = TLS-write 任务已退出（write_rx drop）→ 忽略（探测
                        // 请求是尽力而为，数据面仍继续）。
                        let _ = probe_tx.send(frame);
                    });
                }
                let pkt = match tls_reader.lock().expect("tls reader 锁").try_recv() {
                    Ok(pkt) => Some(pkt),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                        std::thread::sleep(Duration::from_millis(1));
                        None
                    }
                    Err(_) => {
                        // read_channel 关闭 = TLS-read 任务已退出 → 诊断 + C2 掉线
                        // 状态上报（Failed(DataPlane, RetrySameOperation)；自动重连
                        // 前置，见 on_read_channel_closed）。
                        on_read_channel_closed(&writer_log, &writer_status, &writer_operation_id);
                        break;
                    }
                };
                if let Some(pkt) = pkt {
                    // T1：匹配的 ICMP echo reply → 算 ping RTT 写 registry（入站包
                    // 仍正常送进 ring）。
                    if let Some(probe) = probe.as_mut() {
                        if let Some(stats) = &writer_stats {
                            if let Some(rtt) = probe.on_icmp_echo_reply(&pkt, Instant::now()) {
                                stats.record_latency(rtt);
                            }
                        }
                    }
                    let mut sess = writer_session.lock().expect("session 锁");
                    if sess.send(&pkt).is_ok() {
                        count_writer_download(
                            &ring_sent_counter,
                            writer_stats.as_deref(),
                            pkt.len() as u64,
                        );
                    }
                }
            }
        });

        EngineDataPlaneThreads {
            reader_stop,
            writer_stop,
            reader: Some(reader),
            writer: Some(writer),
            ring_received_bytes,
            ring_sent_bytes,
        }
    }
}

/// engine 数据面线程句柄（DP-03）：ring→CSTP reader + CSTP→ring writer，直连 engine
/// session。
///
/// 停止语义（W17 SAFETY-ORDER）：`stop_and_join` 置位 stop → join 两个线程 → 再放掉
/// 线程持有的 `Arc<Mutex<WintunSession>>` 克隆。`Drop` 同序兜底——任何退出路径（含
/// 错误）都先 join 再放 session，绝不把未 join 的 reader 留在 `WintunEndSession` 之后
/// （0.14.1 EndSession 销毁 session 对象，之后 receive 是 UAF）。
pub struct EngineDataPlaneThreads {
    /// reader 线程 stop 标志。
    reader_stop: Arc<AtomicBool>,
    /// writer 线程 stop 标志。
    writer_stop: Arc<AtomicBool>,
    /// reader 线程句柄（ring→CSTP→TLS）。
    reader: Option<std::thread::JoinHandle<()>>,
    /// writer 线程句柄（TLS→CSTP→ring）。
    writer: Option<std::thread::JoinHandle<()>>,
    /// ring 收到字节计数（engine 数据面计数器；证据读取，不再来自 helper）。
    ring_received_bytes: Arc<AtomicU64>,
    /// ring 发送字节计数（engine 数据面计数器；证据读取，不再来自 helper）。
    ring_sent_bytes: Arc<AtomicU64>,
}

impl EngineDataPlaneThreads {
    /// 置位 stop → join 两个线程（W17 SAFETY-ORDER：先 join 再放 session，绝不把
    /// 未 join 的 reader 留在 `WintunEndSession` 之后）。返回
    /// `(ring_received_bytes, ring_sent_bytes)`——engine 数据面计数器，证据读取。
    ///
    /// **D15 有界 join**：join 是**有界**的——两线程各自以 ≤50ms（reader 事件等待 /
    /// writer 空转睡眠）轮询 stop 标志，置位后必在 50ms 内退出。**不能**在此处做
    /// 「2s 超时 detach 兜底」：detach 后立即放 session（`WintunEndSession`）会让
    /// 未 join 的 worker 在已销毁的 session 上 receive/send = UAF（W17 冻结）。超时
    /// 兜底 force-exit 属进程级退出编排（main.rs / 服务形态，D12「2s 清不掉则记录 +
    /// force-exit」），不在此模块内做。
    ///
    /// 幂等：重复调用 / `Drop` 兜底安全（线程句柄 `take()` 后为空）。
    #[must_use]
    pub fn stop_and_join(&mut self) -> (u64, u64) {
        self.reader_stop.store(true, Ordering::SeqCst);
        self.writer_stop.store(true, Ordering::SeqCst);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        (
            self.ring_received_bytes.load(Ordering::SeqCst),
            self.ring_sent_bytes.load(Ordering::SeqCst),
        )
    }

    /// 当前累计 ring 收到字节（存活线程的实时计数器；`stop_and_join` 后不再变化）。
    #[must_use]
    pub fn ring_received(&self) -> u64 {
        self.ring_received_bytes.load(Ordering::SeqCst)
    }

    /// 当前累计 ring 发送字节（存活线程的实时计数器；`stop_and_join` 后不再变化）。
    #[must_use]
    pub fn ring_sent(&self) -> u64 {
        self.ring_sent_bytes.load(Ordering::SeqCst)
    }

    /// 计数器 Arc 克隆（`(ring_received_bytes, ring_sent_bytes)`）——供诊断线程
    /// 存活期轮询（不持有线程句柄，无 Send 约束）。
    #[must_use]
    pub fn counter_arcs(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (
            Arc::clone(&self.ring_received_bytes),
            Arc::clone(&self.ring_sent_bytes),
        )
    }
}

impl Drop for EngineDataPlaneThreads {
    fn drop(&mut self) {
        // W17 兜底：任何退出路径（含错误）都先 join 再放 session Arc 克隆。
        self.reader_stop.store(true, Ordering::SeqCst);
        self.writer_stop.store(true, Ordering::SeqCst);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

/// 包是否为 IPv4（L3 版本字段）。
#[must_use]
pub fn is_ipv4_packet(pkt: &[u8]) -> bool {
    pkt.first().is_some_and(|v| (v >> 4) == 4)
}

// ---------------------------------------------------------------------------
// C2 掉线感知：read_channel 关闭（TLS-read 任务退出）→ 写诊断日志 + 发布数据面
// 掉线 Failed 状态事件（自动重连前置；重连决策属 C3）。
// ---------------------------------------------------------------------------

/// 数据面掉线（连接建立后）的 wire 错误标记。
///
/// 标记方案（C2 决策：复用现有 wire 语义，不新增错误码——proto/domain 已有
/// `ErrorStage::DataPlane` 与 `RetryAdvice::RetrySameOperation`）：
/// - `code = EffectUnknown(13)`：同其它平台类失败（无更精确的既有码）；
/// - `stage = DataPlane(12)`：**区分关键**——现有连接期失败路径
///   （`tunnel_runtime::tunnel_error_to_wire`）一律 `stage=Ingress`，本事件是
///   唯一 `stage=DataPlane` 的来源，core 可据 `coarse=Failed + stage=DataPlane`
///   明确识别「连接建立后数据面掉线」；
/// - `retry = RetrySameOperation(2)`：可重试标记（现有失败路径一律
///   `DoNotRetry`，本事件是唯一 `RetrySameOperation` 来源）——C3 自动重连据此判定。
/// - `native = {Transport, Win32, 0}`：传输层掉线归属。
#[must_use]
fn data_plane_drop_error() -> generated::VpnError {
    generated::VpnError {
        code: generated::ErrorCode::EffectUnknown as i32,
        stage: generated::ErrorStage::DataPlane as i32,
        certainty: 0, // EffectCertainty::Unspecified（对齐现有 Failed 事件惯例）
        retry: generated::RetryAdvice::RetrySameOperation as i32,
        subject: None,
        resource: None,
        native: Some(generated::RedactedNativeError {
            category: generated::NativeErrorCategory::Transport as i32,
            namespace: generated::NativeErrorNamespace::Win32 as i32,
            code: 0,
        }),
    }
}

/// read_channel 关闭（TLS-read 任务已退出）时的处理：写诊断日志 + 数据面掉线
/// 状态上报。
///
/// 独立成函数以便单测——writer 线程整体需要真实 Wintun session 才能构造，而本
/// 掉线发布路径（日志 + `StatusEvent::failed`）可不依赖数据面线程直接验证。
/// `status` 为 `None`（未接线）时保持 C2 之前行为（只写日志，不发布状态）。
fn on_read_channel_closed(
    log: &Option<Arc<crate::log_sink::LogSink>>,
    status: &Option<Arc<StatusPublisher>>,
    operation_id: &[u8],
) {
    if let Some(log) = log {
        log.emit(
            crate::log_sink::LogLevel::Warn,
            "engine",
            "tunnel.dataplane.read-channel-closed",
            "CSTP read channel closed (TLS task exited)",
            &[],
        );
    }
    if let Some(status) = status {
        status.publish(StatusEvent::failed(
            operation_id.to_vec(),
            ConnectPhase::StartingDataPlane,
            data_plane_drop_error(),
        ));
    }
}

// ---------------------------------------------------------------------------
// 单元测试：纯函数 `is_ipv4_packet` + 线程句柄计数器访问器（无需真实 Wintun
// adapter；真实数据面线程的 W17 顺序由集成路径覆盖）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4 版本字段（首字节高 4 位 = 4）。
    #[test]
    fn ipv4_version_field_detected() {
        assert!(is_ipv4_packet(&[0x45, 0x00, 0x00, 0x2a]));
        assert!(is_ipv4_packet(&[0x40, 0x00, 0x00, 0x00]));
        assert!(is_ipv4_packet(&[0x4f, 0xff, 0xff, 0xff]));
    }

    /// 非 IPv4（IPv6 版本字段高 4 位 = 6 / 空 / 无首字节）必须返回 false。
    #[test]
    fn non_ipv4_rejected() {
        assert!(!is_ipv4_packet(&[0x60, 0x00, 0x00, 0x00]), "IPv6 头");
        assert!(!is_ipv4_packet(&[0x6f, 0xff, 0xff, 0xff]), "IPv6 头（全 1 版本）");
        assert!(!is_ipv4_packet(&[]), "空包");
        assert!(!is_ipv4_packet(&[0x00]), "版本 0");
        assert!(!is_ipv4_packet(&[0x05]), "版本 5（非 4/6）");
    }

    /// 线程句柄的计数器访问器初始为 0，且可独立读取（与 `stop_and_join` 的返回值
    /// 同源——都读同一 `Arc<AtomicU64>`）。
    #[test]
    fn thread_counters_start_zero_and_readable() {
        let threads = EngineDataPlaneThreads {
            reader_stop: Arc::new(AtomicBool::new(false)),
            writer_stop: Arc::new(AtomicBool::new(false)),
            reader: None,
            writer: None,
            ring_received_bytes: Arc::new(AtomicU64::new(0)),
            ring_sent_bytes: Arc::new(AtomicU64::new(0)),
        };
        assert_eq!(threads.ring_received(), 0);
        assert_eq!(threads.ring_sent(), 0);
        // stop_and_join 对无线程句柄的空结构是幂等 no-op（不 panic）。
        let mut threads = threads;
        assert_eq!(threads.stop_and_join(), (0, 0));
        assert_eq!(threads.stop_and_join(), (0, 0), "幂等");
    }

    /// `EngineDataPlaneThreads` 的 Drop 对无线程句柄的空结构是安全 no-op（不 panic）。
    #[test]
    fn thread_handle_drop_is_safe_noop() {
        let threads = EngineDataPlaneThreads {
            reader_stop: Arc::new(AtomicBool::new(false)),
            writer_stop: Arc::new(AtomicBool::new(false)),
            reader: None,
            writer: None,
            ring_received_bytes: Arc::new(AtomicU64::new(0)),
            ring_sent_bytes: Arc::new(AtomicU64::new(0)),
        };
        drop(threads);
    }

    // ---- T1 Part A：方向映射（reader=上传=tx，writer=下载=rx）----

    /// 方向映射：reader 计数 → tx 增长、rx 不动；writer 计数 → rx 增长、tx 不动。
    /// 与前端「下载/上传」标签一致（rx=下载，tx=上传）。
    #[test]
    fn direction_mapping_reader_tx_writer_rx() {
        let stats = StatsRegistry::new();
        let mut counter = AtomicU64::new(0);
        count_reader_upload(&mut counter, Some(&stats), 100);
        count_reader_upload(&mut counter, Some(&stats), 50);
        let sample = stats.snapshot();
        assert_eq!(sample.tx_bytes, 150, "reader 消费出站包 = 上传 = tx");
        assert_eq!(sample.rx_bytes, 0, "reader 不写 rx");
        assert_eq!(counter.load(Ordering::SeqCst), 150, "ring 计数器同步增长");

        let mut counter = AtomicU64::new(0);
        count_writer_download(&mut counter, Some(&stats), 200);
        let sample = stats.snapshot();
        assert_eq!(sample.rx_bytes, 200, "writer 送进 ring 入站包 = 下载 = rx");
        assert_eq!(sample.tx_bytes, 150, "writer 不写 tx");
        assert_eq!(counter.load(Ordering::SeqCst), 200);
    }

    /// 方向映射在 stats 为 None（不接线）时仍维持 ring 计数器（T1 前行为）。
    #[test]
    fn direction_mapping_without_stats_keeps_ring_counter() {
        let mut counter = AtomicU64::new(0);
        count_reader_upload(&mut counter, None, 10);
        count_writer_download(&mut counter, None, 20);
        assert_eq!(counter.load(Ordering::SeqCst), 30, "ring 计数器不受 stats 接线影响");
    }

    /// T1 Part A wire 断言：数据面计数（经方向映射 helper）→ registry →
    /// StreamStats 事件 rx/tx 非零（wire 输出非零）。
    #[tokio::test]
    async fn data_plane_counting_reaches_wire_nonzero() {
        use std::sync::atomic::AtomicU64;
        use std::time::Duration;

        let publisher = crate::stats::StatsPublisher::new();
        let reg = publisher.registry().clone();
        // 模拟数据面包流：reader 出站 500B（tx），writer 入站 1000B（rx）。
        let mut reader_counter = AtomicU64::new(0);
        let mut writer_counter = AtomicU64::new(0);
        count_reader_upload(&mut reader_counter, Some(&reg), 500);
        count_writer_download(&mut writer_counter, Some(&reg), 1000);

        let mut rx = publisher.open_stream(10);
        let first = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("first sample")
            .expect("stream alive")
            .expect("event ok");
        assert!(first.tx_bytes > 0, "上传字节非零: {}", first.tx_bytes);
        assert!(first.rx_bytes > 0, "下载字节非零: {}", first.rx_bytes);
        assert_eq!(first.tx_bytes, 500);
        assert_eq!(first.rx_bytes, 1000);
    }

    // ---- C2 掉线感知：read_channel 关闭 → 数据面掉线 Failed 状态上报 ----

    /// 掉线发布（有 status 接线）：`on_read_channel_closed` 必须调用
    /// `status.publish`，事件携带 coarse=Failed + connect_phase=StartingDataPlane +
    /// 掉线错误标记（stage=DataPlane、retry=RetrySameOperation——与连接期失败
    /// stage=Ingress/DoNotRetry 明确区分）。
    #[test]
    fn read_channel_closed_publishes_drop_failed_event() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let publisher = Arc::new(StatusPublisher::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(std::sync::Mutex::new(Vec::<StatusEvent>::new()));
        let calls_c = Arc::clone(&calls);
        let seen_c = Arc::clone(&seen);
        publisher.set_terminal_observer(Arc::new(move |event: &StatusEvent| {
            calls_c.fetch_add(1, Ordering::SeqCst);
            seen_c.lock().unwrap().push(event.clone());
        }));

        let op = vec![0x42u8; 16];
        on_read_channel_closed(&None, &Some(Arc::clone(&publisher)), &op);

        assert_eq!(calls.load(Ordering::SeqCst), 1, "掉线必须发布一个事件");
        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 1);
        let ev = &got[0];
        assert_eq!(ev.operation_id, op, "事件携带关联 operation_id");
        assert_eq!(ev.coarse_phase, generated::StatsPhase::Failed, "掉线 = coarse Failed");
        assert_eq!(ev.connect_phase, ConnectPhase::StartingDataPlane);
        let err = ev.error.as_ref().expect("掉线事件必须携带错误");
        assert_eq!(err.stage, generated::ErrorStage::DataPlane as i32, "stage=DataPlane");
        assert_eq!(err.retry, generated::RetryAdvice::RetrySameOperation as i32, "可重试标记");
        drop(got);
    }

    /// 未接线 status（`None`）→ 掉线路径不发布（保持 C2 之前行为，不 panic）。
    #[test]
    fn read_channel_closed_without_status_is_noop() {
        on_read_channel_closed(&None, &None, &[]);
    }

    /// 掉线错误标记自身可区分：stage=DataPlane + retry=RetrySameOperation（现有
    /// 连接期失败路径一律 stage=Ingress + DoNotRetry——无其它来源产生此组合）。
    #[test]
    fn data_plane_drop_error_is_distinguishable() {
        let err = data_plane_drop_error();
        assert_eq!(err.code, generated::ErrorCode::EffectUnknown as i32);
        assert_eq!(err.stage, generated::ErrorStage::DataPlane as i32);
        assert_eq!(err.retry, generated::RetryAdvice::RetrySameOperation as i32);
        let native = err.native.as_ref().expect("携带 native 传输层归属");
        assert_eq!(
            native.category,
            generated::NativeErrorCategory::Transport as i32
        );
        assert_eq!(native.namespace, generated::NativeErrorNamespace::Win32 as i32);
    }

    /// aux 字段构造：默认（未接线）时 status 为 None、operation_id 为空。
    #[test]
    fn data_plane_aux_default_has_no_status() {
        let aux = DataPlaneAux::default();
        assert!(aux.status.is_none(), "默认不接线状态发布");
        assert!(aux.operation_id.is_empty(), "默认无关联 operation_id");
    }

    // ---- T1 Part B：ICMP echo 构建/匹配 ----

    /// 构建的 echo request 可被自己的 echo reply（type 0 + 同 ident）匹配，RTT 计时正确。
    #[test]
    fn icmp_echo_request_round_trips_match() {
        let source = Ipv4Addr::new(10, 88, 88, 5);
        let target = Ipv4Addr::new(10, 88, 88, 0);
        let ident = 0x1234;
        let req = build_icmp_echo_request(source, target, ident, 7);
        assert_eq!(req.len(), 20 + 8 + 6, "IPv4 头 + ICMP 头 + payload");
        assert_eq!(req[9], 1, "ICMP 协议");
        assert_eq!(req[20], 8, "echo request type");
        assert_eq!(req[24..26], ident.to_be_bytes(), "ident 写入");

        // 构造匹配的 echo reply：源/目标互换 + type 0 + 重算校验和。
        let mut reply = build_icmp_echo_request(target, source, ident, 7);
        reply[20] = 0;
        let sum = internet_checksum(&reply[20..]);
        reply[22] = (sum >> 8) as u8;
        reply[23] = (sum & 0xFF) as u8;
        assert!(is_icmp_echo_reply(&reply, target, source, ident), "匹配 reply");
    }

    /// 不匹配的包（type 8 请求 / 异 ident / 异目标 / 非 ICMP）不得被当作 echo reply。
    #[test]
    fn icmp_echo_reply_rejects_non_matching() {
        let source = Ipv4Addr::new(10, 88, 88, 5);
        let target = Ipv4Addr::new(10, 88, 88, 0);
        let ident = 0x1234;
        let req = build_icmp_echo_request(source, target, ident, 0);
        assert!(!is_icmp_echo_reply(&req, target, source, ident), "type 8 不是 reply");

        let mut reply = build_icmp_echo_request(target, source, ident + 1, 0);
        reply[20] = 0;
        let sum = internet_checksum(&reply[20..]);
        reply[22] = (sum >> 8) as u8;
        reply[23] = (sum & 0xFF) as u8;
        assert!(!is_icmp_echo_reply(&reply, target, source, ident), "异 ident 不匹配");

        assert!(!is_icmp_echo_reply(&[], target, source, ident), "空包");
        let mut v6 = vec![0u8; 28];
        v6[0] = 0x60;
        assert!(!is_icmp_echo_reply(&v6, target, source, ident), "IPv6 不匹配");
    }

    // ---- T1 Part B：探测状态机（DPD→ping fallback / 手动标记 / RTT 计时）----

    fn probe_cfg(dpd_enabled: bool, refresh_marker: Option<PathBuf>) -> LatencyProbeConfig {
        LatencyProbeConfig {
            target: Ipv4Addr::new(10, 88, 88, 0),
            source: Ipv4Addr::new(10, 88, 88, 5),
            dpd_enabled,
            ping_interval: Duration::from_secs(180),
            refresh_marker,
        }
    }

    /// 解码一条探测发出的 CSTP Data 帧 → IP 包（测试便捷）。
    fn decode_data_frame(frame: &[u8]) -> Vec<u8> {
        let mut codec = Codec::new();
        codec.feed(frame);
        match codec.decode().expect("decodes").expect("some") {
            CstpFrame::Data(p) => p,
            other => panic!("expected Data frame, got {other:?}"),
        }
    }

    /// ping 周期触发：interval 未到不发，interval 到发一条，echo reply 匹配 → RTT。
    #[test]
    fn probe_ping_periodic_fires_and_times_reply() {
        let mut probe = ProbeState::new(probe_cfg(false, None));
        let t0 = Instant::now();
        let mut sent: Vec<Vec<u8>> = Vec::new();
        probe.tick(t0, &mut |f| sent.push(f));
        assert!(sent.is_empty(), "interval 未到不发");

        let t1 = t0 + Duration::from_secs(180);
        probe.tick(t1, &mut |f| sent.push(f));
        assert_eq!(sent.len(), 1, "interval 到发一条 ping");

        let ip = decode_data_frame(&sent[0]);
        assert_eq!(ip[16..20], probe.cfg.target.octets(), "ping 包目标 = 探测目标");
        // 构造匹配 echo reply（type 0 + 同 ident）。
        let mut reply = build_icmp_echo_request(probe.cfg.target, probe.cfg.source, 0, 0);
        reply[20] = 0;
        let sum = internet_checksum(&reply[20..]);
        reply[22] = (sum >> 8) as u8;
        reply[23] = (sum & 0xFF) as u8;
        let rtt = probe.on_icmp_echo_reply(&reply, t1 + Duration::from_millis(40));
        assert_eq!(rtt, Some(40), "echo reply 计时 40ms");
        assert!(probe.pending_ping.is_none(), "reply 后清空在途请求");
    }

    /// DPD 优先：周期到发 DPD request；无应答连续超时 → 永久回退 ping。
    #[test]
    fn probe_dpd_timeout_falls_back_to_ping() {
        let mut probe = ProbeState::new(probe_cfg(true, None));
        let t0 = Instant::now();
        let mut sent: Vec<Vec<u8>> = Vec::new();
        // DPD interval 5s。推进 3 个周期且无应答 → 回退 ping。
        let mut t = t0;
        for i in 0..(super::DPD_MAX_TIMEOUTS + 1) {
            t = t0 + Duration::from_secs(5 * u64::from(i + 1));
            probe.tick(t, &mut |f| sent.push(f));
        }
        assert_eq!(probe.kind, ProbeKind::Ping, "DPD 连续无应答 → 回退 ping");
        // 回退后下一个 ping 周期（180s）发 ping（DPD 不再发）。
        let before = sent.len();
        let t_ping = t + Duration::from_secs(180);
        probe.tick(t_ping, &mut |f| sent.push(f));
        assert_eq!(sent.len(), before + 1, "回退后发 ping");
    }

    /// DPD response 到达 → 计时 RTT（`on_dpd_response`）。
    #[test]
    fn probe_dpd_response_times_rtt() {
        let mut probe = ProbeState::new(probe_cfg(true, None));
        let t0 = Instant::now();
        let mut sent: Vec<Vec<u8>> = Vec::new();
        probe.tick(t0 + Duration::from_secs(5), &mut |f| sent.push(f));
        assert_eq!(sent.len(), 1, "DPD request 已发");
        assert!(probe.pending_dpd.is_some());
        let rtt = probe.on_dpd_response(t0 + Duration::from_secs(5) + Duration::from_millis(30));
        assert_eq!(rtt, Some(30), "DPD response 计时 30ms");
        assert_eq!(probe.dpd_timeouts, 0, "response 重置超时计数");
    }

    /// 手动刷新标记：文件内容（epoch 毫秒）新于上次 → 立即探测（无需等周期）。
    #[test]
    fn probe_marker_triggers_immediate_probe() {
        let dir = std::env::temp_dir();
        let marker = dir.join(format!("exv-latency-marker-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let cfg = probe_cfg(false, Some(marker.clone()));
        let mut probe = ProbeState::new(cfg);
        let t0 = Instant::now();
        let mut sent: Vec<Vec<u8>> = Vec::new();
        probe.tick(t0 + Duration::from_secs(1), &mut |f| sent.push(f));
        assert!(sent.is_empty(), "无标记不触发");

        std::fs::write(&marker, "1700000000000").expect("write marker");
        let t1 = t0 + Duration::from_secs(2); // 超过 MARKER_POLL_INTERVAL
        probe.tick(t1, &mut |f| sent.push(f));
        assert_eq!(sent.len(), 1, "新标记立即触发探测");

        // 同值标记不重复触发。
        let t2 = t0 + Duration::from_secs(3);
        probe.tick(t2, &mut |f| sent.push(f));
        assert_eq!(sent.len(), 1, "同值标记不重复触发");

        let _ = std::fs::remove_file(&marker);
    }
}
