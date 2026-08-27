// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! 引擎（host 侧）Wintun 数据面（DP-02/DP-03，C++-faithful）——从 `scenarios::school`
//! 提取的可复用模块（3b-i 纯提取重构，不引入新逻辑）。
//!
//! helper 完成特权初始化（`WintunAdapter::create` + 四族网络设置）后**空闲**；host 侧按
//! **create 名**（`SCHOOL_ADAPTER_NAME`，非 `adapter.alias()`——接口别名可能被 Windows
//! 规范化后不同）open adapter（`WintunAdapter::open` = `WintunOpenAdapter`，不特权；第二句柄
//! `AdapterOpen::Opened` / `owned=false`）并在该句柄上启动引擎自己的 session
//! （`WintunSession::start`，不特权；ring I/O 属引擎）——镜像 C++
//! `native_packet_device.cpp` `RealWintunPacketSession::start`（`open_adapter` +
//! `start_session`）。
//!
//! **drop 顺序（字段声明序；W17 SAFETY-ORDER）**：session 先 drop（`WintunEndSession`）
//! → 再 drop 打开的 adapter 句柄（非创建者 close 不删 adapter）→ 最后释放
//! `WintunLibrary`。adapter 移除仍由 helper 的 creator close 在 Stop 时负责——数据面
//! session 生命周期与 helper 解耦，但 adapter 清理属主仍是 helper（C++ Stop 语义）。
//!
//! **W17 SAFETY-ORDER（冻结）**：`EngineDataPlaneThreads::stop_and_join` / `Drop` 先 join
//! 两个数据面线程再放 session Arc 克隆——`WintunEndSession` 之前 worker 必已 join
//! （0.14.1 的 EndSession 销毁 session 对象，之后 receive 是 UAF）。
//!
//! **relay 记账（W23B）**：reader 线程 `admit_receive_packet`、writer 线程
//! `admit_send_frame`（admission 失败即不写 ring）。这是学校场景 host 侧数据面与
//! 新架构 `crate::engine_data_plane`（engine 特权进程，无 relay 记账）的关键差异。

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use exv_vpn_cstp::codec::{Codec, CstpFrame};
use exv_engine::packet_relay::AttachedPacketRelay;
use exv_vpn_win32_resource::wintun_adapter::{AdapterOpen, WintunAdapter};
use exv_vpn_win32_resource::wintun_api::WintunLibrary;
use exv_vpn_win32_resource::wintun_session::WintunSession;
use windows::Win32::Foundation::WAIT_FAILED;
use windows::Win32::System::Threading::WaitForSingleObject;

use crate::wintun_facts::WINTUN_PROBE_RING_CAPACITY;

/// 引擎（host 侧）Wintun 数据面（DP-02/DP-03）。
///
/// DP-03：session 用 `Arc<Mutex<WintunSession>>` 持有——reader/writer 数据面线程直连
/// session（`receive`/`send` 需 `&mut self`），线程经 `Arc` 共享；`stop_and_join` 在
/// `WintunEndSession` 之前 join 两个线程（W17 冻结顺序）。
pub struct EngineDataPlane {
    /// 引擎 session（在打开的 adapter 句柄上启动；最后一个 `Arc` drop 即
    /// `WintunEndSession`）。
    pub session: Arc<Mutex<WintunSession>>,
    /// 打开的 adapter 句柄（`AdapterOpen::Opened`，`owned=false`；drop 即 close 句柄，
    /// 非创建者 close 不删 adapter）。
    #[allow(dead_code)]
    pub adapter: WintunAdapter,
    /// 保持 wintun.dll 加载（exports 副本已内嵌于 session/adapter；此处仅引用计数配对）。
    pub _lib: WintunLibrary,
}

/// 引擎数据面线程句柄（DP-03）：ring→CSTP reader + CSTP→ring writer，直连引擎 session。
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
    /// ring 收到字节计数（host 数据面计数器；证据读取，不再来自 helper）。
    ring_received_bytes: Arc<AtomicU64>,
    /// ring 发送字节计数（host 数据面计数器；证据读取，不再来自 helper）。
    ring_sent_bytes: Arc<AtomicU64>,
}

/// host 侧 packet relay 状态（W23B 组合 + 单调 sequence 记账）。
pub struct SchoolRelayState {
    /// W23B 组合 relay（admission 记账；writer 侧 admission 失败即不写 ring）。
    pub relay: AttachedPacketRelay,
    /// 单调 sequence 记账（reader/writer 共享）。
    pub next_seq: u64,
}

/// 启动引擎（host 侧）数据面：按 create 名 open adapter + 启动引擎自己的 session。
///
/// DP-02（C++-faithful）：open-by-name + start_session **不特权**（C++ 事实），但
/// 依赖 helper（DP-01）已完成特权初始化（adapter 存在）。断言 `AdapterOpen::Opened`
/// （`owned=false`）——杀 'host 用 create 而非 open（重复创建/需特权）' 与
/// 'host 用 alias() 而非 create 名打开' mutant。成功后由调用方把 `wintun_session_started`
/// 置真（引擎侧 session，不再来自 helper apply 回复的 `session_started=false`）。
///
/// # Errors
///
/// wintun.dll 加载失败 / open 失败（adapter 不存在 → `ERROR_NOT_FOUND` 1168，typed
/// error 而非 panic）/ session 启动失败（容量非 2 的幂 → `WintunSession::start` 已在
/// FFI 前校验拒绝）→ `&'static str` typed 错误（绝不 panic）。
pub fn start_engine_data_plane(dll: &Path, adapter_name: &str) -> Result<EngineDataPlane, &'static str> {
    let lib = WintunLibrary::load(dll).map_err(|_| "engine-wintun-load")?;
    let (adapter, opened) =
        WintunAdapter::open(&lib, adapter_name).map_err(|_| "engine-adapter-open-by-name")?;
    if !matches!(opened, AdapterOpen::Opened) {
        // 引擎必须 open-by-name（第二句柄 `Opened`）；拿到 `Created` = 重复创建 mutant。
        return Err("engine-adapter-open-not-opened");
    }
    let session = WintunSession::start(&lib, &adapter, WINTUN_PROBE_RING_CAPACITY)
        .map_err(|_| "engine-session-start")?;
    Ok(EngineDataPlane {
        // DP-03：session 以 `Arc<Mutex<>>` 共享给 reader/writer 数据面线程。
        session: Arc::new(Mutex::new(session)),
        adapter,
        _lib: lib,
    })
}

impl EngineDataPlane {
    /// DP-03：spawn 引擎数据面线程（ring→CSTP reader + CSTP→ring writer），直连引擎
    /// session（不再经 packet pipe——pipe 数据路径在 DP-04 移除）。
    ///
    /// - **reader 线程**：`read_wait_event`（WaitForSingleObject 50ms，可中断 join）→
    ///   `session.receive()` → `is_ipv4_packet` → relay 记账 → `Codec::encode(
    ///   CstpFrame::Data)` → 引擎 `write_channel`（TLS）→ 学校。
    /// - **writer 线程**：引擎 `read_channel`（TLS 解码帧，IP 包）→ relay 记账 →
    ///   `session.send()` → ring。
    ///
    /// W17 SAFETY-ORDER：返回的 [`EngineDataPlaneThreads`] 在 `stop_and_join`/`Drop`
    /// 时先 join 两个线程，再放掉持有的 session Arc 克隆——`WintunEndSession` 之前
    /// worker 必已 join（0.14.1 之后 receive 是 UAF，冻结顺序）。
    pub fn spawn_data_plane(
        &self,
        write_channel: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        read_channel: &Arc<Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>>,
        relay: Arc<Mutex<SchoolRelayState>>,
    ) -> EngineDataPlaneThreads {
        let reader_stop = Arc::new(AtomicBool::new(false));
        let writer_stop = Arc::new(AtomicBool::new(false));
        let ring_received_bytes = Arc::new(AtomicU64::new(0));
        let ring_sent_bytes = Arc::new(AtomicU64::new(0));

        // ---- reader 线程：ring → relay → STF → write_channel（TLS）。 ----
        let reader_relay = Arc::clone(&relay);
        let reader_session = Arc::clone(&self.session);
        let reader_tx = write_channel.clone();
        let reader_stop_flag = Arc::clone(&reader_stop);
        let ring_recv_counter = Arc::clone(&ring_received_bytes);
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
                    ring_recv_counter.fetch_add(pkt.len() as u64, Ordering::SeqCst);
                    let mut guard = reader_relay.lock().expect("relay 锁");
                    if let Ok(seq) = guard.relay.admit_receive_packet(&pkt) {
                        guard.next_seq = seq.saturating_add(1);
                    }
                    drop(guard);
                    if is_ipv4_packet(&pkt) {
                        let Ok(frame) = Codec::new().encode(&CstpFrame::Data(pkt)) else {
                            continue;
                        };
                        let _ = reader_tx.send(frame);
                    }
                }
            }
        });

        // ---- writer 线程：read_channel（TLS）→ relay → session.send（ring）。 ----
        let writer_relay = Arc::clone(&relay);
        let writer_session = Arc::clone(&self.session);
        let tls_reader = Arc::clone(read_channel);
        let writer_stop_flag = Arc::clone(&writer_stop);
        let ring_sent_counter = Arc::clone(&ring_sent_bytes);
        let writer = std::thread::spawn(move || {
            // 引擎 data 通道是 tokio unbounded receiver：轮询 `try_recv`（空则短睡，
            // 保持 stop 标志的可达性），收到解码后的 IP 包 → relay 记账 → session.send。
            while !writer_stop_flag.load(Ordering::SeqCst) {
                let pkt = match tls_reader.lock().expect("tls reader 锁").try_recv() {
                    Ok(pkt) => Some(pkt),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                        std::thread::sleep(Duration::from_millis(1));
                        None
                    }
                    Err(_) => break,
                };
                if let Some(pkt) = pkt {
                    let mut guard = writer_relay.lock().expect("relay 锁");
                    let next_seq = guard.next_seq;
                    let admitted = guard.relay.admit_send_frame(1, pkt.len(), next_seq).is_ok();
                    if admitted {
                        guard.next_seq = guard.next_seq.saturating_add(1);
                    }
                    drop(guard);
                    if admitted {
                        let mut sess = writer_session.lock().expect("session 锁");
                        if sess.send(&pkt).is_ok() {
                            ring_sent_counter.fetch_add(pkt.len() as u64, Ordering::SeqCst);
                        }
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

impl EngineDataPlaneThreads {
    /// 置位 stop → join 两个线程（W17 SAFETY-ORDER：先 join 再放 session，绝不把
    /// 未 join 的 reader 留在 `WintunEndSession` 之后）。返回
    /// `(ring_received_bytes, ring_sent_bytes)`——host 数据面计数器，证据读取。
    ///
    /// 幂等：重复调用 / `Drop` 兜底安全（线程句柄 `take()` 后为空）。
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
// 单元测试：纯函数 `is_ipv4_packet` + 空线程句柄的幂等 stop/drop（无需真实 Wintun
// adapter；真实数据面线程的 W17 顺序由 school 的跨子网 ring 测试覆盖——保留在原测试
// 位置）。
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

    /// 空 `EngineDataPlaneThreads` 的 `stop_and_join` 与 `Drop` 是幂等 no-op（不 panic）。
    #[test]
    fn thread_handle_stop_and_drop_are_idempotent() {
        let mut threads = EngineDataPlaneThreads {
            reader_stop: Arc::new(AtomicBool::new(false)),
            writer_stop: Arc::new(AtomicBool::new(false)),
            reader: None,
            writer: None,
            ring_received_bytes: Arc::new(AtomicU64::new(0)),
            ring_sent_bytes: Arc::new(AtomicU64::new(0)),
        };
        assert_eq!(threads.stop_and_join(), (0, 0));
        assert_eq!(threads.stop_and_join(), (0, 0), "幂等");
        drop(threads);
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
