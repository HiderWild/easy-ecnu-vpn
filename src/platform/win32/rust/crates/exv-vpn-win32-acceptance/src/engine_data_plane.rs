// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! engine 特权进程内的 Wintun 数据面（阶段 3b）：ring→CSTP→TLS reader + TLS→CSTP→ring
//! writer，**全在 engine 进程内零跨进程**。
//!
//! 旧架构（school.rs，DP-02/DP-03）：helper 进程建 adapter（特权），host 侧按
//! create 名 open-by-name + 引擎 session（非特权假设），数据面线程在 host 侧。
//! 新架构（阶段 3b）：engine 就是特权进程——engine 自己 `WintunAdapter::create` +
//! 自己 `WintunSession::start`，数据面 reader/writer 线程全在 engine 内，无 packet
//! pipe、无跨进程 ring 传递。本模块是这套 engine 数据面的可复用组合：
//!
//! - [`EngineDataPlane::start`]：在**已创建**的 adapter 上启动 engine session
//!   （adapter/lib 由调用方持有——engine 内 `helper_apply` 创建 adapter 并持有到
//!   Stop；本结构只持有 `Arc<Mutex<WintunSession>>` 供 reader/writer 线程共享）。
//! - [`EngineDataPlane::spawn_data_plane`]：spawn 两条数据面线程——
//!   **reader**（ring → `session.receive()` → `Codec::encode(CstpFrame::Data)` →
//!   CSTP `write_channel` → TLS → 学校）与 **writer**（CSTP `read_channel`（TLS
//!   解码帧，IP 包）→ `session.send()` → ring）。
//! - [`EngineDataPlaneThreads::stop_and_join`]：置位 stop → join 两线程 → 返回
//!   `(ring_received_bytes, ring_sent_bytes)`（host/engine 数据面计数器）。
//!
//! **W17 SAFETY-ORDER（冻结）**：`EngineDataPlaneThreads` 在 `stop_and_join`/`Drop`
//! 时**先 join 两个线程，再放掉线程持有的 session Arc 克隆**——`WintunEndSession`
//! 之前 worker 必已 join（0.14.1 的 EndSession 销毁 session 对象，之后 receive 是
//! UAF）。线程的 read-wait event 是 session 管理的（调用方不 CloseHandle），50ms
//! 等待保持 stop 标志可及时观察（可中断 join）。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use exv_vpn_cstp::codec::{Codec, CstpFrame};
use exv_vpn_win32_resource::wintun_adapter::WintunAdapter;
use exv_vpn_win32_resource::wintun_api::WintunLibrary;
use exv_vpn_win32_resource::wintun_session::WintunSession;
use windows::Win32::Foundation::WAIT_FAILED;
use windows::Win32::System::Threading::WaitForSingleObject;

/// engine 数据面（DP-03 结构）：持有共享的 Wintun session 供 reader/writer 数据面
/// 线程直连。
///
/// 本结构只持有 `Arc<Mutex<WintunSession>>`——**不持有 adapter / WintunLibrary**。
/// 调用方（engine 的 `RealNativeOps`，经 `helper_apply`）持有创建者 adapter 与
/// WintunLibrary 并保证其存活覆盖本结构：teardown 顺序是 `stop_and_join` →
/// drop `EngineDataPlane`（`WintunEndSession`）→ `helper_stop`（adapter creator
/// close 移除 adapter、释放 lib）。session 的 `Drop` 用内嵌的 exports 副本调用
/// `WintunEndSession`，不依赖 lib 存活；但 lib 保持 DLL 加载，lib 必须先于
/// session 存活（调用方 teardown 顺序保证）。
pub struct EngineDataPlane {
    /// engine session（在已创建的 adapter 上启动；最后一个 `Arc` drop 即
    /// `WintunEndSession`）。
    pub session: Arc<Mutex<WintunSession>>,
}

impl EngineDataPlane {
    /// 在**已创建**的 adapter 上启动 engine session（engine 特权进程自己建
    /// adapter——`helper_apply` 的 `WintunAdapter::create` 已完成；本调用直接在该
    /// 创建句柄上 `WintunSession::start`，**不再 open-by-name**）。
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

    /// 启动引擎数据面线程（ring→CSTP reader + CSTP→ring writer），直连引擎 session
    /// （不再经 packet pipe——pipe 数据路径在 DP-04 移除）。
    ///
    /// - **reader 线程**：`read_wait_event`（WaitForSingleObject 50ms，可中断 join）→
    ///   `session.receive()` → `is_ipv4_packet` → ring 字节计数 → `Codec::encode(
    ///   CstpFrame::Data)` → engine `write_channel`（TLS）→ 学校。
    /// - **writer 线程**：engine `read_channel`（TLS 解码帧，IP 包）→ ring 字节计数 →
    ///   `session.send()` → ring。
    ///
    /// W17 SAFETY-ORDER：返回的 [`EngineDataPlaneThreads`] 在 `stop_and_join`/`Drop`
    /// 时先 join 两个线程，再放掉持有的 session Arc 克隆——`WintunEndSession` 之前
    /// worker 必已 join。
    pub fn spawn_data_plane(
        &self,
        write_channel: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
        read_channel: &Arc<Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>>,
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
                    if is_ipv4_packet(&pkt) {
                        let Ok(frame) = Codec::new().encode(&CstpFrame::Data(pkt)) else {
                            continue;
                        };
                        let _ = reader_tx.send(frame);
                    }
                }
            }
        });

        // ---- writer 线程：read_channel（TLS）→ ring 计数 → session.send（ring）。 ----
        let writer_session = Arc::clone(&self.session);
        let tls_reader = Arc::clone(read_channel);
        let writer_stop_flag = Arc::clone(&writer_stop);
        let ring_sent_counter = Arc::clone(&ring_sent_bytes);
        let writer = std::thread::spawn(move || {
            // 引擎 data 通道是 tokio unbounded receiver：轮询 `try_recv`（空则短睡，
            // 保持 stop 标志的可达性），收到解码后的 IP 包 → session.send。
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
                    let mut sess = writer_session.lock().expect("session 锁");
                    if sess.send(&pkt).is_ok() {
                        ring_sent_counter.fetch_add(pkt.len() as u64, Ordering::SeqCst);
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
    pub(crate) reader_stop: Arc<AtomicBool>,
    /// writer 线程 stop 标志。
    pub(crate) writer_stop: Arc<AtomicBool>,
    /// reader 线程句柄（ring→CSTP→TLS）。
    reader: Option<std::thread::JoinHandle<()>>,
    /// writer 线程句柄（TLS→CSTP→ring）。
    writer: Option<std::thread::JoinHandle<()>>,
    /// ring 收到字节计数（engine 数据面计数器；证据读取，不再来自 helper）。
    pub(crate) ring_received_bytes: Arc<AtomicU64>,
    /// ring 发送字节计数（engine 数据面计数器；证据读取，不再来自 helper）。
    pub(crate) ring_sent_bytes: Arc<AtomicU64>,
}

impl EngineDataPlaneThreads {
    /// 置位 stop → join 两个线程（W17 SAFETY-ORDER：先 join 再放 session，绝不把
    /// 未 join 的 reader 留在 `WintunEndSession` 之后）。返回
    /// `(ring_received_bytes, ring_sent_bytes)`——engine 数据面计数器，证据读取。
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
// 单元测试：纯函数 `is_ipv4_packet` + 线程句柄计数器访问器（无需真实 Wintun
// adapter；真实数据面线程的 W17 顺序由 engine 集成路径与 school scenario 覆盖）。
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
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
