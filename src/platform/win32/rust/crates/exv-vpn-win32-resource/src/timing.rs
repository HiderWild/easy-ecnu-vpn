// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! 特性门控连接耗时计时埋点（R0 计划 §3 行 R0 / 修订 9 [P2-10]：插桩进 win32-resource
//! 产品代码，逐 Win32 API 级归因）。
//!
//! - **默认关闭零开销**：所有入口在 `timing` feature 关闭时编译为空实现（调用点为
//!   无条件调用，但实体是空函数/ZST，LLVM 直接消除）——默认构建不改变任何产品语义、
//!   零额外执行（观察者效应最小化，计划 §5）。
//! - **只加计时、不改行为**：调用点只在返回/收尾处 `record`，绝不插入等待/轮询/重试。
//! - **跨进程 sink**：`record` 把一行追加写 `EXV_TIMING_FILE` 指定文件（缺省
//!   `%TEMP%\exv-timing-<pid>.log`）并 eprintln。helper/engine 是独立特权进程（无共享
//!   console），文件 sink 保证 host 与 helper 的分段耗时都能落盘、按行合并归因。
//!   行格式：`WALL_MS PID SELF_MS LABEL`（WALL_MS = Unix epoch 毫秒，供跨进程对齐；
//!   SELF_MS = 自本进程启动的单调毫秒；LABEL = 分段名，见各调用点注释）。
//!
//! 使用说明（一句话）：给 `exv-vpn-win32-resource` / `exv-vpn-win32-acceptance` 加
//! `--features timing` 重新构建并运行 acceptance 学校场景，分段耗时逐行追加写
//! `%TEMP%\exv-timing-*.log`（可用 `EXV_TIMING_FILE` 覆盖到单个合并文件），结束按
//! LABEL 汇总即得归因表。

#[cfg(feature = "timing")]
use std::io::Write;
#[cfg(feature = "timing")]
use std::path::PathBuf;
#[cfg(feature = "timing")]
use std::sync::OnceLock;
use std::time::Instant;

/// 计时 sink 的解析后路径（惰性一次；`EXV_TIMING_FILE` 覆盖，否则 `<temp>/exv-timing-<pid>.log`）。
#[cfg(feature = "timing")]
fn timing_file() -> PathBuf {
    if let Ok(p) = std::env::var("EXV_TIMING_FILE")
        && !p.is_empty()
    {
        return PathBuf::from(p);
    }
    std::env::temp_dir().join(format!("exv-timing-{}.log", std::process::id()))
}

/// 进程启动时刻（`SELF_MS` 基准；单调时钟）。
#[cfg(feature = "timing")]
fn process_start() -> Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    *START.get_or_init(Instant::now)
}

/// 追加写一条计时记录（只加计时不改行为；单次 `OpenOptions::append`，调用频率低，
/// 不在热路径——每分段一次）。
#[cfg(feature = "timing")]
pub fn record(label: &str, elapsed_ms: u64) {
    let wall_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let self_ms = u64::try_from(process_start().elapsed().as_millis()).unwrap_or(u64::MAX);
    let line = format!("{wall_ms} {} {self_ms} {label}\n", std::process::id());
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(timing_file())
        .and_then(|mut f| f.write_all(line.as_bytes()));
    let _ = elapsed_ms;
}

/// 空实现桩（feature 关闭：零开销）。
#[cfg(not(feature = "timing"))]
pub fn record(_label: &str, _elapsed_ms: u64) {}

/// 作用域计时 guard：`Drop` 时记录 elapsed（函数级 wrap 用）。feature 关闭时是
/// ZST，构造/析构均被优化消除——调用点可无条件使用。
#[must_use]
pub struct Timed {
    #[cfg(feature = "timing")]
    label: &'static str,
    #[cfg(feature = "timing")]
    start: Instant,
}

impl Timed {
    /// 开始计一段；`Drop` 时把 elapsed ms 写 sink（feature 关闭时为空 ZST）。
    #[must_use]
    pub fn new(label: &'static str) -> Self {
        #[cfg(feature = "timing")]
        {
            Self {
                label,
                start: Instant::now(),
            }
        }
        #[cfg(not(feature = "timing"))]
        {
            let _ = label;
            Self {}
        }
    }

    /// 手动收尾（提前记录后丢弃 guard；`drop` 不再重复记录）。
    #[cfg(feature = "timing")]
    pub fn finish(self) {
        let ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        record(self.label, ms);
    }
}

#[cfg(feature = "timing")]
impl Drop for Timed {
    fn drop(&mut self) {
        let ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        record(self.label, ms);
    }
}

/// 手动计时：`record_elapsed(label, start)` 记录自 `start` 起的分段耗时（跨多条语句 /
/// 条件等待用）。feature 关闭时空实现。
pub fn record_elapsed(label: &str, start: Instant) {
    #[cfg(feature = "timing")]
    {
        let ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        record(label, ms);
    }
    #[cfg(not(feature = "timing"))]
    {
        let _ = (label, start);
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
