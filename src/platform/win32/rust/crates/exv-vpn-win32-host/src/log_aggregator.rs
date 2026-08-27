// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core 日志聚合服务（P2-a）：磁盘文件为唯一真相源。
//!
//! 合并 engine `StreamLogs` 事件与 core 自身事件为**单一条目流**落盘，供未来 UI
//! （P4）与 `logs.list`/`logs.clear` 契约（P2-c）拉取。
//!
//! ## 落盘格式
//!
//! 每个条目一行 JSON（JSONL）：`aggregated.jsonl`。磁盘行 = 真相源；追加写（写前
//! seek 到 EOF）、截断清空，不移动路径（对齐 legacy `logs.clear` 语义：truncate
//! 而非删除）。
//! 行内不存 `seq`——`seq` 就是 1 基的行号，由读取时按行位置派生。这保证重启后
//! 游标只凭文件即可重建（数行即得 `last_seq`），无需任何进程内持久化。
//!
//! ```text
//! {"timestamp_ms":1723,"received_ms":1723,"level":"info","source":"engine",
//!  "component":"engine","code":"","message":"...","fields":{"k":"v"}}
//! ```
//!
//! 条目行内不含 `seq`；`seq`（1 基行号）只存在于读取/API 返回中。`source` 标记
//! 条目来源：`engine`（经 `HelperControl.StreamLogs` 推送）或 `core`（core 自身）。
//!
//! ## 增量游标（P2-c 依赖）
//!
//! - [`LogAggregator::list(after_seq, limit)`]：拉取 `seq > after_seq` 的至多 `limit`
//!   条，返回 [`LogPage`]（`entries` + `next_seq`，`next_seq` = 最后返回条目的
//!   `seq + 1`；无更多时 = `last_seq() + 1`）。
//! - [`LogAggregator::last_seq()`]：当前文件条目数（= 已分配的最大 `seq`）。
//! - [`LogAggregator::clear()`]：truncate 文件并把游标重置为 0（日志从 `seq = 1`
//!   重新开始）。
//!
//! ## 线程模型
//!
//! 单一 `std::sync::Mutex` 守卫写句柄与 `last_seq`；`list` 在锁内重读文件，因此
//! 追加、清空、读取串行一致。日志量级（控制面事件）小，单锁足够。
//!
//! ## 安全
//!
//! 字段只承载结构化诊断元数据，不落凭据/能力/明文（对齐 proto `LogEvent` 安全
//! 注解）。本模块**不**对传入事件做 redact——上游（engine proto、core 自身）已
//! 保证不入敏感字段。

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use exv_vpn_wire::generated::LogEvent;

/// 默认聚合日志文件名（位于 `config_dir()/logs/` 下）。
pub const AGGREGATED_LOG_FILE: &str = "aggregated.jsonl";
/// 日志子目录名（位于 config 目录下）。
pub const LOGS_SUBDIR: &str = "logs";

/// 日志条目来源（落盘 `source` 字段标记）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogSource {
    /// 经 `HelperControl.StreamLogs` 从 engine 推送的日志。
    Engine,
    /// core 自身产生的日志。
    Core,
}

impl LogSource {
    /// 磁盘 `source` 字段的稳定字面量（`engine` | `core`）。
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Engine => "engine",
            Self::Core => "core",
        }
    }
}

/// 聚合日志服务错误。
#[derive(Debug)]
pub enum LogAggError {
    /// 文件系统错误（打开/追加/截断/读取）。
    Io(std::io::Error),
    /// 单行 JSON 序列化/反序列化失败。
    Json(serde_json::Error),
}

impl fmt::Display for LogAggError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "log aggregator io: {e}"),
            Self::Json(e) => write!(f, "log aggregator json: {e}"),
        }
    }
}

impl std::error::Error for LogAggError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(_) => None,
        }
    }
}

impl From<std::io::Error> for LogAggError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for LogAggError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

/// 磁盘条目（JSONL 行内结构）。**不含** `seq`——`seq` 由行位置派生（1 基行号）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskLogEntry {
    /// 事件产生时刻（epoch 毫秒 UTC；engine 事件可为 0 = 未知）。
    pub timestamp_ms: i64,
    /// core 接收/落盘时刻（epoch 毫秒 UTC）。
    pub received_ms: i64,
    /// `info` | `warn` | `error`。
    pub level: String,
    /// `engine` | `core`。
    pub source: String,
    /// 组件（如 `engine`/`packet`/`protocol`/`platform`）。
    pub component: String,
    /// 稳定诊断码，无则空串。
    pub code: String,
    /// 人类可读消息（不含诊断栈）。
    pub message: String,
    /// 结构化键值元数据（无凭据）。
    pub fields: BTreeMap<String, String>,
}

/// 带 `seq` 的日志条目（`list` 返回形态；`seq` = 1 基行号）。
///
/// `serde` 派生供 P2-c `logs.list` 契约返回 JSON（P4 Tauri 直接消费）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// 单调行号（磁盘第 `seq` 行；重启后由文件重建，稳定）。
    pub seq: u64,
    /// 事件产生时刻（epoch 毫秒 UTC；0 = 未知）。
    pub timestamp_ms: i64,
    /// core 接收/落盘时刻（epoch 毫秒 UTC）。
    pub received_ms: i64,
    /// `info` | `warn` | `error`。
    pub level: String,
    /// `engine` | `core`。
    pub source: String,
    /// 组件。
    pub component: String,
    /// 稳定诊断码，无则空串。
    pub code: String,
    /// 人类可读消息。
    pub message: String,
    /// 结构化键值元数据。
    pub fields: BTreeMap<String, String>,
}

/// 增量拉取的返回页（P2-c `logs.list` 的语义底座）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogPage {
    /// `seq > after_seq` 的条目（至多 `limit` 条）。
    pub entries: Vec<LogEntry>,
    /// 下一轮 `list` 的游标：最后返回条目的 `seq + 1`；无更多时 = `last_seq() + 1`。
    pub next_seq: u64,
}

/// `ingest_engine_stream` 的结束状态（P3 断线重连 / P2-b raw-dump 兜底判据）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestOutcome {
    /// engine 流干净结束（EOF）。
    EndOfStream,
    /// 流中途收到 gRPC 错误（transport 断裂信号）。
    StreamError(String),
}

/// 聚合日志服务：磁盘文件为唯一真相源。
pub struct LogAggregator {
    /// 聚合日志文件路径（`<config_dir>/logs/aggregated.jsonl`）。
    path: PathBuf,
    inner: Mutex<AggregatorInner>,
}

struct AggregatorInner {
    /// 写句柄（write 访问以支持 `set_len`；追加前 seek 到 EOF；`clear` truncate
    /// 同一句柄）。
    file: File,
    /// 已写入行数 = 已分配的最大 `seq`（重启后由 `rebuild_cursor` 从文件重建）。
    last_seq: u64,
}

/// 默认聚合日志路径：`config_dir()/logs/aggregated.jsonl`。
///
/// `EXV_CONFIG_DIR` 或 `%USERPROFILE%\.exv` 之上的 `logs/` 子目录，对齐仓库既有
/// config 目录约定（`exv-vpn-win32-config::config_dir`）。
#[must_use]
pub fn aggregated_log_path() -> PathBuf {
    exv_vpn_win32_config::config_dir()
        .join(LOGS_SUBDIR)
        .join(AGGREGATED_LOG_FILE)
}

impl LogAggregator {
    /// 在 `path` 打开（或创建）聚合日志文件，并从文件重建游标（数行 → `last_seq`）。
    ///
    /// 自动创建父目录。追加写；已存在的文件保留历史行（唯一真相源连续）。
    ///
    /// # Errors
    /// 父目录创建或文件打开失败 → `LogAggError::Io`。
    pub fn open(path: &Path) -> Result<Self, LogAggError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // 用 write 而非 append 打开：append 句柄在 Windows 上是 FILE_APPEND_DATA
        // 访问，`set_len(0)`（clear）会拒绝访问；write 句柄同时支持追加写与截断。
        // 追加前显式 seek 到 EOF（clear 截断后句柄位置可能残留在旧 EOF）。
        // `.truncate(false)`：既有历史行必须保留（磁盘 = 唯一真相源，跨重启连续）。
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(path)?;
        let last_seq = rebuild_cursor(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            inner: Mutex::new(AggregatorInner { file, last_seq }),
        })
    }

    /// 在当前 config 目录的默认日志路径打开聚合服务（`aggregated_log_path()`）。
    ///
    /// # Errors
    /// 同 [`LogAggregator::open`]。
    pub fn open_default() -> Result<Self, LogAggError> {
        Self::open(&aggregated_log_path())
    }

    /// 当前聚合日志文件路径。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 追加一条 engine 事件（`HelperControl.StreamLogs` 推送），`source = "engine"`。
    ///
    /// 分配的 `seq` = `last_seq() + 1`。写失败（磁盘满等）不推进游标，返回错误，
    /// 调用方（ingest 任务）记日志继续。engine 事件 `timestamp_ms` 可为 0（未知），
    /// `received_ms` 恒为 core 落盘时刻。
    ///
    /// # Errors
    /// 追加写失败或序列化失败 → `LogAggError`（游标不回退）。
    pub fn append_engine(&self, event: &LogEvent) -> Result<LogEntry, LogAggError> {
        // proto map<string,string> 生成 `HashMap`；磁盘/API 统一用 `BTreeMap` 保证
        // JSON 键序确定（可复现落盘、便于 diff）。转换在聚合边界一次完成。
        let fields: BTreeMap<String, String> = event
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let disk = DiskLogEntry {
            timestamp_ms: event.timestamp_ms,
            received_ms: now_ms(),
            level: event.level.clone(),
            source: LogSource::Engine.as_str().to_string(),
            component: event.component.clone(),
            code: event.code.clone(),
            message: event.message.clone(),
            fields,
        };
        self.append(disk)
    }

    /// 追加一条 core 自身事件，`source = "core"`；`timestamp_ms`/`received_ms` 均为
    /// 当前时刻。
    ///
    /// # Errors
    /// 同 [`LogAggregator::append_engine`]。
    pub fn append_core(
        &self,
        level: &str,
        component: &str,
        code: &str,
        message: &str,
        fields: &BTreeMap<String, String>,
    ) -> Result<LogEntry, LogAggError> {
        let now = now_ms();
        let disk = DiskLogEntry {
            timestamp_ms: now,
            received_ms: now,
            level: level.to_string(),
            source: LogSource::Core.as_str().to_string(),
            component: component.to_string(),
            code: code.to_string(),
            message: message.to_string(),
            fields: fields.clone(),
        };
        self.append(disk)
    }

    /// 把一条磁盘条目追加为一行并推进游标。
    ///
    /// 写前 seek 到 EOF：write 句柄（非 append）在 `clear` 截断后位置可能残留在旧
    /// EOF，必须显式定位到文件尾再写，避免产生空洞。
    fn append(&self, disk: DiskLogEntry) -> Result<LogEntry, LogAggError> {
        let line = serde_json::to_string(&disk)?;
        let mut inner = self.inner.lock().expect("log aggregator lock");
        inner.file.seek(std::io::SeekFrom::End(0))?;
        writeln!(inner.file, "{line}")?;
        inner.file.flush()?;
        inner.last_seq += 1;
        Ok(LogEntry {
            seq: inner.last_seq,
            timestamp_ms: disk.timestamp_ms,
            received_ms: disk.received_ms,
            level: disk.level,
            source: disk.source,
            component: disk.component,
            code: disk.code,
            message: disk.message,
            fields: disk.fields,
        })
    }

    /// 已分配的最大 `seq`（= 磁盘行数）。重启后由文件重建，仅凭文件即可恢复。
    ///
    /// # Panics
    /// 内部互斥锁中毒（另一线程持锁时 panic）→ panic。
    #[must_use]
    pub fn last_seq(&self) -> u64 {
        self.inner.lock().expect("log aggregator lock").last_seq
    }

    /// 增量拉取：返回 `seq > after_seq` 的至多 `limit` 条（P2-c `logs.list` 底座）。
    ///
    /// 在锁内重读磁盘（文件即真相），按行位置派生 `seq`；`limit == 0` 视为无限
    /// （返回全部剩余）。坏行（崩溃残留）跳过但占用 `seq` 槽，游标保持对齐。
    ///
    /// # Errors
    /// 文件不可读 → `LogAggError::Io`。
    ///
    /// # Panics
    /// 内部互斥锁中毒（另一线程持锁时 panic）→ panic。
    pub fn list(&self, after_seq: u64, limit: usize) -> Result<LogPage, LogAggError> {
        let inner = self.inner.lock().expect("log aggregator lock");
        let reader = BufReader::new(File::open(&self.path)?);
        let mut entries = Vec::new();
        for (idx, line) in reader.lines().enumerate() {
            let seq = u64::try_from(idx + 1).unwrap_or(u64::MAX);
            if seq <= after_seq {
                continue;
            }
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            // 坏行（崩溃残留）跳过但占用 seq 槽，游标不破。
            if let Ok(disk) = serde_json::from_str::<DiskLogEntry>(&line) {
                if limit != 0 && entries.len() >= limit {
                    // 已取满；停止读取（后续条目留待下一轮）。
                    break;
                }
                entries.push(LogEntry {
                    seq,
                    timestamp_ms: disk.timestamp_ms,
                    received_ms: disk.received_ms,
                    level: disk.level,
                    source: disk.source,
                    component: disk.component,
                    code: disk.code,
                    message: disk.message,
                    fields: disk.fields,
                });
            }
        }
        // `next_seq` = 最后返回条目的 `seq + 1`；空页 = `last_seq() + 1`（跳过后继
        // 已消费的坏行槽，客户端不会原地空转）。
        let next_seq = entries
            .last()
            .map_or_else(|| inner.last_seq + 1, |e| e.seq + 1);
        Ok(LogPage { entries, next_seq })
    }

    /// 清空聚合日志（truncate 同一文件，游标重置为 0；日志从 `seq = 1` 重新开始）。
    ///
    /// 对齐 legacy `logs.clear` 语义：截断而非删除路径（保留文件身份，含打开句柄）。
    /// 调用方（P2-c `logs.clear`）应告知客户端重置游标。
    ///
    /// # Errors
    /// 截断失败 → `LogAggError::Io`。
    ///
    /// # Panics
    /// 内部互斥锁中毒（另一线程持锁时 panic）→ panic。
    pub fn clear(&self) -> Result<(), LogAggError> {
        let mut inner = self.inner.lock().expect("log aggregator lock");
        inner.file.set_len(0)?;
        // 截断后句柄位置残留在旧 EOF；复位到 0 使后续 append 的 seek-to-end 落到
        // 文件头（避免空洞）。
        inner.file.seek(std::io::SeekFrom::Start(0))?;
        inner.file.flush()?;
        inner.last_seq = 0;
        Ok(())
    }
}

/// 从文件当前内容重建游标：`last_seq` = 非空行数。读取文件全文按行计数，
/// 与 `list` 的 seq 派生（1 基行号）一致。
fn rebuild_cursor(path: &Path) -> Result<u64, LogAggError> {
    let reader = BufReader::new(File::open(path)?);
    let mut lines = 0u64;
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            lines += 1;
        }
    }
    Ok(lines)
}

/// 当前 epoch 毫秒（UTC）。
fn now_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// 消费 engine `StreamLogs` 推送流，逐条落盘到聚合服务（P2-b/P3/R3 接线点）。
///
/// 流干净结束 → [`IngestOutcome::EndOfStream`]；中途 gRPC 错误（transport 断裂）
/// → [`IngestOutcome::StreamError`] 并停止（P3 据此重连 / P2-b raw-dump 兜底）。
/// 单条落盘失败只记录（`tracing::warn!`）不中断流——日志推送不能拖垮聚合。
/// **纯单向输出**（D3 铁律 / R3）：本函数只写聚合文件，绝不读回、绝不驱动任何
/// 状态——日志是纯消费端数据。
///
/// ## 与 engine 内部 tick 的关系（P2-b 协调决定）
///
/// engine 每个事件有内部单调 tick，但 wire `LogEvent` **不携带 tick 字段**（proto
/// 冻结），core 无法从事件读到 engine tick。因此本模块的 `after_seq` 游标是
/// **core 自有的、文件派生的**（`seq` = 聚合文件行号），与 engine tick 完全独立；
/// `logs.list`/`logs.clear`（P2-c）只消费 core 聚合文件，不需要 tick 换算。
///
/// 断线重连补拉：调用方以 `client.stream_logs(resume_tick)` 打开流时自选 `resume_tick`
/// ——本模块不感知。当前契约建议 `resume_tick = 0`（从当前流位置开始、不补拉），
/// 断线缺口由 engine raw 文件（`engine-raw-<pid>.log`，P2-b）离线对账（O4：raw
/// 仅离线调试用途）。若未来需要精确补拉，须给 `LogEvent` 补 `tick` 字段（proto
/// 变更，P2-c 契约闭合时由协调者评估）。
pub async fn ingest_engine_stream<S>(
    stream: S,
    aggregator: std::sync::Arc<LogAggregator>,
) -> IngestOutcome
where
    S: tokio_stream::Stream<Item = Result<LogEvent, tonic::Status>>,
{
    use tokio_stream::StreamExt;
    // `pin!` 让任意 `Stream`（含 `Pin<Box<dyn Stream>>` 这类非 `Unpin` 盒）可用
    // `StreamExt::next` 消费——调用方不必保证 `S: Unpin`。
    let mut stream = std::pin::pin!(stream);
    loop {
        match stream.next().await {
            Some(Ok(event)) => {
                if let Err(e) = aggregator.append_engine(&event) {
                    tracing::warn!(error = %e, "aggregate engine log failed");
                }
            }
            Some(Err(status)) => return IngestOutcome::StreamError(status.to_string()),
            None => return IngestOutcome::EndOfStream,
        }
    }
}

// ---------------------------------------------------------------------------
// 单元测试：事件落盘、source 标记、after_seq 增量、重启游标重建、clear 语义。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 每个测试独立的临时聚合日志路径（按进程 pid + 用例名隔离，避免并发冲突）。
    fn temp_log_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "exv-log-agg-{tag}-{}.jsonl",
            std::process::id()
        ))
    }

    fn engine_event(level: &str, code: &str, message: &str, timestamp_ms: i64) -> LogEvent {
        LogEvent {
            level: level.to_string(),
            component: "engine".to_string(),
            code: code.to_string(),
            message: message.to_string(),
            // proto map 生成 `HashMap`（与 `append_engine` 的 BTreeMap 转换边界对齐）。
            fields: std::collections::HashMap::from([(
                "pid".to_string(),
                "42".to_string(),
            )]),
            timestamp_ms,
        }
    }

    /// 事件落盘：append 后文件存在且每行一条 JSON，含全部字段。
    #[test]
    fn appends_persist_full_fields_to_disk() {
        let path = temp_log_path("disk");
        let agg = LogAggregator::open(&path).expect("open");
        let entry = agg
            .append_engine(&engine_event("info", "WINTUN_UP", "tunnel up", 1_700_000_000_000))
            .expect("append");

        assert_eq!(entry.seq, 1);
        assert_eq!(entry.source, "engine");
        assert_eq!(entry.level, "info");
        assert_eq!(entry.code, "WINTUN_UP");
        assert_eq!(entry.message, "tunnel up");
        assert_eq!(entry.fields.get("pid").map(String::as_str), Some("42"));

        let raw = std::fs::read_to_string(&path).expect("read file");
        let lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 1, "每事件一行 JSONL");
        assert!(lines[0].contains("\"source\":\"engine\""));
        assert!(lines[0].contains("\"code\":\"WINTUN_UP\""));
        assert!(lines[0].contains("\"timestamp_ms\":1700000000000"));
        assert!(!lines[0].contains("\"seq\""), "行内不存 seq（真相=行号）");
    }

    /// source 标记：engine 与 core 事件必须带上不同 source。
    #[test]
    fn source_marker_distinguishes_engine_and_core() {
        let path = temp_log_path("src");
        let agg = LogAggregator::open(&path).expect("open");

        agg.append_engine(&engine_event("warn", "RTT", "high rtt", 0))
            .expect("engine");
        agg.append_core("error", "platform", "E_GATE", "gate refused", &BTreeMap::new())
            .expect("core");

        let page = agg.list(0, 0).expect("list");
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].source, "engine");
        assert_eq!(page.entries[1].source, "core");
        assert_eq!(page.entries[0].seq, 1);
        assert_eq!(page.entries[1].seq, 2);
    }

    /// `after_seq` 增量：`limit` 分页、`next_seq` 正确、无更多时指向 `last_seq + 1`。
    #[test]
    fn incremental_cursor_after_seq_is_correct() {
        let path = temp_log_path("incr");
        let agg = LogAggregator::open(&path).expect("open");
        for i in 1..=5 {
            agg.append_engine(&engine_event("info", "", &format!("e{i}"), i))
                .expect("append");
        }
        assert_eq!(agg.last_seq(), 5);

        // 取 2 条：seq 1,2；next_seq = 3。
        let p1 = agg.list(0, 2).expect("list");
        assert_eq!(p1.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(p1.next_seq, 3);

        // 从 2 继续取 2 条：seq 3,4；next_seq = 5。
        let p2 = agg.list(2, 2).expect("list");
        assert_eq!(p2.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [3, 4]);
        assert_eq!(p2.next_seq, 5);

        // 从 4 取：seq 5；next_seq = 6。
        let p3 = agg.list(4, 2).expect("list");
        assert_eq!(p3.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [5]);
        assert_eq!(p3.next_seq, 6);

        // 已到末尾：空页，next_seq = last_seq + 1（轮询可用 `next_seq > after_seq`
        // 判断有新日志）。
        let p4 = agg.list(5, 10).expect("list");
        assert!(p4.entries.is_empty());
        assert_eq!(p4.next_seq, 6);
    }

    /// 重启游标重建：重新打开同一文件后 `last_seq` 恢复、可继续追加、seq 连续。
    #[test]
    fn cursor_rebuilds_from_file_after_restart() {
        let path = temp_log_path("restart");
        {
            let agg = LogAggregator::open(&path).expect("open 1");
            agg.append_engine(&engine_event("info", "", "before", 1))
                .expect("append");
            agg.append_core("info", "core", "", "boot", &BTreeMap::new())
                .expect("append");
            assert_eq!(agg.last_seq(), 2);
        } // drop = 进程退出模拟

        // 重启：仅凭文件重建游标。
        let agg = LogAggregator::open(&path).expect("open 2");
        assert_eq!(agg.last_seq(), 2, "重启后从文件重建 last_seq");

        let p = agg.list(0, 0).expect("list");
        assert_eq!(p.entries.len(), 2, "历史行完整保留");
        assert_eq!(p.entries[0].seq, 1);
        assert_eq!(p.entries[0].source, "engine");
        assert_eq!(p.entries[1].seq, 2);
        assert_eq!(p.entries[1].source, "core");

        // 继续追加：seq 从 3 接续。
        let e = agg
            .append_engine(&engine_event("info", "", "after", 3))
            .expect("append");
        assert_eq!(e.seq, 3);
        assert_eq!(agg.last_seq(), 3);
    }

    /// clear：truncate 同一文件、游标归零、后续从 seq 1 重新开始（logs.clear 语义）。
    #[test]
    fn clear_truncates_and_restarts_cursor() {
        let path = temp_log_path("clear");
        let agg = LogAggregator::open(&path).expect("open");
        for i in 1..=3 {
            agg.append_engine(&engine_event("info", "", &format!("e{i}"), i))
                .expect("append");
        }
        assert_eq!(agg.last_seq(), 3);

        agg.clear().expect("clear");
        assert_eq!(agg.last_seq(), 0);
        assert_eq!(agg.list(0, 0).expect("list").entries.len(), 0);
        assert!(std::fs::read_to_string(&path).expect("read").is_empty());

        let e = agg
            .append_engine(&engine_event("info", "", "fresh", 4))
            .expect("append");
        assert_eq!(e.seq, 1, "清空后从 seq 1 重新开始");
        assert_eq!(agg.last_seq(), 1);
    }

    /// limit == 0 表示无限（返回全部剩余）。
    #[test]
    fn zero_limit_returns_all_remaining() {
        let path = temp_log_path("nolimit");
        let agg = LogAggregator::open(&path).expect("open");
        for i in 1..=5 {
            agg.append_core("info", "core", "", &format!("c{i}"), &BTreeMap::new())
                .expect("append");
        }
        let p = agg.list(1, 0).expect("list");
        assert_eq!(p.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [2, 3, 4, 5]);
        assert_eq!(p.next_seq, 6);
    }

    /// 坏行（崩溃残留半行）跳过但占用 seq 槽，后续行 seq 与行号对齐不破。
    #[test]
    fn malformed_line_consumes_seq_slot_without_breaking_cursor() {
        let path = temp_log_path("badline");
        let agg = LogAggregator::open(&path).expect("open");
        agg.append_engine(&engine_event("info", "", "good1", 1))
            .expect("append");
        agg.append_engine(&engine_event("info", "", "good2", 2))
            .expect("append");
        // 模拟崩溃残留：直接向文件追加半行 JSON（不经过 append）。
        {
            let mut f = OpenOptions::new().append(true).open(&path).expect("open");
            writeln!(f, "{{broken").expect("write");
            f.flush().expect("flush");
        }
        // 再次打开（重启），游标 = 3 行。
        let agg = LogAggregator::open(&path).expect("reopen");
        assert_eq!(agg.last_seq(), 3);

        // 坏行被跳过，但 seq 槽保留（后续 new 是 seq 4）。
        let e = agg
            .append_engine(&engine_event("info", "", "good3", 3))
            .expect("append");
        assert_eq!(e.seq, 4);

        let p = agg.list(0, 0).expect("list");
        assert_eq!(
            p.entries.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2, 4],
            "坏行占用 seq 3 槽"
        );
    }

    /// R3：`ingest_engine_stream` 把 engine `StreamLogs` 推送逐条落盘（聚合-only、
    /// 单向下行）——每条一个 JSONL 行，source=engine；流干净结束 → EndOfStream；
    /// 中途 transport 错误 → StreamError 并停止。
    #[tokio::test]
    async fn ingest_engine_stream_persists_events_one_way() {
        use std::sync::Arc;
        use tokio_stream::wrappers::UnboundedReceiverStream;
        use tokio_stream::StreamExt;

        let path = temp_log_path("ingest");
        let agg = Arc::new(LogAggregator::open(&path).expect("open"));
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<LogEvent, tonic::Status>>();
        let stream = UnboundedReceiverStream::new(rx);

        tx.send(Ok(engine_event("info", "WINTUN_UP", "tunnel up", 1_700_000_000_000)))
            .unwrap();
        tx.send(Ok(engine_event("error", "TLS_FAIL", "tls failed", 1_700_000_000_001)))
            .unwrap();
        // 先 drop 发送端：ingest 消费到 None（流干净结束）才返回 EndOfStream——否则
        // 通道永不关闭、测试永久悬挂。
        drop(tx);

        let outcome = ingest_engine_stream(stream, Arc::clone(&agg)).await;
        assert_eq!(outcome, IngestOutcome::EndOfStream, "流干净结束");

        let page = agg.list(0, 0).expect("list");
        assert_eq!(page.entries.len(), 2);
        assert_eq!(page.entries[0].source, "engine");
        assert_eq!(page.entries[0].code, "WINTUN_UP");
        assert_eq!(page.entries[1].code, "TLS_FAIL");
        // 纯单向：磁盘行 = 唯一真相源（不携带 seq；聚合不产生任何状态/事件）。
        let raw = std::fs::read_to_string(&path).expect("read");
        assert_eq!(raw.lines().count(), 2);

        // 中途 transport 错误 → StreamError 并停止（后续事件不再消费）。
        let (tx2, rx2) = tokio::sync::mpsc::unbounded_channel::<Result<LogEvent, tonic::Status>>();
        let stream2 = UnboundedReceiverStream::new(rx2);
        tx2.send(Ok(engine_event("info", "", "before.error", 3))).unwrap();
        tx2.send(Err(tonic::Status::unavailable("transport broken"))).unwrap();
        tx2.send(Ok(engine_event("info", "", "after.error", 4))).unwrap();
        let outcome2 = ingest_engine_stream(stream2, Arc::clone(&agg)).await;
        assert!(
            matches!(outcome2, IngestOutcome::StreamError(_)),
            "transport 错误 → StreamError"
        );
        assert_eq!(agg.last_seq(), 3, "错误后的事件不再落盘");
        let p2 = agg.list(0, 0).expect("list");
        assert_eq!(p2.entries[2].message, "before.error");
    }
}
