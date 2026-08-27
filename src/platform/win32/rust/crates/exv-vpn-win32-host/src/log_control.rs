// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! P2-c `logs.list` / `logs.clear` 契约（host 内方法，面向 P4 Tauri UI）。
//!
//! 语义对齐既有 webui（C++ 参考）：`src/core/rpc/log_actions.cpp` 的 `read_log_lines`
//! （`after_seq`/`limit`/`filter` 语义与返回形状）与 `webui/src/pages/LogsPage.vue`
//! （消费 `seq`/`level`/`message` 字段）。
//!
//! ## 契约
//!
//! - [`LogControlService::list`]：拉历史日志。
//!   - `after_seq`：只返回 `seq > after_seq` 的条目（增量轮询）；`0` = 初始拉取。
//!   - `limit`：截断；默认 [`LOG_LIST_DEFAULT_LIMIT`]（100），上限
//!     [`LOG_LIST_MAX_LIMIT`]（500）——对齐 C++ `kDefaultLogEntries=100` /
//!     `kMaxLogEntriesPerResponse=500`。
//!   - `filter`：可选；大小写不敏感子串，匹配 `level` 或 `message` 文本。
//!   - `after_seq == 0` 返回**尾部**（最近 `limit` 条匹配项——webui 初始加载期望
//!     最近的日志）；`after_seq > 0` 返回 `seq > after_seq` 的前 `limit` 条匹配项。
//!   - 返回 [`LogListReply`]：`entries` 是与 webui 消费一致的事件数组，
//!     `next_seq` 是稳健增量游标（P2-a [`LogPage`] 语义：最后返回条目 `seq + 1`；
//!     空页 = `last_seq + 1`）。
//! - [`LogControlService::clear`]：truncate 聚合文件 + 游标归零，返回
//!   [`LogClearReply`]（`cleared` + 清除前条目数）。
//!
//! ## 与 C++/webui 的对齐点与有意差异
//!
//! | 项 | C++/webui | 本契约 |
//! | --- | --- | --- |
//! | `after_seq` | `seq > after_seq` 增量 | 相同；`0` = 尾部初始拉取 |
//! | `limit` | 默认 100 / 上限 500 | 相同 |
//! | `filter` | 整行子串 | 结构化：`level`/`message` 大小写不敏感子串 |
//! | 返回形状 | `[{seq,timestamp,level,message}]` 数组 | `{entries,next_seq}`；`entries` 即数组，条目字段是 P2-a 结构化超集 |
//! | 响应体量上限 | 6000 字节（legacy 文本行） | 由条目上限 500 覆盖（结构化 JSON 无此问题） |
//! | 清空 | webui 仅前端清 store（C++ 桌面端不调 host） | 本契约提供真实 host 清空（P4 用） |
//!
//! ## 接线
//!
//! - P3：core 组合时构造 `Arc<LogAggregator>`（`LogAggregator::open_default`），
//!   包为 [`LogControlService`]，供 `KernelControl` 语义网关 / host 内方法分发。
//! - P4：Tauri Command 直接调用 `list`/`clear`（进程内方法）。若未来需跨进程
//!   gRPC 暴露（`logs.list`/`logs.clear` 不在冻结的 `KernelControl` proto 中），
//!   须由协调者评估 proto 变更——本模块不改 proto。

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::log_aggregator::{LogAggError, LogAggregator, LogEntry};

/// `logs.list` 的 `limit` 默认值（对齐 C++ `kDefaultLogEntries = 100`）。
pub const LOG_LIST_DEFAULT_LIMIT: usize = 100;
/// `logs.list` 的 `limit` 上限（对齐 C++ `kMaxLogEntriesPerResponse = 500`）。
pub const LOG_LIST_MAX_LIMIT: usize = 500;

/// `logs.list` 请求参数（对齐 C++ `read_log_lines` 的 payload 键：`after_seq`/
/// `limit`/`filter`）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListLogsRequest {
    /// 只返回 `seq > after_seq` 的条目；`0` = 初始拉取（返回尾部）。
    #[serde(default)]
    pub after_seq: u64,
    /// 截断上限；`None` → 默认 [`LOG_LIST_DEFAULT_LIMIT`]，越界夹到
    /// `[1, LOG_LIST_MAX_LIMIT]`。
    #[serde(default)]
    pub limit: Option<usize>,
    /// 可选过滤：大小写不敏感子串，匹配 `level` 或 `message` 文本。
    #[serde(default)]
    pub filter: Option<String>,
}

/// `logs.list` 返回页。
///
/// `entries` 是与 webui 消费一致的事件数组（C++ 返回形状的超集）；`next_seq`
/// 是稳健增量游标（最后返回条目的 `seq + 1`；空页 = `last_seq + 1`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogListReply {
    pub entries: Vec<LogEntry>,
    pub next_seq: u64,
}

/// `logs.clear` 返回。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogClearReply {
    /// 恒为 `true`（失败走错误返回）。
    pub cleared: bool,
    /// 清除前聚合文件中的条目数（游标归零前的 `last_seq`）。
    pub removed_entries: u64,
}

/// P2-c `logs.list`/`logs.clear` 契约实现：包装 [`LogAggregator`]，提供
/// webui/C++ 语义对齐的 host 内方法（P4 Tauri Command 直接调用）。
pub struct LogControlService {
    aggregator: Arc<LogAggregator>,
}

impl LogControlService {
    /// 包装共享的聚合服务（P3 core 组合时构造一次，全进程共享）。
    #[must_use]
    pub fn new(aggregator: Arc<LogAggregator>) -> Self {
        Self { aggregator }
    }

    /// `logs.list`：拉历史日志（增量/尾部 + `limit` 截断 + 可选 `filter`）。
    ///
    /// # Errors
    /// 聚合文件不可读 → `LogAggError::Io`。
    ///
    /// # Panics
    /// 内部互斥锁中毒 → panic（透传自 [`LogAggregator::list`]）。
    pub fn list(&self, req: &ListLogsRequest) -> Result<LogListReply, LogAggError> {
        let limit = effective_limit(req.limit);
        let filter = req
            .filter
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        if filter.is_some() || req.after_seq == 0 {
            // 过滤或初始尾部需要全量扫描（seq 槽由聚合器保留；控制面日志量级小）。
            let all = self.aggregator.list(req.after_seq, 0)?;
            let mut entries: Vec<LogEntry> = match filter {
                Some(needle) => all
                    .entries
                    .into_iter()
                    .filter(|e| matches_filter(e, needle))
                    .collect(),
                None => all.entries,
            };
            if req.after_seq == 0 {
                // 尾部：保留最近 `limit` 条（webui 初始加载期望最近的日志）。
                entries = entries.split_off(entries.len().saturating_sub(limit));
            } else {
                // 过滤后的增量：保留前 `limit` 条。
                entries.truncate(limit);
            }
            return Ok(LogListReply {
                next_seq: next_seq_after(&entries, self.aggregator.last_seq()),
                entries,
            });
        }

        // 无过滤的增量拉取：直接委托聚合器原生路径（含其 `next_seq` 语义）。
        let page = self.aggregator.list(req.after_seq, limit)?;
        Ok(LogListReply {
            entries: page.entries,
            next_seq: page.next_seq,
        })
    }

    /// `logs.clear`：truncate 聚合文件 + 游标归零。
    ///
    /// # Errors
    /// 截断失败 → `LogAggError::Io`。
    ///
    /// # Panics
    /// 内部互斥锁中毒 → panic（透传自 [`LogAggregator::clear`]）。
    pub fn clear(&self) -> Result<LogClearReply, LogAggError> {
        let removed_entries = self.aggregator.last_seq();
        self.aggregator.clear()?;
        Ok(LogClearReply {
            cleared: true,
            removed_entries,
        })
    }
}

/// 规范化 `limit`：`None` → 默认 100；夹到 `[1, LOG_LIST_MAX_LIMIT]`（对齐 C++
/// `kDefaultLogEntries=100` / `kMaxLogEntriesPerResponse=500`，`< 1` 视为 1）。
fn effective_limit(limit: Option<usize>) -> usize {
    limit
        .unwrap_or(LOG_LIST_DEFAULT_LIMIT)
        .clamp(1, LOG_LIST_MAX_LIMIT)
}

/// `filter` 匹配：大小写不敏感子串，命中 `level` 或 `message` 任一即匹配。
fn matches_filter(entry: &LogEntry, filter: &str) -> bool {
    let needle = filter.to_lowercase();
    entry.level.to_lowercase().contains(&needle) || entry.message.to_lowercase().contains(&needle)
}

/// `next_seq` = 最后返回条目的 `seq + 1`；空页 = `last_seq + 1`（对齐
/// [`LogAggregator`] `LogPage` 的游标语义：跳过后继已消费的槽，客户端不空转）。
fn next_seq_after(entries: &[LogEntry], last_seq: u64) -> u64 {
    entries
        .last()
        .map_or_else(|| last_seq + 1, |entry| entry.seq + 1)
}

// ---------------------------------------------------------------------------
// 单元测试：after_seq 增量、limit 截断、filter 行为、clear 游标归零、JSON 形状。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// 每测试独立的临时聚合服务（pid 隔离并发）。
    fn service(tag: &str) -> (Arc<LogAggregator>, LogControlService) {
        let path: PathBuf =
            std::env::temp_dir().join(format!("exv-log-ctl-{tag}-{}.jsonl", std::process::id()));
        let agg = Arc::new(LogAggregator::open(&path).expect("open"));
        let svc = LogControlService::new(Arc::clone(&agg));
        (agg, svc)
    }

    fn append_core(agg: &LogAggregator, level: &str, message: &str) {
        agg.append_core(level, "core", "", message, &BTreeMap::new())
            .expect("append");
    }

    fn seqs(reply: &LogListReply) -> Vec<u64> {
        reply.entries.iter().map(|e| e.seq).collect()
    }

    /// 初始拉取（`after_seq == 0`）返回**尾部**最近 `limit` 条，对齐 webui 初始
    /// 加载期望最近的日志。
    #[test]
    fn initial_load_returns_recent_tail() {
        let (agg, svc) = service("tail");
        for i in 1..=5 {
            append_core(&agg, "info", &format!("e{i}"));
        }
        let reply = svc
            .list(&ListLogsRequest {
                after_seq: 0,
                limit: Some(2),
                filter: None,
            })
            .expect("list");
        assert_eq!(seqs(&reply), [4, 5], "初始拉取应返回最近的 limit 条");
        assert_eq!(reply.next_seq, 6);
    }

    /// `after_seq` 增量：只返回 `seq > after_seq` 的条目。
    #[test]
    fn incremental_after_seq_returns_only_newer() {
        let (agg, svc) = service("incr");
        for i in 1..=5 {
            append_core(&agg, "info", &format!("e{i}"));
        }
        let reply = svc
            .list(&ListLogsRequest {
                after_seq: 2,
                limit: None,
                filter: None,
            })
            .expect("list");
        assert_eq!(seqs(&reply), [3, 4, 5]);
        assert_eq!(reply.next_seq, 6);
    }

    /// 已追平：`after_seq` 到达末尾 → 空页，`next_seq = last_seq + 1`。
    #[test]
    fn incremental_caught_up_is_empty_with_cursor_at_eof() {
        let (agg, svc) = service("caught");
        for i in 1..=3 {
            append_core(&agg, "info", &format!("e{i}"));
        }
        let reply = svc
            .list(&ListLogsRequest {
                after_seq: 3,
                limit: Some(10),
                filter: None,
            })
            .expect("list");
        assert!(reply.entries.is_empty());
        assert_eq!(reply.next_seq, 4);
    }

    /// `limit` 语义：默认 100、上限 500、`< 1` 夹到 1（对齐 C++）。
    #[test]
    fn limit_clamps_default_and_max() {
        let (agg, svc) = service("limit");
        for i in 1..=600 {
            append_core(&agg, "info", &format!("e{i}"));
        }

        // 默认 100：尾部 100 条 = seq 501..=600。
        let dflt = svc
            .list(&ListLogsRequest {
                after_seq: 0,
                limit: None,
                filter: None,
            })
            .expect("list");
        assert_eq!(dflt.entries.len(), 100);
        assert_eq!(seqs(&dflt), (501..=600).collect::<Vec<_>>());

        // 上限 500：尾部 500 条 = seq 101..=600。
        let capped = svc
            .list(&ListLogsRequest {
                after_seq: 0,
                limit: Some(1000),
                filter: None,
            })
            .expect("list");
        assert_eq!(capped.entries.len(), 500);
        assert_eq!(capped.entries.first().expect("first").seq, 101);
        assert_eq!(capped.entries.last().expect("last").seq, 600);

        // `limit == 0` 夹到 1（C++ `limit < 1 → 1`）。
        let min = svc
            .list(&ListLogsRequest {
                after_seq: 0,
                limit: Some(0),
                filter: None,
            })
            .expect("list");
        assert_eq!(seqs(&min), [600]);
    }

    /// `filter` 按 level：只返回 level 匹配的条目，seq 槽保持原值。
    #[test]
    fn filter_by_level_selects_only_matching_level() {
        let (agg, svc) = service("flevel");
        append_core(&agg, "info", "a");
        append_core(&agg, "error", "boom");
        append_core(&agg, "warn", "b");
        append_core(&agg, "error", "c");

        let reply = svc
            .list(&ListLogsRequest {
                after_seq: 0,
                limit: None,
                filter: Some("error".to_string()),
            })
            .expect("list");
        assert_eq!(seqs(&reply), [2, 4], "seq 槽保持原值");
        assert!(reply.entries.iter().all(|e| e.level == "error"));
        assert_eq!(reply.next_seq, 5);
    }

    /// `filter` 按文本：message 大小写不敏感子串匹配。
    #[test]
    fn filter_by_message_text_is_case_insensitive() {
        let (agg, svc) = service("ftext");
        append_core(&agg, "info", "Connection refused");
        append_core(&agg, "info", "tunnel up");

        let reply = svc
            .list(&ListLogsRequest {
                after_seq: 0,
                limit: None,
                filter: Some("REFUSED".to_string()),
            })
            .expect("list");
        assert_eq!(seqs(&reply), [1]);
        assert_eq!(reply.entries[0].message, "Connection refused");
    }

    /// `filter` + `after_seq`：过滤应用在增量之后（不返回 `<= after_seq` 的旧条目）。
    #[test]
    fn filter_with_after_seq_is_incremental() {
        let (agg, svc) = service("fincr");
        append_core(&agg, "info", "one");
        append_core(&agg, "error", "two");
        append_core(&agg, "info", "three");

        let reply = svc
            .list(&ListLogsRequest {
                after_seq: 1,
                limit: None,
                filter: Some("info".to_string()),
            })
            .expect("list");
        // seq 1 是 info 但 <= after_seq，必须被排除；seq 3 是唯一剩余 info。
        assert_eq!(seqs(&reply), [3]);
    }

    /// `filter` + 尾部：初始拉取返回最近 `limit` 条**匹配项**。
    #[test]
    fn filter_result_tails_to_limit() {
        let (agg, svc) = service("ftail");
        append_core(&agg, "info", "ok1");
        append_core(&agg, "error", "boom1");
        append_core(&agg, "info", "ok2");
        append_core(&agg, "error", "boom2");
        append_core(&agg, "error", "boom3");

        let reply = svc
            .list(&ListLogsRequest {
                after_seq: 0,
                limit: Some(2),
                filter: Some("error".to_string()),
            })
            .expect("list");
        assert_eq!(seqs(&reply), [4, 5], "只保留最近的 2 条 error");
    }

    /// `clear`：truncate + 游标归零，返回清除的条目数；后续从 seq 1 重新开始。
    #[test]
    fn clear_reports_removed_entries_and_resets_cursor() {
        let (agg, svc) = service("clear");
        for i in 1..=3 {
            append_core(&agg, "info", &format!("e{i}"));
        }
        let reply = svc.clear().expect("clear");
        assert_eq!(
            reply,
            LogClearReply {
                cleared: true,
                removed_entries: 3,
            }
        );
        assert_eq!(agg.last_seq(), 0, "游标归零");

        let after = svc
            .list(&ListLogsRequest {
                after_seq: 0,
                limit: None,
                filter: None,
            })
            .expect("list");
        assert!(after.entries.is_empty(), "清空后无历史");

        append_core(&agg, "info", "fresh");
        let fresh = svc
            .list(&ListLogsRequest {
                after_seq: 0,
                limit: None,
                filter: None,
            })
            .expect("list");
        assert_eq!(seqs(&fresh), [1], "清空后从 seq 1 重新开始");
    }

    /// `clear` 空文件：`removed_entries == 0`，仍成功。
    #[test]
    fn clear_empty_file_reports_zero() {
        let (_agg, svc) = service("clearempty");
        let reply = svc.clear().expect("clear");
        assert_eq!(
            reply,
            LogClearReply {
                cleared: true,
                removed_entries: 0,
            }
        );
    }

    /// 返回 JSON 形状（P4 Tauri 消费）：`entries` 数组 + `next_seq`；条目含
    /// webui 消费的 `seq`/`level`/`message` 字段。
    #[test]
    fn list_reply_serializes_to_webui_compatible_json() {
        let (agg, svc) = service("json");
        append_core(&agg, "error", "gate refused");
        let reply = svc
            .list(&ListLogsRequest {
                after_seq: 0,
                limit: None,
                filter: None,
            })
            .expect("list");

        let json = serde_json::to_value(&reply).expect("serialize");
        assert!(json.get("next_seq").is_some(), "顶层含 next_seq 游标");
        let entries = json.get("entries").expect("顶层含 entries 数组");
        assert!(entries.is_array());
        let first = &entries[0];
        assert_eq!(first["seq"], 1);
        assert_eq!(first["level"], "error");
        assert_eq!(first["message"], "gate refused");
        assert_eq!(first["timestamp_ms"], reply.entries[0].timestamp_ms);
    }

    /// 请求可从 JSON payload 反序列化（Tauri Command 参数 / C++ payload 形状）。
    #[test]
    fn request_deserializes_from_json_payload() {
        let req: ListLogsRequest =
            serde_json::from_str(r#"{"after_seq": 3, "limit": 200, "filter": "error"}"#)
                .expect("parse");
        assert_eq!(req.after_seq, 3);
        assert_eq!(req.limit, Some(200));
        assert_eq!(req.filter.as_deref(), Some("error"));

        let defaults: ListLogsRequest = serde_json::from_str("{}").expect("parse empty");
        assert_eq!(defaults.after_seq, 0);
        assert_eq!(defaults.limit, None);
        assert_eq!(defaults.filter, None);
    }
}
