//! 结构化日志镜像（proto/exv/v1/helper_control.proto: LogEvent）。
//! StreamLogs 由 core 推送，UI 经 Event 订阅（P4-b）。字段与 proto 一致，
//! 安全性：no field carries a secret / capability / free-text diagnostic stack。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// 单条结构化日志事件（UI 视图）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEvent {
    /// info | warn | error
    pub level: String,
    /// e.g. engine, packet, protocol, platform
    pub component: String,
    /// 稳定诊断代码，空表示无。
    pub code: String,
    /// 人类可读消息（无诊断栈）。
    pub message: String,
    /// 结构化键值元数据（无 secret）。
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
    /// wall-clock epoch 毫秒（UTC），0 = 未知。
    pub timestamp_ms: i64,
}

/// 日志历史拉取的分片（P4-3：Command 拉历史 chunk + after_seq）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogChunk {
    pub events: Vec<LogEvent>,
    /// 本分片末条的事件序号，作为下次 after_seq 游标。
    pub next_after_seq: u64,
    /// 是否还有更多（分页）。
    pub has_more: bool,
}

/// 清空 core 持久化日志后的结果（KernelControl.LogsClear）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogsClearReply {
    pub cleared: bool,
    pub removed_entries: u64,
}
