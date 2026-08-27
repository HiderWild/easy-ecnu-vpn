// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! P2-a 日志聚合服务（`exv_core::log_aggregator`）集成测试。
//!
//! 从 crate 外验证 P2-c `logs.list`/`logs.clear` 契约所依赖的公开游标 API：
//!
//! - 合并流落盘（engine + core 事件 → 单一 JSONL 文件，`source` 标记）；
//! - `after_seq` 增量拉取（`LogPage.entries` + `next_seq` 的轮询语义）；
//! - 重启后游标仅凭文件重建（文件 = 唯一真相源）；
//! - `clear` 截断同一文件并重置游标。

use std::collections::BTreeMap;
use std::path::PathBuf;

use exv_core::log_aggregator::LogAggregator;
use exv_vpn_wire::generated::LogEvent;

/// 每测试独立的临时聚合日志路径（pid 隔离并发）。
fn temp_log_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("exv-log-agg-it-{tag}-{}.jsonl", std::process::id()))
}

fn engine_event(message: &str, timestamp_ms: i64) -> LogEvent {
    LogEvent {
        level: "warn".to_string(),
        component: "engine".to_string(),
        code: "PLATFORM".to_string(),
        message: message.to_string(),
        // proto map 生成 `HashMap`。
        fields: std::collections::HashMap::from([(
            "iface".to_string(),
            "wintun0".to_string(),
        )]),
        timestamp_ms,
    }
}

/// 合并流落盘 + source 标记 + 公开游标 API 端到端。
#[test]
fn merged_stream_with_source_markers_and_incremental_paging() {
    let path = temp_log_path("merged");
    let agg = LogAggregator::open(&path).expect("open");

    // engine 事件（StreamLogs 推送）+ core 事件交错落盘。
    agg.append_engine(&engine_event("engine boot", 100)).expect("e1");
    agg.append_core("info", "gate", "", "gate admitted", &BTreeMap::new())
        .expect("c1");
    agg.append_engine(&engine_event("tunnel up", 200)).expect("e2");

    // 全部条目：source 交替标记，seq 按落盘顺序单调。
    let all = agg.list(0, 0).expect("list all");
    assert_eq!(all.entries.len(), 3);
    assert_eq!(all.entries[0].source, "engine");
    assert_eq!(all.entries[0].component, "engine");
    assert_eq!(all.entries[1].source, "core");
    assert_eq!(all.entries[1].message, "gate admitted");
    assert_eq!(all.entries[2].source, "engine");
    assert_eq!(all.entries[2].seq, 3);
    assert_eq!(all.next_seq, 4);
    assert_eq!(agg.last_seq(), 3);

    // 增量轮询语义：cursor = 已消费位置，list(cursor) 只返回新增。
    let first_page = agg.list(0, 2).expect("page 1");
    assert_eq!(first_page.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [1, 2]);
    let rest = agg.list(first_page.next_seq - 1, 0).expect("page 2");
    assert_eq!(rest.entries.iter().map(|e| e.seq).collect::<Vec<_>>(), [3]);
}

/// 重启后游标仅凭文件重建：历史完整保留，追加 seq 连续，无进程内状态。
#[test]
fn cursor_rebuilds_solely_from_disk_after_restart() {
    let path = temp_log_path("restart-it");
    {
        let agg = LogAggregator::open(&path).expect("open 1");
        agg.append_engine(&engine_event("pre-restart", 1)).expect("e");
        assert_eq!(agg.last_seq(), 1);
    }

    // 重启：新进程只看到磁盘文件。
    let agg = LogAggregator::open(&path).expect("open 2");
    assert_eq!(agg.last_seq(), 1, "last_seq 从文件行数重建");
    let before = agg.list(0, 0).expect("history");
    assert_eq!(before.entries.len(), 1);
    assert_eq!(before.entries[0].seq, 1);
    assert_eq!(before.entries[0].message, "pre-restart");

    let e = agg.append_core("info", "core", "", "post-restart", &BTreeMap::new())
        .expect("append after restart");
    assert_eq!(e.seq, 2, "追加 seq 从文件末接续");
    assert_eq!(agg.last_seq(), 2);
}

/// clear 截断同一文件、游标归零、后续从 seq 1 重新开始（logs.clear 语义）。
#[test]
fn clear_truncates_and_resets_cursor() {
    let path = temp_log_path("clear-it");
    let agg = LogAggregator::open(&path).expect("open");
    for i in 1..=3 {
        agg.append_core("info", "core", "", &format!("line {i}"), &BTreeMap::new())
            .expect("append");
    }
    agg.clear().expect("clear");

    assert_eq!(agg.last_seq(), 0);
    assert!(agg.list(0, 0).expect("empty").entries.is_empty());
    assert!(std::fs::metadata(&path).expect("exists").len() == 0, "文件被截断为空");

    let e = agg.append_core("info", "core", "", "fresh", &BTreeMap::new())
        .expect("append after clear");
    assert_eq!(e.seq, 1);
}
