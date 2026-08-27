// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// P2-b RED→GREEN tests for the engine structured log sink:
//
//   1. **事件推送**：`LogSink::open_stream` 返回的 mpsc 接收端按序收到真实 `LogEvent`
//      （level/component/code/message/fields/timestamp_ms 结构完整）；
//   2. **raw-dump 触发**：无 StreamLogs 接收端（`resume_tick` 未挂接）或推送失败
//      （gRPC stream 断开 → 接收端 drop）时，同一事件直写 `engine-raw-<pid>.log`
//      （NDJSON 行），并清空失效的推送通道；
//   3. **恢复切回**：断线后重新 `open_stream(resume_tick)` → 先补拉 `tick > resume_tick`
//      的缓冲历史，再无缝切回实时推送；`resume_tick == 0` 表示从当前流位置开始（不补拉）。
//
// 这些是 engine（本 crate）侧契约；core（P2-a 聚合）侧消费同一 proto LogEvent。

use std::time::Duration;

use exv_engine::log_sink::{LogLevel, LogSink, RawLogDumper};
use exv_vpn_wire::generated;

/// A temp-dir dumper for a test, returning the `TempDir` guard (kept alive) and the dumper.
fn temp_dumper(tag: &str) -> (tempfile::TempDir, RawLogDumper) {
    let dir = tempfile::tempdir().expect("temp dir");
    let dumper = RawLogDumper::new(dir.path().join("logs"));
    let _ = tag;
    (dir, dumper)
}

/// Receive one event from the stream with a bounded timeout.
async fn recv(
    rx: &mut tokio::sync::mpsc::Receiver<Result<generated::LogEvent, tonic::Status>>,
) -> generated::LogEvent {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("stream delivers event")
        .expect("stream alive")
        .expect("event ok")
}

/// Parse every line of the raw dump file as JSON.
fn dump_lines(path: &std::path::Path) -> Vec<serde_json::Value> {
    let content = std::fs::read_to_string(path).expect("raw dump readable");
    content
        .lines()
        .map(|l| serde_json::from_str(l).expect("raw dump line is JSON"))
        .collect()
}

/// 事件推送：挂接流后 emit 的事件按序、结构完整到达接收端。
#[tokio::test]
async fn live_push_delivers_events_in_order() {
    let (_dir, dumper) = temp_dumper("live");
    let sink = LogSink::new(dumper);
    let mut rx = sink.open_stream(0);

    sink.emit(LogLevel::Info, "engine", "boot.started", "engine booting", &[("pid", "42")]);
    sink.emit(LogLevel::Warn, "auth", "lease.refused", "handshake refused", &[]);
    sink.emit(LogLevel::Error, "cstp", "tls.failed", "tls handshake failed", &[]);

    let e1 = recv(&mut rx).await;
    assert_eq!(e1.level, "info");
    assert_eq!(e1.component, "engine");
    assert_eq!(e1.code, "boot.started");
    assert_eq!(e1.message, "engine booting");
    assert_eq!(e1.fields.get("pid").map(String::as_str), Some("42"));
    assert!(e1.timestamp_ms > 0, "timestamp populated");

    let e2 = recv(&mut rx).await;
    assert_eq!(e2.level, "warn");
    assert_eq!(e2.code, "lease.refused");

    let e3 = recv(&mut rx).await;
    assert_eq!(e3.level, "error");
    assert_eq!(e3.code, "tls.failed");
}

/// raw-dump 触发：无接收端（未挂接）时事件直写独立 raw 文件（NDJSON 行）。
#[test]
fn emit_without_stream_writes_raw_dump() {
    let (_dir, dumper) = temp_dumper("dump");
    let sink = LogSink::new(dumper);

    sink.emit(LogLevel::Info, "engine", "boot.started", "engine booting", &[("pid", "42")]);
    sink.emit(LogLevel::Error, "cstp", "tls.failed", "tls handshake failed", &[]);

    assert!(!sink.is_push_attached(), "no stream attached");
    let path = sink.dump_path();
    assert!(path.exists(), "raw dump file created");
    let lines = dump_lines(&path);
    assert_eq!(lines.len(), 2, "both events appended");
    assert_eq!(lines[0]["level"], "info");
    assert_eq!(lines[0]["code"], "boot.started");
    assert_eq!(lines[0]["fields"]["pid"], "42");
    assert_eq!(lines[1]["level"], "error");
    assert_eq!(lines[1]["code"], "tls.failed");
}

/// raw-dump 触发（推送失败）：挂接后 drop 接收端（模拟 gRPC stream 断开）→ 推送通道
/// 被清空，同一事件直写 raw 文件，后续事件继续落 raw。
#[tokio::test]
async fn push_failure_falls_back_to_raw_dump() {
    let (_dir, dumper) = temp_dumper("fallback");
    let sink = LogSink::new(dumper);

    let mut rx = sink.open_stream(0);
    sink.emit(LogLevel::Info, "engine", "pre.drop", "before drop", &[]);
    assert_eq!(recv(&mut rx).await.code, "pre.drop");
    assert!(sink.is_push_attached());

    drop(rx); // 断线：gRPC stream 关闭，接收端 drop

    sink.emit(LogLevel::Warn, "engine", "post.drop", "after drop", &[]);
    assert!(!sink.is_push_attached(), "failed push channel cleared");

    let path = sink.dump_path();
    let lines = dump_lines(&path);
    assert_eq!(lines.len(), 1, "only the post-drop event hit raw dump");
    assert_eq!(lines[0]["code"], "post.drop");
}

/// 恢复切回：断线后重新挂接（带 resume_tick）→ 补拉缓冲历史，再无缝切回实时推送；
/// 已消费（tick <= resume_tick）的事件不重复投递。
#[tokio::test]
async fn reconnect_backfills_and_switches_back() {
    let (_dir, dumper) = temp_dumper("recover");
    let sink = LogSink::new(dumper);

    // 第一次连接：消费 e1（tick 1）。
    let mut rx1 = sink.open_stream(0);
    sink.emit(LogLevel::Info, "engine", "e1", "first", &[]);
    assert_eq!(recv(&mut rx1).await.code, "e1");
    let seen_tick = sink.last_tick(); // 1（core 记录的最后一个单调 tick）

    drop(rx1); // 断线

    // 断线期间的事件 e2（tick 2）只能落 raw dump。
    sink.emit(LogLevel::Warn, "engine", "e2", "during gap", &[]);
    assert!(!sink.is_push_attached());

    // 重连：带 resume_tick = 最后消费的 tick → 补拉 e2（tick 2 > 1）。
    let mut rx2 = sink.open_stream(seen_tick);
    let backfilled = recv(&mut rx2).await;
    assert_eq!(backfilled.code, "e2", "gap event backfilled on resume");

    // 恢复后实时推送 e3（tick 3）。
    sink.emit(LogLevel::Error, "engine", "e3", "live again", &[]);
    assert!(sink.is_push_attached(), "push restored");
    let live = recv(&mut rx2).await;
    assert_eq!(live.code, "e3");

    // e1 不应被重放（tick 1 <= resume_tick 1）。
    tokio::time::timeout(Duration::from_millis(150), rx2.recv())
        .await
        .expect_err("no duplicate e1 replay")
        .to_string();
}

/// resume_tick == 0：从当前流位置开始，不补拉断线前历史（新 core 只拿实时增量）。
#[tokio::test]
async fn resume_zero_skips_prior_history() {
    let (_dir, dumper) = temp_dumper("resume0");
    let sink = LogSink::new(dumper);

    let mut rx1 = sink.open_stream(0);
    sink.emit(LogLevel::Info, "engine", "before.gap", "pre-disconnect", &[]);
    assert_eq!(recv(&mut rx1).await.code, "before.gap");
    drop(rx1);

    sink.emit(LogLevel::Warn, "engine", "during.gap", "gap event", &[]); // → raw dump

    let mut rx2 = sink.open_stream(0); // 0 = 当前流位置
    sink.emit(LogLevel::Error, "engine", "live.after", "post-connect", &[]);
    let first = recv(&mut rx2).await;
    assert_eq!(first.code, "live.after", "resume 0 starts at current position");
}

/// raw-dump 写失败降级：目录不可创建（父路径是文件）→ dump 返回 false 且不 panic，
/// 之后 emit 仍不 panic（推送路径不受影响）。
#[tokio::test]
async fn raw_dump_write_failure_degrades_gracefully() {
    let dir = tempfile::tempdir().expect("temp dir");
    let blocker = dir.path().join("blocker");
    std::fs::write(&blocker, b"x").expect("blocker file");
    // 父路径是文件 → create_dir_all 失败 → dumper 自禁用。
    let dumper = RawLogDumper::new(blocker.join("logs"));
    let sink = LogSink::new(dumper);

    sink.emit(LogLevel::Warn, "engine", "no.write", "write impossible", &[]);
    assert!(!sink.dump_path().exists(), "no file created on failed dir");

    // 推送路径不受影响：挂接后事件仍可送达。
    let mut rx = sink.open_stream(0);
    sink.emit(LogLevel::Info, "engine", "push.ok", "push unaffected", &[]);
    assert_eq!(recv(&mut rx).await.code, "push.ok");
}

/// `RawLogDumper::disabled` 永不自建文件（HelperControlService 默认构造用），dump 返回 false。
#[test]
fn disabled_dumper_never_writes() {
    let dumper = RawLogDumper::disabled();
    let sink = LogSink::new(dumper);
    sink.emit(LogLevel::Info, "engine", "null.sink", "dropped", &[]);
    assert!(!sink.dump_path().exists(), "disabled dumper writes nothing");
}

/// LogLevel 字符串映射与 proto 契约一致（info | warn | error）。
#[test]
fn log_level_maps_to_proto_strings() {
    assert_eq!(LogLevel::Info.as_str(), "info");
    assert_eq!(LogLevel::Warn.as_str(), "warn");
    assert_eq!(LogLevel::Error.as_str(), "error");
}

/// 单调 tick 严格递增（resume_tick 的序列基础）。
#[test]
fn ticks_are_strictly_monotonic() {
    let (_dir, dumper) = temp_dumper("tick");
    let sink = LogSink::new(dumper);
    sink.emit(LogLevel::Info, "engine", "a", "a", &[]);
    let t1 = sink.last_tick();
    sink.emit(LogLevel::Warn, "engine", "b", "b", &[]);
    let t2 = sink.last_tick();
    sink.emit(LogLevel::Error, "engine", "c", "c", &[]);
    let t3 = sink.last_tick();
    assert!(t1 < t2 && t2 < t3, "ticks strictly increase: {t1} < {t2} < {t3}");
}
