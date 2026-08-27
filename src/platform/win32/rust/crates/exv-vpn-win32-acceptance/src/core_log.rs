// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core 侧**统一日志层**（WSP3 模式）：带时间戳写 stdout + 日志文件。
//!
//! core 是唯一日志层：engine/未来 UI 的日志经 log 管道（`exv-vpn-win32-ipc::log_pipe`）
//! 回流到 core 后，最终都经本模块 `log_line` 落盘——格式统一（每行带 `[+NNN.NN s]`
//! 时间戳前缀，自进程启动墙钟秒数）。
//!
//! - `open_log_file`：打开 `--log-file`（追加写，自动建父目录；失败静默忽略）；
//! - `log_line`：`[+NNN.NN s] <msg>`，写 stdout + 日志文件，flush 立即落盘；
//! - `now_marker`：时间戳前缀（供需要前缀但不落盘的场景复用）。

use std::io::Write;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

/// 日志文件（`--log-file` 时打开）：所有输出同时写 stdout 与日志。
static LOG_FILE: Mutex<Option<std::fs::File>> = Mutex::new(None);

/// 进程启动时刻（首次调用 `now_marker`/`log_line` 时惰性初始化）。
static START: OnceLock<std::time::Instant> = OnceLock::new();

/// `[+NNN.NN s]` 时间戳（自进程启动墙钟秒数，3 位小数）。
#[must_use]
pub fn now_marker() -> String {
    let start = *START.get_or_init(std::time::Instant::now);
    format!("[+{:.3} s]", start.elapsed().as_secs_f64())
}

/// 打开日志文件（`--log-file`；追加写）。自动创建父目录；打开失败静默忽略
/// （stdout 仍可见，进程不因日志失败而中止）。
pub fn open_log_file(path: &Path) {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(path)
        && let Ok(mut g) = LOG_FILE.lock()
    {
        *g = Some(f);
    }
}

/// 记录一行日志：`[+NNN.NN s] <msg>`，写 stdout + 日志文件（flush 立即落盘）。
///
/// 从 log 管道回流的 engine/UI 日志也经本函数落盘（`coordination` 的 `LogPipeServer`
/// 回调把它转给 `log_line`），保证所有日志行时间戳格式统一。
pub fn log_line(s: &str) {
    let line = format!("{} {}", now_marker(), s);
    println!("{line}");
    let _ = std::io::stdout().flush();
    if let Ok(mut g) = LOG_FILE.lock()
        && let Some(f) = g.as_mut()
    {
        let _ = writeln!(f, "{line}");
        let _ = f.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `open_log_file` + `log_line`：日志文件必须生成、每行带 `[+NNN.NN s]` 时间戳前缀、
    /// 追加写（两次调用都落盘）。
    #[test]
    fn log_line_writes_timestamped_file() {
        let dir = std::env::temp_dir().join(format!("exv-core-log-test-{}", std::process::id()));
        let path = dir.join("t.log");
        let _ = std::fs::remove_dir_all(&dir);
        open_log_file(&path);
        log_line("[core] hello");
        log_line("[core] world");
        let content = std::fs::read_to_string(&path).expect("log file readable");
        assert!(
            content.lines().all(|l| l.starts_with("[+")),
            "每行必须带时间戳前缀，got {content}"
        );
        assert!(content.contains("[core] hello"), "第一行必须落盘，got {content}");
        assert!(content.contains("[core] world"), "第二行必须落盘，got {content}");
        // 关闭日志句柄（否则 Windows 上删除打开的文件会失败），再清理临时目录。
        *LOG_FILE.lock().expect("log file 锁") = None;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
