// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W29-A crash-matrix scenario 二进制（`run-native-acceptance.ps1 -Scenario
//! crash-matrix` 的派发目标）：解析 `--evidence-dir` / `--log-file`，运行
//! `run_crash_matrix`，把完整 `CrashMatrixEvidence` JSON 写入
//! `<EvidenceDir>/crash-matrix.json`，并在 stdout 打印一行
//! `CRASH_MATRIX_EVIDENCE:<compact-json>`（PowerShell anchor 消费行）。
//!
//! 同一二进制同时是矩阵子进程角色的宿主（env 标记分派，不进 evidence 发布路径）：
//! helper-hold（`EXV_W29_HELPER_ROLE=1`：compose + 命名 crash 边界 + host 死亡
//! 监控）、host-dummy（`EXV_W29_HOST_DUMMY=1`：sleep 至被杀）与纯逻辑 exercise
//! 复验（`EXV_W29_EXERCISE=<name>`：进程 restart 复验）。
//!
//! **权限**：脚本以提权 PowerShell 派发本二进制（矩阵需要 elevated 环境驱动真实
//! kill/restart）；本二进制不像受控纵切那样自我降权——elevated 是矩阵的前提，非
//! elevated 时证据诚实标记 `WIN_ACCEPTANCE_ENV_INVALID:host_not_elevated`。
//!
//! 退出码：0 = `environment_state == "completed"`；2 = 环境无效 / not_run /
//! 纵切失败（`WIN_ACCEPTANCE_ENV_INVALID:<predicate>` 或 `not_run/...` 已在证据中）。

use std::io::Write;
use std::path::PathBuf;

use exv_vpn_win32_acceptance::scenarios::crash_matrix::{
    run_crash_matrix, run_crash_matrix_exercise, run_crash_matrix_helper_role,
    run_crash_matrix_host_dummy,
};

/// 日志文件（--log-file 时打开）：所有输出同时写 stdout 与日志（WSP3 模式）。
static LOG_FILE: std::sync::Mutex<Option<std::fs::File>> = std::sync::Mutex::new(None);

fn log_line(s: &str) {
    println!("{s}");
    let _ = std::io::stdout().flush();
    if let Ok(mut g) = LOG_FILE.lock()
        && let Some(f) = g.as_mut()
    {
        let _ = writeln!(f, "{s}");
        let _ = f.flush();
    }
}

fn main() {
    // 子进程角色（矩阵纵切驱动；不进 evidence 发布路径）。
    if std::env::var_os("EXV_W29_HELPER_ROLE").is_some() {
        std::process::exit(run_crash_matrix_helper_role());
    }
    if std::env::var_os("EXV_W29_HOST_DUMMY").is_some() {
        run_crash_matrix_host_dummy();
    }
    if let Ok(exercise) = std::env::var("EXV_W29_EXERCISE") {
        std::process::exit(run_crash_matrix_exercise(&exercise));
    }

    // 脚本派发：--evidence-dir / --log-file。
    let args = parse_args();
    if let Some(lp) = &args.log_file
        && let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(lp)
        && let Ok(mut g) = LOG_FILE.lock()
    {
        *g = Some(f);
    }

    log_line("== EXV W29 Stop/crash/unknown-effect saturation (crash matrix) ==");
    let ev = run_crash_matrix();

    // 发布证据：JSON 文件 + CRASH_MATRIX_EVIDENCE:<json> 行。
    let json =
        serde_json::to_string(&ev).unwrap_or_else(|e| format!("evidence-serialize-error:{e}"));
    if let Some(dir) = &args.evidence_dir {
        let path = dir.join("crash-matrix.json");
        if std::fs::create_dir_all(dir)
            .and_then(|_| std::fs::write(&path, &json))
            .is_ok()
        {
            log_line(&format!("EVIDENCE: {}", path.display()));
        } else {
            log_line(&format!("WARN: 无法写入 evidence 文件 {}", path.display()));
        }
    }
    log_line(&format!("CRASH_MATRIX_EVIDENCE:{json}"));
    log_line(&format!(
        "== environment_state = {} ==",
        ev.environment_state
    ));

    let code = if ev.environment_state == "completed" { 0 } else { 2 };
    log_line(&format!("== scenario exit code: {code} =="));
    std::process::exit(code);
}

struct Args {
    evidence_dir: Option<PathBuf>,
    log_file: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut a = Args {
        evidence_dir: None,
        log_file: None,
    };
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--evidence-dir" {
            if let Some(v) = args.get(i + 1) {
                a.evidence_dir = Some(PathBuf::from(v));
            }
        } else if args[i] == "--log-file"
            && let Some(v) = args.get(i + 1)
        {
            a.log_file = Some(PathBuf::from(v));
        }
        i += 1;
    }
    a
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
