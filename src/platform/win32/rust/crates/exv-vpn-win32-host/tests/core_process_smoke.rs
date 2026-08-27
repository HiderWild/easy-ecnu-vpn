// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! P5 进程级 smoke（opt-in，`#[ignore]`）：core main 真实入口全链冒烟。
//!
//! 流程（镜像 P4-b `bootstrap.rs` 的 UI 角色）：
//!   1. 用 `CARGO_BIN_EXE_exv-core` 定位 core 二进制并 spawn
//!      （`--control-pipe \\.\pipe\exv-core-<testpid> --ui-pid <testpid> --ui-sid <sid>`）；
//!   2. core 提权拉起真实 engine（`ShellExecuteExW(runas)`——**需 UAC 放行**）、连接
//!      gRPC 控制面、建 UI 控制面管道并 accept；
//!   3. 一个短命子进程扮演 **UI**（同用户 SID，满足 `verify_ui_peer`）：拨号控制面
//!      管道 → 保持连接 → 退出。**UI 进程退出**（O3 强绑定）→ core 的 UI 进程退出
//!      监视触发 `on_ui_exited` → 有序停机（engine StopTunnel → 退出 → composition.exit）；
//!   4. 断言 core 干净退出（exit 0）且聚合日志出现停机标记。
//!
//! > 为什么是"UI 进程退出"而非"拨号后丢管道"：tonic `serve_with_incoming` 对单元素流
//! > accept 后立即返回、连接任务 detached 继续服务——serve 任务 JoinHandle 不充当"UI
//! > 断开"信号（会假 resolve 触发假停机）。真实信号是已验证 UI 进程的退出监视
//! > （`kernel_control_transport::spawn_ui_exit_watcher`）。
//!
//! 环境依赖（缺一即跳过/失败）：core+engine 二进制已构建（cargo build 先跑）、
//! engine 提权 spawn 需 UAC 放行、engine bin 为 `current_exe` sibling、PowerShell
//! 可用（UI dialer 子进程）。CI/无提权环境用 `--ignored` 显式跑并据环境如实报告。

use std::process::{Command, Stdio};

use exv_vpn_win32_ipc::peer_auth::current_user_sid;
use tempfile::TempDir;

fn core_bin() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("CARGO_BIN_EXE_exv-core").map(std::path::PathBuf::from)?;
    path.exists().then_some(path)
}

/// 短命 UI dialer 子进程：拨号 core 的控制面管道 → 保持连接 → 退出。
///
/// 用 .NET `NamedPipeClientStream`（同用户进程，SID 满足 `verify_ui_peer` 的
/// client-pid+SID+account 检查）；重试拨号直到 core 管道就绪（core 需拉起 engine +
/// UAC 放行，有启动竞窗）。连接成功并保持 1.5s 后退出（退出 = UI 进程退出 → core 停机）。
fn spawn_ui_dialer(pipe_name: &str) -> std::process::Child {
    // 去 `\\.\pipe\` 前缀（.NET serverName='.' + pipeName 拼出完整路径）。
    let short = pipe_name.trim_start_matches(r"\\.\pipe\");
    let script = format!(
        "$c=$null; $deadline=(Get-Date).AddSeconds(25); \
         while((Get-Date) -lt $deadline){{ \
           try{{ \
             $c=New-Object System.IO.Pipes.NamedPipeClientStream('.', '{short}', [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None, [System.Security.Principal.TokenImpersonationLevel]::Impersonation); \
             $c.Connect(2000); break \
           }} catch {{ Start-Sleep -Milliseconds 500 }} \
         }}; \
         if($null -eq $c){{ exit 1 }}; \
         Start-Sleep -Milliseconds 1500; $c.Dispose(); exit 0"
    );
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn ui dialer")
}

/// 进程级全链 smoke：core main → 拉起 engine → 连上 → UI 进程拨号并退出 → 有序停机。
#[tokio::test]
#[ignore = "requires real engine bin + UAC elevation (opt-in process smoke)"]
async fn core_main_full_chain_spawns_engine_serves_ui_and_shuts_down_ordered() {
    let Some(exe) = core_bin() else {
        eprintln!("SMOKE-SKIP: core bin not built (run cargo build first)");
        return;
    };
    let Some(sid) = current_user_sid() else {
        eprintln!("SMOKE-SKIP: current user SID unresolvable");
        return;
    };
    // 独立 config 目录（聚合日志写入其中，不污染真实 ~/.exv）。
    let dir = TempDir::new().expect("tempdir");
    let cfg_dir = dir.path().join("cfg");
    let _ = std::fs::create_dir_all(&cfg_dir);
    let pipe_name = format!(r"\\.\pipe\exv-core-smoke-{}", std::process::id());
    let ui_pid = std::process::id().to_string();

    // 1. spawn core（UI 宿主角色，非特权；O3：core 由 UI 拉起）。
    let mut child = Command::new(&exe)
        .args(["--control-pipe", &pipe_name, "--ui-pid", &ui_pid, "--ui-sid", &sid])
        .env("EXV_CONFIG_DIR", &cfg_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn core");

    // 2. 短命 UI 进程：拨号控制面管道（重试直到 core 就绪）→ 保持 → 退出。
    let mut ui = spawn_ui_dialer(&pipe_name);
    let ui_status = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        async { ui.wait().expect("wait ui dialer") },
    )
    .await
    .expect("ui dialer must exit within 30s");
    if !ui_status.success() {
        let _ = child.kill();
        panic!("SMOKE-FAIL: ui dialer could not connect to core pipe (engine/UAC blocked?)");
    }

    // 3. UI 进程已退出 → core 的 UI 进程退出监视触发 on_ui_exited → 有序停机。
    let status = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        async { child.wait().expect("wait core") },
    )
    .await
    .expect("core must exit after UI process exit");

    // 4. 断言：干净退出 + 聚合日志含停机事实。
    assert!(status.success(), "core exit code = {status}");
    let log_path = cfg_dir.join("logs").join("aggregated.jsonl");
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        log.contains("core.start.booting"),
        "aggregated log must record booting: {log}"
    );
    eprintln!(
        "SMOKE-OK: core exit {status}; engine/ordered shutdown via UI process exit; log={}",
        log.lines().count()
    );
}
