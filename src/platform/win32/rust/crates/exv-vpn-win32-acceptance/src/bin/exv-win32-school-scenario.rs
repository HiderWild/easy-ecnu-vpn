// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W30-A 学校 scenario 二进制（`run-native-acceptance.ps1 -Scenario school` 的
//! 派发目标）——**core 协调层**（阶段 4-ii-b）。
//!
//! 两进程架构最终形态：本二进制是 **core**（普通用户 token，纯协调层）。它读
//! `ExvConfig`（`%USERPROFILE%\.exv\config.json` + 独立 `key.bin`）→ 解密凭据 →
//! 可信解析网关 real_ip → 组装 `ConnectRequest` → 提权拉起唯一特权进程
//! **engine**（`engine_spawn`，ShellExecuteExW runas）→ 经控制面 Named Pipe
//! （`control_client`）双向认证 → 发 `Connect` → 收 `StatusChanged`/`Stats`/`Error`
//! → 展示/记录 → 发 `Disconnect` → 等待 engine 退出清理。认证/CSTP/数据面/建卡/
//! 写路由全部在 engine，core 只指挥、不碰数据/特权/Wintun、**永不 elevated**。
//!
//! **权限拓扑（新模型）**：core 普通（`core_token_elevated=false` 是**预期**）——
//! 本二进制不再要求宿主 elevated（旧 `school.rs` 的 `host_token_elevated` 强制已
//! 移除）；engine 特权（验证 engine token elevated，fail closed）。core 被提权
//! 运行时诚实标记 `WIN_ACCEPTANCE_ENV_INVALID:core_elevated_unexpected`（不冒充）。
//!
//! **配置来源**：凭据/网关/UA/MTU/校园路由全部来自 config（解密），不再经
//! `EXV_RUST_VPN_SCHOOL_TARGET` 等环境变量注入，也不经 cred-file/TTY one-shot。
//! 证据（`CoreCoordinationEvidence`）只记录协调层可诚实观测的事实，绝不记录明文
//! 凭据。
//!
//! 解析 `--evidence-dir` / `--log-file`（/ `--config-dir` 测试诊断用），运行
//! `run_core_coordination`，把完整证据 JSON 写入
//! `<EvidenceDir>/school-scenario.json`，并在 stdout 打印一行
//! `SCHOOL_SCENARIO_EVIDENCE:<compact-json>`（PowerShell anchor 消费行）。
//!
//! 退出码：0 = `environment_state == "completed"`；2 = 环境无效 / not_run / 连接失败。

use std::path::PathBuf;

use exv_vpn_win32_acceptance::coordination::run_core_coordination;
use exv_vpn_win32_acceptance::core_log::{log_line, open_log_file};
use exv_vpn_win32_acceptance::scenarios::controlled;

fn main() {
    let args = parse_args();
    // 统一日志层：`core_log::log_line` 带 `[+NNN.NN s]` 时间戳写 stdout + 日志文件；
    // engine/UI 的日志经 log 管道回流后也经同一 `log_line` 落盘（core 是唯一日志层）。
    if let Some(lp) = &args.log_file {
        open_log_file(lp);
    }

    log_line("== EXV W30 school VPN core coordination scenario ==");

    // 自我降权：core 必须普通用户（特权封死铁律），但用户可能从提权终端启动本
    // 二进制。提权启动时经 schtasks /RL LIMITED 把自身降权为普通态（对齐 W28 已验证
    // 的 spawn_deelevated_self 机制）再跑协调流程；普通态下再 RunAs 拉起特权 engine。
    // 降权子进程标记 EXV_DELEV_CHILD=1 时即使仍 elevated 也禁止再次降权（防死循环）。
    let already_delevated = std::env::var("EXV_DELEV_CHILD").is_ok();
    if controlled::is_elevated() && !already_delevated {
        log_line("process is elevated: de-elevating self to ordinary host via schtasks /RL LIMITED ...");
        match spawn_deelevated_self(&args) {
            Ok(code) => {
                log_line(&format!("de-elevated core child exited with code {code}"));
                std::process::exit(code);
            }
            Err(e) => {
                log_line(&format!("de-elevation failed: {e}"));
                std::process::exit(2);
            }
        }
    }
    if controlled::is_elevated() {
        log_line("WARNING: de-elevation did not produce an ordinary core; the scenario will record core_elevated_unexpected");
    }

    // core 协调层：读 config → 解密凭据 → 解析 → 启 engine → 连 → Connect →
    // 展示 → 断连 → 清理。
    let ev = run_core_coordination(
        args.config_dir.as_deref(),
        if args.hold { args.stop_file.as_deref() } else { None },
    );

    // 发布证据：JSON 文件 + SCHOOL_SCENARIO_EVIDENCE:<json> 行。
    let json = serde_json::to_string(&ev).unwrap_or_else(|e| format!("evidence-serialize-error:{e}"));
    if let Some(dir) = &args.evidence_dir {
        let path = dir.join("school-scenario.json");
        if std::fs::create_dir_all(dir)
            .and_then(|_| std::fs::write(&path, &json))
            .is_ok()
        {
            log_line(&format!("EVIDENCE: {}", path.display()));
        } else {
            log_line(&format!("WARN: 无法写入 evidence 文件 {}", path.display()));
        }
    }
    log_line(&format!("SCHOOL_SCENARIO_EVIDENCE:{json}"));

    // 协调事实摘要（拓扑证明：core 普通 + engine 特权 + 连接成功）。
    log_line(&format!(
        "== topology: core_elevated={} engine_pid={:?} engine_elevated={} ==",
        ev.core_token_elevated, ev.engine_pid, ev.engine_token_elevated
    ));
    log_line(&format!(
        "== connect: connected={} route_applied={} rx={} tx={} ==",
        ev.connected, ev.route_applied, ev.stats_rx_bytes, ev.stats_tx_bytes
    ));
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
    /// config 目录覆盖（测试/诊断；缺省 = 产品默认 `%USERPROFILE%\.exv`）。
    config_dir: Option<PathBuf>,
    /// persistent-tunnel hold 模式：Connect 成功后保持隧道存活供校内资源测试。
    hold: bool,
    /// hold 模式的 stop 条件文件路径（`--stop-file`；文件出现即停止 hold 走正常
    /// Disconnect 清理；缺省 = stdin EOF / Enter）。
    stop_file: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut a = Args {
        evidence_dir: None,
        log_file: None,
        config_dir: None,
        hold: false,
        stop_file: None,
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
        } else if args[i] == "--config-dir"
            && let Some(v) = args.get(i + 1)
        {
            a.config_dir = Some(PathBuf::from(v));
        } else if args[i] == "--hold" {
            a.hold = true;
        } else if args[i] == "--stop-file"
            && let Some(v) = args.get(i + 1)
        {
            a.stop_file = Some(PathBuf::from(v));
        }
        i += 1;
    }
    a
}

/// 降权派生子进程（Task Scheduler `/RL LIMITED`：任务进程由 Task Scheduler（SYSTEM）
/// 以当前用户交互登录会话的过滤 token 创建——TokenElevation=0、medium integrity、
/// 无 Administrators SID，与 Explorer 双击启动非提权进程同源），子进程以相同参数
/// 重新运行本二进制——ordinary core host。机制与 W28 `spawn_deelevated_self` 对齐
/// （2026-08-15 rerun 实证 probe3：`tokenelev=0 isadmin=False`）。
///
/// elevated 进程创建一次性计划任务 `ExvCoreDelev-<pid>`（/RL LIMITED 非最高权限）
/// 并 /Run 触发；子进程经 .cmd 包装设置 `EXV_DELEV_CHILD=1` 防二次降权，并把退出码
/// 写入 temp 退出文件，本函数轮询读取后原样传递（completed=0 / 环境无效=2）。
/// 曾试机制（restricted token / linked token）全部否决——见 W28 记录。
fn spawn_deelevated_self(args: &Args) -> Result<i32, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let cmdline = build_command_line(&exe, args);
    let pid = std::process::id();
    let tmp = std::env::temp_dir();
    let wrapper_path = tmp.join(format!("exv-core-delev-{pid}.cmd"));
    let exit_file = tmp.join(format!("exv-core-delev-{pid}.exit"));
    let task_name = format!("ExvCoreDelev{pid}");

    // 1. 清理同名残留任务（忽略失败）。
    let _ = run_schtasks(&format!("/Delete /TN {task_name} /F"));

    // 2. 写一次性 .cmd 包装（CRLF；cmd 逐行解析，%ERRORLEVEL% 在 exe 行之后
    //    展开——正确捕获退出码）：设置降权标记 env，运行本二进制，记录退出码。
    let wrapper = format!(
        "@echo off\r\nset EXV_DELEV_CHILD=1\r\n{cmdline}\r\necho %ERRORLEVEL%> \"{exit}\"\r\n",
        exit = exit_file.display()
    );
    std::fs::write(&wrapper_path, wrapper).map_err(|e| format!("write wrapper: {e}"))?;
    let _ = std::fs::remove_file(&exit_file);

    // 3. 创建一次性计划任务（/RL LIMITED：以用户过滤 token 运行——ordinary host）。
    let create = run_schtasks(&format!(
        "/Create /TN {task_name} /TR \"{wrapper}\" /SC ONCE /ST 23:59 /F /RL LIMITED",
        wrapper = wrapper_path.display()
    ))?;
    if create != 0 {
        return Err(format!("schtasks /Create failed: {create}"));
    }
    // 4. 触发任务。
    let run = run_schtasks(&format!("/Run /TN {task_name}"))?;
    if run != 0 {
        return Err(format!("schtasks /Run failed: {run}"));
    }
    // 5. 轮询退出码文件（≤5 分钟，与 W28 的等待上限一致）。
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5 * 60);
    let code = loop {
        if let Ok(s) = std::fs::read_to_string(&exit_file) {
            break s.trim().parse::<i32>().unwrap_or(2);
        }
        if std::time::Instant::now() >= deadline {
            return Err("wait for de-elevated child failed: timeout".to_string());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    };
    // 6. 清理：删除任务、包装、退出码文件。
    let _ = run_schtasks(&format!("/Delete /TN {task_name} /F"));
    let _ = std::fs::remove_file(&wrapper_path);
    let _ = std::fs::remove_file(&exit_file);
    Ok(code)
}

/// 运行 schtasks.exe 并等待其退出，返回退出码。
fn run_schtasks(args: &str) -> Result<i32, String> {
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, PROCESS_INFORMATION, STARTUPINFOW,
        PROCESS_CREATION_FLAGS, WaitForSingleObject,
    };

    let mut cmdline_w: Vec<u16> = format!("schtasks {args}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // lpApplicationName 显式指定 system32\schtasks.exe；cmdline 首 token 被忽略。
    // 注：0.62.2 的 Param 无 Option<PCWSTR> 实现——按值传 PCWSTR（CopyType）。
    let app = windows::core::PCWSTR(windows::core::w!("C:\\Windows\\System32\\schtasks.exe").as_ptr());
    // SAFETY: cmdline_w 可变（CreateProcessW 允许改写）；si/pi 有效。
    let ok = unsafe {
        CreateProcessW(
            app,
            Some(windows::core::PWSTR(cmdline_w.as_mut_ptr())),
            None,
            None,
            false,
            PROCESS_CREATION_FLAGS(0),
            None,
            windows::core::PCWSTR::default(),
            &raw const si,
            &raw mut pi,
        )
    };
    if ok.is_err() {
        return Err(format!("spawn schtasks failed: {ok:?}"));
    }
    // SAFETY: pi.hThread 立即关闭；pi.hProcess 等待后关闭。
    unsafe {
        let _ = CloseHandle(pi.hThread);
    }
    // SAFETY: pi.hProcess 有效。
    let rc = unsafe { WaitForSingleObject(pi.hProcess, 30_000) };
    let mut code: u32 = 0;
    // SAFETY: pi.hProcess 有效（关闭前读取）；code 是输出参数。
    let get_ok = unsafe { GetExitCodeProcess(pi.hProcess, &raw mut code) };
    // SAFETY: 进程句柄关闭。
    unsafe {
        let _ = CloseHandle(pi.hProcess);
    }
    if rc != WAIT_OBJECT_0 {
        return Err("schtasks wait timeout".to_string());
    }
    if get_ok.is_err() {
        return Err("GetExitCodeProcess(schtasks) failed".to_string());
    }
    Ok(i32::try_from(code).unwrap_or(-1))
}

/// 子进程命令行（同参数 + 降权标记；core 的 args 完整透传——--evidence-dir /
/// --log-file / --config-dir / --hold / --stop-file）。
fn build_command_line(exe: &std::path::Path, args: &Args) -> String {
    let mut parts = vec![format!("\"{}\"", exe.display())];
    if let Some(dir) = &args.evidence_dir {
        parts.push("--evidence-dir".to_string());
        parts.push(format!("\"{}\"", dir.display()));
    }
    if let Some(lp) = &args.log_file {
        parts.push("--log-file".to_string());
        parts.push(format!("\"{}\"", lp.display()));
    }
    if let Some(cd) = &args.config_dir {
        parts.push("--config-dir".to_string());
        parts.push(format!("\"{}\"", cd.display()));
    }
    if args.hold {
        parts.push("--hold".to_string());
    }
    if let Some(sf) = &args.stop_file {
        parts.push("--stop-file".to_string());
        parts.push(format!("\"{}\"", sf.display()));
    }
    parts.join(" ")
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
