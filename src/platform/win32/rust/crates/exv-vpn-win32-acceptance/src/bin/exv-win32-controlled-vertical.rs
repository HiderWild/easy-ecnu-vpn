// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W28-A 受控纵切 scenario 二进制（`run-native-acceptance.ps1 -Scenario controlled` 的
//! 派发目标）：解析 `--evidence-dir` / `--log-file`，运行
//! `run_controlled_vertical`，把完整 `ControlledVerticalEvidence` JSON 写入
//! `<EvidenceDir>/controlled-vertical.json`，并在 stdout 打印一行
//! `CONTROLLED_VERTICAL_EVIDENCE:<compact-json>`（PowerShell anchor 消费行）。
//!
//! **权限拓扑**：纵切要求 ordinary host + elevated helper。脚本以提权 PowerShell 派发
//! 本二进制时，本二进制先把自身降权（restricted token，去 Administrators SID +
//! medium integrity）派生子进程运行场景——子进程才是 ordinary host（真实
//! `TokenElevation` 观测），再由子进程 RunAs 拉起 elevated helper。降权失败则诚实
//! 退出（不冒充）。
//!
//! 退出码：0 = `environment_state == "completed"`；2 = 环境无效 / not_run /
//! 降权失败（`WIN_ACCEPTANCE_ENV_INVALID:<predicate>` 或 `not_run/...` 已在证据中）。

use std::io::Write;
use std::path::PathBuf;

use exv_vpn_win32_acceptance::scenarios::controlled::run_controlled_vertical;
use exv_vpn_win32_acceptance::wintun_facts::resolve_dll_path;

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
    let args = parse_args();
    if let Some(lp) = &args.log_file
        && let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(lp)
        && let Ok(mut g) = LOG_FILE.lock()
    {
        *g = Some(f);
    }

    log_line("== EXV W28 controlled TLS/CSTP + Wintun vertical ==");

    // 降权子进程标记：EXV_W28_DELEV_CHILD=1 时即使仍 elevated 也禁止再次降权
    // （防死循环）；此时运行场景会让证据诚实标记 host-process-elevated。
    let already_delevated = std::env::var("EXV_W28_DELEV_CHILD").is_ok();
    if is_elevated() && !already_delevated {
        log_line("process is elevated: de-elevating self for the ordinary host role ...");
        match spawn_deelevated_self(&args) {
            Ok(code) => {
                log_line(&format!("de-elevated host child exited with code {code}"));
                std::process::exit(code);
            }
            Err(e) => {
                log_line(&format!("de-elevation failed: {e}"));
                std::process::exit(2);
            }
        }
    }
    if is_elevated() {
        log_line("WARNING: de-elevation did not produce an ordinary host; the scenario will record WIN_ACCEPTANCE_ENV_INVALID:host-process-elevated");
    }

    let dll = resolve_dll_path(None);
    let ev = run_controlled_vertical(&dll);

    // 发布证据：JSON 文件 + CONTROLLED_VERTICAL_EVIDENCE:<json> 行。
    let json = serde_json::to_string(&ev).unwrap_or_else(|e| format!("evidence-serialize-error:{e}"));
    if let Some(dir) = &args.evidence_dir {
        let path = dir.join("controlled-vertical.json");
        if std::fs::create_dir_all(dir)
            .and_then(|_| std::fs::write(&path, &json))
            .is_ok()
        {
            log_line(&format!("EVIDENCE: {}", path.display()));
        } else {
            log_line(&format!("WARN: 无法写入 evidence 文件 {}", path.display()));
        }
    }
    log_line(&format!("CONTROLLED_VERTICAL_EVIDENCE:{json}"));
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

/// 当前进程是否 elevated（TokenElevation 观测；与 scenario 同一观测实现）。
fn is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: GetCurrentProcess 伪句柄，无需关闭。
    let process = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        return false;
    }
    let mut elevated = false;
    let mut size = 0u32;
    // SAFETY: 尺寸查询。
    unsafe {
        let _ = GetTokenInformation(token, TokenElevation, None, 0, &raw mut size);
    }
    if size != 0 {
        let mut buff = vec![0u8; size as usize];
        let len = u32::try_from(buff.len()).unwrap_or(0);
        // SAFETY: buff 有效。
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some(buff.as_mut_ptr().cast::<std::ffi::c_void>()),
                len,
                &raw mut size,
            )
        };
        if ok.is_ok() && buff.len() >= 4 {
            elevated = u32::from_ne_bytes(buff[0..4].try_into().unwrap_or([0u8; 4])) != 0;
        }
    }
    // SAFETY: token 句柄关闭。
    unsafe {
        let _ = CloseHandle(token);
    }
    elevated
}

/// 降权派生子进程（Task Scheduler `/RL LIMITED`：任务进程由 Task Scheduler
/// （SYSTEM）以当前用户交互登录会话的过滤 token 创建——TokenElevation=0、
/// medium integrity、无 Administrators SID，与 Explorer 双击启动非提权进程
/// 同源），子进程以相同参数重新运行本二进制——ordinary host。
///
/// 机制（2026-08-15 rerun 实证，probe `exv-w28-schtasks-probe3.log`：
/// `tokenelev=0 isadmin=False`）：elevated 进程创建一次性计划任务
/// `ExvW28Delev-<pid>`（/RL LIMITED 非最高权限）并 /Run 触发；子进程经 .cmd
/// 包装设置 `EXV_W28_DELEV_CHILD=1` 防二次降权，并把退出码写入 temp 退出文件，
/// 本函数轮询读取后原样传递（completed=0 / 环境无效=2）。
///
/// 曾试机制全部否决（2026-08-15 rerun 实测）：
///   * CreateProcessWithTokenW/CreateProcessAsUserW + CreateRestrictedToken
///     restricted token：E_INVALIDARG (87)（缺 CREATE_UNICODE_ENVIRONMENT 修正
///     后 spawn 虽成功但子进程主线程从未调度——kernel32 未映射、0 CPU）；且
///     TokenElevation 属性保留（子进程仍被观测为 elevated →
///     WIN_ACCEPTANCE_ENV_INVALID:host-process-elevated）；CreateProcessAsUserW
///     另因 Elevated token 无 SeAssignPrimaryTokenPrivilege 报 1314。
///   * TokenLinkedToken linked token：无 SeTcbPrivilege 时返回
///     SecurityIdentification impersonation token，CreateProcessWithTokenW 与
///     DuplicateTokenEx→primary 均报 ERROR_BAD_IMPERSONATION_LEVEL (1346)。
fn spawn_deelevated_self(args: &Args) -> Result<i32, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let cmdline = build_command_line(&exe, args);
    let pid = std::process::id();
    let tmp = std::env::temp_dir();
    let wrapper_path = tmp.join(format!("exv-w28-delev-{pid}.cmd"));
    let exit_file = tmp.join(format!("exv-w28-delev-{pid}.exit"));
    let task_name = format!("ExvW28Delev{pid}");

    // 1. 清理同名残留任务（忽略失败）。
    let _ = run_schtasks(&format!("/Delete /TN {task_name} /F"));

    // 2. 写一次性 .cmd 包装（CRLF；cmd 逐行解析，%ERRORLEVEL% 在 exe 行之后
    //    展开——正确捕获退出码）：设置降权标记 env，运行本二进制，记录退出码。
    let wrapper = format!(
        "@echo off\r\nset EXV_W28_DELEV_CHILD=1\r\n{cmdline}\r\necho %ERRORLEVEL%> \"{exit}\"\r\n",
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
    // 5. 轮询退出码文件（≤5 分钟，与旧 token 启动的等待上限一致）。
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

/// 子进程命令行（同参数 + 降权标记）。
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
    parts.join(" ")
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
