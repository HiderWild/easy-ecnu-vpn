// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core 侧启动特权 engine 子进程（阶段 4-ii-a：core 启动 engine）。
//!
//! 两进程架构：**core**（普通 token，永不 elevated）经 `ShellExecuteExW(runas)` 提权拉起唯一特权进程
//! **engine**（建卡/路由/网络设置/认证/CSTP/数据面），随后经控制面 Named Pipe（`control_client`）指挥它。
//! 本模块提供：
//! - `spawn_engine_elevated`：提权 spawn engine bin，返回 `(pid, handle)`——复用
//!   `scenarios::controlled::spawn_helper_elevated` 的 ShellExecuteExW(runas) 机制（engine 与
//!   helper 同构：普通 core 拉起特权子进程）；
//! - `engine_bin_path`：定位 `exv-win32-engine` 可执行路径（`CARGO_BIN_EXE_exv-win32-engine`
//!   或 `current_exe` sibling），复用 `controlled::helper_bin_path` 模式；
//! - `engine_args_for_spawn` + `engine_control_pipe_name`：构造 engine 启动参数（控制面管道名按
//!   core PID 唯一、wintun.dll 路径、journal 目录、authority 名、host pid、adapter 名），对齐
//!   `controlled::helper_args_for_spawn` 模式与 `engine::parse_engine_args` 契约；
//! - `verify_engine_elevated`：观测 engine 进程 token 是否 elevated（fail closed）。

use std::path::{Path, PathBuf};

use windows::Win32::Foundation::HANDLE;

use exv_vpn_win32_ipc::log_pipe::LOG_PIPE_NAME;
use exv_vpn_win32_ipc::peer_auth::current_user_sid;

use crate::engine::ENGINE_ADAPTER_NAME;
use crate::scenarios::controlled;
use crate::wintun_facts::resolve_dll_path;

/// 提权 spawn engine 进程（ShellExecuteExW runas；返回 pid + 进程句柄）。
///
/// 复用 `controlled::spawn_helper_elevated` 的同一 ShellExecuteExW(runas) 机制（engine 是 helper
/// 的同构特权进程——普通 core 拉起、UAC 静默通过或拒绝）。返回的 `HANDLE` 由调用者持有：
/// 用 `controlled::wait_process_exit` 等待退出，或用 `CloseHandle` 关闭。
///
/// # Errors
/// ShellExecuteExW(runas) 失败 / 未返回进程句柄 / PID 为 0。
pub fn spawn_engine_elevated(exe: &Path, args: &[String]) -> Result<(u32, HANDLE), String> {
    controlled::spawn_helper_elevated(exe, args)
}

/// engine bin 的可执行路径（测试流：`CARGO_BIN_EXE_exv-win32-engine`；bin 流：`current_exe` 同目录
/// sibling）。复用 `controlled::helper_bin_path` 模式，bin 名替换为 `exv-win32-engine`。
#[must_use]
pub fn engine_bin_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_exv-win32-engine") {
        let bp = PathBuf::from(p);
        if bp.exists() {
            return Some(bp);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let name = if exe.file_name()?.to_string_lossy().ends_with(".exe") {
        "exv-win32-engine.exe"
    } else {
        "exv-win32-engine"
    };
    Some(dir.join(name))
}

/// engine 控制面 Named Pipe 名（按 core PID 唯一——同一 core 反复拉起 engine 不冲突）。
///
/// 与 `engine_args_for_spawn` 中的 `--control-pipe` 值一致；core 提权拉起 engine 后用它连接
/// （`control_client::EngineControlClient::connect`）。命名沿用 helper 约定的 `-c` 后缀（区分
/// 未来可能加入的 packet pipe）。
#[must_use]
pub fn engine_control_pipe_name() -> String {
    let host_pid = std::process::id();
    format!(r"\\.\pipe\exv-engine-{host_pid}-c")
}

/// engine 的启动参数（core 侧构造；管道名按 core PID 唯一）。
///
/// 参数契约与 `engine::parse_engine_args` 对齐：必需 `--control-pipe`、`--dll`、`--host-pid`；
/// 可选 `--journal-dir`/`--authority-name`/`--adapter-name`/`--user-sid`。wintun.dll 路径经
/// `wintun_facts::resolve_dll_path` 解析（env `EXV_RUST_VPN_WINTUN_DLL` 或默认路径），与
/// `controlled::helper_args_for_spawn` 同源。
///
/// `--user-sid` 携带 **core** 进程的用户 SID：engine 用它建控制面管道 DACL，授权普通用户
/// core 连接（engine 是特权进程，默认 ACL 只含 SYSTEM/Administrators，普通 core 会被拒）。
/// SID 不可解析（极罕见）时省略该参数，engine 回退本进程用户 SID——同用户拓扑下两者相等。
#[must_use]
pub fn engine_args_for_spawn() -> Vec<String> {
    let host_pid = std::process::id();
    let journal_dir = std::env::temp_dir()
        .join(format!("exv-engine-journal-{host_pid}"))
        .display()
        .to_string();
    let dll = resolve_dll_path(None).display().to_string();
    let mut args = vec![
        "--control-pipe".to_string(),
        engine_control_pipe_name(),
        "--dll".to_string(),
        dll,
        "--journal-dir".to_string(),
        journal_dir,
        "--authority-name".to_string(),
        format!("Local\\exv-engine-{host_pid}-authority"),
        "--host-pid".to_string(),
        host_pid.to_string(),
        "--adapter-name".to_string(),
        ENGINE_ADAPTER_NAME.to_string(),
    ];
    if let Some(sid) = current_user_sid() {
        args.push("--user-sid".to_string());
        args.push(sid);
    }
    // log 管道（固定名多实例）：engine 连入后把日志经 core 统一 `log_line` 落盘。
    args.push("--log-pipe".to_string());
    args.push(LOG_PIPE_NAME.to_string());
    args
}

/// 观测 engine 进程 token 是否 elevated（fail closed：无法打开进程/读 token 即 false）。
/// 复用 `controlled::process_token_elevated`（helper 的同一观测实现）。
#[must_use]
pub fn verify_engine_elevated(pid: u32) -> bool {
    controlled::process_token_elevated(pid)
}

// ---------------------------------------------------------------------------
// 单元测试：参数契约往返（parse 回来）+ 管道名唯一 + bin 路径解析 + elevation 探针
// （探针 elevation-gated：非 elevated 环境 runas 弹 UAC，自动化无法可靠推进，诚实短路）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `engine_args_for_spawn` 产出的参数必须能被 `engine::parse_engine_args` 原样解析，
    /// 且必需字段（control-pipe/dll/host-pid）齐备、adapter 名默认 ExvEngine、管道名唯一。
    #[test]
    fn engine_args_for_spawn_parse_round_trip() {
        let pid = std::process::id();
        let spawn_argv = {
            let mut v = vec!["exv-win32-engine".to_string()];
            v.extend(engine_args_for_spawn());
            v
        };
        let args = crate::engine::parse_engine_args_from(&spawn_argv).expect("args parse ok");
        assert_eq!(args.control_pipe, engine_control_pipe_name());
        assert_eq!(args.control_pipe, format!(r"\\.\pipe\exv-engine-{pid}-c"));
        assert!(!args.dll.as_os_str().is_empty(), "dll 必须非空");
        assert_eq!(args.host_pid, pid);
        assert_eq!(args.adapter_name, ENGINE_ADAPTER_NAME);
        assert_eq!(
            args.authority_name,
            format!("Local\\exv-engine-{pid}-authority")
        );
        assert!(args
            .journal_dir
            .display()
            .to_string()
            .contains(&format!("exv-engine-journal-{pid}")));
        assert_eq!(
            args.core_user_sid.as_deref(),
            current_user_sid().as_deref(),
            "--user-sid 必须携带 core 用户 SID（engine 用它建控制面 DACL）"
        );
        assert_eq!(
            args.log_pipe.as_deref(),
            Some(LOG_PIPE_NAME),
            "--log-pipe 必须携带固定 log 管道名（engine 连入后把日志送回 core 落盘）"
        );
    }

    /// `engine_control_pipe_name` 按 core PID 唯一。
    #[test]
    fn engine_control_pipe_name_unique_per_pid() {
        let name = engine_control_pipe_name();
        assert!(name.starts_with(r"\\.\pipe\exv-engine-"), "pipe 前缀");
        assert!(name.ends_with("-c"), "control 后缀");
        assert!(
            name.contains(&std::process::id().to_string()),
            "必须含 core PID"
        );
    }

    /// `engine_bin_path` 必须解析（`CARGO_BIN_EXE` 或 sibling），文件名与 engine bin 一致。
    /// 不断言文件存在（cargo test 上下文 bin 未必已构建；探针测试单独做存在性门禁）。
    #[test]
    fn engine_bin_path_resolves_name() {
        let Some(p) = engine_bin_path() else {
            panic!("engine_bin_path 必须解析出路径");
        };
        let name = p.file_name().expect("file name").to_string_lossy();
        assert!(
            name == "exv-win32-engine" || name == "exv-win32-engine.exe",
            "bin 名必须为 exv-win32-engine，got {name}"
        );
    }

    /// elevation 探针：仅当测试进程本身已 elevated 时，提权拉起 engine bin 并观测其 token
    /// 为 elevated（elevated 父进程 runas 不弹 UAC、静默建 elevated 子进程）；非 elevated 环境
    /// 诚实短路（不冒充）。engine bin 未构建（测试流）时同样短路。
    #[test]
    fn spawn_engine_elevated_token_probe() {
        if !controlled::is_elevated() {
            // 非 elevated：runas 会弹 UAC，自动化无法可靠推进。
            return;
        }
        let Some(exe) = engine_bin_path().filter(|p| p.exists()) else {
            // engine bin 未构建（cargo test 仅构建 lib 测试目标时）。
            return;
        };
        let args = engine_args_for_spawn();
        let (pid, handle) = spawn_engine_elevated(&exe, &args).expect("spawn engine elevated");
        // 给 engine 一点启动时间（CreateProcess 返回后进程对象已存在，token 已固定）。
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            verify_engine_elevated(pid),
            "engine token 必须 elevated（engine 是唯一特权进程）"
        );
        // engine 在等 core 连接（run_engine_role 阻塞于 connect），探针不消费它——直接终止。
        // SAFETY: handle 是 spawn 返回的有效进程句柄；进程已观测完，TerminateProcess 主动结束。
        unsafe {
            let _ = windows::Win32::System::Threading::TerminateProcess(handle, 1);
        }
        // SAFETY: 进程句柄使用后关闭。
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
    }
}
