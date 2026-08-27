// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// S2 服务基础设施（完整服务形态 W28 第一批）：engine 可作 SCM 服务常驻。
//
// 本模块是**库侧**服务原语；main.rs（bin）负责 ServiceMain 接线与生命周期分叉：
// - [`EngineExitForm`]：engine 进程退出形态（oneshot = core 生命周期；service = SCM
//   生命周期）——驱动 main.rs 生命周期分叉（D1）。
// - SCM 子命令：[`install_service`] / [`uninstall_service`] / [`start_service`]
//   （复用 runas 提权边界，本机 admin；不新建特权二进制，D4）。
// - SCM failure actions（CR R3.1）：崩溃后 `SC_ACTION_RESTART` 由 SCM 重新拉起。
// - 服务常量：服务名 / 显示名 / 服务控制面管道名。
//
// 与 C++ legacy webui 的差异：legacy helper 服务名 `exv-helper`（被弃用参考）；Rust
// 产品 engine 是独立特权二进制（`exv-engine`），服务名 `exv-engine`。

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

/// SCM 服务名（Rust 产品 engine 服务）。
pub const SERVICE_NAME: &str = "exv-engine";

/// SCM 显示名。
pub const SERVICE_DISPLAY_NAME: &str = "EXV Engine Service";

/// 服务模式控制面 Named Pipe 名（稳定名；oneshot 按 core PID 唯一，见
/// host `engine_control_pipe_name`）。
pub const SERVICE_CONTROL_PIPE: &str = r"\\.\pipe\exv-engine-service-c";

/// engine 创建的 Wintun adapter 名（与 host `ENGINE_ADAPTER_NAME` 一致）。
pub const ENGINE_ADAPTER_NAME: &str = "ExvEngine";

/// SCM 状态转换的硬上限：服务必须在有限时间内进入 Stopped，避免安装/卸载请求无限
/// 占用 Core 的操作通道。引擎正常 teardown 通常 <1s；3s 足够覆盖慢机器并提前报错。
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(3);
/// DeleteService 后只等待一个短的 SCM settle 窗口。服务句柄已显式释放，正常机器上
/// 条目会在首个轮询内消失；若 SCM 仍处于 marked-for-delete，卸载仍按 DeleteService
/// 成功返回，下一次安装会复用 install 侧的 wait_service_removed 重试（service.rs:284），
/// 因此卸载侧可以更激进地缩短等待。
const SERVICE_REMOVE_WAIT_TIMEOUT: Duration = Duration::from_millis(500);
const SERVICE_REMOVE_WAIT_POLL: Duration = Duration::from_millis(50);

/// engine 进程退出形态（D1）：驱动 main.rs 生命周期分叉。
///
/// - **oneshot**：engine 生命周期 = core 生命周期——core 进程句柄 signaled（正常关停随行
///   / 崩溃 / kill）**或**心跳超时（hung-core 硬时间界兜底）→ 自退。两者都是退出触发。
/// - **service**：engine 生命周期 = SCM——无心跳自清理、无 core-pid watch（无单一 core
///   可等）；SCM 停止控制码（`SERVICE_CONTROL_STOP`/`SHUTDOWN`）→ [`Self::Service`] 的
///   `scm_stop` 信号 → 退出清理路径。
pub enum EngineExitForm {
    /// oneshot：engine 生命周期 = core 生命周期。
    Oneshot {
        /// core（host）进程 PID——engine 侧 `OpenProcess` 等待其退出（随行兜底）。
        core_handle: u32,
        /// 心跳超时上界（毫秒；硬时间界兜底，默认 [`crate::heartbeat::HEARTBEAT_TIMEOUT_MS`]）。
        heartbeat_timeout: u64,
    },
    /// service：engine 生命周期 = SCM。
    Service {
        /// SCM 停止信号（ServiceMain 收到 `SERVICE_CONTROL_STOP`/`SHUTDOWN` 后置位 true）。
        scm_stop: tokio::sync::watch::Receiver<bool>,
    },
}

impl EngineExitForm {
    /// oneshot 是否启用心跳自清理（**service 形态禁用**——SCM 管生死，无心跳 watchdog）。
    #[must_use]
    pub fn uses_heartbeat(&self) -> bool {
        matches!(self, EngineExitForm::Oneshot { .. })
    }

    /// oneshot 是否启用 core 进程句柄监视（**service 形态禁用**——服务常驻，无单一 core
    /// 可等）。
    #[must_use]
    pub fn uses_core_process_watch(&self) -> bool {
        matches!(self, EngineExitForm::Oneshot { .. })
    }

    /// oneshot 的 core 句柄（PID）；service 形态返回 `None`。
    #[must_use]
    pub fn core_handle(&self) -> Option<u32> {
        match self {
            EngineExitForm::Oneshot { core_handle, .. } => Some(*core_handle),
            EngineExitForm::Service { .. } => None,
        }
    }

    /// oneshot 的心跳超时上界（毫秒）；service 形态返回 `None`。
    #[must_use]
    pub fn heartbeat_timeout(&self) -> Option<u64> {
        match self {
            EngineExitForm::Oneshot { heartbeat_timeout, .. } => Some(*heartbeat_timeout),
            EngineExitForm::Service { .. } => None,
        }
    }
}

/// 服务安装可选参数（从 `--service-install` 命令行读取；缺省回退默认）。
#[derive(Debug)]
pub struct ServiceInstallOptions {
    /// wintun.dll 路径（注册进服务启动参数，ServiceMain 用它建数据面）。
    pub dll: PathBuf,
    /// 创建的 adapter 名。
    pub adapter_name: String,
    /// 授权 core 用户 SID（安装用户；服务引擎用它建控制面管道 DACL + 每次 accept 验证）。
    pub core_user_sid: String,
    /// 用户配置目录（服务以 LocalSystem 运行，不能依赖它自己的 `%USERPROFILE%`）。
    pub config_dir: PathBuf,
}

/// 解析服务安装可选参数（`--dll`/`--adapter-name`/`--user-sid`/`--config-dir`；缺省回退）。`--user-sid`
/// 缺省回退当前进程用户 SID（runas 提权保持同一用户 SID——安装用户即 core 用户）。
///
/// # Errors
/// 显式 `--config-dir` 不是绝对目录、服务配置目录回退值不是绝对目录，或当前用户 SID
/// 无法解析（且未显式传 `--user-sid`）→ fail closed（服务管道 DACL 必须有授权 SID）。
pub fn parse_install_options(argv: &[String]) -> Result<ServiceInstallOptions, String> {
    let mut dll = default_wintun_dll_path();
    let mut adapter_name = ENGINE_ADAPTER_NAME.to_string();
    let mut user_sid: Option<String> = None;
    let mut config_dir = exv_vpn_win32_config::config_dir();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--dll" => dll = PathBuf::from(argv.get(i + 1).cloned().unwrap_or_default()),
            "--adapter-name" => {
                adapter_name = argv.get(i + 1).cloned().unwrap_or_default();
            }
            "--user-sid" => user_sid = argv.get(i + 1).cloned(),
            "--config-dir" => {
                let value = argv.get(i + 1).ok_or_else(|| {
                    "--config-dir requires an absolute directory path".to_string()
                })?;
                let path = PathBuf::from(value);
                if value.is_empty() || value.starts_with("--") || !path.is_absolute() {
                    return Err("--config-dir requires an absolute directory path".to_string());
                }
                config_dir = path;
            }
            _ => {} // 未知参数忽略（前向兼容；含 --service-install 本身）。
        }
        i += 1;
    }
    if config_dir.as_os_str().is_empty() || !config_dir.is_absolute() {
        return Err("--config-dir must resolve to an absolute directory path".to_string());
    }
    let core_user_sid = match user_sid.filter(|s| !s.is_empty()).or_else(current_user_sid) {
        Some(sid) => sid,
        None => return Err("cannot resolve core user SID for service pipe DACL".to_string()),
    };
    Ok(ServiceInstallOptions {
        dll,
        adapter_name,
        core_user_sid,
        config_dir,
    })
}

/// wintun.dll 冻结默认路径（`%USERPROFILE%\.exv\...`；与 host `process_lifecycle` 一致）。
#[must_use]
fn default_wintun_dll_path() -> PathBuf {
    let home = std::env::var_os("USERPROFILE").unwrap_or_else(|| ".".into());
    PathBuf::from(home)
        .join(".exv")
        .join("wintun")
        .join("wintun")
        .join("bin")
        .join("amd64")
        .join("wintun.dll")
}

/// 当前进程用户 SID（与 acceptance `peer_auth` 同源）。
#[must_use]
fn current_user_sid() -> Option<String> {
    exv_vpn_win32_ipc::peer_auth::current_user_sid()
}

/// SCM 错误 → 携带原因的字符串。
pub(crate) fn scm_error(e: windows_service::Error) -> String {
    format!("service control manager: {e}")
}

/// 是否「服务已存在」类错误（ERROR_SERVICE_EXISTS=1073 / ERROR_SERVICE_MARKED_FOR_DELETE
/// =1072）——安装修复路径的判据。
fn service_exists(e: &windows_service::Error) -> bool {
    match e {
        windows_service::Error::Winapi(io_err) => {
            matches!(io_err.raw_os_error(), Some(1073 | 1072))
        }
        _ => false,
    }
}

/// 是否「服务已不存在」或「已经在删除中」——卸载是幂等操作，重复调用时两者都
/// 应进入收尾路径，而不是再次向 SCM 提交 DeleteService。
fn service_absent_or_marked_for_delete(e: &windows_service::Error) -> bool {
    match e {
        windows_service::Error::Winapi(io_err) => {
            matches!(io_err.raw_os_error(), Some(1060 | 1072))
        }
        _ => false,
    }
}

pub(crate) fn service_not_found(e: &windows_service::Error) -> bool {
    matches!(
        e,
        windows_service::Error::Winapi(io_err) if io_err.raw_os_error() == Some(1060)
    )
}

pub(crate) fn service_marked_for_delete(e: &windows_service::Error) -> bool {
    matches!(
        e,
        windows_service::Error::Winapi(io_err) if io_err.raw_os_error() == Some(1072)
    )
}

/// 服务启动参数（SCM 启动时传给 ServiceMain）：`--service` + 控制面稳定管道 + dll +
/// adapter 名 + 授权 SID + 用户配置目录。
fn service_launch_arguments(options: &ServiceInstallOptions) -> Vec<OsString> {
    vec![
        OsString::from("--service"),
        OsString::from("--control-pipe"),
        OsString::from(SERVICE_CONTROL_PIPE),
        OsString::from("--dll"),
        OsString::from(&options.dll),
        OsString::from("--adapter-name"),
        OsString::from(&options.adapter_name),
        OsString::from("--user-sid"),
        OsString::from(&options.core_user_sid),
        OsString::from("--config-dir"),
        OsString::from(&options.config_dir),
    ]
}

/// 安装（或修复）engine SCM 服务（`--service-install`）。本机 admin（runas 提权边界内）。
///
/// - 新建：`CreateService`（LocalSystem，OnDemand/manual 启动，D10）+ failure actions。
/// - 已存在：修复路径——`ChangeServiceConfig` 重配启动参数 + 重设 failure actions。
///
/// # Errors
/// 安装参数解析失败（SID 不可得）或 SCM 操作失败（非提权 / 服务冲突）→ 携带原因的字符串。
pub fn install_service(argv: &[String]) -> Result<(), String> {
    let options = parse_install_options(argv)?;
    let exe = std::env::current_exe().map_err(|e| format!("cannot resolve engine bin: {e}"))?;
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)
            .map_err(scm_error)?;
    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        // 产品预期：服务常驻待命、不会倒下（开机自启 + 失败动作重启）。连接侧仍有
        // PromptStart 兜底（已装未跑 → connect 先启动），此处自启覆盖「打开 UI 服务
        // 总是停止」的体验问题。
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: service_launch_arguments(&options),
        dependencies: vec![],
        account_name: None, // LocalSystem（特权服务）。
        account_password: None,
    };
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::STOP;
    match manager.create_service(&service_info, access) {
        Ok(service) => {
            // failure-actions 是崩溃后的增强保护，不应阻断服务主体安装或 PSK 写入。
            // 某些 SCM 权限/系统版本组合可能拒绝 ChangeServiceConfig2；核心安装仍可
            // 安全完成，后续启动由 ServiceMain 自身的非零退出负责暴露初始化失败。
            if let Err(error) = service.update_failure_actions(restart_failure_actions()) {
                eprintln!("warning: configure service failure actions: {}", scm_error(error));
            }
        }
        Err(e) if service_marked_for_delete(&e) => {
            // 上一次卸载已成功调用 DeleteService，但 SCM 尚未释放 marked-for-delete
            // 条目。把等待放在新的 install 尝试上，而不是让 uninstall 本身承担长轮询。
            if !wait_service_removed() {
                return Err(
                    "service remains marked for delete; retry install after SCM settles".to_string(),
                );
            }
            let service = manager
                .create_service(&service_info, access)
                .map_err(scm_error)?;
            if let Err(error) = service.update_failure_actions(restart_failure_actions()) {
                eprintln!("warning: configure service failure actions: {}", scm_error(error));
            }
        }
        Err(e) if service_exists(&e) => {
            // 修复路径：已安装 → 重配启动参数 + 重设 failure actions（幂等安装）。
            // 运行中的服务不能只换配置/PSK：旧进程仍持有旧 PSK，随后 Core 用新 PSK
            // 连接必然失败。先停到 Stopped，再改配置并轮换密钥；调用方随后统一负责
            // bootstrap start。
            let service = manager.open_service(SERVICE_NAME, access).map_err(scm_error)?;
            stop_service_instance(&service)?;
            service.change_config(&service_info).map_err(scm_error)?;
            if let Err(error) = service.update_failure_actions(restart_failure_actions()) {
                eprintln!("warning: configure service failure actions: {}", scm_error(error));
            }
        }
        Err(e) => return Err(scm_error(e)),
    }

    // S3/D2 + M14：每次安装（含修复）都**轮换**服务 PSK——生成新 32 字节随机密钥写
    // `%ProgramData%\exv\service.key`（DACL = SYSTEM + 安装用户）。engine 服务启动时读
    // 新 key；旧 key 的既有连接断开即失效（服务重启读新 key 后）。重装 = 撤销旧密钥。
    let _new_psk = exv_vpn_win32_ipc::service_key::write_service_psk(&options.core_user_sid)
        .map_err(|e| format!("write service PSK: {e}"))?;
    // 服务引擎（LocalSystem）组装时 `load_config()` 读用户 config.json；该文件显式
    // ACL 通常只含安装用户（凭据保护），LocalSystem 读被拒（ACCESS_DENIED → 服务模式
    // 连接组装失败）。安装（提权）时给 SYSTEM 授予读权限，服务才可读 server/user_agent/
    // routes（凭据经 wire 传，不落盘）。best-effort：授权失败不阻断安装（core 可后续修复）。
    grant_system_read_config(&options.config_dir);
    Ok(())
}

/// 给 `config_dir/config.json` 授予 `NT AUTHORITY\SYSTEM` 读权限（服务引擎 LocalSystem
/// 读用户配置所需）。best-effort：失败仅记 warning，不阻断安装。
fn grant_system_read_config(config_dir: &std::path::Path) {
    let config_path = config_dir.join("config.json");
    if !config_path.is_file() {
        return;
    }
    let status = std::process::Command::new("icacls")
        .arg(&config_path)
        .args(["/grant", r"*S-1-5-18:(R)"])
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("warning: grant SYSTEM read on config: icacls exit {:?}", s.code()),
        Err(e) => eprintln!("warning: grant SYSTEM read on config: {e}"),
    }
}

/// 卸载 engine SCM 服务（`--service-uninstall`）。运行中先停（干净删除）再
/// `DeleteService`。
///
/// R3 卸载对策：`DeleteService` 成功后清理残留——有界轮询等服务条目完全移除（避免
/// 立即重装撞 `ERROR_SERVICE_MARKED_FOR_DELETE`=1072 窗口）+ 删除孤儿 PSK（卸载不彻底
/// 的载荷残留会误导健康模型 `HealthState::PayloadOrphan`）。轮询超时**不**视为卸载失败
/// （`DeleteService` 已成功，条目最终由 SCM 清场）；PSK 删除失败则诚实上报。
///
/// # Errors
/// SCM 打开 / 查询 / 停止 / 删除失败（服务未安装或已在删除中按幂等成功处理）或残留
/// PSK 清理失败 → 携带原因的字符串。
pub fn uninstall_service() -> Result<(), String> {
    let t_total = Instant::now();
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(scm_error)?;
    let service = match manager.open_service(
        SERVICE_NAME,
        ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(service) => service,
        Err(error) if service_absent_or_marked_for_delete(&error) => {
            let cleanup_result = uninstall_cleanup(
                wait_service_removed,
                exv_vpn_win32_ipc::service_key::delete_service_psk,
            );
            cleanup_result.map_err(|e| format!("uninstall cleanup: {e}"))?;
            tracing::info!("uninstall cleanup-only (already absent)");
            return Ok(());
        }
        Err(error) => return Err(scm_error(error)),
    };
    // `stop_service_instance` 是唯一的停止入口：它观察 StartPending/Running/
    // StopPending 并在 Stopped 后才继续。这里不能先发一个被忽略错误的 stop 再调用
    // 第二套停止逻辑，否则"停止完成"与"删除完成"在调用链上难以区分，也会制造
    // 额外的 SCM 状态竞态。
    let t = Instant::now();
    stop_service_instance(&service)?;
    eprintln!("[exv-uninstall] stop_service_instance: {}ms", t.elapsed().as_millis());
    // 到这里才进入真正的卸载阶段。DeleteService 成功是卸载事务的业务完成点；SCM
    // 可能因 services.msc 等外部句柄短暂保留 marked-for-delete，但这不应再被 Core
    // 回传成 installed=true（由 Core 的 service_removed_override 处理）。
    let t = Instant::now();
    service.delete().map_err(scm_error)?;
    eprintln!("[exv-uninstall] DeleteService: {}ms", t.elapsed().as_millis());
    // DeleteService 只把条目标记为待删除；最后一个 service handle 释放后 SCM
    // 才能真正移除条目。若在这里继续持有 `service`，下面的 bounded wait 会必然
    // 等满超时，导致卸载看起来像卡死并拖慢下一次 install。
    drop(service);
    let t = Instant::now();
    let cleanup_result = uninstall_cleanup(
        wait_service_removed,
        exv_vpn_win32_ipc::service_key::delete_service_psk,
    );
    cleanup_result.map_err(|e| format!("uninstall cleanup: {e}"))?;
    eprintln!("[exv-uninstall] cleanup (wait_removed+delete_psk): {}ms", t.elapsed().as_millis());
    eprintln!("[exv-uninstall] total: {}ms", t_total.elapsed().as_millis());
    Ok(())
}

/// SCM 的重复状态返回码：把同一目标状态视为幂等成功。
fn service_already_running(e: &windows_service::Error) -> bool {
    matches!(
        e,
        windows_service::Error::Winapi(io_err) if io_err.raw_os_error() == Some(1056)
    )
}

fn service_not_active(e: &windows_service::Error) -> bool {
    matches!(
        e,
        windows_service::Error::Winapi(io_err) if io_err.raw_os_error() == Some(1062)
    )
}

fn service_cannot_accept_control(e: &windows_service::Error) -> bool {
    matches!(
        e,
        windows_service::Error::Winapi(io_err) if io_err.raw_os_error() == Some(1061)
    )
}

/// 停止请求的结果：1061 是另一个控制者正在改变服务状态时的瞬态拒绝，应重新查询后有限重试。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StopRequestResult {
    Requested,
    AlreadyStopped,
    Retry,
}

const MAX_STOP_REQUEST_ATTEMPTS: u8 = 3;

/// 轮询服务状态直到彻底进入 Stopped。
///
/// 把轮询器与具体 SCM 句柄分开，既保证所有停止入口共享同一语义，也让单元测试能够
/// 覆盖"请求已提交但仍处于 StopPending"的窗口。
fn wait_for_service_stopped<Query, Request>(
    timeout: Duration,
    poll: Duration,
    mut query_status: Query,
    mut request_stop: Request,
) -> Result<(), String>
where
    Query: FnMut() -> Result<ServiceState, String>,
    Request: FnMut() -> Result<StopRequestResult, String>,
{
    let deadline = std::time::Instant::now() + timeout;
    let mut stop_requested = false;
    let mut stop_attempts = 0u8;
    loop {
        let state = query_status()?;
        if state == ServiceState::Stopped {
            return Ok(());
        }
        // StartPending/ContinuePending/PausePending 先等待状态转换；稳定 Running 或 Paused
        // 都可以接受 Stop。StopPending 只等待 SCM 最终报告 Stopped，绝不重复发控制码。
        if matches!(state, ServiceState::Running | ServiceState::Paused)
            && !stop_requested
            && stop_attempts < MAX_STOP_REQUEST_ATTEMPTS
        {
            stop_attempts += 1;
            match request_stop()? {
                StopRequestResult::Requested | StopRequestResult::AlreadyStopped => {
                    stop_requested = true;
                }
                StopRequestResult::Retry => {}
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "service did not stop within {}ms (state={:?})",
                timeout.as_millis(),
                state
            ));
        }
        std::thread::sleep(poll);
    }
}

/// 请求停止并等待服务彻底进入 Stopped，避免 ChangeServiceConfig/DeleteService 与
/// SCM 的 StopPending 窗口交叉。等待有界，失败明确返回，不把前端留在无限"操作中"。
fn stop_service_instance(service: &Service) -> Result<(), String> {
    wait_for_service_stopped(
        SERVICE_STOP_TIMEOUT,
        Duration::from_millis(100),
        || {
            service
                .query_status()
                .map(|status| status.current_state)
                .map_err(scm_error)
        },
        || match service.stop() {
            Ok(_) => Ok(StopRequestResult::Requested),
            // 另一个控制请求已经让服务离开 Running；继续查询真实状态，不提前返回。
            Err(error) if service_not_active(&error) => Ok(StopRequestResult::AlreadyStopped),
            // services.msc/SCM 并发控制造成的 1061 只表示本次控制码没有被接受；
            // 外层会重新查询状态并有限重试，避免把瞬态竞态误报成停止失败。
            Err(error) if service_cannot_accept_control(&error) => Ok(StopRequestResult::Retry),
            Err(error) => Err(scm_error(error)),
        },
    )
}

/// 卸载收尾（R3）：SCM 条目 `DeleteService` 成功后清理残留载荷。
///
/// 顺序契约（单测锚定）：先有界轮询等服务条目完全移除，再删孤儿 PSK。两者都不可提前
/// 于条目删除（条目删除是 `uninstall_service` 的 SCM 前置步骤，本函数只承接删除后的
/// 收尾）。PSK 删除失败 → 诚实上报（载荷残留会让后续健康模型误判 PayloadOrphan）。
fn uninstall_cleanup(
    wait_removed: impl FnOnce() -> bool,
    delete_psk: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    let _removed = wait_removed();
    delete_psk()
}

/// DeleteService 后有界轮询等服务条目完全移除（上限 1500ms / 间隔 50ms）。
///
/// SCM 在最后一个句柄释放前将条目标记为待删除（marked-for-delete）：期间
/// `OpenServiceW` 仍可成功但 `CreateService` 报 1072——立即重装会撞窗。轮询直至
/// 打不开服务（= 服务不存在 1060）即移除完成。SCM 打开失败 → 无从确认，按已移除
/// 处理（best-effort；条目删除已成功）。
fn wait_service_removed() -> bool {
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return true; // SCM 打开失败：无从确认，按已移除处理（best-effort）。
    };
    let deadline = std::time::Instant::now() + SERVICE_REMOVE_WAIT_TIMEOUT;
    loop {
        match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
            Ok(_) => {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(SERVICE_REMOVE_WAIT_POLL);
            }
            Err(error) if service_not_found(&error) => return true, // 条目已完全移除。
            Err(error) if service_marked_for_delete(&error) => {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(SERVICE_REMOVE_WAIT_POLL);
            }
            Err(_) => return true, // 其它打开失败：按 best-effort 视为条目已不可见。
        }
    }
}

/// 启动 engine SCM 服务（`--service-start`）。
///
/// # Errors
/// SCM 打开 / 启动失败（含服务未安装）→ 携带原因的字符串。
pub fn start_service() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(scm_error)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::START)
        .map_err(scm_error)?;
    match service.start::<&str>(&[]) {
        Ok(()) => {}
        Err(error) if service_already_running(&error) => {}
        Err(error) => return Err(scm_error(error)),
    }
    Ok(())
}

/// SCM failure actions（CR R3.1）：崩溃后由 SCM 以 `SC_ACTION_RESTART` 重新拉起。
///
/// reset_period 86_400s（24h）：失败计数无新失败即归零；delay 1s：崩溃后 1 秒重启。
#[must_use]
pub fn restart_failure_actions() -> ServiceFailureActions {
    ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(1),
        }]),
    }
}

// ---------------------------------------------------------------------------
// 单元测试：EngineExitForm 分派（service 禁用心跳 / core-pid watch）+ 子命令解析 +
// failure actions（纯逻辑；SCM 真机集成在 tests/service_lifecycle.rs，env 门控）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// oneshot 形态：启用心跳自清理 + core 进程句柄监视；暴露 core_handle/heartbeat_timeout。
    #[test]
    fn oneshot_form_enables_heartbeat_and_core_watch() {
        let form = EngineExitForm::Oneshot {
            core_handle: 4242,
            heartbeat_timeout: 15_000,
        };
        assert!(form.uses_heartbeat(), "oneshot 必须启用心跳自清理");
        assert!(
            form.uses_core_process_watch(),
            "oneshot 必须启用 core 进程句柄监视"
        );
        assert_eq!(form.core_handle(), Some(4242));
        assert_eq!(form.heartbeat_timeout(), Some(15_000));
    }

    /// service 形态：**禁用心跳自清理 + core-pid watch**（SCM 管生死）；无 core_handle。
    #[test]
    fn service_form_disables_heartbeat_and_core_watch() {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let form = EngineExitForm::Service { scm_stop: rx };
        assert!(
            !form.uses_heartbeat(),
            "service 形态必须禁用心跳自清理（SCM 管生死）"
        );
        assert!(
            !form.uses_core_process_watch(),
            "service 形态必须禁用 core 进程句柄监视（无单一 core 可等）"
        );
        assert_eq!(form.core_handle(), None);
        assert_eq!(form.heartbeat_timeout(), None);
        let _ = tx;
    }

    /// failure actions（CR R3.1）：SC_ACTION_RESTART 在 1s 延迟；reset 24h。
    #[test]
    fn restart_failure_actions_restart_after_crash() {
        let actions = restart_failure_actions();
        let list = actions.actions.expect("actions present");
        assert_eq!(list.len(), 1, "单一 SC_ACTION_RESTART");
        assert_eq!(list[0].action_type, ServiceActionType::Restart);
        assert_eq!(list[0].delay, Duration::from_secs(1));
    }

    /// 服务安装参数解析：显式 `--dll`/`--adapter-name`/`--user-sid` 覆盖缺省。
    #[test]
    fn parse_install_options_honors_overrides() {
        let argv = vec![
            "exv-engine".to_string(),
            "--service-install".to_string(),
            "--dll".to_string(),
            r"C:\custom\wintun.dll".to_string(),
            "--adapter-name".to_string(),
            "MyAdapter".to_string(),
            "--user-sid".to_string(),
            "S-1-5-21-1-2-3-4".to_string(),
            "--config-dir".to_string(),
            r"C:\Users\Alice\.exv".to_string(),
        ];
        let opts = parse_install_options(&argv).expect("parse");
        assert_eq!(opts.dll, PathBuf::from(r"C:\custom\wintun.dll"));
        assert_eq!(opts.adapter_name, "MyAdapter");
        assert_eq!(opts.core_user_sid, "S-1-5-21-1-2-3-4");
        assert_eq!(opts.config_dir, PathBuf::from(r"C:\Users\Alice\.exv"));
    }

    /// 显式配置目录缺少值时必须 fail closed，不能变成空路径或相对路径。
    #[test]
    fn parse_install_options_rejects_invalid_config_dir_value() {
        for value in [None, Some(""), Some("--dll"), Some("relative\\.exv")] {
            let mut argv = vec![
                "exv-engine".to_string(),
                "--service-install".to_string(),
                "--config-dir".to_string(),
            ];
            if let Some(value) = value {
                argv.push(value.to_string());
            }
            let error = parse_install_options(&argv)
                .err()
                .expect("invalid config dir must fail");
            assert!(error.contains("--config-dir"), "error should name the option: {error}");
        }
    }

    /// 服务安装参数解析：全部缺省时回退默认（dll 默认路径 + adapter 默认名 + 当前用户 SID）。
    #[test]
    fn parse_install_options_falls_back_to_defaults() {
        let argv = vec!["exv-engine".to_string(), "--service-install".to_string()];
        let opts = parse_install_options(&argv).expect("parse with defaults");
        assert!(
            opts.dll.to_string_lossy().contains("wintun.dll"),
            "缺省 dll 必须含 wintun.dll，got {}",
            opts.dll.display()
        );
        assert_eq!(opts.adapter_name, ENGINE_ADAPTER_NAME);
        // 缺省 SID = 当前用户 SID；SID 不可解析（极罕见）时诚实短路。
        if let Some(sid) = current_user_sid() {
            assert_eq!(opts.core_user_sid, sid);
        }
    }

    /// 服务启动参数契约：`--service` + 稳定控制管道 + dll + adapter + SID（ServiceMain
    /// 解析所需字段齐备）。
    #[test]
    fn service_launch_arguments_contain_required_fields() {
        let opts = ServiceInstallOptions {
            dll: PathBuf::from(r"C:\wintun\wintun.dll"),
            adapter_name: ENGINE_ADAPTER_NAME.to_string(),
            core_user_sid: "S-1-5-21-1-2-3-4".to_string(),
            config_dir: PathBuf::from(r"C:\Users\Alice\.exv"),
        };
        let args = service_launch_arguments(&opts);
        let joined = args
            .iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(joined.contains("--service"), "必须含 --service");
        assert!(joined.contains(SERVICE_CONTROL_PIPE), "必须含稳定控制管道");
        assert!(joined.contains(r"C:\wintun\wintun.dll"), "必须含 dll");
        assert!(joined.contains(ENGINE_ADAPTER_NAME), "必须含 adapter 名");
        assert!(joined.contains("S-1-5-21-1-2-3-4"), "必须含授权 SID");
        assert!(joined.contains(r"C:\Users\Alice\.exv"), "必须含用户配置目录");
    }

    /// 停止命令必须等待 StopPending 结束，而不能把"停止请求已提交"当作 Stopped。
    #[test]
    fn stop_poll_waits_for_stopped_after_request() {
        let mut states = [
            ServiceState::Running,
            ServiceState::StopPending,
            ServiceState::Stopped,
        ]
        .into_iter();
        let mut requests = 0;

        wait_for_service_stopped(
            Duration::from_secs(1),
            Duration::ZERO,
            || Ok(states.next().unwrap_or(ServiceState::Stopped)),
            || {
                requests += 1;
                Ok(StopRequestResult::Requested)
            },
        )
        .expect("stop poll reaches Stopped");

        assert_eq!(requests, 1, "只应向 SCM 提交一次停止请求");
    }

    /// StartPending 先收敛到 Running 时，停止器仍应继续完成完整停止收敛。
    #[test]
    fn stop_poll_waits_through_start_pending() {
        let mut states = [
            ServiceState::StartPending,
            ServiceState::Running,
            ServiceState::StopPending,
            ServiceState::Stopped,
        ]
        .into_iter();
        let mut requests = 0;

        wait_for_service_stopped(
            Duration::from_secs(1),
            Duration::ZERO,
            || Ok(states.next().unwrap_or(ServiceState::Stopped)),
            || {
                requests += 1;
                Ok(StopRequestResult::Requested)
            },
        )
        .expect("start pending should converge to stopped");

        assert_eq!(requests, 1);
    }

    /// 已暂停服务也能直接接受 Stop，不应无谓等待到超时。
    #[test]
    fn stop_poll_requests_stop_for_paused_service() {
        let mut states = [
            ServiceState::Paused,
            ServiceState::StopPending,
            ServiceState::Stopped,
        ]
        .into_iter();
        let mut requests = 0;

        wait_for_service_stopped(
            Duration::from_secs(1),
            Duration::ZERO,
            || Ok(states.next().unwrap_or(ServiceState::Stopped)),
            || {
                requests += 1;
                Ok(StopRequestResult::Requested)
            },
        )
        .expect("paused service should converge to stopped");

        assert_eq!(requests, 1);
    }

    /// services.msc/SCM 并发控制造成的 1061 是可重试竞态；观察到 StopPending 后继续等待。
    #[test]
    fn stop_poll_retries_transient_control_rejection() {
        let mut states = [
            ServiceState::Running,
            ServiceState::Running,
            ServiceState::StopPending,
            ServiceState::Stopped,
        ]
        .into_iter();
        let mut outcomes = [StopRequestResult::Retry, StopRequestResult::Requested].into_iter();
        let mut requests = 0;

        wait_for_service_stopped(
            Duration::from_secs(1),
            Duration::ZERO,
            || Ok(states.next().unwrap_or(ServiceState::Stopped)),
            || {
                requests += 1;
                Ok(outcomes.next().unwrap_or(StopRequestResult::Requested))
            },
        )
        .expect("transient control rejection should be retried");

        assert_eq!(requests, 2);
    }

    /// 服务名/管道名常量形态（UI/SCM 契约的稳定标识）。
    #[test]
    fn service_constants_are_well_formed() {
        assert!(!SERVICE_NAME.is_empty());
        assert!(!SERVICE_DISPLAY_NAME.is_empty());
        assert!(SERVICE_CONTROL_PIPE.starts_with(r"\\.\pipe\"));
        assert!(SERVICE_CONTROL_PIPE.ends_with("-c"), "控制面管道 -c 后缀");
    }

    /// R3 卸载收尾顺序契约：先有界轮询等服务条目完全移除，再删孤儿 PSK（载荷残留清理
    /// 必须在条目删除之后——条目删除是 `uninstall_service` 的 SCM 前置步骤）。
    #[test]
    fn uninstall_cleanup_waits_removal_then_deletes_psk() {
        // 两个闭包都要记录顺序 → 共享 `Rc<RefCell>`（同一 `order` 的双可变借用）。
        use std::cell::RefCell;
        use std::rc::Rc;
        let order = Rc::new(RefCell::new(Vec::new()));
        uninstall_cleanup(
            {
                let order = Rc::clone(&order);
                move || {
                    order.borrow_mut().push("wait_removed");
                    true
                }
            },
            {
                let order = Rc::clone(&order);
                move || {
                    order.borrow_mut().push("delete_psk");
                    Ok(())
                }
            },
        )
        .expect("cleanup must succeed");
        assert_eq!(*order.borrow(), vec!["wait_removed", "delete_psk"]);
    }

    /// R3 卸载收尾：PSK 删除失败 → 诚实上报（载荷残留会让健康模型误判 PayloadOrphan）；
    /// 轮询结果被忽略（`DeleteService` 已成功，超时不是卸载失败）。
    #[test]
    fn uninstall_cleanup_propagates_psk_delete_error_but_ignores_wait_timeout() {
        // 轮询超时（false）不阻塞清理；PSK 删除失败照常上报。
        let err = uninstall_cleanup(
            || {
                false // wait timed out
            },
            || Err("disk full".to_string()),
        )
        .expect_err("psk delete failure must surface");
        assert_eq!(err, "disk full");

        // 轮询成功 + PSK 成功 → Ok。
        uninstall_cleanup(
            || true,
            || Ok(()),
        )
        .expect("cleanup ok");
    }
}
