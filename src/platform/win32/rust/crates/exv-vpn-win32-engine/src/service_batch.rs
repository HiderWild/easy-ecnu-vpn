// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// S2-A：engine `--service-batch` 批量提权模式——一次 runas 拉起完成完整服务操作序列
// （1 次 UAC）。host 经临时文件传请求 / 收结果：
//   `engine.exe --service-batch --request <req-file> --result <res-file> --host-pid <pid>`
// （ShellExecuteExW 拿不到 stdio，用临时文件；`--host-pid` 由 S2-B 用于防孤儿）。
//
// 安全边界（阶段 2 方案文档）：
// - **只 dispatch 固定 [`BatchStep`] 枚举**——不执行任意命令、不拼接 shell。
// - 请求体 ≤ [`MAX_REQUEST_BYTES`]；`version == 1`；序列 ≤ [`MAX_BATCH_STEPS`]；
//   `config_dir` 绝对路径；`deny_unknown_fields`（多余字段被拒）。
// - 任一步失败 → **中止后续**，result ok=false + 非零退出码。
// - 文件生命周期：读 req（≤64KB）→ 执行 → 写 result → **finally 删除 req；result 由 host 读后删**
//   （提权进程不残留请求/结果临时文件）。
// - Verify 探活复用 `SERVICE_CONTROL_PIPE` + PSK-HMAC（gRPC KeepAlive RPC 干净收尾，
//   不把常驻服务 accept-loop 留在残缺连接上）。

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tonic::codegen::http::Uri;
use tonic::codegen::Service;
use tonic::transport::Endpoint;

use crate::service::{
    install_service, scm_error, service_not_found, start_service, uninstall_service,
    SERVICE_CONTROL_PIPE, SERVICE_NAME,
};
use exv_vpn_win32_ipc::peer_auth::{
    decode_identity_frame, IDENTITY_FRAME_HEADER_LEN, IDENTITY_FRAME_MAX_SID_LEN, SYSTEM_SID,
};
use exv_vpn_win32_ipc::service_key::{ct_eq, hmac_sha256, random_32};
use exv_vpn_wire::generated;
use generated::helper_control_client::HelperControlClient;

/// 批量协议版本（唯一接受 1）。
pub const BATCH_VERSION: u32 = 1;
/// 单次批量序列步数上限（防恶意超大序列占住提权进程）。
pub const MAX_BATCH_STEPS: usize = 8;
/// 请求体大小上限（64 KiB）。
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Verify 步骤 keepalive 探活超时（默认 30s）。
pub const VERIFY_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(30);
/// Verify 步骤等待 SCM 进入 Running 的超时（Start 后服务先 StartPending，再 Running）。
pub const VERIFY_SCM_RUNNING_TIMEOUT: Duration = Duration::from_secs(30);
/// SCM Running 轮询间隔。
const SCM_POLL_INTERVAL: Duration = Duration::from_millis(250);

// ---------------------------------------------------------------------------
// Wire 类型（serde JSON；`deny_unknown_fields`——host 侧旧字段/拼写错误在解析即拒）。
// ---------------------------------------------------------------------------

/// 一次批量提权请求（host 写入 `<req-file>`；engine 读取执行）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBatchRequest {
    /// 协议版本（必须等于 [`BATCH_VERSION`]）。
    pub version: u32,
    /// 顺序执行的步骤序列（≤ [`MAX_BATCH_STEPS`]；无 Stop——停止线已在阶段 1 移除）。
    pub sequence: Vec<BatchStep>,
    /// 用户配置目录（绝对路径；Install 步骤注册进服务启动参数）。
    pub config_dir: String,
}

/// 批量步骤（**固定枚举**，无任意命令执行入口）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStep {
    /// SCM 安装（含 REPAIR 语义，复用 `install_service`）。
    Install,
    /// SCM 启动。
    Start,
    /// SCM 卸载（内部先停，复用 `uninstall_service`）。
    Uninstall,
    /// 检查 SCM Running + keepalive 探活（`SERVICE_CONTROL_PIPE` + PSK-HMAC）。
    Verify,
    /// 检查 SCM 服务已不存在。
    VerifyRemoved,
}

/// 单步执行结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchStepResult {
    /// 该步对应的步骤。
    pub step: BatchStep,
    /// 是否成功。
    pub ok: bool,
    /// 成功 = 描述；失败 = 携带原因。
    pub message: String,
}

/// 批量执行结果（engine 写入 `<result-file>`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBatchResult {
    /// 全部步骤成功。
    pub ok: bool,
    /// 逐步骤结果（失败即中止；仅含已执行步骤）。
    pub steps: Vec<BatchStepResult>,
    /// 总述（成功 = "batch completed"；失败 = 定位到失败步骤）。
    pub message: String,
}

// ---------------------------------------------------------------------------
// 校验（纯逻辑，可单测）
// ---------------------------------------------------------------------------

/// 校验请求形状：version == 1、序列 ≤ [`MAX_BATCH_STEPS`]、`config_dir` 绝对路径。
///
/// # Errors
/// 任一校验不通过 → 携带原因的字符串（fail closed）。
pub fn validate_request(request: &ServiceBatchRequest) -> Result<(), String> {
    if request.version != BATCH_VERSION {
        return Err(format!(
            "unsupported batch version {} (expected {BATCH_VERSION})",
            request.version
        ));
    }
    if request.sequence.len() > MAX_BATCH_STEPS {
        return Err(format!(
            "batch sequence of {} steps exceeds limit {MAX_BATCH_STEPS}",
            request.sequence.len()
        ));
    }
    let config = PathBuf::from(&request.config_dir);
    if request.config_dir.is_empty() || !config.is_absolute() {
        return Err("batch config_dir must be an absolute directory path".to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 服务操作 seam（测试注入 fake；生产 = [`RealServiceOps`]）
// ---------------------------------------------------------------------------

/// 批量步骤对应的服务操作原语（可注入 seam——单测不触碰真 SCM/管道）。
///
/// 每个方法返回 `Err` 表示该步骤失败（携带原因；编排层随即中止后续步骤）。
pub trait BatchServiceOps {
    /// `Install`：SCM 安装（含 REPAIR）。
    ///
    /// # Errors
    /// SCM 安装 / 修复失败 → 携带原因的字符串。
    fn install(&mut self, config_dir: &str) -> Result<(), String>;
    /// `Start`：SCM 启动。
    ///
    /// # Errors
    /// SCM 启动失败（含服务未安装）→ 携带原因的字符串。
    fn start(&mut self) -> Result<(), String>;
    /// `Uninstall`：SCM 卸载（内部先停）。
    ///
    /// # Errors
    /// SCM 卸载 / 残留清理失败 → 携带原因的字符串。
    fn uninstall(&mut self) -> Result<(), String>;
    /// `Verify`：SCM Running + keepalive 探活。
    ///
    /// # Errors
    /// SCM 非 Running / 探活失败 / 超时 → 携带原因的字符串。
    fn verify(&mut self) -> Result<(), String>;
    /// `VerifyRemoved`：SCM 服务已不存在。
    ///
    /// # Errors
    /// 服务仍注册 / SCM 查询失败 → 携带原因的字符串。
    fn verify_removed(&mut self) -> Result<(), String>;
}

/// 生产服务操作：复用 `service.rs` 既有 SCM 原语 + `SERVICE_CONTROL_PIPE` keepalive 探活。
struct RealServiceOps;

impl BatchServiceOps for RealServiceOps {
    fn install(&mut self, config_dir: &str) -> Result<(), String> {
        // 复用 `install_service`：解析参数从 argv 读；`--config-dir` 显式传入，其余
        // 回退默认（dll 冻结路径 / adapter 默认名 / 当前用户 SID——runas 提权保持同用户）。
        let argv = vec![
            "exv-engine".to_string(),
            "--service-install".to_string(),
            "--config-dir".to_string(),
            config_dir.to_string(),
        ];
        install_service(&argv)
    }

    fn start(&mut self) -> Result<(), String> {
        start_service()
    }

    fn uninstall(&mut self) -> Result<(), String> {
        uninstall_service()
    }

    fn verify(&mut self) -> Result<(), String> {
        verify_service_ready()
    }

    fn verify_removed(&mut self) -> Result<(), String> {
        verify_service_removed()
    }
}

// ---------------------------------------------------------------------------
// 编排：顺序执行 + 任一步失败即中止（可注入 ops；单测走 fake）
// ---------------------------------------------------------------------------

/// 执行请求的完整序列并返回结果结构（不写文件；校验失败同样产出 ok=false 结果）。
fn execute_batch(request: &ServiceBatchRequest, ops: &mut dyn BatchServiceOps) -> ServiceBatchResult {
    if let Err(e) = validate_request(request) {
        return ServiceBatchResult {
            ok: false,
            steps: Vec::new(),
            message: e,
        };
    }
    let t_batch = Instant::now();
    let mut steps = Vec::with_capacity(request.sequence.len());
    for (index, step) in request.sequence.iter().enumerate() {
        let t_step = Instant::now();
        let outcome = match step {
            BatchStep::Install => ops.install(&request.config_dir),
            BatchStep::Start => ops.start(),
            BatchStep::Uninstall => ops.uninstall(),
            BatchStep::Verify => ops.verify(),
            BatchStep::VerifyRemoved => ops.verify_removed(),
        };
        let step_elapsed = t_step.elapsed().as_millis();
        eprintln!("[exv-batch] step {} ({}): ok={} elapsed={}ms", index, step_label(*step), outcome.is_ok(), step_elapsed);
        match outcome {
            Ok(()) => {
                steps.push(BatchStepResult {
                    step: *step,
                    ok: true,
                    message: step_label(*step).to_string(),
                });
            }
            Err(e) => {
                steps.push(BatchStepResult {
                    step: *step,
                    ok: false,
                    message: e.clone(),
                });
                return ServiceBatchResult {
                    ok: false,
                    steps,
                    message: format!("step {} ({}) failed: {e}", index + 1, step_label(*step)),
                };
            }
        }
    }
    let total_elapsed_ms = t_batch.elapsed().as_millis();
    eprintln!("[exv-batch] all steps completed: {} steps in {}ms", request.sequence.len(), total_elapsed_ms);
    ServiceBatchResult {
        ok: true,
        steps,
        message: "batch completed".to_string(),
    }
}

/// 步骤的稳定标签（结果消息 / 失败定位用）。
fn step_label(step: BatchStep) -> &'static str {
    match step {
        BatchStep::Install => "install",
        BatchStep::Start => "start",
        BatchStep::Uninstall => "uninstall",
        BatchStep::Verify => "verify",
        BatchStep::VerifyRemoved => "verify_removed",
    }
}

/// 执行批量并把 [`ServiceBatchResult`] 写入 `<result-path>`。
///
/// 任一校验失败 / 任一步失败 → result ok=false（仍写入），返回 `Err`（main 以非零码退）。
///
/// # Errors
/// 校验失败 / 任一步失败 / 结果文件写入失败 → 携带原因的字符串。
pub fn run_batch(request: &ServiceBatchRequest, result_path: &Path) -> Result<(), String> {
    run_batch_with_ops(request, result_path, &mut RealServiceOps)
}

/// [`run_batch`] 的可注入 ops 变体（单测用 fake ops，避免真 SCM/管道依赖）。
fn run_batch_with_ops(
    request: &ServiceBatchRequest,
    result_path: &Path,
    ops: &mut dyn BatchServiceOps,
) -> Result<(), String> {
    let result = execute_batch(request, ops);
    write_result(result_path, &result)?;
    if result.ok {
        Ok(())
    } else {
        Err(result.message)
    }
}

/// 把结果 JSON 写入 `<result-path>`（父目录由 host 保证存在）。
///
/// # Errors
/// 序列化 / 写文件失败 → 携带原因的字符串。
fn write_result(result_path: &Path, result: &ServiceBatchResult) -> Result<(), String> {
    let json = serde_json::to_string_pretty(result)
        .map_err(|e| format!("serialize batch result: {e}"))?;
    std::fs::write(result_path, json)
        .map_err(|e| format!("write batch result {}: {e}", result_path.display()))
}

/// 写一个仅含 message 的失败结果（请求解析/超限等执行前失败也要让 host 可诊断）。
fn write_error_result(result_path: &Path, message: &str) -> Result<(), String> {
    write_result(
        result_path,
        &ServiceBatchResult {
            ok: false,
            steps: Vec::new(),
            message: message.to_string(),
        },
    )
}

// ---------------------------------------------------------------------------
// 文件生命周期：读 req（≤64KB）→ 执行 → 写 result → finally 删除 req；result 保留给 host（读后删）。
// ---------------------------------------------------------------------------

/// 从 `<request-path>` 读请求（校验 ≤ [`MAX_REQUEST_BYTES`]）、执行并写结果到
/// `<result-path>`。**finally 删除 req 文件**（输入已消费）；**result 文件保留**，
/// 由 host 在 `wait_exit_code` 后读取并校验，读毕删除。
///
/// # Errors
/// 请求读取 / 超限 / 解析失败，或批量执行失败 / 结果写入失败 → 携带原因的字符串。
pub fn run_batch_from_files(request_path: &Path, result_path: &Path) -> Result<(), String> {
    run_batch_from_files_with_ops(request_path, result_path, &mut RealServiceOps)
}

/// [`run_batch_from_files`] 的可注入 ops 变体（单测走 fake ops）。
fn run_batch_from_files_with_ops(
    request_path: &Path,
    result_path: &Path,
    ops: &mut dyn BatchServiceOps,
) -> Result<(), String> {
    // finally 清理：无论成功/失败/异常都删除 req（输入已消费）。result 是向 host 交付
    // 结果的唯一通道（ShellExecuteExW 无 stdio），必须保留到 host 读取后由 host 删除。
    struct Cleanup<'a> {
        request: &'a Path,
    }
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.request);
        }
    }
    let _cleanup = Cleanup {
        request: request_path,
    };

    let bytes = std::fs::read(request_path)
        .map_err(|e| format!("read batch request {}: {e}", request_path.display()))?;
    if bytes.len() > MAX_REQUEST_BYTES {
        let message = format!("batch request exceeds {MAX_REQUEST_BYTES} bytes");
        write_error_result(result_path, &message)?;
        return Err(message);
    }
    let request: ServiceBatchRequest = match serde_json::from_slice(&bytes) {
        Ok(request) => request,
        Err(e) => {
            let message = format!("batch request malformed: {e}");
            write_error_result(result_path, &message)?;
            return Err(message);
        }
    };
    run_batch_with_ops(&request, result_path, ops)
}

// ---------------------------------------------------------------------------
// S2-C 孤儿 watchdog：批量进程运行期间监控 host；host 中途退出 → 终止（防孤儿）。
// 决策/主体在 lib（可单测 seam）；进程等待由 main 注入（复用 `wait_core_process_exit`
// 的同一实现），生产终止 = `process::exit`。
// ---------------------------------------------------------------------------

/// 批量孤儿 watchdog 决策（可测）：host 退出信号已到，判断是否应终止批量进程。
///
/// - `completed == true`（批量已返回，result 已写/已交付）→ **不终止**——进程即将正常
///   退出，watchdog 恰在此时返回不得误杀正常路径。
/// - `completed == false`（host 中途退出、批量未完成）→ **终止**——防孤儿。
pub fn should_terminate_orphan_batch(completed: &AtomicBool) -> bool {
    !completed.load(Ordering::SeqCst)
}

/// 批量孤儿 watchdog 主体（可测 seam）：等待 host 退出信号；批量未完成 → 终止。
///
/// 生产路径由 main `spawn_batch_orphan_watchdog` 注入真实进程等待
/// （`wait_core_process_exit` 的同步实现）+ `process::exit`；单测注入 fake 等待 /
/// 记录式终止验证「已完成不杀 / 未完成杀」决策与竞态处理。
pub fn orphan_watchdog_body(
    wait_host_exit: impl FnOnce(),
    completed: &AtomicBool,
    terminate: impl FnOnce(),
) {
    wait_host_exit();
    if should_terminate_orphan_batch(completed) {
        terminate();
    }
}

// ---------------------------------------------------------------------------
// 生产 Verify / VerifyRemoved：SCM 查询 + keepalive 探活（SERVICE_CONTROL_PIPE + PSK-HMAC）。
// ---------------------------------------------------------------------------

/// `Verify`：SCM Running 轮询等待（Start 后服务经 StartPending→Running）。
///
/// 注意：批量进程是 runas 提权的**用户**身份，而服务控制管道 DACL = SYSTEM + core_sid
/// （WSP1 §4 frozen shape），用户进程打开管道被拒 → 原 keepalive 管道探活必然
/// 「transport error」（2026-08-23 实测）。控制面 liveness 由 host 的 connect 完整
/// 校验（core SID 在 DACL 内 + PSK 握手），批量 Verify 只确认 SCM Running 即可。
fn verify_service_ready() -> Result<(), String> {
    wait_for_service_running(VERIFY_SCM_RUNNING_TIMEOUT)
}

/// 轮询等待 SCM 服务进入 Running（`StartPending`/`StopPending` 等过渡态不判失败）。
fn wait_for_service_running(timeout: Duration) -> Result<(), String> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match service_scm_running() {
            Ok(()) => return Ok(()),
            Err(e) => {
                if std::time::Instant::now() >= deadline {
                    return Err(e);
                }
                std::thread::sleep(SCM_POLL_INTERVAL);
            }
        }
    }
}

/// `VerifyRemoved`：SCM 服务已不存在（`ERROR_SERVICE_DOES_NOT_EXIST` = 1060）。
fn verify_service_removed() -> Result<(), String> {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(scm_error)?;
    match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(_) => Err("service still registered".to_string()),
        Err(e) if service_not_found(&e) => Ok(()),
        Err(e) => Err(scm_error(e)),
    }
}

/// SCM 状态必须为 Running。
fn service_scm_running() -> Result<(), String> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(scm_error)?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        .map_err(scm_error)?;
    let status = service.query_status().map_err(scm_error)?;
    if status.current_state != ServiceState::Running {
        return Err(format!(
            "service not running (state={:?})",
            status.current_state
        ));
    }
    Ok(())
}

/// keepalive 探活入口（同步）：建单线程 tokio runtime，把拨号 + 握手 + `KeepAlive` RPC
/// 整体放进 [`VERIFY_KEEPALIVE_TIMEOUT`] 硬时间界。
// TODO(cleanup): 管道探活因 DACL(USER 无权) 已从 Verify 移除；此链路暂保留为死代码，
// 后续随「批量加固 backlog」统一清理。
#[allow(dead_code)]
fn probe_keepalive_gate(psk: &[u8; 32], timeout: Duration) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("build keepalive probe runtime: {e}"))?;
    runtime.block_on(async {
        tokio::time::timeout(timeout, probe_keepalive_async(psk))
            .await
            .map_err(|_| format!("keepalive probe timed out after {}ms", timeout.as_millis()))?
    })
}

/// keepalive 探活（async）：拨号服务控制管道 → 身份帧 + PSK-HMAC 双向挑战 → 一条
/// gRPC `KeepAlive` RPC（证明服务 engine 已具备业务响应能力）→ 丢弃 client（干净收尾）。
async fn probe_keepalive_async(psk: &[u8; 32]) -> Result<(), String> {
    let connector = ServicePipeConnector {
        name: SERVICE_CONTROL_PIPE.to_string(),
        expected_sid: SYSTEM_SID.to_string(),
        psk: *psk,
    };
    let endpoint = Endpoint::from_static("http://engine.local");
    let channel = endpoint
        .connect_with_connector(connector)
        .await
        .map_err(|e| format!("connect service control pipe: {e}"))?;
    let mut client = HelperControlClient::new(channel);
    client
        .keep_alive(generated::KeepAliveRequest { monotonic_tick: 0 })
        .await
        .map_err(|e| format!("keepalive rpc: {e}"))?;
    Ok(())
}

/// 拨号 + 完整握手（身份帧 + PSK 挑战）的 tonic connector（`Response = TokioIo<NamedPipeClient>`）。
struct ServicePipeConnector {
    /// 服务控制面管道名（`SERVICE_CONTROL_PIPE`）。
    name: String,
    /// 期望的服务 engine 用户 SID（LocalSystem = [`SYSTEM_SID`]）。
    expected_sid: String,
    /// service 模式共享 PSK（engine 启动读入；探活证明对端持有）。
    psk: [u8; 32],
}

/// connector future 输出（`NamedPipeClient` 包装成 hyper IO）。
type PipeConnecting = Pin<Box<dyn Future<Output = Result<TokioIo<NamedPipeClient>, std::io::Error>> + Send>>;

impl Service<Uri> for ServicePipeConnector {
    type Response = TokioIo<NamedPipeClient>;
    type Error = std::io::Error;
    type Future = PipeConnecting;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let name = self.name.clone();
        let expected_sid = self.expected_sid.clone();
        let psk = self.psk;
        Box::pin(async move {
            let mut pipe = dial_service_pipe(&name).await?;
            handshake_service_pipe(&mut pipe, &expected_sid, &psk)
                .await
                .map_err(std::io::Error::other)?;
            Ok(TokioIo::new(pipe))
        })
    }
}

/// 管道对端（server）进程 PID——`GetNamedPipeServerProcessId`，无需 `OpenProcess` 特权。
fn pipe_server_process_id(pipe: &NamedPipeClient) -> Result<u32, String> {
    use std::os::windows::io::AsRawHandle;

    let mut pid = 0u32;
    // SAFETY: `pipe.as_raw_handle()` 是已连接的 client pipe 句柄，`pid` 是有效输出参数。
    if let Err(e) = unsafe {
        windows::Win32::System::Pipes::GetNamedPipeServerProcessId(
            windows::Win32::Foundation::HANDLE(pipe.as_raw_handle()),
            &raw mut pid,
        )
    } {
        return Err(format!("service engine process query failed: {e}"));
    }
    Ok(pid)
}

/// 有界重试拨号服务控制管道（服务刚启动/连接刚关闭未重建实例的竞窗）。
async fn dial_service_pipe(name: &str) -> Result<NamedPipeClient, std::io::Error> {
    for _ in 0..30 {
        match ClientOptions::new().open(name) {
            Ok(pipe) => return Ok(pipe),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    Err(std::io::Error::other(format!(
        "dial service control pipe {name} exhausted retries"
    )))
}

/// client 侧 pre-gRPC 握手：读 engine 自报身份帧（校验 SID = SYSTEM）→ PSK-HMAC 双向挑战。
/// 与 `grpc_transport::psk_challenge_server` 逐帧对称（帧序：身份帧 → `nonce_e` →
/// 应答 + `nonce_s` → server 应答）。
async fn handshake_service_pipe(
    pipe: &mut NamedPipeClient,
    expected_sid: &str,
    psk: &[u8; 32],
) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 0. 自报身份帧（6 字节头 + 变长 UTF-8 SID）——不读会错位后续字节流。
    let mut header = [0u8; IDENTITY_FRAME_HEADER_LEN];
    pipe.read_exact(&mut header)
        .await
        .map_err(|e| format!("read identity header: {e}"))?;
    let sid_len = u16::from_le_bytes([header[4], header[5]]) as usize;
    if sid_len > IDENTITY_FRAME_MAX_SID_LEN {
        return Err(format!("identity frame SID length {sid_len} exceeds cap"));
    }
    let mut sid_bytes = vec![0u8; sid_len];
    pipe.read_exact(&mut sid_bytes)
        .await
        .map_err(|e| format!("read identity sid: {e}"))?;
    let mut frame = Vec::with_capacity(IDENTITY_FRAME_HEADER_LEN + sid_len);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&sid_bytes);
    let identity = decode_identity_frame(&frame).ok_or_else(|| "identity frame malformed".to_string())?;
    // 交叉核验 PID（自报 == 管道对端进程；GetNamedPipeServerProcessId 免特权）+ SID。
    let server_pid = pipe_server_process_id(pipe)?;
    if identity.process_id != server_pid {
        return Err(format!(
            "service engine pid mismatch: self-reported {}, pipe server {server_pid}",
            identity.process_id
        ));
    }
    if identity.user_sid != expected_sid {
        return Err(format!(
            "service engine SID mismatch: expected {expected_sid}, observed {}",
            identity.user_sid
        ));
    }

    // 1. server nonce。
    let mut nonce_e = [0u8; 32];
    pipe.read_exact(&mut nonce_e)
        .await
        .map_err(|e| format!("read challenge nonce: {e}"))?;
    // 2. 应答 `HMAC(psk, nonce_e || "c2e")` + 自己的 nonce_s。
    let nonce_s = random_32()?;
    let response = hmac_sha256(psk, &tagged(&nonce_e, b"c2e"));
    pipe.write_all(&response)
        .await
        .map_err(|e| format!("send challenge response: {e}"))?;
    pipe.write_all(&nonce_s)
        .await
        .map_err(|e| format!("send client nonce: {e}"))?;
    // 3. 恒时验证 server 应答 `HMAC(psk, nonce_s || "e2c")`。
    let mut reply = [0u8; 32];
    pipe.read_exact(&mut reply)
        .await
        .map_err(|e| format!("read challenge reply: {e}"))?;
    let expected = hmac_sha256(psk, &tagged(&nonce_s, b"e2c"));
    if !ct_eq(&reply, &expected) {
        return Err("keepalive probe: reply mismatch".to_string());
    }
    Ok(())
}

/// `base || suffix`（challenge 域标签；与 `grpc_transport` 同构）。
fn tagged(base: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(base.len() + suffix.len());
    out.extend_from_slice(base);
    out.extend_from_slice(suffix);
    out
}

// ---------------------------------------------------------------------------
// 单元测试：校验 / 编排 / 文件生命周期（fake ops，不触碰真 SCM/管道）。
// SCM 真机集成（安装/启动/卸载/探活全链）留 S2-C / 业务验收（env 门控 + 标 ignored）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 记录型 fake ops：按调用序记录步骤；可配置第 N 次调用失败（1-indexed）。
    struct FakeOps {
        calls: Vec<BatchStep>,
        fail_on_call: Option<usize>,
        fail_message: String,
    }

    impl FakeOps {
        fn new() -> Self {
            Self {
                calls: Vec::new(),
                fail_on_call: None,
                fail_message: "boom".to_string(),
            }
        }

        fn failing_on(call: usize) -> Self {
            Self {
                calls: Vec::new(),
                fail_on_call: Some(call),
                fail_message: "boom".to_string(),
            }
        }

        fn record(&mut self, step: BatchStep) -> Result<(), String> {
            self.calls.push(step);
            if self.fail_on_call == Some(self.calls.len()) {
                return Err(self.fail_message.clone());
            }
            Ok(())
        }
    }

    impl BatchServiceOps for FakeOps {
        fn install(&mut self, _config_dir: &str) -> Result<(), String> {
            self.record(BatchStep::Install)
        }
        fn start(&mut self) -> Result<(), String> {
            self.record(BatchStep::Start)
        }
        fn uninstall(&mut self) -> Result<(), String> {
            self.record(BatchStep::Uninstall)
        }
        fn verify(&mut self) -> Result<(), String> {
            self.record(BatchStep::Verify)
        }
        fn verify_removed(&mut self) -> Result<(), String> {
            self.record(BatchStep::VerifyRemoved)
        }
    }

    fn sample_request(sequence: Vec<BatchStep>) -> ServiceBatchRequest {
        ServiceBatchRequest {
            version: 1,
            sequence,
            config_dir: r"C:\Users\Alice\.exv".to_string(),
        }
    }

    /// 序列全部成功 → ok=true，steps 逐项正确，ops 按序收到每个步骤。
    #[test]
    fn batch_all_steps_succeed_reports_each_step_ok() {
        let request = sample_request(vec![
            BatchStep::Install,
            BatchStep::Start,
            BatchStep::Verify,
        ]);
        let mut ops = FakeOps::new();
        let result = execute_batch(&request, &mut ops);
        assert!(result.ok, "全部步骤成功必须 ok=true，got {}", result.message);
        assert_eq!(result.message, "batch completed");
        assert_eq!(result.steps.len(), 3);
        assert!(result.steps.iter().all(|s| s.ok), "每步都必须 ok");
        assert_eq!(ops.calls, request.sequence, "ops 必须按序收到每个步骤");
        assert_eq!(result.steps[0].message, "install");
    }

    /// 中间一步失败 → 中止后续（后续步骤不被调用）、ok=false、消息定位失败步骤。
    #[test]
    fn batch_middle_step_failure_aborts_subsequent() {
        let request = sample_request(vec![
            BatchStep::Install,
            BatchStep::Start,
            BatchStep::Verify,
        ]);
        let mut ops = FakeOps::failing_on(2); // Start 第 2 步失败。
        let result = execute_batch(&request, &mut ops);
        assert!(!result.ok, "任一步失败必须 ok=false");
        assert_eq!(result.steps.len(), 2, "失败即中止，只应含已执行步骤");
        assert!(result.steps[0].ok);
        assert!(!result.steps[1].ok);
        assert_eq!(result.steps[1].step, BatchStep::Start);
        assert_eq!(ops.calls, vec![BatchStep::Install, BatchStep::Start], "后续 Verify 不得执行");
        assert!(result.message.contains("step 2"), "消息必须定位失败步骤: {}", result.message);
    }

    /// Verify 探活失败 → 该步 fail（fake verify 返回 Err，模拟探活失败）。
    #[test]
    fn batch_verify_probe_failure_marks_step_failed() {
        let request = sample_request(vec![BatchStep::Verify]);
        let mut ops = FakeOps::failing_on(1);
        let result = execute_batch(&request, &mut ops);
        assert!(!result.ok);
        assert_eq!(result.steps.len(), 1);
        assert_eq!(result.steps[0].step, BatchStep::Verify);
        assert!(!result.steps[0].ok);
        assert!(result.message.contains("verify"), "消息必须点名 verify: {}", result.message);
    }

    /// `deny_unknown_fields` 生效：多余字段 → 反序列化拒绝。
    #[test]
    fn request_rejects_unknown_fields() {
        let json = r#"{"version":1,"sequence":["start"],"config_dir":"C:\\x","extra":1}"#;
        let err = serde_json::from_str::<ServiceBatchRequest>(json)
            .expect_err("多余字段必须被 deny_unknown_fields 拒绝");
        assert!(err.to_string().contains("unknown field"), "got {err}");
    }

    /// `version != 1` → 拒绝。
    #[test]
    fn request_rejects_wrong_version() {
        let mut request = sample_request(vec![BatchStep::Start]);
        request.version = 2;
        let err = validate_request(&request).expect_err("version != 1 必须拒绝");
        assert!(err.contains("version"), "got {err}");
    }

    /// 序列 > 8 步 → 拒绝。
    #[test]
    fn request_rejects_too_many_steps() {
        let request = sample_request(vec![BatchStep::Verify; MAX_BATCH_STEPS + 1]);
        let err = validate_request(&request).expect_err("序列超过上限必须拒绝");
        assert!(err.contains("limit"), "got {err}");
    }

    /// `config_dir` 相对路径 / 空 → 拒绝。
    #[test]
    fn request_rejects_relative_config_dir() {
        for dir in [String::new(), "relative\\.exv".to_string(), "..\\exv".to_string()] {
            let request = ServiceBatchRequest {
                version: 1,
                sequence: vec![BatchStep::Install],
                config_dir: dir,
            };
            let err = validate_request(&request).expect_err("相对 config_dir 必须拒绝");
            assert!(err.contains("absolute"), "got {err}");
        }
    }

    /// 请求体超 64KB → 拒绝（执行前失败，结果文件写出失败态）。
    #[test]
    fn request_rejects_oversized_payload() {
        let dir = tempfile::tempdir().expect("temp dir");
        let req = dir.path().join("req.json");
        let res = dir.path().join("res.json");
        std::fs::write(&req, vec![b'x'; MAX_REQUEST_BYTES + 1]).expect("write oversized req");

        let mut ops = FakeOps::new();
        let err = run_batch_from_files_with_ops(&req, &res, &mut ops)
            .expect_err("超限请求必须失败");
        assert!(err.contains("exceeds"), "got {err}");
        assert!(ops.calls.is_empty(), "超限请求不得执行任何步骤");
    }

    /// 文件清理（成功）：req 被 engine 删除；result 保留（交付给 host 读取，host 读后删）。
    #[test]
    fn batch_files_cleaned_up_after_success() {
        let dir = tempfile::tempdir().expect("temp dir");
        let req = dir.path().join("req.json");
        let res = dir.path().join("res.json");
        let request = sample_request(vec![BatchStep::Start]);
        std::fs::write(&req, serde_json::to_vec(&request).expect("serialize req"))
            .expect("write req");

        let mut ops = FakeOps::new();
        run_batch_from_files_with_ops(&req, &res, &mut ops)
            .expect("成功批量必须 Ok");
        assert!(!req.exists(), "req 文件必须被删除");
        assert!(res.exists(), "result 文件必须保留给 host 读取");
        let result: ServiceBatchResult =
            serde_json::from_slice(&std::fs::read(&res).expect("read result"))
                .expect("result JSON 形状合法");
        assert!(result.ok, "成功批量 ok=true");
        assert_eq!(ops.calls, vec![BatchStep::Start]);
    }

    /// 文件清理（失败）：finally 删除 req；失败态 result 保留（host 读后删）。
    #[test]
    fn batch_files_cleaned_up_after_failure() {
        let dir = tempfile::tempdir().expect("temp dir");
        let req = dir.path().join("req.json");
        let res = dir.path().join("res.json");
        let request = sample_request(vec![BatchStep::Install, BatchStep::Verify]);
        std::fs::write(&req, serde_json::to_vec(&request).expect("serialize req"))
            .expect("write req");

        let mut ops = FakeOps::failing_on(1);
        run_batch_from_files_with_ops(&req, &res, &mut ops)
            .expect_err("失败批量必须返回 Err（非零退出码）");
        assert!(!req.exists(), "req 文件必须被删除");
        assert!(res.exists(), "失败态 result 文件必须保留给 host 读取");
    }

    /// `run_batch_with_ops`：失败时写出 ok=false 的结果文件并返回 Err。
    #[test]
    fn run_batch_writes_failed_result_and_returns_err() {
        let dir = tempfile::tempdir().expect("temp dir");
        let res = dir.path().join("res.json");
        let request = sample_request(vec![BatchStep::Uninstall]);
        let mut ops = FakeOps::failing_on(1);

        let err = run_batch_with_ops(&request, &res, &mut ops)
            .expect_err("步骤失败必须返回 Err");
        assert!(err.contains("step 1"), "got {err}");
        let written: ServiceBatchResult =
            serde_json::from_slice(&std::fs::read(&res).expect("result file written"))
                .expect("result JSON parses");
        assert!(!written.ok);
        assert_eq!(written.steps.len(), 1);
        assert!(!written.steps[0].ok);
    }

    /// 成功序列：结果文件写出 ok=true。
    #[test]
    fn run_batch_writes_ok_result_on_success() {
        let dir = tempfile::tempdir().expect("temp dir");
        let res = dir.path().join("res.json");
        let request = sample_request(vec![BatchStep::VerifyRemoved]);
        let mut ops = FakeOps::new();

        run_batch_with_ops(&request, &res, &mut ops).expect("成功批量必须 Ok");
        let written: ServiceBatchResult =
            serde_json::from_slice(&std::fs::read(&res).expect("result file written"))
                .expect("result JSON parses");
        assert!(written.ok);
        assert_eq!(written.steps.len(), 1);
        assert!(written.steps[0].ok);
    }

    /// BatchStep JSON 往返：snake_case 枚举（host 消费形状契约）。
    #[test]
    fn batch_step_json_round_trip_snake_case() {
        assert_eq!(
            serde_json::to_string(&BatchStep::Install).expect("serialize"),
            "\"install\""
        );
        assert_eq!(
            serde_json::to_string(&BatchStep::VerifyRemoved).expect("serialize"),
            "\"verify_removed\""
        );
        assert_eq!(
            serde_json::from_str::<BatchStep>("\"start\"").expect("parse"),
            BatchStep::Start
        );
    }

    // -------------------------------------------------------------------------
    // S2-C 孤儿 watchdog：host 退出信号 vs 批量完成标志的决策。用 fake 等待/记录式
    // 终止 seam 验证「已完成不杀 / 未完成杀」与竞态处理，不触碰真实进程。进程级
    // （host 退出 → 批量 engine 退出）留 tests/ 集成（env 门控 + 标 ignored）。
    // -------------------------------------------------------------------------

    /// host 退出信号已到但批量未完成 → 终止（防孤儿：host 中途退出，engine 不得遗留）。
    #[test]
    fn orphan_watchdog_terminates_when_host_exits_before_batch_completes() {
        let completed = AtomicBool::new(false);
        let mut terminated = false;
        orphan_watchdog_body(|| {}, &completed, || terminated = true);
        assert!(terminated, "host 中途退出且批量未完成 → 必须终止（防孤儿）");
    }

    /// 批量已完成（result 已写/已交付）后 host 退出信号才到 → 不终止。
    /// 竞态处理：批量完成写 result 后进程即将退出，watchdog 恰在此刻返回不得误杀正常路径。
    #[test]
    fn orphan_watchdog_does_not_terminate_when_batch_completed_first() {
        let completed = AtomicBool::new(true);
        let mut terminated = false;
        orphan_watchdog_body(|| {}, &completed, || terminated = true);
        assert!(!terminated, "批量已完成 → watchdog 不得误杀正常路径");
    }
}
