// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! 特权 **engine** 进程角色（阶段 3a 骨架 + **阶段 3b：engine 进程内认证 + CSTP +
//! Wintun 数据面**）。
//!
//! 两进程架构：普通用户 token 的 **core**（纯协调层 + 日志层 + 请求翻译）与特权 token 的
//! **engine**（唯一特权进程）。engine 是唯一 native mutation authority：建 Wintun adapter、
//! 写路由/网络设置（复用 `scenarios::controlled::helper_apply`）、清理（复用
//! `helper_stop`）。**阶段 3b** 把认证（`WebvpnLogin::perform_login`）/ CSTP
//! （`CstpSession::open`）/ 数据面（ring→CSTP→TLS→学校，`engine_data_plane` 模块）
//! 全部迁入 engine 进程——engine 的 `Connect` 处理：凭据（控制面管道收到，一次性，
//! 用后 zeroize）→ 认证 → CSTP（offer 即真实 tunnel plan）→ 特权初始化（helper_apply
//! 建 adapter + 四族网络设置，plan 来自 offer）→ `WintunSession::start`（engine 自己
//! 建 session）→ `spawn_data_plane`（reader/writer 线程全在 engine，零跨进程）→
//! 状态机推进 `Connecting → Connected`（成功）或 `Error`（失败，带错误详情）。
//!
//! 控制面：engine 建 byte-mode Named Pipe server（DACL = SYSTEM + 当前用户、
//! `PIPE_REJECT_REMOTE_CLIENTS`、`FIRST_PIPE_INSTANCE`），接受 core 连接后双向认证
//! （server 侧 `PeerAuthenticator` 验 core 的 pid+SID；client 侧 core 验 engine），
//! 握手后进入命令循环，处理 `CoreToEngine` 命令并回 `EngineToCore` 回复。
//!
//! 本模块是 test-only 的自动化调试入口，不进入安装包（与 acceptance crate 其它模块一致）。

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use exv_vpn_cstp::connector::{BootstrapConfig, TrustPolicy};
use exv_vpn_cstp::session::{CstpSession, SessionError};
use exv_vpn_cstp::webvpn::{LoginError, WebvpnLogin};
use exv_vpn_win32_ipc::engine_protocol::{
    read_json_frame, write_json_frame, ConnectRequest, CoreToEngine, EngineHelloReply,
    EngineHelloReq, EngineState, EngineToCore, FrameError,
};
use exv_vpn_win32_ipc::log_pipe::{LogEvent, LogPipeClient};
use exv_vpn_win32_ipc::named_pipe_io::NamedPipeByteStream;
use exv_vpn_win32_ipc::peer_auth::{PeerAuthenticator, current_user_sid};

use crate::engine_data_plane::{EngineDataPlane, EngineDataPlaneThreads};
use crate::scenarios::controlled::{self, ApplyReq, HelperArgs, HelperNativeState};
use crate::wintun_facts::WINTUN_PROBE_RING_CAPACITY;

/// CSTP gateway 端口（阶段 3b：TLS/CSTP 直连真实网关 IP 的默认端口；协议帧未携带
/// 端口字段，使用标准 HTTPS/CSTP 端口）。
const ENGINE_CSTP_GATEWAY_PORT: u16 = 443;

/// engine 创建的 Wintun adapter 名称（可被 `--adapter-name` 覆盖）。
pub const ENGINE_ADAPTER_NAME: &str = "ExvEngine";

/// engine 进程启动参数。
#[derive(Debug, Clone)]
pub struct EngineArgs {
    /// 控制面命名管道名（core 连接的目标）。
    pub control_pipe: String,
    /// wintun.dll 路径。
    pub dll: PathBuf,
    /// durable journal 目录（teardown 记录；helper_stop 复用）。
    pub journal_dir: PathBuf,
    /// `Local\`-scoped authority mutex 名（阶段后续 authority 组合使用）。
    pub authority_name: String,
    /// 声明的 core（host）进程 id——engine 侧核对 client pid 必须等于它。
    pub host_pid: u32,
    /// 创建的 adapter 名称。
    pub adapter_name: String,
    /// core 进程显式传入的用户 SID——engine 用它建控制面管道 DACL（授权普通用户 core
    /// 连接，普通 token 才连得上）；缺省时回退 engine 本进程用户 SID（同用户拓扑下两者相等）。
    pub core_user_sid: Option<String>,
    /// core 暴露的 log 管道名（`--log-pipe`；engine 连入后经它把日志送回 core 统一落盘）。
    /// `None` 时 engine 日志只写自身 stdout（runas 新窗口，不回流）。
    pub log_pipe: Option<String>,
}

/// 解析 engine bin 命令行参数（`--key value`）。
pub fn parse_engine_args() -> Result<EngineArgs, String> {
    let argv: Vec<String> = std::env::args().collect();
    parse_engine_args_from(&argv)
}

/// 从 `Vec<String>` 解析 engine 参数（可测试注入；`argv[0]` 是程序名，与
/// `std::env::args()` 形状一致）。
pub(crate) fn parse_engine_args_from(argv: &[String]) -> Result<EngineArgs, String> {
    let mut a = EngineArgs {
        control_pipe: String::new(),
        dll: PathBuf::new(),
        journal_dir: std::env::temp_dir().join("exv-engine-journal"),
        authority_name: String::new(),
        host_pid: 0,
        adapter_name: ENGINE_ADAPTER_NAME.to_string(),
        core_user_sid: None,
        log_pipe: None,
    };
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--control-pipe" => a.control_pipe = argv.get(i + 1).cloned().unwrap_or_default(),
            "--dll" => a.dll = PathBuf::from(argv.get(i + 1).cloned().unwrap_or_default()),
            "--journal-dir" => {
                a.journal_dir = PathBuf::from(argv.get(i + 1).cloned().unwrap_or_default())
            }
            "--authority-name" => {
                a.authority_name = argv.get(i + 1).cloned().unwrap_or_default()
            }
            "--host-pid" => {
                a.host_pid = argv
                    .get(i + 1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_default();
            }
            "--adapter-name" => a.adapter_name = argv.get(i + 1).cloned().unwrap_or_default(),
            "--user-sid" => a.core_user_sid = argv.get(i + 1).cloned(),
            "--log-pipe" => a.log_pipe = argv.get(i + 1).cloned(),
            _ => {}
        }
        i += 1;
    }
    if a.control_pipe.is_empty() || a.dll.as_os_str().is_empty() || a.host_pid == 0 {
        return Err("engine args incomplete (need --control-pipe, --dll, --host-pid)".to_string());
    }
    Ok(a)
}

/// engine 日志客户端（连接 core 的 log 管道；best-effort——管道不可用时日志只走 stdout）。
static LOG_CLIENT: std::sync::Mutex<Option<LogPipeClient>> = std::sync::Mutex::new(None);

/// 打开 log 管道客户端（`--log-pipe`）。带小重试（core 可能在 engine 启动后片刻才建好
/// server 实例）；失败静默降级为 stdout-only（不阻塞 engine 启动）。
pub(crate) fn open_log_pipe(name: &str) {
    for _ in 0..5 {
        match LogPipeClient::connect(name) {
            Ok(c) => {
                if let Ok(mut g) = LOG_CLIENT.lock() {
                    *g = Some(c);
                }
                return;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
        }
    }
}

/// engine 日志行：写 stdout + 发送到 core 的 log 管道（**core 统一加时间戳落盘**）。
/// 消息自带 `[engine]` 来源前缀（未来 UI 用 `[ui]`）；阶段耗时经 `PhaseTimer::mark`
/// 生成的后缀（`+Xs (ΔYs)`）由 engine 计算、core 只负责时间戳前缀与落盘。
pub(crate) fn log_line(s: &str) {
    println!("{s}");
    let _ = std::io::stdout().flush();
    if let Ok(mut g) = LOG_CLIENT.lock()
        && let Some(c) = g.as_mut()
    {
        c.send_event(&LogEvent {
            level: "info".to_string(),
            message: s.to_string(),
        });
    }
}

/// engine 阶段计时（局部：把各阶段耗时写进日志消息，随 LogEvent 发送给 core）。
struct PhaseTimer {
    start: std::time::Instant,
    last: std::time::Instant,
}

impl PhaseTimer {
    fn start() -> Self {
        let now = std::time::Instant::now();
        Self { start: now, last: now }
    }

    /// 距阶段序列起始的总时长 + 距上一阶段的增量，格式化为日志消息后缀。
    /// R0 计时：同一 delta 额外写 timing sink（`acceptance.engine.<label>`），与
    /// `helper_apply` / resource 叶 seam 一起合并归因（feature 关闭时零开销）。
    fn mark(&mut self, label: &str) -> String {
        let now = std::time::Instant::now();
        let total = now.duration_since(self.start).as_secs_f64();
        let delta = now.duration_since(self.last).as_secs_f64();
        exv_vpn_win32_resource::timing::record_elapsed(
            &format!("acceptance.engine.{label}"),
            self.last,
        );
        self.last = now;
        format!("{label}: +{total:.3}s (Δ{delta:.3}s)")
    }
}

/// 运行 engine 角色（解析后的参数 → 建控制面管道 → 双向认证 → 命令循环）。
/// 返回进程退出码（0 = 干净退出；2 = engine 侧身份/初始化失败）。
pub fn run_engine_role(args: &EngineArgs) -> i32 {
    if let Some(name) = &args.log_pipe {
        open_log_pipe(name);
    }
    log_line("[engine] role start");
    match run_engine_inner(args, RealNativeOps::new(args), controlled::is_elevated()) {
        Ok(code) => code,
        Err(e) => {
            log_line(&format!("[engine] fatal: {e}"));
            1
        }
    }
}

/// engine 主流程。`native` 是隧道原生操作（真实 = `RealNativeOps`；测试 = mock）；
/// `engine_elevated` 是 engine 进程的 elevation 观测（真实 = `controlled::is_elevated()`，
/// 测试可注入以模拟特权 engine）。
pub(crate) fn run_engine_inner<N: EngineNativeOps>(
    args: &EngineArgs,
    native: N,
    engine_elevated: bool,
) -> Result<i32, String> {
    let own_sid = current_user_sid().ok_or("engine: cannot read own SID")?;
    log_line(&format!(
        "[engine] run_engine_inner: pid={} elevated={}",
        std::process::id(),
        engine_elevated
    ));
    log_line(&format!(
        "[engine] args: control_pipe='{}' dll='{}' log_pipe='{:?}'",
        args.control_pipe,
        args.dll.display(),
        args.log_pipe
    ));

    // ---- 建控制面 byte-mode pipe server（DACL = SYSTEM + core 用户 SID；FIRST_INSTANCE；
    //      REJECT_REMOTE_CLIENTS）并接受 core 连接。DACL 必须显式授权 core 的用户 SID：
    //      engine 是特权进程，默认 ACL 只含 SYSTEM/Administrators，普通用户 core 连不上
    //      （ERROR_ACCESS_DENIED）。core 启动时经 `--user-sid` 传入；缺省回退本进程用户
    //      SID（同用户拓扑下与 core 一致）。 ----
    let dacl_user_sid = args.core_user_sid.as_deref().unwrap_or(&own_sid);
    let server = NamedPipeByteStream::create_server_with_dacl(&args.control_pipe, 1, Some(dacl_user_sid))
        .map_err(|e| format!("engine: create control pipe: {e:?}"))?;
    log_line("[engine] control pipe server created");
    server
        .connect()
        .map_err(|e| format!("engine: accept core connection: {e:?}"))?;
    log_line("[engine] core connected (control pipe)");

    // ---- server 侧双向认证：client pid 必须等于声明的 host pid；client SID 必须等于
    //      本进程 SID（core 与 engine 同用户，只是 token 权限不同）。 ----
    let peer = PeerAuthenticator::new(own_sid.clone())
        .authenticate_client(&server)
        .map_err(|e| format!("engine: core auth failed: {e:?}"))?;
    if peer.process_id != args.host_pid {
        return Err(format!(
            "engine: core pid {} != expected host pid {}",
            peer.process_id, args.host_pid
        ));
    }
    log_line(&format!(
        "[engine] peer auth ok: pid={} account={}",
        peer.process_id, peer.account_name
    ));

    let mut server = server;
    // 消费 core 的握手请求（与 helper 的命令循环对齐：hello 帧先消费，命令循环从
    // 下一帧对齐）。
    let hello_req: EngineHelloReq = read_json_frame(&mut server)
        .map_err(|e| format!("engine: read hello: {e:?}"))?;
    let host_verified = hello_req.host_pid == args.host_pid;
    let hello = EngineHelloReply {
        ok: host_verified,
        error: if host_verified {
            None
        } else {
            Some("host pid mismatch".to_string())
        },
        engine_pid: std::process::id(),
        engine_sid: own_sid,
        engine_account: peer.account_name.clone(),
        engine_elevated,
    };
    write_json_frame(&mut server, &hello).map_err(|e| format!("engine: write hello: {e:?}"))?;
    if !host_verified {
        log_line("[engine] hello rejected (host pid mismatch)");
        return Ok(2);
    }
    log_line("[engine] hello exchanged");

    // ---- 命令循环。 ----
    let mut command_loop = EngineCommandLoop::new(native);
    let outcome = command_loop.run(&mut server);
    log_line("[engine] command loop ended");
    // core 断开 / 命令循环错误：owner-lost 清理（adapter 移除、路由回滚）。
    command_loop.shutdown_cleanup();
    match outcome {
        Ok(()) | Err(FrameError::PeerClosed) => Ok(0),
        Err(e) => Err(format!("engine: command loop: {e:?}")),
    }
}

/// 隧道原生操作 seam（命令循环的测试注入点）。
pub(crate) trait EngineNativeOps {
    /// 建立隧道：认证 + CSTP + 特权初始化 + 数据面（`req` 为 `&mut`——凭据一次性，
    /// 消费后由实现 zeroize）。返回应用事实；失败携带 `EngineConnectError`
    /// （认证失败含网关 `a0` 结果码与 SAML 标记）。
    fn apply_tunnel(&mut self, req: &mut ConnectRequest) -> Result<EngineAppliedFacts, EngineConnectError>;
    /// 清理：停数据面、移除路由、删 adapter。
    fn teardown(&mut self) -> Result<(), String>;
    /// 当前 engine 状态。
    fn state(&self) -> EngineState;
    /// 流量统计（数据面 ring 字节计数；未连接时恒 0）。
    fn stats(&self) -> EngineStatsSnapshot;
}

/// 特权初始化后的 adapter/网络事实（供 StatusChanged/RouteApplied 回复参考）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EngineAppliedFacts {
    pub adapter_name: Option<String>,
    pub adapter_luid: Option<u64>,
    pub adapter_ifindex: Option<u32>,
    pub address_applied: Option<String>,
    pub mtu_applied: Option<u32>,
    pub routes_applied: Vec<String>,
    pub dns_applied: Vec<String>,
    pub inventory: Vec<String>,
}

/// 流量统计快照。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct EngineStatsSnapshot {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub speed: u64,
    pub latency_ms: u32,
}

/// Connect 阶段失败的受控错误：携带 domain 错误码 + 网关 `a0` 结果码 + 可读
/// `detail`，直接映射到 `EngineToCore::Error { code, a0, detail }`（core 侧可据
/// `code`/`a0` 区分错误类别，不只靠可读文本）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EngineConnectError {
    /// domain 错误码（MVP 仅 `ENGINE_CODE_SAML_REQUIRED` 非 0）。
    pub code: u32,
    /// 网关 `a0` 结果码（登录被拒时：`a0=15` 真凭据错、`a0=8`/`114`/`115`/`16`
    /// 请求形态问题；非登录失败恒 0）。
    pub a0: u32,
    /// 可读错误详情（typed 变体名，绝不含 secret/cookie）。
    pub detail: String,
}

/// SAML 要求的特定 domain 错误码：MVP 不支持交互式 SAML，engine 诚实标记
/// （core 侧据 `code == ENGINE_CODE_SAML_REQUIRED` 区分“需要 SAML”与普通失败）。
const ENGINE_CODE_SAML_REQUIRED: u32 = 1;

impl EngineConnectError {
    /// 认证阶段失败：从 `LoginError` 读网关 `a0` 结果码（`err.a0_result()`）与
    /// SAML 标记（`LoginError::SamlRequired` → 特定 `code`）。
    fn login(err: &LoginError) -> Self {
        let a0 = err
            .a0_result()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let code = if matches!(err, LoginError::SamlRequired) {
            ENGINE_CODE_SAML_REQUIRED
        } else {
            0
        };
        Self {
            code,
            a0,
            detail: format!("engine: login:{err:?}"),
        }
    }

    /// CSTP 会话阶段失败（无 a0；typed `SessionError` 变体名进 detail）。
    fn session(err: SessionError) -> Self {
        Self {
            code: 0,
            a0: 0,
            detail: format!("engine: connect-tunnel:{err:?}"),
        }
    }

    /// 其它失败（特权初始化 / 数据面；无 a0）。
    fn plain(detail: impl Into<String>) -> Self {
        Self {
            code: 0,
            a0: 0,
            detail: detail.into(),
        }
    }
}

/// 真实原生操作（阶段 3b）：认证（`WebvpnLogin`）→ CSTP（`CstpSession`）→
/// 特权初始化（复用 `controlled::helper_apply`，DP-01 create-then-idle 契约）→
/// engine 数据面（`engine_data_plane` 模块：`WintunSession::start` +
/// `spawn_data_plane`）。清理复用 `controlled::helper_stop`。
///
/// **字段声明顺序即 Drop 顺序（W17 SAFETY-ORDER + 资源逆序）**：`data_plane_threads`
/// （先 join）→ `data_plane`（session `WintunEndSession`）→ `cstp`（CSTP 通道 drop →
/// TLS 数据任务退出）→ `native`（adapter creator close 移除 adapter、释放 lib）→
/// `rt`（tokio 运行时最后 drop——所有 spawn 的 TLS 任务已退出，不阻塞 shutdown）——
/// 任何退出路径（含 teardown 中途错误后的结构 Drop）都保证 session 先于 adapter 结束、
/// CSTP 任务先于运行时结束。
pub(crate) struct RealNativeOps<'a> {
    args: &'a EngineArgs,
    data_plane_threads: Option<EngineDataPlaneThreads>,
    data_plane: Option<EngineDataPlane>,
    cstp: Option<EngineCstp>,
    native: Option<HelperNativeState>,
    state: EngineState,
    /// 已 stop 的数据面累计 ring 收到字节（`stats()` 合并存活线程计数器）。
    rx_bytes: u64,
    /// 已 stop 的数据面累计 ring 发送字节（`stats()` 合并存活线程计数器）。
    tx_bytes: u64,
    /// tokio 异步运行时（认证/CSTP 需要；最后 drop）。
    rt: Arc<tokio::runtime::Runtime>,
}

/// engine 持有的 CSTP 会话通道（保持 TLS 数据任务存活：`write_channel` sender +
/// `read_channel` receiver 任一 drop 都会让 `CstpSession::open` 内 spawn 的
/// TLS 读/写任务退出）。
///
/// 字段只写不读——本结构的作用是**持有**通道句柄以保持 TLS 任务存活，读取由数据面
/// 线程经克隆完成；`dead_code` 警告是有意的 lifetime-holding 模式。
#[allow(dead_code)]
struct EngineCstp {
    write_channel: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    read_channel: Arc<Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>>,
}

impl<'a> RealNativeOps<'a> {
    pub(crate) fn new(args: &'a EngineArgs) -> Self {
        Self {
            args,
            data_plane_threads: None,
            data_plane: None,
            cstp: None,
            native: None,
            state: EngineState::Idle,
            rx_bytes: 0,
            tx_bytes: 0,
            rt: Arc::new(
                tokio::runtime::Runtime::new()
                    .expect("engine: tokio runtime（认证/CSTP 需要异步运行时）"),
            ),
        }
    }
}

impl EngineNativeOps for RealNativeOps<'_> {
    #[allow(clippy::too_many_lines)] // 阶段线性（认证→CSTP→建卡→数据面）+ 逐阶段计时日志，保可读性优先
    fn apply_tunnel(&mut self, req: &mut ConnectRequest) -> Result<EngineAppliedFacts, EngineConnectError> {
        if self.native.is_some() {
            return Err(EngineConnectError::plain("engine: duplicate connect"));
        }
        let mut t = PhaseTimer::start();
        log_line("[engine] apply_tunnel begin");

        // ---- 阶段 1：认证 + CSTP（真实学校网关；plan 来自真实 offer）。 ----
        let hostname = req.server.clone();
        let gateway_ip: Ipv4Addr = req
            .real_ip
            .parse()
            .map_err(|_| EngineConnectError::plain(format!("engine: invalid real_ip '{}'", req.real_ip)))?;
        let gateway_addr = SocketAddr::from((gateway_ip, ENGINE_CSTP_GATEWAY_PORT));

        let login = match self.rt.block_on(WebvpnLogin::perform_login_with_user_agent(
            &hostname,
            gateway_addr,
            TrustPolicy::Production, // 真实学校链（同 school.rs 策略）
            None,
            req.credentials.username().as_bytes(),
            req.credentials.password().as_bytes(),
            &req.user_agent,
        )) {
            Ok(login) => login,
            Err(err) => {
                // 凭据一次性契约：登录失败同样一次消费后立即 zeroize（不等待
                // ConnectRequest Drop）。SAML / a0 结果码经 `EngineConnectError::login`
                // 结构化透出（core 侧可区分“凭据错 a0=15”与“请求形态 a0=8/114/115/16”
                // 以及“SAML 要求”）。
                log_line(&format!(
                    "[engine] login FAILED: a0={:?} err={err:?}",
                    err.a0_result()
                ));
                t.mark("login-failed");
                req.credentials.zeroize();
                return Err(EngineConnectError::login(&err));
            }
        };
        // 凭据一次性契约：登录已消费 → 立即 zeroize（不等待 ConnectRequest Drop）。
        req.credentials.zeroize();
        log_line(&format!("[engine] {}", t.mark("login-ok")));

        let cfg = BootstrapConfig {
            hostname: hostname.clone(),
            gateway_addr,
            trust: TrustPolicy::Production,
            dtls_offered: false, // MVP：TLS/CSTP only（offer 出现 dtls 即拒绝）
            deadline: None,
            socket_binder: None,
            gateway_resolver: None,
        };
        let session = match self.rt.block_on(CstpSession::open_with_user_agent(
            cfg,
            Some(&login),
            Some(&req.user_agent),
        )) {
            Ok(session) => session,
            Err(err) => {
                log_line(&format!("[engine] cstp-open FAILED: {err:?}"));
                t.mark("cstp-open-failed");
                return Err(EngineConnectError::session(err));
            }
        };
        log_line(&format!("[engine] {}", t.mark("cstp-open-ok")));
        let offer = session.offer_plan.clone();
        // 拆流：write_channel（reader 线程发 TLS）克隆 + read_channel（writer 线程收
        // TLS 解码帧）包 Arc<Mutex>。**先作局部持有**——只有全部可失败步骤（helper_apply
        // / data-plane start）成功后才落进 `self.cstp`；任何中途错误路径局部 drop 即关闭
        // CSTP 通道（TLS 任务退出、学校连接断开），不泄漏连接。
        let write_channel = session.write_channel.clone();
        let read_channel = Arc::new(Mutex::new(session.read_channel));

        // ---- 阶段 2：特权初始化（engine 内建 adapter + 四族网络设置；plan 来自
        //      真实 offer——address/prefix/mtu/dns/routes 以 CSTP offer 为准）。 ----
        let apply_req = ApplyReq {
            cmd: "apply".to_string(),
            dll: self.args.dll.display().to_string(),
            adapter_name: self.args.adapter_name.clone(),
            address: offer.ipv4_address.to_string(),
            prefix: offer.prefix,
            mtu: u32::from(offer.mtu),
            dns: offer.dns_servers.iter().map(|d| d.to_string()).collect(),
            routes: offer.routes.clone(),
            campus_routes: req.campus_routes.clone(),
        };
        let native = match controlled::helper_apply(&apply_req) {
            Ok(native) => native,
            Err(e) => {
                log_line(&format!("[engine] helper-apply FAILED: {e}"));
                t.mark("helper-apply-failed");
                return Err(EngineConnectError::plain(e));
            }
        };
        log_line(&format!("[engine] {}", t.mark("helper-apply-ok")));

        // ---- 阶段 3：engine 数据面（engine 自己建 session + reader/writer 线程，
        //      全在 engine 进程内零跨进程）。 ----
        let plane = match EngineDataPlane::start(&native._lib, &native.adapter, WINTUN_PROBE_RING_CAPACITY)
        {
            Ok(plane) => plane,
            Err(e) => {
                log_line(&format!("[engine] data-plane-start FAILED: {e}"));
                t.mark("data-plane-start-failed");
                return Err(EngineConnectError::plain(format!("engine: data-plane:{e}")));
            }
        };
        let threads = plane.spawn_data_plane(write_channel.clone(), &read_channel);
        log_line(&format!("[engine] {}", t.mark("data-plane-started")));

        let facts = EngineAppliedFacts {
            adapter_name: Some(native.adapter_name.clone()),
            adapter_luid: Some(native.luid),
            adapter_ifindex: Some(native.adapter.ifindex()),
            address_applied: native.address_applied.clone(),
            mtu_applied: native.mtu_applied_value,
            routes_applied: native.routes_applied.clone(),
            dns_applied: native.dns_applied.clone(),
            inventory: native.inventory.clone(),
        };
        // 全部可失败步骤已成功：现在把 CSTP 通道/数据面/native 落进 self。
        self.cstp = Some(EngineCstp {
            write_channel,
            read_channel,
        });
        self.native = Some(native);
        self.data_plane = Some(plane);
        self.data_plane_threads = Some(threads);
        self.state = EngineState::Connected;
        log_line(&format!("[engine] {}", t.mark("apply-tunnel-done")));
        Ok(facts)
    }

    fn teardown(&mut self) -> Result<(), String> {
        // 状态机：Connected → Disconnecting → Disconnected。先标记 Disconnecting，
        // 完成 teardown（或失败 Error）后再推进。
        self.state = EngineState::Disconnecting;
        // 1. 停数据面线程（先 join，再放 session Arc 克隆；W17 SAFETY-ORDER）。
        if let Some(mut threads) = self.data_plane_threads.take() {
            let (rx, tx) = threads.stop_and_join();
            self.rx_bytes = rx;
            self.tx_bytes = tx;
        }
        // 2. 结束 session（drop data plane → `WintunEndSession`）——必须在 adapter
        //    creator close 之前（W17：session 先于 adapter）。
        self.data_plane = None;
        // 3. 关闭 CSTP 通道（drop write/read channel → `CstpSession::open` 内 spawn
        //    的 TLS 读/写任务收到关闭信号退出；学校连接断开）。
        self.cstp = None;
        // 4. 清理：路由/DNS 逆序 restore + adapter creator close（`helper_stop`）。
        if self.native.is_none() {
            self.state = EngineState::Disconnected;
            return Ok(());
        }
        let reply = controlled::helper_stop(&helper_args_from_engine(self.args), self.native.take());
        if !reply.ok {
            self.state = EngineState::Error;
            return Err(reply.error.unwrap_or_else(|| "engine teardown failed".to_string()));
        }
        self.state = EngineState::Disconnected;
        Ok(())
    }

    fn state(&self) -> EngineState {
        self.state
    }

    fn stats(&self) -> EngineStatsSnapshot {
        let mut rx = self.rx_bytes;
        let mut tx = self.tx_bytes;
        if let Some(t) = &self.data_plane_threads {
            rx = rx.saturating_add(t.ring_received());
            tx = tx.saturating_add(t.ring_sent());
        }
        EngineStatsSnapshot {
            rx_bytes: rx,
            tx_bytes: tx,
            speed: 0,
            latency_ms: 0,
        }
    }
}

/// 从 engine 参数构造 helper_stop 所需的 `HelperArgs`（packet pipe 不需要——engine 数据面
/// 直连自己的 session/ring）。
fn helper_args_from_engine(args: &EngineArgs) -> HelperArgs {
    HelperArgs {
        control_pipe: args.control_pipe.clone(),
        packet_pipe: String::new(),
        dll: args.dll.clone(),
        journal_dir: args.journal_dir.clone(),
        authority_name: args.authority_name.clone(),
        host_pid: args.host_pid,
        adapter_name: args.adapter_name.clone(),
    }
}

/// engine 命令循环：处理 `CoreToEngine` 命令并产生 `EngineToCore` 回复。
pub(crate) struct EngineCommandLoop<N: EngineNativeOps> {
    native: N,
    subscribe: bool,
}

impl<N: EngineNativeOps> EngineCommandLoop<N> {
    pub(crate) fn new(native: N) -> Self {
        Self {
            native,
            subscribe: false,
        }
    }

    /// 处理一条命令，返回应发给 core 的回复批。
    pub(crate) fn handle(&mut self, cmd: CoreToEngine) -> Vec<EngineToCore> {
        match cmd {
            CoreToEngine::Connect(mut req) => {
                // 状态机推进：先发 `Connecting`，再做认证/CSTP/数据面，然后
                // `Connected`（成功）或 `Error`（失败，带错误详情）。
                log_line("[engine] Connect command received");
                let mut replies = vec![EngineToCore::StatusChanged {
                    state: EngineState::Connecting,
                    reason: None,
                }];
                match self.native.apply_tunnel(&mut req) {
                    Ok(_facts) => {
                        log_line("[engine] Connect -> Connected");
                        replies.push(EngineToCore::StatusChanged {
                            state: EngineState::Connected,
                            reason: None,
                        });
                        replies.push(EngineToCore::RouteApplied {
                            ok: true,
                            conflict: false,
                        });
                    }
                    Err(e) => {
                        // 结构化透出：认证失败携带网关 `a0` 结果码与 SAML 标记
                        // （`code == ENGINE_CODE_SAML_REQUIRED`）；core 侧可据此区分
                        // 凭据错（a0=15）/ 请求形态（a0=8/114/115/16）/ SAML 要求。
                        log_line(&format!(
                            "[engine] Connect FAILED: code={} a0={} detail={}",
                            e.code, e.a0, e.detail
                        ));
                        replies.push(EngineToCore::Error {
                            code: e.code,
                            a0: e.a0,
                            detail: Some(e.detail.clone()),
                        });
                        replies.push(EngineToCore::StatusChanged {
                            state: EngineState::Error,
                            reason: Some(e.detail),
                        });
                    }
                }
                replies
            }
            CoreToEngine::Disconnect { cleanup } => {
                if cleanup {
                    // 状态机：Connected → Disconnecting → Disconnected。先推
                    // Disconnecting，再做 teardown（W17 SAFETY-ORDER：先 join
                    // reader/writer，再结束 session/CSTP，最后 helper_stop 逆序
                    // restore + adapter creator close），成功后 Disconnected、
                    // 失败 Error。
                    let mut replies = vec![EngineToCore::StatusChanged {
                        state: EngineState::Disconnecting,
                        reason: None,
                    }];
                    match self.native.teardown() {
                        Ok(()) => replies.push(EngineToCore::StatusChanged {
                            state: EngineState::Disconnected,
                            reason: None,
                        }),
                        Err(e) => {
                            replies.push(EngineToCore::Error {
                                code: 0,
                                a0: 0,
                                detail: Some(e.clone()),
                            });
                            replies.push(EngineToCore::StatusChanged {
                                state: EngineState::Error,
                                reason: Some(e),
                            });
                        }
                    }
                    replies
                } else {
                    // 仅断开控制面：保留隧道，标记 Disconnected（控制面重连场景）。
                    vec![EngineToCore::StatusChanged {
                        state: EngineState::Disconnected,
                        reason: None,
                    }]
                }
            }
            CoreToEngine::Reconnect => vec![EngineToCore::StatusChanged {
                state: self.native.state(),
                reason: None,
            }],
            CoreToEngine::UpdateCredentials { credentials } => {
                // one-shot 凭据：reconnect 语义（阶段 3b 范围外）不消费；Drop 时 zeroize。
                drop(credentials);
                vec![]
            }
            CoreToEngine::GetStatus => vec![EngineToCore::StatusChanged {
                state: self.native.state(),
                reason: None,
            }],
            CoreToEngine::GetStats => {
                let s = self.native.stats();
                vec![EngineToCore::Stats {
                    rx_bytes: s.rx_bytes,
                    tx_bytes: s.tx_bytes,
                    speed: s.speed,
                    latency_ms: s.latency_ms,
                }]
            }
            CoreToEngine::Subscribe { enabled } => {
                self.subscribe = enabled;
                vec![]
            }
            CoreToEngine::Heartbeat => vec![EngineToCore::StatusChanged {
                state: self.native.state(),
                reason: None,
            }],
        }
    }

    /// 命令循环：读命令 → 写回复批，直到 core 断开（PeerClosed）。
    pub(crate) fn run(&mut self, pipe: &mut NamedPipeByteStream) -> Result<(), FrameError> {
        loop {
            let cmd: CoreToEngine = read_json_frame(pipe)?;
            let replies = self.handle(cmd);
            for reply in &replies {
                write_json_frame(pipe, reply)?;
            }
        }
    }

    /// owner-lost 清理：core 断开 / 循环错误后的 best-effort teardown。
    pub(crate) fn shutdown_cleanup(&mut self) {
        let _ = self.native.teardown();
    }
}

// ---------------------------------------------------------------------------
// 单元测试：参数解析 + 命令循环（mock native）+ 控制面管道往返（真实 pipe）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use exv_core::control_client::EngineControlClient;

    use super::*;

    fn test_pipe_name(tag: &str) -> String {
        format!(r"\\.\pipe\exv-engine-test-{tag}-{}", std::process::id())
    }

    fn test_connect_request() -> ConnectRequest {
        ConnectRequest {
            server: "vpn-cn.ecnu.edu.cn".to_string(),
            real_ip: "10.88.88.1".to_string(),
            prefix: 24,
            credentials: exv_vpn_win32_ipc::engine_protocol::Credentials::new("student", "s3cret"),
            user_agent: "AnyConnect Win_x86_64 4.10.05095".to_string(),
            mtu: 1420,
            dns: vec!["10.88.88.53".to_string()],
            routes: vec!["10.99.99.0/24".to_string()],
            campus_routes: Vec::new(),
        }
    }

    fn test_engine_args(tag: &str) -> EngineArgs {
        let host_pid = std::process::id();
        EngineArgs {
            control_pipe: test_pipe_name(tag),
            dll: PathBuf::from("C:\\unused\\wintun.dll"),
            journal_dir: std::env::temp_dir().join(format!("exv-engine-test-journal-{host_pid}-{tag}")),
            authority_name: format!("Local\\exv-engine-test-{host_pid}-{tag}"),
            host_pid,
            adapter_name: ENGINE_ADAPTER_NAME.to_string(),
            core_user_sid: Some(current_user_sid().expect("current user sid")),
            log_pipe: None,
        }
    }

    /// mock 观测探针：记录 `apply_tunnel` 所见的一次性凭据明文与 zeroize 后状态
    /// （凭据零化测试的断言面）。
    #[derive(Default)]
    struct MockProbe {
        password_seen: String,
        zeroized_after: bool,
    }

    #[derive(Default)]
    struct MockNativeOps {
        state: EngineState,
        applied: bool,
        teardown_calls: u32,
        probe: Arc<Mutex<MockProbe>>,
        /// 注入的 Connect 失败（非 `None` 时 `apply_tunnel` 立即返回它，凭据仍消费）。
        error: Option<EngineConnectError>,
    }

    impl EngineNativeOps for MockNativeOps {
        fn apply_tunnel(&mut self, req: &mut ConnectRequest) -> Result<EngineAppliedFacts, EngineConnectError> {
            // 一次性凭据契约（与真实 engine 一致）：无论成败都先消费后 zeroize。
            let password = req.credentials.password().to_string();
            req.credentials.zeroize();
            {
                let mut p = self.probe.lock().expect("probe 锁");
                p.password_seen = password;
                p.zeroized_after = req.credentials.password().is_empty();
            }
            if let Some(err) = self.error.clone() {
                self.state = EngineState::Error;
                return Err(err);
            }
            self.applied = true;
            self.state = EngineState::Connected;
            Ok(EngineAppliedFacts {
                adapter_name: Some("MockEngine".to_string()),
                adapter_luid: Some(42),
                adapter_ifindex: Some(7),
                address_applied: Some(req.real_ip.clone()),
                mtu_applied: Some(req.mtu),
                routes_applied: req.routes.clone(),
                dns_applied: req.dns.clone(),
                inventory: Vec::new(),
            })
        }

        fn teardown(&mut self) -> Result<(), String> {
            self.teardown_calls += 1;
            // 状态机：Connected → Disconnecting → Disconnected（与真实 engine 一致）。
            self.state = EngineState::Disconnecting;
            self.state = EngineState::Disconnected;
            Ok(())
        }

        fn state(&self) -> EngineState {
            self.state
        }

        fn stats(&self) -> EngineStatsSnapshot {
            EngineStatsSnapshot::default()
        }
    }

    /// 参数解析：完整参数。
    #[test]
    fn parse_engine_args_ok() {
        let host_pid = std::process::id();
        let argv = vec![
            "exv-win32-engine".to_string(),
            "--control-pipe".to_string(),
            r"\\.\pipe\exv-engine-parse".to_string(),
            "--dll".to_string(),
            "C:\\wintun.dll".to_string(),
            "--host-pid".to_string(),
            host_pid.to_string(),
            "--adapter-name".to_string(),
            "CustomAdapter".to_string(),
            "--log-pipe".to_string(),
            r"\\.\pipe\exv-log".to_string(),
        ];
        // 模拟 std::env::args()：首个参数是程序名，后续成对出现。
        let args = parse_engine_args_from(&argv);
        let a = args.expect("args parse ok");
        assert_eq!(a.control_pipe, r"\\.\pipe\exv-engine-parse");
        assert_eq!(a.dll, PathBuf::from("C:\\wintun.dll"));
        assert_eq!(a.host_pid, host_pid);
        assert_eq!(a.adapter_name, "CustomAdapter");
        assert_eq!(a.log_pipe.as_deref(), Some(r"\\.\pipe\exv-log"));
    }

    /// 参数解析：缺少必需参数。
    #[test]
    fn parse_engine_args_missing_required() {
        let bad = vec!["exv-win32-engine".to_string(), "--control-pipe".to_string()];
        assert!(parse_engine_args_from(&bad).is_err());
    }

    /// 命令循环：Connect → Connecting → Connected + RouteApplied；GetStatus/GetStats；
    /// Disconnect → Disconnected。
    #[test]
    fn command_loop_connect_status_disconnect() {
        let mut loop_ = EngineCommandLoop::new(MockNativeOps::default());

        let replies = loop_.handle(CoreToEngine::Connect(test_connect_request()));
        assert_eq!(replies.len(), 3, "Connect 必须先发 Connecting 再发 Connected + RouteApplied");
        assert!(matches!(
            replies[0],
            EngineToCore::StatusChanged {
                state: EngineState::Connecting,
                ..
            }
        ));
        assert!(matches!(
            replies[1],
            EngineToCore::StatusChanged {
                state: EngineState::Connected,
                ..
            }
        ));
        assert!(matches!(
            replies[2],
            EngineToCore::RouteApplied { ok: true, .. }
        ));

        let replies = loop_.handle(CoreToEngine::GetStatus);
        assert!(matches!(
            replies[0],
            EngineToCore::StatusChanged {
                state: EngineState::Connected,
                ..
            }
        ));

        let replies = loop_.handle(CoreToEngine::GetStats);
        assert!(matches!(replies[0], EngineToCore::Stats { .. }));

        let replies = loop_.handle(CoreToEngine::Disconnect { cleanup: true });
        assert_eq!(replies.len(), 2, "Disconnect 必须先推 Disconnecting 再推 Disconnected");
        assert!(matches!(
            replies[0],
            EngineToCore::StatusChanged {
                state: EngineState::Disconnecting,
                ..
            }
        ));
        assert!(matches!(
            replies[1],
            EngineToCore::StatusChanged {
                state: EngineState::Disconnected,
                ..
            }
        ));

        let replies = loop_.handle(CoreToEngine::GetStatus);
        assert!(matches!(
            replies[0],
            EngineToCore::StatusChanged {
                state: EngineState::Disconnected,
                ..
            }
        ));
    }

    /// 命令循环：Disconnect(cleanup=false) 保留隧道但标记 Disconnected；Subscribe/
    /// UpdateCredentials 无回复。
    #[test]
    fn command_loop_disconnect_no_cleanup_and_fire_and_forget() {
        let mut loop_ = EngineCommandLoop::new(MockNativeOps::default());

        let replies = loop_.handle(CoreToEngine::Disconnect { cleanup: false });
        assert!(matches!(
            replies[0],
            EngineToCore::StatusChanged {
                state: EngineState::Disconnected,
                ..
            }
        ));

        assert!(loop_.handle(CoreToEngine::Subscribe { enabled: true }).is_empty());
        assert!(loop_
            .handle(CoreToEngine::UpdateCredentials {
                credentials: exv_vpn_win32_ipc::engine_protocol::Credentials::new("u", "p"),
            })
            .is_empty());
    }

    /// Connect 命令把一次性凭据传进 `apply_tunnel`，后者消费后**立即 zeroize**
    /// （凭据一次性契约：登录使用后清零，不等待 `ConnectRequest` Drop）。
    #[test]
    fn connect_consumes_and_zeroizes_credentials() {
        let probe = Arc::new(Mutex::new(MockProbe::default()));
        let native = MockNativeOps {
            probe: Arc::clone(&probe),
            ..Default::default()
        };
        let mut loop_ = EngineCommandLoop::new(native);

        let replies = loop_.handle(CoreToEngine::Connect(test_connect_request()));
        assert!(
            replies.iter().any(|r| matches!(
                r,
                EngineToCore::StatusChanged {
                    state: EngineState::Connected,
                    ..
                }
            )),
            "mock Connect 必须成功"
        );

        let p = probe.lock().expect("probe 锁");
        assert_eq!(p.password_seen, "s3cret", "apply_tunnel 必须收到凭据明文");
        assert!(p.zeroized_after, "apply_tunnel 必须消费后 zeroize 一次性凭据");
    }

    /// Connect 登录失败必须结构化透出网关 `a0` 结果码与 SAML 标记：core 侧收到的
    /// `EngineToCore::Error` 携带 `a0`（凭据错 `a0=15`）且状态 Error；SAML 要求时
    /// `code == ENGINE_CODE_SAML_REQUIRED`（MVP 不支持 SAML 的诚实标记，core 可据此
    /// 区分“需要交互式 SAML”与普通失败）。
    #[test]
    fn connect_login_failure_propagates_a0_and_saml() {
        // 凭据被拒（a0=15，school.rs 语义）：Error.a0 必须携带结果码。
        let native = MockNativeOps {
            error: Some(EngineConnectError::login(&LoginError::login_rejected_with_detail(
                Some("15".to_string()),
            ))),
            ..Default::default()
        };
        let mut loop_ = EngineCommandLoop::new(native);
        let replies = loop_.handle(CoreToEngine::Connect(test_connect_request()));
        let error = replies
            .iter()
            .find_map(|r| match r {
                EngineToCore::Error { code, a0, detail } => Some((*code, *a0, detail.clone())),
                _ => None,
            })
            .expect("Connect 失败必须回 Error 消息");
        assert_eq!((error.0, error.1), (0, 15), "凭据被拒必须携带 a0=15 结果码");
        assert!(
            error.2.as_deref().is_some_and(|d| d.contains("login")),
            "detail 必须含 login 前缀，got {:?}",
            error.2
        );
        assert!(
            replies.iter().any(|r| matches!(
                r,
                EngineToCore::StatusChanged {
                    state: EngineState::Error,
                    ..
                }
            )),
            "登录失败后状态必须 Error"
        );

        // SAML 要求：code == ENGINE_CODE_SAML_REQUIRED（MVP 不支持的诚实标记）。
        let native = MockNativeOps {
            error: Some(EngineConnectError::login(&LoginError::SamlRequired)),
            ..Default::default()
        };
        let mut loop_ = EngineCommandLoop::new(native);
        let replies = loop_.handle(CoreToEngine::Connect(test_connect_request()));
        let error = replies
            .iter()
            .find_map(|r| match r {
                EngineToCore::Error { code, a0, detail } => Some((*code, *a0, detail.clone())),
                _ => None,
            })
            .expect("SAML 失败必须回 Error 消息");
        assert_eq!(
            (error.0, error.1),
            (ENGINE_CODE_SAML_REQUIRED, 0),
            "SAML 要求必须 code=ENGINE_CODE_SAML_REQUIRED 且 a0=0"
        );
        assert!(
            error.2.as_deref().is_some_and(|d| d.contains("SamlRequired")),
            "SAML detail 必须含 SamlRequired 变体名，got {:?}",
            error.2
        );
    }

    /// engine 日志落盘链路：`log_line` + `PhaseTimer` 生成的日志事件经 log 管道送达
    /// core 侧 server（core 用统一 `log_line` 落盘的接收面）。阶段计时消息必须含
    /// `+X.XXXs (ΔY.YYYs)` 形状。
    #[test]
    fn engine_log_line_delivers_phase_timed_events_to_log_pipe() {
        use exv_vpn_win32_ipc::log_pipe::{LogEvent, LogPipeServer};

        let name = format!(r"\\.\pipe\exv-engine-log-{}", std::process::id());
        let received = Arc::new(Mutex::new(Vec::new()));
        let recv = Arc::clone(&received);
        let _server = LogPipeServer::start(&name, None, 4, move |ev: LogEvent| {
            recv.lock()
                .expect("recv 锁")
                .push(format!("{}:{}", ev.level, ev.message));
        })
        .expect("start log server");

        open_log_pipe(&name);
        let mut t = PhaseTimer::start();
        log_line("[engine][log-test] apply_tunnel begin");
        log_line(&format!("[engine][log-test] {}", t.mark("login-ok")));
        log_line(&format!("[engine][log-test] {}", t.mark("cstp-open-ok")));

        // `LOG_CLIENT` 是进程级 static：并行测试的 `log_line` 也会经它发送（best-effort），
        // 故只过滤本测试的 `[log-test]` 标记消息做断言（顺序 = 发送顺序，单 accept 线程
        // 逐帧读）。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let mine = received
                .lock()
                .expect("recv 锁")
                .iter()
                .filter(|m| m.contains("[log-test]"))
                .cloned()
                .collect::<Vec<_>>();
            if mine.len() >= 3 || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mine = received
            .lock()
            .expect("recv 锁")
            .iter()
            .filter(|m| m.contains("[log-test]"))
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(mine.len(), 3, "本测试 3 条日志事件必须送达，got {mine:?}");
        assert!(mine[0].contains("apply_tunnel begin"), "got {mine:?}");
        assert!(mine[1].contains("login-ok: +"), "阶段计时必须含 +X.XXXs，got {mine:?}");
        assert!(mine[1].contains("(Δ"), "必须含增量 Δ，got {mine:?}");
        assert!(mine[2].contains("cstp-open-ok: +"), "got {mine:?}");

        // 清理静态 LOG_CLIENT（防跨测试污染——后续测试 log_line 仍走 stdout-only）。
        *LOG_CLIENT.lock().expect("log client 锁") = None;
        drop(_server);
    }

    /// 完整 engine 骨架往返（真实 pipe）：engine 线程建控制面管道 → core 客户端连接 →
    /// 双向认证 → Connect/GetStatus/Disconnect 往返。
    #[test]
    fn engine_control_pipe_round_trip() {
        let tag = "roundtrip";
        let host_pid = std::process::id();
        let sid = current_user_sid().expect("current user sid");
        let args = test_engine_args(tag);
        let control_pipe = args.control_pipe.clone();

        let engine =
            std::thread::spawn(move || run_engine_inner(&args, MockNativeOps::default(), true));

        let mut client =
            EngineControlClient::connect(&control_pipe, host_pid, host_pid, &sid)
                .expect("core connects to engine");

        let replies = client
            .send(&CoreToEngine::Connect(test_connect_request()))
            .expect("send connect");
        assert!(
            replies.iter().any(|r| matches!(
                r,
                EngineToCore::StatusChanged {
                    state: EngineState::Connected,
                    ..
                }
            )),
            "Connect 主回复必须是 Connected，got {replies:?}"
        );
        assert!(
            replies
                .iter()
                .any(|r| matches!(r, EngineToCore::RouteApplied { ok: true, .. })),
            "Connect 必须携带 RouteApplied，got {replies:?}"
        );

        let replies = client
            .send(&CoreToEngine::GetStatus)
            .expect("send get-status");
        assert!(
            replies.iter().any(|r| matches!(
                r,
                EngineToCore::StatusChanged {
                    state: EngineState::Connected,
                    ..
                }
            )),
            "GetStatus 必须回 Connected，got {replies:?}"
        );

        let replies = client
            .send(&CoreToEngine::Disconnect { cleanup: true })
            .expect("send disconnect");
        assert!(
            replies.iter().any(|r| matches!(
                r,
                EngineToCore::StatusChanged {
                    state: EngineState::Disconnected,
                    ..
                }
            )),
            "Disconnect 必须回 Disconnected，got {replies:?}"
        );

        drop(client); // 关闭控制面 → engine 命令循环收到 PeerClosed → 干净退出
        let code = engine.join().expect("engine thread joins").expect("engine ok");
        assert_eq!(code, 0, "engine 必须干净退出");
    }

}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
