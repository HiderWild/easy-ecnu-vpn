// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

// 产品化（用户拍板 2026-08-19）：host 为 GUI 产品进程，隐藏控制台黑框。
// 注：workspace [profile.release] rustc-link-arg-bins=/SUBSYSTEM:WINDOWS 不生效
//（rustc 自身再发 /SUBSYSTEM:CONSOLE 覆盖），必须以本属性声明。
#![windows_subsystem = "windows"]

//! Win32 非特权 host（core 进程）真实入口（P5 补尾）。
//!
//! 本二进制由 Tauri 宿主（UI）spawn（P4-b `core_process.rs` 契约），执行
//! **UI → core → engine** 两跳进程架构中 core 的全部生命周期：
//!
//! 1. **CLI 解析**：`--control-pipe <name>`（`KernelControl` 服务管道，名按 UI PID
//!    唯一 `\\.\pipe\exv-core-<ui_pid>`）、`--ui-pid <pid>`（UI 进程 PID，身份记录）、
//!    `--ui-sid <sid>`（UI 用户 SID——管道 DACL + accept 后 peer 验证；缺省回退当前
//!    用户 SID，同用户拓扑下相等）。
//! 2. **compose**：打开共享日志聚合器 → 提权拉起唯一特权进程 engine
//!    （`ShellExecuteExW(runas)` + 拓扑门禁：engine 必须 elevated）→ 经双向认证
//!    Named Pipe 连接 engine gRPC 控制面（`EngineControlGrpcClient::connect`）→
//!    组合 `KernelControlService`（共享 composition/engine 控制面/日志聚合器）→
//!    组装 `CoreRuntime`。
//! 3. **serve**：`serve_kernel_control_pipe` 建 UI 控制面管道（DACL = SYSTEM +
//!    UI SID）→ accept 一个 UI 连接 → 验证 UI peer（client pid + user SID +
//!    account name）→ gate 授权 → 拉起 engine 事件/统计转发器 → 返回
//!    [`UiKernelControlHandles`] 接进 `CoreRuntime`。
//! 4. **运行**：`CoreRuntime::run` 主循环——等 UI 彻底退出（O3 强绑定：UI **进程**退出
//!    → 传输层进程监视触发 `on_ui_exited` → 停机；tonic serve 任务不充当"UI 断开"
//!    信号——单元素流 accept 后即返回、连接任务 detached 继续服务）或显式停机；
//!    运行期监听 engine 掉线（liveness）→ 驱动 `composition.on_helper_link_terminal`
//!    （engine 死亡 ≠ core 死亡）。
//! 5. **停机**：`shutdown_core` 有序停机（先 RPC waiter 取消 → engine 发退出包
//!    （`StopTunnel` 业务停机）后即返 → `composition.exit()`）→ core 退出；engine 由
//!    退出包 / core 进程句柄 / 心跳（P2）三重保证随 core 退出（UI 只等 core）。
//!
//! **engine 不得遗留（O3）**：engine 子进程句柄归 `EngineSupervisor`/`EngineChild`
//! 所有，任何失败路径 drop 即强制终止已拉起的 engine。

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use exv_core::composition::compose_nonprivileged_host;
use exv_core::crash_recovery::{
    CrashRecovery, GrpcClientConnector, ProductSupervisorFactory, SystemResidueProbe,
};
use exv_core::engine_lifecycle::{ElevatedEngineSpawner, EngineSlot, EngineSupervisor};
use exv_core::grpc_control::{EngineControlGrpcClient, KernelEngineControl};
use exv_core::kernel_control_service::KernelControlService;
use exv_core::kernel_control_transport::{
    lookup_account_name, serve_kernel_control_pipe,
};
use exv_core::log_aggregator::LogAggregator;
use exv_core::process_lifecycle::{engine_control_pipe_name, ENGINE_ADAPTER_NAME};
use exv_core::shutdown::{CoreRuntime, UiLifetime};
use exv_vpn_win32_ipc::peer_auth::{current_user_sid, VerifiedPipePeer};
use exv_vpn_wire::generated::KeepAliveRequest;

/// R2：oneshot engine 就绪轮询上界（原生判据=拨号+认证成功 或 keepalive 回复，任一生效
/// 即就位；engine 冷启动/UAC 慢不因首次拨号失败而终止 core）。
const ONESHOT_READY_TIMEOUT: Duration = Duration::from_secs(15);
/// R2：oneshot engine 就绪轮询间隔。
const ONESHOT_READY_POLL: Duration = Duration::from_millis(500);
/// R2：oneshot keepalive 确认单次超时（拨号+认证成功后确认 gRPC 服务实际响应）。
const ONESHOT_KEEPALIVE_CONFIRM_TIMEOUT: Duration = Duration::from_secs(3);

/// 启动参数用法说明（`--help` / 参数错误时打印）。
const USAGE: &str = "\
EXV core (exv-core)

用法: exv-core --control-pipe <name> --ui-pid <pid> [--ui-sid <sid>]

必需参数（P4-b core_process.rs 契约）:
  --control-pipe <name>  KernelControl 服务管道名（\\\\.\\pipe\\exv-core-<ui_pid>）
  --ui-pid <pid>         UI（Tauri 宿主）进程 PID
  --ui-sid <sid>         UI 进程用户 SID（缺省回退当前用户 SID；同用户拓扑下相等）
";

/// core 进程 CLI 参数（P4-b `core_process.rs` spawn 契约的 core 侧解析）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreArgs {
    /// `KernelControl` 服务管道名（`serve_kernel_control_pipe`；名按 UI PID 唯一）。
    pub control_pipe: String,
    /// UI 进程 PID（core 日志/身份记录）。
    pub ui_pid: u32,
    /// UI 进程用户 SID（管道 DACL + accept 后 peer 验证）；`None` = UI 未传
    /// （core 回退当前用户 SID，同用户拓扑下相等）。
    pub ui_sid: Option<String>,
}

impl CoreArgs {
    /// 解析 CLI 参数（`--control-pipe`/`--ui-pid`/`--ui-sid`）。
    ///
    /// 未知参数忽略（前向兼容）；`--help`/`-h` 返回 `Err`（打印用法）。`--ui-sid`
    /// 缺省允许（UI 可能省略——core 回退当前用户 SID）。
    ///
    /// # Errors
    /// 必需参数缺失 / `--ui-pid` 非数字 → 携带原因的字符串（同时作为 usage 提示）。
    pub fn parse<I: IntoIterator<Item = String>>(args: I) -> Result<Self, String> {
        let mut control_pipe: Option<String> = None;
        let mut ui_pid: Option<u32> = None;
        let mut ui_sid: Option<String> = None;
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--control-pipe" => control_pipe = args.next(),
                "--ui-pid" => {
                    ui_pid = args
                        .next()
                        .and_then(|v| v.parse::<u32>().ok())
                }
                "--ui-sid" => ui_sid = args.next(),
                "--help" | "-h" => return Err(USAGE.to_string()),
                _ => {} // 未知参数忽略（前向兼容）。
            }
        }
        let control_pipe = control_pipe
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "--control-pipe <name> is required".to_string())?;
        let ui_pid = ui_pid.ok_or_else(|| "--ui-pid <pid> is required (numeric)".to_string())?;
        let ui_sid = ui_sid.filter(|s| !s.is_empty());
        Ok(Self {
            control_pipe,
            ui_pid,
            ui_sid,
        })
    }

    /// 生效的 UI 用户 SID：显式 `--ui-sid` 优先；缺省回退当前进程用户 SID
    /// （core 与 UI 同用户拓扑，两者相等）。
    ///
    /// # Errors
    /// `--ui-sid` 缺失且当前用户 SID 无法解析 → 携带原因的字符串。
    pub fn effective_ui_sid(&self) -> Result<String, String> {
        if let Some(sid) = &self.ui_sid {
            return Ok(sid.clone());
        }
        current_user_sid()
            .ok_or_else(|| "--ui-sid missing and current user SID unresolvable".to_string())
    }
}

/// 构造 composition 绑定的 engine peer 身份（PID + 用户 SID + account name）。
///
/// engine 由 core 提权拉起（唯一特权进程），其身份经 gRPC 双向认证（pid+SID）核实；
/// account name 供 composition 的 helper 绑定语义与 gate 授权的身份事实使用（任何
/// 解析失败返回空串——fail closed 由 gate 在需要处执行）。
#[must_use]
pub fn engine_peer_for(pid: u32, user_sid: &str) -> VerifiedPipePeer {
    let account_name = lookup_account_name(user_sid);
    VerifiedPipePeer {
        process_id: pid,
        user_sid: user_sid.to_string(),
        logon_sid: None,
        account_name,
    }
}

/// core 进程主路径（可测单元：参数解析/compose 顺序；进程级由集成覆盖）。
///
/// 返回进程退出码：`0` = 正常有序停机；`1` = 启动失败（engine 拉起/连接/UI 控制面
/// 建立失败）。任何失败路径下已拉起的 engine 由 `EngineSupervisor` 的 Drop 兜底终止
/// （O3：engine 不得遗留）。
pub async fn run_core(args: CoreArgs) -> i32 {
    // 1. 生效的 UI SID（管道 DACL + peer 验证的输入）。
    let ui_sid = match args.effective_ui_sid() {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("core: {e}");
            return 1;
        }
    };

    // 2. 共享日志聚合器（product 日志通道 = 磁盘聚合文件；UI 经 logs.list 拉取）。
    let logs = match LogAggregator::open_default() {
        Ok(logs) => logs,
        Err(e) => {
            eprintln!("core: open aggregated log failed: {e}");
            return 1;
        }
    };
    let logs = Arc::new(logs);
    let _ = logs.append_core(
        "info",
        "core",
        "core.start.booting",
        &format!(
            "core booting: ui_pid={} control_pipe={}",
            args.ui_pid, args.control_pipe
        ),
        &std::collections::BTreeMap::new(),
    );

    // 3. 提权拉起唯一特权进程 engine（拓扑门禁：非 elevated 即拒绝）。
    let mut supervisor = match EngineSupervisor::spawn_product(&ElevatedEngineSpawner) {
        Ok(supervisor) => supervisor,
        Err(e) => {
            let _ = logs.append_core(
                "error",
                "core",
                "core.engine.spawn_failed",
                &format!("engine spawn failed: {e}"),
                &std::collections::BTreeMap::new(),
            );
            eprintln!("core: {e}");
            return 1;
        }
    };
    let engine_pid = supervisor.pid().unwrap_or_default();

    // 4. 连接 engine gRPC 控制面（双向认证 Named Pipe；engine 是状态权威）。R2：有界轮询
    //    等 engine 就绪——原生判据 = 拨号+认证成功（`EngineControlGrpcClient::connect`）；
    //    keepalive 回复 = 替代信号（确认 gRPC 服务实际响应）。engine 冷启动慢不因首次拨号
    //    失败而终止 core；`connect` 内部已含拨号重试（30×100ms），此处兜底更长窗口。
    let user_sid = current_user_sid().unwrap_or_else(|| ui_sid.clone());
    let ready_start = Instant::now();
    let client = loop {
        // 每次迭代的失败事实（`Err` = 本拍拨号/认证/keepalive 未达成；`Ok` 仅经
        // `break` 返回 client，故循环内 `Err` 恒为最近一次未达成的详情）。
        let outcome: Result<(), String> = match EngineControlGrpcClient::connect(
            &engine_control_pipe_name(),
            engine_pid,
            &user_sid,
        )
        .await
        {
            Ok(client) => {
                // 原生判据达成（拨号+认证）。keepalive 确认：gRPC 服务实际响应才算就绪。
                let mut confirmed = client;
                match tokio::time::timeout(
                    ONESHOT_KEEPALIVE_CONFIRM_TIMEOUT,
                    confirmed.keep_alive(KeepAliveRequest { monotonic_tick: 0 }),
                )
                .await
                {
                    Ok(Ok(_)) => break confirmed,
                    Ok(Err(e)) => {
                        // 连接成功但 keepalive 未回复（gRPC 服务未就绪）→ 丢弃本 client，
                        // 下一拍重连（client Drop → liveness 监视因 Receiver 全弃自动退出）。
                        Err(format!("keepalive confirm rejected: {e:?}"))
                    }
                    Err(_) => Err("keepalive confirm timeout".to_string()),
                }
            }
            Err(e) => Err(format!("{e:?}")),
        };
        if ready_start.elapsed() >= ONESHOT_READY_TIMEOUT {
            let detail = outcome.unwrap_err();
            let _ = logs.append_core(
                "error",
                "core",
                "core.engine.connect_failed",
                &format!("engine control connect timed out: {detail}"),
                &std::collections::BTreeMap::new(),
            );
            eprintln!("core: engine control connect failed: {detail}");
            return 1; // supervisor Drop → engine 终止（O3）。
        }
        tokio::time::sleep(ONESHOT_READY_POLL).await;
    };
    let liveness = client.liveness();
    let engine: Arc<Mutex<dyn KernelEngineControl>> = Arc::new(Mutex::new(client));
    supervisor.attach_client(Arc::clone(&engine), liveness);
    // P3 崩溃自愈：共享 engine 控制面槽（服务/转发器/KeepAlive 与 CrashRecovery 共用；
    // respawn 换入新 client 后写路径自动指向新 engine）。
    let engine_slot = EngineSlot::new(engine);

    // 5. 组合：composition（绑定 engine 身份）+ KernelControlService + CoreRuntime。
    let engine_peer = engine_peer_for(engine_pid, &user_sid);
    let composition = match compose_nonprivileged_host(&engine_peer) {
        Ok(composition) => composition,
        Err(e) => {
            let _ = logs.append_core(
                "error",
                "core",
                "core.compose.failed",
                &format!("composition failed: {e:?}"),
                &std::collections::BTreeMap::new(),
            );
            eprintln!("core: composition failed: {e:?}");
            return 1;
        }
    };
    // 确保 key.bin 存在：全新安装时 host 启动即初始化，避免 config_set 保存密码静默
    // 失败（password key unavailable）→ connect KeyMissing（dbg-auth 2026-08-23 根因 #1）。
    let _ = exv_vpn_win32_config::ExvConfig::ensure_key(&exv_vpn_win32_config::config_dir());
    // 服务持共享日志聚合器；main 侧保留一份 Arc 供停机结果落盘（UI 可观测全生命周期）。
    let (shared_composition, service) = KernelControlService::from_composition(
        composition,
        engine_slot.clone(),
        exv_vpn_win32_config::config_dir(),
        Arc::clone(&logs),
    );
    // UI 生命周期信号（O3 强绑定）：CoreRuntime 与 serve 传输层共享同一事实——传输层
    // 的 UI 进程退出监视触发 on_ui_exited，run 的 select 等待同一信号。
    let ui = UiLifetime::new();
    let mut runtime = CoreRuntime::new(
        ui.clone(),
        Arc::clone(&shared_composition),
        supervisor,
    );

    // 6. serve UI 控制面：accept UI → 验证 peer → gate 授权 → UI 进程退出监视 →
    //    拉起事件/统计转发器。
    let handles = match serve_kernel_control_pipe(&args.control_pipe, &ui_sid, service, ui).await {
        Ok(handles) => handles,
        Err(e) => {
            eprintln!("core: serve kernel control pipe failed: {e}");
            return 1; // supervisor Drop → engine 终止（O3）。
        }
    };
    runtime.set_serve_task(handles.serve_task);
    runtime.set_forwarder_task(handles.forwarder);
    runtime.set_stats_forwarder_task(handles.stats_forwarder);
    runtime.set_logs_forwarder_task(handles.logs_forwarder);
    // C3a 自动重连 worker（host 侧重连驱动；停机先中止释放服务克隆引用）。
    runtime.set_reconnect_worker_task(handles.reconnect_worker);
    // P2 有界存留：KeepAlive 心跳 tick（engine 侧 15s 未收到即自清理+自退出）。
    runtime.set_keepalive_ticker_task(handles.keepalive_ticker);

    // P3 崩溃自愈：engine 掉线（liveness 翻 false）→ respawn 全链路——新提权拉起 → 新
    // client → composition 身份重建（engine PID 变）→ 回 Idle；不自动重连（用户再点连接
    // 走正常登录）。
    let recovery = CrashRecovery::new(
        Arc::new(ProductSupervisorFactory),
        Arc::new(GrpcClientConnector),
        Arc::new(SystemResidueProbe {
            adapter_name: ENGINE_ADAPTER_NAME.to_string(),
        }),
        engine_slot.clone(),
        Arc::clone(&shared_composition),
        handles.ui_peer,
        user_sid,
    );
    runtime.set_crash_recovery(recovery);

    // 7. 运行：等 UI 退出 / 显式停机 → 有序停机（发退出包后即返；engine 由三重保证
    //    随 core 退出，UI 只等 core）。
    let outcome = runtime.run().await;
    let summary = format!(
        "engine={:?} stop_requests={} rpc_waiter_cancellations={} teardown_started={}",
        outcome.engine,
        outcome.stop_requests,
        outcome.rpc_waiter_cancellations,
        outcome.teardown_started,
    );
    eprintln!("core: shutdown complete: {summary}");
    let _ = logs.append_core(
        "info",
        "core",
        "core.shutdown.complete",
        &summary,
        &std::collections::BTreeMap::new(),
    );
    0
}

#[tokio::main]
async fn main() {
    let args = match CoreArgs::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    let code = run_core(args).await;
    std::process::exit(code);
}

// ---------------------------------------------------------------------------
// 单元测试：参数解析契约（纯）+ UI SID 回退 + engine peer 身份组装。
// 进程级（拉起 engine → serve 管道 → 连接 → 停机）需真实 engine bin + 提权，
// 由外部集成验证（见任务报告）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `CoreArgs::parse`：必需参数齐备时解析成功且值一致。
    #[test]
    fn parse_full_args_round_trip() {
        let args = CoreArgs::parse(
            [
                "exv-core".to_string(),
                "--control-pipe".to_string(),
                r"\\.\pipe\exv-core-4242".to_string(),
                "--ui-pid".to_string(),
                "4242".to_string(),
                "--ui-sid".to_string(),
                "S-1-5-21-1-2-3-4".to_string(),
            ]
            .into_iter(),
        )
        .expect("full args parse");
        assert_eq!(args.control_pipe, r"\\.\pipe\exv-core-4242");
        assert_eq!(args.ui_pid, 4242);
        assert_eq!(args.ui_sid.as_deref(), Some("S-1-5-21-1-2-3-4"));
    }

    /// `CoreArgs::parse`：`--ui-sid` 缺省允许（`None`——core 回退当前用户 SID）。
    #[test]
    fn parse_ui_sid_optional() {
        let args = CoreArgs::parse(
            [
                "--control-pipe".to_string(),
                r"\\.\pipe\exv-core-7".to_string(),
                "--ui-pid".to_string(),
                "7".to_string(),
            ]
            .into_iter(),
        )
        .expect("parse without ui-sid");
        assert_eq!(args.ui_sid, None);
    }

    /// `CoreArgs::parse`：必需参数缺失 / `--ui-pid` 非数字 → `Err`。
    #[test]
    fn parse_rejects_missing_or_invalid_required_args() {
        // 缺 --control-pipe。
        assert!(CoreArgs::parse(
            ["--ui-pid".to_string(), "1".to_string()].into_iter(),
        )
        .is_err());
        // 缺 --ui-pid。
        assert!(CoreArgs::parse(
            [
                "--control-pipe".to_string(),
                r"\\.\pipe\exv-core-1".to_string(),
            ]
            .into_iter(),
        )
        .is_err());
        // --ui-pid 非数字。
        assert!(CoreArgs::parse(
            [
                "--control-pipe".to_string(),
                r"\\.\pipe\exv-core-1".to_string(),
                "--ui-pid".to_string(),
                "not-a-pid".to_string(),
            ]
            .into_iter(),
        )
        .is_err());
        // --control-pipe 空值。
        assert!(CoreArgs::parse(
            [
                "--control-pipe".to_string(),
                String::new(),
                "--ui-pid".to_string(),
                "1".to_string(),
            ]
            .into_iter(),
        )
        .is_err());
    }

    /// `CoreArgs::parse`：未知参数忽略（前向兼容），不影响必需参数解析。
    #[test]
    fn parse_ignores_unknown_args() {
        let args = CoreArgs::parse(
            [
                "--future-flag".to_string(),
                "x".to_string(),
                "--control-pipe".to_string(),
                r"\\.\pipe\exv-core-3".to_string(),
                "--ui-pid".to_string(),
                "3".to_string(),
            ]
            .into_iter(),
        )
        .expect("unknown args ignored");
        assert_eq!(args.control_pipe, r"\\.\pipe\exv-core-3");
        assert_eq!(args.ui_pid, 3);
    }

    /// `effective_ui_sid`：显式 `--ui-sid` 优先；缺省回退当前用户 SID（同用户拓扑）。
    #[test]
    fn effective_ui_sid_prefers_explicit_then_falls_back() {
        let explicit = CoreArgs {
            control_pipe: r"\\.\pipe\exv-core-1".to_string(),
            ui_pid: 1,
            ui_sid: Some("S-1-5-21-explicit".to_string()),
        };
        assert_eq!(
            explicit.effective_ui_sid().expect("explicit"),
            "S-1-5-21-explicit"
        );

        // 缺省回退：当前用户 SID 可解析时成功且等于 current_user_sid。
        let fallback = CoreArgs {
            control_pipe: r"\\.\pipe\exv-core-2".to_string(),
            ui_pid: 2,
            ui_sid: None,
        };
        match current_user_sid() {
            Some(sid) => assert_eq!(fallback.effective_ui_sid().expect("fallback"), sid),
            None => assert!(fallback.effective_ui_sid().is_err(), "无法解析 SID 时 fail closed"),
        }
    }

    /// `engine_peer_for`：PID + SID + 解析出的 account name 组装完整（composition 绑定
    /// engine 身份所需的三项身份事实齐备）。
    #[test]
    fn engine_peer_for_assembles_identity_facts() {
        let Some(sid) = current_user_sid() else {
            return; // 当前用户 SID 不可解析（极罕见）——诚实短路。
        };
        let peer = engine_peer_for(4242, &sid);
        assert_eq!(peer.process_id, 4242);
        assert_eq!(peer.user_sid, sid);
        assert!(
            !peer.account_name.is_empty(),
            "当前用户 SID 必须解析出 account name"
        );
    }
}
