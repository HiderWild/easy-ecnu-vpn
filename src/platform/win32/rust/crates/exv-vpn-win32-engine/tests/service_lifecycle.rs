// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// S2 服务生命周期独立测试（tests/service_lifecycle.rs）——不与 S1（packet_relay.rs /
// grpc_server.rs admission+relay）或 t1-stats（data_plane/stats/tunnel_runtime/cstp）
// 撞测试文件。覆盖：
// - [`EngineExitForm`] 分派（service 形态禁用心跳自清理 + core-pid watch，SCM 管生死）；
// - 服务 accept-loop（注入 fake server：连续 accept / SCM stop / 服务端关闭 / 失败传播）；
// - 服务停止 → 退出清理入口触发（accept-loop 返回 `Stopped` = 清理入口的触发信号）；
// - engine 子命令解析 + SCM failure actions（SC_ACTION_RESTART）。
//
// SCM 集成真机（需 admin）分栏：标 `#[ignore]` + env 门控（`EXV_SCM_INTEGRATION=1` 且
// 测试进程已提权），属 S5 业务验收的 opt-in 预演。

use std::path::PathBuf;
use std::time::Duration;

use exv_engine::grpc_transport::{
    accept_loop, AcceptLoopOutcome, AcceptServe, ControlPlaneReady,
};
use exv_engine::service::{
    parse_install_options, restart_failure_actions, EngineExitForm, SERVICE_CONTROL_PIPE,
    SERVICE_DISPLAY_NAME, SERVICE_NAME,
};

#[tokio::test]
async fn service_startup_ready_is_one_shot_and_failure_is_not_running() {
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let mut ready = ControlPlaneReady::new(tx);

    assert!(tokio::time::timeout(Duration::from_millis(5), &mut rx)
        .await
        .is_err());
    ready.report_ready().expect("ready receiver is alive");
    assert_eq!(rx.await.expect("ready notification"), Ok(()));
    assert_eq!(ready.report_ready(), Err("control-plane readiness already reported".to_string()));
}

// ---------------------------------------------------------------------------
// EngineExitForm 分派（D1）：service 形态禁用心跳自清理 + core-pid watch。
// ---------------------------------------------------------------------------

/// oneshot 形态：启用心跳 + core 进程句柄监视（生命周期 = core）。
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

/// service 形态：**无心跳**、**无 core-pid watch**——SCM 管生死（验收判据 3）。
#[test]
fn service_form_disables_heartbeat_and_core_watch() {
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let form = EngineExitForm::Service { scm_stop: rx };
    assert!(
        !form.uses_heartbeat(),
        "service 形态必须禁用心跳自清理（SCM 管生死，验收判据 3）"
    );
    assert!(
        !form.uses_core_process_watch(),
        "service 形态必须禁用 core 进程句柄监视（无单一 core 可等）"
    );
    assert_eq!(form.core_handle(), None);
    assert_eq!(form.heartbeat_timeout(), None);
}

// ---------------------------------------------------------------------------
// 服务 accept-loop（注入 fake server）：连续 accept / SCM stop / 服务端关闭 / 失败。
// ---------------------------------------------------------------------------

/// 记录型 fake acceptor（注入 fake server 的可测 seam）：可配置连续 N 次后服务端关闭、
/// 或第 1 次即失败、或永远继续。
///
/// 注：每次 serve 前 `sleep(1ms)` 模拟真实 [`ServiceAcceptor`] 阻塞于 accept 的行为——
/// 当前线程 tokio runtime 下，完全立即返回的 busy-loop 会饿死计时器驱动（SCM stop
/// 信号测试将永不触发）。
struct FakeAcceptor {
    served: u32,
    stop_after: Option<u32>,
    fail_with: Option<String>,
}

impl AcceptServe for FakeAcceptor {
    async fn serve_one(&mut self) -> Result<bool, String> {
        if let Some(fail) = &self.fail_with {
            return Err(fail.clone());
        }
        // 模拟真实 accept 阻塞（真实 acceptor await pipe connect，让出驱动）。
        tokio::time::sleep(Duration::from_millis(1)).await;
        self.served += 1;
        if let Some(n) = self.stop_after
            && self.served >= n
        {
            return Ok(false);
        }
        Ok(true)
    }
}

/// 服务端连续 accept：每个 serve_one 独立（独立 verify / 独立 owner 流），循环推进直到
/// 服务端关闭。
#[tokio::test]
async fn service_accept_loop_continues_until_server_closed() {
    let acceptor = FakeAcceptor {
        served: 0,
        stop_after: Some(3),
        fail_with: None,
    };
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let outcome = accept_loop(acceptor, rx).await;
    assert_eq!(
        outcome,
        AcceptLoopOutcome::ServerClosed,
        "服务端关闭（Ok(false)）必须结束 accept-loop"
    );
}

/// SCM stop → accept-loop 返回 `Stopped`（= 退出清理路径的入口触发，验收判据 5）。
#[tokio::test]
async fn service_accept_loop_stops_on_scm_stop() {
    let acceptor = FakeAcceptor {
        served: 0,
        stop_after: None,
        fail_with: None,
    };
    let (tx, rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(accept_loop(acceptor, rx));
    tokio::time::sleep(Duration::from_millis(20)).await;
    tx.send(true).expect("stop signal send");
    let outcome = tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("loop within timeout")
        .expect("task ok");
    assert_eq!(
        outcome,
        AcceptLoopOutcome::Stopped,
        "SCM 停止信号必须让 accept-loop 返回 Stopped（退出清理入口触发）"
    );
}

/// 停止信号发送端 drop → 视同停止（防 busy-loop）。
#[tokio::test]
async fn service_accept_loop_treats_sender_drop_as_stop() {
    let acceptor = FakeAcceptor {
        served: 0,
        stop_after: None,
        fail_with: None,
    };
    let (tx, rx) = tokio::sync::watch::channel(false);
    drop(tx);
    let outcome = accept_loop(acceptor, rx).await;
    assert_eq!(
        outcome,
        AcceptLoopOutcome::Stopped,
        "停止信号发送端 drop 必须视同停止（防 busy-loop）"
    );
}

/// 失败传播：serve_one 返回 Err → `Failed`（携带原因；循环终止）。
#[tokio::test]
async fn service_accept_loop_propagates_failure() {
    let acceptor = FakeAcceptor {
        served: 0,
        stop_after: None,
        fail_with: Some("boom".to_string()),
    };
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let outcome = accept_loop(acceptor, rx).await;
    assert_eq!(
        outcome,
        AcceptLoopOutcome::Failed("boom".to_string()),
        "serve_one 失败必须传播"
    );
}

// ---------------------------------------------------------------------------
// engine 子命令解析 + SCM failure actions。
// ---------------------------------------------------------------------------

/// `--service-install` 可选参数解析：显式 `--dll`/`--adapter-name`/`--user-sid` 覆盖缺省。
#[test]
fn service_install_options_honor_overrides() {
    let argv = vec![
        "exv-engine".to_string(),
        "--service-install".to_string(),
        "--dll".to_string(),
        r"C:\custom\wintun.dll".to_string(),
        "--adapter-name".to_string(),
        "MyAdapter".to_string(),
        "--user-sid".to_string(),
        "S-1-5-21-1-2-3-4".to_string(),
    ];
    let opts = parse_install_options(&argv).expect("parse");
    assert_eq!(opts.dll, PathBuf::from(r"C:\custom\wintun.dll"));
    assert_eq!(opts.adapter_name, "MyAdapter");
    assert_eq!(opts.core_user_sid, "S-1-5-21-1-2-3-4");
}

/// SCM failure actions（CR R3.1）：崩溃后 `SC_ACTION_RESTART`，1s 延迟。
#[test]
fn failure_actions_restart_after_crash() {
    use windows_service::service::ServiceActionType;
    let actions = restart_failure_actions();
    let list = actions.actions.expect("actions present");
    assert_eq!(list.len(), 1, "单一 SC_ACTION_RESTART");
    assert_eq!(list[0].action_type, ServiceActionType::Restart);
    assert_eq!(list[0].delay, Duration::from_secs(1));
}

/// 服务常量（SCM/UI 契约的稳定标识）。
#[test]
fn service_constants_are_stable() {
    assert_eq!(SERVICE_NAME, "exv-engine");
    assert!(!SERVICE_DISPLAY_NAME.is_empty());
    assert!(SERVICE_CONTROL_PIPE.starts_with(r"\\.\pipe\"));
}

// ---------------------------------------------------------------------------
// SCM 集成真机（需 admin；默认跳过）
// 门控：`EXV_SCM_INTEGRATION=1` 且测试进程已提权。真实安装/启动/停止/卸载 engine 服务。
// 属 S5 业务验收的 opt-in 预演——S2 只做可单测逻辑 + 真机标注。
// ---------------------------------------------------------------------------

/// 测试进程是否 elevated（OpenProcessToken + TokenElevation；fail closed）。
fn is_elevated() -> bool {
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::Foundation::CloseHandle;
    let process = unsafe { GetCurrentProcess() };
    let mut token = windows::Win32::Foundation::HANDLE::default();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        return false;
    }
    let mut elevated = false;
    let mut size = 0u32;
    unsafe {
        let _ = GetTokenInformation(token, TokenElevation, None, 0, &raw mut size);
    }
    if size != 0 {
        let mut buffer = vec![0u8; size as usize];
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some(buffer.as_mut_ptr().cast()),
                size,
                &raw mut size,
            )
        };
        if ok.is_ok() && buffer.len() >= 4 {
            elevated = u32::from_ne_bytes(buffer[0..4].try_into().unwrap_or([0u8; 4])) != 0;
        }
    }
    unsafe {
        let _ = CloseHandle(token);
    }
    elevated
}

/// 真机全链：安装 → 启动 → 卸载（engine 子命令，本机 admin）。
#[test]
#[ignore = "SCM 集成真机（需 admin + 真实服务环境），S5 业务验收跑"]
fn scm_integration_install_start_uninstall() {
    if std::env::var("EXV_SCM_INTEGRATION").as_deref() != Ok("1") {
        eprintln!("S2 SCM 集成真机: EXV_SCM_INTEGRATION=1 未置位，跳过");
        return;
    }
    if !is_elevated() {
        eprintln!("S2 SCM 集成真机: 测试进程非提权，跳过（需 admin）");
        return;
    }
    let argv = vec!["exv-engine".to_string(), "--service-install".to_string()];
    exv_engine::service::install_service(&argv)
        .expect("S2 SCM 集成真机: 安装 engine 服务");
    exv_engine::service::start_service()
        .expect("S2 SCM 集成真机: 启动 engine 服务");
    exv_engine::service::uninstall_service()
        .expect("S2 SCM 集成真机: 卸载 engine 服务");
}
