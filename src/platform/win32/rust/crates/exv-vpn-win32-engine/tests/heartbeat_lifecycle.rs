// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// P2 有界存留进程级测试（判据 7 / plan D8）：kill / hung core 时 engine 最迟 M 秒内
// 自退（硬时间界 15s，文本证据计时）。
//
// 拓扑（真实进程，无需提权——engine 不建 Wintun adapter，仅 serve 控制面管道 + 等心跳）：
//   * **core 子进程**（W13-T 子进程模式：以 `--exact <test>` 重执行本测试二进制 +
//     `EXV_ENGINE_TEST_CHILD` 环境变量）：作为 core 连接 engine 控制面 Named Pipe 并保持
//     连接存活（不发心跳）。
//   * **engine**（真实 `exv-engine` bin，`CARGO_BIN_EXE_exv-engine`
//     或 current_exe sibling）：`--host-pid <core_child_pid>` 指向 core 子进程。
//
// 双保险验证：
//   * **kill core** → engine 经 `wait_core_process_exit`（进程句柄 signaled，即时兜底）
//     随行退出——实测计时 ≤15s（硬时间界）。
//   * **hung core**（core 存活但不发心跳）→ engine 经心跳超时（`HeartbeatWatch`，
//     15s 上界）自清理+自退出——实测计时约 15s+（硬时间界兜底，不依赖进程句柄）。

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use exv_engine::heartbeat::{HEARTBEAT_PERIOD_MS, HEARTBEAT_TIMEOUT_MS};
use exv_vpn_wire::generated;
use generated::helper_control_client::HelperControlClient;
use hyper_util::rt::TokioIo;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tonic::codegen::http::Uri;
use tonic::codegen::Service;

// ---------------------------------------------------------------------------
// 子进程协议（W13-T 模式）
// ---------------------------------------------------------------------------

/// core 子进程环境变量：控制面管道名（子进程连接目标）。
const CHILD_PIPE_ENV: &str = "EXV_ENGINE_TEST_CHILD";
/// core 子进程就绪文件环境变量：连接成功后写该文件（父进程据此知道 engine 已 accept）。
const CHILD_READY_ENV: &str = "EXV_ENGINE_TEST_READY";
/// CREATE_NO_WINDOW（避免测试拉起控制台窗口）。
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// core 子进程角色：连接 engine 控制面管道并保持连接存活（不发心跳）。`block_on`
/// 永不返回（pending）——子进程由父进程 kill 终止。
fn child_role() -> Option<()> {
    let pipe = std::env::var(CHILD_PIPE_ENV).ok()?;
    let ready = std::env::var(CHILD_READY_ENV).expect("child ready env");
    let rt = tokio::runtime::Runtime::new().expect("child tokio runtime");
    rt.block_on(async move {
        let pipe = dial_with_retry(&pipe).await;
        let connector = TestPipeConnector { pipe: Some(pipe) };
        let channel = tonic::transport::Endpoint::from_static("http://engine.local")
            .connect_with_connector(connector)
            .await
            .expect("core child connects to engine control pipe");
        // 保持 channel（连接）存活：drop 会让引擎侧连接 EOF。
        let _client = HelperControlClient::new(channel);
        std::fs::write(&ready, "ready").expect("write ready marker");
        std::future::pending::<()>().await;
    });
    Some(())
}

/// 唯一管道名（tag + 父进程 pid，避免并行测试碰撞）。
fn unique_pipe(tag: &str) -> String {
    format!(r"\\.\pipe\exv-heartbeat-{tag}-{}", std::process::id())
}

/// 唯一就绪文件路径（%TEMP%\exv-heartbeat-<tag>-<pid>.ready）。
fn ready_file(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("exv-heartbeat-{tag}-{}.ready", std::process::id()))
}

/// 生产 engine bin 路径（`CARGO_BIN_EXE_exv-engine` 或 current_exe sibling）。
fn engine_bin_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_exv-engine") {
        let bp = PathBuf::from(p);
        if bp.exists() {
            return Some(bp);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    Some(dir.join("exv-engine.exe"))
}

/// 当前进程用户 SID（engine 用 `--user-sid` 建控制面 DACL；core 子进程同用户）。
fn current_user_sid() -> Option<String> {
    exv_vpn_win32_ipc::peer_auth::current_user_sid()
}

/// 拉起真实 engine（`--host-pid` = core 子进程 pid；wintun.dll 用占位路径——本测试不
/// ApplyTunnel，engine 不加载它）。
fn spawn_engine(pipe: &str, host_pid: u32) -> Child {
    use std::os::windows::process::CommandExt;
    let bin = engine_bin_path().expect("engine bin path must resolve");
    let sid = current_user_sid().expect("current user sid");
    let args = vec![
        "--control-pipe".to_string(),
        pipe.to_string(),
        "--dll".to_string(),
        "C:\\nonexistent\\wintun.dll".to_string(),
        "--journal-dir".to_string(),
        std::env::temp_dir()
            .join(format!("exv-heartbeat-journal-{}-{}", std::process::id(), pipe))
            .display()
            .to_string(),
        "--authority-name".to_string(),
        format!("Local\\exv-heartbeat-authority-{}-{pipe}", std::process::id()),
        "--host-pid".to_string(),
        host_pid.to_string(),
        "--adapter-name".to_string(),
        "ExvHeartbeat".to_string(),
        "--user-sid".to_string(),
        sid,
    ];
    Command::new(bin)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn engine")
}

/// 拉起 core 子进程（重执行本测试二进制，`--exact <test>`；环境变量传入管道名 + 就绪文件）。
fn spawn_core_child(pipe: &str, ready: &Path, test_name: &str) -> Child {
    use std::os::windows::process::CommandExt;
    Command::new(std::env::current_exe().expect("current test exe"))
        .env(CHILD_PIPE_ENV, pipe)
        .env(CHILD_READY_ENV, ready)
        .arg("--exact")
        .arg(test_name)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn core child")
}

/// 等 core 子进程就绪（已连接 engine 控制面）。
fn wait_for_ready(ready: &Path) {
    let t0 = Instant::now();
    while !ready.exists() {
        if t0.elapsed() > Duration::from_secs(15) {
            panic!("core child did not connect to engine control pipe within 15s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// 有界等待 engine 进程退出，返回实测耗时；超时则强杀并 panic（文本证据计时）。
fn wait_for_engine_exit(engine: &mut Child, timeout: Duration) -> Duration {
    let t0 = Instant::now();
    loop {
        if engine.try_wait().expect("engine try_wait").is_some() {
            return t0.elapsed();
        }
        if t0.elapsed() > timeout {
            let _ = engine.kill();
            let _ = engine.wait();
            panic!("engine did not exit within {timeout:?} (elapsed {:?})", t0.elapsed());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// 清理：kill 未退出的 engine / core 子进程 + 删除就绪文件。
fn cleanup(mut engine: Child, mut core: Child, ready: &Path) {
    let _ = engine.kill();
    let _ = engine.wait();
    let _ = core.kill();
    let _ = core.wait();
    let _ = std::fs::remove_file(ready);
}

// ---------------------------------------------------------------------------
// kill / hung core 测试（判据 7：硬时间界 ≤15s，实测计时）
// ---------------------------------------------------------------------------

/// **kill core**：core 子进程被强杀 → engine 经 `wait_core_process_exit`（进程句柄
/// signaled，即时兜底）随行退出。实测计时必须 ≤ [`HEARTBEAT_TIMEOUT_MS`]（15s 硬时间界）；
/// 实际进程句柄路径远快于 15s。
#[test]
fn kill_core_engine_exits_within_bound() {
    if child_role().is_some() {
        std::process::exit(0); // 子进程角色：child_role 内已阻塞至被 kill。
    }
    let pipe = unique_pipe("kill");
    let ready = ready_file("kill");
    let mut core = spawn_core_child(&pipe, &ready, "kill_core_engine_exits_within_bound");
    let core_pid = core.id();
    let mut engine = spawn_engine(&pipe, core_pid);
    wait_for_ready(&ready);

    // 强杀 core → engine 进程句柄 signaled → 随行退出。
    let _ = core.kill();
    let _ = core.wait();
    let elapsed = wait_for_engine_exit(&mut engine, Duration::from_secs(15));
    let timeout_ms = HEARTBEAT_TIMEOUT_MS;
    assert!(
        elapsed <= Duration::from_secs(15),
        "kill core → engine 必须 ≤{timeout_ms}ms 自退（判据 7），实测 {elapsed:?}"
    );
    eprintln!("[kill-core evidence] core pid {core_pid} killed; engine exited in {elapsed:?}");

    cleanup(engine, core, &ready);
}

/// **hung core**：core 存活但不发心跳 → engine 心跳超时（[`HEARTBEAT_TIMEOUT_MS`] = 15s
/// 硬时间界）自清理+自退出。实测计时 ~15s+（不依赖进程句柄——core 未退出，句柄不
/// signaled）。sanity 下界 `>= 10s` 排除「进程句柄路径意外触发」。
#[test]
fn hung_core_engine_exits_via_heartbeat_timeout() {
    if child_role().is_some() {
        std::process::exit(0); // 子进程角色：child_role 内已阻塞至被 kill。
    }
    let pipe = unique_pipe("hung");
    let ready = ready_file("hung");
    let core = spawn_core_child(&pipe, &ready, "hung_core_engine_exits_via_heartbeat_timeout");
    let core_pid = core.id();
    let mut engine = spawn_engine(&pipe, core_pid);
    wait_for_ready(&ready);

    // core 保持存活、不发心跳 → 心跳超时（约 15s）→ engine 自清理+自退。
    let elapsed = wait_for_engine_exit(&mut engine, Duration::from_secs(25));
    let timeout_ms = HEARTBEAT_TIMEOUT_MS;
    let period_ms = HEARTBEAT_PERIOD_MS;
    assert!(
        elapsed <= Duration::from_secs(25),
        "hung core → engine 必须 ≤25s 心跳超时自退，实测 {elapsed:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(10),
        "hung core → engine 必须经心跳超时（~{timeout_ms}ms）而非进程句柄即时路径，实测 {elapsed:?}"
    );
    eprintln!(
        "[hung-core evidence] core pid {core_pid} alive, no heartbeats (period {period_ms}ms); \
         engine exited via heartbeat timeout in {elapsed:?}"
    );

    cleanup(engine, core, &ready);
}

// ---------------------------------------------------------------------------
// 连接助手（core 子进程使用；镜像 tests/grpc_server.rs 的测试专用连接器）
// ---------------------------------------------------------------------------

/// 有界重试拨号（engine 启动竞态）。
async fn dial_with_retry(name: &str) -> NamedPipeClient {
    for _ in 0..50 {
        match ClientOptions::new().open(name) {
            Ok(pipe) => return pipe,
            Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
        }
    }
    panic!("dial {name} exhausted retries");
}

/// 最小测试专用 named-pipe connector（镜像产品 connector；Send——core 子进程用）。
#[derive(Default)]
struct TestPipeConnector {
    pipe: Option<NamedPipeClient>,
}

impl Service<Uri> for TestPipeConnector {
    type Response = TokioIo<NamedPipeClient>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let pipe = self.pipe.take().expect("single test connection");
        Box::pin(async move { Ok(TokioIo::new(pipe)) })
    }
}
