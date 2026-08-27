// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
//
// S2-C 批量集成测试（真 engine 进程级）。贴近既有 `scm_integration` 惯例：真 SCM 场景
// 标 `#[ignore]` + env 门控（`EXV_SCM_INTEGRATION=1`），S5 业务验收跑。覆盖：
//   1. 文件生命周期对真 engine：host 写 req → engine 删 req → result 保留 → host 读后删。
//   2. engine 中途被杀 → result 缺失 → host 失败路径（host 侧缺 result 已有单测）。
//   3. 孤儿 watchdog：host 进程退出 → 批量 engine 退出（防孤儿）。
//   4. uninstall → VerifyRemoved（真 SCM，需 admin）。
//
// 进程级场景（被杀 / 孤儿）用「req 指向 named pipe 阻塞 engine」确定性模拟「批量进行中」，
// 不依赖真 SCM——engine 打开 req 管道后阻塞在 read 上，直至被杀 / host 退出触发 watchdog。
//
// 业务验收锚点（无法自动化，不硬编码）：**install 恰 1 次 UAC**——安装/修复/启动/卸载经
// `--service-batch` 一次 runas 完成（计划文档阶段 2 验收锚点），真 UAC 交互由 S5 人工验收。

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use exv_engine::service_batch::{
    BatchStep, ServiceBatchRequest, ServiceBatchResult, MAX_REQUEST_BYTES,
};
use exv_vpn_win32_ipc::named_pipe_io::NamedPipeByteStream;
use uuid::Uuid;

/// engine bin（cargo 为集成测试注入 `CARGO_BIN_EXE_exv-engine`）。
fn engine_bin() -> Option<PathBuf> {
    let path = std::env::var_os("CARGO_BIN_EXE_exv-engine").map(PathBuf::from)?;
    path.exists().then_some(path)
}

/// 测试进程是否 elevated（OpenProcessToken + TokenElevation；fail closed；真 SCM 门控）。
fn is_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TokenElevation};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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

/// 真 SCM 场景门控：`EXV_SCM_INTEGRATION=1`（admin 依赖由各测试自行判 elevated）。
fn scm_integration_gate() -> bool {
    if std::env::var("EXV_SCM_INTEGRATION").as_deref() != Ok("1") {
        eprintln!("S2-C SCM 集成门控: EXV_SCM_INTEGRATION=1 未置位，跳过");
        return false;
    }
    true
}

/// 临时目录：%TEMP%\exv-s2c-<pid>-<tag>。
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("exv-s2c-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// 写批量请求文件（host 角色）。DACL 形状（SYSTEM + 当前用户 SID）是 host 侧契约，
/// 由 S2-B host 单测覆盖（本测试聚焦 engine 侧文件生命周期）。
fn write_request(path: &Path, request: &ServiceBatchRequest) {
    let json = serde_json::to_vec(request).expect("serialize batch request");
    assert!(json.len() <= MAX_REQUEST_BYTES, "request must be within limit");
    std::fs::write(path, json).expect("write batch request file");
}

/// 读批量结果文件并校验 JSON 形状（`deny_unknown_fields`）。
fn read_result(path: &Path) -> ServiceBatchResult {
    let bytes = std::fs::read(path).expect("read batch result file");
    serde_json::from_slice(&bytes).expect("batch result JSON shape valid")
}

/// 有界等待子进程退出（`Some(code)`=已退出；`None`=超时）。
fn wait_exit(child: &mut Child, timeout: Duration) -> Option<i32> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("child try_wait") {
            return status.code();
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// spawn engine `--service-batch`（host-pid = 测试进程自身）并等待退出。
fn spawn_batch_and_wait(exe: &Path, req: &Path, res: &Path, timeout: Duration) -> Option<i32> {
    let mut engine = spawn_engine(exe, req, res, &std::process::id().to_string());
    wait_exit(&mut engine, timeout)
}

/// spawn engine `--service-batch`（host-pid 可指定，供孤儿场景注入外部 host 子进程）。
fn spawn_engine(exe: &Path, req: &Path, res: &Path, host_pid: &str) -> Child {
    Command::new(exe)
        .args([
            "--service-batch",
            "--request",
            &req.display().to_string(),
            "--result",
            &res.display().to_string(),
            "--host-pid",
            host_pid,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn engine --service-batch")
}

/// 创建阻塞 req 管道（server 实例；engine 作为 client 打开后阻塞在 read 上，确定性模拟
/// 「批量进行中」）。返回 `(pipe_name, connected_rx, release_tx)`：
/// - connect 线程在 engine 连上后发送 `connected_rx`；
/// - 线程保持 server 句柄存活直到 `release_tx` 被 drop（关闭句柄会让 engine 的 client
///   read 收到 EOF，不再阻塞）。
fn spawn_blocking_req_pipe() -> (String, Receiver<()>, Sender<()>) {
    let name = format!(
        r"\\.\pipe\exv-batch-req-{}-{}",
        std::process::id(),
        Uuid::new_v4().simple()
    );
    let server = NamedPipeByteStream::create_server(&name, 1)
        .unwrap_or_else(|e| panic!("create blocking req pipe {name}: {e:?}"));
    let (connected_tx, connected_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let _ = server.connect();
        let _ = connected_tx.send(());
        // 保持 server 句柄存活（见函数注释）。
        let _ = release_rx.recv();
    });
    (name, connected_rx, release_tx)
}

/// 等 engine 连上阻塞管道（server 侧 ConnectNamedPipe resolve）；engine 中途退出 → panic
/// （setup 失败：engine 未到达批量阻塞点）。
fn wait_pipe_connect(rx: &Receiver<()>, engine: &mut Child, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = engine.try_wait().expect("engine try_wait") {
            panic!("engine exited before connecting to block pipe: {status}");
        }
        if rx.try_recv().is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("engine did not connect to block pipe within {timeout:?}");
}

// ---------------------------------------------------------------------------
// 1. 文件生命周期对真 engine（VerifyRemoved：非 admin 可跑，仍触真 SCM 查询）。
// ---------------------------------------------------------------------------

/// host 写 req → engine 删 req → result 保留 → host 读后删（真 engine 二进制）。
#[test]
#[ignore = "process-level engine batch integration (opt-in: EXV_SCM_INTEGRATION=1 + real engine bin)"]
fn service_batch_file_lifecycle_on_real_engine() {
    if !scm_integration_gate() {
        return;
    }
    let Some(exe) = engine_bin() else {
        eprintln!("SKIP: engine bin not built (run cargo build first)");
        return;
    };
    let dir = temp_dir("lifecycle");
    let req = dir.join("req.json");
    let res = dir.join("res.json");
    write_request(
        &req,
        &ServiceBatchRequest {
            version: 1,
            sequence: vec![BatchStep::VerifyRemoved],
            config_dir: exv_vpn_win32_config::config_dir()
                .to_string_lossy()
                .into_owned(),
        },
    );

    let exit = spawn_batch_and_wait(&exe, &req, &res, Duration::from_secs(30))
        .expect("engine must exit within 30s");
    // 生命周期契约与步骤成败无关：engine 必删 req、必保留 result、host 读后删。
    // VerifyRemoved 的成败依赖本机 SCM 状态（服务是否已装，如本机 exv-engine 已装 →
    // 该步 ok=false + 退出码 1）——生命周期测试不钉步骤成败，只钉文件契约。
    assert!(!req.exists(), "engine 必须删除已消费的 req 文件");
    assert!(res.exists(), "result 文件必须保留给 host 读取");
    let result = read_result(&res);
    assert_eq!(
        result.steps.len(),
        1,
        "批量必须实际执行单步（结果 JSON 携带步骤结论）"
    );
    assert_eq!(result.steps[0].step, BatchStep::VerifyRemoved);
    std::fs::remove_file(&res).expect("host 读后删除 result");
    eprintln!("lifecycle exit={exit:?}, step_ok={}", result.steps[0].ok);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 2. engine 中途被杀 → result 缺失 → host 失败路径。
// ---------------------------------------------------------------------------

/// engine 在批量进行中（阻塞于 req 管道 read）被杀 → result 文件缺失（批量未完成）。
#[test]
#[ignore = "process-level engine batch integration (opt-in: real engine bin)"]
fn service_batch_engine_killed_leaves_no_result() {
    let Some(exe) = engine_bin() else {
        eprintln!("SKIP: engine bin not built (run cargo build first)");
        return;
    };
    let dir = temp_dir("killed");
    let res = dir.join("res.json");
    let (pipe_name, connected_rx, _release) = spawn_blocking_req_pipe();

    let mut engine = Command::new(&exe)
        .args([
            "--service-batch",
            "--request",
            &pipe_name,
            "--result",
            &res.display().to_string(),
            "--host-pid",
            &std::process::id().to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn engine --service-batch");

    // engine 已连上 req 管道（阻塞在 read）——批量确认「进行中」。
    wait_pipe_connect(&connected_rx, &mut engine, Duration::from_secs(15));
    let _ = engine.kill();
    let exit = wait_exit(&mut engine, Duration::from_secs(15)).expect("engine must exit after kill");
    assert!(
        !res.exists(),
        "engine 中途被杀 → result 文件不得出现（批量未完成 → host 失败路径）"
    );
    eprintln!("killed engine exit={exit:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 3. 孤儿 watchdog：host 进程退出 → 批量 engine 退出（防孤儿）。
// ---------------------------------------------------------------------------

/// host（powershell sleep 子进程）在批量进行中退出 → 批量 engine 必须随之退出（不遗留），
/// 且不以成功码退出、不产出 result（批量未完成）。
#[test]
#[ignore = "process-level orphan watchdog integration (opt-in: real engine bin)"]
fn service_batch_orphan_watchdog_kills_engine_when_host_exits() {
    let Some(exe) = engine_bin() else {
        eprintln!("SKIP: engine bin not built (run cargo build first)");
        return;
    };
    let dir = temp_dir("orphan");
    let res = dir.join("res.json");
    let (pipe_name, connected_rx, _release) = spawn_blocking_req_pipe();

    // host 子进程：真实存活进程（powershell sleep），engine 的 --host-pid 指向它。
    let mut host = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Sleep -Seconds 120",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn host child");
    let host_pid = host.id();

    let mut engine = spawn_engine(&exe, Path::new(&pipe_name), &res, &host_pid.to_string());
    // engine 已连上 req 管道（阻塞在 read）——批量确认「进行中」，host 此刻被杀。
    wait_pipe_connect(&connected_rx, &mut engine, Duration::from_secs(15));
    let _ = host.kill();
    let _ = host.wait();

    // 孤儿 watchdog：host 退出 → 批量 engine 退出（不遗留）。
    let exit = wait_exit(&mut engine, Duration::from_secs(15))
        .expect("engine must exit within 15s after host death (orphan watchdog)");
    assert_ne!(exit, 0, "孤儿路径 engine 不得以成功码退出（批量未完成）");
    assert!(!res.exists(), "孤儿路径 result 不得出现（批量未完成）");
    eprintln!("orphan engine exit={exit:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 4. 真 SCM：install [Install,Start,Verify] → uninstall [Uninstall,VerifyRemoved]。
//    需 admin（测试进程提权，engine 继承 token）。清理：uninstall 在断言失败时也尽力执行。
// ---------------------------------------------------------------------------

/// SCM 真机全链（install → uninstall → VerifyRemoved）经 `--service-batch` 真 engine。
#[test]
#[ignore = "SCM 集成真机（需 admin + 真实服务环境），S5 业务验收跑"]
fn service_batch_install_uninstall_on_real_scm() {
    if !scm_integration_gate() {
        return;
    }
    if !is_elevated() {
        eprintln!("S2-C SCM 集成真机: 测试进程非提权，跳过（需 admin）");
        return;
    }
    let Some(exe) = engine_bin() else {
        eprintln!("SKIP: engine bin not built (run cargo build first)");
        return;
    };
    let dir = temp_dir("scm");
    let config_dir = dir.join("cfg");
    let _ = std::fs::create_dir_all(&config_dir);

    // 安装/修复序列 [Install,Start,Verify]（一次 runas 的批量等价；测试直接 spawn 继承提权 token）。
    let req_i = dir.join("req-install.json");
    let res_i = dir.join("res-install.json");
    write_request(
        &req_i,
        &ServiceBatchRequest {
            version: 1,
            sequence: vec![BatchStep::Install, BatchStep::Start, BatchStep::Verify],
            config_dir: config_dir.display().to_string(),
        },
    );

    // 失败时也尽力卸载，避免遗留已注册服务（config_dir 与 install 一致——validate_request
    // 要求绝对路径，空串会被拒绝，卸载步骤不执行）。
    struct ScmCleanup {
        exe: PathBuf,
        dir: PathBuf,
        config_dir: PathBuf,
    }
    impl Drop for ScmCleanup {
        fn drop(&mut self) {
            let req = self.dir.join("cleanup-req.json");
            let res = self.dir.join("cleanup-res.json");
            let _ = std::fs::write(
                &req,
                serde_json::to_vec(&ServiceBatchRequest {
                    version: 1,
                    sequence: vec![BatchStep::Uninstall, BatchStep::VerifyRemoved],
                    config_dir: self.config_dir.display().to_string(),
                })
                .expect("serialize cleanup request"),
            );
            let _ = spawn_batch_and_wait(&self.exe, &req, &res, Duration::from_secs(60));
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
    let _cleanup = ScmCleanup {
        exe: exe.clone(),
        dir: dir.clone(),
        config_dir: config_dir.clone(),
    };

    let exit = spawn_batch_and_wait(&exe, &req_i, &res_i, Duration::from_secs(60))
        .expect("install batch must exit within 60s");
    assert_eq!(exit, 0, "install batch must exit 0");
    let result_i = read_result(&res_i);
    assert!(result_i.ok, "install batch ok: {}", result_i.message);
    assert!(!req_i.exists(), "req 必须被 engine 删除");

    // 卸载序列 [Uninstall,VerifyRemoved]。
    let req_u = dir.join("req-uninstall.json");
    let res_u = dir.join("res-uninstall.json");
    write_request(
        &req_u,
        &ServiceBatchRequest {
            version: 1,
            sequence: vec![BatchStep::Uninstall, BatchStep::VerifyRemoved],
            config_dir: config_dir.display().to_string(),
        },
    );
    let exit = spawn_batch_and_wait(&exe, &req_u, &res_u, Duration::from_secs(60))
        .expect("uninstall batch must exit within 60s");
    assert_eq!(exit, 0, "uninstall batch must exit 0");
    let result_u = read_result(&res_u);
    assert!(result_u.ok, "uninstall batch ok: {}", result_u.message);
    assert_eq!(
        result_u.steps.last().map(|s| s.step),
        Some(BatchStep::VerifyRemoved),
        "uninstall 序列末步必须 VerifyRemoved"
    );
    assert!(
        result_u.steps.last().is_some_and(|s| s.ok),
        "VerifyRemoved 必须成功（服务已不存在）"
    );
}
