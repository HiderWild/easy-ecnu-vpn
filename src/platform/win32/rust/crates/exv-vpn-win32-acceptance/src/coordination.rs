// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! core 协调层（阶段 4-ii-b）：school-scenario bin 的 core 侧编排。
//!
//! 两进程架构最终形态：**core**（普通用户 token，纯协调层）读 `ExvConfig` → 解密凭据 →
//! 组装 `ConnectRequest`（`server`/`real_ip`/`credentials`/`user_agent`/`mtu`/`routes`）→
//! 提权拉起唯一特权进程 **engine**（`engine_spawn`）→ 经控制面 Named Pipe（`control_client`）
//! 双向认证 → 发 `Connect` → 收 `StatusChanged`/`Stats`/`Error` → 展示/记录 → 发
//! `Disconnect` → 等待 engine 退出清理。认证/CSTP/数据面/建卡/写路由全部在 engine，
//! core 只指挥、不碰数据/特权/Wintun。
//!
//! **权限拓扑（新模型）**：core 普通（`core_token_elevated == false` 是**预期**）；
//! engine 特权（`engine_token_elevated` 必须为 true，fail closed）。本模块对 core
//! elevated 诚实标记 `WIN_ACCEPTANCE_ENV_INVALID:core_elevated_unexpected`（不冒充）；
//! 对 engine 非特权标记 `WIN_ACCEPTANCE_ENV_INVALID:engine_not_elevated`。
//!
//! **凭据**：来自 config 解密（`ExvConfig::decrypt_password` + 独立 `key.bin`），
//! 一次性组装进 `Credentials`，经 `send_owned` 发送后由协议层零化；本地明文
//! `password` 在组装后 best-effort 零化。证据只记录 `password_decrypted` 事实，
//! 绝不记录明文。
//!
//! **证据**：新建 `CoreCoordinationEvidence`（core 侧可诚实观测的事实——拓扑 /
//! config / 解析 / 控制面 / 状态机 / 统计 / 断连清理），写入 `school-scenario.json`
//! 供验收消费。旧 `SchoolScenarioEvidence`（school.rs 单进程 flow 的证据）保留，
//! 由旧 oracle 测试继续消费。

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use exv_vpn_win32_config::ExvConfig;
use exv_core::control_client::EngineControlClient;
use exv_vpn_win32_ipc::engine_protocol::{
    ConnectRequest, Credentials, EngineState, EngineToCore,
};
use exv_vpn_win32_ipc::log_pipe::{LogPipeServer, LOG_PIPE_MAX_INSTANCES, LOG_PIPE_NAME};
use exv_vpn_win32_ipc::peer_auth::current_user_sid;

use crate::core_log;
use crate::direct_connect;
use crate::engine_spawn::{
    engine_args_for_spawn, engine_bin_path, engine_control_pipe_name, spawn_engine_elevated,
    verify_engine_elevated,
};
use crate::evidence::{ENV_INVALID_PREFIX, ENV_STATE_COMPLETED, NOT_RUN_BLOCKED_PREFIX};
use crate::scenarios::controlled;

// ---------------------------------------------------------------------------
// 证据结构：core 协调层可诚实观测的事实。
// ---------------------------------------------------------------------------

/// core 协调层证据。验收证明「core 普通 + engine 特权 + 连接成功」：
/// `core_token_elevated=false`（预期普通）+ `engine_token_elevated=true` +
/// `connected` + `route_applied` + `disconnect_sent`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
#[allow(clippy::struct_excessive_bools)] // 证据结构：协调层可观测的布尔事实集合，语义独立
pub struct CoreCoordinationEvidence {
    /// `completed` 或 `WIN_ACCEPTANCE_ENV_INVALID:<predicate>` /
    /// `not_run/blocked_by_environment:<predicate>`。
    pub environment_state: String,
    // ---- 拓扑事实（新权限模型） ----
    /// core（本进程）PID。
    pub core_pid: Option<u32>,
    /// core token 是否 elevated。**普通用户是预期**：`false` 才是正确拓扑。
    pub core_token_elevated: bool,
    /// engine 进程 PID。
    pub engine_pid: Option<u32>,
    /// engine token 是否 elevated（唯一特权进程；必须为 true，fail closed）。
    pub engine_token_elevated: bool,
    // ---- config 事实 ----
    /// config 是否成功加载。
    pub config_loaded: bool,
    /// config 目录。
    pub config_dir: Option<String>,
    /// 网关 hostname（`ExvConfig.server`）。
    pub server: Option<String>,
    /// config 是否携带用户名。
    pub username_present: bool,
    /// 密码是否已成功解密（非空明文；证据不记录明文本身）。
    pub password_decrypted: bool,
    /// 客户端 user-agent。
    pub user_agent: Option<String>,
    /// 隧道 MTU。
    pub mtu: Option<u32>,
    /// config 路由（campus 路由，经 engine 特权安装）。
    pub config_routes: Vec<String>,
    // ---- 可信解析 ----
    /// 可信解析出的真实网关 IP（`ConnectRequest.real_ip`）。
    pub gateway_real_ip: Option<String>,
    /// 实际使用的解析来源（`doh`/`udp53`/`system`）。
    pub resolution_source: Option<String>,
    /// 解析失败时的逐层描述（成功为 None）。
    pub resolution_error: Option<String>,
    // ---- 控制面 ----
    /// 控制面 Named Pipe 名。
    pub control_pipe_name: Option<String>,
    /// 控制面管道已连接。
    pub control_connected: bool,
    /// engine 身份（pid+SID）已双向验证。
    pub engine_peer_verified: bool,
    // ---- Connect 流程 ----
    /// `Connect` 命令已发出。
    pub connect_command_sent: bool,
    /// 观测到的 `StatusChanged` 状态序列（`Connecting`/`Connected`/`Error`/…）。
    pub status_events: Vec<String>,
    /// 是否到达 `Connected`。
    pub connected: bool,
    /// `RouteApplied` 是否成功。
    pub route_applied: bool,
    /// `Error` 事件 domain 错误码（无错误为 None）。
    pub error_code: Option<u32>,
    /// `Error` 事件网关 `a0` 结果码（无错误为 None）。
    pub error_a0: Option<u32>,
    /// `Error` 事件可读详情（无错误为 None）。
    pub error_detail: Option<String>,
    // ---- 流量统计 ----
    /// 累计接收字节。
    pub stats_rx_bytes: u64,
    /// 累计发送字节。
    pub stats_tx_bytes: u64,
    /// 实时速率（bytes/s）。
    pub stats_speed: u64,
    /// RTT（ms）。
    pub stats_latency_ms: u32,
    // ---- 断连与清理 ----
    /// `Disconnect` 命令已发出（engine 完整 teardown）。
    pub disconnect_sent: bool,
    /// engine 已执行清理（Disconnect cleanup=true 路径）。
    pub engine_cleanup: bool,
    /// engine 进程在断连后已退出（控制面关闭 → `PeerClosed` → engine 退出）。
    pub engine_exited_after_disconnect: bool,
    // ---- secret 卫生 ----
    /// `Credentials` 发送后已零化（`send_owned` 契约）。
    pub secret_zeroized_after_send: bool,
    /// 证据 JSON 不含 raw secret（序列化扫描后置真）。
    pub no_raw_secret_in_evidence: bool,
    /// 协调阶段 journal（顺序事实）。
    pub phase_journal: Vec<String>,
}

impl CoreCoordinationEvidence {
    /// 动态事实是否已完整观测。验收证明 = core 普通 + engine 特权 + 连接成功 +
    /// 路由应用 + 正常断连清理 + engine 退出。
    #[must_use]
    pub fn is_dynamic_complete(&self) -> bool {
        !self.core_token_elevated
            && self.engine_token_elevated
            && self.config_loaded
            && self.password_decrypted
            && self.gateway_real_ip.is_some()
            && self.control_connected
            && self.engine_peer_verified
            && self.connect_command_sent
            && self.connected
            && self.route_applied
            && self.disconnect_sent
            && self.engine_cleanup
            && self.engine_exited_after_disconnect
    }
}

/// 全默认（未观测）的 core 协调证据骨架。
#[must_use]
pub fn default_core_coordination_evidence() -> CoreCoordinationEvidence {
    CoreCoordinationEvidence {
        environment_state: ENV_INVALID_PREFIX.to_string(),
        core_pid: Some(std::process::id()),
        core_token_elevated: false,
        engine_pid: None,
        engine_token_elevated: false,
        config_loaded: false,
        config_dir: None,
        server: None,
        username_present: false,
        password_decrypted: false,
        user_agent: None,
        mtu: None,
        config_routes: Vec::new(),
        gateway_real_ip: None,
        resolution_source: None,
        resolution_error: None,
        control_pipe_name: None,
        control_connected: false,
        engine_peer_verified: false,
        connect_command_sent: false,
        status_events: Vec::new(),
        connected: false,
        route_applied: false,
        error_code: None,
        error_a0: None,
        error_detail: None,
        stats_rx_bytes: 0,
        stats_tx_bytes: 0,
        stats_speed: 0,
        stats_latency_ms: 0,
        disconnect_sent: false,
        engine_cleanup: false,
        engine_exited_after_disconnect: false,
        secret_zeroized_after_send: false,
        no_raw_secret_in_evidence: false,
        phase_journal: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// 协调主流程（school-scenario bin 的 core 侧编排）。
// ---------------------------------------------------------------------------

/// 阶段耗时日志（stderr，脚本可重定向到日志文件）。每个 `label` 打印自进程启动
/// 的墙钟秒数与距上一阶段的增量——定位延迟归属（config / 网关解析 / engine 拉起
/// UAC / engine 认证+CSTP）的关键证据。
fn phase_timer(label: &str, last: &mut std::time::Instant) {
    let now = std::time::Instant::now();
    eprintln!(
        "[core-stage] {label}: +{:.3}s (Δ{:.3}s)",
        now.duration_since(*last).as_secs_f64(),
        now.duration_since(*last).as_secs_f64()
    );
    *last = now;
}

/// 运行 core 协调层完整流程并返回证据。
///
/// `config_dir` 为 `None` 时使用产品默认 config 目录（`ExvConfig::load()` 语义）；
/// 测试/诊断可显式传入临时目录。`hold` 为 `Some`（persistent-tunnel hold）时，
/// Connect 成功后**不立即 Disconnect**：打印 `TUNNEL_READY` 并保持隧道存活
/// （engine 数据面运行），直到 `--stop-file` 出现或 stdin EOF——期间用户可测试
/// 校内资源（真实业务流：经 Wintun ring→engine→学校），然后正常 Disconnect。
#[must_use]
#[allow(clippy::too_many_lines)] // 完整协调编排（config→解析→spawn→connect→flow→disconnect），阶段线性清晰
pub fn run_core_coordination(
    config_dir: Option<&Path>,
    hold_stop_file: Option<&Path>,
) -> CoreCoordinationEvidence {
    let mut last = std::time::Instant::now();
    let mut ev = default_core_coordination_evidence();
    ev.core_pid = Some(std::process::id());
    ev.core_token_elevated = controlled::is_elevated();
    ev.phase_journal.push("coordination-start".to_string());
    phase_timer("start", &mut last);

    // ---- 权限拓扑门禁：core 必须普通用户（新权限模型）。 ----
    if ev.core_token_elevated {
        ev.phase_journal.push("topology-gate:core-elevated-rejected".to_string());
        return blocked(ev, "WIN_ACCEPTANCE_ENV_INVALID:core_elevated_unexpected");
    }
    ev.phase_journal.push("topology-gate:core-non-elevated-ok".to_string());

    // ---- 阶段 1：读 config → 解密凭据。 ----
    let dir = config_dir.map_or_else(exv_vpn_win32_config::config_dir, Path::to_path_buf);
    ev.config_dir = Some(dir.display().to_string());
    let cfg = match ExvConfig::load_from_dir(&dir) {
        Ok(cfg) => cfg,
        Err(e) => {
            ev.phase_journal.push("config-load-failed".to_string());
            return blocked(ev, &format!("{NOT_RUN_BLOCKED_PREFIX}:config-load-failed:{e}"));
        }
    };
    ev.config_loaded = true;
    ev.server = Some(cfg.server.clone());
    ev.username_present = !cfg.username.is_empty();
    ev.user_agent = Some(cfg.user_agent.clone());
    ev.mtu = Some(cfg.mtu);
    ev.config_routes.clone_from(&cfg.routes);
    ev.phase_journal.push("config-loaded".to_string());
    phase_timer("config-loaded", &mut last);

    let key = match ExvConfig::load_key(&dir) {
        Ok(Some(key)) => key,
        Ok(None) => {
            ev.phase_journal.push("credential-key-missing".to_string());
            return blocked(ev, &format!("{NOT_RUN_BLOCKED_PREFIX}:credential-key-missing"));
        }
        Err(e) => {
            ev.phase_journal.push("credential-key-read-failed".to_string());
            return blocked(ev, &format!("{NOT_RUN_BLOCKED_PREFIX}:credential-key-read-failed:{e}"));
        }
    };
    let mut password = match cfg.decrypt_password(&key) {
        Ok(p) if !p.is_empty() => {
            ev.password_decrypted = true;
            ev.phase_journal.push("credential-decrypted".to_string());
            phase_timer("credential-decrypted", &mut last);
            p
        }
        Ok(_) => {
            ev.phase_journal.push("password-not-remembered".to_string());
            return blocked(ev, &format!("{NOT_RUN_BLOCKED_PREFIX}:password-not-remembered"));
        }
        Err(e) => {
            ev.phase_journal.push("password-decrypt-failed".to_string());
            return blocked(ev, &format!("{NOT_RUN_BLOCKED_PREFIX}:password-decrypt-failed:{e}"));
        }
    };

    // ---- 阶段 2：可信解析网关 real_ip（组装 Connect 参数的一部分）。 ----
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => {
            ev.phase_journal.push("gateway-resolve-failed:tokio-runtime".to_string());
            return blocked(ev, &format!("{NOT_RUN_BLOCKED_PREFIX}:gateway-resolve-failed:tokio-runtime"));
        }
    };
    let nics = match direct_connect::find_physical_nics() {
        Ok(nics) => nics,
        Err(e) => {
            ev.phase_journal.push("gateway-resolve-failed:nic-discovery".to_string());
            return blocked(
                ev,
                &format!("{NOT_RUN_BLOCKED_PREFIX}:gateway-resolve-failed:nic-discovery:{e}"),
            );
        }
    };
    let resolve_cfg = match direct_connect::DualLineConfig::production(nics.first().map(|n| n.ifindex)) {
        Ok(dl_cfg) => dl_cfg,
        Err(e) => {
            ev.phase_journal.push("gateway-resolve-failed:config".to_string());
            return blocked(ev, &format!("{NOT_RUN_BLOCKED_PREFIX}:gateway-resolve-failed:config:{e}"));
        }
    };
    let real_ip = match direct_connect::resolve_gateway_dual_line(&resolve_cfg, &rt, &cfg.server) {
        Ok((ip, src)) => {
            ev.resolution_source = Some(src.as_str().to_string());
            ev.phase_journal.push("gateway-resolved".to_string());
            phase_timer("gateway-resolved", &mut last);
            ip
        }
        Err(layer_errors) => {
            let desc = layer_errors
                .iter()
                .map(direct_connect::ResolveLayerError::describe)
                .collect::<Vec<_>>()
                .join(";");
            ev.resolution_error = Some(desc.clone());
            ev.phase_journal.push("gateway-resolve-failed".to_string());
            return blocked(ev, &format!("{NOT_RUN_BLOCKED_PREFIX}:gateway-resolve-failed:{desc}"));
        }
    };
    ev.gateway_real_ip = Some(real_ip.to_string());

    // ---- 阶段 2.5：建 log 管道 server（core 暴露的 Log API——固定名多实例；engine /
    //      未来 UI 连入发日志，core 统一 `core_log::log_line` 落盘）。server 创建失败
    //      （另一 core 已持固定名）时优雅降级：不建 log server，engine 日志只走其 stdout。
    //      句柄绑定 `_log_server` 保持存活到本函数结束（accept 线程独立运行，进程退出
    //      时随之结束）。 ----
    let _log_server = match LogPipeServer::start(
        LOG_PIPE_NAME,
        current_user_sid().as_deref(),
        LOG_PIPE_MAX_INSTANCES,
        |ev| core_log::log_line(&format!("[{}] {}", ev.level, ev.message)),
    ) {
        Ok(s) => Some(s),
        Err(e) => {
            core_log::log_line(&format!("[core] log pipe server unavailable: {e:?}"));
            None
        }
    };

    // ---- 阶段 3：提权拉起 engine。 ----
    let exe = match engine_bin_path() {
        Some(exe) => exe,
        None => {
            ev.phase_journal.push("engine-bin-not-found".to_string());
            return blocked(ev, &format!("{NOT_RUN_BLOCKED_PREFIX}:engine-bin-not-found"));
        }
    };
    let spawn_args = engine_args_for_spawn();
    let (pid, handle) = match spawn_engine_elevated(&exe, &spawn_args) {
        Ok(x) => x,
        Err(e) => {
            ev.phase_journal.push("engine-spawn-failed".to_string());
            return blocked(ev, &format!("{NOT_RUN_BLOCKED_PREFIX}:engine-spawn-failed:{e}"));
        }
    };
    ev.engine_pid = Some(pid);
    ev.phase_journal.push("engine-spawned".to_string());
    phase_timer("engine-spawned (UAC / runas)", &mut last);

    // ---- 权限拓扑门禁：engine 必须特权（唯一特权进程）。 ----
    ev.engine_token_elevated = verify_engine_elevated(pid);
    if !ev.engine_token_elevated {
        ev.phase_journal.push("engine-elevation-gate:rejected".to_string());
        terminate_process(handle);
        return blocked(ev, "WIN_ACCEPTANCE_ENV_INVALID:engine_not_elevated");
    }
    ev.phase_journal.push("engine-elevation-verified".to_string());
    phase_timer("engine-elevation-verified", &mut last);

    // ---- 阶段 4：连 engine 控制面管道（双向认证）。 ----
    let sid = match current_user_sid() {
        Some(sid) => sid,
        None => {
            ev.phase_journal.push("control-connect-failed:no-sid".to_string());
            terminate_process(handle);
            return blocked(ev, &format!("{NOT_RUN_BLOCKED_PREFIX}:control-connect-failed:no-sid"));
        }
    };
    let pipe_name = engine_control_pipe_name();
    ev.control_pipe_name = Some(pipe_name.clone());
    let mut client = match EngineControlClient::connect(&pipe_name, std::process::id(), pid, &sid) {
        Ok(client) => client,
        Err(e) => {
            // 连接失败：engine 可能仍阻塞在 server accept 上（无人连接），等待会让
            // 它挂死到超时——直接终止（owner-lost 清理由 engine 的 shutdown_cleanup
            // 负责，但进程已无法优雅退出，这里诚实终止）。
            ev.phase_journal.push("control-connect-failed".to_string());
            let pred = format!("{NOT_RUN_BLOCKED_PREFIX}:control-connect-failed:{e:?}");
            terminate_process(handle);
            return blocked(ev, &pred);
        }
    };
    ev.control_connected = true;
    ev.engine_peer_verified = true;
    ev.phase_journal.push("control-connected".to_string());
    phase_timer("control-connected", &mut last);
    client.enable_event_channel();

    // ---- 阶段 5：发 Connect → 收 StatusChanged/Stats/Error。 ----
    let flow_result = run_coordinate_flow(&mut client, &cfg, &real_ip.to_string(), &password);
    // `connect_tunnel` 经 `send_owned` 发送后零化请求内的一次性凭据（协议契约：
    // 即使后续读回复失败，`send_owned` 也在发送后零化）——这里把事实置真。
    ev.secret_zeroized_after_send = true;
    // 本地明文 `password` 已组装进 `Credentials` 并被零化，立即清零本地副本。
    zeroize_local(&mut password);

    match flow_result {
        Ok(outcome) => {
            ev.connect_command_sent = true;
            ev.status_events = outcome.status_events;
            ev.connected = outcome.connected;
            ev.route_applied = outcome.route_applied;
            ev.error_code = outcome.error_code;
            ev.error_a0 = outcome.error_a0;
            ev.error_detail = outcome.error_detail;
            ev.stats_rx_bytes = outcome.stats_rx_bytes;
            ev.stats_tx_bytes = outcome.stats_tx_bytes;
            ev.stats_speed = outcome.stats_speed;
            ev.stats_latency_ms = outcome.stats_latency_ms;
            ev.phase_journal.push("connect-sent".to_string());
            // Connect→Connected 全程（engine 内认证 + CSTP + 建卡 + 路由 + 数据面）。
            phase_timer("connect->connected (engine auth+CSTP)", &mut last);
        }
        Err(e) => {
            ev.phase_journal.push(format!("connect-flow-failed:{e}"));
            let pred = format!("{NOT_RUN_BLOCKED_PREFIX}:connect-flow-failed:{e}");
            // 即使 Connect 失败也继续断连清理（engine Disconnect cleanup 幂等）。
            let outcome = disconnect_engine(client, handle, &mut ev);
            return finish_evidence(ev, Some(&pred), outcome);
        }
    }

    // ---- 阶段 5.5：hold 模式——Connect 成功后保持隧道存活（不 Disconnect），
    //      打印 TUNNEL_READY 供用户测试校内资源，直到 stop 条件出现。 ----
    if let Some(stop_file) = hold_stop_file {
        if ev.connected {
            println!("TUNNEL_READY: engine_pid={} connected={} route_applied={}",
                ev.engine_pid.unwrap_or(0), ev.connected, ev.route_applied);
            let _ = std::io::Write::flush(&mut std::io::stdout());
            // 保持存活直到 stop-file 出现或 deadline（用户测试校内资源期间隧道持续）。
            // **仅轮询 stop-file**：不用 stdin（降权/后台运行时 stdin 是 null/EOF，
            // 阻塞 read 或立即 EOF 都会破坏 hold）。stop-file 由外层脚本/用户创建。
            let deadline = std::time::Instant::now() + Duration::from_secs(3600);
            loop {
                if std::path::Path::new(stop_file).exists() {
                    println!("HOLD_STOP: stop-file {} present", stop_file.display());
                    break;
                }
                if std::time::Instant::now() > deadline {
                    println!("HOLD_STOP: deadline");
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        } else {
            println!("HOLD_SKIP: not connected (hold requires Connected)");
        }
    }

    // ---- 阶段 6：断连 → 清理 → 等待 engine 退出。 ----
    let outcome = disconnect_engine(client, handle, &mut ev);

    if ev.is_dynamic_complete() {
        finish_evidence(ev, None, outcome)
    } else {
        let pred = if outcome {
            format!("{NOT_RUN_BLOCKED_PREFIX}:incomplete-flow")
        } else {
            format!("{NOT_RUN_BLOCKED_PREFIX}:disconnect-failed")
        };
        finish_evidence(ev, Some(&pred), outcome)
    }
}

// ---------------------------------------------------------------------------
// 可测核心：组装 Connect 参数 + 连 engine（假 engine 可注入）。
// ---------------------------------------------------------------------------

/// Connect 流程的观测结果。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct CoreFlowOutcome {
    /// 观测到的状态事件（`Connecting`/`Connected`/`Error`/`reason:<..>`）。
    pub status_events: Vec<String>,
    /// 是否到达 `Connected`。
    pub connected: bool,
    /// `RouteApplied` 是否成功。
    pub route_applied: bool,
    /// `Error` 事件 domain 错误码。
    pub error_code: Option<u32>,
    /// `Error` 事件网关 `a0` 结果码。
    pub error_a0: Option<u32>,
    /// `Error` 事件可读详情。
    pub error_detail: Option<String>,
    /// 累计接收字节。
    pub stats_rx_bytes: u64,
    /// 累计发送字节。
    pub stats_tx_bytes: u64,
    /// 实时速率（bytes/s）。
    pub stats_speed: u64,
    /// RTT（ms）。
    pub stats_latency_ms: u32,
}

/// 从 config 组装 `ConnectRequest`。
///
/// `real_ip` 是可信解析出的真实网关 IP（engine 的 CSTP 直连目标）；`password` 是
/// 解密后的明文凭据（一次性，组装进 `Credentials` 后由 `send_owned` 零化）。
/// tunnel 参数（prefix/mtu/dns/routes）以真实 CSTP offer 为准（engine 侧覆盖），
/// config 只携带 server/real_ip/credentials/user_agent/campus_routes——`routes`
/// 字段留空、`campus_routes` 携带 config 的校园路由（engine 特权安装）。
#[must_use]
pub(crate) fn assemble_connect_request(
    cfg: &ExvConfig,
    real_ip: &str,
    password: &str,
) -> ConnectRequest {
    ConnectRequest {
        server: cfg.server.clone(),
        real_ip: real_ip.to_string(),
        prefix: 32, // school 网关默认 /32；engine 以 offer 覆盖
        credentials: Credentials::new(cfg.username.clone(), password),
        user_agent: cfg.user_agent.clone(),
        mtu: cfg.mtu,
        dns: Vec::new(),
        routes: Vec::new(),
        campus_routes: cfg.routes.clone(),
    }
}

/// 对已连接的 engine 执行 Connect 流程：发 `Connect` → 解析回复批 → 查询统计。
///
/// # Errors
/// 控制面掉线 / 帧读写失败 / 等待超时（`ControlClientError`）。
pub(crate) fn run_coordinate_flow(
    client: &mut EngineControlClient,
    cfg: &ExvConfig,
    real_ip: &str,
    password: &str,
) -> Result<CoreFlowOutcome, String> {
    let req = assemble_connect_request(cfg, real_ip, password);
    let replies = client
        .connect_tunnel(req)
        .map_err(|e| format!("connect-tunnel:{e:?}"))?;

    let mut outcome = CoreFlowOutcome::default();
    for reply in &replies {
        match reply {
            EngineToCore::StatusChanged { state, reason } => {
                outcome.status_events.push(format!("{state:?}"));
                if *state == EngineState::Connected {
                    outcome.connected = true;
                }
                if let Some(r) = reason {
                    outcome.status_events.push(format!("reason:{r}"));
                }
            }
            EngineToCore::RouteApplied { ok, conflict } => {
                outcome.route_applied = *ok;
                if *conflict {
                    outcome.status_events.push("route-conflict".to_string());
                }
            }
            EngineToCore::Error { code, a0, detail } => {
                outcome.error_code = Some(*code);
                outcome.error_a0 = Some(*a0);
                outcome.error_detail = detail.clone();
                outcome
                    .status_events
                    .push(format!("Error(code={code},a0={a0})"));
            }
            EngineToCore::Stats { .. } | EngineToCore::CredentialRequired => {}
        }
    }

    // 查询流量统计（未连接时 engine 恒 0）。
    let stats_replies = client
        .get_stats()
        .map_err(|e| format!("get-stats:{e:?}"))?;
    for reply in &stats_replies {
        if let EngineToCore::Stats {
            rx_bytes,
            tx_bytes,
            speed,
            latency_ms,
        } = reply
        {
            outcome.stats_rx_bytes = *rx_bytes;
            outcome.stats_tx_bytes = *tx_bytes;
            outcome.stats_speed = *speed;
            outcome.stats_latency_ms = *latency_ms;
        }
    }
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// 内部工具。
// ---------------------------------------------------------------------------

/// 断连 + 关闭控制面 + 等待 engine 退出。返回 engine 是否干净退出。
///
/// `client` 以值传入：`drop(client)` 真正关闭控制面管道（engine 命令循环读
/// `PeerClosed` 后退出）；`&mut` 引用无法关闭底层连接。
fn disconnect_engine(
    mut client: EngineControlClient,
    handle: windows::Win32::Foundation::HANDLE,
    ev: &mut CoreCoordinationEvidence,
) -> bool {
    match client.disconnect(true) {
        Ok(_) => {
            ev.disconnect_sent = true;
            ev.engine_cleanup = true;
            ev.phase_journal.push("disconnect-sent".to_string());
        }
        Err(e) => {
            ev.phase_journal.push(format!("disconnect-failed:{e:?}"));
        }
    }
    drop(client); // 关闭控制面 → engine 命令循环读 PeerClosed → 退出
    wait_engine_exit(handle, ev)
}

/// 等待 engine 进程退出（有界；超时/失败时手动关闭句柄）。返回是否退出。
fn wait_engine_exit(
    handle: windows::Win32::Foundation::HANDLE,
    ev: &mut CoreCoordinationEvidence,
) -> bool {
    let exited = controlled::wait_process_exit(handle, 30_000);
    ev.engine_exited_after_disconnect = exited;
    if !exited {
        // wait_process_exit 超时未关闭句柄；此处手动关闭。
        // SAFETY: handle 是 spawn 返回的有效进程句柄。
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(handle);
        }
    }
    ev.phase_journal.push("engine-exit-waited".to_string());
    exited
}

/// 终止 engine 进程并关闭句柄（拓扑门禁失败路径）。
fn terminate_process(handle: windows::Win32::Foundation::HANDLE) {
    // SAFETY: handle 是 spawn 返回的有效进程句柄；进程已观测完，主动结束。
    unsafe {
        let _ = windows::Win32::System::Threading::TerminateProcess(handle, 1);
        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }
}

/// 记录 blocked predicate 并 finalize（secret 扫描 + journal 收尾）。
fn blocked(mut ev: CoreCoordinationEvidence, predicate: &str) -> CoreCoordinationEvidence {
    ev.phase_journal.push("blocked".to_string());
    finish_evidence(ev, Some(predicate), false)
}

/// finalize：设置 environment_state（优先失败 predicate，其次 completed/incomplete）、
/// 序列化扫描 secret 卫生。
fn finish_evidence(
    mut ev: CoreCoordinationEvidence,
    predicate: Option<&str>,
    disconnected_ok: bool,
) -> CoreCoordinationEvidence {
    ev.environment_state = match predicate {
        Some(p) => p.to_string(),
        None if ev.is_dynamic_complete() => ENV_STATE_COMPLETED.to_string(),
        None => {
            let suffix = if disconnected_ok {
                "incomplete-flow"
            } else {
                "disconnect-failed"
            };
            format!("{NOT_RUN_BLOCKED_PREFIX}:{suffix}")
        }
    };
    let json = serde_json::to_string(&ev).unwrap_or_default();
    let forbidden = [
        "PRIVATE KEY",
        "BEGIN CERTIFICATE",
        "Cookie:",
        "Authorization:",
        "password=",
        "group=",
        "username=",
    ];
    ev.no_raw_secret_in_evidence = !forbidden.iter().any(|m| json.contains(m));
    ev
}

/// Best-effort 零化本地明文 String（密码组装后立即清零，不留缓冲）。
fn zeroize_local(s: &mut String) {
    // SAFETY: 覆写 String 的已使用字节为 0（与协议层 `Credentials::zeroize` 同款）。
    unsafe {
        for b in s.as_mut_vec() {
            *b = 0;
        }
    }
    s.clear();
}

// ---------------------------------------------------------------------------
// 单元测试：纯逻辑（config→组装参数）+ 假 engine 往返（连假 engine→发 Connect）。
// 不需要 elevation / 真实 gateway / wintun.dll。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::thread;

    use exv_vpn_win32_ipc::engine_protocol::{
        CoreToEngine, EngineHelloReply, EngineHelloReq, FrameError, read_json_frame,
        write_json_frame,
    };
    use exv_vpn_win32_ipc::named_pipe_io::NamedPipeByteStream;

    use super::*;

    fn unique_pipe_name(tag: &str) -> String {
        format!(r"\\.\pipe\exv-coordination-{tag}-{}", std::process::id())
    }

    /// 假 engine 服务端（同进程线程；server pid == 本进程 pid、SID == 当前用户
    /// SID，满足控制面双向认证）。`handler` 决定命令回复（对
    /// `Subscribe`/`UpdateCredentials` 应回空批，与真实 engine 命令循环一致）。
    fn spawn_fake_engine(
        tag: &str,
        handler: impl Fn(CoreToEngine) -> Vec<EngineToCore> + Send + 'static,
    ) -> (String, thread::JoinHandle<()>) {
        let name = unique_pipe_name(tag);
        let name_for_engine = name.clone();
        let sid = current_user_sid().expect("current user sid");
        let pid = std::process::id();
        let handle = thread::spawn(move || {
            let server =
                NamedPipeByteStream::create_server(&name_for_engine, 1).expect("create server");
            server.connect().expect("accept client");
            let mut server = server;

            let hello: EngineHelloReq = read_json_frame(&mut server).expect("read hello");
            assert_eq!(hello.host_pid, pid, "fake engine must see the declared host pid");
            write_json_frame(
                &mut server,
                &EngineHelloReply {
                    ok: true,
                    error: None,
                    engine_pid: pid,
                    engine_sid: sid.clone(),
                    engine_account: String::new(),
                    engine_elevated: true,
                },
            )
            .expect("write hello");

            loop {
                let cmd: CoreToEngine = match read_json_frame(&mut server) {
                    Ok(cmd) => cmd,
                    Err(FrameError::PeerClosed) => break,
                    Err(e) => panic!("fake engine read: {e:?}"),
                };
                let replies = handler(cmd);
                for reply in &replies {
                    write_json_frame(&mut server, &reply).expect("write reply");
                }
            }
        });
        (name, handle)
    }

    /// 连接假 engine（同进程：server pid == 本进程 pid、SID == 当前用户）。
    fn connect_client(name: &str) -> EngineControlClient {
        let pid = std::process::id();
        let sid = current_user_sid().expect("current user sid");
        EngineControlClient::connect(name, pid, pid, &sid).expect("client connect")
    }

    fn sample_config() -> ExvConfig {
        ExvConfig {
            server: "vpn-cn.ecnu.edu.cn".to_string(),
            username: "student".to_string(),
            password: "ciphertext".to_string(),
            remember_password: true,
            routes: vec!["202.120.80.0/20".to_string()],
            user_agent: "AnyConnect Win_x86_64 4.10.05095".to_string(),
            mtu: 1420,
            // C1 为 ExvConfig 新增 `server_bypass_ips`（control_bypass 双来源）后，
            // 本测试构造缺该字段导致 acceptance test 目标编译失败（C4 为跑通门禁补上）。
            server_bypass_ips: Vec::new(),
            auto_reconnect: false,
            auto_reconnect_max_attempts: 0,
        }
    }

    /// 组装 Connect 参数：config → server/real_ip/credentials/user_agent/mtu/campus_routes
    /// 映射正确，tunnel 参数（routes/dns）留空由 offer 覆盖。
    #[test]
    fn assemble_connect_request_from_config() {
        let cfg = sample_config();
        let req = assemble_connect_request(&cfg, "10.1.2.3", "s3cret");
        assert_eq!(req.server, "vpn-cn.ecnu.edu.cn");
        assert_eq!(req.real_ip, "10.1.2.3");
        assert_eq!(req.prefix, 32);
        assert_eq!(req.credentials.username(), "student");
        assert_eq!(req.credentials.password(), "s3cret");
        assert_eq!(req.user_agent, "AnyConnect Win_x86_64 4.10.05095");
        assert_eq!(req.mtu, 1420);
        assert_eq!(req.campus_routes, vec!["202.120.80.0/20"]);
        assert!(req.routes.is_empty(), "routes 由真实 offer 覆盖，config 不携带");
        assert!(req.dns.is_empty(), "dns 由真实 offer 覆盖，config 不携带");
    }

    /// 读 config（含 AES 密封密码）→ 解密 → 组装参数 → 连假 engine → 发 Connect。
    /// 假 engine 回 Connected + RouteApplied + Stats；flow 返回完整观测。
    #[test]
    fn read_config_assemble_and_connect_fake_engine() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = ExvConfig::ensure_key(dir.path()).expect("ensure key");
        let mut cfg = ExvConfig {
            server: "vpn-cn.ecnu.edu.cn".to_string(),
            username: "student".to_string(),
            routes: vec!["202.120.80.0/20".to_string()],
            ..ExvConfig::default()
        };
        cfg.set_password_encrypted("s3cret", &key).expect("encrypt");
        cfg.save_to_dir(dir.path()).expect("save config");

        // 重新加载 → 解密（独立 key.bin）。
        let loaded = ExvConfig::load_from_dir(dir.path()).expect("load config");
        let password = loaded.decrypt_password(&key).expect("decrypt password");
        assert_eq!(password, "s3cret", "AES 密封密码必须能解回明文");

        let (name, handle) = spawn_fake_engine("flow", |cmd| match cmd {
            CoreToEngine::Connect(req) => {
                assert_eq!(
                    req.credentials.password(),
                    "s3cret",
                    "wire 必须携带明文凭据（序列化先于零化）"
                );
                vec![
                    EngineToCore::StatusChanged {
                        state: EngineState::Connecting,
                        reason: None,
                    },
                    EngineToCore::StatusChanged {
                        state: EngineState::Connected,
                        reason: None,
                    },
                    EngineToCore::RouteApplied {
                        ok: true,
                        conflict: false,
                    },
                ]
            }
            CoreToEngine::GetStats => vec![EngineToCore::Stats {
                rx_bytes: 42,
                tx_bytes: 84,
                speed: 7,
                latency_ms: 3,
            }],
            CoreToEngine::Disconnect { .. } => vec![EngineToCore::StatusChanged {
                state: EngineState::Disconnected,
                reason: None,
            }],
            _ => vec![],
        });

        let mut client = connect_client(&name);
        let outcome = run_coordinate_flow(&mut client, &loaded, "10.1.2.3", &password)
            .expect("coordinate flow must succeed");
        assert!(outcome.connected, "必须观测到 Connected");
        assert!(outcome.route_applied, "必须观测到 RouteApplied ok");
        assert!(outcome.error_code.is_none(), "无错误");
        assert_eq!(outcome.stats_rx_bytes, 42);
        assert_eq!(outcome.stats_tx_bytes, 84);
        assert_eq!(outcome.stats_speed, 7);
        assert_eq!(outcome.stats_latency_ms, 3);
        assert!(
            outcome
                .status_events
                .iter()
                .any(|s| s == "Connecting" || s == "Connected"),
            "状态序列必须含 Connecting/Connected，got {:?}",
            outcome.status_events
        );

        // 断连清理（同外层的 disconnect_engine 语义）。
        client.disconnect(true).expect("disconnect");
        drop(client);
        handle.join().expect("fake engine thread joins");
    }

    /// Connect 失败（engine 回 Error）时 flow 必须诚实记录错误，不冒充 Connected。
    #[test]
    fn connect_failure_records_error_not_connected() {
        let (name, handle) = spawn_fake_engine("connect-error", |cmd| match cmd {
            CoreToEngine::Connect(_) => vec![
                EngineToCore::Error {
                    code: 1,
                    a0: 15,
                    detail: Some("engine: login:LoginRejected".to_string()),
                },
                EngineToCore::StatusChanged {
                    state: EngineState::Error,
                    reason: Some("engine: login:LoginRejected".to_string()),
                },
            ],
            // GetStats 期待回复（与真实 engine 命令循环一致：至少回一帧）。
            CoreToEngine::GetStats => vec![EngineToCore::Stats {
                rx_bytes: 0,
                tx_bytes: 0,
                speed: 0,
                latency_ms: 0,
            }],
            _ => vec![],
        });

        let mut client = connect_client(&name);
        let outcome = run_coordinate_flow(&mut client, &sample_config(), "10.1.2.3", "bad")
            .expect("flow returns outcome even on connect error");
        assert!(!outcome.connected, "不得冒充 Connected");
        assert!(!outcome.route_applied);
        assert_eq!(outcome.error_code, Some(1));
        assert_eq!(outcome.error_a0, Some(15));
        assert!(
            outcome.error_detail.as_deref().is_some_and(|d| d.contains("LoginRejected")),
            "必须记录引擎登录失败的 typed 详情"
        );

        drop(client);
        handle.join().expect("fake engine thread joins");
    }

    /// 凭据零化事实：`send_owned` 发送后，请求内凭据本地副本已被零化（`connect_tunnel`
    /// 走同一 `send_owned` 路径；本模块据此置 `secret_zeroized_after_send=true`）。
    #[test]
    fn connect_sends_then_zeroizes_credentials() {
        let (name, handle) = spawn_fake_engine("zeroize", |cmd| match cmd {
            CoreToEngine::Connect(_) => vec![EngineToCore::StatusChanged {
                state: EngineState::Connected,
                reason: None,
            }],
            _ => vec![],
        });
        let mut client = connect_client(&name);
        let cfg = sample_config();
        let mut cmd = CoreToEngine::Connect(assemble_connect_request(&cfg, "10.1.2.3", "s3cret"));
        client.send_owned(&mut cmd).expect("send connect");
        match &cmd {
            CoreToEngine::Connect(req) => {
                assert!(
                    req.credentials.password().is_empty(),
                    "password 必须已零化（send_owned 契约）"
                );
                assert!(
                    req.credentials.username().is_empty(),
                    "username 必须已零化（send_owned 契约）"
                );
            }
            _ => panic!("expected Connect"),
        }
        drop(client);
        handle.join().expect("fake engine thread joins");
    }

    /// 证据 `is_dynamic_complete` 必须满足「core 普通 + engine 特权 + 连接成功 +
    /// 路由应用 + 断连清理 + engine 退出」；缺任一 obligation 不得 completed。
    #[test]
    fn evidence_completeness_requires_full_topology() {
        let mut ev = default_core_coordination_evidence();
        ev.core_token_elevated = false;
        ev.engine_token_elevated = true;
        ev.config_loaded = true;
        ev.password_decrypted = true;
        ev.gateway_real_ip = Some("10.1.2.3".to_string());
        ev.control_connected = true;
        ev.engine_peer_verified = true;
        ev.connect_command_sent = true;
        ev.connected = true;
        ev.route_applied = true;
        ev.disconnect_sent = true;
        ev.engine_cleanup = true;
        ev.engine_exited_after_disconnect = true;
        assert!(ev.is_dynamic_complete(), "完整拓扑必须 completed");

        // core elevated → 不得 completed（拓扑错误）。
        let mut bad = ev.clone();
        bad.core_token_elevated = true;
        assert!(!bad.is_dynamic_complete(), "core elevated 不得 completed");

        // engine 非特权 → 不得 completed。
        let mut bad = ev.clone();
        bad.engine_token_elevated = false;
        assert!(!bad.is_dynamic_complete(), "engine 非特权不得 completed");

        // 未连接 → 不得 completed。
        let mut bad = ev.clone();
        bad.connected = false;
        assert!(!bad.is_dynamic_complete(), "未连接不得 completed");
    }

    /// 证据 JSON 序列化往返（验收消费契约：可解析 + 字段稳定）。
    #[test]
    fn evidence_serializes_round_trip() {
        let ev = default_core_coordination_evidence();
        let json = serde_json::to_string(&ev).expect("serialize");
        let back: CoreCoordinationEvidence = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, ev, "证据必须 JSON 往返");
        assert!(
            !json.contains("s3cret") && !json.contains("password="),
            "默认证据不得泄漏任何凭据标记"
        );
    }
}
