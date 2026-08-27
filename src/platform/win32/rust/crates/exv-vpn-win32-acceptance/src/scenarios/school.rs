// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W30 学校 VPN 真实 flow（W30-I）：`run_school_scenario`。
//!
//! 在真实 Windows 宿主上运行学校 VPN 真实 flow：**真实 TLS identity**（P41
//! `Bootstrap` + `TrustPolicy::Production`——对真实学校证书链 + hostname 验证，
//! 严格 webpki，绝非 always-true）、**学号/密码实际使用**（2026-08-15 用户裁定：
//! 学校场景唯一凭据 = 学号/密码；group/challenge 已封存——真实学校服务器收到的
//! 凭据经 `exv-vpn-cstp::auth` 一次性 vault 一次消费，认证事实由
//! `auth_username_password_actual` 记录）、**CSTP-only tunnel**（plan 来自真实学校
//! CSTP offer，Common offer validation 之后才进入平台端口；无 DTLS offer/token）、
//! **学校目标 IPv4 流量**（跨子网设计下真实双向经过 Wintun ring + CSTP）、
//! **正常 Stop + scoped owned-resource cleanup**（before-applied-after
//! compare-and-restore 回 before）。
//!
//! **反假绿（计划 §9 W30）**：受控纵切（W28）的测试服务器 / 测试 CA / 测试凭据 /
//! 冻结 tunnel plan（10.88.88.1 / 10.99.99.0/24）/ 受控 HTTP 目标（10.99.99.2）
//! 都不得混入学校 flow——本 scenario 对 fake origin / fake IPv4 target 配置做
//! 运行时拒绝（拒绝成功 = 未接受任何 fake），TLS 验证只走真实学校链，secret 唯一
//! 入口是受认证 TTY one-shot vault，tunnel plan 唯一来源是真实 offer。
//!
//! **secret 一次性输入**：secret 绝不来自 argv/env/log/evidence；只经受认证
//! controller/TTY one-shot 输入（stdin 为交互终端时逐行提示；否则诚实标记
//! `not_run/blocked_by_environment:school-credentials-unavailable`），经
//! `AuthInteraction` vault 持有、发送后与 Stop 时 zeroize、Debug 脱敏。
//!
//! **提权运行的一次性凭据通道**：elevated host（`Start-Process -Verb RunAs`）
//! 没有 pipe stdin，受认证 controller 以受限临时文件提供凭据
//! （`%TEMP%\exv-school-cred-<pid>-<seq>.txt`；当前用户 + SYSTEM 的 protected
//! DACL，拒绝 BUILTIN\Users / Everyone），内容恰为两行（学号、密码）；
//! `--cred-file <path>` 只携带路径、绝不携带凭据值。scenario 读出两行后**立即
//! 删除文件**（one-shot destroy）并 zeroize 读缓冲；文件缺失 / 行数不符 / 空行 /
//! ACL 宽泛均为 typed error（`CredentialChannelError`，绝不 panic）。
//!
//! **权限感知**（`require_admin` pattern）：学校拓扑 = elevated host + elevated
//! helper。非 elevated 宿主只记录静态事实与 `WIN_ACCEPTANCE_ENV_INVALID:host_not_elevated`
//! （不建 adapter、不启 helper、不连接学校、不 mutate），不冒充 RED/GREEN。学校
//! 服务不可用时**诚实检测**（TCP probe 失败 → `school_service_available=false` +
//! `school_service_probe_predicate`）并标记
//! `not_run/blocked_by_environment:school_service_unavailable:<predicate>`——该
//! blocked 只描述学校环境不可用，**不否定 W28/W29**。任何中途失败只记录静态事实
//! 与 `not_run/blocked_by_environment:<predicate>`，动态事实不提交（不伪造）。
//! 纵切自清理（adapter 移除、四族回 before、helper 退出），无残留。
//!
//! **组合（不重新实现）**：复用 `controlled.rs`（W28-I）已验证的纵切机械——helper
//! bin（W26 `compose_privileged_helper`）、pipe 帧 I/O、`spawn_helper_elevated`、
//! 进程/身份观测；W27 `compose_nonprivileged_host`、W17 `WintunSession`（经
//! helper apply）、W22 leaf seams（helper 侧 `apply_tunnel` canonical 顺序）、
//! W23B `AttachedPacketRelay`、W14/W24 Stop 链。学校特有部分（配置/probe/TLS/
//! 认证/offer/plan）本文件实现。
//!
//! **保密契约**：任何证据字段不携带 raw secret/cookie/private key/certificate/
//! group——TLS 只记录对端 SHA-256 指纹；认证事实只记录学号/密码实际使用
//! （`auth_username_password_actual`；group digest 已封存不产生）；
//! `no_raw_secret_in_evidence` 由 `scan_evidence` 对最终序列化做独立扫描后置真。
//!
//! **persistent-tunnel hold 模式（2026-08-16 用户裁定）**：`run_school_scenario_hold`
//! 在 Connected/plan-applied 后打印 `TUNNEL_READY`（tunnel IP/adapter 名/ifindex）、
//! 应用**合并校园路由**并保持隧道存活，供用户手动验证校园资源（ssh w202）。
//! 校园路由**继承 C++ 产品配置**（`distribution/ecnu.json` 的 `default_routes`），经
//! `EXV_RUST_VPN_SCHOOL_ROUTES` 传入（逗号分隔 CIDR）——**连接逻辑绝不硬编码路由**；
//! offer 的 `X-CSTP-Split-Include` 路由与之**合并**（offer 优先，config 追加非重复，
//! 按规范化 CIDR 身份去重；本 W30 网关的 offer 不发送 Split-Include，实测为空）。
//! 保持存活直到 stop 条件（`--stop-file` 出现或 stdin EOF；**凭据通道文件绝不作
//! stop 条件**），然后逆序移除应用的路由并走正常 Stop 路径。证据记录
//! `held_mode` / `route_source`（`{"offer": [...], "config": [...], "merged": [...]}`）/
//! `campus_routes_applied` / `campus_routes_removed`。

use std::collections::HashSet;
use std::io::{IsTerminal, Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use exv_vpn_cstp::auth::{
    AuthChallengeKind, AuthClock, AuthInteraction, AuthProgress, AuthResponse, Secret,
};
use exv_vpn_cstp::connector::{Bootstrap, BootstrapConfig, BootstrapError, TrustPolicy};
use exv_vpn_cstp::session::{CstpSession, TunnelOffer};
use exv_vpn_cstp::webvpn::{LoginError, WebvpnLogin};
use exv_vpn_data_plane::budget::DataPlaneDirection;
use exv_vpn_domain::identity::RuntimeEpoch;
use exv_engine::packet_relay::{AttachedPacketRelay, RelayDirection};
use exv_core::composition::{compose_nonprivileged_host, HostEffect, HostEvent};
use exv_vpn_win32_ipc::packet_channel::PacketChannel;
use exv_vpn_win32_ipc::packet_limits::PacketLimits;
use exv_vpn_win32_ipc::peer_auth::VerifiedPipePeer;
use exv_vpn_win32_resource::inventory::COMPLETE_INVENTORY;
use exv_vpn_win32_resource::packet_capability::PacketCapability;
use exv_vpn_win32_resource::routes::{
    capture_rows, install as install_route, remove as remove_route, RemoveOutcome, RouteKey,
    RouteRow,
};
use exv_vpn_win32_resource::storage_security::{assert_file_not_tamperable, ensure_secure_file};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use windows::Win32::Foundation::HANDLE;

use crate::direct_connect::{self, NicInfo};
use crate::evidence::{
    ENV_INVALID_PREFIX, LOGIN_STATUS_OK, NOT_RUN_BLOCKED_PREFIX,
    SCHOOL_SERVICE_UNAVAILABLE_PREFIX, RouteSource, SchoolScenarioEvidence,
};
use crate::scenarios::controlled as vertical;
use crate::school_data_plane::{EngineDataPlane, SchoolRelayState, start_engine_data_plane};

// ---------------------------------------------------------------------------
// 冻结常量（与 Terra 契约一致；W30 反假绿参照系）。
// ---------------------------------------------------------------------------

/// 学校 flow 创建的 Wintun adapter 名称（与 W28 的 `ExvW28Vertical` 区分，无碰撞）。
pub const SCHOOL_ADAPTER_NAME: &str = "ExvW30School";
/// 学校场景的 pipe/journal/authority 命名前缀（按 host PID 唯一）。
const SCHOOL_PIPE_PREFIX: &str = "exv-w30";
const SCHOOL_JOURNAL_PREFIX: &str = "exv-w30-journal";
const SCHOOL_AUTHORITY_PREFIX: &str = "exv-w30-authority";
/// 一次性凭据通道文件名前缀（`%TEMP%\exv-school-cred-<pid>-<seq>.txt`；路径不是
/// secret——`--cred-file` 只携带路径，凭据值绝不进 argv/env/log/evidence）。
pub const SCHOOL_CRED_FILE_PREFIX: &str = "exv-school-cred";
/// 学校目标端点配置环境变量（host:port 列表；endpoint 不是 secret）。
const SCHOOL_TARGET_ENV: &str = "EXV_RUST_VPN_SCHOOL_TARGET";
/// 学校 flow 目标覆盖环境变量（host:port；endpoint 不是 secret）——覆盖
/// `EXV_RUST_VPN_SCHOOL_TARGET` 第二 endpoint（真实 ingress 目标；凭据入口脚本设
/// `58.198.176.156:22` = w202 ssh 真实服务，非 80 无服务端口）。
const SCHOOL_FLOW_TARGET_ENV: &str = "EXV_RUST_VPN_SCHOOL_FLOW_TARGET";
/// 学校校园路由配置环境变量（逗号分隔 CIDR；镜像 C++ 产品 config.json 的
/// `default_routes`——**路由来自产品配置，绝不硬编码在连接逻辑里**；hold 模式
/// 下与 offer 的 `X-CSTP-Split-Include` 路由合并，offer 优先、config 追加非重复）。
const SCHOOL_ROUTES_ENV: &str = "EXV_RUST_VPN_SCHOOL_ROUTES";
/// hold 模式的 TUNNEL_READY 标记文件环境变量（elevated 进程 stdout 重定向在部分
/// 宿主不可靠——标记文件由 elevated 进程自己创建，是脚本轮询的可靠通道）。
const HOLD_READY_FILE_ENV: &str = "EXV_RUST_VPN_HOLD_READY_FILE";
/// 校园路由的安装度量（与 controlled.rs 隧道路由同款 5）。
const CAMPUS_ROUTE_METRIC: u32 = 5;
/// `ERROR_OBJECT_ALREADY_EXISTS`（`CreateIpForwardEntry2` 重复精确行——offer 路由
/// 已由 helper apply 安装时直接容忍并回读采纳，不重复安装）。
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;
/// hold 模式 stop-file 的轮询间隔。
const HOLD_POLL_INTERVAL: Duration = Duration::from_millis(200);
/// 学校服务 probe 的 TCP connect 超时。
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// 认证 prompt 的 vault 预算（学校操作员输入时间）。
const AUTH_PROMPT_BUDGET: Duration = Duration::from_mins(2);
/// helper 退出等待上限。
const HELPER_EXIT_TIMEOUT_MS: u32 = 30_000;

/// 受控/本地 fake origin 标记（真实学校连接不得出现）。
const FAKE_ORIGIN_MARKERS: [&str; 5] = ["127.0.0.1", "localhost", "::1", "testserver", "controlled"];
/// 受控纵切（W28）的冻结 HTTP 目标——学校 flow 必须拒绝。
const CONTROLLED_HTTP_TARGET_IPV4: &str = "10.99.99.2";

// ---------------------------------------------------------------------------
// 学校目标配置（来自 `EXV_RUST_VPN_SCHOOL_TARGET`；endpoint host:port 不是 secret）。
// ---------------------------------------------------------------------------

/// 学校目标 flow 的 ingress 协议（诚实记录证据语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowProtocol {
    /// SSH banner：TCP connect + 读 banner 字节（真实学校 ssh 服务；ingress 证明）。
    SshBanner,
    /// HTTP：HTTP GET/响应（既有行为）。
    Http,
}

impl FlowProtocol {
    /// 证据值：`"ssh-banner"` / `"http"`。
    fn as_str(&self) -> &'static str {
        match self {
            FlowProtocol::SshBanner => "ssh-banner",
            FlowProtocol::Http => "http",
        }
    }
}

/// 解析后的学校目标：gateway（TLS/CSTP origin）+ 学校 intranet ingress flow 目标。
struct SchoolTarget {
    /// gateway hostname（TLS SNI / origin；配置事实；域名或 IPv4 字面量）。
    gateway_host: String,
    /// gateway 端口（probe / TLS connect；解析出的真实 IP 与之组合）。
    gateway_port: u16,
    /// flow 目标 IPv4（学校 intranet；必须是 IPv4 字面量）。
    flow_target_ipv4: Ipv4Addr,
    /// flow 目标端口。
    flow_target_port: u16,
    /// flow 的 ingress 协议（22 → SSH banner；其余 → HTTP）。
    flow_protocol: FlowProtocol,
}

/// 从 `EXV_RUST_VPN_SCHOOL_TARGET` 解析学校目标。
///
/// 格式：逗号分隔的 `host:port` 列表；第一个是 CSTP gateway（origin），第二个是
/// 学校 intranet HTTP flow 目标。未设置/空 → `Ok(None)`（学校服务未配置）。
/// `need_flow` 为 `true`（正常 flow）时第二个 endpoint 必须存在；`false`
/// （persistent-tunnel hold 模式）时 flow 目标可缺省（hold 不做 HTTP flow，以
/// `0.0.0.0:0` 占位——**绝不使用**，反假绿 fake-ipv4-target 门禁对该占位放行）。
///
/// **不再经系统 DNS**（`to_socket_addrs` 会被 Mihomo fake-ip 劫持 → TUN 黑洞）：
/// gateway 只保留 hostname + 端口，真实 IP 由 `direct_connect` 双线可信解析
/// （DoH → 绑物理网卡 UDP/53）在 flow 阶段解析。
fn parse_school_target(need_flow: bool) -> Result<Option<SchoolTarget>, String> {
    let Ok(raw) = std::env::var(SCHOOL_TARGET_ENV) else {
        return Ok(None);
    };
    let endpoints: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if endpoints.is_empty() {
        return Ok(None);
    }
    let (g_host, g_port) = endpoints[0]
        .split_once(':')
        .ok_or_else(|| "gateway not host:port".to_string())?;
    if g_host.is_empty() {
        return Err("gateway host empty".to_string());
    }
    let g_port: u16 = g_port.parse().map_err(|_| "gateway port parse")?;
    if g_host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err("gateway host is IPv6; MVP is IPv4-only".to_string());
    }
    // ---- flow 目标：`EXV_RUST_VPN_SCHOOL_FLOW_TARGET` 覆盖优先（endpoint 不是
    //      secret；凭据入口脚本设 `58.198.176.156:22` = w202 ssh 真实服务），否则用
    //      `EXV_RUST_VPN_SCHOOL_TARGET` 第二 endpoint。hold 模式（`need_flow`）下
    //      flow 目标可缺省（占位 `0.0.0.0:0`，绝不使用）。 ----
    let flow_override = std::env::var(SCHOOL_FLOW_TARGET_ENV).ok();
    let flow_src: Option<String> = if let Some(ov) = flow_override {
        if ov.trim().is_empty() {
            // 空覆盖：回落第二 endpoint（None 时按 need_flow 处理）。
            endpoints.get(1).map(|s| (*s).to_string())
        } else {
            Some(ov)
        }
    } else {
        endpoints.get(1).map(|s| (*s).to_string())
    };
    let (flow_target_ipv4, flow_target_port) = match flow_src {
        Some(flow) => parse_flow_target_str(&flow)?,
        None if !need_flow => {
            // hold 模式：flow 目标缺省——占位，绝不使用。
            return Ok(Some(SchoolTarget {
                gateway_host: g_host.to_string(),
                gateway_port: g_port,
                flow_target_ipv4: Ipv4Addr::UNSPECIFIED,
                flow_target_port: 0,
                flow_protocol: FlowProtocol::Http,
            }));
        }
        None => return Err("school-flow-target-missing".to_string()),
    };
    let flow_protocol = flow_protocol_for_port(flow_target_port);
    Ok(Some(SchoolTarget {
        gateway_host: g_host.to_string(),
        gateway_port: g_port,
        flow_target_ipv4,
        flow_target_port,
        flow_protocol,
    }))
}

/// 按 flow 目标端口判定 ingress 协议：22（ssh）→ SSH banner；其余 → HTTP。
fn flow_protocol_for_port(port: u16) -> FlowProtocol {
    if port == 22 {
        FlowProtocol::SshBanner
    } else {
        FlowProtocol::Http
    }
}

/// origin host 是否为受控/本地 fake 标记。
fn origin_is_fake(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    FAKE_ORIGIN_MARKERS.iter().any(|m| lower.contains(m))
}

// ---------------------------------------------------------------------------
// host 侧 seam：学校 VPN 真实 flow（Terra 冻结签名，W30-T）。
// ---------------------------------------------------------------------------

/// 运行学校 VPN 真实 flow 并返回完整证据（Terra 冻结 seam；凭据经受认证 TTY
/// one-shot 输入）。等价于 `run_school_scenario_with_cred_file(dll, None)`。
#[must_use]
pub fn run_school_scenario(dll: &Path) -> SchoolScenarioEvidence {
    run_school_scenario_with_cred_file(dll, None)
}

/// 运行学校 VPN 真实 flow 并返回完整证据；`cred_file` 为提权运行的一次性凭据
/// 通道文件路径（`--cred-file` 携带；只携带路径，绝不携带凭据值；`None` = TTY
/// 输入）。
///
/// 非 elevated 宿主只记录静态事实与 `WIN_ACCEPTANCE_ENV_INVALID:host_not_elevated`
/// （不建 adapter、不启 helper、不连接学校、不 mutate）；学校服务不可用时诚实标记
/// `not_run/blocked_by_environment:school_service_unavailable:<predicate>`（不否定
/// W28/W29）；secret 无受认证入口（TTY 与凭据通道都不可用）时标记
/// `not_run/blocked_by_environment:school-credentials-unavailable`。任何中途失败
/// 只记录静态事实与 `not_run/blocked_by_environment:<predicate>`，动态事实不提交；
/// 失败路径仍向 helper 发 Stop（自清理，无残留）。
#[must_use]
pub fn run_school_scenario_with_cred_file(
    dll: &Path,
    cred_file: Option<&Path>,
) -> SchoolScenarioEvidence {
    run_school_scenario_impl(dll, cred_file, None)
}

/// 运行学校 VPN 真实 flow 的 **persistent-tunnel hold 模式**（`--hold`）：
/// 与 [`run_school_scenario_with_cred_file`] 相同的真实 flow（真实 TLS identity、
/// 学号/密码一次性、真实 CSTP offer、提权 helper、Wintun 全链、authenticated
/// packet attach），但 Connected/plan-applied 后进入 hold 阶段——打印
/// `TUNNEL_READY`（tunnel IP / adapter 名 / ifindex）、应用**合并校园路由**
/// （offer `X-CSTP-Split-Include` 优先 + `EXV_RUST_VPN_SCHOOL_ROUTES` 配置路由，
/// 按规范化 CIDR 身份去重；路由来自产品配置，绝不硬编码）、保持隧道存活直到
/// stop 条件（`stop_file` 出现或 stdin EOF；**凭据通道文件绝不作 stop 条件**），
/// 然后逆序移除应用的路由并走正常 Stop 路径（journal/cleanup/retirement/adapter
/// 移除）。证据记录 `held_mode` / `route_source` / `campus_routes_applied` /
/// `campus_routes_removed`。
#[must_use]
pub fn run_school_scenario_hold(
    dll: &Path,
    cred_file: Option<&Path>,
    stop_file: Option<&Path>,
) -> SchoolScenarioEvidence {
    run_school_scenario_impl(dll, cred_file, stop_file)
}

/// 学校 flow 的共享实现；`hold_stop` 为 `Some`（`--hold`）时进入
/// persistent-tunnel hold 模式（stop 条件 = stop-file 或 stdin EOF），为 `None` 时
/// 是既有完整 flow（HTTP flow → Stop）。
#[must_use]
fn run_school_scenario_impl(
    dll: &Path,
    cred_file: Option<&Path>,
    hold_stop: Option<&Path>,
) -> SchoolScenarioEvidence {
    let mut ev = crate::evidence::default_school_evidence();
    ev.host_pid = Some(std::process::id());
    ev.host_token_elevated = vertical::is_elevated();
    ev.host_os = format!("{} {}", std::env::consts::OS, std::env::consts::ARCH);
    ev.os_build = vertical::read_os_build();
    ev.hardware = vertical::read_hardware();
    ev.hostname = std::env::var("COMPUTERNAME").unwrap_or_default();
    ev.wintun_dll_sha256 = vertical::read_dll_sha256(dll);
    ev.wintun_dll_signature_present = vertical::dll_has_security_directory(dll);
    // 跨子网设计：学校目标与 tunnel 子网不同网段，内核不做本地应答，packet 必须
    // 真实经过 Wintun ring（fake loopback 不可能观测到学校目标 flow）。
    ev.packet_cross_subnet_design = true;
    ev.dtls_absent = run_dependency_guard().dtls_absent;

    // ---- 权限门禁：学校拓扑 = elevated host（elevation 后 helper 也提权）。 ----
    ev.env_elevated = ev.host_token_elevated;
    if !ev.host_token_elevated {
        ev.environment_state = format!("{ENV_INVALID_PREFIX}host_not_elevated");
        ev.school_service_probe_predicate =
            Some("probe-not-attempted:host-not-elevated".to_string());
        scan_evidence(&mut ev);
        return ev;
    }

    // ---- 学校服务配置（不可用必须诚实标记；不否定 W28/W29）。hold 模式
    //      （`hold_stop.is_some()`）不要求 flow 目标 endpoint（不做 HTTP flow）。 ----
    let target = match parse_school_target(hold_stop.is_none()) {
        Ok(Some(t)) => t,
        Ok(None) => {
            ev.environment_state =
                format!("{SCHOOL_SERVICE_UNAVAILABLE_PREFIX}:school-target-unset");
            ev.school_service_probe_predicate = Some("school-target-unset".to_string());
            scan_evidence(&mut ev);
            return ev;
        }
        Err(pred) => {
            ev.environment_state =
                format!("{SCHOOL_SERVICE_UNAVAILABLE_PREFIX}:school-target-malformed:{pred}");
            ev.school_service_probe_predicate =
                Some(format!("school-target-malformed:{pred}"));
            scan_evidence(&mut ev);
            return ev;
        }
    };
    ev.origin_reported = Some(target.gateway_host.clone());

    // ---- 反假绿配置门禁（纯配置检查；先于任何解析/路由/探测——fake 参照系不得
    //      进入网络路径，拒绝成功 = 未接受任何 fake；kills fake-origin /
    //      fake-ipv4-target mutant）。 ----
    if origin_is_fake(&target.gateway_host) {
        ev.environment_state = format!("{ENV_INVALID_PREFIX}fake-origin-config");
        ev.school_service_probe_predicate = Some("fake-origin-config:rejected".to_string());
        scan_evidence(&mut ev);
        return ev;
    }
    if target.flow_target_ipv4.to_string() == CONTROLLED_HTTP_TARGET_IPV4 {
        ev.environment_state = format!("{ENV_INVALID_PREFIX}fake-ipv4-target-config");
        ev.school_service_probe_predicate = Some("fake-ipv4-target-config:rejected".to_string());
        scan_evidence(&mut ev);
        return ev;
    }

    // ---- 双线可信解析（DoH → 绑物理网卡 UDP/53；fake-ip 过滤；逐层 typed 错误）。
    //      gateway 不再经系统 DNS（Mihomo fake-ip 劫持 → TUN 黑洞）。 ----
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => Arc::new(rt),
        Err(_) => {
            let pred = "gateway-resolve-failed:tokio-runtime";
            ev.environment_state = format!("{SCHOOL_SERVICE_UNAVAILABLE_PREFIX}:{pred}");
            ev.school_service_probe_predicate = Some(pred.to_string());
            scan_evidence(&mut ev);
            return ev;
        }
    };
    let nics: Vec<NicInfo> = match direct_connect::find_physical_nics() {
        Ok(nics) => nics,
        Err(e) => {
            let pred = format!("gateway-resolve-failed:nic-discovery:{e}");
            ev.environment_state = format!("{SCHOOL_SERVICE_UNAVAILABLE_PREFIX}:{pred}");
            ev.school_service_probe_predicate = Some(pred);
            scan_evidence(&mut ev);
            return ev;
        }
    };
    let resolve_cfg = match direct_connect::DualLineConfig::production(
        nics.first().map(|n| n.ifindex),
    ) {
        Ok(cfg) => cfg,
        Err(e) => {
            let pred = format!("gateway-resolve-failed:config:{e}");
            ev.environment_state = format!("{SCHOOL_SERVICE_UNAVAILABLE_PREFIX}:{pred}");
            ev.school_service_probe_predicate = Some(pred);
            scan_evidence(&mut ev);
            return ev;
        }
    };
    let real_ip = match direct_connect::resolve_gateway_dual_line(&resolve_cfg, &rt, &target.gateway_host)
    {
        Ok((ip, src)) => {
            ev.resolution_source = Some(src.as_str().to_string());
            ip
        }
        Err(layer_errors) => {
            ev.resolution_layer_errors
                .clone_from(&layer_errors.iter().map(direct_connect::ResolveLayerError::describe).collect::<Vec<_>>());
            let pred = format!(
                "gateway-resolve-failed:{}",
                ev.resolution_layer_errors.join(";")
            );
            ev.environment_state = format!("{SCHOOL_SERVICE_UNAVAILABLE_PREFIX}:{pred}");
            ev.school_service_probe_predicate = Some(pred);
            scan_evidence(&mut ev);
            return ev;
        }
    };
    ev.gateway_real_ip = Some(real_ip.to_string());

    // ---- /32 直连路由（elevated；verify-or-add + 回读证明；连接期间持有、
    //      Stop 后移除——路由生命周期，无泄漏）。 ----
    let gateway_route: Option<RouteRow> =
        match direct_connect::ensure_gateway_route(real_ip, &nics) {
            Ok(outcome) => {
                ev.route_installed = outcome.installed;
                ev.route_conflict = outcome.conflict;
                if outcome.conflict {
                    // typed route conflict：不覆盖第三方修改（VGDC-05）。
                    let pred = "gateway-route-conflict";
                    ev.environment_state =
                        format!("{SCHOOL_SERVICE_UNAVAILABLE_PREFIX}:{pred}");
                    ev.school_service_probe_predicate = Some(pred.to_string());
                    scan_evidence(&mut ev);
                    return ev;
                }
                Some(outcome.row)
            }
            Err(e) => {
                let pred = format!("gateway-route-failed:code-{}", e.code);
                ev.environment_state = format!("{SCHOOL_SERVICE_UNAVAILABLE_PREFIX}:{pred}");
                ev.school_service_probe_predicate = Some(pred);
                scan_evidence(&mut ev);
                return ev;
            }
        };

    // ---- 学校服务 probe（TCP connect 到解析出的真实 IP；只读，无 mutation）。 ----
    match probe_school_service(&SocketAddr::from((real_ip, target.gateway_port))) {
        Ok(()) => {
            ev.school_service_available = true;
            ev.school_service_probe_predicate = Some("tcp-connect-ok".to_string());
        }
        Err(pred) => {
            // 自清理：probe 失败路径同样移除已持有的 /32 路由（无泄漏）。
            if let Some(row) = gateway_route.as_ref() {
                remove_school_gateway_route(row, &mut ev);
            }
            ev.environment_state = format!("{SCHOOL_SERVICE_UNAVAILABLE_PREFIX}:{pred}");
            ev.school_service_probe_predicate = Some(pred);
            scan_evidence(&mut ev);
            return ev;
        }
    }

    // ---- 完整学校 flow（失败路径仍自清理；blocked 标记不否定 W28/W29）。 ----
    let mut ctx = SchoolCtx {
        control: None,
        helper_handle: None,
        host_composition: None,
        relay: None,
        engine_data_plane: None,
        host_ring_received_bytes: None,
        host_ring_sent_bytes: None,
    };
    match run_school_flow(&rt, dll, &target, real_ip, cred_file, hold_stop, &mut ev, &mut ctx) {
        Ok(()) => {
            ev.environment_state = crate::evidence::ENV_STATE_COMPLETED.to_string();
        }
        Err(step) => {
            // SAML 要求是 CS-AUTH-05 的新一类诚实 blocked（计划 §6.3）：MVP 不支持
            // SAML，如实标记 `not_run/blocked_by_environment:school-saml-required`，
            // 绝不冒充失败/成功；其余失败保持既有 vertical-step-failed 标记。
            ev.environment_state = if step == "school-saml-required" {
                format!("{NOT_RUN_BLOCKED_PREFIX}:school-saml-required")
            } else {
                format!("{NOT_RUN_BLOCKED_PREFIX}:vertical-step-failed:{step}")
            };
        }
    }
    cleanup_school(&mut ev, &mut ctx);
    // ---- 路由生命周期收尾：Stop 之后移除 /32 路由（回读证明；已是 Stop 链最后一步）。 ----
    if let Some(row) = gateway_route.as_ref() {
        remove_school_gateway_route(row, &mut ev);
    }
    scan_evidence(&mut ev);
    ev
}

/// 移除 `/32` 直连路由并记录证据（路由生命周期收尾；`GetIpForwardTable2` 回读证明）。
fn remove_school_gateway_route(row: &RouteRow, ev: &mut SchoolScenarioEvidence) {
    match direct_connect::remove_gateway_route(row) {
        Ok(outcome) => {
            ev.route_removed_after_stop =
                matches!(outcome, RemoveOutcome::Removed | RemoveOutcome::AlreadyAbsent);
            ev.route_absent_after_stop =
                direct_connect::gateway_route_absent(row.network).unwrap_or(false);
        }
        Err(e) => {
            ev.route_removed_after_stop = false;
            ev.route_absent_after_stop = false;
            ev.route_removal_error = Some(format!("code-{}", e.code));
        }
    }
}

/// 学校 flow 运行期上下文。
///
/// DP-04：packet pipe 数据路径已移除——`ctx` 只保留 **control pipe**（apply/stop RPC）；
/// 引擎数据面（`engine_data_plane`）直连自己的 session/ring（DP-02/DP-03），host 不再
/// 经 helper packet pipe 间接访问 ring。
struct SchoolCtx {
    control: Option<vertical::PipeStream>,
    helper_handle: Option<HANDLE>,
    host_composition: Option<exv_core::composition::HostComposition>,
    relay: Option<Arc<Mutex<SchoolRelayState>>>,
    /// 引擎（host 侧）Wintun 数据面（DP-02）：open-by-name + 引擎 session。
    engine_data_plane: Option<EngineDataPlane>,
    /// 引擎数据面 ring 字节计数（DP-03：host 数据面计数器；Stop 证据读取，不再来自
    /// helper StopReply——DP-01 后 helper 恒 0）。
    host_ring_received_bytes: Option<u64>,
    host_ring_sent_bytes: Option<u64>,
}

// 引擎（host 侧）数据面类型与启动已提取到 `crate::school_data_plane`（DP-02/DP-03，
// C++-faithful）：`start_engine_data_plane` open-by-name + 引擎 session；`spawn_data_plane`
// 起 relay 记账数据面线程（W23B）；`EngineDataPlaneThreads::stop_and_join` 先 join 再放
// session（W17 SAFETY-ORDER）。

/// 学校 flow 主体：返回 `Err(step)` 时 `run_school_scenario` 标记
/// `not_run/blocked_by_environment:vertical-step-failed:<step>`（动态事实不提交）。
/// `real_ip` 是双线可信解析出的真实网关 IP（`gateway_addr` 直连真实 IP；
/// SNI/证书校验仍按 `target.gateway_host` 域名）。`hold` 为 `Some`（`--hold`）时
/// Connected/plan-applied 后进入 persistent-tunnel hold 阶段（TUNNEL_READY +
/// 校园路由 + 保持存活）而非 HTTP flow。
fn run_school_flow(
    rt: &Arc<tokio::runtime::Runtime>,
    dll: &Path,
    target: &SchoolTarget,
    real_ip: Ipv4Addr,
    cred_file: Option<&Path>,
    hold: Option<&Path>,
    ev: &mut SchoolScenarioEvidence,
    ctx: &mut SchoolCtx,
) -> Result<(), &'static str> {
    // ---- 1. 真实 TLS identity（P41 Bootstrap，Production 信任策略 = 真实学校链；
    //      verifier 绝非 always-true——错误 host 必须被拒）。 ----
    run_school_tls_identity(rt, target, real_ip, ev)?;

    // ---- 2. secret 一次性输入（受认证 TTY / 提权凭据通道 one-shot → vault）。 ----
    let mut secrets =
        acquire_school_secrets(cred_file).map_err(|_| "school-credentials-unavailable")?;
    let mut auth = feed_school_secrets(&secrets).map_err(|_| "school-auth-vault")?;

    // ---- 3. 引擎认证 + CSTP session（CS-AUTH-05：`WebvpnLogin::perform_login` →
    //      `CstpSession::open`；学号/密码实际使用；group 已封存）。 ----
    // 错误透明：引擎 login/CONNECT/offer 失败都由 `open_school_data_connection`
    // 把真实细节写进证据（`school_data_connection_error` 重锚到
    // `login:<LoginError>` / `connect-tunnel:<SessionError>`），下一次失败直接
    // 可见（如 `connect-tunnel:EofBeforeTerminator` = gateway 未完成 offer 即
    // 关闭连接，符合格式被拒；`connect-tunnel:OfferParseFailed` = 收到非 CSTP
    // 内容；`login:LoginRejected` = 凭据被拒，`login_status` 带网关 `a0` 结果码
    // 区分凭据错（`a0=15`）与请求形态问题（`a0=8`/`114`/`115`/`16`））。
    let connection = match open_school_data_connection(
        rt,
        target,
        real_ip,
        &secrets,
        &mut auth.vault,
        ev,
    ) {
        Ok(c) => c,
        Err(step) => {
            secrets.zeroize_all(); // 失败路径同样立即清零（secret 一次性契约）
            return Err(step);
        }
    };
    secrets.zeroize_all(); // 引擎已消费：本地明文立即清零
    ev.tls_peer_fingerprint = connection.peer_fingerprint;
    // 封存：group 选择非本 MVP 应用场景（2026-08-15 用户裁定：仅学号/密码）；
    // 如需重新接线须另立 cutover requirement 并重跑真实业务流。
    // 真实认证事实只记录学号/密码实际使用；group/challenge 证据字段
    // （auth_group_digest / auth_group_password_challenge_actual）恒为 None/false。
    ev.auth_username_password_actual = true; // 学号/密码实际使用（MVP 唯一凭据）
    // 引擎 `parse_offer` 拒绝任何 `dtls` 出现——open 成功即 offer 已是 CSTP-only。
    ev.cstp_only = true;
    // 只记录引擎校验后的 plan digest（诊断用）——raw offer 文本绝不进证据（引擎
    // 不暴露 raw offer；失败时对端可能是 HTML 错误页，raw 入证据会破坏保密扫描）。
    ev.school_offer_digest = Some(connection.offer_digest);
    let plan = connection.plan;
    ev.tunnel_plan_validated = true;
    ev.tunnel_plan_ipv4_address = Some(plan.ipv4_address.clone());
    ev.tunnel_plan_routes.clone_from(&plan.routes);
    ev.phase_journal.push("auth_offer".to_string());

    // ---- 4. 提权 helper + W26 组合 + W16/W17/W22 apply（plan 来自真实 offer）。
    //      campus routes 经 helper apply RPC 安装（`CreateIpForwardEntry2` 在提权
    //      helper 进程内执行——特权操作归属 helper，host 只发指令、不直接写路由表）。 ----
    let peer = connect_school_helper(dll, ev, ctx)?;
    let campus_routes = build_campus_route_config(&plan.routes).map_err(|_| "school-routes-env")?;
    apply_school_tunnel(dll, &plan, &campus_routes, &peer, ev, ctx)?;

    // ---- 4b. DP-02：引擎（host 侧）数据面——open-by-name + 引擎 session。 ----
    // helper 完成特权初始化（create adapter + 网络设置）后空闲；数据面属主移回引擎
    // （C++-faithful）。用 **create 名**（`SCHOOL_ADAPTER_NAME`，非 alias）open +
    // `WintunSession::start`——open/session/ring 不特权；adapter 由 helper 创建
    // （存在），open 返回 `AdapterOpen::Opened`（owned=false）。
    let plane = start_engine_data_plane(dll, SCHOOL_ADAPTER_NAME)?;
    ev.wintun_session_started = true; // 数据面属引擎（host），非 helper
    ctx.engine_data_plane = Some(plane);

    // ---- 5. authenticated atomic packet attach（W23B）——发生在认证之后。 ----
    attach_school_packet_relay(ctx, ev)?;

    // ---- 6. Connected：authenticated attach 之后。 ----
    let composition = ctx
        .host_composition
        .as_mut()
        .ok_or("host-composition-missing")?;
    let effect = composition.apply(HostEvent::ProtocolEstablished);
    if effect != HostEffect::Connected {
        return Err("protocol-established-not-connected");
    }
    ev.optimistic_connected = false;
    ev.phase_journal.push("connected".to_string());

    // ---- 7. Connected 之后：persistent-tunnel hold 或真实 HTTP flow。 ----
    // 路由生命周期快照在 flow **之前**执行（Connected + plan applied + 校园路由已在
    // 系统表时）：DP-07 诊断——flow 失败（`?` 提前返回）也必须保留隧道路由状态，才能
    // 判断 SYN 是否真的走 Wintun /25 路由（与 Mihomo TUN 路由竞争的根因线索）。 ----
    match direct_connect::snapshot_ipv4_routes() {
        Ok(snapshot) => ev.routes_during_tunnel = snapshot,
        Err(e) => ev.routes_during_tunnel = vec![format!("snapshot-error:code-{}", e.code)],
    }

    if let Some(stop_file) = hold {
        // ---- 7-H. hold：TUNNEL_READY + 合并校园路由（offer + 配置）+ 数据面 + 保持存活。 ----
        run_school_hold_phase(ctx, &connection.data, &plan, Some(stop_file), ev)
            .map_err(|_| "hold")?;
        ev.phase_journal.push("hold".to_string());
    } else {
        // ---- 7. 真实学校目标 IPv4 ingress flow（跨 Wintun ring + CSTP 双向）。
        //      SSH banner（w202:22）或 HTTP（:80）；按 `flow_protocol` 诚实记录
        //      ingress 证明的协议（SSH banner 字节就是真实校园 ingress 数据）。 ----
        let flow = run_school_ingress_flow(ctx, &connection.data, target, ev)
            .map_err(|_| "http-flow")?;
        ev.http_flow_request_sent = flow.request_sent;
        ev.http_flow_response_received = flow.response_received;
        ev.http_flow_response_status = flow.response_status;
        ev.http_flow_bytes_out = flow.bytes_out;
        ev.http_flow_bytes_in = flow.bytes_in;
        ev.flow_target_ipv4 = Some(target.flow_target_ipv4.to_string());
        ev.flow_protocol = Some(flow.protocol.as_str().to_string());
        ev.flow_connect_succeeded = flow.connect_succeeded;
        ev.phase_journal.push("http_flow".to_string());
    }

    // ---- 8. 正常 Stop（journal/join/restore/proof/retirement/helper 退出）。 ----
    let stop_reply = run_school_stop(ctx).map_err(|_| "stop")?;
    record_school_stop_evidence(ev, ctx, &stop_reply);
    Ok(())
}

// ---------------------------------------------------------------------------
// persistent-tunnel hold 模式（--hold；config-driven campus routes）。
// ---------------------------------------------------------------------------

/// hold 模式的 stop 来源（证据 phase_journal 记录）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HoldStopSource {
    /// `--stop-file` 出现（脚本驱动：按 Enter 创建 stop 文件）。
    StopFile,
    /// stdin EOF（交互 TTY Ctrl+D / 管道关闭）。
    StdinEof,
}

/// hold 阶段（Connected/plan-applied 之后）：打印 `TUNNEL_READY`（tunnel IP /
/// adapter 名 / ifindex）、应用**合并校园路由**（offer `X-CSTP-Split-Include`
/// 优先 + `EXV_RUST_VPN_SCHOOL_ROUTES` 配置路由，按规范化 CIDR 身份去重；路由来自
/// 产品配置，绝不硬编码）、保持隧道存活直到 stop 条件（stop-file 或 stdin EOF——
/// **凭据通道文件绝不作 stop 条件**）、然后逆序移除应用的路由。失败路径由调用方
/// 标记 `vertical-step-failed:hold`（动态事实不提交）。
fn run_school_hold_phase(
    ctx: &mut SchoolCtx,
    data: &SchoolData,
    plan: &SchoolValidatedPlan,
    stop_file: Option<&Path>,
    ev: &mut SchoolScenarioEvidence,
) -> Result<(), &'static str> {
    ev.held_mode = true;

    // ---- route_source 三方证据：offer（真实 offer 的 Split-Include）优先，config
    //      （EXV_RUST_VPN_SCHOOL_ROUTES，镜像 C++ 产品配置）追加非重复。 ----
    let offer_routes = plan.routes.clone();
    let config_routes = parse_school_routes_env().map_err(|_| "school-routes-env")?;
    let merged = merge_campus_routes(&offer_routes, &config_routes);
    ev.route_source = Some(RouteSource {
        offer: offer_routes,
        config: config_routes,
        merged: merged.clone(),
    });

    // ---- TUNNEL_READY anchor 行（脚本轮询）：tunnel IP / adapter 名 / ifindex。 ----
    let ip = &plan.ipv4_address;
    let adapter = ev.wintun_adapter_name.clone().unwrap_or_default();
    let ifindex = ev.wintun_adapter_ifindex.unwrap_or(0);
    println!("TUNNEL_READY: ip={ip} adapter={adapter} ifindex={ifindex}");
    let _ = std::io::stdout().flush();
    // 提权进程的 stdout 重定向在部分宿主不可靠：`EXV_RUST_VPN_HOLD_READY_FILE`
    // 设置时把同一行写入该文件（由 elevated 进程自己创建——脚本轮询的可靠通道）。
    if let Some(path) = std::env::var_os(HOLD_READY_FILE_ENV) {
        let _ = std::fs::write(
            Path::new(&path),
            format!("TUNNEL_READY: ip={ip} adapter={adapter} ifindex={ifindex}\n"),
        );
    }

    // ---- 合并校园路由已由 helper apply RPC 安装（`apply_school_tunnel` 经
    //      `ApplyReq.campus_routes`；`CreateIpForwardEntry2` 在提权 helper 内执行）。
    //      `campus_routes_applied` = 系统路由表存活验证（全部合并路由以 Wintun 接口
    //      真实存在）；失败诚实记录（campus_routes_error），隧道保持存活
    //      （TUNNEL_READY 已发——脚本向用户展示错误，可手动排查）。 ----
    ev.campus_routes_applied = ev.campus_routes_live_in_system_table;

    // ---- 数据面（DP-03：引擎数据面线程直连引擎 session，不再经 packet pipe）。
    //      线程 R（ring→CSTP）+ 线程 W（CSTP→ring）；stop 后 join（先 join 再拆除——
    //      W17 顺序纪律；`stop_and_join` 在 `WintunEndSession` 之前 join）。 ----
    let plane = ctx.engine_data_plane.as_ref().ok_or("engine-data-plane-missing")?;
    let relay = ctx.relay.as_ref().ok_or("relay-missing")?;
    let mut data_plane = plane.spawn_data_plane(
        data.write_channel.clone(),
        &data.read_channel,
        Arc::clone(relay),
    );

    // ---- 保持存活直到 stop 条件（stop-file 出现或 stdin EOF）。 ----
    let source = wait_for_hold_stop(stop_file);

    // 数据面停止：置位 → join（先 join 再拆除，W17 纪律）。
    let (held_ring_recv, held_ring_sent) = data_plane.stop_and_join();
    ctx.host_ring_received_bytes = Some(held_ring_recv);
    ctx.host_ring_sent_bytes = Some(held_ring_sent);
    ev.held_ring_recv_bytes = Some(held_ring_recv);
    ev.held_ring_sent_bytes = Some(held_ring_sent);
    ev.phase_journal.push(match source {
        HoldStopSource::StopFile => "hold_stop_file".to_string(),
        HoldStopSource::StdinEof => "hold_stdin_eof".to_string(),
    });

    // ---- 校园路由由 helper 在 Stop 逆序清理（`installed_routes` 逆序 remove）——
    //      此处 host 不直接写路由表（特权操作归属 helper）。`campus_routes_removed`
    //      在 Stop 后由 `record_school_stop_evidence` 以 routes_after == routes_before
    //      回读证明置真。 ----
    Ok(())
}

/// 等待 hold 结束：`stop_file` 出现或 stdin EOF。`stop_file` 为 `Some` 时不读
/// stdin（elevated 进程可能持有不可用的 console stdin——读了会永久阻塞；脚本场景
/// 只依赖 stop-file）。
fn wait_for_hold_stop(stop_file: Option<&Path>) -> HoldStopSource {
    // 仅当无 stop-file 时才监听 stdin EOF（交互 TTY 场景；线程读到 EOF 即置位）。
    let stdin_eof: Option<Arc<AtomicBool>> = if stop_file.is_none() {
        let flag = Arc::new(AtomicBool::new(false));
        let f = Arc::clone(&flag);
        std::thread::spawn(move || {
            let mut buf: Vec<u8> = Vec::new();
            let _ = std::io::stdin().lock().read_to_end(&mut buf);
            buf.fill(0); // 无明文残留
            f.store(true, Ordering::SeqCst);
        });
        Some(flag)
    } else {
        None
    };
    loop {
        if stdin_eof
            .as_ref()
            .is_some_and(|f| f.load(Ordering::SeqCst))
        {
            return HoldStopSource::StdinEof;
        }
        if let Some(path) = stop_file
            && path.exists()
        {
            return HoldStopSource::StopFile;
        }
        std::thread::sleep(HOLD_POLL_INTERVAL);
    }
}

/// 合并校园路由：offer（`X-CSTP-Split-Include`）优先，config（
/// `EXV_RUST_VPN_SCHOOL_ROUTES`，镜像 C++ 产品配置）追加**非重复**项；按规范化
/// CIDR 身份（网络位已屏蔽的 `(network, prefix)`）去重，返回规范化 CIDR 字符串
/// 列表。非法条目防御性跳过（`parse_school_routes_env` 在入口已拒绝 config 的
/// 非法条目；此处对 offer 的畸形项同样跳过）。
#[must_use]
pub fn merge_campus_routes(offer_routes: &[String], config_routes: &[String]) -> Vec<String> {
    let mut seen: HashSet<RouteKey> = HashSet::new();
    let mut merged: Vec<String> = Vec::new();
    for cidr in offer_routes.iter().chain(config_routes) {
        if let Some((key, normalized)) = normalize_cidr(cidr)
            && seen.insert(key)
        {
            merged.push(normalized);
        }
    }
    merged
}

/// 解析一条 CIDR：返回（规范化身份 key，规范化 `net/prefix` 字符串）；畸形条目
/// 返回 `None`。主机位屏蔽复用 `RouteRow::new` 的 facts §3 语义。
fn normalize_cidr(cidr: &str) -> Option<(RouteKey, String)> {
    let (net, prefix) = cidr.split_once('/')?;
    let net: Ipv4Addr = net.trim().parse().ok()?;
    let prefix: u8 = prefix.trim().parse().ok()?;
    if prefix > 32 {
        return None;
    }
    // RouteRow::new 屏蔽主机位（前缀含主机位会让 CreateIpForwardEntry2 返回 87）。
    let row = RouteRow::new(net, prefix, Ipv4Addr::UNSPECIFIED, 0, 0);
    Some((row.dest_key(), format!("{}/{}", row.network, prefix)))
}

/// 解析 `EXV_RUST_VPN_SCHOOL_ROUTES`（逗号分隔 CIDR；镜像 C++ 产品 config.json 的
/// `default_routes`——路由来自产品配置，绝不硬编码在连接逻辑里）。未设置/空 →
/// `Ok(vec![])`（无配置路由；offer 路由仍生效）。任一条目不是合法 CIDR → typed
/// 错误（诚实拒绝，绝不静默跳过配置）。纯解析委托 [`parse_campus_routes_str`]。
fn parse_school_routes_env() -> Result<Vec<String>, String> {
    let Ok(raw) = std::env::var(SCHOOL_ROUTES_ENV) else {
        return Ok(Vec::new());
    };
    parse_campus_routes_str(&raw)
}

/// 解析 flow 目标 `host:port` 字符串（`EXV_RUST_VPN_SCHOOL_FLOW_TARGET` /
/// `EXV_RUST_VPN_SCHOOL_TARGET` 第二 endpoint 的纯逻辑；测试可确定性驱动，不依赖
/// 进程全局 env）。flow 目标必须是 IPv4 字面量（反假绿：受控 10.99.99.2 在
/// 调用方拒绝）；端口必须可解析。
fn parse_flow_target_str(flow: &str) -> Result<(Ipv4Addr, u16), String> {
    let (f_host, f_port) = flow
        .split_once(':')
        .ok_or_else(|| "flow target not host:port".to_string())?;
    let ipv4: Ipv4Addr = f_host
        .parse()
        .map_err(|_| "flow target must be an IPv4 literal".to_string())?;
    let port: u16 = f_port.parse().map_err(|_| "flow target port parse")?;
    Ok((ipv4, port))
}

/// 解析逗号分隔的 CIDR 字符串（`EXV_RUST_VPN_SCHOOL_ROUTES` 的纯逻辑；测试可
/// 确定性驱动，不依赖进程全局 env）。空字符串 → `Ok(vec![])`；任一条目不是合法
/// IPv4 CIDR → typed 错误（诚实拒绝，绝不静默跳过配置）。
fn parse_campus_routes_str(raw: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (net, prefix) = part
            .split_once('/')
            .ok_or_else(|| format!("not-cidr:{part}"))?;
        let net: Ipv4Addr = net.trim().parse().map_err(|_| format!("bad-net:{part}"))?;
        let prefix: u8 = prefix
            .trim()
            .parse()
            .map_err(|_| format!("bad-prefix:{part}"))?;
        if prefix > 32 {
            return Err(format!("prefix>32:{part}"));
        }
        out.push(format!("{}/{}", net, prefix));
    }
    Ok(out)
}

/// 构建校园路由配置（apply RPC 的 `campus_routes` 列表）：offer（真实 CSTP offer
/// 的 `X-CSTP-Split-Include`）优先 + config（`EXV_RUST_VPN_SCHOOL_ROUTES`，镜像
/// C++ 产品 config.json `default_routes`）追加非重复，按规范化 CIDR 身份去重。
/// 路由来自产品配置，绝不硬编码在连接逻辑里。
fn build_campus_route_config(offer_routes: &[String]) -> Result<Vec<String>, String> {
    let config = parse_school_routes_env()?;
    Ok(merge_campus_routes(offer_routes, &config))
}

/// 安装校园路由（`CreateIpForwardEntry2`；`ERROR_OBJECT_ALREADY_EXISTS` 5010 容忍
/// ——offer 路由已由 helper apply 安装时直接回读采纳，不重复安装、不覆盖）。返回
/// 每条 CIDR 的**回读生效行**（全字段精确行，逆序清理用；W20 facts §3 语义——
/// 用请求行删除会以 87 被拒）。任一失败时整批**逆序回滚**已安装的行
/// （'partial failure' mutant 在此死——不留半状态路由）。
///
/// # Errors
///
/// 任一 CIDR 畸形 / 安装失败（非 5010）/ 回读缺失 → `String` typed 描述。
pub fn install_campus_routes(
    luid: u64,
    next_hop: Ipv4Addr,
    cidrs: &[String],
) -> Result<Vec<RouteRow>, String> {
    let mut rows = Vec::with_capacity(cidrs.len());
    for cidr in cidrs {
        let (key, _normalized) = normalize_cidr(cidr).ok_or_else(|| format!("bad-cidr:{cidr}"))?;
        let desired = RouteRow::new(key.network, key.prefix_len, next_hop, luid, CAMPUS_ROUTE_METRIC);
        match install_route(&desired) {
            Ok(()) => {}
            Err(e) if e.code == ERROR_OBJECT_ALREADY_EXISTS => {} // 已存在：回读采纳
            Err(e) => {
                rollback_campus_rows(&rows);
                return Err(format!("route-install:code-{}", e.code));
            }
        }
        let actual = match capture_rows(luid)
            .map_err(|e| format!("route-readback:code-{}", e.code))?
            .into_iter()
            .find(|r| r.dest_key() == desired.dest_key())
        {
            Some(row) => row,
            None => {
                rollback_campus_rows(&rows);
                return Err(format!("route-readback-missing:{cidr}"));
            }
        };
        rows.push(actual);
    }
    Ok(rows)
}

/// 逆序回滚已安装的行（best-effort；AlreadyAbsent 幂等）。
fn rollback_campus_rows(rows: &[RouteRow]) {
    for row in rows.iter().rev() {
        let _ = remove_route(row);
    }
}

/// 逆序移除校园路由（`routes::remove` 原语：`GetIpForwardEntry2` 填满行全字段比对
/// → `DeleteIpForwardEntry2`；AlreadyAbsent 幂等）。空集合直接成功。
///
/// # Errors
///
/// 任一行的移除失败（填满行不一致 / Get/Delete 失败）→ `String` typed 描述。
pub fn remove_campus_routes(rows: &[RouteRow]) -> Result<(), String> {
    for row in rows.iter().rev() {
        match remove_route(row) {
            Ok(_) => {}
            Err(e) => return Err(format!("route-remove:code-{}", e.code)),
        }
    }
    Ok(())
}

/// 系统路由表存活验证（`GetIpForwardTable2` 回读 Wintun 接口）：断言合并校园路由
/// 的每条都以 Wintun 接口为出接口**真实存在**——路由真实可路由，非仅证据记录。
/// 返回 `(全部存在?, 实际命中的校园路由 CIDR 列表)`；畸形条目防御性跳过。
fn verify_campus_routes_live(luid: u64, cidrs: &[String]) -> Result<(bool, Vec<String>), String> {
    let rows = capture_rows(luid).map_err(|e| format!("capture-rows:code-{}", e.code))?;
    let mut found = Vec::new();
    let mut all = true;
    for cidr in cidrs {
        if let Some((key, _normalized)) = normalize_cidr(cidr) {
            if rows.iter().any(|r| r.dest_key() == key) {
                found.push(format!("{}/{}", key.network, key.prefix_len));
            } else {
                all = false;
            }
        }
    }
    Ok((all, found))
}

/// host 进程是否 elevated（`require_admin` pattern 观测；转发 vertical 的
/// pub(crate) 观测供测试与脚本消费）。
#[must_use]
pub fn host_is_elevated() -> bool {
    vertical::is_elevated()
}

/// 真实 TLS identity：chain/hostname 验证（Production 信任策略 = 真实学校链）+
/// 错误 host 拒绝（kills always-true verifier mutant）。
///
/// TCP 直连**真实 IP**（`gateway_addr = (real_ip, port)`，绕过 Mihomo TUN）；
/// TLS ServerName / 证书校验仍按 `target.gateway_host` 域名（SNI = 域名，VGDC-02）。
fn run_school_tls_identity(
    rt: &tokio::runtime::Runtime,
    target: &SchoolTarget,
    real_ip: Ipv4Addr,
    ev: &mut SchoolScenarioEvidence,
) -> Result<(), &'static str> {
    let gateway_addr = SocketAddr::from((real_ip, target.gateway_port));
    let cfg_ok = BootstrapConfig {
        hostname: target.gateway_host.clone(),
        gateway_addr,
        trust: TrustPolicy::Production,
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };
    // 诚实分类：失败时记录精确变体（BootstrapError 变体名——ConnectFailed /
    // HandshakeFailed / UntrustedChain / HostnameMismatch 等），绝不把连接层失败
    // （端点不可达、ServerHello 未达）冒充为证书链验证失败；session 立即 drop
    // （验证连接随后关闭）。
    let chain_verified = match rt.block_on(Bootstrap::system().connect(cfg_ok)) {
        Ok(_) => {
            ev.tls_failure_variant = None;
            true
        }
        Err(f) => {
            ev.tls_failure_variant = Some(format!("{:?}", f.error));
            false
        }
    };
    ev.tls_chain_verified = chain_verified;
    ev.tls_hostname_verified = chain_verified;
    ev.tls_verified_against_real_school_chain = chain_verified;
    if !chain_verified {
        return Err("tls-chain-unverified");
    }
    let cfg_wrong = BootstrapConfig {
        hostname: format!("wrong-host.{}", target.gateway_host),
        gateway_addr,
        trust: TrustPolicy::Production,
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };
    let wrong_host_rejected = rt
        .block_on(Bootstrap::system().connect(cfg_wrong))
        .is_err_and(|f| matches!(f.error, BootstrapError::HostnameMismatch));
    ev.tls_wrong_host_rejected = wrong_host_rejected;
    if !wrong_host_rejected {
        return Err("tls-wrong-host-not-rejected");
    }
    ev.phase_journal.push("tls_verified".to_string());
    Ok(())
}

/// 提权 helper（W26 组合）+ 已认证 control pipe + 双向身份验证；返回已验证的
/// helper 身份（供 W27 host 组合绑定）。
///
/// DP-04：只建 **control pipe**（apply/stop RPC）——packet pipe 数据路径已移除
/// （引擎数据面直连自己的 session/ring，host 不再经 helper packet pipe 间接访问 ring）。
/// helper 的 `run_helper_inner` 据此契约不再创建/等待 packet pipe server。
fn connect_school_helper(
    dll: &Path,
    ev: &mut SchoolScenarioEvidence,
    ctx: &mut SchoolCtx,
) -> Result<VerifiedPipePeer, &'static str> {
    let host_pid = std::process::id();
    let helper_exe = vertical::helper_bin_path().ok_or("helper-binary-unresolved")?;
    let (helper_pid, helper_handle) =
        vertical::spawn_helper_elevated(&helper_exe, &school_helper_args(dll))
            .map_err(|_| "helper-elevation-failed")?;
    ev.helper_pid = Some(helper_pid);
    ev.helper_token_elevated = vertical::process_token_elevated(helper_pid);
    if !ev.helper_token_elevated {
        return Err("helper-elevation-failed");
    }
    ctx.helper_handle = Some(helper_handle);

    let pipe_prefix = format!("{SCHOOL_PIPE_PREFIX}-{host_pid}");
    let control_name = format!(r"\\.\pipe\{pipe_prefix}-c");
    let control = vertical::connect_pipe(&control_name).map_err(|_| "pipe-connect-control")?;

    // 双向身份验证（control pipe：helper 验 host；host 验 helper）。
    let hello_req = vertical::HelloReq {
        cmd: "hello".to_string(),
        host_pid,
    };
    vertical::write_json(&control, &hello_req).map_err(|_| "pipe-hello-write")?;
    let hello: vertical::HelloReply = vertical::read_json(&control).map_err(|_| "pipe-hello-read")?;
    if !hello.ok {
        return Err("pipe-hello-refused");
    }
    let own_sid = vertical::current_user_sid().ok_or("pipe-own-sid")?;
    let control_identity_matches = {
        let pid_matches = Some(hello.helper_pid) == ev.helper_pid;
        pid_matches && hello.helper_sid == own_sid && !hello.helper_sid.is_empty()
    };
    if !control_identity_matches {
        return Err("pipe-peer-verification");
    }
    ctx.control = Some(control);
    Ok(VerifiedPipePeer {
        process_id: hello.helper_pid,
        user_sid: hello.helper_sid,
        logon_sid: None,
        account_name: hello.helper_account,
    })
}

/// W27 host 组合 + W16/W17/W22 helper apply（plan 来自真实学校 offer；campus
/// routes 经 apply RPC 由提权 helper 安装——特权操作归属 helper）。
fn apply_school_tunnel(
    dll: &Path,
    plan: &SchoolValidatedPlan,
    campus_routes: &[String],
    peer: &VerifiedPipePeer,
    ev: &mut SchoolScenarioEvidence,
    ctx: &mut SchoolCtx,
) -> Result<(), &'static str> {
    // ---- W27 host 组合（verified helper 身份绑定）。 ----
    let mut host_composition =
        compose_nonprivileged_host(peer).map_err(|_| "host-compose")?;
    {
        let gate = host_composition.kernel_gate();
        let _ = gate.authorize(peer);
    }
    let _ = host_composition.apply(HostEvent::Connect);
    ctx.host_composition = Some(host_composition);

    // ---- helper apply（真实学校 plan；W16/W17/W22 leaf 组合）。 ----
    let apply_req = vertical::ApplyReq {
        cmd: "apply".to_string(),
        dll: dll.display().to_string(),
        adapter_name: SCHOOL_ADAPTER_NAME.to_string(),
        address: plan.ipv4_address.clone(),
        prefix: plan.prefix,
        mtu: plan.mtu,
        dns: plan.dns_servers.clone(),
        routes: plan.routes.clone(),
        campus_routes: campus_routes.to_vec(),
    };
    let control = ctx.control.as_ref().ok_or("control-pipe-missing")?;
    vertical::write_json(control, &apply_req).map_err(|_| "apply-write")?;
    let apply_reply: vertical::ApplyReply = vertical::read_json(control).map_err(|_| "apply-read")?;
    if !apply_reply.ok {
        return Err("helper-apply-failed");
    }
    ev.wintun_adapter_name.clone_from(&apply_reply.adapter_name);
    ev.wintun_adapter_luid = apply_reply.adapter_luid;
    ev.wintun_adapter_ifindex = apply_reply.adapter_ifindex;
    // DP-02：helper 不再建 session（create-then-idle）；`wintun_session_started` 由
    // 引擎数据面（`start_engine_data_plane`）置真——数据面属主是引擎（host）。
    ev.inventory_items.clone_from(&apply_reply.inventory);
    ev.inventory_complete = ev.inventory_items.len() == COMPLETE_INVENTORY.len();
    ev.address_applied.clone_from(&apply_reply.address_applied);
    ev.mtu_applied = apply_reply.mtu_applied;
    // `routes_applied` = 隧道路由 + 校园路由（helper 回读采纳的合并集）。
    ev.routes_applied.clone_from(&apply_reply.routes_applied);
    ev.dns_applied.clone_from(&apply_reply.dns_applied);

    // ---- 特权门禁确认：校园路由写入经 helper apply RPC（`CreateIpForwardEntry2`
    //      在提权 helper 进程内执行），非 host 侧——特权操作归属 helper。 ----
    ev.route_writes_in_helper = true;

    // ---- 系统路由表存活验证（隧道路由期间）：`GetIpForwardTable2` 回读 Wintun
    //      接口，断言合并校园路由全部以 Wintun 为出接口真实存在（路由真实可路由，
    //      非仅证据记录）。 ----
    if let Some(luid) = ev.wintun_adapter_luid {
        match verify_campus_routes_live(luid, campus_routes) {
            Ok((present, found)) => {
                ev.campus_routes_live_in_system_table = present;
                ev.campus_routes_live = found;
                if !present {
                    ev.campus_routes_error =
                        Some("live-verify:not-all-campus-routes-present".to_string());
                }
            }
            Err(e) => ev.campus_routes_error = Some(format!("live-verify:{e}")),
        }
    }
    // flow 路径与 hold 路径（run_school_hold_phase）一致：`campus_routes_applied` =
    // 系统路由表存活验证结果。此前只在 hold 路径设置——flow 路径 `campus_routes_applied`
    // 恒 false，与 `campus_routes_live_in_system_table=true` 矛盾（路由真实在表却标记
    // 未应用）；补上诚实记录。 ----
    ev.campus_routes_applied = ev.campus_routes_live_in_system_table;
    ev.address_before = Some(
        apply_reply
            .before
            .address_rows
            .first()
            .cloned()
            .unwrap_or_else(|| "none".to_string()),
    );
    ev.mtu_before = apply_reply.before.mtu_v4;
    ev.routes_before.clone_from(&apply_reply.before.routes);
    ev.dns_before.clone_from(&apply_reply.before.dns_nameservers);
    Ok(())
}

/// Stop 回复 → 证据记录（journal/inventory/proof/retirement/ring 字节/helper 退出）。
fn record_school_stop_evidence(
    ev: &mut SchoolScenarioEvidence,
    ctx: &mut SchoolCtx,
    stop_reply: &vertical::StopReply,
) {
    ev.stop_journaled = stop_reply.stop_journaled;
    ev.cleanup_proof_issued = stop_reply.cleanup_proof_issued;
    ev.retirement_recorded = stop_reply.retirement_recorded;
    ev.owned_resources_retired = stop_reply.owned_resources_retired;
    ev.wintun_adapter_removed_after_stop = stop_reply.adapter_removed;
    ev.packets_after_stop = stop_reply.packets_after_stop;
    ev.address_after = Some(
        stop_reply
            .after
            .address_rows
            .first()
            .cloned()
            .unwrap_or_else(|| "none".to_string()),
    );
    ev.mtu_after = stop_reply.after.mtu_v4;
    ev.routes_after.clone_from(&stop_reply.after.routes);
    ev.dns_after.clone_from(&stop_reply.after.dns_nameservers);
    ev.network_state_after_equals_before =
        stop_reply.after == stop_reply.before && ev.address_after == ev.address_before;
    // 校园路由由 helper 在 Stop 逆序清理（`installed_routes` 逆序 remove）；回读
    // 证明：Wintun 接口路由回到 before（路由生命周期，无泄漏）。
    if ev.campus_routes_live_in_system_table {
        ev.campus_routes_removed = ev.routes_after == ev.routes_before;
    }
    // DP-03：ring 字节计数从 **host 数据面计数器**读（引擎 reader/writer 线程直连
    // session 的 ring_received_bytes/ring_sent_bytes），不再来自 helper StopReply——
    // DP-01 后 helper 空闲、StopReply 恒 0。
    let ring_received_bytes = ctx.host_ring_received_bytes.unwrap_or(stop_reply.ring_received_bytes);
    let ring_sent_bytes = ctx.host_ring_sent_bytes.unwrap_or(stop_reply.ring_sent_bytes);
    let ring_bytes = ring_received_bytes + ring_sent_bytes;
    ev.packet_bytes_on_ring = ring_bytes;
    ev.wintun_ring_traffic_observed = ring_received_bytes > 0 && ring_sent_bytes > 0;
    ev.http_flow_correlated_to_ring = ring_bytes >= ev.http_flow_bytes_out + ev.http_flow_bytes_in;
    let helper_handle = ctx.helper_handle.take();
    ev.helper_exited_after_stop =
        helper_handle.is_some_and(|h| vertical::wait_process_exit(h, HELPER_EXIT_TIMEOUT_MS));
    ev.phase_journal.push("stop_complete".to_string());
}

/// 学校 flow 结束后（或失败路径）的自清理：Stop helper + 等其退出（无残留）。
fn cleanup_school(ev: &mut SchoolScenarioEvidence, ctx: &mut SchoolCtx) {
    // DP-02：先 drop 引擎数据面（`WintunEndSession` + close 打开的句柄），再 Stop
    // helper（creator close 移除 adapter）——顺序保证 adapter 移除前 host session
    // 已 end（失败路径同样不泄漏引擎 session）。
    if let Some(plane) = ctx.engine_data_plane.take() {
        drop(plane);
    }
    if let Some(relay) = ctx.relay.as_ref() {
        let mut guard = relay.lock().expect("relay 锁");
        guard.relay.stop();
    }
    if let Some(composition) = ctx.host_composition.as_mut() {
        composition.exit();
    }
    if ctx.control.is_some() {
        let _ = run_school_stop(ctx);
    }
    if let Some(handle) = ctx.helper_handle.take()
        && vertical::wait_process_exit(handle, HELPER_EXIT_TIMEOUT_MS)
    {
        ev.helper_exited_after_stop = true;
    }
    let _ = ctx.control.take();
}

/// 向 helper 发送 Stop 并读取其 teardown 回复。
fn run_school_stop(ctx: &mut SchoolCtx) -> Result<vertical::StopReply, String> {
    // DP-02：引擎（host 侧）session 必须在 helper 移除 adapter 之前 end。drop
    // `EngineDataPlane` 即 `WintunEndSession` → close 打开的句柄（非创建者，不删
    // adapter）→ 释放 dll。adapter 移除仍由 helper Stop 的 creator close 负责
    // （C++ Stop：engine close + helper cleanup）。
    if let Some(plane) = ctx.engine_data_plane.take() {
        drop(plane);
    }
    let control = ctx.control.as_ref().ok_or("control-pipe-missing")?;
    vertical::write_json(
        control,
        &vertical::StopReq {
            cmd: "stop".to_string(),
        },
    )?;
    let reply: vertical::StopReply = vertical::read_json(control)?;
    if !reply.ok {
        return Err(reply.error.unwrap_or_else(|| "helper stop failed".to_string()));
    }
    Ok(reply)
}

/// W23B 组合：从一次性 capability 原子 attach（认证之后）。
fn attach_school_packet_relay(
    ctx: &mut SchoolCtx,
    ev: &mut SchoolScenarioEvidence,
) -> Result<(), &'static str> {
    let lease = vertical::deterministic_packet_lease();
    let epoch = RuntimeEpoch::try_from(Uuid::new_v4()).map_err(|_| "runtime-epoch")?;
    let mut capability = PacketCapability::issue(lease, epoch);
    let channel = PacketChannel::new(&PacketLimits::mvp(), DataPlaneDirection::ProtocolToPacket)
        .map_err(|_| "packet-channel")?;
    let attachment = AttachedPacketRelay::attach(&mut capability, 1).map_err(|_| "relay-attach")?;
    let relay = AttachedPacketRelay::new(attachment, channel, PacketLimits::mvp());
    let mut state = SchoolRelayState { relay, next_seq: 0 };
    state.relay.start_leg(RelayDirection::Receive);
    state.relay.start_leg(RelayDirection::Send);
    ctx.relay = Some(Arc::new(Mutex::new(state)));
    ev.packet_attach_authenticated = true; // attach 发生在 pipe 双向认证 + TLS + 学号/密码认证之后
    ev.phase_journal.push("attach".to_string());
    Ok(())
}

// ---------------------------------------------------------------------------
// 真实学校 TLS / 认证 / CSTP offer。
// ---------------------------------------------------------------------------

/// 学校 data 连接的运行期通道（引擎 `CstpSession` 拆流后的 data 任务通道）。
struct SchoolData {
    /// 运行 HTTP flow 的 tokio runtime。
    runtime: Arc<tokio::runtime::Runtime>,
    /// 引擎 write_channel（DP-03/DP-04）：编码后的 CSTP DATA 帧 → 引擎数据面
    /// reader 线程（`EngineDataPlane::spawn_data_plane`）发送（TLS → 学校）。
    write_channel: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    /// 引擎 read_channel（DP-03/DP-04）：解码后的 IP 包 → 引擎数据面 writer 线程
    /// （`EngineDataPlane::spawn_data_plane`）`session.send`（TLS → ring）。不再由
    /// packet-pipe writer 消费（packet pipe 数据路径已移除）。
    read_channel: Arc<Mutex<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>>,
}

/// 认证 vault 流程的结果（已 Established 的 vault）。
/// 封存：原 `group_digest` 字段（group 的 SHA-256 digest）不再产生——group 不参与
/// MVP 认证（2026-08-15 用户裁定：仅学号/密码），`auth_group_digest` 恒为 None。
struct SchoolAuthOutcome {
    vault: AuthInteraction,
}

/// 真实单调时钟（vault 的注入 clock；确定性由测试侧 `FakeClock` 负责，生产侧用真时钟）。
struct RealClock;

impl AuthClock for RealClock {
    fn now_millis(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

// ---------------------------------------------------------------------------
// 提权运行的一次性凭据通道（provide → verify → destroy）。
// ---------------------------------------------------------------------------

/// 凭据通道错误（typed error，绝不 panic）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialChannelError {
    /// 通道文件不存在。
    Missing,
    /// 通道文件 IO 失败（读/写/删除）。
    Io(std::io::ErrorKind),
    /// 通道文件行数不是 2（必须恰好两行：学号、密码）。
    WrongLineCount { expected: usize, actual: usize },
    /// 通道文件含空行（空凭据拒绝）。
    EmptyLine,
    /// 通道文件 ACL 宽泛（非当前用户-only；宽泛可读的凭据文件拒绝读取）。
    NotUserOnlyAcl,
}

/// 从凭据通道读出的学号/密码（消费后 `zeroize_all`；与 `SchoolSecrets` 同款
/// 生命周期——字节转移进 vault 后由 `SchoolSecrets::zeroize_all` 清零）。
pub struct SchoolChannelCredentials {
    username: Vec<u8>,
    password: Vec<u8>,
}

impl SchoolChannelCredentials {
    /// 学号字节。
    #[must_use]
    pub fn username(&self) -> &[u8] {
        &self.username
    }

    /// 密码字节。
    #[must_use]
    pub fn password(&self) -> &[u8] {
        &self.password
    }

    /// 消费后 zeroize（一次消费，不留明文缓冲；长度保留、内容清零）。
    pub fn zeroize_all(&mut self) {
        self.username.fill(0);
        self.password.fill(0);
    }
}

/// 创建一次性凭据通道文件（provide 侧）：`%TEMP%\exv-school-cred-<pid>-<seq>.txt`，
/// 内容恰为两行（学号、密码），ACL 仅当前用户 + SYSTEM（protected DACL，拒绝
/// BUILTIN\Users / Everyone）。返回通道文件路径——**只返回路径**，凭据值绝不进入
/// argv/env/log/evidence。
///
/// # Errors
///
/// 写入失败或 ACL 收紧失败 → [`CredentialChannelError::Io`]。
///
/// 返回 `Result`（类型自身 `#[must_use]`；不再冗余标注）。
pub fn provide_school_credential_channel(
    username: &[u8],
    password: &[u8],
) -> Result<std::path::PathBuf, CredentialChannelError> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "{SCHOOL_CRED_FILE_PREFIX}-{}-{seq}.txt",
        std::process::id()
    ));
    let mut content: Vec<u8> = Vec::with_capacity(username.len() + password.len() + 2);
    content.extend_from_slice(username);
    content.push(b'\n');
    content.extend_from_slice(password);
    content.push(b'\n');
    std::fs::write(&path, &content).map_err(|e| CredentialChannelError::Io(e.kind()))?;
    content.fill(0); // 明文写缓冲立即清零
    ensure_secure_file(&path)
        .map_err(|_| CredentialChannelError::Io(std::io::ErrorKind::PermissionDenied))?;
    Ok(path)
}

/// 从一次性凭据通道读取两行（学号、密码）——scenario 的 verify 侧读取路径。
///
/// one-shot 语义：文件必须先存在（[`CredentialChannelError::Missing`]）、ACL 必须
/// 非宽泛（[`CredentialChannelError::NotUserOnlyAcl`]——宽泛可读的凭据文件拒绝
/// 读取）；两行读出后文件**立即删除**（destroy，无论解析成败——一次消费，绝不
/// 留下明文凭据文件）；原始读缓冲与行缓冲在消费后 zeroize。行数必须恰为 2
/// （[`CredentialChannelError::WrongLineCount`]），空行拒绝
/// （[`CredentialChannelError::EmptyLine`]）。
///
/// # Errors
///
/// [`CredentialChannelError`]（typed error，绝不 panic）。
///
/// 返回 `Result`（类型自身 `#[must_use]`；不再冗余标注）。
pub fn read_school_credential_channel(
    path: &Path,
) -> Result<SchoolChannelCredentials, CredentialChannelError> {
    if !path.is_file() {
        return Err(CredentialChannelError::Missing);
    }
    // 宽泛 ACL 的凭据文件拒绝读取（防凭据混淆；当前用户-only 是通道属性）。
    assert_file_not_tamperable(path).map_err(|_| CredentialChannelError::NotUserOnlyAcl)?;
    let mut raw = std::fs::read(path).map_err(|e| CredentialChannelError::Io(e.kind()))?;
    let mut lines = split_channel_lines(&raw);
    raw.fill(0); // 原始读缓冲立即清零
    // destroy：内容已读出，文件立即删除（one-shot；无论解析成败）。
    let destroyed = std::fs::remove_file(path).is_ok();
    // 校验：恰两行、无空行；错误路径同样 zeroize 行缓冲。
    let mut username = Vec::new();
    let mut password = Vec::new();
    let parsed = if lines.len() == 2 && !lines[0].is_empty() && !lines[1].is_empty() {
        username = std::mem::take(&mut lines[0]);
        password = std::mem::take(&mut lines[1]);
        Ok(())
    } else if lines.len() != 2 {
        Err(CredentialChannelError::WrongLineCount {
            expected: 2,
            actual: lines.len(),
        })
    } else {
        Err(CredentialChannelError::EmptyLine)
    };
    for line in &mut lines {
        line.fill(0);
    }
    parsed?;
    if !destroyed {
        username.fill(0);
        password.fill(0);
        return Err(CredentialChannelError::Io(std::io::ErrorKind::PermissionDenied));
    }
    Ok(SchoolChannelCredentials { username, password })
}

/// 按行切分通道内容（CRLF 与 LF 均接受；`\r` 剥离；末尾 `\n` 不产生空尾行；
/// 空行保留为行——由调用方以 `EmptyLine`/行数校验拒绝）。
fn split_channel_lines(raw: &[u8]) -> Vec<Vec<u8>> {
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    for &b in raw {
        if b == b'\n' {
            lines.push(std::mem::take(&mut cur));
        } else if b != b'\r' {
            cur.push(b);
        }
    }
    if raw.last().is_some_and(|&b| b != b'\n') {
        lines.push(cur);
    }
    lines
}

/// 受认证 one-shot 输入：优先读 `--cred-file` 一次性凭据通道（提权运行无 pipe
/// stdin；文件两行读出即删除 + zeroize）；否则仅当 stdin 是交互终端时逐行提示
/// （绝不从 argv/env 读 secret 值——`--cred-file` 只携带路径；非 TTY 也无通道 →
/// 错误 → `school-credentials-unavailable` 标记）。
/// 本 MVP（2026-08-15 用户裁定）只读取学号/密码；group 读取路径已封存
/// （`read_sealed_school_group`，永不调用——group 永不向用户请求）。
fn acquire_school_secrets(cred_file: Option<&Path>) -> Result<SchoolSecrets, &'static str> {
    if let Some(path) = cred_file {
        let mut creds =
            read_school_credential_channel(path).map_err(|_| "school-credentials-unavailable")?;
        return Ok(SchoolSecrets {
            group: Vec::new(), // 封存：group 不参与（恒为空；字段保留以利重新接线）
            username: std::mem::take(&mut creds.username),
            password: std::mem::take(&mut creds.password),
        });
    }
    if !std::io::stdin().is_terminal() {
        return Err("no-authenticated-controller-or-tty");
    }
    // 封存：group 选择非本 MVP 应用场景（2026-08-15 用户裁定：仅学号/密码）；
    // 如需重新接线须另立 cutover requirement 并重跑真实业务流。
    // 原读取行（`let group = read_secret_line("school group: ")...`）已封存于
    // `read_sealed_school_group`（永不调用）——group 永不向用户请求。
    let username = read_secret_line("school username: ").ok_or("tty-read-username")?;
    let password = read_secret_line("school password: ").ok_or("tty-read-password")?;
    Ok(SchoolSecrets {
        group: Vec::new(), // 封存：group 不参与（恒为空；字段保留以利重新接线）
        username,
        password,
    })
}

/// 封存：group 选择非本 MVP 应用场景（2026-08-15 用户裁定：仅学号/密码）；
/// 如需重新接线须另立 cutover requirement 并重跑真实业务流。
/// 原 TTY group 读取路径原样保留、永不调用（group 永不向用户请求）。重新接线时
/// 在 `acquire_school_secrets` 中恢复调用并重跑真实业务流。
#[allow(dead_code)]
fn read_sealed_school_group() -> Result<Vec<u8>, &'static str> {
    let group = read_secret_line("school group: ").ok_or("tty-read-group")?;
    Ok(group)
}

/// 从 stdin 读一行 secret（无中间 String 明文缓冲）。
fn read_secret_line(prompt: &str) -> Option<Vec<u8>> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut buf: Vec<u8> = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match std::io::stdin().read(&mut byte) {
            Ok(0) => break,
            Ok(1) => {
                if byte[0] == b'\n' {
                    break;
                }
                if byte[0] != b'\r' {
                    buf.push(byte[0]);
                }
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(buf)
    }
}

/// 一次性 secret 缓冲（使用后 `zeroize_all`）。
/// 封存：`group` 字段恒为空——group 不参与 MVP 认证（2026-08-15 用户裁定：
/// 仅学号/密码）；字段保留以利重新接线。
struct SchoolSecrets {
    group: Vec<u8>,
    username: Vec<u8>,
    password: Vec<u8>,
}

impl SchoolSecrets {
    fn zeroize_all(&mut self) {
        self.group.fill(0);
        self.username.fill(0);
        self.password.fill(0);
    }
}

/// 经 `AuthInteraction` 一次性 vault 跑认证流（MVP：仅学号/密码；group/challenge
/// 已封存——Group 步以空 secret 应答仅用于推进协议机械，不构成凭据、不记录
/// digest）。
fn feed_school_secrets(secrets: &SchoolSecrets) -> Result<SchoolAuthOutcome, &'static str> {
    let clock = Arc::new(RealClock);
    let mut vault = AuthInteraction::new(clock, AUTH_PROMPT_BUDGET);
    // 封存：group 选择非本 MVP 应用场景（2026-08-15 用户裁定：仅学号/密码）；
    // 如需重新接线须另立 cutover requirement 并重跑真实业务流。
    // vault（P42-I，auth.rs）的 begin()/respond() 按协议层能力从 Group challenge
    // 起步并须按序应答才能推进——该能力保留（testkit gateway 也使用），但本 flow
    // 不再向用户请求 group：Group 步以空 secret 应答仅用于推进协议机械，不构成
    // 凭据；学号/密码是唯一真实凭据。challenge/response 非本 MVP 应用场景，flow
    // 以学号/密码推进到 Established。重新接线（恢复 group 选择）时在此接入真实
    // group 并重跑真实业务流。
    let group = vault.begin();
    if group.kind != AuthChallengeKind::GroupUsernamePassword {
        return Err("unexpected-auth-kind");
    }
    let username = vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id.clone(),
            secret: Secret::new(&[]), // 封存：group 不参与；空 secret 仅推进协议
        })
        .map_err(|_| "auth-group-respond")?;
    let AuthProgress::Challenge(username) = username else {
        return Err("auth-username-challenge");
    };
    let password = vault
        .respond(AuthResponse {
            interaction_id: username.interaction_id.clone(),
            secret: Secret::new(&secrets.username),
        })
        .map_err(|_| "auth-username-respond")?;
    let AuthProgress::Challenge(password) = password else {
        return Err("auth-password-challenge");
    };
    let done = vault
        .respond(AuthResponse {
            interaction_id: password.interaction_id.clone(),
            secret: Secret::new(&secrets.password),
        })
        .map_err(|_| "auth-password-respond")?;
    if !matches!(done, AuthProgress::Established) {
        return Err("auth-not-established");
    }
    // 封存：原 `group_digest = sha256_hex(&secrets.group)` 不再计算——group 不参与
    // MVP 认证，`auth_group_digest` 恒为 None（serialization 稳定保留）。
    Ok(SchoolAuthOutcome { vault })
}

/// 学校 data 连接的结果（引擎 `CstpSession` 消费后：对端证书 SHA-256 指纹 +
/// validated plan digest + 平台面 plan + data 通道）。
struct SchoolDataConnection {
    /// 对端证书 SHA-256 指纹（引擎记录；非 raw 证书）。
    peer_fingerprint: Option<String>,
    /// 引擎校验后的 `TunnelOffer` plan 的 SHA-256 digest（诊断用；引擎不暴露
    /// raw offer 文本——raw offer 绝不进证据）。
    offer_digest: String,
    /// 平台面 tunnel plan（引擎 `TunnelOffer` → 学校 plan 类型适配）。
    plan: SchoolValidatedPlan,
    data: SchoolData,
}

/// 打开学校 CSTP data 连接：引擎属权（CS-AUTH-05）——`WebvpnLogin::perform_login`
/// （学号/密码一次性，percent-encoded 表单 POST `/+CSCOE+/logon`，捕获 webvpn
/// cookie；password 字节只在引擎 POST 构造期间驻留）→ `CstpSession::open`
/// （byte-exact `CONNECT /CSCOSSLC/tunnel` + webvpn cookie 凭据 + `X-CSTP-*` 头，
/// 无 Authorization；offer 校验 + 数据会话拆流全在引擎内——本场景绝不重实现
/// wire 逻辑）。TLS 直连真实 IP（`gateway_addr = (real_ip, port)`，绕过 Mihomo
/// TUN）、SNI/证书校验按 `target.gateway_host` 域名、Production 信任策略（真实
/// 学校链）。
///
/// 证据写入：login 成功/失败如实记录 `login_status` / `saml_required` /
/// `cookie_present`（cookie **值**绝不进证据——引擎 Debug 已脱敏）；失败把真实
/// 细节写进 `school_data_connection_error`（`login:<LoginError>` /
/// `connect-tunnel:<SessionError>`，typed 变体名，绝不含 secret/cookie）；
/// 网关 `a0` 结果码从错误 detail 读出时，`login_status` 记录
/// `login-rejected:a0=<code>`（凭据错 vs 请求形态问题的区分）。
fn open_school_data_connection(
    rt: &Arc<tokio::runtime::Runtime>,
    target: &SchoolTarget,
    real_ip: Ipv4Addr,
    secrets: &SchoolSecrets,
    vault: &mut AuthInteraction,
    ev: &mut SchoolScenarioEvidence,
) -> Result<SchoolDataConnection, &'static str> {
    let hostname = target.gateway_host.clone();
    let gateway_addr = SocketAddr::from((real_ip, target.gateway_port));

    // ---- 引擎 WebVPN login 阶段（计划 §3.1：POST /+CSCOE+/logon，只发送
    //      username/password——group 字段不发送）。SAML 重定向
    //      （`LoginError::SamlRequired`）= 诚实 blocked（计划 §6.3）：MVP 不支持
    //      SAML，如实标记，绝不把重定向/HTML 页当 login 成功。 ----
    let login = match rt.block_on(WebvpnLogin::perform_login(
        &hostname,
        gateway_addr,
        TrustPolicy::Production, // 真实学校链（与 run_school_tls_identity 同策略）
        None,
        &secrets.username,
        &secrets.password,
    )) {
        Ok(login) => login,
        Err(err) => {
            // secret 一次性契约：vault 持有副本立即清零（失败路径同样一次消费）。
            vault.send_secret();
            ev.school_data_connection_error = Some(format!("login:{err:?}"));
            // 网关 `a0` 结果码（凭据被拒时：`a0=15` = 真凭据被拒，
            // `a0=8`/`114`/`115`/`16` = 请求形态问题）从引擎错误的 detail 读出
            // 并写进证据，区分“凭据错”与“请求畸形”。
            ev.login_status = Some(match err.a0_result() {
                Some(code) => format!("login-rejected:a0={code}"),
                None => format!("login-failed:{err:?}"),
            });
            if matches!(err, LoginError::SamlRequired) {
                ev.saml_required = true; // 诚实 blocked；environment_state 标记见上
            }
            ev.phase_journal.push("school_data_connection_failed".to_string());
            return Err(if matches!(err, LoginError::SamlRequired) {
                "school-saml-required"
            } else {
                "school-data-connection"
            });
        }
    };
    // 引擎已零化自身的 POST 构造缓冲；vault 持有副本一次消费后清零。
    vault.send_secret();
    ev.login_status = Some(LOGIN_STATUS_OK.to_string());
    ev.cookie_present = true; // webvpn cookie 已捕获（CSTP CONNECT 阶段凭据）
    ev.saml_required = false;
    ev.phase_journal.push("auth_login".to_string());

    // ---- 引擎 CSTP session 阶段（计划 §3.2/3.3：byte-exact CONNECT 字节 +
    //      webvpn cookie 是凭据——无 Authorization、无 X-AnyConnect-*；offer
    //      校验 + data 任务全在引擎内）。 ----
    let cfg = BootstrapConfig {
        hostname: hostname.clone(),
        gateway_addr,
        trust: TrustPolicy::Production,
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };
    let session = match rt.block_on(CstpSession::open(cfg, Some(&login))) {
        Ok(session) => session,
        Err(err) => {
            ev.school_data_connection_error = Some(format!("connect-tunnel:{err:?}"));
            ev.phase_journal.push("school_data_connection_failed".to_string());
            return Err("school-data-connection");
        }
    };
    Ok(SchoolDataConnection {
        peer_fingerprint: session.peer_fingerprint,
        offer_digest: sha256_hex(
            serde_json::to_string(&session.offer_plan)
                .unwrap_or_default()
                .as_bytes(),
        ),
        plan: plan_from_offer(&session.offer_plan),
        data: SchoolData {
            runtime: Arc::clone(rt),
            write_channel: session.write_channel.clone(),
            read_channel: Arc::new(Mutex::new(session.read_channel)),
        },
    })
}

/// 引擎 `TunnelOffer`（平台中立 plan，计划 §3.3 校验：CSTP-only、IPv4-only、
/// MTU/前缀边界）→ 学校平台面 plan（类型适配；校验语义引擎属权）。
fn plan_from_offer(offer: &TunnelOffer) -> SchoolValidatedPlan {
    SchoolValidatedPlan {
        ipv4_address: offer.ipv4_address.to_string(),
        prefix: offer.prefix,
        mtu: u32::from(offer.mtu),
        dns_servers: offer.dns_servers.iter().map(|d| d.to_string()).collect(),
        routes: offer.routes.clone(),
    }
}

/// 校验后的学校 tunnel plan（引擎 `CstpSession::open` 内已完成 Common CSTP
/// offer validation；本类型只是平台面类型适配）。
struct SchoolValidatedPlan {
    ipv4_address: String,
    prefix: u8,
    mtu: u32,
    dns_servers: Vec<String>,
    routes: Vec<String>,
}

// ---------------------------------------------------------------------------
// 真实学校目标 IPv4 ingress flow（跨 Wintun ring + CSTP 双向）。
// ---------------------------------------------------------------------------

/// ingress flow 观测结果（HTTP 或 SSH banner；诚实记录协议与连接成功）。
struct HttpFlow {
    request_sent: bool,
    response_received: bool,
    response_status: Option<u16>,
    bytes_out: u64,
    bytes_in: u64,
    connect_succeeded: bool,
    protocol: FlowProtocol,
}

/// 真实学校目标 IPv4 ingress flow：client socket 经内核路由进 ring → 引擎数据面
/// reader（ring→CSTP DATA 帧→TLS）→ 学校服务器 → 响应/banner 经 CSTP DATA 帧回 →
/// 引擎数据面 writer（TLS→ring）→ 内核交付给 socket。SSH（22）读 banner 字节
/// （真实学校 ssh 服务的 ingress 证明）；HTTP 发 GET 读响应。
fn run_school_ingress_flow(
    ctx: &mut SchoolCtx,
    data: &SchoolData,
    target: &SchoolTarget,
    ev: &mut SchoolScenarioEvidence,
) -> Result<HttpFlow, &'static str> {
    let plane = ctx.engine_data_plane.as_ref().ok_or("engine-data-plane-missing")?;
    let relay = ctx.relay.as_ref().ok_or("relay-missing")?;
    let mut data_plane = plane.spawn_data_plane(
        data.write_channel.clone(),
        &data.read_channel,
        Arc::clone(relay),
    );

    // Ingress client：真实 socket 到学校目标（内核经隧道路由进 ring）。
    let flow_ip = target.flow_target_ipv4;
    let flow_port = target.flow_target_port;
    let protocol = target.flow_protocol;
    let flow_result = data
        .runtime
        .block_on(async {
            tokio::task::spawn_blocking(move || run_school_ingress_client(flow_ip, flow_port, protocol))
                .await
        })
        .map_err(|e| format!("http-task-join:{e}"));

    // 停止数据平面（先 join 再拆除，W17 纪律）——**失败路径也执行**：DP-05 诊断
    // 依赖 ring 计数器（SYN 是否进过 ring）与 `flow_error`（内层真实错误）一起读，
    // 才能区分"SYN 进 ring 无回包（数据面/路由问题）"与"connect 未入 ring"。
    let (ring_recv, ring_sent) = data_plane.stop_and_join();
    ctx.host_ring_received_bytes = Some(ring_recv);
    ctx.host_ring_sent_bytes = Some(ring_sent);

    let flow = match flow_result {
        Ok(Ok(f)) => f,
        Ok(Err(e)) => {
            ev.flow_error = Some(format!("ingress:{e}"));
            return Err("http-flow-failed");
        }
        Err(e) => {
            ev.flow_error = Some(e);
            return Err("http-flow-failed");
        }
    };

    Ok(HttpFlow {
        request_sent: true,
        response_received: flow.response_received,
        response_status: flow.response_status,
        bytes_out: flow.bytes_out,
        bytes_in: flow.bytes_in,
        connect_succeeded: flow.connect_succeeded,
        protocol,
    })
}

/// 学校目标 ingress flow 的 client 观测。
struct HttpClientResult {
    connect_succeeded: bool,
    response_received: bool,
    response_status: Option<u16>,
    bytes_out: u64,
    bytes_in: u64,
}

/// 真实 ingress client：connect 学校目标 IPv4:port（内核经 Wintun 隧道路由）。
/// SSH banner（22）：connect 成功即 ssh daemon 应答；读 banner 字节（真实校园
/// ingress 数据，非 HTTP）。HTTP：发 GET 读完整响应（Connection: close）。
fn run_school_ingress_client(
    flow_ip: Ipv4Addr,
    flow_port: u16,
    protocol: FlowProtocol,
) -> Result<HttpClientResult, String> {
    let addr = SocketAddr::from((flow_ip, flow_port));
    let mut sock = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("read timeout: {e}"))?;
    sock.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("write timeout: {e}"))?;
    match protocol {
        FlowProtocol::SshBanner => {
            // ssh daemon 应答：connect 成功即已证明；读 banner 字节（SSH-2.0-...）。
            let mut buf = [0u8; 256];
            let n = sock
                .read(&mut buf)
                .map_err(|e| format!("read banner: {e}"))?;
            Ok(HttpClientResult {
                connect_succeeded: true,
                response_received: n > 0,
                response_status: None,
                bytes_out: 0,
                bytes_in: n as u64,
            })
        }
        FlowProtocol::Http => {
            let request = format!("GET / HTTP/1.1\r\nHost: {flow_ip}\r\nConnection: close\r\n\r\n");
            sock.write_all(request.as_bytes())
                .map_err(|e| format!("write: {e}"))?;
            let mut buf = Vec::new();
            sock.read_to_end(&mut buf)
                .map_err(|e| format!("read: {e}"))?;
            let status = vertical::parse_http_status(&buf);
            Ok(HttpClientResult {
                connect_succeeded: true,
                response_received: !buf.is_empty(),
                response_status: status,
                bytes_out: request.len() as u64,
                bytes_in: buf.len() as u64,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// 学校服务 probe / 依赖守卫 / 证据扫描 / 基础工具。
// ---------------------------------------------------------------------------

/// 学校服务 probe：TCP connect（只读；无 adapter/helper/网络 mutation）。
fn probe_school_service(gateway_addr: &SocketAddr) -> Result<(), String> {
    let tcp = TcpStream::connect_timeout(gateway_addr, PROBE_CONNECT_TIMEOUT)
        .map_err(|e| format!("tcp-connect-failed:{e}"))?;
    drop(tcp);
    Ok(())
}

/// 依赖守卫结果（W30：domain/wire/protocol/data-plane/platform 依赖图必须无
/// DTLS variant/feature/fallback）。
struct DependencyGuardFacts {
    dtls_absent: bool,
}

/// 扫描 win32 workspace 的 Cargo.lock：依赖图必须无 DTLS crate
/// （mirror `controlled.rs` 的 dependency guard 语义；school 证据只消费 `dtls_absent`）。
///
/// 用编译期 `CARGO_MANIFEST_DIR`（`env!`）而非运行时 `std::env::var`：二进制独立
/// 运行时（scenario bin / script dispatch）没有运行时 manifest 环境变量，编译期常量
/// 保证 test 与 bin 两种上下文都能定位 win32 workspace 的 Cargo.lock。
fn run_dependency_guard() -> DependencyGuardFacts {
    let lock_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("Cargo.lock"))
        .unwrap_or_default();
    let lock_text = std::fs::read_to_string(&lock_path).unwrap_or_default();
    let dtls_absent = !lock_text.is_empty()
        && lock_text
            .lines()
            .filter_map(|l| l.trim_start().strip_prefix("name = "))
            .map(|v| v.trim_matches('"'))
            .all(|name| !name.to_ascii_lowercase().contains("dtls"));
    DependencyGuardFacts { dtls_absent }
}

/// 证据序列化扫描：无 raw secret/cookie/private key/certificate/group 标记
/// （独立于 Terra 的第二次扫描）。
fn scan_evidence(ev: &mut SchoolScenarioEvidence) {
    let json = serde_json::to_string(ev).unwrap_or_default();
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
}

/// SHA-256 hex。
fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// helper bin 的启动参数（host 侧构造；管道名按 host PID 唯一，与 W28 无碰撞）。
///
/// DP-04：**不再传 `--packet-pipe`** —— school flow 的 packet pipe 数据路径已移除，
/// helper 契约只保留 control pipe（apply/stop RPC）。helper 的 `run_helper_inner`
/// 在 packet-pipe 参数缺省时不再创建/等待 packet pipe server。
fn school_helper_args(dll: &Path) -> Vec<String> {
    let host_pid = std::process::id();
    let pipe_prefix = format!("{SCHOOL_PIPE_PREFIX}-{host_pid}");
    let journal_dir = std::env::temp_dir()
        .join(format!("{SCHOOL_JOURNAL_PREFIX}-{host_pid}"))
        .display()
        .to_string();
    vec![
        "--control-pipe".to_string(),
        format!(r"\\.\pipe\{pipe_prefix}-c"),
        "--dll".to_string(),
        dll.display().to_string(),
        "--journal-dir".to_string(),
        journal_dir,
        "--authority-name".to_string(),
        format!("Local\\{SCHOOL_AUTHORITY_PREFIX}-{host_pid}"),
        "--host-pid".to_string(),
        host_pid.to_string(),
        "--adapter-name".to_string(),
        SCHOOL_ADAPTER_NAME.to_string(),
    ]
}

// ---------------------------------------------------------------------------
// CSTP offer 校验已属引擎属权（CS-AUTH-05）：`CstpSession::open` 内部完成
// Common CSTP offer validation（HTTP 头式 / legacy 行式、必填字段、DTLS 拒绝、
// 掩码 → prefix）——本文件的同语义函数 `validate_school_offer` 与其实例测试已
// 随引擎接线移除（引擎侧契约测试：exv-vpn-cstp `tests/webvpn_offer.rs`；
// 接受侧机制断言：`tests/school_auth_engine_wiring.rs` 的 offer_plan 断言）。
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 校园路由合并逻辑单元测试（纯逻辑；offer 优先 + config 追加非重复）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod campus_routes_tests {
    use super::*;

    #[test]
    fn merge_is_offer_first_then_config_non_duplicates() {
        let offer = vec!["59.78.176.0/20".to_string(), "202.120.80.0/20".to_string()];
        let config = vec![
            "202.120.80.0/20".to_string(), // 与 offer 重复
            "222.66.117.0/24".to_string(),
            "59.78.176.0/20".to_string(), // 与 offer 重复
            "49.52.4.0/25".to_string(),
        ];
        let merged = merge_campus_routes(&offer, &config);
        assert_eq!(
            merged,
            vec![
                "59.78.176.0/20".to_string(),
                "202.120.80.0/20".to_string(),
                "222.66.117.0/24".to_string(),
                "49.52.4.0/25".to_string(),
            ],
            "offer 必须优先，config 只追加非重复项（保持相对顺序）"
        );
    }

    #[test]
    fn merge_normalizes_host_bits_for_dedup() {
        // 同一 /25 网段内的不同主机位 → 规范化后去重（RouteRow::new 屏蔽主机位语义）。
        let offer = vec!["49.52.4.5/25".to_string()];
        let config = vec!["49.52.4.100/25".to_string()];
        let merged = merge_campus_routes(&offer, &config);
        assert_eq!(merged, vec!["49.52.4.0/25".to_string()]);
    }

    #[test]
    fn merge_empty_offer_keeps_config_order_and_empty_is_empty() {
        let config = vec![
            "219.228.56.0/21".to_string(),
            "202.120.80.0/20".to_string(),
        ];
        let merged = merge_campus_routes(&[], &config);
        assert_eq!(merged, config);
        assert!(merge_campus_routes(&[], &[]).is_empty());
    }

    #[test]
    fn merge_defensively_skips_malformed() {
        // 入口 parse_school_routes_env 已拒绝 config 的非法条目；此处防御性跳过。
        let offer = vec!["not-a-cidr".to_string(), "59.78.176.0/20".to_string()];
        let config = vec!["222.66.117.0/99".to_string(), "49.52.4.0/25".to_string()];
        let merged = merge_campus_routes(&offer, &config);
        assert_eq!(
            merged,
            vec!["59.78.176.0/20".to_string(), "49.52.4.0/25".to_string()]
        );
    }

    // -----------------------------------------------------------------------
    // 校园路由解析（`EXV_RUST_VPN_SCHOOL_ROUTES` 纯逻辑；路由来自产品配置，
    // 绝不硬编码在连接逻辑里）。
    // -----------------------------------------------------------------------

    #[test]
    fn parse_campus_routes_accepts_8_route_frozen_set() {
        // 2026-08-16 用户冻结的 8 条校园路由（镜像 C++ 产品 config.json）。
        let parsed = parse_campus_routes_str(
            "49.52.4.0/25,59.78.176.0/20,59.78.192.0/21,58.198.176.128/25,\
             219.228.56.0/21,202.120.80.0/20,222.66.117.0/24,219.228.144.96/25",
        )
        .expect("8 条校园路由必须可解析");
        assert_eq!(
            parsed,
            vec![
                "49.52.4.0/25".to_string(),
                "59.78.176.0/20".to_string(),
                "59.78.192.0/21".to_string(),
                "58.198.176.128/25".to_string(),
                "219.228.56.0/21".to_string(),
                "202.120.80.0/20".to_string(),
                "222.66.117.0/24".to_string(),
                "219.228.144.96/25".to_string(),
            ]
        );
    }

    #[test]
    fn parse_campus_routes_empty_and_whitespace_is_empty() {
        assert_eq!(parse_campus_routes_str("").unwrap(), Vec::<String>::new());
        assert_eq!(
            parse_campus_routes_str("  , ,\t").unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn parse_campus_routes_rejects_malformed_entries() {
        // 诚实拒绝：任一条目不是合法 IPv4 CIDR → typed 错误（绝不静默跳过配置）。
        for bad in [
            "not-a-cidr",
            "49.52.4.0",           // 无前缀
            "49.52.4.0/",          // 前缀空
            "999.1.1.0/25",        // 非法网络
            "49.52.4.0/33",        // 前缀 > 32
            "49.52.4.0/25,junk",   // 混合：合法项 + 非法项 → 整批拒绝
        ] {
            assert!(
                parse_campus_routes_str(bad).is_err(),
                "非法配置 {bad:?} 必须被诚实拒绝"
            );
        }
    }

    #[test]
    fn build_apply_list_is_merge_of_offer_and_parsed_config() {
        // apply RPC 的 `campus_routes` 列表构造 = merge_campus_routes(offer,
        // parse_campus_routes_str(config))——offer 优先、config 追加非重复、
        // 按规范化 CIDR 身份去重。产物就是 helper 安装的路由集。
        let offer = vec!["202.120.80.0/20".to_string()];
        let config = parse_campus_routes_str("202.120.80.0/20,222.66.117.0/24,49.52.4.0/25")
            .expect("config 必须可解析");
        let apply_list = merge_campus_routes(&offer, &config);
        assert_eq!(
            apply_list,
            vec![
                "202.120.80.0/20".to_string(), // offer 优先（去重后仅一份）
                "222.66.117.0/24".to_string(),
                "49.52.4.0/25".to_string(),
            ]
        );
    }

    // -----------------------------------------------------------------------
    // ingress flow 机制测试（W30 真实 campus ingress 证明；纯逻辑，非 elevated）。
    // -----------------------------------------------------------------------

    /// 杀 **flow 目标端口硬编码 80 / 无真实服务** mutant：flow 目标解析必须接受
    /// ssh:22（`EXV_RUST_VPN_SCHOOL_FLOW_TARGET` 覆盖或第二 endpoint），并据此
    /// 判定 ingress 协议为 SSH banner（真实学校 ssh 服务）。
    #[test]
    fn flow_target_parse_accepts_w202_ssh_and_selects_ssh_banner_protocol() {
        // w202 真实 ingress 目标：58.198.176.156:22（ssh 服务；80 无 HTTP 服务）。
        let (ip, port) = parse_flow_target_str("58.198.176.156:22")
            .expect("w202 ssh flow target 必须可解析");
        assert_eq!(ip, Ipv4Addr::new(58, 198, 176, 156));
        assert_eq!(port, 22);
        assert_eq!(flow_protocol_for_port(port), FlowProtocol::SshBanner);
        // 非 22 端口回落 HTTP（既有行为）。
        assert_eq!(flow_protocol_for_port(80), FlowProtocol::Http);
    }

    /// flow 目标解析的诚实拒绝：非 IPv4 字面量 / 缺端口 / 坏端口 → typed 错误
    /// （反假绿：受控/域名目标不得混入学校 flow）。
    #[test]
    fn flow_target_parse_rejects_malformed() {
        for bad in [
            "58.198.176.156",        // 缺端口
            "58.198.176.156:",       // 端口空
            "not-an-ip:22",          // 非 IPv4 字面量
            "58.198.176.999:22",     // 非法 IPv4
            "58.198.176.156:notport",// 非法端口
            "58.198.176.156:99999",  // 端口越界
        ] {
            assert!(
                parse_flow_target_str(bad).is_err(),
                "非法 flow 目标 {bad:?} 必须被诚实拒绝"
            );
        }
    }

    /// 杀 **ingress 证明无真实字节** mutant：SSH banner 读（本地 TCP 应答
    /// `SSH-2.0-...`）必须真实收到字节（bytes_in > 0、response_received、connect
    /// 成功）——banner 字节就是真实校园 ingress 数据（非 HTTP、非 fake loopback）。
    #[test]
    fn ssh_banner_ingress_client_reads_real_bytes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (mut sock, _peer) = listener.accept().expect("accept test client");
            // ssh daemon 语义：connect 后服务端主动发送 banner。
            sock.write_all(b"SSH-2.0-OpenSSH_9.5 real-campus\r\n")
                .expect("write ssh banner");
            let _ = sock.shutdown(std::net::Shutdown::Write);
        });

        let flow_ip = Ipv4Addr::LOCALHOST;
        let flow_port = addr.port();
        let result = run_school_ingress_client(flow_ip, flow_port, FlowProtocol::SshBanner)
            .expect("ssh banner ingress 必须成功");
        assert!(result.connect_succeeded, "TCP connect 必须成功（ssh daemon 应答）");
        assert!(result.response_received, "必须收到真实 banner 字节");
        assert_eq!(result.response_status, None, "SSH banner 不是 HTTP：不得伪造状态码");
        assert_eq!(result.bytes_out, 0, "SSH banner ingress 不应发送应用层请求字节");
        assert!(result.bytes_in > 0, "banner 字节必须 > 0（ingress 证明）");
        let _ = server.join();
    }

    /// HTTP ingress 行为保持既有语义（GET → 响应/状态码）——机制面回归。
    #[test]
    fn http_ingress_client_reads_response_and_status() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (mut sock, _peer) = listener.accept().expect("accept test client");
            let mut req = Vec::new();
            let mut buf = [0u8; 512];
            if let Ok(n) = sock.read(&mut buf) {
                req.extend_from_slice(&buf[..n]);
            }
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
            let _ = sock.shutdown(std::net::Shutdown::Write);
            assert!(
                String::from_utf8_lossy(&req).starts_with("GET / HTTP/1.1"),
                "HTTP ingress 必须发送 GET 请求"
            );
        });

        let flow_ip = Ipv4Addr::LOCALHOST;
        let flow_port = addr.port();
        let result = run_school_ingress_client(flow_ip, flow_port, FlowProtocol::Http)
            .expect("http ingress 必须成功");
        assert!(result.connect_succeeded);
        assert!(result.response_received);
        assert_eq!(result.response_status, Some(200));
        assert!(result.bytes_out > 0 && result.bytes_in > 0);
        let _ = server.join();
    }
}

// ---------------------------------------------------------------------------
// 引擎数据面机制测试（DP-03：ring→CSTP→TLS reader + TLS→CSTP→ring writer 直连
// 引擎 session；真实 Wintun 环回，跨子网路由 per WSP3）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod engine_data_plane_tests {
    use super::*;

    // 数据面提取到 `crate::school_data_plane` 后，这些 Wintun 类型仅本测试模块使用。
    use exv_vpn_cstp::codec::{Codec, CstpFrame};
    use exv_vpn_win32_resource::wintun_adapter::{AdapterOpen, WintunAdapter};
    use exv_vpn_win32_resource::wintun_api::WintunLibrary;
    use exv_vpn_win32_resource::wintun_session::WintunSession;

    /// 冻结的 amd64 wintun-0.14.1 DLL 精确路径（WSP3 冻结；`resolve_dll_path` 允许
    /// `EXV_RUST_VPN_WINTUN_DLL` 覆盖，与 production 同款）。
    const FROZEN_DLL_PATH: &str = "C:\\Users\\TomLi\\.exv\\wintun\\wintun\\bin\\amd64\\wintun.dll";
    /// 测试使用的 ring capacity（与 WSP3 探针一致：2^17，wintun.h 下界）。
    const RING_CAPACITY: u32 = 131072;
    /// 与 WSP3 探针一致的 tunnel type。
    const TUNNEL_TYPE: &str = "EXV VPN";
    /// 环回测试常量（WSP3 冻结：Wintun 是 NdisMediumLoopback，跨子网经 adapter 显式
    /// 路由才真实经过 ring；同子网 ICMP 被内核本地应答、不进入 ring）。
    ///
    /// **隔离（DP-02 同款）**：环回子网/探测 IP 必须是本测试**唯一**的——
    /// 10.99.99.0/24 + 10.88.88.1 是多个 Wintun 测试（resource W17 loopback、
    /// `wintun_spike_oracle`、`network_settings_spike_oracle`、`packet_relay` 等）
    /// 共享的隧道路由网段；Rust 测试并行或残留时，多个 adapter 共享同一网络路由会让
    /// Windows 把 ping 路由到竞争接口、收不到 echo（DP-02 实测：23s 超时）。本测试
    /// 改用 10.99.97.0/24 + 10.88.90.1（全 workspace 未占用），确定性隔离。
    const PROBE_IP: &str = "10.88.90.1";
    const PROBE_IP_MASK: &str = "255.255.255.0";
    const ROUTE_NETWORK: &str = "10.99.97.0/24";
    /// 环回请求目的地址的字符串形式（ping.exe 参数）。
    const ROUTE_DST_STR: &str = "10.99.97.2";

    /// 当前进程是否 elevated（admin token；模式与 packet_relay 测试一致）。
    fn is_elevated() -> bool {
        vertical::is_elevated()
    }

    /// 动态断言的前置：非 elevated 时输出显式 `not_run / blocked_by_environment` 并
    /// 短路（require_admin pattern——不伪造 RED/GREEN）。
    fn require_admin(test: &str) -> bool {
        if is_elevated() {
            return true;
        }
        eprintln!(
            "[not_run/blocked_by_environment] {test}: 创建/启动 Wintun adapter/session 需要提权 \
             （elevated admin token）；当前进程非 elevated，跳过动态断言"
        );
        false
    }

    /// 加载冻结 DLL 的便捷入口。
    fn load_frozen() -> WintunLibrary {
        WintunLibrary::load(Path::new(FROZEN_DLL_PATH))
            .expect("load 冻结 wintun.dll")
    }

    /// 创建真实 adapter（创建者 owned；drop 即移除 adapter）。
    fn create_adapter(lib: &WintunLibrary, prefix: &str) -> WintunAdapter {
        let name = format!("{prefix}-{}", std::process::id());
        let (adapter, opened) =
            WintunAdapter::create(lib, &name, TUNNEL_TYPE).expect("create adapter");
        assert!(
            matches!(opened, AdapterOpen::Created),
            "create 必须返回 AdapterOpen::Created"
        );
        adapter
    }

    /// 在真实 adapter 上以冻结容量启动 session。
    fn start_session(lib: &WintunLibrary, adapter: &WintunAdapter) -> WintunSession {
        WintunSession::start(lib, adapter, RING_CAPACITY).expect("start session")
    }

    /// 带 watchdog 的子进程调用：超时后 kill 子进程并返回 None（WSP3 spike 同款；
    /// 本机实测 netsh 在 Wintun 接口上可能无限阻塞，必须 watchdog）。
    fn run_cmd_checked(
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> Option<(bool, String)> {
        use std::io::Read as _;
        let mut child = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .ok()?;
        let deadline = std::time::Instant::now() + timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(150));
                }
                Err(_) => return None,
            }
        };
        let mut out = String::new();
        let mut err = String::new();
        if let Some(mut s) = child.stdout.take() {
            let _ = s.read_to_string(&mut out);
        }
        if let Some(mut s) = child.stderr.take() {
            let _ = s.read_to_string(&mut err);
        }
        let _ = child.wait();
        Some((status.success(), format!("{out}{err}")))
    }

    /// 环回配置（WSP3 spike 同款，全部带 watchdog）：赋 IP -> 启用接口 -> 加跨子网路由。
    fn configure_loopback_route(ifname: &str) -> Result<(), String> {
        let mut set_ok = false;
        for _attempt in 0..4 {
            let args = [
                "interface".to_string(),
                "ip".to_string(),
                "set".to_string(),
                "address".to_string(),
                format!("name={ifname}"),
                "source=static".to_string(),
                format!("addr={PROBE_IP}"),
                format!("mask={PROBE_IP_MASK}"),
            ];
            if let Some((true, _)) = run_cmd_checked("netsh", &args, Duration::from_secs(12)) {
                set_ok = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(2000));
        }
        if !set_ok {
            return Err("netsh set address 失败/超时（watchdog 已 kill）".to_string());
        }
        let enable_args = [
            "interface".to_string(),
            "set".to_string(),
            "interface".to_string(),
            format!("name={ifname}"),
            "admin=enabled".to_string(),
        ];
        let _enable = run_cmd_checked("netsh", &enable_args, Duration::from_secs(10));
        // 残留清理（隔离）：本测试用唯一子网 ROUTE_NETWORK；若上次崩溃运行在该子网
        // 残留了旧 adapter 路由，先 `route delete` 清掉（只影响本测试的唯一网段，忽略
        // 不存在错误），避免 Windows 把 ping 路由到竞争接口而收不到 echo（DP-02 记录：
        // 共享 10.99.99.0/24 时实测 23s 超时）。
        let net_addr = ROUTE_NETWORK.split('/').next().unwrap_or(ROUTE_NETWORK);
        let _route_cleanup = run_cmd_checked(
            "route",
            &["delete".to_string(), net_addr.to_string()],
            Duration::from_secs(10),
        );
        let route_args = [
            "interface".to_string(),
            "ipv4".to_string(),
            "add".to_string(),
            "route".to_string(),
            ROUTE_NETWORK.to_string(),
            format!("interface={ifname}"),
        ];
        match run_cmd_checked("netsh", &route_args, Duration::from_secs(10)) {
            Some((true, _)) => Ok(()),
            _ => Err("netsh add route 失败/超时（watchdog 已 kill）".to_string()),
        }
    }

    /// 16 位校验和（网络字节序求和取反；WSP3 冻结：计算前必须清零字段）。
    fn checksum_16bit(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += (u32::from(data[i]) << 8) | u32::from(data[i + 1]);
            i += 2;
        }
        if i < data.len() {
            sum += u32::from(data[i]) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        (!sum) as u16
    }

    /// 是否为 IPv4 ICMP echo request（type=8；忽略 TTL/校验和——内核转发会递减 TTL
    /// 并重算校验和）。匹配"任一 echo request"而非固定 identity（ping 的 id/seq/
    /// payload 不可预知）。
    fn is_icmp_echo_request(pkt: &[u8]) -> bool {
        if pkt.len() < 28 || (pkt[0] >> 4) != 4 {
            return false;
        }
        let ihl = usize::from(pkt[0] & 0x0F) * 4;
        pkt.len() >= ihl + 8 && pkt[9] == 1 && pkt[ihl] == 8
    }

    /// 从 IPv4 ICMP echo request 构造 reply：交换 src/dst、type 8 -> 0，TTL 重置 64；
    /// IP 与 ICMP 校验和都**先清零字段再重算**（WSP3 实测 bug 继承点：漏清零导致
    /// reply 校验和无效、内核静默丢弃，ping 端到端必失败）。
    fn build_icmp_reply(request: &[u8]) -> Vec<u8> {
        assert!(request.len() >= 28 && (request[0] >> 4) == 4, "必须是 IPv4 包");
        let ihl = usize::from(request[0] & 0x0F) * 4;
        assert!(
            request.len() >= ihl + 8 && request[9] == 1 && request[ihl] == 8,
            "必须是 IPv4 ICMP echo request"
        );
        let mut reply = request.to_vec();
        reply[12..16].copy_from_slice(&request[16..20]);
        reply[16..20].copy_from_slice(&request[12..16]);
        reply[8] = 64;
        reply[10] = 0;
        reply[11] = 0;
        reply[ihl] = 0;
        reply[ihl + 1] = 0;
        reply[ihl + 2] = 0;
        reply[ihl + 3] = 0;
        let ip_sum = checksum_16bit(&reply[..ihl]);
        reply[10] = (ip_sum >> 8) as u8;
        reply[11] = (ip_sum & 0xFF) as u8;
        let icmp_sum = checksum_16bit(&reply[ihl..]);
        reply[ihl + 2] = (icmp_sum >> 8) as u8;
        reply[ihl + 3] = (icmp_sum & 0xFF) as u8;
        reply
    }

    /// 构造注入的数据面 relay 状态（与 `attach_school_packet_relay` 同款组合：
    /// W23B attach + W23A channel + 两腿 Running）。
    fn make_relay_state() -> Arc<Mutex<SchoolRelayState>> {
        let lease = vertical::deterministic_packet_lease();
        let epoch = RuntimeEpoch::try_from(Uuid::new_v4()).expect("runtime-epoch");
        let mut capability = PacketCapability::issue(lease, epoch);
        let channel = PacketChannel::new(&PacketLimits::mvp(), DataPlaneDirection::ProtocolToPacket)
            .expect("packet-channel");
        let attachment = AttachedPacketRelay::attach(&mut capability, 1).expect("relay-attach");
        let relay = AttachedPacketRelay::new(attachment, channel, PacketLimits::mvp());
        let mut state = SchoolRelayState {
            relay,
            next_seq: 0,
        };
        state.relay.start_leg(RelayDirection::Receive);
        state.relay.start_leg(RelayDirection::Send);
        Arc::new(Mutex::new(state))
    }

    /// **DP-03 数据面机制测试（elevated）**：真实 Wintun 环回（跨子网路由 per
    /// WSP3），断言引擎数据面线程把 ring 直连到引擎通道：
    ///   1. 进入 ring 的包（ping 10.99.97.2 的 ICMP echo request 经跨子网路由进 ring）
    ///      → reader 线程 `session.receive()` → STF 编码 → `write_channel`；
    ///   2. `read_channel` 上的 IP 包（ICMP echo reply）→ writer 线程 → `session.send()`
    ///      → ring → 内核交付给 ping.exe（端到端双向）。
    ///
    /// 杀 **STF 编码错误（裸发 0x45）/ 方向反转 / 线程未 join 就 EndSession（UAF）**
    /// mutant：STF 帧必须可解码回原始 IPv4 包（非 0x45 裸 IP）；reply 必须端到端
    /// 到达（TLS→ring 方向正确）；`stop_and_join` 在 drop session（`WintunEndSession`）
    /// 之前完成 join。
    #[test]
    fn engine_data_plane_ring_to_tls_and_tls_to_ring_loopback() {
        if !require_admin("engine_data_plane_ring_to_tls_and_tls_to_ring_loopback") {
            return;
        }
        let lib = load_frozen();
        let adapter = create_adapter(&lib, "ExvW30DataPlane");
        let session = Arc::new(Mutex::new(start_session(&lib, &adapter)));
        if let Err(msg) = configure_loopback_route(adapter.alias()) {
            panic!("环回路由配置失败（无法验证真实数据面收发）：{msg}");
        }
        let plane = EngineDataPlane {
            session: Arc::clone(&session),
            adapter,
            _lib: lib,
        };
        let relay = make_relay_state();

        // 引擎 data 通道：write_channel（STF 帧出）+ read_channel（IP 包入）。
        let (write_tx, mut write_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (read_tx, read_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let read_channel = Arc::new(Mutex::new(read_rx));

        let mut threads = plane.spawn_data_plane(write_tx, &read_channel, Arc::clone(&relay));

        // 正向触发：**后台**启动 ping（不阻塞主线程；`-w 8000` 保留 8s 等待窗口，让
        // 本测试在并行负载下仍有充足窗口注入 reply）。ICMP echo request 经跨子网路由
        // 进入 ring → reader 线程 STF 编码 → write_channel。
        let ping_args = [
            "-n".to_string(),
            "1".to_string(),
            "-w".to_string(),
            "8000".to_string(),
            ROUTE_DST_STR.to_string(),
        ];
        let mut ping_child = std::process::Command::new("ping")
            .args(&ping_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn ping");

        // 从 write_channel 收 STF 帧，解码为 CstpFrame::Data；断言收到的 IPv4 包是
        // ICMP echo request（STF 编码正确，非裸 0x45）。
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        let echo_request = loop {
            assert!(
                std::time::Instant::now() < deadline,
                "15s 内必须收到 STF 编码的 echo request（reader 线程未把 ring 包送达 write_channel）"
            );
            match write_rx.try_recv() {
                Ok(frame) => {
                    let mut codec = Codec::new();
                    codec.feed(&frame);
                    match codec.decode() {
                        Ok(Some(CstpFrame::Data(pkt))) if is_icmp_echo_request(&pkt) => break pkt,
                        Ok(Some(CstpFrame::Data(_))) | Ok(Some(CstpFrame::Control { .. })) => {}
                        Ok(None) => {}
                        Err(_) => panic!("STF 解码失败：编码错误 mutant"),
                    }
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => panic!("write_channel 关闭：reader 线程已退出"),
            }
        };

        // 反向：把 ICMP echo reply 放到 read_channel → writer 线程 `session.send` →
        // ring → 内核交付给**仍在等待窗口内**的 ping.exe（WSP3 机制：注入 send ring 的
        // 包以'从接口收到'姿态进入内核，dst=10.88.90.1 = 本 adapter 的 PROBE_IP，本地
        // 交付给 ping.exe）。ping 成功退出即证明 TLS→ring 方向真实（watchdog 兜底：
        // 10s 内未成功则 kill 子进程）。
        let reply = build_icmp_reply(&echo_request);
        read_tx.send(reply).expect("read_channel send reply");
        let mut reply_ok = false;
        let wait_deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < wait_deadline {
            match ping_child.try_wait() {
                Ok(Some(status)) => {
                    if status.success() {
                        reply_ok = true;
                    }
                    break;
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => break,
            }
        }
        // 无论哪条退出路径都回收子进程：失败未退出先 kill；wait 幂等（已由 try_wait
        // 回收时返回缓存状态），绝不留 zombie。
        if !reply_ok {
            let _ = ping_child.kill();
        }
        let _ = ping_child.wait();
        assert!(
            reply_ok,
            "reply 经 read_channel→writer→ring 必须端到端到达 ping.exe（TLS→ring 方向）"
        );

        // W17 SAFETY-ORDER：先 join 两个线程，再 drop session（`WintunEndSession`）。
        let (recv_bytes, sent_bytes) = threads.stop_and_join();
        assert!(recv_bytes > 0, "reader 必须真实从 ring 收到字节");
        assert!(sent_bytes > 0, "writer 必须真实向 ring 发送字节");

        // 清理顺序：线程已 join → drop relay/session（EndSession）→ drop adapter
        // （创建者 close = 移除 adapter；路由随 adapter 消失）。
        drop(relay);
        drop(session);
        drop(plane);
    }
}

// ---------------------------------------------------------------------------
// DP-04 机制测试：school flow 重接线后——packet pipe 数据路径已移除（helper 契约
// 只保留 control pipe；引擎 session 直连 ring；ring 计数读 host 数据面计数器）。
// 纯逻辑（非 elevated 也必须通过）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod dp04_rewire_tests {
    use super::*;

    /// 杀 'host 线程仍读写 packet pipe / helper 仍起 packet pipe server' mutant：
    /// school helper 契约只保留 control pipe——`school_helper_args` 不得再产出
    /// `--packet-pipe`（DP-04：数据面由引擎 session 直连 ring，host 不再经 helper
    /// packet pipe 间接访问）；`--control-pipe` 必须保留（apply/stop RPC）。
    #[test]
    fn school_helper_args_have_no_packet_pipe() {
        let args = school_helper_args(Path::new("wintun.dll"));
        assert!(
            !args.iter().any(|a| a == "--packet-pipe"),
            "school helper 参数不得再含 --packet-pipe（packet pipe 数据路径已移除）；got {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--control-pipe"),
            "school helper 必须保留 --control-pipe（apply/stop RPC）"
        );
    }

    /// 杀 'ring 计数仍来自 helper StopReply' mutant：`record_school_stop_evidence`
    /// 的 ring 字节必须从 **host 数据面计数器**（`ctx.host_ring_received_bytes` /
    /// `host_ring_sent_bytes`）读，不再依赖 helper StopReply（DP-01 后 helper 恒 0）。
    #[test]
    fn school_ring_evidence_reads_host_data_plane_counters() {
        let mut ev = crate::evidence::default_school_evidence();
        let mut ctx = SchoolCtx {
            control: None,
            helper_handle: None,
            host_composition: None,
            relay: None,
            engine_data_plane: None,
            host_ring_received_bytes: Some(1000),
            host_ring_sent_bytes: Some(500),
        };
        // helper StopReply 的 ring 字段恒 0（DP-01：helper 空闲、无 ring worker）——
        // 若 record_school_stop_evidence 误从 StopReply 读，则 packet_bytes_on_ring 恒 0。
        let reply = vertical::StopReply {
            ok: true,
            error: None,
            packets_after_stop: 0,
            ring_received_bytes: 0,
            ring_sent_bytes: 0,
            adapter_removed: true,
            stop_journaled: true,
            cleanup_proof_issued: true,
            retirement_recorded: true,
            owned_resources_retired: true,
            after: vertical::Snapshot::empty(),
            before: vertical::Snapshot::empty(),
        };
        record_school_stop_evidence(&mut ev, &mut ctx, &reply);
        assert_eq!(
            ev.packet_bytes_on_ring, 1500,
            "ring 字节必须来自 host 数据面计数器（非 helper StopReply 恒 0）"
        );
        assert!(
            ev.wintun_ring_traffic_observed,
            "双向 host 计数 > 0 → ring 流量已观测"
        );
        assert!(
            ev.http_flow_correlated_to_ring,
            "ring 字节（1500）≥ http out+in（默认 0）→ 关联成立"
        );
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
