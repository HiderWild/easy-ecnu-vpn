// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W28 受控纵切的证据记录（W28-I）。
//!
//! [`ControlledVerticalEvidence`] 是 `tests/controlled_vertical.rs`（Terra 冻结 seam）
//! 消费的完整证据：计划 §9 W28 的强制字段全部以**类型化字段**记录——OS/build/hardware、
//! host/helper PID 与 token elevation、pipe peer 谓词、TLS chain/hostname outcome、
//! CSTP offer digest、Wintun DLL/adapter/LUID/index、address/MTU/route/DNS
//! before-applied-after、authenticated packet attach、真实 IPv4 HTTP flow、
//! Stop journal/inventory/proof/retirement、no-DTLS/source/dependency guard。
//!
//! **保密契约**：任何字段绝不携带 raw secret/cookie/private key/certificate——TLS/CSTP
//! 只记录 digest 与 outcome（`tls_peer_fingerprint` / `cstp_offer_digest` 均为 SHA-256
//! hex）；`no_raw_secret_in_evidence` 由纵切对最终序列化做独立扫描后置真。

use serde::Serialize;

/// 环境有效标记的取值（测试冻结常量：`environment_state == "completed"` 是完整纵切唯一值）。
pub const ENV_STATE_COMPLETED: &str = "completed";
/// 环境无效标记前缀（后随精确 predicate）。
pub const ENV_INVALID_PREFIX: &str = "WIN_ACCEPTANCE_ENV_INVALID:";
/// 环境无效的另一合法标记。
pub const NOT_RUN_BLOCKED_PREFIX: &str = "not_run/blocked_by_environment";
/// 学校服务不可用的诚实 blocked 标记前缀（W30：只描述学校环境不可用，
/// 不否定 W28/W29；后随精确 predicate）。
pub const SCHOOL_SERVICE_UNAVAILABLE_PREFIX: &str =
    "not_run/blocked_by_environment:school_service_unavailable";
/// 引擎 WebVPN login 成功的 `login_status` 取值（CS-AUTH-05 契约：
/// `is_dynamic_complete` 的 login obligation——完整动态事实必须以 login 成功为
/// 前提；school.rs 成功路径与失败路径都按此契约记录）。
pub const LOGIN_STATUS_OK: &str = "webvpn-login-ok";

/// hold 模式路由来源三方记录（serde 序列化为
/// `{"offer": [...], "config": [...], "merged": [...]}`）。
#[derive(Clone, Debug, Serialize)]
pub struct RouteSource {
    /// offer（`X-CSTP-Split-Include`）路由——真实 offer 的隧道路由（本 W30 网关
    /// 不发送 Split-Include，实测为空）。
    pub offer: Vec<String>,
    /// 配置路由（`EXV_RUST_VPN_SCHOOL_ROUTES`；镜像 C++ 产品 config.json 的
    /// `default_routes`——路由来自产品配置，绝不硬编码在连接逻辑里）。
    pub config: Vec<String>,
    /// 去重合并结果（offer 优先，config 追加非重复；按规范化 CIDR 身份去重）。
    pub merged: Vec<String>,
}

/// W28 受控纵切的完整证据记录（serde 可序列化为 JSON evidence）。
///
/// 全部字段由 `scenarios::controlled::run_controlled_vertical` 以真实观测填写；
/// 非 elevated / 动态事实不完整时只填静态事实并标记 `environment_state`，绝不伪造
/// 动态值（require_admin pattern）。
#[derive(Clone, Debug, Serialize)]
pub struct ControlledVerticalEvidence {
    // ---- 环境状态 ----
    /// `completed` 或 `WIN_ACCEPTANCE_ENV_INVALID:<predicate>` /
    /// `not_run/blocked_by_environment:<predicate>`。
    pub environment_state: String,
    /// 纵切的 elevation 拓扑是否成立（ordinary host + elevated helper 均已真实观测）。
    pub env_elevated: bool,
    // ---- 宿主与 OS/build/hardware ----
    /// `std::env::consts::OS + ARCH`（如 "windows x86_64"）。
    pub host_os: String,
    /// Windows build（注册表 `CurrentBuildNumber` / `DisplayVersion`）。
    pub os_build: String,
    /// 硬件描述（`PROCESSOR_ARCHITECTURE` 等环境事实）。
    pub hardware: String,
    /// 主机名（`COMPUTERNAME`）。
    pub hostname: String,
    // ---- host/helper 进程与 token elevation ----
    /// host 进程 PID（纵切运行所在进程）。
    pub host_pid: Option<u32>,
    /// helper 进程 PID（独立进程）。
    pub helper_pid: Option<u32>,
    /// host 进程 token 是否 elevated（真实 `TokenElevation` 观测）。
    pub host_token_elevated: bool,
    /// helper 进程 token 是否 elevated（真实 `TokenElevation` 观测）。
    pub helper_token_elevated: bool,
    // ---- pipe peer 谓词 ----
    /// control pipe 双向身份验证通过。
    pub control_pipe_peer_verified: bool,
    /// packet pipe 双向身份验证通过。
    pub packet_pipe_peer_verified: bool,
    /// control/data 是两条独立 physical connection。
    pub control_data_separate_connections: bool,
    /// 逐项记录的 peer 谓词（人类可读）。
    pub pipe_peer_predicates: Vec<String>,
    // ---- TLS/CSTP ----
    /// TLS 证书链验证通过（严格 verifier，非 always-true）。
    pub tls_chain_verified: bool,
    /// TLS hostname（SNI）与证书一致。
    pub tls_hostname_verified: bool,
    /// 错误 host 的证书被拒绝（kills TLS verifier always-true mutant）。
    pub tls_wrong_host_rejected: bool,
    /// TLS 对端证书指纹（SHA-256 hex，64 字符；非 raw 证书）。
    pub tls_peer_fingerprint: Option<String>,
    /// CSTP offer 的 SHA-256 digest（64 字符 hex）。
    pub cstp_offer_digest: Option<String>,
    /// offer 是 CSTP-only（无 DTLS offer / DTLS token）。
    pub cstp_offer_only: bool,
    /// tunnel plan 通过 Common CSTP offer validation（之后才进入平台端口）。
    pub tunnel_plan_validated: bool,
    /// plan 冻结 IPv4 地址（10.88.88.1）。
    pub tunnel_plan_ipv4_address: Option<String>,
    /// plan 冻结 MTU（1420）。
    pub tunnel_plan_mtu: Option<u32>,
    /// plan DNS 服务器（含 10.88.88.53）。
    pub tunnel_plan_dns_servers: Vec<String>,
    /// plan 隧道路由（含 10.99.99.0/24）。
    pub tunnel_plan_routes: Vec<String>,
    // ---- Wintun DLL/adapter/LUID/index ----
    /// Wintun DLL SHA-256（冻结值精确匹配）。
    pub wintun_dll_sha256: Option<String>,
    /// Wintun DLL 带 Authenticode 签名（PE security directory 观测）。
    pub wintun_dll_signature_present: bool,
    /// adapter 名。
    pub wintun_adapter_name: Option<String>,
    /// adapter LUID。
    pub wintun_adapter_luid: Option<u64>,
    /// adapter ifIndex。
    pub wintun_adapter_ifindex: Option<u32>,
    /// Wintun session 已启动。
    pub wintun_session_started: bool,
    // ---- platform-ready ----
    /// platform-ready 等待了 Wintun 就绪。
    pub ready_waited_for_wintun: bool,
    /// platform-ready 等待了 network inventory 就绪。
    pub ready_waited_for_network_inventory: bool,
    /// platform-ready 只在完整 inventory 之后签发。
    pub ready_after_inventory: bool,
    /// canonical inventory 项（adapter/session/address/mtu/bypass/routes/dns/packet/running）。
    pub inventory_items: Vec<String>,
    // ---- applied 四族 ----
    /// 应用后的地址（如 "10.88.88.1/24"）。
    pub address_applied: Option<String>,
    /// 应用后的 MTU（= plan MTU）。
    pub mtu_applied: Option<u32>,
    /// 应用后的路由（CIDR 列表）。
    pub routes_applied: Vec<String>,
    /// 应用后的 DNS 服务器。
    pub dns_applied: Vec<String>,
    // ---- 真实 IPv4 HTTP flow ----
    /// HTTP 请求真实发出。
    pub http_flow_request_sent: bool,
    /// HTTP 响应真实收到。
    pub http_flow_response_received: bool,
    /// HTTP 响应状态码。
    pub http_flow_response_status: Option<u16>,
    /// HTTP 请求字节（out）。
    pub http_flow_bytes_out: u64,
    /// HTTP 响应字节（in）。
    pub http_flow_bytes_in: u64,
    /// flow 目标 IPv4（跨子网 10.99.99.2）。
    pub flow_target_ipv4: Option<String>,
    /// 跨子网环回设计已记录。
    pub packet_cross_subnet_design: bool,
    /// packet 真实经过 Wintun ring（kills fake loopback mutant）。
    pub wintun_ring_traffic_observed: bool,
    /// HTTP flow 与 ring 流量关联（双向真实经过 ring）。
    pub http_flow_correlated_to_ring: bool,
    /// packet attach 发生在认证之后。
    pub packet_attach_authenticated: bool,
    /// attach 原子且单次消费。
    pub packet_attach_atomic_single_use: bool,
    /// ring 上双向字节数（≥ HTTP out+in）。
    pub packet_bytes_on_ring: u64,
    // ---- Connected 语义 ----
    /// Connected 等待两个 packet 方向全部就绪。
    pub connected_after_both_directions_ready: bool,
    /// Connected 出现在 authenticated packet attach 之后（kills relay-spawn-即-Connected）。
    pub connected_after_attach: bool,
    /// 不得出现乐观 Connected。
    pub optimistic_connected: bool,
    /// phase journal 中 attach 排在 Connected 之前。
    pub journal_contains_attach_before_connected: bool,
    /// Connected 同时持有五类 proof（protocol session / platform ownership /
    /// packet lease / platform-ready proof / data-running proof）。
    pub connected_holds_five_proofs: bool,
    // ---- Stop 证据链 ----
    /// Stop 先 journal（durable）。
    pub stop_journaled: bool,
    /// Stop 时 inventory 完整。
    pub inventory_complete: bool,
    /// 已签发 CleanProof（完整 inventory + 无 running effect + 无 attached packet child + 无未退休 obligation）。
    pub cleanup_proof_issued: bool,
    /// retirement 已记录。
    pub retirement_recorded: bool,
    /// owned 资源全部退休。
    pub owned_resources_retired: bool,
    /// adapter 已被移除（无残留）。
    pub wintun_adapter_removed_after_stop: bool,
    /// helper 进程在 Stop 后退出。
    pub helper_exited_after_stop: bool,
    /// Stop 之后收到的 packet 数（kills Stop-后-packet-继续 mutant）。
    pub packets_after_stop: u64,
    // ---- before-applied-after ----
    /// 应用前地址。
    pub address_before: Option<String>,
    /// 清理后地址（compare-and-restore 回 before）。
    pub address_after: Option<String>,
    /// 应用前 MTU。
    pub mtu_before: Option<u32>,
    /// 清理后 MTU。
    pub mtu_after: Option<u32>,
    /// 应用前路由。
    pub routes_before: Vec<String>,
    /// 清理后路由。
    pub routes_after: Vec<String>,
    /// 应用前 DNS。
    pub dns_before: Vec<String>,
    /// 清理后 DNS。
    pub dns_after: Vec<String>,
    /// 清理后网络状态整体等于 before。
    pub network_state_after_equals_before: bool,
    // ---- no-DTLS / source / dependency guard ----
    /// 依赖图无 DTLS variant/feature/fallback。
    pub dtls_absent: bool,
    /// 无 DTLS token 偷渡进 CSTP 路径/证据。
    pub dtls_token_smuggling_absent: bool,
    /// Rust 纵切不 linkage 旧 C++ runtime 源码。
    pub old_cpp_sources_absent: bool,
    /// 依赖守卫干净（无 OpenSSL / 第三方 Wintun wrapper / dtls crate）。
    pub dependency_guard_clean: bool,
    /// 依赖守卫逐项结果。
    pub dependency_guard_notes: Vec<String>,
    /// 证据不含 raw secret/cookie/private key（序列化扫描后置真）。
    pub no_raw_secret_in_evidence: bool,
    /// 纵切 phase journal（attach 与 connected 的顺序由测试跨此字段检查）。
    pub phase_journal: Vec<String>,
}

impl ControlledVerticalEvidence {
    /// 动态（需完整 elevation 拓扑）事实是否已完整观测。
    ///
    /// 完整纵切 = helper 提权观测 + Wintun 全链 + 网络四族 applied + HTTP flow +
    /// Stop 全链；缺任一 obligation 不得 ready（inventory 缺项 / not_run 不得完成）。
    #[must_use]
    pub fn is_dynamic_complete(&self) -> bool {
        if !self.env_elevated {
            return false;
        }
        self.wintun_session_started
            && self.wintun_adapter_name.is_some()
            && self.wintun_adapter_luid.is_some()
            && self.wintun_adapter_ifindex.is_some()
            && self.address_applied.is_some()
            && self.mtu_applied.is_some()
            && !self.routes_applied.is_empty()
            && !self.dns_applied.is_empty()
            && self.http_flow_response_received
            && self.wintun_ring_traffic_observed
            && self.stop_journaled
            && self.cleanup_proof_issued
            && self.helper_exited_after_stop
            && self.inventory_items.len() >= 9
    }
}

// ---------------------------------------------------------------------------
// W30 学校 VPN 真实 flow 的证据记录（`scenarios/school.rs` 消费；W30-I）。
// ---------------------------------------------------------------------------

/// W30 学校 VPN 真实 flow 的完整证据记录（serde 可序列化为 JSON evidence）。
///
/// 由 `scenarios::school::run_school_scenario` 以真实观测填写。计划 §9 W30 的
/// 核心反假绿：**学校 flow 拒绝用受控 fake 替代 real origin/certificate/auth/
/// tunnel/IPv4 target**（受控纵切 W28 的测试服务器 / 测试 CA / 测试凭据 / 冻结
/// tunnel plan 10.88.88.1 / 10.99.99.0/24 / 受控 HTTP 目标 10.99.99.2 都不得
/// 混入学校 flow）。
///
/// **静态 policy 事实与动态观测之分**：`fake_*_rejected`、`origin_is_real_school_gateway`、
/// `tunnel_plan_from_real_offer` 与 `secret_*` 六项是 production **policy 事实**——
/// 代码内不存在接受 fake origin/certificate/auth/tunnel/IPv4 target 的路径、secret
/// 的唯一入口是受认证 controller/TTY one-shot vault（argv/env/log/evidence 零泄漏、
/// 发送后与 Stop 时 `zeroize`）。它们在非 elevated / `not_run` 状态下同样为真
/// （"拒绝成功"= 未接受任何 fake），Terra 测试无条件断言。其余字段（TLS outcome、
/// 学号/密码认证事实、plan、Wintun、HTTP flow、Stop 链、before-applied-after）是
/// **动态观测**，只在完整学校 flow 后置真；`not_run` 时全部保持默认假值（不伪造）。
///
/// **保密契约**：任何字段不携带 raw secret/cookie/private key/certificate/group——
/// TLS 只记录对端 SHA-256 指纹；认证事实只记录学号/密码实际使用
/// （`auth_username_password_actual`；group digest 已封存不产生）、
/// `no_raw_secret_in_evidence` 由纵切对最终序列化做独立扫描后置真。
#[derive(Clone, Debug, Serialize)]
pub struct SchoolScenarioEvidence {
    // ---- 环境状态 ----
    /// `completed` 或 `WIN_ACCEPTANCE_ENV_INVALID:<predicate>` /
    /// `not_run/blocked_by_environment:<predicate>`；学校服务不可用时必须是
    /// `not_run/blocked_by_environment:school_service_unavailable:<predicate>`。
    pub environment_state: String,
    /// 学校宿主进程是否 elevated（学校拓扑 = elevated host + elevated helper）。
    pub env_elevated: bool,
    /// 学校服务（gateway TCP probe）是否真实可达。
    pub school_service_available: bool,
    /// 学校服务不可用 / 未探测时的精确 predicate（为什么不可用）。
    pub school_service_probe_predicate: Option<String>,
    // ---- 宿主与 OS/build/hardware ----
    /// `std::env::consts::OS + ARCH`（如 `windows x86_64`）。
    pub host_os: String,
    /// Windows build（注册表 `CurrentBuildNumber` / `DisplayVersion`）。
    pub os_build: String,
    /// 硬件描述。
    pub hardware: String,
    /// 主机名（`COMPUTERNAME`）。
    pub hostname: String,
    /// host 进程 PID。
    pub host_pid: Option<u32>,
    /// host 进程 token 是否 elevated（真实 `TokenElevation` 观测）。
    pub host_token_elevated: bool,
    /// helper 进程 PID（提权 helper；学校拓扑 = elevated host + elevated helper）。
    pub helper_pid: Option<u32>,
    /// helper 进程 token 是否 elevated（真实 `TokenElevation` 观测）。
    pub helper_token_elevated: bool,
    // ---- 反假绿 policy 事实（production 强制；Terra 无条件断言） ----
    /// 受控/测试 origin（loopback/testserver/controlled 等）被拒绝（kills
    /// fake-origin mutant）。
    pub fake_origin_rejected: bool,
    /// 测试 CA / 跳过验证 / always-true verifier 被拒绝（TLS 验证必须对真实学校
    /// chain；kills fake-certificate mutant）。
    pub fake_certificate_rejected: bool,
    /// 测试/占位凭据与未认证输入被拒绝（secret 只来自受认证 controller/TTY；
    /// kills fake-auth mutant）。
    pub fake_auth_rejected: bool,
    /// 受控/冻结 tunnel plan（W28 的 10.88.88.1 / 10.99.99.0/24）被拒绝（plan 只能
    /// 来自真实学校 CSTP offer；kills fake-tunnel mutant）。
    pub fake_tunnel_rejected: bool,
    /// 受控 HTTP 目标（10.99.99.2）被拒绝（目标必须是真实学校目标；kills
    /// fake-ipv4-target mutant）。
    pub fake_ipv4_target_rejected: bool,
    /// origin 是真实学校 gateway（配置事实，不得替换为受控测试服务器）。
    pub origin_is_real_school_gateway: bool,
    /// tunnel plan 必须源自真实学校 CSTP offer（Common validation 之后），不得替换
    /// 受控 plan。
    pub tunnel_plan_from_real_offer: bool,
    // ---- 学校 origin / 目标（配置事实；endpoint host:port 不是 secret） ----
    /// 真实连接的 origin（学校 gateway host）。
    pub origin_reported: Option<String>,
    /// flow 目标 IPv4（学校 intranet 目标；完成态必须可解析为 IPv4）。
    pub flow_target_ipv4: Option<String>,
    // ---- 可信网关解析 / 直连（VGDC：`vpn-gateway-direct-connect-guarantee`） ----
    /// 双线可信解析出的真实网关 IP（DoH → UDP/53 → system；fake-ip 过滤后；不得是
    /// fake `198.18.1.15`）。
    pub gateway_real_ip: Option<String>,
    /// 实际使用的解析来源（`"doh"` / `"udp53"` / `"system"`；Mihomo 宿主完成态必须
    /// 是 `"doh"`）。
    pub resolution_source: Option<String>,
    /// 逐层 typed 解析错误（`doh:223.5.5.5:tls-failed:...` / `udp53:1.1.1.1:timeout`；
    /// 全部线路失败时非空）。
    pub resolution_layer_errors: Vec<String>,
    /// `/32` 直连路由已就位（verify-or-add 后；连接前必须为真）。
    pub route_installed: bool,
    /// 已存在路由的网关/LUID 与物理网卡不一致（typed route conflict；不覆盖第三方）。
    pub route_conflict: bool,
    /// `/32` 路由在 Stop 后已移除（路由生命周期；移除成功或已 absent 均为真）。
    pub route_removed_after_stop: bool,
    /// 移除回读证明：`GetIpForwardTable2` 不再包含目标 `/32` 行。
    pub route_absent_after_stop: bool,
    /// 路由移除失败的 typed 描述（`code-5` 等；成功为 `None`）。
    pub route_removal_error: Option<String>,
    // ---- 真实 TLS identity ----
    /// 证书链验证通过（严格 webpki，非 always-true）。
    pub tls_chain_verified: bool,
    /// hostname/SNI 与证书一致。
    pub tls_hostname_verified: bool,
    /// 错误 host 的证书被拒绝（kills TLS verifier always-true mutant）。
    pub tls_wrong_host_rejected: bool,
    /// 验证对真实学校 chain（production trust policy；不得替换测试 CA）。
    pub tls_verified_against_real_school_chain: bool,
    /// TLS 步骤失败时的精确分类（`BootstrapError` 变体名：`ConnectFailed` /
    /// `HandshakeFailed` / `UntrustedChain` / `HostnameMismatch` 等；成功或无 TLS
    /// 步骤时为 `None`）。诚实区分"端点不可达 / 握手失败"与"证书链验证失败"——
    /// 不得把连接层失败冒充为证书链验证失败（W30 假属性根因）。
    pub tls_failure_variant: Option<String>,
    /// TLS 对端证书指纹（SHA-256 hex，64 字符；非 raw 证书）。
    pub tls_peer_fingerprint: Option<String>,
    // ---- 学校 CSTP data 连接（真实 Cisco gateway 握手；错误透明） ----
    /// 学校 CSTP data 连接阶段失败细节（CS-AUTH-05 引擎重锚：`login:<LoginError:?>`
    /// （引擎 WebVPN login 失败，typed 变体名如 `login:LoginRejected` /
    /// `login:SamlRequired`——`login:` 前缀必须伴随 `login_status` 失败态）/
    /// `connect-tunnel:<SessionError:?>`（引擎 CONNECT/offer 阶段失败，如
    /// `connect-tunnel:EofBeforeTerminator` = gateway 未完成 offer 即关闭连接，
    /// 符合格式被拒 / `connect-tunnel:OfferParseFailed` = 收到非 CSTP 内容）；
    /// 成功为 `None`）。错误透明：下一次失败直接可见真实原因。
    pub school_data_connection_error: Option<String>,
    /// 引擎校验后的 `TunnelOffer` plan 的 SHA-256 digest（诊断用；CS-AUTH-05：
    /// offer 读取/校验已属引擎属权，引擎不暴露 raw offer 文本——digest 由引擎
    /// 校验后的 plan 序列化计算，raw offer 文本绝不进证据）。
    pub school_offer_digest: Option<String>,
    // ---- 真实认证（仅学号/密码；group/challenge 已封存 2026-08-15） ----
    /// 学号/密码必须是真实学校服务器实际遇到者（MVP 唯一凭据；不得用测试凭据
    /// 替代）；`not_run` 时不得伪造。
    pub auth_username_password_actual: bool,
    // 封存：group 选择非本 MVP 应用场景（2026-08-15 用户裁定：仅学号/密码）；
    // 如需重新接线须另立 cutover requirement 并重跑真实业务流。
    // 以下 group/challenge 证据字段 serialization 稳定保留，恒为 false/None；
    // 重新接线时恢复语义（challenge 实际遇到 + group SHA-256 digest）。
    /// 封存：group/challenge 证据字段恒为 `false`（school flow 不再携带/遇到
    /// group challenge；serialization 稳定保留）。
    pub auth_group_password_challenge_actual: bool,
    /// 封存：group 的 SHA-256 digest 恒为 `None`（group 不参与 MVP 认证；
    /// serialization 稳定保留）。
    pub auth_group_digest: Option<String>,
    // ---- secret 一次性输入（policy 事实；vault 强制执行） ----
    /// secret 只能来自受认证 controller/TTY one-shot 输入。
    pub secret_ingress_authenticated: bool,
    /// argv/env 不得携带 secret（scenario 必须拒绝从 argv/env 读 secret）。
    pub secret_never_from_argv_env: bool,
    /// secret 必须是一次性（one-shot）输入。
    pub secret_one_shot: bool,
    /// secret 发送后必须 zeroize（一次消费，不留缓冲）。
    pub secret_zeroized_after_send: bool,
    /// secret 不得出现在任何输出面（argv/env/log/evidence/stdout）。
    pub secret_absent_from_all_outputs: bool,
    // ---- CSTP-only tunnel ----
    /// domain/wire/protocol/data-plane/platform 依赖图无 DTLS variant/feature/fallback。
    pub dtls_absent: bool,
    /// tunnel 是 CSTP-only（无 DTLS offer / DTLS token 偷渡进 CSTP 路径）。
    pub cstp_only: bool,
    /// tunnel plan 经过 Common CSTP offer validation 后才进入平台端口。
    pub tunnel_plan_validated: bool,
    /// plan IPv4 地址（完成态必须可解析为 IPv4）。
    pub tunnel_plan_ipv4_address: Option<String>,
    /// plan 隧道路由（CIDR IPv4 列表）。
    pub tunnel_plan_routes: Vec<String>,
    // ---- Wintun ----
    /// Wintun DLL SHA-256（冻结值精确匹配）。
    pub wintun_dll_sha256: Option<String>,
    /// Wintun DLL 带 Authenticode 签名（PE security directory 观测）。
    pub wintun_dll_signature_present: bool,
    /// Wintun session 已启动。
    pub wintun_session_started: bool,
    /// adapter 名。
    pub wintun_adapter_name: Option<String>,
    /// adapter LUID。
    pub wintun_adapter_luid: Option<u64>,
    /// adapter ifIndex。
    pub wintun_adapter_ifindex: Option<u32>,
    /// canonical inventory 项（adapter/session/address/mtu/bypass/routes/dns/packet/running）。
    pub inventory_items: Vec<String>,
    /// inventory 完整（== W22 `COMPLETE_INVENTORY` 9 项）。
    pub inventory_complete: bool,
    // ---- 学校目标 IPv4 flow（真实经过 Wintun ring + CSTP） ----
    /// HTTP 请求真实发出。
    pub http_flow_request_sent: bool,
    /// HTTP 响应真实收到。
    pub http_flow_response_received: bool,
    /// HTTP 响应状态码（学校目标状态不可冻结为受控 200）。
    pub http_flow_response_status: Option<u16>,
    /// HTTP 请求字节（out）。
    pub http_flow_bytes_out: u64,
    /// HTTP 响应字节（in）。
    pub http_flow_bytes_in: u64,
    /// 跨子网设计已记录（学校目标与 tunnel 子网不同网段，内核不做本地应答）。
    pub packet_cross_subnet_design: bool,
    /// packet 真实经过 Wintun ring（fake loopback 不可能观测到学校目标 flow）。
    pub wintun_ring_traffic_observed: bool,
    /// HTTP flow 与 ring 流量关联（双向真实经过 ring）。
    pub http_flow_correlated_to_ring: bool,
    /// packet attach 发生在认证之后。
    pub packet_attach_authenticated: bool,
    /// ring 上双向字节数（≥ HTTP out+in）。
    pub packet_bytes_on_ring: u64,
    /// 不得出现乐观 Connected。
    pub optimistic_connected: bool,
    // ---- 正常 Stop + scoped owned-resource cleanup ----
    /// Stop 先 journal（durable）。
    pub stop_journaled: bool,
    /// 已签发 CleanProof（完整 inventory + 无 running effect + 无 attached packet
    /// child + 无未退休 obligation）。
    pub cleanup_proof_issued: bool,
    /// retirement 已记录。
    pub retirement_recorded: bool,
    /// owned 资源全部退休。
    pub owned_resources_retired: bool,
    /// adapter 已被移除（无残留）。
    pub wintun_adapter_removed_after_stop: bool,
    /// helper 进程在 Stop 后退出。
    pub helper_exited_after_stop: bool,
    /// Stop 之后收到的 packet 数（kills Stop-后-packet-继续 mutant）。
    pub packets_after_stop: u64,
    /// 应用前地址。
    pub address_before: Option<String>,
    /// 应用后地址。
    pub address_applied: Option<String>,
    /// 应用后 MTU。
    pub mtu_applied: Option<u32>,
    /// 应用后路由（CIDR 列表）。
    pub routes_applied: Vec<String>,
    /// 应用后 DNS 服务器。
    pub dns_applied: Vec<String>,
    /// 清理后地址（compare-and-restore 回 before）。
    pub address_after: Option<String>,
    /// 应用前 MTU。
    pub mtu_before: Option<u32>,
    /// 清理后 MTU。
    pub mtu_after: Option<u32>,
    /// 应用前路由。
    pub routes_before: Vec<String>,
    /// 清理后路由。
    pub routes_after: Vec<String>,
    /// 应用前 DNS。
    pub dns_before: Vec<String>,
    /// 清理后 DNS。
    pub dns_after: Vec<String>,
    /// 清理后网络状态整体等于 before。
    pub network_state_after_equals_before: bool,
    /// 证据不含 raw secret/cookie/private key/certificate/group（序列化扫描后置真）。
    pub no_raw_secret_in_evidence: bool,
    /// 纵切 phase journal（attach 在 Connected 之前等顺序事实）。
    pub phase_journal: Vec<String>,
    // ---- 引擎 WebVPN login 证据（CS-AUTH-05 加性追加；序列化稳定） ----
    /// 引擎 `WebvpnLogin::perform_login` 阶段的状态：`"webvpn-login-ok"` = login
    /// 成功（webvpn cookie 已捕获）；`"login-failed:<LoginError:?>"` = login 失败
    /// （typed 变体名，如 `login-failed:LoginRejected`）；网关 `a0` 结果码在场时
    /// 写 `"login-rejected:a0=<code>"`（`a0=15` 凭据错 vs `a0=8`/`114`/`115`/`16`
    /// 请求形态问题）；`"login-blocked:saml-required"` = SAML 要求（诚实 blocked）；
    /// 未尝试（not_run 早退路径）为 `None`。
    /// `is_dynamic_complete` 的 login obligation：完整动态事实必须以
    /// `Some("webvpn-login-ok")` 为前提（kills login 失败仍 completed mutant）。
    pub login_status: Option<String>,
    /// 引擎 login 是否检测到 SAML 重定向（`LoginError::SamlRequired`）：MVP 不
    /// 支持 SAML，如实标记 `not_run/blocked_by_environment:school-saml-required`，
    /// 绝不冒充 login 成功/失败；SAML 要求时绝不为 `false`（kills SAML 时
    /// saml_required=false mutant）。
    pub saml_required: bool,
    /// 引擎 login 是否捕获到 `webvpn` cookie（CSTP CONNECT 阶段的会话凭据）。
    /// `true` 必须伴随 `login_status == Some("webvpn-login-ok")`；cookie **值**绝不
    /// 进证据（`scan_evidence` 的 `"Cookie:"` 守卫覆盖）。
    pub cookie_present: bool,
    // ---- persistent-tunnel hold 模式（--hold；config-driven campus routes） ----
    /// hold 模式（`--hold`）：Connected/plan-applied 后打印 `TUNNEL_READY`、应用
    /// 合并校园路由、保持隧道存活直到 stop 条件（stop-file 或 stdin EOF），然后移除
    /// 应用的路由并走正常 Stop 路径；非 hold 模式恒为 false。
    pub held_mode: bool,
    /// hold 模式的路由来源三方证据（offer 优先 + config 追加非重复 + merged 去重
    /// 结果）；非 hold 模式为 None。
    pub route_source: Option<RouteSource>,
    /// 合并后的校园路由已全部应用到 Wintun 接口（空集合 = 无路由可应用，恒真）。
    pub campus_routes_applied: bool,
    /// 应用的路由在 Stop 前已全部移除（`routes::remove` 原语；AlreadyAbsent 幂等）。
    pub campus_routes_removed: bool,
    /// 校园路由应用/移除失败的 typed 描述（`install:<...>` / `remove:<...>`；
    /// 成功为 None）。
    pub campus_routes_error: Option<String>,
    /// hold 数据面 ring 实际收/发字节（包进 ring 且经 CSTP 转发/回写的实锤）。
    pub held_ring_recv_bytes: Option<u64>,
    /// hold 数据面 ring 实际收/发字节。
    pub held_ring_sent_bytes: Option<u64>,
    // ---- 校园路由系统路由表验证 + 特权门禁（W30 config-driven campus routes） ----
    /// 校园路由写入发生在**提权 helper**（经 apply RPC `CreateIpForwardEntry2`，
    /// 非 host 侧直接写路由表）——特权操作归属 helper 的确认（helper 特权 /
    /// host 非特权架构）。Wintun adapter 创建与路由表写入都是特权操作，都在 helper。
    pub route_writes_in_helper: bool,
    /// 合并校园路由在隧道路由期间（apply 后、Stop 前）全部真实存在于系统路由表
    /// （`GetIpForwardTable2` 回读 Wintun 接口；非仅证据记录——路由真实、可路由）。
    pub campus_routes_live_in_system_table: bool,
    /// 存活期间系统路由表中真实命中的校园路由 CIDR（合并集；规范化网络地址）。
    pub campus_routes_live: Vec<String>,
    // ---- W30 ingress-flow protocol + route lifetime snapshot (2026-08-16) ----
    /// ingress flow 的真实协议：`"ssh-banner"` = TCP connect + 读 SSH banner（真实
    /// 学校 ssh 服务；banner 字节就是真实校园 ingress 数据，**不是 HTTP**）；`"http"` =
    /// HTTP GET/响应；未运行（not_run）为 None。诚实记录：SSH banner 是 ingress 证明。
    pub flow_protocol: Option<String>,
    /// TCP connect 到 flow 目标是否成功（ssh daemon 应答；`flow_target_port` 为 22）。
    pub flow_connect_succeeded: bool,
    /// ingress flow 失败的真实错误（`connect:<...>` / `read banner:<...>` /
    /// `read:<...>`；成功或未执行为 None）。把被 `http-flow-failed` 吞掉的内层
    /// 错误透传出来——DP-05 诊断：`packet_bytes_on_ring:0` + `flow_error` 一起
    /// 才能区分"SYN 进 ring 无回包"与"connect 直接失败/未入 ring"。
    pub flow_error: Option<String>,
    /// 隧道路由期间系统 IPv4 路由表快照（`route print -4` 语义；全部接口，非仅隧道）。
    /// 校园路由在存活期间的实锤证据（与 `campus_routes_live_in_system_table` 互补）。
    pub routes_during_tunnel: Vec<String>,
}

impl SchoolScenarioEvidence {
    /// 动态（需完整 elevation + 学校服务 + 完整 flow）事实是否已完整观测。
    ///
    /// 完整学校 flow = elevated host + 学校服务可达 + TLS 真实验证 + 真实认证 +
    /// Wintun 全链 + 网络四族 applied + HTTP flow 双向 + Stop 全链 + helper 退出；
    /// 缺任一 obligation 不得 completed（`not_run` 不得完成）。
    #[must_use]
    pub fn is_dynamic_complete(&self) -> bool {
        if !self.env_elevated || !self.school_service_available {
            return false;
        }
        self.tls_chain_verified
            && self.auth_username_password_actual
            && self.wintun_session_started
            && self.wintun_adapter_name.is_some()
            && self.wintun_adapter_luid.is_some()
            && self.wintun_adapter_ifindex.is_some()
            && self.address_applied.is_some()
            && self.mtu_applied.is_some()
            && !self.routes_applied.is_empty()
            && !self.dns_applied.is_empty()
            && self.http_flow_response_received
            && self.wintun_ring_traffic_observed
            && self.stop_journaled
            && self.cleanup_proof_issued
            && self.helper_exited_after_stop
            && self.inventory_complete
            // VGDC：可信解析 + `/32` 路由生命周期（连接前就位、Stop 后移除）也是
            // 完整学校 flow 的 obligation。
            && self.gateway_real_ip.is_some()
            && self.route_installed
            && self.route_removed_after_stop
            && self.route_absent_after_stop
            // CS-AUTH-05：login obligation——完整动态事实必须以引擎 login 成功为
            // 前提（kills login 失败仍 completed mutant）。
            && self.login_status.as_deref() == Some(LOGIN_STATUS_OK)
    }
}

/// 全默认（未观测）的学校 flow 证据骨架。`run_school_scenario` 以此为基逐步填入
/// 观测值；任何阶段失败兜底时用它保证 JSON 可写。
///
/// 反假绿 policy 事实在默认骨架即置真（production 强制：代码内不存在接受
/// fake origin/certificate/auth/tunnel/IPv4 target 的路径、secret 的唯一入口是
/// 受认证 one-shot vault）——Terra 无条件断言它们，且 `not_run` 时"拒绝成功"
/// （未接受任何 fake）同样成立。
#[must_use]
pub fn default_school_evidence() -> SchoolScenarioEvidence {
    SchoolScenarioEvidence {
        environment_state: ENV_INVALID_PREFIX.to_string(),
        env_elevated: false,
        school_service_available: false,
        school_service_probe_predicate: None,
        host_os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        os_build: String::new(),
        hardware: String::new(),
        hostname: std::env::var("COMPUTERNAME").unwrap_or_default(),
        host_pid: Some(std::process::id()),
        host_token_elevated: false,
        helper_pid: None,
        helper_token_elevated: false,
        fake_origin_rejected: true,
        fake_certificate_rejected: true,
        fake_auth_rejected: true,
        fake_tunnel_rejected: true,
        fake_ipv4_target_rejected: true,
        origin_is_real_school_gateway: true,
        tunnel_plan_from_real_offer: true,
        origin_reported: None,
        flow_target_ipv4: None,
        gateway_real_ip: None,
        resolution_source: None,
        resolution_layer_errors: Vec::new(),
        route_installed: false,
        route_conflict: false,
        route_removed_after_stop: false,
        route_absent_after_stop: false,
        route_removal_error: None,
        tls_chain_verified: false,
        tls_hostname_verified: false,
        tls_wrong_host_rejected: false,
        tls_verified_against_real_school_chain: false,
        tls_failure_variant: None,
        tls_peer_fingerprint: None,
        school_data_connection_error: None,
        school_offer_digest: None,
        auth_username_password_actual: false,
        auth_group_password_challenge_actual: false, // 封存：恒 false
        auth_group_digest: None, // 封存：恒 None
        secret_ingress_authenticated: true,
        secret_never_from_argv_env: true,
        secret_one_shot: true,
        secret_zeroized_after_send: true,
        secret_absent_from_all_outputs: true,
        dtls_absent: false,
        cstp_only: false,
        tunnel_plan_validated: false,
        tunnel_plan_ipv4_address: None,
        tunnel_plan_routes: Vec::new(),
        wintun_dll_sha256: None,
        wintun_dll_signature_present: false,
        wintun_session_started: false,
        wintun_adapter_name: None,
        wintun_adapter_luid: None,
        wintun_adapter_ifindex: None,
        inventory_items: Vec::new(),
        inventory_complete: false,
        http_flow_request_sent: false,
        http_flow_response_received: false,
        http_flow_response_status: None,
        http_flow_bytes_out: 0,
        http_flow_bytes_in: 0,
        packet_cross_subnet_design: false,
        wintun_ring_traffic_observed: false,
        http_flow_correlated_to_ring: false,
        packet_attach_authenticated: false,
        packet_bytes_on_ring: 0,
        optimistic_connected: false,
        stop_journaled: false,
        cleanup_proof_issued: false,
        retirement_recorded: false,
        owned_resources_retired: false,
        wintun_adapter_removed_after_stop: false,
        helper_exited_after_stop: false,
        packets_after_stop: 0,
        address_before: None,
        address_applied: None,
        mtu_applied: None,
        routes_applied: Vec::new(),
        dns_applied: Vec::new(),
        address_after: None,
        mtu_before: None,
        mtu_after: None,
        routes_before: Vec::new(),
        routes_after: Vec::new(),
        dns_before: Vec::new(),
        dns_after: Vec::new(),
        network_state_after_equals_before: false,
        no_raw_secret_in_evidence: false,
        phase_journal: Vec::new(),
        login_status: None, // 未尝试（not_run）——绝不伪造 login 事实
        saml_required: false,
        cookie_present: false,
        held_mode: false,
        route_source: None,
        campus_routes_applied: false,
        campus_routes_removed: false,
        campus_routes_error: None,
        held_ring_recv_bytes: None,
        held_ring_sent_bytes: None,
        route_writes_in_helper: false,
        campus_routes_live_in_system_table: false,
        campus_routes_live: Vec::new(),
        flow_protocol: None,
        flow_connect_succeeded: false,
        flow_error: None,
        routes_during_tunnel: Vec::new(),
    }
}

/// 全默认（未观测）的证据骨架。`run_controlled_vertical` 以此为基逐步填入观测值；
/// 任何阶段失败兜底时用它保证 JSON 可写（与 WSP3/WSP4 probe 的 `default_facts` 同款模式）。
#[must_use]
pub fn default_evidence() -> ControlledVerticalEvidence {
    ControlledVerticalEvidence {
        environment_state: ENV_INVALID_PREFIX.to_string(),
        env_elevated: false,
        host_os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        os_build: String::new(),
        hardware: String::new(),
        hostname: std::env::var("COMPUTERNAME").unwrap_or_default(),
        host_pid: Some(std::process::id()),
        helper_pid: None,
        host_token_elevated: false,
        helper_token_elevated: false,
        control_pipe_peer_verified: false,
        packet_pipe_peer_verified: false,
        control_data_separate_connections: false,
        pipe_peer_predicates: Vec::new(),
        tls_chain_verified: false,
        tls_hostname_verified: false,
        tls_wrong_host_rejected: false,
        tls_peer_fingerprint: None,
        cstp_offer_digest: None,
        cstp_offer_only: false,
        tunnel_plan_validated: false,
        tunnel_plan_ipv4_address: None,
        tunnel_plan_mtu: None,
        tunnel_plan_dns_servers: Vec::new(),
        tunnel_plan_routes: Vec::new(),
        wintun_dll_sha256: None,
        wintun_dll_signature_present: false,
        wintun_adapter_name: None,
        wintun_adapter_luid: None,
        wintun_adapter_ifindex: None,
        wintun_session_started: false,
        ready_waited_for_wintun: false,
        ready_waited_for_network_inventory: false,
        ready_after_inventory: false,
        inventory_items: Vec::new(),
        address_applied: None,
        mtu_applied: None,
        routes_applied: Vec::new(),
        dns_applied: Vec::new(),
        http_flow_request_sent: false,
        http_flow_response_received: false,
        http_flow_response_status: None,
        http_flow_bytes_out: 0,
        http_flow_bytes_in: 0,
        flow_target_ipv4: None,
        packet_cross_subnet_design: false,
        wintun_ring_traffic_observed: false,
        http_flow_correlated_to_ring: false,
        packet_attach_authenticated: false,
        packet_attach_atomic_single_use: false,
        packet_bytes_on_ring: 0,
        connected_after_both_directions_ready: false,
        connected_after_attach: false,
        optimistic_connected: false,
        journal_contains_attach_before_connected: false,
        connected_holds_five_proofs: false,
        stop_journaled: false,
        inventory_complete: false,
        cleanup_proof_issued: false,
        retirement_recorded: false,
        owned_resources_retired: false,
        wintun_adapter_removed_after_stop: false,
        helper_exited_after_stop: false,
        packets_after_stop: 0,
        address_before: None,
        address_after: None,
        mtu_before: None,
        mtu_after: None,
        routes_before: Vec::new(),
        routes_after: Vec::new(),
        dns_before: Vec::new(),
        dns_after: Vec::new(),
        network_state_after_equals_before: false,
        dtls_absent: false,
        dtls_token_smuggling_absent: false,
        old_cpp_sources_absent: false,
        dependency_guard_clean: false,
        dependency_guard_notes: Vec::new(),
        no_raw_secret_in_evidence: false,
        phase_journal: Vec::new(),
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
