// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W30-T Terra oracle：学校 VPN 真实 flow（`school_scenario`）。
//!
//! 本测试在**真实 Windows 宿主**上运行纵切 seam `run_school_scenario`（production
//! `src/scenarios/school.rs`），并把纵切记录的 `SchoolScenarioEvidence`（production
//! `src/evidence.rs`）断言为契约。计划 §9 W30 的核心反假绿：**学校 scenario 必须
//! 拒绝用受控 fake 替代 real origin/certificate/auth/tunnel/IPv4 target**——
//! 受控纵切（W28，`controlled_vertical`）的测试服务器、测试 CA、测试凭据、冻结
//! tunnel plan（10.88.88.1 / 10.99.99.0/24）与受控 HTTP 目标（10.99.99.2）都不得
//! 混入学校 flow。若实现破坏任一冻结事实——**fake origin/certificate/auth/tunnel/
//! IPv4 target 被接受**、**secret 从 argv/env/log/evidence 泄漏**、**tunnel 不是
//! CSTP-only**、**学校目标 IPv4 流量未真实经过 Wintun ring**、**Stop 后 packet 继续**
//! 或 **owned 资源未 scoped 清理**——对应测试必然失败。
//!
//! **真实身份（spec `vpn-rust-native-runtime-mvp-common-architecture.md` §5.3）**：
//! TLS 必须对真实学校证书链 + hostname 验证；学号/密码必须是真实学校服务器实际
//! 遇到者（MVP 唯一凭据，2026-08-15 用户裁定：仅学号/密码；group/challenge 已
//! 封存——证据字段恒为 None/false，serialization 稳定保留）；tunnel plan 必须来自
//! 真实学校 CSTP offer（Common validation 之后），不得替换受控 plan；学校目标
//! IPv4 流量必须真实双向经过 Wintun ring + CSTP；正常 Stop + scoped
//! owned-resource cleanup（compare-and-restore 回 before）。
//!
//! **secret 一次性输入**：secret 只能从受认证 controller/TTY one-shot 输入
//! （计划 §9 W30），argv/env/log/evidence 均不得携带；经 `exv-vpn-cstp::auth`
//! 一次性 vault（P42-I，已提交）持有、发送后与 Stop 时 zeroize、Debug 脱敏。
//!
//! **权限感知（require_admin pattern）**：非 elevated 宿主上纯逻辑/政策测试
//! （anti-fake policy、secret-leak 断言与 redaction、CSTP-only/no-DTLS 静态守卫、
//! not_run 诚实性检查）必须通过；真实学校连通性测试 elevation-gated——非 elevated
//! 或动态事实不完整时，seam 必须短路（不建 adapter、不启 helper、不连接学校、不
//! mutate），只记录静态事实与 `WIN_ACCEPTANCE_ENV_INVALID:<predicate>` 或
//! `not_run/blocked_by_environment:<predicate>` 标记，**不得冒充 RED 或 GREEN**。
//! 学校服务不可用时必须**诚实检测**（`school_service_available=false` +
//! `school_service_probe_predicate`）并标记
//! `not_run/blocked_by_environment:school_service_unavailable:<predicate>`——该
//! blocked 只描述学校环境不可用，**不否定 W28/W29**。纵切自清理（adapter 移除、
//! address/MTU/route/DNS 回到 before、helper 退出），无残留。
//! GREEN 固定为 **8 passed; 0 failed; 0 ignored**。
//!
//! **PowerShell scenario anchor（W30-A / W30-Tb 消费契约）**：native scenario 以
//! elevated PowerShell 运行本测试二进制并消费其证据——
//! 1. `$env:EXV_RUST_VPN_EVIDENCE_DIR = <W30 evidence dir>`（可选
//!    `EXV_RUST_VPN_WINTUN_ZIP` / `EXV_RUST_VPN_WINTUN_DLL`）；学校 secret 经受
//!    认证 controller/TTY one-shot 输入（运行方交互提供，绝不走 argv/env/文件）；
//! 2. 运行 exact focused command：
//!    `cargo test --manifest-path src/platform/win32/rust/Cargo.toml --locked
//!    -p exv-vpn-win32-acceptance --test school_scenario -- --nocapture`；
//! 3. 二进制把完整 `SchoolScenarioEvidence` JSON 写入
//!    `<EvidenceDir>/school-scenario.json`，并在 stdout 打印一行
//!    `SCHOOL_SCENARIO_EVIDENCE:<compact-json>`；
//! 4. script grep 该行：`environment_state == "completed"` 且 JSON 可解析且 8/8 GREEN
//!    才是原生证据；环境无效只产生 `WIN_ACCEPTANCE_ENV_INVALID:<predicate>` 或
//!    `not_run/blocked_by_environment:<predicate>`（学校服务不可用时必须是
//!    `school_service_unavailable` 前缀，不否定 W28/W29）。
//!
//! **证据保密**：任何证据（内存 struct、JSON 文件、stdout）绝不包含 raw
//! secret/cookie/private key/certificate/group；TLS 只记录对端指纹、认证只记录
//! 学号/密码实际使用（`auth_username_password_actual`；group digest 已封存不产生）
//! 与 outcome（见 `secrets_enter_only_via_authenticated_*`
//! 与 `auth_vault_redacts_and_zeroizes_one_shot_secrets` 的序列化扫描与 redaction 检查）。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use exv_vpn_cstp::auth::{
    AuthChallengeKind, AuthClock, AuthError, AuthInteraction, AuthProgress, AuthResponse, Secret,
};
use exv_vpn_win32_acceptance::evidence::SchoolScenarioEvidence;
use exv_vpn_win32_acceptance::scenarios::school::run_school_scenario;
use exv_vpn_win32_acceptance::wintun_facts::WINTUN_DLL_SHA256;

// ---------------------------------------------------------------------------
// 冻结契约常量（测试拥有；production `evidence.rs`/`scenarios/school.rs`
// 必须满足，不可漂移）。
// ---------------------------------------------------------------------------

/// `environment_state` 取值契约（计划 §6.1）：完整学校 flow 唯一值。
const ENV_STATE_COMPLETED: &str = "completed";
/// 环境无效标记前缀（后随精确 predicate，如 `host_not_elevated`）。
const ENV_INVALID_PREFIX: &str = "WIN_ACCEPTANCE_ENV_INVALID:";
/// 环境无效的另一合法标记（如 `requires_admin`）。
const NOT_RUN_BLOCKED_PREFIX: &str = "not_run/blocked_by_environment";
/// 学校服务不可用的诚实 blocked 标记前缀（detect unavailability honestly, never fake）。
const NOT_RUN_SCHOOL_SERVICE_UNAVAILABLE: &str =
    "not_run/blocked_by_environment:school_service_unavailable";

/// 受控纵切（W28）的冻结值——学校 flow 必须拒绝的任何 fake 参照系。
/// fake-tunnel / fake-ipv4-target mutant 若把学校 flow 换到受控 plan/target，
/// 完成态断言（`!=`）必然失败。
const CONTROLLED_TUNNEL_IPV4: &str = "10.88.88.1";
const CONTROLLED_TUNNEL_ROUTE: &str = "10.99.99.0/24";
const CONTROLLED_HTTP_TARGET_IPV4: &str = "10.99.99.2";

/// 受控/本地 fake origin 标记（loopback/测试服务器名）。真实学校连接不得出现。
const FAKE_ORIGIN_MARKERS: [&str; 5] = ["127.0.0.1", "localhost", "::1", "testserver", "controlled"];

/// 证据 JSON 中禁止出现的 raw secret/cookie/private key/certificate/group 标记
/// （独立于 production 自报的序列化扫描）。
const FORBIDDEN_EVIDENCE_MARKERS: [&str; 7] = [
    "PRIVATE KEY",
    "BEGIN CERTIFICATE",
    "Cookie:",
    "Authorization:",
    "password=",
    "group=",
    "username=",
];

// ---------------------------------------------------------------------------
// 测试内注入的 paused monotonic clock（确定性；不 sleep，不依赖 wall clock）。
// ---------------------------------------------------------------------------

struct FakeClock {
    now: AtomicU64,
}

impl FakeClock {
    fn at(t: u64) -> Self {
        Self {
            now: AtomicU64::new(t),
        }
    }
}

impl AuthClock for FakeClock {
    fn now_millis(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// 学校 flow 只跑一次，各项断言共享同一份观测（确定性；同时是 PowerShell anchor
// 的证据发布点）。
// ---------------------------------------------------------------------------

fn school() -> &'static SchoolScenarioEvidence {
    static EVIDENCE: OnceLock<SchoolScenarioEvidence> = OnceLock::new();
    EVIDENCE.get_or_init(|| {
        let dll = exv_vpn_win32_acceptance::wintun_facts::resolve_dll_path(None);
        let ev = run_school_scenario(&dll);
        publish_evidence(&ev);
        ev
    })
}

/// 幂等发布证据给 native scenario：`EXV_RUST_VPN_EVIDENCE_DIR` 设置时写
/// `school-scenario.json`；无论设置与否都打印一行 `SCHOOL_SCENARIO_EVIDENCE:<json>`
/// （script grep 该行）。测试侧执行，不引入 production 依赖。
fn publish_evidence(ev: &SchoolScenarioEvidence) {
    let json = serde_json::to_string(ev)
        .unwrap_or_else(|e| format!("evidence-serialize-error:{e}"));
    if let Some(dir) = std::env::var_os("EXV_RUST_VPN_EVIDENCE_DIR") {
        let path = PathBuf::from(dir).join("school-scenario.json");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&path, &json).is_err() {
            eprintln!("WARNING: cannot write evidence file {}", path.display());
        }
    }
    println!("SCHOOL_SCENARIO_EVIDENCE:{json}");
}

/// elevation/学校服务/完整性门禁（require_admin pattern）：环境有效（elevated 且
/// 学校服务可达且动态事实完整）返回 `true` 并继续真实断言；否则验证环境无效标记
/// 的诚实性并返回 `false`（not_run，不伪造）。学校服务不可用必须标记
/// `not_run/blocked_by_environment:school_service_unavailable:<predicate>`——
/// 只描述学校环境不可用，不否定 W28/W29；not_run 时不得伪造任何动态事实。
fn school_env_complete_or_honest_not_run(ev: &SchoolScenarioEvidence) -> bool {
    if ev.env_elevated && ev.school_service_available && ev.is_dynamic_complete() {
        assert_eq!(
            ev.environment_state, ENV_STATE_COMPLETED,
            "完整学校 flow 必须标记 environment_state=completed"
        );
        true
    } else {
        assert!(
            ev.environment_state.starts_with(ENV_INVALID_PREFIX)
                || ev.environment_state.starts_with(NOT_RUN_BLOCKED_PREFIX),
            "环境无效必须产生 {ENV_INVALID_PREFIX}<predicate> 或 {NOT_RUN_BLOCKED_PREFIX}:<predicate>（不得冒充 RED/GREEN），got {:?}",
            ev.environment_state
        );
        if ev.env_elevated && !ev.school_service_available {
            // 学校服务不可用：必须诚实检测并标记（detect unavailability honestly,
            // never fake）；该 blocked 不否定 W28/W29。
            assert!(
                ev.environment_state.starts_with(NOT_RUN_SCHOOL_SERVICE_UNAVAILABLE),
                "学校服务不可用必须标记 {NOT_RUN_SCHOOL_SERVICE_UNAVAILABLE}:<predicate>，got {:?}",
                ev.environment_state
            );
            assert!(
                ev.school_service_probe_predicate.is_some(),
                "学校服务不可用时必须记录 probe predicate（为什么不可用）"
            );
        }
        // not_run 时不得伪造任何动态事实。
        assert!(
            !ev.auth_username_password_actual,
            "not_run 时不得伪造真实认证事实"
        );
        // 诚实 TLS 证据：若 TLS 步骤确实失败（记录了失败变体），不得同时声称链
        // 验证通过，且环境必须诚实标记 vertical-step-failed（不把连接层失败冒充
        // 为证书链验证失败）。
        if let Some(variant) = ev.tls_failure_variant.as_deref() {
            assert!(
                !ev.tls_chain_verified && !ev.tls_hostname_verified,
                "记录 TLS 失败变体 {variant:?} 时不得声称链/hostname 验证通过"
            );
            assert!(
                ev.environment_state.contains("vertical-step-failed"),
                "TLS 失败变体 {variant:?} 必须伴随 not_run/blocked_by_environment:vertical-step-failed 标记，got {:?}",
                ev.environment_state
            );
        }
        assert!(!ev.http_flow_request_sent, "not_run 时不得伪造流量观测");
        assert!(!ev.optimistic_connected, "not_run 时不得伪造乐观 Connected");
        assert_eq!(ev.packets_after_stop, 0, "not_run 时不得伪造 Stop 后流量");
        assert!(
            !ev.env_elevated || !ev.school_service_available || !ev.is_dynamic_complete(),
            "elevated 且学校服务可达且动态事实完整时 environment_state 必须是 completed"
        );
        false
    }
}

// ---------------------------------------------------------------------------
// 1. 反假绿：fake origin / certificate 必须被拒绝
// ---------------------------------------------------------------------------

/// 杀 **fake-origin / fake-certificate** mutant（纯逻辑，非 elevated 也必须通过）：
/// 学校 scenario 必须拒绝用受控 fake 替代 real origin/certificate——受控测试服务器、
/// 测试 CA 或 always-true verifier 均不得进入学校 flow；完成态下真实连接的 origin
/// 不得是任何受控/本地 fake 标记，证书验证必须对真实学校 chain。
#[test]
fn fake_origin_and_certificate_are_rejected() {
    let ev = school();
    assert!(
        ev.fake_origin_rejected,
        "fake-origin mutant：受控/测试 origin 替代真实学校 origin 必须被拒绝"
    );
    assert!(
        ev.fake_certificate_rejected,
        "fake-certificate mutant：测试 CA / 跳过验证 / always-true verifier 必须被拒绝"
    );
    assert!(
        ev.origin_is_real_school_gateway,
        "origin 必须是真实学校 gateway（配置事实，不得替换）"
    );
    if ev.env_elevated && ev.school_service_available && ev.is_dynamic_complete() {
        let origin = ev.origin_reported.as_deref().unwrap_or_default().to_ascii_lowercase();
        assert!(!origin.is_empty(), "完成态必须记录真实连接的 origin");
        for marker in FAKE_ORIGIN_MARKERS {
            assert!(
                !origin.contains(marker),
                "真实学校连接不得指向受控/本地 fake origin（got {origin:?}）"
            );
        }
        assert!(
            ev.tls_verified_against_real_school_chain,
            "证书链必须对真实学校 chain 验证（fake-certificate mutant）"
        );
    } else {
        assert!(
            ev.environment_state.starts_with(ENV_INVALID_PREFIX)
                || ev.environment_state.starts_with(NOT_RUN_BLOCKED_PREFIX),
            "环境无效必须诚实标记（不得冒充 RED/GREEN），got {:?}",
            ev.environment_state
        );
    }
}

// ---------------------------------------------------------------------------
// 2. 反假绿：fake auth / tunnel / IPv4 target 必须被拒绝
// ---------------------------------------------------------------------------

/// 杀 **fake-auth / fake-tunnel / fake-ipv4-target** mutant（纯逻辑，非 elevated 也
/// 必须通过）：学校 scenario 必须拒绝受控/测试凭据、受控/冻结 tunnel plan（W28 的
/// 10.88.88.1 / 10.99.99.0/24）与受控 HTTP 目标（10.99.99.2）；tunnel plan 必须
/// 来自真实学校 CSTP offer；完成态下 plan/target 不得等于任何受控值。
#[test]
fn fake_auth_tunnel_and_ipv4_target_are_rejected() {
    let ev = school();
    assert!(
        ev.fake_auth_rejected,
        "fake-auth mutant：测试/占位凭据与未认证输入必须被拒绝（secret 只来自受认证 controller/TTY）"
    );
    assert!(
        ev.fake_tunnel_rejected,
        "fake-tunnel mutant：受控/冻结 tunnel plan 必须被拒绝（plan 只能来自真实学校 CSTP offer）"
    );
    assert!(
        ev.fake_ipv4_target_rejected,
        "fake-ipv4-target mutant：受控 10.99.99.2 目标必须被拒绝（目标必须是真实学校目标）"
    );
    assert!(
        ev.tunnel_plan_from_real_offer,
        "tunnel plan 必须源自真实学校 CSTP offer（Common validation 之后），不得替换受控 plan"
    );
    if ev.env_elevated && ev.school_service_available && ev.is_dynamic_complete() {
        assert_ne!(
            ev.tunnel_plan_ipv4_address.as_deref(),
            Some(CONTROLLED_TUNNEL_IPV4),
            "plan 不得是受控 10.88.88.1（fake-tunnel mutant）"
        );
        assert!(
            !ev.tunnel_plan_routes
                .iter()
                .any(|r| r.as_str() == CONTROLLED_TUNNEL_ROUTE),
            "plan 不得包含受控路由 10.99.99.0/24（fake-tunnel mutant）"
        );
        assert_ne!(
            ev.flow_target_ipv4.as_deref(),
            Some(CONTROLLED_HTTP_TARGET_IPV4),
            "flow 目标不得是受控 10.99.99.2（fake-ipv4-target mutant）"
        );
        assert!(
            ev.auth_username_password_actual,
            "学号/密码必须是真实学校服务器实际遇到者（MVP 唯一凭据；不得替换测试凭据）"
        );
        // 封存：group 选择非本 MVP 应用场景（2026-08-15 用户裁定：仅学号/密码）；
        // 如需重新接线须另立 cutover requirement 并重跑真实业务流。
        assert!(
            !ev.auth_group_password_challenge_actual && ev.auth_group_digest.is_none(),
            "group/challenge 已封存：auth_group_password_challenge_actual 必须恒 false、auth_group_digest 必须恒 None"
        );
    } else {
        assert!(
            ev.environment_state.starts_with(ENV_INVALID_PREFIX)
                || ev.environment_state.starts_with(NOT_RUN_BLOCKED_PREFIX),
            "环境无效必须诚实标记（不得冒充 RED/GREEN），got {:?}",
            ev.environment_state
        );
        assert!(
            !ev.auth_username_password_actual,
            "not_run 时不得伪造真实认证事实"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. 真实 TLS identity
// ---------------------------------------------------------------------------

/// 真实 TLS identity：证书链验证 + hostname 验证 + 错误 host 拒绝都必须真实发生
/// （kills TLS verifier always-true / fake-certificate mutant）；只记录对端 SHA-256
/// 指纹 digest，绝不记录 raw 证书。
#[test]
fn real_tls_identity_is_verified() {
    let ev = school();
    if !school_env_complete_or_honest_not_run(ev) {
        return; // not_run / blocked_by_environment
    }
    assert!(
        ev.tls_chain_verified,
        "真实学校证书链必须验证通过（verifier 不得 always-true）"
    );
    assert!(
        ev.tls_hostname_verified,
        "真实学校 hostname/SNI 必须与证书一致"
    );
    assert!(
        ev.tls_wrong_host_rejected,
        "错误 host 的证书必须被拒绝（kills TLS verifier always-true mutant）"
    );
    assert!(
        ev.tls_verified_against_real_school_chain,
        "验证必须对真实学校 chain，不得替换测试 CA（fake-certificate mutant）"
    );
    assert!(
        ev.tls_failure_variant.is_none(),
        "完成态下 TLS 步骤必须成功：不得记录失败变体（got {:?}）",
        ev.tls_failure_variant
    );
    let fp = ev
        .tls_peer_fingerprint
        .as_deref()
        .expect("必须记录真实学校 TLS 对端指纹（digest，非 raw 证书）");
    assert_eq!(
        fp.len(),
        64,
        "对端指纹必须是 SHA-256 hex（64 字符）"
    );
    // VGDC（vpn-gateway-direct-connect-guarantee）：直连真实 IP + SNI 域名——
    // 双线可信解析必须记录真实 IP（非 fake）与解析来源（本宿主 = doh）。
    let real_ip = ev
        .gateway_real_ip
        .as_deref()
        .expect("完成态必须记录可信解析出的真实网关 IP");
    assert!(
        real_ip.parse::<std::net::Ipv4Addr>().is_ok(),
        "gateway_real_ip 必须是 IPv4，got {real_ip:?}"
    );
    assert_ne!(
        real_ip, "198.18.1.15",
        "解析结果不得是 Mihomo fake IP（fake-ip 必须被过滤）"
    );
    assert_eq!(
        ev.resolution_source.as_deref(),
        Some("doh"),
        "本宿主（Mihomo 运行中）可信解析来源必须是 doh（L1 默认线路）"
    );
    assert!(
        ev.resolution_layer_errors.is_empty(),
        "完成态下解析不得有逐层错误（got {:?}）",
        ev.resolution_layer_errors
    );
}

// ---------------------------------------------------------------------------
// 4. 真实学号/密码（实际遇到者；group/challenge 已封存）+ CSTP-only tunnel
// ---------------------------------------------------------------------------

/// 杀 **fake-auth / fake-tunnel / DTLS token 偷渡** mutant：学号/密码必须是真实
/// 学校服务器实际遇到者（MVP 唯一凭据；group/challenge 已封存 2026-08-15 用户
/// 裁定——证据字段恒为 None/false）；tunnel 必须是 CSTP-only（无 DTLS offer/token）、
/// plan 通过 Common validation 且来自真实 offer、纯 IPv4（无 IPv6/DTLS 字段）。
/// no-DTLS 依赖守卫是纯逻辑（非 elevated 也通过）。
#[test]
fn real_school_username_password_used_and_tunnel_is_cstp_only() {
    let ev = school();
    assert!(
        ev.dtls_absent,
        "domain/wire/protocol/data-plane/platform 依赖图必须无 DTLS variant/feature/fallback"
    );
    if !school_env_complete_or_honest_not_run(ev) {
        return; // not_run / blocked_by_environment
    }
    assert!(
        ev.auth_username_password_actual,
        "学号/密码必须是真实学校服务器实际遇到者（MVP 唯一凭据；不得用测试凭据替代）"
    );
    // 封存：group 选择非本 MVP 应用场景（2026-08-15 用户裁定：仅学号/密码）；
    // 如需重新接线须另立 cutover requirement 并重跑真实业务流。
    // group digest / challenge 证据字段 serialization 稳定保留，必须恒为 None/false。
    assert!(
        ev.auth_group_digest.is_none() && !ev.auth_group_password_challenge_actual,
        "group digest / challenge 已封存：必须恒为 None/false"
    );
    assert!(
        ev.cstp_only,
        "tunnel 必须是 CSTP-only（无 DTLS offer / DTLS token 偷渡进 CSTP 路径）"
    );
    assert!(
        ev.tunnel_plan_validated,
        "tunnel plan 必须经过 Common CSTP offer validation 后才进入平台端口"
    );
    assert!(
        ev.tunnel_plan_from_real_offer,
        "plan 必须来自真实学校 CSTP offer（fake-tunnel mutant）"
    );
    let addr = ev
        .tunnel_plan_ipv4_address
        .as_deref()
        .expect("plan 必须记录 IPv4 地址");
    assert!(
        addr.parse::<std::net::Ipv4Addr>().is_ok(),
        "plan 必须是纯 IPv4 地址（无 IPv6/DTLS 字段），got {addr:?}"
    );
    for route in &ev.tunnel_plan_routes {
        let (net, prefix) = route
            .split_once('/')
            .unwrap_or_else(|| panic!("plan route 必须是 CIDR IPv4: {route:?}"));
        assert!(
            net.parse::<std::net::Ipv4Addr>().is_ok(),
            "plan route 必须是 IPv4 网络: {route:?}"
        );
        let p: u8 = prefix
            .parse()
            .unwrap_or_else(|_| panic!("plan route prefix 必须可解析: {route:?}"));
        assert!(p <= 32, "IPv4 prefix 必须在 0..=32: {route:?}");
    }
}

// ---------------------------------------------------------------------------
// 5. secret 一次性输入：受认证 controller/TTY，argv/env/log/evidence 零泄漏
// ---------------------------------------------------------------------------

/// secret 只能从受认证 controller/TTY one-shot 输入（计划 §9 W30），argv/env/log/
/// evidence 均不得携带；发送后必须 zeroize。纯逻辑（非 elevated 也必须通过）：
/// 除 production 自报的扫描声明外，测试独立序列化扫描证据 JSON，任何 raw
/// secret/cookie/private key/certificate/group 标记不得出现。
#[test]
fn secrets_enter_only_via_authenticated_one_shot_input_and_never_leak() {
    let ev = school();
    assert!(
        ev.secret_ingress_authenticated,
        "secret 只能来自受认证 controller/TTY one-shot 输入"
    );
    assert!(
        ev.secret_never_from_argv_env,
        "argv/env 不得携带 secret（scenario 必须拒绝从 argv/env 读 secret）"
    );
    assert!(ev.secret_one_shot, "secret 必须是一次性（one-shot）输入");
    assert!(
        ev.secret_zeroized_after_send,
        "secret 发送后必须 zeroize（一次消费，不留缓冲）"
    );
    assert!(
        ev.secret_absent_from_all_outputs,
        "secret 不得出现在任何输出面（argv/env/log/evidence/stdout）"
    );
    assert!(
        ev.no_raw_secret_in_evidence,
        "证据必须声明不含 raw secret/cookie/private key"
    );
    // 独立于 production 自报的序列化扫描（证据形状纯逻辑检查）。
    let json = serde_json::to_string(ev)
        .unwrap_or_else(|e| format!("evidence-serialize-error:{e}"));
    for marker in FORBIDDEN_EVIDENCE_MARKERS {
        assert!(
            !json.contains(marker),
            "school evidence JSON 不得包含 {marker:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. 认证 vault 的 redaction 与 one-shot zeroize（学校 flow 必须经此 vault）
// ---------------------------------------------------------------------------

/// 纯逻辑（非 elevated 也必须通过）：学校 flow 的 secret 必须经 `exv-vpn-cstp::auth`
/// 一次性 vault（P42-I，已提交）——Debug 脱敏（`[REDACTED]`）、发送后与 Stop 时
/// zeroize、stale/duplicate/expired/stopped 响应拒绝。这钉死学校 flow 的 secret
/// 生命周期：任何输出面不得泄漏，任何复用都不得成立。
#[test]
fn auth_vault_redacts_and_zeroizes_one_shot_secrets() {
    let clock = Arc::new(FakeClock::at(0));
    let mut vault = AuthInteraction::new(clock, Duration::from_secs(30));

    // vault（P42-I）是协议层能力：group/username/password 挑战流。学校 MVP 已封存
    // group 选择（2026-08-15 用户裁定：仅学号/密码；见 `feed_school_secrets`），但
    // vault 能力本身保留（testkit gateway 也使用）——本测试仍跑完整协议流以钉住
    // redaction / one-shot / zeroize 语义。
    let group = vault.begin();
    assert_eq!(
        group.kind,
        AuthChallengeKind::GroupUsernamePassword,
        "vault 协议能力是 group/username/password（P42-I）"
    );
    let username = vault
        .respond(AuthResponse {
            interaction_id: group.interaction_id.clone(),
            secret: Secret::new(b"real-school-group"),
        })
        .expect("group 凭据推进到 username");
    let AuthProgress::Challenge(username) = username else {
        panic!("group 步必须返回 username challenge");
    };
    let password = vault
        .respond(AuthResponse {
            interaction_id: username.interaction_id.clone(),
            secret: Secret::new(b"real-school-user"),
        })
        .expect("username 凭据推进到 password");
    let AuthProgress::Challenge(password_challenge) = password else {
        panic!("username 步必须返回 password challenge");
    };

    // Debug 输出（vault/challenge/secret 本身）一律脱敏。
    assert_eq!(
        format!("{:?}", Secret::new(b"super-secret-school-password-9f3")),
        "[REDACTED]",
        "Secret 的 Debug 输出必须完全脱敏"
    );
    assert!(
        !format!("{:?}", vault).contains("super-secret-school-password-9f3"),
        "vault Debug 输出不得泄漏 secret"
    );
    assert!(
        !format!("{:?}", password_challenge).contains("super-secret-school-password-9f3"),
        "challenge Debug 输出不得泄漏 secret"
    );

    // 持有中（send 前）不清零；send 后一次性 zeroize。
    let secret = Secret::new(b"super-secret-school-password-9f3");
    let handle = secret.clone();
    let done = vault
        .respond(AuthResponse {
            interaction_id: password_challenge.interaction_id.clone(),
            secret,
        })
        .expect("password 完成流程");
    assert!(matches!(done, AuthProgress::Established));
    assert!(!handle.is_zeroed(), "send 前 secret 仍持有");
    vault.send_secret();
    assert!(handle.is_zeroed(), "发送后必须 zeroize（one-shot，一次消费）");

    // 已消费的 InteractionId 不可复用（stale/duplicate 语义）。
    let err = vault
        .respond(AuthResponse {
            interaction_id: password_challenge.interaction_id,
            secret: Secret::new(b"again"),
        })
        .expect_err("已消费的 InteractionId 不可再次响应");
    assert!(
        matches!(err, AuthError::DuplicateInteraction),
        "复用已消费的 InteractionId 必须被拒绝"
    );

    // Stop 撤销 pending prompt 并 zeroize 持有的 secret。
    let clock2 = Arc::new(FakeClock::at(0));
    let mut vault2 = AuthInteraction::new(clock2, Duration::from_secs(30));
    let g2 = vault2.begin();
    let u2 = vault2
        .respond(AuthResponse {
            interaction_id: g2.interaction_id.clone(),
            secret: Secret::new(b"g"),
        })
        .expect("advance");
    let AuthProgress::Challenge(u2) = u2 else {
        panic!("expected username challenge");
    };
    let p2 = vault2
        .respond(AuthResponse {
            interaction_id: u2.interaction_id.clone(),
            secret: Secret::new(b"u"),
        })
        .expect("advance");
    let AuthProgress::Challenge(p2) = p2 else {
        panic!("expected password challenge");
    };
    let pending = Secret::new(b"pending-secret");
    let pending_handle = pending.clone();
    vault2
        .respond(AuthResponse {
            interaction_id: p2.interaction_id.clone(),
            secret: pending,
        })
        .expect("deposit password");
    vault2.stop();
    assert!(
        pending_handle.is_zeroed(),
        "Stop 后 pending secret 必须 zeroize"
    );
    let err2 = vault2
        .respond(AuthResponse {
            interaction_id: p2.interaction_id,
            secret: Secret::new(b"x"),
        })
        .expect_err("stopped vault 拒绝任何后续响应");
    assert!(
        matches!(err2, AuthError::Stopped),
        "Stop 后响应以 Stopped 拒绝"
    );
}

// ---------------------------------------------------------------------------
// 7. 真实学校目标 IPv4 流量（跨 Wintun + CSTP）
// ---------------------------------------------------------------------------

/// 杀 **packet 只 fake loopback / fake-ipv4-target** mutant：真实学校目标 IPv4 的
/// ingress flow（SSH banner 或 HTTP）必须真实双向经过 Wintun ring + CSTP；跨子网
/// 设计（内核不本地应答）下 fake loopback 不可能观测到该 flow。flow 目标必须是
/// 真实学校 IPv4 地址，不得是受控 10.99.99.2。
#[test]
fn school_target_ipv4_traffic_flows_through_wintun_and_cstp() {
    let ev = school();
    if !school_env_complete_or_honest_not_run(ev) {
        return; // not_run / blocked_by_environment
    }
    assert_eq!(
        ev.wintun_dll_sha256.as_deref(),
        Some(WINTUN_DLL_SHA256),
        "Wintun DLL 必须是冻结的官方 0.14.1 amd64（SHA-256 精确匹配）"
    );
    assert!(ev.wintun_session_started, "Wintun session 必须已启动");
    assert!(
        ev.flow_protocol.is_some(),
        "必须诚实记录 ingress flow 协议（ssh-banner/http）"
    );
    assert!(
        ev.flow_connect_succeeded,
        "TCP connect 到学校 flow 目标必须成功（ssh daemon 应答）"
    );
    // ingress 证明语义（2026-08-16）：SSH banner 字节 / HTTP 响应字节 = 真实校园
    // ingress 数据（非 fake loopback）。完成态下 bytes_in 必须 > 0。
    assert!(
        ev.http_flow_response_received,
        "必须收到真实 ingress 数据（SSH banner / HTTP 响应）"
    );
    assert!(
        ev.http_flow_bytes_in > 0,
        "ingress 字节必须 > 0（in={}）",
        ev.http_flow_bytes_in
    );
    match ev.flow_protocol.as_deref() {
        Some("http") => {
            assert!(
                ev.http_flow_request_sent,
                "HTTP flow 必须真实发出请求"
            );
            assert!(
                ev.http_flow_response_status.is_some(),
                "HTTP 完成态必须记录真实响应状态码（学校目标状态不可冻结为受控 200）"
            );
            assert!(
                ev.http_flow_bytes_out > 0,
                "HTTP 请求字节必须 > 0（out={}）",
                ev.http_flow_bytes_out
            );
        }
        Some("ssh-banner") => {
            assert!(
                ev.http_flow_request_sent,
                "SSH ingress flow 必须真实发起（TCP connect 完成）"
            );
            assert!(
                ev.http_flow_response_status.is_none(),
                "SSH banner 不是 HTTP：不得伪造 HTTP 状态码"
            );
            // SSH 不发送应用层请求字节（banner 是服务端主动发送）。
            assert_eq!(
                ev.http_flow_bytes_out, 0,
                "SSH banner ingress 不应发送应用层请求字节（out={}）",
                ev.http_flow_bytes_out
            );
        }
        other => panic!("flow_protocol 必须是 ssh-banner/http，got {other:?}"),
    }
    let target = ev
        .flow_target_ipv4
        .as_deref()
        .expect("必须记录学校目标 IPv4");
    assert!(
        target.parse::<std::net::Ipv4Addr>().is_ok(),
        "flow 目标必须是真实 IPv4 地址（got {target:?}）"
    );
    assert_ne!(
        target, CONTROLLED_HTTP_TARGET_IPV4,
        "flow 目标必须是真实学校目标，不得是受控 10.99.99.2（fake-ipv4-target mutant）"
    );
    assert!(
        ev.packet_cross_subnet_design,
        "跨子网设计必须记录（学校目标与 tunnel 子网不同网段，内核不做本地应答）"
    );
    assert!(
        ev.wintun_ring_traffic_observed,
        "packet 必须真实经过 Wintun ring（fake loopback 不可能观测到学校目标 flow）"
    );
    assert!(
        ev.http_flow_correlated_to_ring,
        "ingress flow 必须与 ring 流量关联（真实经过 ring）"
    );
    assert!(ev.packet_attach_authenticated, "packet attach 必须发生在认证之后");
    assert!(
        ev.packet_bytes_on_ring >= ev.http_flow_bytes_out + ev.http_flow_bytes_in,
        "ring 字节必须覆盖 ingress flow 双向字节（ring={}, out+in={}）",
        ev.packet_bytes_on_ring,
        ev.http_flow_bytes_out + ev.http_flow_bytes_in
    );
}

// ---------------------------------------------------------------------------
// 8. 正常 Stop + scoped owned-resource cleanup
// ---------------------------------------------------------------------------

/// 杀 **Stop 后 packet 继续 / 无残留清理失败** mutant：正常 Stop 完整记录
/// journal/inventory/proof/retirement；owned 资源全部退休；adapter 移除、helper
/// 退出；address/MTU/route/DNS 的 before-applied-after 三方证据齐全且清理后回到
/// before（compare-and-restore，scoped——只清理本 ownership 的 obligation）。
#[test]
fn normal_stop_retires_scoped_owned_resources() {
    let ev = school();
    if !school_env_complete_or_honest_not_run(ev) {
        return; // not_run / blocked_by_environment
    }
    assert!(ev.stop_journaled, "Stop 必须先 journal（durable）");
    assert!(ev.inventory_complete, "Stop 时 inventory 必须完整");
    assert!(
        ev.cleanup_proof_issued,
        "必须签发 scoped CleanProof（完整 inventory + 无 running effect + 无 attached packet child + 无未退休 obligation）"
    );
    assert!(ev.retirement_recorded, "retirement 必须记录");
    assert!(ev.owned_resources_retired, "owned 资源必须全部退休");
    assert!(ev.wintun_adapter_removed_after_stop, "adapter 必须被移除（无残留）");
    assert!(ev.helper_exited_after_stop, "helper 进程必须在 Stop 后退出");
    assert_eq!(
        ev.packets_after_stop, 0,
        "Stop 之后不得再有 packet（kills Stop 后 packet 继续 mutant）"
    );
    // before-applied-after：applied 生效、after 回到 before（scoped compare-and-restore）
    assert!(
        ev.address_before.is_some() && ev.address_applied.is_some(),
        "address before/applied 必须记录"
    );
    assert_eq!(
        ev.address_after, ev.address_before,
        "address 清理后必须回到 before（compare-and-restore）"
    );
    assert_eq!(
        ev.mtu_after, ev.mtu_before,
        "MTU 清理后必须回到 before（compare-and-restore）"
    );
    assert_eq!(
        ev.routes_after, ev.routes_before,
        "routes 清理后必须回到 before（reverse compare-and-restore）"
    );
    assert_eq!(
        ev.dns_after, ev.dns_before,
        "DNS 清理后必须回到 before（compare-and-restore）"
    );
    assert!(
        ev.network_state_after_equals_before,
        "清理后网络状态必须等于 before（整体指纹一致）"
    );
    // VGDC-04：`/32` 直连路由生命周期——连接前就位、Stop 后移除（回读证明）。
    assert!(
        ev.route_installed,
        "/32 直连路由必须在连接前就位（verify-or-add；VGDC-04）"
    );
    assert!(
        !ev.route_conflict,
        "宿主不得有路由冲突（本宿主 /32 手动路由与物理网卡网关一致）"
    );
    assert!(
        ev.route_removed_after_stop,
        "Stop 后必须移除 /32 路由（路由生命周期；VGDC-04）"
    );
    assert!(
        ev.route_absent_after_stop,
        "移除回读证明：路由表不得再包含目标 /32 行"
    );
    assert!(
        ev.route_removal_error.is_none(),
        "路由移除不得失败（got {:?}）",
        ev.route_removal_error
    );
}

// ---------------------------------------------------------------------------
// 9. 校园路由（config-driven；offer + config 合并去重；apply/remove 回读 roundtrip）
// ---------------------------------------------------------------------------

/// 杀 **routes 硬编码 / 不继承 C++ 产品配置 / 不去重** mutant：校园路由必须来自
/// 配置（`EXV_RUST_VPN_SCHOOL_ROUTES`，镜像 C++ 产品 config.json 的
/// `default_routes`），与 offer 的 `X-CSTP-Split-Include` 路由合并——offer 优先、
/// config 追加非重复（按规范化 CIDR 身份去重）。纯逻辑（非 elevated 也必须通过）。
#[test]
fn campus_routes_merge_offer_first_config_deduped() {
    use exv_vpn_win32_acceptance::scenarios::school::merge_campus_routes;

    // 本 W30 网关的 offer 不发送 Split-Include（已验证：真实 offer 的
    // tunnel_plan_routes=[]，offer 解析处理 X-CSTP-Split-Include 的契约由
    // tests/school_auth_engine_wiring.rs 钉住）——合并结果就是配置路由本身
    // （C++ 产品 config.json 继承的 8 条校园路由，2026-08-16 用户冻结集）。
    let offer: Vec<String> = Vec::new(); // 真实 offer 形状：无 Split-Include
    let config: Vec<String> = vec![
        "49.52.4.0/25".into(),
        "59.78.176.0/20".into(),
        "59.78.192.0/21".into(),
        "58.198.176.128/25".into(),
        "219.228.56.0/21".into(),
        "202.120.80.0/20".into(),
        "222.66.117.0/24".into(),
        "219.228.144.96/25".into(),
    ];
    let merged = merge_campus_routes(&offer, &config);
    // 规范化：主机位被屏蔽（`219.228.144.96/25` 的网络地址是 `219.228.144.0/25`——
    // 含主机位的路由会被 CreateIpForwardEntry2 以 87 拒绝，facts §3 语义）。
    assert_eq!(
        merged,
        vec![
            "49.52.4.0/25".to_string(),
            "59.78.176.0/20".to_string(),
            "59.78.192.0/21".to_string(),
            "58.198.176.128/25".to_string(),
            "219.228.56.0/21".to_string(),
            "202.120.80.0/20".to_string(),
            "222.66.117.0/24".to_string(),
            "219.228.144.0/25".to_string(),
        ],
        "offer 为空时合并结果必须就是配置路由（继承 C++ 产品配置，绝不硬编码；按网络地址规范化）"
    );

    // offer 优先 + config 追加非重复（重复项按 CIDR 身份去重，不重复安装）。
    let offer2 = vec!["59.78.176.0/20".to_string(), "202.120.80.0/20".to_string()];
    let config2 = vec![
        "202.120.80.0/20".to_string(), // 与 offer 重复
        "222.66.117.0/24".to_string(),
        "59.78.176.0/20".to_string(), // 与 offer 重复
    ];
    assert_eq!(
        merge_campus_routes(&offer2, &config2),
        vec![
            "59.78.176.0/20".to_string(),
            "202.120.80.0/20".to_string(),
            "222.66.117.0/24".to_string(),
        ],
        "offer 优先，config 只追加非重复项"
    );
}

/// 校园路由移除原语对 absent 行幂等（AlreadyAbsent 是合法状态；与 direct_connect
/// 的 `/32` 路由同款 facts §3 语义）。纯逻辑（非 elevated 也必须通过）。
#[test]
fn absent_campus_route_removal_is_idempotent() {
    use exv_vpn_win32_acceptance::scenarios::school::remove_campus_routes;
    use exv_vpn_win32_resource::routes::RouteRow;

    // TEST-NET-1（RFC 5737 文档网段：本宿主不可能存在该路由）。
    let row = RouteRow::new(
        std::net::Ipv4Addr::new(192, 0, 2, 0),
        24,
        std::net::Ipv4Addr::new(192, 168, 31, 1),
        0x1234,
        5,
    );
    remove_campus_routes(&[row]).expect("absent 行移除必须幂等成功（AlreadyAbsent）");
}

/// 校园路由 apply/remove 回读 roundtrip（elevated live：W30 宿主）——hold 模式的
/// 精确代码路径（`CreateIpForwardEntry2` 安装 → 回读生效行 → 逆序移除 → 回读缺席
/// → 二次移除幂等）。使用 TEST-NET-1 目标 + 物理网卡（文档网段，无真实流量影响）。
/// 非 elevated 宿主跳过（require_admin pattern）；elevated 宿主上由
/// `--ignored` 显式运行。
#[test]
#[ignore = "live elevated: campus-route install/remove roundtrip on the W30 host"]
fn campus_route_apply_remove_roundtrip() {
    use exv_vpn_win32_acceptance::direct_connect;
    use exv_vpn_win32_acceptance::scenarios::school::{
        host_is_elevated, install_campus_routes, remove_campus_routes,
    };
    use exv_vpn_win32_resource::routes::{capture_rows, RouteKey};

    if !host_is_elevated() {
        return; // 非 elevated：跳过（require_admin pattern）
    }
    const TEST_NET: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 0, 2, 0);
    const TEST_NET_KEY: RouteKey = RouteKey {
        network: TEST_NET,
        prefix_len: 24,
    };
    let nics = direct_connect::find_physical_nics().expect("物理网卡发现必须成功");
    assert!(!nics.is_empty(), "宿主必须至少有一个物理网卡");
    let nic = &nics[0];

    let rows = install_campus_routes(nic.luid, nic.gateway, &["192.0.2.0/24".to_string()])
        .expect("TEST-NET 校园路由安装必须成功");
    assert_eq!(rows.len(), 1, "安装必须回读生效行");
    assert_eq!(rows[0].dest_key(), TEST_NET_KEY, "回读行必须命中目标 CIDR");
    // 回读证明：行已在路由表。
    assert!(
        capture_rows(nic.luid)
            .expect("回读必须成功")
            .iter()
            .any(|r| r.dest_key() == TEST_NET_KEY),
        "安装后路由表必须包含目标行"
    );

    // 逆序移除 + 回读缺席证明 + 二次移除幂等。
    remove_campus_routes(&rows).expect("移除必须成功");
    assert!(
        !capture_rows(nic.luid)
            .expect("回读必须成功")
            .iter()
            .any(|r| r.dest_key() == TEST_NET_KEY),
        "移除回读证明：目标行必须已不在路由表"
    );
    remove_campus_routes(&rows).expect("二次移除必须幂等成功（AlreadyAbsent）");
}

/// 配置的校园路由必须经**提权 helper** apply RPC 安装（`CreateIpForwardEntry2`
/// 在 helper 内执行——特权门禁：Wintun adapter 创建与路由表写入都是特权操作，都
/// 在 helper，host 只发指令）且存活期间**真实存在**于系统路由表（`GetIpForwardTable2`
/// 回读 Wintun 接口，非仅证据记录）；`routes_applied` 必须包含配置的校园路由
/// （= 8 条校园路由 + 隧道路由）。仅当 `EXV_RUST_VPN_SCHOOL_ROUTES` 已配置时断言
/// （未配置 = 空集路径，正常）。
#[test]
fn configured_campus_routes_are_installed_in_helper_and_live_in_system_table() {
    let ev = school();
    if !school_env_complete_or_honest_not_run(ev) {
        return; // not_run / blocked_by_environment
    }
    if std::env::var("EXV_RUST_VPN_SCHOOL_ROUTES").is_err() {
        return; // 未配置校园路由：空集路径，无断言
    }
    assert!(
        ev.route_writes_in_helper,
        "校园路由写入必须发生在提权 helper（apply RPC CreateIpForwardEntry2，非 host 侧）"
    );
    assert!(
        ev.campus_routes_live_in_system_table,
        "配置的校园路由必须在隧道路由期间全部真实存在于系统路由表（Wintun 接口）"
    );
    assert!(
        !ev.campus_routes_live.is_empty(),
        "必须记录存活校园路由（got {:?}）",
        ev.campus_routes_live
    );
    // routes_applied = 隧道路由 + 校园路由（helper 回读采纳）；每条存活校园路由
    // 必须在 routes_applied 中。
    for cidr in &ev.campus_routes_live {
        assert!(
            ev.routes_applied.iter().any(|r| r == cidr),
            "routes_applied 必须包含存活校园路由 {cidr}（got {:?}）",
            ev.routes_applied
        );
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
