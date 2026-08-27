// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W28-T Terra oracle：受控 TLS/CSTP + Wintun 纵切（`controlled_vertical`）。
//!
//! 本测试在**真实 Windows 宿主**上运行纵切 seam `run_controlled_vertical`（production
//! `src/scenarios/controlled.rs`），并把纵切记录的 `ControlledVerticalEvidence`
//! （production `src/evidence.rs`）断言为契约。若实现破坏任一冻结事实——
//! **TLS verifier always-true**、**relay spawn 即 Connected**（authenticated attach
//! 之前乐观 Connected）、**packet 只 fake loopback**（不真实经过 Wintun ring，
//! 跨子网环回设计下 HTTP flow 不可能被观测）、**DTLS token 偷渡**进 CSTP 路径、
//! **Stop 后 packet 继续**——对应测试必然失败。
//!
//! **权限感知（require_admin pattern）**：非 elevated 宿主上纯逻辑/证据形状测试
//! （`dtls_and_old_cpp_paths_are_absent`、`oracle_kills_fake_packet_or_optimistic_connected_mutant`
//! 以及所有 not_run 诚实性检查）必须通过；真实纵切测试 elevation-gated——非 elevated
//! 或动态事实不完整时，seam 必须短路（不建 adapter、不启 helper、不 mutate），只记录
//! 静态事实与 `WIN_ACCEPTANCE_ENV_INVALID:<predicate>` 或 `not_run/blocked_by_environment`
//! 标记，**不得冒充 RED 或 GREEN**。纵切自清理（adapter 移除、address/MTU/route/DNS
//! 回到 before、helper 退出），无残留。
//! GREEN 固定为 **8 passed; 0 failed; 0 ignored**。
//!
//! **PowerShell scenario anchor（W28-A / W28-Tb 消费契约）**：native scenario 以
//! elevated PowerShell 运行本测试二进制并消费其证据——
//! 1. `$env:EXV_RUST_VPN_EVIDENCE_DIR = <W28 evidence dir>`（可选
//!    `EXV_RUST_VPN_WINTUN_ZIP` / `EXV_RUST_VPN_WINTUN_DLL`）；
//! 2. 运行 exact focused command：
//!    `cargo test --manifest-path src/platform/win32/rust/Cargo.toml --locked
//!    -p exv-vpn-win32-acceptance --test controlled_vertical -- --nocapture`；
//! 3. 二进制把完整 `ControlledVerticalEvidence` JSON 写入
//!    `<EvidenceDir>/controlled-vertical.json`，并在 stdout 打印一行
//!    `CONTROLLED_VERTICAL_EVIDENCE:<compact-json>`；
//! 4. script grep 该行：`environment_state == "completed"` 且 JSON 可解析且 8/8 GREEN
//!    才是原生证据；环境无效只产生 `WIN_ACCEPTANCE_ENV_INVALID:<predicate>` 或
//!    `not_run/blocked_by_environment`。
//!
//! **证据保密**：任何证据（内存 struct、JSON 文件、stdout）绝不包含 raw
//! secret/cookie/private key/certificate；TLS/CSTP 只记录 digest 与 outcome
//! （见 `no_raw_secret_in_evidence` 与 `dtls_and_old_cpp_paths_are_absent` 的
//! 序列化扫描）。

use std::path::PathBuf;
use std::sync::OnceLock;

use exv_vpn_win32_acceptance::evidence::ControlledVerticalEvidence;
use exv_vpn_win32_acceptance::scenarios::controlled::run_controlled_vertical;
use exv_vpn_win32_acceptance::wintun_facts::WINTUN_DLL_SHA256;

// ---------------------------------------------------------------------------
// 冻结契约常量（测试拥有；production `evidence.rs`/`scenarios/controlled.rs`
// 必须满足，不可漂移）。
// ---------------------------------------------------------------------------

/// `environment_state` 取值契约（计划 §6.1）：完整纵切唯一值。
const ENV_STATE_COMPLETED: &str = "completed";
/// 环境无效标记前缀（后随精确 predicate，如 `host_not_elevated`）。
const ENV_INVALID_PREFIX: &str = "WIN_ACCEPTANCE_ENV_INVALID:";
/// 环境无效的另一合法标记（如 `requires_admin`）。
const NOT_RUN_BLOCKED_PREFIX: &str = "not_run/blocked_by_environment";

/// 受控纵切的冻结 tunnel plan（延续 WSP3/WSP4 已冻结的 Spark 事实）。
const CONTROLLED_TUNNEL_IPV4: &str = "10.88.88.1";
const CONTROLLED_TUNNEL_MTU: u32 = 1420;
const CONTROLLED_TUNNEL_DNS: &str = "10.88.88.53";
const CONTROLLED_TUNNEL_ROUTE: &str = "10.99.99.0/24";

/// 跨子网 HTTP 目标：与 tunnel 子网（10.88.88.0/24）**不同网段**，内核不做本地应答，
/// 流量必须真实经过 Wintun ring——fake loopback（同子网）不可能观测到 HTTP flow。
const CONTROLLED_HTTP_TARGET_IPV4: &str = "10.99.99.2";
const CONTROLLED_HTTP_EXPECTED_STATUS: u16 = 200;

/// 完整 inventory 的 canonical 项（W22 aggregate：adapter/session/address/MTU/
/// bypass/routes/DNS/packet/running，缺一不可）。
const INVENTORY_CANONICAL_ITEMS: [&str; 9] = [
    "adapter",
    "session",
    "address",
    "mtu",
    "bypass",
    "routes",
    "dns",
    "packet",
    "running",
];

/// 证据 JSON 中禁止出现的 raw secret/cookie/private key/certificate 标记
/// （独立于 production 自报的序列化扫描）。
const FORBIDDEN_EVIDENCE_MARKERS: [&str; 5] = [
    "PRIVATE KEY",
    "BEGIN CERTIFICATE",
    "Cookie:",
    "Authorization:",
    "password=",
];

/// 纵切只跑一次，各项断言共享同一份观测（确定性；同时是 PowerShell anchor 的
/// 证据发布点）。
fn vertical() -> &'static ControlledVerticalEvidence {
    static EVIDENCE: OnceLock<ControlledVerticalEvidence> = OnceLock::new();
    EVIDENCE.get_or_init(|| {
        let dll = exv_vpn_win32_acceptance::wintun_facts::resolve_dll_path(None);
        let ev = run_controlled_vertical(&dll);
        publish_evidence(&ev);
        ev
    })
}

/// 幂等发布证据给 native scenario：`EXV_RUST_VPN_EVIDENCE_DIR` 设置时写
/// `controlled-vertical.json`；无论设置与否都打印一行 `CONTROLLED_VERTICAL_EVIDENCE:<json>`
/// （script grep 该行）。测试侧执行，不引入 production 依赖。
fn publish_evidence(ev: &ControlledVerticalEvidence) {
    let json = serde_json::to_string(ev)
        .unwrap_or_else(|e| format!("evidence-serialize-error:{e}"));
    if let Some(dir) = std::env::var_os("EXV_RUST_VPN_EVIDENCE_DIR") {
        let path = PathBuf::from(dir).join("controlled-vertical.json");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if std::fs::write(&path, &json).is_err() {
            eprintln!("WARNING: cannot write evidence file {}", path.display());
        }
    }
    println!("CONTROLLED_VERTICAL_EVIDENCE:{json}");
}

/// elevation/完整性门禁（require_admin pattern）：环境有效（elevated 且动态事实
/// 完整）返回 `true` 并继续真实断言；否则验证环境无效标记的诚实性并返回 `false`
/// （not_run，不伪造）。
fn env_complete_or_honest_not_run(ev: &ControlledVerticalEvidence) -> bool {
    if ev.env_elevated && ev.is_dynamic_complete() {
        assert_eq!(
            ev.environment_state, ENV_STATE_COMPLETED,
            "完整纵切必须标记 environment_state=completed"
        );
        true
    } else {
        assert!(
            ev.environment_state.starts_with(ENV_INVALID_PREFIX)
                || ev.environment_state.starts_with(NOT_RUN_BLOCKED_PREFIX),
            "环境无效必须产生 {ENV_INVALID_PREFIX}<predicate> 或 {NOT_RUN_BLOCKED_PREFIX}（不得冒充 RED/GREEN），got {:?}",
            ev.environment_state
        );
        assert!(
            !ev.env_elevated || !ev.is_dynamic_complete(),
            "elevated 且动态事实完整时 environment_state 必须是 completed"
        );
        false
    }
}

// ---------------------------------------------------------------------------
// 1. 普通 host + 提权 helper 完成受控 connect
// ---------------------------------------------------------------------------

/// 反假绿核心：非特权 host 进程 + 独立提权 helper 进程完成受控 connect；
/// 双向 pipe peer 身份谓词成立；control/data 独立 connection。
#[test]
fn ordinary_host_and_elevated_helper_complete_controlled_connect() {
    let ev = vertical();
    if !env_complete_or_honest_not_run(ev) {
        return; // not_run / blocked_by_environment
    }
    // 宿主与 OS/build/hardware 证据
    assert!(ev.host_os.contains("Windows"), "host_os 必须记录 Windows: {}", ev.host_os);
    assert!(!ev.os_build.is_empty(), "os_build 必须记录");
    assert!(!ev.hardware.is_empty(), "hardware 必须记录");
    assert!(!ev.hostname.is_empty(), "hostname 必须记录");
    // host/helper PID 与 token elevation
    assert_eq!(ev.host_pid, Some(std::process::id()), "纵切在 host 进程内运行");
    assert!(ev.helper_pid.is_some(), "必须记录 helper PID");
    assert_ne!(ev.helper_pid, Some(std::process::id()), "helper 必须是独立进程");
    assert!(!ev.host_token_elevated, "host 必须是非提权进程（ordinary host）");
    assert!(
        ev.helper_token_elevated,
        "helper 必须是提权进程（唯一 native mutation authority）"
    );
    // pipe peer 谓词（双向身份，WSP1 冻结语义）
    assert!(
        ev.control_pipe_peer_verified,
        "control pipe peer 必须通过双向身份验证（host 验 helper、helper 验 host）"
    );
    assert!(
        ev.packet_pipe_peer_verified,
        "packet pipe peer 必须通过双向身份验证"
    );
    assert!(
        ev.control_data_separate_connections,
        "control/data 必须是两条独立已认证 connection（W12 语义）"
    );
    assert!(
        !ev.pipe_peer_predicates.is_empty(),
        "pipe peer 谓词必须逐项记录，got {:?}",
        ev.pipe_peer_predicates
    );
    // PowerShell anchor：设置证据目录时必须写出与内存一致的可解析 JSON 文件
    if let Some(dir) = std::env::var_os("EXV_RUST_VPN_EVIDENCE_DIR") {
        let path = PathBuf::from(dir).join("controlled-vertical.json");
        assert!(path.exists(), "native scenario 消费契约：evidence 文件必须写入 {}", path.display());
        let on_disk: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&path).unwrap_or_default(),
        )
        .unwrap_or_else(|e| panic!("evidence 文件必须是合法 JSON: {e}"));
        assert_eq!(
            on_disk["environment_state"].as_str(),
            Some(ev.environment_state.as_str()),
            "evidence 文件 environment_state 必须与内存一致"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. TLS 对端与 CSTP-only offer
// ---------------------------------------------------------------------------

/// 杀 **TLS verifier always-true** mutant：证书链验证 + hostname 验证 + 错误 host
/// 拒绝都必须真实发生；offer 必须是 CSTP-only（无 DTLS offer/token），offer digest
/// 与 tunnel plan（Common validation 后）精确冻结。
#[test]
fn tls_peer_and_cstp_only_offer_are_verified() {
    let ev = vertical();
    if !env_complete_or_honest_not_run(ev) {
        return; // not_run / blocked_by_environment
    }
    assert!(ev.tls_chain_verified, "TLS 证书链必须验证通过（verifier 不得 always-true）");
    assert!(ev.tls_hostname_verified, "TLS hostname 必须验证通过（SNI 与证书一致）");
    assert!(
        ev.tls_wrong_host_rejected,
        "错误 host 的证书必须被拒绝（kills TLS verifier always-true mutant）"
    );
    assert!(
        ev.tls_peer_fingerprint.is_some(),
        "必须记录 TLS 对端指纹（digest，非 raw 证书）"
    );
    assert_eq!(
        ev.tls_peer_fingerprint.as_deref().map(str::len),
        Some(64),
        "对端指纹必须是 SHA-256 hex（64 字符）"
    );
    assert!(ev.cstp_offer_digest.is_some(), "必须记录 CSTP offer digest");
    assert_eq!(
        ev.cstp_offer_digest.as_deref().map(str::len),
        Some(64),
        "offer digest 必须是 SHA-256 hex（64 字符）"
    );
    assert!(
        ev.cstp_offer_only,
        "offer 必须是 CSTP-only（无 DTLS offer / DTLS token 偷渡）"
    );
    assert!(
        ev.tunnel_plan_validated,
        "tunnel plan 必须经过 Common CSTP offer validation 后才进入平台端口"
    );
    // tunnel plan 冻结值（WSP4 已冻结的 Spark 事实）
    assert_eq!(
        ev.tunnel_plan_ipv4_address.as_deref(),
        Some(CONTROLLED_TUNNEL_IPV4),
        "plan 地址必须等于冻结值"
    );
    assert_eq!(ev.tunnel_plan_mtu, Some(CONTROLLED_TUNNEL_MTU), "plan MTU 必须等于冻结值");
    assert!(
        ev.tunnel_plan_dns_servers
            .iter()
            .any(|s| s.as_str() == CONTROLLED_TUNNEL_DNS),
        "plan DNS 必须包含冻结服务器"
    );
    assert!(
        ev.tunnel_plan_routes.iter().any(|r| r.as_str() == CONTROLLED_TUNNEL_ROUTE),
        "plan routes 必须包含冻结隧道路由"
    );
    assert!(
        ev.tunnel_plan_ipv4_address
            .as_deref()
            .is_some_and(|a| a.parse::<std::net::Ipv4Addr>().is_ok()),
        "plan 必须是纯 IPv4（无 IPv6/DTLS 字段）"
    );
}

// ---------------------------------------------------------------------------
// 3. platform-ready 等待 Wintun 与 network inventory
// ---------------------------------------------------------------------------

/// platform-ready 必须等待 Wintun（冻结 DLL/adapter/LUID/index/session）与 network
/// inventory（address/MTU/route/DNS）全部就绪；inventory 必须是 canonical 完整集合
/// （缺任一 obligation 不得 ready——mutant: omit inventory item 被杀死）。
#[test]
fn platform_ready_waits_for_wintun_and_network_inventory() {
    let ev = vertical();
    if !env_complete_or_honest_not_run(ev) {
        return; // not_run / blocked_by_environment
    }
    // Wintun DLL/adapter/LUID/index
    assert_eq!(
        ev.wintun_dll_sha256.as_deref(),
        Some(WINTUN_DLL_SHA256),
        "Wintun DLL 必须是冻结的官方 0.14.1 amd64（SHA-256 精确匹配）"
    );
    assert!(ev.wintun_dll_signature_present, "Wintun DLL 必须带 Authenticode 签名");
    assert!(ev.wintun_adapter_name.is_some(), "必须记录 adapter 名");
    assert!(ev.wintun_adapter_luid.is_some(), "必须记录 adapter LUID");
    assert!(ev.wintun_adapter_ifindex.is_some(), "必须记录 adapter ifIndex");
    assert!(ev.wintun_session_started, "Wintun session 必须已启动");
    // ready 顺序
    assert!(ev.ready_waited_for_wintun, "platform-ready 必须等待 Wintun 就绪");
    assert!(
        ev.ready_waited_for_network_inventory,
        "platform-ready 必须等待 network inventory 就绪"
    );
    assert!(
        ev.ready_after_inventory,
        "platform-ready 只能在完整 inventory 之后签发"
    );
    // canonical inventory
    for item in INVENTORY_CANONICAL_ITEMS {
        assert!(
            ev.inventory_items.iter().any(|i| i.as_str() == item),
            "inventory 必须包含 canonical 项 {item}（got {:?}）",
            ev.inventory_items
        );
    }
    // 四族 applied 证据
    assert!(ev.address_applied.is_some(), "address applied 必须记录");
    assert_eq!(ev.mtu_applied, Some(CONTROLLED_TUNNEL_MTU), "MTU applied 必须等于 plan MTU");
    assert!(!ev.routes_applied.is_empty(), "routes applied 必须记录");
    assert!(!ev.dns_applied.is_empty(), "DNS applied 必须记录");
}

// ---------------------------------------------------------------------------
// 4. 真实 IPv4 HTTP flow 跨 Wintun + CSTP
// ---------------------------------------------------------------------------

/// 杀 **packet 只 fake loopback** mutant：真实 IPv4 HTTP flow 的请求与响应必须
/// 双向真实经过 Wintun ring + CSTP；跨子网设计（内核不本地应答）下，fake
/// loopback 不可能观测到该 flow。
#[test]
fn real_ipv4_http_crosses_wintun_and_cstp() {
    let ev = vertical();
    if !env_complete_or_honest_not_run(ev) {
        return; // not_run / blocked_by_environment
    }
    assert!(ev.http_flow_request_sent, "HTTP 请求必须真实发出");
    assert!(ev.http_flow_response_received, "HTTP 响应必须真实收到");
    assert_eq!(
        ev.http_flow_response_status,
        Some(CONTROLLED_HTTP_EXPECTED_STATUS),
        "HTTP 响应必须为 {CONTROLLED_HTTP_EXPECTED_STATUS}"
    );
    assert!(
        ev.http_flow_bytes_out > 0 && ev.http_flow_bytes_in > 0,
        "HTTP flow 双向字节必须 > 0（out={}, in={}）",
        ev.http_flow_bytes_out,
        ev.http_flow_bytes_in
    );
    assert_eq!(
        ev.flow_target_ipv4.as_deref(),
        Some(CONTROLLED_HTTP_TARGET_IPV4),
        "flow 目标必须是跨子网地址（同子网会被内核本地应答，不构成 ring 证据）"
    );
    assert!(ev.packet_cross_subnet_design, "跨子网环回设计必须记录在证据");
    assert!(
        ev.wintun_ring_traffic_observed,
        "packet 必须真实经过 Wintun ring（kills fake loopback mutant）"
    );
    assert!(
        ev.http_flow_correlated_to_ring,
        "HTTP flow 必须与 ring 流量关联（双向真实经过 ring，fake loopback 不可能）"
    );
    assert!(ev.packet_attach_authenticated, "packet attach 必须发生在认证之后");
    assert!(ev.packet_attach_atomic_single_use, "attach 必须原子且单次消费");
    assert!(
        ev.packet_bytes_on_ring >= ev.http_flow_bytes_out + ev.http_flow_bytes_in,
        "ring 字节必须覆盖 HTTP flow 双向字节（ring={}, out+in={}）",
        ev.packet_bytes_on_ring,
        ev.http_flow_bytes_out + ev.http_flow_bytes_in
    );
}

// ---------------------------------------------------------------------------
// 5. Connected 等待双向 packet 就绪
// ---------------------------------------------------------------------------

/// 杀 **relay spawn 即 Connected** mutant：Connected 必须等 authenticated packet
/// attach 与双向 packet 就绪（spec：线程/task spawn 不算 ready；attach 原子消费
/// capability；乐观 Connected 禁止）。非 elevated 时验证 not_run 诚实性
/// （不伪造乐观值）。
#[test]
fn connected_waits_for_both_packet_directions() {
    let ev = vertical();
    if !env_complete_or_honest_not_run(ev) {
        // not_run：不得把乐观/假事实填为 true。
        assert!(!ev.optimistic_connected, "not_run 时不得伪造乐观 Connected");
        assert!(
            !ev.connected_after_attach,
            "not_run 时不得伪造 connected_after_attach"
        );
        return;
    }
    assert!(
        ev.connected_after_both_directions_ready,
        "Connected 必须等待两个 packet 方向全部就绪"
    );
    assert!(
        ev.connected_after_attach,
        "Connected 必须出现在 authenticated packet attach 之后（kills relay spawn 即 Connected mutant）"
    );
    assert!(!ev.optimistic_connected, "不得出现乐观 Connected（attach/spawn 之前）");
    assert!(
        ev.journal_contains_attach_before_connected,
        "phase journal 中 attach 必须排在 Connected 之前"
    );
    assert!(
        ev.connected_holds_five_proofs,
        "Connected 必须同时持有 protocol session + platform ownership + packet lease + platform-ready proof + data-running proof（缺一不可）"
    );
    assert!(ev.packet_attach_authenticated, "attach 必须是认证后的 attach");
    assert!(ev.packet_attach_atomic_single_use, "attach 必须原子且单次消费（无第二 reader/writer）");
}

// ---------------------------------------------------------------------------
// 6. Stop 退休 owned 资源 + before-applied-after 证据
// ---------------------------------------------------------------------------

/// 杀 **Stop 后 packet 继续** mutant + 完整 Stop 证据：journal/inventory/proof/
/// retirement 全部记录；address/MTU/route/DNS 的 before-applied-after 三方证据
/// 齐全且清理后回到 before；adapter 移除、helper 退出、无残留。
#[test]
fn stop_retires_owned_resources_with_before_after_evidence() {
    let ev = vertical();
    if !env_complete_or_honest_not_run(ev) {
        return; // not_run / blocked_by_environment
    }
    // Stop 证据链
    assert!(ev.stop_journaled, "Stop 必须先 journal（durable）");
    assert!(ev.inventory_complete, "Stop 时 inventory 必须完整");
    assert!(
        ev.cleanup_proof_issued,
        "必须签发 CleanProof（完整 inventory + 无 running effect + 无 attached packet child + 无未退休 obligation）"
    );
    assert!(ev.retirement_recorded, "retirement 必须记录");
    assert!(ev.owned_resources_retired, "owned 资源必须全部退休");
    assert!(ev.wintun_adapter_removed_after_stop, "adapter 必须被移除（无残留）");
    assert!(ev.helper_exited_after_stop, "helper 进程必须在 Stop 后退出");
    assert_eq!(
        ev.packets_after_stop, 0,
        "Stop 之后不得再有 packet（kills Stop 后 packet 继续 mutant）"
    );
    // before-applied-after：applied 生效、after 回到 before
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
    assert_eq!(ev.mtu_applied, Some(CONTROLLED_TUNNEL_MTU), "MTU applied 必须等于 plan MTU");
    assert!(
        ev.network_state_after_equals_before,
        "清理后网络状态必须等于 before（整体指纹一致）"
    );
}

// ---------------------------------------------------------------------------
// 7. 纯逻辑守卫：无 DTLS、无旧 C++、无第三方依赖、证据无 secret
// ---------------------------------------------------------------------------

/// 纯逻辑测试（**非 elevated 也必须通过**）：依赖图/源码无 DTLS variant/feature/
/// fallback（杀 **DTLS token 偷渡** mutant）、无旧 C++ runtime linkage、无第三方
/// Wintun wrapper/OpenSSL；证据序列化不得含 raw secret/cookie/private key/certificate。
#[test]
fn dtls_and_old_cpp_paths_are_absent() {
    let ev = vertical();
    assert!(
        ev.dtls_absent,
        "domain/wire/protocol/data-plane/platform 依赖图必须无 DTLS variant/feature/fallback"
    );
    assert!(
        ev.dtls_token_smuggling_absent,
        "不得有 DTLS token 偷渡进 CSTP 路径/证据（kills DTLS token 偷渡 mutant）"
    );
    assert!(
        ev.old_cpp_sources_absent,
        "Rust 纵切不得 linkage 旧 C++ runtime 源码"
    );
    assert!(
        ev.dependency_guard_clean,
        "依赖守卫必须干净（无 OpenSSL、无第三方 Wintun wrapper、无 dtls crate）"
    );
    assert!(
        !ev.dependency_guard_notes.is_empty(),
        "依赖守卫的逐项结果必须记录，got {:?}",
        ev.dependency_guard_notes
    );
    assert!(
        ev.no_raw_secret_in_evidence,
        "证据必须声明不含 raw secret/cookie/private key"
    );
    // 独立于 production 自报的序列化扫描（证据形状纯逻辑检查）
    let json = serde_json::to_string(ev)
        .unwrap_or_else(|e| format!("evidence-serialize-error:{e}"));
    for marker in FORBIDDEN_EVIDENCE_MARKERS {
        assert!(
            !json.contains(marker),
            "evidence JSON 不得包含 {marker:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. 反假绿：fake packet / 乐观 Connected 必须被杀死
// ---------------------------------------------------------------------------

/// 反假绿（oracle_kills_*）：环境完成后 packet 必须真实经 ring、Connected 必须等
/// authenticated attach（fake loopback 与乐观 Connected 均为死）；环境无效时不得
/// 把事实填为 true——必须诚实标记 `WIN_ACCEPTANCE_ENV_INVALID:<predicate>` 或
/// `not_run/blocked_by_environment`，不冒充 RED/GREEN。
#[test]
fn oracle_kills_fake_packet_or_optimistic_connected_mutant() {
    let ev = vertical();
    if ev.env_elevated && ev.is_dynamic_complete() {
        assert!(ev.wintun_ring_traffic_observed, "fake loopback mutant：真实 ring 流量必须被观测");
        assert!(ev.packet_bytes_on_ring > 0, "ring 字节必须 > 0");
        assert!(
            ev.http_flow_correlated_to_ring,
            "HTTP flow 必须与 ring 关联（fake loopback 不可能）"
        );
        assert!(ev.connected_after_attach, "Connected 必须等 authenticated attach");
        assert!(!ev.optimistic_connected, "乐观 Connected 必须为 false");
        assert!(
            ev.connected_after_both_directions_ready,
            "Connected 必须等双向 packet 就绪"
        );
    } else {
        // 环境无效：诚实 not_run，不得伪造任何事实。
        assert!(
            ev.environment_state.starts_with(ENV_INVALID_PREFIX)
                || ev.environment_state.starts_with(NOT_RUN_BLOCKED_PREFIX),
            "环境无效必须标记 {ENV_INVALID_PREFIX}<predicate> 或 {NOT_RUN_BLOCKED_PREFIX}，got {:?}",
            ev.environment_state
        );
        assert!(!ev.wintun_ring_traffic_observed, "not_run 时不得伪造 ring 流量事实");
        assert!(!ev.optimistic_connected, "not_run 时不得伪造乐观 Connected");
        assert_eq!(ev.packets_after_stop, 0, "not_run 时不得伪造 Stop 后流量");
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
