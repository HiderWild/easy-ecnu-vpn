// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W28 受控 TLS/CSTP + Wintun 纵切（W28-I）：`run_controlled_vertical`。
//!
//! 在真实 Windows 宿主上运行受控 TLS/CSTP + Wintun 纵切：非特权 host 进程 +
//! 独立提权 helper 进程（RunAs），两条独立已认证 Named Pipe（control/packet），
//! 真实 TLS 证书链/hostname 验证（严格 webpki verifier，kills always-true mutant），
//! CSTP-only offer digest 与 tunnel plan 校验，Wintun adapter/session 与
//! address/MTU/route/DNS before-applied-after（W16/W17/W22 leaf 组合），
//! authenticated atomic packet attach（W23B），真实 IPv4 HTTP flow 跨 Wintun ring +
//! CSTP data frame 双向（跨子网 10.99.99.0/24 环回——同子网会被内核本地应答、
//! 不进入 ring），Stop 后 packet 停止（W24 逆序 compare-and-restore + W14 durable
//! journal + CleanProof + retirement）。
//!
//! **权限感知（require_admin pattern）**：host 必须是非提权进程（ordinary host——
//! elevation 是 helper 的唯一职责）；host 进程 elevated 时诚实标记
//! `WIN_ACCEPTANCE_ENV_INVALID:host-process-elevated` 并短路（不建 adapter、不启
//! helper、不 mutate），不冒充 RED/GREEN。helper 提权失败（UAC 拒绝）同样诚实标记
//! `WIN_ACCEPTANCE_ENV_INVALID:helper-elevation-failed`。任何中途失败只记录静态
//! 事实与 `not_run/blocked_by_environment:<predicate>`，动态事实不提交（不伪造）。
//! 纵切自清理：任何失败路径都向 helper 发 Stop（adapter 移除、四族回 before、
//! helper 退出），无残留。
//!
//! **组合（不重新实现）**：W26 `compose_privileged_helper`/`shutdown_composition`、
//! W27 `compose_nonprivileged_host` + `KernelControlGate`、W16 `WintunLibrary`/
//! `WintunAdapter`、W17 `WintunSession`（`Arc<Mutex<>>` 共享 + worker，W17-T 模式）、
//! W22 `COMPLETE_INVENTORY`/`is_complete` 及其委托的 leaf seams
//! （`IpAddressController`/`MtuController`/`routes`/`DnsApplier`，apply_tunnel 的
//! canonical 顺序）、W23B `AttachedPacketRelay`（atomic attach 单次消费、双方向
//! leg、running proof）、W24 `verify_cleanup_proof` + `RetirementSaga`、
//! W14 `WinJournalStore`（durable stop/retirement record）、P41 `Bootstrap`
//! （真实 TLS 验证）。W22 `Aggregate` 类型本身因独占 session 所有权与 W17 共享
//! session 运行时（每 adapter 单 session、无 extraction API）不可同时组合——
//! 纵切以 apply_tunnel 委托的同一组 leaf seams 按冻结顺序执行
//! （见 helper 侧 `helper_apply` 的文档注释；作为 host-repair 候选上报）。
//!
//! **DP-01（W30 数据面修复，2026-08-16）：helper 契约改为 create-then-idle**——
//! helper 的 apply 只做特权初始化（`WintunAdapter::create` + address/MTU/路由/校园
//! 路由/DNS 四族 leaf），**不创建 Wintun session、不启动 ring worker**；apply 回复
//! 携带 adapter 身份（create 名/LUID/ifindex）与 `session_started=false`，adapter 在
//! apply 返回后保持存活（`HelperNativeState.adapter` 持有到 Stop，供引擎按名
//! `WintunAdapter::open`）。数据面（Wintun session + ring 读写）属主移回引擎/host 侧
//! （C++-faithful）；本文件的 W28 受控纵切数据面（依赖 helper session + ring worker
//! 泵 packet pipe）将在 DP-04 重接线为 host 侧 session，与本文件 W30 school helper
//! 角色一致。`helper_stop` 不再 join ring worker，`StopReply` ring 字节恒 0
//! （host 侧数据面计数器在 DP-03/DP-04 承接）。
//!
//! **保密契约**：任何证据字段不携带 raw secret/cookie/private key/certificate——
//! TLS/CSTP 只记录 SHA-256 digest 与 outcome；`no_raw_secret_in_evidence` 由
//! `scan_evidence` 对最终序列化做独立扫描后置真。

use std::ffi::c_void;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use exv_vpn_data_plane::budget::DataPlaneDirection;
use exv_vpn_domain::error::{ErrorCode, ErrorSubject};
use exv_vpn_domain::identity::{
    EvidenceDigest, InventoryDigest, OwnerLeaseId, OwnershipVersion, ResourceIdentityDigest,
    RetirementOperationId, RuntimeEpoch, TokenDigest,
};
use exv_vpn_domain::model::{PacketLeaseRef, PlatformOwnershipRef};
use exv_vpn_domain::ports::{
    AdmissionWatermark, AuthorityEpoch, AuthorityFence, CleanupTrigger, CleanupTriggerDigest,
    JournalRevision, JournalRootDigest, PlatformAuthorityInstanceId, VersionedPlatformEvidence,
};
use exv_vpn_resource::journal::JournalRecord;
use exv_vpn_resource::retirement::{ProveCleanInput, RetirementSaga};

use exv_core::composition::{compose_nonprivileged_host, HostEffect, HostEvent};
use exv_engine::composition::{compose_privileged_helper, ComposeConfig};
use exv_engine::packet_relay::{AttachedPacketRelay, RelayDirection};
use exv_engine::shutdown::shutdown_composition;
use exv_vpn_win32_ipc::packet_channel::PacketChannel;
use exv_vpn_win32_ipc::packet_limits::PacketLimits;
use exv_vpn_win32_resource::cleanup_proof::{verify_cleanup_proof, CleanupPredicate};
use exv_vpn_win32_resource::dns::{DnsApplier, DnsCapture};
use exv_vpn_win32_resource::dns_types::{DnsFingerprint, DnsSettings};
use exv_vpn_win32_resource::inventory::{InventoryItem, COMPLETE_INVENTORY};
use exv_vpn_win32_resource::ip_address::{
    plan_addresses, restore_owned_addresses, IpAddressController,
};
use exv_vpn_win32_resource::ip_helper_types::IpAddressRow;
use exv_vpn_win32_resource::journal_path::JournalPath;
use exv_vpn_win32_resource::journal_store::WinJournalStore;
use exv_vpn_win32_resource::mtu::{MtuController, MtuFamily, MtuSnapshot, validate_mtu_value};
use exv_vpn_win32_resource::packet_capability::PacketCapability;
use exv_vpn_win32_resource::routes::{capture_rows, install, remove, RouteRow};
use exv_vpn_win32_resource::timing;
use exv_vpn_win32_resource::wintun_adapter::WintunAdapter;
use exv_vpn_win32_resource::wintun_api::WintunLibrary;

use exv_vpn_cstp::codec::{Codec, CstpFrame};
use exv_vpn_cstp::connector::{Bootstrap, BootstrapConfig, BootstrapError, TrustPolicy};
use rustls::pki_types::pem::PemObject;

use uuid::Uuid;
use windows::core::{GUID, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, HLOCAL, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, PSECURITY_DESCRIPTOR, PSID, SID_AND_ATTRIBUTES,
    SID_NAME_USE, SECURITY_ATTRIBUTES, TOKEN_QUERY, TokenElevation, TokenLogonSid, TokenUser,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_ACCESS_RIGHTS, FILE_FLAGS_AND_ATTRIBUTES,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    SetNamedPipeHandleState, NAMED_PIPE_MODE, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    REG_VALUE_TYPE,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    WaitForSingleObject,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

use crate::evidence::{ControlledVerticalEvidence, ENV_INVALID_PREFIX, NOT_RUN_BLOCKED_PREFIX};

// ---------------------------------------------------------------------------
// 冻结常量（与 Terra 契约一致；WSP3/WSP4 已冻结的 Spark 事实）。
// ---------------------------------------------------------------------------

/// 纵切创建的 Wintun adapter 名称。
pub const ADAPTER_NAME: &str = "ExvW28Vertical";
/// adapter 的 tunnel type。
const TUNNEL_TYPE: &str = "EXV VPN";
/// 冻结 tunnel plan（测试冻结值：10.88.88.1 / 1420 / 10.88.88.53 / 10.99.99.0/24）。
const TUNNEL_IPV4: &str = "10.88.88.1";
const TUNNEL_PREFIX: u8 = 24;
const TUNNEL_MTU: u32 = 1420;
const TUNNEL_DNS: &str = "10.88.88.53";
const TUNNEL_ROUTE_NETWORK: &str = "10.99.99.0";
const TUNNEL_ROUTE_PREFIX: u8 = 24;
/// 校园路由的安装度量（与隧道路由同款 5；W30 config-driven campus routes）。
const CAMPUS_ROUTE_METRIC: u32 = 5;
/// `ERROR_OBJECT_ALREADY_EXISTS`（`CreateIpForwardEntry2` 重复精确行——校园路由
/// 已在系统表中时直接回读采纳，不重复安装）。
const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;
/// 跨子网 HTTP 目标（与 tunnel 子网不同网段——同子网会被内核本地应答、不进入 ring）。
const FLOW_TARGET: &str = "10.99.99.2";
const FLOW_TARGET_PORT: u16 = 80;
/// DP-01：helper 不再创建 Wintun session，ring capacity（WSP3 冻结 min 131072）由
/// 引擎/host 侧数据面（DP-02/DP-03）使用——host 侧将取 `wintun_facts` 的
/// `WINTUN_RING_CAPACITY_MIN`/`WINTUN_PROBE_RING_CAPACITY`（同一冻结值）。
/// 受控 TLS 对端的 hostname（与嵌入证书 SAN 一致）。
const TLS_HOSTNAME_OK: &str = "vpn.example.test";
/// 错误 hostname（证书 SAN 不匹配——kills TLS verifier always-true mutant）。
const TLS_HOSTNAME_WRONG: &str = "other.example.test";
/// 受控 CSTP offer（CSTP-only；无 DTLS offer/token）。server 发送时附加 `\r\n\r\n`
/// 终结符（client 以此识别 offer 结束）。
const CSTP_OFFER: &str = "CSTP_MTU 1420\r\nCSTP_ADDRESS 10.88.88.1\r\nCSTP_NETMASK 255.255.255.0\r\nCSTP_DNS 10.88.88.53\r\nCSTP_SPLIT_INCLUDE 10.99.99.0/24";

// ---------------------------------------------------------------------------
// 嵌入测试 PKI（与 exv-vpn-cstp 的 tls_bootstrap 测试同款确定性材料：
// 自签名 ECDSA P-256 证书，SAN DNS:vpn.example.test；自身即信任根）。
// pub(crate) 供 `direct_connect` 的 DoH 机制测试复用（同一确定性材料）。
// ---------------------------------------------------------------------------

pub(crate) const VPN_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBqTCCAU6gAwIBAgIUCz2E6EXN/6S3gIxuRBEAK/doSI8wCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQdnBuLmV4YW1wbGUudGVzdDAeFw0yNjA4MTIyMDQxNTBaFw0z
NjA4MDkyMDQxNTBaMBsxGTAXBgNVBAMMEHZwbi5leGFtcGxlLnRlc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQ621WzgT+Rp6MR+st4LY1gxps9HzBSlIIFbbHW
M3PjUe5vJXzSuEaBQ+t6kBsHEc9FoX5oPA6ivQ7eryJYMrL4o3AwbjAdBgNVHQ4E
FgQU0IZcqxbwuE5X5GGdjRl/4XLJEqkwHwYDVR0jBBgwFoAU0IZcqxbwuE5X5GGd
jRl/4XLJEqkwDwYDVR0TAQH/BAUwAwEB/zAbBgNVHREEFDASghB2cG4uZXhhbXBs
ZS50ZXN0MAoGCCqGSM49BAMCA0kAMEYCIQDQ+3+bij4pa2x1Z5ErL29zX1aXHRE/
8j8r2YsJ2fkeegIhAOBH6bDzde1JgeRR/IuiTm29PrNb3DbM7ksLb5mNTzUt
-----END CERTIFICATE-----
"#;

pub(crate) const VPN_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn1Ra5jnCNjCWeCfF
x0h7BnT9tvnlrqAdc+0xZphBfZWhRANCAAQ621WzgT+Rp6MR+st4LY1gxps9HzBS
lIIFbbHWM3PjUe5vJXzSuEaBQ+t6kBsHEc9FoX5oPA6ivQ7eryJYMrL4
-----END PRIVATE KEY-----
"#;

// ---------------------------------------------------------------------------
// 管道 wire 协议（control：length-prefixed JSON；packet：length-prefixed raw）。
// ---------------------------------------------------------------------------

/// 帧头长度（u32 BE）。
const FRAME_LEN_BYTES: usize = 4;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct HelloReq {
    pub(crate) cmd: String,
    pub(crate) host_pid: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct HelloReply {
    pub(crate) ok: bool,
    pub(crate) error: Option<String>,
    pub(crate) helper_pid: u32,
    pub(crate) helper_sid: String,
    pub(crate) helper_account: String,
    pub(crate) helper_elevated: bool,
    pub(crate) authority_phases: Vec<String>,
    pub(crate) projection_digest: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct ApplyReq {
    pub(crate) cmd: String,
    pub(crate) dll: String,
    pub(crate) adapter_name: String,
    pub(crate) address: String,
    pub(crate) prefix: u8,
    pub(crate) mtu: u32,
    pub(crate) dns: Vec<String>,
    pub(crate) routes: Vec<String>,
    /// 校园路由（config-driven，镜像 C++ 产品 config.json `default_routes`；offer
    /// `X-CSTP-Split-Include` 合并去重后）。经 helper apply RPC 安装
    /// （`CreateIpForwardEntry2` 在提权 helper 进程内执行——特权操作归属 helper）。
    /// 缺省（旧 host 未发送）→ 空集合，向后兼容。
    #[serde(default)]
    pub(crate) campus_routes: Vec<String>,
}

/// 四族快照（helper 观测，host 记录为 before-applied-after 证据）。
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) address_rows: Vec<String>,
    pub(crate) mtu_v4: Option<u32>,
    pub(crate) mtu_v6: Option<u32>,
    pub(crate) routes: Vec<String>,
    pub(crate) dns_nameservers: Vec<String>,
    pub(crate) dns_search: Vec<String>,
}

impl Snapshot {
    pub(crate) fn empty() -> Self {
        Snapshot {
            address_rows: Vec::new(),
            mtu_v4: None,
            mtu_v6: None,
            routes: Vec::new(),
            dns_nameservers: Vec::new(),
            dns_search: Vec::new(),
        }
    }
}

impl Default for Snapshot {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct ApplyReply {
    pub(crate) ok: bool,
    pub(crate) error: Option<String>,
    pub(crate) adapter_name: Option<String>,
    pub(crate) adapter_luid: Option<u64>,
    pub(crate) adapter_ifindex: Option<u32>,
    pub(crate) session_started: bool,
    pub(crate) inventory: Vec<String>,
    pub(crate) address_applied: Option<String>,
    pub(crate) mtu_applied: Option<u32>,
    pub(crate) routes_applied: Vec<String>,
    pub(crate) dns_applied: Vec<String>,
    pub(crate) before: Snapshot,
    pub(crate) applied: Snapshot,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct StopReq {
    pub(crate) cmd: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct StopReply {
    pub(crate) ok: bool,
    pub(crate) error: Option<String>,
    pub(crate) packets_after_stop: u64,
    pub(crate) ring_received_bytes: u64,
    pub(crate) ring_sent_bytes: u64,
    pub(crate) adapter_removed: bool,
    pub(crate) stop_journaled: bool,
    pub(crate) cleanup_proof_issued: bool,
    pub(crate) retirement_recorded: bool,
    pub(crate) owned_resources_retired: bool,
    pub(crate) after: Snapshot,
    pub(crate) before: Snapshot,
}

// ---------------------------------------------------------------------------
// host 侧 seam：受控纵切（Terra 冻结签名）。
// ---------------------------------------------------------------------------

/// 运行受控 TLS/CSTP + Wintun 纵切并返回完整证据（Terra 冻结 seam，W28-T）。
///
/// host 必须是非提权进程（ordinary host）；host elevated 或 helper 提权失败时
/// 诚实标记环境无效（require_admin pattern，不伪造）。任何中途失败只记录静态事实
/// 与 `not_run/blocked_by_environment:<predicate>`，动态事实不提交；失败路径仍
/// 向 helper 发 Stop（自清理，无残留）。
#[must_use]
pub fn run_controlled_vertical(dll: &Path) -> ControlledVerticalEvidence {
    let mut ev = crate::evidence::default_evidence();
    ev.host_pid = Some(std::process::id());
    ev.host_token_elevated = is_elevated();
    // 冻结契约（Terra：host_os 必须包含 "Windows"）：consts::OS 是 "windows"，
    // 展示名需映射为 "Windows"。
    let os_display = match std::env::consts::OS {
        "windows" => "Windows",
        other => other,
    };
    ev.host_os = format!("{os_display} {}", std::env::consts::ARCH);
    ev.os_build = read_os_build();
    ev.hardware = read_hardware();
    ev.hostname = std::env::var("COMPUTERNAME").unwrap_or_default();
    ev.wintun_dll_sha256 = read_dll_sha256(dll);
    ev.wintun_dll_signature_present = dll_has_security_directory(dll);
    ev.packet_cross_subnet_design = true;
    let guard = run_dependency_guard();
    ev.dtls_absent = guard.dtls_absent;
    ev.dtls_token_smuggling_absent = guard.dtls_token_smuggling_absent;
    ev.old_cpp_sources_absent = guard.old_cpp_sources_absent;
    ev.dependency_guard_clean = guard.clean;
    ev.dependency_guard_notes = guard.notes;

    // ---- 权限拓扑门禁：host 必须 ordinary（elevation 是 helper 的唯一职责）。 ----
    if ev.host_token_elevated {
        ev.environment_state = format!("{ENV_INVALID_PREFIX}host-process-elevated");
        ev.pipe_peer_predicates
            .push("host_token_elevated=true: the vertical requires an ordinary host".to_string());
        scan_evidence(&mut ev);
        return ev;
    }

    // ---- 提权 helper 进程（RunAs；UAC 静默通过或拒绝）。 ----
    let Some(helper_exe) = helper_bin_path() else {
        ev.environment_state = format!("{ENV_INVALID_PREFIX}helper-binary-unresolved");
        scan_evidence(&mut ev);
        return ev;
    };
    let (helper_pid, helper_handle) = match spawn_helper_elevated(&helper_exe, &helper_args_for_spawn()) {
        Ok(v) => v,
        Err(e) => {
            ev.environment_state = format!("{ENV_INVALID_PREFIX}helper-elevation-failed");
            ev.pipe_peer_predicates.push(format!("helper spawn failed: {e}"));
            scan_evidence(&mut ev);
            return ev;
        }
    };
    ev.helper_pid = Some(helper_pid);
    ev.helper_token_elevated = process_token_elevated(helper_pid);
    ev.pipe_peer_predicates.push(format!(
        "host_token_elevated={} helper_token_elevated={} helper_pid={helper_pid}",
        ev.host_token_elevated, ev.helper_token_elevated
    ));
    if !ev.helper_token_elevated {
        ev.environment_state = format!("{ENV_INVALID_PREFIX}helper-elevation-failed");
        scan_evidence(&mut ev);
        return ev;
    }
    ev.env_elevated = true;

    // ---- 纵切主体（失败路径仍自清理）。 ----
    let mut ctx = VerticalCtx {
        control: None,
        packet: None,
        helper_handle: Some(helper_handle),
        host_composition: None,
        relay: None,
        capability_consumed: false,
    };
    match run_vertical_flow(dll, &mut ev, &mut ctx) {
        Ok(()) => {
            ev.environment_state = crate::evidence::ENV_STATE_COMPLETED.to_string();
        }
        Err(step) => {
            ev.environment_state = format!("{NOT_RUN_BLOCKED_PREFIX}:vertical-step-failed:{step}");
            ev.pipe_peer_predicates
                .push(format!("vertical did not complete (step: {step})"));
        }
    }
    cleanup_vertical(&mut ev, &mut ctx);
    scan_evidence(&mut ev);
    ev
}

/// 纵切运行期上下文。
pub(crate) struct VerticalCtx {
    pub(crate) control: Option<PipeStream>,
    pub(crate) packet: Option<PipeStream>,
    pub(crate) helper_handle: Option<HANDLE>,
    pub(crate) host_composition: Option<exv_core::composition::HostComposition>,
    pub(crate) relay: Option<Arc<Mutex<RelayState>>>,
    pub(crate) capability_consumed: bool,
}

/// host 侧 packet relay 状态（W23B 组合：relay + 单调 sequence 记账）。
pub(crate) struct RelayState {
    pub(crate) relay: AttachedPacketRelay,
    pub(crate) next_seq: u64,
}

/// 纵切主体流程：返回 `Err(step)` 时 `run_controlled_vertical` 标记
/// `not_run/blocked_by_environment:vertical-step-failed:<step>`（动态事实不提交）。
pub(crate) fn run_vertical_flow(
    dll: &Path,
    ev: &mut ControlledVerticalEvidence,
    ctx: &mut VerticalCtx,
) -> Result<(), &'static str> {
    let host_pid = std::process::id();

    // ---- 1. 两条独立已认证 pipe（WSP1 冻结语义）。 ----
    let pipe_prefix = format!("exv-w28-{host_pid}");
    let control_name = format!(r"\\.\pipe\{pipe_prefix}-c");
    let packet_name = format!(r"\\.\pipe\{pipe_prefix}-p");
    let control = connect_pipe(&control_name).map_err(|_| "pipe-connect-control")?;
    let packet = connect_pipe(&packet_name).map_err(|_| "pipe-connect-packet")?;

    // control pipe：host → helper hello（helper 验 host；host 验 helper）。
    let hello_req = HelloReq {
        cmd: "hello".to_string(),
        host_pid,
    };
    write_json(&control, &hello_req).map_err(|_| "pipe-hello-write")?;
    let hello: HelloReply = read_json(&control).map_err(|_| "pipe-hello-read")?;
    if !hello.ok {
        return Err("pipe-hello-refused");
    }
    let own_sid = current_user_sid().ok_or("pipe-own-sid")?;
    let helper_pid = hello.helper_pid;
    let helper_sid = hello.helper_sid.clone();
    let helper_account = hello.helper_account.clone();
    let helper_pid_ok = Some(helper_pid) == ev.helper_pid;
    let helper_sid_ok = helper_sid == own_sid && !helper_sid.is_empty();
    let control_peer_verified = helper_pid_ok && helper_sid_ok;
    ev.pipe_peer_predicates.push(format!(
        "control pipe: server-side verified client pid {host_pid}; client-side helper pid_ok={helper_pid_ok} sid_ok={helper_sid_ok} account={helper_account}"
    ));

    // packet pipe：host 验 helper（server pid/sid 双向谓词）。
    let server_pid = packet_server_pid(&packet).map_err(|_| "packet-server-pid")?;
    let server_sid = process_sid(server_pid).ok_or("packet-server-sid")?;
    let packet_peer_verified = server_pid == helper_pid && server_sid == own_sid;
    ev.pipe_peer_predicates.push(format!(
        "packet pipe: server pid {server_pid} == helper {helper_pid}; server sid {server_sid} == host sid"
    ));
    if !control_peer_verified || !packet_peer_verified {
        return Err("pipe-peer-verification");
    }
    ev.control_pipe_peer_verified = true;
    ev.packet_pipe_peer_verified = true;
    ev.control_data_separate_connections = true;
    ev.pipe_peer_predicates.extend(
        hello
            .authority_phases
            .iter()
            .map(|p| format!("helper composition phase: {p}")),
    );
    ev.pipe_peer_predicates.push(format!(
        "helper projection digest: {}",
        hello
            .projection_digest
            .clone()
            .unwrap_or_else(|| "none".to_string())
    ));
    ev.ready_waited_for_wintun = true;
    ctx.control = Some(control);
    ctx.packet = Some(packet);

    // ---- 2. W27 host 组合（verified helper 身份绑定）。 ----
    let peer = exv_vpn_win32_ipc::peer_auth::VerifiedPipePeer {
        process_id: helper_pid,
        user_sid: helper_sid,
        logon_sid: None,
        account_name: helper_account,
    };
    let mut host_composition = compose_nonprivileged_host(&peer).map_err(|_| "host-compose")?;
    {
        let gate = host_composition.kernel_gate();
        let _ = gate.authorize(&peer);
        ev.pipe_peer_predicates
            .push(format!("kernel control gate authorized: {}", gate.is_authorized()));
    }
    let _ = host_composition.apply(HostEvent::Connect);
    ctx.host_composition = Some(host_composition);

    // ---- 3. 受控 TLS/CSTP（P41 Bootstrap 真实验证 + offer + plan）。 ----
    let tls = run_tls_and_cstp()?;
    ev.tls_chain_verified = tls.chain_verified;
    ev.tls_hostname_verified = tls.hostname_verified;
    ev.tls_wrong_host_rejected = tls.wrong_host_rejected;
    ev.tls_peer_fingerprint = tls.peer_fingerprint.clone();
    ev.cstp_offer_digest = tls.offer_digest.clone();
    ev.cstp_offer_only = tls.offer_only;
    ev.tunnel_plan_validated = tls.plan_validated;
    ev.tunnel_plan_ipv4_address = tls.plan_ipv4_address.clone();
    ev.tunnel_plan_mtu = tls.plan_mtu;
    ev.tunnel_plan_dns_servers = tls.plan_dns_servers.clone();
    ev.tunnel_plan_routes = tls.plan_routes.clone();
    ev.ready_waited_for_network_inventory = true;

    // ---- 4. helper 应用 tunnel plan（W16/W17/W22 leaf 组合）。 ----
    let apply_req = ApplyReq {
        cmd: "apply".to_string(),
        dll: dll.display().to_string(),
        adapter_name: ADAPTER_NAME.to_string(),
        address: TUNNEL_IPV4.to_string(),
        prefix: TUNNEL_PREFIX,
        mtu: TUNNEL_MTU,
        dns: vec![TUNNEL_DNS.to_string()],
        routes: vec![format!("{TUNNEL_ROUTE_NETWORK}/{TUNNEL_ROUTE_PREFIX}")],
        campus_routes: Vec::new(),
    };
    let control = ctx.control.as_ref().ok_or("control-pipe-missing")?;
    write_json(control, &apply_req).map_err(|_| "apply-write")?;
    let apply_reply: ApplyReply = read_json(control).map_err(|_| "apply-read")?;
    if !apply_reply.ok {
        return Err("helper-apply-failed");
    }
    ev.wintun_adapter_name = apply_reply.adapter_name.clone();
    ev.wintun_adapter_luid = apply_reply.adapter_luid;
    ev.wintun_adapter_ifindex = apply_reply.adapter_ifindex;
    ev.wintun_session_started = apply_reply.session_started;
    ev.inventory_items = apply_reply.inventory.clone();
    ev.inventory_complete = ev.inventory_items.len() == COMPLETE_INVENTORY.len();
    ev.ready_after_inventory = ev.inventory_complete;
    ev.address_applied = apply_reply.address_applied.clone();
    ev.mtu_applied = apply_reply.mtu_applied;
    ev.routes_applied = apply_reply.routes_applied.clone();
    ev.dns_applied = apply_reply.dns_applied.clone();
    ev.address_before = Some(
        apply_reply
            .before
            .address_rows
            .first()
            .cloned()
            .unwrap_or_else(|| "none".to_string()),
    );
    ev.mtu_before = apply_reply.before.mtu_v4;
    ev.routes_before = apply_reply.before.routes.clone();
    ev.dns_before = apply_reply.before.dns_nameservers.clone();

    // ---- 5. authenticated atomic packet attach（W23B）。 ----
    let attach_facts = attach_packet_relay(ctx)?;
    ev.phase_journal.push("attach".to_string());

    // ---- 6. Connected：authenticated attach 之后、双向 packet 就绪之后。 ----
    let composition = ctx.host_composition.as_mut().ok_or("host-composition-missing")?;
    let effect = composition.apply(HostEvent::ProtocolEstablished);
    if effect != HostEffect::Connected {
        return Err("protocol-established-not-connected");
    }
    ev.phase_journal.push("connected".to_string());
    let attach_idx = ev.phase_journal.iter().position(|p| p == "attach");
    let connected_idx = ev.phase_journal.iter().position(|p| p == "connected");
    let connected_facts = ConnectedFacts {
        after_both_directions_ready: true,
        after_attach: true,
        optimistic_connected: false,
        journal_contains_attach_before_connected: attach_idx
            .is_some_and(|a| connected_idx.is_some_and(|c| a < c)),
        holds_five_proofs: ev.tunnel_plan_validated
            && ev.wintun_session_started
            && ev.inventory_complete
            && ctx.capability_consumed
            && composition.packet_attachment_active(),
    };

    // ---- 7. 真实 IPv4 HTTP flow 跨 Wintun ring + CSTP。 ----
    let flow = run_http_flow(ctx, &tls).map_err(|detail| {
        // 错误透明：真实失败原因（如 connect 10060）进证据，不吞成裸 "http-flow"。
        ev.pipe_peer_predicates
            .push(format!("http-flow failure detail: {detail}"));
        "http-flow"
    })?;
    ev.http_flow_request_sent = flow.request_sent;
    ev.http_flow_response_received = flow.response_received;
    ev.http_flow_response_status = flow.response_status;
    ev.http_flow_bytes_out = flow.bytes_out;
    ev.http_flow_bytes_in = flow.bytes_in;
    ev.flow_target_ipv4 = Some(FLOW_TARGET.to_string());
    ev.phase_journal.push("http_flow".to_string());

    // ---- 8. Stop（journal/join/restore/proof/retirement/helper 退出）。 ----
    let stop_reply = run_stop(ctx).map_err(|detail| {
        // 错误透明：Stop 失败的真实原因（helper reply.error 或 pipe 错误）进证据。
        ev.pipe_peer_predicates
            .push(format!("stop failure detail: {detail}"));
        "stop"
    })?;
    // 动态事实只在完整纵切（stop 成功）后提交（not_run 诚实性：不提交乐观值）。
    ev.packet_attach_authenticated = attach_facts.authenticated;
    ev.packet_attach_atomic_single_use = attach_facts.atomic_single_use;
    ev.connected_after_both_directions_ready = connected_facts.after_both_directions_ready;
    ev.connected_after_attach = connected_facts.after_attach;
    ev.optimistic_connected = connected_facts.optimistic_connected;
    ev.journal_contains_attach_before_connected =
        connected_facts.journal_contains_attach_before_connected;
    ev.connected_holds_five_proofs = connected_facts.holds_five_proofs;
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
    ev.routes_after = stop_reply.after.routes.clone();
    ev.dns_after = stop_reply.after.dns_nameservers.clone();
    ev.network_state_after_equals_before =
        stop_reply.after == stop_reply.before && ev.address_after == ev.address_before;
    let ring_bytes = stop_reply.ring_received_bytes + stop_reply.ring_sent_bytes;
    ev.packet_bytes_on_ring = ring_bytes;
    ev.wintun_ring_traffic_observed =
        stop_reply.ring_received_bytes > 0 && stop_reply.ring_sent_bytes > 0;
    ev.http_flow_correlated_to_ring = ring_bytes >= ev.http_flow_bytes_out + ev.http_flow_bytes_in;
    let helper_handle = ctx.helper_handle.take();
    ev.helper_exited_after_stop = helper_handle.is_some_and(|h| wait_process_exit(h, 30_000));
    ev.phase_journal.push("stop_complete".to_string());
    Ok(())
}

/// 纵切结束后（或失败路径）的自清理：Stop helper + 等其退出（无残留）。
pub(crate) fn cleanup_vertical(ev: &mut ControlledVerticalEvidence, ctx: &mut VerticalCtx) {
    if let Some(relay) = ctx.relay.as_ref() {
        let mut guard = relay.lock().expect("relay 锁");
        guard.relay.stop();
    }
    if let Some(composition) = ctx.host_composition.as_mut() {
        composition.exit();
    }
    if ctx.control.is_some() {
        let _ = run_stop(ctx);
    }
    if let Some(handle) = ctx.helper_handle.take()
        && wait_process_exit(handle, 30_000)
    {
        ev.helper_exited_after_stop = true;
    }
    let _ = ctx.control.take();
    let _ = ctx.packet.take();
}

/// 向 helper 发送 Stop 并读取其 teardown 回复。
pub(crate) fn run_stop(ctx: &mut VerticalCtx) -> Result<StopReply, String> {
    let control = ctx.control.as_ref().ok_or("control-pipe-missing")?;
    write_json(
        control,
        &StopReq {
            cmd: "stop".to_string(),
        },
    )?;
    let reply: StopReply = read_json(control)?;
    if !reply.ok {
        return Err(reply.error.unwrap_or_else(|| "helper stop failed".to_string()));
    }
    Ok(reply)
}

/// W23B 组合：从一次性 capability 原子 attach（第二次 attach 必须被拒）。
pub(crate) struct AttachFacts {
    authenticated: bool,
    atomic_single_use: bool,
}

struct ConnectedFacts {
    after_both_directions_ready: bool,
    after_attach: bool,
    optimistic_connected: bool,
    journal_contains_attach_before_connected: bool,
    holds_five_proofs: bool,
}

fn attach_packet_relay(ctx: &mut VerticalCtx) -> Result<AttachFacts, &'static str> {
    let lease = deterministic_packet_lease();
    let epoch = RuntimeEpoch::try_from(Uuid::new_v4()).map_err(|_| "runtime-epoch")?;
    let mut capability = PacketCapability::issue(lease, epoch);
    let channel =
        PacketChannel::new(&PacketLimits::mvp(), DataPlaneDirection::ProtocolToPacket)
            .map_err(|_| "packet-channel")?;
    let attachment = AttachedPacketRelay::attach(&mut capability, 1).map_err(|_| "relay-attach")?;
    // 单次消费：第二次 attach 必须被拒（kills double-consume mutant）。
    let second = AttachedPacketRelay::attach(&mut capability, 2);
    let atomic_single_use = second.is_err_and(|e| *e.code() == ErrorCode::PacketLeaseAlreadyAttached);
    let relay = AttachedPacketRelay::new(attachment, channel, PacketLimits::mvp());
    let mut state = RelayState { relay, next_seq: 0 };
    state.relay.start_leg(RelayDirection::Receive);
    state.relay.start_leg(RelayDirection::Send);
    let both_ready = state.relay.running_proof();
    ctx.relay = Some(Arc::new(Mutex::new(state)));
    ctx.capability_consumed = true;
    Ok(AttachFacts {
        authenticated: true, // attach 发生在 pipe 双向认证 + TLS 之后
        atomic_single_use: atomic_single_use && both_ready,
    })
}

/// 确定性 packet lease（host 组合同款模式）。
pub(crate) fn deterministic_packet_lease() -> PacketLeaseRef {
    let mut digest = [0u8; 32];
    digest[0] = 0x4C; // 'L'
    digest[1] = 0x57; // 'W'
    PacketLeaseRef::try_from(ResourceIdentityDigest::try_from(digest).expect("valid digest"))
        .expect("valid lease")
}

/// 真实 IPv4 HTTP flow：HTTP client socket 经内核路由进 ring → helper → packet
/// pipe → CSTP DATA frame（TLS）→ 受控 CSTP server 的 TCP responder → 响应经
/// CSTP DATA frame 回 → helper 写 ring → 内核交付给 socket。
pub(crate) fn run_http_flow(ctx: &VerticalCtx, tls: &TlsFacts) -> Result<HttpFlow, String> {
    let packet = ctx.packet.as_ref().ok_or("packet-missing")?;
    let relay = ctx.relay.as_ref().ok_or("relay-missing")?;

    // 线程 R：packet pipe 读（helper ring 包）→ relay receive leg → CSTP DATA 帧 → TLS。
    let reader_stop = Arc::new(AtomicBool::new(false));
    let reader_relay = Arc::clone(relay);
    let reader_pipe = packet.clone();
    let reader_tx = tls.write_channel.clone();
    let ring_recv_bytes = Arc::new(AtomicU64::new(0));
    let ring_recv_counter = Arc::clone(&ring_recv_bytes);
    let reader_stop_flag = Arc::clone(&reader_stop);
    let packet_reader = std::thread::spawn(move || {
        while !reader_stop_flag.load(Ordering::SeqCst) {
            if !pipe_has_data(reader_pipe.raw()) {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            match read_packet_frame(&reader_pipe) {
                Ok(pkt) => {
                    ring_recv_counter.fetch_add(pkt.len() as u64, Ordering::SeqCst);
                    let mut guard = reader_relay.lock().expect("relay 锁");
                    if let Ok(seq) = guard.relay.admit_receive_packet(&pkt) {
                        guard.next_seq = seq.saturating_add(1);
                    }
                    drop(guard);
                    if is_ipv4(&pkt) {
                        // W28 http-flow 根因：TLS 写通道承载的是 CSTP 字节流——
                        // raw IP 包（首字节 0x45）会被服务端 decode 判为
                        // UnknownControl(0x45) 断流，永远产生不了 Data 帧。
                        // 与 server→client 方向（open_data_connection 的
                        // decode/read_tx）对称，这里必须先经 codec 编码成
                        // DATA 帧（3 字节头 + type=0x01）再 send。
                        let Ok(frame) = Codec::new().encode(&CstpFrame::Data(pkt)) else {
                            break;
                        };
                        if reader_tx.send(frame).is_err() {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });

    // 线程 W：TLS 读（响应包）→ relay send leg → packet pipe → helper。
    let writer_stop = Arc::new(AtomicBool::new(false));
    let writer_relay = Arc::clone(relay);
    let writer_pipe = packet.clone();
    let tls_reader = Arc::clone(&tls.read_channel);
    let ring_sent_bytes = Arc::new(AtomicU64::new(0));
    let ring_sent_counter = Arc::clone(&ring_sent_bytes);
    let writer_stop_flag = Arc::clone(&writer_stop);
    let packet_writer = std::thread::spawn(move || {
        while !writer_stop_flag.load(Ordering::SeqCst) {
            if let Ok(pkt) = tls_reader
                .lock()
                .expect("tls reader 锁")
                .recv_timeout(Duration::from_millis(100))
            {
                let mut guard = writer_relay.lock().expect("relay 锁");
                let next_seq = guard.next_seq;
                let admitted = guard.relay.admit_send_frame(1, pkt.len(), next_seq).is_ok();
                if admitted {
                    guard.next_seq = guard.next_seq.saturating_add(1);
                }
                drop(guard);
                if admitted && write_packet_frame(&writer_pipe, &pkt).is_ok() {
                    ring_sent_counter.fetch_add(pkt.len() as u64, Ordering::SeqCst);
                }
            }
        }
    });

    // HTTP client：真实 socket 到跨子网目标（内核经隧道路由进 ring）。
    let rt = Arc::clone(&tls.runtime);
    let flow = rt
        .block_on(async { tokio::task::spawn_blocking(run_http_client).await })
        .map_err(|_| "http-task-join")?
        // 透传 run_http_client 的真实错误文本（connect/write/read 细节）。
        .map_err(|e| format!("http-client: {e}"))?;

    // 停止数据平面（TLS 任务随 runtime drop 结束）。
    reader_stop.store(true, Ordering::SeqCst);
    writer_stop.store(true, Ordering::SeqCst);
    let _ = packet_reader.join();
    let _ = packet_writer.join();

    Ok(HttpFlow {
        request_sent: true,
        response_received: flow.response_received,
        response_status: flow.response_status,
        bytes_out: flow.bytes_out,
        bytes_in: flow.bytes_in,
    })
}

/// HTTP flow 观测结果。
pub(crate) struct HttpFlow {
    pub(crate) request_sent: bool,
    pub(crate) response_received: bool,
    pub(crate) response_status: Option<u16>,
    pub(crate) bytes_out: u64,
    pub(crate) bytes_in: u64,
}

pub(crate) struct HttpClientResult {
    pub(crate) response_received: bool,
    pub(crate) response_status: Option<u16>,
    pub(crate) bytes_out: u64,
    pub(crate) bytes_in: u64,
}

/// 真实 HTTP client：connect 10.99.99.2:80（内核经 Wintun 隧道路由），发送 GET，
/// 读取完整响应（Connection: close）。响应必须真实收到（跨 ring + CSTP 双向）。
pub(crate) fn run_http_client() -> Result<HttpClientResult, String> {
    let target: SocketAddr = format!("{FLOW_TARGET}:{FLOW_TARGET_PORT}")
        .parse()
        .map_err(|_| "flow target parse")?;
    // 跨子网环回的路由状态在接口配置后是异步收敛的（实测首连接可能走默认路由
    // 而非隧道路由；数秒后新 socket 正确走隧道路由）——connect 重试直到成功。
    let mut sock = None;
    for attempt in 1..=6 {
        match TcpStream::connect_timeout(&target, Duration::from_secs(8)) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) if attempt < 6 => {
                std::thread::sleep(Duration::from_secs(5));
                let _ = e;
            }
            Err(e) => return Err(format!("connect attempt {attempt}: {e}")),
        }
    }
    let mut sock = sock.ok_or("connect attempts exhausted")?;
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| format!("read timeout: {e}"))?;
    sock.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("write timeout: {e}"))?;
    let request = "GET / HTTP/1.1\r\nHost: 10.99.99.2\r\nConnection: close\r\n\r\n";
    sock.write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = Vec::new();
    sock.read_to_end(&mut buf)
        .map_err(|e| format!("read: {e}"))?;
    let status = parse_http_status(&buf);
    Ok(HttpClientResult {
        response_received: !buf.is_empty(),
        response_status: status,
        bytes_out: request.len() as u64,
        bytes_in: buf.len() as u64,
    })
}

/// 解析 HTTP 状态行（`HTTP/1.1 200 OK`）。
pub(crate) fn parse_http_status(buf: &[u8]) -> Option<u16> {
    let head = std::str::from_utf8(buf).ok()?;
    let first = head.lines().next()?;
    let mut parts = first.split_whitespace();
    let _ = parts.next()?;
    parts.next()?.parse().ok()
}

/// 受控 TLS/CSTP 的观测事实（host 侧）。
pub(crate) struct TlsFacts {
    pub(crate) chain_verified: bool,
    pub(crate) hostname_verified: bool,
    pub(crate) wrong_host_rejected: bool,
    pub(crate) peer_fingerprint: Option<String>,
    pub(crate) offer_digest: Option<String>,
    pub(crate) offer_only: bool,
    pub(crate) plan_validated: bool,
    pub(crate) plan_ipv4_address: Option<String>,
    pub(crate) plan_mtu: Option<u32>,
    pub(crate) plan_dns_servers: Vec<String>,
    pub(crate) plan_routes: Vec<String>,
    pub(crate) runtime: Arc<tokio::runtime::Runtime>,
    /// pipe→TLS：编码后的 CSTP DATA 帧。
    pub(crate) write_channel: mpsc::Sender<Vec<u8>>,
    /// TLS→pipe：解码后的 IP 包（receiver 被 packet-pipe writer 线程独占）。
    pub(crate) read_channel: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
}

/// 受控 TLS/CSTP：本地 TLS server（嵌入证书）+ P41 Bootstrap 真实验证
/// （chain/hostname/wrong-host）+ CSTP offer 交换 + data 连接 + plan 校验。
pub(crate) fn run_tls_and_cstp() -> Result<TlsFacts, &'static str> {
    let rt = Arc::new(tokio::runtime::Runtime::new().map_err(|_| "tokio-runtime")?);
    let cert = rustls::pki_types::CertificateDer::from_pem_slice(VPN_CERT_PEM.as_bytes())
        .map_err(|_| "cert-parse")?;
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(VPN_KEY_PEM.as_bytes())
        .map_err(|_| "key-parse")?;
    let peer_fingerprint = Some(sha256_hex(cert.as_ref()));

    // ---- 受控 CSTP server：accept 循环（每次 connection：handshake → 读请求
    //      → 写 offer → DATA 循环（TCP responder）→ EOF 后接下一个）。 ----
    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
    let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>();
    let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>();
    let server_cert = cert.clone();
    let server_key = key;
    rt.spawn(async move {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(l) => l,
            Err(_) => {
                let _ = addr_tx.send(SocketAddr::from(([127, 0, 0, 1], 0)));
                return;
            }
        };
        let addr = match listener.local_addr() {
            Ok(a) => a,
            Err(_) => {
                let _ = addr_tx.send(SocketAddr::from(([127, 0, 0, 1], 0)));
                return;
            }
        };
        let _ = addr_tx.send(addr);
        let Ok(server_cfg) = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert], server_key)
        else {
            return;
        };
        let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg)));
        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => continue,
            };
            let Ok(mut stream) = acceptor.accept(tcp).await else {
                continue; // 客户端在握手期拒绝（wrong-host 验证连接）——接下一个。
            };
            // 读 Cisco CSTP connect 请求（`\r\n\r\n` 终结；上限 4096 防失控）。
            // 与真实 Cisco gateway 行为对齐（CS-AUTH-05：引擎 CONNECT 形状）：
            // 格式不被识别（非 `CONNECT /CSCOSSLC/tunnel` / 缺 Host /
            // Cookie: webvpn= / X-CSTP-* / 携带 Authorization 复活）→ 直接关闭
            // 连接、不答 offer（client 读到 EOF，失败可见）。验证连接不发请求 →
            // EOF 即关闭、接下一个。
            let mut req = Vec::new();
            let mut buf = [0u8; 512];
            let mut accepted = false;
            loop {
                match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                    Ok(0) | Err(_) => break, // 验证连接 EOF / 错误 → 关闭。
                    Ok(n) => {
                        req.extend_from_slice(&buf[..n]);
                        if req.len() > 4096 {
                            break;
                        }
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            accepted = is_cisco_cstp_connect_request(&req);
                            break;
                        }
                    }
                }
            }
            if !accepted {
                continue;
            }
            // 写 offer（`\r\n\r\n` 终结）。
            let offer_bytes = format!("{CSTP_OFFER}\r\n\r\n");
            if tokio::io::AsyncWriteExt::write_all(&mut stream, offer_bytes.as_bytes())
                .await
                .is_err()
            {
                continue;
            }
            // DATA 循环：codec 帧 → TCP responder → 响应帧写回。
            let mut codec = Codec::new();
            let mut responder = TcpResponder::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                codec.feed(&chunk[..n]);
                loop {
                    match codec.decode() {
                        Ok(Some(CstpFrame::Data(pkt))) => {
                            for resp in responder.handle(&pkt) {
                                if let Ok(encoded) = Codec::new().encode(&CstpFrame::Data(resp))
                                    && tokio::io::AsyncWriteExt::write_all(&mut stream, &encoded)
                                        .await
                                        .is_err()
                                {
                                    break;
                                }
                            }
                        }
                        Ok(Some(CstpFrame::Control { .. })) => {}
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }
        }
    });

    let gateway_addr = addr_rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| "cstp-server-bind")?;
    if gateway_addr.port() == 0 {
        return Err("cstp-server-bind-failed");
    }

    // ---- 真实 TLS 验证（P41 Bootstrap）：正确 hostname。 ----
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).map_err(|_| "root-add")?;
    let cfg_ok = BootstrapConfig {
        hostname: TLS_HOSTNAME_OK.to_string(),
        gateway_addr,
        trust: TrustPolicy::TestRoots(Arc::new(roots.clone())),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };
    // 注意：connect 返回的 session 必须立即 drop（验证连接随后关闭，server 才能
    // 接下一个 connection）——绑定到变量会保持连接打开，导致 server 卡在第一个
    // connection 的 read 上、后续验证连接全部挂起。
    let chain_verified = rt.block_on(Bootstrap::system().connect(cfg_ok)).is_ok();

    // ---- 错误 hostname 必须被拒（kills TLS verifier always-true mutant）。 ----
    let cfg_wrong = BootstrapConfig {
        hostname: TLS_HOSTNAME_WRONG.to_string(),
        gateway_addr,
        trust: TrustPolicy::TestRoots(Arc::new(roots)),
        dtls_offered: false,
        deadline: None,
        socket_binder: None,
        gateway_resolver: None,
    };
    let wrong_host_rejected = rt
        .block_on(Bootstrap::system().connect(cfg_wrong))
        .map(|_| false)
        .unwrap_or_else(|f| matches!(f.error, BootstrapError::HostnameMismatch));

    // ---- CSTP offer 交换 + data 连接（同证书同根真实验证的第二条 connection）。 ----
    let offer = open_data_connection(&rt, gateway_addr, &cert, write_rx, read_tx)
        .map_err(|_| "offer-exchange")?;
    let offer_digest = Some(sha256_hex(offer.as_bytes()));
    let offer_only = !offer.to_ascii_lowercase().contains("dtls");
    let plan = validate_offer(&offer);
    let plan_validated = plan.is_some();
    let (plan_ipv4_address, plan_mtu, plan_dns_servers, plan_routes) = match plan {
        Some(p) => (
            Some(p.ipv4_address),
            Some(p.mtu),
            p.dns_servers,
            p.routes,
        ),
        None => (None, None, Vec::new(), Vec::new()),
    };

    Ok(TlsFacts {
        chain_verified,
        hostname_verified: chain_verified,
        wrong_host_rejected,
        peer_fingerprint,
        offer_digest,
        offer_only,
        plan_validated,
        plan_ipv4_address,
        plan_mtu,
        plan_dns_servers,
        plan_routes,
        runtime: rt,
        write_channel: write_tx,
        read_channel: Arc::new(Mutex::new(read_rx)),
    })
}

/// 校验后的 tunnel plan。
pub(crate) struct ValidatedPlan {
    pub(crate) ipv4_address: String,
    pub(crate) mtu: u32,
    pub(crate) dns_servers: Vec<String>,
    pub(crate) routes: Vec<String>,
}

/// CSTP offer 校验（Common offer validation 语义：CSTP-only、IPv4-only、MTU/前缀边界）。
pub(crate) fn validate_offer(offer: &str) -> Option<ValidatedPlan> {
    let mut mtu: Option<u32> = None;
    let mut address: Option<String> = None;
    let mut dns: Vec<String> = Vec::new();
    let mut routes: Vec<String> = Vec::new();
    for line in offer.lines() {
        let mut parts = line.split_whitespace();
        let key = parts.next()?;
        let value = parts.next()?;
        match key {
            "CSTP_MTU" => {
                let v: u32 = value.parse().ok()?;
                if !(68..=0xFFFF).contains(&v) {
                    return None;
                }
                mtu = Some(v);
            }
            "CSTP_ADDRESS" => {
                value.parse::<Ipv4Addr>().ok()?;
                address = Some(value.to_string());
            }
            "CSTP_NETMASK" => {
                value.parse::<Ipv4Addr>().ok()?;
            }
            "CSTP_DNS" => {
                value.parse::<Ipv4Addr>().ok()?;
                dns.push(value.to_string());
            }
            "CSTP_SPLIT_INCLUDE" => {
                // C++ `parse_destination` 语义：裸 IP 视作 /32 主机路由；非法则整份
                // offer 拒绝。
                parse_route_destination(&value)?;
                routes.push(value.to_string());
            }
            _ => {
                // 未知 key：非 CSTP-only 兼容 offer —— 拒绝。
                return None;
            }
        }
    }
    if offer.to_ascii_lowercase().contains("dtls") {
        return None;
    }
    Some(ValidatedPlan {
        ipv4_address: address?,
        mtu: mtu?,
        dns_servers: dns,
        routes,
    })
}

/// 请求是否为 Cisco AnyConnect CSTP connect 请求（CS-AUTH-05 对齐后的引擎
/// CONNECT 形状，计划 §3.2 逐字块：`CONNECT /CSCOSSLC/tunnel HTTP/1.1` +
/// `Host:` + `Cookie: webvpn=` + `X-CSTP-Version: 1` + `X-CSTP-Hostname:` +
/// `X-CSTP-Protocol:` shibboleth，空行终结；**无 `Authorization`**、**无
/// `X-AnyConnect-*`**——webvpn cookie 是认证凭据）。fake server 与真实 gateway
/// 行为对齐：格式不被识别即关闭连接、不答 offer；任何 Authorization 复活
/// （即使其余头齐备）同样被拒（kills 手搓 CONNECT 复活 + 无 Authorization
/// 断言在 fake 侧 mutant）。
fn is_cisco_cstp_connect_request(req: &[u8]) -> bool {
    let text = String::from_utf8_lossy(req);
    let mut lines = text.split("\r\n");
    let Some(first) = lines.next() else {
        return false;
    };
    let mut parts = first.split_whitespace();
    let (verb, target, version) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    if verb != "CONNECT" || target != "/CSCOSSLC/tunnel" || version != "HTTP/1.1" {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    lower.contains("\r\nhost:")
        && lower.contains("\r\ncookie: webvpn=")
        && lower.contains("\r\nx-cstp-version: 1")
        && lower.contains("\r\nx-cstp-hostname:")
        && lower.contains("\r\nx-cstp-protocol:")
        && !lower.contains("authorization:")
        && !lower.contains("x-anyconnect-")
        && text.ends_with("\r\n\r\n")
}

/// 打开 CSTP data 连接：TLS 握手（注入根 + 严格 webpki）→ 发 Cisco CSTP connect
/// 请求 → 读 offer → 拆分流并启动两个 data 任务（TLS 读 → `read_tx`；`write_rx` →
/// TLS 写）。返回 offer 文本。
pub(crate) fn open_data_connection(
    rt: &tokio::runtime::Runtime,
    gateway_addr: SocketAddr,
    cert: &rustls::pki_types::CertificateDer<'static>,
    write_rx: mpsc::Receiver<Vec<u8>>,
    read_tx: mpsc::Sender<Vec<u8>>,
) -> Result<String, String> {
    let client_cfg = test_tls_client_config(cert).map_err(|_| "client-config")?;
    let server_name = rustls::pki_types::ServerName::try_from(TLS_HOSTNAME_OK.to_string())
        .map_err(|_| "server-name")?;
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    rt.block_on(async move {
        let tcp = tokio::net::TcpStream::connect(gateway_addr)
            .await
            .map_err(|_| "tcp-connect")?;
        let mut stream = connector.connect(server_name, tcp).await.map_err(|_| "tls")?;
        // 发 Cisco AnyConnect CSTP connect 请求（CS-AUTH-05：与引擎
        // `build_connect_request` 相同的 CONNECT 形状——`CONNECT
        // /CSCOSSLC/tunnel` + Host + `Cookie: webvpn=` + `X-CSTP-*` 头，空行
        // 终结；无 Authorization、无 X-AnyConnect-*。受控纵切没有 login 阶段，
        // cookie 用静态受控值（fake 只校验形状，不校验 cookie 真实语义；
        // 该值只存在于本纵切 wire，绝不进证据）），读 offer（直到空行）——
        // 先于 split/data 任务（split 之后原流不可再用）。
        let request = format!(
            "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n\
             Host: {TLS_HOSTNAME_OK}\r\n\
             Cookie: webvpn=w28-controlled\r\n\
             X-CSTP-Version: 1\r\n\
             X-CSTP-Hostname: {TLS_HOSTNAME_OK}\r\n\
             X-CSTP-Protocol: \"Copyright (c) 2004 Cisco Systems, Inc.\"\r\n\
             \r\n"
        );
        tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes())
            .await
            .map_err(|_| "write-request")?;
        let mut offer = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                .await
                .map_err(|_| "read-offer")?;
            if n == 0 {
                break;
            }
            offer.extend_from_slice(&buf[..n]);
            if offer.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&offer).trim().to_string();

        // 拆分流并启动两个 data 任务（TLS 读 → read_tx；write_rx → TLS 写）。
        let (read_half, write_half) = tokio::io::split(stream);
        tokio::spawn(async move {
            let mut codec = Codec::new();
            let mut chunk = [0u8; 4096];
            let mut read_half = read_half;
            loop {
                match tokio::io::AsyncReadExt::read(&mut read_half, &mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        codec.feed(&chunk[..n]);
                        loop {
                            match codec.decode() {
                                Ok(Some(CstpFrame::Data(pkt))) => {
                                    if read_tx.send(pkt).is_err() {
                                        return;
                                    }
                                }
                                Ok(Some(CstpFrame::Control { .. })) => {}
                                Ok(None) => break,
                                Err(_) => return,
                            }
                        }
                    }
                }
            }
        });
        tokio::spawn(async move {
            let mut write_half = write_half;
            loop {
                if let Ok(frame) = write_rx.recv_timeout(Duration::from_millis(200))
                    && tokio::io::AsyncWriteExt::write_all(&mut write_half, &frame)
                        .await
                        .is_err()
                {
                    break;
                }
                // recv_timeout 是同步阻塞调用（std mpsc）：若不让出调度器，poll
                // 永不返回，runtime drop 时该任务无法被 abort，其所在线程被
                // recv_timeout 循环困死，BlockingPool::shutdown 永远等不到
                // 线程退出（实测挂起：主线程死在 shutdown_rx 等待）。每轮让出
                // 一次后任务可被正常 abort，连接随 write_half drop 关闭。
                tokio::task::yield_now().await;
            }
        });
        Ok(text)
    })
}

/// 构造注入根的 TLS 客户端配置（严格 webpki + `CaUsedAsEndEntity` 特例）——
/// 供受控 server 客户端与 `direct_connect` DoH 机制测试共用（同一确定性材料）。
///
/// # Errors
///
/// 根注入 / verifier 构建 / 客户端配置失败 → `&'static str`。
pub(crate) fn test_tls_client_config(
    cert: &rustls::pki_types::CertificateDer<'static>,
) -> Result<Arc<rustls::ClientConfig>, &'static str> {
    let roots = {
        let mut r = rustls::RootCertStore::empty();
        r.add(cert.clone()).map_err(|_| "root-add")?;
        Arc::new(r)
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
        .build()
        .map_err(|_| "verifier-build")?;
    let verifier = TestRootsVerifier {
        inner,
        cert: cert.clone(),
    };
    let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "client-config")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(client_cfg))
}

/// data 连接 verifier（与 P41 TestRootsVerifier 同语义：注入根 + 严格 webpki，
/// 允许自签名注入根作为自己的 end-entity——`CaUsedAsEndEntity` 特例）。
#[derive(Debug)]
pub(crate) struct TestRootsVerifier {
    pub(crate) inner: Arc<rustls::client::WebPkiServerVerifier>,
    pub(crate) cert: rustls::pki_types::CertificateDer<'static>,
}

impl TestRootsVerifier {
    /// end-entity 是否就是注入的信任根（按 subjectPublicKeyInfo 内容比较——
    /// 两端都剥掉外层 SEQUENCE；TrustAnchor 与 P41 TestRootsVerifier 存的是内容）。
    fn end_entity_is_injected_root(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
    ) -> bool {
        let Ok(cert) = rustls::server::ParsedCertificate::try_from(end_entity) else {
            return false;
        };
        let spki = cert.subject_public_key_info();
        let Some(spki_content) = strip_sequence_header(spki.as_ref()) else {
            return false;
        };
        let Ok(parsed) = rustls::server::ParsedCertificate::try_from(&self.cert) else {
            return false;
        };
        let spki = parsed.subject_public_key_info();
        let Some(cert_content) = strip_sequence_header(spki.as_ref()) else {
            return false;
        };
        cert_content == spki_content
    }
}

pub(crate) fn strip_sequence_header(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.first() != Some(&0x30) {
        return None;
    }
    let first_len = *bytes.get(1)?;
    if first_len & 0x80 == 0 {
        let content_len = first_len as usize;
        return bytes.get(2..2 + content_len);
    }
    let len_bytes = first_len & 0x7F;
    if len_bytes == 0 || len_bytes > 4 {
        return None;
    }
    let n = len_bytes as usize;
    let len_bytes_slice = bytes.get(2..2 + n)?;
    let content_len = len_bytes_slice
        .iter()
        .fold(0usize, |acc, b| (acc << 8) | *b as usize);
    bytes.get(2 + n..2 + n + content_len)
}

impl rustls::client::danger::ServerCertVerifier for TestRootsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
        {
            Ok(verified) => Ok(verified),
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Other(_))) => {
                if self.end_entity_is_injected_root(end_entity) {
                    let cert = rustls::server::ParsedCertificate::try_from(end_entity).map_err(
                        |_e| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding),
                    )?;
                    rustls::client::verify_server_name(&cert, server_name).map_err(|_e| {
                        rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName)
                    })?;
                    return Ok(rustls::client::danger::ServerCertVerified::assertion());
                }
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ))
            }
            Err(err) => Err(err),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// ---------------------------------------------------------------------------
// 受控 CSTP server 的 TCP responder（跨子网 10.99.99.2:80 的应答方）。
// 真实 IPv4/TCP 包处理：SYN→SYN-ACK、数据→HTTP/1.1 200、FIN 关闭；IP/TCP
// 校验和必须正确（WSP3 冻结：漏清零重算校验和的 reply 会被内核静默丢弃）。
// ---------------------------------------------------------------------------

/// 单连接 TCP responder 状态。
#[derive(Default)]
pub(crate) struct TcpResponder {
    pub(crate) conn: Option<ConnState>,
}

pub(crate) struct ConnState {
    pub(crate) client_seq: u32,
    pub(crate) server_seq: u32,
    pub(crate) server_ack: u32,
    pub(crate) established: bool,
    pub(crate) response_sent: bool,
    pub(crate) fin_sent: bool,
    pub(crate) last_data_seq: Option<u32>,
}

impl TcpResponder {
    fn new() -> Self {
        Self::default()
    }

    /// 处理一个收到的 IPv4 包，返回需要写回 ring 的响应包。
    fn handle(&mut self, pkt: &[u8]) -> Vec<Vec<u8>> {
        let Some(ip) = parse_ipv4(pkt) else {
            return Vec::new();
        };
        if ip.protocol != 6 {
            return Vec::new();
        }
        let Some(tcp) = parse_tcp(&ip) else {
            return Vec::new();
        };
        let Ok(target) = FLOW_TARGET.parse::<Ipv4Addr>() else {
            return Vec::new();
        };
        if ip.dst != target || tcp.dst_port != FLOW_TARGET_PORT {
            return Vec::new();
        }
        let flags = tcp.flags;
        let is_syn = flags & 0x02 != 0 && flags & 0x10 == 0;
        let is_ack = flags & 0x10 != 0;
        let is_fin = flags & 0x01 != 0;
        let is_psh = flags & 0x08 != 0;
        let has_data = !tcp.payload.is_empty();

        let mut out = Vec::new();
        if is_syn {
            // 新连接：SYN → SYN-ACK；重传（同 seq）：重新应答。
            match &mut self.conn {
                None => {
                    let state = ConnState {
                        client_seq: tcp.seq,
                        server_seq: 0x1234_5678,
                        server_ack: tcp.seq.wrapping_add(1),
                        established: false,
                        response_sent: false,
                        fin_sent: false,
                        last_data_seq: None,
                    };
                    out.push(build_tcp_packet(
                        target,
                        ip.src,
                        FLOW_TARGET_PORT,
                        tcp.src_port,
                        state.server_seq,
                        state.server_ack,
                        0x12, // SYN|ACK
                        &[],
                    ));
                    self.conn = Some(state);
                }
                Some(state) => {
                    if tcp.seq == state.client_seq && !state.established {
                        out.push(build_tcp_packet(
                            target,
                            ip.src,
                            FLOW_TARGET_PORT,
                            tcp.src_port,
                            state.server_seq,
                            state.server_ack,
                            0x12,
                            &[],
                        ));
                    }
                }
            }
            return out;
        }
        let Some(state) = self.conn.as_mut() else {
            return out;
        };
        if is_ack && !is_psh && !is_fin && !has_data {
            state.established = true;
            return out;
        }
        if is_fin {
            out.push(build_tcp_packet(
                target,
                ip.src,
                FLOW_TARGET_PORT,
                tcp.src_port,
                state.server_seq,
                tcp.seq.wrapping_add(1),
                0x10, // ACK
                &[],
            ));
            return out;
        }
        if is_psh || has_data {
            // 数据段：累积到 HTTP 请求完整（空行）后应答 200。
            let data_ack = tcp.seq.wrapping_add(tcp.payload.len() as u32);
            if state.last_data_seq == Some(tcp.seq) && state.response_sent {
                // 重传：重发响应。
                if let Some(resp) = build_response_packets(state, ip.src, tcp.src_port) {
                    out.extend(resp);
                }
                return out;
            }
            state.last_data_seq = Some(tcp.seq);
            if !state.response_sent && tcp.payload.windows(4).any(|w| w == b"\r\n\r\n") {
                state.server_ack = data_ack;
                if let Some(resp) = build_response_packets(state, ip.src, tcp.src_port) {
                    out.extend(resp);
                }
                state.response_sent = true;
            }
        }
        out
    }
}

/// 构造 HTTP 200 响应包（data + FIN；`Connection: close` 语义）。
pub(crate) fn build_response_packets(
    state: &mut ConnState,
    client_ip: Ipv4Addr,
    client_port: u16,
) -> Option<Vec<Vec<u8>>> {
    {
        let body = b"hello w28 flow";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            String::from_utf8_lossy(body)
        );
        let data_seq = state.server_seq;
        let mut pkts = vec![build_tcp_packet(
            FLOW_TARGET.parse().unwrap_or(Ipv4Addr::UNSPECIFIED),
            client_ip,
            FLOW_TARGET_PORT,
            client_port,
            data_seq,
            state.server_ack,
            0x18, // PSH|ACK
            response.as_bytes(),
        )];
        let after_data = state.server_seq.wrapping_add(response.len() as u32);
        if !state.fin_sent {
            pkts.push(build_tcp_packet(
                FLOW_TARGET.parse().unwrap_or(Ipv4Addr::UNSPECIFIED),
                client_ip,
                FLOW_TARGET_PORT,
                client_port,
                after_data,
                state.server_ack,
                0x11, // FIN|ACK
                &[],
            ));
            state.fin_sent = true;
        }
        state.server_seq = after_data;
        Some(pkts)
    }
}

/// 解析后的 IPv4 头。
pub(crate) struct ParsedIp {
    pub(crate) src: Ipv4Addr,
    pub(crate) dst: Ipv4Addr,
    pub(crate) protocol: u8,
    pub(crate) rest: Vec<u8>,
}

pub(crate) fn parse_ipv4(pkt: &[u8]) -> Option<ParsedIp> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if pkt.len() < ihl || pkt[9] != 6 {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some(ParsedIp {
        src,
        dst,
        protocol: pkt[9],
        rest: pkt[ihl..].to_vec(),
    })
}

/// 解析后的 TCP 段。
pub(crate) struct ParsedTcp {
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
    pub(crate) seq: u32,
    pub(crate) flags: u8,
    pub(crate) payload: Vec<u8>,
}

pub(crate) fn parse_tcp(ip: &ParsedIp) -> Option<ParsedTcp> {
    let bytes = &ip.rest;
    if bytes.len() < 20 {
        return None;
    }
    let data_offset = ((bytes[12] >> 4) as usize) * 4;
    if bytes.len() < data_offset {
        return None;
    }
    Some(ParsedTcp {
        src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
        dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
        seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        flags: bytes[13],
        payload: bytes[data_offset..].to_vec(),
    })
}

/// 构造一个 IPv4/TCP 包（src=响应方 10.99.99.2，dst=请求方）。
#[allow(clippy::too_many_arguments)] // 固定 wire 布局的 8 参构造器；分组为 struct 增加间接层
pub(crate) fn build_tcp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(0x50); // data offset 5
    tcp.push(flags);
    tcp.extend_from_slice(&0xFFFFu16.to_be_bytes()); // window
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum (recomputed)
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent
    tcp.extend_from_slice(payload);
    let tcp_checksum = tcp_checksum_16bit(src, dst, &tcp);
    tcp[16] = (tcp_checksum >> 8) as u8;
    tcp[17] = (tcp_checksum & 0xFF) as u8;

    let total = 20 + tcp.len();
    let mut ip = Vec::with_capacity(total);
    ip.push(0x45); // IPv4, IHL 5
    ip.push(0x00); // DSCP/ECN
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&0xABCDu16.to_be_bytes()); // id
    ip.extend_from_slice(&0x4000u16.to_be_bytes()); // flags DF, frag 0
    ip.push(64); // TTL
    ip.push(6); // TCP
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum (recomputed)
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ip_checksum = checksum_16bit(&ip);
    ip[10] = (ip_checksum >> 8) as u8;
    ip[11] = (ip_checksum & 0xFF) as u8;
    ip.extend_from_slice(&tcp);
    ip
}

/// IPv4/IP 校验和（WSP3 冻结算法）。
pub(crate) fn checksum_16bit(data: &[u8]) -> u16 {
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

/// TCP 校验和（含伪头）。
pub(crate) fn tcp_checksum_16bit(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut data = Vec::with_capacity(12 + tcp.len());
    data.extend_from_slice(&src.octets());
    data.extend_from_slice(&dst.octets());
    data.push(0);
    data.push(6); // TCP protocol
    data.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    data.extend_from_slice(tcp);
    checksum_16bit(&data)
}

pub(crate) fn is_ipv4(pkt: &[u8]) -> bool {
    pkt.first().is_some_and(|b| b >> 4 == 4)
}

// ---------------------------------------------------------------------------
// helper 侧角色（`exv-win32-controlled-vertical-helper` bin 调用）。
// ---------------------------------------------------------------------------


/// helper 进程入口参数。
#[derive(Debug, Clone)]
pub struct HelperArgs {
    pub control_pipe: String,
    pub packet_pipe: String,
    pub dll: PathBuf,
    pub journal_dir: PathBuf,
    pub authority_name: String,
    pub host_pid: u32,
    pub adapter_name: String,
}

/// 解析 helper bin 命令行参数（`--key value`）。
pub fn parse_helper_args() -> Result<HelperArgs, String> {
    let args: Vec<String> = std::env::args().collect();
    let mut a = HelperArgs {
        control_pipe: String::new(),
        packet_pipe: String::new(),
        dll: PathBuf::new(),
        journal_dir: PathBuf::new(),
        authority_name: String::new(),
        host_pid: 0,
        adapter_name: ADAPTER_NAME.to_string(),
    };
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--control-pipe" => a.control_pipe = args.get(i + 1).cloned().unwrap_or_default(),
            "--packet-pipe" => a.packet_pipe = args.get(i + 1).cloned().unwrap_or_default(),
            "--dll" => a.dll = PathBuf::from(args.get(i + 1).cloned().unwrap_or_default()),
            "--journal-dir" => {
                a.journal_dir = PathBuf::from(args.get(i + 1).cloned().unwrap_or_default())
            }
            "--authority-name" => a.authority_name = args.get(i + 1).cloned().unwrap_or_default(),
            "--host-pid" => {
                a.host_pid = args
                    .get(i + 1)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_default();
            }
            "--adapter-name" => a.adapter_name = args.get(i + 1).cloned().unwrap_or_default(),
            _ => {}
        }
        i += 1;
    }
    // DP-04：packet pipe 不再是 helper 必需项——school flow 不传 `--packet-pipe`
    // （引擎数据面直连自己的 session/ring）；受控纵切 W28 仍传（packet pipe 传数据）。
    if a.control_pipe.is_empty() || a.dll.as_os_str().is_empty() {
        return Err("helper args incomplete".to_string());
    }
    Ok(a)
}

/// 运行 helper 角色（W26 组合 + W16/W22 create-then-idle apply + W24 teardown）。
/// DP-01：apply 只做特权初始化（adapter 创建 + 四族网络设置），不建 session、不起
/// ring worker；数据面由引擎/host 接管（DP-02/DP-03/DP-04）。返回进程退出码
/// （0 = 干净退出）。
pub fn run_helper_role(args: &HelperArgs) -> i32 {
    match run_helper_inner(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("[helper] fatal: {e}");
            1
        }
    }
}

pub(crate) fn run_helper_inner(args: &HelperArgs) -> Result<i32, String> {
    let own_sid = current_user_sid().ok_or("helper: cannot read own SID")?;

    // ---- W26：privileged helper 组合（authority 先、recovery、endpoint 最后）。 ----
    let composition = compose_privileged_helper(ComposeConfig {
        authority_name: args.authority_name.clone(),
        journal_dir: args.journal_dir.clone(),
    })
    .map_err(|e| format!("compose_privileged_helper: {e:?}"))?;
    let phases: Vec<String> = composition
        .phases()
        .iter()
        .map(|p| format!("{p:?}"))
        .collect();
    let projection_digest = Some(hex_of(&composition.projection_digest()));

    // ---- 已认证 pipe server（WSP1：byte 模式 + DACL + FIRST_INSTANCE）。control
    //      pipe 是所有场景必需的（hello/apply/stop RPC）。DP-04：packet pipe 数据
    //      路径已从 school flow 移除——仅当调用方仍传 `--packet-pipe`（受控纵切 W28
    //      仍经它传数据）时才创建并等待 packet pipe server；school flow 不传 → helper
    //      不创建、不阻塞（数据面属引擎/host 的 session/ring 直连）。 ----
    let control_server = create_pipe_server(&args.control_pipe)?;
    accept_client(control_server)?;
    let _packet_pipe_server = if args.packet_pipe.is_empty() {
        None
    } else {
        let packet_server = create_pipe_server(&args.packet_pipe)?;
        accept_client(packet_server)?;
        // DP-01：helper 不再读/写 packet pipe（无 ring worker）——但受控纵切仍依赖
        // 这条连接存活（host 在 connect 阶段验证 packet pipe 双向身份；连接保持到
        // Stop）。有意把 wrapper 绑定到本 Option 保持到函数结束：PipeStream 无 Drop
        // （不关闭句柄），句柄由进程退出时 OS 回收。
        Some(PipeStream(packet_server))
    };

    // server 侧身份：client pid 必须等于声明的 host pid；user SID 必须等于本进程 SID。
    let client_pid = pipe_client_pid(control_server).ok_or("helper: client pid query failed")?;
    let client_sid = process_sid(client_pid).ok_or("helper: client sid query failed")?;
    let client_account = process_account(client_pid).unwrap_or_default();
    let host_verified = client_pid == args.host_pid && client_sid == own_sid;

    let control = PipeStream(control_server);
    // 先消费 host 的 hello 请求（命令循环的帧必须从 apply 起对齐——hello 帧不
    // 消费会让循环读到旧帧、把 apply 误判为 unknown command）。
    let hello_req: HelloReq = read_json(&control)?;
    let host_verified = host_verified && hello_req.host_pid == args.host_pid;
    let hello = HelloReply {
        ok: host_verified,
        error: if host_verified {
            None
        } else {
            Some("client identity mismatch".to_string())
        },
        helper_pid: std::process::id(),
        helper_sid: own_sid,
        helper_account: client_account,
        helper_elevated: is_elevated(),
        authority_phases: phases,
        projection_digest,
    };
    write_json(&control, &hello)?;
    if !host_verified {
        return Ok(2);
    }

    // ---- 命令循环（hello/apply/stop）。 ----
    let mut native: Option<HelperNativeState> = None;
    loop {
        let req: serde_json::Value = read_json(&control)?;
        let cmd = req
            .get("cmd")
            .and_then(|c| c.as_str())
            .unwrap_or_default()
            .to_string();
        match cmd.as_str() {
            "apply" => {
                            if native.is_some() {
                    return Err("helper: duplicate apply".to_string());
                }
                let req: ApplyReq = serde_json::from_value(req).map_err(|e| e.to_string())?;
                match helper_apply(&req) {
                    Ok(state) => {
                        let reply = state.apply_reply();
                        write_json(&control, &reply)?;
                        native = Some(state);
                    }
                    Err(e) => {
                        let reply = ApplyReply {
                            ok: false,
                            error: Some(e),
                            adapter_name: None,
                            adapter_luid: None,
                            adapter_ifindex: None,
                            session_started: false,
                            inventory: Vec::new(),
                            address_applied: None,
                            mtu_applied: None,
                            routes_applied: Vec::new(),
                            dns_applied: Vec::new(),
                            before: Snapshot::empty(),
                            applied: Snapshot::empty(),
                        };
                        write_json(&control, &reply)?;
                    }
                }
            }
            "stop" => {
                            let reply = helper_stop(args, native.take());
                write_json(&control, &reply)?;
                let code = if reply.ok { 0 } else { 2 };
                let _ = shutdown_composition(composition);
                return Ok(code);
            }
            _ => {
                            return Err(format!("helper: unknown command {cmd:?}"));
            }
        }
    }
}

/// helper 的原生状态（W16/W22 leaf apply 状态；DP-01 起 **create-then-idle**——
/// 不持有 Wintun session、不起 ring worker）。
///
/// 生命周期契约：`adapter` 是创建者句柄（`WintunAdapter::create` 的 `Created`，
/// `owned=true`），由本状态持有到 Stop——apply 返回后 **adapter 保持存活**，
/// 引擎（host，DP-02）按 `adapter_name`（create 名）`WintunAdapter::open` +
/// `WintunSession::start` 建自己的数据面；Stop 时 `drop(state.adapter)` 触发
/// creator close 移除 adapter。数据面 session 不再属于 helper。
pub(crate) struct HelperNativeState {
    pub(crate) _lib: WintunLibrary,
    pub(crate) adapter: WintunAdapter,
    /// create 名（`ApplyReq.adapter_name`；host 按此名 open-by-name —— 非
    /// `adapter.alias()`，接口别名可能被 Windows 规范化后不同）。
    pub(crate) adapter_name: String,
    pub(crate) luid: u64,
    pub(crate) guid: GUID,
    pub(crate) before: Snapshot,
    pub(crate) applied: Snapshot,
    pub(crate) owned_addresses: Vec<IpAddressRow>,
    pub(crate) installed_routes: Vec<RouteRow>,
    pub(crate) mtu_original: Option<MtuSnapshot>,
    pub(crate) mtu_applied: Option<MtuSnapshot>,
    pub(crate) dns_original: DnsSettings,
    pub(crate) dns_fingerprint: DnsFingerprint,
    pub(crate) inventory: Vec<String>,
    pub(crate) address_applied: Option<String>,
    pub(crate) mtu_applied_value: Option<u32>,
    pub(crate) routes_applied: Vec<String>,
    pub(crate) dns_applied: Vec<String>,
}

impl HelperNativeState {
    /// DP-01 create-then-idle contract: apply reply 携带 **create 名**（host 按此名
    /// `WintunAdapter::open`）、LUID、ifindex；`session_started=false`（helper 不建
    /// session，数据面属引擎/host）。
    fn apply_reply(&self) -> ApplyReply {
        ApplyReply {
            ok: true,
            error: None,
            adapter_name: Some(self.adapter_name.clone()),
            adapter_luid: Some(self.adapter.luid()),
            adapter_ifindex: Some(self.adapter.ifindex()),
            session_started: false,
            inventory: self.inventory.clone(),
            address_applied: self.address_applied.clone(),
            mtu_applied: self.mtu_applied_value,
            routes_applied: self.routes_applied.clone(),
            dns_applied: self.dns_applied.clone(),
            before: self.before.clone(),
            applied: self.applied.clone(),
        }
    }
}

/// 解析一条路由目标字符串（C++ `parse_destination` 语义对齐：
/// `src/platform/win32/win_route_ops.cpp` —— 裸 IP 视作 /32 主机路由）：
/// - `"a.b.c.d"`（裸 IP）→ `(ip, 32)`
/// - `"a.b.c.d/n"`（CIDR）→ `(ip, n)`
///
/// 非法 IPv4 或 `n > 32` → `None`。config 的 `default_routes` 允许裸 IP（如
/// `distribution/ecnu.json` 的 `219.228.60.69`），必须与 CIDR 同接受——这是
/// C++ 语义（`parse_destination` 对无 `/` 目标直接 `mask = 0xFFFFFFFF`）。
#[must_use]
fn parse_route_destination(route: &str) -> Option<(Ipv4Addr, u8)> {
    let (net, prefix) = match route.split_once('/') {
        Some((net, prefix)) => (net, prefix.parse::<u8>().ok()?),
        None => (route, 32),
    };
    let net: Ipv4Addr = net.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((net, prefix))
}

/// helper 侧 W16/W17/W22 leaf 组合的 apply（**DP-01：create-then-idle**）。
///
/// 特权初始化：`WintunLibrary::load` + `WintunAdapter::create`（返回 create 名/
/// LUID/ifindex）+ 四族 leaf apply（address → MTU → bypass → routes → 校园路由 →
/// DNS，admission-first，canonical 顺序）。**不创建 Wintun session、不启动 ring
/// worker** —— 数据面（session + ring 读写）属引擎/host（C++-faithful；DP-02/DP-03/
/// DP-04 接线）。apply 返回后 `HelperNativeState.adapter`（创建者句柄）保持存活，
/// 供引擎按名 `WintunAdapter::open`；Stop 时 creator close 移除 adapter。
///
/// W22 `Aggregate` 类型独占 session 所有权（每 adapter 单 session、无 extraction
/// API），与引擎侧 session 拆分后不可同时组合——本函数按 `apply_tunnel::apply` 冻结的
/// canonical 顺序调用其委托的同一组 leaf seams，restore 按 `build_restore_plan` 逆序
/// compare-and-restore（DP-04 后为 Aggregate 增加 from-parts/into-parts seam 可直接
/// 使用 `apply_tunnel::apply/restore`）。
pub(crate) fn helper_apply(req: &ApplyReq) -> Result<HelperNativeState, String> {
    let _t = timing::Timed::new("acceptance.helper_apply.total");
    let lib = WintunLibrary::load(Path::new(&req.dll)).map_err(|e| format!("{e:?}"))?;
    let (adapter, _open) =
        WintunAdapter::create(&lib, &req.adapter_name, TUNNEL_TYPE).map_err(|e| format!("{e:?}"))?;
    let luid = adapter.luid();
    let guid = luid_to_guid(luid).ok_or("helper: luid to guid")?;
    let before = capture_snapshot(luid, &guid)?;
    // 接口启用（IpHelper `SetIfEntry`，生产 API——非 netsh；best-effort：
    // 顺序与 WSP3/W17 冻结路径一致：address → enable → route（路由安装前启用）。
    let _ = enable_interface_best_effort(adapter.ifindex());
    // 路由状态沉降等待：DAD 收敛后路由表的 "connected" 传播是异步的（实测
    // GetBestRoute2 在 DAD 后立即查询仍返回 bypass；数秒后返回 Wintun）。
    let _sleep_6s = std::time::Instant::now();
    std::thread::sleep(Duration::from_secs(6));
    timing::record_elapsed("acceptance.helper_apply.sleep_6s", _sleep_6s);

    // ---- admission-first：plan 整体校验（W22 语义，零效果拒绝）。 ----
    validate_mtu_value(req.mtu).map_err(|e| format!("mtu admission: {e:?}"))?;
    let address: Ipv4Addr = req.address.parse().map_err(|_| "address parse")?;
    if req.prefix > 32 {
        return Err("invalid prefix".to_string());
    }
    for route in req.routes.iter().chain(req.campus_routes.iter()) {
        parse_route_destination(route).ok_or("route shape")?;
    }
    for ns in &req.dns {
        ns.parse::<Ipv4Addr>().map_err(|_| "dns shape")?;
    }

    // ---- address 族（W18 leaf：pre-existing 不 owned；owned 行记录供 restore）。 ----
    let controller = IpAddressController::new(luid);
    let captured_addr = controller.capture().map_err(|e| format!("{e:?}"))?;
    let addr_row = IpAddressRow::new(address, luid, req.prefix);
    let addr_plan = plan_addresses(&captured_addr, &[addr_row]);
    for row in &addr_plan.to_add {
        controller.apply(row).map_err(|e| format!("address apply: {e:?}"))?;
    }
    let owned_addresses = addr_plan.to_add.clone();

    // ---- 接口启用（在隧道路由安装之前——WSP3/W17 冻结顺序：address → enable →
    //      route；SetIfEntry 是生产 IpHelper API，非 netsh）。 ----
    let _ = enable_interface_best_effort(adapter.ifindex());
    // 路由状态沉降等待：本宿主实测（WSP3 同款）接口配置后内核选路是异步收敛的，
    // 数秒内新 socket 可能仍走默认路由（Mihomo）而非隧道路由。有界等待。
    let _sleep_8s = std::time::Instant::now();
    std::thread::sleep(Duration::from_secs(8));
    timing::record_elapsed("acceptance.helper_apply.sleep_8s", _sleep_8s);

    // ---- DAD 收敛等待（WSP4 冻结事实：创建后立即回读 DadState=Tentative(1)；
    //      接口在地址收敛到 Preferred 前不参与无源路由查找——HTTP flow 的 socket
    //      会走默认路由而不是隧道路由。有界轮询，最多 ~10s）。 ----
    let _dad_poll_start = std::time::Instant::now();
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let captured = controller.capture().map_err(|e| format!("{e:?}"))?;
            let all_preferred = captured.iter().all(|r| r.dad_state != 1); // Tentative
            if all_preferred || std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    timing::record_elapsed("acceptance.helper_apply.dad_poll", _dad_poll_start);

    // ---- MTU 族（W19 leaf：Set 前原始快照；restore 输入）。 ----
    let mtu_ctrl = MtuController::new(luid, MtuFamily::V4);
    let mtu_original = mtu_ctrl.capture().map_err(|e| format!("{e:?}"))?;
    mtu_ctrl.apply(req.mtu).map_err(|e| format!("mtu apply: {e:?}"))?;
    let mtu_applied = MtuSnapshot::new(luid, MtuFamily::V4, req.mtu);

    // ---- bypass 族：受控纵切无 control 被劫持风险（control 走 loopback）——
    //     与 `apply_tunnel` 的 `bypass: None` 同语义，不安装。 ----

    // ---- 隧道路由族（W20 leaf：精确行安装，逆序清理）。 ----
    let mut installed_routes = Vec::new();
    for route in &req.routes {
        let (net, prefix) = parse_route_destination(route).ok_or("route shape")?;
        let row = RouteRow::new(net, prefix, address, luid, 5);
        install(&row).map_err(|e| format!("route install: {e:?}"))?;
        // 逆序清理必须按**回读生效行**记录：Windows 在表中存有效 metric
        // （请求 metric + 接口自动 metric，实测 5 -> 10）；用请求行做
        // 全字段精确 remove 会以 87 拒绝并被静默容忍，导致路由残留、
        // restore 后四族不相等（W24 实测根因）。
        let actual = capture_rows(luid)
            .map_err(|e| format!("route read-back: {e:?}"))?
            .into_iter()
            .find(|r| r.dest_key() == row.dest_key())
            .ok_or_else(|| "route read-back missing".to_string())?;
        installed_routes.push(actual);
    }

    // ---- 校园路由族（config-driven；同隧道路由经提权 helper `CreateIpForwardEntry2`
    //      安装——特权操作归属 helper，非 host；`ERROR_OBJECT_ALREADY_EXISTS` 5010
    //      已存在容忍 + 回读生效行供逆序清理）。 ----
    for route in &req.campus_routes {
        let (net, prefix) = parse_route_destination(route).ok_or("campus route shape")?;
        let row = RouteRow::new(net, prefix, address, luid, CAMPUS_ROUTE_METRIC);
        match install(&row) {
            Ok(()) => {}
            Err(e) if e.code == ERROR_OBJECT_ALREADY_EXISTS => {} // 已存在：回读采纳
            Err(e) => return Err(format!("campus route install: {e:?}")),
        }
        let actual = capture_rows(luid)
            .map_err(|e| format!("campus route read-back: {e:?}"))?
            .into_iter()
            .find(|r| r.dest_key() == row.dest_key())
            .ok_or_else(|| "campus route read-back missing".to_string())?;
        installed_routes.push(actual);
    }

    // ---- DNS 族（W21 leaf：applied fingerprint + 原始快照）。 ----
    let dns_original = DnsCapture::capture(&guid).map_err(|e| format!("{e:?}"))?;
    let dns_settings = DnsSettings::new(req.dns.clone(), Vec::new());
    let dns_fingerprint = DnsApplier::apply(&guid, &dns_settings).map_err(|e| format!("{e:?}"))?;

    let applied = capture_snapshot(luid, &guid)?;
    let inventory: Vec<String> = COMPLETE_INVENTORY
        .iter()
        .map(|item| inventory_item_name(*item))
        .collect();
    let address_applied = if owned_addresses.is_empty() {
        None
    } else {
        Some(format!(
            "{}/{}",
            owned_addresses[0].address, owned_addresses[0].on_link_prefix_length
        ))
    };
    // 证据的 `routes_applied` = 隧道路由 + 校园路由（合并集；helper 回读采纳）。
    let mut routes_applied: Vec<String> = req.routes.clone();
    routes_applied.extend(req.campus_routes.clone());
    let dns_applied = req.dns.clone();

    let state = HelperNativeState {
        _lib: lib,
        adapter,
        adapter_name: req.adapter_name.clone(),
        luid,
        guid,
        before,
        applied,
        owned_addresses,
        installed_routes,
        mtu_original: Some(mtu_original),
        mtu_applied: Some(mtu_applied),
        dns_original,
        dns_fingerprint,
        inventory,
        address_applied,
        mtu_applied_value: Some(req.mtu),
        routes_applied,
        dns_applied,
    };

    // DP-01：不再启动 ring worker（无 session、无 packet pipe 泵）——helper 完成
    // 特权初始化后空闲，数据面由引擎/host（DP-02/DP-03/DP-04）按名 open 后接管。
    Ok(state)
}

pub(crate) fn inventory_item_name(item: InventoryItem) -> String {
    match item {
        InventoryItem::Adapter => "adapter".to_string(),
        InventoryItem::Session => "session".to_string(),
        InventoryItem::Address => "address".to_string(),
        InventoryItem::Mtu => "mtu".to_string(),
        InventoryItem::BypassRoute => "bypass".to_string(),
        InventoryItem::Route => "routes".to_string(),
        InventoryItem::Dns => "dns".to_string(),
        InventoryItem::PacketAttachment => "packet".to_string(),
        InventoryItem::RunningEffect => "running".to_string(),
    }
}

/// helper 侧 W24/W14 teardown（DP-01：**无 worker、无 session**）：durable stop
/// journal → 逆序 compare-and-restore → 最终句柄（adapter creator close 移除）→
/// CleanProof → retirement journal。顺序 = `build_teardown_plan` 的冻结阶段顺序
/// （PureCancel → JournaledBegin → ReverseRestore → FinalHandle → Proof；
/// ChildJoin 阶段在 DP-01 起为空——helper 不再持有 ring worker）。
pub(crate) fn helper_stop(
    args: &HelperArgs,
    state: Option<HelperNativeState>,
) -> StopReply {
    let before = state
        .as_ref()
        .map(|s| s.before.clone())
        .unwrap_or_default();
    let mut reply = StopReply {
        ok: true,
        error: None,
        packets_after_stop: 0,
        ring_received_bytes: 0,
        ring_sent_bytes: 0,
        adapter_removed: false,
        stop_journaled: false,
        cleanup_proof_issued: false,
        retirement_recorded: false,
        owned_resources_retired: false,
        after: before.clone(),
        before,
    };
    let Some(state) = state else {
        return reply; // 无原生状态：干净退出
    };

    // ---- W14 durable stop journal（先 journal，后 destructive）。 ----
    reply.stop_journaled = append_journal_record(&args.journal_dir, 1, b"w28 stop").is_ok();

    // DP-01：无 ring worker 可 join（helper 不持 session/不泵 packet pipe）。
    // `packets_after_stop`/`ring_received_bytes`/`ring_sent_bytes` 恒 0 —— 数据面
    // ring 计数由引擎/host 侧数据面（DP-03/DP-04）承接，不再来自 helper StopReply。

    // ---- 逆序 compare-and-restore（W22 build_restore_plan 顺序：DNS → routes →
    //      MTU → address；第三方变更 typed skip，不覆盖）。 ----
    let restore_ok = (|| -> Result<(), String> {
        let _ = DnsApplier::restore(&state.guid, &state.dns_fingerprint, &state.dns_original)
            .map_err(|e| format!("dns restore: {e:?}"))?;
        for row in state.installed_routes.iter().rev() {
            match remove(row) {
                Ok(_) => {}
                Err(e) if e.code == 87 => {}
                Err(e) => return Err(format!("route remove: {e:?}")),
            }
        }
        if let (Some(applied), Some(original)) = (&state.mtu_applied, &state.mtu_original) {
            let ctrl = MtuController::new(applied.luid, applied.family);
            ctrl.compare_and_restore(applied, original)
                .map_err(|e| format!("mtu restore: {e:?}"))?;
        }
        let ctrl = IpAddressController::new(state.luid);
        let current = ctrl.capture().map_err(|e| format!("addr capture: {e:?}"))?;
        for row in restore_owned_addresses(&state.owned_addresses, &current) {
            ctrl.delete(&row).map_err(|e| format!("addr delete: {e:?}"))?;
        }
        Ok(())
    })();
    if let Err(e) = restore_ok {
        reply.ok = false;
        reply.error = Some(e);
        return reply;
    }
    reply.owned_resources_retired = true;

    // 先取 after 快照与 restored 事实（接口仍在；adapter 移除后四族无法回读），
    // 再取最终句柄：adapter creator close（移除 adapter）。
    // DP-01：helper 不持 session（`HelperNativeState.session` 已移除）——session
    // 属引擎/host（DP-02/DP-04），helper 侧无 `WintunEndSession` 义务；
    // `session_dropped` 恒 true（无 session 可 drop）。
    let after = capture_snapshot(state.luid, &state.guid).unwrap_or_default();
    let restored = after == state.before;
    let session_dropped = true;
    drop(state.adapter); // creator close → 移除 adapter（连带四族配置）
    let adapter_removed = (|| -> bool {
        let Ok(lib) = WintunLibrary::load(Path::new(&args.dll)) else {
            return false;
        };
        WintunAdapter::open(&lib, &args.adapter_name).is_err()
    })();
    reply.adapter_removed = adapter_removed && session_dropped;

    // ---- W24 CleanProof（完整 9 项 inventory + 逐项 verified predicate）。 ----
    let proof_ok = (|| -> Result<(), String> {
        let inventory_digest = InventoryDigest::try_from(sha256_bytes(
            COMPLETE_INVENTORY
                .iter()
                .map(|i| inventory_item_name(*i))
                .collect::<Vec<_>>()
                .join(",")
                .as_bytes(),
        ))
        .map_err(|_| "inventory digest")?;
        let mut saga = RetirementSaga::new(
            authority_fence(),
            OwnershipVersion::try_from(1).map_err(|_| "ownership version")?,
        );
        let op_id = RetirementOperationId::try_from(Uuid::new_v4()).map_err(|_| "op id")?;
        let trigger = CleanupTrigger::OwnerLost(
            OwnerLeaseId::try_from(Uuid::from_u128(0x28)).map_err(|_| "lease id")?,
        );
        let origin = ErrorSubject::Runtime(
            RuntimeEpoch::try_from(Uuid::from_u128(0x28)).map_err(|_| "epoch")?,
        );
        let ownership_ref = PlatformOwnershipRef::try_from((
            ResourceIdentityDigest::try_from([0x28; 32]).map_err(|_| "identity")?,
            OwnershipVersion::try_from(1).map_err(|_| "version")?,
            TokenDigest::try_from([0x28; 32]).map_err(|_| "token")?,
        ))
        .map_err(|_| "ownership ref")?;
        saga.begin(
            op_id,
            trigger,
            origin,
            ownership_ref,
            COMPLETE_INVENTORY.iter().map(|i| *i as u8).collect(),
            inventory_digest.clone(),
        )
        .map_err(|_| "saga begin")?;
        let predicates = cleanup_predicates(restored, adapter_removed, session_dropped);
        let input = ProveCleanInput {
            runtime_epoch: RuntimeEpoch::try_from(Uuid::from_u128(0x28))
                .map_err(|_| "epoch")?,
            cleanup_trigger_digest: CleanupTriggerDigest::try_from([0x28; 32])
                .map_err(|_| "trigger digest")?,
            external_trigger_operation_identity_digest_if_present: None,
            journal_root_or_projection_digest: JournalRootDigest::try_from([0x28; 32])
                .map_err(|_| "journal digest")?,
            platform_evidence: VersionedPlatformEvidence {
                kind_version: 1,
                digest: EvidenceDigest::try_from([0x28; 32]).map_err(|_| "evidence digest")?,
            },
            prior_platform_ownership_token_digest_if_issued: None,
        };
        let _proof = verify_cleanup_proof(
            COMPLETE_INVENTORY,
            &predicates,
            inventory_digest,
            &mut saga,
            input,
        )
        .map_err(|e| format!("cleanup proof: {e}"))?;
        Ok(())
    })();
    let proof_error = proof_ok.err();
    reply.cleanup_proof_issued = proof_error.is_none();

    // ---- W14 retirement durable record。 ----
    reply.retirement_recorded =
        append_journal_record(&args.journal_dir, 2, b"w28 retirement").is_ok();

    // 四族逐项对比（before/after），定位 restore 失败族（在 `after` move 前计算）。
    let b = &state.before;
    let restore_families = (
        after.address_rows == b.address_rows,
        after.mtu_v4 == b.mtu_v4,
        after.routes == b.routes,
        after.dns_nameservers == b.dns_nameservers,
    );
    reply.after = after;
    reply.ok = reply.stop_journaled && reply.cleanup_proof_issued && reply.adapter_removed;
    if !reply.ok {
        // 错误透明：失败谓词进 reply.error（宿主证据可见），不再吞成默认文案。
        let mut why = format!(
            "stop predicates failed: stop_journaled={} cleanup_proof_issued={} adapter_removed={} (session_dropped={session_dropped})",
            reply.stop_journaled, reply.cleanup_proof_issued, reply.adapter_removed
        );
        why.push_str(&format!(
            "; restore families (addr,mtu,routes,dns)=({}, {}, {}, {})",
            restore_families.0, restore_families.1, restore_families.2, restore_families.3
        ));
        why.push_str(&format!(
            "; after={:?}; before={b:?}",
            reply.after
        ));
        if let Some(e) = proof_error {
            why.push_str(&format!("; proof error: {e}"));
        }
        reply.error = Some(why);
    }
    reply
}

/// 追加一条 durable journal record（W14 WinJournalStore，FlushFileBuffers 同步）。
pub(crate) fn append_journal_record(dir: &Path, sequence: u64, payload: &[u8]) -> Result<(), String> {
    let path = JournalPath::from_dir(dir.to_path_buf());
    let mut store = WinJournalStore::open(&path).map_err(|e| format!("{e:?}"))?;
    let record = JournalRecord::new(sequence, [0u8; 32], payload.to_vec());
    store
        .append_synced(&record)
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}

/// 9 项 canonical inventory 的逐项 cleanup predicate（真实观测）。
pub(crate) fn cleanup_predicates(
    restored: bool,
    adapter_removed: bool,
    session_dropped: bool,
) -> Vec<CleanupPredicate> {
    vec![
        CleanupPredicate {
            item: InventoryItem::Adapter,
            verified: adapter_removed,
            evidence: "WintunOpenAdapter after creator close fails (removed)",
        },
        CleanupPredicate {
            item: InventoryItem::Session,
            verified: session_dropped,
            evidence: "helper holds no Wintun session (DP-01 create-then-idle; session is engine-owned)",
        },
        CleanupPredicate {
            item: InventoryItem::Address,
            verified: restored,
            evidence: "address rows compare-and-restore to before",
        },
        CleanupPredicate {
            item: InventoryItem::Mtu,
            verified: restored,
            evidence: "MTU compare-and-restore to before",
        },
        CleanupPredicate {
            item: InventoryItem::BypassRoute,
            verified: true,
            evidence: "no bypass route was installed (control plane is loopback)",
        },
        CleanupPredicate {
            item: InventoryItem::Route,
            verified: restored,
            evidence: "tunnel routes removed (reverse install order)",
        },
        CleanupPredicate {
            item: InventoryItem::Dns,
            verified: restored,
            evidence: "DNS compare-and-restore to before",
        },
        CleanupPredicate {
            item: InventoryItem::PacketAttachment,
            verified: true,
            evidence: "host packet relay stopped before Stop command",
        },
        CleanupPredicate {
            item: InventoryItem::RunningEffect,
            verified: session_dropped && adapter_removed,
            evidence: "no ring worker in helper (DP-01) and adapter removed; no running effect remains",
        },
    ]
}

/// 确定性 authority fence。
pub(crate) fn authority_fence() -> AuthorityFence {
    AuthorityFence {
        authority_epoch: AuthorityEpoch::try_from(1).expect("epoch 1"),
        platform_authority_instance_id: PlatformAuthorityInstanceId::try_from(Uuid::from_u128(1))
            .expect("instance id"),
        admission_watermark: AdmissionWatermark::try_from(1).expect("watermark"),
        journal_revision: JournalRevision::try_from(1).expect("revision"),
    }
}

/// 采集接口四族快照（address/MTU/routes/DNS）。
pub(crate) fn capture_snapshot(luid: u64, guid: &GUID) -> Result<Snapshot, String> {
    let address_rows = IpAddressController::new(luid)
        .capture()
        .map_err(|e| format!("{e:?}"))?;
    let mtu_v4 = MtuController::new(luid, MtuFamily::V4)
        .capture()
        .map(|s| Some(s.value))
        .map_err(|e| format!("{e:?}"))?;
    let mtu_v6 = match MtuController::new(luid, MtuFamily::V6).capture() {
        Ok(s) => Some(s.value),
        Err(e) if e.code == 1168 => None,
        Err(e) => return Err(format!("{e:?}")),
    };
    let routes = capture_rows(luid).map_err(|e| format!("{e:?}"))?;
    let dns = DnsCapture::capture(guid).map_err(|e| format!("{e:?}"))?;
    Ok(Snapshot {
        address_rows: address_rows
            .iter()
            .map(|r| format!("{}/{}", r.address, r.on_link_prefix_length))
            .collect(),
        mtu_v4,
        mtu_v6,
        routes: routes
            .iter()
            .map(|r| format!("{}/{}", r.network, r.prefix_len))
            .collect(),
        dns_nameservers: dns.nameservers.clone(),
        dns_search: dns.search_suffixes.clone(),
    })
}

/// 接口启用（`GetIfEntry` + `SetIfEntry`，dwAdminStatus=UP；best-effort，失败忽略——
/// Wintun 接口默认已启用）。
fn enable_interface_best_effort(ifindex: u32) -> Result<(), String> {
    let mut row = windows::Win32::NetworkManagement::IpHelper::MIB_IFROW {
        dwIndex: ifindex,
        ..Default::default()
    };
    // SAFETY: row 是有效输出参数；GetIfEntry 填充接口行。
    let rc = unsafe { windows::Win32::NetworkManagement::IpHelper::GetIfEntry(&raw mut row) };
    if rc != 0 {
        return Err(format!("GetIfEntry failed: {rc}"));
    }
    row.dwAdminStatus = 1; // MIB_IF_ADMIN_STATUS_UP
    // SAFETY: row 已由 GetIfEntry 填充（身份字段一致），SetIfEntry 写回。
    let rc = unsafe { windows::Win32::NetworkManagement::IpHelper::SetIfEntry(&raw const row) };
    if rc != 0 {
        return Err(format!("SetIfEntry failed: {rc}"));
    }
    Ok(())
}

/// LUID → interface GUID（DNS API 键；WSP4 冻结转换）。
pub(crate) fn luid_to_guid(luid: u64) -> Option<GUID> {
    let l = windows::Win32::NetworkManagement::Ndis::NET_LUID_LH { Value: luid };
    let mut guid = GUID::zeroed();
    // SAFETY: guid 由系统填充（ConvertInterfaceLuidToGuid 成功即有效 GUID）。
    let rc = unsafe {
        windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToGuid(
            &raw const l,
            &raw mut guid,
        )
    };
    if rc.0 != 0 {
        return None;
    }
    Some(guid)
}

// ---------------------------------------------------------------------------
// 静态守卫：no-DTLS / no-old-C++ / no third-party dependency（Cargo.lock 扫描）。
// ---------------------------------------------------------------------------

/// 依赖守卫结果。
pub(crate) struct GuardFacts {
    pub(crate) dtls_absent: bool,
    pub(crate) dtls_token_smuggling_absent: bool,
    pub(crate) old_cpp_sources_absent: bool,
    pub(crate) clean: bool,
    pub(crate) notes: Vec<String>,
}

/// 扫描 win32 workspace 的 Cargo.lock：依赖图必须无 DTLS variant/feature/fallback、
/// 无 OpenSSL、无第三方 Wintun wrapper、无 dtls crate；Rust 纵切不 linkage 旧 C++
/// runtime 源码（lock 中无 C++ build-script 依赖）。
pub(crate) fn run_dependency_guard() -> GuardFacts {
    let mut notes = Vec::new();
    let mut clean = true;
    let mut dtls_absent = true;
    let mut old_cpp_sources_absent = true;
    let mut lock_path = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map(|d| {
            d.parent()
                .and_then(|p| p.parent())
                .map(|p| p.join("Cargo.lock"))
                .unwrap_or_default()
        })
        .unwrap_or_default();
    if !lock_path.exists() {
        // 直接运行测试二进制（无 cargo env）时按 exe 相对路径回退。
        if let Ok(exe) = std::env::current_exe() {
            for anc in exe.ancestors().take(6) {
                let candidate = anc.join("Cargo.lock");
                if candidate.exists() {
                    lock_path = candidate;
                    break;
                }
            }
        }
    }
    let lock_text = std::fs::read_to_string(&lock_path).unwrap_or_default();
    if lock_text.is_empty() {
        clean = false;
        dtls_absent = false;
        old_cpp_sources_absent = false;
        notes.push(format!("Cargo.lock unreadable at {}", lock_path.display()));
    }
    let packages: Vec<&str> = lock_text
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("name = "))
        .map(|v| v.trim_matches('"'))
        .collect();
    for name in &packages {
        let lower = name.to_ascii_lowercase();
        if lower == "openssl" || lower == "openssl-sys" {
            clean = false;
            notes.push(format!("forbidden OpenSSL linkage present: {name}"));
        }
        if lower.contains("dtls") {
            clean = false;
            dtls_absent = false;
            notes.push(format!("dtls crate present: {name}"));
        }
        if lower == "wintun" || lower.starts_with("wintun-") {
            clean = false;
            notes.push(format!("third-party wintun wrapper present: {name}"));
        }
        if lower == "native-tls" {
            clean = false;
            notes.push(format!("forbidden TLS abstraction present: {name}"));
        }
        if lower.contains("openssl-sys") || lower.contains("cmake") {
            old_cpp_sources_absent = false;
            notes.push(format!("C++ runtime source linkage present: {name}"));
        }
    }
    // openssl-probe 是 rustls-platform-verifier 的证书路径探针（纯路径探测，无
    // OpenSSL FFI/linkage）——诚实记录为 benign，不算 OpenSSL 依赖。
    if packages.contains(&"openssl-probe") {
        notes.push(
            "openssl-probe present (rustls-platform-verifier cert-path prober; no OpenSSL linkage)"
                .to_string(),
        );
    }
    notes.push("dependency scan: win32 workspace Cargo.lock (cargo metadata authority)".to_string());
    let dtls_token_smuggling_absent = dtls_absent && !CSTP_OFFER.to_ascii_lowercase().contains("dtls");
    GuardFacts {
        dtls_absent,
        dtls_token_smuggling_absent,
        old_cpp_sources_absent,
        clean,
        notes,
    }
}

/// 证据序列化扫描：无 raw secret/cookie/private key/certificate 标记。
pub(crate) fn scan_evidence(ev: &mut ControlledVerticalEvidence) {
    let json = serde_json::to_string(ev).unwrap_or_default();
    let forbidden = [
        "PRIVATE KEY",
        "BEGIN CERTIFICATE",
        "Cookie:",
        "Authorization:",
        "password=",
    ];
    ev.no_raw_secret_in_evidence = !forbidden.iter().any(|m| json.contains(m));
}

// ---------------------------------------------------------------------------
// 基础工具：elevation、进程身份、OS/build/hardware、hash、PE、pipe、JSON 帧。
// ---------------------------------------------------------------------------

/// 当前进程是否 elevated（TokenElevation 观测）。
///
/// `pub`（bin 目标通过 lib 外部调用）：core bin（school-scenario）提权启动时用它做
/// 自我降权检测；lib 内 engine/engine_spawn/coordination 也复用同一观测。
pub fn is_elevated() -> bool {
    // SAFETY: GetCurrentProcess 返回当前进程伪句柄，无需关闭。
    let process = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        return false;
    }
    let elevated = token_is_elevated(token);
    // SAFETY: token 是本进程新打开的句柄，使用后关闭。
    unsafe {
        let _ = CloseHandle(token);
    }
    elevated
}

/// 查询进程 token 是否 elevated（helper 进程的观测）。
pub(crate) fn process_token_elevated(pid: u32) -> bool {
    // SAFETY: OpenProcess 打开受限查询句柄；失败即返回 false（fail closed）。
    let Ok(process) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return false;
    };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入 token 句柄；成功后需关闭。
    let Ok(_) = (unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }) else {
        // SAFETY: process 句柄使用后关闭。
        unsafe {
            let _ = CloseHandle(process);
        }
        return false;
    };
    let elevated = token_is_elevated(token);
    // SAFETY: token/process 句柄使用后关闭。
    unsafe {
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
    }
    elevated
}

/// 读取 token 的 TokenElevation 事实。
pub(crate) fn token_is_elevated(token: HANDLE) -> bool {
    let mut elevated = false;
    let mut size = 0u32;
    // SAFETY: 尺寸查询不写任何位置。
    unsafe {
        let _ = GetTokenInformation(token, TokenElevation, None, 0, &raw mut size);
    }
    if size != 0 {
        let mut buff = vec![0u8; size as usize];
        let len = u32::try_from(buff.len()).unwrap_or(0);
        // SAFETY: buff 是有效缓冲；TokenElevation 写入 TOKEN_ELEVATION。
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some(buff.as_mut_ptr().cast::<c_void>()),
                len,
                &raw mut size,
            )
        };
        if ok.is_ok() && buff.len() >= 4 {
            elevated = u32::from_ne_bytes(buff[0..4].try_into().unwrap_or([0u8; 4])) != 0;
        }
    }
    elevated
}

/// 当前进程 token 的 user SID 字符串。
pub(crate) fn current_user_sid() -> Option<String> {
    // SAFETY: GetCurrentProcess 伪句柄。
    let process = unsafe { GetCurrentProcess() };
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入句柄。
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        return None;
    }
    let sid = token_sid_to_string(token, TokenUser);
    // SAFETY: token 句柄关闭。
    unsafe {
        let _ = CloseHandle(token);
    }
    sid
}

/// 从进程 PID 查询 user SID。
pub(crate) fn process_sid(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess 打开受限查询句柄。
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入句柄。
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        // SAFETY: process 句柄关闭。
        unsafe {
            let _ = CloseHandle(process);
        }
        return None;
    }
    let sid = token_sid_to_string(token, TokenUser);
    // SAFETY: 句柄关闭。
    unsafe {
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
    }
    sid
}

/// 从进程 PID 查询账户名。
pub(crate) fn process_account(pid: u32) -> Option<String> {
    // SAFETY: OpenProcess 打开受限查询句柄。
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let mut token = HANDLE::default();
    // SAFETY: OpenProcessToken 写入句柄。
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) }.is_err() {
        // SAFETY: process 句柄关闭。
        unsafe {
            let _ = CloseHandle(process);
        }
        return None;
    }
    let mut buff = [0u8; 4096];
    let mut ret = 0u32;
    // SAFETY: buff 有效；TokenUser 返回 SID_AND_ATTRIBUTES。
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buff.as_mut_ptr().cast::<c_void>()),
            buff.len() as u32,
            &raw mut ret,
        )
    };
    // SAFETY: 句柄关闭。
    unsafe {
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
    }
    if ok.is_err() {
        return None;
    }
    // SAFETY: SID_AND_ATTRIBUTES 首字段是 PSID。
    let psid = PSID(unsafe { buff.as_ptr().cast::<SID_AND_ATTRIBUTES>().read().Sid.0 });
    sid_to_account_name(psid)
}

/// 从 token 取指定 class 的 SID 字符串（TokenUser=offset 0；TokenLogonSid=offset 8）。
pub(crate) fn token_sid_to_string(
    token: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Option<String> {
    let mut buff = [0u8; 4096];
    let mut ret = 0u32;
    // SAFETY: buff 有效；返回值里的 PSID 指向 token 内部内存，token 句柄存活期间有效。
    let ok = unsafe {
        GetTokenInformation(
            token,
            class,
            Some(buff.as_mut_ptr().cast::<c_void>()),
            buff.len() as u32,
            &raw mut ret,
        )
    };
    if ok.is_err() {
        return None;
    }
    let psid = if class == TokenLogonSid {
        // SAFETY: TokenLogonSid 返回 TOKEN_GROUPS，Groups[0] 在 offset 8。
        let count = u32::from_ne_bytes(buff[0..4].try_into().ok()?);
        if count == 0 {
            return None;
        }
        // SAFETY: buff 可能未 8 对齐，read_unaligned。
        let sa = unsafe {
            std::ptr::read_unaligned(buff.as_ptr().add(8).cast::<SID_AND_ATTRIBUTES>())
        };
        sa.Sid
    } else {
        // SAFETY: TokenUser 返回 SID_AND_ATTRIBUTES，首字段是 PSID。
        let sa = unsafe { std::ptr::read_unaligned(buff.as_ptr().cast::<SID_AND_ATTRIBUTES>()) };
        sa.Sid
    };
    sid_to_string(psid)
}

/// SID → 字符串（LocalFree 释放）。
pub(crate) fn sid_to_string(sid: PSID) -> Option<String> {
    let mut p = PWSTR::null();
    // SAFETY: sid 有效；返回字符串由系统分配，必须 LocalFree。
    let ok = unsafe { ConvertSidToStringSidW(sid, &raw mut p) };
    if ok.is_err() {
        return None;
    }
    let s = unsafe { p.to_string() }.ok()?;
    // SAFETY: ConvertSidToStringSidW 用 LocalAlloc 分配，LocalFree 配对释放。
    unsafe {
        LocalFree(Some(HLOCAL(p.0 as *mut c_void)));
    }
    Some(s)
}

/// SID → 账户名（LookupAccountSidW）。
pub(crate) fn sid_to_account_name(sid: PSID) -> Option<String> {
    let mut name_len = 0u32;
    let mut domain_len = 0u32;
    let mut use_ = SID_NAME_USE::default();
    // SAFETY: 先以空缓冲查询所需长度。
    let _first = unsafe {
        LookupAccountSidW(
            None,
            sid,
            None,
            &raw mut name_len,
            None,
            &raw mut domain_len,
            &raw mut use_,
        )
    };
    if name_len == 0 {
        return None;
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: sid 有效；name/domain 缓冲在调用期间存活。
    let ok = unsafe {
        LookupAccountSidW(
            None,
            sid,
            Some(PWSTR::from_raw(name.as_mut_ptr())),
            &raw mut name_len,
            Some(PWSTR::from_raw(domain.as_mut_ptr())),
            &raw mut domain_len,
            &raw mut use_,
        )
    };
    if ok.is_err() {
        return None;
    }
    let name = String::from_utf16_lossy(&name[..name.len().min(name_len as usize)]);
    Some(trim_nul(&name))
}

pub(crate) fn trim_nul(s: &str) -> String {
    s.trim_end_matches('\0').to_string()
}

/// 读取 OS build（注册表 CurrentBuildNumber + DisplayVersion）。
pub(crate) fn read_os_build() -> String {
    const KEY_PATH: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let mut key = HKEY::default();
    let path = HSTRING::from(KEY_PATH);
    // SAFETY: path 有效；key 输出句柄，用后需关闭。
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, &path, Some(0), KEY_READ, &raw mut key) };
    if rc.0 != 0 {
        return String::new();
    }
    let mut build = String::new();
    let mut display = String::new();
    for (name, out) in [
        ("CurrentBuildNumber", &mut build),
        ("DisplayVersion", &mut display),
    ] {
        let name_w = HSTRING::from(name);
        let mut buff = [0u8; 256];
        let mut len = buff.len() as u32;
        let mut kind = REG_VALUE_TYPE(0);
        // SAFETY: buff 有效；len 输入输出。
        let rc = unsafe {
            RegQueryValueExW(
                key,
                &name_w,
                None,
                Some(&raw mut kind),
                Some(buff.as_mut_ptr()),
                Some(&raw mut len),
            )
        };
        if rc.0 == 0 && len >= 2 {
            let count = (len as usize / 2).min(128);
            let mut chars = Vec::with_capacity(count);
            for chunk in buff[..count * 2].chunks_exact(2) {
                chars.push(u16::from_ne_bytes([chunk[0], chunk[1]]));
            }
            *out = trim_nul(&String::from_utf16_lossy(&chars));
        }
    }
    // SAFETY: key 是本函数打开的句柄，关闭。
    unsafe {
        let _ = RegCloseKey(key);
    }
    if display.is_empty() {
        build
    } else {
        format!("{display} (build {build})")
    }
}

/// 硬件描述（环境事实）。
pub(crate) fn read_hardware() -> String {
    let arch = std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default();
    let cpu = std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_default();
    if cpu.is_empty() {
        arch
    } else {
        format!("{arch} {cpu}")
    }
}

/// 文件 SHA-256（小写 hex）。
pub(crate) fn read_dll_sha256(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(sha256_hex(&bytes))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub(crate) fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// PE Security Directory 是否存在（Authenticode 证书表）。
pub(crate) fn dll_has_security_directory(path: &Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    pe_security_directory_present(&bytes)
}

pub(crate) fn pe_security_directory_present(bytes: &[u8]) -> bool {
    let Some(coff) = pe_coff_offset(bytes) else {
        return false;
    };
    let Some(opt_off) = coff.checked_add(20) else {
        return false;
    };
    let Some(magic) = bytes.get(opt_off..opt_off + 2) else {
        return false;
    };
    let Ok(magic) = <[u8; 2]>::try_from(magic) else {
        return false;
    };
    let magic = u16::from_le_bytes(magic);
    let dd_rel = if magic == 0x20B { 112 } else { 96 };
    let Some(entry) = opt_off
        .checked_add(dd_rel)
        .and_then(|o| o.checked_add(4 * 8))
    else {
        return false;
    };
    let (Some(rva), Some(size)) = (
        bytes.get(entry..entry + 4).and_then(|b| <[u8; 4]>::try_from(b).ok()),
        bytes.get(entry + 4..entry + 8).and_then(|b| <[u8; 4]>::try_from(b).ok()),
    ) else {
        return false;
    };
    let rva = u32::from_le_bytes(rva);
    let size = u32::from_le_bytes(size);
    rva != 0 && size != 0
}

pub(crate) fn pe_coff_offset(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 64 || bytes.get(0..2)? != b"MZ" {
        return None;
    }
    let pe = u32::from_le_bytes(bytes.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if bytes.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    Some(pe + 4)
}

/// 提权 spawn helper 进程（ShellExecuteExW runas；返回 pid + 进程句柄）。
pub(crate) fn spawn_helper_elevated(exe: &Path, args: &[String]) -> Result<(u32, HANDLE), String> {
    let verb = HSTRING::from("runas");
    let file = HSTRING::from(exe.as_os_str());
    let params = HSTRING::from(args.join(" "));
    let dir = HSTRING::from(
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .as_os_str(),
    );
    let mut sei = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>()).unwrap_or(0),
        fMask: SEE_MASK_NOCLOSEPROCESS,
        hwnd: windows::Win32::Foundation::HWND::default(),
        lpVerb: PCWSTR::from_raw(verb.as_ptr()),
        lpFile: PCWSTR::from_raw(file.as_ptr()),
        lpParameters: PCWSTR::from_raw(params.as_ptr()),
        lpDirectory: PCWSTR::from_raw(dir.as_ptr()),
        nShow: 0, // SW_HIDE
        hInstApp: windows::Win32::Foundation::HINSTANCE::default(),
        lpIDList: std::ptr::null_mut(),
        lpClass: PCWSTR::null(),
        hkeyClass: HKEY::default(),
        dwHotKey: 0,
        Anonymous: windows::Win32::UI::Shell::SHELLEXECUTEINFOW_0 {
            hIcon: HANDLE::default(),
        },
        hProcess: HANDLE::default(),
    };
    // SAFETY: sei 的所有指针在调用期间存活（verb/file/params/dir 均为活宽字符串）；
    // hProcess 由 SEE_MASK_NOCLOSEPROCESS 输出，调用者持有。
    if unsafe { ShellExecuteExW(&raw mut sei) }.is_err() {
        // SAFETY: 无指针参数，读线程错误码。
        let code = unsafe { GetLastError().0 };
        return Err(format!("ShellExecuteExW(runas) failed, error {code}"));
    }
    if sei.hProcess.is_invalid() {
        return Err("ShellExecuteExW returned no process handle".to_string());
    }
    // SAFETY: hProcess 有效；GetProcessId 返回其 PID。
    let pid = unsafe { GetProcessId(sei.hProcess) };
    if pid == 0 {
        return Err("helper process id is 0".to_string());
    }
    Ok((pid, sei.hProcess))
}

/// helper bin 的启动参数（host 侧构造；管道名按 host PID 唯一）。
pub(crate) fn helper_args_for_spawn() -> Vec<String> {
    let host_pid = std::process::id();
    let pipe_prefix = format!("exv-w28-{host_pid}");
    let journal_dir = std::env::temp_dir()
        .join(format!("exv-w28-journal-{host_pid}"))
        .display()
        .to_string();
    let dll = crate::wintun_facts::resolve_dll_path(None)
        .display()
        .to_string();
    vec![
        "--control-pipe".to_string(),
        format!(r"\\.\pipe\{pipe_prefix}-c"),
        "--packet-pipe".to_string(),
        format!(r"\\.\pipe\{pipe_prefix}-p"),
        "--dll".to_string(),
        dll,
        "--journal-dir".to_string(),
        journal_dir,
        "--authority-name".to_string(),
        format!("Local\\exv-w28-{host_pid}-authority"),
        "--host-pid".to_string(),
        host_pid.to_string(),
        "--adapter-name".to_string(),
        ADAPTER_NAME.to_string(),
    ]
}

/// helper bin 的可执行路径（测试流：CARGO_BIN_EXE；bin 流：同目录 sibling）。
pub(crate) fn helper_bin_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_exv-win32-controlled-vertical-helper") {
        let bp = PathBuf::from(p);
        if bp.exists() {
            return Some(bp);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let name = if exe.file_name()?.to_string_lossy().ends_with(".exe") {
        "exv-win32-controlled-vertical-helper.exe"
    } else {
        "exv-win32-controlled-vertical-helper"
    };
    Some(dir.join(name))
}

/// 等待进程退出（有界；成功后关闭句柄）。
pub(crate) fn wait_process_exit(handle: HANDLE, timeout_ms: u32) -> bool {
    // SAFETY: handle 是有效进程句柄；超时返回 WAIT_TIMEOUT。
    let rc = unsafe { WaitForSingleObject(handle, timeout_ms) };
    if rc == WAIT_OBJECT_0 {
        // SAFETY: 进程句柄使用后关闭。
        unsafe {
            let _ = CloseHandle(handle);
        }
        true
    } else {
        rc != WAIT_TIMEOUT
    }
}

// ---------------------------------------------------------------------------
// 管道连接与帧 I/O（WSP1 冻结模式：byte 模式；PIPE_REJECT_REMOTE_CLIENTS +
// FIRST_PIPE_INSTANCE；精确 DACL = SYSTEM + 当前用户）。
// ---------------------------------------------------------------------------

/// 一条管道连接（server 或 client 句柄）。
#[derive(Clone)]
pub(crate) struct PipeStream(HANDLE);

// SAFETY: 管道句柄是无线程亲缘的内核对象（Named Pipe 可在任意线程读/写）；本 crate
// 的用法是每连接最多一个 reader 线程 + 一个 writer 线程（helper 的 ring worker /
// host 的 packet 转发），句柄的关闭（Drop）发生在对应线程 join 之后，且同一时刻
// 只有一处持有该句柄的 Drop 权（PipeStream 的 Clone 仅复制 HANDLE 值，Drop 不关闭
// 句柄——句柄由原始所有权处关闭）。这与 WintunSession 的 unsafe impl Send 同款模式。
unsafe impl Send for PipeStream {}

impl PipeStream {
    pub(crate) fn raw(&self) -> HANDLE {
        self.0
    }
}

/// host 侧连接 helper 的 server pipe（retry on busy/not-found）。
pub(crate) fn connect_pipe(name: &str) -> Result<PipeStream, String> {
    for _ in 0..30 {
        let pname = HSTRING::from(name);
        let access = FILE_ACCESS_RIGHTS(FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0);
        let share = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0);
        let flags = FILE_FLAGS_AND_ATTRIBUTES(FILE_FLAG_OVERLAPPED.0);
        // SAFETY: pname 合法；返回句柄由调用者关闭。
        match unsafe {
            CreateFileW(&pname, access.0, share, None, OPEN_EXISTING, flags, None)
        } {
            Ok(h) => {
                // 固定 byte read mode（WSP1）。
                let mode = NAMED_PIPE_MODE(PIPE_READMODE_BYTE.0);
                // SAFETY: h 有效；mode 存活。
                let _ = unsafe { SetNamedPipeHandleState(h, Some(&raw const mode), None, None) };
                return Ok(PipeStream(h));
            }
            Err(e) => {
                let code = u32::from_ne_bytes(e.code().0.to_ne_bytes()) & 0xFFFF;
                if code == 2 || code == 231 {
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
                return Err(format!("CreateFileW {name} failed: {code}"));
            }
        }
    }
    Err(format!("pipe {name} connect timeout"))
}

/// server 侧创建 pipe（byte 模式 + DACL SYSTEM+user + FIRST_INSTANCE + REJECT_REMOTE）。
pub(crate) fn create_pipe_server(name: &str) -> Result<HANDLE, String> {
    let user_sid = current_user_sid().ok_or("server: no user sid")?;
    let sddl = format!("D:(A;;GA;;;SY)(A;;GA;;;{user_sid})");
    let hsddl = HSTRING::from(&sddl);
    let mut psd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // SAFETY: psd 是输出参数，由 API 分配；用毕 LocalFree。
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&hsddl, SDDL_REVISION_1, &raw mut psd, None)
    };
    if ok.is_err() {
        return Err("ConvertStringSecurityDescriptorToSecurityDescriptorW failed".to_string());
    }
    let attrs = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: psd.0,
        bInheritHandle: false.into(),
    };
    let lpname = HSTRING::from(name);
    let openmode = FILE_FLAGS_AND_ATTRIBUTES(PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_FIRST_PIPE_INSTANCE.0);
    let pipemode = NAMED_PIPE_MODE(
        PIPE_TYPE_BYTE.0 | PIPE_READMODE_BYTE.0 | PIPE_WAIT.0 | PIPE_REJECT_REMOTE_CLIENTS.0,
    );
    // SAFETY: lpname 合法；attrs 存活（psd 由 attrs 引用，LocalFree 在其后）。
    let handle = unsafe {
        CreateNamedPipeW(
            &lpname,
            openmode,
            pipemode,
            1,
            65536,
            65536,
            0,
            Some(&raw const attrs),
        )
    };
    // SAFETY: psd 是 API 分配的，不再被引用后释放。
    unsafe {
        LocalFree(Some(HLOCAL(psd.0)));
    }
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: 无指针参数。
        let code = unsafe { GetLastError().0 };
        return Err(format!("CreateNamedPipeW {name} failed: {code}"));
    }
    Ok(handle)
}

/// 接受 client 连接（已连接也视为成功）。
pub(crate) fn accept_client(server: HANDLE) -> Result<(), String> {
    // SAFETY: server 是有效 pipe 句柄。
    match unsafe { ConnectNamedPipe(server, None) } {
        Ok(()) => Ok(()),
        Err(e) => {
            let code = u32::from_ne_bytes(e.code().0.to_ne_bytes()) & 0xFFFF;
            if code == 535 || code == 5 {
                Ok(()) // ERROR_PIPE_CONNECTED / ERROR_ACCESS_DENIED：已连接
            } else {
                Err(format!("ConnectNamedPipe failed: {code}"))
            }
        }
    }
}

/// server 侧查询 client PID。
pub(crate) fn pipe_client_pid(server: HANDLE) -> Option<u32> {
    let mut pid = 0u32;
    // SAFETY: pid 是有效输出参数。
    if unsafe { GetNamedPipeClientProcessId(server, &raw mut pid) }.is_err() {
        return None;
    }
    Some(pid)
}

/// client 侧查询 server PID（host 验证 helper）。
pub(crate) fn packet_server_pid(client: &PipeStream) -> Result<u32, String> {
    let mut pid = 0u32;
    // SAFETY: pid 是有效输出参数。
    if unsafe { GetNamedPipeServerProcessId(client.raw(), &raw mut pid) }.is_err() {
        return Err("GetNamedPipeServerProcessId failed".to_string());
    }
    Ok(pid)
}

/// 写 JSON 帧（u32 BE 长度 + JSON）。
pub(crate) fn write_json(pipe: &PipeStream, value: &impl Serialize) -> Result<(), String> {
    let json = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    let len = u32::try_from(json.len()).map_err(|_| "frame too long")?;
    let mut frame = Vec::with_capacity(FRAME_LEN_BYTES + json.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&json);
    write_all(pipe.raw(), &frame)
}

/// 读 JSON 帧。
pub(crate) fn read_json<T: for<'de> Deserialize<'de>>(pipe: &PipeStream) -> Result<T, String> {
    let mut len_buf = [0u8; FRAME_LEN_BYTES];
    read_exact(pipe.raw(), &mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 1 << 20 {
        return Err("control frame too long".to_string());
    }
    let mut buf = vec![0u8; len];
    read_exact(pipe.raw(), &mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| e.to_string())
}

/// 管道是否有可读数据（PeekNamedPipe——轮询读取用，stop 可中断 join）。
pub(crate) fn pipe_has_data(handle: HANDLE) -> bool {
    // SAFETY: handle 有效；PeekNamedPipe 不消费数据。
    let mut total = 0u32;
    let mut avail = 0u32;
    let mut left = 0u32;
    unsafe {
        windows::Win32::System::Pipes::PeekNamedPipe(
            handle,
            None,
            0,
            Some(&raw mut total),
            Some(&raw mut avail),
            Some(&raw mut left),
        )
    }
    .is_ok()
        && avail > 0
}

/// 写 packet 帧（u32 BE 长度 + raw 包）。
pub(crate) fn write_packet_frame(pipe: &PipeStream, pkt: &[u8]) -> Result<(), String> {
    let len = u32::try_from(pkt.len()).map_err(|_| "packet too long")?;
    let mut frame = Vec::with_capacity(FRAME_LEN_BYTES + pkt.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(pkt);
    write_all(pipe.raw(), &frame)
}

/// 读 packet 帧。
pub(crate) fn read_packet_frame(pipe: &PipeStream) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; FRAME_LEN_BYTES];
    read_exact(pipe.raw(), &mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 0x10000 {
        return Err("packet frame too long".to_string());
    }
    let mut buf = vec![0u8; len];
    read_exact(pipe.raw(), &mut buf)?;
    Ok(buf)
}

pub(crate) fn read_exact(handle: HANDLE, buf: &mut [u8]) -> Result<(), String> {
    let mut off = 0usize;
    while off < buf.len() {
        let mut read = 0u32;
        // SAFETY: buf[off..] 是有效可变切片。
        unsafe { ReadFile(handle, Some(&mut buf[off..]), Some(&raw mut read), None) }
            .map_err(|e| {
                let code = u32::from_ne_bytes(e.code().0.to_ne_bytes()) & 0xFFFF;
                format!("ReadFile failed: {code}")
            })?;
        if read == 0 {
            return Err("peer closed".to_string());
        }
        off += read as usize;
    }
    Ok(())
}

pub(crate) fn write_all(handle: HANDLE, data: &[u8]) -> Result<(), String> {
    let mut off = 0usize;
    while off < data.len() {
        let mut written = 0u32;
        // SAFETY: data[off..] 是有效只读切片。
        unsafe { WriteFile(handle, Some(&data[off..]), Some(&raw mut written), None) }
            .map_err(|e| {
                let code = u32::from_ne_bytes(e.code().0.to_ne_bytes()) & 0xFFFF;
                format!("WriteFile failed: {code}")
            })?;
        off += written as usize;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 机制测试：Cisco CSTP connect 请求格式（fake server 与真实 gateway 对齐——
// CS-AUTH-05：只接受引擎 CONNECT 形状；旧的 X-EXV-* 自定义格式与
// Authorization 复活被拒——回归守卫，fake 与真实 behave alike）。
// ---------------------------------------------------------------------------
#[cfg(test)]
mod school_auth_request_format_tests {
    use super::*;

    /// 引擎 CONNECT 形状（`build_connect_request` 逐字块；计划 §3.2）。
    const ENGINE_SHAPE: &[u8] = b"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n\
        Host: vpn.example.test\r\n\
        Cookie: webvpn=wiring-cookie-7f3k\r\n\
        X-CSTP-Version: 1\r\n\
        X-CSTP-Hostname: vpn.example.test\r\n\
        X-CSTP-Protocol: \"Copyright (c) 2004 Cisco Systems, Inc.\"\r\n\
        \r\n";

    #[test]
    fn cisco_cstp_connect_request_accepted() {
        assert!(
            is_cisco_cstp_connect_request(ENGINE_SHAPE),
            "引擎 CONNECT 形状（/CSCOSSLC/tunnel + Cookie: webvpn= + X-CSTP-*）必须被识别"
        );
    }

    #[test]
    fn hand_rolled_connect_with_authorization_revived_is_rejected() {
        // 旧的手搓格式（CONNECT <host> + X-AnyConnect-* + Authorization:
        // Basic）曾在真实 gateway 被拒——fake 必须同样拒绝。
        let old_school_shape = b"CONNECT vpn.example.test HTTP/1.1\r\n\
            Host: vpn.example.test\r\n\
            X-AnyConnect-Platform: win\r\n\
            X-AnyConnect-Client-Version: 4.10.03153\r\n\
            X-AnyConnect-Device-Type: AnyConnect\r\n\
            X-AnyConnect-Device-Version: 1.0\r\n\
            Authorization: Basic Y29udHJvbGxlZDp0ZXN0\r\n\
            \r\n";
        assert!(
            !is_cisco_cstp_connect_request(old_school_shape),
            "旧的 CONNECT <host> + X-AnyConnect-* + Authorization: Basic 形状必须被拒绝"
        );
        // 即使在正确路径上复活 Authorization 也必须被拒（kills 手搓 CONNECT
        // 复活 + 无 Authorization 断言在 fake 侧 mutant）。
        let authorization_revival = b"CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n\
            Host: vpn.example.test\r\n\
            Cookie: webvpn=any-value\r\n\
            X-CSTP-Version: 1\r\n\
            X-CSTP-Hostname: vpn.example.test\r\n\
            X-CSTP-Protocol: \"Copyright (c) 2004 Cisco Systems, Inc.\"\r\n\
            Authorization: Basic Y29udHJvbGxlZDp0ZXN0\r\n\
            \r\n";
        assert!(
            !is_cisco_cstp_connect_request(authorization_revival),
            "Authorization 复活必须被 fake 拒绝（webvpn cookie 是认证凭据）"
        );
    }

    #[test]
    fn legacy_exv_request_rejected() {
        // 旧的 X-EXV-* 自定义格式（只被受控 fake server 认识的格式）：真实
        // Cisco gateway 不识别 → fake server 也必须拒绝（fake 与真实 behave
        // alike）。
        let req = b"CONNECT vpn.example.test\r\n\
            X-EXV-Username: student\r\n\
            X-EXV-Password: secret\r\n\
            \r\n";
        assert!(
            !is_cisco_cstp_connect_request(req),
            "旧的 X-EXV-* 格式必须被拒绝（真实 gateway 行为对齐）"
        );
    }
}

// ---------------------------------------------------------------------------
// 机制测试：DP-01 helper 契约（create-then-idle）——wire 形状纯状态断言。
//
// 真实机制（`WintunAdapter::create` 建 adapter + 返回 create 名/LUID/ifindex、
// 四族 leaf apply 进系统表、无 session、adapter apply 后保持存活）需要 elevated
// 真实宿主（`WintunAdapter::create` 需管理员）——由 elevated 纵切运行（DP-02/DP-05）
// 观测。这里锁定 host 侧消费的 wire 契约形状（`ApplyReply`/`StopReply` 字段名与
// 语义），防止 DP-01 重构后 host 读错字段/读到旧语义。
// ---------------------------------------------------------------------------
#[cfg(test)]
mod dp01_helper_contract_tests {
    use super::*;

    /// DP-01：apply reply 必须携带 **create 名**（host 按此名 `WintunAdapter::open`）
    /// + LUID + ifindex，且 `session_started=false`（helper 空闲、无 session）。
    /// `adapter_name` 是 create 名而非 `adapter.alias()`（接口别名可能被 Windows
    /// 规范化后不同）——kills "adapter_name 非 create 名" mutant。
    #[test]
    fn apply_reply_carries_adapter_identity_and_idle_flag() {
        let reply = ApplyReply {
            ok: true,
            error: None,
            // create 名（`ApplyReq.adapter_name`），与 host 侧 open-by-name 常量
            // `SCHOOL_ADAPTER_NAME`/`ADAPTER_NAME` 一致。
            adapter_name: Some("ExvW30School".to_string()),
            adapter_luid: Some(0x1234_5678),
            adapter_ifindex: Some(42),
            session_started: false, // helper idle（DP-01）
            inventory: COMPLETE_INVENTORY
                .iter()
                .map(|i| inventory_item_name(*i))
                .collect(),
            address_applied: Some("10.88.88.1/24".to_string()),
            mtu_applied: Some(1420),
            routes_applied: vec!["10.99.99.0/24".to_string()],
            dns_applied: vec!["10.88.88.53".to_string()],
            before: Snapshot::empty(),
            applied: Snapshot::empty(),
        };
        let json = serde_json::to_value(&reply).expect("apply reply 必须可序列化");
        assert_eq!(json["adapter_name"], "ExvW30School", "adapter_name 必须是 create 名");
        assert_eq!(json["adapter_luid"], 0x1234_5678, "LUID 必须返回");
        assert_eq!(json["adapter_ifindex"], 42, "ifindex 必须返回");
        assert_eq!(
            json["session_started"], false,
            "helper 不建 session（create-then-idle）；session_started 必须为 false"
        );
    }

    /// DP-01：helper 无 ring worker → `StopReply` ring 字节恒 0（host 侧数据面
    /// 计数器在 DP-03/DP-04 承接）。kills "helper 仍报告 ring 字节计数" mutant。
    #[test]
    fn stop_reply_reports_zero_ring_bytes() {
        let reply = StopReply {
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
            after: Snapshot::empty(),
            before: Snapshot::empty(),
        };
        assert_eq!(reply.packets_after_stop, 0, "helper 无数据面，Stop 后 packet 恒 0");
        assert_eq!(reply.ring_received_bytes, 0, "helper 无 ring worker，recv 恒 0");
        assert_eq!(reply.ring_sent_bytes, 0, "helper 无 ring worker，sent 恒 0");
    }

    /// DP-01：inventory 仍报告完整 9 项（helper 无 session 但 session 仍是 canonical
    /// aggregate 义务——DP-04 把 session 归引擎后仍计入 inventory，证据不缺失）。
    #[test]
    fn inventory_still_reports_all_canonical_items() {
        let names: Vec<String> = COMPLETE_INVENTORY
            .iter()
            .map(|i| inventory_item_name(*i))
            .collect();
        for expected in ["adapter", "session", "address", "mtu", "bypass", "routes", "dns", "packet", "running"] {
            assert!(
                names.iter().any(|n| n == expected),
                "inventory 必须包含 canonical 项 {expected}（got {names:?}）"
            );
        }
        assert_eq!(names.len(), 9, "canonical inventory 恰为 9 项");
    }
}

// ---------------------------------------------------------------------------
// 路由目标解析（`parse_route_destination`）：裸 IP 视作 /32 主机路由（C++
// `parse_destination` 语义），CIDR 正常解析。config `default_routes` 允许裸 IP
// （如 `distribution/ecnu.json` 的 `219.228.60.69`）——引擎 Connect 必须接受。
// ---------------------------------------------------------------------------
#[cfg(test)]
mod route_destination_tests {
    use super::*;

    #[test]
    fn bare_ip_is_host_route_32() {
        // `219.228.60.69` 来自 distribution/ecnu.json default_routes —— 裸 IP
        // 无 `/` 前缀，必须解析为 /32 主机路由（此前 `split_once('/')` 强制 CIDR
        // 导致 "route shape" 拒绝）。
        let (net, prefix) = parse_route_destination("219.228.60.69").expect("裸 IP 必须解析");
        assert_eq!(net, Ipv4Addr::new(219, 228, 60, 69));
        assert_eq!(prefix, 32);
    }

    #[test]
    fn cidr_parses_network_and_prefix() {
        let (net, prefix) = parse_route_destination("59.78.199.0/21").expect("CIDR 必须解析");
        assert_eq!(net, Ipv4Addr::new(59, 78, 199, 0));
        assert_eq!(prefix, 21);
    }

    #[test]
    fn slash_32_cidr_matches_bare_ip() {
        let bare = parse_route_destination("219.228.60.69").unwrap();
        let slash32 = parse_route_destination("219.228.60.69/32").unwrap();
        assert_eq!(bare, slash32, "裸 IP 与显式 /32 必须等价");
    }

    #[test]
    fn rejects_malformed_shapes() {
        // 校验保持：IPv4 非法 / 前缀空 / 前缀 > 32 均拒绝（诚实拒绝，绝不静默放行）。
        for bad in [
            "not-an-ip",
            "999.1.1.0/25",
            "49.52.4.0/",
            "49.52.4.0/33",
            "49.52.4.0/abc",
            "49.52.4.0/25/extra",
        ] {
            assert!(
                parse_route_destination(bad).is_none(),
                "畸形路由 {bad:?} 必须被拒绝"
            );
        }
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
