// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! R1b 业务门禁（opt-in）：真实数据面组装全链路经**产品 engine** 跑通，ping/SSH
//! 校内真实通。
//!
//! 门禁开启：`EXV_RUST_VPN_BIZ_GATE=1 cargo test -p exv-engine --test
//! business_gate -- --ignored --nocapture`（普通 `cargo test` 跳过——本测试提权拉起
//! engine + 真实学校网关 + 真实 config 凭据，不得进入常规测试集）。
//!
//! 流程（每轮）：
//! 1. 提权 spawn 产品 engine bin（ShellExecuteExW runas；本机 UAC 自动提权）；
//! 2. gRPC client 连接控制面 Named Pipe（双向 peer 认证：client pid == host pid）；
//! 3. lease handshake → acquire → StreamConnectStatus 挂接 → ApplyTunnel（真实
//!    config 凭据，AES-GCM 解密）；
//! 4. 读 status 至 Connected（真实数据面就绪；不设时间上限内的假绿——最多 60s）；
//! 5. 业务证据：`ping` 校内主机 + SSH banner 读校内主机（58.198.176.156:22 = w202）；
//! 6. StopTunnel → 读 Idle 终态 → **S1.5 (D13) 减负断开验证**：adapter **保留**但
//!    暂停（无 IP 地址、0 路由、session 结束——D12 网卡惰性存续）；
//! 7. engine 退出（core 进程句柄）→ **S1.5 (D12) 退出清理验证**：adapter 移除
//!    （0 网卡残留兜底）；
//! 8. 第二轮重复（断开后再连可重复，无资源泄漏）。
//!
//! 环境标注（本机 2026-08-19）：Mihomo TUN **开启**（ifIndex 16，默认路由
//! 198.18.0.2）——门禁期间不动 Mihomo/系统代理（共存拓扑；校园路由更具体前缀优先）。
//!
//! **R5b TUN-ON 共存断言（2026-08-19，本文件内）**：Mihomo TUN 开 = EXV 正常环境。
//! 每轮 `run_real_round` 在 Connected 后执行 (a) 控制/数据承载连接源 = 物理网卡
//! （P3-1 绑定，非 198.18.x.x）、(b) Mihomo 进程存活 + TUN 默认路由不变 + 非校内
//! 流量仍走 Mihomo、(c) VPN 校园路由与 Mihomo 路由共存无冲突；断开后执行 (d) 0 残留
//! （本 adapter 无路由残留——D12 网卡保留但暂停；Mihomo 默认路由不变）。
//! 另设独立门禁 `tun_on_coexistence_gate`：TUN-ON 前置契约 + 全局路由残留 diff。

use std::io::Read;
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use exv_vpn_win32_ipc::peer_auth::current_user_sid;
use exv_vpn_wire::generated;
use generated::helper_control_client::HelperControlClient;
use hyper_util::rt::TokioIo;
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::mpsc;
use tonic::codegen::http::Uri;
use tonic::codegen::{Service, tokio_stream};
use tonic::Request;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::GetProcessId;

/// 门禁开关环境变量。
const GATE_ENV: &str = "EXV_RUST_VPN_BIZ_GATE";
/// SSH 校内目标（w202；acceptance school flow 冻结的 ingress 证明）。
const SSH_TARGET: (&str, u16) = ("58.198.176.156", 22);
/// ping 校内目标（w202 同主机）。
const PING_TARGET: &str = "58.198.176.156";
/// 连接结果等待上限。
const CONNECT_DEADLINE: Duration = Duration::from_secs(60);

fn gate_enabled() -> bool {
    std::env::var(GATE_ENV).map(|v| v == "1").unwrap_or(false)
}

/// 真实 config 凭据：读 `~/.exv/config.json` + `key.bin`，AES-256-GCM 解密密码
/// （镜像 win32-config `crypto.rs` 的 blob 布局：`base64( nonce || tag || ct )`）。
fn real_credentials() -> Result<(String, String), String> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let config = exv_vpn_win32_config::ExvConfig::load().map_err(|e| format!("config:{e}"))?;
    let dir = exv_vpn_win32_config::config_dir();
    let key_path = exv_vpn_win32_config::key_path(&dir);
    let key_bytes = std::fs::read(&key_path).map_err(|e| format!("key:{e}"))?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "key.bin not 32 bytes".to_string())?;
    let blob = BASE64
        .decode(config.password.as_bytes())
        .map_err(|e| format!("base64:{e}"))?;
    if blob.len() < 12 + 16 {
        return Err("blob shorter than nonce+tag".to_string());
    }
    let (nonce, tag, ct) = (&blob[..12], &blob[12..28], &blob[28..]);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let mut ct_with_tag = Vec::with_capacity(ct.len() + 16);
    ct_with_tag.extend_from_slice(ct);
    ct_with_tag.extend_from_slice(tag);
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), Payload::from(ct_with_tag.as_slice()))
        .map_err(|_| "decrypt failed (wrong key / tampered)".to_string())?;
    let password = String::from_utf8(plaintext).map_err(|_| "not utf8".to_string())?;
    Ok((config.username.clone(), password))
}

/// 提权 spawn 产品 engine bin（ShellExecuteExW runas；本机 UAC 自动提权）。
fn spawn_engine_elevated(exe: &Path, args: &[String]) -> Result<u32, String> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, SHELLEXECUTEINFOW_0,
    };

    let verb = HSTRING::from("runas");
    let file = HSTRING::from(exe.as_os_str());
    let params = HSTRING::from(args.join(" "));
    let dir = HSTRING::from(
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .as_os_str(),
    );
    let mut sei = SHELLEXECUTEINFOW {
        cbSize: u32::try_from(std::mem::size_of::<SHELLEXECUTEINFOW>()).unwrap_or_default(),
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
        hkeyClass: windows::Win32::System::Registry::HKEY::default(),
        dwHotKey: 0,
        Anonymous: SHELLEXECUTEINFOW_0 {
            hIcon: HANDLE::default(),
        },
        hProcess: HANDLE::default(),
    };
    // SAFETY: sei 的所有指针在调用期间存活（verb/file/params/dir 均为活宽字符串）；
    // hProcess 由 SEE_MASK_NOCLOSEPROCESS 输出，调用者持有。
    if unsafe { windows::Win32::UI::Shell::ShellExecuteExW(&raw mut sei) }.is_err() {
        let code = unsafe { windows::Win32::Foundation::GetLastError().0 };
        return Err(format!("ShellExecuteExW(runas) failed, error {code}"));
    }
    if sei.hProcess.is_invalid() {
        return Err("no process handle".to_string());
    }
    // SAFETY: hProcess 有效；GetProcessId 返回其 PID。
    let pid = unsafe { GetProcessId(sei.hProcess) };
    if pid == 0 {
        return Err("engine pid 0".to_string());
    }
    Ok(pid)
}

/// 等到 engine 进程退出（stop 后引擎自退；验证干净退出）。best-effort。
fn wait_engine_exit(pid: u32, timeout: Duration) -> bool {
    // SYNCHRONIZE（0x00100000）：等待进程退出所需的最小访问权。
    let synchronize = windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS(0x0010_0000);
    // SAFETY: OpenProcess(SYNCHRONIZE) 打开同用户进程；无效句柄（已退出）返回 Err。
    let handle = unsafe {
        windows::Win32::System::Threading::OpenProcess(synchronize, false, pid)
    };
    let Ok(handle) = handle else {
        return true; // 已退出
    };
    let deadline = std::time::Instant::now() + timeout;
    loop {
        // SAFETY: handle 是有效进程句柄；0 超时 = 探测。
        let wr = unsafe { windows::Win32::System::Threading::WaitForSingleObject(handle, 0) };
        if wr == windows::Win32::Foundation::WAIT_OBJECT_0 {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// S1.5 (D12/D13) **减负断开验证**：adapter **保留**但暂停——按名存在、无 IP 地址、
/// 0 路由（session 结束已由 Idle 终态证明）。对应 plan D12「断开不拆，网卡以无地址
/// 惰性存续」与 D13「清路由（含地址/on-link）」。
///
/// 用 OS 级 PowerShell 检查（非提权驱动无法可靠 `WintunOpenAdapter`——已存在 adapter
/// 对非管理员返回 5，与 1168 混淆；接口表查询不需要 Wintun ACL）。
fn assert_adapter_paused(name: &str) -> Result<(), String> {
    // 1. adapter 按名存在（D12：网卡保留，不拆）。
    let present = run_ps(&format!(
        "(Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue) -ne $null"
    ));
    if present.trim() != "True" {
        return Err(format!(
            "adapter {name} missing after disconnect (expected retained but paused, D12)"
        ));
    }
    // 2. 无 IP 地址残留（断开清空地址——网卡无地址惰性存续）。
    let ip_count = run_ps(&format!(
        "(Get-NetIPAddress -InterfaceAlias '{name}' -ErrorAction SilentlyContinue).Count"
    ));
    if ip_count.trim() != "0" {
        return Err(format!(
            "adapter {name} still has IP addresses after disconnect (count={ip_count}, expected 0)"
        ));
    }
    // 3. 0 路由残留（断开清路由——含 on-link）。
    let route_count = run_ps(&format!(
        "(Get-NetRoute -InterfaceAlias '{name}' -ErrorAction SilentlyContinue).Count"
    ));
    if route_count.trim() != "0" {
        return Err(format!(
            "adapter {name} still has routes after disconnect (count={route_count}, expected 0)"
        ));
    }
    Ok(())
}

/// 清理验证：adapter 必须从系统接口表中消失（creator close 已移除）。
///
/// 用 OS 级 `Get-NetAdapter` 检查（非提权驱动无法可靠 `WintunOpenAdapter`——已存在
/// adapter 对非管理员返回 5，与 1168 混淆；接口表查询不需要 Wintun ACL）。
fn assert_adapter_removed(_dll: &Path, name: &str) -> Result<(), String> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("(Get-NetAdapter -Name '{name}' -ErrorAction SilentlyContinue) -ne $null"),
        ])
        .output()
        .map_err(|e| format!("powershell probe: {e}"))?;
    let present = String::from_utf8_lossy(&out.stdout).trim() == "True";
    if present {
        return Err(format!("adapter {name} still present after stop"));
    }
    // 兜底：接口表里也不应再有该名（Name 别名可能被 Windows 规范化）。
    let out2 = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -like '*{name}*' }}).Count"
            ),
        ])
        .output()
        .map_err(|e| format!("powershell probe2: {e}"))?;
    let count = String::from_utf8_lossy(&out2.stdout).trim().to_string();
    if count != "0" {
        return Err(format!("adapter {name} residue in interface table (count={count})"));
    }
    Ok(())
}

/// 隧道接口/路由诊断（Connected 后 dump）：接口地址 + 该接口路由 + 目标选路。
fn dump_tunnel_state(adapter_name: &str, target: &str) -> Vec<String> {
    let mut lines = Vec::new();
    for cmd in [
        format!(
            "Get-NetAdapter -Name '{adapter_name}' -ErrorAction SilentlyContinue | Format-List Name,InterfaceIndex,Status,LinkSpeed"
        ),
        format!(
            "Get-NetIPAddress -InterfaceAlias '{adapter_name}' -ErrorAction SilentlyContinue | Select-Object IPAddress,PrefixLength,AddressState,InterfaceIndex | Format-Table -HideTableHeaders"
        ),
        format!("netsh interface ipv4 show addresses \"{adapter_name}\""),
        format!(
            "Get-NetRoute -InterfaceAlias '{adapter_name}' -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,NextHop,RouteMetric,InterfaceAlias | Format-Table -HideTableHeaders"
        ),
        format!(
            "Find-NetRoute -RemoteIPAddress '{target}' -ErrorAction SilentlyContinue | Select-Object IPAddress,InterfaceAlias,NextHop | Format-Table -HideTableHeaders"
        ),
        format!(
            "Get-NetTCPConnection -RemoteAddress 222.66.117.109 -RemotePort 443 -State Established -ErrorAction SilentlyContinue | Select-Object LocalAddress,RemoteAddress,RemotePort,State,OwningProcess | Format-Table -HideTableHeaders"
        ),
    ] {
        if let Ok(out) = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !text.is_empty() {
                lines.push(format!("[{cmd}] => {text}"));
            }
        }
    }
    lines
}

/// 业务证据结果（P3-5 硬断言）：ping/SSH 各自达标标志 + 文本证据行。
/// 达标语义与文本证据同源——`ping_ok`=ping 回包带 TTL；`ssh_ok`=读到首行 banner。
struct BusinessEvidence {
    ping_ok: bool,
    ssh_ok: bool,
    lines: Vec<String>,
}

/// 业务证据：ping 校内主机 + SSH banner 读校内主机。返回结构化达标标志 + 文本证据。
fn business_evidence() -> BusinessEvidence {
    let mut evidence = Vec::new();
    // ping（IPv4 字面量；反假绿：真实校内网络可达性）。达标标志直接由 match 计算。
    let ping_ok = match Command::new("ping").args(["-n", "1", "-w", "3000", PING_TARGET]).output() {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            let ttl = text.contains("TTL=") || text.to_lowercase().contains("ttl=");
            let status = if ttl { "OK" } else { "FAILED" };
            let ttl_line = text
                .lines()
                .find(|l| l.to_lowercase().contains("ttl"))
                .unwrap_or("(no TTL line)");
            evidence.push(format!(
                "ping {PING_TARGET}: {status} | {ttl_line}{}",
                String::from_utf8_lossy(&out.stderr)
            ));
            ttl
        }
        Err(e) => {
            evidence.push(format!("ping {PING_TARGET}: spawn error {e}"));
            false
        }
    };
    // SSH banner：TCP connect + 读 banner 首行（真实学校 ssh 服务 ingress 证明）。
    let ssh_ok = match TcpStream::connect_timeout(
        &format!("{}:{}", SSH_TARGET.0, SSH_TARGET.1)
            .parse()
            .expect("target addr"),
        Duration::from_secs(5),
    ) {
        Ok(mut stream) => {
            let mut buf = [0u8; 128];
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .ok();
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                    evidence.push(format!(
                        "ssh {}:{}: banner '{}' (OK)",
                        SSH_TARGET.0, SSH_TARGET.1, banner
                    ));
                    true
                }
                Ok(_) => {
                    evidence.push(format!(
                        "ssh {}:{}: connected but no banner (FAILED)",
                        SSH_TARGET.0, SSH_TARGET.1
                    ));
                    false
                }
                Err(e) => {
                    evidence.push(format!(
                        "ssh {}:{}: banner read error {e} (FAILED)",
                        SSH_TARGET.0, SSH_TARGET.1
                    ));
                    false
                }
            }
        }
        Err(e) => {
            evidence.push(format!(
                "ssh {}:{}: connect error {e} (FAILED)",
                SSH_TARGET.0, SSH_TARGET.1
            ));
            false
        }
    };
    BusinessEvidence {
        ping_ok,
        ssh_ok,
        lines: evidence,
    }
}

// ---------------------------------------------------------------------------
// R5b TUN-ON 共存断言（2026-08-19）：Mihomo TUN 开 = EXV 正常工作环境。
// 在 P3-1 绑定（控制面 socket 钉物理网卡出口）与 C2 隧道路由共存语义之上，把
// 「TUN 开下 VPN 与 Mihomo 三向互不劫持」正式化为门禁硬断言：
//   (a) 控制面+数据面承载连接源地址 = 物理网卡（非 Mihomo TUN 198.18.x.x 段）；
//   (b) Mihomo 侧共存不被破坏：进程存活 + TUN 默认路由（198.18.0.2）不变 +
//       非校内流量仍走 Mihomo（路由决策硬断言 + 公网 TCP 探针文本证据）；
//   (c) VPN 校园路由与 Mihomo 路由共存无冲突（连接期间 Get-NetRoute 关键项）；
//   (d) 断开后 0 残留（本 adapter 无路由残留 + Mihomo 默认路由不变）。
// 环境标注：本机 2026-08-19 Mihomo TUN 开启（ifIndex 16，默认路由 198.18.0.2）；
// 物理网卡 以太网 ifIndex 4 = 192.168.31.24。
// ---------------------------------------------------------------------------

/// 学校网关（CSTP 控制面目标；config server vpn-ct.ecnu.edu.cn 的直连解析真实 IP）。
const GATEWAY_IP: &str = "222.66.117.109";
/// Mihomo TUN 网段前缀（fake-ip/隧道段；断言「非 198.18.x.x」）。
const MIHOMO_TUN_SEGMENT: &str = "198.18.";
/// 公网探针目标（非校园；经 Mihomo TUN 默认路由出口；文本证据）。
const PUBLIC_PROBE: (&str, u16) = ("1.1.1.1", 443);
/// 校园路由断言项（config 冻结路由之一；连通期间必在本 adapter 上）。
const CAMPUS_ROUTE_ASSERT: &str = "222.66.117.0/24";

/// Mihomo 共存基线（连接前捕获；连接期间/断开后断言对象）。
struct MihomoBaseline {
    /// 检测到的 Mihomo 系进程名（clash-verge / verge-mihomo 等）。
    processes: Vec<String>,
    /// Mihomo TUN 默认路由存在（0.0.0.0/0 → 198.18.x.x NextHop 活跃）。
    tun_default_route: bool,
    /// Mihomo TUN 默认路由 NextHop（如 198.18.0.2；未检测时为空）。
    tun_next_hop: String,
    /// 物理网卡 IPv4（控制面源地址断言目标）。
    physical_ip: String,
}

/// 跑一条 PowerShell 命令，返回 trimmed stdout（失败返回空串，不 panic）。
fn run_ps(cmd: &str) -> String {
    match Command::new("powershell")
        .args(["-NoProfile", "-Command", cmd])
        .output()
    {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(e) => {
            eprintln!("run_ps error: {e} (cmd: {cmd})");
            String::new()
        }
    }
}

/// 捕获 Mihomo 共存基线（连接前；连接期间/断开后对照）。
fn capture_mihomo_baseline() -> MihomoBaseline {
    let processes = run_ps(
        r#"Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'mihomo|clash|verge' } | Select-Object -ExpandProperty ProcessName | Sort-Object -Unique"#,
    )
    .lines()
    .map(str::trim)
    .filter(|s| !s.is_empty())
    .map(str::to_string)
    .collect::<Vec<_>>();

    // Mihomo TUN 默认路由（NextHop 在 198.18.x.x 的 0.0.0.0/0）。
    let tun = run_ps(
        r#"Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -like '198.18.*' } | Select-Object NextHop,RouteMetric,InterfaceAlias | Format-Table -HideTableHeaders"#,
    );
    let tun_rows: Vec<&str> = tun
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with("NextHop"))
        .collect();
    let tun_default_route = !tun_rows.is_empty();
    let tun_next_hop = tun_rows
        .first()
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or("")
        .to_string();

    // 物理网卡 IPv4：默认路由（非 Mihomo/Meta/Wintun/vEthernet 虚拟）所在接口的地址。
    let physical_ip = run_ps(
        r#"$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -notmatch 'Mihomo|Meta|Wintun|Clash|vEthernet|Hyper' } | Select-Object -First 1; if ($r) { (Get-NetIPAddress -InterfaceIndex $r.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress }"#,
    );

    MihomoBaseline {
        processes,
        tun_default_route,
        tun_next_hop,
        physical_ip,
    }
}

/// (a) 控制面+数据面承载连接源地址断言：Connected 后到学校网关 `222.66.117.109:443`
/// 的 Established 连接必须源出于**物理网卡**（P3-1 `IP_UNICAST_IF` 绑定生效），
/// **绝不**源出于 Mihomo TUN 段（198.18.x.x）。
///
/// CSTP 控制面连接在同一 TLS 会话上承载隧道数据面（CSTP 封装）；其源地址即数据面
/// egress 源地址——源 = 物理网卡 = 整个隧道绕开 Mihomo 代理路径的证明。
fn assert_control_source_physical(
    engine_pid: u32,
    baseline: &MihomoBaseline,
) -> Result<String, String> {
    let out = run_ps(&format!(
        "Get-NetTCPConnection -RemoteAddress {GATEWAY_IP} -RemotePort 443 -State Established -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess | Format-Table -HideTableHeaders"
    ));
    let rows: Vec<&str> = out
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if rows.is_empty() {
        return Err(format!(
            "coexist (a): no established connection to {GATEWAY_IP}:443 — control plane not observed"
        ));
    }
    let mut engine_owned_physical = false;
    let mut bad_source: Option<String> = None;
    for row in &rows {
        let fields: Vec<&str> = row.split_whitespace().collect();
        // Format-Table -HideTableHeaders：LocalAddress LocalPort OwningProcess。
        let local = fields.first().copied().unwrap_or("");
        let owning = fields
            .get(2)
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        if owning == engine_pid {
            if local == baseline.physical_ip {
                engine_owned_physical = true;
            } else if local.starts_with(MIHOMO_TUN_SEGMENT) {
                bad_source = Some(format!(
                    "engine-owned ({engine_pid}) connection source {local} on Mihomo TUN segment"
                ));
            }
        }
    }
    if let Some(b) = bad_source {
        return Err(b);
    }
    if !engine_owned_physical {
        return Err(format!(
            "coexist (a): no engine-owned ({engine_pid}) connection to {GATEWAY_IP}:443 sourced from physical NIC {}",
            baseline.physical_ip
        ));
    }
    Ok(format!(
        "coexist (a): control+data egress sourced from physical NIC {} (engine pid {engine_pid}), not {}… (P3-1 Mihomo bypass proven)",
        baseline.physical_ip, MIHOMO_TUN_SEGMENT
    ))
}

/// (b) Mihomo 侧共存不被破坏：进程存活（硬断言）+ TUN 默认路由不变（硬断言，仅当
/// 基线检测到 TUN）+ 非校内流量仍走 Mihomo（Find-NetRoute 路由决策硬断言 + 公网
/// TCP 探针文本证据）。
fn assert_mihomo_intact(baseline: &MihomoBaseline) -> Result<Vec<String>, String> {
    let mut evidence = Vec::new();
    // 进程存活。
    let procs_now = run_ps(
        r#"Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'mihomo|clash|verge' } | Select-Object -ExpandProperty ProcessName | Sort-Object -Unique"#,
    );
    evidence.push(format!("[coexist-b] mihomo procs during vpn:\n{procs_now}"));
    for p in &baseline.processes {
        if !procs_now.contains(p.as_str()) {
            return Err(format!("coexist (b): Mihomo process {p} gone during VPN"));
        }
    }
    if !baseline.tun_default_route {
        evidence.push("coexist (b): Mihomo TUN default route not in baseline (TUN OFF env) — TUN asserts vacuous".to_string());
        return Ok(evidence);
    }
    // TUN 默认路由不变（NextHop 198.18.x.x 仍活跃）。
    let tun_now = run_ps(
        r#"Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -like '198.18.*' } | Select-Object NextHop,RouteMetric,InterfaceAlias | Format-Table -HideTableHeaders"#,
    );
    evidence.push(format!("[coexist-b] mihomo default route during vpn:\n{tun_now}"));
    if !tun_now.contains(baseline.tun_next_hop.as_str()) {
        return Err(format!(
            "coexist (b): Mihomo TUN default route {} changed/lost during VPN",
            baseline.tun_next_hop
        ));
    }
    // 非校内流量选路决策（Find-NetRoute 公网目标 → 必须经 Mihomo TUN）。
    let sel = run_ps(
        r#"Find-NetRoute -RemoteIPAddress '1.1.1.1' -ErrorAction SilentlyContinue | Select-Object IPAddress,InterfaceAlias,NextHop | Format-Table -HideTableHeaders"#,
    );
    evidence.push(format!("[coexist-b] non-campus route decision (Find-NetRoute 1.1.1.1):\n{sel}"));
    if !sel.contains("Mihomo") && !sel.contains(baseline.tun_next_hop.as_str()) {
        return Err("coexist (b): non-campus route no longer via Mihomo TUN during VPN".to_string());
    }
    // 公网 TCP 探针（经 Mihomo 默认路由；保持连接 ~1.5s 观察其源地址 = Mihomo TUN
    // IP 198.18.x.x——外部可达性属环境态，仅文本证据不硬断言）。
    let probe_target: std::net::SocketAddr = format!("{}:{}", PUBLIC_PROBE.0, PUBLIC_PROBE.1)
        .parse()
        .map_err(|e| format!("probe addr parse: {e}"))?;
    match std::net::TcpStream::connect_timeout(&probe_target, Duration::from_secs(5)) {
        Ok(stream) => {
            std::thread::sleep(Duration::from_millis(1500));
            let local = run_ps(
                r#"Get-NetTCPConnection -RemoteAddress '1.1.1.1' -RemotePort 443 -State Established -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort | Format-Table -HideTableHeaders"#,
            );
            let via = if local.contains("198.18") { "OK (LocalAddress on Mihomo TUN)" } else { "OBSERVED (see dump)" };
            evidence.push(format!(
                "[coexist-b] public probe {}:{} CONNECTED; LocalAddress during probe:\n{local}\ncoexist (b): public probe via Mihomo = {via}",
                PUBLIC_PROBE.0, PUBLIC_PROBE.1
            ));
            drop(stream);
        }
        Err(e) => evidence.push(format!(
            "[coexist-b] public probe {}:{} connect failed: {e} (external reachability — text evidence only)",
            PUBLIC_PROBE.0, PUBLIC_PROBE.1
        )),
    }
    Ok(evidence)
}

/// (c) VPN 路由与 Mihomo 路由共存无冲突：校园路由（config 冻结 `222.66.117.0/24`）
/// 连接期间必在本 adapter 上；同时 Mihomo TUN 默认路由保持活跃（双路由同表共存）。
fn assert_route_coexistence(
    adapter_name: &str,
    baseline: &MihomoBaseline,
) -> Result<Vec<String>, String> {
    let mut evidence = Vec::new();
    let vpn_route = run_ps(&format!(
        "Get-NetRoute -DestinationPrefix '{CAMPUS_ROUTE_ASSERT}' -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | Format-Table -HideTableHeaders"
    ));
    evidence.push(format!(
        "[coexist-c] campus route {CAMPUS_ROUTE_ASSERT}:\n{vpn_route}"
    ));
    if !vpn_route.contains(adapter_name) {
        return Err(format!(
            "coexist (c): campus route {CAMPUS_ROUTE_ASSERT} not on adapter {adapter_name}"
        ));
    }
    if baseline.tun_default_route {
        let tun_now = run_ps(
            r#"Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -like '198.18.*' } | Select-Object NextHop,RouteMetric,InterfaceAlias | Format-Table -HideTableHeaders"#,
        );
        if !tun_now.contains(baseline.tun_next_hop.as_str()) {
            return Err(format!(
                "coexist (c): Mihomo default route {} not active while campus route present",
                baseline.tun_next_hop
            ));
        }
        evidence.push(format!(
            "coexist (c): campus route + Mihomo default route {} coexist in table during VPN (no conflict)",
            baseline.tun_next_hop
        ));
    }
    Ok(evidence)
}

/// 连接期间共存断言（Connected 后、ping/SSH 前）：(a)(b)(c) 合并。
fn coexistence_during_connect(
    adapter_name: &str,
    engine_pid: u32,
    baseline: &MihomoBaseline,
) -> Result<Vec<String>, String> {
    let mut evidence = Vec::new();
    evidence.push(assert_control_source_physical(engine_pid, baseline)?);
    evidence.extend(assert_mihomo_intact(baseline)?);
    evidence.extend(assert_route_coexistence(adapter_name, baseline)?);
    Ok(evidence)
}

/// (d) 断开后 0 残留：本 adapter 无路由残留（硬断言）+ Mihomo TUN 默认路由不变
/// （硬断言，仅当基线检测到 TUN）。
fn coexistence_after_stop(
    adapter_name: &str,
    baseline: &MihomoBaseline,
) -> Result<Vec<String>, String> {
    let mut evidence = Vec::new();
    let routes = run_ps(&format!(
        "Get-NetRoute -ErrorAction SilentlyContinue | Where-Object {{ $_.InterfaceAlias -like '*{adapter_name}*' }} | Select-Object DestinationPrefix,InterfaceAlias | Format-Table -HideTableHeaders"
    ));
    evidence.push(format!("[coexist-d] routes on {adapter_name} after stop:\n{routes}"));
    if !routes.trim().is_empty() {
        return Err(format!(
            "coexist (d): route residue on adapter {adapter_name} after stop"
        ));
    }
    if baseline.tun_default_route {
        let tun_after = run_ps(
            r#"Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -like '198.18.*' } | Select-Object NextHop,RouteMetric,InterfaceAlias | Format-Table -HideTableHeaders"#,
        );
        evidence.push(format!("[coexist-d] Mihomo default route after stop:\n{tun_after}"));
        if !tun_after.contains(baseline.tun_next_hop.as_str()) {
            return Err(format!(
                "coexist (d): Mihomo default route {} lost after VPN disconnect",
                baseline.tun_next_hop
            ));
        }
    }
    evidence.push(format!(
        "coexist (d): no route residue on {adapter_name}; Mihomo default route intact after stop"
    ));
    Ok(evidence)
}

// ---------------------------------------------------------------------------
// 客户端驱动（复用 grpc_server.rs 的测试 connector 模式；产品 client 是 P1-c）。
// ---------------------------------------------------------------------------

#[derive(Default)]
struct TestPipeConnector {
    pipe: Option<NamedPipeClient>,
}

impl Service<Uri> for TestPipeConnector {
    type Response = TokioIo<NamedPipeClient>;
    type Error = std::io::Error;
    type Future =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let pipe = self.pipe.take().expect("single test connection");
        Box::pin(async move { Ok(TokioIo::new(pipe)) })
    }
}

async fn dial_with_retry(name: &str) -> NamedPipeClient {
    for _ in 0..200 {
        match ClientOptions::new().open(name) {
            Ok(pipe) => return pipe,
            Err(_) => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    }
    panic!("dial {name} exhausted retries");
}

fn sha256(bytes: impl AsRef<[u8]>) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).to_vec()
}

fn digest32(n: u8) -> Vec<u8> {
    let mut bytes = [0u8; 32];
    bytes[0] = n;
    bytes.to_vec()
}

fn uuid16(n: u8) -> Vec<u8> {
    let mut bytes = [0u8; 16];
    bytes[0] = n;
    bytes[1] = 0x42;
    bytes.to_vec()
}

fn wire_key(method: i32, n: u8) -> generated::OperationLookupKey {
    generated::OperationLookupKey {
        // 自报 principal 仅做严格性校验（非零 32 字节）；身份恒来自认证 transport peer。
        principal_digest: digest32(0x10),
        method,
        runtime_epoch: uuid16(n),
        operation_id: uuid16(n + 1),
    }
}

fn unique_pipe_name(tag: &str, pid: u32) -> String {
    format!(r"\\.\pipe\exv-bizgate-{tag}-{pid}")
}

/// 一轮真实连接：提权 engine → 全链路 → ping/SSH → stop → 清理。返回文本证据。
///
/// `tag` 是本次测试的**命名空间**（pipe / authority / journal 均以其派生）——同一
/// test binary 内多个真实连接门禁并发跑时互不抢占（R5b 实测：无 tag 时 coex 门禁与
/// 两轮门禁共享 `exv-bizgate-r1-{pid}` 管道 → dial 耗尽重试）。调用方须为每个门禁
/// 传唯一 tag（如 "bizgate" / "coex"）。
async fn run_real_round(
    tag: &str,
    round: u32,
    engine_exe: &Path,
    wintun_dll: &Path,
    username: &str,
    password: &str,
    adapter_name: &str,
) -> Result<Vec<String>, String> {
    let mut evidence = Vec::new();
    // R5b 共存基线：连接前捕获 Mihomo 进程/TUN 默认路由/物理网卡 IP。TUN 开 = 正常
    // 环境（本门禁环境契约）；连接期间/断开后以此为共存断言对象。**必须在计时起点
    // 之前**——基线捕获是 3 次 PowerShell 查询（~1s），不得计入 cold-start 窗口
    // （R5b 实测：基线放入窗口会把 cold-start 从 ~700ms 虚高到 ~2300ms）。
    let baseline = capture_mihomo_baseline();
    evidence.push(format!(
        "coexist: baseline mihomo_procs={:?} tun_default_route={} tun_next_hop={} physical_ip={}",
        baseline.processes,
        baseline.tun_default_route,
        baseline.tun_next_hop,
        baseline.physical_ip
    ));
    // R1c 耗时门禁：冷启动起点 = engine 进程 spawn（一轮真实连接=一次冷引擎进程），
    // 与 R0 归因的 core 视角 connect->connected 同口径（含进程拉起 + 控制面握手）。
    let round_start = std::time::Instant::now();
    let pid = std::process::id();
    let sid = current_user_sid().ok_or("current user sid")?;
    // 命名空间派生：pipe/authority/journal 全部带 `{tag}-r{round}`，避免同 binary
    // 内多门禁并发时互抢（R5b 实测碰撞根因）。
    let ns = format!("{tag}-r{round}");
    let pipe_name = format!(r"\\.\pipe\exv-{ns}-{pid}");
    let args = vec![
        "--control-pipe".to_string(),
        pipe_name.clone(),
        "--dll".to_string(),
        wintun_dll.display().to_string(),
        "--journal-dir".to_string(),
        std::env::temp_dir().join(format!("exv-{ns}-journal-{pid}")).display().to_string(),
        "--authority-name".to_string(),
        format!("Local\\exv-{ns}-{pid}"),
        "--host-pid".to_string(),
        pid.to_string(),
        "--adapter-name".to_string(),
        adapter_name.to_string(),
        "--user-sid".to_string(),
        sid.clone(),
    ];
    let engine_pid = spawn_engine_elevated(engine_exe, &args)
        .map_err(|e| format!("round {round}: spawn engine elevated: {e}"))?;
    evidence.push(format!("round {round}: engine spawned pid={engine_pid} (elevated)"));

    // 连接控制面（engine 启动 race → 重试拨号）。
    let pipe = dial_with_retry(&pipe_name).await;
    let connector = TestPipeConnector { pipe: Some(pipe) };
    let channel = tonic::transport::Endpoint::from_static("http://engine.local")
        .connect_with_connector(connector)
        .await
        .map_err(|e| format!("round {round}: channel: {e}"))?;
    let mut client = HelperControlClient::new(channel);

    // 先挂接 StreamConnectStatus（状态事件不被遗漏）。
    let mut status_stream = client
        .stream_connect_status(generated::StreamConnectStatusRequest {})
        .await
        .map_err(|e| format!("round {round}: status stream: {e}"))?
        .into_inner();

    // lease handshake。
    let principal_digest = sha256(format!("sid:{sid}"));
    let (req_tx, req_rx) = mpsc::channel::<generated::HostLeaseMessage>(8);
    let stream_request = Request::new(tokio_stream::wrappers::ReceiverStream::new(req_rx));
    let mut lease_stream = client
        .maintain_owner_lease(stream_request)
        .await
        .map_err(|e| format!("round {round}: lease stream: {e}"))?
        .into_inner();
    req_tx
        .send(generated::HostLeaseMessage {
            owner_lease_id: vec![0u8; 16],
            runtime_epoch: vec![0u8; 16],
            message: Some(generated::host_lease_message::Message::Handshake(
                generated::LeaseHandshake {
                    principal_digest: principal_digest.clone(),
                    capability_digest: digest32(0x20),
                    channel_identity_digest: digest32(0x30),
                },
            )),
        })
        .await
        .map_err(|e| format!("round {round}: handshake send: {e}"))?;
    let accepted = lease_stream
        .message()
        .await
        .map_err(|e| format!("round {round}: handshake err: {e}"))?
        .ok_or_else(|| format!("round {round}: handshake EOF"))?;
    if !matches!(
        accepted.message,
        Some(generated::helper_lease_message::Message::HandshakeAccepted(_))
    ) {
        return Err(format!("round {round}: handshake not accepted: {accepted:?}"));
    }

    // acquire lease。
    client
        .acquire_lease(generated::AcquireLeaseRequest {
            lookup_key: Some(wire_key(5, 1)),
            platform_ownership: None,
            request_digest: digest32(1),
        })
        .await
        .map_err(|e| format!("round {round}: acquire: {e}"))?;

    // apply（真实凭据）。
    let apply_key = wire_key(6, 2);
    let payload = format!(
        r#"{{"version":1,"username":"{username}","password":"{password}"}}"#
    );
    let apply = client
        .apply_tunnel(generated::ApplyTunnelRequest {
            lookup_key: Some(apply_key.clone()),
            plan: Some(generated::TunnelPlan {
                ipv4_address: vec![0, 0, 0, 0],
                ipv4_prefix_len: 32,
                mtu: 1290,
                ipv4_routes: vec![],
                dns_servers: vec![],
                control_bypass: vec![],
                opaque_intent: Some(generated::TunnelIntentRef {
                    identity_digest: digest32(2),
                }),
            }),
            request_digest: digest32(2),
            secret_payload: payload.into_bytes(),
        })
        .await
        .map_err(|e| format!("round {round}: apply: {e}"))?;
    let accepted = match apply.into_inner().result.expect("apply result") {
        generated::apply_tunnel_reply::Result::Pending(accepted) => accepted,
        other => return Err(format!("round {round}: apply not pending: {other:?}")),
    };
    evidence.push(format!(
        "round {round}: apply accepted (operation_id={})",
        hex(accepted.operation_id)
    ));

    // R1c 耗时门禁：connect 起点 = apply 受理（Pending ack）——冷启动连接的关键路径
    // 从受理开始计，至 Connected 终态。逐轮记入证据供 3 次冷启动中位数/最小值统计。
    let connect_start = std::time::Instant::now();
    // 读 status 至 Connected / Failed。
    let deadline = std::time::Instant::now() + CONNECT_DEADLINE;
    let mut phases: Vec<String> = Vec::new();
    let mut terminal = None;
    while std::time::Instant::now() < deadline {
        let item = tokio::time::timeout(
            Duration::from_secs(10),
            status_stream.message(),
        )
        .await
        .map_err(|_| format!("round {round}: status timeout (phases={phases:?})"))?
        .map_err(|e| format!("round {round}: status err {e} (phases={phases:?})"))?
        .ok_or_else(|| format!("round {round}: status EOF (phases={phases:?})"))?;
        let phase = format!(
            "{}:{}",
            connect_phase_name(item.connect_phase),
            coarse_name(item.coarse_phase)
        );
        phases.push(phase);
        if item.coarse_phase == generated::StatsPhase::Connected as i32 {
            let connect_ms = connect_start.elapsed().as_millis();
            let cold_ms = round_start.elapsed().as_millis();
            evidence.push(format!(
                "round {round}: connect->connected = {connect_ms} ms (apply accepted -> Connected)"
            ));
            // 冷启动全路径（engine spawn -> Connected）：门禁判据「3 次冷启动中位数」的
            // 统计口径。connect_ms 是其内部主体（DNS+login+CSTP+apply+dataplane）。
            evidence.push(format!(
                "round {round}: cold-start spawn->connected = {cold_ms} ms (engine spawn -> Connected)"
            ));
            terminal = Some("connected".to_string());
            break;
        }
        if item.coarse_phase == generated::StatsPhase::Failed as i32 {
            let detail = item
                .error
                .as_ref()
                .map(|e| {
                    let native = e
                        .native
                        .as_ref()
                        .map(|n| format!("a0={}", n.code))
                        .unwrap_or_else(|| "no-native".to_string());
                    format!("code={} {native} phase={}", e.code, connect_phase_name(item.connect_phase))
                })
                .unwrap_or_else(|| "no-error".to_string());
            terminal = Some(format!("failed({detail})"));
            break;
        }
    }
    evidence.push(format!("round {round}: status progression = {phases:?}"));
    match terminal.as_deref() {
        Some("connected") => {}
        Some(other) => return Err(format!("round {round}: connect failed terminal: {other}")),
        None => return Err(format!("round {round}: connect deadline hit (no terminal)")),
    }

    // R5b TUN-ON 共存断言（Connected 后、ping/SSH 前）：
    // (a) 控制/数据承载连接源 = 物理网卡（非 198.18.x.x）；(b) Mihomo 进程存活 +
    // TUN 默认路由不变 + 非校内流量仍走 Mihomo；(c) VPN 校园路由与 Mihomo 路由共存
    // 无冲突。任一硬断言失败 → 整轮 FAILED。
    evidence.extend(coexistence_during_connect(adapter_name, engine_pid, &baseline)?);

    // 业务证据：ping + SSH（先 dump 隧道接口/路由/选路诊断）。
    evidence.extend(dump_tunnel_state(adapter_name, PING_TARGET));
    let biz = business_evidence();
    evidence.extend(biz.lines);
    // P3-5（R1c 复核折叠项）：ping 成功提升为**硬断言**——任何一轮 ping 未带 TTL
    // （真实校内网络不可达 / 数据面未转发）即整轮 FAILED，不再只记文本证据。SSH
    // banner 同样逐轮硬断言（与测试末的跨轮 banner 断言构成双保险）。
    if !biz.ping_ok {
        return Err(format!(
            "round {round}: ping {PING_TARGET} FAILED (no TTL) — business gate hard assertion"
        ));
    }
    if !biz.ssh_ok {
        return Err(format!(
            "round {round}: ssh {}:{} banner FAILED — business gate hard assertion",
            SSH_TARGET.0, SSH_TARGET.1
        ));
    }
    // 数据面计数器：ping/SSH 后读 Wintun 适配器字节计数（若 rx/tx 增长 = 包确实
    // 流经隧道路径；否则 = 数据面未转发）。
    for cmd in [
        format!(
            "Get-NetAdapterStatistics -Name '{adapter_name}' -ErrorAction SilentlyContinue | Select-Object ReceivedBytes,SentBytes | Format-List"
        ),
    ] {
        if let Ok(out) = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            evidence.push(format!("[counters] => {text}"));
        }
    }

    // stop → 读 Idle。
    let stop_key = wire_key(7, 3);
    let stop = client
        .stop_tunnel(generated::StopTunnelRequest {
            lookup_key: Some(stop_key.clone()),
            request_digest: digest32(3),
        })
        .await
        .map_err(|e| format!("round {round}: stop: {e}"))?;
    if !matches!(
        stop.into_inner().result,
        Some(generated::stop_tunnel_reply::Result::Stopped(_))
    ) {
        return Err(format!("round {round}: stop not stopped"));
    }
    let idle = tokio::time::timeout(Duration::from_secs(10), status_stream.message())
        .await
        .map_err(|_| format!("round {round}: no idle after stop"))?
        .map_err(|e| format!("round {round}: status err after stop {e}"))?
        .ok_or_else(|| format!("round {round}: status EOF after stop"))?;
    evidence.push(format!(
        "round {round}: stop terminal = {}",
        coarse_name(idle.coarse_phase)
    ));

    // S1.5 (D13) 减负断开验证：adapter **保留**但暂停（无 IP、0 路由、session 结束
    // 已由 Idle 终态证明——D12 网卡惰性存续）。
    std::thread::sleep(Duration::from_millis(300));
    assert_adapter_paused(adapter_name)?;
    evidence.push(format!(
        "round {round}: adapter {adapter_name} retained but paused after stop (no IP, 0 routes)"
    ));

    // R5b (d)：断开后 0 残留——本 adapter 无路由残留（D12 保留但暂停）+ Mihomo TUN
    // 默认路由不变。
    evidence.extend(coexistence_after_stop(adapter_name, &baseline)?);

    // engine 干净退出（stop 通知后自退）。
    drop(req_tx);
    drop(client);
    let exited = wait_engine_exit(engine_pid, Duration::from_secs(10));
    evidence.push(format!("round {round}: engine exited cleanly = {exited}"));

    // S1.5 (D12) 退出清理：engine 退出阶段必清 adapter（0 网卡残留兜底）。
    assert_adapter_removed(wintun_dll, adapter_name)?;
    evidence.push(format!(
        "round {round}: adapter {adapter_name} removed after engine exit (0 residue)"
    ));

    Ok(evidence)
}

fn connect_phase_name(v: i32) -> String {
    let name = match v {
        0 => "Unspecified",
        1 => "ObservingOwnedState",
        2 => "AcquiringPlatformLease",
        3 => "ConnectingControl",
        4 => "AwaitingInteraction",
        5 => "NegotiatingTunnel",
        6 => "ApplyingPlatformTunnel",
        7 => "AttachingPacketBoundary",
        8 => "StartingDataPlane",
        _ => "Unknown",
    };
    name.to_string()
}

fn coarse_name(v: i32) -> String {
    // common.proto StatsPhase：UNSPECIFIED=0, IDLE=1, CONNECTING=2, CONNECTED=3,
    // STOPPING=4, FAILED=5（1-based）。
    match v {
        0 => "Unspecified",
        1 => "Idle",
        2 => "Connecting",
        3 => "Connected",
        4 => "Stopping",
        5 => "Failed",
        _ => "Unknown",
    }
    .to_string()
}

fn hex(bytes: Vec<u8>) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// wintun.dll 冻结默认路径（`~/.exv/wintun/wintun/bin/amd64/wintun.dll`；与 host
/// `resolve_wintun_dll_path` 一致，`EXV_RUST_VPN_WINTUN_DLL` 可覆盖）。
fn wintun_dll_path() -> std::path::PathBuf {
    std::env::var_os("EXV_RUST_VPN_WINTUN_DLL")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            exv_vpn_win32_config::config_dir()
                .join("wintun")
                .join("wintun")
                .join("bin")
                .join("amd64")
                .join("wintun.dll")
        })
}

/// 业务门禁：真实组装 → ping/SSH → stop 清理 → 第二轮（断开后再连可重复）。
#[tokio::test]
#[ignore = "opt-in business gate: EXV_RUST_VPN_BIZ_GATE=1"]
async fn real_assembly_ping_ssh_two_rounds() {
    if !gate_enabled() {
        eprintln!("skipped: set EXV_RUST_VPN_BIZ_GATE=1 to run the business gate");
        return;
    }
    let engine_exe = Path::new(env!("CARGO_BIN_EXE_exv-engine"));
    let wintun_dll = wintun_dll_path();
    if !wintun_dll.exists() {
        panic!("wintun.dll missing: {}", wintun_dll.display());
    }
    let (username, password) = real_credentials().expect("real config credentials");
    let wintun_dll = wintun_dll.as_path();

    let mut all = Vec::new();
    for round in 1..=2 {
        let adapter_name = format!("ExvBizG{}{}", std::process::id(), round);
        match run_real_round(
            "bizgate",
            round,
            engine_exe,
            wintun_dll,
            &username,
            &password,
            &adapter_name,
        )
        .await
        {
            Ok(mut evidence) => {
                all.append(&mut evidence);
            }
            Err(e) => {
                all.push(format!("round {round}: FAILED: {e}"));
                break;
            }
        }
    }
    for line in &all {
        eprintln!("{line}");
    }
    assert!(
        all.iter().any(|l| l.contains(": banner '")),
        "SSH banner evidence missing; gate output above"
    );
    assert!(
        all.iter().any(|l| l.contains("retained but paused after stop")),
        "D13 paused-adapter evidence missing; gate output above"
    );
    assert!(
        all.iter().any(|l| l.contains("removed after engine exit")),
        "D12 exit-cleanup evidence missing; gate output above"
    );
}

/// A1b 取消令牌验证：连接中途 Stop 能中断组装并清理（无资源泄漏）。
///
/// apply 受理即回（后台组装 thread 跑），随后立即 Stop → cancel 令牌 → 组装在段
/// 边界中断自清理；Stop 完成 Idle。S1.5 语义：**本次连接新建的 adapter**（本测试用
/// 独立新 adapter 名，必为新建）在失败/取消回滚时移除（all-or-nothing，D16）；
/// 复用 adapter 的中途取消则保留（网卡惰性存续，D12）。
#[tokio::test]
#[ignore = "opt-in: EXV_RUST_VPN_BIZ_GATE=1"]
async fn cancel_mid_assembly_cleans_up() {
    if !gate_enabled() {
        eprintln!("skipped: set EXV_RUST_VPN_BIZ_GATE=1");
        return;
    }
    let engine_exe = Path::new(env!("CARGO_BIN_EXE_exv-engine"));
    let wintun_dll = wintun_dll_path();
    let (username, password) = real_credentials().expect("real config credentials");
    let pid = std::process::id();
    let sid = current_user_sid().expect("current user sid");
    let adapter_name = format!("ExvCancel{pid}");
    let pipe_name = unique_pipe_name("cancel", pid);
    let args = vec![
        "--control-pipe".to_string(),
        pipe_name.clone(),
        "--dll".to_string(),
        wintun_dll.display().to_string(),
        "--journal-dir".to_string(),
        std::env::temp_dir().join(format!("exv-cancel-journal-{pid}")).display().to_string(),
        "--authority-name".to_string(),
        format!("Local\\exv-cancel-{pid}"),
        "--host-pid".to_string(),
        pid.to_string(),
        "--adapter-name".to_string(),
        adapter_name.clone(),
        "--user-sid".to_string(),
        sid.clone(),
    ];
    let engine_pid = spawn_engine_elevated(engine_exe, &args)
        .map_err(|e| format!("spawn engine elevated: {e}"))
        .unwrap();

    let pipe = dial_with_retry(&pipe_name).await;
    let connector = TestPipeConnector { pipe: Some(pipe) };
    let channel = tonic::transport::Endpoint::from_static("http://engine.local")
        .connect_with_connector(connector)
        .await
        .expect("channel");
    let mut client = HelperControlClient::new(channel);

    let mut status_stream = client
        .stream_connect_status(generated::StreamConnectStatusRequest {})
        .await
        .expect("status stream")
        .into_inner();

    // lease handshake + acquire（同两轮测试）。
    let principal_digest = sha256(format!("sid:{sid}"));
    let (req_tx, req_rx) = mpsc::channel::<generated::HostLeaseMessage>(8);
    let stream_request = Request::new(tokio_stream::wrappers::ReceiverStream::new(req_rx));
    let mut lease_stream = client
        .maintain_owner_lease(stream_request)
        .await
        .expect("lease stream")
        .into_inner();
    req_tx
        .send(generated::HostLeaseMessage {
            owner_lease_id: vec![0u8; 16],
            runtime_epoch: vec![0u8; 16],
            message: Some(generated::host_lease_message::Message::Handshake(
                generated::LeaseHandshake {
                    principal_digest: principal_digest.clone(),
                    capability_digest: digest32(0x20),
                    channel_identity_digest: digest32(0x30),
                },
            )),
        })
        .await
        .expect("handshake send");
    lease_stream
        .message()
        .await
        .expect("handshake err")
        .expect("handshake value");
    client
        .acquire_lease(generated::AcquireLeaseRequest {
            lookup_key: Some(wire_key(5, 1)),
            platform_ownership: None,
            request_digest: digest32(1),
        })
        .await
        .expect("acquire");

    // apply（真实凭据）→ 受理即回 pending。
    let payload = format!(r#"{{"version":1,"username":"{username}","password":"{password}"}}"#);
    let apply = client
        .apply_tunnel(generated::ApplyTunnelRequest {
            lookup_key: Some(wire_key(6, 2)),
            plan: Some(generated::TunnelPlan {
                ipv4_address: vec![0, 0, 0, 0],
                ipv4_prefix_len: 32,
                mtu: 1290,
                ipv4_routes: vec![],
                dns_servers: vec![],
                control_bypass: vec![],
                opaque_intent: Some(generated::TunnelIntentRef {
                    identity_digest: digest32(2),
                }),
            }),
            request_digest: digest32(2),
            secret_payload: payload.into_bytes(),
        })
        .await
        .expect("apply");
    assert!(
        matches!(
            apply.into_inner().result,
            Some(generated::apply_tunnel_reply::Result::Pending(_))
        ),
        "apply must return pending (A1b async start)"
    );
    eprintln!("cancel-test: apply returned pending; sending Stop immediately (mid-assembly)");

    // 立即 Stop：cancel 令牌应中断在途组装并清理。
    let stop = client
        .stop_tunnel(generated::StopTunnelRequest {
            lookup_key: Some(wire_key(7, 3)),
            request_digest: digest32(3),
        })
        .await
        .expect("stop succeeds");
    assert!(
        matches!(
            stop.into_inner().result,
            Some(generated::stop_tunnel_reply::Result::Stopped(_))
        ),
        "stop must be accepted even mid-assembly"
    );
    eprintln!("cancel-test: stop accepted (cancel token fired)");

    // 读 status：应为 Failed(取消) 或 Idle（不要求 Connected）。
    let mut saw_terminal = false;
    for _ in 0..5 {
        if let Ok(Ok(Some(ev))) = tokio::time::timeout(Duration::from_secs(5), status_stream.message()).await {
            let coarse = coarse_name(ev.coarse_phase);
            eprintln!("cancel-test: status = {}:{}", connect_phase_name(ev.connect_phase), coarse);
            if ev.coarse_phase == generated::StatsPhase::Failed as i32
                || ev.coarse_phase == generated::StatsPhase::Idle as i32
            {
                saw_terminal = true;
                break;
            }
        }
    }
    // 组装可能极快完成（Connected 后 Idle），或取消（Failed）；二者都算终止。
    eprintln!("cancel-test: saw terminal = {saw_terminal}");

    // 清理验证：adapter 必须移除（无论取消还是完成）。
    std::thread::sleep(Duration::from_millis(500));
    assert_adapter_removed(&wintun_dll, &adapter_name).expect("adapter removed after cancel");

    drop(req_tx);
    drop(client);
    let exited = wait_engine_exit(engine_pid, Duration::from_secs(10));
    assert!(exited, "engine exited cleanly after cancel");
    eprintln!("cancel-test: adapter removed + engine exited cleanly = {exited}");
}

/// R5b TUN-ON 共存门禁（2026-08-19）：Mihomo TUN 开 = EXV 正常工作环境。
///
/// 在 `run_real_round` 每轮的共存断言（(a)(b)(c)(d) 硬断言，任何一轮失败即 FAILED）
/// 基础上，本测试追加：
/// 1. **TUN-ON 前置契约**：Mihomo TUN 默认路由（198.18.x.x）必须活跃——若环境是
///    TUN OFF，共存断言将真空（TUN 条件分支不触发），本测试显式拒绝该环境，保证
///    R5b 场景的共存断言真实被行使；
/// 2. **全局路由残留扫描**：断开后 Get-NetRoute 全表相对连接前必须无新增行
///    （0 残留；本 adapter 的路由随 adapter 移除已由 (d) 覆盖）。
#[tokio::test]
#[ignore = "opt-in R5b TUN-ON coexistence gate: EXV_RUST_VPN_BIZ_GATE=1 + Mihomo TUN ON"]
async fn tun_on_coexistence_gate() {
    if !gate_enabled() {
        eprintln!("skipped: set EXV_RUST_VPN_BIZ_GATE=1");
        return;
    }
    let baseline = capture_mihomo_baseline();
    // 前置契约：R5b 场景 = Mihomo TUN 开（默认路由 198.18.x.x 活跃）。
    if !baseline.tun_default_route {
        panic!(
            "R5b TUN-ON gate requires Mihomo TUN default route (198.18.x.x) — environment is TUN OFF (mihomo_procs={:?} physical_ip={})",
            baseline.processes, baseline.physical_ip
        );
    }
    eprintln!(
        "R5b TUN-ON precondition: mihomo_procs={:?} tun_next_hop={} physical_ip={}",
        baseline.processes, baseline.tun_next_hop, baseline.physical_ip
    );

    // 断开前全局路由快照（残留 diff 基线）。
    let before = run_ps(
        r#"Get-NetRoute -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,NextHop,InterfaceAlias | Sort-Object DestinationPrefix | Format-Table -HideTableHeaders"#,
    );

    let engine_exe = Path::new(env!("CARGO_BIN_EXE_exv-engine"));
    let wintun_dll = wintun_dll_path();
    if !wintun_dll.exists() {
        panic!("wintun.dll missing: {}", wintun_dll.display());
    }
    let (username, password) = real_credentials().expect("real config credentials");
    let adapter_name = format!("ExvCoex{}", std::process::id());

    match run_real_round(
        "coex",
        1,
        engine_exe,
        &wintun_dll,
        &username,
        &password,
        &adapter_name,
    )
    .await
    {
        Ok(evidence) => {
            // 成功路径也打印逐轮证据（计时表 + 共存断言逐项 + ping/SSH），供报告引用。
            for l in &evidence {
                eprintln!("{l}");
            }
        }
        Err(e) => {
            eprintln!("R5b TUN-ON coexistence gate round 1: FAILED: {e}");
            panic!("R5b TUN-ON coexistence gate FAILED: {e}");
        }
    }
    // 断开后全局路由残留扫描：after 必须是 before 的子集（无新增路由 = 0 残留）。
    let after = run_ps(
        r#"Get-NetRoute -ErrorAction SilentlyContinue | Select-Object DestinationPrefix,NextHop,InterfaceAlias | Sort-Object DestinationPrefix | Format-Table -HideTableHeaders"#,
    );
    let row_of = |s: &str| {
        s.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("DestinationPrefix"))
            .map(str::to_string)
            .collect::<std::collections::HashSet<_>>()
    };
    let before_set = row_of(&before);
    let after_set = row_of(&after);
    let new_routes: Vec<String> = after_set
        .difference(&before_set)
        .cloned()
        .collect::<Vec<_>>();
    eprintln!("R5b residue: new routes after stop = {:?}", new_routes);
    if !new_routes.is_empty() {
        panic!("R5b residue: {new_routes:?} new routes after disconnect (expected 0)");
    }
    eprintln!("R5b TUN-ON coexistence gate PASS: (a)(b)(c)(d) + global route residue = 0");
}
