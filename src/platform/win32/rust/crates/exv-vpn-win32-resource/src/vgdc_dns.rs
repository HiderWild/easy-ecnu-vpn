// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// 规格：docs/superpowers/specs/2026-08-15-vpn-gateway-direct-connect-guarantee.md；
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；
// PRD G-⑤ / C4：docs/superpowers/plans/2026-08-17-vpn-rust-proxy-tun-coexistence-prd.md。

//! 生产 VGDC 双线可信网关解析（DoH 直连 → 绑物理网卡 UDP/53 兜底）——PRD G-⑤ / C4。
//!
//! 本模块是 VGDC 双线 DNS 的**生产**实现，自 acceptance `direct_connect.rs` 提升而来
//! （`提升复用`，不 fork 两份；acceptance 侧改为薄重导出）。engine 解析 VPN 服务器
//! 域名时经 [`resolve_gateway_dual_line`] 走直连，不经 Mihomo fake-ip DNS 劫持：
//!
//! - **L1 DoH（默认）**：HTTPS 查询阿里 `https://223.5.5.5/resolve` → Cloudflare
//!   `https://1.1.1.1/dns-query`，走 proxy-safe TLS wiring（rustls +
//!   rustls-platform-verifier；测试注入 TestRoots）。查询路径不被 Mihomo fake-ip
//!   DNS 劫持。
//! - **L2 UDP/53 绑物理网卡**：UDP 查询公共 resolver（1.1.1.1 / 8.8.8.8 /
//!   114.114.114.114），socket 以 `IP_UNICAST_IF` 绑物理网卡 ifindex（不经 Mihomo TUN
//!   默认路由）。
//! - **fake-ip 过滤**：198.18.0.0/15（RFC 2544 / Clash fake-ip 池）在每条线路内过滤。
//! - **逐层 typed 失败**：一条线路失败 → 记录 typed 错误 → 下一条线路；全部失败 →
//!   [`ResolveLayerError`] 向量（证据记录 `describe()`）。
//!
//! 与 C3（`exv-vpn-cstp` connector `socket_binder` seam）衔接：本模块的
//! [`resolve_gateway_dual_line`] 产出真实物理出口 IP 供 CSTP connector 连接；
//! [`socket_binder_for_ifindex`] 供给 `BootstrapConfig.socket_binder`（IP_UNICAST_IF
//! 绑物理网卡，控制面连接不走 Mihomo 默认路由）。生产装配点（engine 拉起后、connect
//! 前）见 `exv-engine::vgdc_connect`。
//!
//! 与 acceptance 的差异：`resolve_gateway_dual_line` 改为 **async**（tokio 原生，DoH
//! 直接 await，不 block_on 外部 runtime）；acceptance 侧提供同步 shim 兼容既有调用面。

use std::net::{Ipv4Addr, SocketAddr};
use std::os::windows::io::AsRawSocket;
use std::sync::Arc;

use exv_vpn_cstp::connector::SocketBinder;
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinSock::{
    setsockopt, AF_INET, IPPROTO_IP, IP_UNICAST_IF, SOCKET, SOCKET_ADDRESS, SOCKADDR_INET,
};

/// 每层解析 deadline（spec VGDC-05：全程有 deadline，不再出现无限挂起）。
const LAYER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);
/// UDP/53 单次查询读写超时（proxy_safe_resolver 同款 2s）。
const DNS_UDP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
/// DNS 查询 ID（proxy_safe_resolver 同款冻结值）。
const DNS_QUERY_ID: [u8; 2] = [0x12, 0x34];
/// `IF_TYPE_ETHERNET_CSMACD`（物理以太网）。
const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
/// `IF_TYPE_IEEE80211`（物理 Wi-Fi）。
const IF_TYPE_IEEE80211: u32 = 71;

/// 物理网卡发现结果（`GetAdaptersAddresses`；UDP/53 绑网卡 + /32 路由共用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NicInfo {
    /// 网卡 LUID（`NET_LUID_LH.Value`）。
    pub luid: u64,
    /// 网卡 ifIndex（`IP_UNICAST_IF` 绑网卡 + 路由行共用）。
    pub ifindex: u32,
    /// 网卡网关（`/32` 路由的 next-hop）。
    pub gateway: Ipv4Addr,
    /// 网卡 IPv4 单播地址（源地址选择；发现辅助判据）。
    pub local_ip: Ipv4Addr,
    /// 友好名（人类可读；排除虚拟/隧道适配器用）。
    pub friendly_name: String,
    /// 网卡 IPv4 接口度量（候选排序：越小越优先）。
    pub ipv4_metric: u32,
}

/// 解析来源（证据 `resolution_source`：`"doh"` / `"udp53"` / `"system"`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionSource {
    /// gateway host 本身就是 IPv4 字面量（无需 DNS；fake-ip 过滤后直接采用）。
    System,
    /// DoH 线路成功（记录 endpoint）。
    Doh(Ipv4Addr),
    /// 绑物理网卡 UDP/53 线路成功（记录 resolver）。
    Udp53(Ipv4Addr),
}

impl ResolutionSource {
    /// 证据值：`"system"` / `"doh"` / `"udp53"`。
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Doh(_) => "doh",
            Self::Udp53(_) => "udp53",
        }
    }
}

/// DoH 线路 typed 错误（逐层记录；不 panic）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DohErrorKind {
    /// TCP 连接失败（端点不可达）。
    ConnectFailed(String),
    /// TLS 握手失败（证书链/网络）。
    TlsFailed(String),
    /// HTTP 状态非 200。
    HttpStatus(u16),
    /// DoH JSON `Status` 非 0（DNS 层失败）。
    DnsStatus(u64),
    /// 响应无法解析（非 HTTP / 非 JSON / 缺字段）。
    BadResponse(String),
    /// 过滤 fake-ip 后无 IPv4 结果。
    NoIpv4Result,
    /// deadline 超时。
    DeadlineExceeded,
    /// 请求构造失败（非法 host / server name）。
    BadRequest(String),
}

impl DohErrorKind {
    /// 证据 predicate 片段（`doh:<endpoint>:<片段>`）。
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::ConnectFailed(e) => format!("connect-failed:{e}"),
            Self::TlsFailed(e) => format!("tls-failed:{e}"),
            Self::HttpStatus(code) => format!("http-status-{code}"),
            Self::DnsStatus(code) => format!("dns-status-{code}"),
            Self::BadResponse(detail) => format!("bad-response:{detail}"),
            Self::NoIpv4Result => "no-ipv4-result".to_string(),
            Self::DeadlineExceeded => "deadline".to_string(),
            Self::BadRequest(detail) => format!("bad-request:{detail}"),
        }
    }
}

/// UDP/53 线路 typed 错误（逐层记录；不 panic）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Udp53ErrorKind {
    /// 发送失败（socket/网卡绑定的系统错误）。
    QueryFailed(String),
    /// 响应无法解析（短包 / ID 不匹配 / 非响应 / 截断）。
    BadResponse(String),
    /// DNS RCODE 非 0。
    DnsRcode(u8),
    /// 过滤 fake-ip 后无 IPv4 结果。
    NoIpv4Result,
    /// 读取超时（deadline 内无响应）。
    Timeout,
    /// 查询构造失败（非法 host：空 label / label > 63）。
    BadQuery(String),
}

impl Udp53ErrorKind {
    /// 证据 predicate 片段（`udp53:<resolver>:<片段>`）。
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::QueryFailed(e) => format!("query-failed:{e}"),
            Self::BadResponse(detail) => format!("bad-response:{detail}"),
            Self::DnsRcode(code) => format!("dns-rcode-{code}"),
            Self::NoIpv4Result => "no-ipv4-result".to_string(),
            Self::Timeout => "timeout".to_string(),
            Self::BadQuery(detail) => format!("bad-query:{detail}"),
        }
    }
}

/// 单层解析错误（L1 DoH 或 L2 UDP/53；证据逐层记录）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveLayerError {
    /// DoH 线路失败。
    Doh {
        /// 失败 endpoint。
        endpoint: Ipv4Addr,
        /// typed 错误。
        kind: DohErrorKind,
    },
    /// UDP/53 线路失败。
    Udp53 {
        /// 失败 resolver。
        resolver: Ipv4Addr,
        /// typed 错误。
        kind: Udp53ErrorKind,
    },
    /// gateway host 是 fake-ip 字面量（198.18.0.0/15）——直接拒绝。
    FakeIpLiteral(Ipv4Addr),
}

impl ResolveLayerError {
    /// 证据 predicate 片段（`doh:223.5.5.5:tls-failed:...` / `udp53:1.1.1.1:timeout`）。
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Doh { endpoint, kind } => format!("doh:{endpoint}:{}", kind.describe()),
            Self::Udp53 { resolver, kind } => format!("udp53:{resolver}:{}", kind.describe()),
            Self::FakeIpLiteral(ip) => format!("fake-ip-literal:{ip}"),
        }
    }
}

/// DoH endpoint 配置（endpoint IP + 查询路径）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DohEndpoint {
    /// DoH 服务器 IP（TCP 443）。
    pub ip: Ipv4Addr,
    /// JSON API 路径（阿里 `/resolve`；Cloudflare `/dns-query`）。
    pub path: &'static str,
}

/// 双线解析配置（可注入——机制测试用假 endpoint/假 verifier；生产用
/// [`DualLineConfig::production`]）。
#[derive(Debug, Clone)]
pub struct DualLineConfig {
    /// DoH endpoint 列表（按优先级；一条失败 → 下一条）。
    pub doh_endpoints: Vec<DohEndpoint>,
    /// TLS 客户端配置（生产 = rustls-platform-verifier；测试 = 注入 TestRoots）。
    pub doh_client_config: std::sync::Arc<rustls::ClientConfig>,
    /// UDP/53 resolver 列表（按优先级；proxy_safe_resolver 同款三公共 resolver）。
    pub udp53_resolvers: Vec<SocketAddr>,
    /// 绑物理网卡 ifindex（None = 不绑——仅测试假 socket 使用；生产恒为 Some）。
    pub udp53_ifindex: Option<u32>,
}

impl DualLineConfig {
    /// 生产配置：DoH `223.5.5.5/resolve` → `1.1.1.1/dns-query`（默认线路），
    /// UDP/53 `1.1.1.1` → `8.8.8.8` → `114.114.114.114`（fallback 线路，绑物理网卡）。
    ///
    /// # Errors
    ///
    /// rustls-platform-verifier 初始化失败 → `String` 描述。
    pub fn production(ifindex: Option<u32>) -> Result<Self, String> {
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls_platform_verifier::Verifier::new(provider.clone())
            .map_err(|_| "platform-verifier".to_string())?;
        let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| "client-config".to_string())?
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
            .with_no_client_auth();
        Ok(Self {
            doh_endpoints: vec![
                DohEndpoint {
                    ip: Ipv4Addr::new(223, 5, 5, 5),
                    path: "/resolve",
                },
                DohEndpoint {
                    ip: Ipv4Addr::new(1, 1, 1, 1),
                    path: "/dns-query",
                },
            ],
            doh_client_config: std::sync::Arc::new(client_cfg),
            udp53_resolvers: vec![
                SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53)),
                SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)),
                SocketAddr::from((Ipv4Addr::new(114, 114, 114, 114), 53)),
            ],
            udp53_ifindex: ifindex,
        })
    }
}

/// fake-ip 检测：198.18.0.0/15（RFC 2544 / Clash fake-ip 池；proxy_safe_resolver
/// `is_fake_ip_v4` 同款语义）。
#[must_use]
pub fn is_fake_ip_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
}

// ---------------------------------------------------------------------------
// L1：DoH（HTTPS；proxy-safe TLS wiring——school.rs / controlled.rs 同款）。
// ---------------------------------------------------------------------------

/// 对单个 DoH endpoint 执行 `name=A` JSON 查询；fake-ip 结果过滤。
///
/// `endpoint` 是 TCP 目标（生产 `(ip, 443)`；测试指向假 HTTPS 服务器）；
/// `server_name` 是 TLS SNI + 证书校验名（生产 = endpoint IP；测试 = 注入根 SAN）。
///
/// # Errors
///
/// [`DohErrorKind`]（typed；connect/TLS/HTTP/DNS 层逐层分类）。
pub async fn doh_query(
    client_config: std::sync::Arc<rustls::ClientConfig>,
    endpoint: SocketAddr,
    server_name: String,
    path: &str,
    host: &str,
) -> Result<Ipv4Addr, DohErrorKind> {
    let connector = tokio_rustls::TlsConnector::from(client_config);
    let server_name = rustls::pki_types::ServerName::try_from(server_name)
        .map_err(|_| DohErrorKind::BadRequest("server-name".to_string()))?;
    let tcp = tokio::time::timeout(LAYER_DEADLINE, tokio::net::TcpStream::connect(endpoint))
        .await
        .map_err(|_| DohErrorKind::DeadlineExceeded)?
        .map_err(|e| DohErrorKind::ConnectFailed(e.to_string()))?;
    let mut stream = tokio::time::timeout(LAYER_DEADLINE, connector.connect(server_name, tcp))
        .await
        .map_err(|_| DohErrorKind::DeadlineExceeded)?
        .map_err(|e| DohErrorKind::TlsFailed(e.to_string()))?;
    let query = format!(
        "GET {path}?name={}&type=A HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n",
        url_encode_host(host),
        endpoint.ip()
    );
    tokio::io::AsyncWriteExt::write_all(&mut stream, query.as_bytes())
        .await
        .map_err(|e| DohErrorKind::ConnectFailed(e.to_string()))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(
            LAYER_DEADLINE,
            tokio::io::AsyncReadExt::read(&mut stream, &mut chunk),
        )
        .await
        .map_err(|_| DohErrorKind::DeadlineExceeded)?
        .map_err(|e| DohErrorKind::TlsFailed(e.to_string()))?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    parse_doh_response(&raw)
}

/// DoH JSON 响应解析（HTTP 状态 + `Status` + `Answer[]` 过滤 fake-ip 后的首个 A 记录）。
///
/// # Errors
///
/// [`DohErrorKind`]（HTTP 层 / DNS 层 / 无 IPv4 结果）。
fn parse_doh_response(raw: &[u8]) -> Result<Ipv4Addr, DohErrorKind> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| DohErrorKind::BadResponse("no-http-header-end".to_string()))?;
    let head = String::from_utf8_lossy(&raw[..header_end]);
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| DohErrorKind::BadResponse("no-status-line".to_string()))?;
    if status != 200 {
        return Err(DohErrorKind::HttpStatus(status));
    }
    let body = &raw[header_end + 4..];
    let json: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| DohErrorKind::BadResponse(format!("json:{e}")))?;
    let dns_status = json
        .get("Status")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| DohErrorKind::BadResponse("no-status".to_string()))?;
    if dns_status != 0 {
        return Err(DohErrorKind::DnsStatus(dns_status));
    }
    let answers = json
        .get("Answer")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| DohErrorKind::BadResponse("no-answer".to_string()))?;
    for entry in answers {
        let is_a = entry.get("type").and_then(serde_json::Value::as_u64) == Some(1);
        if !is_a {
            continue;
        }
        let data = entry
            .get("data")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if let Ok(ip) = data.parse::<Ipv4Addr>()
            && !is_fake_ip_v4(ip)
        {
            return Ok(ip);
        }
    }
    Err(DohErrorKind::NoIpv4Result)
}

/// URL 查询参数编码（host 只允许 `[a-zA-Z0-9.-]`；其余字节 `%XX`）。
#[must_use]
fn url_encode_host(host: &str) -> String {
    let mut out = String::with_capacity(host.len());
    for b in host.bytes() {
        if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// L2：UDP/53 绑物理网卡（proxy_safe_resolver `dns_a_query_bound` 的 Rust 移植；
// 绑网卡 = `IP_UNICAST_IF` setsockopt，Windows 语义等价物）。
// ---------------------------------------------------------------------------

/// 构造 DNS A 查询（id `0x1234`、RD=1、qdcount=1；proxy_safe_resolver 同款字节布局）。
///
/// # Errors
///
/// 空 label / label > 63 → [`Udp53ErrorKind::BadQuery`]。
fn build_dns_query(host: &str) -> Result<Vec<u8>, Udp53ErrorKind> {
    let mut q = Vec::with_capacity(host.len() + 16);
    q.extend_from_slice(&DNS_QUERY_ID);
    q.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Udp53ErrorKind::BadQuery(format!("label:{label}")));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, class IN
    Ok(q)
}

/// 跳过 DNS name（普通标签与压缩指针均支持；返回 name 之后的偏移）。
///
/// 语义与 proxy_safe_resolver 的 `skip_name` 一致：遇到压缩指针（`0xC0`）即认为
/// name 结束于指针之后（answer 记录边界在指针之后；question name 不会压缩）。
fn skip_name(resp: &[u8], mut off: usize) -> Result<usize, Udp53ErrorKind> {
    loop {
        let Some(&lab) = resp.get(off) else {
            return Err(Udp53ErrorKind::BadResponse("name-eof".to_string()));
        };
        if lab == 0 {
            return Ok(off + 1);
        }
        if lab & 0xC0 == 0xC0 {
            if off + 2 > resp.len() {
                return Err(Udp53ErrorKind::BadResponse("ptr-eof".to_string()));
            }
            return Ok(off + 2);
        }
        if lab > 63 {
            return Err(Udp53ErrorKind::BadResponse("label-too-long".to_string()));
        }
        off += 1 + usize::from(lab);
        if off > resp.len() {
            return Err(Udp53ErrorKind::BadResponse("label-eof".to_string()));
        }
    }
}

/// 解析 DNS 响应：ID/QR/RCODE 校验 + question 跳过 + Answer 的 A 记录（fake-ip 过滤）。
///
/// # Errors
///
/// 响应非法（短包 / ID 不匹配 / 非响应 / 截断 / 非零 RCODE）或过滤后无 IPv4 →
/// [`Udp53ErrorKind`]。
fn parse_dns_response(resp: &[u8], query_id: &[u8; 2]) -> Result<Vec<Ipv4Addr>, Udp53ErrorKind> {
    if resp.len() < 12 {
        return Err(Udp53ErrorKind::BadResponse("short".to_string()));
    }
    if &resp[..2] != query_id {
        return Err(Udp53ErrorKind::BadResponse("id-mismatch".to_string()));
    }
    if resp[2] & 0x80 == 0 {
        return Err(Udp53ErrorKind::BadResponse("not-response".to_string()));
    }
    let rcode = resp[3] & 0x0F;
    if rcode != 0 {
        return Err(Udp53ErrorKind::DnsRcode(rcode));
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    if qdcount == 0 {
        return Err(Udp53ErrorKind::BadResponse("no-question".to_string()));
    }
    let mut off = 12usize;
    for _ in 0..qdcount {
        off = skip_name(resp, off)?;
        off += 4; // question type + class
    }
    let mut out = Vec::new();
    for _ in 0..ancount {
        off = skip_name(resp, off)?;
        if off + 10 > resp.len() {
            return Err(Udp53ErrorKind::BadResponse("answer-truncated".to_string()));
        }
        let atype = u16::from_be_bytes([resp[off], resp[off + 1]]);
        let rdlen = u16::from_be_bytes([resp[off + 8], resp[off + 9]]);
        off += 10;
        if off + usize::from(rdlen) > resp.len() {
            return Err(Udp53ErrorKind::BadResponse("rdlen-eof".to_string()));
        }
        if atype == 1 && rdlen == 4 {
            let ip = Ipv4Addr::new(resp[off], resp[off + 1], resp[off + 2], resp[off + 3]);
            if !is_fake_ip_v4(ip) && !out.contains(&ip) {
                out.push(ip);
            }
        }
        off += usize::from(rdlen);
    }
    if out.is_empty() {
        return Err(Udp53ErrorKind::NoIpv4Result);
    }
    Ok(out)
}

/// 绑物理网卡 UDP/53 A 查询（`proxy_safe_resolver::dns_a_query_bound` 的 Win32 移植）。
///
/// `ifindex` 为 `Some` 时以 `IP_UNICAST_IF` 强制出口为物理网卡（绕过 Mihomo TUN 的
/// 0.0.0.0/0 默认路由）；`None` 不绑（仅测试假 socket 使用）。生产 `resolver` 端口
/// 恒为 53；测试可注入任意端口。
///
/// # Errors
///
/// 查询构造 / 发送 / 读取 / 解析失败 → [`Udp53ErrorKind`]（typed；不 panic）。
pub fn dns_a_query_udp(
    host: &str,
    resolver: SocketAddr,
    ifindex: Option<u32>,
) -> Result<Vec<Ipv4Addr>, Udp53ErrorKind> {
    let query = build_dns_query(host)?;
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| Udp53ErrorKind::QueryFailed(format!("bind:{e}")))?;
    if let Some(index) = ifindex {
        // SAFETY: sock 句柄有效；IP_UNICAST_IF 的 optval 是网卡索引的网络字节序
        // DWORD（Windows 文档：IPv4 的索引值必须以网络字节序存储）。
        let rc = unsafe {
            setsockopt(
                SOCKET(sock.as_raw_socket() as usize),
                IPPROTO_IP.0,
                IP_UNICAST_IF,
                Some(&index.to_be_bytes()[..]),
            )
        };
        if rc != 0 {
            return Err(Udp53ErrorKind::QueryFailed(format!("ip-unicast-if:{rc}")));
        }
    }
    sock.set_read_timeout(Some(DNS_UDP_TIMEOUT))
        .map_err(|e| Udp53ErrorKind::QueryFailed(format!("read-timeout:{e}")))?;
    sock.set_write_timeout(Some(DNS_UDP_TIMEOUT))
        .map_err(|e| Udp53ErrorKind::QueryFailed(format!("write-timeout:{e}")))?;
    sock.send_to(&query, resolver)
        .map_err(|e| Udp53ErrorKind::QueryFailed(format!("send:{e}")))?;
    let mut resp = [0u8; 512];
    let (n, _peer) = sock
        .recv_from(&mut resp)
        .map_err(|e| Udp53ErrorKind::QueryFailed(format!("recv:{e}")))?;
    if n == 0 {
        return Err(Udp53ErrorKind::BadResponse("empty".to_string()));
    }
    parse_dns_response(&resp[..n], &DNS_QUERY_ID)
}

// ---------------------------------------------------------------------------
// 双线解析（L1 DoH → L2 UDP/53；一条失败 → 下一条；全部失败 → typed 向量）。
// ---------------------------------------------------------------------------

/// 双线可信解析（fake-ip 过滤；逐层 typed 错误收集）——**async 生产入口**。
///
/// gateway host 为 IPv4 字面量时直接采用（`ResolutionSource::System`；fake-ip 字面量
/// 拒绝）；否则按配置顺序试 DoH 全部 endpoint，再试 UDP/53 全部 resolver。
///
/// UDP/53 线路是 std 同步 socket（`read_timeout` 2s 有界阻塞），在 async 上下文内直接
/// 调用——与 acceptance 参考语义一致，单次查询以 DNS_UDP_TIMEOUT 为界、整体由
/// LAYER_DEADLINE 约束，不 panic。
///
/// # Errors
///
/// 全部线路失败 → [`ResolveLayerError`] 向量（每层一条；证据 `describe()`）。
pub async fn resolve_gateway_dual_line(
    cfg: &DualLineConfig,
    host: &str,
) -> Result<(Ipv4Addr, ResolutionSource), Vec<ResolveLayerError>> {
    // R0 计时：整体 + 逐层（LAYER_DEADLINE 5s / DNS_UDP_TIMEOUT 2s 是上界，实际耗时
    // 逐层落盘——归因 vgdc_dns 是否吃 apply 段之外的时间）。
    let _t = crate::timing::Timed::new("resource.vgdc_dns.resolve_total");
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        if is_fake_ip_v4(ip) {
            return Err(vec![ResolveLayerError::FakeIpLiteral(ip)]);
        }
        return Ok((ip, ResolutionSource::System));
    }
    let mut layer_errors: Vec<ResolveLayerError> = Vec::new();
    for ep in &cfg.doh_endpoints {
        let layer_start = std::time::Instant::now();
        match doh_query(
            std::sync::Arc::clone(&cfg.doh_client_config),
            SocketAddr::from((ep.ip, 443)),
            ep.ip.to_string(),
            ep.path,
            host,
        )
        .await
        {
            Ok(ip) => {
                crate::timing::record_elapsed(
                    &format!("resource.vgdc_dns.doh_ok:{}", ep.ip),
                    layer_start,
                );
                return Ok((ip, ResolutionSource::Doh(ep.ip)));
            }
            Err(kind) => {
                crate::timing::record_elapsed(
                    &format!("resource.vgdc_dns.doh_fail:{}", ep.ip),
                    layer_start,
                );
                layer_errors.push(ResolveLayerError::Doh {
                    endpoint: ep.ip,
                    kind,
                });
            }
        }
    }
    for resolver in &cfg.udp53_resolvers {
        // MVP 是 IPv4-only：V6 resolver 视为该层 typed 失败（不 panic）。
        let resolver_ip = match resolver.ip() {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => {
                layer_errors.push(ResolveLayerError::Udp53 {
                    resolver: Ipv4Addr::UNSPECIFIED,
                    kind: Udp53ErrorKind::BadQuery("ipv6-resolver".to_string()),
                });
                continue;
            }
        };
        let layer_start = std::time::Instant::now();
        match dns_a_query_udp(host, *resolver, cfg.udp53_ifindex) {
            Ok(mut ips) => {
                let ip = ips.remove(0);
                crate::timing::record_elapsed(
                    &format!("resource.vgdc_dns.udp53_ok:{}", resolver_ip),
                    layer_start,
                );
                return Ok((ip, ResolutionSource::Udp53(resolver_ip)));
            }
            Err(kind) => {
                crate::timing::record_elapsed(
                    &format!("resource.vgdc_dns.udp53_fail:{}", resolver_ip),
                    layer_start,
                );
                layer_errors.push(ResolveLayerError::Udp53 {
                    resolver: resolver_ip,
                    kind,
                });
            }
        }
    }
    Err(layer_errors)
}

// ---------------------------------------------------------------------------
// 物理网卡发现（GetAdaptersAddresses；UDP/53 绑网卡 + /32 路由共用）。
// ---------------------------------------------------------------------------

/// `SOCKET_ADDRESS` → IPv4 地址（非 `AF_INET` 返回 `None`）。
#[must_use]
fn ipv4_of(sa: &SOCKET_ADDRESS) -> Option<Ipv4Addr> {
    if sa.lpSockaddr.is_null() {
        return None;
    }
    // SAFETY: lpSockaddr 指向 SOCKADDR_INET 兼容缓冲区（sockaddr 存储足以容纳）；
    // AF_INET 分支下 sin_addr 有效（routes.rs 同款读取路径）。
    let inet = unsafe { &*sa.lpSockaddr.cast::<SOCKADDR_INET>() };
    if unsafe { inet.si_family } != AF_INET {
        return None;
    }
    // SAFETY: AF_INET 分支下 Ipv4.sin_addr 有效；S_addr 按网络字节序存于内存
    // （x86 LE：to_le_bytes 还原字节顺序，routes.rs 同款实测修正）。
    let octets = unsafe { inet.Ipv4.sin_addr.S_un.S_addr }.to_le_bytes();
    Some(Ipv4Addr::from(octets))
}

/// 适配器第一个 IPv4 单播地址。
#[must_use]
fn first_ipv4_unicast(a: &IP_ADAPTER_ADDRESSES_LH) -> Option<Ipv4Addr> {
    let mut cur = a.FirstUnicastAddress;
    while !cur.is_null() {
        // SAFETY: 系统链表（GetAdaptersAddresses 所有权）；非空指针有效。
        let ua = unsafe { &*cur };
        if let Some(ip) = ipv4_of(&ua.Address) {
            return Some(ip);
        }
        cur = ua.Next;
    }
    None
}

/// 适配器第一个 IPv4 网关。
#[must_use]
fn first_ipv4_gateway(a: &IP_ADAPTER_ADDRESSES_LH) -> Option<Ipv4Addr> {
    let mut cur = a.FirstGatewayAddress;
    while !cur.is_null() {
        // SAFETY: 系统链表（GetAdaptersAddresses 所有权）；非空指针有效。
        let ga = unsafe { &*cur };
        if let Some(ip) = ipv4_of(&ga.Address) {
            return Some(ip);
        }
        cur = ga.Next;
    }
    None
}

/// 虚拟/隧道适配器名称标记（排除 Mihomo TUN / Wintun / Hyper-V 虚拟交换机等）。
#[must_use]
fn is_virtual_adapter_name(name: &str) -> bool {
    const MARKERS: [&str; 15] = [
        "wintun", "mihomo", "clash", "meta", "tun", "loopback", "virtual", "vehernet",
        "hyper-v", "docker", "tailscale", "zerotier", "vmware", "virtualbox", "exv",
    ];
    let lower = name.to_ascii_lowercase();
    MARKERS.iter().any(|m| lower.contains(m))
}

/// 发现全部物理网卡（以太网/802.11、OperStatus Up、有 IPv4 单播 + 网关、非虚拟）；
/// 按 `ipv4_metric` 升序（越小越优先）。
///
/// # Errors
///
/// `GetAdaptersAddresses` 失败 → `String` 描述。
pub fn find_physical_nics() -> Result<Vec<NicInfo>, String> {
    let mut size: u32 = 0;
    // SAFETY: 首次调用只查询所需缓冲区大小（adapter 缓冲区 None；size 由系统填充）。
    let rc = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_INET.0),
            GAA_FLAG_INCLUDE_GATEWAYS,
            None,
            None,
            &raw mut size,
        )
    };
    if rc != 0 && rc != ERROR_BUFFER_OVERFLOW {
        return Err(format!("GetAdaptersAddresses rc={rc}"));
    }
    // 对齐：u64 缓冲区（IP_ADAPTER_ADDRESSES_LH 需要 8 字节对齐）。
    let mut buf = vec![0u64; size as usize / 8 + 2];
    let ptr = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut out_size = (buf.len() * 8) as u32;
    // SAFETY: 缓冲区按请求大小分配且对齐；系统填充链表（同一调用返回后 buf 存活）。
    let rc = unsafe {
        GetAdaptersAddresses(
            u32::from(AF_INET.0),
            GAA_FLAG_INCLUDE_GATEWAYS,
            None,
            Some(ptr),
            &raw mut out_size,
        )
    };
    if rc != 0 {
        return Err(format!("GetAdaptersAddresses rc={rc}"));
    }
    let mut out: Vec<NicInfo> = Vec::new();
    // SAFETY: 系统填充的链表；Next 链按 Length 约束（Windows 保证有效）。
    let mut cur = ptr;
    while !cur.is_null() {
        let a = unsafe { &*cur };
        let is_physical = a.IfType == IF_TYPE_ETHERNET_CSMACD || a.IfType == IF_TYPE_IEEE80211;
        if is_physical && a.OperStatus == IfOperStatusUp && !a.FirstGatewayAddress.is_null() {
            let friendly_name = unsafe { a.FriendlyName.to_string() }.unwrap_or_default();
            if !is_virtual_adapter_name(&friendly_name)
                && let (Some(local_ip), Some(gateway)) =
                    (first_ipv4_unicast(a), first_ipv4_gateway(a))
            {
                // SAFETY: 读 union 成员（Anonymous1 的 IfIndex、Luid.Value；
                // routes.rs 同款读取路径）。
                let (ifindex, luid) = unsafe { (a.Anonymous1.Anonymous.IfIndex, a.Luid.Value) };
                out.push(NicInfo {
                    luid,
                    ifindex,
                    gateway,
                    local_ip,
                    friendly_name,
                    ipv4_metric: a.Ipv4Metric,
                });
            }
        }
        cur = a.Next;
    }
    out.sort_by_key(|n| n.ipv4_metric);
    Ok(out)
}

/// `ERROR_BUFFER_OVERFLOW`（`GetAdaptersAddresses` 首次 size 查询的预期返回）。
const ERROR_BUFFER_OVERFLOW: u32 = 111;

// ---------------------------------------------------------------------------
// C3 生产供给：CSTP/TLS 控制面 socket 出口绑定（IP_UNICAST_IF；自 acceptance
// `socket_binder.rs` 提升，供 `BootstrapConfig.socket_binder` 注入）。
// ---------------------------------------------------------------------------

/// 由物理出口 ifindex 构造 CSTP/TLS 控制面 socket 出口绑定闭包
/// （`IP_UNICAST_IF`，网络字节序，绑定点 = TCP connect 之前）。
///
/// `ifindex == 0`（无效/未探测）返回 `None`，调用方可回退到不绑定（默认路由）。
///
/// # Errors
///
/// 无（绑定的 setsockopt 失败在闭包调用时以 `std::io::Error` 返回，connect 会以
/// `BootstrapError::ConnectFailed` 中止）。
#[must_use]
pub fn socket_binder_for_ifindex(ifindex: u32) -> Option<Arc<SocketBinder>> {
    if ifindex == 0 {
        return None;
    }
    Some(Arc::new(move |socket: &tokio::net::TcpSocket| -> std::io::Result<()> {
        let raw = socket.as_raw_socket();
        // SAFETY: socket 句柄有效（tokio TcpSocket 持有）；IP_UNICAST_IF 的 optval
        // 是网卡索引的网络字节序 DWORD（Windows 文档：IPv4 索引必须网络字节序存储，
        // 否则 WSAEADDRNOTAVAIL，见 dev.22 实测）。
        let rc = unsafe {
            setsockopt(
                SOCKET(raw as usize),
                IPPROTO_IP.0,
                IP_UNICAST_IF,
                Some(&ifindex.to_be_bytes()[..]),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc));
        }
        Ok(())
    }))
}

// ---------------------------------------------------------------------------
// 机制测试（非 elevated）：DoH 假 HTTPS 服务器（注入 TestRoots）、UDP/53 假 socket、
// fake-ip 过滤、层回退矩阵、物理网卡发现、socket binder 参数形态。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, mpsc};

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};

    use super::*;

    /// 测试 host（嵌入证书 SAN）。
    const TEST_HOST: &str = "vpn.example.test";
    /// 假 DoH 服务器返回的 A 记录。
    const FAKE_A_IP: [u8; 4] = [222, 66, 117, 109];

    // 测试 TLS 材料（自签 ECDSA P-256；SAN DNS:vpn.example.test；与 acceptance
    // `controlled.rs` 同源材料，测试夹具允许副本——逻辑不 fork，仅静态数据）。
    const VPN_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
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
    const VPN_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn1Ra5jnCNjCWeCfF
x0h7BnT9tvnlrqAdc+0xZphBfZWhRANCAAQ621WzgT+Rp6MR+st4LY1gxps9HzBS
lIIFbbHWM3PjUe5vJXzSuEaBQ+t6kBsHEc9FoX5oPA6ivQ7eryJYMrL4
-----END PRIVATE KEY-----
"#;

    fn test_cert() -> rustls::pki_types::CertificateDer<'static> {
        use rustls::pki_types::pem::PemObject;
        rustls::pki_types::CertificateDer::from_pem_slice(VPN_CERT_PEM.as_bytes())
            .expect("嵌入测试证书必须可解析")
    }

    /// 注入 TestRoots 的测试 TLS 客户端配置（严格 webpki + `CaUsedAsEndEntity` 特例——
    /// 自签名测试根作为自己的 end-entity；acceptance `controlled::TestRootsVerifier`
    /// 同款语义）。
    fn test_tls_client_config(
        cert: &rustls::pki_types::CertificateDer<'static>,
    ) -> Result<std::sync::Arc<rustls::ClientConfig>, String> {
        let roots = {
            let mut r = rustls::RootCertStore::empty();
            r.add(cert.clone()).map_err(|_| "root-add".to_string())?;
            Arc::new(r)
        };
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            roots,
            provider.clone(),
        )
        .build()
        .map_err(|e| format!("verifier:{e}"))?;
        let verifier = TestRootsVerifier {
            inner,
            cert: cert.clone(),
        };
        let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| "client-config".to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(std::sync::Arc::new(client_cfg))
    }

    /// 测试根 verifier（acceptance `controlled::TestRootsVerifier` 同款：注入根 +
    /// 严格 webpki，允许自签名注入根作为自己的 end-entity——`CaUsedAsEndEntity` 特例）。
    #[derive(Debug)]
    struct TestRootsVerifier {
        inner: Arc<rustls::client::WebPkiServerVerifier>,
        cert: rustls::pki_types::CertificateDer<'static>,
    }

    impl TestRootsVerifier {
        /// end-entity 是否就是注入的信任根（按 subjectPublicKeyInfo 内容比较——
        /// 两端都剥掉外层 SEQUENCE；TrustAnchor 与 acceptance 存的是内容）。
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

    /// 剥掉 DER `SEQUENCE` 头（返回内容；acceptance `strip_sequence_header` 同款）。
    fn strip_sequence_header(bytes: &[u8]) -> Option<&[u8]> {
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
        ) -> Result<ServerCertVerified, rustls::Error> {
            match self.inner.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ) {
                Ok(verified) => Ok(verified),
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Other(_),
                )) => {
                    if self.end_entity_is_injected_root(end_entity) {
                        let cert = rustls::server::ParsedCertificate::try_from(end_entity)
                            .map_err(|_e| {
                                rustls::Error::InvalidCertificate(
                                    rustls::CertificateError::BadEncoding,
                                )
                            })?;
                        rustls::client::verify_server_name(&cert, server_name).map_err(|_e| {
                            rustls::Error::InvalidCertificate(
                                rustls::CertificateError::NotValidForName,
                            )
                        })?;
                        return Ok(ServerCertVerified::assertion());
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
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls12_signature(message, cert, dss)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.inner.verify_tls13_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.inner.supported_verify_schemes()
        }
    }

    fn ok_doh_body(ip: [u8; 4]) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-json\r\nConnection: close\r\n\r\n\
             {{\"Status\":0,\"Answer\":[{{\"name\":\"{TEST_HOST}.\",\"type\":1,\"TTL\":60,\"data\":\"{}.{}.{}.{}\"}}]}}",
            ip[0], ip[1], ip[2], ip[3]
        )
    }

    /// 在 127.0.0.1 上起一个一次性假 HTTPS DoH 服务器（嵌入证书；读请求 → 写 body →
    /// 关闭）。返回 (runtime, addr)——同 runtime 上 spawn，测试 block_on 查询。
    fn spawn_fake_doh_server(body: String) -> (tokio::runtime::Runtime, SocketAddr) {
        use rustls::pki_types::pem::PemObject;
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let cert = test_cert();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(VPN_KEY_PEM.as_bytes())
            .expect("嵌入测试私钥必须可解析");
        let (tx, rx) = mpsc::channel::<SocketAddr>();
        rt.spawn(async move {
            let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
                Ok(l) => l,
                Err(_) => return,
            };
            let addr = match listener.local_addr() {
                Ok(a) => a,
                Err(_) => return,
            };
            let _ = tx.send(addr);
            let (tcp, _peer) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let server_cfg = match rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
            {
                Ok(c) => c,
                Err(_) => return,
            };
            let acceptor =
                std::sync::Arc::new(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg)));
            let Ok(mut stream) = acceptor.accept(tcp).await else {
                return;
            };
            let mut req = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let Ok(n) = tokio::io::AsyncReadExt::read(&mut stream, &mut chunk).await else {
                    return;
                };
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&chunk[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, body.as_bytes()).await;
        });
        let addr = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("假 DoH 服务器必须完成 bind");
        (rt, addr)
    }

    /// 构造假 DNS 响应（question 回显 + 压缩指针 answer）。
    fn build_fake_dns_response(ips: &[[u8; 4]]) -> Vec<u8> {
        let mut r: Vec<u8> = Vec::new();
        r.extend_from_slice(&DNS_QUERY_ID);
        r.extend_from_slice(&[
            0x81, 0x80, 0x00, 0x01, 0x00, ips.len() as u8, 0x00, 0x00, 0x00, 0x00,
        ]);
        for label in TEST_HOST.split('.') {
            r.push(label.len() as u8);
            r.extend_from_slice(label.as_bytes());
        }
        r.push(0);
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        for ip in ips {
            r.extend_from_slice(&[0xC0, 0x0C]); // 压缩指针 → question name
            r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
            r.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
            r.extend_from_slice(&[0x00, 0x04]);
            r.extend_from_slice(ip);
        }
        r
    }

    /// 假 UDP/53 服务器：绑定 127.0.0.1 随机端口，收查询 → 回假响应；返回服务器地址
    /// （客户端 socket 自行 bind 后向该地址发送——内核 recv 队列缓冲，无先发后收竞态）。
    fn spawn_fake_udp_resolver(resp: Vec<u8>) -> SocketAddr {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp bind");
        let addr = server.local_addr().expect("local addr");
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            if let Ok((_n, peer)) = server.recv_from(&mut buf) {
                let _ = server.send_to(&resp, peer);
            }
        });
        addr
    }

    // ---- fake-ip 过滤 ----

    #[test]
    fn fake_ip_filter_boundaries() {
        assert!(is_fake_ip_v4(Ipv4Addr::new(198, 18, 0, 0)));
        assert!(is_fake_ip_v4(Ipv4Addr::new(198, 18, 1, 15)));
        assert!(is_fake_ip_v4(Ipv4Addr::new(198, 19, 255, 255)));
        assert!(!is_fake_ip_v4(Ipv4Addr::new(198, 17, 255, 255)));
        assert!(!is_fake_ip_v4(Ipv4Addr::new(198, 20, 0, 0)));
        assert!(!is_fake_ip_v4(Ipv4Addr::new(222, 66, 117, 109)));
        assert!(!is_fake_ip_v4(Ipv4Addr::new(127, 0, 0, 1)));
    }

    // ---- L1 DoH 机制 ----

    #[test]
    fn doh_resolves_against_fake_https_server() {
        let (rt, addr) = spawn_fake_doh_server(ok_doh_body(FAKE_A_IP));
        let cfg = test_tls_client_config(&test_cert()).expect("test client config");
        let ip = rt
            .block_on(doh_query(cfg, addr, TEST_HOST.to_string(), "/resolve", TEST_HOST))
            .expect("DoH 查询必须成功");
        assert_eq!(ip, Ipv4Addr::from(FAKE_A_IP));
    }

    #[test]
    fn doh_filters_fake_ip_answer() {
        let (rt, addr) = spawn_fake_doh_server(ok_doh_body([198, 18, 1, 15]));
        let cfg = test_tls_client_config(&test_cert()).expect("test client config");
        let err = rt
            .block_on(doh_query(cfg, addr, TEST_HOST.to_string(), "/resolve", TEST_HOST))
            .expect_err("fake-ip 结果必须被过滤");
        assert_eq!(err, DohErrorKind::NoIpv4Result);
    }

    #[test]
    fn doh_rejects_nonzero_dns_status() {
        let body = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-json\r\nConnection: close\r\n\r\n{\"Status\":2,\"Answer\":[]}";
        let (rt, addr) = spawn_fake_doh_server(body.to_string());
        let cfg = test_tls_client_config(&test_cert()).expect("test client config");
        let err = rt
            .block_on(doh_query(cfg, addr, TEST_HOST.to_string(), "/resolve", TEST_HOST))
            .expect_err("Status 非 0 必须被拒绝");
        assert_eq!(err, DohErrorKind::DnsStatus(2));
    }

    #[test]
    fn doh_rejects_http_error_status() {
        let body = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let (rt, addr) = spawn_fake_doh_server(body.to_string());
        let cfg = test_tls_client_config(&test_cert()).expect("test client config");
        let err = rt
            .block_on(doh_query(cfg, addr, TEST_HOST.to_string(), "/resolve", TEST_HOST))
            .expect_err("HTTP 404 必须被拒绝");
        assert_eq!(err, DohErrorKind::HttpStatus(404));
    }

    #[test]
    fn doh_rejects_bad_body() {
        let body = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nnot-json";
        let (rt, addr) = spawn_fake_doh_server(body.to_string());
        let cfg = test_tls_client_config(&test_cert()).expect("test client config");
        let err = rt
            .block_on(doh_query(cfg, addr, TEST_HOST.to_string(), "/resolve", TEST_HOST))
            .expect_err("坏响应体必须被拒绝");
        assert!(matches!(err, DohErrorKind::BadResponse(_)));
    }

    // ---- L2 UDP/53 机制 ----

    #[test]
    fn udp53_resolves_against_fake_socket() {
        let addr = spawn_fake_udp_resolver(build_fake_dns_response(&[FAKE_A_IP]));
        let ips = dns_a_query_udp(TEST_HOST, addr, None).expect("UDP/53 查询必须成功");
        assert_eq!(ips, vec![Ipv4Addr::from(FAKE_A_IP)]);
    }

    #[test]
    fn udp53_filters_fake_ip_answer() {
        let addr = spawn_fake_udp_resolver(build_fake_dns_response(&[[198, 18, 1, 15]]));
        let err = dns_a_query_udp(TEST_HOST, addr, None).expect_err("fake-ip 结果必须被过滤");
        assert_eq!(err, Udp53ErrorKind::NoIpv4Result);
    }

    #[test]
    fn udp53_rejects_id_mismatch() {
        let mut resp = build_fake_dns_response(&[FAKE_A_IP]);
        resp[0] ^= 0xFF;
        let addr = spawn_fake_udp_resolver(resp);
        let err = dns_a_query_udp(TEST_HOST, addr, None).expect_err("ID 不匹配必须被拒绝");
        assert!(matches!(err, Udp53ErrorKind::BadResponse(_)));
    }

    #[test]
    fn udp53_rejects_truncated_response() {
        let mut resp = build_fake_dns_response(&[FAKE_A_IP]);
        resp.truncate(10);
        let addr = spawn_fake_udp_resolver(resp);
        let err = dns_a_query_udp(TEST_HOST, addr, None).expect_err("截断响应必须被拒绝");
        assert!(matches!(err, Udp53ErrorKind::BadResponse(_)));
    }

    #[test]
    fn dns_query_rejects_bad_labels() {
        assert!(matches!(
            build_dns_query("a..b"),
            Err(Udp53ErrorKind::BadQuery(_))
        ));
        let long = format!("{}.com", "x".repeat(64));
        assert!(matches!(
            build_dns_query(&long),
            Err(Udp53ErrorKind::BadQuery(_))
        ));
        assert!(build_dns_query("vpn-ct.ecnu.edu.cn").is_ok());
    }

    // ---- 层回退矩阵（async 入口） ----

    #[tokio::test]
    async fn falls_back_to_udp53_when_doh_unreachable() {
        let udp_addr = spawn_fake_udp_resolver(build_fake_dns_response(&[FAKE_A_IP]));
        let cfg = DualLineConfig {
            doh_endpoints: vec![DohEndpoint {
                ip: Ipv4Addr::LOCALHOST, // 127.0.0.1:443 无监听 → connect refused
                path: "/resolve",
            }],
            doh_client_config: test_tls_client_config(&test_cert()).expect("test client config"),
            udp53_resolvers: vec![udp_addr],
            udp53_ifindex: None,
        };
        let (ip, src) = resolve_gateway_dual_line(&cfg, TEST_HOST)
            .await
            .expect("L2 必须兜底");
        assert_eq!(ip, Ipv4Addr::from(FAKE_A_IP));
        let SocketAddr::V4(udp_v4) = udp_addr else {
            panic!("假 socket 必须是 IPv4");
        };
        assert_eq!(src, ResolutionSource::Udp53(*udp_v4.ip()));
    }

    #[tokio::test]
    async fn both_layers_fail_with_typed_errors() {
        let cfg = DualLineConfig {
            doh_endpoints: vec![DohEndpoint {
                ip: Ipv4Addr::LOCALHOST, // connect refused
                path: "/resolve",
            }],
            doh_client_config: test_tls_client_config(&test_cert()).expect("test client config"),
            udp53_resolvers: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))], // 无监听 → timeout
            udp53_ifindex: None,
        };
        let errors = resolve_gateway_dual_line(&cfg, TEST_HOST)
            .await
            .expect_err("全部线路失败必须 typed");
        assert_eq!(errors.len(), 2, "必须逐层记录错误（doh + udp53）");
        let described: Vec<String> = errors.iter().map(ResolveLayerError::describe).collect();
        assert!(
            described[0].starts_with("doh:127.0.0.1:connect-failed"),
            "got {described:?}"
        );
        assert!(
            described[1].starts_with("udp53:127.0.0.1:query-failed"),
            "got {described:?}"
        );
    }

    #[tokio::test]
    async fn ip_literal_uses_system_source() {
        let cfg = DualLineConfig {
            doh_endpoints: Vec::new(),
            doh_client_config: test_tls_client_config(&test_cert()).expect("test client config"),
            udp53_resolvers: Vec::new(),
            udp53_ifindex: None,
        };
        let (ip, src) = resolve_gateway_dual_line(&cfg, "222.66.117.109")
            .await
            .expect("IP 字面量直接采用");
        assert_eq!(ip, Ipv4Addr::new(222, 66, 117, 109));
        assert_eq!(src, ResolutionSource::System);
    }

    #[tokio::test]
    async fn fake_ip_literal_is_rejected() {
        let cfg = DualLineConfig {
            doh_endpoints: Vec::new(),
            doh_client_config: test_tls_client_config(&test_cert()).expect("test client config"),
            udp53_resolvers: Vec::new(),
            udp53_ifindex: None,
        };
        let errors = resolve_gateway_dual_line(&cfg, "198.18.1.15")
            .await
            .expect_err("fake-ip 字面量必须拒绝");
        assert_eq!(
            errors,
            vec![ResolveLayerError::FakeIpLiteral(Ipv4Addr::new(198, 18, 1, 15))]
        );
    }

    // ---- socket binder 参数形态 ----

    /// 真实未连接 TcpSocket 上，物理网卡 ifindex 的 `IP_UNICAST_IF` 绑定必须返回
    /// `Ok`（rc=0；setsockopt 层面即证明绑定参数形态正确，无需建立连接）。依赖宿主
    /// 至少有一个物理网卡；无物理网卡的宿主跳过断言。
    #[test]
    fn binder_accepts_detected_physical_nic_ifindex() {
        let nics = find_physical_nics().expect("物理网卡发现必须成功");
        let Some(nic) = nics.first() else {
            return; // 无物理网卡：不可验证，跳过（非失败）。
        };
        let binder = socket_binder_for_ifindex(nic.ifindex).expect("非零 ifindex 必须产出绑定闭包");
        let socket = tokio::net::TcpSocket::new_v4().expect("创建未连接 socket");
        binder(&socket).expect("物理网卡 ifindex 的 IP_UNICAST_IF 绑定必须 rc=0");
    }

    /// ifindex == 0（未探测/无效）必须产出 `None`——调用方回退到不绑定默认路由。
    #[test]
    fn zero_ifindex_yields_none() {
        assert!(socket_binder_for_ifindex(0).is_none());
    }

    // ---- live 解析（本宿主；`--ignored` 门控：Mihomo 运行中，双线解析真实网关）。 ----

    /// 真机 live 解析：在 Mihomo TUN + fake-ip 运行中，双线解析 `vpn-ct.ecnu.edu.cn`
    /// 必须返回真实 IP 222.66.117.109（非 fake 198.18.1.15），来源 doh。
    #[test]
    #[ignore = "live network verification on the W30 host (Mihomo running)"]
    fn live_resolve_vpn_gateway() {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let cfg = DualLineConfig::production(None).expect("production config");
        rt.block_on(resolve_gateway_dual_line(&cfg, "vpn-ct.ecnu.edu.cn"))
            .map(|(ip, src)| {
                println!("LIVE_RESOLVE: ip={ip} source={}", src.as_str());
                assert_eq!(ip, Ipv4Addr::new(222, 66, 117, 109));
                assert_eq!(src.as_str(), "doh");
            })
            .unwrap_or_else(|errors| {
                let detail: Vec<String> =
                    errors.iter().map(ResolveLayerError::describe).collect();
                panic!("LIVE_RESOLVE failed: {}", detail.join("; "));
            });
    }

    /// 真机物理网卡发现：打印候选物理网卡（UDP/53 绑网卡与 /32 路由的事实基础）。
    #[test]
    #[ignore = "live network verification on the W30 host"]
    fn live_find_physical_nics() {
        let nics = find_physical_nics().expect("物理网卡发现必须成功");
        assert!(!nics.is_empty(), "宿主必须至少有一个物理网卡");
        for n in &nics {
            println!(
                "LIVE_NIC: name={} luid={} ifindex={} gateway={} local_ip={} metric={}",
                n.friendly_name, n.luid, n.ifindex, n.gateway, n.local_ip, n.ipv4_metric
            );
        }
    }
}
