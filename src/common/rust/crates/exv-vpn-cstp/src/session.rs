// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! CSTP session phase (CS-AUTH-02-I): `CONNECT /CSCOSSLC/tunnel` + webvpn
//! cookie + data session.
//!
//! [`CstpSession::open`] runs the full chain over a real
//! [`Bootstrap`](crate::connector::Bootstrap) TLS connection under the injected
//! trust policy: it writes the byte-exact CONNECT request (plan §3.2 verbatim
//! block; openconnect `cstp.c` `start_cstp_connection()` anchors — the tag pin
//! and per-line verification are recorded at the leaf commit, per plan §3
//! provenance discipline), reads the offer up to its `\r\n\r\n` terminator
//! (early EOF is the typed [`SessionError::EofBeforeTerminator`], never a
//! success), validates it into a [`TunnelOffer`] plan (engine version of the
//! school `validate_school_offer` semantics, plan §3.3; an HTTP error status /
//! non-CSTP content is [`SessionError::OfferParseFailed`]), splits the stream,
//! and hands the two halves to two data tasks (engine version of the school
//! `spawn_school_data_tasks` pattern) so the returned session carries working
//! CSTP data channels: frames sent on `write_channel` go on the wire raw, and
//! gateway frames arrive decoded as `CstpFrame::Data` payloads on
//! `read_channel`.

use std::net::Ipv4Addr;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::codec::{Codec, CodecError, CstpFrame};
use crate::connector::{Bootstrap, BootstrapConfig, BootstrapError};
use crate::webvpn::{
    LoginSession, build_connect_request, build_connect_request_with_user_agent,
};

/// Upper bound on the offer head before it is rejected as non-CSTP content.
const MAX_OFFER: usize = 16 * 1024;

/// The validated CSTP tunnel offer plan (engine version of the school
/// `validate_school_offer` semantics, plan §3.3).
///
/// `Serialize` only, never `Deserialize` (C01 discipline: a safe business
/// representation, not a live runtime).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TunnelOffer {
    /// The gateway-assigned IPv4 address (`X-CSTP-Address`).
    pub ipv4_address: Ipv4Addr,
    /// The prefix length derived from `X-CSTP-Netmask` (contiguous masks only).
    pub prefix: u8,
    /// The negotiated tunnel MTU (68..=65535).
    pub mtu: u16,
    /// The gateway-assigned DNS servers (`X-CSTP-DNS`, whitespace-separated).
    pub dns_servers: Vec<Ipv4Addr>,
    /// The split-include routes as `"net/prefix"` CIDR strings (school-aligned).
    pub routes: Vec<String>,
}

// ---------------------------------------------------------------------------
// T1 latency probe seam（单侧宿主豁免政策：文件内注释位置/目的/必要性）。
// ---------------------------------------------------------------------------
// 位置：DPD wire 判别常量 + 控制面事件类型放在 session.rs（而非 codec.rs）——engine
// 延迟探测（T1）需要向网关注入 DPD request（上传方向）并感知 DPD response 到达；
// codec.rs 在 T1 的文件边界之外，故常量与事件类型随消费它的控制面出口同居本文件。
// 必要性：codec 只解码 keepalive（0x07）控制帧，DPD 0x03/0x04 走 `UnknownControl`
// 错误路径返回——若不在此转义，读任务会在首个 DPD 响应帧处死亡（会话断链）。
// 目的：把控制面事件（含 DPD response 探测信号）透出给 engine 的延迟探测循环，
// 且保持读任务对未知控制帧的存活（健壮性提升，非 T1 之前的行为破坏）。

/// CSTP wire packet type for a DPD (dead-peer-detection) request (AnyConnect 0x03).
///
/// Defined here rather than in `codec.rs` by the single-host exemption policy (see
/// the module note above): the engine latency probe (T1) sends DPD requests on the
/// upload path and needs the wire discriminant; the codec is outside T1's file
/// boundary. The codec does not decode 0x03/0x04 — they surface as
/// `CodecError::UnknownControl`, and this module maps the response to the probe
/// signal (see [`CstpControlEvent::DpdResponse`]).
pub const CSTP_PACKET_TYPE_DPD_REQUEST: u8 = 0x03;

/// CSTP wire packet type for a DPD response (AnyConnect 0x04) — the RTT probe signal.
pub const CSTP_PACKET_TYPE_DPD_RESPONSE: u8 = 0x04;

/// A CSTP control-plane event surfaced from the data session's read path.
///
/// The codec decodes keepalive control frames into [`CstpFrame::Control`]; DPD
/// responses (wire kind 0x04) surface as `UnknownControl` codec errors and are
/// mapped here to the dedicated probe signal so the engine can time dead-peer
/// detection RTT without the read task dying on an unknown control frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CstpControlEvent {
    /// A decoded control frame (e.g. keepalive) with its wire kind and body.
    Control { kind: u8, body: Vec<u8> },
    /// A DPD response frame (wire kind 0x04) was received.
    DpdResponse,
}

/// An established CSTP data session (the outcome of a successful CONNECT
/// phase). Debug never leaks the session cookie (it holds none).
#[derive(Debug)]
pub struct CstpSession {
    /// The validated offer plan (address/prefix/mtu/dns/routes).
    pub offer_plan: TunnelOffer,
    /// SHA-256 hex digest of the peer certificate, when the handshake exposed
    /// one (never the raw certificate).
    pub peer_fingerprint: Option<String>,
    /// Raw on-wire CSTP frames to send (Codec-encoded by the caller).
    pub write_channel: mpsc::UnboundedSender<Vec<u8>>,
    /// Decoded `CstpFrame::Data` payloads received from the gateway.
    pub read_channel: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Control-plane events (keepalive frames + the DPD-response probe signal) that
    /// arrive on the data session's read path. Consumed by the engine's latency
    /// probe; a dropped consumer is non-fatal (control events are best-effort).
    pub control_rx: mpsc::UnboundedReceiver<CstpControlEvent>,
}

/// Typed failure of the CSTP CONNECT/session phase (plan §2.2).
#[allow(
    clippy::module_name_repetitions,
    reason = "API fixed verbatim by the CS-AUTH-02-T test contract (tests/webvpn_connect.rs)"
)]
#[derive(Debug)]
pub enum SessionError {
    /// The TLS bootstrap rejected the peer (untrusted chain / hostname
    /// mismatch / handshake / connect / IPv6 target / DTLS offer).
    TlsFailed(BootstrapError),
    /// Writing the CONNECT request to the gateway failed.
    WriteFailed,
    /// The connection ended (EOF) before the offer's `\r\n\r\n` terminator:
    /// the gateway rejected the request format.
    EofBeforeTerminator,
    /// The offer could not be parsed into a valid tunnel plan (HTTP error
    /// status / non-CSTP content / missing required field).
    OfferParseFailed,
    /// `open` was called without a login session: a cookie-less CONNECT is
    /// rejected BEFORE any network activity.
    MissingSession,
}

impl CstpSession {
    /// Establish the CSTP session over a real TLS connection:
    /// Bootstrap(TrustPolicy from `cfg`) -> byte-exact CONNECT request
    /// (plan §3.2, `build_connect_request` bytes) -> offer read (HTTP-head
    /// style until `\r\n\r\n`; early EOF is [`SessionError::EofBeforeTerminator`])
    /// -> validated [`TunnelOffer`] plan -> stream split -> two data tasks.
    ///
    /// The webvpn cookie captured by the committed CS-AUTH-01 login flows into
    /// the CONNECT request verbatim and IS the credential: no `Authorization`
    /// and no `X-AnyConnect-*` header is ever written.
    ///
    /// # Errors
    ///
    /// * [`SessionError::MissingSession`] — `login` is `None` (no network
    ///   activity happens).
    /// * [`SessionError::TlsFailed`] — the bootstrap rejected the peer.
    /// * [`SessionError::WriteFailed`] — the CONNECT request could not be
    ///   written.
    /// * [`SessionError::EofBeforeTerminator`] — EOF before the offer's
    ///   `\r\n\r\n` terminator.
    /// * [`SessionError::OfferParseFailed`] — non-CSTP offer content (HTTP
    ///   error status / missing required field).
    pub async fn open(
        cfg: BootstrapConfig,
        login: Option<&LoginSession>,
    ) -> Result<CstpSession, SessionError> {
        Self::open_with_user_agent(cfg, login, None).await
    }

    /// Establish the CSTP session with an explicit client `User-Agent` on the
    /// CONNECT request — the additive per-connection override of the login
    /// phase's client name ([`crate::webvpn::default_user_agent`] /
    /// [`WebvpnLogin::perform_login_with_user_agent`](crate::webvpn::WebvpnLogin::perform_login_with_user_agent);
    /// the C++ `make_cstp_connect_request` shape). The webvpn cookie is
    /// still the credential; the UA is the client identity the gateway logs.
    ///
    /// `user_agent: None` writes the legacy UA-less CONNECT (verified working
    /// on the school gateway); `Some` carries the given UA. The client name
    /// is never hardcoded into the flow: the caller passes it here, and a
    /// config/settings layer may substitute its own platform default.
    ///
    /// # Errors
    ///
    /// Same as [`CstpSession::open`].
    pub async fn open_with_user_agent(
        cfg: BootstrapConfig,
        login: Option<&LoginSession>,
        user_agent: Option<&str>,
    ) -> Result<CstpSession, SessionError> {
        // A cookie-less CONNECT is a typed error BEFORE any network activity
        // (kills the "cookie missing still CONNECTs" mutant).
        let login = login.ok_or(SessionError::MissingSession)?;

        let host = cfg.hostname.clone();
        let bootstrap_session = Bootstrap::system()
            .connect(cfg)
            .await
            .map_err(|failure| SessionError::TlsFailed(failure.error))?;

        // The frozen bootstrap stays opaque; the TLS stream is handed over
        // through the additive `into_stream` accessor (connector.rs, §7
        // governance record). The peer certificate fingerprint is a SHA-256
        // digest, never the raw certificate.
        let mut stream = bootstrap_session.into_stream();
        let fingerprint = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first().cloned())
            .map(|cert| sha256_hex(cert.as_ref()));

        // --- CONNECT request: byte-exact plan §3.2 bytes; the webvpn cookie
        // is the credential (no Authorization, no X-AnyConnect-*). The
        // additive UA variant carries the caller's client name. ---
        let request = match user_agent {
            Some(user_agent) => build_connect_request_with_user_agent(&host, login, user_agent),
            None => build_connect_request(&host, login),
        };
        stream
            .write_all(&request)
            .await
            .map_err(|_| SessionError::WriteFailed)?;
        stream
            .flush()
            .await
            .map_err(|_| SessionError::WriteFailed)?;

        // --- Offer read: HTTP-head style up to the `\r\n\r\n` terminator.
        // EOF before the terminator = the gateway rejected the request format
        // (typed error, never a partial-offer success). ---
        let mut buf = Vec::new();
        let mut tmp = [0u8; 512];
        let head_end = loop {
            match stream.read(&mut tmp).await {
                // The gateway closed the connection before the offer's
                // `\r\n\r\n` terminator (a rejected request format): a clean
                // EOF (`Ok(0)`) and an abrupt close without close_notify
                // (read `Err`) are the same observed rejection signature and
                // surface as the typed EofBeforeTerminator — never a success.
                Ok(0) | Err(_) => return Err(SessionError::EofBeforeTerminator),
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(end) = find_header_end(&buf) {
                        break end;
                    }
                    if buf.len() > MAX_OFFER {
                        return Err(SessionError::OfferParseFailed);
                    }
                }
            }
        };

        // Bytes past the terminator belong to the CSTP binary frame stream and
        // are handed to the read data task (never dropped).
        let remainder = buf.split_off(head_end);
        let head = String::from_utf8_lossy(&buf);
        let offer_plan = parse_offer(&head).ok_or(SessionError::OfferParseFailed)?;

        // --- Split the stream; the two data tasks carry the binary framing
        // (engine version of the school spawn_school_data_tasks pattern) ---
        let (read_half, write_half) = tokio::io::split(stream);
        let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (read_tx, read_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        // T1 latency probe seam: control events (keepalive + DPD-response probe
        // signal) ride a dedicated channel so the engine can time dead-peer RTT
        // without mixing control frames into the data payload stream.
        let (control_tx, control_rx) = mpsc::unbounded_channel::<CstpControlEvent>();
        spawn_data_tasks(read_half, write_half, read_tx, write_rx, remainder, control_tx);

        Ok(CstpSession {
            offer_plan,
            peer_fingerprint: fingerprint,
            write_channel: write_tx,
            read_channel: read_rx,
            control_rx,
        })
    }
}

/// Parse an offer head (up to the `\r\n\r\n` terminator) into a validated
/// tunnel plan, or `None` when the content is not a valid CSTP offer (plan
/// §3.3 semantics; engine version of the school `validate_school_offer`).
///
/// Both line styles parse into the SAME plan (school L1326-1330): the HTTP
/// header style (`X-CSTP-Address: 10.88.88.1`, colon-split) and the legacy
/// line style (`CSTP_ADDRESS 10.88.88.1`, whitespace-split — the school
/// `validate_school_offer` branch at school.rs L1345-1352, 受控对齐保留).
///
/// HTTP wrapper headers are ignored; `X-CSTP-*` keys normalize to `CSTP_*`; the
/// required `CSTP_MTU` (68..=65535) / `CSTP_ADDRESS` (IPv4) / `CSTP_NETMASK`
/// (contiguous mask -> prefix 0..=32) must all be present; `CSTP_DNS` /
/// `CSTP_SPLIT_INCLUDE` items are validated individually; unknown `CSTP_*` /
/// `X-CSTP-*` keys are ignored (real-gateway extra fields); any `dtls`
/// appearance rejects the offer; a non-2xx HTTP status (rejection page) is
/// non-CSTP content.
fn parse_offer(head: &str) -> Option<TunnelOffer> {
    // The HTTP wrapper status must be 2xx: an error status is non-CSTP offer
    // content and never becomes a data session.
    let status = head.lines().next()?.split_whitespace().nth(1)?;
    let status: u16 = status.parse().ok()?;
    if !(200..=299).contains(&status) {
        return None;
    }

    let mut mtu: Option<u16> = None;
    let mut address: Option<Ipv4Addr> = None;
    let mut netmask: Option<Ipv4Addr> = None;
    let mut dns_servers: Vec<Ipv4Addr> = Vec::new();
    let mut routes: Vec<String> = Vec::new();
    for line in head.lines().skip(1) {
        // Key/value split, school `validate_school_offer` alignment (school.rs
        // L1345-1352): colon first (HTTP header style), else the first
        // whitespace (legacy line style); a keyless line is ignored, never
        // fatal.
        let (key, value) = match line.split_once(':') {
            // HTTP header style: `X-CSTP-Address: 10.88.88.1`.
            Some((key, value)) => (key, value.trim()),
            // Legacy line style: `CSTP_ADDRESS 10.88.88.1`（空白分隔，受控对齐
            // 保留）— the first whitespace token is the key, the rest of the
            // line is the value.
            None => {
                let Some(idx) = line.find(char::is_whitespace) else {
                    continue;
                };
                (line[..idx].trim(), line[idx..].trim())
            }
        };
        // `X-CSTP-Address` -> `CSTP_ADDRESS`（legacy 键原样；CS-AUTH-03 对齐）。
        let key = match key.strip_prefix("X-CSTP-") {
            Some(rest) => format!("CSTP_{}", rest.replace('-', "_")),
            None => key.to_string(),
        };
        match key.to_ascii_uppercase().as_str() {
            "CSTP_MTU" => {
                let v: u16 = value.parse().ok()?;
                if !(68..=u16::MAX).contains(&v) {
                    return None;
                }
                mtu = Some(v);
            }
            "CSTP_ADDRESS" => {
                address = Some(value.parse::<Ipv4Addr>().ok()?);
            }
            "CSTP_NETMASK" => {
                netmask = Some(value.parse::<Ipv4Addr>().ok()?);
            }
            "CSTP_DNS" => {
                for token in value.split_whitespace() {
                    dns_servers.push(token.parse::<Ipv4Addr>().ok()?);
                }
            }
            "CSTP_SPLIT_INCLUDE" => {
                for token in value.split_whitespace() {
                    let (net, prefix) = token.split_once('/')?;
                    net.parse::<Ipv4Addr>().ok()?;
                    let prefix: u8 = prefix.parse().ok()?;
                    if prefix > 32 {
                        return None;
                    }
                    routes.push(token.to_string());
                }
            }
            _ => {
                // Unknown keys (`CSTP_*` / `X-CSTP-*` extra fields of real
                // gateways) are ignored — still CSTP-only; non-CSTP content
                // fails the required-field checks below.
                continue;
            }
        }
    }
    // Any `dtls` appearance rejects the offer (plan §3.3: the MVP is
    // TLS/CSTP only).
    if head.to_ascii_lowercase().contains("dtls") {
        return None;
    }
    let prefix = netmask_to_prefix(netmask?)?;
    Some(TunnelOffer {
        ipv4_address: address?,
        prefix,
        mtu: mtu?,
        dns_servers,
        routes,
    })
}

/// A contiguous IPv4 netmask -> prefix length (a non-contiguous mask is
/// rejected; school `netmask_to_prefix` pattern).
fn netmask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let mut prefix = 0u8;
    let mut seen_zero = false;
    for octet in mask.octets() {
        for bit in (0..8).rev() {
            if octet & (1 << bit) != 0 {
                if seen_zero {
                    return None;
                }
                prefix += 1;
            } else {
                seen_zero = true;
            }
        }
    }
    Some(prefix)
}

/// The byte offset just past the `\r\n\r\n` header terminator, if present.
fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
}

/// The lowercase hex SHA-256 digest of `bytes` (school `sha256_hex` pattern).
fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Map one codec decode outcome to a control-plane event (or `None` for data /
/// non-control outcomes).
///
/// DPD responses surface through the codec's `UnknownControl(0x04)` error path (the
/// codec only decodes keepalive control frames); this maps that error to the RTT
/// probe signal without killing the read task. Other unknown control kinds yield
/// `None` (they are skipped by the caller, never fatal).
fn control_event_for_decode(
    outcome: &Result<Option<CstpFrame>, CodecError>,
) -> Option<CstpControlEvent> {
    match outcome {
        Ok(Some(CstpFrame::Control { kind, body })) => Some(CstpControlEvent::Control {
            kind: *kind,
            body: body.clone(),
        }),
        Err(CodecError::UnknownControl(kind)) if *kind == CSTP_PACKET_TYPE_DPD_RESPONSE => {
            Some(CstpControlEvent::DpdResponse)
        }
        _ => None,
    }
}

/// Split the stream into the two data tasks: the TLS read half is decoded by
/// the frozen P40 `Codec` and `CstpFrame::Data` payloads are delivered on
/// `read_tx`; frames on `write_rx` are written to the TLS write half raw (engine
/// version of the school `spawn_school_data_tasks` pattern). `offer_remainder`
/// holds bytes that arrived after the offer terminator and belongs to the binary
/// frame stream.
///
/// T1 control-plane surface: decoded control frames (keepalive) and the DPD-response
/// probe signal are forwarded on `control_tx` (best-effort — a dropped consumer is
/// non-fatal). An unknown control frame is SKIPPED rather than fatal: the read task
/// must survive a gateway control frame the codec cannot decode (in particular a
/// DPD response, which the codec reports as `UnknownControl(0x04)`).
fn spawn_data_tasks(
    read_half: tokio::io::ReadHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    write_half: tokio::io::WriteHalf<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
    read_tx: mpsc::UnboundedSender<Vec<u8>>,
    write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    offer_remainder: Vec<u8>,
    control_tx: mpsc::UnboundedSender<CstpControlEvent>,
) {
    tokio::spawn(async move {
        let mut codec = Codec::new();
        codec.feed(&offer_remainder);
        let mut read_half = read_half;
        let mut chunk = [0u8; 4096];
        loop {
            match read_half.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    codec.feed(&chunk[..n]);
                    loop {
                        match codec.decode() {
                            Ok(Some(CstpFrame::Data(payload))) => {
                                if read_tx.send(payload).is_err() {
                                    return;
                                }
                            }
                            outcome => {
                                // Surface control-plane events (keepalive + DPD
                                // response) to the latency probe; a dropped consumer
                                // is non-fatal.
                                if let Some(event) = control_event_for_decode(&outcome) {
                                    let _ = control_tx.send(event);
                                }
                                match outcome {
                                    Ok(None) => break,                    // need more bytes
                                    Err(CodecError::UnknownControl(_)) => {} // skip, keep reading
                                    Err(_) => return,                     // genuine stream error
                                    _ => {} // Ok(Some(Control)) already surfaced
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        let mut write_half = write_half;
        let mut write_rx = write_rx;
        while let Some(frame) = write_rx.recv().await {
            if write_half.write_all(&frame).await.is_err() {
                break;
            }
        }
    });
}

// ---------------------------------------------------------------------------
// 单元测试：T1 控制面事件映射（DPD response 探测信号 + keepalive 转发 + 未知
// 控制帧存活）。`control_event_for_decode` 是纯函数，直接断言解码结果→事件。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// DPD wire 判别常量：request=0x03 / response=0x04（AnyConnect 标准）。
    #[test]
    fn dpd_wire_discriminants() {
        assert_eq!(CSTP_PACKET_TYPE_DPD_REQUEST, 0x03);
        assert_eq!(CSTP_PACKET_TYPE_DPD_RESPONSE, 0x04);
    }

    /// keepalive 控制帧（codec 可解码）→ `Control` 事件，携带 wire kind + body。
    #[test]
    fn decoded_control_frame_surfaces_as_control_event() {
        let outcome = Ok(Some(CstpFrame::Control {
            kind: 0x07,
            body: vec![1, 2, 3],
        }));
        assert_eq!(
            control_event_for_decode(&outcome),
            Some(CstpControlEvent::Control {
                kind: 0x07,
                body: vec![1, 2, 3],
            })
        );
    }

    /// DPD response（0x04）以 `UnknownControl` 错误路径出现 → 映射为 `DpdResponse`
    /// 探测信号（读任务据此算 RTT，且不死亡）。
    #[test]
    fn dpd_response_maps_from_unknown_control_error() {
        let outcome = Err(CodecError::UnknownControl(CSTP_PACKET_TYPE_DPD_RESPONSE));
        assert_eq!(
            control_event_for_decode(&outcome),
            Some(CstpControlEvent::DpdResponse)
        );
    }

    /// 其它未知控制帧（非 DPD response）→ `None`（调用方跳过，不致命）。
    #[test]
    fn other_unknown_control_yields_none() {
        let outcome = Err(CodecError::UnknownControl(0x09));
        assert_eq!(control_event_for_decode(&outcome), None);
    }

    /// Data 帧 / 半帧（`Ok(None)`）/ 其它错误 → `None`（数据面不被控制事件污染）。
    #[test]
    fn data_and_stream_outcomes_yield_none() {
        assert_eq!(control_event_for_decode(&Ok(Some(CstpFrame::Data(vec![0x45])))), None);
        assert_eq!(control_event_for_decode(&Ok(None)), None);
        assert_eq!(control_event_for_decode(&Err(CodecError::Truncated)), None);
        assert_eq!(control_event_for_decode(&Err(CodecError::BadMagic)), None);
    }

    /// `CstpControlEvent` 可 Debug/Clone/Eq（事件随 channel 传递所需）。
    #[test]
    fn control_event_implements_debug_clone_eq() {
        let a = CstpControlEvent::DpdResponse;
        let b = a.clone();
        assert_eq!(a, b);
        let _ = format!("{a:?}");
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
