// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! PAC 一次性开环包装（设计文档
//! `docs/superpowers/plans/2026-08-24-system-proxy-awareness-design.md` §5.6、
//! §7 结论 3）。
//!
//! 三块能力，全部自包含在本模块：
//!
//! 1. [`wrap_pac_script`]：纯文本包装原 PAC 脚本——校验原文恰有一处
//!    `function FindProxyForURL` 声明，把标识符统一改名为
//!    [`ORIGINAL_FN_ALIAS`]，文末追加同名包装函数（先行豁免判定返回
//!    `DIRECT`；否则在 `try` 块内委托原名，`catch` 回退 `DIRECT`）。
//! 2. [`PacEndpoint`]：`127.0.0.1` 动态端口微型 HTTP 端点，一次性伺服包装
//!    文本；生命周期绑定持有者，`Drop` 即关。
//! 3. [`fetch_pac_script`]：连接瞬间从 `AutoConfigURL` 一次性 GET 原文。
//!
//! **开环语义**：只对连接瞬间的观测结果负责，注入后不跟踪后续变化。
//! **零扰动红线**：所有失败路径（下载失败 / 包装失败 / 端点故障）的终态都是
//! 「回退直连或回到用户原 PAC 行为」，绝不出现黑洞式断网；校验失败是类型化
//! 错误，调用方 fail-closed 回退为「仅提示」，注册表零写入。
//!
//! HTTP 实现选型：std [`std::net`] 手写最小 HTTP/1.0（GET 一个路径足够），
//! 不引入 tokio/HTTP 库，保持本 crate 依赖面不变。

use crate::native_error::{NativeError, NativeErrorKind};

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// 一次性 GET 的整体超时（连接 + 读响应）。
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// 伺服路径（写入 `AutoConfigURL` 时也用它拼 URL）。
pub const PAC_SERVE_PATH: &str = "/proxy.pac";

/// 端点 accept 循环的单次阻塞窗口：窗口内无连接则检查关闭标志后重试。
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// 原声明识别文本（大小写敏感，按 PAC 惯例）。
const DECLARATION_TEXT: &str = "function FindProxyForURL";

/// 原 `FindProxyForURL` 在包装后被统一改名的别名。
///
/// 声明处与潜在内部引用都会被改名到这个别名；我们追加的包装函数以原名
/// `FindProxyForURL` 对外，并在委托分支调用本别名。
pub const ORIGINAL_FN_ALIAS: &str = "__exv_original_FindProxyForURL";

/// 单份脚本的防御性体积上限（真实 PAC 通常几 KB）。
pub(crate) const MAX_SCRIPT_BYTES: usize = 8 * 1024 * 1024;

/// 包装函数前后的注释标记（测试与排障定位用）。
const WRAP_BEGIN_MARK: &str = "// ==== EXV PAC wrap begin (one-shot open-loop wrapper) ====";
const WRAP_END_MARK: &str = "// ==== EXV PAC wrap end ====";

/// 构造「脚本不可包装」类型化错误（协议类；调用方 fail-closed 回退仅提示）。
fn err_unwrappable(reason: &str) -> NativeError {
    NativeError {
        kind: NativeErrorKind::Protocol,
        code: 0,
        message: format!("pac_script_unwrappable: {reason}"),
    }
}

/// 构造「下载不支持/失败」类型化错误。
fn err_fetch(kind: NativeErrorKind, code: u32, reason: String) -> NativeError {
    NativeError {
        kind,
        code,
        message: reason,
    }
}

/// 纯函数：原脚本 + 豁免条目 → 包装脚本。
///
/// 校验原文恰有一处 `function FindProxyForURL` 声明（大小写敏感）；把该
/// 标识符的所有出现（声明处与潜在内部引用）替换为 [`ORIGINAL_FN_ALIAS`]；
/// 文末追加同名包装函数：
///
/// a) 先行豁免判定（try 块之外）：host 精确匹配豁免条目，或匹配 `a.b.c.*`
///    通配尾段（条目以 `.*` 结尾即视为尾段通配），返回 `"DIRECT"`；
/// b) `try` 块内委托原函数；`catch` 回退 `"DIRECT"`（降级保险：原逻辑运行时
///    异常回退直连不断网）。
///
/// 最后做括号平衡 sanity 自检，不平衡视为不可包装（fail-closed）。
///
/// # Errors
///
/// 原文为空、已带包装别名、声明缺失或多处、装配后括号不平衡时，返回
/// `kind = Protocol`、message 以 `pac_script_unwrappable:` 开头的类型化错误。
#[must_use]
pub fn wrap_pac_script(original: &str, exempt: &[String]) -> Result<String, NativeError> {
    if original.trim().is_empty() {
        return Err(err_unwrappable("empty script"));
    }
    // 防御性拒绝二次包装：别名已在原文中出现说明这是我们的产物或伪造物。
    if original.contains(ORIGINAL_FN_ALIAS) {
        return Err(err_unwrappable(
            "script already carries the EXV wrapper alias",
        ));
    }
    match original.matches(DECLARATION_TEXT).count() {
        1 => {}
        0 => {
            return Err(err_unwrappable(
                "no `function FindProxyForURL` declaration found",
            ))
        }
        n => {
            return Err(err_unwrappable(&format!(
                "{n} `function FindProxyForURL` declarations found, exactly 1 required"
            )))
        }
    }

    // 标识符级整体改名：声明处与潜在内部引用一并落到别名上。
    let renamed = original.replace("FindProxyForURL", ORIGINAL_FN_ALIAS);

    let mut out = String::with_capacity(renamed.len() + 1024);
    out.push_str(&renamed);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out.push_str(WRAP_BEGIN_MARK);
    out.push('\n');
    out.push_str(&build_wrapper_source(exempt));
    out.push_str(WRAP_END_MARK);
    out.push('\n');

    // 合法 PAC 语法的最低限度 sanity：三类括号全程平衡。
    if !brackets_balanced(&out) {
        return Err(err_unwrappable("bracket imbalance in assembled script"));
    }
    Ok(out)
}

/// 生成追加到文末的包装函数源码（豁免判定 → try 委托 → catch DIRECT）。
fn build_wrapper_source(exempt: &[String]) -> String {
    let mut w = String::new();
    w.push_str("function __exv_is_exempt(host) {\n");
    w.push_str("  var h = String(host || \"\").toLowerCase();\n");
    w.push_str(&emit_exempt_conditions(exempt));
    w.push_str("  return false;\n");
    w.push_str("}\n");
    w.push_str("function FindProxyForURL(url, host) {\n");
    w.push_str("  if (__exv_is_exempt(host)) { return \"DIRECT\"; }\n");
    w.push_str("  try {\n");
    w.push_str(&format!("    return {ORIGINAL_FN_ALIAS}(url, host);\n"));
    w.push_str("  } catch (e) {\n");
    w.push_str("    return \"DIRECT\";\n");
    w.push_str("  }\n");
    w.push_str("}\n");
    w
}

/// 把豁免条目逐条翻译成 JS 判定语句。
///
/// - 精确条目：大小写不敏感全等比较（host 在 JS 侧已统一小写）；
/// - 尾段通配条目（以 `.*` 结尾，如 `a.b.c.*`）：前缀比较且要求尾段非空；
/// - 空条目与裸 `*` 直接忽略（裸 `*` 等于放行全部流量，绝不生成）。
///
/// 未识别形态一律降级为字面精确匹配，宁可漏豁免也不放宽匹配。
fn emit_exempt_conditions(exempt: &[String]) -> String {
    let mut out = String::new();
    for entry in exempt {
        let trimmed = entry.trim();
        if trimmed.is_empty() || trimmed == "*" {
            continue;
        }
        let lowered = trimmed.to_ascii_lowercase();
        if let Some(base) = lowered.strip_suffix(".*") {
            let mut prefix = base.to_string();
            if !prefix.ends_with('.') {
                prefix.push('.');
            }
            // lastIndexOf(x, 0) === 0 是老式 PAC 引擎可用的 startsWith 写法。
            let cond = format!(
                "  if (h.lastIndexOf({}, 0) === 0 && h.length > {}) {{ return true; }}\n",
                js_quote(&prefix),
                prefix.chars().count()
            );
            out.push_str(&cond);
        } else {
            let cond = format!(
                "  if (h === {}) {{ return true; }}\n",
                js_quote(&lowered)
            );
            out.push_str(&cond);
        }
    }
    out
}

/// 最小 JS 字符串字面量转义（反斜杠、双引号与控制字符）。
fn js_quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// 简单括号平衡 sanity 断言：`() {} []` 三类括号线性扫描全程不出现负深度，
/// 且结束时深度归零。
fn brackets_balanced(text: &str) -> bool {
    let (mut paren, mut brace, mut brack) = (0i64, 0i64, 0i64);
    for ch in text.chars() {
        match ch {
            '(' => paren += 1,
            ')' => {
                paren -= 1;
                if paren < 0 {
                    return false;
                }
            }
            '{' => brace += 1,
            '}' => {
                brace -= 1;
                if brace < 0 {
                    return false;
                }
            }
            '[' => brack += 1,
            ']' => {
                brack -= 1;
                if brack < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    paren == 0 && brace == 0 && brack == 0
}

/// Loopback 微型 PAC HTTP 端点（一次性语义）。
///
/// - [`PacEndpoint::spawn`] 在 `127.0.0.1:0` 动态端口监听，后台线程 accept；
///   对任何 GET 一律返回 `200 OK` + `application/x-ns-proxy-autoconfig` +
///   固定脚本正文。
/// - 生命周期绑定持有者：[`Drop for PacEndpoint`] 关闭 listener 使 accept
///   线程在下一个轮询窗口内退出，随后 `join` 回收；不提供更新脚本的接口
///   （一次性语义，需要新脚本就起新端点）。
/// - 非常驻组件：设计 §5.6 的安装顺序纪律（端点先可服务 → 再改注册表 →
///   再广播）与拆除 grace 由调用方（engine 接线层）负责，本类型只保证
///   「Drop 即关」。
#[derive(Debug)]
pub struct PacEndpoint {
    port: u16,
    /// 关闭标志 + accept 线程句柄；线程侧持有 listener 的 Arc 引用。
    worker: Arc<PacWorker>,
}

/// 端点后台线程的共享状态。
struct PacWorker {
    shutdown: AtomicBool,
    handle: Mutex<Option<thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for PacWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacWorker")
            .field("shutdown", &self.shutdown.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl PacEndpoint {
    /// 在 `127.0.0.1:0` 起端点伺服 `script`。
    ///
    /// # Errors
    ///
    /// loopback 监听失败（端口资源/防火墙策略等）时原样返回 `io::Error`。
    pub fn spawn(script: Arc<String>) -> Result<Self, io::Error> {
        let listener = Arc::new(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?);
        let port = listener.local_addr()?.port();
        let worker = Arc::new(PacWorker {
            shutdown: AtomicBool::new(false),
            handle: Mutex::new(None),
        });
        let worker_for_thread = Arc::clone(&worker);
        let listener_for_thread = Arc::clone(&listener);
        let handle = thread::Builder::new()
            .name("exv-pac-endpoint".to_string())
            .spawn(move || {
                serve_until_closed(&listener_for_thread, script.as_str(), &worker_for_thread);
            })?;
        *worker
            .handle
            .lock()
            .map_err(|poisoned| io::Error::other(poisoned.to_string()))? = Some(handle);
        Ok(Self { port, worker })
    }

    /// 已绑定的动态端口（用于拼 `http://127.0.0.1:<port>/proxy.pac`）。
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// 本端点的完整伺服 URL。
    #[must_use]
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}{PAC_SERVE_PATH}", self.port)
    }
}

impl Drop for PacEndpoint {
    fn drop(&mut self) {
        // 1) 置位关闭标志：accept 循环在下个轮询窗口（<= ACCEPT_POLL_INTERVAL）
        //    退出。Windows 上跨线程解除阻塞 accept 不可靠，轮询窗口是兜底；
        //    join 至多等一个窗口。
        self.worker.shutdown.store(true, Ordering::SeqCst);
        // 2) join 回收线程。
        if let Ok(mut slot) = self.worker.handle.lock() {
            if let Some(handle) = slot.take() {
                let _ = handle.join();
            }
        }
    }
}

/// accept 循环主体：短窗口 `set_nonblocking` 轮询关闭标志；对任何 GET 一律
/// 返回固定脚本正文（一次性语义，无路由、无状态）。
fn serve_until_closed(listener: &TcpListener, script: &str, worker: &PacWorker) {
    loop {
        if worker.shutdown.load(Ordering::SeqCst) {
            return;
        }
        // 短窗口：先非阻塞探测，无连接则睡半个轮询间隔再查标志。
        let _ = listener.set_nonblocking(true);
        match listener.accept() {
            Ok((stream, _addr)) => {
                let _ = listener.set_nonblocking(false);
                serve_one(&stream, script);
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                let _ = listener.set_nonblocking(false);
                thread::sleep(ACCEPT_POLL_INTERVAL / 2);
            }
            Err(_) => {
                // 瞬态错误：休眠后重试，直到 shutdown。
                let _ = listener.set_nonblocking(false);
                if worker.shutdown.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
        }
    }
}

/// 处理单条连接：读请求直到空行或读尽（不解析），写最小 HTTP/1.0 响应后关。
///
/// 响应头按规格固定：`HTTP/1.0 200 OK` + `Content-Type:
/// application/x-ns-proxy-autoconfig` + `Content-Length: N` + 连接关闭。
fn serve_one(mut stream: &TcpStream, script: &str) {
    let mut request = [0u8; 1024];
    // 读一次请求头即可（浏览器 GET 很小）；对端未发就绪时靠 read 超时兜底。
    let _ = stream.read(&mut request);

    let body = script.as_bytes();
    let response = format!(
        "HTTP/1.0 200 OK\r\n\
         Content-Type: application/x-ns-proxy-autoconfig\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let mut out = response.into_bytes();
    out.extend_from_slice(body);
    let _ = stream.write_all(&out);
    let _ = stream.flush();
}

/// 从 PAC URL 一次性 GET 脚本原文（设计 §5.6「下载」）。
///
/// 仅支持 `http://127.0.0.1[:port]/…` 类 loopback 明文地址——大多数代理软件
/// 的 PAC 就是本地 http 地址；`https://` 直接报类型化错误
/// [`fetch_https_unsupported`]（v1 限制）。响应非 200、超时（5 秒）、连接
/// 失败同样报类型化错误；调用方 fail-closed 回退为「仅提示」，注册表零写入。
///
/// # Errors
///
/// - URL 非 http 或 host 非 `127.0.0.1`：`Unsupported` /
///   `pac_fetch_unsupported_url`
/// - https：`Unsupported` / `pac_fetch_https_unsupported`
/// - 连接失败 / 超时：`Transport` / `pac_fetch_connect_failed`
/// - 非 200：`Protocol` / `pac_fetch_http_status_<code>`
/// - body 非合法 UTF-8：`Protocol` / `pac_fetch_invalid_utf8`
pub fn fetch_pac_script(url: &str) -> Result<String, NativeError> {
    let addr = parse_loopback_http_url(url)?;

    let stream = TcpStream::connect_timeout(&addr, FETCH_TIMEOUT).map_err(|e| err_fetch(
        NativeErrorKind::Transport,
        e.raw_os_error().map_or(0, |c| u32::try_from(c).unwrap_or(0)),
        format!("pac_fetch_connect_failed: {url}: {e}"),
    ))?;
    stream
        .set_read_timeout(Some(FETCH_TIMEOUT))
        .map_err(|e| err_fetch(NativeErrorKind::Transport, 0, format!("pac_fetch_connect_failed: {url}: set_read_timeout: {e}")))?;
    stream
        .set_write_timeout(Some(FETCH_TIMEOUT))
        .map_err(|e| err_fetch(NativeErrorKind::Transport, 0, format!("pac_fetch_connect_failed: {url}: set_write_timeout: {e}")))?;

    fetch_via_stream(stream, url)
}

/// 在已建立的连接上执行「GET → 解析状态行与头 → 读 body」。独立成函数供
/// 单测注入内存流场景（真实路径走 [`fetch_pac_script`]）。
fn fetch_via_stream<S: Read + Write>(mut stream: S, url: &str) -> Result<String, NativeError> {
    let request = format!("GET {PAC_SERVE_PATH} HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(|e| {
        err_fetch(
            NativeErrorKind::Transport,
            e.raw_os_error().map_or(0, |c| u32::try_from(c).unwrap_or(0)),
            format!("pac_fetch_request_write_failed: {url}: {e}"),
        )
    })?;

    let mut raw = Vec::new();
    let deadline = Instant::now() + FETCH_TIMEOUT;
    loop {
        let mut chunk = [0u8; 4096];
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(err_fetch(
                NativeErrorKind::Transport,
                0,
                format!("pac_fetch_timeout: {url}"),
            ));
        }
        // 每次读都压在总预算内；流式响应到 EOF 即结束。
        set_read_deadline_hint(&mut stream, remaining);
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                ) =>
            {
                return Err(err_fetch(
                    NativeErrorKind::Transport,
                    0,
                    format!("pac_fetch_timeout: {url}"),
                ))
            }
            Err(e) => {
                return Err(err_fetch(
                    NativeErrorKind::Transport,
                    e.raw_os_error().map_or(0, |c| u32::try_from(c).unwrap_or(0)),
                    format!("pac_fetch_read_failed: {url}: {e}"),
                ))
            }
        }
        if raw.len() > MAX_SCRIPT_BYTES {
            return Err(err_fetch(
                NativeErrorKind::Protocol,
                0,
                format!("pac_fetch_too_large: {url}"),
            ));
        }
    }

    parse_http_response(&raw, url)
}

/// 把剩余时间预算落到流的读超时上（`S: Read + Write` 泛型路径下的近似：
/// 只有真 `TcpStream` 才生效，测试桩忽略）。
fn set_read_deadline_hint<S: Read>(_stream: &mut S, _remaining: Duration) {
    // TcpStream 特化需要 downcast；这里保持简单——外层 fetch_pac_script 已在
    // connect 后统一设置过 5 秒读超时，本函数仅为泛型测试桩占位。
}

/// 解析 HTTP/1.x 响应：状态行必须 200，头里找 Content-Length（缺失则读到
/// EOF 的全部字节即 body），返回 UTF-8 body。
fn parse_http_response(raw: &[u8], url: &str) -> Result<String, NativeError> {
    let split_at = find_header_end(raw).ok_or_else(|| {
        err_fetch(
            NativeErrorKind::Protocol,
            0,
            format!("pac_fetch_malformed_response: {url}"),
        )
    })?;
    let head = String::from_utf8_lossy(&raw[..split_at]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.split(' ');
    let version_ok = parts.next().is_some_and(|v| v.starts_with("HTTP/"));
    let code = parts.next().and_then(|c| c.parse::<u32>().ok());
    match (version_ok, code) {
        (true, Some(200)) => {}
        (true, Some(other)) => {
            return Err(err_fetch(
                NativeErrorKind::Protocol,
                other.min(u32::from(u16::MAX)),
                format!("pac_fetch_http_status_{other}: {url}"),
            ))
        }
        _ => {
            return Err(err_fetch(
                NativeErrorKind::Protocol,
                0,
                format!("pac_fetch_malformed_response: {url}: {status_line:?}"),
            ))
        }
    }

    let body_bytes = &raw[split_at + 4..];
    String::from_utf8(body_bytes.to_vec()).map_err(|_| {
        err_fetch(
            NativeErrorKind::Protocol,
            0,
            format!("pac_fetch_invalid_utf8: {url}"),
        )
    })
}

/// 定位 `\r\n\r\n`（头结束处），返回头部结束行首索引。
fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n")
}

/// 解析 `http://127.0.0.1[:port]/…` 形式的 loopback URL 为 SocketAddr。
fn parse_loopback_http_url(url: &str) -> Result<SocketAddr, NativeError> {
    const HTTPS_HINT: &str =
        "https PAC URL unsupported in v1 (most proxy PACs are local http://127.0.0.1)";
    let rest = url.strip_prefix("https://").map_or_else(
        || url.strip_prefix("http://").ok_or_else(|| {
            err_fetch(
                NativeErrorKind::Unsupported,
                0,
                format!("pac_fetch_unsupported_url: {url}"),
            )
        }),
        |_https| {
            Err(err_fetch(
                NativeErrorKind::Unsupported,
                0,
                format!("pac_fetch_https_unsupported: {HTTPS_HINT}: {url}"),
            ))
        },
    )?;
    let authority_path = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = split_host_port(authority_path)?;
    if host != "127.0.0.1" {
        return Err(err_fetch(
            NativeErrorKind::Unsupported,
            0,
            format!("pac_fetch_unsupported_url: only 127.0.0.1 hosts allowed, got {host}"),
        ));
    }
    Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}

/// 拆 `host:port`；缺省端口为 80（PAC AutoConfigURL 常省略）。
fn split_host_port(authority: &str) -> Result<(String, u16), NativeError> {
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let parsed = port.parse::<u16>().map_err(|_| {
                err_fetch(
                    NativeErrorKind::Unsupported,
                    0,
                    format!("pac_fetch_unsupported_url: bad port {port:?}"),
                )
            })?;
            Ok((host.to_ascii_lowercase(), parsed))
        }
        None => Ok((authority.to_ascii_lowercase(), 80)),
    }
}



#[cfg(test)]
mod system_proxy_pac_tests {
    use super::{ORIGINAL_FN_ALIAS, WRAP_BEGIN_MARK, brackets_balanced, wrap_pac_script};

    /// 标准最小原脚本。
    fn sample_original() -> String {
        "function FindProxyForURL(url, host) {\n  return \"PROXY 127.0.0.1:7890\";\n}\n"
            .to_string()
    }

    #[test]
    fn wraps_single_declaration_into_delegate_form() {
        let exempt: Vec<String> = Vec::new();
        let wrapped = wrap_pac_script(&sample_original(), &exempt).expect("wrap must succeed");

        // 原声明被改名到别名，包装函数以原名对外。
        assert!(wrapped.contains(&format!("function {ORIGINAL_FN_ALIAS}(url, host)")));
        assert_eq!(wrapped.matches("function FindProxyForURL").count(), 1);
        assert!(wrapped.contains(WRAP_BEGIN_MARK));

        // 豁免守卫在 try 之前；委托分支与 catch 降级都在。
        assert!(wrapped.contains("if (__exv_is_exempt(host)) { return \"DIRECT\"; }"));
        assert!(wrapped.contains(&format!("    return {ORIGINAL_FN_ALIAS}(url, host);")));
        assert!(wrapped.contains("} catch (e) {"));
        assert!(wrapped.contains("return \"DIRECT\";"));
    }

    #[test]
    fn rejects_zero_declarations() {
        let script = "function SomethingElse(url) { return \"DIRECT\"; }\n";
        let err = wrap_pac_script(script, &[]).expect_err("zero declarations must fail");
        assert_eq!(err.kind(), crate::native_error::NativeErrorKind::Protocol);
        assert!(err.message.contains("pac_script_unwrappable"), "{}", err.message);
    }

    #[test]
    fn rejects_multiple_declarations() {
        let mut script = sample_original();
        script.push_str(&sample_original());
        let err = wrap_pac_script(&script, &[]).expect_err("two declarations must fail");
        assert!(err.message.contains("pac_script_unwrappable"), "{}", err.message);
        assert!(err.message.contains("declarations found"), "{}", err.message);
    }

    #[test]
    fn rejects_empty_script() {
        let err = wrap_pac_script("", &[]).expect_err("empty script must fail");
        assert!(err.message.contains("pac_script_unwrappable"));
        let ws = wrap_pac_script("   \n\t", &[]).expect_err("whitespace-only must fail");
        assert!(ws.message.contains("pac_script_unwrappable"));
    }

    #[test]
    fn declaration_matching_is_case_sensitive() {
        // 大小写不符的写法不算声明：宁可放弃包装（fail-closed）也不猜。
        for variant in [
            "Function FindProxyForURL(url, host) { return \"DIRECT\"; }\n",
            "function findproxyforurl(url, host) { return \"DIRECT\"; }\n",
            "FUNCTION FINDPROXYFORURL(url, host) { return \"DIRECT\"; }\n",
        ] {
            let err = wrap_pac_script(variant, &[]).expect_err("case variants must not count");
            assert!(
                err.message.contains("no `function FindProxyForURL`"),
                "{}",
                err.message
            );
        }
    }

    #[test]
    fn renames_every_identifier_occurrence_including_internal_refs() {
        let script = concat!(
            "function FindProxyForURL(url, host) {\n",
            "  var again = FindProxyForURL;\n",
            "  return \"PROXY 127.0.0.1:7890\";\n",
            "}\n",
        );
        let wrapped = wrap_pac_script(script, &[]).expect("wrap must succeed");

        // 原文两处标识符（声明 + 内部引用）都改为别名；加上包装函数的委托
        // 调用，别名共出现 3 次；除包装函数声明外不再有裸的 FindProxyForURL。
        assert_eq!(wrapped.matches(ORIGINAL_FN_ALIAS).count(), 3);
        let stripped = wrapped.replace(ORIGINAL_FN_ALIAS, "");
        assert_eq!(stripped.matches("FindProxyForURL").count(), 1);
    }

    #[test]
    fn preserves_original_body_before_wrapper_mark() {
        let wrapped = wrap_pac_script(&sample_original(), &[]).expect("wrap must succeed");
        let idx = wrapped.find(WRAP_BEGIN_MARK).expect("begin mark present");
        let head = &wrapped[..idx];
        assert!(head.contains("function __exv_original_FindProxyForURL(url, host)"));
        assert!(head.contains("\"PROXY 127.0.0.1:7890\""));
        // 包装内容只追加在原文之后：head 恰为「原文做别名替换」的结果。
        let expected_renamed =
            sample_original().replace("FindProxyForURL", ORIGINAL_FN_ALIAS);
        assert!(head.starts_with(expected_renamed.trim_end_matches('\n')));
    }

    #[test]
    fn rejects_already_wrapped_script() {
        let script = format!(
            "function {ORIGINAL_FN_ALIAS}(url, host) {{ return \"DIRECT\"; }}\n\
             function FindProxyForURL(url, host) {{ return {ORIGINAL_FN_ALIAS}(url, host); }}\n"
        );
        let err = wrap_pac_script(&script, &[]).expect_err("double wrap must fail");
        assert!(err.message.contains("already carries the EXV wrapper alias"));
    }

    #[test]
    fn rejects_bracket_imbalance_in_original() {
        let script = "function FindProxyForURL(url, host {\n  return \"DIRECT\";\n}\n";
        let err = wrap_pac_script(script, &[]).expect_err("unbalanced parens must fail");
        assert!(err.message.contains("bracket imbalance"), "{}", err.message);
    }

    #[test]
    fn assembled_output_passes_balance_check_on_success() {
        let wrapped = wrap_pac_script(&sample_original(), &[]).expect("wrap must succeed");
        assert!(brackets_balanced(&wrapped));
    }

    #[test]
    fn emits_exact_and_wildcard_exempt_conditions() {
        let exempt = vec![
            "Intranet.Example.Edu".to_string(),
            "10.1.2.*".to_string(),
        ];
        let wrapped = wrap_pac_script(&sample_original(), &exempt).expect("wrap must succeed");

        // 精确条目：统一小写后全等比较。
        assert!(wrapped.contains("if (h === \"intranet.example.edu\") { return true; }"));
        // 尾段通配：前缀 "10.1.2."（长度 7）+ 尾段非空。
        assert!(wrapped.contains(
            "if (h.lastIndexOf(\"10.1.2.\", 0) === 0 && h.length > 7) { return true; }"
        ));
    }

    #[test]
    fn skips_dangerous_or_blank_exempt_entries() {
        let exempt = vec![
            String::new(),
            "   ".to_string(),
            "*".to_string(),
        ];
        let wrapped = wrap_pac_script(&sample_original(), &exempt).expect("wrap must succeed");
        // 裸 `*` 与空条目不得产生任何放行条件；is_exempt 恒 false 但结构完整。
        assert!(!wrapped.contains("lastIndexOf"));
        assert!(wrapped.contains("return false;"));
        assert!(wrapped.contains(&format!("return {ORIGINAL_FN_ALIAS}(url, host);")));
    }

    #[test]
    fn non_dot_star_trailing_asterisk_degrades_to_literal_match() {
        // 非 `.*` 规范形态（如 `10.1.2*`）：降级为字面精确匹配，绝不放宽。
        let exempt = vec!["10.1.2*".to_string()];
        let wrapped = wrap_pac_script(&sample_original(), &exempt).expect("wrap must succeed");
        assert!(wrapped.contains("if (h === \"10.1.2*\") { return true; }"));
        assert!(!wrapped.contains("lastIndexOf"));
    }

    #[test]
    fn js_quote_escapes_specials() {
        assert_eq!(super::js_quote("plain"), "\"plain\"");
        assert_eq!(super::js_quote("a\"b\\c\nd"), "\"a\\\"b\\\\c\\nd\"");
    }

    #[test]
    fn balance_scanner_detects_negative_depth_and_leftover() {
        assert!(brackets_balanced(""));
        assert!(brackets_balanced("f(a){return [b,c];}"));
        assert!(!brackets_balanced(")"));          // 先负后归零
        assert!(!brackets_balanced("(("));         // 有剩余
        assert!(!brackets_balanced("{]"));         // 交叉但各自不平衡
        assert!(brackets_balanced("{[(a)]}(x[y])"));
    }

    // ------------------------------------------------------------------
    // PacEndpoint：spawn / port / 伺服 / Drop 即关
    // ------------------------------------------------------------------

    use super::{PAC_SERVE_PATH, PacEndpoint, fetch_pac_script};
    use std::io::{self, Read, Write};
    use std::net::TcpStream;
    use std::thread;
    use std::time::Duration;

    /// 从端点取一次响应原文（连接 + 读尽 + 关闭）。
    fn read_response(endpoint: &PacEndpoint) -> Vec<u8> {
        let mut stream =
            TcpStream::connect(("127.0.0.1", endpoint.port())).expect("connect loopback");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        stream
            .write_all(format!("GET {PAC_SERVE_PATH} HTTP/1.0\r\n\r\n").as_bytes())
            .expect("write request");
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).expect("read response");
        raw
    }

    #[test]
    fn endpoint_spawns_on_dynamic_loopback_port_and_serves_script() {
        let script = std::sync::Arc::new("function FindProxyForURL() {}".to_string());
        let endpoint = PacEndpoint::spawn(std::sync::Arc::clone(&script))
            .expect("endpoint spawn on 127.0.0.1:0");

        assert_ne!(endpoint.port(), 0, "kernel-assigned port");
        assert_eq!(
            endpoint.url(),
            format!("http://127.0.0.1:{}{PAC_SERVE_PATH}", endpoint.port())
        );

        let raw = read_response(&endpoint);
        let text = String::from_utf8(raw.clone()).expect("ascii http");
        assert!(text.starts_with("HTTP/1.0 200 OK\r\n"), "{text}");
        assert!(
            text.contains("Content-Type: application/x-ns-proxy-autoconfig\r\n"),
            "{text}"
        );
        let expected_len = script.as_bytes().len();
        assert!(
            text.contains(&format!("Content-Length: {expected_len}\r\n")),
            "{text}"
        );
        // body 与脚本逐字节一致（头以 \r\n\r\n 结束）。
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("header end");
        assert_eq!(&raw[split + 4..], script.as_bytes());
    }

    #[test]
    fn endpoint_serves_identical_body_to_repeat_requests() {
        let script = std::sync::Arc::new("// pac".to_string());
        let endpoint = PacEndpoint::spawn(std::sync::Arc::clone(&script)).expect("spawn");

        for _ in 0..3 {
            let raw = read_response(&endpoint);
            let text = String::from_utf8(raw).expect("ascii");
            assert!(text.starts_with("HTTP/1.0 200 OK\r\n"));
            assert!(text.ends_with("// pac"));
        }
    }

    #[test]
    fn endpoint_drop_closes_listener_within_poll_window() {
        let endpoint =
            PacEndpoint::spawn(std::sync::Arc::new("// pac".to_string())).expect("spawn");
        let port = endpoint.port();
        drop(endpoint);

        // Drop join 至多等一个轮询窗口；此后端口必须不再可连。
        thread::sleep(Duration::from_millis(ACCEPT_POLL_INTERVAL_MS_TEST));
        let result = TcpStream::connect(("127.0.0.1", port));
        assert!(result.is_err(), "port {port} should be closed after drop");
    }

    /// 测试用轮询间隔常量镜像（避免测试模块直接依赖内部常量命名）。
    const ACCEPT_POLL_INTERVAL_MS_TEST: u64 = 150;

    // ------------------------------------------------------------------
    // fetch_pac_script：https 拒绝 / URL 解析 / 回环自证 / 非 200 / 畸形响应
    // ------------------------------------------------------------------

    use super::{err_fetch, fetch_via_stream, parse_http_response, parse_loopback_http_url};
    use crate::native_error::NativeErrorKind;

    // `fetch_pac_script` 已在上方 use 引入。

    struct StubStream {
        payload: Vec<u8>,
        written: usize,
    }

    impl Read for StubStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let remaining = &self.payload[self.written..];
            let n = remaining.len().min(buf.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.written += n;
            Ok(n)
        }
    }

    impl Write for StubStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn https_url_is_typed_unsupported() {
        let err = fetch_pac_script("https://proxy.example.com/wpad.dat")
            .expect_err("https must be rejected");
        assert_eq!(err.kind(), NativeErrorKind::Unsupported);
        assert!(
            err.message.contains("pac_fetch_https_unsupported"),
            "{}",
            err.message
        );
        assert!(err.message.contains("v1"), "{}", err.message);
    }

    #[test]
    fn non_http_scheme_is_unsupported() {
        for url in ["ftp://127.0.0.1/pac", "file:///C:/pac.js", "127.0.0.1:8080/pac"] {
            let err = fetch_pac_script(url).expect_err(url);
            assert_eq!(err.kind(), NativeErrorKind::Unsupported, "{url}");
            assert!(
                err.message.contains("pac_fetch_unsupported_url"),
                "{}",
                err.message
            );
        }
    }

    #[test]
    fn non_loopback_host_is_unsupported() {
        let err = fetch_pac_script("http://192.168.1.1:8080/wpad.dat")
            .expect_err("non-loopback host must be rejected");
        assert_eq!(err.kind(), NativeErrorKind::Unsupported);
        assert!(err.message.contains("only 127.0.0.1"), "{}", err.message);
    }

    #[test]
    fn url_parser_defaults_port_80_and_accepts_explicit() {
        let addr = parse_loopback_http_url("http://127.0.0.1/proxy.pac").expect("ok");
        assert_eq!(addr.port(), 80);
        let addr = parse_loopback_http_url("http://127.0.0.1:9911/a?b#c").expect("ok");
        assert_eq!(addr.port(), 9911);
        let bad = parse_loopback_http_url("http://127.0.0.1:notaport/x")
            .expect_err("bad port");
        assert!(bad.message.contains("bad port"), "{}", bad.message);
    }

    #[test]
    fn fetch_roundtrips_through_local_endpoint() {
        let original = "function FindProxyForURL(url, host) {\n  return \"DIRECT\";\n}\n";
        let endpoint = PacEndpoint::spawn(std::sync::Arc::new(original.to_string()))
            .expect("spawn endpoint");

        let fetched = fetch_pac_script(&format!(
            "http://127.0.0.1:{}{PAC_SERVE_PATH}",
            endpoint.port()
        ))
        .expect("fetch must succeed");
        assert_eq!(fetched, original, "round-trip must return the exact bytes");
    }

    #[test]
    fn fetch_reports_non_200_status_as_protocol_error() {
        let payload = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec();
        let err = fetch_via_stream(StubStream { payload, written: 0 }, "u")
            .expect_err("404 must fail");
        assert_eq!(err.kind(), NativeErrorKind::Protocol);
        assert!(
            err.message.contains("pac_fetch_http_status_404"),
            "{}",
            err.message
        );
        assert_eq!(err.code, 404);
    }

    #[test]
    fn fetch_reports_malformed_response_and_bad_utf8() {
        let truncated = b"HTTP/1.0 200 OK\r\npartial-header-no-end".to_vec();
        let err = fetch_via_stream(
            StubStream { payload: truncated, written: 0 },
            "u",
        )
        .expect_err("missing header terminator must fail");
        assert!(err.message.contains("pac_fetch_malformed_response"));

        let bad_utf8 = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n\xFF\xFE".to_vec();
        let err = fetch_via_stream(StubStream { payload: bad_utf8, written: 0 }, "u")
            .expect_err("invalid utf-8 body must fail");
        assert!(err.message.contains("pac_fetch_invalid_utf8"));
    }

    #[test]
    fn parse_http_response_returns_body_without_length_header() {
        let payload = b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nfunction f(){}".to_vec();
        let body = parse_http_response(&payload, "u").expect("ok");
        assert_eq!(body, "function f(){}");
        let _unused = err_fetch(NativeErrorKind::Protocol, 0, String::from(""));
        let _unused2 = super::find_header_end(b"\r\n\r\n");
    }
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
