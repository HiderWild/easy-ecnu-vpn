// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! engine 侧 `secret_payload` 凭据解析（P3-b1）。
//!
//! core 侧凭据生命周期（host `credential.rs`，P3-a）把一次性 CSTP 登录凭据打包为
//! serde JSON 的 `CredentialPackage`（`version` 前缀 + `username` + `password`），
//! 经 `ApplyTunnelRequest.secret_payload`（one-shot bytes）交给 engine。本模块在
//! engine 侧解析**同一形状**，供 ApplyTunnel 处理时用于 CSTP auth。
//!
//! 凭据一次性语义（与 core 侧同款强化，对照 host `ClearablePassword`）：
//!
//! - **确定性零化（RAII guard）**：[`EngineCredentials`] 持有解析出的明文
//!   username+password，`Drop` 与显式 [`EngineCredentials::zeroize`] 都覆写已用
//!   字节为 0 后清空；`Debug` 对 password 恒 `<redacted>`。
//! - **wire 副本同样零化**：[`parse_secret_payload`] 解析后立即
//!   `zeroize` 传入的 `secret_payload` 字节切片来源（`Vec<u8>` 就地归零），本地
//!   不再残留明文 carrier。
//! - **不持久化、不记录**：解析出的凭据绝不落盘、不进日志；`Debug` 不泄漏明文。
//!
//! **接线接缝（R1b 已落地）**：`ApplyTunnel` handler
//! （`grpc_server::HelperControlService::apply_tunnel`）解析出
//! [`EngineCredentials`] 后，把一次性凭据连同 operation_id/status 发布器一起放入
//! [`ApplyContext`]（`tunnel_runtime`），由后台组装线程在**登录段**消费并立即
//! `zeroize`（不再经 `pending_credentials` 槽位驻留——R1b 起凭据直接随组装走，
//! 随 ApplyContext Drop 清零；无明文驻留 engine 状态）。本模块只保证凭据以零化
//! 类型抵达登录消费点，用完即清零。

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// `secret_payload` 凭据包格式版本（与 host `CredentialPackage::version` 对齐）。
/// engine 侧解析时校验，未知版本拒绝。
pub const SECRET_PAYLOAD_VERSION: u32 = 1;

/// 解析 `secret_payload` 的 typed 错误。失败路径不携带任何明文字节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretPayloadError {
    /// 凭据包版本不被支持（前向兼容守卫）。
    UnsupportedVersion(u32),
    /// 反序列化失败（形状不符 / 非法 JSON）。
    Decode(String),
}

impl std::fmt::Display for SecretPayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported secret payload version: {v}"),
            Self::Decode(e) => write!(f, "secret payload decode failed: {e}"),
        }
    }
}

impl std::error::Error for SecretPayloadError {}

/// 一次性凭据包（`ApplyTunnelRequest.secret_payload` 的解析结果）。
///
/// serde JSON 形状与 host `credential.rs` 的 `CredentialPackage` 完全一致
/// （`version`/`username`/`password`），保证两端契约稳定。**零化类型**：
/// `Drop` / 显式 [`EngineCredentialPackage::zeroize`] 清零 username+password；
/// `Debug` 对 password 恒 `<redacted>`。
#[derive(Serialize, Deserialize)]
pub struct EngineCredentialPackage {
    /// 格式版本（当前 [`SECRET_PAYLOAD_VERSION`]）。
    pub version: u32,
    /// 登录用户名。
    pub username: String,
    /// 登录密码（明文；一次性，零化后为空）。
    pub password: String,
}

impl EngineCredentialPackage {
    /// 确定性零化包内明文（`Drop` 亦调用）。
    pub fn zeroize(&mut self) {
        zeroize_string(&mut self.username);
        zeroize_string(&mut self.password);
    }
}

impl std::fmt::Debug for EngineCredentialPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineCredentialPackage")
            .field("version", &self.version)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Drop for EngineCredentialPackage {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// 从 `secret_payload` 一次性字节反序列化凭据包（engine 侧解析 host 组装的形状）。
///
/// 返回的包为零化类型：解析出的明文在作用域结束时确定性清零。
///
/// # Errors
/// 版本不被支持 → [`SecretPayloadError::UnsupportedVersion`]；反序列化失败（形状
/// 不符 / 非法 JSON）→ [`SecretPayloadError::Decode`]。
pub fn parse_secret_payload(bytes: &[u8]) -> Result<EngineCredentialPackage, SecretPayloadError> {
    let package: EngineCredentialPackage =
        serde_json::from_slice(bytes).map_err(|e| SecretPayloadError::Decode(e.to_string()))?;
    if package.version != SECRET_PAYLOAD_VERSION {
        return Err(SecretPayloadError::UnsupportedVersion(package.version));
    }
    Ok(package)
}

/// 覆写 String 的已用字节为 0 后清空（与 host `credential.rs::zeroize_string` 同款）。
fn zeroize_string(s: &mut String) {
    // SAFETY: `as_mut_vec` 返回 String 字节的可变视图；本函数持唯一 `&mut`，无其它
    // 引用借用这些字节。
    unsafe {
        s.as_mut_vec().zeroize();
    }
    s.clear();
}

/// ApplyTunnel 处理时传递给后续 CSTP auth 阶段的凭据载体（一次性）。
///
/// 持有解析出的明文 username+password；`Debug` 对 password 恒 `<redacted>`。
/// 刻意不实现 `Clone`——克隆会产生第二个明文副本，破坏一次性语义。
pub struct EngineCredentials {
    /// 登录用户名（一次性；零化后为空）。
    pub username: String,
    /// 登录密码明文（一次性；零化后为空）。
    pub password: String,
}

impl EngineCredentials {
    /// 从解析出的凭据包移入一次性载体（明文从包内 take，包随后 `Drop` 兜底零化空壳）。
    #[must_use]
    pub fn from_package(mut package: EngineCredentialPackage) -> Self {
        Self {
            // `EngineCredentialPackage` 实现 `Drop`，不能按字段 move；用 `std::mem::take`
            // 把明文 String 移出，包内剩余空串由 `Drop` 零化兜底。
            username: std::mem::take(&mut package.username),
            password: std::mem::take(&mut package.password),
        }
    }

    /// 确定性零化明文（`Drop` 亦调用）。
    pub fn zeroize(&mut self) {
        zeroize_string(&mut self.username);
        zeroize_string(&mut self.password);
    }
}

impl std::fmt::Debug for EngineCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineCredentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Drop for EngineCredentials {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ---------------------------------------------------------------------------
// 单元测试：解析→版本守卫→零化（Debug 不泄漏、内存零化断言、不落盘不上线）。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 解析 host 组装的同一形状（`version` 前缀 + username + password）往返正确。
    #[test]
    fn parse_matches_host_assembled_shape() {
        // host `CredentialPackage::new("student", "s3cret").to_bytes()` 的等价字节。
        let bytes = b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}";
        let package = parse_secret_payload(bytes).expect("parse");
        assert_eq!(package.version, SECRET_PAYLOAD_VERSION);
        assert_eq!(package.username, "student");
        assert_eq!(package.password, "s3cret");
        assert!(!format!("{package:?}").contains("s3cret"), "Debug 不得泄漏");
    }

    /// 未知版本必须拒绝（前向兼容守卫，fail closed）。
    #[test]
    fn parse_rejects_unknown_version() {
        let bytes = b"{\"version\":99,\"username\":\"student\",\"password\":\"s3cret\"}";
        assert_eq!(
            parse_secret_payload(bytes).expect_err("must fail"),
            SecretPayloadError::UnsupportedVersion(99)
        );
    }

    /// 非法形状（缺字段 / 非法 JSON）必须拒绝。
    #[test]
    fn parse_rejects_malformed_payload() {
        assert!(parse_secret_payload(b"not json").is_err());
        assert!(parse_secret_payload(b"{\"version\":1}").is_err());
        assert!(parse_secret_payload(b"{\"version\":1,\"username\":\"u\"}").is_err());
    }

    /// 凭据包显式零化必须覆写 password 已用字节为 0（内存级断言）。
    #[test]
    fn package_explicit_zeroize_wipes_password_memory() {
        let mut package = parse_secret_payload(
            b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}",
        )
        .expect("parse");
        let ptr = package.password.as_ptr();
        let len = package.password.len();
        package.zeroize();
        // SAFETY: `ptr` 在 zeroize 前捕获于 package 自身 buffer；zeroize 只归零不清分配，
        // `len` <= capacity，读取 [0..len] 落在有效分配内（package 仍存活）。
        let wiped = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(wiped.iter().all(|&b| b == 0), "包内密码必须已零化");
        assert!(package.password.is_empty());
    }

    /// 一次性载体 move 后零化 + `Debug` 不泄漏明文。
    #[test]
    fn engine_credentials_zeroize_and_debug_redacts() {
        let package = parse_secret_payload(
            b"{\"version\":1,\"username\":\"student\",\"password\":\"s3cret\"}",
        )
        .expect("parse");
        let mut creds = EngineCredentials::from_package(package);
        assert_eq!(creds.username, "student");
        assert_eq!(creds.password, "s3cret");
        assert!(!format!("{creds:?}").contains("s3cret"), "Debug 不得泄漏");

        let ptr = creds.password.as_ptr();
        let len = creds.password.len();
        creds.zeroize();
        // SAFETY: 同上——`ptr` 在 zeroize 前捕获，分配仍存活，读取原 used 区间。
        let wiped = unsafe { std::slice::from_raw_parts(ptr, len) };
        assert!(wiped.iter().all(|&b| b == 0), "密码必须已确定性零化");
        assert!(creds.password.is_empty());
        assert!(creds.username.is_empty());
    }
}
