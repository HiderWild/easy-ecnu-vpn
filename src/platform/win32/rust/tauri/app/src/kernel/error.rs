//! Command 层错误类型。serde 序列化，随 invoke() 返回值传到前端。

use std::fmt;

/// UI Command 层错误。P4-a 阶段仅有骨架错误（not_wired）；
/// P4-b 真实接线后扩展 gRPC/通道错误。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "message", rename_all = "snake_case")]
pub enum AppError {
    /// Command 已定义但尚未接线到 core（P4-b 前占位）。
    NotWired(String),
    /// core 进程不可达（未启动/通道断开）。
    CoreUnreachable(String),
    /// 服务已安装但未运行（R5：connect 路由 `service_not_running|` 前缀 → 弹恢复 modal）。
    ServiceNotRunning(String),
    /// 服务 mode 连接失败（R5：connect 路由 `service_connect_failed|` 前缀 → 弹恢复 modal）。
    ServiceConnectFailed(String),
    /// 内部错误。
    Internal(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotWired(m) => write!(f, "not wired to core: {m}"),
            Self::CoreUnreachable(m) => write!(f, "core unreachable: {m}"),
            Self::ServiceNotRunning(m) => write!(f, "service not running: {m}"),
            Self::ServiceConnectFailed(m) => write!(f, "service connect failed: {m}"),
            Self::Internal(m) => write!(f, "internal: {m}"),
        }
    }
}

impl std::error::Error for AppError {}
