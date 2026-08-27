// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! W29 stop-saturation 的 helper-hold 角色（W29-I）。
//!
//! [`run_stop_pressure_helper`] 以 W26 顺序 compose 提权 helper
//! （authority -> recovery -> endpoint，组合 [`compose_privileged_helper`]，绝不
//! 重新实现），compose 成功（composition live、authority 持有中）后**才**写
//! `ready_marker` 文件；随后 [`StopPressureHelper::hold_until_killed`] 一直 hold 到
//! 被 TerminateProcess（绝不执行 shutdown = crash 语义，authority 留给下一个
//! waiter 以 WAIT_ABANDONED 接管）；[`StopPressureHelper::shutdown`] 走 W26
//! [`shutdown_composition`] 的反序 teardown（先 join 再释放 authority）。
//!
//! 本模块是 tests/crash_matrix.rs 冻结的 helper 角色 seam：
//! `StopPressureConfig` / `run_stop_pressure_helper` / `StopPressureHelper`
//! （`hold_until_killed` / `shutdown`）；crash-matrix 纵切（`crash_matrix.rs`）
//! 以同一函数驱动真实 kill/restart 子进程（`scenarios::stop_pressure` 的 helper
//! 角色，等价于 TK80 testkit crash.rs 的 named crash point seam 占位）。

use std::path::PathBuf;
use std::time::Duration;

use exv_engine::composition::{
    ComposeConfig, ComposeError, HelperComposition, compose_privileged_helper,
};
use exv_engine::shutdown::shutdown_composition;
use exv_vpn_win32_resource::native_error::NativeError;

/// helper-hold 角色的配置（tests/crash_matrix.rs 冻结字段）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopPressureConfig {
    /// `Local\` 作用域的 authority mutex 名（W13）。
    pub authority_name: String,
    /// durable journal 目录（W14）。
    pub journal_dir: PathBuf,
    /// 只在 composition live（authority 持有中）后才写的 ready marker 路径。
    pub ready_marker: PathBuf,
}

/// helper-hold 角色的类型化失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopPressureError {
    /// W26 compose 失败（authority / journal / recovery / corrupt）。
    Compose(ComposeError),
    /// compose 成功但 ready marker 无法写入（失败路径先 shutdown 自清理）。
    Marker(String),
    /// 有序 shutdown 失败（类型化 native 错误）。
    Shutdown(NativeError),
}

/// live 的 helper-hold 组合（authority 持有中）。
pub struct StopPressureHelper {
    composition: HelperComposition,
}

impl StopPressureHelper {
    /// Hold 直至被 TerminateProcess：绝不执行 shutdown（crash 语义）。
    pub fn hold_until_killed(&mut self) -> ! {
        loop {
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    /// 有序 shutdown：W26 反序 teardown（先 join 再释放 authority）。
    ///
    /// # Errors
    ///
    /// 返回类型化 [`NativeError`]（当前纯组合阶段不会失败）。
    pub fn shutdown(self) -> Result<(), StopPressureError> {
        shutdown_composition(self.composition)
            .map(|_| ())
            .map_err(StopPressureError::Shutdown)
    }
}

/// Compose helper（W26 顺序）并发布 ready marker，随后返回 live 的 hold 组合。
///
/// compose 成功（authority 持有中、endpoint 已发布）后**才**写 `ready_marker`
/// （= composition live）；compose 失败不写 marker、不留状态。marker 内容携带
/// helper PID 与 composition 的 durable projection digest（跨 restart 的
/// stable-digest 复验由 crash-matrix 读取）。
///
/// # Errors
///
/// compose 失败返回 [`StopPressureError::Compose`]；marker 写失败返回
/// [`StopPressureError::Marker`]（失败路径先 shutdown 自清理）。
pub fn run_stop_pressure_helper(
    config: StopPressureConfig,
) -> Result<StopPressureHelper, StopPressureError> {
    let composition = compose_privileged_helper(ComposeConfig {
        authority_name: config.authority_name.clone(),
        journal_dir: config.journal_dir.clone(),
    })
    .map_err(StopPressureError::Compose)?;
    let digest = composition.projection_digest();
    let payload = format!(
        "pid={} digest={}\n",
        std::process::id(),
        hex_digest(&digest)
    );
    if std::fs::write(&config.ready_marker, payload).is_err() {
        let _ = shutdown_composition(composition);
        return Err(StopPressureError::Marker(format!(
            "cannot write ready marker {}",
            config.ready_marker.display()
        )));
    }
    Ok(StopPressureHelper { composition })
}

/// 32 字节 digest 的 hex 表示（marker 内容；跨 restart 的 stable-digest 对比）。
fn hex_digest(digest: &[u8; 32]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。
