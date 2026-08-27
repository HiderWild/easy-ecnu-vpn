// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。

//! Win32 非特权 host 平台 crate。
//!
//! W27-I：`composition`（非特权 host 组合：绑定已验 helper 身份、进程 token
//! elevation 观测、单 runtime actor + KernelControlGate、W23A/W23B packet leg
//! 组合）与 `kernel_control`（`ClearableSecret` + `KernelControlGate`）已实现；
//! `shutdown` 仍为构建接缝占位。
//!
//! P1-c：`grpc_transport`（Named Pipe ↔ tonic 传输 + client 侧 engine peer 认证）、
//! `grpc_control`（产品 wire 的 tonic `HelperControlClient`，取代 JSON frame 成为
//! core→engine 通道）、`kernel_control_service`（面向 Tauri UI 的 `KernelControl`
//! 服务骨架）已实现。legacy `control_client`（JSON frame）保留作 acceptance 参考。
//!
//! P2-a：`log_aggregator`（core 日志聚合服务）已实现——合并 engine `StreamLogs`
//! 事件与 core 自身事件落盘（磁盘文件为唯一真相源），提供 `after_seq` 增量游标
//! （P2-c `logs.list`/`logs.clear` 契约的语义底座）与 `ingest_engine_stream`
//! 接线点。
//!
//! R3：日志纯单向输出链路已接线——`KernelControlService::spawn_log_forwarder`
//! 订阅 engine `StreamLogs` 并经 `ingest_engine_stream` 聚合落盘（只写磁盘，绝不
//! 回流状态，D3 铁律）；engine `LogSink` 已改造为扇出/多订阅（多消费方同时挂接、
//! 互不饿死）。
//!
//! P3-a：`credential`（core 凭据生命周期产品化）已实现——读 `ExvConfig` +
//! 独立 `key.bin` → 解密（`load_credentials`）→ RAII 确定性零化明文中间态
//! （[`ClearablePassword`]）→ 组装一次性 `secret_payload`（[`CredentialPackage`]
//! 序列化逻辑）→ 与 `grpc_control::hand_off_request` 配对、发送后 `zeroize_connect_secret`
//! 清零 wire 副本。HelperControl wire 尚无 `secret_payload` 字段（proto 缺口见
//! 模块文档）；KernelControl `ConnectRequest.secret_payload`（P3-b）可直接复用本模块
//! payload 字节。
//!
//! P3-c2：`process_lifecycle`（engine 进程原语：bin/args/spawn/verify/wait/terminate）、
//! `engine_lifecycle`（[`EngineSupervisor`]：spawn→connect→stop→wait-exit）、`shutdown`
//! （[`UiLifetime`]/[`CoreRuntime`]/`shutdown_core`：O3 UI 强绑定 + 有序停机 + composition
//! 钩子接线）与 `kernel_control_transport`（UI-facing `KernelControl` Named Pipe 传输层，
//! UI 断开 → 停机）已实现。

pub mod composition;
pub mod control_client;
pub mod crash_recovery;
pub mod credential;
pub mod engine_lifecycle;
pub mod grpc_control;
pub mod guards;
pub mod grpc_transport;
pub mod kernel_control;
pub mod kernel_control_service;
pub mod kernel_control_transport;
pub mod log_aggregator;
pub mod log_control;
pub mod plan_exempt;
pub mod process_lifecycle;
pub mod service_status;
pub mod shutdown;
pub mod stats;

// EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。
// cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；重新接线须另立 cutover requirement 并重跑真实业务流——该条件已由 2026-08-17 cutover 满足。