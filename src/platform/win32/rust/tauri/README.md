# EXV Tauri 桌面 UI（Phase 4 · P4-a 骨架）

独立 requirement：`vpn-rust-tauri-desktop-ui`（spec：不塞进 Common workspace）。
前端重写（O2）：不复用 C++ `webui/` 代码，仅参考其功能清单。
计划：`docs/superpowers/plans/2026-08-17-vpn-rust-native-runtime-productization-plan.md` Phase 4。

## 结构

```
src/platform/win32/rust/tauri/        # 独立 workspace（独立 Cargo.lock）
├── Cargo.toml                        # workspace 根（members = ["app"]）
├── app/                              # Tauri 应用 crate（tauri v2）
│   ├── tauri.conf.json               # devUrl: localhost:1420；frontendDist: ../frontend/dist
│   ├── capabilities/default.json     # 权限：core IPC + event + window + log
│   ├── build.rs
│   ├── icons/                        # 占位图标（P4 正式版需替换品牌图标）
│   └── src/
│       ├── main.rs / lib.rs          # Builder：命令注册、托盘、窗口生命周期
│       ├── lifecycle.rs              # 托盘最小化不退出；彻底退出→notify_core_shutdown（O3 接缝）
│       └── kernel/                   # UI↔core 语义层（mirror wire 契约）
│           ├── state.rs              # RuntimeSnapshot/RuntimeEvent/ConnectPhase/OperationReply
│           ├── logs.rs               # LogEvent/LogChunk
│           ├── commands.rs           # Tauri Command：connect/stop/snapshot/logs_list/config_*/respond_interaction
│           ├── events.rs             # Event 名 + emit 辅助（exv://status|logs|interaction）
│           ├── client.rs             # CoreClient 接缝 + CoreState（P4-b 接真实 gRPC 通道）
│           └── error.rs              # AppError（not_wired / core_unreachable / internal）
└── frontend/                         # Vue3 + Vite + TS（前端重写）
    ├── package.json / vite.config.ts / tsconfig.json / index.html
    └── src/
        ├── main.ts / App.vue         # 侧边栏 + 三页路由（连接/日志/设置）
        ├── lib/ipc.ts                # 类型化 invoke()/listen() 封装（mirror Rust 契约）
        └── pages/                    # ConnectPage / LogsPage / SettingsPage
```

## 构建 / 运行

环境注意：cargo 不在标准 PATH；D: 磁盘接近满，target 在 D: 需注意剩余空间。

```bash
export PATH="/c/Users/TomLi/.rustup/toolchains/1.96.0-x86_64-pc-windows-msvc/bin:$PATH"

# 前端依赖（一次）
cd src/platform/win32/rust/tauri/frontend && npm install

# 前端开发服务器（tauri.conf.json beforeDevCommand 会自动起）
cd src/platform/win32/rust/tauri && CARGO_TARGET_DIR=$(pwd)/target cargo run -p exv-ui

# 仅 Rust 侧类型检查（不构建前端）
cd src/platform/win32/rust/tauri && CARGO_TARGET_DIR=$(pwd)/target cargo check -p exv-ui

# 前端独立构建
cd src/platform/win32/rust/tauri/frontend && npm run build
```

### Windows 生产包构建约束

生产包必须先执行 `npm run build`，再执行 `cargo build --release -p exv-ui`。
`src/platform/win32/rust/tauri/Cargo.toml` 已启用 Tauri 的 `custom-protocol` feature；
该 feature 关闭开发模式的 `devUrl`，让 release UI 从内置 `frontendDist` 加载资源。
如果 release 构建日志出现 `DEP_TAURI_DEV=true`，产物仍会尝试访问
`http://localhost:1420`，不得进入安装包；正确的生产构建必须出现
`DEP_TAURI_DEV=false`。

首次 `cargo check`/`run` 会拉取并编译 Tauri 依赖树（~数百 crate，数分钟到十几分钟）。

### 当前 Tauri 生产组装入口

Windows 下不要直接执行无扩展名的 `frontend\\node_modules\\.bin\\tauri` shim；PowerShell
可能解析到不产生构建结果的 shim，随后把旧的 `exv-ui.exe` 复制进运行目录。当前唯一
可复现的生产构建入口是：

```powershell
# Ensure `cargo` and `rustc` are discoverable from your own Rust toolchain setup.
cd src\\platform\\win32\\rust\\tauri
npm exec --no-install --prefix .\\frontend tauri build -- --no-bundle
cd ..\\..\\..\\..
powershell -ExecutionPolicy Bypass -File scripts\\assemble-runtime-trio.ps1 `
  -OutDir build\\release-ui-merged\\runtime-trio-current
powershell -ExecutionPolicy Bypass -File scripts\\package-rust-setup.ps1 `
  -SetupToolsDir build-setup-rust `
  -OutDir build\\release-ui-merged -KeepInstallers 2
```

未传入 `-Version` 时，安装器版本默认取自 `app/tauri.conf.json`。

`assemble-runtime-trio.ps1` 已固定调用 Windows `tauri.cmd`，并在复制前检查命令 shim
存在；交付前必须核对 payload 中 `exv-ui.exe` 与
`src\\platform\\win32\\rust\\tauri\\target\\release\\exv-ui.exe` 的 SHA-256 一致，
不能只依据文件名或时间戳判断“最新”。

## P4-a 阶段现状（诚实边界）

- Command/Event 类型与接缝就位，签名即契约（mirror `proto/exv/v1/` wire）。
- 所有 Command 后端经 `CoreClient` 返回 `AppError::NotWired`（P4-b 前占位）。
- WatchEvents/StreamLogs 订阅为 Event 名 + emit 辅助（接缝），未接真实推送源。
- 托盘：最小化不退出（CloseRequested → hide）；「退出」→ `notify_core_shutdown`（O3 接缝，当前仅日志）。
- 图标为占位（cyan 环），正式版需替换。

## P4-a 验证结果（2026-08-17）

- `cargo check -p exv-ui`：通过，无错误无警告。
- `npm run build`（vue-tsc + vite）：通过，产物 `frontend/dist/`（72 kB JS / 4.6 kB CSS）。
- `cargo build -p exv-ui`：通过，产出 `target/debug/exv-ui.exe`（14.7 MB，debug）。
  验证完成后已删除该 target 目录释放 D: 空间（共享 worktree，D: 曾降至 423M 空闲）；
  重建约需 5–10 分钟（cargo registry 缓存位于 C: 已热身）。
- 环境：cargo 1.96.0（完整路径）；node v24 / npm 11；C: 78G 空闲（cargo cache）；
  D: 空间紧张（win32 rust + root 两个 target 共 20G+；tauri target 约 2.9G，构建时需预留）。

## P4-b IPC 接线说明（已实现；2026-08-17）

架构前提（计划 §1）：core 是独立进程（普通用户 token · 纯协调层 · 语义网关），
UI 不直连 engine。Tauri host 进程是 core 的唯一 UI 入口。

通道：**Tauri Command → host Rust → core 的 KernelControl gRPC 端点（Named Pipe）**。

1. **core 进程形态**：core 独立进程，暴露 `KernelControl` 服务（proto
   `kernel_control.proto`：Connect/RespondInteraction/Stop/Reconcile/GetOperation/
   GetSnapshot/WatchEvents）。其传输层在
   `crates/exv-vpn-win32-host/src/kernel_control_transport.rs` / `grpc_transport.rs`。
2. **传输选型（Windows）**：**named pipe**（`\\.\pipe\exv-core-<ui_pid>`，
   mutually-authenticated，与 host↔engine 的 pipe 认证同构）。
   - UI 侧 client 拨号 + server 身份验证在 `app/src/kernel/core_transport.rs`
     （镜像 host `grpc_transport.rs`：`dial_core_pipe_with_retry` +
     `verify_core_server_pipe` + `connect_core_channel`）。
   - core 侧验证 UI peer（pid + user SID + account）由 host
     `kernel_control_transport::verify_ui_peer` 完成（P5 落 host main 时接线）。
3. **生命周期（O3 强绑定）**：core 由 **Tauri 宿主进程 spawn**（`core_process.rs`，
   非特权直接拉起——core 是普通用户 token）。UI 彻底退出（托盘「退出」）→
   `notify_core_shutdown`（`lifecycle.rs`）：中止事件订阅 → `app.exit(0)` →
   进程 teardown drop channel → 控制面管道关闭 → core `serve_task` resolve →
   `shutdown_core` 有序停机（engine StopTunnel → engine 终止）→ core 退出。
   **core 由 pipe-close 感知自行退出**；UI 侧 `CoreChild` 不做 Drop 强杀（避免打断
   有序停机），`terminate` 为挂死兜底。
4. **接线点**：
   - `kernel/client.rs`：`CoreClient` 方法体改为真实 tonic 调用；
     `CoreHandle::Dialed { channel, core_peer }`。
   - `kernel/wire.rs`：wire → UI 镜像类型机械映射 + 请求组装（connect/stop/
     respond_interaction）。
   - `kernel/events.rs`：`spawn_subscriptions` 拉起 WatchEvents 订阅 task
     （`stream.next()` → `emit_status`，断线退避重连 + resume tick）。
   - `kernel/bootstrap.rs`：Tauri setup 时 spawn core → 拨号 → 管理状态 → 挂订阅。
   - `commands.rs`：命令签名不变，仅 async 化（`State` 仍同步可用）。
5. **依赖**：`app/Cargo.toml` 增补 `tonic`/`http`/`hyper-util`/`tower`/`uuid`/
   `sha2`/`windows`，并**复用 Root workspace 的 `exv-vpn-wire`**（path dependency）
   作为 `KernelControlClient` + wire 消息类型源——不复制 proto、不重生成，避免
   wire 契约分叉。tonic 版本与核心 workspace 一致（0.14.x）。

### P4-b 诚实边界（wire 缺口）

`KernelControl` 冻结 wire 只有 Connect/RespondInteraction/Stop/Reconcile/GetOperation/
GetSnapshot/WatchEvents。以下命令无 wire 端点，保留 typed `NotWired`（不假装完成，
proto 变更须协调者评估）：
- `logs_list`（`logs.list`/`logs.clear` 在 host `log_control.rs` 为进程内方法，不在
  KernelControl proto）；
- `config_get` / `config_set`（core config 契约不在 wire 上）。
- `exv://logs` 事件（StreamLogs 是 HelperControl 的 engine→core 通道，core 未向 UI
  暴露）——emit seam 保留，前端仍监听该名，接线后生效。

## P5-c 统计展示说明（已实现；2026-08-17）

连接页展示 rx/tx 速度（bytes/s，参考 C++ `formatTrafficRate` 逻辑）、累计流量
（rx/tx bytes）、延迟与统计阶段；连接状态（phase/connected）来自 `WatchEvents`
`RuntimeSnapshot`（P4-b 已真实接线）。

**P5-c wire 缺口（数据通道）**：统计数值源在 host `EventBus` 统计 lane
（`publish_stats`/`subscribe_stats`/`current_stats`，host `kernel_control_service.rs`；
P5-b core 侧归一化：累计字节增量 / 时间间隔的速度 + 累计流量透传）。但 `KernelControl`
冻结 wire 无统计 RPC、`RuntimeSnapshot`（proto `common.proto`）无统计字段——**UI 目前
无法经 wire 取到统计**。tauri 侧已备好完整管道与 typed `NotWired` seam：
- `kernel/stats.rs`：UI 侧 `RuntimeStats` 镜像（serde，与 host `RuntimeStats` 字段一致）；
- `stats` 命令（`CoreClient::stats`）+ `exv://stats` 事件（`emit_stats`）+ `onStats`
  前端监听 + `CoreState.last_stats` 缓存——wire 源落地后仅需把 seam 换为真实调用；
- 前端 `ConnectPage.vue` 统计面板已完整渲染；seam 未接线期显示「统计通道待接线
  （P5-c）」占位，不假装有数据。

host/proto 变更须协调者评估（建议见 `app/src/kernel/stats.rs` 模块文档：A. 扩展
`RuntimeSnapshot` 增 `stats` 字段；B. `KernelControl` 增 `GetStats`/`StreamStats` RPC）。
给 P6 验收：统计数值通道接通 = 把 `CoreClient::stats` 从 seam 换为真实调用 + 前端
`onStats` 订阅生效；速度/流量格式化逻辑与显示已完成并随 seam 就位。

### 构建环境注意（P4-b 起）

D: 磁盘长期 100% 满。Tauri 构建改用 **C: 上的 target**：
```bash
export PATH="/c/Users/TomLi/.rustup/toolchains/1.96.0-x86_64-pc-windows-msvc/bin:$PATH"
cd src/platform/win32/rust/tauri
CARGO_TARGET_DIR=/c/Users/TomLi/AppData/Local/Temp/exv-tauri-target cargo check -p exv-ui
CARGO_TARGET_DIR=/c/Users/TomLi/AppData/Local/Temp/exv-tauri-target cargo test -p exv-ui
```
（不再用 `$(pwd)/target`——D: 已满，link.exe 会 LNK1180/LNK1108 失败。）

## 与核心 runtime workspace 的关系

- 独立 workspace、独立 Cargo.lock、独立依赖治理（计划 §4 风险项：需单独 Cargo.toml）。
- 不修改 `src/platform/win32/rust/Cargo.toml`（其 members 仅 `crates/*`，tauri/ 不加入）。
- 不共享 `src/platform/win32/rust/.cargo/config.toml`（TMP/TEMP workaround 适用目录树，
  本目录位于其下，自动继承，勿删除）。
- 未来如需复用 core 类型：path dependency 或经 gRPC 通道，P4-b 决定。
