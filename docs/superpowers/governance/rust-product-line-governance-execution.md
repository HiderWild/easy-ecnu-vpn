# Rust 产品线门禁执行适配说明（2026-08-17）

> **政策语义不变，执行载体换 cargo。** 本文记录 governance 门禁从 C++ 执行适配层
> （Python unittest + CMake/CTest）迁移到 Rust 产品线（cargo test + run-native-acceptance.ps1）
> 的落地方式：宽松门禁政策语义语言无关，执行载体由本文件明确；旧 C++ 执行物保留为
> 历史参考，**不再是活动门禁**。
>
> 依据：
> - Cutover 记录：`docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md`（C++ 弃用、Rust 为正式活动产品线）
> - 产品化计划：`docs/superpowers/plans/2026-08-17-vpn-rust-native-runtime-productization-plan.md` §2 `Phase 6`（P6-2 门禁适配）
> - 唯一活跃政策正文：`docs/superpowers/governance/business-first-host-repair-policy.md`（及本目录 README 入口）

---

## 1. 政策语义（不变，语言无关）

宽松门禁政策语义由 `business-first-host-repair-policy.md` 定义，与执行语言无关。迁移只换
执行载体，不重定义政策。必须遵守的语义锚点：

1. **真实错误驱动、开放世界**：未知或未建模状态不触发阻塞、强制核验、补偿、穷举或完整性证明。
2. **未知不阻塞**：只有真实发生、可观察的错误才进入处理；未知错误如实报告为未知，给重试/重启/日志反馈等下一步。
3. **禁止跨宿主联合状态机**：禁止跨模块/跨系统/跨进程/跨宿主联合状态机用于执行、投影、诊断、验收或离线模型检查。
4. **宿主业务流优先**：修复实际业务路径时可直接修 Common、共享构建、契约和测试。
5. **真实流才是整合输入**：各宿主分别跑通的真实用户级业务流才是 Common 整合正输入；失败或缺证只是缺陷证据，不是否决。
6. **双轨不逼删**：双轨版本可共存；不得用 `#error`/`#warning`/validator 逼删未接线版本。
7. **诚实回执**：模块检查只证明模块、真实宿主业务流才证明宿主、执行回执说明实际运行范围；不把 mock/收据/测试数量伪装成业务通过。

**不得重新引入的旧门禁语义**（政策 §6 已废止，本适配不使其回归）：

- Common-first 阻塞（以 Common 基底/规格/manifest/分支存在作为开始、继续或提交条件）；
- `blocked_by_common` 白名单状态机；
- 模型穷举 / 跨宿主完整性证明作为业务阻塞。

## 2. C++ 执行物现状与处置（保留历史参考，不再是活动门禁）

以下执行物在 Rust 主工作线 `codex/req-vpn-rust-native-runtime-mvp-common` 上仍存在于 git
（`git ls-files` 确认），但 C++ 已弃用、Rust 为正式产品线（cutover 记录 §1）。处置原则：
**保留为历史参考，不删除、不逼删（政策 §3），不再承担产品线活动门禁。**

| 执行物 | 位置 | 性质 | 处置 |
| --- | --- | --- | --- |
| governance Python 测试（8 文件） | `tests/governance/test_*.py` | Python unittest；部分绑定 C++ 结构（读取 `CMakeLists.txt`、调用 `cmake`/`ctest`、假定 C++ 产物），部分校验政策正文（`business-first-host-repair-policy.md`、README） | 历史参考，非活动门禁。政策正文校验类内容的思想已并入本文 §1；C++ 结构绑定类不再对 Rust 产品线生效 |
| Common 本机模块检查器 | `scripts/run_common_native_acceptance.py` | Python；固定 `cmake`/`ctest` 调用，假定 C++ 产物结构；构造上 `host_real_passed=false`，只做 Common 模块检查 | 历史参考，非活动门禁。Rust 产品线模块检查载体为 `cargo test`（§3.1） |
| CTest 注册 | 根 `CMakeLists.txt` `add_test(... LABELS "governance")` | 绑定 C++ 构建系统 | 保留；C++ 弃用后不承担产品线门禁。Rust 产品线不依赖 CMake/CTest |
| Common 历史验收契约 | `docs/superpowers/governance/common-native-acceptance-policy.json`、`common-native-acceptance-bundle.schema.json` | Common 本机模块检查的旧契约/证据格式 | 历史参考。Rust acceptance 证据使用自身 serde 类型化字段（`exv-vpn-win32-acceptance/src/evidence.rs`） |
| 政策正文与入口 | `docs/superpowers/governance/business-first-host-repair-policy.md`、`README.md` | **唯一活跃正文 + 入口** | 保持活跃；本文是对其执行载体的适配说明 |

> 注：`tests/governance/test_*.py` 中校验政策正文的断言（如禁止旧门禁语义的文字）思想已在
> §1 以 Rust 产品线可执行的方式固化（cargo 门禁 + 人工评审 + 真实流验收），不另建 Python 执行层。

## 3. Rust 产品线门禁执行物（活动）

Rust 工作区：`src/platform/win32/rust/`（独立 Cargo workspace，成员为 `crates/*` 六个
Win32 crate；Common 业务语义在 `src/common/rust/crates/*` 以相对路径依赖引用）。

### 3.1 模块检查层（cargo 载体）

| 门禁 | 命令（在 `src/platform/win32/rust/` 下） | 说明 |
| --- | --- | --- |
| 模块测试（最小集） | `cargo test -p <crate>` | 单 crate 单元/集成测试；本文验证样例：`cargo test -p exv-vpn-win32-ipc`（46 通过，见 §4） |
| 模块测试（全量） | `cargo test --workspace` | Win32 workspace 六个 crate 全部测试；`core_process_smoke` 为 `#[ignore]` opt-in（§3.3） |
| 格式 | `cargo fmt --check` | 产品线格式门禁 |
| lint | `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | 产品线 lint 门禁（计划 §0 验收曾用） |
| Common 语义测试 | 随 workspace 构建作为依赖被校验；或对具体 crate `cargo test -p <common-crate> --manifest-path` | `src/common/rust/crates/*` 的跨平台业务逻辑模块测试（11 crate / 29 集成测试文件）；经 Win32 workspace 的路径依赖参与构建 |

**边界（政策 §4）**：模块检查只证明模块的局部行为，不证明宿主真实通过。模块层全绿不等于
真实业务流通过；真实宿主结论必须由 §3.2 产生。

### 3.2 真实宿主业务流层（run-native-acceptance.ps1 载体）

入口：`src/platform/win32/rust/scripts/run-native-acceptance.ps1`

```
powershell -File src/platform/win32/rust/scripts/run-native-acceptance.ps1 `
    -Scenario <controlled|crash-matrix|school> -EvidenceDir <evidence目录>
```

- **场景**：`controlled`（受控纵切）/ `crash-matrix`（崩溃矩阵）/ `school`（真实学校流）。
- **前置**：release 构建（`cargo build --locked --release`，缺场景二进制时自动构建）、Wintun DLL
  （`EXV_RUST_VPN_WINTUN_DLL`）、school 场景凭据/路由来自 config（`%USERPROFILE%\.exv`）非 env 注入。
- **提权语义**：`controlled`/`crash-matrix` 需 elevation（`Start-Process -Verb RunAs` 自举，
  `IS_ADMIN` 标记写入 `elevated-marker.txt`）；`school` = core（普通）拉 engine（特权）双进程拓扑。
- **环境无效诚实标记**（W26..W30 约定）：`WIN_ACCEPTANCE_ENV_INVALID:<predicate>` /
  `not_run/blocked_by_environment:<predicate>`；环境无效绝不伪装成 RED/GREEN。
- **证据落盘**：`<EvidenceDir>/acceptance-evidence.json`（编排事实 + 前置标记 + 场景 §9 字段）+
  `acceptance-run.log`（转写）+ `elevated-marker.txt`（提权上下文）+ `<scenario>-scenario.log`（场景自日志）。
- **保密契约**：`no_raw_secrets_written=true`；raw secret/cookie/私钥绝不进 argv/env/log/evidence。
- 证据目录惯例：`docs/superpowers/evidence/vpn-rust-native-runtime-mvp/win32/<W 编号>/`
  （既有 W28/W29/W30/W30-real/W31-core-engine 为前例）。

### 3.3 全链 smoke（进程级，P6-b 入口）

`crates/exv-vpn-win32-host/tests/core_process_smoke.rs`：core main 真实入口全链冒烟——spawn core →
提权拉起真实 engine → gRPC 控制面连接 → 建 UI 控制面管道并 accept → 扮演 UI 拨号后断开
（O3 UI 强绑定）→ 有序停机断言。`#[ignore]` opt-in（需 engine bin + UAC 放行）：
`cargo test -p exv-core --test core_process_smoke -- --ignored`。

**scope 边界**：模块检查（§3.1）只证明模块；smoke 是进程级全链自检；**真实宿主业务流验收**
（connect → data → Stop → recovery 在原生宿主跑通）是 P6-b 范畴，复用 §3.2 的 school 场景
与 cutover 记录 §3 基线。

### 3.4 回执原则

- 每项执行记录实际运行范围：跑了什么（命令、场景、宿主）、范围是什么（模块级 / 进程级 / 真实流）。
- 不把 mock、收据、测试数量、commit SHA 伪装成业务通过（政策 §4）。
- 证据 JSON 里 null 字段 = 未观测，不得以 null 宣称通过（`environment_state=completed` 是完整纵切唯一完成值）。

## 4. 验证回执（2026-08-17）

模块层最小集实际运行（本适配建立时验证）：

```
cargo test -p exv-vpn-win32-ipc        # 46 passed, 0 failed, 0 ignored; exit 0
```

运行环境：Windows 11 Pro (26200)，Rust 1.96.0 MSVC toolchain，`src/platform/win32/rust` 工作区
（`CARGO_TARGET_DIR=$(pwd)/target`）。覆盖 `exv-vpn-win32-ipc` 的 lib 测试 + 5 个集成测试文件
（含 `engine_protocol`、`plane_isolation` 等）。**范围**：模块级测试；不构成真实业务流验收。
`core_process_smoke` 未跑（需 UAC + engine bin，属 P6-b 真实流范畴）。

> 注：`cargo test -p exv-vpn-win32-ipc` 输出中有一处 `unused_mut` warning（集成测试源码），
> 非测试失败；模块测试全部通过。该 warning 属源码质量项，由对应模块 worker 处理，不在本适配范围。

## 5. 给 P6-b（真实业务流验收）的入口说明

- **验收入口**：§3.2 `run-native-acceptance.ps1 -Scenario school`（core 普通 + engine 特权真实学校流，
  复用 cutover 基线 §3）；`controlled` 纵切与 `crash-matrix` 为补充场景。
- **前置清单**：release 构建就位；`EXV_RUST_VPN_WINTUN_DLL` 指向 Wintun DLL；**Mihomo TUN 关闭**
  （W31-core-engine 已证实默认路由干扰）；真实凭据 config（`~/.exv`）。
- **验收流程**：connect → data（真实业务流往返）→ Stop → recovery 完整闭环（cutover 记录 §3）。
- **证据**：写 `docs/superpowers/evidence/vpn-rust-native-runtime-mvp/win32/<新编号>/`，
  遵守 §3.2 证据契约与 §3.4 回执原则。
- **完成判据**：`environment_state=completed`、`no_raw_secrets_written=true`、Stop 后
  `network_state_after_equals_before=true`、engine 退出干净（W31 先例）。

## 6. 关联文档

- 政策正文：`docs/superpowers/governance/business-first-host-repair-policy.md`
- Cutover：`docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md`
- 产品化计划：`docs/superpowers/plans/2026-08-17-vpn-rust-native-runtime-productization-plan.md`（Phase 6）
- 验收证据：`docs/superpowers/evidence/vpn-rust-native-runtime-mvp/win32/`
- Rust workspace README：`src/platform/win32/rust/README.md`
