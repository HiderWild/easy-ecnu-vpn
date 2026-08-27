<!-- EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。 -->
<!-- cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；门禁执行适配见 docs/superpowers/governance/rust-product-line-governance-execution.md。 -->

# Rust Win32 平台路径入口（VPN Rust 原生运行时 MVP）

## 当前状态

**Rust 为正式活动产品线**（cutover 2026-08-17：`docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md`；
C++ 已弃用、仅作参考）。`src/platform/win32/rust/` 是 Rust 产品线的 Win32 平台 Cargo workspace
（`vpn-rust-native-runtime-mvp` 及其产品化 Phase 1–6）。

本路径是一个独立的、自包含的 Cargo workspace，不进入现有 CMake 产品 target，也不接入
现有 UI、产品 CLI 或 installer（这些属于 C++ 历史路径，仅作参考，不再承担活动产品交付）。
门禁执行适配（cargo 载体 + run-native-acceptance.ps1 真实流验收）见
`docs/superpowers/governance/rust-product-line-governance-execution.md`。

## 平台边界

本 workspace 只承载 Windows 原生资源与宿主拓扑，包括：

- 特权 helper 与非特权 host，通过相互认证的 Named Pipe（mutually-authenticated
  Named Pipe）通信；
- Wintun L3 设备；
- Windows 地址 / MTU / route / DNS API。

跨平台业务语义（VpnRuntimeActor、command/outcome、identity/fence、资源
ownership、effect certainty、取消与 stale-completion 规则）保留在 Rust Common
路径 `src/common/rust/`，由本平台 workspace 通过相对路径引用。

本路径不是跨进程、跨宿主的联合状态机，也不规定 Windows 与 Darwin 必须采用
相同的原生进程、helper 或 provider 拓扑。各平台的最终 binary、原生资源实现与
真实宿主验证仍由各自平台 workspace 负责。

## 当前 MVP 的明确非目标

以下能力不属于当前 `vpn-rust-native-runtime-mvp` MVP：

- DTLS，以及 UDP data transport；
- UI 与 Tauri；
- 产品 CLI；
- Linux native adapter、Linux 原生调试或 Linux 原生交付结论。

`exv-vpn-win32-acceptance` 仅是 test-only 的自动化调试入口，不是产品 CLI，
也不进入安装包。

## 规格与重新接线

本路径遵循：

- 顶层需求：
  `docs/superpowers/specs/vpn-rust-native-runtime-mvp.md`
- Win32 平台计划；Common Architecture：
  `docs/superpowers/specs/vpn-rust-native-runtime-mvp-common-architecture.md`

任何重新接线都必须另立独立的 cutover requirement，明确引用顶层需求，并在
Windows 原生宿主上重新运行真实 VPN 业务流。一个平台的结果不能替代另一个平台
的真实宿主结果。

在该 cutover requirement 完成前，本 Rust Win32 路径不得接入现有 CMake、UI、
产品 CLI 或 installer。

## 双轨事实说明的性质

本 README 与 Rust 文件头的 cutover 纯注释只陈述当前事实（Rust 为活动产品线、
C++ 仅参考）；它们不构成 validator、删除时钟或验收门禁。双轨共存政策见
`docs/superpowers/governance/business-first-host-repair-policy.md` §3：不得使用
`#error`、`#warning` 或 source scanner 强制删除未接线路径。

<!-- EXV_CUTOVER（2026-08-17）：Rust 为正式活动产品线；C++ 已弃用、仅作参考。 -->
<!-- cutover 记录：docs/superpowers/evidence/2026-08-17-rust-native-product-line-cutover.md；门禁执行适配见 docs/superpowers/governance/rust-product-line-governance-execution.md。 -->