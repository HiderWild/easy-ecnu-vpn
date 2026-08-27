# Rust Common 路径入口（VPN Rust 原生运行时 MVP）

## 当前状态

当前活动产品路径仍是 C++。`src/common/rust/` 是
`vpn-rust-native-runtime-mvp` 的 Rust Common 路径；在当前 MVP 中它保持未接线，
只服务本需求的 acceptance。

本路径不进入现有 CMake 产品 target，也不接入现有 UI、产品 CLI 或 installer。
现有 C++ 产品路径继续承担当前产品交付；在完成独立切换前，不删除旧 C++ 路径，
也不让两个 runtime 同时拥有同一个业务连接。

## Common 边界

这里的 Common 是紧凑的、局部的 VPN 业务微内核：它只冻结必须跨平台保持一致的
业务语义，例如局部 `VpnRuntimeActor`、稳定的 command/outcome、identity/fence、
资源 ownership、effect certainty、取消和 stale-completion 规则。

Common 不是跨进程、跨宿主的联合状态机，也不规定 Windows 与 Darwin 必须采用相同
的原生进程、helper 或 provider 拓扑。各平台的最终 binary、原生资源实现与真实
宿主验证仍由各自平台 workspace 负责。

## 当前 MVP 的明确非目标

以下能力不属于当前 `vpn-rust-native-runtime-mvp` MVP：

- DTLS，以及 UDP data transport；
- UI 与 Tauri；
- 产品 CLI；
- Linux native adapter、Linux 原生调试或 Linux 原生交付结论。

`exv-vpn-acceptance` 仅是 test-only 的自动化调试入口，不是产品 CLI，也不进入
安装包。

## 规格与重新接线

本路径遵循：

- 顶层需求：
  `docs/superpowers/specs/vpn-rust-native-runtime-mvp.md`
- Common Architecture：
  `docs/superpowers/specs/vpn-rust-native-runtime-mvp-common-architecture.md`

任何重新接线都必须另立独立的 cutover requirement，明确引用顶层需求，并在
Windows 与 Darwin 各自对应的原生宿主上重新运行真实 VPN 业务流。一个平台的
结果不能替代另一个平台的真实宿主结果。

在该 cutover requirement 完成前，Rust Common 路径不得接入现有 CMake、UI、产品
CLI 或 installer。

## 双轨事实说明的性质

本 README 与 Rust MVP 文件中的双轨纯注释只陈述当前未接线和 C++ 仍为活动路径这一
事实；它们不构成 validator、删除时钟或验收门禁。不得使用 `#error`、`#warning`
或 source scanner 强制删除未接线路径；仅缺少这类事实说明时，应作为可内联补齐的
`RV-P2` 文档尾项处理，不能否定已经通过的业务 slice 或真实宿主结果。
