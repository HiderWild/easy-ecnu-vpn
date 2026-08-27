# 业务流优先治理入口

[业务流优先的宿主修复治理政策](business-first-host-repair-policy.md) 是本目录的**唯一活跃正文**。
所有 Common 边界、宿主修复、双轨版本、真实用户业务流、测试和证据结论均直接遵循该政策。

**执行载体**：Rust 产品线（cargo 为正式语言与活动产品线）的门禁执行方式见
[Rust 产品线门禁执行适配说明](rust-product-line-governance-execution.md)——政策语义不变、
执行载体换 cargo；旧 C++ 执行物（`tests/governance/` Python 测试、`scripts/run_common_native_acceptance.py`、
CTest 注册）保留为历史参考、不再是活动门禁。

本目录中的其他设计、记录、模板和历史材料只用于追溯背景。它们不能恢复未知状态门禁、跨宿主
联合状态机制或以元数据代替原生宿主真实用户业务流的规则。需要排查实际问题时，记录观察事实和
当前修补，并按政策在受影响原生宿主重跑相应业务流。

GitHub Actions 保持禁用；本地模块测试和真实用户业务流测试各自记录其当前事实，缺少真实流证据
时不得声称该宿主已经通过。
