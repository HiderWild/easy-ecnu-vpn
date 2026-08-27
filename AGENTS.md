## CodeGraph 代码结构定位

代码结构定位必须优先使用 CodeGraph。若仓库根目录没有 `.codegraph/`，先在仓库根目录执行
`codegraph init .`；索引变化后执行 `codegraph sync`，需要完整重建时执行
`codegraph index .`。优先使用 `codegraph explore`、`codegraph node` 和
`codegraph files`。

只有 CodeGraph CLI 不可用或初始化失败时，才记录失败原因并使用 `rg` 或直接阅读文件作为
后备；不得把未运行 CodeGraph 的结果表述为 CodeGraph 证据。

## 业务流优先的宿主修复治理

[业务流优先的宿主修复治理政策](docs/superpowers/governance/business-first-host-repair-policy.md)
是本仓库相关治理的**唯一活跃正文**。涉及 Common、宿主修复、双轨版本、业务流验收、证据与
流程脚本时，必须以该政策为准；不得用提交元数据、离线模型、未知状态或跨宿主联合机制替代宿主
真实用户业务流。历史设计仅用于理解已有材料，不再产生新的治理要求。

## 禁止 GitHub Actions

本仓库禁用 GitHub Actions，不得把它用于 CI、验收门禁或原生平台证据。不得新增
`.github/workflows/`、启用 Actions 或派发 workflow。构建、测试、架构和治理命令必须在
本地原生宿主运行；宿主不可用时，只记录该宿主未运行，不得伪造真实通过。

## 文档语言

新建或新增内容的仓库文档，主要自然语言统一使用中文。标题、背景、设计、任务、状态、验收
结论和说明文字都应使用中文；必要的技术术语、产品名、缩写和稳定标识可以保留原文。

代码标识符、文件路径、命令、配置键、协议字面量、API 名称、测试原始输出、上游原文引用，
以及历史机器 JSON 不要求翻译。

## Architecture JSON 本地验收

Architecture JSON CRUD 验收必须先让以下命令成功：

`python3 -m tools.architecture_json doctor --require mutate`

macOS 使用依赖完整的 Conda `base` 环境：

~~~bash
/opt/anaconda3/bin/conda run -n base \
  python3 -m tools.architecture_json doctor --require mutate
/opt/anaconda3/bin/conda run -n base \
  python3 -m unittest discover \
    -s tests/tooling \
    -p 'test_architecture_json_*.py' \
    -v
~~~

不得把 doctor 失败且大量测试被 skip 的解释器结果判定为绿色。工具自身不得安装依赖；每个
本地宿主负责提供文档要求的依赖环境。
