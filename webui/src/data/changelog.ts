export interface ChangelogEntry {
  version: string
  title: string
  dateLabel: string
  inferred?: boolean
  highlights: string[]
}

export const changelogEntries: ChangelogEntry[] = [
  {
    version: '3.3.7',
    title: 'helper 断开后的连接恢复',
    dateLabel: '2026-07-06',
    highlights: [
      '连接成功后如果 service 或 oneshot helper 被终止，核心会回收连接 attempt 与 active tunnel guard，避免下一次连接被误判为仍在进行。',
      '连接创建期间 helper 意外退出时，vpn.connect 会识别本进程的 PreparingHelper 残留并自动重试，避免继续报 Helper connection could not be established。',
      '重连恢复期间即使 helper 状态仍显示 connected，只要存在旧 session 或 CoreLease 残留，也会清理同进程连接守卫并允许用户重试。',
      '已连接后 helper 控制管道断开时只标记辅助服务不可用，不再把 Helper control pipe disconnected during VPN session 当作阻塞错误弹窗。',
      '连接过程中 CoreLease 或 helper 控制面先降级、但 native 数据面随后成功时，核心会清理控制面旧错误，不再在已连接状态弹出 Helper control pipe disconnected during VPN session。',
      '修复旧 helper 重连失败晚到时覆盖新连接成功状态的问题，已连接后会清除过期错误模态。',
      '重连启动前会向当前 helper 验证旧 CoreLease，helper 已重启时会重新获取租约，避免连接已恢复却弹出 empty session_id 错误。',
      '核心状态汇聚层会在 controller 已连接时清理或抑制迟到的连接失败，并等待已接受启动的 helper service 真正可用后再判定结果。',
      'vpn.connect 遇到同进程 stale guard 时会先核对本地 runtime 终止态，清理成功后自动重试一次。',
      '修正启动重置发布空闲状态时误释放 active tunnel guard 的竞态，避免 oneshot 重连前的资源守卫被提前清掉。',
      '修复 helper 被结束后旧重连 controller 与用户重试并行的竞态，避免重试已成功却因核心 RPC transport 关闭继续弹错。',
      '补充 helper 生命周期 reconcile 与连接 attempt retry 日志，便于定位服务被结束、管道断开和重连被阻塞的原因。',
    ],
  },
  {
    version: '3.3.6',
    title: '连接清理与服务维护稳定性',
    dateLabel: '2026-06-28',
    highlights: [
      '完善 oneshot 与持久 helper 的断开清理，释放连接事务和 CoreLease，避免快速重连时复用到旧状态。',
      '优化服务安装、卸载和修复路径，正在连接时先给出确认并统一走断开流程。',
      '修复 A/B 类私有路由开关未勾选时仍可能应用宽网段路由的问题。',
      '加速空闲态服务维护路径，减少不必要的连接准备等待。',
    ],
  },
  {
    version: '3.3.5',
    title: '仪表盘、托盘与 helper 生命周期体验',
    dateLabel: '2026-06-28',
    highlights: [
      '刷新主仪表盘布局和浅色主题默认强调色，提升状态扫描和视觉层次。',
      '增加托盘状态快照、静默启动和后台断开能力，窗口不再被无谓唤起。',
      '强化 helper service / oneshot 生命周期守卫，改进健康检查和意外断开恢复。',
      '统一密码显示、保存密码覆盖提示和快速设置连接前应用顺序。',
      '补齐 Windows helper 稳定安装目录中的 Wintun 运行时文件。',
    ],
  },
  {
    version: '3.3.4',
    title: 'helper 架构简化与服务操作过渡',
    dateLabel: '2026-06-26',
    inferred: true,
    highlights: [
      '引入 helper 单实例保护和固定 oneshot endpoint，降低多实例漂移风险。',
      '拆分 helper 控制、隧道和维护 lane，让高权限操作和连接事务互不阻塞。',
      '把服务安装、卸载和修复改为 runas 启动路径，减少 daemon 内部特权操作。',
      '清理旧的 session handoff 链路，为后续 helper 重用和退出清理打基础。',
    ],
  },
  {
    version: '3.3.3',
    title: 'macOS 原生 WebView 应用包',
    dateLabel: '2026-06-23',
    highlights: [
      '新增标准 macOS EXV.app 包结构，可拖入 Applications 后直接启动。',
      '让 macOS 包内资源使用相对路径解析，减少安装路径和工作目录差异带来的问题。',
      '完善 macOS 打包校验、Info.plist 版本信息和构建文档。',
    ],
  },
  {
    version: '3.3.2',
    title: 'Windows 安装包与服务维护',
    dateLabel: '2026-06-21',
    highlights: [
      '提供 Windows x64 installer 和 portable zip，并加入发布打包脚本。',
      '改进 helper service 重新安装、卸载、修复和快捷方式清理流程。',
      '增强配置导入导出、Quick Start 和 minimal mode 对话框体验。',
      '禁用 WebView 缩放手势，减少误触导致的界面比例变化。',
    ],
  },
  {
    version: '3.3.1',
    title: '连接建立流程解耦与真实链路修复',
    dateLabel: '2026-06-19',
    inferred: true,
    highlights: [
      '拆分连接意图、原生握手、认证交互和 packet attach 阶段，让连接建立流程更清晰可恢复。',
      '引入固定 RPC lane 调度和异步 host message 处理，避免 UI 与核心动作互相阻塞。',
      '修复真实 VPN 连接链路中的认证提示、状态探测和 Windows core IPC 探测问题。',
      '加强连接 pipeline 的回归测试和平台 readiness 快照。',
    ],
  },
  {
    version: '3.3.0',
    title: '从 CLI 转向原生 UI 桌面版',
    dateLabel: '2026-06-16',
    highlights: [
      '完成从命令行版本到带 UI 桌面版本的主要转向，建立原生 WebView shell 与前端渲染输出。',
      '实现 Windows WebView2、macOS WKWebView 和 Linux WebKitGTK shell 基础设施。',
      '建立 UI shell 与 core RPC 的消息桥、版本身份和生命周期注册机制。',
      '退役 Electron 生产打包路径，统一走原生 WebView 包结构。',
    ],
  },
]
