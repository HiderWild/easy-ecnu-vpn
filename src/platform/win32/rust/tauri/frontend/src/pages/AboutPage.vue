<script setup lang="ts">
import { inject, onMounted, ref } from "vue";

import {
  CORE_CONFIG_GATEWAY_KEY,
  createCoreConfigGateway,
  isCoreConfigKey,
  type CoreConfigGateway,
} from "../product/core-config";
import { PRODUCT_VERSION } from "../product/version";

/** 关于页（左侧栏独立入口；与设置/日志并列）。品牌展示（图标/应用名/副标题/版本/作者/仓库）
 * + 更新日志（第一项默认展开）+ 未知核心配置只读。 */

const props = defineProps<{ gateway?: CoreConfigGateway }>();

const injectedGateway = inject(CORE_CONFIG_GATEWAY_KEY, null);
const gateway = props.gateway ?? injectedGateway ?? createCoreConfigGateway();
const otherItems = ref<ReadonlyArray<{ key: string; value: string }>>([]);
const loadError = ref<string | null>(null);

onMounted(async () => {
  try {
    const items = await gateway.configGet();
    otherItems.value = items.filter((item) => !isCoreConfigKey(item.key));
  } catch {
    loadError.value = "暂时无法读取配置。";
  }
});

/** 产品作者与项目仓库（继承 C++ 产品线 distribution/ecnu.json 的身份信息）。 */
const AUTHOR = "HiderWild";
const REPOSITORY_LABEL = "HiderWild/exv-ecnuvpn";
const REPOSITORY_URL = "https://github.com/HiderWild/exv-ecnuvpn/";

/**
 * 打开外部浏览器：优先走 Tauri `open_external` 命令（WebView2 会拦截 window.open）；
 * 命令不可用时回退到 window.open。
 */
async function openRepository() {
  const url = REPOSITORY_URL;
  try {
    const { invoke } = await import("@tauri-apps/api/core");
    await invoke("open_external", { url });
    return;
  } catch {
    // 命令不可用（独立预览/测试环境）时回退到浏览器窗口打开。
  }
  window.open(url, "_blank", "noopener,noreferrer");
}

/** 版本更新日志（继承 C++ 产品线 webui/src/data/changelog.ts 的历史条目，最前补当前版本）。 */
export interface ChangelogEntry {
  version: string;
  dateLabel: string;
  inferred?: boolean;
  highlights: string[];
}

const CHANGELOG_ENTRIES: ChangelogEntry[] = [
  {
    version: "4.0.0",
    dateLabel: "2026-08-25",
    highlights: [
      "使用 Rust 完全重构，重组业务流和架构设计。",
      "原生 UI、Core 与 Engine 全链路接线，提供连接、设置、日志与关于等核心页面。",
      "重构后的连接路径将连接延迟最高降低 82%。",
    ],
  },
  {
    version: "3.3.7",
    dateLabel: "2026-07-06",
    highlights: [
      "连接成功后如果 service 或 oneshot helper 被终止，核心会回收连接 attempt 与 active tunnel guard，避免下一次连接被误判为仍在进行。",
      "连接创建期间 helper 意外退出时，vpn.connect 会识别本进程的 PreparingHelper 残留并自动重试，避免继续报 Helper connection could not be established。",
      "重连恢复期间即使 helper 状态仍显示 connected，只要存在旧 session 或 CoreLease 残留，也会清理同进程连接守卫并允许用户重试。",
      "已连接后 helper 控制管道断开时只标记服务不可用，不再把 Helper control pipe disconnected during VPN session 当作阻塞错误弹窗。",
      "连接过程中 CoreLease 或 helper 控制面先降级、但 native 数据面随后成功时，核心会清理控制面旧错误，不再在已连接状态弹出 Helper control pipe disconnected during VPN session。",
      "修复旧 helper 重连失败晚到时覆盖新连接成功状态的问题，已连接后会清除过期错误模态。",
      "重连启动前会向当前 helper 验证旧 CoreLease，helper 已重启时会重新获取租约，避免连接已恢复却弹出 empty session_id 错误。",
      "核心状态汇聚层会在 controller 已连接时清理或抑制迟到的连接失败，并等待已接受启动的 helper service 真正可用后再判定结果。",
      "vpn.connect 遇到同进程 stale guard 时会先核对本地 runtime 终止态，清理成功后自动重试一次。",
      "修正启动重置发布空闲状态时误释放 active tunnel guard 的竞态，避免 oneshot 重连前的资源守卫被提前清掉。",
      "修复 helper 被结束后旧重连 controller 与用户重试并行的竞态，避免重试已成功却因核心 RPC transport 关闭继续弹错。",
      "补充 helper 生命周期 reconcile 与连接 attempt retry 日志，便于定位服务被结束、管道断开和重连被阻塞的原因。",
    ],
  },
  {
    version: "3.3.6",
    dateLabel: "2026-06-28",
    highlights: [
      "完善 oneshot 与持久 helper 的断开清理，释放连接事务和 CoreLease，避免快速重连时复用到旧状态。",
      "优化服务安装、卸载和修复路径，正在连接时先给出确认并统一走断开流程。",
      "修复 A/B 类私有路由开关未勾选时仍可能应用宽网段路由的问题。",
      "加速空闲态服务维护路径，减少不必要的连接准备等待。",
    ],
  },
  {
    version: "3.3.5",
    dateLabel: "2026-06-28",
    highlights: [
      "刷新主仪表盘布局和浅色主题默认强调色，提升状态扫描和视觉层次。",
      "增加托盘状态快照、静默启动和后台断开能力，窗口不再被无谓唤起。",
      "强化 helper service / oneshot 生命周期守卫，改进健康检查和意外断开恢复。",
      "统一密码显示、保存密码覆盖提示和快速设置连接前应用顺序。",
      "补齐 Windows helper 稳定安装目录中的 Wintun 运行时文件。",
    ],
  },
  {
    version: "3.3.4",
    dateLabel: "2026-06-26",
    inferred: true,
    highlights: [
      "引入 helper 单实例保护和固定 oneshot endpoint，降低多实例漂移风险。",
      "拆分 helper 控制、隧道和维护 lane，让高权限操作和连接事务互不阻塞。",
      "把服务安装、卸载和修复改为 runas 启动路径，减少 daemon 内部特权操作。",
      "清理旧的 session handoff 链路，为后续 helper 重用和退出清理打基础。",
    ],
  },
  {
    version: "3.3.3",
    dateLabel: "2026-06-23",
    highlights: [
      "新增标准 macOS EXV.app 包结构，可拖入 Applications 后直接启动。",
      "让 macOS 包内资源使用相对路径解析，减少安装路径和工作目录差异带来的问题。",
      "完善 macOS 打包校验、Info.plist 版本信息和构建文档。",
    ],
  },
  {
    version: "3.3.2",
    dateLabel: "2026-06-21",
    highlights: [
      "提供 Windows x64 installer 和 portable zip，并加入发布打包脚本。",
      "改进 helper service 重新安装、卸载、修复和快捷方式清理流程。",
      "增强配置导入导出、Quick Start 和 minimal mode 对话框体验。",
      "禁用 WebView 缩放手势，减少误触导致的界面比例变化。",
    ],
  },
  {
    version: "3.3.1",
    dateLabel: "2026-06-19",
    inferred: true,
    highlights: [
      "拆分连接意图、原生握手、认证交互和 packet attach 阶段，让连接建立流程更清晰可恢复。",
      "引入固定 RPC lane 调度和异步 host message 处理，避免 UI 与核心动作互相阻塞。",
      "修复真实 VPN 连接链路中的认证提示、状态探测和 Windows core IPC 探测问题。",
      "加强连接 pipeline 的回归测试和平台 readiness 快照。",
    ],
  },
  {
    version: "3.3.0",
    dateLabel: "2026-06-16",
    highlights: [
      "完成从命令行版本到带 UI 桌面版本的主要转向，建立原生 WebView shell 与前端渲染输出。",
      "实现 Windows WebView2、macOS WKWebView 和 Linux WebKitGTK shell 基础设施。",
      "建立 UI shell 与 core RPC 的消息桥、版本身份和生命周期注册机制。",
      "退役 Electron 生产打包路径，统一走原生 WebView 包结构。",
    ],
  },
];
</script>

<template>
  <section class="about-page" aria-labelledby="about-title">
    <header class="about-hero">
      <img class="about-logo" src="../assets/exv-logo.svg" alt="EXV 产品 Logo" />
      <div class="about-hero__text">
        <h1 id="about-title">EXV</h1>
        <p class="about-subtitle">for ECNU</p>
      </div>
    </header>

    <div class="about-card">
      <dl class="about-facts">
        <div class="about-fact">
          <dt>版本</dt>
          <dd data-testid="about-version">{{ PRODUCT_VERSION }}</dd>
        </div>
        <div class="about-fact">
          <dt>作者</dt>
          <dd data-testid="about-author">{{ AUTHOR }}</dd>
        </div>
        <div class="about-fact">
          <dt>项目仓库</dt>
          <dd>
            <a
              class="about-repo"
              data-testid="about-repository"
              :href="REPOSITORY_URL"
              rel="noopener noreferrer"
              @click.prevent="openRepository"
            >
              <svg class="about-repo__icon" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
              <span class="about-repo__label">{{ REPOSITORY_LABEL }}</span>
            </a>
          </dd>
        </div>
      </dl>

      <details class="about-changelog" data-testid="about-changelog" open>
        <summary class="about-changelog__summary">
          <span>更新日志</span>
          <span class="about-changelog__count">{{ CHANGELOG_ENTRIES.length }} 个版本</span>
        </summary>
        <div class="about-changelog__list">
          <details
            v-for="(entry, index) in CHANGELOG_ENTRIES"
            :key="entry.version"
            class="about-changelog__entry"
            :open="index === 0"
          >
            <summary class="about-changelog__entry-summary">
              <span class="about-changelog__entry-head">
                <span class="about-changelog__entry-version">v{{ entry.version }}</span>
                <span v-if="entry.inferred" class="about-changelog__badge">历史归纳</span>
              </span>
              <span class="about-changelog__entry-date">{{ entry.dateLabel }}</span>
            </summary>
            <ul class="about-changelog__highlights">
              <li v-for="highlight in entry.highlights" :key="highlight">
                {{ highlight }}
              </li>
            </ul>
          </details>
        </div>
      </details>

      <div v-if="otherItems.length" class="about-advanced" data-testid="about-advanced">
        <h2>其它配置（只读）</h2>
        <div class="readonly-list">
          <div v-for="item in otherItems" :key="item.key" class="readonly-row">
            <span>{{ item.key }}</span><span>{{ item.value }}</span>
          </div>
        </div>
      </div>
      <p v-else-if="loadError" class="about-state">{{ loadError }}</p>
    </div>
  </section>
</template>

<style scoped>
.about-page { min-width: 0; }
.about-hero { display: flex; align-items: center; gap: var(--space-4); margin-top: var(--product-page-top-gap); margin-bottom: var(--space-5); }
.about-logo { width: 64px; height: 64px; flex: none; }
.about-hero__text h1 { margin: 0 0 var(--space-1); font-size: clamp(22px, 2.2vw, 30px); letter-spacing: -0.02em; }
.about-hero__text p { margin: 0; color: var(--text-secondary); font-size: 14px; }
.about-card { padding: var(--space-5); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); background: var(--surface-panel); }
.about-facts { display: grid; gap: var(--space-2); margin: 0 0 var(--space-3); }
.about-fact { display: grid; grid-template-columns: minmax(0, 0.95fr) minmax(0, 1.05fr); gap: var(--space-2); align-items: baseline; min-width: 0; }
.about-fact dt { color: var(--text-secondary); font-size: 13px; }
.about-fact dd { margin: 0; min-width: 0; overflow-wrap: anywhere; color: var(--text-primary); font-size: 14px; font-variant-numeric: tabular-nums; text-align: right; }
.about-repo {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  color: var(--text-primary);
  font-weight: 600;
  text-decoration: none;
  transition:
    border-color var(--motion-fast) var(--motion-ease),
    color var(--motion-fast) var(--motion-ease);
}
.about-repo:hover { border-color: var(--accent); color: var(--accent); text-decoration: none; }
.about-repo__icon { width: 16px; height: 16px; flex: none; }
.about-repo__label { min-width: 0; overflow-wrap: anywhere; }
.about-changelog { margin: 0 0 var(--space-3); border-top: 1px solid var(--border-subtle); padding-top: var(--space-3); }
.about-changelog__summary { display: flex; align-items: center; justify-content: space-between; gap: var(--space-2); color: var(--text-primary); font-size: 14px; font-weight: 600; cursor: pointer; }
.about-changelog__count { color: var(--text-secondary); font-size: 12px; font-weight: 400; }
.about-changelog__list { display: grid; gap: var(--space-2); margin-top: var(--space-2); }
.about-changelog__entry { border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: var(--space-2) var(--space-3); }
.about-changelog__entry-summary {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-2);
  cursor: pointer;
}
.about-changelog__entry-head { display: flex; align-items: center; gap: var(--space-2); min-width: 0; }
.about-changelog__entry-version { color: var(--text-primary); font-size: 14px; font-weight: 600; white-space: nowrap; }
.about-changelog__badge { border: 1px solid var(--border-subtle); border-radius: 999px; padding: 0 6px; color: var(--text-secondary); font-size: 11px; line-height: 18px; white-space: nowrap; }
.about-changelog__entry-date { color: var(--text-secondary); font-size: 12px; white-space: nowrap; }
.about-changelog__highlights { margin: var(--space-2) 0 0; padding: var(--space-2) 0 0 var(--space-4); border-top: 1px solid var(--border-subtle); color: var(--text-secondary); font-size: 13px; line-height: 1.6; }
.about-changelog__highlights li { margin: var(--space-1) 0; }
.about-advanced h2 { margin: 0 0 var(--space-2); font-size: 15px; }
.readonly-list { display: grid; gap: 0; }
.readonly-row { display: flex; align-items: center; justify-content: space-between; gap: var(--space-3); min-height: 36px; color: var(--text-secondary); font-size: 13px; }
.readonly-row span:last-child { color: var(--text-primary); font-weight: 600; text-align: right; }
.about-state { margin: 0; color: var(--text-secondary); font-size: 13px; }
</style>
