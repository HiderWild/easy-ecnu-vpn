<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, ref, watch } from "vue";

import RoutesModal from "../components/RoutesModal.vue";
import ServicePanel from "../components/ServicePanel.vue";
import SettingsRow from "../components/SettingsRow.vue";
import SettingsSectionAxis from "../components/SettingsSectionAxis.vue";
import { pushToast } from "../lib/toast";
import { APPEARANCE_KEY, type Appearance } from "../product/appearance";
import { PRODUCT_RUNTIME_KEY, type ProductRuntime } from "../product/runtime";
import {
  CORE_CONFIG_FIELDS,
  CORE_CONFIG_GATEWAY_KEY,
  createCoreConfigGateway,
  isCoreConfigKey,
  isVpnServerPreset,
  normalizeCoreConfigValue,
  normalizeServerValue,
  VPN_SERVERS,
  type CoreConfigGateway,
  type CoreConfigKey,
} from "../product/core-config";
import {
  activeSection,
  drafts,
  feedback,
  items,
  loadedOnce,
  loadError,
  loading,
  original,
  saving,
} from "../product/settings-state";
import {
  CLOSE_PREFERENCE_LABELS,
  editUiPreference,
  loadUiPreferences,
  uiPrefsDirty,
  uiPrefsDraft,
  updateUiPreferences,
} from "../product/ui-prefs";

const props = defineProps<{
  gateway?: CoreConfigGateway;
  appearance?: Appearance;
}>();

const injectedAppearance = inject(APPEARANCE_KEY, null);
const resolvedAppearance = props.appearance ?? injectedAppearance;
if (resolvedAppearance === null) throw new Error("设置页需要本地外观状态。");
const appearance: Appearance = resolvedAppearance;

const injectedGateway = inject(CORE_CONFIG_GATEWAY_KEY, null);
const gateway = props.gateway ?? injectedGateway ?? createCoreConfigGateway();
const runtime = inject(PRODUCT_RUNTIME_KEY, null) as ProductRuntime | null;
// 状态来自模块级 store（内存持久化：切页重挂载不丢草稿/浏览位置，不重新读取覆盖）。

/** 分区标题（≤2 字，滚动轴与页内 h2 共用文案；icon 为滚动轴常显图标的键）。 */
const sections = [
  { id: "connection", label: "连接", icon: "connection" },
  { id: "startup", label: "功能", icon: "startup" },
  { id: "appearance", label: "外观", icon: "appearance" },
  { id: "diagnostics", label: "通知", icon: "diagnostics" },
  { id: "experimental", label: "实验性", icon: "experimental" },
] as const;

/** 连接与网络分栏：core 配置中留在本栏的字段（user_agent / mtu 迁入实验性）。 */
const CONNECTION_KEYS: readonly CoreConfigKey[] = [
  "server",
  "username",
  "password",
  "remember_password",
  "routes",
  "auto_reconnect",
  "auto_reconnect_max_attempts",
];

const accents = [
  { id: "azure", label: "蔚蓝" },
  { id: "violet", label: "紫罗兰" },
  { id: "jade", label: "青玉" },
  { id: "amber", label: "琥珀" },
] as const;

const knownFields = computed(() =>
  CORE_CONFIG_FIELDS.filter((field) => Object.prototype.hasOwnProperty.call(drafts.value, field.key)),
);

function fieldDraft(key: CoreConfigKey): string {
  return drafts.value[key] ?? "";
}

/** 渲染用字段：密码行仅在「记住密码」勾选时展示（未勾选无从编辑已保存密码）。 */
const visibleFields = computed(() =>
  knownFields.value.filter(
    (field) => field.key !== "password" || drafts.value["remember_password"] === "true",
  ),
);

const connectionFields = computed(() =>
  visibleFields.value.filter(
    (field) =>
      (CONNECTION_KEYS as readonly string[]).includes(field.key) ||
      field.key === "password",
  ).filter(
    (field) => field.key !== "auto_reconnect_max_attempts" || drafts.value.auto_reconnect === "true",
  ),
);

function experimentalDraft(key: "mtu" | "user_agent"): string {
  return fieldDraft(key);
}

function updateText(key: CoreConfigKey, event: Event): void {
  drafts.value[key] = (event.target as HTMLInputElement).value;
  feedback.value[key] = undefined;
}

function updateBoolean(key: CoreConfigKey, event: Event): void {
  drafts.value[key] = (event.target as HTMLInputElement).checked ? "true" : "false";
  feedback.value[key] = undefined;
}

/**
 * VPN 服务器下拉：预设地址或「自定义」。
 * 初始按草稿归一（命中预设选预设，否则自定义）；用户显式切换用 serverChoice 覆盖；
 * 手填命中预设时归一回到预设项（与旧 C++ applyServerChoice 一致）。
 */
function deriveServerChoice(): string {
  const value = normalizeServerValue(drafts.value.server ?? "");
  return isVpnServerPreset(value) ? value : "custom";
}

const serverChoice = ref(deriveServerChoice());

watch(
  () => drafts.value.server,
  () => {
    serverChoice.value = deriveServerChoice();
  },
);

/** 下拉切换：选预设直接写回草稿；选「自定义」保留当前值交由文本框续编辑。 */
function onServerChoiceChange(event: Event): void {
  const value = (event.target as HTMLSelectElement).value;
  feedback.value.server = undefined;
  serverChoice.value = value;
  if (value !== "custom") drafts.value.server = value;
}

/** 自动重连次数输入框仅在自动重连开关开启时可设置。 */
function reconnectAttemptsDisabled(): boolean {
  return drafts.value.auto_reconnect !== "true";
}

/** 路由编辑模态开关（路由行只展示条目数 + 修改按钮，编辑在模态内完成）。 */
const routesModalOpen = ref(false);

/** 当前 routes 草稿拆分为条目列表（逗号分隔）。 */
const routesList = computed(() =>
  (drafts.value.routes ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean),
);

const routesSummary = computed(() => `${routesList.value.length} 条路由`);

/**
 * 路由模态保存：立即单独提交 routes（与 saveAll 同一条 configSet 出口），
 * 不进入设置页草稿/脏状态（成功后同步 drafts 与 original，页面不出现「保存设置」）。
 */
async function onRoutesSave(routes: string[]): Promise<void> {
  routesModalOpen.value = false;
  const value = routes.join(",");
  try {
    const saved = await gateway.configSet([{ key: "routes", value }]);
    if (!saved) {
      pushToast("路由保存失败。", "error");
      return;
    }
    drafts.value.routes = value;
    original.value.routes = value;
    feedback.value.routes = undefined;
    pushToast("路由已保存。", "success");
  } catch {
    pushToast("路由保存失败。", "error");
  }
}

async function load(): Promise<void> {
  loading.value = true;
  loadError.value = null;
  feedback.value = {};
  try {
    const nextItems = await gateway.configGet();
    const nextDrafts: Record<string, string> = {};
    for (const item of nextItems) if (isCoreConfigKey(item.key)) nextDrafts[item.key] = item.value;
    // 密码是 AES-GCM 密文 blob，core 不回显：始终以空起始，由用户显式输入新密码。
    if (!("password" in nextDrafts)) nextDrafts["password"] = "";
    items.value = nextItems;
    drafts.value = nextDrafts;
    original.value = { ...nextDrafts };
    loadedOnce.value = true;
  } catch {
    items.value = [];
    drafts.value = {};
    original.value = {};
    loadError.value = "暂时无法读取核心配置。";
  } finally {
    loading.value = false;
    // 内容加载完成后高度变化，重新定位当前分区。
    requestAnimationFrame(updateActiveSectionFromScroll);
  }
}

/** core 配置是否存在未保存的修改。 */
const isCoreDirty = computed(() =>
  knownFields.value.some((field) => {
    const raw = drafts.value[field.key] ?? "";
    const loaded = original.value[field.key] ?? "";
    return raw !== loaded;
  }),
);

/**
 * 页顶单一「保存设置」入口：解析全部脏修改并分流应用——
 *   * core 配置键 → configSet（批量）；
 *   * 前端偏好键 → 注册表 + ui-preferences 文件。
 * 校验错误内联显示在字段旁；成功/失败走 toast。
 */
async function saveAll(): Promise<void> {
  if (saving.value) return;

  // 分流一：core 配置脏键。
  const pending: { key: CoreConfigKey; value: string }[] = [];
  for (const field of knownFields.value) {
    const raw = drafts.value[field.key] ?? "";
    if (raw === (original.value[field.key] ?? "")) continue;
    const normalized = normalizeCoreConfigValue(field.key, raw);
    if (!normalized.ok) {
      feedback.value[field.key] = normalized.message;
      return; // 校验错误内联；不提交
    }
    pending.push({ key: field.key, value: normalized.value });
  }

  // 分流二：前端偏好草稿（可能为空）。
  const hasPrefChanges = uiPrefsDirty.value;

  if (pending.length === 0 && !hasPrefChanges) return;

  saving.value = true;
  let coreOk = true;
  try {
    if (pending.length > 0) {
      const saved = await gateway.configSet(pending);
      if (!saved) {
        coreOk = false;
      }
    }
    if (!coreOk) {
      pushToast("保存失败。", "error");
      return;
    }
    for (const item of pending) {
      drafts.value[item.key] = item.value;
      original.value[item.key] = item.value;
      feedback.value[item.key] = undefined;
    }
    // 前端偏好保存失败时内部已回滚并 toast；此处不再覆盖其消息。
    const prefsOk = hasPrefChanges ? await updateUiPreferences() : true;
    if (prefsOk) {
      pushToast("设置已保存。", "success");
    }
  } catch {
    pushToast("保存失败。", "error");
  } finally {
    saving.value = false;
  }
}

function selectSection(id: string): void {
  if (!sections.some((section) => section.id === id)) return;
  activeSection.value = id;
  const target = sectionElements.get(id) ?? document.getElementById(`settings-${id}`);
  target?.scrollIntoView({
    behavior: appearance.state.value.motion === "reduced" ? "auto" : "smooth",
    block: "start",
  });
}

/**
 * 滚动位置观察（替代窄横带相交观察策略，修复滑块抽动与最后分区卡位）：
 *   * 单调判定：检测线（滚动容器顶部 + SECTION_READ_OFFSET）之上「最靠后」的分区为当前分区，
 *     分区滑过检测线才切换一次，不再随相交比来回抖动；
 *   * 底部回退：滚动到底时强制激活最后分区，短内容分区（实验性）也能命中。
 */
const SECTION_READ_OFFSET = 88;
const BOTTOM_EPSILON = 4;
const pageRoot = ref<HTMLElement | null>(null);
let scrollContainer: HTMLElement | null = null;
/** 分区元素缓存：挂载时从组件根收集（不依赖全局 document 查询，便于独立挂载测试）。 */
const sectionElements = new Map<string, HTMLElement>();

function collectSectionElements(): void {
  sectionElements.clear();
  const root = pageRoot.value;
  if (!root) return;
  for (const section of sections) {
    const element = root.querySelector<HTMLElement>(`#settings-${section.id}`);
    if (element) sectionElements.set(section.id, element);
  }
}

/** 解析实际滚动容器：设置页两分区后，内容在 .settings-page__layout 内滚动；
 *  独立环境（测试/预览）回退到滚动祖先/文档根。 */
function resolveScrollContainer(): HTMLElement | null {
  const inner = pageRoot.value?.querySelector<HTMLElement>(".settings-page__layout");
  if (inner) return inner;
  const host = document.querySelector<HTMLElement>(".product-content--scrollable");
  if (host) return host;
  let node: HTMLElement | null = pageRoot.value?.parentElement ?? null;
  while (node) {
    const overflowY = window.getComputedStyle(node).overflowY;
    if (overflowY === "auto" || overflowY === "scroll") return node;
    node = node.parentElement;
  }
  return document.scrollingElement as HTMLElement | null;
}

function setActiveSection(id: string): void {
  if (sections.some((section) => section.id === id)) activeSection.value = id;
}

function updateActiveSectionFromScroll(): void {
  const container = scrollContainer;
  if (!container) return;
  const { scrollTop, clientHeight, scrollHeight } = container;
  // 测量未就绪或内容不可滚动：不做判定，保持当前分区。
  if (clientHeight <= 0 || scrollHeight <= clientHeight) return;
  if (scrollTop + clientHeight >= scrollHeight - BOTTOM_EPSILON) {
    setActiveSection(sections[sections.length - 1].id);
    return;
  }
  const readLine = container.getBoundingClientRect().top + SECTION_READ_OFFSET;
  let current: string = sections[0].id;
  for (const section of sections) {
    const element = sectionElements.get(section.id);
    if (element && element.getBoundingClientRect().top <= readLine) current = section.id;
    else break;
  }
  setActiveSection(current);
}

function bindScrollTracking(): void {
  scrollContainer = resolveScrollContainer();
  if (!scrollContainer) return;
  scrollContainer.addEventListener("scroll", updateActiveSectionFromScroll, { passive: true });
  window.addEventListener("resize", updateActiveSectionFromScroll);
  requestAnimationFrame(updateActiveSectionFromScroll);
}

function unbindScrollTracking(): void {
  if (!scrollContainer) return;
  scrollContainer.removeEventListener("scroll", updateActiveSectionFromScroll);
  window.removeEventListener("resize", updateActiveSectionFromScroll);
  scrollContainer = null;
}

onMounted(() => {
  collectSectionElements();
  void loadUiPreferences();
  if (loadedOnce.value) {
    // 从其它页切回：不重新读取（保留草稿/浏览位置），恢复滚动到上次分区锚点。
    requestAnimationFrame(() => {
      const target = sectionElements.get(activeSection.value) ?? document.getElementById(`settings-${activeSection.value}`);
      target?.scrollIntoView({ block: "start" });
    });
  } else {
    void load();
  }
  bindScrollTracking();
});

onUnmounted(() => unbindScrollTracking());
</script>

<template>
  <section ref="pageRoot" class="settings-page" aria-labelledby="settings-title">
    <header class="settings-page__header">
      <div>
        <h1 id="settings-title">设置</h1>
      </div>
      <button
        v-if="isCoreDirty || uiPrefsDirty"
        type="button"
        class="settings-save-all"
        data-testid="save-all-settings"
        :disabled="saving"
        @click="saveAll"
      >
        保存设置
      </button>
    </header>

    <div class="settings-page__layout" data-testid="settings-page-layout">
      <div class="settings-page__content">
        <section id="settings-connection" class="settings-section" data-testid="settings-connection">
          <header class="settings-section__header">
            <div><h2>连接</h2></div>
          </header>

          <div v-if="loading" class="settings-state">正在读取核心配置…</div>
          <div v-else-if="loadError" class="settings-state settings-state--error">
            <span>{{ loadError }}</span><button type="button" data-testid="retry-settings" @click="load">重试</button>
          </div>
          <template v-else>
            <div v-if="connectionFields.length" class="settings-fields-grid">
              <SettingsRow
                v-for="field in connectionFields"
                :key="field.key"
                :class="{ 'settings-row--dense': true, 'settings-row--wide': field.kind === 'routes' }"
                :label="field.label"
                :description="field.description"
                :data-testid="`setting-${field.key}`"
              >
                <div class="config-control">
                  <template v-if="field.kind === 'routes'">
                    <span class="routes-summary" data-testid="routes-summary">{{ routesSummary }}</span>
                    <button
                      type="button"
                      class="routes-edit-button"
                      data-testid="routes-edit"
                      @click="routesModalOpen = true"
                    >
                      修改
                    </button>
                  </template>
                  <div v-else-if="field.kind === 'server'" class="server-choice">
                    <select
                      class="settings-server-preference"
                      :data-testid="`input-${field.key}`"
                      :value="serverChoice"
                      :aria-label="field.label"
                      @change="onServerChoiceChange($event)"
                    >
                      <option v-for="server in VPN_SERVERS" :key="server.value" :value="server.value">{{ server.value }}</option>
                      <option value="custom">自定义</option>
                    </select>
                    <input
                      v-if="serverChoice === 'custom'"
                      :data-testid="`input-${field.key}-custom`"
                      type="text"
                      autocomplete="off"
                      :value="drafts[field.key] ?? ''"
                      :aria-label="`${field.label}（自定义）`"
                      @input="updateText(field.key, $event)"
                    >
                  </div>
                  <input
                    v-else-if="field.kind === 'number'"
                    :data-testid="`input-${field.key}`"
                    type="number"
                    min="0"
                    step="1"
                    autocomplete="off"
                    :value="drafts[field.key] ?? ''"
                    :aria-label="field.label"
                    :disabled="reconnectAttemptsDisabled()"
                    @input="updateText(field.key, $event)"
                  >
                  <input
                    v-else-if="field.kind !== 'boolean'"
                    :data-testid="`input-${field.key}`"
                    :type="field.kind === 'password' ? 'password' : 'text'"
                    :placeholder="field.kind === 'password' ? '留空保持已保存密码' : undefined"
                    autocomplete="off"
                    :value="drafts[field.key] ?? ''"
                    :aria-label="field.label"
                    @input="updateText(field.key, $event)"
                  >
                  <label v-else class="boolean-control">
                    <input
                      :data-testid="`input-${field.key}`"
                      type="checkbox"
                      :checked="drafts[field.key] === 'true'"
                      :aria-label="field.label"
                      @change="updateBoolean(field.key, $event)"
                    >
                    <span>{{ drafts[field.key] === "true" ? "开启" : "关闭" }}</span>
                  </label>
                  <span v-if="feedback[field.key]" :data-testid="`feedback-${field.key}`" class="config-feedback">{{ feedback[field.key] }}</span>
                </div>
              </SettingsRow>
            </div>
            <p v-else class="settings-state">暂无</p>
          </template>

        </section>

        <section id="settings-service" class="settings-service-section" data-testid="settings-service">
          <ServicePanel
            v-if="runtime !== null"
            :service="runtime.state.value.service"
            :auto-install="false"
            :busy="false"
            :show-connect-options="false"
            data-testid="settings-service-control"
          />
          <p v-else class="settings-state settings-service-section__unavailable">运行时不可用，无法管理服务。</p>
        </section>

        <section id="settings-startup" class="settings-section" data-testid="settings-startup">
           <header class="settings-section__header"><div><h2>功能</h2></div></header>
           <div class="settings-fields-grid settings-fields-grid--static">
            <SettingsRow class="settings-row--dense" label="开机自动运行" description="登录 Windows 后自动启动 EXV。">
              <label class="boolean-control">
                <input data-testid="ui-pref-launch_at_login" type="checkbox" :checked="uiPrefsDraft.launch_at_login" aria-label="开机自动运行" @change="editUiPreference('launch_at_login', ($event.target as HTMLInputElement).checked)">
                <span>{{ uiPrefsDraft.launch_at_login ? "开启" : "关闭" }}</span>
              </label>
            </SettingsRow>
            <SettingsRow class="settings-row--dense" label="启动静默" description="启动时不弹出主窗口，仅托盘驻留，可从托盘唤出。">
              <label class="boolean-control">
                <input data-testid="ui-pref-silent_startup" type="checkbox" :checked="uiPrefsDraft.silent_startup" aria-label="启动静默" @change="editUiPreference('silent_startup', ($event.target as HTMLInputElement).checked)">
                <span>{{ uiPrefsDraft.silent_startup ? "开启" : "关闭" }}</span>
              </label>
            </SettingsRow>
            <SettingsRow class="settings-row--dense" label="连接后最小化到托盘" description="连接成功后自动把主窗口最小化到托盘。">
              <label class="boolean-control">
                <input data-testid="ui-pref-minimize_to_tray_on_connect" type="checkbox" :checked="uiPrefsDraft.minimize_to_tray_on_connect" aria-label="连接后最小化到托盘" @change="editUiPreference('minimize_to_tray_on_connect', ($event.target as HTMLInputElement).checked)">
                <span>{{ uiPrefsDraft.minimize_to_tray_on_connect ? "开启" : "关闭" }}</span>
              </label>
            </SettingsRow>
            <SettingsRow class="settings-row--dense" label="启动时自动连接" description="应用启动且空闲时自动发起连接。">
              <label class="boolean-control">
                <input data-testid="ui-pref-auto_connect_on_launch" type="checkbox" :checked="uiPrefsDraft.auto_connect_on_launch" aria-label="启动时自动连接" @change="editUiPreference('auto_connect_on_launch', ($event.target as HTMLInputElement).checked)">
                <span>{{ uiPrefsDraft.auto_connect_on_launch ? "开启" : "关闭" }}</span>
              </label>
            </SettingsRow>
            <SettingsRow class="settings-row--dense" label="关闭按钮行为" description="点击窗口关闭按钮时的动作。">
              <select class="settings-close-preference" data-testid="ui-pref-close_preference" :value="uiPrefsDraft.close_preference" aria-label="关闭按钮行为" @change="editUiPreference('close_preference', ($event.target as HTMLSelectElement).value as 'smart' | 'tray' | 'quit')">
                <option value="smart">{{ CLOSE_PREFERENCE_LABELS.smart }}</option><option value="tray">{{ CLOSE_PREFERENCE_LABELS.tray }}</option><option value="quit">{{ CLOSE_PREFERENCE_LABELS.quit }}</option>
              </select>
            </SettingsRow>
           </div>
         </section>

        <section id="settings-appearance" class="settings-section" data-testid="settings-appearance">
          <header class="settings-section__header"><div><h2>外观</h2></div></header>
          <SettingsRow class="settings-row--dense" label="主题" description="跟随系统或固定为浅色、深色。">
            <select data-testid="appearance-theme" :value="appearance.state.value.theme" aria-label="主题" @change="appearance.setTheme(($event.target as HTMLSelectElement).value as 'system' | 'light' | 'dark')">
              <option value="system">跟随系统</option><option value="light">浅色</option><option value="dark">深色</option>
            </select>
          </SettingsRow>
          <SettingsRow class="settings-row--dense" label="强调色" description="用于主操作与当前状态，不改变语义颜色。">
            <div class="accent-options" role="group" aria-label="强调色">
              <button v-for="accent in accents" :key="accent.id" :data-testid="`appearance-accent-${accent.id}`" class="accent-option" :class="{ 'accent-option--active': appearance.state.value.accent === accent.id }" type="button" :aria-pressed="appearance.state.value.accent === accent.id" @click="appearance.setAccent(accent.id)">{{ accent.label }}</button>
            </div>
          </SettingsRow>
          <SettingsRow class="settings-row--dense" label="动效" description="减少动效会保留状态与文字，但停止循环视觉效果。">
            <select data-testid="appearance-motion" :value="appearance.state.value.motion" aria-label="动效" @change="appearance.setMotion(($event.target as HTMLSelectElement).value as 'normal' | 'reduced')">
              <option value="normal">正常</option><option value="reduced">减少动效</option>
            </select>
          </SettingsRow>
        </section>

        <section id="settings-diagnostics" class="settings-section" data-testid="settings-diagnostics">
          <header class="settings-section__header"><div><h2>通知</h2></div></header>
          <div class="settings-fields-grid settings-fields-grid--static">
            <SettingsRow class="settings-row--dense" label="建立连接时发送通知" description="连接成功建立后显示系统通知弹窗。">
              <label class="boolean-control">
                <input data-testid="ui-pref-connect_notify" type="checkbox" :checked="uiPrefsDraft.connect_notify" aria-label="建立连接时发送通知" @change="editUiPreference('connect_notify', ($event.target as HTMLInputElement).checked)">
                <span>{{ uiPrefsDraft.connect_notify ? "开启" : "关闭" }}</span>
              </label>
            </SettingsRow>
            <SettingsRow class="settings-row--dense" label="断开连接时发送通知" description="连接断开后显示系统通知弹窗。">
              <label class="boolean-control">
                <input data-testid="ui-pref-disconnect_notify" type="checkbox" :checked="uiPrefsDraft.disconnect_notify" aria-label="断开连接时发送通知" @change="editUiPreference('disconnect_notify', ($event.target as HTMLInputElement).checked)">
                <span>{{ uiPrefsDraft.disconnect_notify ? "开启" : "关闭" }}</span>
              </label>
            </SettingsRow>
            <SettingsRow class="settings-row--dense" label="触发重连时发送通知" description="触发重连时显示系统通知弹窗；仅在开启自动重连后真正生效。">
              <label class="boolean-control">
                <input data-testid="ui-pref-reconnect_notify" type="checkbox" :checked="uiPrefsDraft.reconnect_notify" aria-label="触发重连时发送通知" @change="editUiPreference('reconnect_notify', ($event.target as HTMLInputElement).checked)">
                <span>{{ uiPrefsDraft.reconnect_notify ? "开启" : "关闭" }}</span>
              </label>
            </SettingsRow>
            <SettingsRow class="settings-row--dense" label="窗口在前台时不发送通知" description="主窗口可见时无需发送连接类通知；优先级最高。">
              <label class="boolean-control">
                <input data-testid="ui-pref-suppress_notify_when_foreground" type="checkbox" :checked="uiPrefsDraft.suppress_notify_when_foreground" aria-label="窗口在前台时不发送通知" @change="editUiPreference('suppress_notify_when_foreground', ($event.target as HTMLInputElement).checked)">
                <span>{{ uiPrefsDraft.suppress_notify_when_foreground ? "开启" : "关闭" }}</span>
              </label>
            </SettingsRow>
          </div>
        </section>

        <section id="settings-experimental" class="settings-section settings-experimental" data-testid="settings-experimental">
          <header class="settings-section__header"><div><h2>实验性</h2></div></header>
          <p class="settings-state settings-experimental__notice" data-testid="experimental-notice">
            以下为高级选项：默认值已经过适配，<strong>推荐维持默认</strong>。修改可能导致连接异常或被服务端拒绝。
          </p>
          <div class="settings-fields-grid settings-fields-grid--static">
            <SettingsRow class="settings-row--dense" label="MTU" description="网络接口 MTU。默认值已适配校园网；非专业场景建议保持默认。">
              <input
                data-testid="input-mtu"
                inputmode="numeric"
                type="text"
                autocomplete="off"
                :value="experimentalDraft('mtu')"
                aria-label="MTU"
                @input="updateText('mtu', $event)"
              >
              <span v-if="feedback['mtu']" class="config-feedback">{{ feedback['mtu'] }}</span>
            </SettingsRow>
            <SettingsRow class="settings-row--dense" label="User-Agent" description="连接请求的客户端标识。修改可能导致服务端拒绝连接；建议保持默认。">
              <input
                data-testid="input-user_agent"
                type="text"
                autocomplete="off"
                :value="experimentalDraft('user_agent')"
                aria-label="User-Agent"
                @input="updateText('user_agent', $event)"
              >
              <span v-if="feedback['user_agent']" class="config-feedback">{{ feedback['user_agent'] }}</span>
            </SettingsRow>
          </div>
        </section>

      </div>

      <SettingsSectionAxis :sections="sections" :active-section="activeSection" @select="selectSection" />
    </div>

    <RoutesModal
      :routes="routesList"
      :open="routesModalOpen"
      @save="onRoutesSave"
      @close="routesModalOpen = false"
    />
  </section>
</template>

<style scoped>
.settings-page {
  min-width: 0;
  /* 两分区骨架：banner 固定顶部（flex:none），设置项在下方独立滚动容器内滚动。
     header 不随内容滚走、内容不从 header 旁穿帮。 */
  display: flex;
  flex-direction: column;
  height: 100%;
  min-height: 0;
  padding-top: var(--product-page-top-gap);
  --settings-header-height: 52px;
  --settings-select-width: 160px;
  /* 壳层 .product-content 已取消上下内边距；banner 直接落在内容顶部，不再被
     外层留白推离或被 overflow 裁剪。 */
  margin-top: 0;
}
.settings-page__header {
  display: flex;
  flex: none;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  height: var(--settings-header-height);
  margin: 0;
  padding: 0;
  /* 无圆角无缝隙：顶部完整横条，不设 border-bottom，与下方设置项容器自然衔接。 */
  background: var(--surface-canvas);
}
.settings-page__header h1 { margin-bottom: 0; font-size: clamp(22px, 2.2vw, 30px); letter-spacing: -0.02em; }
.settings-section__header p { margin-bottom: 0; color: var(--text-secondary); }
.settings-save-all { flex: none; min-height: 36px; padding: 6px 16px; margin-top: 0; border: 1px solid var(--accent); border-radius: var(--radius-md); background: var(--accent); color: var(--accent-on); font-size: 13px; font-weight: 600; cursor: pointer; }
.settings-save-all:hover:not(:disabled) { border-color: var(--accent-strong); background: var(--accent-strong); }
.settings-save-all:disabled { opacity: 0.6; cursor: default; }
.settings-page__layout {
  /* 内层独立滚动容器：banner 固定，设置项在此滚动（隐藏滚动条，复用外层无滚动条约定）。 */
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  scrollbar-width: none;
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: var(--space-5);
  align-items: start;
  padding-top: 0;
}
.settings-page__layout::-webkit-scrollbar { display: none; }
.settings-page__content {
  display: grid;
  gap: var(--space-4);
  min-width: 0;
  padding-bottom: var(--space-4);
}
.settings-section { scroll-margin-top: var(--space-5); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); padding: var(--space-4) var(--space-5); background: var(--surface-panel); }
.settings-service-section { scroll-margin-top: var(--space-5); min-width: 0; }
.settings-service-section__unavailable { margin: 0; padding: var(--space-5); border: 1px solid var(--border-subtle); border-radius: var(--radius-lg); background: var(--surface-panel); }
.settings-section__header { display: flex; align-items: baseline; justify-content: space-between; gap: var(--space-3); margin-bottom: var(--space-2); padding-bottom: var(--space-2); border-bottom: 1px solid var(--border-subtle); }
.settings-section__header h2 { margin: 0 0 2px; font-size: 16px; }
.settings-section__header p { font-size: 12px; }
.settings-section__lead { padding: var(--space-1) 0 0; }
.settings-fields-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 480px), 1fr)); column-gap: var(--space-5); row-gap: var(--space-2); }
.settings-fields-grid .settings-row--wide { grid-column: 1 / -1; }
.settings-state { margin: 0; padding: var(--space-3) 0; color: var(--text-secondary); font-size: 13px; }
.settings-state--error { display: flex; align-items: center; justify-content: space-between; gap: var(--space-3); color: var(--state-danger); }
.accent-options, .config-control { display: flex; min-width: 0; align-items: center; justify-content: flex-end; gap: 6px; }
.accent-options { flex-wrap: wrap; }
.accent-option { min-width: 38px; min-height: 32px; padding: 5px 8px; color: var(--text-secondary); font-size: 12px; }
.accent-option--active { border-color: var(--accent); background: var(--accent-subtle); color: var(--text-primary); }
.config-control > input { flex: 1 1 0; min-width: 0; width: auto; }
.settings-page select { width: var(--settings-select-width); min-width: 0; flex: 0 0 var(--settings-select-width); }
.settings-page select.settings-close-preference,
.settings-page select.settings-server-preference { width: 208px; flex: 0 0 208px; }
.server-choice { display: flex; min-width: 0; align-items: center; justify-content: flex-end; gap: 6px; }
.server-choice select { min-height: 34px; }
.server-choice input[type="text"] { flex: 1 1 0; min-width: 0; width: auto; }
.boolean-control { display: inline-flex; align-items: center; gap: 7px; min-height: 34px; color: var(--text-primary); white-space: nowrap; }
.boolean-control input { width: 18px; height: 18px; accent-color: var(--accent); }
.config-feedback { flex: 0 0 auto; color: var(--state-success); font-size: 11px; }
.routes-summary { flex: none; color: var(--text-secondary); white-space: nowrap; font-size: 13px; }
.routes-edit-button { flex: none; min-height: 32px; padding: 4px 14px; border-color: var(--accent); background: var(--accent); color: var(--accent-on); font-weight: 600; cursor: pointer; }
.routes-edit-button:hover { border-color: var(--accent-strong); background: var(--accent-strong); }
.settings-readonly { color: var(--text-secondary); white-space: nowrap; }
.settings-experimental { border-color: var(--state-warning, #b7791f40); }
.settings-experimental__notice { color: var(--text-secondary); }
.settings-experimental__notice strong { color: var(--text-primary); }

@media (max-width: 900px) {
  .settings-page__layout { grid-template-columns: minmax(0, 1fr); gap: var(--space-4); }
  .settings-section { padding-inline: var(--space-4); }
}

@media (max-width: 760px) {
  .settings-page__layout { grid-template-columns: 1fr; }
  .settings-fields-grid { grid-template-columns: 1fr; }
  .settings-fields-grid .settings-row--wide { grid-column: auto; }
  .settings-section__header { align-items: flex-start; }
}

@media (max-width: 480px) {
  .settings-section__header { display: block; }
  .settings-section__count { display: block; margin-top: 4px; }
}

.motion-reduced .settings-page *, [data-motion="reduced"] .settings-page * { scroll-behavior: auto; transition: none !important; animation: none !important; }
</style>
