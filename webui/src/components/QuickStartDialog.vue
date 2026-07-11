<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { FileUp, Rocket } from 'lucide-vue-next'
import ModalShell from './ModalShell.vue'
import PasswordField from './PasswordField.vue'
import TokenInput from './TokenInput.vue'
import { distributionConfig } from '../generated/distribution'
import { useConfigStore } from '../stores/config'
import {
  themeAccentPalettes,
  useThemeStore,
  type ThemeAccentTheme,
  type ThemeMode,
} from '../stores/theme'
import { normalizeError, useVpnStore } from '../stores/vpn'
import { useUiStore } from '../stores/ui'
import {
  detectImportEnvelope,
  friendlyImportConfigError,
  importEnvelopeToPayload,
} from '../utils/configTransfer'

type ClosePreference = 'smart' | 'tray' | 'quit'

const ui = useUiStore()
const config = useConfigStore()
const vpn = useVpnStore()
const theme = useThemeStore()

const isDesktop = typeof window !== 'undefined' && !!window.exv
const serverOptions: string[] = distributionConfig.vpnServers.map((server) => server.value)

const mode = ref<'quick' | 'custom'>('quick')
const serverChoice = ref<string>(distributionConfig.defaultVpnServer)
const customServer = ref('')
const username = ref('')
const password = ref('')
const rememberPassword = ref(false)
const installService = ref(true)
const autoReconnect = ref(true)
const launchAtLogin = ref(false)
const autoConnectOnLaunch = ref(false)
const minimizeToTrayOnConnect = ref(false)
const closePreference = ref<ClosePreference>('smart')
const routes = ref<string[]>([])
const busy = ref(false)
const error = ref('')
const fileInput = ref<HTMLInputElement | null>(null)
const formDirty = ref(false)

const themeOptions: Array<{ value: ThemeMode }> = [
  { value: 'light' },
  { value: 'dark' },
  { value: 'system' },
]

const closePreferenceOptions: Array<{ value: ClosePreference; label: string }> = [
  { value: 'smart', label: '智能' },
  { value: 'tray', label: '托盘' },
  { value: 'quit', label: '退出' },
]

const panelSize = computed(() => mode.value === 'custom' ? 'xl' : 'md')
const defaultServer = computed(() => ui.quickStartRequest?.defaults.server || distributionConfig.defaultVpnServer)
const rememberPasswordEnabled = computed(() => password.value.length > 0)
const showSavedPasswordOverwriteHint = computed(() => Boolean(config.authConfig.password_stored))
const quickStartDescription = computed(() =>
  ui.quickStartRequest?.reason === 'invalid'
    ? '配置文件不完整，已重新初始化。'
    : '',
)
const activeAccentTheme = computed<ThemeAccentTheme>(() => {
  if (theme.mode === 'system') return theme.systemDark ? 'dark' : 'light'
  return theme.mode
})
const activeAccentOptions = computed(() => themeAccentPalettes[activeAccentTheme.value])
const showInstallServiceOption = computed(() => !vpn.serviceInstalled)

function normalizeServerChoice(server: string) {
  return server.trim().replace(/^https?:\/\//i, '').replace(/\/$/, '').toLowerCase()
}

function applyServerChoice(server: string) {
  const normalizedServer = normalizeServerChoice(server)
  if (serverOptions.includes(normalizedServer)) {
    serverChoice.value = normalizedServer
    customServer.value = ''
  } else if (server.trim()) {
    serverChoice.value = 'custom'
    customServer.value = server.trim()
  } else {
    serverChoice.value = distributionConfig.defaultVpnServer
    customServer.value = ''
  }
}

function currentServer() {
  if (mode.value !== 'custom') return defaultServer.value
  return serverChoice.value === 'custom' ? customServer.value.trim() : serverChoice.value
}

function normalizeClosePreference(action: unknown): ClosePreference {
  return action === 'tray' || action === 'quit' || action === 'smart' ? action : 'smart'
}

async function loadClosePreference() {
  if (!isDesktop || !window.exv?.window.getClosePreference) return
  const result = await window.exv.window.getClosePreference()
  closePreference.value = normalizeClosePreference(result?.action)
}

function quickStartAccentSelected(accentKey: string) {
  return activeAccentTheme.value === 'light'
    ? theme.lightAccent === accentKey
    : theme.darkAccent === accentKey
}

function selectQuickStartThemeMode(mode: ThemeMode) {
  theme.setThemeMode(mode)
}

function selectQuickStartAccent(accentKey: string) {
  theme.setAccent(activeAccentTheme.value, accentKey)
}

watch(
  () => ui.showQuickStart,
  async (visible) => {
    if (!visible) return
    mode.value = 'quick'
    error.value = ''
    formDirty.value = false
    applyServerChoice(defaultServer.value)
    username.value = ''
    password.value = ''
    rememberPassword.value = false
    installService.value = ui.quickStartRequest?.defaults.install_service ?? true
    autoReconnect.value = config.settings.auto_reconnect
    launchAtLogin.value = config.settings.launch_at_login
    autoConnectOnLaunch.value = config.settings.auto_connect_on_launch
    minimizeToTrayOnConnect.value = config.settings.minimize_to_tray_on_connect
    closePreference.value = 'smart'
    routes.value = vpn.routes.map((route) => route.cidr)
    await Promise.allSettled([
      config.fetchAuthConfig(),
      config.fetchSettings(),
      vpn.fetchRoutes(),
      vpn.fetchServiceStatus(),
      loadClosePreference(),
    ])
    if (!ui.showQuickStart || formDirty.value) return
    if (vpn.serviceInstalled) {
      installService.value = false
    }
    applyServerChoice(config.authConfig.server || defaultServer.value)
    username.value = config.authConfig.username || ''
    autoReconnect.value = config.settings.auto_reconnect
    launchAtLogin.value = config.settings.launch_at_login
    autoConnectOnLaunch.value = config.settings.auto_connect_on_launch
    minimizeToTrayOnConnect.value = config.settings.minimize_to_tray_on_connect
    routes.value = vpn.routes.map((route) => route.cidr)
  },
)

watch(
  () => password.value,
  (value) => {
    if (!value) {
      rememberPassword.value = false
    }
  },
)

function skip() {
  ui.dismissQuickStart()
}

function markFormDirty() {
  formDirty.value = true
  error.value = ''
}

function handleServerChoiceChange(event: Event) {
  serverChoice.value = (event.target as HTMLSelectElement).value
  if (serverChoice.value !== 'custom') {
    customServer.value = ''
  }
  markFormDirty()
}

function handleCustomServerInput(event: Event) {
  customServer.value = (event.target as HTMLInputElement).value
  markFormDirty()
}

function updateRoutes(value: string | string[]) {
  markFormDirty()
  routes.value = Array.isArray(value) ? value : []
}

function validate() {
  if (mode.value === 'custom' && !currentServer()) {
    error.value = '请填写 VPN 服务器'
    return false
  }
  if (!username.value.trim()) {
    error.value = '请填写用户名'
    return false
  }
  if (!password.value) {
    error.value = '请填写密码'
    return false
  }
  error.value = ''
  return true
}

async function saveQuickStartSettings() {
  await config.saveSettings(
    mode.value === 'custom'
      ? {
          auto_reconnect: autoReconnect.value,
          launch_at_login: launchAtLogin.value,
          auto_connect_on_launch: autoConnectOnLaunch.value,
          minimize_to_tray_on_connect: minimizeToTrayOnConnect.value,
        }
      : { launch_at_login: launchAtLogin.value },
  )

  if (mode.value === 'custom') {
    await window.exv?.window.setClosePreference?.(closePreference.value)
  }
}

async function saveCustomRoutes() {
  await vpn.resetRoutes()
  for (const route of routes.value.map((item) => item.trim()).filter(Boolean)) {
    await vpn.addRoute(route)
  }
}

async function confirm() {
  if (!validate() || busy.value) return
  busy.value = true
  try {
    await config.saveAuthConfig({
      server: currentServer(),
      username: username.value.trim(),
      password: rememberPassword.value ? password.value : '',
      remember_password: rememberPassword.value,
      user_agent: config.authConfig.user_agent,
    })
    await saveQuickStartSettings()
    if (mode.value === 'custom') {
      await saveCustomRoutes()
    }
    ui.completeQuickStart()
    if (installService.value) {
      await vpn.fetchServiceStatus()
    }
    if (installService.value && !vpn.serviceInstalled) {
      const installed = await vpn.requestInstallService({ confirmWhenInactive: false })
      if (!installed) {
        ui.requestError({ title: '服务安装失败', message: '配置已保存，可稍后在设置中重新安装服务。' })
      }
    }
  } catch (err) {
    error.value = normalizeError(err).message
  } finally {
    busy.value = false
  }
}

function openImport() {
  fileInput.value?.click()
}

async function onImportFile(event: Event) {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]
  target.value = ''
  if (!file) return
  busy.value = true
  try {
    const text = await file.text()
    const envelope = detectImportEnvelope(text)
    let importPassword: string | undefined
    if (envelope.format === 'protected') {
      const passwordValue = await ui.requestPassword('请输入导入配置的保护口令', {
        description: '受保护的配置文件需要导出口令才能解密。',
        submitLabel: '确认',
        cancelLabel: '取消',
      })
      if (passwordValue === null) return
      importPassword = passwordValue
    }
    await config.importConfig(importEnvelopeToPayload(envelope, importPassword))
    await Promise.all([config.fetchAuthConfig(), config.fetchSettings(), vpn.fetchRoutes()])
    ui.completeQuickStart()
  } catch (err) {
    error.value = friendlyImportConfigError(err)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <ModalShell
    :open="ui.showQuickStart"
    title="快速入门"
    :description="quickStartDescription"
    :size="panelSize"
    :close-on-scrim="false"
    :body-scroll="false"
    @close="skip"
  >
    <template #icon>
      <Rocket class="h-4 w-4" />
    </template>

    <template #header-end>
      <div class="quick-start-dialog__mode-tabs">
        <button
          type="button"
          :class="mode === 'quick' ? 'is-active' : ''"
          @click="mode = 'quick'"
        >
          简要
        </button>
        <button
          type="button"
          :class="mode === 'custom' ? 'is-active' : ''"
          @click="mode = 'custom'"
        >
          自定义
        </button>
      </div>
    </template>

    <input ref="fileInput" type="file" class="hidden" accept="application/json,.json" @change="onImportFile" />

    <div :class="mode === 'custom' ? 'quick-start-dialog__custom-grid' : 'quick-start-dialog__quick-stack'">
      <div class="quick-start-dialog__section quick-start-dialog__section--identity">
        <label v-if="mode === 'custom'" class="block">
          <span class="mb-1 block text-xs font-medium text-muted">VPN 服务器</span>
          <select
            :value="serverChoice"
            class="exv-select w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-foreground outline-none focus:border-primary"
            @change="handleServerChoiceChange"
          >
            <option v-for="server in serverOptions" :key="server" :value="server">
              {{ server }}
            </option>
            <option value="custom">自定义</option>
          </select>
        </label>
        <label v-if="mode === 'custom' && serverChoice === 'custom'" class="block">
          <span class="mb-1 block text-xs font-medium text-muted">自定义服务器</span>
          <input
            :value="customServer"
            class="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-foreground outline-none focus:border-primary"
            placeholder="请输入 VPN 服务器地址"
            @input="handleCustomServerInput"
          />
        </label>
        <label class="block">
          <span class="mb-1 block text-xs font-medium text-muted">用户名</span>
          <input
            v-model="username"
            class="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-foreground outline-none focus:border-primary"
            autocomplete="username"
            @input="markFormDirty"
          />
        </label>
        <label class="block">
          <span class="mb-1 block text-xs font-medium text-muted">密码</span>
          <PasswordField
            v-model="password"
            input-class="w-full rounded-lg border border-border bg-bg px-3 py-2 pr-11 text-sm text-foreground outline-none focus:border-primary"
            autocomplete="current-password"
            :show-saved-password-overwrite-hint="showSavedPasswordOverwriteHint"
            @input="markFormDirty"
          />
        </label>
        <label
          class="flex items-center gap-2 text-xs"
          :class="rememberPasswordEnabled ? 'text-muted' : 'text-muted/60'"
        >
          <input
            v-model="rememberPassword"
            type="checkbox"
            :disabled="!rememberPasswordEnabled"
            class="h-3.5 w-3.5 rounded border-border bg-bg accent-accent disabled:cursor-not-allowed disabled:opacity-45"
            @change="markFormDirty"
          />
          记住密码（加密存储）
        </label>

        <div v-if="mode === 'custom'" class="quick-start-dialog__close-block">
          <span class="mb-1 block text-xs font-medium text-muted">关闭窗口行为</span>
          <div class="quick-start-dialog__close-options">
            <button
              v-for="option in closePreferenceOptions"
              :key="option.value"
              type="button"
              :class="closePreference === option.value ? 'is-active' : ''"
              @click="closePreference = option.value; markFormDirty()"
            >
              <span v-if="option.value === 'smart'">智能</span>
              <span v-else-if="option.value === 'tray'">托盘</span>
              <span v-else>退出</span>
            </button>
          </div>
        </div>

        <div v-if="mode === 'custom'" class="quick-start-dialog__personalization">
          <span class="quick-start-dialog__personalization-title">个性化</span>
          <div class="quick-start-dialog__theme-control" aria-label="主题与高亮色">
            <div class="quick-start-dialog__theme-modes">
              <button
                v-for="option in themeOptions"
                :key="option.value"
                type="button"
                :class="theme.mode === option.value ? 'is-active' : ''"
                @click="selectQuickStartThemeMode(option.value)"
              >
                <span v-if="option.value === 'light'">浅色</span>
                <span v-else-if="option.value === 'dark'">深色</span>
                <span v-else>系统</span>
              </button>
            </div>
            <div class="quick-start-dialog__accent-dots">
              <button
                v-for="option in activeAccentOptions"
                :key="option.key"
                type="button"
                :aria-label="option.label"
                :class="quickStartAccentSelected(option.key) ? 'is-active' : ''"
                @click="selectQuickStartAccent(option.key)"
              >
                <span
                  class="quick-start-dialog__accent-dot"
                  :style="{ backgroundColor: option.color }"
                  aria-hidden="true"
                />
              </button>
            </div>
          </div>
        </div>
      </div>

      <div class="quick-start-dialog__section quick-start-dialog__section--runtime">
        <span v-if="mode === 'custom'" class="quick-start-dialog__section-title">常用开关</span>
        <label
          v-if="showInstallServiceOption"
          class="quick-start-dialog__setting-row"
        >
          <span>
            <span class="block text-foreground">安装辅助服务</span>
            <span class="mt-0.5 block text-xs text-muted">优先使用系统服务连接。</span>
          </span>
          <input v-model="installService" type="checkbox" @change="markFormDirty" />
        </label>
        <label v-if="mode === 'custom'" class="quick-start-dialog__setting-row">
          <span>
            <span class="block text-foreground">断线重连</span>
            <span class="mt-0.5 block text-xs text-muted">连接中断后自动恢复。</span>
          </span>
          <input v-model="autoReconnect" type="checkbox" @change="markFormDirty" />
        </label>
        <label v-if="mode === 'custom'" class="quick-start-dialog__setting-row">
          <span>
            <span class="block text-foreground">开机自启</span>
            <span class="mt-0.5 block text-xs text-muted">登录系统后自动启动 EXV。</span>
          </span>
          <input v-model="launchAtLogin" type="checkbox" @change="markFormDirty" />
        </label>
        <label v-if="mode === 'custom'" class="quick-start-dialog__setting-row">
          <span>
            <span class="block text-foreground">启动时自动连接</span>
            <span class="mt-0.5 block text-xs text-muted">客户端启动后建立 VPN。</span>
          </span>
          <input v-model="autoConnectOnLaunch" type="checkbox" @change="markFormDirty" />
        </label>
        <label v-if="mode === 'custom'" class="quick-start-dialog__setting-row">
          <span>
            <span class="block text-foreground">连接后缩小到托盘区</span>
            <span class="mt-0.5 block text-xs text-muted">连接建立后隐藏主窗口。</span>
          </span>
          <input v-model="minimizeToTrayOnConnect" type="checkbox" @change="markFormDirty" />
        </label>
      </div>

      <div v-if="mode === 'quick'" class="quick-start-dialog__personalization">
        <span class="quick-start-dialog__personalization-title">个性化</span>
        <div class="quick-start-dialog__theme-control" aria-label="主题与高亮色">
          <div class="quick-start-dialog__theme-modes">
            <button
              v-for="option in themeOptions"
              :key="option.value"
              type="button"
              :class="theme.mode === option.value ? 'is-active' : ''"
              @click="selectQuickStartThemeMode(option.value)"
            >
              <span v-if="option.value === 'light'">浅色</span>
              <span v-else-if="option.value === 'dark'">深色</span>
              <span v-else>系统</span>
            </button>
          </div>
          <div class="quick-start-dialog__accent-dots">
            <button
              v-for="option in activeAccentOptions"
              :key="option.key"
              type="button"
              :aria-label="option.label"
              :class="quickStartAccentSelected(option.key) ? 'is-active' : ''"
              @click="selectQuickStartAccent(option.key)"
            >
              <span
                class="quick-start-dialog__accent-dot"
                :style="{ backgroundColor: option.color }"
                aria-hidden="true"
              />
            </button>
          </div>
        </div>
      </div>

      <div
        v-if="mode === 'custom'"
        class="quick-start-dialog__section quick-start-dialog__section--network"
      >
        <div class="quick-start-dialog__route-block">
          <span class="mb-1 block text-xs font-medium text-muted">路由</span>
          <TokenInput
            class="quick-start-dialog__route-input"
            :model-value="routes"
            mode="tokens"
            placeholder="添加路由"
            @update:model-value="updateRoutes"
          />
        </div>
      </div>
    </div>

    <p v-if="error" class="mt-3 text-xs text-destructive">{{ error }}</p>

    <template #actions>
      <button
        type="button"
        class="mr-auto inline-flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-sm text-muted hover:bg-surface/80 disabled:opacity-60"
        :disabled="busy"
        @click="openImport"
      >
        <FileUp class="h-4 w-4" />
        导入配置
      </button>
      <button
        type="button"
        class="rounded-lg border border-border px-3 py-2 text-sm text-muted hover:bg-surface/80 disabled:opacity-60"
        :disabled="busy"
        @click="skip"
      >
        跳过
      </button>
      <button
        type="button"
        class="rounded-lg bg-primary px-3 py-2 text-sm text-white hover:bg-primary/90 disabled:opacity-60"
        :disabled="busy"
        @click="confirm"
      >
        {{ busy ? '处理中...' : '确认' }}
      </button>
    </template>
  </ModalShell>
</template>

<style scoped>
.quick-start-dialog__mode-tabs,
.quick-start-dialog__theme-modes,
.quick-start-dialog__close-options {
  display: grid;
  border: 1px solid var(--color-border);
  border-radius: 8px;
  background: var(--color-bg);
  padding: 3px;
}

.quick-start-dialog__mode-tabs {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  width: 148px;
}

.quick-start-dialog__theme-control {
  display: flex;
  width: 100%;
  align-items: center;
  justify-content: space-between;
  gap: 5px;
}

.quick-start-dialog__theme-modes {
  grid-template-columns: repeat(3, minmax(0, 1fr));
  width: min(100%, 180px);
}

.quick-start-dialog__mode-tabs button,
.quick-start-dialog__theme-modes button,
.quick-start-dialog__close-options button {
  min-width: 0;
  border-radius: 6px;
  padding: 5px 8px;
  color: var(--color-muted);
  font-size: 12px;
  line-height: 1.2;
  transition: background-color 140ms ease, color 140ms ease;
}

.quick-start-dialog__mode-tabs button.is-active,
.quick-start-dialog__theme-modes button.is-active,
.quick-start-dialog__close-options button.is-active {
  background: var(--color-surface);
  color: var(--color-foreground);
}

.quick-start-dialog__accent-dots {
  display: flex;
  align-items: center;
  justify-content: flex-start;
  margin-left: auto;
  gap: 7px;
  padding-left: 2px;
}

.quick-start-dialog__accent-dots button {
  display: grid;
  width: 18px;
  height: 18px;
  place-items: center;
  border-radius: 999px;
  border: 1px solid transparent;
}

.quick-start-dialog__accent-dots button.is-active {
  border-color: var(--color-accent);
}

.quick-start-dialog__accent-dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  box-shadow: 0 0 0 1px var(--color-border);
}

.quick-start-dialog__quick-stack {
  display: grid;
  gap: 12px;
}

.quick-start-dialog__custom-grid {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 0.85fr) minmax(0, 1.15fr);
  align-items: stretch;
  min-height: 0;
  gap: 10px;
}

.quick-start-dialog__section {
  display: grid;
  min-width: 0;
  gap: 10px;
}

.quick-start-dialog__custom-grid .quick-start-dialog__section {
  gap: 8px;
}

.quick-start-dialog__section--identity {
  align-self: stretch;
}

.quick-start-dialog__section--network {
  align-self: stretch;
  grid-column: 3;
  grid-row: 1;
  min-height: 0;
}

.quick-start-dialog__section-title {
  min-height: 25px;
  color: var(--color-muted);
  font-size: 12px;
  font-weight: 600;
  line-height: 1.3;
}

.quick-start-dialog__custom-grid :deep(input:not([type='checkbox']):not([type='radio'])),
.quick-start-dialog__custom-grid select {
  padding-top: 7px;
  padding-bottom: 7px;
}

.quick-start-dialog__setting-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  border: 1px solid var(--color-border);
  border-radius: 8px;
  background: var(--color-bg);
  padding: 8px 10px;
  font-size: 13px;
}

.quick-start-dialog__setting-row input[type='checkbox'] {
  width: 16px;
  height: 16px;
  flex: 0 0 auto;
  accent-color: var(--color-accent);
}

.quick-start-dialog__close-block,
.quick-start-dialog__personalization {
  display: grid;
  min-width: 0;
  gap: 6px;
}

.quick-start-dialog__personalization {
  margin-top: auto;
}

.quick-start-dialog__personalization-title {
  color: var(--color-muted);
  font-size: 12px;
  font-weight: 600;
  line-height: 1.3;
}

.quick-start-dialog__route-block {
  display: grid;
  grid-template-rows: auto minmax(0, 1fr);
  align-content: stretch;
  height: 100%;
  min-height: 0;
}

.quick-start-dialog__route-input {
  height: 100%;
  min-height: 0;
}

.quick-start-dialog__route-input :deep(.token-input__tokens) {
  max-height: 128px;
}

.quick-start-dialog__close-options {
  grid-template-columns: repeat(3, minmax(0, 1fr));
}

@media (max-width: 760px) {
  .quick-start-dialog__theme-control {
    align-items: center;
  }

  .quick-start-dialog__custom-grid {
    grid-template-columns: 1fr;
  }

  .quick-start-dialog__section--network {
    grid-column: auto;
    grid-row: auto;
  }
}
</style>
