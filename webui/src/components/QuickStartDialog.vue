<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { FileUp, Rocket, Settings2 } from 'lucide-vue-next'
import ModalShell from './ModalShell.vue'
import PasswordField from './PasswordField.vue'
import TokenInput from './TokenInput.vue'
import { distributionConfig } from '../generated/distribution'
import { useConfigStore } from '../stores/config'
import { normalizeError, useVpnStore } from '../stores/vpn'
import { useUiStore } from '../stores/ui'
import {
  detectImportEnvelope,
  friendlyImportConfigError,
  importEnvelopeToPayload,
} from '../utils/configTransfer'

const ui = useUiStore()
const config = useConfigStore()
const vpn = useVpnStore()

const mode = ref<'quick' | 'custom'>('quick')
const username = ref('')
const password = ref('')
const rememberPassword = ref(false)
const launchAtLogin = ref(false)
const routes = ref<string[]>([])
const settingsForm = ref({
  mtu: 1290,
  dtls: true,
})
const busy = ref(false)
const error = ref('')
const fileInput = ref<HTMLInputElement | null>(null)

const panelSize = computed(() => mode.value === 'custom' ? 'lg' : 'md')
const defaultServer = computed(() => ui.quickStartRequest?.defaults.server || distributionConfig.defaultVpnServer)
const shouldInstallService = computed(() => ui.quickStartRequest?.defaults.install_service ?? true)
const rememberPasswordEnabled = computed(() => password.value.length > 0)
const showSavedPasswordOverwriteHint = computed(() => Boolean(config.authConfig.password_stored))
const quickStartDescription = computed(() =>
  ui.quickStartRequest?.reason === 'invalid'
    ? '配置文件不完整，已重新初始化。'
    : '首次使用前补全连接信息。',
)

watch(
  () => ui.showQuickStart,
  async (visible) => {
    if (!visible) return
    mode.value = 'quick'
    error.value = ''
    username.value = ''
    password.value = ''
    rememberPassword.value = false
    launchAtLogin.value = false
    routes.value = vpn.routes.map((route) => route.cidr)
    settingsForm.value = {
      mtu: config.settings.mtu || 1290,
      dtls: config.settings.dtls,
    }
    await Promise.allSettled([
      config.fetchAuthConfig(),
      config.fetchSettings(),
      vpn.fetchRoutes(),
      vpn.fetchServiceStatus(),
    ])
    username.value = config.authConfig.username || ''
    routes.value = vpn.routes.map((route) => route.cidr)
    settingsForm.value = {
      mtu: config.settings.mtu || 1290,
      dtls: config.settings.dtls,
    }
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
  ui.closeQuickStart()
}

function updateRoutes(value: string | string[]) {
  routes.value = Array.isArray(value) ? value : []
}

function validate() {
  if (!username.value.trim()) {
    error.value = '请填写用户名'
    return false
  }
  if (!password.value) {
    error.value = '请填写密码'
    return false
  }
  if (mode.value === 'custom' && (settingsForm.value.mtu < 576 || settingsForm.value.mtu > 1500)) {
    error.value = 'MTU 必须在 576 到 1500 之间'
    return false
  }
  error.value = ''
  return true
}

async function saveQuickStartSettings() {
  const settingsPayload = {
    launch_at_login: launchAtLogin.value,
    mtu: settingsForm.value.mtu,
    dtls: settingsForm.value.dtls,
  }
  await config.saveSettings(
    mode.value === 'custom'
      ? settingsPayload
      : { launch_at_login: settingsPayload.launch_at_login },
  )
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
      server: defaultServer.value,
      username: username.value.trim(),
      password: rememberPassword.value ? password.value : '',
      remember_password: rememberPassword.value,
      user_agent: config.authConfig.user_agent,
    })
    await saveQuickStartSettings()
    if (mode.value === 'custom') {
      await saveCustomRoutes()
    }
    ui.closeQuickStart()
    if (shouldInstallService.value && !vpn.serviceInstalled) {
      const installed = await vpn.installService()
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
    ui.closeQuickStart()
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
    @close="skip"
  >
    <template #icon>
      <Rocket class="h-4 w-4" />
    </template>

    <input ref="fileInput" type="file" class="hidden" accept="application/json,.json" @change="onImportFile" />

    <div class="mb-3 grid grid-cols-2 rounded-lg border border-border bg-bg p-1 text-sm">
      <button
        type="button"
        class="rounded-md px-3 py-2"
        :class="mode === 'quick' ? 'bg-surface text-foreground' : 'text-muted hover:text-foreground'"
        @click="mode = 'quick'"
      >
        快速
      </button>
      <button
        type="button"
        class="rounded-md px-3 py-2"
        :class="mode === 'custom' ? 'bg-surface text-foreground' : 'text-muted hover:text-foreground'"
        @click="mode = 'custom'"
      >
        自定义
      </button>
    </div>

    <div class="space-y-3">
      <label class="block">
        <span class="mb-1 block text-xs font-medium text-muted">用户名</span>
        <input
          v-model="username"
          class="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-foreground outline-none focus:border-primary"
          autocomplete="username"
          @input="error = ''"
        />
      </label>
      <label class="block">
        <span class="mb-1 block text-xs font-medium text-muted">密码</span>
        <PasswordField
          v-model="password"
          input-class="w-full rounded-lg border border-border bg-bg px-3 py-2 pr-11 text-sm text-foreground outline-none focus:border-primary"
          autocomplete="current-password"
          :show-saved-password-overwrite-hint="showSavedPasswordOverwriteHint"
          @input="error = ''"
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
        />
        记住密码（加密存储）
      </label>

      <label class="flex items-center justify-between gap-3 rounded-lg border border-border bg-bg px-3 py-2 text-sm">
        <span>
          <span class="block text-foreground">开机自启</span>
          <span class="mt-0.5 block text-xs text-muted">登录系统后自动启动 EXV 客户端。</span>
        </span>
        <input
          v-model="launchAtLogin"
          type="checkbox"
          class="h-4 w-4 cursor-pointer rounded border-border bg-bg accent-accent"
        />
      </label>

      <div v-if="mode === 'custom'" class="space-y-3">
        <label class="block">
          <span class="mb-1 block text-xs font-medium text-muted">路由</span>
          <TokenInput
            :model-value="routes"
            mode="tokens"
            placeholder="输入 CIDR 后回车"
            @update:model-value="updateRoutes"
          />
        </label>
        <label class="flex items-center justify-between gap-3 rounded-lg border border-border bg-bg px-3 py-2 text-sm">
          <span class="flex items-center gap-2 text-foreground"><Settings2 class="h-4 w-4" /> DTLS</span>
          <input v-model="settingsForm.dtls" type="checkbox" class="h-4 w-4 rounded border-border bg-bg text-primary" />
        </label>
        <label class="block">
          <span class="mb-1 block text-xs font-medium text-muted">MTU</span>
          <input
            v-model.number="settingsForm.mtu"
            min="576"
            max="1500"
            type="number"
            class="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-foreground outline-none focus:border-primary"
          />
        </label>
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
