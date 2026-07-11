<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  AlertTriangle,
  CheckCircle,
  Download,
  HardDriveDownload,
  Key,
  RefreshCcw,
  Settings,
  Trash2,
  Upload,
} from 'lucide-vue-next'
import ModalShell from '../../components/ModalShell.vue'
import PasswordField from '../../components/PasswordField.vue'
import ToggleSwitch from '../../components/ToggleSwitch.vue'
import { useConfigStore, type SettingsConfig } from '../../stores/config'
import { useUiStore } from '../../stores/ui'
import { normalizeError, useVpnStore } from '../../stores/vpn'
import {
  detectImportEnvelope,
  friendlyImportConfigError,
  importEnvelopeToPayload,
} from '../../utils/configTransfer'

const props = defineProps<{
  settingsDraft: SettingsConfig
}>()

const emit = defineEmits<{
  'update:settingsDraft': [value: SettingsConfig]
  reloadSettings: []
}>()

type ClosePreference = 'smart' | 'tray' | 'quit'

const config = useConfigStore()
const vpn = useVpnStore()
const ui = useUiStore()
const isDesktop = typeof window !== 'undefined' && !!window.exv

const busyDriver = ref<'wintun' | 'tap' | null>(null)
const systemMessage = ref<{ text: string } | null>(null)
const installFeedback = ref<{ driver: 'wintun' | 'tap'; takes_effect: string } | null>(null)
const importFileInput = ref<HTMLInputElement | null>(null)
const importBusy = ref(false)
const exportBusy = ref(false)
const showExportDialog = ref(false)
const exportIncludePassword = ref(false)
const exportPassword = ref('')
const exportPasswordTouched = ref(false)
const closePreference = ref<ClosePreference>('smart')
const closePreferenceBusy = ref(false)

const fallbackSettingsDraft: SettingsConfig = {
  mtu: 1400,
  dtls: true,
  dtls_mode: 'auto',
  extra_args: '',
  log_path: '',
  webui_port: 18080,
  webui_host: '127.0.0.1',
  webui_enabled: true,
  vpn_engine: 'native',
  windows_tunnel_driver: 'auto',
  windows_tap_interface: '',
  auto_reconnect: true,
  retry_limit: 0,
  minimal_mode: false,
  service_install_prompt_seen: false,
  minimal_install_service_before_connect: true,
  minimize_to_tray_on_connect: false,
  include_class_a_private_routes: false,
  include_class_b_private_routes: false,
  launch_at_login: false,
  auto_connect_on_launch: false,
  silent_startup: false,
  connection_state_notifications: false,
}

const settingsForm = computed(() => props.settingsDraft ?? fallbackSettingsDraft)

const closePreferenceOptions: Array<{ value: ClosePreference; label: string }> = [
  { value: 'smart', label: '智能处理' },
  { value: 'tray', label: '缩小到托盘' },
  { value: 'quit', label: '彻底退出' },
]

const PROTECTED_EXPORT_WARNING =
  '导出的配置包含可恢复的 VPN 密码。请把导出文件当作敏感文件保存，不要通过不可信渠道共享。'

const nativeEngineSelected = computed(() => settingsForm.value.vpn_engine === 'native')
const tapNativeBackendImplemented = false
const driverSupported = computed(() => !!config.driverStatus?.supported)
const tapAdapters = computed(() => config.driverStatus?.tap_adapters || [])
const activeRuntimeStatus = computed(() => config.runtimeStatus)
const runtimeMissing = computed(() => !!activeRuntimeStatus.value && !activeRuntimeStatus.value.available)
const wintunReady = computed(() => {
  const status = config.driverStatus
  if (!status) return false
  return status.wintun_missing === false ||
    status.wintun_bundled === true ||
    (status.wintun_adapters?.length ?? 0) > 0
})
const tapReady = computed(() => {
  const status = config.driverStatus
  if (!status) return false
  return status.tap_missing === false ||
    status.tap_available === true ||
    (status.tap_adapters?.length ?? 0) > 0
})
const wintunStatusText = computed(() => {
  const status = config.driverStatus
  if (!status) return '未检测到 Wintun'
  if (status.wintun_bundled) return '已检测到内置 wintun.dll'
  if ((status.wintun_adapters?.length ?? 0) > 0) return '已检测到 Wintun 适配器'
  return '未检测到内置 wintun.dll'
})
const wintunMissing = computed(() => config.driverStatus?.wintun_missing ?? !wintunReady.value)
const tapMissing = computed(() => config.driverStatus?.tap_missing ?? !tapReady.value)
const driverReadiness = computed(() => {
  const status = config.driverStatus
  if (!status) return 'unavailable'
  if (status.effective_driver_status) return status.effective_driver_status
  return wintunReady.value || tapReady.value ? 'ready' : 'unavailable'
})
const runtimeReady = computed(() => activeRuntimeStatus.value?.available ?? true)
const runtimeSourceText = computed(() => activeRuntimeStatus.value?.source ?? '未知')
const runtimePathText = computed(() => activeRuntimeStatus.value?.path || '原生引擎由应用内置提供')
const runtimeDirectoryText = computed(() => activeRuntimeStatus.value?.bundled_runtime_dir || '原生引擎随应用提供')
const anyDriverAvailable = computed(() => {
  if (!config.driverStatus) return false
  return wintunReady.value || tapReady.value
})
const hasSavedPasswordForExport = computed(() =>
  Boolean(config.authConfig.remember_password && config.authConfig.password_stored),
)
const exportPasswordRequired = computed(() =>
  exportIncludePassword.value && hasSavedPasswordForExport.value && exportPassword.value.trim().length === 0,
)

const launchAtLoginModel = computed({
  get: () => settingsForm.value.launch_at_login,
  set: (value: boolean) => updateSettingField('launch_at_login', value),
})

const rememberedPasswordReady = computed(() =>
  Boolean(config.authConfig.remember_password && config.authConfig.password_stored),
)

const startupAutoConnectAllowed = computed(() =>
  rememberedPasswordReady.value && vpn.serviceInstalled,
)

const startupAutoConnectReason = computed(() => {
  if (!rememberedPasswordReady.value) return '需要先保存并记住密码。'
  if (!vpn.serviceInstalled) return '需要先安装 Helper 服务。'
  return ''
})

const startupAutoConnectModel = computed({
  get: () => settingsForm.value.auto_connect_on_launch,
  set: (value: boolean) => {
    if (value && !startupAutoConnectAllowed.value) {
      ui.requestError({
        title: '无法开启启动时自动连接',
        message: startupAutoConnectReason.value,
      })
      return
    }
    updateSettingField('auto_connect_on_launch', value)
  },
})

const minimizeToTrayOnConnectModel = computed({
  get: () => settingsForm.value.minimize_to_tray_on_connect,
  set: (value: boolean) => updateSettingField('minimize_to_tray_on_connect', value),
})

const silentStartupModel = computed({
  get: () => settingsForm.value.silent_startup,
  set: (value: boolean) => updateSettingField('silent_startup', value),
})

const connectionStateNotificationsModel = computed({
  get: () => settingsForm.value.connection_state_notifications,
  set: (value: boolean) => updateSettingField('connection_state_notifications', value),
})

const driverReadinessLabel = computed(() => {
  switch (driverReadiness.value) {
    case 'ready': return '驱动就绪'
    case 'degraded': return '驱动降级'
    case 'unavailable': return '驱动不可用'
    default: return '未知'
  }
})

const driverReadinessColor = computed(() => {
  switch (driverReadiness.value) {
    case 'ready': return 'text-success'
    case 'degraded': return 'text-warning'
    case 'unavailable': return 'text-red-400'
    default: return 'text-muted'
  }
})

const serviceButtonLabel = computed(() => {
  if (vpn.serviceOperation === 'install') return '安装中...'
  if (vpn.serviceOperation === 'uninstall') return '卸载中...'
  return vpn.serviceInstalled ? '卸载服务' : '安装服务'
})

const serviceButtonInstalled = computed(() => {
  if (vpn.serviceOperation === 'uninstall') return true
  if (vpn.serviceOperation === 'install') return false
  return vpn.serviceInstalled
})

const cliButtonLabel = computed(() => {
  if (vpn.cliOperation === 'install') return '安装中...'
  if (vpn.cliOperation === 'uninstall') return '卸载中...'
  return vpn.cliStatus?.installed ? '卸载 CLI' : '安装 CLI'
})

const cliButtonInstalled = computed(() => {
  if (vpn.cliOperation === 'uninstall') return true
  if (vpn.cliOperation === 'install') return false
  return vpn.cliStatus?.installed ?? false
})

async function refreshRuntime() {
  if (!isDesktop) return
  await Promise.all([
    config.fetchRuntimeStatus(),
    config.fetchDriverStatus(),
  ])
}

function normalizeClosePreference(action: unknown): ClosePreference {
  return action === 'tray' || action === 'quit' || action === 'smart' ? action : 'smart'
}

async function loadClosePreference() {
  if (!isDesktop || !window.exv?.window.getClosePreference) return
  try {
    const result = await window.exv?.window.getClosePreference?.()
    closePreference.value = normalizeClosePreference(result?.action)
  } catch (error) {
    ui.requestError({ title: '读取关闭窗口设置失败', message: normalizeError(error).message })
  }
}

async function saveClosePreference(action: ClosePreference) {
  const previous = closePreference.value
  closePreference.value = action
  if (!isDesktop || !window.exv?.window.setClosePreference) return
  closePreferenceBusy.value = true
  try {
    const result = await window.exv?.window.setClosePreference?.(action)
    closePreference.value = normalizeClosePreference(result?.action ?? action)
    ui.addToast('关闭窗口处理方式已保存', 'success')
  } catch (error) {
    closePreference.value = previous
    ui.requestError({ title: '保存关闭窗口设置失败', message: normalizeError(error).message })
  } finally {
    closePreferenceBusy.value = false
  }
}

async function resetClosePreference() {
  const previous = closePreference.value
  closePreference.value = 'smart'
  if (!isDesktop || !window.exv?.window.resetClosePreference) return
  closePreferenceBusy.value = true
  try {
    await window.exv?.window.resetClosePreference?.()
  } catch (error) {
    closePreference.value = previous
    throw error
  } finally {
    closePreferenceBusy.value = false
  }
}

async function loadSystemSettings() {
  await Promise.all([
    vpn.fetchServiceStatus(),
    vpn.fetchCliStatus(),
  ])

  if (isDesktop) {
    try {
      await Promise.all([
        refreshRuntime(),
        loadClosePreference(),
      ])
    } catch (error) {
      ui.requestError({ title: '刷新运行时失败', message: normalizeError(error).message })
    }
  }
}

function updateSettingField<K extends keyof SettingsConfig>(key: K, value: SettingsConfig[K]) {
  emit('update:settingsDraft', {
    ...settingsForm.value,
    [key]: value,
  })
}

async function toggleService() {
  systemMessage.value = null
  const installed = vpn.serviceInstalled
  const ok = installed ? await vpn.requestUninstallService() : await vpn.requestInstallService()
  if (ok) {
    ui.addToast(installed ? '辅助服务已卸载' : '辅助服务已安装', 'success')
  } else if (vpn.serviceStatus?.operation_state === 'in_progress') {
    ui.addToast(installed ? '辅助服务卸载已启动，正在更新状态' : '辅助服务安装已启动，正在更新状态', 'warning')
  } else if (vpn.serviceStatus?.operation_state === 'warning') {
    ui.requestError({
      title: installed ? '辅助服务卸载需确认' : '辅助服务安装需确认',
      message: vpn.serviceStatus.warning || '请刷新服务状态或查看日志后确认。',
    })
  }
}

async function toggleCli() {
  systemMessage.value = null
  const installed = vpn.cliStatus?.installed ?? false
  const ok = installed ? await vpn.uninstallCli() : await vpn.installCli()
  if (ok) {
    ui.addToast(installed ? 'CLI 已卸载' : 'CLI 已安装；请打开新终端使用 exv', 'success')
  }
}

async function installDriver(driver: 'wintun' | 'tap') {
  busyDriver.value = driver
  systemMessage.value = null
  installFeedback.value = null
  try {
    const result = await config.installDriver(driver)
    await config.fetchDriverStatus()
    if (driver === 'tap' && !settingsForm.value.windows_tap_interface && tapAdapters.value.length > 0) {
      updateSettingField('windows_tap_interface', tapAdapters.value[0])
    }
    const takesEffect = result.takes_effect || (driver === 'wintun' ? 'next_connect' : 'immediately')
    installFeedback.value = { driver, takes_effect: takesEffect }
    systemMessage.value = {
      text: takesEffect === 'next_connect'
        ? 'Wintun 运行时已就绪，下次连接时生效'
        : 'TAP 安装完成，立即生效。如已连接 VPN，建议断开重连。',
    }
  } catch (error) {
    ui.requestError({ title: '安装驱动失败', message: normalizeError(error).message })
  } finally {
    busyDriver.value = null
  }
}

function triggerImportConfig() {
  if (importBusy.value) return
  importFileInput.value?.click()
}

function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onerror = () => reject(reader.error || new Error('读取文件失败'))
    reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : '')
    reader.readAsText(file)
  })
}

async function handleImportFileChange(event: Event) {
  const target = event.target as HTMLInputElement
  const file = target.files?.[0]
  target.value = ''
  if (!file) return
  if (importBusy.value) return
  importBusy.value = true
  try {
    const text = await readFileAsText(file)
    const envelope = detectImportEnvelope(text)
    let password: string | undefined
    if (envelope.format === 'protected') {
      const passwordValue = await ui.requestPassword('请输入导入配置的保护口令', {
        description: '受保护的配置文件需要导出口令才能解密。',
        submitLabel: '确认',
        cancelLabel: '取消',
      })
      if (passwordValue === null) return
      password = passwordValue
    }
    await config.importConfig(importEnvelopeToPayload(envelope, password))
    ui.addToast('配置已导入', 'success')
    emit('reloadSettings')
  } catch (error) {
    ui.requestError({
      title: '导入配置失败',
      message: friendlyImportConfigError(error),
      secondaryLabel: '确认',
    })
  } finally {
    importBusy.value = false
  }
}

function downloadExport(filename: string, payload: string) {
  const blob = new Blob([payload], { type: 'application/octet-stream' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  setTimeout(() => URL.revokeObjectURL(url), 0)
}

async function exportConfigWithoutPassword() {
  const result = await config.exportConfig({ protected: false })
  ui.addToast('配置已导出（不含密码）', 'success')
  downloadExport('exv-config.json', result.data)
}

async function openExportDialog() {
  if (exportBusy.value) return
  exportIncludePassword.value = false
  exportPassword.value = ''
  exportPasswordTouched.value = false
  exportBusy.value = true
  try {
    await config.fetchAuthConfig()
    if (!hasSavedPasswordForExport.value) {
      await exportConfigWithoutPassword()
      return
    }
  } catch (error) {
    ui.requestError({
      title: '导出配置失败',
      message: normalizeError(error).message,
      secondaryLabel: '确认',
    })
    return
  } finally {
    exportBusy.value = false
  }
  showExportDialog.value = true
}

function closeExportDialog() {
  showExportDialog.value = false
  exportIncludePassword.value = false
  exportPassword.value = ''
  exportPasswordTouched.value = false
}

function updateExportIncludePassword(value: boolean) {
  exportIncludePassword.value = value
  exportPasswordTouched.value = value
  if (!value) {
    exportPassword.value = ''
  }
}

async function submitExportConfig() {
  if (exportBusy.value) return
  exportPasswordTouched.value = true
  if (exportPasswordRequired.value) return

  exportBusy.value = true
  try {
    const includesPassword = exportIncludePassword.value && hasSavedPasswordForExport.value
    const result = await config.exportConfig({ protected: includesPassword, password: includesPassword ? exportPassword.value : undefined })
    downloadExport(includesPassword ? 'exv-config.protected' : 'exv-config.json', result.data)
    closeExportDialog()
    if (includesPassword) {
      ui.requestError({
        title: '导出已完成',
        message: PROTECTED_EXPORT_WARNING,
        secondaryLabel: '确认',
      })
    } else {
      ui.addToast('配置已导出（不含密码）', 'success')
    }
  } catch (error) {
    closeExportDialog()
    ui.requestError({
      title: '导出配置失败',
      message: normalizeError(error).message,
      secondaryLabel: '确认',
    })
  } finally {
    exportBusy.value = false
  }
}

function resetConfigAction() {
  ui.requestConfirm('此操作会清空所有 VPN 配置，是否继续？', async () => {
    try {
      await config.resetConfig(true)
      ui.resetQuickStartDismissal()
      await resetClosePreference()
      ui.addToast('配置已重置', 'success')
      emit('reloadSettings')
    } catch (error) {
      ui.requestError({ title: '重置配置失败', message: normalizeError(error).message })
    }
  })
}

function resetKeyAction() {
  ui.requestConfirm('此操作会清除本地保存的加密密码，下次连接需重新输入。是否继续？', async () => {
    try {
      await config.resetKey(true)
      ui.addToast('已重置加密密钥', 'success')
    } catch (error) {
      ui.requestError({ title: '重置加密密钥失败', message: normalizeError(error).message })
    }
  })
}

onMounted(() => {
  void loadSystemSettings()
})
</script>

<template>
  <section class="rounded-xl border border-border bg-surface p-5">
    <div class="mb-4 flex items-start justify-between gap-4">
      <h2 class="flex items-center gap-2 text-base font-semibold text-foreground">
        <Settings class="h-5 w-5 text-accent" />
        系统
      </h2>
      <button
        v-if="isDesktop"
        class="flex items-center gap-2 rounded-lg border border-border px-3 py-2 text-xs text-foreground transition-colors hover:border-accent/50"
        @click="refreshRuntime"
      >
        <RefreshCcw class="h-3.5 w-3.5" />
        刷新
      </button>
    </div>

    <div class="space-y-5">
      <div>
        <label class="mb-1.5 block text-xs font-medium text-muted">日志文件路径</label>
        <input
          :value="settingsForm.log_path"
          type="text"
          placeholder="~/.exv/exv.log"
          class="w-full rounded-lg border border-border bg-bg px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted transition-colors focus:border-accent/50 focus:outline-none"
          @input="updateSettingField('log_path', ($event.target as HTMLInputElement).value)"
        />
      </div>

      <div>
        <label class="mb-1.5 block text-xs font-medium text-muted">额外参数</label>
        <input
          :value="settingsForm.extra_args"
          type="text"
          :placeholder="nativeEngineSelected ? '--no-dtls --authgroup=students' : '额外兼容参数'"
          class="w-full rounded-lg border border-border bg-bg px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted transition-colors focus:border-accent/50 focus:outline-none"
          @input="updateSettingField('extra_args', ($event.target as HTMLInputElement).value)"
        />
        <p v-if="nativeEngineSelected" class="mt-1 text-xs text-muted">
          原生模式仅支持 --no-dtls、--useragent=...、--authgroup=...、--csd-wrapper=...；其他参数会在连接前明确拒绝。
        </p>
      </div>

      <div v-if="isDesktop" class="flex items-center justify-between rounded-lg border border-border bg-bg/40 px-4 py-3">
        <div>
          <p class="text-sm text-foreground">开机自启</p>
          <p class="text-xs text-muted">登录系统后自动启动 EXV 客户端。</p>
        </div>
        <ToggleSwitch v-model="launchAtLoginModel" />
      </div>

      <div class="flex items-center justify-between rounded-lg border border-border bg-bg/40 px-4 py-3">
        <div>
          <p class="text-sm text-foreground">启动时自动连接</p>
          <p class="text-xs text-muted">
            {{ startupAutoConnectAllowed ? '客户端启动后自动建立 VPN 连接。' : startupAutoConnectReason }}
          </p>
        </div>
        <ToggleSwitch
          v-model="startupAutoConnectModel"
          :disabled="!startupAutoConnectAllowed && !settingsForm.auto_connect_on_launch"
        />
      </div>

      <div v-if="isDesktop" class="flex items-center justify-between rounded-lg border border-border bg-bg/40 px-4 py-3">
        <div>
          <p class="text-sm text-foreground">连接后缩小到托盘区</p>
          <p class="text-xs text-muted">连接建立后自动隐藏窗口，托盘菜单仍可显示或断开连接。</p>
        </div>
        <ToggleSwitch v-model="minimizeToTrayOnConnectModel" />
      </div>

      <div v-if="isDesktop" class="flex items-center justify-between rounded-lg border border-border bg-bg/40 px-4 py-3">
        <div>
          <p class="text-sm text-foreground">静默启动</p>
          <p class="text-xs text-muted">首次启动进程时不显示主窗口；托盘或再次运行仍会显示。</p>
        </div>
        <ToggleSwitch v-model="silentStartupModel" />
      </div>

      <div v-if="isDesktop" class="flex items-center justify-between rounded-lg border border-border bg-bg/40 px-4 py-3">
        <div>
          <p class="text-sm text-foreground">连接状态系统通知</p>
          <p class="text-xs text-muted">连接成功或断开连接时发送系统通知。</p>
        </div>
        <ToggleSwitch v-model="connectionStateNotificationsModel" />
      </div>

      <div v-if="isDesktop" class="flex flex-col gap-3 rounded-lg border border-border bg-bg/40 px-4 py-3 md:flex-row md:items-center md:justify-between">
        <div class="min-w-0">
          <p class="text-sm text-foreground">关闭窗口时</p>
          <p class="text-xs text-muted">默认智能处理：有连接时缩小到托盘，无连接时直接退出。</p>
        </div>
        <select
          :value="closePreference"
          :disabled="closePreferenceBusy"
          class="exv-select w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-foreground transition-colors focus:border-accent/50 focus:outline-none disabled:opacity-50 md:w-64"
          @change="saveClosePreference(($event.target as HTMLSelectElement).value as ClosePreference)"
        >
          <option
            v-for="option in closePreferenceOptions"
            :key="option.value"
            :value="option.value"
          >
            {{ option.label }}
          </option>
        </select>
      </div>

      <div class="border-t border-border pt-4">
        <div class="mb-3">
          <p class="text-sm font-medium text-foreground">Helper 服务</p>
          <p class="text-xs text-muted">安装后连接和断开不需要每次提权。</p>
        </div>
        <button
          :disabled="vpn.serviceBusy"
          :class="[
            'inline-flex items-center gap-2 rounded-lg px-5 py-2.5 text-sm font-medium text-white transition-colors disabled:opacity-50',
            serviceButtonInstalled ? 'bg-destructive hover:bg-destructive/90' : 'bg-accent hover:bg-accent/90',
          ]"
          @click="toggleService"
        >
          <Trash2 v-if="serviceButtonInstalled" class="h-4 w-4" />
          <Download v-else class="h-4 w-4" />
          {{ serviceButtonLabel }}
        </button>
      </div>

      <div class="border-t border-border pt-4">
        <div class="mb-3">
          <p class="text-sm font-medium text-foreground">配置导入 / 导出 / 重置</p>
          <p class="text-xs text-muted">导入或导出 VPN 配置；密码保护导出的文件可在不同设备间安全迁移。</p>
        </div>
        <input
          ref="importFileInput"
          type="file"
          class="hidden"
          accept=".json,.protected,.txt,application/json,application/octet-stream,text/plain"
          @change="handleImportFileChange"
        />
        <div class="flex flex-wrap gap-3">
          <button
            aria-label="导入配置"
            :disabled="importBusy"
            class="inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-foreground transition-colors hover:border-accent/50 disabled:opacity-50"
            @click="triggerImportConfig"
          >
            <Download class="h-4 w-4" />
            {{ importBusy ? '导入中...' : '导入配置' }}
          </button>
          <button
            aria-label="导出配置"
            :disabled="exportBusy"
            class="inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-foreground transition-colors hover:border-accent/50 disabled:opacity-50"
            @click="openExportDialog"
          >
            <Upload class="h-4 w-4" />
            {{ exportBusy && !showExportDialog ? '导出中...' : '导出配置' }}
          </button>
          <button
            class="inline-flex items-center gap-2 rounded-lg bg-destructive px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-destructive/90"
            @click="resetConfigAction"
          >
            <Trash2 class="h-4 w-4" />
            重置配置
          </button>
          <button
            class="inline-flex items-center gap-2 rounded-lg border border-destructive/50 px-4 py-2 text-sm text-destructive transition-colors hover:bg-destructive/10"
            @click="resetKeyAction"
          >
            <Key class="h-4 w-4" />
            重置加密密钥
          </button>
        </div>
      </div>

      <div v-if="isDesktop" class="border-t border-border pt-4">
        <div class="mb-3">
          <p class="text-sm font-medium text-foreground">终端 CLI</p>
          <p class="text-xs text-muted">
            {{ vpn.cliStatus?.installed ? '已安装全局 exv 命令。' : '未安装全局命令；仍可从应用包内 bin 目录直接运行 exv。' }}
          </p>
          <p class="mt-1 break-all font-mono text-[11px] text-muted">
            {{ vpn.cliStatus?.installed ? vpn.cliStatus.installPath : vpn.cliStatus?.targetPath }}
          </p>
          <p v-if="vpn.cliStatus?.warning" class="mt-1 text-xs text-warning">
            {{ vpn.cliStatus.warning }}
          </p>
          <p v-else-if="vpn.cliStatus?.installed && !vpn.cliStatus.availableInPath" class="mt-1 text-xs text-warning">
            已安装；请打开新终端让 PATH 生效。
          </p>
        </div>
        <div class="flex flex-wrap gap-3">
          <button
            :disabled="!!vpn.cliOperation"
            :class="[
              'inline-flex items-center gap-2 rounded-lg px-5 py-2.5 text-sm font-medium text-white transition-colors disabled:opacity-50',
              cliButtonInstalled ? 'bg-destructive hover:bg-destructive/90' : 'bg-accent hover:bg-accent/90',
            ]"
            @click="toggleCli"
          >
            <Trash2 v-if="cliButtonInstalled" class="h-4 w-4" />
            <Download v-else class="h-4 w-4" />
            {{ cliButtonLabel }}
          </button>
          <button
            :disabled="!!vpn.cliOperation"
            class="inline-flex items-center gap-2 rounded-lg border border-border px-4 py-2.5 text-sm text-foreground transition-colors hover:border-accent/50 disabled:opacity-50"
            @click="vpn.fetchCliStatus()"
          >
            <RefreshCcw class="h-4 w-4" />
            刷新
          </button>
        </div>
      </div>

      <div v-if="isDesktop" class="border-t border-border pt-4">
        <div class="mb-4 flex items-center gap-2">
          <span :class="runtimeReady ? 'text-success' : 'text-red-400'" class="text-lg leading-none">&#9679;</span>
          <span class="text-sm font-medium" :class="runtimeReady ? 'text-foreground' : 'text-red-400'">
            {{ runtimeReady ? '运行时就绪' : '运行时缺失，需要修复' }}
          </span>
        </div>

        <div class="space-y-4">
          <div class="grid gap-4 text-sm md:grid-cols-2">
            <div class="rounded-lg border border-border bg-bg p-4">
              <p class="mb-2 text-xs text-muted">当前 VPN 引擎</p>
              <p class="font-medium text-foreground">
                {{ runtimeSourceText }}
              </p>
              <p class="mt-2 break-all text-xs text-muted">
                {{ runtimePathText }}
              </p>
            </div>
            <div class="rounded-lg border border-border bg-bg p-4">
              <p class="mb-2 text-xs text-muted">版本</p>
              <p class="font-medium text-foreground">
                {{ config.runtimeStatus?.version || '未知' }}
              </p>
              <p class="mt-2 break-all text-xs text-muted">
                {{ runtimeDirectoryText }}
              </p>
            </div>
          </div>

          <div v-if="runtimeMissing" class="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            <p class="font-medium">原生运行时不可用</p>
            <p class="mt-1 text-xs text-red-300/80">
              {{ config.runtimeStatus?.missing_what || 'VPN 连接需要原生运行时组件。' }}
            </p>
            <p v-if="config.runtimeStatus?.recommended_action" class="mt-1 text-xs text-red-300/80">
              {{ config.runtimeStatus.recommended_action }}
            </p>
            <p v-if="config.runtimeStatus?.effect_on_connect" class="mt-1 text-xs text-red-300/60">
              {{ config.runtimeStatus.effect_on_connect }}
            </p>
          </div>

          <div v-if="driverSupported" class="space-y-4">
            <div class="flex items-center gap-2 text-sm">
              <CheckCircle v-if="driverReadiness === 'ready'" class="h-4 w-4 text-success" />
              <AlertTriangle v-else class="h-4 w-4" :class="driverReadinessColor" />
              <span :class="driverReadinessColor">{{ driverReadinessLabel }}</span>
              <span v-if="driverReadiness === 'unavailable'" class="text-xs text-red-400/80">- 需要至少一个可用隧道驱动</span>
              <span v-else-if="driverReadiness === 'degraded'" class="text-xs text-warning/80">- 首选驱动缺失，回退可用</span>
            </div>

            <div v-if="!anyDriverAvailable" class="rounded-lg border border-warning/30 bg-warning/10 px-4 py-3 text-sm text-warning">
              <p class="font-medium">隧道驱动缺失</p>
              <p class="mt-1 text-xs text-warning/80">
                需要至少一个可用的隧道驱动（Wintun 或 TAP）才能建立 VPN 连接。
              </p>
            </div>

            <div class="grid gap-4 md:grid-cols-2">
              <div>
                <label class="mb-1.5 block text-xs font-medium text-muted">Windows 隧道驱动</label>
                <select
                  :value="settingsForm.windows_tunnel_driver"
                  class="exv-select w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-foreground transition-colors focus:border-accent/50 focus:outline-none"
                  @change="updateSettingField('windows_tunnel_driver', ($event.target as HTMLSelectElement).value as SettingsConfig['windows_tunnel_driver'])"
                >
                  <option value="auto">自动（优先 Wintun）</option>
                  <option value="wintun">Wintun</option>
                  <option value="tap" disabled>TAP（后端未接入）</option>
                </select>
              </div>

              <div>
                <label class="mb-1.5 block text-xs font-medium text-muted">TAP 接口</label>
                <select
                  :value="settingsForm.windows_tap_interface"
                  :disabled="tapAdapters.length === 0"
                  class="exv-select w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-foreground transition-colors focus:border-accent/50 focus:outline-none disabled:opacity-50"
                  @change="updateSettingField('windows_tap_interface', ($event.target as HTMLSelectElement).value)"
                >
                  <option value="">选择 TAP 适配器</option>
                  <option v-for="adapter in tapAdapters" :key="adapter" :value="adapter">
                    {{ adapter }}
                  </option>
                </select>
              </div>
            </div>

            <div class="grid gap-4 text-sm md:grid-cols-2">
              <div class="rounded-lg border border-border bg-bg p-4">
                <div class="mb-2 flex items-center gap-2">
                  <p class="text-xs text-muted">Wintun</p>
                  <span v-if="!wintunMissing" class="rounded bg-success/10 px-2 py-0.5 text-xs text-success">就绪</span>
                  <span v-else class="rounded bg-warning/10 px-2 py-0.5 text-xs text-warning">缺失</span>
                </div>
                <p class="font-medium text-foreground">{{ wintunStatusText }}</p>
                <p v-if="wintunMissing && config.driverStatus?.wintun_recommended_action" class="mt-2 text-xs text-warning/80">
                  {{ config.driverStatus.wintun_recommended_action }}
                </p>
              </div>

              <div class="rounded-lg border border-border bg-bg p-4">
                <div class="mb-2 flex items-center gap-2">
                  <p class="text-xs text-muted">TAP</p>
                  <span class="rounded bg-warning/10 px-2 py-0.5 text-xs text-warning">后端未接入</span>
                  <span v-if="config.driverStatus?.tap_available" class="rounded bg-success/10 px-2 py-0.5 text-xs text-success">已安装</span>
                  <span v-else-if="config.driverStatus?.tap_can_install" class="rounded bg-warning/10 px-2 py-0.5 text-xs text-warning">可安装</span>
                  <span v-else class="rounded bg-red-500/10 px-2 py-0.5 text-xs text-red-400">不可用</span>
                </div>
                <p class="font-medium text-foreground">
                  {{ config.driverStatus?.tap_available ? '已检测到安装的适配器' : '未检测到 TAP 适配器' }}
                </p>
                <p v-if="tapMissing && config.driverStatus?.tap_recommended_action" class="mt-2 text-xs text-warning/80">
                  {{ config.driverStatus.tap_recommended_action }}
                </p>
                <p class="mt-2 text-xs text-warning/80">
                  TAP 后端未接入 native 引擎；安装 TAP 目前不能让 EXV 通过 TAP 建立连接。
                </p>
              </div>
            </div>

            <div class="flex flex-wrap gap-3">
              <button
                :disabled="busyDriver === 'wintun'"
                class="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-foreground transition-colors hover:border-accent/50 disabled:opacity-50"
                @click="installDriver('wintun')"
              >
                <HardDriveDownload class="h-4 w-4" />
                {{ busyDriver === 'wintun' ? '准备中...' : '准备 Wintun' }}
              </button>
              <button
                :disabled="busyDriver === 'tap' || !tapNativeBackendImplemented"
                title="TAP 后端未接入 native 引擎，安装驱动不会让当前连接路径可用"
                class="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-foreground transition-colors hover:border-accent/50 disabled:opacity-50"
                @click="installDriver('tap')"
              >
                <HardDriveDownload class="h-4 w-4" />
                {{ busyDriver === 'tap' ? '安装中...' : '安装 TAP' }}
              </button>
            </div>

            <div v-if="installFeedback" class="rounded-lg border border-border bg-bg p-3 text-xs text-muted">
              <template v-if="installFeedback.takes_effect === 'next_connect'">
                Wintun 运行时已就绪，下次连接时生效。
              </template>
              <template v-else>
                TAP 安装完成，立即生效。如已连接 VPN，建议断开重连。
              </template>
            </div>
          </div>
        </div>
      </div>

      <div v-if="systemMessage" class="flex items-center gap-3 pt-1">
        <div
          class="rounded-lg bg-success/10 px-4 py-2.5 text-sm text-success"
        >
          {{ systemMessage.text }}
        </div>
      </div>
    </div>

    <Teleport to="body">
      <ModalShell
        :open="showExportDialog"
        title="导出配置"
        description="选择是否一同导出已保存的 VPN 密码。"
        size="md"
        @close="closeExportDialog"
      >
        <div class="space-y-4">
          <label class="flex cursor-pointer items-start gap-3 rounded-lg border border-border bg-bg p-3">
            <input
              :checked="exportIncludePassword"
              type="checkbox"
              class="mt-1 h-4 w-4 cursor-pointer accent-accent"
              @change="updateExportIncludePassword(($event.target as HTMLInputElement).checked)"
            />
            <span>
              <span class="block text-sm font-medium text-foreground">一同导出密码</span>
              <span class="mt-1 block text-xs leading-5 text-muted">需要设置导出口令，用于保护包含密码的配置文件。</span>
            </span>
          </label>

          <div>
            <label class="mb-1.5 block text-xs font-medium text-muted">导出口令</label>
            <PasswordField
              v-model="exportPassword"
              :disabled="!exportIncludePassword"
              placeholder="选择导出密码时必填"
              input-class="w-full rounded-lg border border-border bg-bg px-3 py-2 pr-11 text-sm text-foreground placeholder:text-muted transition-colors focus:border-accent/50 focus:outline-none disabled:opacity-50"
              @blur="exportPasswordTouched = true"
            />
            <p
              v-if="exportPasswordRequired && exportPasswordTouched"
              class="mt-1.5 text-xs text-warning"
            >
              一同导出密码时，导出口令是必填项。
            </p>
          </div>
        </div>

        <template #actions>
          <button
            type="button"
            class="rounded-lg border border-border px-4 py-2 text-sm text-foreground transition-colors hover:border-accent/50"
            @click="closeExportDialog"
          >
            取消
          </button>
          <button
            type="button"
            :disabled="exportPasswordRequired || exportBusy"
            class="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent/90 disabled:opacity-50"
            @click="submitExportConfig"
          >
            {{ exportBusy ? '导出中...' : '导出' }}
          </button>
        </template>
      </ModalShell>
    </Teleport>
  </section>
</template>
