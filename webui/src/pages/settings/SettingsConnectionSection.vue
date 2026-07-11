<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { EthernetPort } from 'lucide-vue-next'
import ToggleSwitch from '../../components/ToggleSwitch.vue'
import {
  useConfigStore,
  type CoreInspection,
  type DtlsSettingsMode,
  type SettingsConfig,
} from '../../stores/config'
import { useUiStore } from '../../stores/ui'
import { normalizeError } from '../../stores/vpn'

const props = defineProps<{
  settingsDraft: SettingsConfig
}>()

const emit = defineEmits<{
  'update:settingsDraft': [value: SettingsConfig]
}>()

const config = useConfigStore()
const ui = useUiStore()
const isDesktop = typeof window !== 'undefined' && !!window.exv

const coreInspection = ref<CoreInspection | null>(null)
const coreMaintenanceBusy = ref(false)

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

const dtlsModeOptions: Array<{ value: DtlsSettingsMode; label: string; help: string }> = [
  { value: 'auto', label: '自动', help: '连接成功后优先尝试 DTLS，失败会回落 CSTP/TLS。' },
  { value: 'enabled', label: '开启', help: '每次连接成功后都尝试 DTLS。' },
  { value: 'disabled', label: '关闭', help: '仅使用 CSTP/TLS。' },
]

const dtlsModeModel = computed<DtlsSettingsMode>({
  get: () => settingsForm.value.dtls_mode ?? (settingsForm.value.dtls ? 'auto' : 'disabled'),
  set: (value) => {
    emit('update:settingsDraft', {
      ...settingsForm.value,
      dtls_mode: value,
      dtls: value !== 'disabled',
    })
  },
})

const dtlsModeHelp = computed(() =>
  dtlsModeOptions.find((option) => option.value === dtlsModeModel.value)?.help ??
  dtlsModeOptions[0].help,
)

function setDtlsMode(value: DtlsSettingsMode) {
  dtlsModeModel.value = value
}

const autoReconnectModel = computed({
  get: () => settingsForm.value.auto_reconnect,
  set: (value: boolean) => updateSettingField('auto_reconnect', value),
})

const showCoreMaintenanceBanner = computed(() => {
  const inspection = coreInspection.value
  if (!inspection) return false
  return inspection.state === 'broken' || inspection.risk === 'high'
})

function updateSettingField<K extends keyof SettingsConfig>(key: K, value: SettingsConfig[K]) {
  emit('update:settingsDraft', {
    ...settingsForm.value,
    [key]: value,
  })
}

function updateNumberField(key: 'mtu' | 'retry_limit', event: Event) {
  const value = Number((event.target as HTMLInputElement).value)
  updateSettingField(key, key === 'retry_limit' ? Math.max(0, Math.trunc(value || 0)) : value)
}

async function inspectCoreSilently() {
  try {
    coreInspection.value = await config.inspectCore()
  } catch {
    coreInspection.value = null
  }
}

function killStaleCoreAction() {
  ui.requestConfirm('确认终止该内核进程？此操作不可撤销。', async () => {
    if (coreMaintenanceBusy.value) return
    coreMaintenanceBusy.value = true
    try {
      await config.killStaleCore(true)
      ui.addToast('已清理', 'success')
      await inspectCoreSilently()
    } catch (error) {
      ui.requestError({ title: '清理残留进程失败', message: normalizeError(error).message })
    } finally {
      coreMaintenanceBusy.value = false
    }
  })
}

onMounted(async () => {
  if (isDesktop) {
    void inspectCoreSilently()
  }
})
</script>

<template>
  <section class="rounded-xl border border-border bg-surface p-5">
    <h2 class="mb-4 flex items-center gap-2 text-base font-semibold text-foreground">
      <EthernetPort class="h-5 w-5 text-accent" />
      连接
    </h2>

    <div
      v-if="showCoreMaintenanceBanner"
      class="mb-4 rounded-lg border border-warning/30 bg-warning/10 px-4 py-3 text-sm text-warning"
    >
      <p class="font-medium">检测到残留 / 异常的 VPN 内核进程</p>
      <p class="mt-1 text-xs text-warning/80">
        已发现可能无响应或卡死的内核（pid {{ coreInspection?.pid ?? '-' }}）。是否清理？
      </p>
      <button
        :disabled="coreMaintenanceBusy"
        class="mt-3 rounded-lg border border-warning/50 px-4 py-2 text-xs font-medium text-warning transition-colors hover:bg-warning/20 disabled:opacity-50"
        @click="killStaleCoreAction"
      >
        清理残留进程
      </button>
    </div>

    <div class="space-y-5">
      <div>
        <label class="mb-1.5 block text-xs font-medium text-muted">MTU</label>
        <input
          :value="settingsForm.mtu"
          type="number"
          min="576"
          max="1500"
          class="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-foreground transition-colors focus:border-accent/50 focus:outline-none"
          @input="updateNumberField('mtu', $event)"
        />
      </div>

      <div class="rounded-lg border border-border bg-bg/40 px-4 py-3">
        <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div class="min-w-0">
            <p class="text-sm text-foreground">DTLS</p>
            <p class="text-xs text-muted">{{ dtlsModeHelp }}</p>
          </div>
          <div class="inline-grid w-full grid-cols-3 rounded-lg border border-border bg-bg p-1 text-xs sm:w-auto">
            <button
              v-for="option in dtlsModeOptions"
              :key="option.value"
              type="button"
              :class="[
                'min-w-16 rounded-md px-3 py-1.5 font-medium transition-colors',
                dtlsModeModel === option.value
                  ? 'bg-accent text-white'
                  : 'text-muted hover:text-foreground',
              ]"
              @click="setDtlsMode(option.value)"
            >
              {{ option.label }}
            </button>
          </div>
        </div>
      </div>

      <div class="flex items-center justify-between rounded-lg border border-border bg-bg/40 px-4 py-3">
        <div>
          <p class="text-sm text-foreground">断线重连</p>
          <p class="text-xs text-muted">连接进程意外退出后自动尝试重新连接</p>
        </div>
        <ToggleSwitch v-model="autoReconnectModel" />
      </div>

      <div>
        <label class="mb-1.5 block text-xs font-medium text-muted">重连尝试次数</label>
        <input
          :value="settingsForm.retry_limit"
          type="number"
          min="0"
          :disabled="!autoReconnectModel"
          class="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-foreground transition-colors focus:border-accent/50 focus:outline-none disabled:cursor-not-allowed disabled:opacity-60"
          @input="updateNumberField('retry_limit', $event)"
        />
        <p class="mt-1 text-xs text-muted">开启断线重连时，0 表示无限重连；关闭断线重连后不会自动重连。</p>
      </div>
    </div>
  </section>
</template>
