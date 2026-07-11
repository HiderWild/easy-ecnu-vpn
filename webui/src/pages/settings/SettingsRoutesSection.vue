<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Plus, Route as RouteIcon, Trash2 } from 'lucide-vue-next'
import type { SettingsConfig } from '../../stores/config'
import { useUiStore } from '../../stores/ui'
import { useVpnStore } from '../../stores/vpn'

const props = defineProps<{
  settingsDraft: SettingsConfig
}>()

const emit = defineEmits<{
  'update:settingsDraft': [value: SettingsConfig]
}>()

const vpn = useVpnStore()
const ui = useUiStore()

const routes = ref<string[]>([])
const newRoute = ref('')
const routesBusy = ref(false)
const routeMessage = ref<{ text: string } | null>(null)

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
const broadPrivateRouteWarningVisible = computed(() =>
  settingsForm.value.include_class_a_private_routes ||
  settingsForm.value.include_class_b_private_routes,
)

function updateSettingField<K extends keyof SettingsConfig>(key: K, value: SettingsConfig[K]) {
  emit('update:settingsDraft', {
    ...settingsForm.value,
    [key]: value,
  })
}

async function loadRoutes() {
  await vpn.fetchRoutes()
  routes.value = vpn.routes.map((r) => r.cidr)
}

async function addRoute() {
  const cidr = newRoute.value.trim()
  if (!cidr || routes.value.includes(cidr) || routesBusy.value) return

  routesBusy.value = true
  routeMessage.value = null
  try {
    await vpn.addRoute(cidr)
    routes.value = vpn.routes.map((entry) => entry.cidr)
    newRoute.value = ''
    routeMessage.value = { text: '路由已添加' }
  } catch (error: any) {
    ui.requestError({ title: '添加路由失败', message: error?.message || '添加失败' })
  } finally {
    routesBusy.value = false
  }
}

async function removeRoute(index: number) {
  if (routesBusy.value) return
  const cidr = routes.value[index]
  if (!cidr) return

  routesBusy.value = true
  routeMessage.value = null
  try {
    await vpn.removeRoute(cidr)
    routes.value = vpn.routes.map((entry) => entry.cidr)
    routeMessage.value = { text: '路由已删除' }
  } catch (error: any) {
    ui.requestError({ title: '删除路由失败', message: error?.message || '删除失败' })
  } finally {
    routesBusy.value = false
  }
}

onMounted(() => {
  void loadRoutes()
})
</script>

<template>
  <section class="rounded-xl border border-border bg-surface p-5">
    <h2 class="mb-4 flex items-center gap-2 text-base font-semibold text-foreground">
      <RouteIcon class="h-5 w-5 text-accent" />
      路由
    </h2>

    <p class="mb-4 text-sm text-muted">
      配置分流路由，仅将指定网段的流量通过 VPN 隧道。
    </p>

    <div class="mb-4 space-y-3 rounded-lg border border-border bg-bg p-4">
      <label class="flex cursor-pointer items-start gap-3">
        <input
          :checked="settingsForm.include_class_a_private_routes"
          type="checkbox"
          class="mt-1 h-4 w-4 cursor-pointer accent-accent"
          @change="updateSettingField('include_class_a_private_routes', ($event.target as HTMLInputElement).checked)"
        />
        <span>
          <span class="block text-sm font-medium text-foreground">处理所有 A 类内网地址（10 开头）</span>
          <span class="mt-0.5 block text-xs text-muted">连接时添加 10.0.0.0/8 路由。</span>
        </span>
      </label>

      <label class="flex cursor-pointer items-start gap-3">
        <input
          :checked="settingsForm.include_class_b_private_routes"
          type="checkbox"
          class="mt-1 h-4 w-4 cursor-pointer accent-accent"
          @change="updateSettingField('include_class_b_private_routes', ($event.target as HTMLInputElement).checked)"
        />
        <span>
          <span class="block text-sm font-medium text-foreground">处理所有 B 类内网地址（172.16-172.31 开头）</span>
          <span class="mt-0.5 block text-xs text-muted">连接时添加 172.16.0.0/12 路由。</span>
        </span>
      </label>

      <p
        v-if="broadPrivateRouteWarningVisible"
        class="rounded-lg border border-warning/30 bg-warning/10 px-3 py-2 text-xs text-warning"
      >
        将大段A类/B类内网地址经由 exv 处理可能导致本机物理局域网内某些资源无法访问。
      </p>
    </div>

    <div class="mb-4 flex items-center gap-3">
      <input
        v-model="newRoute"
        type="text"
        placeholder="例如 10.0.0.0/8"
        class="min-w-0 flex-1 rounded-lg border border-border bg-bg px-4 py-2.5 font-mono text-sm text-foreground placeholder:text-muted transition-colors focus:border-accent/50 focus:outline-none"
        @keyup.enter="addRoute"
      />
      <button
        :disabled="routesBusy"
        class="flex cursor-pointer items-center gap-2 rounded-lg border border-border px-4 py-2.5 text-sm text-foreground transition-colors hover:border-accent/50 disabled:cursor-default disabled:opacity-50"
        @click="addRoute"
      >
        <Plus class="h-4 w-4" />
        添加
      </button>
    </div>

    <div class="space-y-3">
      <div
        v-for="(routeItem, index) in routes"
        :key="routeItem"
        class="flex items-center gap-3 rounded-lg border border-border bg-bg px-4 py-2.5"
      >
        <span class="min-w-0 flex-1 truncate font-mono text-sm text-foreground">{{ routeItem }}</span>
        <button
          :disabled="routesBusy"
          class="cursor-pointer text-muted transition-colors hover:text-destructive disabled:cursor-default disabled:opacity-50"
          @click="removeRoute(index)"
        >
          <Trash2 class="h-4 w-4" />
        </button>
      </div>
    </div>

    <div
      v-if="routeMessage"
      class="mt-4 rounded-lg bg-success/10 px-4 py-2.5 text-sm text-success"
    >
      {{ routeMessage.text }}
    </div>
    <p v-else class="mt-4 text-xs text-muted">
      点击添加或垃圾桶后立即写入配置，无需再保存。
    </p>
  </section>
</template>
