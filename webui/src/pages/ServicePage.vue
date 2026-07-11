<script setup lang="ts">
import { computed, onMounted, onUnmounted } from 'vue'
import { useVpnStore } from '../stores/vpn'
import { useUiStore } from '../stores/ui'
import { useSSE } from '../composables/useSSE'
import StatusBadge from '../components/StatusBadge.vue'
import { Download, RefreshCw, Terminal, Trash2 } from 'lucide-vue-next'

const vpn = useVpnStore()
const ui = useUiStore()
const { connect: eventsConnect, disconnect: eventsDisconnect } = useSSE()

const platform = computed(() => {
  const path = vpn.serviceStatus?.path || ''
  if (path.includes('LaunchDaemons') || path.includes('/usr/local/bin')) return 'darwin'
  if (path.includes('Program Files') || path.includes('exv-helper.exe')) return 'win32'
  return 'generic'
})

const installCommand = computed(() => platform.value === 'win32' ? 'exv service install' : 'sudo exv service install')
const uninstallCommand = computed(() => platform.value === 'win32' ? 'exv service uninstall' : 'sudo exv service uninstall')

const serviceBadgeStatus = computed(() => {
  if (!vpn.serviceStatus?.installed) return 'disconnected' as const
  return vpn.serviceStatus.running ? 'running' : 'stopped'
})

const showInstallButton = computed(() => {
  return vpn.serviceOperation === 'install' ||
    (!vpn.serviceStatus?.installed && vpn.serviceOperation !== 'uninstall')
})

const showUninstallButton = computed(() => {
  return vpn.serviceOperation === 'uninstall' ||
    (Boolean(vpn.serviceStatus?.installed) && vpn.serviceOperation !== 'install')
})

const serviceHeadline = computed(() => {
  if (!vpn.serviceStatus?.installed) return '辅助服务'
  return vpn.serviceStatus.label || '辅助服务'
})

const serviceSubtitle = computed(() => {
  return vpn.serviceStatus?.binary_path || vpn.serviceStatus?.path || '未安装'
})

onMounted(() => {
  vpn.fetchServiceStatus()
  eventsConnect()
})

onUnmounted(() => {
  eventsDisconnect()
})

function install() {
  void runServiceAction('install')
}

function uninstall() {
  void runServiceAction('uninstall')
}

async function runServiceAction(action: 'install' | 'uninstall') {
  const ok = action === 'install'
    ? await vpn.requestInstallService()
    : await vpn.requestUninstallService()
  await vpn.fetchServiceStatus()
  if (ok) {
    ui.addToast(action === 'install' ? '辅助服务安装完成' : '辅助服务卸载完成', 'success')
    return
  }
  if (vpn.serviceStatus?.operation_state === 'in_progress') {
    ui.addToast(action === 'install' ? '辅助服务安装已启动，正在更新状态' : '辅助服务卸载已启动，正在更新状态', 'warning')
    return
  }
  if (vpn.serviceStatus?.operation_state === 'warning') {
    ui.requestError({
      title: action === 'install' ? '辅助服务安装需确认' : '辅助服务卸载需确认',
      message: vpn.serviceStatus.warning || '请刷新服务状态或查看日志后确认。',
    })
    return
  }
  ui.requestError({
    title: action === 'install' ? '辅助服务安装未完成' : '辅助服务卸载未完成',
    message: '请查看操作输出或日志后重试。',
  })
}
</script>

<template>
  <div class="h-full overflow-hidden py-4">
    <h1 class="text-xl font-semibold text-foreground mb-4">服务管理</h1>

    <div class="grid h-[calc(100%-3rem)] grid-cols-2 gap-4">
    <div class="bg-surface border border-border rounded-xl p-5">
      <div class="flex items-center justify-between mb-6">
        <div class="flex items-center gap-3">
          <Terminal class="w-5 h-5 text-muted" />
          <div>
            <p class="text-sm font-medium text-foreground">{{ serviceHeadline }}</p>
            <p class="text-xs text-muted break-all">{{ serviceSubtitle }}</p>
            <p v-if="vpn.serviceStatus?.endpoint" class="text-xs text-muted break-all mt-1">
              {{ vpn.serviceStatus.endpoint }}
            </p>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <StatusBadge :status="serviceBadgeStatus" />
        </div>
      </div>

      <div class="grid grid-cols-2 md:grid-cols-5 gap-3 border-t border-border pt-5 text-xs">
        <div>
          <p class="text-muted mb-1">Installed</p>
          <p class="text-foreground">{{ vpn.serviceStatus?.installed ? 'yes' : 'no' }}</p>
        </div>
        <div>
          <p class="text-muted mb-1">Running</p>
          <p class="text-foreground">{{ vpn.serviceStatus?.running ? 'yes' : 'no' }}</p>
        </div>
        <div>
          <p class="text-muted mb-1">Available</p>
          <p class="text-foreground">{{ vpn.serviceStatus?.available ? 'yes' : 'no' }}</p>
        </div>
        <div>
          <p class="text-muted mb-1">Mode</p>
          <p class="text-foreground">{{ vpn.serviceStatus?.mode || 'unknown' }}</p>
        </div>
        <div>
          <p class="text-muted mb-1">State</p>
          <p class="text-foreground">{{ vpn.serviceStatus?.service_state ?? '--' }}</p>
        </div>
      </div>

      <p v-if="vpn.serviceStatus?.warning" class="mt-4 text-xs text-warning">
        {{ vpn.serviceStatus.warning }}
      </p>

      <div class="flex flex-wrap items-center gap-3 border-t border-border pt-5 mt-5">
        <button
          v-if="showInstallButton"
          :disabled="vpn.serviceBusy"
          class="flex items-center gap-2 bg-accent text-white rounded-md px-5 py-2 text-sm font-medium hover:bg-accent/90 disabled:opacity-50 transition-colors"
          @click="install"
        >
          <Download class="w-4 h-4" />
          {{ vpn.serviceOperation === 'install' ? '安装中...' : '安装服务' }}
        </button>

        <button
          v-if="showUninstallButton"
          :disabled="vpn.serviceBusy"
          class="flex items-center gap-2 bg-destructive text-white rounded-md px-5 py-2 text-sm font-medium hover:bg-destructive/90 disabled:opacity-50 transition-colors"
          @click="uninstall"
        >
          <Trash2 class="w-4 h-4" />
          {{ vpn.serviceOperation === 'uninstall' ? '卸载中...' : '卸载服务' }}
        </button>

        <button
          :disabled="vpn.serviceBusy"
          class="flex items-center gap-2 border border-border text-muted rounded-md px-5 py-2 text-sm hover:text-foreground hover:bg-surface disabled:opacity-50 transition-colors"
          @click="vpn.fetchServiceStatus()"
        >
          <RefreshCw class="w-4 h-4" />
          刷新
        </button>
      </div>
    </div>

    <div
      v-if="vpn.serviceProgress.length"
      class="bg-surface border border-border rounded-lg p-5"
    >
      <h2 class="text-sm font-medium text-foreground mb-3">操作输出</h2>
      <div class="bg-bg rounded-md p-4 font-mono text-xs text-foreground space-y-1 max-h-64 overflow-auto">
        <div v-for="(entry, index) in vpn.serviceProgress" :key="`${entry.timestamp}-${index}`">
          <span class="text-muted">{{ new Date(entry.timestamp).toLocaleTimeString() }}</span>
          <span class="ml-2">{{ entry.message }}</span>
        </div>
      </div>
    </div>

    <div v-else class="bg-surface border border-border rounded-lg p-5">
      <h2 class="text-sm font-medium text-foreground mb-3">操作输出</h2>
      <p class="text-sm text-muted">暂无服务操作输出。</p>
    </div>

    <div class="col-span-2 bg-surface border border-border rounded-lg p-5">
      <h2 class="text-sm font-medium text-foreground mb-3 flex items-center gap-2">
        <Terminal class="w-4 h-4" />
        终端命令
      </h2>
      <div class="bg-bg rounded-md p-4 font-mono text-xs text-foreground space-y-2">
        <div>
          <span class="text-muted"># 安装 helper 服务</span>
          <br />
          {{ installCommand }}
        </div>
        <div>
          <span class="text-muted"># 卸载 helper 服务</span>
          <br />
          {{ uninstallCommand }}
        </div>
        <div>
          <span class="text-muted"># 查看状态</span>
          <br />
          exv service status
        </div>
      </div>
    </div>
    </div>
  </div>
</template>
