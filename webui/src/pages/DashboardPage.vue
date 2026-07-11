<script setup lang="ts">
import { computed, ref } from 'vue'
import DashboardConnectionHero from '../components/dashboard/DashboardConnectionHero.vue'
import DashboardVisualStage from '../components/dashboard/DashboardVisualStage.vue'
import { useConfigStore } from '../stores/config'
import { useVpnStore } from '../stores/vpn'

defineOptions({ name: 'DashboardPage' })

const vpn = useVpnStore()
const config = useConfigStore()

const installServiceBeforeConnect = ref(true)

const minimizeToTrayOnConnect = computed({
  get: () => config.settings.minimize_to_tray_on_connect,
  set: (value: boolean) => {
    void config.saveSettings({ minimize_to_tray_on_connect: value })
  },
})

const autoReconnect = computed({
  get: () => config.settings.auto_reconnect,
  set: (value: boolean) => {
    void config.saveSettings({ auto_reconnect: value })
  },
})

const retryLimit = computed({
  get: () => config.settings.retry_limit,
  set: (value: number) => {
    void config.saveSettings({ retry_limit: Math.max(0, Math.trunc(value || 0)) })
  },
})

const connected = computed(() => Boolean(vpn.status?.connected))
const connecting = computed(() => vpn.connectInFlight)
const disconnecting = computed(() => vpn.disconnectInFlight)
const showInstallServiceChoice = computed(() => (
  !connected.value &&
  !connecting.value &&
  !disconnecting.value &&
  !vpn.loading &&
  !vpn.serviceBusy &&
  !vpn.serviceAvailable &&
  !vpn.serviceInstalled
))
const installServiceChoiceDisabled = computed(() => connecting.value || disconnecting.value || vpn.loading || vpn.serviceBusy)
const showMinimizeToTrayChoice = computed(() => !connected.value && !connecting.value && !disconnecting.value)
const showServiceRepairAction = computed(() => (
  !connected.value &&
  !connecting.value &&
  !disconnecting.value &&
  !vpn.loading &&
  vpn.serviceInstalled &&
  !vpn.serviceAvailable
))
const serviceRepairLabel = '尝试修复'

const statusLabel = computed(() => {
  if (disconnecting.value) return '正在断开'
  if (connecting.value) return vpn.connectionProgress.label
  if (connected.value) return '连接已建立'
  if (vpn.lastError) return '需要处理'
  return '未连接'
})

const statusDescription = computed(() => {
  if (disconnecting.value) return '正在关闭隧道并恢复本机网络状态。'
  if (connecting.value) return vpn.connectionProgress.description
  if (connected.value) {
    return vpn.status?.network_ready ? '隧道接口和路由已写入，正在通过 EXV 转发校园网流量。' : 'VPN 进程已启动，正在等待网络就绪。'
  }
  if (vpn.lastError) return '请在弹窗中处理本次操作失败。'
  if (vpn.serviceAvailable) return '服务可用，点击电源按钮即可连接。'
  if (vpn.serviceInstalled) return '服务已安装但当前不可用，点击电源按钮会尝试使用可用后端连接。'
  return installServiceBeforeConnect.value
    ? '点击电源按钮会先安装服务，然后自动建立连接。'
    : '点击电源按钮会为本次连接请求临时授权。'
})

const powerButtonLabel = computed(() => {
  if (vpn.loading || vpn.serviceBusy) return '处理中'
  if (connecting.value) return '取消连接'
  if (connected.value) return '断开连接'
  return '连接'
})

const powerAnimating = computed(() => connecting.value || vpn.loading || disconnecting.value)
const powerButtonClass = computed(() => {
  if (powerAnimating.value) return 'bg-warning text-white hover:bg-warning/90 shadow-warning/20'
  if (connected.value) return 'bg-accent text-white hover:bg-accent/90 shadow-accent/20'
  return 'bg-destructive text-white hover:bg-destructive/90 shadow-destructive/20'
})
const powerButtonDisabled = computed(() => !connecting.value && (vpn.loading || vpn.serviceBusy))

const routePolicyDescription = computed(() => {
  if (!vpn.status) return '正在应用校园网路由和虚拟网卡配置。'
  if (vpn.status.route_policy === 'exv-before-proxy-tun') {
    return connected.value
      ? '校园内网流量已写入 EXV 虚拟网卡；默认出口和代理 TUN 保持在 EXV 后方。'
      : '正在应用校园网路由和虚拟网卡配置。'
  }
  return connected.value
    ? '校园内网流量已写入 EXV 虚拟网卡，其他流量继续按系统默认出口处理。'
    : '正在应用校园网路由和虚拟网卡配置。'
})

const visualStageTone = computed(() => {
  if (disconnecting.value || connecting.value) return 'warning' as const
  if (connected.value) return 'accent' as const
  return 'muted' as const
})

const visualStageActive = computed(() => connecting.value || disconnecting.value)

const visualStageHeadline = computed(() => {
  if (disconnecting.value) return '正在恢复本机网络'
  if (connecting.value) return vpn.connectionProgress.label || '正在建立连接'
  if (connected.value) return vpn.status?.network_ready ? '校园网通道运行中' : '等待网络就绪'
  if (vpn.lastError) return '上次连接需要处理'
  return ''
})

const visualStageDetail = computed(() => {
  if (disconnecting.value) return '正在关闭隧道、移除路由并恢复连接前状态。'
  if (connecting.value) return vpn.connectionProgress.description || routePolicyDescription.value
  if (connected.value) return routePolicyDescription.value
  if (vpn.lastError) return '查看弹窗提示后处理异常，再重新连接。'
  return ''
})

const visualStageSteps = computed(() => connecting.value ? vpn.connectionProgressSteps : [])
const visualStageCurrentKey = computed(() => connecting.value ? vpn.connectionProgress.key : '')
const showPreConnectInfo = computed(() => !connected.value && !connecting.value && !disconnecting.value)

const coreStatusLabel = computed(() => {
  if (vpn.status) return '正常'
  if (vpn.lastErrorType === 'native_failure' || vpn.lastErrorType === 'parse_failure') return '断连'
  return '断连'
})

const coreStatusTone = computed(() => (vpn.status ? 'accent' as const : 'warning' as const))
const proxyTunLabel = computed(() => vpn.upstreamVirtualDetected ? vpn.upstreamVirtualLabel : '--')

function handlePowerClick() {
  if (vpn.dashboardConnectGuardHeld) return
  if (connecting.value) {
    void vpn.cancelConnect()
    return
  }
  if (vpn.loading || vpn.serviceBusy) return
  vpn.connectFromDashboard(showInstallServiceChoice.value && installServiceBeforeConnect.value)
}

function handleServiceRepairClick() {
  if (vpn.serviceBusy || vpn.loading) return
  void vpn.repairService()
}

const serviceState = computed(() => {
  if (vpn.serviceBusy) return { label: '处理中', tone: 'warning' as const }
  if (vpn.serviceAvailable) return { label: '可用', tone: 'accent' as const }
  if (vpn.serviceInstalled) return { label: '需修复', tone: 'warning' as const }
  return { label: '未安装', tone: 'muted' as const }
})

const connectionState = computed(() => {
  if (disconnecting.value) return { label: '正在断开', tone: 'warning' as const }
  if (connecting.value) return { label: '连接中', tone: 'warning' as const }
  if (vpn.lastError) return { label: '需要处理', tone: 'warning' as const }
  if (!connected.value) return { label: '未连接', tone: 'muted' as const }
  return { label: '已连接', tone: 'accent' as const }
})

</script>

<template>
  <div class="dashboard-page-grid h-full">
    <h1 class="sr-only text-3xl">主面板</h1>

    <DashboardConnectionHero
      class="dashboard-page-grid__hero"
      :connected="connected"
      :connecting="connecting"
      :power-animating="powerAnimating"
      :power-button-class="powerButtonClass"
      :power-button-label="powerButtonLabel"
      :power-button-disabled="powerButtonDisabled"
      :status-label="statusLabel"
      :status-description="statusDescription"
      @power="handlePowerClick"
    />

    <DashboardVisualStage
      class="dashboard-page-grid__visual"
      :state-label="connectionState.label"
      :headline="visualStageHeadline"
      :detail="visualStageDetail"
      :tone="visualStageTone"
      :active="visualStageActive"
      :steps="visualStageSteps"
      :current-key="visualStageCurrentKey"
      v-model:install-service-before-connect="installServiceBeforeConnect"
      v-model:minimize-to-tray-on-connect="minimizeToTrayOnConnect"
      v-model:auto-reconnect="autoReconnect"
      v-model:retry-limit="retryLimit"
      :show-pre-connect-info="showPreConnectInfo"
      :show-service-repair-action="showServiceRepairAction"
      :service-repair-disabled="vpn.serviceBusy"
      :service-repair-label="serviceRepairLabel"
      :show-install-service-choice="showInstallServiceChoice"
      :install-service-choice-disabled="installServiceChoiceDisabled"
      :show-minimize-to-tray-choice="showMinimizeToTrayChoice"
      :core-status-label="coreStatusLabel"
      :core-status-tone="coreStatusTone"
      :service-status-label="serviceState.label"
      :service-status-tone="serviceState.tone"
      :proxy-tun-label="proxyTunLabel"
      @repair="handleServiceRepairClick"
    />
  </div>
</template>

<style scoped>
.dashboard-page-grid {
  display: grid;
  min-height: 0;
  grid-template-rows: 9.25rem minmax(0, 1fr);
  gap: 0.75rem;
  overflow: hidden;
}

.dashboard-page-grid__hero {
  grid-column: 1;
  grid-row: 1;
}

.dashboard-page-grid__visual {
  grid-column: 1;
  grid-row: 2;
}

@media (max-width: 860px) {
  .dashboard-page-grid {
    grid-template-rows: auto minmax(16rem, 1fr);
    overflow: auto;
  }

  .dashboard-page-grid__hero,
  .dashboard-page-grid__visual {
    grid-column: 1;
  }

  .dashboard-page-grid__hero {
    grid-row: 1;
  }

  .dashboard-page-grid__visual {
    grid-row: 2;
  }
}
</style>
