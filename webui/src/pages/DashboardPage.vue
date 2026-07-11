<script setup lang="ts">
import { computed, ref } from 'vue'
import DashboardActionBar from '../components/dashboard/DashboardActionBar.vue'
import DashboardConnectionHero from '../components/dashboard/DashboardConnectionHero.vue'
import DashboardStatusRail from '../components/dashboard/DashboardStatusRail.vue'
import DashboardVisualStage from '../components/dashboard/DashboardVisualStage.vue'
import { useConfigStore } from '../stores/config'
import { useVpnStore } from '../stores/vpn'

defineOptions({ name: 'DashboardPage' })

const vpn = useVpnStore()
const config = useConfigStore()

const installServiceBeforeConnect = ref(true)

function switchToMinimalMode() {
  void config.saveSettings({ minimal_mode: true })
}

const connected = computed(() => Boolean(vpn.status?.connected))
const connecting = computed(() => vpn.connectInFlight)
const disconnecting = computed(() => vpn.disconnectInFlight)
const upstreamAdapters = computed(() => vpn.status?.upstream_virtual_adapters || [])
const hasUpstreamVirtual = computed(() => Boolean(vpn.status?.upstream_virtual_detected || upstreamAdapters.value.length > 0))
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

const vpnPathActive = computed(() => connected.value && Boolean(vpn.status?.network_ready))

const upstreamVirtualNames = computed(() => {
  return upstreamAdapters.value.map((adapter) => adapter.name).filter(Boolean).join('、')
})

const upstreamVirtualCaption = computed(() => {
  return upstreamVirtualNames.value || vpn.status?.upstream_virtual_message || '已检测到'
})

const networkProbeSummary = computed(() => {
  if (!vpn.status) return '正在探测本机出口'
  if (hasUpstreamVirtual.value) return `已发现代理 TUN：${upstreamVirtualCaption.value}`
  return '未发现代理 TUN，当前使用系统默认出口'
})

const routePolicyDescription = computed(() => {
  if (!vpn.status) return '启动后会显示 EXV 与系统出口的相对位置。'
  if (vpn.status.route_policy === 'exv-before-proxy-tun') {
    return connected.value
      ? '校园内网流量已写入 EXV 虚拟网卡；默认出口和代理 TUN 保持在 EXV 后方。'
      : '连接时校园内网路由会写入 EXV 虚拟网卡；默认出口和代理 TUN 保持在 EXV 后方。'
  }
  return connected.value
    ? '校园内网流量已写入 EXV 虚拟网卡，其他流量继续按系统默认出口处理。'
    : '连接时校园内网流量会进入 EXV 虚拟网卡，其他流量继续按系统默认出口处理。'
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
  return '准备建立校园网连接'
})

const visualStageDetail = computed(() => {
  if (disconnecting.value) return '正在关闭隧道、移除路由并恢复连接前状态。'
  if (connecting.value) return vpn.connectionProgress.description || routePolicyDescription.value
  if (connected.value) return routePolicyDescription.value
  if (vpn.lastError) return '查看弹窗提示后处理异常，再重新连接。'
  return `${networkProbeSummary.value}。${routePolicyDescription.value}`
})

function handlePowerClick() {
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

const uptimeFormatted = computed(() => {
  const total = vpn.displayUptimeSeconds
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
})

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

const statusRailItems = computed(() => [
  { label: '用户', value: vpn.status?.username || '--' },
  { label: '运行时长', value: connected.value ? uptimeFormatted.value : '--' },
  {
    label: '内网地址',
    value: vpn.status?.internal_ip || '--',
    tone: vpnPathActive.value ? 'accent' as const : 'muted' as const,
  },
  { label: 'VPN 服务器', value: vpn.status?.server || '未配置' },
  { label: '代理 TUN', value: hasUpstreamVirtual.value ? upstreamVirtualCaption.value : '--' },
  { label: '服务', value: serviceState.value.label, tone: serviceState.value.tone },
])
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
    />

    <DashboardStatusRail
      class="dashboard-page-grid__rail"
      :items="statusRailItems"
      :connection-state-label="connectionState.label"
      :connection-state-tone="connectionState.tone"
    />

    <DashboardActionBar
      class="dashboard-page-grid__actions"
      v-model:install-service-before-connect="installServiceBeforeConnect"
      :show-service-repair-action="showServiceRepairAction"
      :service-repair-disabled="vpn.serviceBusy"
      :service-repair-label="serviceRepairLabel"
      :show-install-service-choice="showInstallServiceChoice"
      :install-service-choice-disabled="installServiceChoiceDisabled"
      @repair="handleServiceRepairClick"
      @switch-to-minimal="switchToMinimalMode"
    />
  </div>
</template>

<style scoped>
.dashboard-page-grid {
  display: grid;
  min-height: 0;
  grid-template-columns: minmax(0, 1fr) 13rem;
  grid-template-rows: 9.25rem minmax(0, 1fr) 3.25rem;
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

.dashboard-page-grid__rail {
  grid-column: 2;
  grid-row: 1 / 3;
}

.dashboard-page-grid__actions {
  grid-column: 1 / 3;
  grid-row: 3;
}

@media (max-width: 860px) {
  .dashboard-page-grid {
    grid-template-columns: minmax(0, 1fr);
    grid-template-rows: auto minmax(16rem, 1fr) auto auto;
    overflow: auto;
  }

  .dashboard-page-grid__hero,
  .dashboard-page-grid__visual,
  .dashboard-page-grid__rail,
  .dashboard-page-grid__actions {
    grid-column: 1;
  }

  .dashboard-page-grid__hero {
    grid-row: 1;
  }

  .dashboard-page-grid__visual {
    grid-row: 2;
  }

  .dashboard-page-grid__rail {
    grid-row: 3;
  }

  .dashboard-page-grid__actions {
    grid-row: 4;
  }
}
</style>
