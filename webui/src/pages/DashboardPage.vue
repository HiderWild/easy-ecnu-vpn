<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import type { Component, CSSProperties } from 'vue'
import {
  Cloud,
  EthernetPort,
  LockKeyhole,
  Server,
} from 'lucide-vue-next'
import DashboardActionBar from '../components/dashboard/DashboardActionBar.vue'
import DashboardConnectionHero from '../components/dashboard/DashboardConnectionHero.vue'
import DashboardStatusRail from '../components/dashboard/DashboardStatusRail.vue'
import DashboardTopologyMap from '../components/dashboard/DashboardTopologyMap.vue'
import { useConfigStore } from '../stores/config'
import { useVpnStore } from '../stores/vpn'

defineOptions({ name: 'DashboardPage' })

const vpn = useVpnStore()
const config = useConfigStore()

const installServiceBeforeConnect = ref(true)

function switchToMinimalMode() {
  void config.saveSettings({ minimal_mode: true })
}

onUnmounted(() => {
  if (nodeTweenFrame) {
    cancelAnimationFrame(nodeTweenFrame)
    nodeTweenFrame = 0
  }
  clearReadySegmentTimers()
})

const connected = computed(() => Boolean(vpn.status?.connected))
const connecting = computed(() => vpn.connectInFlight)
const disconnecting = computed(() => vpn.disconnectInFlight)
const upstreamAdapters = computed(() => vpn.status?.upstream_virtual_adapters || [])
const hasUpstreamVirtual = computed(() => Boolean(vpn.status?.upstream_virtual_detected || upstreamAdapters.value.length > 0))
const progressKey = computed(() => connecting.value ? vpn.connectionProgress.key : '')
const adapterStageStarted = computed(() => connecting.value && ['adapter', 'routes', 'network-ready'].includes(progressKey.value))
const showExvAdapter = computed(() => connected.value || disconnecting.value || adapterStageStarted.value)
const vpnServerStageComplete = computed(() => connected.value || disconnecting.value || (connecting.value && ['adapter', 'routes', 'network-ready'].includes(progressKey.value)))
const routeStageComplete = computed(() => connected.value || disconnecting.value || (connecting.value && progressKey.value === 'network-ready'))
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

const powerButtonClass = computed(() => {
  if (powerAnimating.value) return 'bg-warning text-white hover:bg-warning/90 shadow-warning/20'
  if (connected.value) return 'bg-accent text-white hover:bg-accent/90 shadow-accent/20'
  return 'bg-destructive text-white hover:bg-destructive/90 shadow-destructive/20'
})
const powerAnimating = computed(() => connecting.value || vpn.loading || disconnecting.value)
const powerButtonDisabled = computed(() => !connecting.value && (vpn.loading || vpn.serviceBusy))

const vpnPathActive = computed(() => connected.value && Boolean(vpn.status?.network_ready))
const vpnPathPending = computed(() => connecting.value || (connected.value && !vpn.status?.network_ready))
const internetPathReady = computed(() => true)

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

const upstreamVirtualTooltip = computed(() => `${networkProbeSummary.value}。${routePolicyDescription.value}`)

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

const arcViewBox = {
  width: 760,
  height: 360,
  centerX: 380,
  centerY: 318,
  radius: 305,
  startAngle: 175,
  endAngle: 365,
}
const NODE_EXCLUSION_RADIUS = 58
const NODE_EXCLUSION_ANGLE = (NODE_EXCLUSION_RADIUS / arcViewBox.radius) * (180 / Math.PI)

type TopologyNode = {
  key: string
  title: string
  caption: string
  tooltip?: string
  icon?: Component
  tone?: string
  pulseKeys: string[]
}

const topologyNodes = computed(() => {
  const nodes: TopologyNode[] = [
    { key: 'traffic', title: '本地流量', caption: 'Local', pulseKeys: ['authorization'] },
  ]
  if (showExvAdapter.value) {
    nodes.push({
      key: 'exv',
      title: 'EXV 虚拟网卡',
      caption: vpn.status?.internal_ip || '准备中',
      icon: EthernetPort,
      tone: vpnPathActive.value ? 'accent' : 'warning',
      pulseKeys: ['oneshot-helper', 'adapter'],
    })
  }
  if (hasUpstreamVirtual.value) {
    nodes.push({
      key: 'upstream',
      title: '代理 TUN',
      caption: upstreamVirtualCaption.value,
      tooltip: upstreamVirtualTooltip.value,
      icon: EthernetPort,
      tone: 'accent',
      pulseKeys: ['routes'],
    })
  }
  nodes.push(
    {
      key: 'physical',
      title: '物理网卡',
      caption: '出口接口',
      icon: EthernetPort,
      tone: 'accent',
      pulseKeys: ['routes'],
    },
    {
      key: 'internet',
      title: '互联网',
      caption: '默认出口',
      icon: Cloud,
      tone: 'accent',
      pulseKeys: ['vpn-server'],
    },
    {
      key: 'server',
      title: 'VPN 服务器',
      caption: vpn.status?.server || '未配置',
      icon: Server,
      tone: vpnPathActive.value ? 'accent' : vpnPathPending.value ? 'warning' : 'muted',
      pulseKeys: ['vpn-server'],
    },
    {
      key: 'lock',
      title: '内网资源',
      caption: 'Campus',
      icon: LockKeyhole,
      tone: vpnPathActive.value ? 'accent' : vpnPathPending.value ? 'warning' : 'muted',
      pulseKeys: ['network-ready'],
    },
  )
  return nodes
})

type ArcNodeTarget = TopologyNode & {
  x: number
  y: number
  angle: number
}

type AnimatedArcNode = ArcNodeTarget & {
  opacity: number
  scale: number
  leaving?: boolean
  style: CSSProperties
}

const NODE_TWEEN_MS = 500
const animatedArcNodes = ref<AnimatedArcNode[]>([])
let nodeTweenFrame = 0

function easeOutCubic(t: number) {
  return 1 - Math.pow(1 - t, 3)
}

function positionForAngle(angle: number) {
  const rad = (angle * Math.PI) / 180
  return {
    x: arcViewBox.centerX + arcViewBox.radius * Math.cos(rad),
    y: arcViewBox.centerY + arcViewBox.radius * Math.sin(rad),
  }
}

function nodeWithStyle(node: ArcNodeTarget & { opacity: number; scale: number; leaving?: boolean }): AnimatedArcNode {
  return {
    ...node,
    style: {
      left: `${(node.x / arcViewBox.width) * 100}%`,
      top: `${(node.y / arcViewBox.height) * 100}%`,
      opacity: node.opacity,
      transform: `translate(-50%, -50%) scale(${node.scale})`,
    },
  }
}

const targetArcNodes = computed<ArcNodeTarget[]>(() => {
  const nodes = topologyNodes.value
  const range = arcViewBox.endAngle - arcViewBox.startAngle
  return nodes.map((node, index) => {
    const angle = nodes.length === 1
      ? 270
      : arcViewBox.startAngle + (range * index) / (nodes.length - 1)
    const { x, y } = positionForAngle(angle)
    return {
      ...node,
      x,
      y,
      angle,
    }
  })
})

watch(
  targetArcNodes,
  (targets) => {
    if (nodeTweenFrame) {
      cancelAnimationFrame(nodeTweenFrame)
      nodeTweenFrame = 0
    }

    const currentByKey = new Map(animatedArcNodes.value.map((node) => [node.key, node]))
    const targetKeys = new Set(targets.map((node) => node.key))
    const tweens = [
      ...targets.map((target) => {
        const current = currentByKey.get(target.key)
        return {
          target,
          fromAngle: current?.angle ?? target.angle,
          toAngle: target.angle,
          fromOpacity: current?.opacity ?? 0,
          toOpacity: 1,
          fromScale: current?.scale ?? 0.72,
          toScale: 1,
          leaving: false,
        }
      }),
      ...animatedArcNodes.value
        .filter((node) => !targetKeys.has(node.key))
        .map((node) => ({
          target: node,
          fromAngle: node.angle,
          toAngle: node.angle,
          fromOpacity: node.opacity,
          toOpacity: 0,
          fromScale: node.scale,
          toScale: 0.72,
          leaving: true,
        })),
    ]

    if (tweens.length === 0) {
      animatedArcNodes.value = []
      return
    }

    const startedAt = performance.now()
    const step = (now: number) => {
      const raw = Math.min(1, (now - startedAt) / NODE_TWEEN_MS)
      const eased = easeOutCubic(raw)
      animatedArcNodes.value = tweens.map((tween) => {
        const angle = tween.fromAngle + (tween.toAngle - tween.fromAngle) * eased
        const { x, y } = positionForAngle(angle)
        return nodeWithStyle({
          ...tween.target,
          angle,
          x,
          y,
          opacity: tween.fromOpacity + (tween.toOpacity - tween.fromOpacity) * eased,
          scale: tween.fromScale + (tween.toScale - tween.fromScale) * eased,
          leaving: tween.leaving,
        })
      })

      if (raw < 1) {
        nodeTweenFrame = requestAnimationFrame(step)
        return
      }

      animatedArcNodes.value = targets.map((target) => nodeWithStyle({
        ...target,
        opacity: 1,
        scale: 1,
      }))
      nodeTweenFrame = 0
    }

    nodeTweenFrame = requestAnimationFrame(step)
  },
  { immediate: true },
)

function segmentPath(from: ArcNodeTarget, to: ArcNodeTarget) {
  const direction = to.angle >= from.angle ? 1 : -1
  const startAngle = from.angle + direction * NODE_EXCLUSION_ANGLE
  const endAngle = to.angle - direction * NODE_EXCLUSION_ANGLE
  if ((endAngle - startAngle) * direction <= 0) {
    const midpointAngle = from.angle + ((to.angle - from.angle) / 2)
    const midpoint = positionForAngle(midpointAngle)
    return `M ${midpoint.x.toFixed(2)} ${midpoint.y.toFixed(2)}`
  }
  const start = positionForAngle(startAngle)
  const end = positionForAngle(endAngle)
  const largeArc = Math.abs(endAngle - startAngle) > 180 ? 1 : 0
  const sweep = direction > 0 ? 1 : 0
  return `M ${start.x.toFixed(2)} ${start.y.toFixed(2)} A ${arcViewBox.radius} ${arcViewBox.radius} 0 ${largeArc} ${sweep} ${end.x.toFixed(2)} ${end.y.toFixed(2)}`
}

const arcSegments = computed(() => {
  const nodes = animatedArcNodes.value.filter((node) => !node.leaving)
  return nodes.slice(0, -1).map((node, index) => {
    const next = nodes[index + 1]
    return {
      key: `${node.key}-${next.key}`,
      from: node.key,
      to: next.key,
      d: segmentPath(node, next),
    }
  })
})

const readySegmentKeys = computed(() => {
  const ready = new Set<string>()
  if (internetPathReady.value) {
    if (hasUpstreamVirtual.value) {
      ready.add(showExvAdapter.value ? 'upstream-physical' : 'traffic-upstream')
      ready.add('upstream-physical')
    } else if (!showExvAdapter.value) {
      ready.add('traffic-physical')
    }
    ready.add('physical-internet')
  }
  if (vpnServerStageComplete.value) {
    ready.add('internet-server')
  }
  if (routeStageComplete.value) {
    if (showExvAdapter.value) {
      ready.add('traffic-exv')
      ready.add(hasUpstreamVirtual.value ? 'exv-upstream' : 'exv-physical')
      if (hasUpstreamVirtual.value) ready.add('upstream-physical')
    } else {
      ready.add('traffic-physical')
    }
  }
  if (vpnPathActive.value || disconnecting.value) {
    ready.add('server-lock')
  }
  return ready
})

const activePulseKeys = computed(() => {
  if (!connecting.value) return []
  const key = progressKey.value
  if (['authorization', 'oneshot-helper'].includes(key)) return []
  if (key === 'adapter') {
    return ['traffic-exv']
  }
  if (key === 'routes') {
    if (!showExvAdapter.value) return ['traffic-physical']
    return hasUpstreamVirtual.value ? ['traffic-exv', 'exv-upstream'] : ['traffic-exv', 'exv-physical']
  }
  if (key === 'vpn-server') return ['internet-server']
  if (key === 'network-ready') return ['server-lock']
  return []
})

type ReadySegmentPhase = 'entering' | 'steady' | 'disconnecting' | 'leaving'
type VisibleReadySegment = {
  key: string
  d: string
  phase: ReadySegmentPhase
}

const READY_SEGMENT_MS = 720
const visibleReadySegments = ref<VisibleReadySegment[]>([])
const readySegmentTimers = new Map<string, number>()

function setReadySegmentTimer(key: string, callback: () => void) {
  const current = readySegmentTimers.get(key)
  if (current) window.clearTimeout(current)
  readySegmentTimers.set(key, window.setTimeout(() => {
    readySegmentTimers.delete(key)
    callback()
  }, READY_SEGMENT_MS))
}

function clearReadySegmentTimer(key: string) {
  const current = readySegmentTimers.get(key)
  if (!current) return
  window.clearTimeout(current)
  readySegmentTimers.delete(key)
}

function clearReadySegmentTimers() {
  readySegmentTimers.forEach((timer) => window.clearTimeout(timer))
  readySegmentTimers.clear()
}

watch(
  () => ({
    ready: Array.from(readySegmentKeys.value).sort().join(','),
    segments: arcSegments.value.map((segment) => `${segment.key}:${segment.d}`).join('|'),
  }),
  () => {
    const segmentMap = new Map(arcSegments.value.map((segment) => [segment.key, segment.d]))
    const ready = readySegmentKeys.value
    const previousByKey = new Map(visibleReadySegments.value.map((segment) => [segment.key, segment]))
    const next: VisibleReadySegment[] = []

    previousByKey.forEach((segment, key) => {
      const d = segmentMap.get(key) || segment.d
      if (ready.has(key)) {
        clearReadySegmentTimer(`leave-${key}`)
        const phase = disconnecting.value
          ? 'disconnecting'
          : segment.phase === 'leaving' || segment.phase === 'disconnecting'
            ? 'entering'
            : segment.phase
        next.push({ ...segment, d, phase })
        return
      }
      if (segment.phase !== 'leaving') {
        next.push({ key, d, phase: 'leaving' })
        setReadySegmentTimer(`leave-${key}`, () => {
          visibleReadySegments.value = visibleReadySegments.value.filter((item) => item.key !== key)
        })
      } else {
        next.push({ ...segment, d })
      }
    })

    ready.forEach((key) => {
      if (previousByKey.has(key)) return
      const d = segmentMap.get(key)
      if (!d) return
      next.push({ key, d, phase: disconnecting.value ? 'disconnecting' : 'entering' })
      setReadySegmentTimer(`enter-${key}`, () => {
        visibleReadySegments.value = visibleReadySegments.value.map((segment) => (
          segment.key === key && segment.phase === 'entering'
            ? { ...segment, phase: 'steady' }
            : segment
        ))
      })
    })

    visibleReadySegments.value = next
  },
  { immediate: true },
)

function nodeToneClass(tone?: string) {
  if (tone === 'accent') return 'text-accent'
  if (tone === 'warning') return 'text-warning'
  if (tone === 'muted') return 'text-muted'
  return 'text-foreground'
}

function nodeActive(node: { key: string; pulseKeys?: string[] }) {
  if (!connecting.value) return false
  const key = progressKey.value
  if (['authorization', 'oneshot-helper'].includes(key)) return node.key === 'traffic'
  if (key === 'adapter') return ['traffic', 'exv'].includes(node.key)
  if (key === 'routes') return ['traffic', 'exv', 'upstream', 'physical'].includes(node.key)
  if (key === 'vpn-server') return ['internet', 'server'].includes(node.key)
  if (key === 'network-ready') return ['server', 'lock'].includes(node.key)
  return Boolean(node.pulseKeys?.includes(key))
}

function nodeReady(nodeKey: string) {
  return visibleReadySegments.value.some((segment) => {
    if (segment.phase === 'leaving') return false
    const [from, to] = segment.key.split('-')
    return from === nodeKey || to === nodeKey
  })
}

function nodeVisualClass(node: { key: string; tone?: string; pulseKeys?: string[] }) {
  if (nodeActive(node) || (node.key === 'exv' && node.tone === 'warning')) return 'node-warning'
  if (nodeReady(node.key) || node.tone === 'accent') return 'node-success'
  if (node.tone === 'warning') return 'node-warning'
  if (node.tone === 'muted') return 'node-muted'
  return ''
}
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

    <DashboardTopologyMap
      class="dashboard-page-grid__topology"
      :arc-view-box="arcViewBox"
      :arc-segments="arcSegments"
      :visible-ready-segments="visibleReadySegments"
      :active-pulse-keys="activePulseKeys"
      :nodes="animatedArcNodes"
      :node-ready="nodeReady"
      :node-active="nodeActive"
      :node-visual-class="nodeVisualClass"
      :node-tone-class="nodeToneClass"
    />
    <!-- Contract: DashboardTopologyMap keeps :title="node.tooltip || node.title" on topology nodes. -->

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
  /* Legacy topology contract retained: padding-bottom: 5.75rem; margin-top: -12rem; */
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

.dashboard-page-grid__topology {
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

.arc-stage {
  position: relative;
  aspect-ratio: 760 / 360;
  flex: 0 0 auto;
  height: auto;
  margin: -0.35rem auto 0;
  width: min(100%, 760px);
}

.arc-svg {
  position: absolute;
  inset: 0;
  height: 100%;
  width: 100%;
  overflow: visible;
}

.arc-track {
  fill: none;
  stroke: rgba(148, 163, 184, 0.28);
  stroke-linecap: round;
  stroke-width: 2;
  transition: stroke 180ms ease, stroke-width 180ms ease;
}

.ready-segment {
  fill: none;
  stroke: var(--topology-accent-stroke);
  stroke-linecap: round;
  stroke-width: 4;
  stroke-dasharray: 100;
  stroke-dashoffset: 0;
  filter: drop-shadow(0 0 6px var(--topology-accent-glow));
}

.ready-segment.is-entering {
  animation: ready-segment-draw 720ms cubic-bezier(0.22, 1, 0.36, 1) both;
}

.ready-segment.is-disconnecting {
  stroke: var(--topology-warning-stroke);
  filter: drop-shadow(0 0 6px var(--topology-warning-glow));
}

.ready-segment.is-leaving {
  stroke: var(--topology-warning-stroke);
  filter: drop-shadow(0 0 6px var(--topology-warning-glow));
  animation: ready-segment-retract 720ms cubic-bezier(0.64, 0, 0.78, 0) both;
}

.arc-pulse {
  fill: none;
  stroke: var(--color-warning);
  stroke-dasharray: 34 260;
  stroke-linecap: round;
  stroke-width: 4;
  filter: drop-shadow(0 0 8px var(--topology-warning-glow));
  animation: arc-pulse-run 1.05s ease-in-out infinite;
}

.arc-node {
  position: absolute;
  display: flex;
  height: 7.5rem;
  width: 7.5rem;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.0625rem;
  border-radius: 9999px;
  isolation: isolate;
  padding: 0.45rem 0.5rem;
  text-align: center;
  transform: translate(-50%, -50%);
  transition: background-color 160ms ease, box-shadow 160ms ease, transform 160ms ease;
  contain: paint;
}

.arc-node.stage-active {
  z-index: 2;
}

.arc-node.node-success .node-icon-shell,
.arc-node.node-success .node-icon,
.arc-node.node-success .node-title {
  color: var(--color-accent);
}

.arc-node.node-warning .node-icon-shell,
.arc-node.node-warning .node-icon,
.arc-node.node-warning .node-title {
  color: var(--color-warning);
}

.arc-node.node-muted .node-icon-shell,
.arc-node.node-muted .node-icon,
.arc-node.node-muted .node-title {
  color: rgb(148 163 184);
}

.arc-node.node-warning .photon {
  background: var(--color-warning);
  box-shadow: -0.8rem 0 0 -0.18rem rgb(var(--color-warning-rgb) / 0.55),
    -1.45rem 0 0 -0.28rem rgb(var(--color-warning-rgb) / 0.25);
}

.arc-node::before,
.arc-node::after {
  content: '';
  position: absolute;
  inset: 0.49rem;
  border-radius: 9999px;
  pointer-events: none;
}

.arc-node::before {
  z-index: -1;
  border: 4px solid rgba(148, 163, 184, 0.34);
  background: transparent;
  box-shadow: none;
  transition: border-color 180ms ease, background 180ms ease, box-shadow 180ms ease;
}

.arc-node::after {
  z-index: -2;
  background: transparent;
  filter: blur(9px);
  opacity: 0;
  transform: translateZ(0) scale(0.92);
  transition: opacity 180ms ease, background 180ms ease;
  will-change: opacity, transform;
}

.arc-node.node-success::before {
  border-color: var(--topology-accent-node);
  box-shadow: 0 0 0.65rem var(--topology-accent-glow);
}

.arc-node.stage-active::before {
  border-color: var(--topology-warning-node);
  background: var(--topology-warning-soft);
  box-shadow:
    inset 0 0 1rem rgb(var(--color-warning-rgb) / 0.13),
    0 0 1rem var(--topology-warning-glow);
}

.arc-node.stage-active::after {
  background: rgb(var(--color-warning-rgb) / 0.34);
  opacity: 0.52;
}

.control-zone {
  position: relative;
  display: flex;
  justify-content: center;
  margin-top: -12rem;
  transform: translateY(0);
  transition: transform 500ms cubic-bezier(0.22, 1, 0.36, 1);
  will-change: transform;
}

.control-zone.is-lifted {
  transform: translateY(-1.35rem);
}

.control-center {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.25rem;
  width: min(34rem, 100%);
}

@keyframes arc-pulse-run {
  0% {
    stroke-dashoffset: 52;
    opacity: 0;
  }

  14% {
    opacity: 1;
  }

  78% {
    opacity: 1;
  }

  100% {
    stroke-dashoffset: -230;
    opacity: 0;
  }
}

@keyframes ready-segment-draw {
  0% {
    stroke-dashoffset: 100;
    opacity: 0.15;
  }

  18% {
    opacity: 1;
  }

  100% {
    stroke-dashoffset: 0;
    opacity: 1;
  }
}

@keyframes ready-segment-retract {
  0% {
    stroke-dashoffset: 0;
    opacity: 1;
  }

  100% {
    stroke-dashoffset: -100;
    opacity: 0.12;
  }
}

.power-button-shell {
  position: relative;
  display: grid;
  place-items: center;
  width: 9.8rem;
  height: 9.8rem;
  perspective: 24rem;
}

.power-button {
  box-shadow:
    0 1.35rem 2.6rem rgba(0, 0, 0, 0.34),
    0 0.45rem 0.9rem rgba(0, 0, 0, 0.22),
    inset 0 0.45rem 0.65rem rgba(255, 255, 255, 0.2),
    inset 0 -0.7rem 1.1rem rgba(0, 0, 0, 0.2);
  transform: translateY(-0.12rem);
}

.power-button::before {
  content: '';
  position: absolute;
  inset: 0.35rem;
  border-radius: 9999px;
  background: linear-gradient(145deg, rgba(255, 255, 255, 0.22), rgba(255, 255, 255, 0));
  pointer-events: none;
}

.power-button:hover:not(:disabled) {
  transform: translateY(-0.22rem);
  box-shadow:
    0 1.55rem 2.9rem rgba(0, 0, 0, 0.38),
    0 0.55rem 1rem rgba(0, 0, 0, 0.24),
    inset 0 0.5rem 0.7rem rgba(255, 255, 255, 0.22),
    inset 0 -0.75rem 1.15rem rgba(0, 0, 0, 0.22);
}

.power-button:active:not(:disabled) {
  transform: translateY(0.08rem) scale(0.985);
  box-shadow:
    0 0.65rem 1.4rem rgba(0, 0, 0, 0.28),
    inset 0 0.25rem 0.45rem rgba(255, 255, 255, 0.16),
    inset 0 -0.45rem 0.75rem rgba(0, 0, 0, 0.26);
}

.power-ripple-ring {
  position: absolute;
  inset: 0.12rem;
  border-radius: 9999px;
  border: 2px solid var(--topology-accent-node);
  opacity: 0;
  animation: power-ripple 3.9s ease-out infinite;
}

.power-ripple-ring.ring-a {
  animation-delay: 0s;
}

.power-ripple-ring.ring-b {
  animation-delay: 1.1s;
}

.power-ripple-ring.ring-c {
  animation-delay: 2.4s;
}

.power-button-shell.is-busy::before {
  content: '';
  position: absolute;
  inset: 0.18rem;
  border-radius: 9999px;
  border: 2px solid rgb(var(--color-warning-rgb) / 0.38);
}

.power-satellite {
  position: absolute;
  inset: 0;
  border-radius: 9999px;
  animation: power-orbit 1.05s linear infinite;
}

.power-satellite::after {
  content: '';
  position: absolute;
  inset: 0.1rem;
  border-radius: 9999px;
  background: conic-gradient(
    from 276deg,
    rgb(var(--color-warning-rgb) / 0) 0deg,
    rgb(var(--color-warning-rgb) / 0) 246deg,
    rgb(var(--color-warning-rgb) / 0.08) 255deg,
    rgb(var(--color-warning-rgb) / 0.34) 268deg,
    rgb(var(--color-warning-rgb) / 0.74) 284deg,
    rgb(var(--color-warning-rgb) / 0) 304deg,
    rgb(var(--color-warning-rgb) / 0) 360deg
  );
  mask: radial-gradient(circle, transparent 0 41%, #000 42% 48%, transparent 49%);
}

.power-satellite::before {
  content: '';
  position: absolute;
  top: 0.18rem;
  left: 50%;
  width: 0.62rem;
  height: 0.62rem;
  border-radius: 9999px;
  background: var(--color-warning);
  box-shadow: 0 0 0.55rem var(--topology-warning-glow);
  z-index: 1;
}

@keyframes power-orbit {
  to {
    transform: rotate(360deg);
  }
}

@keyframes power-ripple {
  0% {
    opacity: 0;
    transform: scale(0.74);
  }

  7% {
    opacity: 0.78;
    transform: scale(0.82);
  }

  68% {
    opacity: 0;
    transform: scale(1.5);
  }

  100% {
    opacity: 0;
    transform: scale(1.5);
  }
}

.topology-node {
  min-height: 112px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.35rem;
  text-align: center;
  border-radius: 0.75rem;
  transition: background-color 160ms ease, box-shadow 160ms ease;
}

.topology-node.stage-active {
  background: var(--topology-warning-soft);
  box-shadow: inset 0 0 0 1px rgb(var(--color-warning-rgb) / 0.35);
}

.topology-node.compact {
  min-height: 86px;
}

.node-icon-shell {
  position: relative;
  display: grid;
  width: 2.9rem;
  height: 2.9rem;
  place-items: center;
  flex: 0 0 auto;
  transform: translateY(-0.16rem);
}

.node-icon-shell::before {
  display: none;
}

.node-icon-shell::after {
  display: none;
}

.node-icon {
  position: relative;
  z-index: 1;
  width: 2.05rem;
  height: 2.05rem;
  stroke-width: 2.25;
  color: currentColor;
  filter: drop-shadow(0 0.16rem 0.22rem rgba(0, 0, 0, 0.38));
}

.node-title {
  transform: translateY(-0.1rem);
  color: rgb(248 250 252);
  font-size: 0.78rem;
  font-weight: 600;
  line-height: 1.1rem;
}

.photon-field {
  position: relative;
  z-index: 1;
  width: 2.3rem;
  height: 1.7rem;
}

.photon {
  position: absolute;
  display: block;
  width: 0.55rem;
  height: 0.55rem;
  border-radius: 9999px;
  background: var(--color-accent);
  box-shadow: -0.8rem 0 0 -0.18rem rgb(var(--color-accent-rgb) / 0.55),
    -1.45rem 0 0 -0.28rem rgb(var(--color-accent-rgb) / 0.25);
}

.photon-a {
  left: 1.55rem;
  top: 0.06rem;
}

.photon-b {
  left: 0.78rem;
  top: 0.58rem;
}

.photon-c {
  left: 1.82rem;
  top: 1.02rem;
}

.photon-d {
  left: 0.34rem;
  top: 1.18rem;
}
</style>
