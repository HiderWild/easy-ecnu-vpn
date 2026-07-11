<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import {
  FileText, Info, LayoutDashboard, Settings,
} from 'lucide-vue-next'
import appIconUrl from '../assets/app-icon.svg'
import { distributionConfig } from '../generated/distribution'
import { useVpnStore } from '../stores/vpn'

const router = useRouter()
const route = useRoute()
const vpn = useVpnStore()
const showSidebarStatusDetails = computed(() => Boolean(vpn.status?.connected))
const dtlsTooltipAnchor = ref<HTMLElement | null>(null)
const dtlsTooltipVisible = ref(false)
const dtlsTooltipStyle = ref<Record<string, string>>({})
let dtlsTooltipListenersAttached = false

const navItems = [
  { path: '/', name: '主面板', icon: LayoutDashboard },
  { path: '/settings', name: '设置', icon: Settings },
  { path: '/logs', name: '日志', icon: FileText },
  { path: '/about', name: '关于', icon: Info },
]

function isActive(path: string) {
  if (path === '/') return route.path === '/'
  return route.path.startsWith(path)
}

onMounted(() => {
  if (vpn.isDesktop) void vpn.fetchStatus()
})

const uptimeFormatted = computed(() => {
  const total = vpn.displayUptimeSeconds
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
})

const connectionState = computed(() => {
  if (vpn.disconnectInFlight) return { label: '正在断开', tone: 'warning' }
  if (vpn.connectInFlight) return { label: '连接中', tone: 'warning' }
  if (vpn.lastError) return { label: '需要处理', tone: 'warning' }
  if (!vpn.status?.connected) return { label: '未连接', tone: 'muted' }
  return { label: '已连接', tone: 'accent' }
})

const dtlsState = computed(() => {
  const status = vpn.status
  const fallbackTooltip = '服务器未提供或不支持 DTLS，EXV 已回退到 CSTP/TLS，不影响正常使用。可在设置中关闭 DTLS。'
  if (vpn.disconnectInFlight) return { label: '关闭中', tone: 'warning' }
  if (vpn.connectInFlight) return { label: '协商中', tone: 'warning' }
  if (!status?.connected) return { label: 'DTLS', tone: 'muted' }
  if (status.active_data_channel === 'dtls') return { label: '已启用', tone: 'accent' }
  if (status.dtls_mode === 'disabled' || status.dtls_state === 'disabled') {
    return { label: '已关闭', tone: 'muted' }
  }
  if (status.dtls_state === 'not_advertised_or_skipped') {
    return { label: '未协商', tone: 'muted', tooltip: fallbackTooltip }
  }
  if (status.dtls_state === 'attempted_and_fell_back_to_tls' || (status.dtls_fallback_count ?? 0) > 0) {
    return { label: '已回退', tone: 'warning', tooltip: fallbackTooltip }
  }
  return { label: 'CSTP/TLS', tone: 'muted' }
})

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max)
}

function positionDtlsTooltip() {
  const anchor = dtlsTooltipAnchor.value
  if (!anchor || typeof window === 'undefined') return

  const viewportMargin = 10
  const rect = anchor.getBoundingClientRect()
  const tooltipWidth = Math.min(248, Math.max(160, window.innerWidth - viewportMargin * 2))
  const maxLeft = Math.max(viewportMargin, window.innerWidth - tooltipWidth - viewportMargin)
  const left = clamp(
    rect.left + rect.width / 2 - tooltipWidth / 2,
    viewportMargin,
    maxLeft,
  )
  const arrowLeft = clamp(
    rect.left + rect.width / 2 - left,
    16,
    tooltipWidth - 16,
  )

  dtlsTooltipStyle.value = {
    left: `${left}px`,
    top: `${Math.max(viewportMargin, rect.top - 8)}px`,
    width: `${tooltipWidth}px`,
    '--sidebar-tooltip-arrow-left': `${arrowLeft}px`,
  }
}

function attachDtlsTooltipListeners() {
  if (dtlsTooltipListenersAttached || typeof window === 'undefined') return
  window.addEventListener('resize', positionDtlsTooltip)
  window.addEventListener('scroll', positionDtlsTooltip, true)
  dtlsTooltipListenersAttached = true
}

function detachDtlsTooltipListeners() {
  if (!dtlsTooltipListenersAttached || typeof window === 'undefined') return
  window.removeEventListener('resize', positionDtlsTooltip)
  window.removeEventListener('scroll', positionDtlsTooltip, true)
  dtlsTooltipListenersAttached = false
}

function showDtlsTooltip() {
  if (!dtlsState.value.tooltip) return
  dtlsTooltipVisible.value = true
  void nextTick(() => {
    positionDtlsTooltip()
    attachDtlsTooltipListeners()
  })
}

function hideDtlsTooltip() {
  dtlsTooltipVisible.value = false
  detachDtlsTooltipListeners()
}

watch(
  () => dtlsState.value.tooltip,
  (tooltip) => {
    if (!tooltip) {
      hideDtlsTooltip()
    } else if (dtlsTooltipVisible.value) {
      void nextTick(positionDtlsTooltip)
    }
  },
)

onBeforeUnmount(() => {
  hideDtlsTooltip()
})

const sidebarStatusItems = computed(() => [
  { label: '用户', value: vpn.status?.username || '--' },
  { label: '运行时长', value: vpn.status?.connected ? uptimeFormatted.value : '--' },
  { label: '代理 TUN', value: vpn.upstreamVirtualLabel },
  { label: '内网地址', value: vpn.status?.internal_ip || '--' },
  { label: 'VPN 服务器', value: vpn.status?.server || '--' },
])
</script>

<template>
  <nav class="absolute inset-y-0 left-0 z-40 flex w-44 flex-col border-r border-border bg-surface/80 backdrop-blur-sm">
    <div class="flex items-center justify-between gap-3 px-3 py-4">
      <div class="min-w-0">
        <button
          class="flex min-w-0 items-center gap-2.5 text-left transition-colors hover:text-accent"
          @click="router.push('/')"
        >
          <img :src="appIconUrl" alt="" class="h-9 w-9 shrink-0" />
          <span class="min-w-0 leading-tight">
            <span class="block text-lg font-bold text-foreground">{{ distributionConfig.appName }}</span>
            <span class="block text-xs font-semibold text-muted">{{ distributionConfig.brandSubtitle }}</span>
          </span>
        </button>
      </div>
    </div>

    <div class="min-h-0 flex-1 px-3 pb-4">
      <div class="flex flex-col items-stretch gap-1.5 overflow-y-auto">
        <button
          v-for="item in navItems"
          :key="item.path"
          :class="[
            'flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm whitespace-nowrap transition-colors',
            isActive(item.path)
              ? 'bg-primary/50 text-foreground shadow-[inset_0_0_0_1px_rgba(255,255,255,0.06)]'
              : 'text-muted hover:bg-bg/70 hover:text-foreground'
          ]"
          @click="router.push(item.path)"
        >
          <component :is="item.icon" class="h-4 w-4 shrink-0" />
          <span class="flex-1 text-left">{{ item.name }}</span>
        </button>
      </div>
    </div>

    <div class="px-3 pb-3">
      <div
        :class="[
          'space-y-3',
          showSidebarStatusDetails ? 'border-t border-border pt-3' : '',
        ]"
      >
        <div v-if="showSidebarStatusDetails" class="space-y-2">
          <div
            v-for="item in sidebarStatusItems"
            :key="item.label"
            class="min-w-0"
          >
            <p class="text-[0.66rem] leading-4 text-muted">{{ item.label }}</p>
            <p class="truncate text-xs font-semibold leading-4 text-foreground" :title="item.value">
              {{ item.value }}
            </p>
          </div>
        </div>

        <div class="sidebar-status-pill">
          <div class="sidebar-status-pill__item">
            <span
              :class="[
                'sidebar-status-pill__dot',
                connectionState.tone === 'accent' ? 'is-accent' : connectionState.tone === 'warning' ? 'is-warning' : 'is-muted',
              ]"
            />
            <span class="truncate text-muted">{{ connectionState.label }}</span>
          </div>
          <span class="sidebar-status-pill__divider" aria-hidden="true" />
          <div
            ref="dtlsTooltipAnchor"
            class="sidebar-status-pill__item sidebar-status-pill__item--dtls"
            :tabindex="dtlsState.tooltip ? 0 : undefined"
            :aria-describedby="dtlsTooltipVisible ? 'sidebar-dtls-tooltip' : undefined"
            @mouseenter="showDtlsTooltip"
            @mouseleave="hideDtlsTooltip"
            @focus="showDtlsTooltip"
            @blur="hideDtlsTooltip"
          >
            <span
              :class="[
                'sidebar-status-pill__dot',
                dtlsState.tone === 'accent' ? 'is-accent' : dtlsState.tone === 'warning' ? 'is-warning' : 'is-muted',
              ]"
            />
            <span class="truncate text-muted">{{ dtlsState.label }}</span>
          </div>
        </div>
      </div>
    </div>
  </nav>
  <Teleport to="body">
    <div
      v-if="dtlsTooltipVisible && dtlsState.tooltip"
      id="sidebar-dtls-tooltip"
      class="sidebar-floating-tooltip"
      :style="dtlsTooltipStyle"
      role="tooltip"
    >
      {{ dtlsState.tooltip }}
      <span class="sidebar-floating-tooltip__arrow" aria-hidden="true" />
    </div>
  </Teleport>
</template>

<style scoped>
.sidebar-status-pill {
  display: grid;
  min-height: 2.05rem;
  grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr);
  align-items: center;
  gap: 0.45rem;
  border: 1px solid var(--color-border);
  border-radius: 9999px;
  background: rgb(var(--color-background-rgb) / 0.4);
  padding: 0.35rem 0.55rem;
  font-size: 0.72rem;
  line-height: 1rem;
}

.sidebar-status-pill__item {
  position: relative;
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 0.35rem;
}

.sidebar-status-pill__item--dtls {
  justify-content: flex-end;
}

.sidebar-status-pill__divider {
  width: 1px;
  height: 0.95rem;
  background: var(--color-border);
}

.sidebar-status-pill__dot {
  width: 0.52rem;
  height: 0.52rem;
  flex: 0 0 auto;
  border-radius: 9999px;
  background: var(--color-muted);
}

.sidebar-status-pill__dot.is-accent {
  background: var(--color-accent);
}

.sidebar-status-pill__dot.is-warning {
  background: var(--color-warning);
}

.sidebar-floating-tooltip {
  position: fixed;
  z-index: 10000;
  transform: translateY(-100%);
  border: 1px solid color-mix(in srgb, var(--color-border) 88%, var(--color-surface));
  border-radius: 8px;
  background: color-mix(in srgb, var(--color-surface) 94%, var(--color-background));
  box-shadow: 0 0.9rem 2.2rem rgb(0 0 0 / 0.18);
  color: var(--color-foreground);
  padding: 0.58rem 0.68rem;
  pointer-events: none;
  white-space: normal;
  font-size: 0.72rem;
  font-weight: 500;
  line-height: 1.38;
}

.sidebar-floating-tooltip__arrow {
  position: absolute;
  left: var(--sidebar-tooltip-arrow-left, 50%);
  bottom: -0.36rem;
  width: 0.65rem;
  height: 0.65rem;
  border-right: 1px solid color-mix(in srgb, var(--color-border) 88%, var(--color-surface));
  border-bottom: 1px solid color-mix(in srgb, var(--color-border) 88%, var(--color-surface));
  background: inherit;
  transform: translateX(-50%) rotate(45deg);
}
</style>
