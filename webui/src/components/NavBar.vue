<script setup lang="ts">
import { computed, onMounted } from 'vue'
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

const proxyTunLabel = computed(() => {
  const adapters = vpn.status?.upstream_virtual_adapters || []
  if (adapters.length > 0) {
    return adapters.map((adapter) => adapter.name).filter(Boolean).join('、') || '已检测到'
  }
  return vpn.status?.upstream_virtual_message || '--'
})

const connectionState = computed(() => {
  if (vpn.disconnectInFlight) return { label: '正在断开', tone: 'warning' }
  if (vpn.connectInFlight) return { label: '连接中', tone: 'warning' }
  if (vpn.lastError) return { label: '需要处理', tone: 'warning' }
  if (!vpn.status?.connected) return { label: '未连接', tone: 'muted' }
  return { label: '已连接', tone: 'accent' }
})

const sidebarStatusItems = computed(() => [
  { label: '用户', value: vpn.status?.username || '--' },
  { label: '运行时长', value: vpn.status?.connected ? uptimeFormatted.value : '--' },
  { label: '代理 TUN', value: proxyTunLabel.value },
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

        <div class="flex items-center gap-2 rounded-full border border-border bg-bg/40 px-2.5 py-1.5 text-xs">
          <span
            :class="[
              'h-2 w-2 rounded-full',
              connectionState.tone === 'accent' ? 'bg-accent' : connectionState.tone === 'warning' ? 'bg-warning' : 'bg-muted',
            ]"
          />
          <span class="truncate text-muted">{{ connectionState.label }}</span>
        </div>
      </div>
    </div>
  </nav>
</template>
