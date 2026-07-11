<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { RouterView } from 'vue-router'
import { useRoute } from 'vue-router'
import AppWindowFrame from './components/AppWindowFrame.vue'
import NavBar from './components/NavBar.vue'
import MinimalModeView from './components/MinimalModeView.vue'
import { useSSE } from './composables/useSSE'
import { useConfigStore } from './stores/config'
import { useThemeStore } from './stores/theme'
import { useUiStore } from './stores/ui'
import { useVpnStore } from './stores/vpn'
import { requestQuickStartForMissingLocalData } from './utils/quickStart'
import { GlobalWindowStack } from './windows'

const config = useConfigStore()
const vpn = useVpnStore()
const ui = useUiStore()
const theme = useThemeStore()
const { connect: sseConnect, disconnect: sseDisconnect, coreCrashed, coreCrashInfo, resetCrashState } = useSSE()
const route = useRoute()

const minimalMode = computed(() => config.settings.minimal_mode)
const settingsReady = ref(false)
const keptAlivePages = ['DashboardPage', 'SettingsPage', 'LogsPage', 'AboutPage']
let autoConnectAttempted = false
let connectionNotificationState: boolean | null = null
const modalRoute = computed(() =>
  route.path.startsWith('/modal/') ||
  (typeof window !== 'undefined' && window.location.hash.startsWith('#/modal/')),
)

function advancedPageShellClass(routeName: unknown) {
  if (routeName === 'dashboard') return 'h-full min-h-0 mx-auto w-full max-w-5xl'
  if (routeName === 'settings') return 'h-full min-h-0 w-full'
  return 'h-full min-h-0 mx-auto w-[90%] max-w-none'
}

onMounted(async () => {
  theme.initialize()
  if (modalRoute.value) return
  sseConnect()
  const [settingsResult, authResult] = await Promise.allSettled([
    config.fetchSettings(),
    config.fetchAuthConfig(),
    vpn.fetchAppShellState(),
    vpn.fetchStatus(),
  ])
  const authConfigReady = authResult.status === 'fulfilled' && authResult.value === true
  const settingsConfigReady = settingsResult.status === 'fulfilled' && settingsResult.value === true
  settingsReady.value = true
  connectionNotificationState = Boolean(vpn.status?.connected)
  if (authConfigReady && settingsConfigReady && requestQuickStartForMissingLocalData()) return
  await maybeAutoConnectOnLaunch()
})

onUnmounted(() => {
  sseDisconnect()
})

async function maybeAutoConnectOnLaunch() {
  if (autoConnectAttempted) return
  autoConnectAttempted = true
  if (!config.settings.auto_connect_on_launch) return
  if (!config.authConfig.remember_password || !config.authConfig.password_stored) return
  if (!vpn.serviceInstalled) return
  if (vpn.status?.connected) return
  await vpn.connect()
}

watch(
  () => vpn.status?.connected,
  (value) => {
    if (!settingsReady.value) return
    const connected = Boolean(value)
    if (connectionNotificationState === null) {
      connectionNotificationState = connected
      return
    }
    if (connected === connectionNotificationState) return
    connectionNotificationState = connected
    if (!config.settings.connection_state_notifications) return
    const server = vpn.status?.server
    const title = connected ? 'EXV 已连接' : 'EXV 已断开'
    const body = connected
      ? server ? `已连接到 ${server}` : '校园网连接已建立。'
      : '校园网连接已断开。'
    void window.exv?.shell?.notify?.({ title, body })
  },
)

async function handleCoreRestart() {
  try {
    await window.exv?.core.restart()
    resetCrashState()
    ui.addToast('内核已重启', 'success')
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    ui.addToast(`重启失败: ${message}`, 'error')
  }
}

async function handleCoreQuit() {
  try {
    await window.exv?.core.quit()
  } catch {
    // App is quitting, errors expected
  }
}
</script>

<template>
  <RouterView v-if="modalRoute" />
  <AppWindowFrame
    v-else
    :mode="minimalMode ? 'minimal' : 'advanced'"
  >
    <div v-if="!settingsReady" class="h-full bg-bg" aria-hidden="true" />
    <MinimalModeView v-else-if="minimalMode" />
    <div v-else class="app-advanced-shell flex h-full overflow-hidden bg-bg text-foreground font-sans">
      <NavBar />
      <main class="min-w-0 flex-1 overflow-hidden pl-44">
        <div class="flex h-full min-w-0 flex-col">
          <div class="app-advanced-content-titlebar-spacer h-[34px] shrink-0 border-b border-border/80" aria-hidden="true" />
          <div class="min-h-0 w-full flex-1 overflow-hidden px-4 py-4">
            <RouterView v-slot="{ Component, route: viewRoute }">
              <div :class="advancedPageShellClass(viewRoute.name)">
                <KeepAlive :include="keptAlivePages">
                  <component :is="Component" :key="viewRoute.name" />
                </KeepAlive>
              </div>
            </RouterView>
          </div>
        </div>
      </main>
    </div>

    <GlobalWindowStack
      :core-crashed="coreCrashed"
      :core-crash-info="coreCrashInfo"
      @restart-core="handleCoreRestart"
      @quit-core="handleCoreQuit"
    />
  </AppWindowFrame>
</template>

<style scoped>
.app-advanced-shell {
  min-height: calc(100vh - 34px);
}

</style>
