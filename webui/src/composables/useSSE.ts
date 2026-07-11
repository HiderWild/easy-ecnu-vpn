import { ref, onUnmounted } from 'vue'
import { useConfigStore } from '../stores/config'
import { useVpnStore, type LogEntry, type ServiceProgressEntry, type VpnStatus } from '../stores/vpn'
import { useUiStore } from '../stores/ui'
import type { QuickStartRequestEvent } from '../types/exv'

export interface CoreCrashedEvent {
  exitCode: number | null
  signal: string | null
  error?: string
}

export function useSSE() {
  const connected = ref(false)
  const error = ref<string | null>(null)
  const coreCrashed = ref(false)
  const coreCrashInfo = ref<CoreCrashedEvent | null>(null)
  let unsubscribe: (() => void) | null = null

  function handleQuickStartRequest(data: QuickStartRequestEvent) {
    const ui = useUiStore()
    const config = useConfigStore()
    if (!config.settings.minimal_mode) {
      return ui.openQuickStart(data)
    }

    const missingUsername = !config.authConfig.username.trim()
    const missingPassword = !(
      config.authConfig.remember_password && config.authConfig.password_stored
    )
    if (!missingUsername && !missingPassword) return

    void ui.requestCredentials({
      missingUsername,
      missingPassword,
      username: config.authConfig.username,
      rememberPassword: data.defaults.remember_password,
      message: missingUsername && missingPassword
        ? '请输入用户名和密码'
        : missingUsername
          ? '请输入用户名'
          : '请输入密码',
    })
  }

  function connect() {
    if (window.exv) {
      disconnect()
      unsubscribe = window.exv.events.subscribe((event) => {
        connected.value = true
        error.value = null

        if (event.type === 'log') {
          const store = useVpnStore()
          const data = event.data as Partial<LogEntry> & { raw?: string }
          store.addLog({
            timestamp: data.timestamp || new Date().toISOString(),
            level: data.level || 'info',
            message: data.message || data.raw || '',
          })
        }

        if (event.type === 'status' && event.data && typeof event.data === 'object') {
          const store = useVpnStore()
          store.updateStatusFromEvent(event.data as Partial<VpnStatus>)
        }

        if (event.type === 'service-progress' && event.data && typeof event.data === 'object') {
          const store = useVpnStore()
          store.addServiceProgress(event.data as ServiceProgressEntry)
        }

        if (event.type === 'quick-start-request' && event.data && typeof event.data === 'object') {
          handleQuickStartRequest(event.data as QuickStartRequestEvent)
        }

        if (event.type === 'core-crashed' && event.data && typeof event.data === 'object') {
          coreCrashed.value = true
          coreCrashInfo.value = event.data as CoreCrashedEvent
        }
      })
      return
    }
    error.value = 'Desktop event bridge is unavailable'
  }

  function disconnect() {
    if (unsubscribe) {
      unsubscribe()
      unsubscribe = null
    }
    connected.value = false
  }

  function resetCrashState() {
    coreCrashed.value = false
    coreCrashInfo.value = null
  }

  onUnmounted(() => {
    disconnect()
  })

  return { connected, error, connect, disconnect, coreCrashed, coreCrashInfo, resetCrashState }
}
