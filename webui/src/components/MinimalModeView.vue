<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { Power } from 'lucide-vue-next'
import PasswordField from './PasswordField.vue'
import { useConfigStore } from '../stores/config'
import { useUiStore } from '../stores/ui'
import { useVpnStore } from '../stores/vpn'

const config = useConfigStore()
const ui = useUiStore()
const vpn = useVpnStore()

const username = ref('')
const password = ref('')
const rememberPassword = ref(false)
const installServiceBeforeConnect = ref(true)

const busy = computed(() => vpn.loading || vpn.serviceBusy || vpn.disconnectInFlight)
const connected = computed(() => Boolean(vpn.status?.connected))
const connecting = computed(() => vpn.connectInFlight)
const connectedLayout = computed(() => connected.value && !vpn.disconnectInFlight)
const hasStoredPassword = computed(() => Boolean(config.authConfig.password_stored))
const showServiceChoice = computed(() => !vpn.serviceAvailable && !vpn.serviceInstalled)

const statusText = computed(() => {
  if (vpn.disconnectInFlight) return '断开中'
  if (connecting.value) return '连接中'
  if (connected.value) return '已连接'
  return '未连接'
})

const powerButtonLabel = computed(() => {
  if (connecting.value) return '取消连接'
  if (connected.value) return '断开连接'
  return '连接'
})

const powerClass = computed(() => {
  if (connecting.value || busy.value) return 'is-warning'
  if (connected.value) return 'is-connected'
  return 'is-disconnected'
})

const uptimeFormatted = computed(() => {
  const total = vpn.displayUptimeSeconds
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  return h > 0
    ? `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
    : `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`
})

const internalIpText = computed(() => vpn.status?.internal_ip || '--')
const usernameText = computed(() => vpn.status?.username || username.value || 'EXV')
const sessionModeLabel = computed(() => {
  if (vpn.currentSessionMode === 'helper') return '服务'
  if (vpn.currentSessionMode === 'elevated') return '临时'
  if (vpn.currentSessionMode === 'direct') return '直连'
  return '待机'
})

onMounted(async () => {
  await Promise.allSettled([
    config.fetchAuthConfig(),
    config.fetchSettings(),
    vpn.fetchServiceStatus(),
  ])
  username.value = config.authConfig.username
  rememberPassword.value = config.authConfig.remember_password
  installServiceBeforeConnect.value = config.settings.minimal_install_service_before_connect
})

watch(
  () => config.authConfig.username,
  (next) => {
    if (!username.value) username.value = next
  },
)

watch(
  () => config.authConfig.remember_password,
  (next) => {
    rememberPassword.value = next
  },
)

watch(
  () => config.settings.minimal_install_service_before_connect,
  (next) => {
    installServiceBeforeConnect.value = next
  },
)

watch(installServiceBeforeConnect, (next) => {
  if (next === config.settings.minimal_install_service_before_connect) return
  void config.saveSettings({ minimal_install_service_before_connect: next })
})

async function saveAuthForConnect() {
  const nextUsername = username.value.trim()
  if (!rememberPassword.value) {
    if (!password.value) {
      ui.addToast('未勾选记住时，请输入本次连接密码。', 'warning')
      return { ok: false as const }
    }
    await config.saveAuthConfig({
      ...config.authConfig,
      username: nextUsername,
      password: '',
      remember_password: false,
    })
    return { ok: true as const, password: password.value }
  }

  if (password.value) {
    await config.saveAuthConfig({
      ...config.authConfig,
      username: nextUsername,
      password: password.value,
      remember_password: true,
    })
    return { ok: true as const, password: undefined }
  }

  if (!hasStoredPassword.value) {
    ui.addToast('勾选记住时，请先输入要保存的密码。', 'warning')
    return { ok: false as const }
  }

  if (nextUsername !== config.authConfig.username || !config.authConfig.remember_password) {
    await config.saveAuthConfig({
      ...config.authConfig,
      username: nextUsername,
      password: '',
      remember_password: true,
    })
  }
  return { ok: true as const, password: undefined }
}

async function handlePowerClick() {
  if (connecting.value) {
    await vpn.cancelConnect()
    return
  }
  if (busy.value) return
  if (connected.value) {
    if (vpn.currentSessionMode === 'helper') {
      await vpn.disconnect()
    } else {
      await vpn.disconnectElevated()
    }
    return
  }

  const auth = await saveAuthForConnect()
  if (!auth.ok) return

  let ok = false
  if (vpn.serviceAvailable) {
    ok = await vpn.connect(auth.password)
  } else if (installServiceBeforeConnect.value && showServiceChoice.value) {
    const installed = await vpn.requestInstallService({ confirmWhenInactive: false })
    if (!installed) return
    ok = await vpn.connect(auth.password)
  } else {
    ok = await vpn.connectElevated(auth.password)
  }
  if (ok) password.value = ''
}
</script>

<template>
  <main
    class="minimal-shell"
    :class="{
      'is-connecting': connecting,
      'is-disconnecting': vpn.disconnectInFlight,
      'is-connected': connectedLayout,
    }"
  >
    <div class="minimal-shell__body">
      <div class="minimal-shell__status-stack">
        <button
          type="button"
          class="minimal-power-button"
          :class="powerClass"
          :aria-label="powerButtonLabel"
          :disabled="busy"
          @click="handlePowerClick"
        >
          <Power class="minimal-power-button__icon" />
        </button>
        <p class="minimal-shell__status-text">{{ statusText }}</p>
      </div>

      <div v-if="connectedLayout" class="minimal-shell__connected">
        <p class="minimal-shell__connected-name">{{ usernameText }}</p>
        <p class="minimal-shell__connected-meta">
          {{ internalIpText }} · {{ uptimeFormatted }} · {{ sessionModeLabel }}
        </p>
      </div>

      <form v-else class="minimal-shell__form" @submit.prevent="handlePowerClick">
        <div class="minimal-shell__field-row">
          <input
            v-model="username"
            type="text"
            autocomplete="username"
            placeholder="用户名"
            class="minimal-shell__input"
          />
          <label
            v-if="showServiceChoice"
            class="minimal-shell__utility minimal-shell__utility--service"
          >
            <input
              v-model="installServiceBeforeConnect"
              type="checkbox"
              class="minimal-shell__checkbox"
            />
            服务
          </label>
        </div>

        <div class="minimal-shell__field-row">
          <PasswordField
            v-model="password"
            autocomplete="current-password"
            placeholder="密码"
            wrapper-class="minimal-shell__password"
            input-class="minimal-shell__input"
            reveal-button-class="minimal-shell__password-reveal"
            :show-saved-password-overwrite-hint="hasStoredPassword && rememberPassword"
            @keyup-enter="handlePowerClick"
          />
          <label class="minimal-shell__utility minimal-shell__utility--remember">
            <input
              v-model="rememberPassword"
              type="checkbox"
              class="minimal-shell__checkbox"
            />
            记住
          </label>
        </div>
      </form>
    </div>

    <div class="minimal-shell__activity">
      <span class="minimal-activity-beam" />
    </div>
  </main>
</template>

<style scoped>
.minimal-shell {
  display: grid;
  grid-template-rows: minmax(0, 1fr) auto;
  height: 100%;
  min-height: 0;
  padding: 0.42rem 0.62rem 0.16rem;
  overflow: hidden;
  background: var(--color-bg);
  color: var(--color-foreground);
}

.minimal-shell__body {
  display: grid;
  min-height: 0;
  grid-template-columns: 4.15rem minmax(0, 1fr);
  align-items: center;
  gap: 0.5rem;
}

.minimal-shell__status-stack {
  display: grid;
  justify-items: center;
  gap: 0.32rem;
}

.minimal-power-button {
  position: relative;
  display: grid;
  width: 2.72rem;
  height: 2.72rem;
  place-items: center;
  border-radius: 9999px;
  color: white;
  transition: transform 150ms ease, filter 150ms ease;
  box-shadow:
    0 0.76rem 1.35rem rgba(0, 0, 0, 0.34),
    inset 0 0.32rem 0.5rem rgba(255, 255, 255, 0.2),
    inset 0 -0.48rem 0.76rem rgba(0, 0, 0, 0.24);
}

.minimal-power-button.is-warning {
  background: var(--color-warning);
}

.minimal-power-button.is-connected {
  background: var(--color-accent);
}

.minimal-power-button.is-disconnected {
  background: var(--color-destructive);
}

.minimal-power-button:hover:not(:disabled) {
  transform: translateY(-0.08rem);
}

.minimal-power-button:disabled {
  cursor: not-allowed;
  opacity: 0.78;
}

.minimal-power-button__icon {
  width: 1.05rem;
  height: 1.05rem;
}

.minimal-shell__status-text {
  max-width: 3.7rem;
  overflow: hidden;
  text-align: center;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--color-muted);
  font-size: 0.68rem;
  font-weight: 500;
  line-height: 0.75rem;
}

.minimal-shell__connected {
  min-width: 0;
}

.minimal-shell__connected-name {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 0.78rem;
  font-weight: 600;
}

.minimal-shell__connected-meta {
  margin-top: 0.18rem;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--color-muted);
  font-size: 0.66rem;
}

.minimal-shell__form {
  min-width: 0;
}

.minimal-shell__field-row {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 0.38rem;
}

.minimal-shell__field-row + .minimal-shell__field-row {
  margin-top: 0.2rem;
}

:deep(.minimal-shell__input) {
  height: 1.56rem;
  min-width: 0;
  width: 100%;
  border: 1px solid var(--color-border);
  border-radius: 0.42rem;
  background: var(--color-surface);
  padding: 0 0.46rem;
  color: var(--color-foreground);
  font-size: 0.72rem;
  outline: none;
}

:deep(.minimal-shell__input:focus) {
  border-color: var(--color-accent);
}

.minimal-shell__password {
  min-width: 0;
  flex: 1 1 auto;
}

:deep(.minimal-shell__password-reveal) {
  right: 0.12rem;
  height: 1.32rem;
  width: 1.32rem;
}

.minimal-shell__utility {
  display: inline-flex;
  height: 1.56rem;
  flex: 0 0 auto;
  align-items: center;
  gap: 0.2rem;
  border: 1px solid var(--color-border);
  border-radius: 0.42rem;
  background: var(--color-surface);
  padding: 0 0.36rem;
  color: var(--color-muted);
  font-size: 0.66rem;
  white-space: nowrap;
}

.minimal-shell__checkbox {
  width: 0.72rem;
  height: 0.72rem;
  accent-color: var(--color-accent);
}

.minimal-shell__activity {
  position: relative;
  height: 0.1rem;
  overflow: hidden;
}

.minimal-activity-beam {
  display: block;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, transparent 0%, rgb(var(--color-accent-rgb) / 0.82) 50%, transparent 100%);
  filter: blur(0.5px);
  opacity: 0.55;
}

.minimal-shell.is-connecting .minimal-activity-beam,
.minimal-shell.is-disconnecting .minimal-activity-beam {
  animation: minimal-activity-flow 2.4s ease-in-out infinite;
}

.minimal-shell.is-connected .minimal-activity-beam {
  animation: minimal-activity-drift 8.5s ease-in-out infinite;
}

@keyframes minimal-activity-flow {
  0% {
    transform: translateX(-18%);
    opacity: 0.28;
  }
  50% {
    transform: translateX(0);
    opacity: 0.82;
  }
  100% {
    transform: translateX(18%);
    opacity: 0.28;
  }
}

@keyframes minimal-activity-drift {
  0%,
  100% {
    opacity: 0.34;
  }
  50% {
    opacity: 0.72;
  }
}

@media (prefers-reduced-motion: reduce) {
  .minimal-activity-beam {
    animation: none !important;
  }
}
</style>
