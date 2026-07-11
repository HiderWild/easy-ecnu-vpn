<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { Power } from 'lucide-vue-next'
import PasswordField from './PasswordField.vue'
import ToggleSwitch from './ToggleSwitch.vue'
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

const powerClass = computed(() => {
  if (connecting.value || busy.value) return 'bg-warning text-white shadow-warning/20'
  if (connected.value) return 'bg-accent text-white shadow-accent/20'
  return 'bg-destructive text-white shadow-destructive/20'
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

function switchToAdvancedMode() {
  void config.saveSettings({ minimal_mode: false })
}

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
    const installed = await vpn.installService()
    if (!installed) return
    ok = await vpn.connect(auth.password)
  } else {
    ok = await vpn.connectElevated(auth.password)
  }
  if (ok) password.value = ''
}
</script>

<template>
  <main class="flex h-full bg-bg px-2.5 py-2.5 text-foreground">
    <div
      v-if="connectedLayout"
      class="relative flex min-h-0 w-full items-center justify-center"
    >
      <div class="flex flex-col items-center">
        <button
          type="button"
          :disabled="busy"
          :class="[
            'minimal-power-button grid h-12 w-12 place-items-center rounded-full transition-transform duration-150 disabled:cursor-not-allowed disabled:opacity-80',
            powerClass,
          ]"
          @click="handlePowerClick"
        >
          <Power class="h-5 w-5" />
        </button>
        <p class="mt-1.5 text-center text-[11px] font-medium leading-4 text-muted">{{ statusText }}</p>
      </div>

      <label class="absolute left-[calc(50%+2.45rem)] top-1/2 flex -translate-y-1/2 items-center gap-1.5 text-[11px] text-muted">
        <span>极简</span>
        <ToggleSwitch
          :model-value="false"
          @update:model-value="switchToAdvancedMode"
        />
      </label>
    </div>

    <div
      v-else
      class="flex min-h-0 w-full items-center gap-2"
    >
      <div class="flex shrink-0 flex-col items-center">
        <button
          type="button"
          :disabled="busy"
          :class="[
            'minimal-power-button grid h-12 w-12 place-items-center rounded-full transition-transform duration-150 disabled:cursor-not-allowed disabled:opacity-80',
            powerClass,
          ]"
          @click="handlePowerClick"
        >
          <Power class="h-5 w-5" />
        </button>
        <p class="mt-1.5 max-w-[4rem] truncate text-center text-[11px] font-medium leading-4 text-muted">{{ statusText }}</p>
      </div>

      <div class="min-w-0 flex-1 space-y-1.5">
        <div class="flex items-center gap-1.5">
          <input
            v-model="username"
            type="text"
            autocomplete="username"
            placeholder="用户名"
            class="h-8 min-w-0 flex-1 rounded-md border border-border bg-surface px-2 text-xs text-foreground placeholder:text-muted/50 focus:border-accent focus:outline-none"
          />
          <label class="flex h-8 shrink-0 items-center gap-1.5 rounded-md border border-border bg-surface px-1.5 text-[11px] text-muted">
            <span>极简</span>
            <ToggleSwitch
              :model-value="false"
              @update:model-value="switchToAdvancedMode"
            />
          </label>
        </div>
        <div class="flex items-center gap-1.5">
          <PasswordField
            v-model="password"
            autocomplete="current-password"
            placeholder="密码"
            wrapper-class="min-w-0 flex-1"
            input-class="h-8 w-full rounded-md border border-border bg-surface px-2 pr-9 text-xs text-foreground placeholder:text-muted/50 focus:border-accent focus:outline-none"
            reveal-button-class="right-1 h-6 w-6"
            :show-saved-password-overwrite-hint="hasStoredPassword && rememberPassword"
            @keyup-enter="handlePowerClick"
          />
          <label class="flex h-8 shrink-0 items-center gap-1 rounded-md border border-border bg-surface px-1.5 text-[11px] text-muted">
            <input
              v-model="rememberPassword"
              type="checkbox"
              class="h-3 w-3 accent-accent"
            />
            记住
          </label>
          <label
            v-if="showServiceChoice"
            class="flex h-8 shrink-0 items-center gap-1 rounded-md border border-border bg-surface px-1.5 text-[11px] text-muted"
          >
            <input
              v-model="installServiceBeforeConnect"
              type="checkbox"
              class="h-3 w-3 accent-accent"
            />
            服务
          </label>
        </div>
      </div>
    </div>
  </main>
</template>

<style scoped>
.minimal-power-button {
  position: relative;
  transform: translateY(-0.08rem);
  box-shadow:
    0 1.05rem 1.9rem rgba(0, 0, 0, 0.36),
    0 0.35rem 0.7rem rgba(0, 0, 0, 0.26),
    inset 0 0.36rem 0.55rem rgba(255, 255, 255, 0.2),
    inset 0 -0.56rem 0.9rem rgba(0, 0, 0, 0.22);
}

.minimal-power-button::before {
  content: '';
  pointer-events: none;
  position: absolute;
  inset: 0.26rem;
  border-radius: 9999px;
  background: linear-gradient(145deg, rgba(255, 255, 255, 0.22), transparent);
}

.minimal-power-button:hover:not(:disabled) {
  transform: translateY(-0.16rem);
  box-shadow:
    0 1.18rem 2.1rem rgba(0, 0, 0, 0.4),
    0 0.42rem 0.8rem rgba(0, 0, 0, 0.28),
    inset 0 0.4rem 0.58rem rgba(255, 255, 255, 0.22),
    inset 0 -0.6rem 0.94rem rgba(0, 0, 0, 0.25);
}

.minimal-power-button:active:not(:disabled) {
  transform: translateY(0.06rem) scale(0.985);
  box-shadow:
    0 0.55rem 1.1rem rgba(0, 0, 0, 0.3),
    inset 0 0.2rem 0.35rem rgba(255, 255, 255, 0.16),
    inset 0 -0.36rem 0.62rem rgba(0, 0, 0, 0.3);
}
</style>
