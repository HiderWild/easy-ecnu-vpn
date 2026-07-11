<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Fingerprint, Key, Server, Shield, User } from 'lucide-vue-next'
import PasswordField from '../../components/PasswordField.vue'
import { distributionConfig } from '../../generated/distribution'
import type { AuthConfig } from '../../stores/config'

const props = defineProps<{
  authDraft: AuthConfig
}>()

const emit = defineEmits<{
  'update:authDraft': [value: AuthConfig]
}>()

const serverOptions: string[] = distributionConfig.vpnServers.map((server) => server.value)
const serverChoice = ref<string>(distributionConfig.defaultVpnServer)
const customServer = ref('')

const fallbackAuthDraft: AuthConfig = {
  server: '',
  username: '',
  password: '',
  password_stored: false,
  user_agent: '',
  remember_password: false,
}

const authForm = computed(() => props.authDraft ?? fallbackAuthDraft)

const rememberPasswordDisabled = computed(() => !authForm.value.username.trim())

const passwordPlaceholder = computed(() =>
  authForm.value.password_stored
    ? '留空表示保留原密码，输入新密码覆盖'
    : '请输入密码',
)
const showSavedPasswordOverwriteHint = computed(() => Boolean(authForm.value.password_stored))

function normalizeServerChoice(server: string) {
  return server.trim().replace(/^https?:\/\//i, '').replace(/\/$/, '').toLowerCase()
}

function applyServerChoice(server: string) {
  const normalizedServer = normalizeServerChoice(server)
  if (serverOptions.includes(normalizedServer)) {
    serverChoice.value = normalizedServer
    customServer.value = ''
  } else if (server) {
    serverChoice.value = 'custom'
    customServer.value = server
  } else {
    serverChoice.value = distributionConfig.defaultVpnServer
    customServer.value = ''
  }
}

function updateAuthField<K extends keyof AuthConfig>(key: K, value: AuthConfig[K]) {
  emit('update:authDraft', {
    ...authForm.value,
    [key]: value,
  })
}

function handleServerChoiceChange(event: Event) {
  const value = (event.target as HTMLSelectElement).value
  serverChoice.value = value
  updateAuthField('server', value === 'custom' ? customServer.value.trim() : value)
}

function handleCustomServerInput(event: Event) {
  const value = (event.target as HTMLInputElement).value
  customServer.value = value
  if (serverChoice.value === 'custom') {
    updateAuthField('server', value.trim())
  }
}

watch(
  () => authForm.value.username,
  (username) => {
    if (username.trim()) return
    if (!authForm.value.remember_password && !authForm.value.password) return
    emit('update:authDraft', {
      ...authForm.value,
      remember_password: false,
      password: '',
    })
  },
)

watch(
  () => authForm.value.remember_password,
  (remember) => {
    if (!remember && authForm.value.password) {
      updateAuthField('password', '')
    }
  },
)

watch(
  () => authForm.value.server,
  (server) => applyServerChoice(server),
  { immediate: true },
)
</script>

<template>
  <section class="rounded-xl border border-border bg-surface p-5">
    <h2 class="mb-4 flex items-center gap-2 text-base font-semibold text-foreground">
      <Shield class="h-5 w-5 text-accent" />
      认证
    </h2>
    <div class="space-y-4">
      <div>
        <label class="mb-1.5 block text-sm text-muted">VPN 服务器</label>
        <div class="space-y-2">
          <div class="relative">
            <Server class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <select
              :value="serverChoice"
              class="exv-select w-full appearance-none rounded-lg border border-border bg-background py-2.5 pl-10 pr-4 text-sm text-foreground focus:border-accent focus:outline-none"
              @change="handleServerChoiceChange"
            >
              <option v-for="server in serverOptions" :key="server" :value="server">
                {{ server }}
              </option>
              <option value="custom">自定义</option>
            </select>
          </div>
          <div v-if="serverChoice === 'custom'" class="relative">
            <Server class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
            <input
              :value="customServer"
              type="text"
              placeholder="请输入 VPN 服务器地址"
              class="w-full rounded-lg border border-border bg-background py-2.5 pl-10 pr-4 text-sm text-foreground placeholder:text-muted/50 focus:border-accent focus:outline-none"
              @input="handleCustomServerInput"
            />
          </div>
        </div>
      </div>

      <div>
        <label class="mb-1.5 block text-sm text-muted">用户名</label>
        <div class="relative">
          <User class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <input
            :value="authForm.username"
            type="text"
            placeholder="用户名"
            autocomplete="username"
            class="w-full rounded-lg border border-border bg-background py-2.5 pl-10 pr-4 text-sm text-foreground placeholder:text-muted/50 focus:border-accent focus:outline-none"
            @input="updateAuthField('username', ($event.target as HTMLInputElement).value)"
          />
        </div>
      </div>

      <div class="flex items-center gap-3">
        <input
          id="remember-password"
          :checked="authForm.remember_password"
          type="checkbox"
          :disabled="rememberPasswordDisabled"
          class="h-4 w-4 rounded border-border accent-accent disabled:cursor-not-allowed disabled:opacity-45"
          @change="updateAuthField('remember_password', ($event.target as HTMLInputElement).checked)"
        />
        <label
          for="remember-password"
          class="text-sm"
          :class="rememberPasswordDisabled ? 'text-muted' : 'text-foreground'"
        >
          记住密码（加密存储）
        </label>
      </div>

      <div v-if="authForm.remember_password">
        <label class="mb-1.5 block text-sm text-muted">密码</label>
        <div class="relative">
          <Key class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <PasswordField
            :value="authForm.password"
            :model-value="authForm.password"
            autocomplete="new-password"
            :placeholder="passwordPlaceholder"
            input-class="w-full rounded-lg border border-border bg-background py-2.5 pl-10 pr-11 text-sm text-foreground placeholder:text-muted/50 focus:border-accent focus:outline-none"
            :show-saved-password-overwrite-hint="showSavedPasswordOverwriteHint"
            @input="updateAuthField('password', ($event.target as HTMLInputElement).value)"
          />
        </div>
      </div>

      <div>
        <label class="mb-1.5 block text-sm text-muted">客户端标识</label>
        <div class="relative">
          <Fingerprint class="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted" />
          <input
            :value="authForm.user_agent"
            type="text"
            placeholder="AnyConnect"
            class="w-full rounded-lg border border-border bg-background py-2.5 pl-10 pr-4 text-sm text-foreground placeholder:text-muted/50 focus:border-accent focus:outline-none"
            @input="updateAuthField('user_agent', ($event.target as HTMLInputElement).value)"
          />
        </div>
        <p class="mt-1 text-xs text-muted">发送到 VPN 服务器的客户端标识字符串</p>
      </div>
    </div>
  </section>
</template>
