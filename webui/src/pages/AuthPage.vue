<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useConfigStore, type AuthConfig } from '../stores/config'
import { useUiStore } from '../stores/ui'
import { Shield, User, Key, Fingerprint, Server } from 'lucide-vue-next'
import PasswordField from '../components/PasswordField.vue'
import { distributionConfig } from '../generated/distribution'

const config = useConfigStore()
const ui = useUiStore()

const saving = ref(false)
const message = ref<{ text: string } | null>(null)
const serverOptions: string[] = distributionConfig.vpnServers.map((server) => server.value)
const serverChoice = ref<string>(distributionConfig.defaultVpnServer)
const customServer = ref('')

const form = ref<AuthConfig>({
  server: '',
  username: '',
  password: '',
  password_stored: false,
  user_agent: '',
  remember_password: false,
})

function normalizeServerChoice(server: string) {
  return server.trim().replace(/^https?:\/\//i, '').replace(/\/$/, '').toLowerCase()
}

onMounted(async () => {
  await config.fetchAuthConfig()
  // Spread without copying back the dummy password value: the backend now
  // returns an empty string for password plus a password_stored boolean.
  form.value = {
    ...config.authConfig,
    password: '',
  }
  const normalizedServer = normalizeServerChoice(form.value.server)
  if (serverOptions.includes(normalizedServer)) {
    serverChoice.value = normalizedServer
    customServer.value = ''
  } else if (form.value.server) {
    serverChoice.value = 'custom'
    customServer.value = form.value.server
  } else {
    serverChoice.value = distributionConfig.defaultVpnServer
  }
})

watch(
  () => form.value.remember_password,
  (remember) => {
    if (!remember) {
      form.value.password = ''
    }
  },
)

const passwordPlaceholder = '请输入密码'

function extractErrorText(err: any): string {
  return (
    err?.response?.data?.error ||
    err?.message ||
    err?.toString?.() ||
    '保存失败'
  )
}

async function save() {
  saving.value = true
  message.value = null
  try {
    form.value.server = serverChoice.value === 'custom'
      ? customServer.value.trim()
      : serverChoice.value
    if (!form.value.remember_password) {
      form.value.password = ''
    }
    // Always send the form values; the backend treats an empty password as
    // "keep the existing one" and an empty user_agent as "no change".
    await config.saveAuthConfig(form.value)
    form.value.password = ''
    form.value.password_stored = config.authConfig.password_stored ?? form.value.password_stored
    message.value = { text: '认证设置已保存' }
  } catch (e: any) {
    ui.requestError({ title: '保存认证设置失败', message: extractErrorText(e) })
  } finally {
    saving.value = false
  }
}
</script>

<template>
  <div class="h-full overflow-hidden py-4">
    <h1 class="text-xl font-semibold text-foreground mb-4 flex items-center gap-2">
      <Shield class="w-5 h-5 text-accent" />
      认证设置
    </h1>

    <div class="bg-surface border border-border rounded-xl p-5">
      <form @submit.prevent="save" class="grid grid-cols-2 gap-4">
        <!-- Server -->
        <div>
          <label class="block text-sm text-muted mb-1.5">VPN 服务器</label>
          <div class="space-y-2">
            <div class="relative">
              <Server class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
              <select
                v-model="serverChoice"
                class="w-full appearance-none bg-background border border-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-accent"
              >
                <option
                  v-for="server in serverOptions"
                  :key="server"
                  :value="server"
                >
                  {{ server }}
                </option>
                <option value="custom">自定义</option>
              </select>
            </div>
            <div v-if="serverChoice === 'custom'" class="relative">
              <Server class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
              <input
                v-model="customServer"
                type="text"
                placeholder="请输入 VPN 服务器地址"
                class="w-full bg-background border border-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-foreground placeholder:text-muted/50 focus:outline-none focus:border-accent"
              />
            </div>
          </div>
        </div>

        <!-- Username -->
        <div>
          <label class="block text-sm text-muted mb-1.5">用户名</label>
          <div class="relative">
            <User class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
            <input
              v-model="form.username"
              type="text"
              placeholder="用户名"
              class="w-full bg-background border border-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-foreground placeholder:text-muted/50 focus:outline-none focus:border-accent"
            />
          </div>
        </div>

        <!-- Password -->
        <div v-if="form.remember_password">
          <label class="block text-sm text-muted mb-1.5">密码</label>
          <div class="relative">
            <Key class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
            <PasswordField
              v-model="form.password"
              autocomplete="new-password"
              :placeholder="passwordPlaceholder"
              input-class="w-full bg-background border border-border rounded-lg pl-10 pr-11 py-2.5 text-sm text-foreground placeholder:text-muted/50 focus:outline-none focus:border-accent"
              :show-saved-password-overwrite-hint="form.password_stored"
            />
          </div>
        </div>

        <!-- Remember Password -->
        <div class="flex items-center gap-3 self-end">
          <input
            v-model="form.remember_password"
            type="checkbox"
            id="remember-password"
            class="w-4 h-4 rounded border-border accent-accent"
          />
          <label for="remember-password" class="text-sm text-foreground">
            记住密码（加密存储）
          </label>
        </div>

        <!-- User Agent -->
        <div>
          <label class="block text-sm text-muted mb-1.5">客户端标识</label>
          <div class="relative">
            <Fingerprint class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted" />
            <input
              v-model="form.user_agent"
              type="text"
              placeholder="AnyConnect"
              class="w-full bg-background border border-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-foreground placeholder:text-muted/50 focus:outline-none focus:border-accent"
            />
          </div>
          <p class="text-xs text-muted mt-1">发送到 VPN 服务器的客户端标识字符串</p>
        </div>

        <!-- Save -->
        <div class="col-span-2 flex items-center gap-3 pt-1">
          <button
            type="submit"
            :disabled="saving"
            class="bg-accent text-white rounded-lg px-6 py-2.5 text-sm font-medium hover:bg-accent/90 disabled:opacity-50 transition-colors"
          >
            {{ saving ? '保存中...' : '保存认证设置' }}
          </button>

        <!-- Message -->
        <div
          v-if="message"
          :class="[
            'text-sm rounded-lg px-4 py-2.5',
            'bg-success/10 text-success'
          ]"
        >
          {{ message.text }}
        </div>
        </div>
      </form>
    </div>
  </div>
</template>
