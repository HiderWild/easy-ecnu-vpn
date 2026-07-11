<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { KeyRound, ShieldCheck, TriangleAlert } from 'lucide-vue-next'
import PasswordField from '../components/PasswordField.vue'
import type { DesktopModalPayload } from '../../host/shared/host-contract'

const busy = ref(false)
const payload = ref<DesktopModalPayload | null>(null)
const route = useRoute()
const password = ref('')
const error = ref('')
const closeChoice = ref<'tray' | 'quit'>('tray')
const rememberCloseChoice = ref(false)
const resolved = ref(false)

const kind = computed(() => payload.value?.kind ?? 'service-install')
const message = computed(() => payload.value?.message ?? '')
const isPassword = computed(() => kind.value === 'password')
const isConfirm = computed(() => kind.value === 'confirm')
const isCloseApp = computed(() => kind.value === 'close-app')

onMounted(async () => {
  const routeKind = route.path.endsWith('/close-app')
    ? 'close-app'
    : route.path.endsWith('/password')
      ? 'password'
      : route.path.endsWith('/confirm')
        ? 'confirm'
        : 'service-install'
  payload.value = await window.exv?.modal.getPayload() ?? { kind: routeKind }
})

async function resolvePrompt(result: unknown) {
  if (busy.value) return
  busy.value = true
  resolved.value = true
  try {
    await window.exv?.modal.resolve(result)
  } finally {
    busy.value = false
  }
}

function submitPassword() {
  if (!password.value) {
    error.value = '请输入密码'
    return
  }
  void resolvePrompt(password.value)
}

function submitCloseChoice() {
  void resolvePrompt({
    action: closeChoice.value,
    remember: rememberCloseChoice.value,
  })
}
</script>

<template>
  <main
    v-if="!resolved"
    class="min-h-screen bg-transparent p-3 text-foreground"
  >
    <form
      v-if="isPassword"
      class="modal-panel mx-auto flex w-full max-w-sm flex-col justify-center rounded-lg border border-border bg-surface p-4 shadow-xl shadow-black/30"
      @submit.prevent="submitPassword"
    >
      <div class="flex items-start gap-2.5">
        <KeyRound class="mt-0.5 h-5 w-5 shrink-0 text-accent" />
        <div class="min-w-0">
          <h1 class="text-sm font-semibold text-foreground">{{ message || '请输入 VPN 密码' }}</h1>
          <p class="mt-1 text-xs leading-5 text-muted">密码仅用于本次连接，不会写入设置。</p>
        </div>
      </div>

      <div class="mt-3.5">
        <PasswordField
          v-model="password"
          autocomplete="current-password"
          autofocus
          input-class="h-10 w-full rounded-lg border border-border bg-bg px-3 pr-11 text-sm text-foreground outline-none transition-colors focus:border-accent"
          placeholder="密码"
          @input="error = ''"
          @keydown.esc.prevent="resolvePrompt(null)"
        />
      </div>
      <p v-if="error" class="mt-2 text-xs text-destructive">{{ error }}</p>

      <div class="mt-4 flex justify-end gap-2">
        <button
          type="button"
          :disabled="busy"
          class="min-h-9 rounded-lg border border-border px-4 py-2 text-sm text-foreground transition-colors hover:border-accent/50 disabled:opacity-50"
          @click="resolvePrompt(null)"
        >
          取消
        </button>
        <button
          type="submit"
          :disabled="busy"
          class="min-h-9 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent/90 disabled:opacity-50"
        >
          连接
        </button>
      </div>
    </form>

    <section
      v-else
      class="modal-panel mx-auto flex w-full max-w-sm flex-col justify-center rounded-lg bg-surface p-4"
      :class="isCloseApp ? 'border-0 shadow-none' : 'border border-border shadow-xl shadow-black/30'"
    >
      <div class="flex items-start gap-2.5">
        <TriangleAlert v-if="isConfirm || isCloseApp" class="mt-0.5 h-5 w-5 shrink-0 text-warning" />
        <ShieldCheck v-else class="mt-0.5 h-5 w-5 shrink-0 text-accent" />
        <div class="min-w-0">
          <h1 class="text-base font-semibold text-foreground">
            {{ isCloseApp ? '关闭 EXV' : isConfirm ? '请确认操作' : '建议您安装辅助服务' }}
          </h1>
          <p class="mt-2 text-sm leading-6 text-muted">
            {{ isCloseApp ? '选择关闭窗口后的处理方式。' : isConfirm ? message : '安装服务可以免于输入密码提权，精简连接流程。需要管理员权限。' }}
          </p>
        </div>
      </div>

      <div v-if="isCloseApp" class="mt-4 space-y-3">
        <fieldset class="space-y-2">
          <label
            class="flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-2.5 transition-colors"
            :class="closeChoice === 'tray' ? 'border-accent/60 bg-accent/10' : 'border-border hover:border-accent/40'"
          >
            <input
              v-model="closeChoice"
              type="radio"
              value="tray"
              class="mt-1 h-4 w-4 shrink-0 accent-accent"
            />
            <span class="min-w-0">
              <span class="block text-sm font-medium text-foreground">保持后台运行</span>
              <span class="mt-0.5 block text-xs leading-5 text-muted">关闭窗口后保留托盘入口，VPN 状态继续保持。</span>
            </span>
          </label>

          <label
            class="flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-2.5 transition-colors"
            :class="closeChoice === 'quit' ? 'border-destructive/70 bg-destructive/10' : 'border-border hover:border-destructive/40'"
          >
            <input
              v-model="closeChoice"
              type="radio"
              value="quit"
              class="mt-1 h-4 w-4 shrink-0 accent-destructive"
            />
            <span class="min-w-0">
              <span class="block text-sm font-medium text-foreground">退出并断连</span>
              <span class="mt-0.5 block text-xs leading-5 text-muted">断开 VPN 后退出 EXV。</span>
            </span>
          </label>
        </fieldset>

        <label class="flex cursor-pointer items-center gap-2 text-xs text-muted">
          <input
            v-model="rememberCloseChoice"
            type="checkbox"
            class="h-4 w-4 rounded border-border bg-bg accent-accent"
          />
          <span>记住我的选择</span>
        </label>

        <div class="flex justify-end gap-2">
          <button
            type="button"
            :disabled="busy"
            class="min-h-9 rounded-lg border border-border px-4 py-2 text-sm text-foreground transition-colors hover:border-accent/50 disabled:opacity-50"
            @click="resolvePrompt('cancel')"
          >
            取消
          </button>
          <button
            type="button"
            :disabled="busy"
            class="min-h-9 rounded-lg px-4 py-2 text-sm font-medium text-white transition-colors disabled:opacity-50"
            :class="closeChoice === 'quit' ? 'bg-destructive hover:bg-destructive/90' : 'bg-accent hover:bg-accent/90'"
            @click="submitCloseChoice"
          >
            确认
          </button>
        </div>
      </div>

      <div v-else class="mt-4 flex justify-end gap-2">
        <button
          type="button"
          :disabled="busy"
          class="min-h-9 rounded-lg border border-border px-4 py-2 text-sm text-foreground transition-colors hover:border-accent/50 disabled:opacity-50"
          @click="resolvePrompt(isConfirm ? false : 'dismiss')"
        >
          {{ isConfirm ? '取消' : '暂不安装' }}
        </button>
        <button
          type="button"
          :disabled="busy"
          class="min-h-9 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent/90 disabled:opacity-50"
          @click="resolvePrompt(isConfirm ? true : 'install')"
        >
          {{ isConfirm ? '确认' : '安装服务' }}
        </button>
      </div>
    </section>
  </main>
</template>

<style scoped>
.modal-panel {
  -webkit-app-region: drag;
  user-select: none;
}

.modal-panel :is(button, input, label) {
  -webkit-app-region: no-drag;
}

.modal-panel input {
  user-select: auto;
}
</style>
