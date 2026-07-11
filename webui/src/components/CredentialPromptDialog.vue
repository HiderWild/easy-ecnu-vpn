<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { KeyRound } from 'lucide-vue-next'
import ModalShell from './ModalShell.vue'
import PasswordField from './PasswordField.vue'
import { useConfigStore } from '../stores/config'
import { useUiStore } from '../stores/ui'

const props = withDefaults(defineProps<{
  compact?: boolean
}>(), {
  compact: false,
})
const config = useConfigStore()
const ui = useUiStore()
const username = ref('')
const password = ref('')
const rememberPassword = ref(true)
const error = ref('')
const usernameRef = ref<HTMLInputElement | null>(null)
const passwordRef = ref<InstanceType<typeof PasswordField> | null>(null)

const credentialPromptTitle = computed(() => {
  const request = ui.credentialPrompt
  if (!request) return ''
  if (request.message) return request.message
  if (request.missingUsername && request.missingPassword) return '请输入用户名和密码'
  if (request.missingUsername) return '请输入用户名'
  return '请输入密码'
})
const credentialPromptNeedsFullWindow = computed(() =>
  props.compact && Boolean(ui.credentialPrompt?.missingUsername),
)
const showSavedPasswordOverwriteHint = computed(() =>
  Boolean(ui.credentialPrompt?.missingPassword && config.authConfig.password_stored),
)

watch(
  () => ui.showCredentialPrompt,
  async (visible) => {
    if (!visible || !ui.credentialPrompt) {
      username.value = ''
      password.value = ''
      error.value = ''
      return
    }
    username.value = ui.credentialPrompt.username
    password.value = ''
    rememberPassword.value = ui.credentialPrompt.rememberPassword
    error.value = ''
    await nextTick()
    if (ui.credentialPrompt.missingUsername) {
      usernameRef.value?.focus()
    } else {
      passwordRef.value?.focus()
    }
  },
)

function submit() {
  const request = ui.credentialPrompt
  if (!request) return
  if (request.missingUsername && !username.value.trim()) {
    error.value = '请输入用户名'
    usernameRef.value?.focus()
    return
  }
  if (request.missingPassword && !password.value) {
    error.value = '请输入密码'
    passwordRef.value?.focus()
    return
  }
  ui.submitCredentialPrompt({
    username: request.missingUsername ? username.value.trim() : undefined,
    password: request.missingPassword ? password.value : undefined,
    rememberPassword: rememberPassword.value,
  })
}

function cancel() {
  ui.closeCredentialPrompt()
}

function enterFullCredentialPrompt() {
  void config.saveSettings({ minimal_mode: false })
}
</script>

<template>
  <ModalShell
    :open="ui.showCredentialPrompt"
    :title="props.compact ? '补全凭据' : credentialPromptTitle"
    :compact="props.compact"
    size="sm"
    @close="cancel"
  >
    <template #icon>
      <KeyRound class="h-4 w-4" />
    </template>

    <p v-if="credentialPromptNeedsFullWindow" class="modal-compact-message">
      需要补全用户名，请切换到完整窗口继续输入。
    </p>

    <form
      v-else
      id="credential-prompt-form"
      :class="props.compact ? 'modal-compact-form' : 'space-y-3'"
      @submit.prevent="submit"
    >
      <label v-if="ui.credentialPrompt?.missingUsername" class="block">
        <span class="mb-1 block text-xs font-medium text-muted">用户名</span>
        <input
          ref="usernameRef"
          v-model="username"
          autocomplete="username"
          class="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-foreground outline-none focus:border-primary"
          @input="error = ''"
          @keydown.esc.prevent="cancel"
        />
      </label>

      <label v-if="ui.credentialPrompt?.missingPassword" class="block">
        <span class="mb-1 block text-xs font-medium text-muted">密码</span>
        <PasswordField
          ref="passwordRef"
          v-model="password"
          autocomplete="current-password"
          input-class="w-full rounded-lg border border-border bg-bg px-3 py-2 pr-11 text-sm text-foreground outline-none focus:border-primary"
          :show-reveal-button="!props.compact"
          :show-saved-password-overwrite-hint="showSavedPasswordOverwriteHint"
          @input="error = ''"
          @keydown.esc.prevent="cancel"
        />
      </label>

      <label v-if="ui.credentialPrompt?.missingPassword && !props.compact" class="flex items-center gap-2 text-xs text-muted">
        <input
          v-model="rememberPassword"
          type="checkbox"
          class="h-4 w-4 rounded border-border bg-bg text-primary focus:ring-primary/40"
        />
        记住密码
      </label>

      <p v-if="error" :class="props.compact ? 'modal-compact-error' : 'text-xs text-destructive'">{{ error }}</p>
    </form>

    <template #actions>
      <button type="button" class="rounded-lg border border-border px-3 py-2 text-sm text-muted hover:bg-surface/80" @click="cancel">
        取消
      </button>
      <button
        v-if="credentialPromptNeedsFullWindow"
        type="button"
        class="rounded-lg bg-primary px-3 py-2 text-sm text-white hover:bg-primary/90"
        @click="enterFullCredentialPrompt"
      >
        完整输入
      </button>
      <button v-else type="submit" form="credential-prompt-form" class="rounded-lg bg-primary px-3 py-2 text-sm text-white hover:bg-primary/90">
        连接
      </button>
    </template>
  </ModalShell>
</template>
