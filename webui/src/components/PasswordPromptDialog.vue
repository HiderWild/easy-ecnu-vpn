<script setup lang="ts">
import { nextTick, ref, watch } from 'vue'
import { KeyRound } from 'lucide-vue-next'
import ModalShell from './ModalShell.vue'
import PasswordField from './PasswordField.vue'
import { useUiStore } from '../stores/ui'

const props = withDefaults(defineProps<{
  compact?: boolean
}>(), {
  compact: false,
})
const ui = useUiStore()
const password = ref('')
const error = ref('')
const inputRef = ref<InstanceType<typeof PasswordField> | null>(null)

watch(
  () => ui.showPasswordPrompt,
  async (visible) => {
    if (!visible) {
      password.value = ''
      error.value = ''
      return
    }
    password.value = ''
    error.value = ''
    await nextTick()
    inputRef.value?.focus()
  },
)

function submit() {
  if (!password.value) {
    error.value = '请输入验证内容'
    return
  }
  const value = password.value
  password.value = ''
  ui.submitPasswordPrompt(value)
}

function cancel() {
  password.value = ''
  ui.closePasswordPrompt()
}
</script>

<template>
  <ModalShell
    :open="ui.showPasswordPrompt"
    :title="props.compact ? '输入口令' : ui.passwordPromptMessage"
    :description="props.compact ? '' : ui.passwordPromptDescription"
    :compact="props.compact"
    size="sm"
    @close="cancel"
  >
    <template #icon>
      <KeyRound class="h-4 w-4" />
    </template>

    <form
      id="legacy-password-prompt-form"
      :class="props.compact ? 'modal-compact-form' : 'space-y-3'"
      @submit.prevent="submit"
    >
      <div>
        <PasswordField
          ref="inputRef"
          v-model="password"
          autocomplete="one-time-code"
          input-class="w-full rounded-lg border border-border bg-bg px-3 py-2 pr-11 text-sm text-foreground outline-none transition-colors focus:border-primary"
          :placeholder="props.compact ? ui.passwordPromptMessage : '密码或验证码'"
          :show-reveal-button="!props.compact"
          @input="error = ''"
          @keydown.esc.prevent="cancel"
        />
      </div>
      <p v-if="error" :class="props.compact ? 'modal-compact-error' : 'text-xs text-destructive'">{{ error }}</p>
    </form>

    <template #actions>
      <button
        type="button"
        class="rounded-lg border border-border px-3 py-2 text-sm text-muted hover:bg-surface/80"
        @click="cancel"
      >
        {{ ui.passwordPromptCancelLabel }}
      </button>
      <button
        type="submit"
        form="legacy-password-prompt-form"
        class="rounded-lg bg-primary px-3 py-2 text-sm text-white hover:bg-primary/90"
      >
        {{ ui.passwordPromptSubmitLabel }}
      </button>
    </template>
  </ModalShell>
</template>
