<script setup lang="ts">
import { computed, ref } from 'vue'
import { X } from 'lucide-vue-next'
import PasswordField from './PasswordField.vue'

const props = withDefaults(defineProps<{
  modelValue: string | string[]
  placeholder?: string
  mode?: 'secret' | 'tokens'
}>(), {
  placeholder: '',
  mode: 'secret',
})

const emit = defineEmits<{
  (event: 'update:modelValue', value: string): void
  (event: 'update:modelValue', value: string[]): void
}>()

const pendingToken = ref('')

const tokens = computed(() => Array.isArray(props.modelValue) ? props.modelValue : [])

function onInput(e: Event) {
  emit('update:modelValue', (e.target as HTMLInputElement).value)
}

function commitTokens(raw: string) {
  const nextTokens = raw
    .split(/[\s,]+/)
    .map((value) => value.trim())
    .filter(Boolean)
  if (nextTokens.length === 0) return
  emit('update:modelValue', [...tokens.value, ...nextTokens])
  pendingToken.value = ''
}

function removeToken(index: number) {
  emit('update:modelValue', tokens.value.filter((_, current) => current !== index))
}

function onTokenKeydown(event: KeyboardEvent) {
  if (event.key === 'Enter' || event.key === ',') {
    event.preventDefault()
    commitTokens(pendingToken.value)
  }
  if (event.key === 'Backspace' && !pendingToken.value && tokens.value.length > 0) {
    removeToken(tokens.value.length - 1)
  }
}

function onTokenPaste(event: ClipboardEvent) {
  const text = event.clipboardData?.getData('text')
  if (!text || !/[\s,]/.test(text)) return
  event.preventDefault()
  commitTokens(text)
}
</script>

<template>
  <div v-if="mode === 'tokens'" class="flex min-h-10 flex-wrap items-center gap-2 rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-foreground focus-within:border-primary">
    <span
      v-for="(token, index) in tokens"
      :key="`${token}-${index}`"
      class="inline-flex max-w-full items-center gap-1 rounded-md bg-surface px-2 py-1 text-xs text-foreground"
    >
      <span class="truncate">{{ token }}</span>
      <button
        type="button"
        class="grid h-4 w-4 place-items-center rounded text-muted hover:bg-bg hover:text-foreground"
        aria-label="移除路由"
        @click="removeToken(index)"
      >
        <X class="h-3 w-3" />
      </button>
    </span>
    <input
      v-model="pendingToken"
      :placeholder="tokens.length === 0 ? placeholder : ''"
      class="min-w-28 flex-1 bg-transparent px-1 py-1 text-sm text-foreground outline-none placeholder:text-muted"
      @blur="commitTokens(pendingToken)"
      @keydown="onTokenKeydown"
      @paste="onTokenPaste"
    />
  </div>

  <div v-else class="relative">
    <PasswordField
      :value="typeof modelValue === 'string' ? modelValue : ''"
      :model-value="typeof modelValue === 'string' ? modelValue : ''"
      :placeholder="placeholder"
      input-class="w-full bg-bg border border-border rounded-lg px-3 py-2 pr-10 text-sm text-foreground font-mono placeholder:text-muted focus:outline-none focus:border-accent/50 transition-colors"
      reveal-button-class="right-1.5"
      @input="onInput"
    />
  </div>
</template>
