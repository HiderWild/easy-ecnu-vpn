<script setup lang="ts">
import { computed, ref } from 'vue'
import { Plus, X } from 'lucide-vue-next'
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
}

function onTokenPaste(event: ClipboardEvent) {
  const text = event.clipboardData?.getData('text')
  if (!text || !/[\s,]/.test(text)) return
  event.preventDefault()
  commitTokens(text)
}
</script>

<template>
  <div v-if="mode === 'tokens'" class="token-input token-input--tokens">
    <div v-if="tokens.length > 0" class="token-input__tokens">
      <span
        v-for="(token, index) in tokens"
        :key="`${token}-${index}`"
        class="token-input__token"
      >
        <span class="token-input__token-label">{{ token }}</span>
        <button
          type="button"
          class="token-input__remove"
          aria-label="移除路由"
          @mousedown.stop
          @click.stop="removeToken(index)"
        >
          <X class="h-3 w-3" />
        </button>
      </span>
    </div>
    <div class="token-input__field-row">
      <input
        v-model="pendingToken"
        :placeholder="placeholder"
        class="token-input__field"
        @blur="commitTokens(pendingToken)"
        @keydown="onTokenKeydown"
        @paste="onTokenPaste"
      />
      <button
        type="button"
        class="token-input__add"
        aria-label="添加路由"
        :disabled="!pendingToken.trim()"
        @mousedown.prevent
        @click="commitTokens(pendingToken)"
      >
        <Plus class="h-3.5 w-3.5" />
      </button>
    </div>
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

<style scoped>
.token-input--tokens {
  display: grid;
  align-content: start;
  min-height: 36px;
  min-width: 0;
  gap: 6px;
  border: 1px solid var(--color-border);
  border-radius: 8px;
  background: var(--color-bg);
  padding: 7px;
  color: var(--color-foreground);
  font-size: 13px;
}

.token-input--tokens:focus-within {
  border-color: var(--color-accent);
}

.token-input__tokens {
  display: flex;
  max-height: 132px;
  min-width: 0;
  flex-wrap: wrap;
  gap: 6px;
  overflow: auto;
  padding-right: 2px;
  overscroll-behavior: contain;
}

.token-input__token {
  display: inline-flex;
  max-width: 100%;
  align-items: center;
  gap: 5px;
  border-radius: 6px;
  background: var(--color-surface);
  padding: 5px 7px;
  color: var(--color-foreground);
  font-size: 12px;
  line-height: 1.2;
}

.token-input__token-label {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.token-input__remove {
  display: grid;
  width: 16px;
  height: 16px;
  flex: 0 0 auto;
  place-items: center;
  border-radius: 4px;
  color: var(--color-muted);
}

.token-input__remove:hover {
  background: var(--color-bg);
  color: var(--color-foreground);
}

.token-input__field {
  min-width: 0;
  flex: 1 1 auto;
  width: 100%;
  border: 0;
  background: transparent;
  color: var(--color-foreground);
  font-size: 13px;
  outline: none;
}

.token-input__field-row {
  display: flex;
  min-height: 32px;
  min-width: 0;
  align-items: center;
  gap: 6px;
  border-radius: 6px;
  background: color-mix(in srgb, var(--color-surface) 32%, transparent);
  padding: 0 4px 0 8px;
}

.token-input__field::placeholder {
  color: var(--color-muted);
}

.token-input__add {
  display: grid;
  width: 24px;
  height: 24px;
  flex: 0 0 auto;
  place-items: center;
  border-radius: 5px;
  color: var(--color-accent);
}

.token-input__add:hover:not(:disabled) {
  background: var(--accent-soft-bg);
}

.token-input__add:disabled {
  cursor: default;
  opacity: 0.45;
}
</style>
