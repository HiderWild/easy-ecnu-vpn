<script setup lang="ts">
import { ref } from 'vue'
import PasswordRevealButton from './PasswordRevealButton.vue'

defineOptions({
  inheritAttrs: false,
})

withDefaults(defineProps<{
  modelValue: string
  placeholder?: string
  autocomplete?: string
  inputClass?: string
  wrapperClass?: string
  revealButtonClass?: string
  showRevealButton?: boolean
  disabled?: boolean
  autofocus?: boolean
  showSavedPasswordOverwriteHint?: boolean
}>(), {
  placeholder: '',
  autocomplete: undefined,
  inputClass: '',
  wrapperClass: '',
  revealButtonClass: '',
  showRevealButton: true,
  disabled: false,
  autofocus: false,
  showSavedPasswordOverwriteHint: false,
})

const emit = defineEmits<{
  'update:modelValue': [value: string]
  input: [event: Event]
  blur: [event: FocusEvent]
  keyupEnter: [event: KeyboardEvent]
}>()

const revealed = ref(false)
const inputRef = ref<HTMLInputElement | null>(null)

function updateValue(event: Event) {
  emit('update:modelValue', (event.target as HTMLInputElement).value)
  emit('input', event)
}

function blur(event: FocusEvent) {
  revealed.value = false
  emit('blur', event)
}

function focus() {
  inputRef.value?.focus()
}

defineExpose({ focus })
</script>

<template>
  <div :class="wrapperClass">
    <div class="relative">
      <input
        ref="inputRef"
        v-bind="$attrs"
        :value="modelValue"
        :type="revealed ? 'text' : 'password'"
        :autocomplete="autocomplete"
        :placeholder="placeholder"
        :disabled="disabled"
        :autofocus="autofocus"
        :class="inputClass"
        @input="updateValue"
        @blur="blur"
        @keyup.enter="emit('keyupEnter', $event)"
      />
      <PasswordRevealButton
        v-if="showRevealButton"
        v-model:revealed="revealed"
        :class="revealButtonClass"
      />
    </div>
    <p v-if="showSavedPasswordOverwriteHint" class="mt-1 text-xs text-muted">
      您已保存过密码，输入并确认后将覆盖原有密码
    </p>
  </div>
</template>
