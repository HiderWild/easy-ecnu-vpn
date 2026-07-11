<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import PasswordRevealButton from './PasswordRevealButton.vue'

defineOptions({
  inheritAttrs: false,
})

const props = withDefaults(defineProps<{
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

const savedPasswordOverwritePlaceholder = '您已保存过密码，输入并确认后将覆盖原有密码'
const effectivePlaceholder = computed(() =>
  props.showSavedPasswordOverwriteHint && !props.modelValue
    ? savedPasswordOverwritePlaceholder
    : props.placeholder,
)

const emit = defineEmits<{
  'update:modelValue': [value: string]
  input: [event: Event]
  blur: [event: FocusEvent]
  keyupEnter: [event: KeyboardEvent]
}>()

const revealed = ref(false)
const inputRef = ref<HTMLInputElement | null>(null)
const hasRevealableValue = computed(() => props.modelValue.length > 0)

watch(
  () => props.modelValue,
  (value) => {
    if (value.length === 0) {
      revealed.value = false
    }
  },
)

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
  <div :class="props.wrapperClass">
    <div class="relative">
      <input
        ref="inputRef"
        v-bind="$attrs"
        :value="props.modelValue"
        :type="revealed ? 'text' : 'password'"
        :autocomplete="props.autocomplete"
        :placeholder="effectivePlaceholder"
        :disabled="props.disabled"
        :autofocus="props.autofocus"
        :class="props.inputClass"
        @input="updateValue"
        @blur="blur"
        @keyup.enter="emit('keyupEnter', $event)"
      />
      <PasswordRevealButton
        v-if="props.showRevealButton && hasRevealableValue"
        v-model:revealed="revealed"
        :class="props.revealButtonClass"
      />
    </div>
  </div>
</template>
