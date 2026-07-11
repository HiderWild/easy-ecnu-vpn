<script setup lang="ts">
import { onBeforeUnmount, onMounted } from 'vue'
import { Eye } from 'lucide-vue-next'

const props = withDefaults(defineProps<{
  revealed: boolean
  class?: string
}>(), {
  class: '',
})

const emit = defineEmits<{
  'update:revealed': [value: boolean]
}>()

function show() {
  emit('update:revealed', true)
}

function hide() {
  emit('update:revealed', false)
}

function handleKeydown(event: KeyboardEvent) {
  if (event.key === ' ' || event.key === 'Enter') {
    event.preventDefault()
    show()
  }
}

function handleKeyup(event: KeyboardEvent) {
  if (event.key === ' ' || event.key === 'Enter') {
    event.preventDefault()
    hide()
  }
}

onMounted(() => {
  window.addEventListener('blur', hide)
})

onBeforeUnmount(() => {
  window.removeEventListener('blur', hide)
})
</script>

<template>
  <button
    type="button"
    :class="[
      'absolute right-2 top-1/2 grid h-8 w-8 -translate-y-1/2 place-items-center rounded-md text-muted transition-colors hover:bg-surface/80 hover:text-foreground',
      props.class,
    ]"
    title="按住显示密码"
    aria-label="按住显示密码"
    :aria-pressed="revealed"
    @pointerdown.prevent="show"
    @pointerup="hide"
    @pointercancel="hide"
    @pointerleave="hide"
    @blur="hide"
    @keydown="handleKeydown"
    @keyup="handleKeyup"
  >
    <Eye class="h-4 w-4" />
  </button>
</template>
