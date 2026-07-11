<script setup lang="ts">
import { Expand, Shrink } from 'lucide-vue-next'

type WindowMode = 'advanced' | 'minimal'

const props = defineProps<{
  modelValue: WindowMode
  disabled?: boolean
  iconOnly?: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [value: WindowMode]
}>()

const options: Array<{
  value: WindowMode
  label: string
  icon: typeof Expand
}> = [
  { value: 'advanced', label: '完整', icon: Expand },
  { value: 'minimal', label: '极简', icon: Shrink },
]

function selectMode(mode: WindowMode) {
  if (props.disabled || mode === props.modelValue) return
  emit('update:modelValue', mode)
}
</script>

<template>
  <div
    class="mode-segmented-control"
    role="group"
    aria-label="窗口模式"
    :class="{ 'mode-segmented-control--icon-only': iconOnly }"
  >
    <button
      v-for="option in options"
      :key="option.value"
      type="button"
      class="mode-segmented-control__button"
      :class="{ 'mode-segmented-control__button--active': modelValue === option.value }"
      :aria-pressed="modelValue === option.value"
      :aria-label="option.label"
      :title="option.label"
      :disabled="disabled"
      @click="selectMode(option.value)"
    >
      <component :is="option.icon" class="h-3.5 w-3.5" aria-hidden="true" />
      <span v-if="!iconOnly">{{ option.label }}</span>
    </button>
  </div>
</template>

<style scoped>
.mode-segmented-control {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  padding: 2px;
  border: 1px solid var(--color-border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--color-bg) 84%, transparent);
  app-region: no-drag;
  -webkit-app-region: no-drag;
}

.mode-segmented-control__button {
  display: inline-flex;
  min-width: 52px;
  height: 24px;
  align-items: center;
  justify-content: center;
  gap: 5px;
  border-radius: 6px;
  color: var(--color-muted);
  font-size: 11px;
  line-height: 1;
  transition: background-color 120ms ease, color 120ms ease;
}

.mode-segmented-control--icon-only .mode-segmented-control__button {
  min-width: 24px;
  width: 24px;
}

.mode-segmented-control__button:hover:not(:disabled) {
  color: var(--color-foreground);
}

.mode-segmented-control__button--active {
  background: color-mix(in srgb, var(--color-accent) 16%, transparent);
  color: var(--color-accent);
}

.mode-segmented-control__button:disabled {
  cursor: default;
  opacity: 0.55;
}
</style>
