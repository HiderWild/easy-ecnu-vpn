<script setup lang="ts">
import { Monitor, Moon, Sun } from 'lucide-vue-next'
import type { Component } from 'vue'
import type { ThemeMode } from '../stores/theme'

const props = defineProps<{
  modelValue: ThemeMode
  disabled?: boolean
  iconOnly?: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [value: ThemeMode]
}>()

const options: Array<{
  value: ThemeMode
  label: string
  icon: Component
}> = [
  { value: 'light', label: '浅色', icon: Sun },
  { value: 'dark', label: '深色', icon: Moon },
  { value: 'system', label: '系统', icon: Monitor },
]

function selectTheme(mode: ThemeMode) {
  if (props.disabled || mode === props.modelValue) return
  emit('update:modelValue', mode)
}
</script>

<template>
  <div
    class="titlebar-theme-mode-control"
    role="group"
    aria-label="主题模式"
    :class="{ 'titlebar-theme-mode-control--icon-only': iconOnly }"
  >
    <button
      v-for="option in options"
      :key="option.value"
      type="button"
      class="titlebar-theme-mode-control__button"
      :class="{ 'titlebar-theme-mode-control__button--active': modelValue === option.value }"
      :aria-pressed="modelValue === option.value"
      :aria-label="option.label"
      :title="option.label"
      :disabled="disabled"
      @click="selectTheme(option.value)"
    >
      <component :is="option.icon" class="h-3.5 w-3.5" aria-hidden="true" />
      <span v-if="!iconOnly">{{ option.label }}</span>
    </button>
  </div>
</template>

<style scoped>
.titlebar-theme-mode-control {
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

.titlebar-theme-mode-control__button {
  display: inline-flex;
  min-width: 51px;
  height: 24px;
  align-items: center;
  justify-content: center;
  gap: 5px;
  padding: 0 3px;
  border-radius: 6px;
  color: var(--color-muted);
  font-size: 11px;
  line-height: 1;
  transition: background-color 120ms ease, color 120ms ease;
}

.titlebar-theme-mode-control--icon-only .titlebar-theme-mode-control__button {
  min-width: 24px;
  width: 24px;
  padding: 0;
}

.titlebar-theme-mode-control__button:hover:not(:disabled) {
  color: var(--color-foreground);
}

.titlebar-theme-mode-control__button--active {
  background: color-mix(in srgb, var(--color-accent) 16%, transparent);
  color: var(--color-accent);
}

.titlebar-theme-mode-control__button:disabled {
  cursor: default;
  opacity: 0.55;
}
</style>
