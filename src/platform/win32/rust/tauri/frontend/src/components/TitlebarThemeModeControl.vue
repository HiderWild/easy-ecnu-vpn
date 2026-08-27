<script setup lang="ts">
import type { ThemePreference } from "../product/appearance";

const props = defineProps<{
  modelValue: ThemePreference;
  disabled?: boolean;
  iconOnly?: boolean;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: ThemePreference];
}>();

const options: ReadonlyArray<{ value: ThemePreference; label: string }> = [
  { value: "light", label: "浅色" },
  { value: "dark", label: "深色" },
  { value: "system", label: "系统" },
];

function selectTheme(value: ThemePreference): void {
  if (props.disabled || value === props.modelValue) return;
  emit("update:modelValue", value);
}
</script>

<template>
  <div
    class="titlebar-theme-mode-control"
    role="group"
    aria-label="主题模式"
    :class="{ 'titlebar-theme-mode-control--icon-only': iconOnly }"
    data-testid="titlebar-theme-mode-control"
  >
    <button
      v-for="option in options"
      :key="option.value"
      :data-testid="`theme-option-${option.value}`"
      type="button"
      class="titlebar-theme-mode-control__button"
      :class="{ 'titlebar-theme-mode-control__button--active': modelValue === option.value }"
      :aria-pressed="modelValue === option.value"
      :aria-label="option.label"
      :title="option.label"
      :disabled="disabled"
      @click="selectTheme(option.value)"
    >
      <svg v-if="option.value === 'light'" class="titlebar-theme-mode-control__icon" viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="1.7" />
        <path d="M12 3v2M12 19v2M3 12h2M19 12h2M5.6 5.6 7 7M17 17l1.4 1.4M18.4 5.6 17 7M7 17l-1.4 1.4" fill="none" stroke="currentColor" stroke-linecap="round" stroke-width="1.7" />
      </svg>
      <svg v-else-if="option.value === 'dark'" class="titlebar-theme-mode-control__icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M19.2 14.7A7.5 7.5 0 0 1 9.3 4.8 7.6 7.6 0 1 0 19.2 14.7Z" fill="none" stroke="currentColor" stroke-linejoin="round" stroke-width="1.7" />
      </svg>
      <svg v-else class="titlebar-theme-mode-control__icon" viewBox="0 0 24 24" aria-hidden="true">
        <rect x="4" y="5" width="16" height="12" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.7" />
        <path d="M8 20h8M12 17v3" fill="none" stroke="currentColor" stroke-linecap="round" stroke-width="1.7" />
      </svg>
      <span v-if="!iconOnly">{{ option.label }}</span>
    </button>
  </div>
</template>
