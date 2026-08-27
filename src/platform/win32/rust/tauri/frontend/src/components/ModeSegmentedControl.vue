<script setup lang="ts">
import type { WindowModePreference } from "../product/appearance";

const props = defineProps<{
  modelValue: WindowModePreference;
  disabled?: boolean;
  iconOnly?: boolean;
}>();

const emit = defineEmits<{
  "update:modelValue": [value: WindowModePreference];
}>();

const options: ReadonlyArray<{ value: WindowModePreference; label: string }> = [
  { value: "advanced", label: "完整" },
  { value: "minimal", label: "极简" },
];

function selectMode(value: WindowModePreference): void {
  if (props.disabled || value === props.modelValue) return;
  emit("update:modelValue", value);
}
</script>

<template>
  <div
    class="mode-segmented-control"
    role="group"
    aria-label="窗口模式"
    :class="{ 'mode-segmented-control--icon-only': iconOnly }"
    data-testid="mode-segmented-control"
  >
    <button
      v-for="option in options"
      :key="option.value"
      :data-testid="`mode-option-${option.value}`"
      type="button"
      class="mode-segmented-control__button"
      :class="{ 'mode-segmented-control__button--active': modelValue === option.value }"
      :aria-pressed="modelValue === option.value"
      :aria-label="option.label"
      :title="option.label"
      :disabled="disabled"
      @click="selectMode(option.value)"
    >
      <svg v-if="option.value === 'advanced'" class="mode-segmented-control__icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M4 5h16v14H4z" fill="none" stroke="currentColor" stroke-width="1.7" />
        <path d="M8 9h8M8 13h5" fill="none" stroke="currentColor" stroke-linecap="round" stroke-width="1.7" />
      </svg>
      <svg v-else class="mode-segmented-control__icon" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M6 6h12v12H6z" fill="none" stroke="currentColor" stroke-width="1.7" />
        <path d="M9 9h6v6H9z" fill="none" stroke="currentColor" stroke-width="1.7" />
      </svg>
      <span v-if="!iconOnly">{{ option.label }}</span>
    </button>
  </div>
</template>
