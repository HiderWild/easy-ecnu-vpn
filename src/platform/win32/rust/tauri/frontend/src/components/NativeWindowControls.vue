<script setup lang="ts">
import { computed } from "vue";

import type { NativeWindowControl, NativeWindowControlState } from "../product/window-chrome";
import type { WindowModePreference } from "../product/appearance";

const props = withDefaults(
  defineProps<{
    mode: WindowModePreference;
    state: NativeWindowControlState;
    disabled?: boolean;
  }>(),
  { disabled: false },
);

const emit = defineEmits<{ activate: [control: NativeWindowControl] }>();

const controls: ReadonlyArray<{ value: NativeWindowControl; label: string }> = [
  { value: "minimize", label: "最小化" },
  { value: "maximize", label: "最大化" },
  { value: "close", label: "关闭" },
];

const visibleControls = computed(() =>
  props.mode === "advanced" ? controls : controls.filter((control) => control.value !== "maximize"),
);
</script>

<template>
  <div class="native-window-controls" data-testid="native-window-controls" aria-label="窗口控制" role="group">
    <button
      v-for="control in visibleControls"
      :key="control.value"
      :data-testid="`native-window-control-${control.value}`"
      type="button"
      class="native-window-control"
      :class="{
        'native-window-control--hover': state.control === control.value,
        'native-window-control--pressed': state.control === control.value && state.pressed,
        'native-window-control--close': control.value === 'close',
      }"
      :aria-label="control.label"
      :disabled="disabled"
      @click.stop="emit('activate', control.value)"
    >
      <svg v-if="control.value === 'minimize'" data-icon="minimize" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M5 12h14" fill="none" stroke="currentColor" stroke-linecap="round" stroke-width="1.8" />
      </svg>
      <svg v-else-if="control.value === 'maximize'" data-icon="maximize" viewBox="0 0 24 24" aria-hidden="true">
        <rect x="5" y="5" width="14" height="14" rx="1" fill="none" stroke="currentColor" stroke-width="1.8" />
      </svg>
      <svg v-else data-icon="close" viewBox="0 0 24 24" aria-hidden="true">
        <path d="m6 6 12 12M18 6 6 18" fill="none" stroke="currentColor" stroke-linecap="round" stroke-width="1.8" />
      </svg>
    </button>
  </div>
</template>
