<script setup lang="ts">
import { computed } from "vue";

import type { ProductUiState } from "../product/types";
import { connectionActionFor } from "../product/connection-action";

const props = defineProps<{
  state: ProductUiState;
  busy: boolean;
}>();

const emit = defineEmits<{
  action: [];
}>();

const action = computed(() => connectionActionFor(props.state));

function requestAction(): void {
  if (!props.busy && action.value.enabled) emit("action");
}
</script>

<template>
  <button
    class="connection-action"
    data-testid="connection-action"
    :data-action="action.kind"
    type="button"
    :disabled="busy || !action.enabled"
    :aria-busy="busy ? 'true' : 'false'"
    @click="requestAction"
  >
    {{ action.label }}
  </button>
</template>

<style scoped>
.connection-action {
  min-width: 112px;
  min-height: 44px;
  border-color: var(--accent);
  background: var(--accent);
  color: var(--accent-on);
  font-weight: 650;
  letter-spacing: 0.02em;
}

.connection-action:hover:not(:disabled) {
  border-color: var(--accent-strong);
  background: var(--accent-strong);
}

.connection-action:disabled {
  border-color: var(--border-subtle);
  background: var(--surface-subtle);
  color: var(--text-secondary);
}
</style>
