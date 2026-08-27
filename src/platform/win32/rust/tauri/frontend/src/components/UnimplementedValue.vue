<script setup lang="ts">
import type { UnimplementedValue as UnimplementedValueModel } from "../product/types";

defineProps<{
  value: UnimplementedValueModel;
}>();
</script>

<template>
  <span class="unimplemented-value" data-testid="unimplemented-value">{{ value.label }}</span>
</template>

<style scoped>
.unimplemented-value {
  color: var(--text-tertiary);
  font-size: 14px;
  white-space: nowrap;
}
</style>
