<script setup lang="ts">
import type { ProductUiState } from "../product/types";
import ConnectionStageList from "./ConnectionStageList.vue";

defineProps<{
  state: ProductUiState;
}>();
</script>

<template>
  <section class="product-connection-visual-stage" data-testid="product-connection-visual-stage">
    <div class="product-connection-visual-stage__visual">
      <section class="product-connection-visual-stage__placeholder" data-testid="connection-visual-placeholder" aria-label="主页状态区域">
        UI 待设计
      </section>
    </div>

    <div v-if="state.stages.length" class="product-connection-visual-stage__stages">
      <ConnectionStageList :stages="state.stages" />
    </div>
  </section>
</template>

<style scoped>
.product-connection-visual-stage {
  display: grid;
  height: 100%;
  min-height: 0;
  min-width: 0;
  grid-template-columns: minmax(0, 1fr);
  gap: var(--space-5);
}

.product-connection-visual-stage:has(.product-connection-visual-stage__stages) {
  grid-template-columns: minmax(0, 1.35fr) minmax(250px, 0.65fr);
}

.product-connection-visual-stage__visual {
  position: relative;
  height: 100%;
  min-height: 0;
  min-width: 0;
  overflow: hidden;
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  background: var(--surface-subtle);
}

.product-connection-visual-stage__placeholder {
  display: grid;
  height: 100%;
  min-height: 0;
  place-items: center;
  color: var(--text-tertiary);
  font-size: 14px;
}

.product-connection-visual-stage__stages {
  align-self: center;
  padding: var(--space-5);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  background: var(--surface-panel);
  box-shadow: var(--shadow-raised);
}

@media (max-width: 1120px) {
  .product-connection-visual-stage:has(.product-connection-visual-stage__stages) {
    grid-template-columns: 1fr;
  }
}

</style>
