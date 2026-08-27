<script setup lang="ts">
import type { ProductStage, StageVisual } from "../product/types";

defineProps<{
  stages: readonly ProductStage[];
}>();

const stateText: Record<StageVisual, string> = {
  complete: "已完成",
  current: "进行中",
  waiting: "等待中",
};
</script>

<template>
  <ol class="stage-list" data-testid="stage-list" aria-label="连接阶段">
    <li
      v-for="stage in stages"
      :key="stage.phase"
      class="stage-item"
      data-testid="stage-item"
      :data-stage-visual="stage.visual"
      :aria-label="`${stage.label}，${stateText[stage.visual]}`"
    >
      <span class="stage-mark" :class="`stage-mark--${stage.visual}`" aria-hidden="true">
        <span v-if="stage.visual === 'complete'">✓</span>
        <span v-else-if="stage.visual === 'current'" class="stage-ring"></span>
        <span v-else>i</span>
      </span>
      <span class="stage-label">{{ stage.label }}</span>
      <span class="visually-hidden">{{ stateText[stage.visual] }}</span>
    </li>
  </ol>
</template>

<style scoped>
.stage-list {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--space-2) var(--space-3);
  margin: 0;
  padding: 0;
  list-style: none;
}

.stage-item {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-2) 0;
  color: var(--text-secondary);
  font-size: 14px;
  line-height: 1.4;
}

.stage-mark {
  display: inline-grid;
  width: 20px;
  height: 20px;
  flex: 0 0 20px;
  place-items: center;
  border: 1px solid var(--border-strong);
  border-radius: 50%;
  color: var(--text-primary);
  font-size: 13px;
  font-weight: 700;
  line-height: 1;
  transition: opacity var(--motion-fast) var(--motion-ease);
}

.stage-mark--complete {
  border-color: var(--state-success);
  color: var(--state-success);
}

.stage-mark--current {
  border-color: var(--state-warning);
  color: var(--state-warning);
}

.stage-ring {
  width: 8px;
  height: 8px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: 50%;
  animation: stage-ring-spin 440ms linear infinite;
}

@keyframes stage-ring-spin {
  to {
    transform: rotate(1turn);
  }
}

@media (prefers-reduced-motion: reduce) {
  .stage-ring {
    animation: none;
  }
}

.stage-label {
  overflow-wrap: anywhere;
}

.visually-hidden {
  position: absolute;
  width: 1px;
  height: 1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
}
</style>
