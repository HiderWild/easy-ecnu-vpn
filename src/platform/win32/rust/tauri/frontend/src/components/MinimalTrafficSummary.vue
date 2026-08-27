<script setup lang="ts">
import type { ProductMetricsAvailable } from "../product/types";

defineProps<{
  metrics: ProductMetricsAvailable | null;
}>();

function displayRate(value: string | null | undefined): string {
  return value ?? "—";
}
</script>

<template>
  <p
    class="minimal-traffic-summary"
    data-testid="minimal-traffic-summary"
    aria-label="上下行网络速率"
  >
    <span class="minimal-traffic-summary__item">
      <svg
        class="minimal-traffic-summary__icon minimal-traffic-summary__icon--upload"
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <!-- 与 C++ WebUI 的 Lucide ArrowUp 保持同一几何。 -->
        <path d="m5 12 7-7 7 7" />
        <path d="M12 19V5" />
      </svg>
      <span>上传 {{ displayRate(metrics?.uploadRate) }}</span>
    </span>
    <span class="minimal-traffic-summary__separator" aria-hidden="true">·</span>
    <span class="minimal-traffic-summary__item">
      <svg
        class="minimal-traffic-summary__icon minimal-traffic-summary__icon--download"
        viewBox="0 0 24 24"
        aria-hidden="true"
      >
        <!-- 与 C++ WebUI 的 Lucide ArrowDown 保持同一几何。 -->
        <path d="M12 5v14" />
        <path d="m19 12-7 7-7-7" />
      </svg>
      <span>下载 {{ displayRate(metrics?.downloadRate) }}</span>
    </span>
  </p>
</template>

<style scoped>
.minimal-traffic-summary {
  display: flex;
  align-items: center;
  min-width: 0;
  margin: 0;
  color: var(--color-text-secondary);
  font-size: var(--font-size-xs);
  line-height: 1.25;
  white-space: nowrap;
}

.minimal-traffic-summary__item {
  display: inline-flex;
  align-items: center;
  min-width: 0;
  gap: var(--space-1);
}

.minimal-traffic-summary__separator {
  margin: 0 var(--space-2);
  color: var(--color-text-muted);
}

.minimal-traffic-summary__icon {
  flex: 0 0 auto;
  width: 14px;
  height: 14px;
  fill: none;
  stroke: currentColor;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 2;
}

.minimal-traffic-summary__icon--upload {
  color: var(--color-warning);
}

.minimal-traffic-summary__icon--download {
  color: var(--color-accent);
}
</style>
