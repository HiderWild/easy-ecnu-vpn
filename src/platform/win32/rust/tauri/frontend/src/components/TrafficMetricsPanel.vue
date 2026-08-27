<script setup lang="ts">
import type { ProductMetricsAvailable } from "../product/types";

withDefaults(
  defineProps<{
    metrics: ProductMetricsAvailable | null;
    showTotals?: boolean;
    compact?: boolean;
  }>(),
  {
    showTotals: false,
    compact: false,
  },
);

const displayMetric = (value: string | null | undefined): string => value ?? "—";
</script>

<template>
  <div
    class="traffic-metrics-panel"
    :class="{ 'traffic-metrics-panel--compact': compact }"
    data-testid="traffic-metrics-panel"
    aria-label="上下行网络指标"
  >
    <div
      class="traffic-metric traffic-metric--upload"
      data-testid="traffic-metric-upload"
      :aria-label="`上传 ${displayMetric(metrics?.uploadRate)}`"
    >
      <svg
        class="traffic-metric__arrow"
        data-direction="up"
        viewBox="0 0 24 24"
        fill="none"
        aria-hidden="true"
      >
        <!-- 与 C++ WebUI 的 Lucide ArrowUp 保持同一几何。 -->
        <path d="m5 12 7-7 7 7" />
        <path d="M12 19V5" />
      </svg>
      <div class="traffic-metric__values">
        <strong class="traffic-metric__rate">{{ displayMetric(metrics?.uploadRate) }}</strong>
        <small v-if="showTotals" class="traffic-metric__total">{{ displayMetric(metrics?.uploadTotal) }}</small>
      </div>
    </div>

    <div
      class="traffic-metric traffic-metric--download"
      data-testid="traffic-metric-download"
      :aria-label="`下载 ${displayMetric(metrics?.downloadRate)}`"
    >
      <svg
        class="traffic-metric__arrow"
        data-direction="down"
        viewBox="0 0 24 24"
        fill="none"
        aria-hidden="true"
      >
        <!-- 与 C++ WebUI 的 Lucide ArrowDown 保持同一几何。 -->
        <path d="M12 5v14" />
        <path d="m19 12-7 7-7-7" />
      </svg>
      <div class="traffic-metric__values">
        <strong class="traffic-metric__rate">{{ displayMetric(metrics?.downloadRate) }}</strong>
        <small v-if="showTotals" class="traffic-metric__total">{{ displayMetric(metrics?.downloadTotal) }}</small>
      </div>
    </div>
  </div>
</template>

<style scoped>
.traffic-metrics-panel {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--space-3);
  min-width: 0;
}

.traffic-metric {
  display: grid;
  min-width: 0;
  min-height: 32px;
  grid-template-columns: 22px minmax(0, 1fr);
  align-items: center;
  gap: var(--space-2);
  padding: 0;
}

.traffic-metric__arrow {
  width: 20px;
  height: 20px;
  align-self: center;
  overflow: visible;
  stroke: currentColor;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 2.6;
}

.traffic-metric--upload .traffic-metric__arrow {
  color: var(--state-warning, #e3a51a);
}

.traffic-metric--download .traffic-metric__arrow {
  color: var(--accent, #2f6fed);
}

.traffic-metric__values {
  display: grid;
  min-width: 0;
  min-height: 32px;
  grid-template-rows: repeat(2, minmax(0, 1fr));
  align-content: center;
  gap: 1px;
  overflow: hidden;
}

.traffic-metric__rate,
.traffic-metric__total {
  overflow: hidden;
  font-variant-numeric: tabular-nums;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.traffic-metric__rate {
  color: var(--text-primary);
  font-size: 14px;
  font-weight: 720;
  line-height: 1.15;
}

.traffic-metric__total {
  color: var(--text-tertiary);
  font-size: 11px;
  line-height: 1.1;
}

.traffic-metrics-panel--compact {
  gap: 6px;
}

.traffic-metrics-panel--compact .traffic-metric {
  min-height: 28px;
  grid-template-columns: 18px minmax(0, 1fr);
  gap: 5px;
}

.traffic-metrics-panel--compact .traffic-metric__arrow {
  width: 16px;
  height: 16px;
}

.traffic-metrics-panel--compact .traffic-metric__rate {
  font-size: 12px;
}

</style>
