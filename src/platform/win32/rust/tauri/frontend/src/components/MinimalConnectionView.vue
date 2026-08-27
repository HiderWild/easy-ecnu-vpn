<script setup lang="ts">
import { computed } from "vue";

import type { ProductConnectionAction } from "../product/connection-action";
import type { ProductUiState } from "../product/types";
import MinimalTrafficSummary from "./MinimalTrafficSummary.vue";

const props = defineProps<{
  state: ProductUiState;
  action: ProductConnectionAction;
}>();

const emit = defineEmits<{ run: [] }>();

const showProgress = computed(() => props.state.status === "connecting" || props.state.status === "awaiting");
const connected = computed(() => props.state.status === "connected");
const availableMetrics = computed(() =>
  props.state.metrics?.availability === "available" ? props.state.metrics : null,
);
const connectionInfo = computed(() => props.state.connectionInfo);
const displayMetric = (value: string | null | undefined): string => value ?? "—";
const currentStage = computed(() => props.state.stages.find((stage) => stage.visual === "current")?.label ?? "");
const detail = computed(() => {
  if (props.state.description?.trim()) return props.state.description.trim();
  const copy: Record<ProductUiState["status"], string> = {
    idle: "准备好后即可连接。",
    connecting: "正在完成连接准备。",
    awaiting: "请完成账户确认。",
    // 已连接无额外说明：极简模式不展示「连接正常，数据正在安全传输」这类幽灵文本。
    connected: "",
    stopping: "正在安全撤销连接配置。",
    reconciling: "正在核对连接状态。",
    failed: "连接未完成，请根据提示处理。",
  };
  return copy[props.state.status];
});

function requestAction(): void {
  if (props.action.enabled) emit("run");
}
</script>

<template>
  <section class="minimal-connection-view" aria-label="极简连接状态">
    <header class="minimal-connection-view__header">
      <div class="minimal-connection-view__copy">
        <h1 class="minimal-connection-view__title" data-testid="minimal-status">{{ state.title }}</h1>
        <p v-if="state.coreStatus === 'stopped'" class="minimal-connection-view__detail">核心已停止</p>
        <p v-if="detail" class="minimal-connection-view__detail">{{ detail }}</p>
      </div>
      <button
        class="minimal-connection-view__action"
        data-testid="minimal-action"
        type="button"
        :disabled="!action.enabled"
        @click="requestAction"
      >
        {{ action.label }}
      </button>
    </header>

    <div v-if="showProgress" class="minimal-progress-wrap" data-testid="minimal-progress" :aria-label="currentStage">
      <div class="minimal-progress" role="list">
        <span
          v-for="(stage, index) in state.stages"
          :key="stage.phase"
          class="minimal-progress-segment"
          :class="`minimal-progress-segment--${stage.visual}`"
          data-testid="minimal-progress-segment"
          :data-stage-index="index"
          role="listitem"
        />
      </div>
      <span class="minimal-progress-label">{{ currentStage }}</span>
    </div>

    <div v-if="connected" class="minimal-traffic" data-testid="minimal-traffic">
      <div class="minimal-connection-meta">
        <span><b>在线</b> {{ displayMetric(state.metrics?.online) }}</span>
        <span><b>账户</b> {{ connectionInfo.account ?? "—" }}</span>
        <span v-if="state.reconnect.enabled"><b>连接时延</b> {{ displayMetric(availableMetrics?.latency) }}</span>
      </div>
      <MinimalTrafficSummary :metrics="availableMetrics" />
    </div>
  </section>
</template>

<style scoped>
.minimal-connection-view {
  width: 328px;
  min-width: 328px;
  height: 102px;
  min-height: 102px;
  overflow: hidden;
  padding: 11px 13px 9px;
  color: var(--text-primary);
}

.minimal-connection-view__header {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}

.minimal-connection-view__copy {
  min-width: 0;
  flex: 1;
}

.minimal-connection-view__title {
  overflow: hidden;
  margin: 0;
  font-size: 17px;
  font-weight: 680;
  line-height: 1.2;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.minimal-connection-view__detail {
  overflow: hidden;
  margin: 3px 0 0;
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.3;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.minimal-connection-view__action {
  flex: none;
  min-width: 72px;
  min-height: 32px;
  padding: 5px 9px;
  border: 1px solid var(--accent);
  border-radius: 7px;
  background: var(--accent);
  color: var(--accent-on);
  font-size: 14px;
  font-weight: 650;
}

.minimal-connection-view__action:hover:not(:disabled) {
  border-color: var(--accent-strong);
  background: var(--accent-strong);
}

.minimal-connection-view__action:disabled {
  border-color: var(--border-subtle);
  background: var(--surface-subtle);
  color: var(--text-secondary);
}

.minimal-progress-wrap {
  margin-top: 10px;
}

.minimal-progress {
  display: grid;
  grid-template-columns: repeat(8, minmax(0, 1fr));
  gap: 3px;
}

.minimal-progress-segment {
  height: 4px;
  border-radius: 999px;
  background: var(--border-subtle);
}

.minimal-progress-segment--complete {
  background: var(--state-success);
}

.minimal-progress-segment--current {
  background: var(--state-warning);
  animation: minimal-progress-pulse var(--motion-standard) ease-in-out infinite alternate;
}

.minimal-progress-label {
  display: block;
  margin-top: 4px;
  overflow: hidden;
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.25;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.minimal-traffic {
  display: grid;
  gap: 4px;
  min-width: 0;
  margin-top: 8px;
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.35;
  font-variant-numeric: tabular-nums;
}

.minimal-connection-meta {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
  overflow: hidden;
}

.minimal-connection-meta span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.minimal-connection-meta b {
  color: var(--text-tertiary);
  font-size: 11px;
  font-weight: 500;
}

@keyframes minimal-progress-pulse {
  from { opacity: 0.55; }
  to { opacity: 1; }
}

@media (prefers-reduced-motion: reduce) {
  .minimal-progress-segment--current {
    animation: none;
  }
}
</style>
