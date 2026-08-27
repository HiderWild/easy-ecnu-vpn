<script setup lang="ts">
import { computed } from "vue";
import { serviceStateLabel, type ProductUiState } from "../product/types";

const props = defineProps<{ state: ProductUiState }>();

const serviceStatus = computed(() => {
  const status = props.state.service.status;
  if (status.kind === "unknown") return "状态未知";
  if (status.kind === "not_installed") return "未安装";
  return serviceStateLabel(status.scmState);
});

const serviceMode = computed(() => {
  const labels = { auto: "自动", service: "服务", oneshot: "一次性", unknown: "未知" } as const;
  return labels[props.state.service.mode];
});

const routePolicy = computed(() => props.state.proxyTun.routePolicy ?? "未报告");
const networkResources = computed(() => props.state.networkResources.available ? "已接入" : "未实现");

/** S4：自动重连次数只有开关开启时显示；关闭时整个项目不存在。 */
const reconnectStatus = computed(() => {
  const r = props.state.reconnect;
  if (r.active) {
    return {
      visible: true,
      label: `重连中 · 第 ${r.currentAttempt} 次`,
    };
  }
  if (r.enabled) {
    return { visible: true, label: `已重连 ${r.currentAttempt} 次` };
  }
  return { visible: false, label: "" };
});
</script>

<template>
  <section class="product-action-bar" data-testid="product-action-bar" aria-label="连接环境摘要">
    <div class="product-action-bar__item">
      <span>服务</span>
      <strong>{{ serviceStatus }}</strong>
      <small>{{ serviceMode }}</small>
    </div>
    <div v-if="reconnectStatus.visible" class="product-action-bar__item" data-testid="reconnect-status">
      <span>自动重连</span>
      <strong>{{ reconnectStatus.label }}</strong>
    </div>
    <div class="product-action-bar__item product-action-bar__item--wide">
      <span>路由策略</span>
      <strong :title="routePolicy">{{ routePolicy }}</strong>
      <small>网络资源 {{ networkResources }}</small>
    </div>
  </section>
</template>

<style scoped>
.product-action-bar {
  display: grid;
  min-width: 0;
  grid-template-columns: minmax(130px, 0.7fr) minmax(150px, 0.85fr) minmax(190px, 1.2fr);
  gap: var(--space-3);
  padding: var(--space-3) var(--space-4);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--surface-panel);
}

.product-action-bar__item {
  display: grid;
  min-width: 0;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: baseline;
  column-gap: var(--space-2);
}

.product-action-bar__item > span {
  color: var(--text-secondary);
  font-size: 12px;
}

.product-action-bar__item > strong {
  min-width: 0;
  overflow: hidden;
  color: var(--text-primary);
  font-size: 13px;
  font-weight: 650;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.product-action-bar__item > small {
  grid-column: 2;
  min-width: 0;
  overflow: hidden;
  color: var(--text-tertiary);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}

@media (max-width: 760px) {
  .product-action-bar {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .product-action-bar__item--wide {
    grid-column: 1 / -1;
  }
}
</style>
