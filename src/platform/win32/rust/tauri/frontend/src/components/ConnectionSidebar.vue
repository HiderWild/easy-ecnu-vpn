<script setup lang="ts">
import { computed } from "vue";

import type { ProductUiState } from "../product/types";
import TrafficMetricsPanel from "./TrafficMetricsPanel.vue";

const props = defineProps<{
  state: ProductUiState;
}>();

const connected = computed(() => props.state.status === "connected");
const availableMetrics = computed(() =>
  props.state.metrics?.availability === "available" ? props.state.metrics : null,
);
const connectionInfo = computed(() => props.state.connectionInfo);
const displayMetric = (value: string | null | undefined): string => value ?? "—";
const systemProxyEnabled = computed(() =>
  props.state.systemProxy.status === "manual" ||
  props.state.systemProxy.status === "automatic" ||
  props.state.systemProxy.status === "mixed",
);
const proxyTunEnabled = computed(() => props.state.proxyTun.status === "detected");
</script>

<template>
  <aside class="connection-sidebar" aria-label="连接信息">
    <div
      class="connection-sidebar__status-pill"
      :class="{ 'connection-sidebar__status-pill--connected': connected }"
      data-testid="connection-status-pill"
    >
      <span class="connection-sidebar__status-dot" />
      <span class="connection-sidebar__status-text">{{ state.title }}</span>
      <span v-if="state.coreStatus === 'stopped'" class="connection-sidebar__core-status">核心已停止</span>
    </div>

    <section v-if="connected" class="sidebar-section" data-testid="traffic-metrics">
      <dl class="info-list connection-summary-list">
        <div class="info-row">
          <dt>在线时长</dt>
          <dd>{{ displayMetric(state.metrics?.online) }}</dd>
        </div>
        <div class="info-row">
          <dt>连接账户</dt>
          <dd>{{ connectionInfo.account ?? "—" }}</dd>
        </div>
      </dl>

      <dl class="info-list connection-details-list">
        <div class="info-row" data-testid="connection-latency">
          <dt>连接时延</dt>
          <dd>{{ displayMetric(availableMetrics?.latency) }}</dd>
        </div>
        <div class="info-row">
          <dt>校内地址</dt>
          <dd>{{ connectionInfo.campusIp ?? "—" }}</dd>
        </div>
        <div v-if="state.reconnect.enabled" class="info-row">
          <dt>重连次数</dt>
          <dd>{{ state.reconnect.currentAttempt }}</dd>
        </div>
        <div class="info-row info-row--vpn-server" data-testid="connection-vpn-server">
          <dt>VPN 服务器</dt>
          <dd :title='connectionInfo.vpnServer ?? "—"'>{{ connectionInfo.vpnServer ?? "—" }}</dd>
        </div>
      </dl>

      <TrafficMetricsPanel :metrics="availableMetrics" :show-totals="true" />
    </section>

    <div class="connection-sidebar__environment" data-testid="sidebar-environment" aria-label="网络环境">
      <span
        class="connection-sidebar__environment-item"
        data-testid="system-proxy-status"
        :data-enabled="systemProxyEnabled"
      >
        <i class="connection-sidebar__status-dot" :class="{ 'connection-sidebar__status-dot--active': systemProxyEnabled }" aria-hidden="true" />
        <span>系统代理</span>
      </span>
      <span class="connection-sidebar__environment-divider" data-testid="sidebar-environment-divider" aria-hidden="true" />
      <span
        class="connection-sidebar__environment-item"
        data-testid="tun-status"
        :data-enabled="proxyTunEnabled"
      >
        <i class="connection-sidebar__status-dot" :class="{ 'connection-sidebar__status-dot--active': proxyTunEnabled }" aria-hidden="true" />
        <span>TUN</span>
      </span>
    </div>
  </aside>
</template>

<style scoped>
.connection-sidebar {
  display: flex;
  min-width: 0;
  flex-direction: column;
  gap: var(--space-4);
  /* 侧栏本身直接落在 product-rail 的灰色底上，不再套白色卡片。 */
  padding: 0;
  border: 0;
  border-radius: 0;
  background: transparent;
}

.connection-sidebar__status-pill {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: 0;
  font-size: 13px;
  color: var(--text-secondary);
}

.connection-sidebar__status-dot {
  width: 8px;
  height: 8px;
  flex-shrink: 0;
  border-radius: 50%;
  background: var(--text-tertiary);
}

.connection-sidebar__status-pill--connected .connection-sidebar__status-dot,
.connection-sidebar__status-dot--active {
  background: var(--state-success);
}

.connection-sidebar__core-status {
  color: var(--state-warning);
  font-size: 12px;
}

.connection-sidebar__environment {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  margin-top: auto;
  color: var(--text-secondary);
  font-size: 12px;
}

.connection-sidebar__environment-item {
  display: inline-flex;
  min-width: 0;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
}

.connection-sidebar__environment-item .connection-sidebar__status-dot {
  width: 6px;
  height: 6px;
}

.connection-sidebar__environment-divider {
  width: 1px;
  height: 14px;
  flex: none;
  background: var(--border-subtle);
}

.info-list {
  display: grid;
  gap: var(--space-2);
  margin: 0;
}

.info-row {
  display: grid;
  grid-template-columns: minmax(0, 0.95fr) minmax(0, 1.05fr);
  gap: var(--space-2);
  align-items: baseline;
  min-width: 0;
}

.info-row dt {
  color: var(--text-secondary);
  font-size: 13px;
}

.info-row dd {
  min-width: 0;
  margin: 0;
  overflow-wrap: anywhere;
  color: var(--text-primary);
  font-size: 14px;
  font-variant-numeric: tabular-nums;
  text-align: right;
}

/* 服务器地址是连接信息中的长标识：任何 rail 宽度都只占一行，鼠标悬停可查看全量值。 */
.info-row--vpn-server dd {
  overflow: hidden;
  overflow-wrap: normal;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.connection-summary-list,
.connection-details-list {
  gap: var(--space-2);
}

.connection-details-list {
  margin-top: var(--space-3);
}

.connection-summary-list .info-row dd,
.connection-details-list .info-row dd {
  font-weight: 600;
}

@container product-rail (max-width: 220px) {
  .info-row {
    grid-template-columns: 1fr;
    gap: 2px;
  }

  .info-row dd {
    text-align: left;
  }
}
</style>
