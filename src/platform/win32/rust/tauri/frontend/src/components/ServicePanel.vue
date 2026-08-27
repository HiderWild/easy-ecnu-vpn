<script setup lang="ts">
import { computed, inject, onMounted, ref } from "vue";

import { commandErrorMessage } from "../lib/command-error";
import type { ServiceControlAction } from "../lib/ipc";
import { pushToast } from "../lib/toast";
import { PRODUCT_RUNTIME_KEY, type ProductRuntime } from "../product/runtime";
import {
  isServiceRunning,
  serviceStateLabel,
  type ProductService,
} from "../product/types";
import ServiceOperationOverlay from "./ServiceOperationOverlay.vue";

const props = withDefaults(
  defineProps<{
    service: ProductService;
    /** 连接页 checkbox 状态（M3「未装即装」偏好）；由连接页持有并传给 connect。 */
    autoInstall: boolean;
    /** 连接页主动作进行中（连接/断开），服务按钮同步禁用避免冲突。 */
    busy: boolean;
    /**
     * 设置页复用本面板时关闭连接页专属呈现（auto-install checkbox / M3 决策提示 /
     * 未知状态回退说明），只保留服务状态与装卸/修复操作按钮。
     */
    showConnectOptions?: boolean;
  }>(),
  { showConnectOptions: true },
);

const emit = defineEmits<{
  "update:autoInstall": [value: boolean];
}>();

const runtime = inject(PRODUCT_RUNTIME_KEY, null) as ProductRuntime | null;

const controlBusy = ref(false);
/** 全屏模态遮罩：install/uninstall/start/repair 在途时 visible。 */
const overlayVisible = ref(false);
const overlayLabel = ref("");

const CONTROL_ACTION_LABEL: Record<ServiceControlAction, string> = {
  query: "正在查询服务状态…",
  install: "正在安装服务…",
  uninstall: "正在卸载服务…",
  start: "正在启动服务…",
};

/** 后端回复文案 → 前端友好文案映射（后端友好文案由另一批任务做，前端先行）。 */
function friendlyServiceMessage(action: ServiceControlAction | "repair", replyMessage: string): string {
  // 后端通用完成标记 → 按 action 映射为具体文案
  if (replyMessage === "batch completed" || replyMessage === "ok" || replyMessage === "操作完成。") {
    switch (action) {
      case "install":
        return "服务安装完成。";
      case "uninstall":
        return "服务卸载完成。";
      case "start":
        return "服务已启动。";
      case "repair":
        return "修复完成：服务已重新安装并由 Core 启动。";
      case "query":
        return replyMessage;
    }
  }
  // 非标准回复原样透传
  return replyMessage || "操作完成。";
}

const anyBusy = computed(() => props.busy || controlBusy.value);

const serviceLabel = computed(() => {
  const status = props.service.status;
  switch (status.kind) {
    case "unknown":
      return "状态未知";
    case "not_installed":
      return "未安装";
    case "installed":
      return serviceStateLabel(status.scmState);
  }
});

/** MED [3]：checkbox 仅在明确「未安装」时可用；未知状态禁用并回退 oneshot。 */
const autoInstallDisabled = computed(() => props.service.status.kind !== "not_installed");

/** M3 决策表四态在 UI 的呈现：服务状态 + checkbox → 将使用的连接方式。 */
const decisionHint = computed(() => {
  const status = props.service.status;
  if (status.kind === "unknown") {
    return "服务状态未知，将按一次性连接处理（查询失败不自动安装）。";
  }
  if (status.kind === "not_installed") {
    return props.autoInstall
      ? "未安装 + 已勾选：将先安装服务再连接。"
      : "未安装 + 未勾选：将使用一次性连接。";
  }
  return isServiceRunning(status.scmState)
    ? "服务运行中：将使用服务模式连接。"
    : "服务已安装未运行：连接时 Core 会自动启动服务。";
});

function toggleAutoInstall(event: Event): void {
  emit("update:autoInstall", (event.target as HTMLInputElement).checked);
}

function messageFor(error: unknown): string {
  return commandErrorMessage(error, "服务操作未完成，请稍后重试。");
}

// 服务感知修复：挂载时主动 query 一次（host GetSnapshot 的缓存可能滞后于 SCM 真实
// 状态，例如服务在 connect 流程内部被 bootstrap 拉起后）。query 是非提权读 + 深度
// 健康自述；失败静默（保持现有快照状态，不打扰用户）。
onMounted(() => {
  if (runtime === null) return;
  void runtime.serviceControl("query").then((reply) => {
    if (reply.service_status !== undefined && reply.service_status !== null) return;
    // 无状态回包时拉一次快照兜底（保持既有呈现）。
    void runtime.triggerLatencyRefresh().catch(() => undefined);
  }).catch(() => undefined);
});

async function runControl(action: ServiceControlAction): Promise<void> {
  if (runtime === null || anyBusy.value) return;
  controlBusy.value = true;
  // query 不遮罩，保持非阻塞
  if (action !== "query") {
    overlayVisible.value = true;
    overlayLabel.value = CONTROL_ACTION_LABEL[action];
  }
  try {
    const reply = await runtime.serviceControl(action);
    if (!reply.ok) {
      pushToast(reply.message || "服务操作失败。", "error");
    } else {
      pushToast(friendlyServiceMessage(action, reply.message || "操作完成。"), "success");
    }
  } catch (error) {
    pushToast(messageFor(error), "error");
  } finally {
    overlayVisible.value = false;
    controlBusy.value = false;
  }
}

/**
 * 修复安装（MED [2]）：直接 install（REPAIR 内部已处理运行中服务），不再先停服务——
 * 服务停止视为错误态，修复对策是启动；install 成功后的 start + readiness 由 Core 统一 bootstrap。
 */
async function runRepair(): Promise<void> {
  if (runtime === null || anyBusy.value) return;
  controlBusy.value = true;
  overlayVisible.value = true;
  overlayLabel.value = "正在修复服务…";
  try {
    const installReply = await runtime.serviceControl("install");
    if (!installReply.ok) {
      throw new Error(installReply.message || "安装服务失败。");
    }
    pushToast(friendlyServiceMessage("repair", "修复完成：服务已重新安装并由 Core 启动。"), "success");
  } catch (error) {
    pushToast(messageFor(error), "error");
  } finally {
    overlayVisible.value = false;
    controlBusy.value = false;
  }
}
</script>

<template>
  <section class="service-panel" data-testid="service-panel" aria-labelledby="service-panel-title">
    <header class="service-panel__header">
      <h2 id="service-panel-title">服务</h2>
    </header>

    <dl class="service-list">
      <div class="service-row">
        <dt>服务状态</dt>
        <dd data-testid="service-status">{{ serviceLabel }}</dd>
      </div>
    </dl>

    <div
      v-if="showConnectOptions && service.status.kind === 'not_installed'"
      class="service-option"
      data-testid="service-auto-install-option"
    >
      <label class="service-checkbox">
        <input
          type="checkbox"
          data-testid="service-auto-install"
          :checked="autoInstall"
          :disabled="anyBusy || autoInstallDisabled"
          aria-label="先安装服务再连接"
          @change="toggleAutoInstall"
        >
        <span>先安装服务再连接</span>
      </label>
      <p class="service-hint">未安装服务时：勾选后先安装并启动服务再连接；不勾选则使用一次性连接。</p>
    </div>
    <p
      v-else-if="showConnectOptions && service.status.kind === 'unknown'"
      class="service-hint service-hint--warn"
      data-testid="service-unknown-note"
    >
      服务状态未知，将按一次性连接处理（查询失败不自动安装）。
    </p>

    <p v-if="showConnectOptions" class="service-hint" data-testid="service-decision-hint">{{ decisionHint }}</p>

    <div class="service-actions" data-testid="service-actions">
      <button
        v-if="service.status.kind === 'not_installed'"
        type="button"
        data-testid="service-install"
        :disabled="anyBusy"
        @click="runControl('install')"
      >
        安装
      </button>
      <button
        v-if="service.status.kind === 'installed' && !isServiceRunning(service.status.scmState)"
        type="button"
        data-testid="service-repair"
        :disabled="anyBusy"
        @click="runRepair"
      >
        修复
      </button>
      <button
        v-if="service.status.kind === 'installed'"
        type="button"
        data-testid="service-uninstall"
        :disabled="anyBusy"
        @click="runControl('uninstall')"
      >
        卸载
      </button>
    </div>

    <ServiceOperationOverlay :visible="overlayVisible" :label="overlayLabel" />
  </section>
</template>

<style scoped>
.service-panel {
  min-width: 0;
  padding: var(--space-5);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  background: var(--surface-panel);
}

.service-panel__header {
  margin-bottom: var(--space-3);
}

.service-panel__header h2 {
  margin-bottom: var(--space-1);
  font-size: 16px;
}

.service-panel__header p,
.service-hint {
  margin-bottom: 0;
  color: var(--text-secondary);
  font-size: 13px;
}

.service-list {
  display: grid;
  gap: var(--space-2);
  margin: 0 0 var(--space-3);
}

.service-row {
  display: grid;
  grid-template-columns: minmax(0, 0.95fr) minmax(0, 1.05fr);
  gap: var(--space-2);
  align-items: baseline;
  min-width: 0;
}

.service-row dt {
  color: var(--text-secondary);
  font-size: 13px;
}

.service-row dd {
  min-width: 0;
  margin: 0;
  overflow-wrap: anywhere;
  color: var(--text-primary);
  font-size: 14px;
  font-variant-numeric: tabular-nums;
  text-align: right;
}

.service-option {
  margin-bottom: var(--space-3);
}

.service-checkbox {
  display: inline-flex;
  align-items: center;
  gap: var(--space-2);
  min-height: 32px;
  color: var(--text-primary);
}

.service-checkbox input {
  width: 18px;
  height: 18px;
  accent-color: var(--accent);
}

.service-checkbox:has(input:disabled) {
  color: var(--text-secondary);
}

.service-hint {
  margin-top: var(--space-1);
}

.service-hint--warn {
  color: var(--state-danger);
}

.service-actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  margin-top: var(--space-4);
  padding-top: var(--space-4);
  border-top: 1px solid var(--border-subtle);
}

.service-actions button {
  min-height: 34px;
  padding: var(--space-1) var(--space-3);
  border: 1px solid var(--accent);
  border-radius: var(--radius-md);
  background: var(--accent);
  color: var(--accent-on);
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
}

.service-actions button:hover:not(:disabled) {
  border-color: var(--accent-strong);
  background: var(--accent-strong);
}

.service-actions button:disabled {
  border-color: var(--border-subtle);
  background: var(--surface-subtle);
  color: var(--text-secondary);
  cursor: default;
}
</style>
