<script setup lang="ts">
import { inject, ref } from "vue";

import { commandErrorMessage } from "../lib/command-error";
import {
  initialSteps,
  markCurrent,
  markDone,
  markFailed,
  stepMarker,
  type RecoveryAction,
  type RecoveryStep,
} from "../product/recovery-steps";
import { PRODUCT_RUNTIME_KEY, type ProductRuntime } from "../product/runtime";

/**
 * R5 服务连接失败恢复 modal。
 *
 * 服务模式连接失败（`service_not_running` / `service_connect_failed`）时由连接页挂起：
 * 三种恢复方式；服务 bootstrap 由 Core 统一负责：
 *   * 清理服务后连接：serviceControl("uninstall") → connect()（路由回 oneshot）；
 *   * 重装服务后连接：serviceControl("install")（Core 自动 start + readiness）→ connect()
 *     （路由回 service）；
 *   * 取消：仅关闭 modal，错误文案保留在页面上。
 * 任一步失败 → 错误显示在 modal 内（不关闭、不丢失恢复入口）。
 */
defineProps<{
  visible: boolean;
  /** 触发 modal 的 connect 失败文案（保留在页面上；取消时不清除）。 */
  errorMessage: string;
}>();

const emit = defineEmits<{
  /** 取消：关闭 modal，页面错误文案保留。 */
  close: [];
  /** 恢复序列成功派发连接：关闭 modal 并清除页面错误文案。 */
  recovered: [];
}>();

const runtime = inject(PRODUCT_RUNTIME_KEY, null) as ProductRuntime | null;

const busyAction = ref<"clean" | "reinstall" | null>(null);
const actionError = ref<string | null>(null);
/** 当前恢复序列的步骤列表（pending/current/done/failed；分步透明）。 */
const steps = ref<RecoveryStep[]>([]);

/** 执行一步：置 current → await → 校验（serviceControl 返回 {ok,message}）→ done；失败置 failed 并抛出。 */
async function runStep(id: string, op: () => Promise<unknown>): Promise<void> {
  steps.value = markCurrent(steps.value, id);
  try {
    const result = await op();
    if (result && typeof result === "object" && "ok" in result) {
      const reply = result as { ok: boolean; message?: string };
      if (!reply.ok) {
        steps.value = markFailed(steps.value, id);
        throw new Error(reply.message || "操作失败。");
      }
    }
    steps.value = markDone(steps.value, id);
  } catch (error) {
    steps.value = markFailed(steps.value, id);
    throw error;
  }
}

async function runSequence(action: RecoveryAction): Promise<void> {
  if (runtime === null || busyAction.value !== null) return;
  busyAction.value = action;
  actionError.value = null;
  steps.value = initialSteps(action);
  try {
    if (action === "clean") {
      // 清理后连接 = 卸载服务 → 一次性连接（uninstall 是独立请求，不并入 connect）。
      await runStep("uninstall", () => runtime.serviceControl("uninstall"));
    } else {
      // 重装后连接 = 安装服务（Core 自动停止运行中服务/安装/启动就绪）→ 服务连接。
      // 不拆显式 stop：架构约定服务常驻、不保留停止逻辑；install 内部 REPAIR 已处理
      // 运行中服务，拆 stop 既违背该约定又徒增一次 UAC。
      await runStep("install", () => runtime.serviceControl("install"));
    }
    // 两个路径都以 connect 收尾；host 按当前服务状态自动路由（oneshot / service）。
    await runStep("connect", () => runtime.connect());
    emit("recovered");
  } catch (error) {
    actionError.value = commandErrorMessage(error, "恢复操作失败，请稍后重试。");
  } finally {
    busyAction.value = null;
  }
}

function cancel(): void {
  if (busyAction.value !== null) return;
  emit("close");
}
</script>

<template>
  <div
    v-if="visible"
    class="modal-overlay"
    data-testid="service-failure-modal"
    role="dialog"
    aria-modal="true"
    aria-labelledby="service-failure-modal-title"
  >
    <div class="modal-card">
      <h2 id="service-failure-modal-title">服务连接失败</h2>
      <p class="modal-error" data-testid="service-failure-error">{{ errorMessage }}</p>
      <p class="modal-hint">服务模式连接未成功。请选择恢复方式：</p>

      <div
        v-if="actionError"
        class="modal-action-error"
        role="alert"
        data-testid="service-failure-action-error"
      >
        {{ actionError }}
      </div>
      <div
        v-if="busyAction"
        class="recovery-steps"
        role="status"
        data-testid="recovery-steps"
      >
        <div
          v-for="step in steps"
          :key="step.id"
          class="recovery-step"
          :class="`recovery-step--${step.status}`"
          :data-testid="`recovery-step-${step.id}`"
        >
          <span class="recovery-step__marker" aria-hidden="true">{{ stepMarker(step.status) }}</span>
          <span class="recovery-step__label">{{ step.label }}</span>
        </div>
      </div>

      <div class="modal-actions">
        <button
          type="button"
          data-testid="service-failure-clean"
          :disabled="busyAction !== null"
          @click="runSequence('clean')"
        >
          清理服务后连接
        </button>
        <button
          type="button"
          data-testid="service-failure-reinstall"
          :disabled="busyAction !== null"
          @click="runSequence('reinstall')"
        >
          重装服务后连接
        </button>
        <button
          type="button"
          data-testid="service-failure-cancel"
          :disabled="busyAction !== null"
          @click="cancel"
        >
          取消
        </button>
      </div>
    </div>
  </div>
</template>

<style scoped>
.modal-overlay {
  position: fixed;
  inset: 0;
  z-index: 50;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--space-5);
  background: rgb(0 0 0 / 0.45);
}

.modal-card {
  width: min(100%, 440px);
  padding: var(--space-6);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  background: var(--surface-panel);
  box-shadow: 0 12px 32px rgb(0 0 0 / 0.28);
  color: var(--text-primary);
}

.modal-card h2 {
  margin-bottom: var(--space-2);
  font-size: 18px;
}

.modal-error {
  margin-bottom: var(--space-2);
  padding: var(--space-3);
  border: 1px solid var(--state-danger);
  border-radius: var(--radius-md);
  color: var(--state-danger);
  font-size: 13px;
}

.modal-hint {
  margin-bottom: var(--space-4);
  color: var(--text-secondary);
  font-size: 13px;
}

.modal-action-error {
  margin-bottom: var(--space-3);
  padding: var(--space-2) var(--space-3);
  border: 1px solid var(--state-danger);
  border-radius: var(--radius-md);
  color: var(--state-danger);
  font-size: 13px;
}

.modal-pending {
  margin-bottom: var(--space-3);
  color: var(--text-secondary);
  font-size: 13px;
}

.recovery-steps {
  display: grid;
  gap: var(--space-2);
  margin-bottom: var(--space-3);
}

.recovery-step {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  min-height: 30px;
  padding: 0 var(--space-2);
  border-radius: var(--radius-md);
  color: var(--text-secondary);
  font-size: 13px;
}

.recovery-step__marker {
  flex: none;
  width: 18px;
  text-align: center;
  font-weight: 700;
}

.recovery-step--current {
  background: color-mix(in srgb, var(--accent) 10%, var(--surface-panel));
  color: var(--text-primary);
  font-weight: 600;
}

.recovery-step--current .recovery-step__marker {
  color: var(--accent);
  animation: recovery-step-pulse 1s ease-in-out infinite;
}

.recovery-step--done {
  color: var(--text-primary);
}

.recovery-step--done .recovery-step__marker {
  color: var(--state-success);
}

.recovery-step--failed {
  color: var(--state-danger);
}

.recovery-step--failed .recovery-step__marker {
  color: var(--state-danger);
}

@keyframes recovery-step-pulse {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.4;
  }
}

.modal-actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}

.modal-actions button {
  min-height: 34px;
  padding: var(--space-1) var(--space-3);
  font-size: 13px;
}

.modal-actions button:disabled {
  border-color: var(--border-subtle);
  background: var(--surface-subtle);
  color: var(--text-secondary);
}
</style>
