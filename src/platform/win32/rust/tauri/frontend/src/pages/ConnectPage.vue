<script setup lang="ts">
import { computed, inject, ref } from "vue";

import ProductActionBar from "../components/ProductActionBar.vue";
import ProductConnectionHero from "../components/ProductConnectionHero.vue";
import ProductConnectionVisualStage from "../components/ProductConnectionVisualStage.vue";
import ServiceConnectFailureModal from "../components/ServiceConnectFailureModal.vue";
import AuthenticationFailureModal from "../components/AuthenticationFailureModal.vue";
import { commandErrorMessage } from "../lib/command-error";
import { pushToast } from "../lib/toast";
import { PRODUCT_RUNTIME_KEY } from "../product/runtime";
import { connectionActionFor } from "../product/connection-action";
import { authModalDismissed } from "../product/ui-transient";

const runtime = inject(PRODUCT_RUNTIME_KEY, null);
const actionBusy = ref(false);
const autoInstallService = ref(false);
/** R5：服务连接失败恢复 modal 的错误文案（服务模式错误走 modal，非服务错误走 toast）。 */
const operationError = ref<string | null>(null);
/** R5：服务连接失败恢复 modal（service_not_running / service_connect_failed）。 */
const serviceModalVisible = ref(false);
const serviceModalError = ref("");

/** R5：connect 拒绝是否为「服务模式连接失败」（需要弹恢复 modal）——识别后端
 *  `AppError::ServiceNotRunning` / `AppError::ServiceConnectFailed` 变体（serde
 *  `{kind,message}`），或消息含稳定前缀（`service_not_running|` / `service_connect_failed|`）。
 *  其余拒绝保持既有错误行行为。 */
function isServiceRecoveryError(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const kind = (error as { kind?: unknown }).kind;
  if (kind === "service_not_running" || kind === "service_connect_failed") return true;
  const message = (error as { message?: unknown }).message;
  if (typeof message === "string") {
    return message.includes("service_not_running|") || message.includes("service_connect_failed|");
  }
  return false;
}

const productState = computed(() => runtime?.state.value ?? null);
const authenticationFailure = computed(
  () => productState.value?.errorCode === "ERROR_CODE_UNAUTHORIZED",
);
const stateDescription = computed(() => {
  const state = productState.value;
  if (state === null) return "";
  if (state.description?.trim()) return state.description.trim();

  const descriptions = {
    idle: "准备好后即可开始连接。",
    connecting: "正在完成连接准备。",
    awaiting: "请完成账户确认。",
    connected: "",
    stopping: "正在安全撤销连接配置。",
    reconciling: "正在核对连接状态。",
    failed: "连接未完成，请查看需要处理的原因。",
  } as const;

  return descriptions[state.status];
});

function messageFor(error: unknown): string {
  return commandErrorMessage(error, "操作未完成，请稍后重试。");
}

async function runAction(): Promise<void> {
  const state = productState.value;
  if (runtime === null || state === null || actionBusy.value) return;
  const action = connectionActionFor(state);
  if (!action.enabled) return;

  // 乐观 UI：点击瞬间禁用按钮 + 占位反馈，不等后端第一个返回。新一轮动作重置
  // 认证模态（下次失败可再次弹起）。
  actionBusy.value = true;
  operationError.value = null;
  authModalDismissed.value = false;
  try {
    if (action.kind === "connect") {
      if (autoInstallService.value && state.service.status.kind === "not_installed") {
        const installReply = await runtime.serviceControl("install");
        if (!installReply.ok) {
          throw new Error(installReply.message || "服务安装失败，无法继续连接。");
        }
      }
      await runtime.connect();
    } else if (action.kind === "stop") {
      await runtime.stop();
    }
  } catch (error) {
    const message = messageFor(error);
    operationError.value = message;
    // R5：服务模式连接失败 → 弹恢复 modal（清理/重装后连接/取消）；其余小错误
    // → 右下角 toast（产品 UI 规则：大段信息走模态、小状态走 toast）。触发后
    // actionBusy 已在 finally 复位，modal 自带 busy。
    if (isServiceRecoveryError(error)) {
      serviceModalError.value = message;
      serviceModalVisible.value = true;
    } else {
      pushToast(message, "error");
    }
  } finally {
    actionBusy.value = false;
  }
}

/** 关闭认证失败模态（一次性提醒；关闭后连接按钮保留「重试」可用）。 */
function closeAuthModal(): void {
  authModalDismissed.value = true;
}

/** R5：取消 → 仅关闭 modal，错误文案保留在页面上。 */
function closeServiceModal(): void {
  serviceModalVisible.value = false;
}

/** R5：恢复序列成功派发连接 → 关闭 modal 并清除页面错误文案（连接状态由状态事件接管）。 */
function recoveredServiceModal(): void {
  serviceModalVisible.value = false;
  operationError.value = null;
}
</script>

<template>
  <section class="connect-page" aria-labelledby="connection-state-title">
    <p v-if="productState === null" class="runtime-unavailable" data-testid="runtime-unavailable">
      暂时无法取得连接状态。
    </p>

    <template v-else>
      <ProductConnectionHero
        :state="productState"
        :description="stateDescription"
        :busy="actionBusy"
        @action="runAction"
      />

      <label
        v-if="
          productState.service.status.kind === 'not_installed' &&
          productState.status === 'idle'
        "
        class="connect-service-install-option"
        data-testid="service-auto-install-option"
      >
        <input
          type="checkbox"
          data-testid="service-auto-install"
          :checked="autoInstallService"
          :disabled="actionBusy"
          aria-label="安装服务后连接"
          @change="autoInstallService = ($event.target as HTMLInputElement).checked"
        >
        <span>安装服务后连接</span>
      </label>

      <div class="connection-layout">
        <ProductConnectionVisualStage :state="productState" />
      </div>

      <ProductActionBar :state="productState" class="connect-page__action-bar" />

      <ServiceConnectFailureModal
        :visible="serviceModalVisible"
        :error-message="serviceModalError"
        @close="closeServiceModal"
        @recovered="recoveredServiceModal"
      />

      <AuthenticationFailureModal
        :visible="authenticationFailure && !authModalDismissed"
        @close="closeAuthModal"
      />
    </template>
  </section>
</template>

<style scoped>
.connect-page {
  display: flex;
  height: 100%;
  min-height: 0;
  flex-direction: column;
  min-width: 0;
  --connect-section-gap: var(--space-5);
  gap: var(--connect-section-gap);
  padding-bottom: var(--connect-section-gap);
  color: var(--text-primary);
}

.connect-service-install-option {
  display: inline-flex;
  width: fit-content;
  align-items: center;
  gap: var(--space-2);
  margin-top: var(--space-3);
  color: var(--text-secondary);
  font-size: 13px;
}

.connect-service-install-option input {
  width: 17px;
  height: 17px;
  accent-color: var(--accent);
}

.runtime-unavailable,
.operation-pending {
  margin: 0;
  padding: var(--space-4);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-md);
  background: var(--surface-panel);
  color: var(--text-secondary);
  font-size: 14px;
}

.operation-pending {
  margin-bottom: var(--space-4);
}

.connection-layout {
  display: grid;
  flex: 1 1 0;
  margin-top: 0;
  min-height: 0;
  min-width: 0;
  overflow-y: auto;
  overscroll-behavior: contain;
}

.connect-page__action-bar {
  margin-top: 0;
  margin-bottom: 0;
  flex: none;
}

</style>
