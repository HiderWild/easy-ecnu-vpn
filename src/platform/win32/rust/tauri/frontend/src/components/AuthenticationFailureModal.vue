<script setup lang="ts">
/**
 * 认证失败（`ERROR_CODE_UNAUTHORIZED`）详细指引模态。
 *
 * 产品 UI 呈现规则：大段信息走模态弹窗（不页内插入组件）。关闭后连接按钮恢复
 * 「重试」可点（connection-action 失败态不禁用），下次连接失败会再次弹起。
 */
defineProps<{
  visible: boolean;
}>();

const emit = defineEmits<{
  close: [];
}>();
</script>

<template>
  <div
    v-if="visible"
    class="modal-overlay"
    data-testid="auth-failure-modal"
    role="dialog"
    aria-modal="true"
    aria-labelledby="auth-failure-title"
  >
    <div class="modal-card">
      <h2 id="auth-failure-title">VPN 网关没有通过本次登录</h2>
      <p class="modal-intro">
        这不是网络通断提示，而是服务器拒绝了认证信息。请按下面步骤处理：
      </p>
      <ol class="modal-steps">
        <li>打开左侧“设置”，进入“连接与网络”。</li>
        <li>检查并保存服务器、用户名和密码；密码修改后必须点击对应的“保存”。</li>
        <li>返回连接页后再次点击“连接”。服务模式会读取同一份已保存配置。</li>
      </ol>
      <p class="modal-hint">
        如果无服务时能连接、安装服务后仍失败，请打开“设置”的“服务”面板点击“修复”，再回到连接页重试；修复会重新登记当前用户的配置目录。
      </p>
      <div class="modal-actions">
        <button type="button" data-testid="auth-failure-close" @click="emit('close')">
          知道了
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
  margin: 0 0 var(--space-2);
  color: var(--state-danger);
  font-size: 18px;
}

.modal-intro,
.modal-hint {
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.6;
}

.modal-steps {
  margin: var(--space-2) 0 var(--space-3);
  padding-left: 1.35rem;
  display: grid;
  gap: var(--space-1);
  color: var(--text-secondary);
  font-size: 13px;
  line-height: 1.6;
}

.modal-hint {
  color: var(--text-tertiary);
}

.modal-actions {
  display: flex;
  justify-content: flex-end;
  margin-top: var(--space-5);
}

.modal-actions button {
  min-height: 34px;
  padding: var(--space-1) var(--space-4);
  border: 1px solid var(--accent);
  border-radius: var(--radius-md);
  background: var(--accent);
  color: var(--accent-on);
  font-size: 13px;
  cursor: pointer;
}

.modal-actions button:hover {
  border-color: var(--accent-strong);
  background: var(--accent-strong);
}
</style>
