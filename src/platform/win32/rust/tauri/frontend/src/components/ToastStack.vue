<script setup lang="ts">
import { useToasts } from "../lib/toast";

const { toasts, dismiss } = useToasts();
</script>

<template>
  <div class="toast-stack" data-testid="toast-stack" aria-live="polite">
    <transition-group name="toast">
      <div
        v-for="toast in toasts"
        :key="toast.id"
        class="toast"
        :class="`toast--${toast.kind}`"
        data-testid="toast"
        role="status"
        @click="dismiss(toast.id)"
      >
        {{ toast.message }}
      </div>
    </transition-group>
  </div>
</template>

<style scoped>
.toast-stack {
  position: fixed;
  right: 16px;
  bottom: 16px;
  z-index: 60;
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-width: 320px;
  pointer-events: none;
}

.toast {
  pointer-events: auto;
  padding: 10px 14px;
  border-radius: 10px;
  border: 1px solid rgb(255 255 255 / 0.14);
  color: #fff;
  font-size: 13px;
  line-height: 1.5;
  box-shadow: 0 6px 20px rgb(0 0 0 / 0.28);
  cursor: pointer;
  white-space: pre-wrap;
}

.toast--info {
  background: #3b6ea8;
}
.toast--success {
  background: #2e7d4f;
}
.toast--warning {
  background: #b07a28;
}
.toast--error {
  background: #b3363b;
}

.toast-enter-active,
.toast-leave-active {
  transition: opacity 0.18s ease, transform 0.18s ease;
}
.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateY(6px);
}
</style>
