<script setup lang="ts">
defineProps<{
  visible: boolean;
  label: string;
}>();
</script>

<template>
  <div
    v-if="visible"
    class="service-overlay"
    data-testid="service-operation-overlay"
    role="dialog"
    aria-modal="true"
    aria-live="polite"
  >
    <div class="service-overlay__card">
      <div class="service-overlay__spinner" aria-hidden="true" />
      <p class="service-overlay__label">{{ label }}</p>
    </div>
  </div>
</template>

<style scoped>
.service-overlay {
  position: fixed;
  inset: 0;
  z-index: 60;
  display: flex;
  align-items: center;
  justify-content: center;
  background: rgb(0 0 0 / 0.45);
}

.service-overlay__card {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--space-3);
  padding: var(--space-6) var(--space-8);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  background: var(--surface-panel);
  box-shadow: 0 12px 32px rgb(0 0 0 / 0.28);
}

.service-overlay__label {
  margin: 0;
  color: var(--text-primary);
  font-size: 14px;
  text-align: center;
}

.service-overlay__spinner {
  width: 28px;
  height: 28px;
  border: 3px solid var(--border-subtle);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: service-spin 0.8s linear infinite;
}

@keyframes service-spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
