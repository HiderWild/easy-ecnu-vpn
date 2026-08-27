<script setup lang="ts">
defineProps<{
  label: string;
  description: string;
}>();
</script>

<template>
  <div class="settings-row">
    <div class="settings-row__copy">
      <div class="settings-row__label">{{ label }}</div>
      <div class="settings-row__description">{{ description }}</div>
    </div>
    <div class="settings-row__control">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.settings-row {
  display: grid;
  grid-template-columns: minmax(0, 0.9fr) minmax(0, 1.1fr);
  gap: var(--space-4);
  align-items: center;
  min-width: 0;
  min-height: 48px;
  padding: 7px 0;
}

.settings-row__copy,
.settings-row__control {
  min-width: 0;
}

.settings-row__label {
  overflow-wrap: anywhere;
  color: var(--text-primary);
  font-weight: 650;
  line-height: 1.25;
}

.settings-row__description {
  margin-top: 2px;
  overflow-wrap: anywhere;
  color: var(--text-secondary);
  font-size: 12px;
  line-height: 1.3;
}

.settings-row__control {
  display: flex;
  min-height: 34px;
  align-items: center;
  justify-content: flex-end;
}

@media (max-width: 700px) {
  .settings-row {
    grid-template-columns: minmax(0, 1fr) minmax(136px, 0.8fr);
    gap: var(--space-3);
  }
}

@media (max-width: 480px) {
  .settings-row {
    grid-template-columns: 1fr;
    gap: var(--space-2);
    padding-block: var(--space-3);
  }

  .settings-row__control {
    justify-content: stretch;
  }
}

.motion-reduced .settings-row,
[data-motion="reduced"] .settings-row {
  transition: none;
}
</style>
