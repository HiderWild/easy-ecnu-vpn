<script setup lang="ts">
defineProps<{
  items: Array<{
    label: string
    value: string
    tone?: 'accent' | 'warning' | 'muted'
  }>
  connectionStateLabel: string
  connectionStateTone: 'accent' | 'warning' | 'muted'
}>()
</script>

<template>
  <aside class="dashboard-status-rail">
    <div class="dashboard-status-rail__summary">
      <span
        :class="[
          'dashboard-status-rail__online-dot',
          connectionStateTone === 'accent' ? 'is-accent' : connectionStateTone === 'warning' ? 'is-warning' : 'is-muted',
        ]"
        aria-hidden="true"
      />
      <div class="min-w-0">
        <p class="text-xs text-muted">当前状态</p>
        <p class="truncate text-sm font-semibold text-foreground">{{ connectionStateLabel }}</p>
      </div>
    </div>

    <dl class="dashboard-status-rail__list">
      <div
        v-for="item in items"
        :key="item.label"
        class="dashboard-status-rail__item"
      >
        <dt>{{ item.label }}</dt>
        <dd
          :class="[
            item.tone === 'accent' ? 'text-accent' : item.tone === 'warning' ? 'text-warning' : 'text-foreground',
          ]"
          :title="item.value"
        >
          {{ item.value }}
        </dd>
      </div>
    </dl>
  </aside>
</template>

<style scoped>
.dashboard-status-rail {
  display: flex;
  min-height: 0;
  flex-direction: column;
  gap: 0.7rem;
  overflow: hidden;
  border: 1px solid var(--color-border);
  border-radius: 8px;
  background: var(--color-surface);
  padding: 0.8rem;
}

.dashboard-status-rail__summary {
  display: flex;
  min-height: 3.2rem;
  align-items: center;
  gap: 0.65rem;
  border-bottom: 1px solid var(--color-border);
  padding-bottom: 0.7rem;
}

.dashboard-status-rail__online-dot {
  width: 0.72rem;
  height: 0.72rem;
  flex: 0 0 auto;
  border-radius: 9999px;
  background: var(--color-muted);
}

.dashboard-status-rail__online-dot.is-accent {
  background: var(--color-accent);
  box-shadow: 0 0 0 0.35rem rgb(var(--color-accent-rgb) / 0.13);
  animation: dashboard-status-pulse 2.4s ease-out infinite;
}

.dashboard-status-rail__online-dot.is-warning {
  background: var(--color-warning);
  box-shadow: 0 0 0 0.35rem rgb(var(--color-warning-rgb) / 0.13);
}

.dashboard-status-rail__list {
  display: grid;
  min-height: 0;
  grid-template-columns: 1fr;
  gap: 0.55rem;
  overflow: hidden;
}

.dashboard-status-rail__item {
  min-width: 0;
}

.dashboard-status-rail__item dt {
  color: var(--color-muted);
  font-size: 0.68rem;
  line-height: 1rem;
}

.dashboard-status-rail__item dd {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 0.78rem;
  font-weight: 600;
  line-height: 1.12rem;
}

@keyframes dashboard-status-pulse {
  0%,
  100% {
    box-shadow: 0 0 0 0.25rem rgb(var(--color-accent-rgb) / 0.1);
  }

  50% {
    box-shadow: 0 0 0 0.55rem rgb(var(--color-accent-rgb) / 0.18);
  }
}

@media (prefers-reduced-motion: reduce) {
  .dashboard-status-rail__online-dot {
    animation: none !important;
  }
}
</style>
