<script setup lang="ts">
import { Wrench } from 'lucide-vue-next'
import ToggleSwitch from '../ToggleSwitch.vue'

defineProps<{
  showServiceRepairAction: boolean
  serviceRepairDisabled: boolean
  serviceRepairLabel: string
  showInstallServiceChoice: boolean
  installServiceChoiceDisabled: boolean
  installServiceBeforeConnect: boolean
}>()

const emit = defineEmits<{
  repair: []
  switchToMinimal: []
  'update:installServiceBeforeConnect': [value: boolean]
}>()

function handleInstallServiceChange(event: Event) {
  emit('update:installServiceBeforeConnect', (event.target as HTMLInputElement).checked)
}
</script>

<template>
  <section class="dashboard-action-bar">
    <div class="flex min-w-0 items-center gap-2">
      <label
        v-if="showInstallServiceChoice"
        class="dashboard-action-bar__choice"
      >
        <input
          :checked="installServiceBeforeConnect"
          type="checkbox"
          :disabled="installServiceChoiceDisabled"
          class="h-3.5 w-3.5 accent-accent"
          @change="handleInstallServiceChange"
        />
        <span class="truncate">连接前安装服务（推荐）</span>
      </label>

      <button
        v-if="showServiceRepairAction"
        type="button"
        :disabled="serviceRepairDisabled"
        class="dashboard-action-bar__button"
        @click="emit('repair')"
      >
        <Wrench class="h-3.5 w-3.5" />
        <span>{{ serviceRepairLabel }}</span>
      </button>
    </div>

    <label class="dashboard-action-bar__mode">
      <span>高级</span>
      <ToggleSwitch
        :model-value="true"
        @update:model-value="emit('switchToMinimal')"
      />
    </label>
  </section>
</template>

<style scoped>
.dashboard-action-bar {
  display: flex;
  min-height: 3.25rem;
  align-items: center;
  justify-content: space-between;
  gap: 0.75rem;
  border: 1px solid var(--color-border);
  border-radius: 8px;
  background: var(--color-surface);
  padding: 0.6rem 0.75rem;
}

.dashboard-action-bar__choice,
.dashboard-action-bar__mode,
.dashboard-action-bar__button {
  display: inline-flex;
  min-height: 2rem;
  align-items: center;
  gap: 0.5rem;
  white-space: nowrap;
  font-size: 0.75rem;
  line-height: 1rem;
}

.dashboard-action-bar__choice {
  min-width: 0;
  max-width: 18rem;
  border: 1px solid var(--color-border);
  border-radius: 9999px;
  background: rgb(var(--color-accent-rgb) / 0.06);
  color: var(--color-muted);
  padding: 0.35rem 0.65rem;
}

.dashboard-action-bar__mode {
  flex: 0 0 auto;
  color: var(--color-muted);
}

.dashboard-action-bar__button {
  border: 1px solid var(--color-border);
  border-radius: 6px;
  background: rgb(var(--color-accent-rgb) / 0.07);
  color: var(--color-foreground);
  font-weight: 500;
  padding: 0.35rem 0.65rem;
  transition: background-color 160ms ease, border-color 160ms ease, color 160ms ease;
}

.dashboard-action-bar__button:hover:not(:disabled) {
  border-color: rgb(var(--color-accent-rgb) / 0.44);
  background: rgb(var(--color-accent-rgb) / 0.12);
  color: var(--color-accent);
}

.dashboard-action-bar__button:disabled {
  cursor: not-allowed;
  opacity: 0.52;
}
</style>
