<script setup lang="ts">
import { AlertTriangle } from 'lucide-vue-next'
import { useUiStore } from '../stores/ui'
import ModalShell from './ModalShell.vue'

const props = withDefaults(defineProps<{
  compact?: boolean
}>(), {
  compact: false,
})
const ui = useUiStore()
</script>

<template>
  <ModalShell
    :open="ui.showConfirm"
    :title="ui.confirmTitle"
    :description="ui.confirmMessage"
    :compact="props.compact"
    size="sm"
    @close="ui.closeConfirm"
  >
    <template #icon>
      <AlertTriangle class="h-4 w-4 text-warning" />
    </template>

    <template #actions>
      <button
        type="button"
        class="rounded-lg border border-border px-3 py-2 text-sm text-muted hover:bg-surface/80"
        @click="ui.closeConfirm"
      >
        {{ ui.confirmCancelLabel }}
      </button>
      <button
        type="button"
        :class="[
          'rounded-lg px-3 py-2 text-sm text-white',
          ui.confirmVariant === 'destructive'
            ? 'bg-destructive hover:bg-destructive/90'
            : 'bg-accent hover:bg-accent/90',
        ]"
        @click="ui.onConfirm"
      >
        {{ ui.confirmConfirmLabel }}
      </button>
    </template>
  </ModalShell>
</template>
