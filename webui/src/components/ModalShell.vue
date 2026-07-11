<script setup lang="ts">
const props = withDefaults(defineProps<{
  open: boolean
  title?: string
  description?: string
  size?: 'sm' | 'md' | 'lg' | 'xl'
  closeOnScrim?: boolean
  bodyScroll?: boolean
  compact?: boolean
}>(), {
  title: '',
  description: '',
  size: 'md',
  closeOnScrim: true,
  bodyScroll: true,
  compact: false,
})

const emit = defineEmits<{
  close: []
}>()

function onScrimClick() {
  if (props.closeOnScrim) emit('close')
}
</script>

<template>
  <div
    v-if="open"
    class="modal-shell__scrim"
    role="presentation"
    @click.self="onScrimClick"
  >
    <section
      class="modal-shell__panel"
      :class="[
        `modal-shell__panel--${size}`,
        compact ? 'modal-shell__panel--compact' : '',
      ]"
      role="dialog"
      aria-modal="true"
      :aria-label="title || undefined"
    >
      <header
        v-if="title || description || $slots.icon || $slots['header-start'] || $slots['header-end']"
        class="modal-shell__header"
      >
        <div class="modal-shell__header-main">
          <div v-if="$slots.icon" class="modal-shell__icon">
            <slot name="icon" />
          </div>
          <div class="modal-shell__heading-stack">
            <div class="modal-shell__heading">
              <h2 v-if="title" class="modal-shell__title">{{ title }}</h2>
              <p v-if="description" class="modal-shell__description">{{ description }}</p>
            </div>
            <div v-if="$slots['header-start']" class="modal-shell__header-start">
              <slot name="header-start" />
            </div>
          </div>
        </div>
        <div v-if="$slots['header-end']" class="modal-shell__header-end">
          <slot name="header-end" />
        </div>
      </header>

      <div
        class="modal-shell__body"
        :class="bodyScroll ? '' : 'modal-shell__body--locked'"
      >
        <slot />
      </div>

      <footer v-if="$slots.actions" class="modal-shell__actions">
        <slot name="actions" />
      </footer>
    </section>
  </div>
</template>

<style>
.modal-shell__scrim {
  position: absolute;
  inset: 0;
  z-index: 120;
  display: grid;
  place-items: center;
  padding: 14px;
  background: var(--modal-scrim-bg);
  backdrop-filter: blur(10px) saturate(1.05);
}

.modal-shell__panel {
  display: flex;
  flex-direction: column;
  width: min(100%, 400px);
  max-height: calc(100vh - 28px);
  overflow: hidden;
  border: 1px solid var(--modal-border);
  border-radius: 8px;
  background: var(--color-surface);
  color: var(--color-foreground);
  box-shadow: var(--modal-shadow);
  padding: 18px;
}

.modal-shell__panel--sm {
  width: min(100%, 360px);
}

.modal-shell__panel--lg {
  width: min(100%, 440px);
}

.modal-shell__panel--xl {
  width: min(100%, 920px);
}

.modal-shell__panel--compact {
  width: min(100%, 294px);
  max-height: calc(100vh - 8px);
  padding: 4px 6px;
  border-radius: 7px;
}

.modal-shell__header {
  display: flex;
  flex: 0 0 auto;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 14px;
}

.modal-shell__header-main {
  display: flex;
  min-width: 0;
  align-items: flex-start;
  gap: 10px;
}

.modal-shell__icon {
  display: grid;
  width: 28px;
  height: 28px;
  flex: 0 0 auto;
  place-items: center;
  border-radius: 8px;
  background: var(--accent-soft-bg);
  color: var(--color-accent);
}

.modal-shell__heading-stack {
  display: grid;
  min-width: 0;
  gap: 8px;
}

.modal-shell__heading {
  min-width: 0;
}

.modal-shell__header-start,
.modal-shell__header-end {
  min-width: 0;
}

.modal-shell__header-end {
  flex: 0 0 auto;
}

.modal-shell__title {
  margin: 0;
  font-size: 15px;
  font-weight: 650;
  line-height: 1.35;
  letter-spacing: 0;
}

.modal-shell__description {
  margin: 4px 0 0;
  color: var(--color-muted);
  font-size: 12px;
  line-height: 1.45;
}

.modal-shell__body {
  flex: 1 1 auto;
  min-width: 0;
  min-height: 0;
  overflow: auto;
  overscroll-behavior: contain;
}

.modal-shell__body--locked {
  overflow: hidden;
  overscroll-behavior: auto;
}

.modal-shell__actions {
  display: flex;
  flex: 0 0 auto;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 8px;
  margin-top: 16px;
}

.modal-shell__panel--compact .modal-shell__header {
  align-items: center;
  gap: 6px;
  margin-bottom: 2px;
}

.modal-shell__panel--compact .modal-shell__header-main {
  gap: 6px;
}

.modal-shell__panel--compact .modal-shell__icon {
  display: none;
}

.modal-shell__panel--compact .modal-shell__heading-stack,
.modal-shell__panel--compact .modal-shell__heading {
  min-width: 0;
}

.modal-shell__panel--compact .modal-shell__title {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12px;
  line-height: 1.15;
}

.modal-shell__panel--compact .modal-shell__description {
  margin-top: 1px;
  font-size: 10.5px;
  line-height: 1.2;
}

.modal-shell__panel--compact .modal-shell__body {
  flex: 0 1 auto;
  overflow: hidden;
  overscroll-behavior: auto;
  color: var(--color-muted);
  font-size: 11px;
  line-height: 1.25;
  overflow-wrap: anywhere;
}

.modal-shell__panel--compact .modal-shell__actions {
  flex-wrap: nowrap;
  align-items: center;
  justify-content: flex-end;
  gap: 4px;
  margin-top: 4px;
  min-width: 0;
}

.modal-shell__panel--compact .modal-shell__actions button {
  min-height: 22px;
  min-width: 0;
  padding: 3px 7px;
  border-radius: 6px;
  font-size: 11px;
  line-height: 1.1;
  white-space: nowrap;
}

.modal-shell__panel--compact input:not([type="checkbox"]):not([type="radio"]),
.modal-shell__panel--compact select {
  min-height: 24px;
  padding: 3px 7px;
  border-radius: 6px;
  font-size: 11px;
  line-height: 1.2;
}

.modal-shell__panel--compact input[type="checkbox"],
.modal-shell__panel--compact input[type="radio"] {
  width: 12px;
  height: 12px;
}

.modal-compact-form {
  display: grid;
  gap: 4px;
}

.modal-compact-message {
  margin: 0;
  color: var(--color-muted);
  font-size: 11px;
  line-height: 1.25;
}

.modal-compact-error {
  margin: 0;
  color: var(--color-destructive);
  font-size: 10.5px;
  line-height: 1.2;
}

@media (max-width: 360px), (max-height: 180px) {
  .modal-shell__scrim {
    align-items: stretch;
    padding: 8px;
  }

  .modal-shell__panel {
    width: 100%;
    max-height: calc(100vh - 16px);
    padding: 12px;
  }

  .modal-shell__header {
    gap: 8px;
    margin-bottom: 10px;
  }

  .modal-shell__icon {
    width: 24px;
    height: 24px;
    border-radius: 7px;
  }

  .modal-shell__actions {
    justify-content: stretch;
    margin-top: 12px;
  }

  .modal-shell__actions button {
    flex: 1 1 96px;
  }

  .modal-shell__panel--compact {
    width: min(100%, 294px);
    max-height: calc(100vh - 8px);
    padding: 4px 6px;
  }

  .modal-shell__panel--compact .modal-shell__header {
    gap: 6px;
    margin-bottom: 2px;
  }

  .modal-shell__panel--compact .modal-shell__actions {
    flex-wrap: nowrap;
    justify-content: flex-end;
    gap: 4px;
    margin-top: 4px;
  }

  .modal-shell__panel--compact .modal-shell__actions button {
    flex: 0 0 auto;
  }
}
</style>
