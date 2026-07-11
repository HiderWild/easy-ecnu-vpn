<script setup lang="ts">
import { Power } from 'lucide-vue-next'

defineProps<{
  connected: boolean
  connecting: boolean
  powerAnimating: boolean
  powerButtonClass: string
  powerButtonLabel: string
  powerButtonDisabled: boolean
  statusLabel: string
  statusDescription: string
}>()

const emit = defineEmits<{
  power: []
}>()
</script>

<template>
  <section class="dashboard-connection-hero">
    <div class="min-w-0">
      <p class="text-xs font-medium text-muted">连接控制</p>
      <p class="mt-1 truncate text-2xl font-semibold leading-tight text-foreground">{{ statusLabel }}</p>
      <p class="mt-2 line-clamp-2 min-h-10 text-sm leading-5 text-muted">{{ statusDescription }}</p>
    </div>

    <div
      :class="[
        'dashboard-hero__ring',
        powerAnimating ? 'is-busy' : '',
        connected && !powerAnimating ? 'is-connected' : '',
        connecting ? 'is-connecting' : '',
      ]"
    >
      <span v-if="powerAnimating" class="dashboard-hero__orbit" aria-hidden="true" />
      <button
        type="button"
        :disabled="powerButtonDisabled"
        :class="[
          'dashboard-hero__button',
          powerButtonClass,
        ]"
        :title="powerButtonLabel"
        :aria-label="powerButtonLabel"
        @click="emit('power')"
      >
        <Power class="h-9 w-9" />
      </button>
    </div>
  </section>
</template>

<style scoped>
.dashboard-connection-hero {
  box-sizing: border-box;
  display: grid;
  min-height: 9.25rem;
  grid-template-columns: minmax(0, 1fr) 11.75rem;
  align-items: center;
  gap: 1rem;
  overflow: hidden;
  border: 1px solid var(--color-border);
  border-radius: 8px;
  background:
    linear-gradient(135deg, rgb(var(--color-accent-rgb) / 0.1), transparent 42%),
    var(--color-surface);
  padding: 1rem 1rem 1rem 1.125rem;
}

.dashboard-hero__ring {
  position: relative;
  display: grid;
  width: 8rem;
  height: 8rem;
  place-items: center;
  align-self: center;
  justify-self: center;
}

.dashboard-hero__ring.is-connected::before,
.dashboard-hero__ring.is-connected::after {
  content: '';
  position: absolute;
  inset: 0.45rem;
  border: 2px solid var(--topology-accent-node);
  border-radius: 9999px;
  opacity: 0;
  animation: dashboard-hero-ripple 3s ease-out infinite;
}

.dashboard-hero__ring.is-connected::after {
  animation-delay: 1.35s;
}

.dashboard-hero__ring.is-busy {
  filter: drop-shadow(0 0 0.8rem var(--topology-warning-glow));
}

.dashboard-hero__orbit {
  position: absolute;
  inset: 0.2rem;
  border-radius: 9999px;
  border: 2px solid rgb(var(--color-warning-rgb) / 0.32);
  border-top-color: var(--color-warning);
  animation: dashboard-hero-spin 1s linear infinite;
}

.dashboard-hero__button {
  position: relative;
  z-index: 1;
  display: grid;
  width: 6.35rem;
  height: 6.35rem;
  place-items: center;
  border-radius: 9999px;
  box-shadow:
    0 1rem 2rem rgba(0, 0, 0, 0.22),
    inset 0 0.35rem 0.6rem rgba(255, 255, 255, 0.18),
    inset 0 -0.55rem 0.9rem rgba(0, 0, 0, 0.2);
  transition: box-shadow 160ms ease, transform 160ms ease;
}

.dashboard-hero__button:hover:not(:disabled) {
  transform: translateY(-0.12rem);
}

.dashboard-hero__button:active:not(:disabled) {
  transform: translateY(0.06rem) scale(0.985);
}

.dashboard-hero__button:disabled {
  cursor: not-allowed;
  opacity: 0.72;
}

@keyframes dashboard-hero-spin {
  to {
    transform: rotate(360deg);
  }
}

@keyframes dashboard-hero-ripple {
  0% {
    opacity: 0;
    transform: scale(0.72);
  }

  12% {
    opacity: 0.72;
  }

  72%,
  100% {
    opacity: 0;
    transform: scale(1.42);
  }
}

@media (prefers-reduced-motion: reduce) {
  .dashboard-hero__ring::before,
  .dashboard-hero__ring::after,
  .dashboard-hero__orbit {
    animation: none !important;
  }
}
</style>
