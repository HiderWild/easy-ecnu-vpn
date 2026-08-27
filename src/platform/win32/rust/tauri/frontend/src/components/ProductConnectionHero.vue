<script setup lang="ts">
import type { ProductUiState } from "../product/types";
import ConnectionActionButton from "./ConnectionActionButton.vue";

defineProps<{
  state: ProductUiState;
  description: string;
  busy: boolean;
}>();

const emit = defineEmits<{ action: [] }>();
</script>

<template>
  <section
    class="product-connection-hero"
    data-testid="product-connection-hero"
    :data-status="state.status"
    :data-severity="state.severity"
    aria-labelledby="connection-state-title"
  >
    <div class="product-connection-hero__copy">
      <h1 id="connection-state-title">{{ state.title }}</h1>
      <p v-if="description">{{ description }}</p>
    </div>

    <div class="product-connection-hero__action">
      <span class="product-connection-hero__signal" aria-hidden="true" />
      <ConnectionActionButton :state="state" :busy="busy" @action="emit('action')" />
    </div>
  </section>
</template>

<style scoped>
.product-connection-hero {
  margin-top: var(--product-page-top-gap);
  display: grid;
  min-height: 148px;
  grid-template-columns: minmax(0, 1fr) 150px;
  align-items: center;
  gap: var(--space-5);
  overflow: hidden;
  padding: var(--space-5) var(--space-6);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-lg);
  background:
    linear-gradient(135deg, color-mix(in srgb, var(--accent) 11%, transparent), transparent 58%),
    var(--surface-panel);
}

.product-connection-hero__copy {
  min-width: 0;
}

.product-connection-hero h1 {
  margin: 0;
  overflow-wrap: anywhere;
  font-size: clamp(22px, 2.1vw, 30px);
  letter-spacing: -0.025em;
  line-height: 1.1;
}

.product-connection-hero__copy > p:last-child {
  max-width: 44rem;
  margin: 8px 0 0;
  color: var(--text-secondary);
  font-size: 14px;
  line-height: 1.45;
}

.product-connection-hero__action {
  position: relative;
  display: grid;
  min-height: 96px;
  place-items: center;
}

.product-connection-hero__signal {
  position: absolute;
  width: 94px;
  height: 94px;
  border: 1px solid color-mix(in srgb, var(--accent) 40%, var(--border-subtle));
  border-radius: 50%;
  opacity: 0.78;
}

.product-connection-hero__signal::before,
.product-connection-hero__signal::after {
  position: absolute;
  inset: 10px;
  border: 1px solid color-mix(in srgb, var(--accent) 26%, transparent);
  border-radius: inherit;
  content: "";
}

.product-connection-hero__signal::after {
  inset: 22px;
  border-color: color-mix(in srgb, var(--accent) 42%, transparent);
}

.product-connection-hero__action :deep(.connection-action) {
  position: relative;
  z-index: 1;
  min-width: 112px;
  min-height: 42px;
  box-shadow: var(--shadow-raised);
}

.product-connection-hero[data-status="connected"] .product-connection-hero__signal {
  border-color: color-mix(in srgb, var(--state-success) 55%, var(--border-subtle));
}

.product-connection-hero[data-status="connecting"] .product-connection-hero__signal,
.product-connection-hero[data-status="awaiting"] .product-connection-hero__signal,
.product-connection-hero[data-status="stopping"] .product-connection-hero__signal,
.product-connection-hero[data-status="reconciling"] .product-connection-hero__signal {
  animation: product-hero-signal 1.6s ease-in-out infinite;
}

@keyframes product-hero-signal {
  0%, 100% { transform: scale(0.96); opacity: 0.48; }
  50% { transform: scale(1.04); opacity: 0.9; }
}

@media (max-width: 560px) {
  .product-connection-hero {
    grid-template-columns: 1fr;
  }

  .product-connection-hero__action {
    justify-content: start;
  }
}

.motion-reduced .product-connection-hero__signal,
[data-motion="reduced"] .product-connection-hero__signal {
  animation: none !important;
}
</style>
