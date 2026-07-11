<script setup lang="ts">
defineProps<{
  stateLabel: string
  headline: string
  detail: string
  tone: 'accent' | 'warning' | 'muted'
  active: boolean
}>()
</script>

<template>
  <section
    :class="[
      'dashboard-visual-stage',
      `is-${tone}`,
      active ? 'is-active' : '',
    ]"
  >
    <div class="dashboard-visual-stage__viewport">
      <div
        class="dashboard-visual-stage__character"
        data-visual-stage="character"
        aria-hidden="true"
      >
        <slot name="character">
          <div class="dashboard-visual-stage__fallback">
            <span>EXV</span>
          </div>
        </slot>
      </div>
      <span class="dashboard-visual-stage__signal" aria-hidden="true" />
    </div>

    <div class="dashboard-visual-stage__copy">
      <p class="dashboard-visual-stage__state">{{ stateLabel }}</p>
      <h2 class="dashboard-visual-stage__headline">{{ headline }}</h2>
      <p class="dashboard-visual-stage__detail">{{ detail }}</p>
    </div>
  </section>
</template>

<style scoped>
.dashboard-visual-stage {
  --stage-tone: var(--color-muted);
  --stage-tone-rgb: var(--color-muted-rgb);

  position: relative;
  display: grid;
  min-height: 0;
  grid-template-columns: minmax(14rem, 0.88fr) minmax(16rem, 1fr);
  align-items: center;
  gap: clamp(0.9rem, 2.6vw, 2.4rem);
  overflow: hidden;
  border: 1px solid var(--color-border);
  border-radius: 8px;
  background:
    linear-gradient(135deg, rgb(var(--stage-tone-rgb) / 0.1), transparent 46%),
    var(--color-surface);
  padding: clamp(1rem, 2.5vw, 2rem);
}

.dashboard-visual-stage.is-accent {
  --stage-tone: var(--color-accent);
  --stage-tone-rgb: var(--color-accent-rgb);
}

.dashboard-visual-stage.is-warning {
  --stage-tone: var(--color-warning);
  --stage-tone-rgb: var(--color-warning-rgb);
}

.dashboard-visual-stage.is-muted {
  --stage-tone: var(--color-muted);
  --stage-tone-rgb: var(--color-muted-rgb);
}

.dashboard-visual-stage__viewport {
  position: relative;
  display: grid;
  min-height: 12rem;
  place-items: center;
  overflow: hidden;
  border: 1px solid rgb(var(--stage-tone-rgb) / 0.22);
  border-radius: 8px;
  background:
    linear-gradient(180deg, rgb(var(--stage-tone-rgb) / 0.08), transparent 62%),
    rgb(var(--color-background-rgb) / 0.52);
}

.dashboard-visual-stage__viewport::before {
  content: '';
  position: absolute;
  inset: 0.95rem;
  border: 1px solid rgb(var(--stage-tone-rgb) / 0.18);
  border-radius: 6px;
  pointer-events: none;
}

.dashboard-visual-stage__character {
  position: relative;
  z-index: 1;
  display: grid;
  width: min(13.2rem, 72%);
  aspect-ratio: 1;
  place-items: center;
}

.dashboard-visual-stage__fallback {
  display: grid;
  width: 100%;
  height: 100%;
  place-items: center;
  border: 1px solid rgb(var(--stage-tone-rgb) / 0.38);
  border-radius: 8px;
  background:
    linear-gradient(145deg, rgb(var(--stage-tone-rgb) / 0.2), rgb(var(--stage-tone-rgb) / 0.06)),
    var(--color-surface);
  color: var(--stage-tone);
  font-size: clamp(1.3rem, 3.3vw, 2.35rem);
  font-weight: 800;
  letter-spacing: 0;
  box-shadow: inset 0 0 0 1px rgb(255 255 255 / 0.06);
}

.dashboard-visual-stage__signal {
  position: absolute;
  left: 1rem;
  right: 1rem;
  bottom: 0.95rem;
  height: 0.2rem;
  overflow: hidden;
  border-radius: 9999px;
  background: rgb(var(--stage-tone-rgb) / 0.14);
}

.dashboard-visual-stage__signal::after {
  content: '';
  position: absolute;
  inset-block: 0;
  left: -36%;
  width: 36%;
  border-radius: inherit;
  background: var(--stage-tone);
  opacity: 0.78;
  transform: translateX(0);
}

.dashboard-visual-stage.is-active .dashboard-visual-stage__signal::after {
  animation: dashboard-visual-stage-scan 1.35s ease-in-out infinite;
}

.dashboard-visual-stage__copy {
  min-width: 0;
  max-width: 34rem;
}

.dashboard-visual-stage__state {
  color: var(--stage-tone);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0;
  line-height: 1.1rem;
}

.dashboard-visual-stage__headline {
  margin-top: 0.45rem;
  color: var(--color-foreground);
  font-size: clamp(1.35rem, 3.2vw, 2.35rem);
  font-weight: 750;
  letter-spacing: 0;
  line-height: 1.08;
}

.dashboard-visual-stage__detail {
  margin-top: 0.75rem;
  color: var(--color-muted);
  font-size: 0.9rem;
  line-height: 1.55;
}

@keyframes dashboard-visual-stage-scan {
  0% {
    transform: translateX(0);
  }

  100% {
    transform: translateX(380%);
  }
}

@media (max-width: 720px) {
  .dashboard-visual-stage {
    grid-template-columns: minmax(0, 1fr);
    align-content: center;
  }

  .dashboard-visual-stage__viewport {
    min-height: 11rem;
  }

  .dashboard-visual-stage__character {
    width: min(11rem, 68%);
  }
}

@media (prefers-reduced-motion: reduce) {
  .dashboard-visual-stage__signal::after {
    animation: none !important;
    transform: translateX(170%);
  }
}
</style>
