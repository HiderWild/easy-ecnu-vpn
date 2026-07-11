<script setup lang="ts">
import type { Component, CSSProperties } from 'vue'

export type DashboardTopologyNode = {
  key: string
  title: string
  caption: string
  tooltip?: string
  icon?: Component
  tone?: string
  pulseKeys?: string[]
}

export type DashboardAnimatedNode = DashboardTopologyNode & {
  opacity: number
  scale: number
  leaving?: boolean
  style: CSSProperties
}

defineProps<{
  arcViewBox: {
    width: number
    height: number
  }
  arcSegments: Array<{
    key: string
    d: string
  }>
  visibleReadySegments: Array<{
    key: string
    d: string
    phase: string
  }>
  activePulseKeys: string[]
  nodes: DashboardAnimatedNode[]
  nodeReady: (nodeKey: string) => boolean
  nodeActive: (node: DashboardTopologyNode) => boolean
  nodeVisualClass: (node: DashboardTopologyNode) => string
  nodeToneClass: (tone?: string) => string
}>()
</script>

<template>
  <section class="dashboard-topology">
    <div class="dashboard-topology__canvas">
      <svg
        class="dashboard-topology__svg"
        :viewBox="`0 0 ${arcViewBox.width} ${arcViewBox.height}`"
        preserveAspectRatio="xMidYMid meet"
        aria-hidden="true"
      >
        <path
          v-for="segment in arcSegments"
          :key="`track-${segment.key}`"
          :d="segment.d"
          pathLength="100"
          class="dashboard-topology__track"
        />
        <path
          v-for="segment in visibleReadySegments"
          :key="`ready-${segment.key}`"
          :d="segment.d"
          pathLength="100"
          :class="[
            'dashboard-topology__ready',
            `is-${segment.phase}`,
          ]"
        />
        <path
          v-for="segment in arcSegments"
          v-show="activePulseKeys.includes(segment.key)"
          :key="`pulse-${segment.key}`"
          :d="segment.d"
          pathLength="100"
          class="dashboard-topology__pulse"
        />
      </svg>

      <div
        v-for="node in nodes"
        :key="node.key"
        :class="[
          'dashboard-topology__node',
          nodeReady(node.key) ? 'node-ready' : '',
          nodeActive(node) ? 'stage-active' : '',
          nodeVisualClass(node),
        ]"
        :style="node.style"
      >
        <div
          v-if="node.key === 'traffic'"
          :class="[
            'dashboard-topology__icon-shell',
            'dashboard-topology__traffic-shell',
            nodeToneClass(node.tone),
          ]"
          aria-hidden="true"
        >
          <div class="dashboard-topology__photon-field">
            <span class="dashboard-topology__photon photon-a" />
            <span class="dashboard-topology__photon photon-b" />
            <span class="dashboard-topology__photon photon-c" />
            <span class="dashboard-topology__photon photon-d" />
          </div>
        </div>
        <div
          v-else
          :class="[
            'dashboard-topology__icon-shell',
            nodeToneClass(node.tone),
          ]"
          aria-hidden="true"
        >
          <component
            :is="node.icon"
            class="dashboard-topology__icon"
          />
        </div>
        <p
          class="dashboard-topology__title"
          :title="node.tooltip || node.title"
        >
          {{ node.title }}
        </p>
      </div>
    </div>
  </section>
</template>

<style scoped>
.dashboard-topology {
  min-height: 0;
  overflow: hidden;
  border: 1px solid var(--color-border);
  border-radius: 8px;
  background:
    linear-gradient(180deg, rgb(var(--color-accent-rgb) / 0.08), transparent 36%),
    var(--color-surface);
  padding: 0.35rem 0.6rem 0.45rem;
}

.dashboard-topology__canvas {
  position: relative;
  height: 100%;
  min-height: 13.5rem;
  overflow: hidden;
}

.dashboard-topology__svg {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
  overflow: visible;
}

.dashboard-topology__track {
  fill: none;
  stroke: rgba(148, 163, 184, 0.28);
  stroke-linecap: round;
  stroke-width: 2;
  transition: stroke 180ms ease, stroke-width 180ms ease;
}

.dashboard-topology__ready {
  fill: none;
  stroke: var(--topology-accent-stroke);
  stroke-dasharray: 100;
  stroke-dashoffset: 0;
  stroke-linecap: round;
  stroke-width: 4;
  filter: drop-shadow(0 0 6px var(--topology-accent-glow));
}

.dashboard-topology__ready.is-entering {
  animation: dashboard-ready-draw 720ms cubic-bezier(0.22, 1, 0.36, 1) both;
}

.dashboard-topology__ready.is-disconnecting {
  stroke: var(--topology-warning-stroke);
  filter: drop-shadow(0 0 6px var(--topology-warning-glow));
}

.dashboard-topology__ready.is-leaving {
  stroke: var(--topology-warning-stroke);
  filter: drop-shadow(0 0 6px var(--topology-warning-glow));
  animation: dashboard-ready-retract 720ms cubic-bezier(0.64, 0, 0.78, 0) both;
}

.dashboard-topology__pulse {
  fill: none;
  stroke: var(--color-warning);
  stroke-dasharray: 34 260;
  stroke-linecap: round;
  stroke-width: 4;
  filter: drop-shadow(0 0 8px var(--topology-warning-glow));
  animation: dashboard-pulse-run 1.05s ease-in-out infinite;
}

.dashboard-topology__node {
  position: absolute;
  display: flex;
  width: 6rem;
  height: 6rem;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 0.05rem;
  border-radius: 9999px;
  isolation: isolate;
  padding: 0.35rem;
  text-align: center;
  transform: translate(-50%, -50%);
  transition: background-color 160ms ease, box-shadow 160ms ease, transform 160ms ease;
  contain: paint;
}

.dashboard-topology__node::before,
.dashboard-topology__node::after {
  content: '';
  position: absolute;
  inset: 0.42rem;
  border-radius: 9999px;
  pointer-events: none;
}

.dashboard-topology__node::before {
  z-index: -1;
  border: 3px solid rgba(148, 163, 184, 0.34);
  transition: border-color 180ms ease, background 180ms ease, box-shadow 180ms ease;
}

.dashboard-topology__node::after {
  z-index: -2;
  background: transparent;
  filter: blur(8px);
  opacity: 0;
  transition: opacity 180ms ease, background 180ms ease;
}

.dashboard-topology__node.stage-active {
  z-index: 2;
}

.dashboard-topology__node.node-success .dashboard-topology__icon-shell,
.dashboard-topology__node.node-success .dashboard-topology__icon,
.dashboard-topology__node.node-success .dashboard-topology__title {
  color: var(--color-accent);
}

.dashboard-topology__node.node-warning .dashboard-topology__icon-shell,
.dashboard-topology__node.node-warning .dashboard-topology__icon,
.dashboard-topology__node.node-warning .dashboard-topology__title {
  color: var(--color-warning);
}

.dashboard-topology__node.node-muted .dashboard-topology__icon-shell,
.dashboard-topology__node.node-muted .dashboard-topology__icon,
.dashboard-topology__node.node-muted .dashboard-topology__title {
  color: rgb(148 163 184);
}

.dashboard-topology__node.node-success::before {
  border-color: var(--topology-accent-node);
  box-shadow: 0 0 0.65rem var(--topology-accent-glow);
}

.dashboard-topology__node.stage-active::before {
  border-color: var(--topology-warning-node);
  background: var(--topology-warning-soft);
  box-shadow:
    inset 0 0 1rem rgb(var(--color-warning-rgb) / 0.13),
    0 0 1rem var(--topology-warning-glow);
}

.dashboard-topology__node.stage-active::after {
  background: rgb(var(--color-warning-rgb) / 0.34);
  opacity: 0.52;
}

.dashboard-topology__icon-shell {
  position: relative;
  display: grid;
  width: 2.5rem;
  height: 2.5rem;
  place-items: center;
  flex: 0 0 auto;
}

.dashboard-topology__icon {
  width: 1.7rem;
  height: 1.7rem;
  stroke-width: 2.25;
  color: currentColor;
  filter: drop-shadow(0 0.12rem 0.2rem rgba(0, 0, 0, 0.34));
}

.dashboard-topology__title {
  color: var(--color-foreground);
  font-size: 0.72rem;
  font-weight: 600;
  line-height: 1rem;
}

.dashboard-topology__photon-field {
  position: relative;
  width: 2.15rem;
  height: 1.55rem;
}

.dashboard-topology__photon {
  position: absolute;
  display: block;
  width: 0.5rem;
  height: 0.5rem;
  border-radius: 9999px;
  background: var(--color-accent);
  box-shadow:
    -0.75rem 0 0 -0.16rem rgb(var(--color-accent-rgb) / 0.55),
    -1.32rem 0 0 -0.25rem rgb(var(--color-accent-rgb) / 0.25);
}

.dashboard-topology__node.node-warning .dashboard-topology__photon {
  background: var(--color-warning);
  box-shadow:
    -0.75rem 0 0 -0.16rem rgb(var(--color-warning-rgb) / 0.55),
    -1.32rem 0 0 -0.25rem rgb(var(--color-warning-rgb) / 0.25);
}

.photon-a {
  left: 1.45rem;
  top: 0.05rem;
}

.photon-b {
  left: 0.72rem;
  top: 0.52rem;
}

.photon-c {
  left: 1.65rem;
  top: 0.95rem;
}

.photon-d {
  left: 0.3rem;
  top: 1.08rem;
}

@keyframes dashboard-pulse-run {
  0% {
    opacity: 0;
    stroke-dashoffset: 52;
  }

  14%,
  78% {
    opacity: 1;
  }

  100% {
    opacity: 0;
    stroke-dashoffset: -230;
  }
}

@keyframes dashboard-ready-draw {
  0% {
    opacity: 0.15;
    stroke-dashoffset: 100;
  }

  18%,
  100% {
    opacity: 1;
  }

  100% {
    stroke-dashoffset: 0;
  }
}

@keyframes dashboard-ready-retract {
  0% {
    opacity: 1;
    stroke-dashoffset: 0;
  }

  100% {
    opacity: 0.12;
    stroke-dashoffset: -100;
  }
}

@media (prefers-reduced-motion: reduce) {
  .dashboard-topology__pulse,
  .dashboard-topology__ready {
    animation: none !important;
  }
}
</style>
