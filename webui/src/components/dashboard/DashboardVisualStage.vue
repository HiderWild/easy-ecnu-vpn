<script setup lang="ts">
import { computed } from 'vue'
import { Wrench } from 'lucide-vue-next'
import type { ConnectionProgressStage } from '../../stores/vpn'

type StageTone = 'accent' | 'warning' | 'muted'
type StageRole = 'previous' | 'current' | 'next'

interface VisibleStage {
  role: StageRole
  stage: ConnectionProgressStage
}

const props = withDefaults(defineProps<{
  stateLabel: string
  headline: string
  detail: string
  tone: StageTone
  active: boolean
  steps?: ConnectionProgressStage[]
  currentKey?: string
  showPreConnectInfo: boolean
  showServiceRepairAction: boolean
  serviceRepairDisabled: boolean
  serviceRepairLabel: string
  showInstallServiceChoice: boolean
  installServiceChoiceDisabled: boolean
  showMinimizeToTrayChoice: boolean
  installServiceBeforeConnect: boolean
  minimizeToTrayOnConnect: boolean
  autoReconnect: boolean
  retryLimit: number
  coreStatusLabel: string
  coreStatusTone: StageTone
  serviceStatusLabel: string
  serviceStatusTone: StageTone
  proxyTunLabel: string
}>(), {
  steps: () => [],
  currentKey: '',
  showPreConnectInfo: false,
  showServiceRepairAction: false,
  serviceRepairDisabled: false,
  serviceRepairLabel: '尝试修复',
  showInstallServiceChoice: false,
  installServiceChoiceDisabled: false,
  showMinimizeToTrayChoice: false,
  installServiceBeforeConnect: true,
  minimizeToTrayOnConnect: false,
  autoReconnect: true,
  retryLimit: 0,
  coreStatusLabel: '断连',
  coreStatusTone: 'warning',
  serviceStatusLabel: '--',
  serviceStatusTone: 'muted',
  proxyTunLabel: '--',
})

const emit = defineEmits<{
  repair: []
  'update:installServiceBeforeConnect': [value: boolean]
  'update:minimizeToTrayOnConnect': [value: boolean]
  'update:autoReconnect': [value: boolean]
  'update:retryLimit': [value: number]
}>()

const sortedSteps = computed(() => {
  return props.steps
    .map((step, originalIndex) => ({ step, originalIndex }))
    .sort((a, b) => (a.step.priority - b.step.priority) || (a.originalIndex - b.originalIndex))
    .map(({ step }) => step)
})

const hasProgress = computed(() => props.active && sortedSteps.value.length > 0)

const fallbackStage = computed<ConnectionProgressStage>(() => ({
  key: `local-${props.tone}`,
  label: props.headline || 'EXV',
  description: props.detail,
  state: props.active ? 'active' : props.tone === 'accent' ? 'done' : 'pending',
  priority: 0,
  visual: props.tone === 'accent' ? 'check' : props.tone === 'warning' ? 'routes' : 'shield',
  source: 'local',
}))

const currentStepIndex = computed(() => {
  const steps = sortedSteps.value
  const keyIndex = props.currentKey ? steps.findIndex((step) => step.key === props.currentKey) : -1
  if (keyIndex >= 0) return keyIndex

  const activeIndex = steps.findIndex((step) => step.state === 'active' || step.state === 'failed')
  if (activeIndex >= 0) return activeIndex

  for (let i = steps.length - 1; i >= 0; i -= 1) {
    const state = steps[i].state
    if (state === 'done' || state === 'skipped') return i
  }

  return 0
})

const visibleStages = computed<VisibleStage[]>(() => {
  if (!hasProgress.value) {
    return [{ role: 'current', stage: fallbackStage.value }]
  }

  const steps = sortedSteps.value
  const current = steps[currentStepIndex.value] ?? steps[0]
  const priorSteps = steps.slice(0, currentStepIndex.value)
  const nextSteps = steps.slice(currentStepIndex.value + 1)
  const previous = [...priorSteps].reverse().find((step) => step.state === 'done' || step.state === 'skipped')
    ?? priorSteps[priorSteps.length - 1]
  const next = nextSteps.find((step) => step.state === 'pending' || step.state === 'active') ?? nextSteps[0]

  return [
    previous ? { role: 'previous', stage: previous } : undefined,
    { role: 'current', stage: current },
    next ? { role: 'next', stage: next } : undefined,
  ].filter((stage): stage is VisibleStage => Boolean(stage))
})

function visualKind(stage: ConnectionProgressStage) {
  const signature = `${stage.visual} ${stage.key}`.toLowerCase()
  if (signature.includes('server') || signature.includes('gateway')) return 'server'
  if (signature.includes('auth') || signature.includes('key') || signature.includes('lock')) return 'key'
  if (signature.includes('intent') || signature.includes('shield') || signature.includes('permission')) return 'shield'
  if (signature.includes('helper') || signature.includes('process') || signature.includes('service')) return 'helper'
  if (signature.includes('adapter') || signature.includes('interface') || signature.includes('tun')) return 'adapter'
  if (signature.includes('route') || signature.includes('dns')) return 'routes'
  if (signature.includes('packet') || signature.includes('forward')) return 'packet'
  if (signature.includes('check') || signature.includes('ready') || signature.includes('confirm')) return 'check'
  return 'shield'
}

function stepStateLabel(state: ConnectionProgressStage['state']) {
  switch (state) {
    case 'active':
      return '进行中'
    case 'done':
      return '完成'
    case 'failed':
      return '异常'
    case 'skipped':
      return '跳过'
    default:
      return '等待'
  }
}

function handleInstallServiceChange(event: Event) {
  emit('update:installServiceBeforeConnect', (event.target as HTMLInputElement).checked)
}

function handleMinimizeToTrayChange(event: Event) {
  emit('update:minimizeToTrayOnConnect', (event.target as HTMLInputElement).checked)
}

function handleAutoReconnectChange(event: Event) {
  emit('update:autoReconnect', (event.target as HTMLInputElement).checked)
}

function handleRetryLimitInput(event: Event) {
  const raw = Number((event.target as HTMLInputElement).value)
  emit('update:retryLimit', Number.isFinite(raw) && raw >= 0 ? Math.trunc(raw) : 0)
}
</script>

<template>
  <section
    :class="[
      'dashboard-visual-stage',
      `is-${tone}`,
      active ? 'is-active' : '',
      hasProgress ? 'is-progress' : '',
    ]"
  >
    <div class="dashboard-visual-stage__viewport">
      <div
        class="dashboard-visual-stage__hologram"
        role="img"
        :aria-label="hasProgress ? '连接进度全息舞台' : headline"
      >
        <span class="dashboard-visual-stage__hologram-grid" aria-hidden="true" />
        <span class="dashboard-visual-stage__hologram-scan" aria-hidden="true" />

        <TransitionGroup
          name="dashboard-visual-stage__hologram-transition"
          tag="div"
          class="dashboard-visual-stage__hologram-items"
        >
          <div
            v-for="item in visibleStages"
            :key="item.stage.key"
            :class="[
              'dashboard-visual-stage__hologram-item',
              `dashboard-visual-stage__hologram-item--${item.role}`,
              `is-${item.stage.state}`,
            ]"
          >
            <div class="dashboard-visual-stage__icon-shell">
              <svg
                class="dashboard-visual-stage__icon"
                viewBox="0 0 96 96"
                aria-hidden="true"
              >
                <g v-if="visualKind(item.stage) === 'server'">
                  <rect x="25" y="14" width="46" height="68" rx="8" />
                  <path d="M31 30H65M31 45H65M31 60H65" />
                  <circle cx="38" cy="30" r="2.8" />
                  <circle cx="38" cy="45" r="2.8" />
                  <circle cx="38" cy="60" r="2.8" />
                  <path d="M40 76H56" />
                </g>
                <g v-else-if="visualKind(item.stage) === 'key'">
                  <rect x="31" y="39" width="34" height="31" rx="7" />
                  <path d="M39 39V31C39 22 45 17 53 17C61 17 67 22 67 31V39" />
                  <path d="M31 61H19M19 61L14 56M19 61L14 66" />
                  <circle cx="49" cy="54" r="4" />
                  <path d="M49 58V64" />
                </g>
                <g v-else-if="visualKind(item.stage) === 'helper'">
                  <circle cx="48" cy="48" r="18" />
                  <path d="M48 21V12M48 84V75M21 48H12M84 48H75M29 29L22 22M74 74L67 67M67 29L74 22M22 74L29 67" />
                  <path d="M41 47L47 53L58 39" />
                </g>
                <g v-else-if="visualKind(item.stage) === 'adapter'">
                  <rect x="20" y="28" width="56" height="38" rx="8" />
                  <path d="M31 66V76M65 66V76M32 40H48M32 52H60" />
                  <path d="M65 34C72 38 76 43 78 50M68 23C80 29 87 38 89 50" />
                  <circle cx="65" cy="52" r="3" />
                </g>
                <g v-else-if="visualKind(item.stage) === 'routes'">
                  <path d="M21 66C36 35 57 66 75 29" />
                  <circle cx="21" cy="66" r="8" />
                  <circle cx="48" cy="48" r="8" />
                  <circle cx="75" cy="29" r="8" />
                  <path d="M67 28H75V36" />
                </g>
                <g v-else-if="visualKind(item.stage) === 'packet'">
                  <path d="M48 14L76 30V64L48 82L20 64V30L48 14Z" />
                  <path d="M20 30L48 47L76 30M48 47V82" />
                  <path d="M34 22L62 39" />
                </g>
                <g v-else-if="visualKind(item.stage) === 'check'">
                  <circle cx="48" cy="48" r="31" />
                  <path d="M31 49L43 61L66 36" />
                </g>
                <g v-else>
                  <path d="M48 13L73 23V43C73 60 62 73 48 81C34 73 23 60 23 43V23L48 13Z" />
                  <path d="M37 46L45 54L61 37" />
                </g>
              </svg>
            </div>
          </div>
        </TransitionGroup>
      </div>

      <span class="dashboard-visual-stage__signal" aria-hidden="true" />
    </div>

    <div
      :class="[
        'dashboard-visual-stage__copy',
        showPreConnectInfo ? 'is-preconnect' : '',
      ]"
    >
      <template v-if="!showPreConnectInfo">
        <p class="dashboard-visual-stage__state">{{ stateLabel }}</p>
        <h2 class="dashboard-visual-stage__headline">{{ headline }}</h2>
        <p class="dashboard-visual-stage__detail">{{ detail }}</p>
      </template>

      <div
        v-if="showPreConnectInfo"
        class="dashboard-visual-stage__preconnect"
      >
        <div class="dashboard-visual-stage__preconnect-grid">
          <div class="dashboard-visual-stage__preconnect-item">
            <span>内核通信</span>
            <strong :class="coreStatusTone === 'accent' ? 'text-accent' : coreStatusTone === 'warning' ? 'text-warning' : 'text-foreground'">{{ coreStatusLabel }}</strong>
          </div>
          <div class="dashboard-visual-stage__preconnect-item">
            <span>服务状态</span>
            <strong :class="serviceStatusTone === 'accent' ? 'text-accent' : serviceStatusTone === 'warning' ? 'text-warning' : 'text-foreground'">{{ serviceStatusLabel }}</strong>
          </div>
          <div class="dashboard-visual-stage__preconnect-item">
            <span>代理 TUN</span>
            <strong :title="proxyTunLabel">{{ proxyTunLabel }}</strong>
          </div>
          <div class="dashboard-visual-stage__preconnect-item dashboard-visual-stage__preconnect-item--reconnect">
            <span>断线重连</span>
            <span class="dashboard-visual-stage__reconnect-controls">
              <input
                :checked="autoReconnect"
                type="checkbox"
                class="h-3.5 w-3.5 accent-accent"
                aria-label="断线重连"
                @change="handleAutoReconnectChange"
              />
              <input
                :value="retryLimit"
                type="number"
                min="0"
                step="1"
                inputmode="numeric"
                :disabled="!autoReconnect"
                class="dashboard-visual-stage__retry-input"
                title="0 代表无限重连"
                aria-label="断线重连次数，0 代表无限重连"
                @input="handleRetryLimitInput"
              />
            </span>
          </div>
        </div>

        <div class="dashboard-visual-stage__controls">
          <label
            v-if="showInstallServiceChoice"
            class="dashboard-visual-stage__choice"
          >
            <input
              :checked="installServiceBeforeConnect"
              type="checkbox"
              :disabled="installServiceChoiceDisabled"
              class="h-3.5 w-3.5 accent-accent"
              @change="handleInstallServiceChange"
            />
            <span>连接前安装服务</span>
          </label>

          <label
            v-if="showMinimizeToTrayChoice"
            class="dashboard-visual-stage__choice"
          >
            <input
              :checked="minimizeToTrayOnConnect"
              type="checkbox"
              class="h-3.5 w-3.5 accent-accent"
              @change="handleMinimizeToTrayChange"
            />
            <span>连接后缩小到托盘区</span>
          </label>

          <button
            v-if="showServiceRepairAction"
            type="button"
            :disabled="serviceRepairDisabled"
            class="dashboard-visual-stage__button"
            @click="emit('repair')"
          >
            <Wrench class="h-3.5 w-3.5" />
            <span>{{ serviceRepairLabel }}</span>
          </button>
        </div>
      </div>

      <ol
        v-if="hasProgress"
        class="dashboard-visual-stage__steps"
        aria-label="连接步骤"
      >
        <li
          v-for="step in sortedSteps"
          :key="step.key"
          :aria-label="`${step.label}，${stepStateLabel(step.state)}`"
          :class="[
            'dashboard-visual-stage__step',
            `dashboard-visual-stage__step--${step.state}`,
          ]"
        >
          <span
            :class="[
              'dashboard-visual-stage__step-indicator',
              `dashboard-visual-stage__step-indicator--${step.state}`,
            ]"
            aria-hidden="true"
          >
            <span v-if="step.state === 'active'" class="dashboard-visual-stage__status-spinner" />
            <svg v-else-if="step.state === 'done'" viewBox="0 0 16 16">
              <path d="M3 8L6.5 11.5L13 4.5" />
            </svg>
            <svg v-else-if="step.state === 'failed'" viewBox="0 0 16 16">
              <path d="M8 2L14 13H2L8 2Z" />
              <path d="M8 6V9M8 11.5V12" />
            </svg>
            <span v-else-if="step.state === 'skipped'">-</span>
            <span v-else>i</span>
          </span>
          <span class="dashboard-visual-stage__step-label">{{ step.label }}</span>
        </li>
      </ol>
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
  grid-template-columns: minmax(12.5rem, 0.82fr) minmax(15rem, 1fr);
  align-items: center;
  gap: clamp(0.85rem, 2.4vw, 2rem);
  overflow: hidden;
  border: 1px solid var(--color-border);
  border-radius: 12px;
  background:
    linear-gradient(135deg, rgb(var(--stage-tone-rgb) / 0.1), transparent 46%),
    var(--color-surface);
  padding: clamp(0.9rem, 2.2vw, 1.65rem);
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
  --stage-tone: var(--color-accent);
  --stage-tone-rgb: var(--color-accent-rgb);
}

.dashboard-visual-stage__viewport {
  position: relative;
  display: grid;
  min-height: clamp(10rem, 31vh, 13rem);
  place-items: center;
  overflow: hidden;
  border: 1px solid rgb(var(--stage-tone-rgb) / 0.22);
  border-radius: 12px;
  background:
    radial-gradient(circle at 52% 45%, rgb(var(--stage-tone-rgb) / 0.16), transparent 45%),
    linear-gradient(180deg, rgb(var(--stage-tone-rgb) / 0.08), transparent 62%),
    rgb(var(--color-background-rgb) / 0.52);
}

.dashboard-visual-stage__viewport::before {
  content: '';
  position: absolute;
  inset: 0.8rem;
  border: 1px solid rgb(var(--stage-tone-rgb) / 0.16);
  border-radius: 9px;
  pointer-events: none;
}

.dashboard-visual-stage__hologram {
  position: relative;
  z-index: 1;
  width: min(18rem, 94%);
  aspect-ratio: 1.4;
  color: var(--stage-tone);
  perspective: 48rem;
}

.dashboard-visual-stage__hologram::before {
  content: '';
  position: absolute;
  right: 12%;
  bottom: 8%;
  left: 12%;
  height: 17%;
  border: 1px solid rgb(var(--stage-tone-rgb) / 0.22);
  border-radius: 50%;
  background: rgb(var(--stage-tone-rgb) / 0.08);
  filter: blur(0.2px);
  transform: rotateX(68deg);
}

.dashboard-visual-stage__hologram::after {
  content: '';
  position: absolute;
  top: 11%;
  left: 50%;
  width: 28%;
  height: 74%;
  background: linear-gradient(180deg, transparent, rgb(var(--stage-tone-rgb) / 0.12), transparent);
  clip-path: polygon(50% 0, 100% 100%, 0 100%);
  opacity: 0.7;
  pointer-events: none;
  transform: translateX(-50%);
}

.dashboard-visual-stage__hologram-grid {
  position: absolute;
  inset: 12% 8% 11%;
  background-image:
    linear-gradient(rgb(var(--stage-tone-rgb) / 0.22) 1px, transparent 1px),
    linear-gradient(90deg, rgb(var(--stage-tone-rgb) / 0.18) 1px, transparent 1px);
  background-size: 1rem 1rem;
  opacity: 0.36;
  mask-image: radial-gradient(circle, #000 34%, transparent 78%);
  transform: rotateX(64deg);
}

.dashboard-visual-stage__hologram-scan {
  position: absolute;
  top: 26%;
  right: 14%;
  left: 14%;
  height: 1px;
  background: rgb(var(--stage-tone-rgb) / 0.72);
  box-shadow: 0 0 0.9rem rgb(var(--stage-tone-rgb) / 0.55);
  opacity: 0.52;
}

.dashboard-visual-stage.is-active .dashboard-visual-stage__hologram-scan {
  animation: dashboard-visual-stage-hologram-scan 1.65s ease-in-out infinite;
}

.dashboard-visual-stage__hologram-items {
  position: absolute;
  inset: 0;
}

.dashboard-visual-stage__hologram-item {
  position: absolute;
  top: 50%;
  left: 50%;
  z-index: 2;
  display: grid;
  width: 7.3rem;
  place-items: center;
  gap: 0.42rem;
  opacity: 0.65;
  filter: saturate(0.9);
  transform-origin: 50%;
  transition:
    opacity 420ms,
    filter 420ms,
    transform 420ms cubic-bezier(0.2, 0.8, 0.2, 1);
}

.dashboard-visual-stage__hologram-item--previous {
  z-index: 1;
  clip-path: inset(-20% -8% -20% 58%);
  filter: saturate(0.82) blur(0.2px);
  opacity: 0.5;
  transform: translate(-166%, -52%) scale(1.24) rotateY(18deg);
}

.dashboard-visual-stage__hologram-item--current {
  z-index: 4;
  filter: drop-shadow(0 0 1rem rgb(var(--stage-tone-rgb) / 0.35));
  opacity: 1;
  transform: translate(-50%, -53%) scale(1);
}

.dashboard-visual-stage__hologram-item--next {
  z-index: 2;
  filter: saturate(0.55);
  opacity: 0.34;
  transform: translate(58%, -48%) scale(0.68) rotateY(-14deg);
}

.dashboard-visual-stage__hologram-transition-enter-active,
.dashboard-visual-stage__hologram-transition-leave-active,
.dashboard-visual-stage__hologram-transition-move {
  transition:
    opacity 520ms,
    filter 520ms,
    transform 520ms cubic-bezier(0.2, 0.8, 0.2, 1);
}

.dashboard-visual-stage__hologram-transition-enter-from {
  filter: saturate(0.35) blur(0.3px);
  opacity: 0;
  transform: translate(118%, -48%) scale(0.42) rotateY(-18deg);
}

.dashboard-visual-stage__hologram-transition-leave-to {
  filter: saturate(0.7) blur(0.8px);
  opacity: 0;
  transform: translate(-238%, -56%) scale(1.56) rotateY(26deg);
}

.dashboard-visual-stage:not(.is-progress) .dashboard-visual-stage__hologram-item--current {
  animation: dashboard-visual-stage-hologram-drift 5.8s ease-in-out infinite;
}

.dashboard-visual-stage.is-active .dashboard-visual-stage__hologram-item--current .dashboard-visual-stage__icon-shell {
  animation: dashboard-visual-stage-hologram-breathe 1.95s ease-in-out infinite;
}

.dashboard-visual-stage__icon-shell {
  position: relative;
  display: grid;
  width: 5.25rem;
  aspect-ratio: 1;
  place-items: center;
  border: 1px solid rgb(var(--stage-tone-rgb) / 0.42);
  border-radius: 12px;
  background:
    linear-gradient(180deg, rgb(255 255 255 / 0.1), transparent),
    rgb(var(--stage-tone-rgb) / 0.09);
  box-shadow:
    inset 0 0 1.25rem rgb(var(--stage-tone-rgb) / 0.12),
    0 0.85rem 2rem rgb(0 0 0 / 0.16);
}

.dashboard-visual-stage__icon-shell::after {
  content: '';
  position: absolute;
  inset: 0.45rem;
  border: 1px solid rgb(var(--stage-tone-rgb) / 0.18);
  border-radius: 9px;
}

.dashboard-visual-stage__icon {
  position: relative;
  z-index: 1;
  width: 3.95rem;
  height: 3.95rem;
  fill: rgb(var(--stage-tone-rgb) / 0.08);
  stroke: currentColor;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 3.6px;
}

.dashboard-visual-stage__signal {
  position: absolute;
  right: 1rem;
  bottom: 0.85rem;
  left: 1rem;
  height: 0.18rem;
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
  animation: dashboard-visual-stage-signal-scan 1.35s ease-in-out infinite;
}

.dashboard-visual-stage__copy {
  min-width: 0;
  max-width: 34rem;
}

.dashboard-visual-stage__copy.is-preconnect {
  align-self: center;
}

.dashboard-visual-stage.is-progress .dashboard-visual-stage__copy {
  display: flex;
  min-height: 0;
  flex-direction: column;
  align-self: center;
  justify-content: center;
}

.dashboard-visual-stage__state {
  color: var(--stage-tone);
  font-size: 0.78rem;
  font-weight: 700;
  letter-spacing: 0;
  line-height: 1.1rem;
}

.dashboard-visual-stage__headline {
  margin-top: 0.42rem;
  color: var(--color-foreground);
  font-size: clamp(1.28rem, 2.9vw, 2.1rem);
  font-weight: 750;
  letter-spacing: 0;
  line-height: 1.08;
}

.dashboard-visual-stage__detail {
  display: -webkit-box;
  margin-top: 0.65rem;
  overflow: hidden;
  color: var(--color-muted);
  font-size: 0.88rem;
  line-height: 1.48;
  -webkit-box-orient: vertical;
  -webkit-line-clamp: 3;
}

.dashboard-visual-stage__preconnect {
  display: grid;
  gap: 0.58rem;
  margin-top: 0;
}

.dashboard-visual-stage__preconnect-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.44rem 0.5rem;
}

.dashboard-visual-stage__preconnect-item {
  display: grid;
  min-width: 0;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  gap: 0.45rem;
  border: 1px solid rgb(var(--color-muted-rgb) / 0.16);
  border-radius: 8px;
  background: rgb(var(--color-background-rgb) / 0.34);
  padding: 0.38rem 0.48rem;
  font-size: 0.72rem;
  line-height: 1rem;
}

.dashboard-visual-stage__preconnect-item span {
  color: var(--color-muted);
  white-space: nowrap;
}

.dashboard-visual-stage__preconnect-item strong {
  min-width: 0;
  overflow: hidden;
  color: var(--color-foreground);
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 700;
}

.dashboard-visual-stage__preconnect-item--reconnect {
  grid-template-columns: auto minmax(5.5rem, 1fr);
}

.dashboard-visual-stage__reconnect-controls {
  display: inline-flex;
  min-width: 0;
  align-items: center;
  justify-self: start;
  gap: 0.38rem;
}

.dashboard-visual-stage__retry-input {
  width: 3.8rem;
  min-width: 0;
  border: 1px solid rgb(var(--stage-tone-rgb) / 0.24);
  border-radius: 6px;
  background: rgb(var(--stage-tone-rgb) / 0.08);
  color: var(--color-foreground);
  padding: 0.08rem 0.34rem;
  font-size: 0.72rem;
  font-weight: 700;
  line-height: 1rem;
}

.dashboard-visual-stage__retry-input:disabled {
  color: var(--color-muted);
  opacity: 0.58;
}

.dashboard-visual-stage__controls {
  display: flex;
  min-width: 0;
  flex-wrap: wrap;
  gap: 0.45rem;
}

.dashboard-visual-stage__choice,
.dashboard-visual-stage__button {
  display: inline-flex;
  min-width: 0;
  min-height: 1.82rem;
  align-items: center;
  gap: 0.42rem;
  border: 1px solid var(--color-border);
  border-radius: 9999px;
  background: rgb(var(--stage-tone-rgb) / 0.07);
  color: var(--color-muted);
  padding: 0.3rem 0.58rem;
  font-size: 0.72rem;
  line-height: 1rem;
}

.dashboard-visual-stage__choice span,
.dashboard-visual-stage__button span {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.dashboard-visual-stage__button {
  color: var(--color-foreground);
  font-weight: 600;
  transition: background-color 160ms ease, border-color 160ms ease, color 160ms ease;
}

.dashboard-visual-stage__button:hover:not(:disabled) {
  border-color: rgb(var(--color-accent-rgb) / 0.44);
  background: rgb(var(--color-accent-rgb) / 0.12);
  color: var(--color-accent);
}

.dashboard-visual-stage__button:disabled {
  cursor: not-allowed;
  opacity: 0.52;
}

.dashboard-visual-stage__choice:has(input:disabled) {
  cursor: not-allowed;
  opacity: 0.52;
}

.dashboard-visual-stage.is-progress .dashboard-visual-stage__detail {
  -webkit-line-clamp: 2;
}

.dashboard-visual-stage__steps {
  display: grid;
  flex: 0 1 auto;
  min-height: 0;
  max-height: clamp(6rem, 22vh, 9rem);
  align-content: start;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0.34rem 0.72rem;
  overflow: auto;
  margin: 0.82rem 0 0;
  padding: 0 0.25rem 0 0;
  list-style: none;
  scrollbar-width: thin;
}

.dashboard-visual-stage__step {
  display: grid;
  min-height: 1.28rem;
  grid-template-columns: 1.08rem minmax(0, 1fr);
  align-items: center;
  gap: 0.38rem;
  color: var(--color-muted);
  font-size: 0.72rem;
  line-height: 1rem;
}

.dashboard-visual-stage__step--done,
.dashboard-visual-stage__step--active {
  color: var(--color-foreground);
}

.dashboard-visual-stage__step--skipped {
  opacity: 0.48;
}

.dashboard-visual-stage__step-label {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 650;
}

.dashboard-visual-stage__step-indicator {
  display: grid;
  width: 1.05rem;
  height: 1.05rem;
  place-items: center;
  border: 1px solid;
  border-radius: 9999px;
  color: var(--color-muted);
  font-size: 0.64rem;
  font-weight: 800;
  line-height: 1;
}

.dashboard-visual-stage__step-indicator svg {
  width: 0.78rem;
  height: 0.78rem;
  fill: none;
  stroke: currentColor;
  stroke-linecap: round;
  stroke-linejoin: round;
  stroke-width: 2.2px;
}

.dashboard-visual-stage__step-indicator--pending {
  background: rgb(var(--color-muted-rgb) / 0.08);
  color: var(--color-muted);
}

.dashboard-visual-stage__step-indicator--active {
  background: rgb(var(--stage-tone-rgb) / 0.1);
  color: var(--stage-tone);
}

.dashboard-visual-stage__step-indicator--done {
  background: rgb(var(--color-success-rgb) / 0.1);
  color: var(--color-success);
}

.dashboard-visual-stage__step-indicator--failed {
  background: rgb(var(--color-warning-rgb) / 0.12);
  color: var(--color-warning);
}

.dashboard-visual-stage__step-indicator--skipped {
  background: transparent;
  color: var(--color-muted);
  opacity: 0.6;
}

.dashboard-visual-stage__status-spinner {
  width: 0.62rem;
  height: 0.62rem;
  border: 2px solid;
  border-top-color: transparent;
  border-radius: 9999px;
  animation: dashboard-visual-stage-status-spin 780ms linear infinite;
}

@keyframes dashboard-visual-stage-hologram-scan {
  0%,
  100% {
    opacity: 0.18;
    transform: translateY(-1.25rem);
  }

  50% {
    opacity: 0.72;
    transform: translateY(3.5rem);
  }
}

@keyframes dashboard-visual-stage-hologram-drift {
  0%,
  100% {
    transform: translate(-50%, -53%) scale(1);
  }

  50% {
    transform: translate(-50%, -57%) scale(1.025);
  }
}

@keyframes dashboard-visual-stage-hologram-breathe {
  0%,
  100% {
    box-shadow:
      inset 0 0 1.25rem rgb(var(--stage-tone-rgb) / 0.12),
      0 0.85rem 2rem rgb(0 0 0 / 0.16);
  }

  50% {
    box-shadow:
      inset 0 0 1.65rem rgb(var(--stage-tone-rgb) / 0.22),
      0 0.85rem 2.35rem rgb(var(--stage-tone-rgb) / 0.24);
  }
}

@keyframes dashboard-visual-stage-signal-scan {
  0% {
    transform: translateX(0);
  }

  100% {
    transform: translateX(380%);
  }
}

@keyframes dashboard-visual-stage-status-spin {
  100% {
    transform: rotate(360deg);
  }
}

@media (max-width: 720px) {
  .dashboard-visual-stage {
    grid-template-columns: minmax(0, 1fr);
    align-content: center;
  }

  .dashboard-visual-stage__viewport {
    min-height: 10rem;
  }

  .dashboard-visual-stage__hologram {
    width: min(16rem, 88%);
  }

  .dashboard-visual-stage__steps {
    flex: none;
    grid-template-columns: minmax(0, 1fr);
    max-height: none;
  }

  .dashboard-visual-stage__preconnect-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}

@media (prefers-reduced-motion: reduce) {
  .dashboard-visual-stage__hologram-item,
  .dashboard-visual-stage__hologram-item--current,
  .dashboard-visual-stage__hologram-transition-enter-active,
  .dashboard-visual-stage__hologram-transition-leave-active,
  .dashboard-visual-stage__hologram-transition-move,
  .dashboard-visual-stage__icon-shell,
  .dashboard-visual-stage__hologram-scan,
  .dashboard-visual-stage__signal::after,
  .dashboard-visual-stage__status-spinner {
    transition: none !important;
    animation: none !important;
  }

  .dashboard-visual-stage__hologram-scan {
    opacity: 0.44;
    transform: translateY(1.25rem);
  }

  .dashboard-visual-stage__signal::after {
    transform: translateX(170%);
  }

  .dashboard-visual-stage__status-spinner {
    border-top-color: currentColor;
  }
}
</style>
