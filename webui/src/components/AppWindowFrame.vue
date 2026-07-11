<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { Minus, X } from 'lucide-vue-next'
import appIconUrl from '../assets/app-icon.svg'
import ModeSegmentedControl from './ModeSegmentedControl.vue'
import TitlebarThemeModeControl from './TitlebarThemeModeControl.vue'
import { useConfigStore } from '../stores/config'
import { useThemeStore, type ThemeMode } from '../stores/theme'
import type { DesktopWindowControl } from '../types/exv'

type WindowMode = 'advanced' | 'minimal'
type TransitionPhase = 'idle' | 'native-resize' | 'settling'

const POST_RESIZE_SETTLE_MS = 50
const HOST_RESIZE_TIMEOUT_MS = 1200

const props = defineProps<{
  mode: WindowMode
}>()

const config = useConfigStore()
const theme = useThemeStore()
const appliedMode = ref<WindowMode>(props.mode)
const visualMode = ref<WindowMode>(props.mode)
const transitionPhase = ref<TransitionPhase>('idle')
const nativeWindowControlState = ref<{
  control: DesktopWindowControl | null
  pressed: boolean
}>({ control: null, pressed: false })
let windowModeRequest = 0
let windowControlUnsubscribe: (() => void) | null = null

const isMac = computed(() => {
  if (typeof navigator === 'undefined') return false
  return navigator.platform.toLowerCase().includes('mac')
})

const isWindows = computed(() => !isMac.value)
const transitionActive = computed(() => transitionPhase.value !== 'idle')
const titlebarTitle = computed(() => visualMode.value === 'minimal' ? 'EXV' : 'EXV')
const frameClass = computed(() => [
  'app-window-frame',
  `app-window-frame--${visualMode.value}`,
  isMac.value ? 'app-window-frame--mac' : 'app-window-frame--windows',
  transitionActive.value ? 'app-window-frame--transitioning' : '',
])

function wait(ms: number) {
  return new Promise<void>((resolve) => window.setTimeout(resolve, ms))
}

function isDesktopWindowControl(value: unknown): value is DesktopWindowControl {
  return value === 'minimize' || value === 'close'
}

function windowControlButtonClass(control: DesktopWindowControl) {
  return {
    'app-window-titlebar__button--native-hover':
      nativeWindowControlState.value.control === control,
    'app-window-titlebar__button--native-pressed':
      nativeWindowControlState.value.control === control &&
      nativeWindowControlState.value.pressed,
  }
}

async function resizeNativeWindow(mode: WindowMode, request: number) {
  const resize = window.exv?.window?.resizeForMode ?? window.exv?.window?.setMode
  if (!resize) return
  await Promise.race([
    resize(mode, request),
    wait(HOST_RESIZE_TIMEOUT_MS).then(() => {
      throw new Error('window resize timed out')
    }),
  ])
}

async function syncInitialWindowMode() {
  const request = ++windowModeRequest
  appliedMode.value = props.mode
  visualMode.value = props.mode
  transitionPhase.value = 'idle'
  try {
    await resizeNativeWindow(props.mode, request)
    if (request !== windowModeRequest) return
    appliedMode.value = props.mode
    visualMode.value = props.mode
  } catch (error) {
    console.error('[window] initial mode sync failed:', error)
  } finally {
    if (request === windowModeRequest) {
      transitionPhase.value = 'idle'
    }
  }
}

async function runModeTransition(nextMode: WindowMode) {
  const request = ++windowModeRequest
  if (appliedMode.value === nextMode) {
    visualMode.value = nextMode
    transitionPhase.value = 'idle'
    return
  }

  try {
    transitionPhase.value = 'native-resize'
    visualMode.value = nextMode
    await resizeNativeWindow(nextMode, request)
    if (request !== windowModeRequest) return
    transitionPhase.value = 'settling'
    await wait(POST_RESIZE_SETTLE_MS)
    if (request !== windowModeRequest) return
    appliedMode.value = nextMode
    visualMode.value = nextMode
  } catch (error) {
    console.error('[window] mode transition failed:', error)
    visualMode.value = appliedMode.value
  } finally {
    if (request === windowModeRequest) {
      transitionPhase.value = 'idle'
    }
  }
}

async function minimizeWindow() {
  if (transitionActive.value) return
  await window.exv?.window?.minimize()
}

async function requestWindowClose() {
  if (transitionActive.value) return
  await window.exv?.window?.requestClose()
}

function handleTitlebarModeChange(mode: WindowMode) {
  if (mode === props.mode) return
  void config.saveSettings({ minimal_mode: mode === 'minimal' })
}

function handleTitlebarThemeModeChange(mode: ThemeMode) {
  theme.setThemeMode(mode)
}

function startWindowDrag(event: PointerEvent) {
  if (isWindows.value) return
  if (event.button !== 0) return
  const target = event.target instanceof Element ? event.target : null
  if (target?.closest('[data-window-control-region="true"], button, a, input, textarea, select')) {
    return
  }
  event.preventDefault()
  void window.exv?.window?.startDrag?.({
    screenX: event.screenX,
    screenY: event.screenY,
    clientX: event.clientX,
    clientY: event.clientY,
    viewWidth: window.innerWidth,
  })
}

watch(
  () => props.mode,
  (nextMode) => {
    void runModeTransition(nextMode)
  },
)

onMounted(() => {
  appliedMode.value = props.mode
  visualMode.value = props.mode
  void syncInitialWindowMode()
  windowControlUnsubscribe = window.exv?.events.subscribe((event) => {
    if (event.type !== 'window-control-state') return
    const data = event.data
    if (!data || typeof data !== 'object') return
    const raw = data as { control?: unknown; pressed?: unknown }
    const control = isDesktopWindowControl(raw.control) ? raw.control : null
    const pressed = raw.pressed === true
    nativeWindowControlState.value = { control, pressed }
  }) ?? null
})

onUnmounted(() => {
  windowControlUnsubscribe?.()
  windowControlUnsubscribe = null
})
</script>

<template>
  <div :class="frameClass">
    <div class="app-window-transparent-host">
      <div class="mode-transition-surface">
        <header
          class="app-window-titlebar"
          data-window-drag-region="true"
          @pointerdown="startWindowDrag"
        >
          <div
            v-if="visualMode === 'minimal'"
            class="app-window-titlebar__identity"
            :aria-label="titlebarTitle"
          >
            <img class="app-window-titlebar__icon" :src="appIconUrl" alt="" />
            <span class="app-window-titlebar__title" aria-hidden="true">EXV</span>
          </div>
          <div class="app-window-titlebar__right" data-window-control-region="true">
            <div class="app-window-titlebar__toolbar">
              <TitlebarThemeModeControl
                class="app-window-titlebar__theme-control"
                :model-value="theme.mode"
                :disabled="transitionActive"
                :icon-only="visualMode === 'minimal'"
                @update:model-value="handleTitlebarThemeModeChange"
              />
              <ModeSegmentedControl
                class="app-window-titlebar__mode-control"
                :model-value="visualMode"
                :disabled="transitionActive"
                :icon-only="visualMode === 'minimal'"
                @update:model-value="handleTitlebarModeChange"
              />
            </div>
            <div
              v-if="isWindows"
              class="app-window-titlebar__controls"
            >
              <button
                type="button"
                class="app-window-titlebar__button"
                :class="windowControlButtonClass('minimize')"
                aria-label="最小化"
                :disabled="transitionActive"
                @click="minimizeWindow"
              >
                <Minus class="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                class="app-window-titlebar__button app-window-titlebar__button--close"
                :class="windowControlButtonClass('close')"
                aria-label="关闭"
                :disabled="transitionActive"
                @click="requestWindowClose"
              >
                <X class="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </header>

        <section class="app-window-content-shell">
          <slot />
        </section>
      </div>
    </div>
  </div>
</template>

<style scoped>
.app-window-frame {
  --titlebar-height: 34px;
  --advanced-width: 879px;
  --advanced-height: 563px;
  --minimal-width: 328px;
  --minimal-height: 136px;
  --mac-traffic-light-inset: 78px;
  --window-radius: 12px;
  --app-window-border-color: rgba(148, 163, 184, 0.32);
  --app-window-shadow-margin: 0px;
  --app-window-shadow-margin-total: 0px;
  --app-window-shadow:
    0 18px 42px -18px rgba(2, 6, 23, 0.64),
    0 10px 24px -18px rgba(15, 23, 42, 0.42),
    0 2px 8px rgba(0, 0, 0, 0.18);
  min-height: 100vh;
  overflow: hidden;
  background: transparent;
  color: inherit;
}

.app-window-transparent-host {
  min-height: 100vh;
  overflow: hidden;
  box-sizing: border-box;
  padding: var(--app-window-shadow-margin);
  background: transparent;
}

.mode-transition-surface {
  position: relative;
  overflow: hidden;
  width: calc(100vw - var(--app-window-shadow-margin-total));
  height: calc(100vh - var(--app-window-shadow-margin-total));
  box-sizing: border-box;
  border: 1px solid var(--app-window-border-color);
  border-radius: var(--window-radius);
  background: transparent;
  box-shadow: var(--app-window-shadow);
  transform-origin: top left;
}

.app-window-frame--minimal.app-window-frame--transitioning .mode-transition-surface {
  width: var(--minimal-width);
  height: var(--minimal-height);
}

.app-window-frame--advanced.app-window-frame--transitioning .mode-transition-surface {
  width: var(--advanced-width);
  height: var(--advanced-height);
}

.app-window-titlebar {
  position: absolute;
  z-index: 60;
  top: 0;
  right: 0;
  left: 0;
  display: flex;
  height: var(--titlebar-height);
  align-items: center;
  justify-content: space-between;
  padding: 4px 4px 4px 10px;
  user-select: none;
  app-region: drag;
  -webkit-app-region: drag;
  background: transparent;
  color: var(--titlebar-fg);
}

.app-window-frame--advanced .app-window-titlebar {
  left: 0;
  right: 0;
  justify-content: flex-end;
  padding: 0;
}

.app-window-frame--minimal .app-window-titlebar {
  position: relative;
  top: auto;
  right: auto;
  left: auto;
  padding: 0 0 0 10px;
  border-bottom: 0;
  background: var(--minimal-titlebar-bg);
}

.app-window-frame--mac .app-window-titlebar {
  padding-left: var(--mac-traffic-light-inset);
}

.app-window-titlebar__identity {
  display: flex;
  min-width: 0;
  height: 100%;
  align-items: center;
  gap: 8px;
}

.app-window-frame--advanced .app-window-titlebar__identity {
  display: none;
}

.app-window-titlebar__icon {
  flex: 0 0 auto;
  height: 18px;
  width: 18px;
}

.app-window-titlebar__title {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  line-height: 1;
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0;
}

.app-window-titlebar__right {
  display: flex;
  height: 100%;
  min-width: 0;
  margin-left: auto;
  align-items: center;
  gap: 12px;
  app-region: no-drag;
  -webkit-app-region: no-drag;
}

.app-window-titlebar__toolbar {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: 8px;
  app-region: no-drag;
  -webkit-app-region: no-drag;
}

.app-window-frame--minimal .app-window-titlebar__right {
  gap: 8px;
}

.app-window-frame--minimal .app-window-titlebar__toolbar {
  gap: 6px;
}

.app-window-titlebar__controls {
  display: flex;
  height: 100%;
  align-items: stretch;
  overflow: hidden;
  app-region: no-drag;
  -webkit-app-region: no-drag;
}

.app-window-titlebar__button {
  display: grid;
  width: 44px;
  place-items: center;
  app-region: no-drag;
  -webkit-app-region: no-drag;
  color: var(--titlebar-button-fg);
  transition: background-color 120ms ease, color 120ms ease;
}

.app-window-titlebar__button:hover:not(:disabled),
.app-window-titlebar__button--native-hover:not(:disabled) {
  background: var(--titlebar-button-hover-bg);
  color: var(--color-foreground);
}

.app-window-titlebar__button:active:not(:disabled),
.app-window-titlebar__button--native-pressed:not(:disabled) {
  background: var(--titlebar-button-hover-bg);
  filter: brightness(0.92);
}

.app-window-titlebar__button--close:hover:not(:disabled),
.app-window-titlebar__button--close.app-window-titlebar__button--native-hover:not(:disabled) {
  background: #dc2626;
  color: white;
}

.app-window-titlebar__button--close:active:not(:disabled),
.app-window-titlebar__button--close.app-window-titlebar__button--native-pressed:not(:disabled) {
  background: #b91c1c;
  color: white;
}

.app-window-titlebar__button:disabled {
  cursor: default;
  opacity: 0.45;
}

.app-window-content-shell {
  height: 100%;
  overflow: hidden;
  background: transparent;
}

.app-window-frame--advanced .app-window-content-shell {
  height: 100%;
}

.app-window-frame--minimal .app-window-content-shell {
  height: calc(100% - var(--titlebar-height));
}
</style>
