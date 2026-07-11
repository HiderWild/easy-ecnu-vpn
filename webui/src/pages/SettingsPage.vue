<script setup lang="ts">
import {
  computed,
  nextTick,
  onActivated,
  onBeforeUnmount,
  onDeactivated,
  onMounted,
  reactive,
  ref,
  watch,
  type Component,
  type ComponentPublicInstance,
} from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { onBeforeRouteLeave } from 'vue-router'
import {
  EthernetPort,
  Palette,
  Route as RouteIcon,
  Save,
  Settings,
  Shield,
} from 'lucide-vue-next'
import { useConfigStore, type AuthConfig, type SettingsConfig } from '../stores/config'
import { usePageStateStore } from '../stores/pageState'
import { useUiStore } from '../stores/ui'
import { normalizeError } from '../stores/vpn'
import SettingsAuthSection from './settings/SettingsAuthSection.vue'
import SettingsConnectionSection from './settings/SettingsConnectionSection.vue'
import SettingsPersonalizationSection from './settings/SettingsPersonalizationSection.vue'
import SettingsSystemSection from './settings/SettingsSystemSection.vue'
import SettingsRoutesSection from './settings/SettingsRoutesSection.vue'
import SettingsSectionAxis from './settings/SettingsSectionAxis.vue'
import {
  formatSettingValue,
  frontendOnlySettingsFields,
  frontendToBackendFieldMap,
  settingChangeKeys,
  settingFieldRegistry,
  type SettingChangeKey,
} from './settings/changeRegistry'
import type { SectionKey, SettingsSectionDescriptor } from './settings/types'

defineOptions({ name: 'SettingsPage' })

type SectionRecord = SettingsSectionDescriptor & { component: Component }

const route = useRoute()
const router = useRouter()
const config = useConfigStore()
const ui = useUiStore()
const pageState = usePageStateStore()

const sections: SectionRecord[] = [
  { key: 'auth', label: '认证', icon: Shield, component: SettingsAuthSection },
  { key: 'connection', label: '连接', icon: EthernetPort, component: SettingsConnectionSection },
  { key: 'personalization', label: '个性化', icon: Palette, component: SettingsPersonalizationSection },
  { key: 'system', label: '系统', icon: Settings, component: SettingsSystemSection },
  { key: 'routes', label: '路由', icon: RouteIcon, component: SettingsRoutesSection },
]

const scrollRoot = ref<HTMLElement | null>(null)
const activeSection = ref<SectionKey>('auth')
const sectionElements = new Map<SectionKey, HTMLElement>()
let scrollListenerAttached = false
let programmaticScroll = false
let restoreFrame: number | null = null
const savingSettings = ref(false)
const saveHover = ref(false)

function defaultAuthDraft(): AuthConfig {
  return {
    server: '',
    username: '',
    password: '',
    password_stored: false,
    user_agent: '',
    remember_password: false,
  }
}

function defaultSettingsDraft(): SettingsConfig {
  return {
    mtu: 1400,
    dtls: true,
    extra_args: '',
    log_path: '',
    webui_port: 18080,
    webui_host: '127.0.0.1',
    webui_enabled: true,
    vpn_engine: 'native',
    windows_tunnel_driver: 'auto',
    windows_tap_interface: '',
    auto_reconnect: true,
    retry_limit: -1,
    minimal_mode: false,
    service_install_prompt_seen: false,
    minimal_install_service_before_connect: true,
    include_class_a_private_routes: false,
    include_class_b_private_routes: false,
    launch_at_login: false,
    auto_connect_on_launch: false,
  }
}

const authDraft = reactive<AuthConfig>(defaultAuthDraft())
const settingsDraft = reactive<SettingsConfig>(defaultSettingsDraft())
const authBaseline = reactive<AuthConfig>(defaultAuthDraft())
const settingsBaseline = reactive<SettingsConfig>(defaultSettingsDraft())

function authDraftFromStore(): AuthConfig {
  return {
    ...config.authConfig,
    password: '',
    password_stored: config.authConfig.password_stored ?? false,
    remember_password: config.authConfig.remember_password ?? false,
  }
}

function setAuthDraft(next: AuthConfig) {
  Object.assign(authDraft, next)
  pageState.rememberSettingsDrafts(authDraft, settingsDraft, authBaseline, settingsBaseline)
}

function setSettingsDraft(next: SettingsConfig) {
  Object.assign(settingsDraft, next)
  pageState.rememberSettingsDrafts(authDraft, settingsDraft, authBaseline, settingsBaseline)
}

function copyDraftsToBaselines() {
  Object.assign(authBaseline, authDraft)
  Object.assign(settingsBaseline, settingsDraft)
  pageState.rememberSettingsDrafts(authDraft, settingsDraft, authBaseline, settingsBaseline)
}

function restoreCachedSettingsDrafts() {
  const cached = pageState.settings
  if (!cached.authDraft || !cached.settingsDraft || !cached.authBaseline || !cached.settingsBaseline) {
    return false
  }
  Object.assign(authDraft, cached.authDraft)
  Object.assign(settingsDraft, cached.settingsDraft)
  Object.assign(authBaseline, cached.authBaseline)
  Object.assign(settingsBaseline, cached.settingsBaseline)
  activeSection.value = cached.activeSection as SectionKey
  return true
}

async function loadSettingsDrafts() {
  await Promise.all([config.fetchAuthConfig(), config.fetchSettings()])
  Object.assign(authDraft, authDraftFromStore())
  Object.assign(settingsDraft, config.settings)
  copyDraftsToBaselines()
}

function sectionProps(key: SectionKey) {
  if (key === 'auth') return { authDraft }
  if (key === 'connection' || key === 'system' || key === 'routes') return { settingsDraft }
  return {}
}

function readSettingField(source: 'draft' | 'baseline', key: SettingChangeKey) {
  const descriptor = settingFieldRegistry[key]
  const root = source === 'draft'
    ? { auth: authDraft, settings: settingsDraft }
    : { auth: authBaseline, settings: settingsBaseline }
  return (root[descriptor.group] as Record<string, unknown>)[descriptor.field]
}

const dirtyChanges = computed(() => settingChangeKeys.flatMap((key) => {
  const previous = readSettingField('baseline', key)
  const current = readSettingField('draft', key)
  if (Object.is(previous, current)) return []
  return [{
    key,
    label: settingFieldRegistry[key].label,
    previous,
    current,
  }]
}))

const pendingChangeRows = computed(() => dirtyChanges.value.map((change) => ({
  key: change.key,
  text: `${change.label}: ${formatSettingValue(change.key, change.previous)} -> ${formatSettingValue(change.key, change.current)}`,
})))

watch(
  () => [
    authDraft.username,
    authDraft.password,
    authDraft.password_stored,
    authDraft.remember_password,
  ],
  () => {
    const hasRememberedPasswordDraft =
      authDraft.remember_password &&
      authDraft.username.trim().length > 0 &&
      (authDraft.password.trim().length > 0 || Boolean(authDraft.password_stored))
    if (!hasRememberedPasswordDraft && settingsDraft.auto_connect_on_launch) {
      settingsDraft.auto_connect_on_launch = false
      pageState.rememberSettingsDrafts(authDraft, settingsDraft, authBaseline, settingsBaseline)
    }
  },
)

function buildDirtyBackendPayloads() {
  const authPayload: Partial<AuthConfig> = {}
  const settingsPayload: Partial<SettingsConfig> = {}
  let frontendOnlyChanged = false

  for (const change of dirtyChanges.value) {
    if (change.key in frontendOnlySettingsFields) {
      frontendOnlyChanged = true
      continue
    }
    const descriptor = frontendToBackendFieldMap[change.key as keyof typeof frontendToBackendFieldMap]
    if (!descriptor) continue

    if (descriptor.backendGroup === 'auth') {
      ;(authPayload as Record<string, unknown>)[descriptor.backendField] = change.current
    } else {
      ;(settingsPayload as Record<string, unknown>)[descriptor.backendField] = change.current
    }
  }

  return { authPayload, settingsPayload, frontendOnlyChanged }
}

async function saveDirtyChanges() {
  if (!dirtyChanges.value.length || savingSettings.value) return
  const { authPayload, settingsPayload, frontendOnlyChanged } = buildDirtyBackendPayloads()
  const authChanged = Object.keys(authPayload).length > 0
  const settingsChanged = Object.keys(settingsPayload).length > 0

  const nextUsername = String(authPayload.username ?? authDraft.username).trim()
  const nextRememberPassword = Boolean(authPayload.remember_password ?? authDraft.remember_password)
  if (!nextUsername && nextRememberPassword) {
    ui.requestError({
      title: '保存修改失败',
      message: '请输入用户名后再开启记住密码',
    })
    return
  }

  savingSettings.value = true
  try {
    if (authChanged) {
      await config.saveAuthConfig(authPayload)
      Object.assign(authDraft, authDraftFromStore())
    }
    if (settingsChanged) {
      await config.saveSettings(settingsPayload)
      Object.assign(settingsDraft, config.settings)
    }
    void frontendOnlyChanged
    copyDraftsToBaselines()
    saveHover.value = false
    ui.addToast('设置修改已保存', 'success')
  } catch (error) {
    const normalized = normalizeError(error)
    if (normalized.recommended_action === 'restart_core' && window.exv?.core.restart) {
      ui.requestError({
        title: '保存修改失败',
        message: normalized.message,
        primaryLabel: '重启内核并重试',
        onPrimary: async () => {
          try {
            await window.exv?.core.restart?.()
            await saveDirtyChanges()
          } catch (restartError) {
            ui.requestError({
              title: '重启内核失败',
              message: normalizeError(restartError).message,
            })
          }
        },
      })
    } else {
      ui.requestError({ title: '保存修改失败', message: normalized.message })
    }
  } finally {
    savingSettings.value = false
  }
}

function setSectionElement(key: SectionKey, el: Element | ComponentPublicInstance | null) {
  if (el instanceof HTMLElement) {
    sectionElements.set(key, el)
    return
  }
  sectionElements.delete(key)
}

function sectionElement(key: SectionKey) {
  return sectionElements.get(key) ?? null
}

function sectionHash(key: SectionKey) {
  return `#settings-${key}`
}

function sectionFromHash(hash: unknown): SectionKey | null {
  if (hash === '#settings-auth' || hash === '#auth') return 'auth'
  if (hash === '#settings-connection' || hash === '#connection') return 'connection'
  if (hash === '#settings-personalization' || hash === '#personalization') return 'personalization'
  if (hash === '#settings-system' || hash === '#system') return 'system'
  if (hash === '#settings-routes' || hash === '#routes') return 'routes'
  return null
}

function sectionFromQuery(value: unknown): SectionKey | null {
  const section = Array.isArray(value) ? value[0] : value
  return section === 'auth' ||
    section === 'connection' ||
    section === 'personalization' ||
    section === 'system' ||
    section === 'routes'
    ? section
    : null
}

function explicitSection(): SectionKey | null {
  return sectionFromHash(route.hash) || sectionFromQuery(route.query.section)
}

function updateActiveSection() {
  const root = scrollRoot.value
  if (!root) return

  const rootRect = root.getBoundingClientRect()
  const threshold = rootRect.top + Math.min(180, root.clientHeight * 0.35)
  let next = activeSection.value

  for (const section of sections) {
    const el = sectionElement(section.key)
    if (!el) continue
    if (el.getBoundingClientRect().top <= threshold) {
      next = section.key
    }
  }
  if (root.scrollTop + root.clientHeight >= root.scrollHeight - 12) {
    next = sections[sections.length - 1].key
  }
  activeSection.value = next
  pageState.settings.activeSection = next
  if (!programmaticScroll) {
    pageState.rememberSettingsScroll(root.scrollTop, next)
  }
}

function rememberCurrentSettingsScroll() {
  const root = scrollRoot.value
  if (!root) return
  if (
    root.scrollTop === 0 &&
    activeSection.value !== 'auth' &&
    pageState.settings.scrollTop > 0
  ) {
    return
  }
  pageState.rememberSettingsScroll(root.scrollTop, activeSection.value)
}

function hasRememberedSettingsScroll() {
  return pageState.settings.userInteracted || pageState.settings.scrollTop > 0
}

function markProgrammaticScroll() {
  programmaticScroll = true
  if (typeof window !== 'undefined') {
    window.setTimeout(() => {
      programmaticScroll = false
    }, 120)
  } else {
    programmaticScroll = false
  }
}

function attachScrollListener() {
  if (scrollListenerAttached) return
  if (!scrollRoot.value) return
  scrollRoot.value.addEventListener('scroll', updateActiveSection, { passive: true })
  scrollListenerAttached = true
}

function detachScrollListener() {
  if (!scrollListenerAttached) return
  scrollRoot.value?.removeEventListener('scroll', updateActiveSection)
  scrollListenerAttached = false
}

async function scrollToSection(
  key: SectionKey,
  updateRoute = true,
  behavior: ScrollBehavior = 'smooth',
) {
  await nextTick()
  markProgrammaticScroll()
  sectionElement(key)?.scrollIntoView({ behavior, block: 'start' })
  activeSection.value = key
  pageState.settings.activeSection = key
  if (updateRoute) {
    pageState.settings.userInteracted = true
  }
  if (updateRoute) {
    router.replace({ path: '/settings', hash: sectionHash(key) })
  }
}

function restoreSettingsScroll() {
  const root = scrollRoot.value
  if (!root) return
  markProgrammaticScroll()
  root.scrollTop = pageState.settings.scrollTop
  activeSection.value = pageState.settings.activeSection as SectionKey
}

function scheduleRestoreSettingsScroll() {
  if (typeof window === 'undefined') {
    restoreSettingsScroll()
    return
  }
  if (restoreFrame !== null) {
    window.cancelAnimationFrame(restoreFrame)
  }
  restoreFrame = window.requestAnimationFrame(() => {
    restoreSettingsScroll()
    restoreFrame = window.requestAnimationFrame(() => {
      restoreSettingsScroll()
      restoreFrame = null
    })
  })
}

onMounted(async () => {
  if (!restoreCachedSettingsDrafts()) {
    await loadSettingsDrafts()
  }
  attachScrollListener()
  const section = explicitSection()
  if (hasRememberedSettingsScroll()) {
    scheduleRestoreSettingsScroll()
    return
  } else if (section) {
    await scrollToSection(section, false, 'auto')
  } else {
    activeSection.value = 'auth'
    markProgrammaticScroll()
    scrollRoot.value?.scrollTo({ top: 0, behavior: 'auto' })
  }
  updateActiveSection()
})

onActivated(() => {
  attachScrollListener()
  void nextTick(() => {
    if (hasRememberedSettingsScroll()) {
      scheduleRestoreSettingsScroll()
      return
    }
    if (explicitSection()) return
    scheduleRestoreSettingsScroll()
  })
})

onDeactivated(() => {
  rememberCurrentSettingsScroll()
  pageState.rememberSettingsDrafts(authDraft, settingsDraft, authBaseline, settingsBaseline)
  detachScrollListener()
})

onBeforeUnmount(() => {
  rememberCurrentSettingsScroll()
  if (restoreFrame !== null && typeof window !== 'undefined') {
    window.cancelAnimationFrame(restoreFrame)
    restoreFrame = null
  }
  detachScrollListener()
})

onBeforeRouteLeave(() => {
  rememberCurrentSettingsScroll()
  pageState.rememberSettingsDrafts(authDraft, settingsDraft, authBaseline, settingsBaseline)
})

watch(
  () => [route.hash, route.query.section],
  () => {
    if (route.path !== '/settings') return
    const section = explicitSection()
    if (section) {
      scrollToSection(section, false, 'auto')
    }
  },
)
</script>

<template>
  <div class="relative h-full overflow-hidden">
    <div class="flex h-full flex-col pr-8">
      <header class="settings-header shrink-0 border-b border-border/70 bg-bg/95 py-3 backdrop-blur">
        <div class="mx-auto flex max-w-4xl items-center gap-4">
          <h1 class="text-3xl font-semibold text-foreground">设置</h1>

          <div class="relative">
            <button
              v-if="dirtyChanges.length"
              type="button"
              :disabled="savingSettings"
              class="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent/90 disabled:opacity-50"
              @mouseenter="saveHover = true"
              @mouseleave="saveHover = false"
              @focus="saveHover = true"
              @blur="saveHover = false"
              @click="saveDirtyChanges"
            >
              <Save class="h-4 w-4" />
              {{ savingSettings ? '保存中...' : '保存修改' }}
            </button>

            <div
              v-if="dirtyChanges.length && saveHover"
              class="settings-save-popover absolute left-0 top-full z-[80] mt-2 w-80 rounded-lg border border-border bg-surface p-3 text-xs text-foreground shadow-xl"
            >
              <p class="mb-2 font-medium">待保存修改</p>
              <div class="space-y-1.5">
                <p
                  v-for="row in pendingChangeRows"
                  :key="row.key"
                  class="truncate text-muted"
                >
                  {{ row.text }}
                </p>
              </div>
            </div>
          </div>
        </div>
      </header>

      <div ref="scrollRoot" class="settings-scroll settings-scroll-body min-h-0 flex-1 overflow-y-auto py-4">
        <div class="mx-auto max-w-4xl space-y-5">
          <section
            v-for="section in sections"
            :id="sectionHash(section.key).slice(1)"
            :key="section.key"
            :ref="(el) => setSectionElement(section.key, el)"
            class="scroll-mt-4"
          >
            <component
              :is="section.component"
              v-bind="sectionProps(section.key)"
              @update:auth-draft="setAuthDraft"
              @update:settings-draft="setSettingsDraft"
              @reload-settings="loadSettingsDrafts"
            />
          </section>
        </div>
      </div>
    </div>

    <SettingsSectionAxis
      :sections="sections"
      :active-section="activeSection"
      @select="(key) => scrollToSection(key)"
    />
  </div>
</template>

<style scoped>
.settings-scroll {
  scrollbar-width: none;
  -ms-overflow-style: none;
}

.settings-scroll::-webkit-scrollbar {
  display: none;
}
</style>
