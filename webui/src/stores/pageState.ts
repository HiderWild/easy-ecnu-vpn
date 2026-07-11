import { defineStore } from 'pinia'
import { reactive } from 'vue'
import type { AuthConfig, SettingsConfig } from './config'

type SettingsSectionName = 'auth' | 'connection' | 'personalization' | 'system' | 'routes'

export const usePageStateStore = defineStore('pageState', () => {
  const pageState = reactive({
    settings: {
      initialized: false,
      scrollTop: 0,
      userInteracted: false,
      activeSection: 'auth' as SettingsSectionName,
      authDraft: null as AuthConfig | null,
      settingsDraft: null as SettingsConfig | null,
      authBaseline: null as AuthConfig | null,
      settingsBaseline: null as SettingsConfig | null,
    },
    logs: {
      scrollTop: 0,
      userScrolled: false,
      autoScroll: true,
      levelFilter: 'all',
    },
  })

  function rememberSettingsDrafts(
    authDraft: AuthConfig,
    settingsDraft: SettingsConfig,
    authBaseline?: AuthConfig,
    settingsBaseline?: SettingsConfig,
  ) {
    pageState.settings.initialized = true
    pageState.settings.authDraft = { ...authDraft }
    pageState.settings.settingsDraft = { ...settingsDraft }
    if (authBaseline) pageState.settings.authBaseline = { ...authBaseline }
    if (settingsBaseline) pageState.settings.settingsBaseline = { ...settingsBaseline }
  }

  function rememberSettingsScroll(scrollTop: number, activeSection: SettingsSectionName) {
    pageState.settings.scrollTop = scrollTop
    pageState.settings.activeSection = activeSection
    pageState.settings.userInteracted = true
  }

  return {
    settings: pageState.settings,
    logs: pageState.logs,
    rememberSettingsDrafts,
    rememberSettingsScroll,
  }
})
