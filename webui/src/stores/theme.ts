import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

export type ThemeMode = 'light' | 'dark' | 'system'
export type ThemeAccentTheme = 'light' | 'dark'
export type LightAccentKey = 'blue' | 'red' | 'cyan'
export type DarkAccentKey = 'sky' | 'violet' | 'green'
export type ThemeAccentKey = LightAccentKey | DarkAccentKey

export interface ThemeAccentOption {
  key: ThemeAccentKey
  label: string
  description: string
  color: string
  rgb: string
}

const STORAGE_KEY = 'exv:theme-mode'
const LIGHT_ACCENT_STORAGE_KEY = 'exv:accent-light'
const DARK_ACCENT_STORAGE_KEY = 'exv:accent-dark'

export const themeAccentPalettes: Record<ThemeAccentTheme, ThemeAccentOption[]> = {
  light: [
    {
      key: 'red',
      label: '校徽红',
      description: '标准校徽红，适合浅色默认高亮。',
      color: '#A41F35',
      rgb: '164 31 53',
    },
    {
      key: 'blue',
      label: '教学蓝',
      description: '清晰、稳重。',
      color: '#2563EB',
      rgb: '37 99 235',
    },
    {
      key: 'cyan',
      label: '湖青',
      description: '更轻快，适合长时间查看。',
      color: '#0891B2',
      rgb: '8 145 178',
    },
  ],
  dark: [
    {
      key: 'sky',
      label: '夜航蓝',
      description: '比绿色更冷静，深色默认。',
      color: '#38BDF8',
      rgb: '56 189 248',
    },
    {
      key: 'violet',
      label: '紫电',
      description: '更有科技感，但不抢文字。',
      color: '#A78BFA',
      rgb: '167 139 250',
    },
    {
      key: 'green',
      label: '原始绿',
      description: '保留旧版强调色。',
      color: '#22C55E',
      rgb: '34 197 94',
    },
  ],
}

function isThemeMode(value: string | null): value is ThemeMode {
  return value === 'light' || value === 'dark' || value === 'system'
}

function isLightAccentKey(value: string | null): value is LightAccentKey {
  return value === 'blue' || value === 'red' || value === 'cyan'
}

function isDarkAccentKey(value: string | null): value is DarkAccentKey {
  return value === 'sky' || value === 'violet' || value === 'green'
}

export const useThemeStore = defineStore('theme', () => {
  const mode = ref<ThemeMode>('system')
  const lightAccent = ref<LightAccentKey>('red')
  const darkAccent = ref<DarkAccentKey>('sky')
  const systemDark = ref(true)
  let initialized = false

  const effectiveTheme = computed<'light' | 'dark'>(() => {
    if (mode.value === 'system') return systemDark.value ? 'dark' : 'light'
    return mode.value
  })

  const effectiveAccent = computed(() => {
    return currentAccent()
  })

  function currentAccent() {
    const themeName = effectiveTheme.value
    const selectedKey = themeName === 'light' ? lightAccent.value : darkAccent.value
    return themeAccentPalettes[themeName].find((option) => option.key === selectedKey) ?? themeAccentPalettes[themeName][0]
  }

  function applyTheme() {
    if (typeof document === 'undefined') return
    document.documentElement.dataset.theme = effectiveTheme.value
    document.documentElement.dataset.themeMode = mode.value
    document.documentElement.style.colorScheme = effectiveTheme.value
    const accent = currentAccent()
    document.documentElement.style.setProperty('--color-accent', accent.color)
    document.documentElement.style.setProperty('--color-accent-rgb', accent.rgb)
  }

  function setThemeMode(nextMode: ThemeMode) {
    mode.value = nextMode
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem(STORAGE_KEY, nextMode)
    }
    applyTheme()
  }

  function setAccent(themeName: ThemeAccentTheme, accentKey: string) {
    if (themeName === 'light') {
      if (!isLightAccentKey(accentKey)) return
      lightAccent.value = accentKey
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(LIGHT_ACCENT_STORAGE_KEY, accentKey)
      }
    } else {
      if (!isDarkAccentKey(accentKey)) return
      darkAccent.value = accentKey
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(DARK_ACCENT_STORAGE_KEY, accentKey)
      }
    }
    applyTheme()
  }

  function initialize() {
    if (initialized) {
      applyTheme()
      return
    }
    initialized = true

    if (typeof localStorage !== 'undefined') {
      const stored = localStorage.getItem(STORAGE_KEY)
      if (isThemeMode(stored)) {
        mode.value = stored
      }
      const storedLightAccent = localStorage.getItem(LIGHT_ACCENT_STORAGE_KEY)
      if (isLightAccentKey(storedLightAccent)) {
        lightAccent.value = storedLightAccent
      }
      const storedDarkAccent = localStorage.getItem(DARK_ACCENT_STORAGE_KEY)
      if (isDarkAccentKey(storedDarkAccent)) {
        darkAccent.value = storedDarkAccent
      }
    }

    if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
      systemDark.value = mediaQuery.matches
      mediaQuery.addEventListener('change', (event) => {
        systemDark.value = event.matches
        applyTheme()
      })
    }

    applyTheme()
  }

  return {
    mode,
    lightAccent,
    darkAccent,
    systemDark,
    effectiveTheme,
    effectiveAccent,
    themeAccentPalettes,
    initialize,
    setThemeMode,
    setAccent,
  }
})
