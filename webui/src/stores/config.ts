import { defineStore } from 'pinia'
import { ref } from 'vue'
import api from '../api/host'
import { distributionConfig } from '../generated/distribution'

export interface AuthConfig {
  server: string
  username: string
  // Empty string means "do not change the stored password". The UI uses
  // password_stored to know whether the backend currently holds an
  // encrypted password.
  password: string
  password_stored?: boolean
  user_agent: string
  remember_password: boolean
}

export type DtlsSettingsMode = 'auto' | 'enabled' | 'disabled'

export interface SettingsConfig {
  mtu: number
  dtls: boolean
  dtls_mode: DtlsSettingsMode
  extra_args: string
  log_path: string
  webui_port: number
  webui_host: string
  webui_enabled: boolean
  vpn_engine: 'native'
  windows_tunnel_driver: 'auto' | 'wintun' | 'tap'
  windows_tap_interface: string
  auto_reconnect: boolean
  retry_limit: number
  minimal_mode: boolean
  service_install_prompt_seen: boolean
  minimal_install_service_before_connect: boolean
  minimize_to_tray_on_connect: boolean
  include_class_a_private_routes: boolean
  include_class_b_private_routes: boolean
  launch_at_login: boolean
  auto_connect_on_launch: boolean
  silent_startup: boolean
  connection_state_notifications: boolean
}

export interface KeyStatus {
  available: boolean
  present: boolean
  status: string
}

export interface CoreInspection {
  state: string
  risk: 'unknown' | 'low' | 'medium' | 'high'
  pid?: number
  ipc_path?: string
}

export interface RuntimeStatus {
  mode: 'native'
  engine: 'native'
  available: boolean
  source: 'native'
  path: string
  version: string
  bundled_runtime_dir: string
  wintun_path?: string
  tap_installer_path?: string
  missing_what?: string
  recommended_action?: string
  effect_on_connect?: string
  wintun_missing?: boolean
  tap_missing?: boolean
}

export interface DriverStatus {
  preferred: 'auto' | 'wintun' | 'tap'
  tap_interface: string
  supported: boolean
  effective_driver?: 'wintun' | 'tap'
  wintun_bundled?: boolean
  wintun_path?: string
  wintun_adapters?: string[]
  wintun_missing?: boolean
  wintun_missing_reason?: string
  wintun_recommended_action?: string
  tap_installer_path?: string
  tap_can_install?: boolean
  tap_adapters?: string[]
  tap_available?: boolean
  tap_missing?: boolean
  tap_missing_reason?: string
  tap_recommended_action?: string
  effective_driver_status?: 'ready' | 'degraded' | 'unavailable'
}

export const useConfigStore = defineStore('config', () => {
  const dtlsModeStorageKey = 'exv:dtls-mode'
  type FrontendLocalBoolKey = 'exv:minimal-mode' | 'exv:minimize-to-tray-on-connect'

  function readLocalBool(key: FrontendLocalBoolKey, fallback: boolean) {
    if (typeof localStorage === 'undefined') return fallback
    const value = localStorage.getItem(key)
    if (value === 'true') return true
    if (value === 'false') return false
    return fallback
  }

  function writeLocalBool(key: FrontendLocalBoolKey, value: boolean) {
    if (typeof localStorage === 'undefined') return
    localStorage.setItem(key, value ? 'true' : 'false')
  }

  function normalizeDtlsMode(value: unknown): DtlsSettingsMode | null {
    return value === 'auto' || value === 'enabled' || value === 'disabled' ? value : null
  }

  function normalizeRetryLimit(value: unknown) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0
      ? Math.trunc(value)
      : 0
  }

  function readLocalDtlsMode(fallback: DtlsSettingsMode): DtlsSettingsMode {
    if (typeof localStorage === 'undefined') return fallback
    return normalizeDtlsMode(localStorage.getItem(dtlsModeStorageKey)) ?? fallback
  }

  function writeLocalDtlsMode(value: DtlsSettingsMode) {
    if (typeof localStorage === 'undefined') return
    localStorage.setItem(dtlsModeStorageKey, value)
  }

  function inferDtlsMode(next: SettingsConfig): DtlsSettingsMode {
    if (!next.dtls) return 'disabled'
    const remote = normalizeDtlsMode(next.dtls_mode)
    if (remote) return remote
    const stored = readLocalDtlsMode('auto')
    return stored === 'disabled' ? 'auto' : stored
  }

  function applyFrontendLocalSettings(next: SettingsConfig) {
    return {
      ...next,
      dtls_mode: inferDtlsMode(next),
      retry_limit: normalizeRetryLimit(next.retry_limit),
      minimal_mode: readLocalBool('exv:minimal-mode', next.minimal_mode),
      minimize_to_tray_on_connect: readLocalBool(
        'exv:minimize-to-tray-on-connect',
        next.minimize_to_tray_on_connect ?? false,
      ),
    }
  }

  function persistFrontendLocalSettings(s: Partial<SettingsConfig>) {
    if (Object.prototype.hasOwnProperty.call(s, 'minimal_mode') && s.minimal_mode != null) {
      writeLocalBool('exv:minimal-mode', s.minimal_mode)
    }
    if (
      Object.prototype.hasOwnProperty.call(s, 'minimize_to_tray_on_connect') &&
      s.minimize_to_tray_on_connect != null
    ) {
      writeLocalBool('exv:minimize-to-tray-on-connect', s.minimize_to_tray_on_connect)
    }
    if (Object.prototype.hasOwnProperty.call(s, 'dtls_mode')) {
      const mode = normalizeDtlsMode(s.dtls_mode)
      if (mode) writeLocalDtlsMode(mode)
    }
  }

  const authConfig = ref<AuthConfig>({
    server: distributionConfig.defaultVpnServer,
    username: '',
    password: '',
    password_stored: false,
    user_agent: '',
    remember_password: false,
  })

  const settings = ref<SettingsConfig>({
    mtu: 1400,
    dtls: true,
    dtls_mode: readLocalDtlsMode('auto'),
    extra_args: '',
    log_path: '',
    webui_port: 18080,
    webui_host: '127.0.0.1',
    webui_enabled: true,
    vpn_engine: 'native',
    windows_tunnel_driver: 'auto',
    windows_tap_interface: '',
    auto_reconnect: true,
    retry_limit: 0,
    minimal_mode: readLocalBool('exv:minimal-mode', false),
    service_install_prompt_seen: false,
    minimal_install_service_before_connect: true,
    minimize_to_tray_on_connect: readLocalBool('exv:minimize-to-tray-on-connect', false),
    include_class_a_private_routes: false,
    include_class_b_private_routes: false,
    launch_at_login: false,
    auto_connect_on_launch: false,
    silent_startup: false,
    connection_state_notifications: false,
  })

  const keyStatus = ref<KeyStatus>({ available: false, present: false, status: 'missing' })
  const runtimeStatus = ref<RuntimeStatus | null>(null)
  const driverStatus = ref<DriverStatus | null>(null)
  const authConfigLoaded = ref(false)
  const authConfigLoadError = ref<string | null>(null)
  const settingsLoaded = ref(false)
  const settingsLoadError = ref<string | null>(null)

  function loadErrorMessage(error: unknown) {
    return error instanceof Error ? error.message : String(error)
  }

  async function fetchAuthConfig() {
    try {
      const { data } = await api.get<AuthConfig>('/config/auth')
      authConfig.value = { ...authConfig.value, ...data }
      authConfigLoaded.value = true
      authConfigLoadError.value = null
      return true
    } catch (e) {
      authConfigLoadError.value = loadErrorMessage(e)
      console.error('[config] fetchAuthConfig failed:', e)
      return false
    }
  }

  async function saveAuthConfig(config: Partial<AuthConfig>) {
    const payload: Partial<AuthConfig> = {}
    if (Object.prototype.hasOwnProperty.call(config, 'server')) {
      payload.server = config.server ?? ''
    }
    if (Object.prototype.hasOwnProperty.call(config, 'username')) {
      payload.username = config.username ?? ''
    }
    if (Object.prototype.hasOwnProperty.call(config, 'password')) {
      payload.password = config.password ?? ''
    }
    if (Object.prototype.hasOwnProperty.call(config, 'remember_password')) {
      payload.remember_password = config.remember_password ?? false
    }
    if (Object.prototype.hasOwnProperty.call(config, 'user_agent')) {
      payload.user_agent = config.user_agent ?? ''
    }
    const { data } = await api.put<AuthConfig>('/config/auth', payload)
    authConfig.value = { ...authConfig.value, ...data }
    authConfigLoaded.value = true
    authConfigLoadError.value = null
  }

  async function fetchSettings() {
    try {
      const { data } = await api.get<SettingsConfig>('/config/settings')
      settings.value = applyFrontendLocalSettings({ ...settings.value, ...data })
      settingsLoaded.value = true
      settingsLoadError.value = null
      return true
    } catch (e) {
      settingsLoadError.value = loadErrorMessage(e)
      console.error('[config] fetchSettings failed:', e)
      return false
    }
  }

  async function saveSettings(input: Partial<SettingsConfig>) {
    const s = { ...input }
    if (Object.prototype.hasOwnProperty.call(s, 'retry_limit')) {
      s.retry_limit = normalizeRetryLimit(s.retry_limit)
    }
    const previous = settings.value
    settings.value = { ...settings.value, ...s }
    persistFrontendLocalSettings(s)
    const remoteSettings = { ...s }
    delete remoteSettings.minimal_mode
    delete remoteSettings.minimize_to_tray_on_connect
    if (Object.keys(remoteSettings).length === 0) return

    try {
      const { data } = await api.put<SettingsConfig>('/config/settings', remoteSettings)
      settings.value = applyFrontendLocalSettings({ ...settings.value, ...data })
      settingsLoaded.value = true
      settingsLoadError.value = null
    } catch (error) {
      settings.value = previous
      persistFrontendLocalSettings({
        minimal_mode: previous.minimal_mode,
        minimize_to_tray_on_connect: previous.minimize_to_tray_on_connect,
        dtls_mode: previous.dtls_mode,
      })
      throw error
    }
  }

  async function fetchKeyStatus() {
    try {
      const { data } = await api.get<KeyStatus>('/config/key')
      keyStatus.value = data
    } catch (e) { console.error('[config] fetchKeyStatus failed:', e) }
  }

  async function fetchRuntimeStatus() {
    const { data } = await api.get<RuntimeStatus>('/runtime')
    runtimeStatus.value = data
  }

  async function fetchDriverStatus() {
    const { data } = await api.get<DriverStatus>('/drivers')
    driverStatus.value = data
  }

  async function installDriver(driver: 'wintun' | 'tap') {
    const { data } = await api.post<{
      ok: boolean
      message: string
      takes_effect?: 'next_connect' | 'immediately'
      status: DriverStatus
    }>('/drivers/install', { driver })
    if (data.status) {
      driverStatus.value = data.status
    }
    return data
  }

  async function importConfig(payload: { format: 'protected' | 'unprotected'; data: string; password?: string }) {
    const { data } = await api.post<{ ok: true }>('/config/import', payload)
    await Promise.all([fetchAuthConfig(), fetchSettings()])
    return data
  }

  async function exportConfig(payload: { protected: boolean; password?: string }) {
    const { data } = await api.post<{ format: 'protected' | 'unprotected'; data: string }>(
      '/config/export', payload,
    )
    return data
  }

  async function resetConfig(confirm: boolean) {
    const { data } = await api.post<{ ok: true }>('/config/reset', { confirm })
    await Promise.all([fetchAuthConfig(), fetchSettings(), fetchKeyStatus()])
    return data
  }

  async function resetKey(confirm: boolean) {
    const { data } = await api.post<{ ok: true }>('/key/reset', { confirm })
    await fetchKeyStatus()
    return data
  }

  async function inspectCore() {
    const { data } = await api.get<CoreInspection>('/maintenance/core')
    return data
  }

  async function killStaleCore(confirm: boolean) {
    const { data } = await api.post<{ ok: true }>('/maintenance/core/kill', { confirm })
    return data
  }

  return {
    authConfig, settings, keyStatus, runtimeStatus, driverStatus,
    authConfigLoaded, authConfigLoadError,
    settingsLoaded, settingsLoadError,
    fetchAuthConfig, saveAuthConfig,
    fetchSettings, saveSettings,
    fetchKeyStatus,
    fetchRuntimeStatus, fetchDriverStatus, installDriver,
    importConfig, exportConfig, resetConfig,
    resetKey,
    inspectCore, killStaleCore,
  }
})
