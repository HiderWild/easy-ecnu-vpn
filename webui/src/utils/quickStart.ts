import { distributionConfig } from '../generated/distribution'
import type { AuthConfig } from '../stores/config'
import { useConfigStore } from '../stores/config'
import { useUiStore, type QuickStartRequest } from '../stores/ui'

export function hasLocalUserData(auth: Pick<AuthConfig, 'username' | 'password_stored'>) {
  return Boolean(auth.username.trim() || auth.password_stored)
}

function missingLocalUserDataRequest(server?: string): QuickStartRequest {
  return {
    reason: 'missing',
    defaults: {
      server: server || distributionConfig.defaultVpnServer,
      remember_password: false,
      install_service: true,
    },
  }
}

export function showQuickStartOrCredentialFallback(request: QuickStartRequest) {
  const ui = useUiStore()
  const config = useConfigStore()

  if (ui.showQuickStart || ui.showCredentialPrompt) return true
  if (request.reason === 'missing' && ui.quickStartDismissed && hasLocalUserData(config.authConfig)) return false
  if (request.reason === 'missing' && hasLocalUserData(config.authConfig)) return false

  if (!config.settings.minimal_mode) {
    ui.openQuickStart(request)
    return true
  }

  const missingUsername = !config.authConfig.username.trim()
  const missingPassword = !(
    config.authConfig.remember_password && config.authConfig.password_stored
  )
  if (!missingUsername && !missingPassword) return false

  void ui.requestCredentials({
    missingUsername,
    missingPassword,
    username: config.authConfig.username,
    rememberPassword: request.defaults.remember_password,
    message: missingUsername && missingPassword
      ? '请输入用户名和密码'
      : missingUsername
        ? '请输入用户名'
        : '请输入密码',
  })
  return true
}

export function requestQuickStartForMissingLocalData() {
  const ui = useUiStore()
  const config = useConfigStore()
  if (!config.authConfigLoaded) return false
  if (config.authConfigLoadError) return false
  if (!config.settingsLoaded) return false
  if (config.settingsLoadError) return false
  if (ui.showQuickStart || ui.showCredentialPrompt) return false
  if (hasLocalUserData(config.authConfig)) return false
  return showQuickStartOrCredentialFallback(
    missingLocalUserDataRequest(config.authConfig.server),
  )
}
