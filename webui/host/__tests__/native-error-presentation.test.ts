import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const webuiRoot = process.cwd()
const storeText = readFileSync(join(webuiRoot, 'src', 'stores', 'vpn.ts'), 'utf8')
const globalTypeText = readFileSync(join(webuiRoot, 'src', 'types', 'exv.d.ts'), 'utf8')

const requiredNativeErrorCodes = [
  'auth_protocol_mismatch',
  'auth_rejected',
  'auth_challenge_required',
  'auth_group_required',
  'auth_expired',
  'csd_required_unsupported',
  'dtls_unavailable',
  'session_timeout',
  'idle_timeout',
  'unsupported_extra_args',
] as const

describe('native error presentation contract', () => {
  it('maps every native connection error code to a renderer descriptor', () => {
    for (const code of requiredNativeErrorCodes) {
      assert.match(storeText, new RegExp(`\\b${code}:\\s*\\{`), `${code} missing from contractErrorMap`)
      assert.match(storeText, new RegExp(`error_type:\\s*'${code}'`), `${code} missing as a typed presentation`)
    }
  })

  it('keeps the desktop global VPN error type in sync', () => {
    for (const code of requiredNativeErrorCodes) {
      assert.match(globalTypeText, new RegExp(`'${code}'`), `${code} missing from ExvApi VpnErrorType`)
    }
  })

  // INVARIANT: the aggregate-auth raw codes (auth_response_invalid /
  // auth_response_too_large) must not slip past the renderer as auth_failed —
  // a real password is correct in this scenario. The store either rewrites the
  // raw code to auth_protocol_mismatch or maps the raw key to the same
  // view_logs descriptor.
  it('renders aggregate-auth response codes as a protocol mismatch, not a credential failure', () => {
    for (const rawCode of ['auth_response_invalid', 'auth_response_too_large']) {
      const headerIdx = storeText.search(new RegExp(`\\b${rawCode}\\b`))
      assert.notEqual(headerIdx, -1,
        `${rawCode} should be addressed in the store (alias or descriptor)`)

      const window = storeText.slice(Math.max(0, headerIdx - 80), headerIdx + 320)
      assert.match(window, /auth_protocol_mismatch/,
        `${rawCode} should resolve to auth_protocol_mismatch`)
      assert.doesNotMatch(window, /error_type:\s*'auth_failed'/,
        `${rawCode} must not be presented as auth_failed`)
      assert.doesNotMatch(window, /recommended_action:\s*'retry_password'/,
        `${rawCode} must not recommend retry_password`)
    }
  })

  it('prefers localized contract copy over raw backend English messages', () => {
    assert.match(storeText, /message:\s*'登录失败，请核对您的用户名和密码。'/,
      'auth_failed should use actionable Chinese copy')
    assert.doesNotMatch(storeText,
      /message:\s*String\(obj\.message\s*\|\|\s*obj\.error\s*\|\|\s*descriptor\.message\)/,
      'canonical backend codes must not render raw English backend messages before localized descriptors')
    assert.doesNotMatch(storeText, /Retry the operation/,
      'user-facing fallback actions should not be English')
    assert.doesNotMatch(storeText, /Operation failed/,
      'user-facing fallback messages should not be English')
  })

  it('localizes common raw native failure messages before showing dialogs', () => {
    const requiredRawMappings = [
      ['Login failed.', '登录失败，请核对您的用户名和密码。'],
      ['Core RPC transport is closed', '核心进程连接已关闭'],
      ['Failed to start elevated one-shot helper.', '临时助手启动失败'],
      ['A native VPN connection attempt is already active.', '已有 VPN 连接流程正在进行'],
      ['invalid X-CSTP-Session-Timeout value', 'VPN 网关返回了异常的会话超时字段'],
      ['Native engine session failed to start', 'VPN 隧道启动失败'],
      ['failed to open or create Wintun adapter', '需要管理员权限才能继续'],
    ] as const

    for (const [rawMessage, localized] of requiredRawMappings) {
      assert.match(storeText, new RegExp(rawMessage.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
        `${rawMessage} should be recognized as a raw failure`)
      assert.match(storeText, new RegExp(localized),
        `${rawMessage} should map to Chinese dialog copy`)
    }
  })

  it('routes broken core transport failures to the in-app core restart action', () => {
    assert.match(storeText, /Core RPC transport is closed[\s\S]*recommended_action:\s*'restart_core'/,
      'closed Core RPC transport should recommend restarting the core')
    assert.match(storeText, /core_comm_broken[\s\S]*recommended_action:\s*'restart_core'/,
      'core_comm_broken should recommend restarting the core')
    assert.match(storeText, /core_unresponsive[\s\S]*recommended_action:\s*'restart_core'/,
      'core_unresponsive should recommend restarting the core')
    assert.doesNotMatch(storeText, /recommended_action:\s*'restart_app'/,
      'broken core transport should not ask users to restart the whole client')
  })
})
