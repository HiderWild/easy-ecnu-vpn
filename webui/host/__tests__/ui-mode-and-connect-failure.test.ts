import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createRequire } from 'node:module'
import type * as TypeScript from 'typescript'

const webuiRoot = process.cwd()
const require = createRequire(join(webuiRoot, 'package.json'))
const ts = require('typescript') as typeof TypeScript

function readSource(...parts: string[]) {
  return readFileSync(join(webuiRoot, ...parts), 'utf8')
}

const configStoreText = readSource('src', 'stores', 'config.ts')
const appText = readSource('src', 'App.vue')
const vpnStoreText = readSource('src', 'stores', 'vpn.ts')
const uiStoreText = readSource('src', 'stores', 'ui.ts')
const dashboardPageText = readSource('src', 'pages', 'DashboardPage.vue')
const dashboardVisualText = readSource('src', 'components', 'dashboard', 'DashboardVisualStage.vue')
const logsPageText = readSource('src', 'pages', 'LogsPage.vue')
const minimalModeViewText = readSource('src', 'components', 'MinimalModeView.vue')
const appWindowFrameText = readSource('src', 'components', 'AppWindowFrame.vue')
const modeSegmentedControlText = readSource('src', 'components', 'ModeSegmentedControl.vue')
const modalShellText = readSource('src', 'components', 'ModalShell.vue')
const hostApiText = readSource('src', 'api', 'host.ts')
const navBarText = readSource('src', 'components', 'NavBar.vue')
const vpnActionsText = readSource('..', 'src', 'core', 'rpc', 'vpn_actions.cpp')

function vueScriptSetup(text: string) {
  const match = text.match(/<script setup[^>]*>([\s\S]*?)<\/script>/)
  assert.ok(match, 'Vue file should contain <script setup>')
  return match[1]
}

function sourceFile(name: string, text: string) {
  return ts.createSourceFile(name, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
}

function collect<T>(
  node: TypeScript.Node,
  predicate: (node: TypeScript.Node) => T | undefined,
): T[] {
  const out: T[] = []
  function visit(current: TypeScript.Node) {
    const value = predicate(current)
    if (value !== undefined) out.push(value)
    ts.forEachChild(current, visit)
  }
  visit(node)
  return out
}

function stringLiterals(text: string) {
  return collect(sourceFile('source.ts', text), (node) =>
    ts.isStringLiteralLike(node) ? node.text : undefined,
  )
}

function functionNames(text: string) {
  return new Set(collect(sourceFile('source.ts', text), (node) =>
    ts.isFunctionDeclaration(node) && node.name ? node.name.text : undefined,
  ))
}

function deletePropertyNames(text: string) {
  return new Set(collect(sourceFile('source.ts', text), (node) => {
    if (!ts.isDeleteExpression(node)) return undefined
    const target = node.expression
    if (ts.isPropertyAccessExpression(target)) return target.name.text
    return undefined
  }))
}

function hasCallNamed(text: string, name: string) {
  return collect(sourceFile('source.ts', text), (node) => {
    if (!ts.isCallExpression(node)) return undefined
    const expression = node.expression
    if (ts.isIdentifier(expression)) return expression.text === name
    if (ts.isPropertyAccessExpression(expression)) return expression.name.text === name
    return false
  }).some(Boolean)
}

function hasPropertyCall(text: string, propertyName: string) {
  return collect(sourceFile('source.ts', text), (node) => {
    if (!ts.isCallExpression(node)) return undefined
    const expression = node.expression
    return ts.isPropertyAccessExpression(expression) && expression.name.text === propertyName
  }).some(Boolean)
}

function hasSetModeCallWithRequest(text: string) {
  return collect(sourceFile('source.ts', text), (node) => {
    if (!ts.isCallExpression(node)) return undefined
    const expression = node.expression
    if (!ts.isPropertyAccessExpression(expression) || expression.name.text !== 'setMode') return false
    return node.arguments.length >= 2 &&
      ts.isIdentifier(node.arguments[0]) &&
      node.arguments[0].text === 'mode' &&
      ts.isIdentifier(node.arguments[1]) &&
      node.arguments[1].text === 'request'
  }).some(Boolean)
}

function hasIdentifier(text: string, name: string) {
  return collect(sourceFile('source.ts', text), (node) =>
    ts.isIdentifier(node) && node.text === name ? true : undefined,
  ).some(Boolean)
}

function hasPrefixIncrement(text: string, name: string) {
  return collect(sourceFile('source.ts', text), (node) =>
    ts.isPrefixUnaryExpression(node) &&
    node.operator === ts.SyntaxKind.PlusPlusToken &&
    ts.isIdentifier(node.operand) &&
    node.operand.text === name ? true : undefined,
  ).some(Boolean)
}

function hasInequality(text: string, leftName: string, rightName: string) {
  return collect(sourceFile('source.ts', text), (node) => {
    if (!ts.isBinaryExpression(node)) return undefined
    const isInequality =
      node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
      node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken
    return isInequality &&
      ts.isIdentifier(node.left) &&
      ts.isIdentifier(node.right) &&
      node.left.text === leftName &&
      node.right.text === rightName
  }).some(Boolean)
}

function hasObjectKeysLengthZeroReturn(text: string, objectName: string) {
  return collect(sourceFile('source.ts', text), (node) => {
    if (!ts.isIfStatement(node)) return undefined
    if (!ts.isReturnStatement(node.thenStatement)) return false
    const expression = node.expression
    if (!ts.isBinaryExpression(expression)) return false
    if (expression.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsEqualsToken) return false
    if (!ts.isNumericLiteral(expression.right) || expression.right.text !== '0') return false
    const left = expression.left
    if (!ts.isPropertyAccessExpression(left) || left.name.text !== 'length') return false
    const call = left.expression
    if (!ts.isCallExpression(call)) return false
    const callee = call.expression
    if (!ts.isPropertyAccessExpression(callee) || callee.name.text !== 'keys') return false
    if (!ts.isIdentifier(callee.expression) || callee.expression.text !== 'Object') return false
    return call.arguments.length === 1 &&
      ts.isIdentifier(call.arguments[0]) &&
      call.arguments[0].text === objectName
  }).some(Boolean)
}

function hasSwitchCase(text: string, literal: string) {
  return collect(sourceFile('source.ts', text), (node) =>
    ts.isCaseClause(node) &&
    ts.isStringLiteralLike(node.expression) &&
    node.expression.text === literal ? true : undefined,
  ).some(Boolean)
}

function hasApiPostToLiteral(text: string, path: string) {
  return collect(sourceFile('source.ts', text), (node) => {
    if (!ts.isCallExpression(node)) return undefined
    const expression = node.expression
    if (!ts.isPropertyAccessExpression(expression) || expression.name.text !== 'post') return false
    if (!ts.isIdentifier(expression.expression) || expression.expression.text !== 'api') return false
    const first = node.arguments[0]
    return first != null && ts.isStringLiteralLike(first) && first.text === path
  }).some(Boolean)
}

function hasGuardedSetError(text: string, skippedErrorType: string) {
  return collect(sourceFile('source.ts', text), (node) => {
    if (!ts.isIfStatement(node)) return undefined
    const expression = node.expression
    if (!ts.isBinaryExpression(expression)) return false
    const isInequality =
      expression.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
      expression.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken
    if (!isInequality) return false
    if (!ts.isStringLiteralLike(expression.right) || expression.right.text !== skippedErrorType) return false
    return collect(node.thenStatement, (child) => {
      if (!ts.isCallExpression(child)) return undefined
      return ts.isIdentifier(child.expression) && child.expression.text === 'setError'
    }).some(Boolean)
  }).some(Boolean)
}

function unionStringMembers(text: string, aliasName: string) {
  const values = new Set<string>()
  const file = sourceFile('source.ts', text)
  collect(file, (node) => {
    if (!ts.isTypeAliasDeclaration(node) || node.name.text !== aliasName) return undefined
    collect(node.type, (member) => {
      if (
        ts.isLiteralTypeNode(member) &&
        ts.isStringLiteral(member.literal)
      ) {
        values.add(member.literal.text)
      }
      return undefined
    })
    return true
  })
  return values
}

function objectLiteralPropertyNames(text: string, objectName: string) {
  const names = new Set<string>()
  collect(sourceFile('source.ts', text), (node) => {
    if (!ts.isVariableDeclaration(node) || node.name.getText() !== objectName) return undefined
    const initializer = node.initializer
    if (!initializer || !ts.isObjectLiteralExpression(initializer)) return undefined
    for (const property of initializer.properties) {
      if (ts.isPropertyAssignment(property)) {
        const name = property.name
        if (ts.isIdentifier(name) || ts.isStringLiteral(name)) names.add(name.text)
      }
    }
    return true
  })
  return names
}

function interfacePropertyNames(text: string, interfaceName: string) {
  const names = new Set<string>()
  collect(sourceFile('source.ts', text), (node) => {
    if (!ts.isInterfaceDeclaration(node) || node.name.text !== interfaceName) return undefined
    for (const member of node.members) {
      if (!ts.isPropertySignature(member) || !member.name) continue
      if (ts.isIdentifier(member.name) || ts.isStringLiteral(member.name)) {
        names.add(member.name.text)
      }
    }
    return true
  })
  return names
}

describe('frontend-owned UI mode state', () => {
  it('keeps renderer-only UI preferences in localStorage', () => {
    const literals = stringLiterals(configStoreText)
    assert.ok(literals.includes('exv:minimal-mode'))
    assert.ok(literals.includes('exv:minimize-to-tray-on-connect'))
    assert.equal(literals.includes('exv:service-install-prompt-seen'), false)
    assert.ok(hasPropertyCall(configStoreText, 'getItem'))
    assert.ok(hasPropertyCall(configStoreText, 'setItem'))

    const names = functionNames(configStoreText)
    assert.ok(names.has('applyFrontendLocalSettings'))
    assert.ok(names.has('persistFrontendLocalSettings'))
  })

  it('sends service prompt config fields through core-owned settings unchanged', () => {
    const deleted = deletePropertyNames(configStoreText)
    assert.ok(deleted.has('minimal_mode'))
    assert.ok(deleted.has('minimize_to_tray_on_connect'))
    assert.equal(deleted.has('dtls_mode'), false)
    assert.equal(deleted.has('service_install_prompt_seen'), false)
    assert.ok(hasObjectKeysLengthZeroReturn(configStoreText, 'remoteSettings'))
  })

  it('hides to tray only after a real connect flow reaches connected', () => {
    assert.match(configStoreText, /minimize_to_tray_on_connect: boolean/)
    assert.match(vpnStoreText, /const connectShouldHideToTray = ref\(false\)/)
    assert.match(vpnStoreText, /connectShouldHideToTray\.value = true/)
    assert.match(vpnStoreText, /function maybeHideToTrayAfterConnect\(nextStatus: VpnStatus\)/)
    assert.match(vpnStoreText, /config\.settings\.minimize_to_tray_on_connect/)
    assert.match(vpnStoreText, /window\.exv\?\.window\?\.hideToTray/)
    const fetchStatusStart = vpnStoreText.indexOf('async function fetchStatus')
    assert.notEqual(fetchStatusStart, -1)
    const fetchStatusEnd = vpnStoreText.indexOf('function withTimeout', fetchStatusStart)
    assert.notEqual(fetchStatusEnd, -1)
    const fetchStatusBlock = vpnStoreText.slice(fetchStatusStart, fetchStatusEnd)
    assert.doesNotMatch(fetchStatusBlock, /connectShouldHideToTray\.value = true/)
  })

  it('suppresses stale asynchronous window mode writes after rapid toggles', () => {
    const frameText = appWindowFrameText
    assert.ok(frameText.includes('windowModeRequest'))
    assert.ok(frameText.includes('resizeForMode'))
    assert.ok(frameText.includes('transitionPhase'))
    assert.ok(frameText.includes("'native-resize'"))
    assert.ok(frameText.includes('settling'))
    assert.equal(frameText.includes('native-resize-before-animation'), false)
    assert.equal(frameText.includes('native-resize-after-animation'), false)
    assert.equal(frameText.includes('MODE_TRANSITION_MS'), false)
    assert.ok(frameText.includes('POST_RESIZE_SETTLE_MS'))
  })

  it('keeps theme and UI mode controls in the titlebar instead of page content', () => {
    assert.match(appWindowFrameText, /TitlebarThemeModeControl/)
    assert.match(appWindowFrameText, /ModeSegmentedControl/)
    assert.match(appWindowFrameText, /app-window-titlebar__toolbar/)
    assert.match(appWindowFrameText, /theme\.setThemeMode/)
    assert.match(appWindowFrameText, /handleTitlebarModeChange/)
    assert.match(appWindowFrameText, /:icon-only="visualMode === 'minimal'"/)

    assert.match(modeSegmentedControlText, /import \{ Expand, Shrink \} from 'lucide-vue-next'/)
    assert.doesNotMatch(modeSegmentedControlText, /Maximize2|Minimize2/)
    assert.match(modeSegmentedControlText, /iconOnly\?: boolean/)

    assert.doesNotMatch(dashboardPageText, /<ModeSegmentedControl/)
    assert.doesNotMatch(minimalModeViewText, /<ModeSegmentedControl/)
    assert.doesNotMatch(minimalModeViewText, /minimal-shell__mode/)
  })

  it('draws a stable one-pixel border around the native window surface', () => {
    const frameText = appWindowFrameText
    assert.ok(frameText.includes('--app-window-border-color'))
    assert.match(frameText, /border:\s*1px solid var\(--app-window-border-color\)/)
    assert.match(frameText, /box-sizing:\s*border-box/)
  })

  it('aligns the native window contour to the physical window edge', () => {
    const frameText = appWindowFrameText
    const shadowDeclaration = frameText.match(/--app-window-shadow:\s*([\s\S]*?);/)?.[1] ?? ''
    assert.ok(frameText.includes('--app-window-shadow'))
    assert.ok(frameText.includes('--app-window-shadow-margin'))
    assert.match(frameText, /--window-radius:\s*12px/)
    assert.match(frameText, /--app-window-shadow-margin:\s*0px/)
    assert.match(frameText, /--app-window-shadow-margin-total:\s*0px/)
    assert.match(frameText, /padding:\s*var\(--app-window-shadow-margin\)/)
    assert.match(frameText, /width:\s*calc\(100vw - var\(--app-window-shadow-margin-total\)\)/)
    assert.match(frameText, /height:\s*calc\(100vh - var\(--app-window-shadow-margin-total\)\)/)
    assert.match(frameText, /box-shadow:\s*var\(--app-window-shadow\)/)
    assert.match(shadowDeclaration, /0\s+18px\s+42px\s+-18px\s+rgba/)
    assert.doesNotMatch(shadowDeclaration, /0\s+0\s+0\s+\d+px/)
  })

  it('keeps the advanced sidebar anchored to the content surface, not the shadow gutter', () => {
    assert.match(navBarText, /<nav class="absolute inset-y-0 left-0/)
    assert.doesNotMatch(navBarText, /<nav class="fixed inset-y-0 left-0/)
  })

  it('keeps minimal-mode prompts inside the shared in-window modal stack', () => {
    assert.match(uiStoreText, /interface ConfirmOptions/)
    assert.match(uiStoreText, /function requestConfirm\(message: string, onConfirm: \(\) => void, options: ConfirmOptions = \{\}\)/)
    assert.match(uiStoreText, /confirmCancelCallback/)
    assert.match(uiStoreText, /function requestPassword\(message: string, options\?:/)
    assert.doesNotMatch(uiStoreText, /window\.exv\.modal\.confirmPrompt/)
    assert.doesNotMatch(uiStoreText, /window\.exv\.modal\.passwordPrompt/)
    assert.doesNotMatch(uiStoreText, /config\.settings\.minimal_mode && window\.exv\?\.modal/)
  })

  it('keeps compact modal panels inside minimal windows without scrollbars', () => {
    assert.match(modalShellText, /max-height:\s*calc\(100vh - 28px\)/)
    assert.match(modalShellText, /display:\s*flex/)
    assert.match(modalShellText, /flex-direction:\s*column/)
    assert.match(modalShellText, /compact\?:\s*boolean/)
    assert.match(modalShellText, /modal-shell__panel--compact/)
    assert.match(modalShellText, /\.modal-shell__panel--compact\s+\.modal-shell__body\s*\{[\s\S]*overflow:\s*hidden/)
    assert.match(modalShellText, /\.modal-shell__panel--compact\s+\.modal-shell__actions\s+button\s*\{[\s\S]*font-size:\s*11px/)
    assert.match(modalShellText, /\.modal-shell__panel--compact\s+\.modal-shell__actions\s+button\s*\{[\s\S]*white-space:\s*nowrap/)
    assert.match(modalShellText, /@media \(max-width: 360px\), \(max-height: 180px\)[\s\S]*\.modal-shell__panel--compact \.modal-shell__actions button\s*\{[\s\S]*flex:\s*0 0 auto/)
  })

  it('keeps the minimal top status concise and vertically balanced', () => {
    assert.doesNotMatch(minimalModeViewText, /minimal-shell__status-detail/)
    assert.doesNotMatch(minimalModeViewText, /临时授权连接|连接前安装服务/)
    assert.doesNotMatch(minimalModeViewText, /minimal-shell__topline/)
    assert.match(minimalModeViewText, /minimal-shell__status-stack/)
    assert.match(minimalModeViewText, /\.minimal-shell__body\s*\{[\s\S]*grid-template-columns:\s*4\.15rem minmax\(0,\s*1fr\)/)
  })

  it('keeps minimal activity chrome within the compact window height budget', () => {
    const compactContentHeightPx = 102
    const rootRemPx = 16
    const shellChromePx = (0.42 + 0.1) * rootRemPx
    const disconnectedFormPx = (1.56 + 0.38 + 1.56) * rootRemPx
    const powerButtonWithStatusPx = (0.75 + 0.32 + 2.72) * rootRemPx

    assert.match(minimalModeViewText, /\.minimal-shell\s*\{[\s\S]*grid-template-rows:\s*minmax\(0,\s*1fr\) auto/)
    assert.match(minimalModeViewText, /\.minimal-shell\s*\{[\s\S]*padding:\s*0\.42rem 0\.62rem 0\.16rem/)
    assert.match(minimalModeViewText, /\.minimal-shell__activity\s*\{[\s\S]*height:\s*0\.1rem/)
    assert.match(minimalModeViewText, /\.minimal-power-button\s*\{[\s\S]*width:\s*2\.72rem;[\s\S]*height:\s*2\.72rem/)
    assert.match(minimalModeViewText, /:deep\(\.minimal-shell__input\)\s*\{[\s\S]*height:\s*1\.56rem/)
    assert.match(minimalModeViewText, /\.minimal-shell__utility\s*\{[\s\S]*height:\s*1\.56rem/)
    assert.match(minimalModeViewText, /\.minimal-shell__field-row \+ \.minimal-shell__field-row\s*\{[\s\S]*margin-top:\s*0\.2rem/)
    assert.doesNotMatch(minimalModeViewText, /minimal-shell__mode/)
    assert.ok(
      compactContentHeightPx - shellChromePx >= Math.max(disconnectedFormPx, powerButtonWithStatusPx),
      '102px minimal content area should leave enough body height for the form and power button',
    )
  })

  it('places the minimal service control above remember after the titlebar frees vertical space', () => {
    const serviceIndex = minimalModeViewText.indexOf('minimal-shell__utility minimal-shell__utility--service')
    const rememberIndex = minimalModeViewText.indexOf('minimal-shell__utility minimal-shell__utility--remember')
    const usernameIndex = minimalModeViewText.indexOf('placeholder="用户名"')
    const passwordIndex = minimalModeViewText.indexOf('placeholder="密码"')

    assert.notEqual(serviceIndex, -1)
    assert.notEqual(rememberIndex, -1)
    assert.notEqual(usernameIndex, -1)
    assert.notEqual(passwordIndex, -1)
    assert.ok(usernameIndex < serviceIndex, 'service control should sit on the username row')
    assert.ok(serviceIndex < passwordIndex, 'service control should appear before password row')
    assert.ok(passwordIndex < rememberIndex, 'remember control should sit on the password row')
  })

  it('uses a soft center-weighted minimal activity beam', () => {
    const beamRule = minimalModeViewText.match(/\.minimal-activity-beam\s*\{[\s\S]*?\n\}/)?.[0] ?? ''

    assert.match(minimalModeViewText, /<span\s+class="minimal-activity-beam"\s*\/>/)
    assert.match(beamRule, /linear-gradient\(90deg,\s*transparent 0%/)
    assert.match(beamRule, /rgb\(var\(--color-accent-rgb\) \/ 0\.82\) 50%/)
    assert.match(beamRule, /transparent 100%/)
    assert.match(minimalModeViewText, /filter:\s*blur\(0\.5px\)/)
    assert.match(
      minimalModeViewText,
      /\.minimal-shell\.is-connecting \.minimal-activity-beam,\s*\.minimal-shell\.is-disconnecting \.minimal-activity-beam\s*\{[\s\S]*animation:\s*minimal-activity-flow 2\.4s ease-in-out infinite;/,
    )
    assert.match(
      minimalModeViewText,
      /\.minimal-shell\.is-connected \.minimal-activity-beam\s*\{[\s\S]*animation:\s*minimal-activity-drift 8\.5s ease-in-out infinite;/,
    )
    assert.match(
      minimalModeViewText,
      /@media \(prefers-reduced-motion: reduce\)\s*\{\s*\.minimal-activity-beam\s*\{[\s\S]*animation:\s*none !important;/,
    )
    assert.doesNotMatch(minimalModeViewText, /\.minimal-shell__activity\s+span/)
    assert.doesNotMatch(minimalModeViewText, /width:\s*30%/)
  })
})

describe('connection failure presentation contract', () => {
  it('maps asynchronous failed status snapshots into the user-facing error dialog', () => {
    const statusFields = interfacePropertyNames(vpnStoreText, 'VpnStatus')
    assert.ok(statusFields.has('error'))
    assert.ok(statusFields.has('error_code'))
    assert.ok(statusFields.has('error_recoverable'))
    assert.ok(statusFields.has('last_error'))
    assert.ok(statusFields.has('dtls_state'))
    assert.ok(statusFields.has('active_data_channel'))
    assert.ok(statusFields.has('dtls_fallback_reason'))
    assert.match(vpnStoreText, /function isTerminalConnectStatus\(nextStatus: VpnStatus\)/)
    assert.match(vpnStoreText, /connectInFlight\.value && isTerminalConnectStatus\(nextStatus\)/)
    assert.match(vpnStoreText, /nextStatus\.connected/)
    assert.match(vpnStoreText, /nextStatus\.error_code/)
    assert.match(vpnStoreText, /function isTerminalConnectStatus\(nextStatus: VpnStatus\)\s*\{[\s\S]*nextStatus\.error/)
    assert.match(vpnStoreText, /nextStatus\.last_error/)
    assert.match(vpnStoreText, /String\(nextStatus\.phase \?\? ''\)\.toLowerCase\(\) === 'failed'/)
    assert.doesNotMatch(vpnStoreText, /connectInFlight\.value && \(nextStatus\.connected \|\| nextStatus\.process_running === false\)/)
    assert.match(vpnStoreText, /const terminalError = statusErrorForConnect\(nextStatus\)/)
    assert.match(vpnStoreText, /terminalError\.code !== 'user_cancelled'[\s\S]*setError\(normalizeError/)
    assert.match(vpnStoreText, /code:\s*terminalError\.code \|\| 'connection_failed'/)
    assert.match(vpnStoreText, /message:\s*terminalError\.message \|\| '连接失败，请打开日志查看详细原因后重试。'/)
    assert.match(vpnStoreText, /lastFailedConnectMode\.value = 'helper'/)
    assert.match(vpnActionsText, /get_legacy_status[\s\S]*\{"code", err\.code\}/)
  })

  it('keeps backend connection failures visible while suppressing user-cancelled errors', () => {
    const errorTypes = unionStringMembers(vpnStoreText, 'VpnErrorType')
    assert.ok(errorTypes.has('connection_failed'))
    assert.ok(errorTypes.has('connection_attempt_active'))
    assert.ok(errorTypes.has('user_cancelled'))

    const contractErrors = objectLiteralPropertyNames(vpnStoreText, 'contractErrorMap')
    assert.ok(contractErrors.has('connection_failed'))
    assert.ok(contractErrors.has('connection_attempt_active'))

    assert.ok(hasGuardedSetError(vpnStoreText, 'user_cancelled'))
  })

  it('keeps runtime monitoring alive after startup and reports post-connect failures', () => {
    assert.match(vpnStoreText, /const runtimeStatusPollTimer = ref<ReturnType<typeof setInterval> \| null>\(null\)/)
    assert.match(vpnStoreText, /const runtimeHadConnectedSession = ref\(false\)/)
    assert.match(vpnStoreText, /const runtimeDisconnectErrorKey = ref<string \| null>\(null\)/)
    assert.match(vpnStoreText, /function normalizedPhase\(nextStatus: VpnStatus\)/)
    assert.match(vpnStoreText, /function shouldKeepRuntimeStatusMonitoring\(nextStatus: VpnStatus\)/)
    assert.match(vpnStoreText, /function statusErrorForRuntimeDisconnect\(nextStatus: VpnStatus\)/)
    assert.match(vpnStoreText, /function startRuntimeStatusMonitoring\(\)/)
    assert.match(vpnStoreText, /function stopRuntimeStatusMonitoring\(\)/)

    const applyStatusStart = vpnStoreText.indexOf('function applyStatus')
    assert.notEqual(applyStatusStart, -1)
    const applyStatusEnd = vpnStoreText.indexOf('function updateStatusFromEvent', applyStatusStart)
    assert.notEqual(applyStatusEnd, -1)
    const applyStatusBlock = vpnStoreText.slice(applyStatusStart, applyStatusEnd)

    assert.match(applyStatusBlock, /runtimeHadConnectedSession\.value = true/)
    assert.match(applyStatusBlock, /startRuntimeStatusMonitoring\(\)/)
    assert.match(applyStatusBlock, /stopRuntimeStatusMonitoring\(\)/)
    assert.match(applyStatusBlock, /shouldKeepRuntimeStatusMonitoring\(nextStatus\)/)
    assert.match(applyStatusBlock, /const runtimeError = statusErrorForRuntimeDisconnect\(nextStatus\)/)
    assert.match(applyStatusBlock, /setError\(normalizeError\(\{/)
    assert.match(applyStatusBlock, /runtimeDisconnectErrorKey\.value = null/)
    assert.match(applyStatusBlock, /phase === 'reconnecting'/)
  })

  it('routes broken installed helper service errors to repair instead of retry', () => {
    const errorTypes = unionStringMembers(vpnStoreText, 'VpnErrorType')
    const serviceStatusFields = interfacePropertyNames(vpnStoreText, 'ServiceStatus')
    assert.ok(errorTypes.has('helper_unavailable'))
    for (const field of [
      'health',
      'diagnostic_code',
      'last_start_api',
      'last_start_native_error',
      'consecutive_start_failures',
      'start_suppressed',
      'start_retry_after_ms',
      'recommended_action',
    ]) {
      assert.ok(serviceStatusFields.has(field), `ServiceStatus missing ${field}`)
    }

    assert.match(vpnStoreText, /service_installed_not_running:\s*\{[\s\S]*error_type:\s*'helper_unavailable'/)
    assert.match(vpnStoreText, /service_installed_not_running:\s*\{[\s\S]*recommended_action:\s*'repair_service'/)
    assert.match(vpnStoreText, /core_lease_conflict:\s*\{[\s\S]*error_type:\s*'helper_unavailable'/)
    assert.match(vpnStoreText, /core_lease_conflict:\s*\{[\s\S]*recommended_action:\s*'repair_service'/)
    assert.match(vpnStoreText, /core_lease_unauthorized:\s*\{[\s\S]*error_type:\s*'helper_unavailable'/)
    assert.match(vpnStoreText, /core_lease_unauthorized:\s*\{[\s\S]*recommended_action:\s*'repair_service'/)
    assert.match(vpnStoreText, /helper_hello_disconnected:\s*\{[\s\S]*error_type:\s*'helper_unavailable'/)
    assert.match(vpnStoreText, /helper_hello_disconnected:\s*\{[\s\S]*recommended_action:\s*'repair_service'/)
    assert.match(vpnStoreText, /helper_hello_failed:\s*\{[\s\S]*error_type:\s*'helper_unavailable'/)
    assert.match(vpnStoreText, /helper_hello_failed:\s*\{[\s\S]*recommended_action:\s*'repair_service'/)
    assert.match(
      vpnStoreText,
      /case 'helper_unavailable':[\s\S]*label:\s*'尝试修复服务'[\s\S]*repairService\(\)/,
    )
    assert.match(
      vpnStoreText,
      /case 'helper_unavailable':[\s\S]*title:\s*'辅助服务不可用'[\s\S]*primaryLabel:\s*'尝试修复服务'[\s\S]*repairService\(\)/,
    )

    const presentationStart = vpnStoreText.indexOf("case 'helper_unavailable':", vpnStoreText.indexOf('function errorPresentation'))
    const presentationEnd = vpnStoreText.indexOf("case 'utun_permission_denied':", presentationStart)
    assert.notEqual(presentationStart, -1)
    assert.notEqual(presentationEnd, -1)
    const helperPresentationBlock = vpnStoreText.slice(presentationStart, presentationEnd)
    assert.doesNotMatch(helperPresentationBlock, /primaryLabel:\s*'重试'/)
  })

  it('clears stale connection errors when status becomes connected', () => {
    const applyStatusStart = vpnStoreText.indexOf('function applyStatus')
    assert.notEqual(applyStatusStart, -1)
    const applyStatusEnd = vpnStoreText.indexOf('function updateStatusFromEvent', applyStatusStart)
    assert.notEqual(applyStatusEnd, -1)
    const applyStatusBlock = vpnStoreText.slice(applyStatusStart, applyStatusEnd)

    const connectedStart = applyStatusBlock.indexOf('if (nextStatus.connected)')
    assert.notEqual(connectedStart, -1)
    const connectTerminalStart = applyStatusBlock.indexOf(
      'if (connectInFlight.value && isTerminalConnectStatus(nextStatus))',
      connectedStart,
    )
    assert.notEqual(connectTerminalStart, -1)
    const connectedBlock = applyStatusBlock.slice(connectedStart, connectTerminalStart)

    assert.match(connectedBlock, /clearError\(\)/)
  })

  it('routes the in-progress yellow button to cancellation instead of a second connect', () => {
    assert.ok(hasSwitchCase(vpnStoreText, 'elevated connecting'))
    assert.ok(hasCallNamed(vpnStoreText, 'cancelConnect'))
    assert.ok(hasApiPostToLiteral(vpnStoreText, '/disconnect'))

    const dashboardScript = vueScriptSetup(dashboardPageText)
    const minimalScript = vueScriptSetup(minimalModeViewText)
    assert.ok(stringLiterals(dashboardScript).includes('取消连接'))
    assert.ok(hasPropertyCall(dashboardScript, 'cancelConnect'))
    assert.ok(hasPropertyCall(minimalScript, 'cancelConnect'))
  })

  it('suppresses transport-closed errors while cancelling an active connect', () => {
    assert.match(vpnStoreText, /function isBenignCancelTransportError\(/)
    assert.match(vpnStoreText, /transport_closed/)
    assert.match(vpnStoreText, /core_comm_broken/)
    assert.match(vpnStoreText, /core_unresponsive/)

    const cancelStart = vpnStoreText.indexOf('async function cancelConnect')
    assert.notEqual(cancelStart, -1)
    const disconnectStart = vpnStoreText.indexOf('async function disconnect', cancelStart)
    assert.notEqual(disconnectStart, -1)
    const cancelBlock = vpnStoreText.slice(cancelStart, disconnectStart)
    assert.match(cancelBlock, /isBenignCancelTransportError\(normalized\)/)
    assert.doesNotMatch(cancelBlock, /if \(normalized\.error_type !== 'user_cancelled'\) setError\(normalized\)/)
  })

  it('does not let service status refresh block disconnect finalization', () => {
    assert.match(vpnStoreText, /SERVICE_STATUS_REFRESH_TIMEOUT_MS\s*=/)
    assert.match(vpnStoreText, /function withTimeout</)
    assert.match(vpnStoreText, /async function fetchServiceStatusWithTimeout\(/)

    const fetchShellStart = vpnStoreText.indexOf('async function fetchAppShellState')
    assert.notEqual(fetchShellStart, -1)
    const startPollingStart = vpnStoreText.indexOf('function startConnectStatusPolling', fetchShellStart)
    assert.notEqual(startPollingStart, -1)
    const fetchShellBlock = vpnStoreText.slice(fetchShellStart, startPollingStart)
    assert.match(fetchShellBlock, /fetchServiceStatusWithTimeout\(\)/)
    assert.doesNotMatch(fetchShellBlock, /fetchStatus\(\), fetchServiceStatus\(\)/)
  })

  it('turns core transport loss during active connect into a visible terminal failure', () => {
    assert.match(vpnStoreText, /function handleStatusPollFailure\(error: unknown\)/)
    assert.match(vpnStoreText, /connectInFlight\.value/)
    assert.match(vpnStoreText, /setError\(normalizeError\(error\)\)/)
    assert.match(vpnStoreText, /stopConnectStatusPolling\(\)/)
    assert.match(vpnStoreText, /stopAuthInteractionPolling\(\)/)
    assert.match(vpnStoreText, /stopConnectionProgress\(\)/)
    assert.match(vpnStoreText, /handleStatusPollFailure\(e\)/)
  })

  it('does not treat a hidden service install checkbox as an install request', () => {
    const dashboardScript = vueScriptSetup(dashboardPageText)
    assert.match(dashboardScript, /vpn\.connectFromDashboard\(\s*showInstallServiceChoice\.value && installServiceBeforeConnect\.value\s*\)/)

    const connectFromDashboardStart = vpnStoreText.indexOf('async function connectFromDashboard')
    assert.notEqual(connectFromDashboardStart, -1)
    const disconnectElevatedStart = vpnStoreText.indexOf('async function disconnectElevated', connectFromDashboardStart)
    assert.notEqual(disconnectElevatedStart, -1)
    const connectFromDashboardBlock = vpnStoreText.slice(connectFromDashboardStart, disconnectElevatedStart)

    assert.match(connectFromDashboardBlock, /const shouldInstallService = installServiceFirst && !serviceInstalled\.value && !serviceAvailable\.value/)
    assert.match(connectFromDashboardBlock, /if \(shouldInstallService\)/)
    assert.match(connectFromDashboardBlock, /if \(serviceInstalled\.value && !serviceAvailable\.value\) \{[\s\S]*await repairService\(\)[\s\S]*await fetchServiceStatus\(\)[\s\S]*if \(serviceAvailable\.value\)/)
    assert.match(connectFromDashboardBlock, /if \(canUseElevatedFallback\.value\) \{[\s\S]*connectElevated\(\)/)
    assert.doesNotMatch(connectFromDashboardBlock, /if \(installServiceFirst\)/)
  })
})

describe('structured connection progress contract', () => {
  it('exposes structured progress stages for the dashboard and future visuals', () => {
    const progressStates = unionStringMembers(vpnStoreText, 'ConnectProgressStepState')
    for (const state of ['pending', 'active', 'done', 'failed', 'skipped']) {
      assert.ok(progressStates.has(state), `missing progress state ${state}`)
    }

    const stageFields = interfacePropertyNames(vpnStoreText, 'ConnectionProgressStage')
    for (const field of ['key', 'label', 'description', 'state', 'priority', 'visual', 'source']) {
      assert.ok(stageFields.has(field), `ConnectionProgressStage should expose ${field}`)
    }
    assert.match(vpnStoreText, /type ConnectionProgressStageSource\s*=\s*'backend'\s*\|\s*'local'/)
    assert.match(vpnStoreText, /const connectionProgressSteps = computed<ConnectionProgressStage\[\]>/)
    assert.match(vpnStoreText, /connectionProgressSteps,/)
  })

  it('localizes known backend progress steps before they reach UI text', () => {
    assert.match(vpnStoreText, /connectProgressStepCopy/)
    for (const copy of [
      '准备连接',
      '接受连接请求并确认本次连接流程',
      '准备 helper',
      '启动或连接本地辅助进程',
      '完成认证',
      '提交凭据并完成网关认证',
      '连接 VPN 服务器',
      '建立到 VPN 网关的加密通道',
      '准备虚拟网卡',
      '创建或打开 EXV 隧道接口',
      '写入网络配置',
      '应用地址、DNS 和路由策略',
      '启动数据转发',
      '启动隧道数据包转发',
      '确认连接可用',
      '等待连接进入可用状态',
    ]) {
      assert.ok(vpnStoreText.includes(copy), `missing localized copy: ${copy}`)
    }
  })

  it('normalizes backend progress with stable priority sorting and current-step selection', () => {
    assert.match(vpnStoreText, /function normalizeBackendConnectionProgressSteps\(/)
    assert.match(vpnStoreText, /originalIndex/)
    assert.match(vpnStoreText, /a\.step\.priority - b\.step\.priority/)
    assert.match(vpnStoreText, /a\.originalIndex - b\.originalIndex/)

    assert.match(vpnStoreText, /function selectConnectionProgressStage\(/)
    assert.match(vpnStoreText, /activeKey/)
    assert.match(vpnStoreText, /step\.key === activeKey/)
    assert.match(vpnStoreText, /step\.state === 'active'/)
    assert.match(vpnStoreText, /step\.state === 'failed'/)
    assert.match(vpnStoreText, /step\.state === 'done' \|\| step\.state === 'skipped'/)
  })

  it('keeps the local timed fallback while preferring backend progress when available', () => {
    assert.match(vpnStoreText, /const localConnectionProgressSteps = computed<ConnectionProgressStage\[\]>/)
    assert.match(vpnStoreText, /source:\s*'local'/)
    assert.match(vpnStoreText, /connectionProgressStageOffset\.value \+ elapsedStage/)
    assert.match(vpnStoreText, /state:\s*index === activeStageIndex \? 'active'/)
    assert.match(vpnStoreText, /status\.value\?\.connect_progress\?\.steps/)
    assert.match(vpnStoreText, /normalizeBackendConnectionProgressSteps\(progress\.steps\)/)
    assert.match(vpnStoreText, /connectionProgressSteps\.value/)
  })

  it('preserves structured progress across partial status events', () => {
    const updateStatusStart = vpnStoreText.indexOf('function updateStatusFromEvent')
    assert.notEqual(updateStatusStart, -1)
    const updateStatusEnd = vpnStoreText.indexOf('const connectionProgress', updateStatusStart)
    assert.notEqual(updateStatusEnd, -1)
    const updateStatusBlock = vpnStoreText.slice(updateStatusStart, updateStatusEnd)

    assert.match(updateStatusBlock, /\.\.\.status\.value,\s*\.\.\.partialStatus/)
    assert.doesNotMatch(vpnStoreText, /delete\s+[^;\n]*connect_progress/)
    assert.doesNotMatch(vpnStoreText, /connect_progress:\s*undefined/)
  })

  it('treats full core status events as authoritative snapshots', () => {
    const fullSnapshotStart = vpnStoreText.indexOf('function isFullStatusSnapshot')
    assert.notEqual(fullSnapshotStart, -1)
    const reconcileStart = vpnStoreText.indexOf('function reconcileAuthoritativeStatusEvent')
    assert.notEqual(reconcileStart, -1)
    const updateStatusStart = vpnStoreText.indexOf('function updateStatusFromEvent')
    assert.notEqual(updateStatusStart, -1)
    const updateStatusEnd = vpnStoreText.indexOf('const connectionProgress', updateStatusStart)
    assert.notEqual(updateStatusEnd, -1)
    const updateStatusBlock = vpnStoreText.slice(updateStatusStart, updateStatusEnd)

    assert.match(vpnStoreText, /typeof data\.connected === 'boolean'/)
    assert.match(vpnStoreText, /typeof data\.process_running === 'boolean'/)
    assert.match(vpnStoreText, /typeof data\.phase === 'string'/)
    assert.match(vpnStoreText, /disconnectInFlight\.value &&[\s\S]*phase === 'idle'[\s\S]*disconnectInFlight\.value = false/)
    assert.match(vpnStoreText, /fullyDisconnected = !nextStatus\.connected && !nextStatus\.process_running/)
    assert.match(vpnStoreText, /connectInFlight\.value && connectTerminal[\s\S]*connectInFlight\.value = false/)
    assert.match(updateStatusBlock, /const fullSnapshot = isFullStatusSnapshot\(partialStatus\)/)
    assert.match(updateStatusBlock, /if \(fullSnapshot\) \{[\s\S]*reconcileAuthoritativeStatusEvent\(nextStatus\)/)
  })
})

describe('desktop log transport contract', () => {
  it('loads logs incrementally with a bounded cursor instead of full history', () => {
    const logsScript = vueScriptSetup(logsPageText)
    assert.match(logsScript, /LOG_FETCH_LIMIT\s*=\s*200/)
    assert.match(logsScript, /lastLogSeq/)
    assert.match(logsScript, /after_seq/)
    assert.match(logsScript, /loadLogChunk/)
    assert.match(logsScript, /setInterval\(\(\)\s*=>\s*{\s*void loadLogChunk\(false\)/)
    assert.match(logsScript, /api\.get<LogEntry\[\]>\('\/logs',\s*\{\s*params/)
  })

  it('passes log query parameters through the desktop host bridge', () => {
    assert.match(hostApiText, /get<T = unknown>\(path: string,\s*options\?:/)
    assert.match(hostApiText, /logs\.list\(plainPayload\(options\?\.params/)
  })

  it('filters logs by selected severity for visible, copied, and exported logs', () => {
    const logsScript = vueScriptSetup(logsPageText)
    const pageStateText = readSource('src', 'stores', 'pageState.ts')

    assert.match(pageStateText, /levelFilter:\s*'all'/)
    assert.match(logsScript, /type LogLevelFilter = 'all' \| 'warn_error' \| 'error'/)
    assert.match(logsScript, /const logLevelFilter = ref<LogLevelFilter>/)
    assert.match(logsScript, /function isWarningOrErrorLog\(entry: LogEntry\)/)
    assert.match(logsScript, /function logMatchesFilter\(entry: LogEntry\)/)
    assert.match(logsScript, /logLevelFilter\.value === 'warn_error'/)
    assert.match(logsScript, /logLevelFilter\.value === 'error'/)
    assert.match(logsPageText, /<select[\s\S]*v-model="logLevelFilter"/)
    assert.match(logsPageText, /全部显示/)
    assert.match(logsPageText, /仅警告和错误/)
    assert.match(logsPageText, /仅错误/)

    const downloadLogsStart = logsScript.indexOf('function downloadLogs()')
    assert.notEqual(downloadLogsStart, -1)
    const downloadLogsEnd = logsScript.indexOf('function copyTextFallback', downloadLogsStart)
    assert.notEqual(downloadLogsEnd, -1)
    const downloadLogsBlock = logsScript.slice(downloadLogsStart, downloadLogsEnd)
    assert.match(downloadLogsBlock, /formatLogs\(visibleLogs\.value\)/)

    const copyLogsStart = logsScript.indexOf('async function copyLogs()')
    assert.notEqual(copyLogsStart, -1)
    const copyLogsEnd = logsScript.indexOf('watch\(', copyLogsStart)
    assert.notEqual(copyLogsEnd, -1)
    const copyLogsBlock = logsScript.slice(copyLogsStart, copyLogsEnd)
    assert.match(copyLogsBlock, /formatLogs\(visibleLogs\.value\)/)
  })
})

describe('dashboard virtual network topology contract', () => {
  it('keeps upstream virtual adapter detection on the dashboard while hiding disconnected sidebar details', () => {
    assert.doesNotMatch(dashboardPageText, /network-probe-strip/)
    assert.match(dashboardPageText, /DashboardVisualStage/)
    assert.match(dashboardPageText, /routePolicyDescription/)
    assert.match(dashboardPageText, /vpn\.upstreamVirtualDetected/)
    assert.match(dashboardPageText, /vpn\.upstreamVirtualLabel/)
    assert.match(dashboardPageText, /:proxy-tun-label="proxyTunLabel"/)
    assert.match(dashboardVisualText, /代理 TUN/)
    assert.doesNotMatch(dashboardPageText, /tooltip:\s*upstreamVirtualTooltip\.value/)
    assert.doesNotMatch(dashboardPageText, /:title="node\.tooltip \|\| node\.title"/)
    assert.match(navBarText, /showSidebarStatusDetails\s*=\s*computed\(\(\) => Boolean\(vpn\.status\?\.connected\)\)/)
  })
})
