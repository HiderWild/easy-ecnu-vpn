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
const logsPageText = readSource('src', 'pages', 'LogsPage.vue')
const minimalModeViewText = readSource('src', 'components', 'MinimalModeView.vue')
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
  it('keeps only minimal mode in renderer localStorage', () => {
    const literals = stringLiterals(configStoreText)
    assert.ok(literals.includes('exv:minimal-mode'))
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
    assert.equal(deleted.has('service_install_prompt_seen'), false)
    assert.ok(hasObjectKeysLengthZeroReturn(configStoreText, 'remoteSettings'))
  })

  it('suppresses stale asynchronous window mode writes after rapid toggles', () => {
    const frameText = readSource('src', 'components', 'AppWindowFrame.vue')
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

  it('draws a stable one-pixel border around the native window surface', () => {
    const frameText = readSource('src', 'components', 'AppWindowFrame.vue')
    assert.ok(frameText.includes('--app-window-border-color'))
    assert.match(frameText, /border:\s*1px solid var\(--app-window-border-color\)/)
    assert.match(frameText, /box-sizing:\s*border-box/)
  })

  it('aligns the native window contour to the physical window edge', () => {
    const frameText = readSource('src', 'components', 'AppWindowFrame.vue')
    const shadowDeclaration = frameText.match(/--app-window-shadow:\s*([\s\S]*?);/)?.[1] ?? ''
    assert.ok(frameText.includes('--app-window-shadow'))
    assert.ok(frameText.includes('--app-window-shadow-margin'))
    assert.match(frameText, /--window-radius:\s*8px/)
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
})

describe('connection failure presentation contract', () => {
  it('maps asynchronous failed status snapshots into the user-facing error dialog', () => {
    const statusFields = interfacePropertyNames(vpnStoreText, 'VpnStatus')
    assert.ok(statusFields.has('error'))
    assert.ok(statusFields.has('error_code'))
    assert.ok(statusFields.has('error_recoverable'))
    assert.ok(statusFields.has('last_error'))
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
    assert.doesNotMatch(connectFromDashboardBlock, /if \(installServiceFirst\)/)
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
})

describe('dashboard virtual network topology contract', () => {
  it('keeps upstream virtual adapter detection on the dashboard while hiding disconnected sidebar details', () => {
    assert.doesNotMatch(dashboardPageText, /network-probe-strip/)
    assert.match(dashboardPageText, /DashboardVisualStage/)
    assert.match(dashboardPageText, /networkProbeSummary/)
    assert.match(dashboardPageText, /routePolicyDescription/)
    assert.match(dashboardPageText, /hasUpstreamVirtual/)
    assert.match(dashboardPageText, /vpn\.status\?\.upstream_virtual_detected/)
    assert.doesNotMatch(dashboardPageText, /tooltip:\s*upstreamVirtualTooltip\.value/)
    assert.doesNotMatch(dashboardPageText, /:title="node\.tooltip \|\| node\.title"/)
    assert.match(navBarText, /showSidebarStatusDetails\s*=\s*computed\(\(\) => Boolean\(vpn\.status\?\.connected\)\)/)
  })
})
