import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

const webuiRoot = process.cwd()
const repoRoot = resolve(webuiRoot, '..')

function readWebui(...parts: string[]) {
  return readFileSync(join(webuiRoot, ...parts), 'utf8')
}

function readRepo(...parts: string[]) {
  return readFileSync(join(repoRoot, ...parts), 'utf8')
}

function fileExists(...parts: string[]) {
  return existsSync(join(webuiRoot, ...parts))
}

function cssBlock(text: string, selector: string) {
  const match = text.match(new RegExp(`${selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\{([\\s\\S]*?)\\n\\}`))
  assert.ok(match, `${selector} block should exist`)
  return match[1]
}

describe('theme dashboard contract', () => {
  it('keeps first-run theme mode on system while defaulting the light accent to ECNU red', () => {
    const themeText = readWebui('src', 'stores', 'theme.ts')

    assert.match(themeText, /const mode = ref<ThemeMode>\('system'\)/)
    assert.match(themeText, /const lightAccent = ref<LightAccentKey>\('red'\)/)
    assert.match(themeText, /const darkAccent = ref<DarkAccentKey>\('sky'\)/)
    assert.match(themeText, /light:\s*\[\s*\{\s*key:\s*'red'[\s\S]*?label:\s*'校徽红'[\s\S]*?color:\s*'#A41F35'[\s\S]*?rgb:\s*'164 31 53'/)
    assert.doesNotMatch(themeText, /light:\s*\[\s*\{\s*key:\s*'blue'/)
  })

  it('uses ECNU red accent and orange secondary highlight before the theme store initializes light mode', () => {
    const styleText = readWebui('src', 'style.css')
    const lightBlock = cssBlock(styleText, '[data-theme="light"]')

    assert.match(lightBlock, /--color-accent:\s*#A41F35;/)
    assert.match(lightBlock, /--color-accent-rgb:\s*164 31 53;/)
    assert.match(lightBlock, /--color-warning:\s*#C75A32;/)
    assert.match(lightBlock, /--color-warning-rgb:\s*199 90 50;/)
  })

  it('shows connection and DTLS in one sidebar status pill with a divider', () => {
    const navBarText = readWebui('src', 'components', 'NavBar.vue')
    const pillBlock = cssBlock(navBarText, '.sidebar-status-pill')

    assert.match(navBarText, /const dtlsState = computed/)
    assert.match(navBarText, /服务器未提供或不支持 DTLS/)
    assert.equal((navBarText.match(/class="sidebar-status-pill"/g) ?? []).length, 1)
    assert.match(navBarText, /sidebar-status-pill__divider/)
    assert.match(navBarText, /sidebar-status-pill__item--dtls/)
    assert.match(navBarText, /<Teleport to="body">/)
    assert.match(navBarText, /sidebar-floating-tooltip/)
    assert.match(navBarText, /positionDtlsTooltip/)
    assert.match(navBarText, /window\.addEventListener\('scroll', positionDtlsTooltip, true\)/)
    assert.match(pillBlock, /grid-template-columns:\s*minmax\(0,\s*1fr\)\s+auto\s+minmax\(0,\s*1fr\);/)
  })

  it('uses the store-level proxy TUN display label instead of raw transient status fields', () => {
    const vpnStoreText = readWebui('src', 'stores', 'vpn.ts')
    const dashboardText = readWebui('src', 'pages', 'DashboardPage.vue')
    const navBarText = readWebui('src', 'components', 'NavBar.vue')

    assert.match(vpnStoreText, /upstreamVirtualDisplayFromStatus/)
    assert.match(vpnStoreText, /upstreamVirtualDetected/)
    assert.match(vpnStoreText, /upstreamVirtualLabel/)
    assert.match(dashboardText, /vpn\.upstreamVirtualDetected/)
    assert.match(dashboardText, /vpn\.upstreamVirtualLabel/)
    assert.match(navBarText, /vpn\.upstreamVirtualLabel/)
    assert.doesNotMatch(navBarText, /upstream_virtual_adapters/)
  })

  it('keeps transient helper empty responses from status polling out of user errors', () => {
    const vpnStoreText = readWebui('src', 'stores', 'vpn.ts')
    const failureStart = vpnStoreText.indexOf('function handleStatusPollFailure')
    assert.notEqual(failureStart, -1)
    const failureEnd = vpnStoreText.indexOf('\n  async function fetchStatus', failureStart)
    assert.notEqual(failureEnd, -1)
    const failureBlock = vpnStoreText.slice(failureStart, failureEnd)

    assert.match(vpnStoreText, /function isTransientHelperStatusRefreshError/)
    assert.match(vpnStoreText, /Empty response from helper daemon/)
    assert.match(failureBlock, /isTransientHelperStatusRefreshError\(error\)/)
    assert.match(failureBlock, /return/)
    assert.match(failureBlock, /setError\(normalizeError\(error\)\)/)
  })

  it('keeps the native advanced window contract after the second dashboard width bump', () => {
    const frameText = readWebui('src', 'components', 'AppWindowFrame.vue')
    const layoutText = readRepo('src', 'app', 'ui_shell', 'window_layout.hpp')

    assert.match(frameText, /--advanced-width:\s*879px;/)
    assert.match(frameText, /--advanced-height:\s*563px;/)
    assert.match(layoutText, /kAppSurfaceAdvancedWindowBounds\{879,\s*563\}/)
  })

  it('keeps the dashboard power button centered in a wider right control lane', () => {
    const heroText = readWebui('src', 'components', 'dashboard', 'DashboardConnectionHero.vue')
    const heroBlock = cssBlock(heroText, '.dashboard-connection-hero')
    const ringBlock = cssBlock(heroText, '.dashboard-hero__ring')

    assert.match(heroBlock, /box-sizing:\s*border-box;/)
    assert.match(heroBlock, /grid-template-columns:\s*minmax\(0,\s*1fr\)\s+11\.75rem;/)
    assert.match(heroBlock, /align-items:\s*center;/)
    assert.match(ringBlock, /align-self:\s*center;/)
    assert.match(ringBlock, /justify-self:\s*center;/)
    assert.doesNotMatch(ringBlock, /justify-self:\s*end;/)
  })

  it('keeps titlebar theme mode buttons readable with added horizontal padding', () => {
    const controlText = readWebui('src', 'components', 'TitlebarThemeModeControl.vue')
    const buttonBlock = cssBlock(controlText, '.titlebar-theme-mode-control__button')
    const iconOnlyBlock = cssBlock(
      controlText,
      '.titlebar-theme-mode-control--icon-only .titlebar-theme-mode-control__button',
    )

    assert.match(buttonBlock, /min-width:\s*51px;/)
    assert.match(buttonBlock, /padding:\s*0 3px;/)
    assert.match(iconOnlyBlock, /padding:\s*0;/)
  })

  it('splits dashboard presentation into focused components inside one compact grid', () => {
    const dashboardText = readWebui('src', 'pages', 'DashboardPage.vue')
    const expectedComponents = [
      'DashboardConnectionHero.vue',
      'DashboardVisualStage.vue',
    ]

    for (const component of expectedComponents) {
      assert.equal(fileExists('src', 'components', 'dashboard', component), true, `${component} should exist`)
      assert.match(dashboardText, new RegExp(`components/dashboard/${component.replace('.vue', '')}`))
    }

    assert.equal(fileExists('src', 'components', 'dashboard', 'DashboardStatusRail.vue'), false)
    assert.doesNotMatch(dashboardText, /DashboardStatusRail/)
    assert.doesNotMatch(dashboardText, /dashboard-page-grid__side/)
    assert.match(dashboardText, /dashboard-page-grid/)
    assert.match(dashboardText, /dashboard-page-grid__visual/)
    assert.doesNotMatch(dashboardText, /dashboard-card/)
    assert.doesNotMatch(dashboardText, /DashboardTopologyMap/)
    assert.doesNotMatch(dashboardText, /topologyNodes|arcSegments|visibleReadySegments/)
  })

  it('prepares the dashboard center area as an animation-ready visual stage', () => {
    const dashboardText = readWebui('src', 'pages', 'DashboardPage.vue')
    const visualStageText = readWebui('src', 'components', 'dashboard', 'DashboardVisualStage.vue')

    assert.match(dashboardText, /DashboardVisualStage/)
    assert.match(dashboardText, /visualStageSteps/)
    assert.match(dashboardText, /visualStageCurrentKey/)
    assert.match(visualStageText, /ConnectionProgressStage/)
    assert.match(visualStageText, /dashboard-visual-stage__hologram/)
    assert.match(visualStageText, /dashboard-visual-stage__steps/)
    assert.match(visualStageText, /TransitionGroup/)
    assert.match(visualStageText, /<svg/)
    assert.doesNotMatch(visualStageText, /dashboard-topology|Topology|arcSegments|visibleReadySegments/)
  })

  it('keeps the dashboard progress copy vertically centered beside the visual stage', () => {
    const visualStageText = readWebui('src', 'components', 'dashboard', 'DashboardVisualStage.vue')
    const progressCopyBlock = cssBlock(
      visualStageText,
      '.dashboard-visual-stage.is-progress .dashboard-visual-stage__copy',
    )

    assert.match(progressCopyBlock, /display:\s*flex;/)
    assert.match(progressCopyBlock, /align-self:\s*center;/)
    assert.match(progressCopyBlock, /justify-content:\s*center;/)
    assert.doesNotMatch(progressCopyBlock, /align-self:\s*stretch;/)
  })

  it('keeps the fine-grained connection steps visible during progress layout', () => {
    const visualStageText = readWebui('src', 'components', 'dashboard', 'DashboardVisualStage.vue')
    const stepsBlock = cssBlock(visualStageText, '.dashboard-visual-stage__steps')

    assert.match(visualStageText, /<ol\s+v-if="hasProgress"[\s\S]*dashboard-visual-stage__steps/)
    assert.match(stepsBlock, /flex:\s*0\s+1\s+auto;/)
    assert.doesNotMatch(stepsBlock, /flex:\s*1\s+1\s+0;/)
    assert.match(stepsBlock, /max-height:\s*clamp\(/)
  })

  it('keeps pre-connect status and choices inside the dashboard visual stage', () => {
    const dashboardText = readWebui('src', 'pages', 'DashboardPage.vue')
    const visualStageText = readWebui('src', 'components', 'dashboard', 'DashboardVisualStage.vue')

    assert.match(dashboardText, /v-model:minimize-to-tray-on-connect/)
    assert.match(dashboardText, /const showMinimizeToTrayChoice = computed/)
    assert.match(dashboardText, /:show-minimize-to-tray-choice="showMinimizeToTrayChoice"/)
    assert.match(dashboardText, /:show-install-service-choice="showInstallServiceChoice"/)
    assert.match(dashboardText, /:core-status-label="coreStatusLabel"/)
    assert.match(dashboardText, /v-model:auto-reconnect="autoReconnect"/)
    assert.match(dashboardText, /v-model:retry-limit="retryLimit"/)
    assert.match(dashboardText, /saveSettings\(\{\s*minimize_to_tray_on_connect:\s*value\s*\}\)/)
    assert.match(dashboardText, /saveSettings\(\{\s*auto_reconnect:\s*value\s*\}\)/)
    assert.match(dashboardText, /saveSettings\(\{\s*retry_limit:\s*Math\.max\(0,\s*Math\.trunc\(value \|\| 0\)\)\s*\}\)/)
    assert.match(visualStageText, /dashboard-visual-stage__preconnect/)
    assert.match(visualStageText, /连接前安装服务/)
    assert.match(visualStageText, /连接后缩小到托盘区/)
    assert.match(visualStageText, /内核通信/)
    assert.match(visualStageText, /服务状态/)
    assert.match(visualStageText, /代理 TUN/)
    assert.match(visualStageText, /断线重连/)
    assert.match(visualStageText, /handleAutoReconnectChange/)
    assert.match(visualStageText, /handleRetryLimitInput/)
    assert.match(visualStageText, /type="number"/)
    assert.doesNotMatch(visualStageText, /reconnectLabel/)
    assert.match(visualStageText, /update:minimizeToTrayOnConnect/)
    assert.match(visualStageText, /handleMinimizeToTrayChange/)
  })

  it('keeps connection and DTLS status out of the dashboard center area', () => {
    const dashboardText = readWebui('src', 'pages', 'DashboardPage.vue')
    const visualStageText = readWebui('src', 'components', 'dashboard', 'DashboardVisualStage.vue')

    assert.doesNotMatch(dashboardText, /:connection-state-label=/)
    assert.doesNotMatch(dashboardText, /:dtls-state-label=/)
    assert.doesNotMatch(visualStageText, /连接状态/)
    assert.doesNotMatch(visualStageText, /DTLS 状态/)
    assert.doesNotMatch(visualStageText, /dashboard-visual-stage__status-summary/)
  })

  it('hides disconnected explanatory copy from the dashboard center controls', () => {
    const dashboardText = readWebui('src', 'pages', 'DashboardPage.vue')
    const visualStageText = readWebui('src', 'components', 'dashboard', 'DashboardVisualStage.vue')

    assert.doesNotMatch(dashboardText, /准备建立校园网连接/)
    assert.doesNotMatch(dashboardText, /已发现代理 TUN：/)
    assert.doesNotMatch(dashboardText, /连接时校园内网路由会写入 EXV 虚拟网卡/)
    assert.match(visualStageText, /v-if="!showPreConnectInfo"/)
  })

  it('keeps status motion meaningful and disables it for reduced motion users', () => {
    const styleText = readWebui('src', 'style.css')
    const dashboardFiles = [
      readWebui('src', 'pages', 'DashboardPage.vue'),
      readWebui('src', 'components', 'dashboard', 'DashboardConnectionHero.vue'),
      readWebui('src', 'components', 'dashboard', 'DashboardVisualStage.vue'),
    ].join('\n')

    assert.match(styleText, /@media \(prefers-reduced-motion:\s*reduce\)/)
    assert.match(dashboardFiles, /@media \(prefers-reduced-motion:\s*reduce\)/)
    assert.match(dashboardFiles, /dashboard-visual-stage__signal/)
    assert.match(dashboardFiles, /dashboard-hero__ring/)
    assert.doesNotMatch(dashboardFiles, /dashboard-visual-stage__online-dot/)
    assert.doesNotMatch(dashboardFiles, /transition:\s*all\b/)
  })
})
