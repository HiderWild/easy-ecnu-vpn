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

  it('uses the same ECNU red fallback before the theme store initializes light mode', () => {
    const styleText = readWebui('src', 'style.css')
    const lightBlock = cssBlock(styleText, '[data-theme="light"]')

    assert.match(lightBlock, /--color-accent:\s*#A41F35;/)
    assert.match(lightBlock, /--color-accent-rgb:\s*164 31 53;/)
  })

  it('keeps the native advanced window contract at 972 by 563', () => {
    const frameText = readWebui('src', 'components', 'AppWindowFrame.vue')
    const layoutText = readRepo('src', 'app', 'ui_shell', 'window_layout.hpp')

    assert.match(frameText, /--advanced-width:\s*972px;/)
    assert.match(frameText, /--advanced-height:\s*563px;/)
    assert.match(layoutText, /kAppSurfaceAdvancedWindowBounds\{972,\s*563\}/)
  })

  it('splits dashboard presentation into focused components inside one compact grid', () => {
    const dashboardText = readWebui('src', 'pages', 'DashboardPage.vue')
    const expectedComponents = [
      'DashboardConnectionHero.vue',
      'DashboardTopologyMap.vue',
      'DashboardStatusRail.vue',
      'DashboardActionBar.vue',
    ]

    for (const component of expectedComponents) {
      assert.equal(fileExists('src', 'components', 'dashboard', component), true, `${component} should exist`)
      assert.match(dashboardText, new RegExp(`components/dashboard/${component.replace('.vue', '')}`))
    }

    assert.match(dashboardText, /dashboard-page-grid/)
    assert.doesNotMatch(dashboardText, /dashboard-card/)
  })

  it('keeps status motion meaningful and disables it for reduced motion users', () => {
    const styleText = readWebui('src', 'style.css')
    const dashboardFiles = [
      readWebui('src', 'pages', 'DashboardPage.vue'),
      readWebui('src', 'components', 'dashboard', 'DashboardConnectionHero.vue'),
      readWebui('src', 'components', 'dashboard', 'DashboardTopologyMap.vue'),
      readWebui('src', 'components', 'dashboard', 'DashboardStatusRail.vue'),
      readWebui('src', 'components', 'dashboard', 'DashboardActionBar.vue'),
    ].join('\n')

    assert.match(styleText, /@media \(prefers-reduced-motion:\s*reduce\)/)
    assert.match(dashboardFiles, /@media \(prefers-reduced-motion:\s*reduce\)/)
    assert.match(dashboardFiles, /dashboard-topology__pulse/)
    assert.match(dashboardFiles, /dashboard-hero__ring/)
    assert.match(dashboardFiles, /dashboard-status-rail__online-dot/)
    assert.doesNotMatch(dashboardFiles, /transition:\s*all\b/)
  })
})
