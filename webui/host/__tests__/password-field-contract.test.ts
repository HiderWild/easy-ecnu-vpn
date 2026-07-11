import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'

const webuiRoot = process.cwd()
const srcRoot = join(webuiRoot, 'src')
const overwriteHintText = '您已保存过密码，输入并确认后将覆盖原有密码'

function readSource(...parts: string[]) {
  return readFileSync(join(webuiRoot, ...parts), 'utf8')
}

function vueFiles(root: string): string[] {
  const entries = readdirSync(root, { withFileTypes: true })
  return entries.flatMap((entry) => {
    const path = join(root, entry.name)
    if (entry.isDirectory()) return vueFiles(path)
    return entry.isFile() && entry.name.endsWith('.vue') ? [path] : []
  })
}

function relativeVuePath(path: string) {
  return relative(srcRoot, path).replace(/\\/g, '/')
}

describe('password field contract', () => {
  it('centralizes password reveal icons in the shared password field components', () => {
    const allowed = new Set([
      'components/PasswordRevealButton.vue',
      'components/PasswordField.vue',
    ])

    for (const file of vueFiles(srcRoot)) {
      const source = readFileSync(file, 'utf8')
      const relativePath = relativeVuePath(file)
      const importsEye = /import\s*\{[^}]*\bEye\b[^}]*\}\s*from\s*'lucide-vue-next'/.test(source)
      const importsEyeOff = /import\s*\{[^}]*\bEyeOff\b[^}]*\}\s*from\s*'lucide-vue-next'/.test(source)
      const rendersEye = /<Eye(?:\s|\/|>)/.test(source)
      const rendersEyeOff = /<EyeOff(?:\s|\/|>)/.test(source)

      if (allowed.has(relativePath)) continue
      assert.equal(importsEye, false, `${relativePath} must not import Eye directly`)
      assert.equal(importsEyeOff, false, `${relativePath} must not import EyeOff directly`)
      assert.equal(rendersEye, false, `${relativePath} must not render Eye directly`)
      assert.equal(rendersEyeOff, false, `${relativePath} must not render EyeOff directly`)
    }
  })

  it('uses press-and-hold reveal semantics in the shared reveal button', () => {
    const button = readSource('src', 'components', 'PasswordRevealButton.vue')

    assert.match(button, /lucide-vue-next/)
    assert.match(button, /\bEye\b/)
    assert.doesNotMatch(button, /\bEyeOff\b/)
    assert.match(button, /aria-label="按住显示密码"/)
    assert.match(button, /title="按住显示密码"/)
    assert.match(button, /pointerdown/)
    assert.match(button, /pointerup/)
    assert.match(button, /pointercancel/)
    assert.match(button, /pointerleave/)
    assert.match(button, /@blur/)
    assert.match(button, /window\.addEventListener\('blur'/)
    assert.match(button, /keyup/)
    assert.match(button, /event\.key === ' '/)
    assert.match(button, /event\.key === 'Enter'/)
  })

  it('shows the unified stored-password overwrite hint at save-password entry points', () => {
    const files = [
      ['src', 'components', 'MinimalModeView.vue'],
      ['src', 'pages', 'settings', 'SettingsAuthSection.vue'],
      ['src', 'components', 'QuickStartDialog.vue'],
      ['src', 'components', 'CredentialPromptDialog.vue'],
    ] as const

    for (const parts of files) {
      const source = readSource(...parts)
      assert.match(
        source,
        new RegExp(`${overwriteHintText}|showSavedPasswordOverwriteHint|show-saved-password-overwrite-hint`),
        `${parts.join('/')} should show or bind the unified overwrite hint`,
      )
    }
  })

  it('removes legacy saved-password copy from password forms', () => {
    for (const file of vueFiles(srcRoot)) {
      const source = readFileSync(file, 'utf8')
      assert.equal(
        source.includes('已保存加密密码，仅在需要修改时输入。'),
        false,
        `${relativeVuePath(file)} should not use the legacy saved-password hint`,
      )
    }
  })
})
