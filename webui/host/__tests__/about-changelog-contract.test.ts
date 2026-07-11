import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { changelogEntries } from '../../src/data/changelog.js'

const expectedVersions = ['3.3.6', '3.3.5', '3.3.4', '3.3.3', '3.3.2', '3.3.1', '3.3.0']

assert.deepEqual(
  changelogEntries.map((entry) => entry.version),
  expectedVersions,
  'About changelog versions must stay newest-to-oldest from 3.3.0 through current',
)

for (const entry of changelogEntries) {
  assert.equal(typeof entry.title, 'string', `${entry.version} title must be present`)
  assert.ok(entry.title.length > 0, `${entry.version} title must be non-empty`)
  assert.match(entry.dateLabel, /^\d{4}-\d{2}-\d{2}$/, `${entry.version} date must be yyyy-mm-dd`)
  assert.ok(entry.highlights.length >= 3, `${entry.version} should have at least three highlights`)
  for (const highlight of entry.highlights) {
    assert.ok(highlight.length >= 12, `${entry.version} highlight should be descriptive`)
  }
}

const inferredVersions = changelogEntries
  .filter((entry) => entry.inferred)
  .map((entry) => entry.version)
assert.deepEqual(inferredVersions, ['3.3.4', '3.3.1'])

const aboutPage = readFileSync(join(process.cwd(), 'src', 'pages', 'AboutPage.vue'), 'utf8')
assert.match(aboutPage, /from '..\/data\/changelog'/)
assert.match(aboutPage, /更新日志/)
assert.match(aboutPage, /v-for="\(entry, index\) in changelogEntries"/)
assert.match(aboutPage, /:open="index === 0"/)
assert.match(aboutPage, /历史归纳/)
