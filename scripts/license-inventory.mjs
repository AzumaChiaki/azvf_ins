import { execFileSync } from 'node:child_process'
import { mkdir, writeFile } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const pnpm = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm'
const workspaces = JSON.parse(execFileSync(
  pnpm,
  ['-r', 'list', '--prod', '--json', '--depth', 'Infinity'],
  { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
))

const packages = new Map()

function visitDependencies(dependencies) {
  if (!dependencies || typeof dependencies !== 'object') return
  for (const [name, dependency] of Object.entries(dependencies)) {
    if (!dependency || typeof dependency !== 'object') continue
    if (typeof dependency.path === 'string' && typeof dependency.version === 'string') {
      packages.set(`${name}@${dependency.version}`, dependency.path)
    }
    visitDependencies(dependency.dependencies)
  }
}

for (const workspace of workspaces) visitDependencies(workspace.dependencies)

const rows = []
const entries = []
const missing = []
for (const [identity, path] of [...packages].sort(([a], [b]) => a.localeCompare(b))) {
  const manifest = JSON.parse(readFileSync(join(path, 'package.json'), 'utf8'))
  if (manifest.private === true || String(manifest.name ?? '').startsWith('@azvf/')) continue
  let license = manifest.license
  if (!license && Array.isArray(manifest.licenses)) {
    license = manifest.licenses.map((entry) => typeof entry === 'string' ? entry : entry?.type).filter(Boolean).join(' OR ')
  }
  const normalized = typeof license === 'string' && license.trim() ? license.trim() : 'MISSING'
  const [name, version] = [identity.slice(0, identity.lastIndexOf('@')), identity.slice(identity.lastIndexOf('@') + 1)]
  rows.push(`${identity}\t${normalized}`)
  entries.push({ name, version, license: normalized })
  if (normalized === 'MISSING' || /^UNLICENSED$/i.test(normalized)) missing.push(identity)
}

process.stdout.write(`PACKAGE\tLICENSE\n${rows.join('\n')}\n`)

await mkdir(resolve(root, 'artifacts'), { recursive: true })
await writeFile(
  resolve(root, 'artifacts/licenses.json'),
  `${JSON.stringify({ generatedAt: new Date().toISOString(), packages: entries }, null, 2)}\n`,
)

if (missing.length) {
  process.stderr.write(`以下生产依赖没有可识别的许可证声明：${missing.join(', ')}\n`)
  process.exitCode = 1
}
