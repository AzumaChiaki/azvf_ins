#!/usr/bin/env node
import { execFileSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const pnpm = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm'
const rootManifest = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'))

const workspaces = JSON.parse(execFileSync(
  pnpm,
  ['-r', 'list', '--prod', '--json', '--depth', 'Infinity'],
  { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
))

const packages = new Map()

function visitDependencies(dependencies) {
  if (!dependencies || typeof dependencies !== 'object') return
  for (const [name, dependency] of Object.entries(dependencies)) {
    if (!dependency || typeof dependency !== 'object') continue
    if (typeof dependency.path === 'string' && typeof dependency.version === 'string') {
      packages.set(`${name}@${dependency.version}`, { name, version: dependency.version, path: dependency.path })
    }
    visitDependencies(dependency.dependencies)
  }
}

for (const workspace of workspaces) visitDependencies(workspace.dependencies)

function purl(name, version) {
  const encodedName = name.startsWith('@')
    ? `%40${name.slice(1).replace('/', '%2F')}`
    : name
  return `pkg:npm/${encodedName}@${encodeURIComponent(version)}`
}

const components = [...packages.values()]
  .filter((entry) => !entry.name.startsWith('@azvf/'))
  .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version))
  .map((entry) => {
    const manifest = JSON.parse(readFileSync(join(entry.path, 'package.json'), 'utf8'))
    const license = typeof manifest.license === 'string' && manifest.license.trim()
      ? manifest.license.trim()
      : undefined
    return {
      type: 'library',
      'bom-ref': purl(entry.name, entry.version),
      name: entry.name,
      version: entry.version,
      purl: purl(entry.name, entry.version),
      ...(license ? { licenses: [{ license: { name: license } }] } : {}),
    }
  })

const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    component: {
      type: 'application',
      name: rootManifest.name,
      version: rootManifest.version,
    },
  },
  components,
}

await mkdir(resolve(root, 'artifacts'), { recursive: true })
const outputPath = resolve(root, 'artifacts/sbom.cdx.json')
await writeFile(outputPath, `${JSON.stringify(sbom, null, 2)}\n`)
console.log(`已生成 SBOM：${outputPath}（${components.length} 个组件）`)
