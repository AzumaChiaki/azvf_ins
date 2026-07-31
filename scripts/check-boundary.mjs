#!/usr/bin/env node
// 安装器构建产物边界扫描：
//   1. 产物中不得出现商业实现、固定生产域名或 reference-authorizer 演示/测试
//      专属标识。
//   2. 产物中必须包含完整的版权与来源署名（作者、上游项目、源码地址）。
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const distWeb = resolve(root, 'packages/installer/dist-web')
const serverEntry = resolve(root, 'packages/installer/dist/server.js')

if (!existsSync(join(distWeb, 'index.html'))) {
  console.error('未找到 Installer 构建产物；请先执行 pnpm --filter @azvf/installer build。')
  process.exit(1)
}
if (!existsSync(serverEntry)) {
  console.error('未找到 Installer 服务端构建产物；请先执行 pnpm --filter @azvf/installer build。')
  process.exit(1)
}

const COMMERCIAL_MARKERS = [
  'afdian', '/api/redeem', '/api/contacts', 'buyer-session-bar',
  'dashboard-order', 'outTradeNo', 'cardkey',
]
const REFERENCE_AUTHORIZER_MARKERS = [
  'reference-authorizer', 'reference-resource', 'reference-entitlement',
  'AZVF reference authorizer resource',
]
const PRODUCTION_DOMAIN_MARKERS = ['azumachiaki.com']
const FORBIDDEN_MARKERS = [...COMMERCIAL_MARKERS, ...REFERENCE_AUTHORIZER_MARKERS, ...PRODUCTION_DOMAIN_MARKERS]

// 必须可见的版权与来源署名字符串。
const REQUIRED_MARKERS = ['AzumaChiaki', 'AstroBox-NG', 'github.com/AzumaChiaki/azvf_ins']

function collectClientAssets() {
  const html = readFileSync(join(distWeb, 'index.html'), 'utf8')
  const assets = join(distWeb, 'assets')
  const absolutePattern = /\/install\/assets\/([\w.-]+\.js)/g
  const chunks = new Set()
  const queue = [...html.matchAll(absolutePattern)].map((match) => match[1])
  while (queue.length > 0) {
    const name = queue.pop()
    if (!name || chunks.has(name)) continue
    chunks.add(name)
    const file = join(assets, name)
    if (!existsSync(file)) continue
    const source = readFileSync(file, 'utf8')
    for (const match of source.matchAll(/["'`]\.\/([\w.-]+\.js)["'`]/g)) queue.push(match[1])
    for (const match of source.matchAll(absolutePattern)) queue.push(match[1])
  }
  const cssPattern = /\/install\/assets\/([\w.-]+\.css)/g
  const css = [...html.matchAll(cssPattern)].map((match) => match[1])
  return { html, chunks: [...chunks], css, assets }
}

const client = collectClientAssets()
const violations = []
const missingRequired = []

function scanText(label, source) {
  for (const marker of FORBIDDEN_MARKERS) {
    if (source.includes(marker)) violations.push({ label, marker })
  }
}

scanText('index.html', client.html)
for (const name of client.chunks) scanText(`assets/${name}`, readFileSync(join(client.assets, name), 'utf8'))
for (const name of client.css) scanText(`assets/${name}`, readFileSync(join(client.assets, name), 'utf8'))

const serverSource = readFileSync(serverEntry, 'utf8')
scanText('dist/server.js', serverSource)

const clientCorpus = client.html + client.chunks.map((name) => readFileSync(join(client.assets, name), 'utf8')).join('\n')
for (const marker of REQUIRED_MARKERS) {
  if (!clientCorpus.includes(marker)) missingRequired.push(marker)
}

console.log(`Installer chunks（${client.chunks.length}）：${client.chunks.join(', ') || '(none)'}`)
console.log(`Installer styles（${client.css.length}）：${client.css.join(', ') || '(none)'}`)

let failed = false
if (violations.length > 0) {
  failed = true
  console.error('\n边界检查未通过——产物中出现禁止标识：')
  for (const violation of violations) console.error(`  [${violation.label}] 含有 ${violation.marker}`)
}
if (missingRequired.length > 0) {
  failed = true
  console.error('\n边界检查未通过——产物缺少必需的合规署名标识：')
  for (const marker of missingRequired) console.error(`  缺少 ${marker}`)
}

if (failed) process.exit(1)
console.log('\n边界检查通过：无违规标识混入，合规署名完整可见。')
