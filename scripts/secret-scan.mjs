#!/usr/bin/env node
// 工作区文本内容的轻量秘密扫描，作为提交前的第一道关口。
// 完整的历史级扫描由 gitleaks 单独执行，不在本脚本职责内。
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const git = process.platform === 'win32' ? 'git.exe' : 'git'

const lsFilesOutput = execFileSync(
  git,
  ['ls-files', '--cached', '--others', '--exclude-standard'],
  { cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
)
const scannedFiles = lsFilesOutput.split(/\r?\n/).filter(Boolean)

const BINARY_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.webp', '.ico', '.woff2', '.wasm'])

const PATTERNS = [
  { name: 'PEM 私钥块', regex: /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/ },
  { name: 'AWS Access Key', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: 'GitHub Token', regex: /\bgh[pousr]_[0-9A-Za-z]{20,}\b/ },
  { name: 'GitHub 细粒度 Token', regex: /\bgithub_pat_[0-9A-Za-z_]{20,}\b/ },
  { name: 'Slack Token', regex: /\bxox[abpr]-[0-9A-Za-z-]{10,}\b/ },
  { name: 'Google API Key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'Stripe Live Key', regex: /\b(?:sk|pk|rk)_live_[0-9A-Za-z]{16,}\b/ },
  { name: 'npm Token', regex: /\bnpm_[0-9A-Za-z]{36}\b/ },
]

const ALLOWED_ENV_NAMES = new Set(['.env.example'])
const findings = []

for (const relativePath of scannedFiles) {
  const segments = relativePath.split('/')
  const base = segments.at(-1)

  if (base.startsWith('.env') && !ALLOWED_ENV_NAMES.has(base)) {
    findings.push({ file: relativePath, name: '未被 .gitignore 排除的 .env 文件', excerpt: base })
    continue
  }

  const dot = base.lastIndexOf('.')
  const extension = dot === -1 ? '' : base.slice(dot).toLowerCase()
  if (BINARY_EXTENSIONS.has(extension)) continue

  let buffer
  try {
    buffer = readFileSync(resolve(root, relativePath))
  } catch {
    continue
  }
  if (buffer.includes(0)) continue

  const content = buffer.toString('utf8')
  for (const pattern of PATTERNS) {
    const match = content.match(pattern.regex)
    if (match) findings.push({ file: relativePath, name: pattern.name, excerpt: match[0].slice(0, 24) })
  }
}

if (findings.length > 0) {
  console.error('秘密扫描发现以下可疑内容：')
  for (const finding of findings) console.error(`  [${finding.name}] ${finding.file}: ${finding.excerpt}…`)
  process.exit(1)
}

console.log(`秘密扫描通过：已检查 ${scannedFiles.length} 个文件，未发现已知模式的凭据泄漏。`)
