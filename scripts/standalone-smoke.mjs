#!/usr/bin/env node
// 独立启动冒烟：只起 reference-authorizer 与 installer 两个进程，验证安装器
// 在没有主仓其余服务的情况下也能独立构建、启动并对外提供服务。
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { access, mkdtemp, readdir, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, resolve } from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const temporary = await mkdtemp(resolve(tmpdir(), 'azvf-ins-smoke-'))
const children = []

function base64(bytes = 32) {
  return randomBytes(bytes).toString('base64')
}

async function availablePort() {
  const server = createServer()
  await new Promise((resolvePromise, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolvePromise)
  })
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('无法分配冒烟测试端口')
  const { port } = address
  await new Promise((resolvePromise, reject) => server.close((error) => error ? reject(error) : resolvePromise()))
  return port
}

async function assertNoTestArtifacts(directory) {
  const entries = await readdir(directory, { withFileTypes: true })
  for (const entry of entries) {
    const path = resolve(directory, entry.name)
    if (entry.isDirectory()) await assertNoTestArtifacts(path)
    else if (/\.(?:test|spec)\./.test(entry.name) || entry.name.endsWith('.map')) {
      throw new Error(`构建产物包含禁止发布的测试或 source map 文件: ${path}`)
    }
  }
}

function launch(name, cwd, environment) {
  const output = []
  const child = spawn(process.execPath, ['dist/server.js'], {
    cwd,
    env: { ...process.env, ...environment },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  children.push(child)
  for (const stream of [child.stdout, child.stderr]) {
    stream.setEncoding('utf8')
    stream.on('data', (chunk) => {
      output.push(chunk)
      if (output.join('').length > 16_384) output.shift()
    })
  }
  child.once('exit', (code, signal) => {
    if (code !== null && code !== 0) process.stderr.write(`${name} 提前退出 (${code}):\n${output.join('')}\n`)
    if (code === null && signal && !['SIGTERM', 'SIGKILL'].includes(signal)) {
      process.stderr.write(`${name} 被信号终止 (${signal}):\n${output.join('')}\n`)
    }
  })
  return { name, child, output }
}

async function waitForHealth(service, url) {
  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    if (service.child.exitCode !== null || service.child.signalCode !== null) {
      throw new Error(`${service.name} 启动失败 (${service.child.exitCode ?? service.child.signalCode})\n${service.output.join('')}`)
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(1_000) })
      const body = await response.json()
      if (response.ok && body?.ok === true) return
    } catch {
      // 进程可能仍在绑定端口，继续轮询。
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 100))
  }
  throw new Error(`${service.name} 健康检查超时\n${service.output.join('')}`)
}

async function terminate(child) {
  if (child.exitCode !== null) return
  child.kill('SIGTERM')
  await Promise.race([
    new Promise((resolvePromise) => child.once('exit', resolvePromise)),
    new Promise((resolvePromise) => setTimeout(resolvePromise, 2_000)),
  ])
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGKILL')
    await new Promise((resolvePromise) => child.once('exit', resolvePromise))
  }
}

try {
  const requiredArtifacts = [
    'packages/contract/dist/index.js',
    'packages/reference-authorizer/dist/server.js',
    'packages/installer/dist/server.js',
    'packages/installer/dist-web/index.html',
  ]
  await Promise.all(requiredArtifacts.map((path) => access(resolve(root, path))))
  await Promise.all([
    'packages/contract/dist',
    'packages/reference-authorizer/dist',
    'packages/installer/dist',
    'packages/installer/dist-web',
  ].map((path) => assertNoTestArtifacts(resolve(root, path))))

  const authorizerPort = await availablePort()
  let installerPort = await availablePort()
  while (installerPort === authorizerPort) installerPort = await availablePort()

  const internalKey = base64()
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
  const publicPem = publicKey.export({ format: 'pem', type: 'spki' }).toString()
  const jwtKeyId = 'azvf-ins-smoke-v1'
  const tokenIssuer = 'azvf-ins-smoke-issuer'
  const tokenAudience = 'azvf-ins-smoke-installer'

  const authorizerService = launch('reference-authorizer', resolve(root, 'packages/reference-authorizer'), {
    HOST: '127.0.0.1',
    PORT: String(authorizerPort),
    LOG_LEVEL: 'silent',
    INTERNAL_CLIENT_ID: 'installer',
    INTERNAL_KEY_ID: 'v1',
    INTERNAL_SIGNING_KEY_B64: internalKey,
    CAPABILITY_HMAC_KEY_B64: base64(),
    JWT_KEY_ID: jwtKeyId,
    JWT_ED25519_PRIVATE_KEY: privatePem,
    TOKEN_ISSUER: tokenIssuer,
    TOKEN_AUDIENCE: tokenAudience,
  })
  await waitForHealth(authorizerService, `http://127.0.0.1:${authorizerPort}/health`)

  const deviceAddr = 'AA:BB:CC:DD:EE:01'
  const authorization = await fetch(`http://127.0.0.1:${authorizerPort}/api/device/authorizations`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deviceAddr }),
  })
  if (!authorization.ok) throw new Error(`reference-authorizer 未能签发设备授权 (HTTP ${authorization.status})`)
  const authorizationBody = await authorization.json()
  if (!authorizationBody?.resourceTokens || typeof authorizationBody.selectedResourceId !== 'string') {
    throw new Error('reference-authorizer 的设备授权响应格式无效')
  }

  const installerService = launch('installer', resolve(root, 'packages/installer'), {
    NODE_ENV: 'production',
    HOST: '127.0.0.1',
    PORT: String(installerPort),
    LOG_LEVEL: 'silent',
    CONSOLE_URL: `http://127.0.0.1:${authorizerPort}/`,
    ALLOW_INSECURE_INTERNAL_HTTP: 'true',
    INTERNAL_CLIENT_ID: 'installer',
    INTERNAL_KEY_ID: 'v1',
    INTERNAL_SIGNING_KEY_B64: internalKey,
    JWT_KEY_ID: jwtKeyId,
    JWT_ED25519_PUBLIC_KEY: publicPem,
    TOKEN_ISSUER: tokenIssuer,
    TOKEN_AUDIENCE: tokenAudience,
    REQUIRE_HTTPS: 'false',
    TRUST_PROXY: 'false',
    CORS_ORIGINS: 'https://installer.azvf-ins-smoke.invalid',
    INSTALLER_DATA_DIR: resolve(temporary, 'installer-data'),
    INSTALLER_DB_PATH: resolve(temporary, 'installer-data/installer.sqlite'),
    SERVE_STATIC: 'true',
    INSTALLER_STATIC_DIR: resolve(root, 'packages/installer/dist-web'),
  })
  await waitForHealth(installerService, `http://127.0.0.1:${installerPort}/health`)

  const installerIndex = await fetch(`http://127.0.0.1:${installerPort}/install/`)
  if (!installerIndex.ok || !(installerIndex.headers.get('content-type') ?? '').includes('text/html')) {
    throw new Error('Installer 静态入口不可用')
  }
  const installerHtml = await installerIndex.text()
  if (!installerHtml.includes('data-installer-boot-fallback')) {
    throw new Error('Installer 入口缺少脚本失败可见兜底')
  }

  const references = [...installerHtml.matchAll(/<(?:script|link)\b[^>]*\b(?:src|href)="([^"]+)"[^>]*>/gi)]
    .map((match) => match[1])
    .filter((value) => /^\/install\/assets\/.+\.(?:css|js)$/.test(value))
  if (!references.some((value) => value.endsWith('.css')) || !references.some((value) => value.endsWith('.js'))) {
    throw new Error('Installer 入口没有同时引用构建后的 CSS 与 JavaScript')
  }
  for (const reference of new Set(references)) {
    const asset = await fetch(`http://127.0.0.1:${installerPort}${reference}`)
    if (!asset.ok) throw new Error(`Installer 静态资源不可用: ${reference} (${asset.status})`)
    await asset.arrayBuffer()
  }

  const sessionAttempt = await fetch(`http://127.0.0.1:${installerPort}/api/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      authToken: authorizationBody.resourceTokens[authorizationBody.selectedResourceId],
      resourceId: authorizationBody.selectedResourceId,
      deviceAddr,
      clientPublicKey: 'not-a-real-key',
    }),
  })
  if (sessionAttempt.status < 400 || sessionAttempt.status >= 500) {
    throw new Error(`Installer /api/session 对畸形请求的响应异常 (HTTP ${sessionAttempt.status})`)
  }

  process.stdout.write('Standalone startup smoke passed: reference-authorizer and installer are independently runnable.\n')
} finally {
  await Promise.all(children.map(terminate))
  await rm(temporary, { recursive: true, force: true })
}
