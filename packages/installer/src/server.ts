import './loadenv.js'
import { constants as fsConstants, createReadStream, existsSync, realpathSync } from 'node:fs'
import { access, readdir, realpath, stat } from 'node:fs/promises'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { extname, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import Fastify, { LogController, type FastifyInstance, type FastifyReply } from 'fastify'
import cors from '@fastify/cors'
import { configureInternalClient } from '@azvf/internal-client'
import { config } from './config.js'
import { RateLimiter } from './rateLimit.js'
import { installerRoutes } from './routes.js'

configureInternalClient(config)

const MIME_TYPES: Readonly<Record<string, string>> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
}

const DEFAULT_MAINTENANCE_FILE = '/run/azvf/deploy-maintenance'
const VITE_ASSET_PATH = /^\/install\/assets\/[A-Za-z0-9][A-Za-z0-9_.-]*-[A-Za-z0-9_-]{8,}\.(?:css|ico|jpe?g|js|json|png|svg|webp|woff2)$/

/** Resolve only the public files emitted by Vite without decoding attacker input. */
export function resolveInstallerStaticPath(rawPath: string): string | undefined {
  const queryStart = rawPath.indexOf('?')
  const path = queryStart === -1 ? rawPath : rawPath.slice(0, queryStart)
  if (path === '/install' || path === '/install/' || path === '/install/index.html') return 'index.html'
  return VITE_ASSET_PATH.test(rawPath) ? rawPath.slice('/install/'.length) : undefined
}

export function rejectBadInstallerUrl(_path: string, _request: IncomingMessage, response: ServerResponse): void {
  response.statusCode = 404
  response.setHeader('content-type', 'application/json; charset=utf-8')
  response.setHeader('cache-control', 'no-store')
  response.setHeader('x-content-type-options', 'nosniff')
  response.end('{"error":"not found"}')
}

function staticNotFound(reply: FastifyReply) {
  return reply.header('cache-control', 'no-store').code(404).send({ error: 'not found' })
}

/**
 * Normalizes a raw Origin header for allowlist comparison. A `crossorigin`
 * module/stylesheet sends Origin even on same-origin fetches, and some
 * embedders (WeChat's WebView, certain proxies) append the default port
 * (`https://host:443`); `new URL(...).origin` strips that, while a bare
 * `Set.has(raw)` would 403 the asset and leave the page stuck on the boot
 * fallback. Malformed values (`null`, userinfo, path, query) resolve to
 * undefined so the caller treats them as untrusted instead of matching.
 */
export function normalizeOrigin(raw: string): string | undefined {
  if (raw === 'null') return undefined
  try {
    const parsed = new URL(raw)
    if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) return undefined
    return parsed.origin
  } catch {
    return undefined
  }
}

export function registerInstallerStaticRoutes(app: FastifyInstance, staticRoot: string): void {
  const sendStatic = async (rawPath: string, reply: FastifyReply) => {
    const allowedPath = resolveInstallerStaticPath(rawPath)
    if (!allowedPath) return staticNotFound(reply)
    const candidate = resolve(staticRoot, allowedPath)
    if (relative(staticRoot, candidate).startsWith(`..${sep}`) || candidate === staticRoot) return staticNotFound(reply)
    try {
      const info = await stat(candidate)
      if (!info.isFile()) return staticNotFound(reply)
      const canonical = await realpath(candidate)
      if (relative(staticRoot, canonical).startsWith(`..${sep}`)) return staticNotFound(reply)
      const extension = extname(canonical).toLowerCase()
      reply.type(MIME_TYPES[extension] ?? 'application/octet-stream')
      reply.header('cache-control', allowedPath.startsWith('assets/') ? 'public, max-age=31536000, immutable' : 'no-cache')
      reply.header('content-length', String(info.size))
      return reply.send(createReadStream(canonical))
    } catch (error: any) {
      if (error?.code === 'ENOENT') return staticNotFound(reply)
      throw error
    }
  }
  app.get('/install', async (req, reply) => sendStatic(req.raw.url ?? '', reply))
  app.get('/install/*', async (req, reply) => sendStatic(req.raw.url ?? '', reply))
}

const BROWSER_FILE_PATTERN = /^\/browsers\/[A-Za-z0-9][A-Za-z0-9_.-]{1,128}\.(?:exe|pkg|apk|dmg|deb|rpm)$/
const BROWSER_DIR_DEFAULT = '/run/azvf/browsers'

export function resolveBrowserDownloadPath(rawPath: string): string | undefined {
  if (!BROWSER_FILE_PATTERN.test(rawPath)) return undefined
  return rawPath.slice('/browsers/'.length) // strip '/browsers/' prefix, leaving just the file name
}

/** Lets the frontend hide a "备用下载" button instead of linking to a file the operator never uploaded. */
export function registerBrowserManifestRoute(app: FastifyInstance, staticRoot: string): void {
  app.get('/browsers/_manifest', async (_req, reply) => {
    let entries: string[]
    try { entries = await readdir(staticRoot) } catch { entries = [] }
    const files = entries.filter((name) => BROWSER_FILE_PATTERN.test(`/browsers/${name}`))
    return reply.header('cache-control', 'no-store').send({ files })
  })
}

export function registerBrowserDownloadRoutes(app: FastifyInstance, staticRoot: string): void {
  app.get('/browsers/:file', async (req, reply) => {
    const rawPath = req.raw.url ?? ''
    const relativePath = resolveBrowserDownloadPath(rawPath)
    if (!relativePath) {
      return reply.header('cache-control', 'no-store').code(404).send({ error: 'not found' })
    }
    const candidate = resolve(staticRoot, relativePath)
    if (relative(staticRoot, candidate).startsWith(`..${sep}`) || candidate === staticRoot) {
      return reply.header('cache-control', 'no-store').code(404).send({ error: 'not found' })
    }
    try {
      const info = await stat(candidate)
      if (!info.isFile()) {
        return reply.header('cache-control', 'no-store').code(404).send({ error: 'not found' })
      }
      const canonical = await realpath(candidate)
      if (relative(staticRoot, canonical).startsWith(`..${sep}`)) {
        return reply.header('cache-control', 'no-store').code(404).send({ error: 'not found' })
      }
      const extension = extname(canonical).toLowerCase()
      const mime: Record<string, string> = {
        '.exe': 'application/vnd.microsoft.portable-executable',
        '.pkg': 'application/x-xar',
        '.apk': 'application/vnd.android.package-archive',
        '.dmg': 'application/x-apple-diskimage',
        '.deb': 'application/vnd.debian.binary-package',
        '.rpm': 'application/x-rpm',
      }
      reply.type(mime[extension] ?? 'application/octet-stream')
      reply.header('cache-control', 'public, max-age=86400')
      reply.header('content-length', String(info.size))
      return reply.send(createReadStream(canonical))
    } catch (error: any) {
      if (error?.code === 'ENOENT') {
        return reply.header('cache-control', 'no-store').code(404).send({ error: 'not found' })
      }
      throw error
    }
  })
}

export function resolveMaintenanceFile(
  production: boolean,
  override: string | undefined = process.env.AZVF_MAINTENANCE_FILE,
): string | undefined {
  const configured = override?.trim()
  if (production) {
    if (configured && configured !== DEFAULT_MAINTENANCE_FILE) {
      throw new Error('生产 AZVF_MAINTENANCE_FILE 必须使用固定部署门禁路径')
    }
    return DEFAULT_MAINTENANCE_FILE
  }
  if (configured) return configured
  return undefined
}

export function registerMaintenanceGate(app: FastifyInstance, production: boolean): void {
  const maintenanceFile = resolveMaintenanceFile(production)
  if (!maintenanceFile) return
  app.addHook('onRequest', async (request, reply) => {
    const safeRead = (request.method === 'GET' || request.method === 'HEAD')
      && (request.url === '/health' || request.url === '/install' || request.url === '/install/'
        || /^\/install\/assets\/[^/?#]+-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*$/.test(request.url))
    if (safeRead || !existsSync(maintenanceFile)) return
    return reply.header('cache-control', 'no-store').code(503).send({ error: 'maintenance' })
  })
}

export async function buildServer() {
  const app = Fastify({
    routerOptions: { onBadUrl: rejectBadInstallerUrl },
    logger: {
      level: process.env.LOG_LEVEL ?? 'info',
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'req.body.code',
          'req.body.deviceSessionToken',
          'req.headers.x-session-control',
          'req.headers.x-azvf-resource-capability',
          'res.headers.set-cookie',
        ],
        censor: '[REDACTED]',
      },
    },
    logController: new LogController({ disableRequestLogging: true }),
    bodyLimit: config.maxBodyBytes,
    // Only the directly connected reverse proxy may supply forwarding data;
    // trusting an arbitrary chain lets clients forge req.ip and bypass limits.
    trustProxy: config.trustProxy ? 1 : false,
    requestTimeout: 30_000,
    connectionTimeout: 10_000,
    keepAliveTimeout: 5_000,
    maxRequestsPerSocket: 1_000,
  })
  registerMaintenanceGate(app, config.env === 'production')
  const globalLimiter = new RateLimiter()

  await app.register(cors, {
    origin(origin, callback) {
      if (!origin) return callback(null, true)
      const normalized = normalizeOrigin(origin)
      callback(null, normalized !== undefined && config.corsOrigins.has(normalized))
    },
    credentials: false,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['content-type', 'authorization', 'x-session-control'],
    maxAge: 600,
    strictPreflight: true,
  })

  app.addHook('onRequest', async (req, reply) => {
    const origin = req.headers.origin
    if (origin) {
      const normalized = normalizeOrigin(origin)
      if (normalized === undefined || !config.corsOrigins.has(normalized)) return reply.code(403).send({ error: 'Origin 不受信任' })
    }
    if (config.requireHttps && req.protocol !== 'https') {
      return reply.code(426).header('upgrade', 'TLS/1.3').send({ error: '必须使用 HTTPS' })
    }
    if (req.url.startsWith('/api/')) {
      const rate = globalLimiter.consume(`api:${req.ip}`, config.apiRateLimitPerMinute)
      if (!rate.allowed) {
        return reply.header('retry-after', String(rate.retryAfterSeconds)).code(429).send({ error: '请求过于频繁' })
      }
    }
  })

  app.addHook('onSend', async (req, reply, payload) => {
    reply.header('x-content-type-options', 'nosniff')
    reply.header('x-frame-options', 'DENY')
    reply.header('referrer-policy', 'no-referrer')
    reply.header('cross-origin-opener-policy', 'same-origin')
    reply.header('cross-origin-resource-policy', 'same-origin')
    reply.header('permissions-policy', 'camera=(), microphone=(), geolocation=(), serial=(self), bluetooth=(self)')
    reply.header(
      'content-security-policy',
      // 下面的 sha256 授权安装页入口文档（index.html）的内联启动脚本：
      // <script nomodule> 旧浏览器提示，以及 boot-fallback / 加载失败看门狗。
      // 缺少任一哈希会让 'script-src self' 静默拦截对应的降级 UI。修改这些
      // 内联块后须重算哈希。
      "default-src 'none'; script-src 'self' 'sha256-i3y6CxKxa9/0FSnrkoNtfV/hJ7KHbarE4ijhd22vUrs=' 'sha256-3z530lbaTfto6CIqfeU+4VzmOqBDDxEuX+KWGrFrTHw=' 'sha256-ipswPX6KkVoyOCimxGno2Mtz7GRkD7W0/mu6wDOskX0='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; worker-src 'self' blob:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'",
    )
    if (config.requireHttps || req.protocol === 'https') reply.header('strict-transport-security', 'max-age=31536000; includeSubDomains')
    if (req.url.startsWith('/api/')) reply.header('cache-control', 'no-store')
    return payload
  })

  app.setErrorHandler((error, req, reply) => {
    const safeError = error as { statusCode?: number; validation?: unknown }
    const status = safeError.statusCode ?? 500
    if (status >= 500) req.log.error({ err: error }, 'unhandled installer request error')
    if (status === 413) return reply.code(413).send({ error: '请求体过大' })
    if (status === 415) return reply.code(415).send({ error: 'Content-Type 不受支持' })
    if (safeError.validation) return reply.code(400).send({ error: '请求格式无效' })
    return reply.code(status >= 400 && status < 500 ? status : 500).send({ error: status >= 500 ? '服务内部错误' : '请求失败' })
  })

  await installerRoutes(app)

  if (config.serveStatic) {
    let staticRoot: string | undefined
    try {
      await access(config.staticDir, fsConstants.R_OK)
      staticRoot = await realpath(config.staticDir)
    } catch (error) {
      if (config.env === 'production') throw new Error(`Installer 前端产物不存在或不可读: ${config.staticDir}`, { cause: error })
      app.log.warn({ path: config.staticDir }, 'Installer static assets are unavailable')
    }

    if (staticRoot) registerInstallerStaticRoutes(app, staticRoot)

    // Browser installer downloads served from a separate directory so large
    // binaries never leak into the Vite public/ build pipeline. The directory
    // must be provisioned by the operator — see deploy/README.md.
    const browserDir = resolve(process.env.INSTALLER_BROWSER_DIR ?? BROWSER_DIR_DEFAULT)
    try {
      await access(browserDir, fsConstants.R_OK)
      registerBrowserManifestRoute(app, browserDir)
      registerBrowserDownloadRoutes(app, browserDir)
    } catch {
      app.log.info({ path: browserDir }, 'browser installer directory not available — fallback download links will 404')
    }
  }

  app.setNotFoundHandler((req, reply) => {
    reply.header('cache-control', 'no-store')
    if (req.url.startsWith('/api/')) return reply.code(404).send({ error: 'not found' })
    return reply.code(404).type('text/plain; charset=utf-8').send('Not Found')
  })

  return app
}

async function main() {
  const app = await buildServer()
  await app.listen({ port: config.port, host: config.host })
}

const entryPoint = process.argv[1] ? realpathSync(resolve(process.argv[1])) : ''
if (entryPoint === realpathSync(fileURLToPath(import.meta.url))) {
  main().catch((error) => {
    console.error(error)
    process.exit(1)
  })
}
