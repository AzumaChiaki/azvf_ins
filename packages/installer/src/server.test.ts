import { mkdir, mkdtemp, realpath, rm, symlink, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Fastify from 'fastify'
import { afterEach, describe, expect, it } from 'vitest'
import {
  normalizeOrigin,
  registerBrowserDownloadRoutes,
  registerBrowserManifestRoute,
  registerInstallerStaticRoutes,
  registerMaintenanceGate,
  rejectBadInstallerUrl,
  resolveBrowserDownloadPath,
  resolveInstallerStaticPath,
  resolveMaintenanceFile,
} from './server.js'

const temporaryDirectories: string[] = []

afterEach(async () => {
  delete process.env.AZVF_MAINTENANCE_FILE
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })))
})

describe('Installer static path allowlist', () => {
  it('allows only the install entry and install-scoped Vite hashed assets', () => {
    expect(resolveInstallerStaticPath('/')).toBeUndefined()
    expect(resolveInstallerStaticPath('/index.html')).toBeUndefined()
    expect(resolveInstallerStaticPath('/install')).toBe('index.html')
    expect(resolveInstallerStaticPath('/install/')).toBe('index.html')
    expect(resolveInstallerStaticPath('/install/index.html')).toBe('index.html')
    expect(resolveInstallerStaticPath('/install/assets/index-AbCd1234.js')).toBe('assets/index-AbCd1234.js')
    expect(resolveInstallerStaticPath('/install/assets/index-AbCd1234.css')).toBe('assets/index-AbCd1234.css')
    expect(resolveInstallerStaticPath('/install/assets/decrypt.worker-C5X1PlTD.js')).toBe('assets/decrypt.worker-C5X1PlTD.js')
  })

  it('serves the installer entry document with a query string', () => {
    expect(resolveInstallerStaticPath('/install?from=redeem')).toBe('index.html')
    expect(resolveInstallerStaticPath('/install/?from=redeem')).toBe('index.html')
  })

  it('never serves a commercial OAuth landing path', () => {
    expect(resolveInstallerStaticPath('/?afdian_redeem=success&claim=abc123')).toBeUndefined()
    expect(resolveInstallerStaticPath('/index.html?afdian_redeem=success')).toBeUndefined()
  })

  it.each([
    '/admin',
    '/internal/health/deep',
    '/server-status',
    '/.env',
    '/../index.html',
    '/assets/index-AbCd1234.js',
    '/install/assets/../index-AbCd1234.js',
    '/install/assets/%2e%2e%2findex-AbCd1234.js',
    '/install/assets%2Findex-AbCd1234.js',
    '/install/assets/index-AbCd1234.js?probe=1',
    '/install/assets/index.js',
    '/install/assets/.hidden-AbCd1234.js',
    '/install/assets/index-AbCd1234.js/extra',
    '/install/assets\\index-AbCd1234.js',
    '/%ZZ',
  ])('rejects non-public or ambiguously encoded path %s', (path) => {
    expect(resolveInstallerStaticPath(path)).toBeUndefined()
  })

  it('serves allowed files with safe cache policy and rejects every other static path without fallback', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'azvf-installer-static-'))
    const outsideDirectory = await mkdtemp(join(tmpdir(), 'azvf-installer-static-outside-'))
    temporaryDirectories.push(directory)
    temporaryDirectories.push(outsideDirectory)
    await mkdir(join(directory, 'assets'))
    await writeFile(join(directory, 'index.html'), '<!doctype html><title>installer</title>')
    await writeFile(join(directory, 'assets/index-AbCd1234.js'), 'export const ready=true')
    await writeFile(join(directory, 'assets/index-AbCd1234.css'), 'body{color:#fff}')
    await writeFile(join(outsideDirectory, 'secret.js'), 'export const secret=true')
    await symlink(join(outsideDirectory, 'secret.js'), join(directory, 'assets/leak-AbCd1234.js'))

    const app = Fastify({ logger: false, routerOptions: { onBadUrl: rejectBadInstallerUrl } })
    registerInstallerStaticRoutes(app, await realpath(directory))
    app.setNotFoundHandler((_request, reply) => reply.header('cache-control', 'no-store').code(404).send({ error: 'not found' }))
    try {
      const entry = await app.inject({ method: 'GET', url: '/install/' })
      expect(entry.statusCode).toBe(200)
      expect(entry.headers['content-type']).toContain('text/html')
      expect(entry.headers['cache-control']).toBe('no-cache')

      for (const [url, contentType] of [
        ['/install/assets/index-AbCd1234.js', 'text/javascript'],
        ['/install/assets/index-AbCd1234.css', 'text/css'],
      ]) {
        const asset = await app.inject({ method: 'GET', url })
        expect(asset.statusCode).toBe(200)
        expect(asset.headers['content-type']).toContain(contentType)
        expect(asset.headers['cache-control']).toBe('public, max-age=31536000, immutable')
        expect(asset.body.length).toBeGreaterThan(0)
      }

      const assetHead = await app.inject({ method: 'HEAD', url: '/install/assets/index-AbCd1234.css' })
      expect(assetHead.statusCode).toBe(200)
      expect(assetHead.headers['content-type']).toContain('text/css')
      expect(assetHead.headers['cache-control']).toBe('public, max-age=31536000, immutable')
      expect(assetHead.body).toBe('')

      for (const url of [
        '/admin', '/internal/health/deep', '/server-status', '/.env',
        '/install/assets/%2e%2e%2findex-AbCd1234.js', '/install/assets%2Findex-AbCd1234.js',
        '/install/assets/leak-AbCd1234.js', '/%ZZ',
      ]) {
        const response = await app.inject({ method: 'GET', url })
        expect(response.statusCode, url).toBe(404)
        expect(response.headers['cache-control']).toBe('no-store')
        expect(response.body).not.toContain('installer')
      }

      const rejectedHead = await app.inject({ method: 'HEAD', url: '/.env' })
      expect(rejectedHead.statusCode).toBe(404)
      expect(rejectedHead.headers['cache-control']).toBe('no-store')
      expect(rejectedHead.body).not.toContain('installer')
    } finally {
      await app.close()
    }
  })
})

describe('Installer deployment maintenance gate', () => {
  it('keeps exact health and safe static reads available while blocking every stateful route', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'azvf-installer-maintenance-'))
    temporaryDirectories.push(directory)
    const marker = join(directory, 'deploy-maintenance')
    process.env.AZVF_MAINTENANCE_FILE = marker

    const app = Fastify({ logger: false })
    registerMaintenanceGate(app, false)
    app.get('/health', async () => ({ ok: true }))
    app.post('/api/probe', async () => ({ api: 'ready' }))
    app.post('/internal/probe', async () => ({ internal: 'ready' }))
    app.get('/install/', async (_request, reply) => reply.type('text/html').send('<!doctype html>ready'))
    app.get('/install/assets/index-AbCd1234.css', async (_request, reply) => reply.type('text/css').send('body{}'))

    try {
      await writeFile(marker, 'deploying\n', { mode: 0o600 })

      const health = await app.inject({ method: 'GET', url: '/health' })
      expect(health.statusCode).toBe(200)
      expect(health.json()).toEqual({ ok: true })

      const entryDuringMaintenance = await app.inject({ method: 'GET', url: '/install/' })
      const assetDuringMaintenance = await app.inject({ method: 'GET', url: '/install/assets/index-AbCd1234.css' })
      expect(entryDuringMaintenance.statusCode).toBe(200)
      expect(assetDuringMaintenance.statusCode).toBe(200)

      for (const request of [
        { method: 'POST' as const, url: '/api/probe' },
        { method: 'POST' as const, url: '/internal/probe' },
        { method: 'GET' as const, url: '/health?details=1' },
        { method: 'GET' as const, url: '/install/assets/index-AbCd1234.css?probe=1' },
        { method: 'GET' as const, url: '/install/assets/unhashed.css' },
        { method: 'POST' as const, url: '/' },
      ]) {
        const response = await app.inject(request)
        expect(response.statusCode).toBe(503)
        expect(response.json()).toEqual({ error: 'maintenance' })
        expect(response.headers['cache-control']).toBe('no-store')
        expect(response.body).not.toContain(marker)
      }

      await unlink(marker)
      const api = await app.inject({ method: 'POST', url: '/api/probe' })
      const internal = await app.inject({ method: 'POST', url: '/internal/probe' })
      const entry = await app.inject({ method: 'GET', url: '/install/' })
      expect(api.json()).toEqual({ api: 'ready' })
      expect(internal.json()).toEqual({ internal: 'ready' })
      expect(entry.statusCode).toBe(200)
      expect(entry.body).toContain('ready')
    } finally {
      await app.close()
    }
  })

  it('does not enable the default marker outside production and cannot disable it with an empty production override', () => {
    expect(resolveMaintenanceFile(false, undefined)).toBeUndefined()
    expect(resolveMaintenanceFile(false, '')).toBeUndefined()
    expect(resolveMaintenanceFile(true, '')).toBe('/run/azvf/deploy-maintenance')
    expect(() => resolveMaintenanceFile(true, '/tmp/wrong-marker')).toThrow(/固定部署门禁路径/)
  })
})

describe('normalizeOrigin', () => {
  // A `crossorigin` module/stylesheet sends Origin even on same-origin fetches,
  // and WeChat's WebView / some proxies append the default port. The allowlist
  // only stores canonical origins, so :443 / :80 must be stripped or the asset
  // is 403'd and the page sticks on the boot fallback.
  it('returns the origin unchanged when already canonical', () => {
    expect(normalizeOrigin('https://install.azki.ai')).toBe('https://install.azki.ai')
    expect(normalizeOrigin('http://install.azki.ai')).toBe('http://install.azki.ai')
  })

  it('strips the default port so :443 / :80 still match the allowlist', () => {
    expect(normalizeOrigin('https://install.azki.ai:443')).toBe('https://install.azki.ai')
    expect(normalizeOrigin('http://install.azki.ai:80')).toBe('http://install.azki.ai')
  })

  it('rejects the opaque null origin and unparseable values as undefined', () => {
    expect(normalizeOrigin('null')).toBeUndefined()
    expect(normalizeOrigin('not-a-url')).toBeUndefined()
    expect(normalizeOrigin('')).toBeUndefined()
  })

  it('rejects origins carrying userinfo, path, query or fragment', () => {
    expect(normalizeOrigin('https://user:pass@install.azki.ai')).toBeUndefined()
    expect(normalizeOrigin('https://install.azki.ai/path')).toBeUndefined()
    expect(normalizeOrigin('https://install.azki.ai?x=1')).toBeUndefined()
    expect(normalizeOrigin('https://install.azki.ai#frag')).toBeUndefined()
  })

  it('does not rewrite a look-alike host into the allowlist host', () => {
    expect(normalizeOrigin('https://install.azki.ai.evil.com')).toBe('https://install.azki.ai.evil.com')
    expect(normalizeOrigin('https://evil.com')).toBe('https://evil.com')
  })
})

describe('Browser download path allowlist', () => {
  it('allows only safe browser installer file names under /browsers/', () => {
    expect(resolveBrowserDownloadPath('/browsers/chrome-standalone-setup-x64.exe')).toBe('chrome-standalone-setup-x64.exe')
    expect(resolveBrowserDownloadPath('/browsers/edge-setup-universal.pkg')).toBe('edge-setup-universal.pkg')
    expect(resolveBrowserDownloadPath('/browsers/chrome-android.apk')).toBe('chrome-android.apk')
    expect(resolveBrowserDownloadPath('/browsers/edge-mac.dmg')).toBe('edge-mac.dmg')
    expect(resolveBrowserDownloadPath('/browsers/chrome.deb')).toBe('chrome.deb')
    expect(resolveBrowserDownloadPath('/browsers/chrome.rpm')).toBe('chrome.rpm')
  })

  it.each([
    '/browsers/../etc/passwd',
    '/browsers/../../../etc/passwd',
    '/browsers/.hidden.exe',
    '/browsers/chrome.exe/extra',
    '/browsers/chrome.sh',
    '/browsers/chrome.txt',
    '/browsers/chrome',
    '/browsers/',
    '/browsers',
    '/api/browsers/chrome.exe',
    '/browsers/chrome.exe?download=1',
  ])('rejects paths outside the browser download pattern: %s', (path) => {
    expect(resolveBrowserDownloadPath(path)).toBeUndefined()
  })

  it('serves allowed installer files with correct MIME types and rejects unsafe paths', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'azvf-browsers-'))
    temporaryDirectories.push(directory)
    await writeFile(join(directory, 'chrome-standalone-setup-x64.exe'), 'fake-exe-content')

    const app = Fastify({ logger: false, routerOptions: { onBadUrl: rejectBadInstallerUrl } })
    registerBrowserDownloadRoutes(app, await realpath(directory))
    app.setNotFoundHandler((_request, reply) => reply.header('cache-control', 'no-store').code(404).send({ error: 'not found' }))

    try {
      // Valid download
      const valid = await app.inject({ method: 'GET', url: '/browsers/chrome-standalone-setup-x64.exe' })
      expect(valid.statusCode).toBe(200)
      expect(valid.headers['content-type']).toContain('application/vnd.microsoft.portable-executable')
      expect(valid.headers['cache-control']).toBe('public, max-age=86400')
      expect(valid.body).toBe('fake-exe-content')

      // HEAD request
      const head = await app.inject({ method: 'HEAD', url: '/browsers/chrome-standalone-setup-x64.exe' })
      expect(head.statusCode).toBe(200)
      expect(head.headers['content-type']).toContain('application/vnd.microsoft.portable-executable')
      expect(head.body).toBe('')

      // Missing file
      const missing = await app.inject({ method: 'GET', url: '/browsers/nonexistent.exe' })
      expect(missing.statusCode).toBe(404)

      // Invalid extension
      const invalid = await app.inject({ method: 'GET', url: '/browsers/chrome.sh' })
      expect(invalid.statusCode).toBe(404)

      // Directory traversal blocked by path pattern
      const traversal = await app.inject({ method: 'GET', url: '/browsers/../etc/passwd' })
      expect(traversal.statusCode).toBe(404)

      // Query string — not allowed by pattern
      const query = await app.inject({ method: 'GET', url: '/browsers/chrome.exe?download=1' })
      expect(query.statusCode).toBe(404)
    } finally {
      await app.close()
    }
  })

  it('manifest lists only files matching the allowed installer pattern, so the frontend can hide unprovisioned fallbacks', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'azvf-browsers-'))
    temporaryDirectories.push(directory)
    await writeFile(join(directory, 'chrome-standalone-setup-x64.exe'), 'fake-exe-content')
    await writeFile(join(directory, 'not-an-installer.txt'), 'ignored')

    const app = Fastify({ logger: false, routerOptions: { onBadUrl: rejectBadInstallerUrl } })
    registerBrowserManifestRoute(app, await realpath(directory))
    registerBrowserDownloadRoutes(app, await realpath(directory))

    try {
      const response = await app.inject({ method: 'GET', url: '/browsers/_manifest' })
      expect(response.statusCode).toBe(200)
      expect(response.headers['cache-control']).toBe('no-store')
      expect(response.json()).toEqual({ files: ['chrome-standalone-setup-x64.exe'] })
    } finally {
      await app.close()
    }
  })

  it('manifest degrades to an empty list instead of throwing when the directory is unreadable', async () => {
    const app = Fastify({ logger: false, routerOptions: { onBadUrl: rejectBadInstallerUrl } })
    registerBrowserManifestRoute(app, join(tmpdir(), 'azvf-browsers-does-not-exist'))

    try {
      const response = await app.inject({ method: 'GET', url: '/browsers/_manifest' })
      expect(response.statusCode).toBe(200)
      expect(response.json()).toEqual({ files: [] })
    } finally {
      await app.close()
    }
  })
})
