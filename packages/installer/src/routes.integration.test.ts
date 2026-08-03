import { createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto'
import { SignJWT } from 'jose'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  TOKEN_AUDIENCE,
  TOKEN_ISSUER,
  WIRE_PROTOCOL_VERSION,
  canonicalResourceManifestV2,
  fromBase64,
  patchWatchfaceChunk,
  WATCHFACE_HEADER_LENGTH,
  WATCHFACE_ID_OFFSET,
  type SignedResourceMeta,
  type SessionInitResponse,
} from '@azvf/contract'
import {
  createChunkSequenceState,
  decryptChunkV2,
  deriveSessionKeys,
  exportPublicKey,
  finalizeChunkSequenceState,
  generateSessionKeypair,
  parseChunkHeaderV2,
  unwrapSessionKey,
  verifyControlMac,
  type SessionControlContext,
} from './crypto/index.js'
const originalFetch = globalThis.fetch
const internalSecret = 'installer-console-test-signing-secret'
const internalKey = createHash('sha256').update(internalSecret).digest()
const clientAttributes = {
  timeZone: 'Asia/Shanghai', language: 'zh-CN', screen: '1920x1080x24',
  hardwareConcurrency: 8, platform: 'MacIntel', engine: 'Chrome' as const,
}

afterEach(() => {
  globalThis.fetch = originalFetch
  vi.restoreAllMocks()
})

function requestNonce(init?: RequestInit): string {
  return new Headers(init?.headers).get('x-azvf-nonce')!
}

function responseMac(nonce: string, status: number, path: string, digest: string, size: number, timestamp: string): string {
  return createHmac('sha256', internalKey)
    .update(`${nonce}\n${status}\n${path}\n${digest}\n${size}\n${timestamp}`)
    .digest('base64url')
}

describe('Installer authenticated v3 route', () => {
  it('enforces quota/lease/control token and streams hidden decoys plus verified real chunks', async () => {
    process.env.LOG_LEVEL = 'silent'
    process.env.SERVE_STATIC = 'false'
    process.env.REQUIRE_HTTPS = 'false'
    process.env.CONSOLE_URL = 'https://console.test/'
    process.env.INTERNAL_SIGNING_KEY = internalSecret
    process.env.INSTALLER_DB_PATH = ':memory:'
    process.env.JWT_KEY_ID = 'integration-key'
    process.env.DECOY_RATIO = '0.5'

    const signingKeys = generateKeyPairSync('ed25519')
    process.env.JWT_ED25519_PUBLIC_KEY_B64 = signingKeys.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')

    const plaintext = new Uint8Array(20_000)
    crypto.getRandomValues(plaintext)
    plaintext.fill(0, 34, 58)
    new TextEncoder().encode('000000000000').forEach((byte, index) => { plaintext[40 + index] = byte })
    const chunkSize = 16_384
    const chunkSha256 = [
      createHash('sha256').update(plaintext.subarray(0, chunkSize)).digest('hex'),
      createHash('sha256').update(plaintext.subarray(chunkSize)).digest('hex'),
    ]
    const unsigned = {
      formatVersion: 2 as const,
      id: 'resource-integration',
      name: 'integration resource',
      resType: 16,
      packageName: null,
      size: plaintext.length,
      sha256: createHash('sha256').update(plaintext).digest('hex'),
      md5: createHash('md5').update(plaintext).digest('hex'),
      watchfaceId: '000000000000',
      version: '2026.1',
      chunkSize,
      totalChunks: 2,
      chunkSha256,
    }
    const manifest = canonicalResourceManifestV2(unsigned, unsigned.chunkSha256)
    const manifestHash = createHash('sha256').update(manifest).digest('hex')
    const meta: SignedResourceMeta = {
      ...unsigned,
      manifestHash,
      manifestSignature: sign(null, Buffer.from(manifestHash, 'hex'), signingKeys.privateKey).toString('base64url'),
      manifestKeyId: 'integration-key',
    }
    const metaBody = Buffer.from(JSON.stringify(meta))
    let consumed = 0
    let orderPayload: Record<string, unknown> | undefined
    const deviceSessionToken = 'device_session_1234567890abcdefghijklmnopqrstuvwxyz'
    const pendingClaimToken = 'pending_claim_1234567890abcdefghijklmnopqrstuvwxyz'
    let inspectionRequests = 0
    let deviceAuthorizationRequests = 0
    const telemetryEvents: string[] = []

    globalThis.fetch = vi.fn(async (input, init) => {
      const url = new URL(String(input))
      const nonce = requestNonce(init)
      const timestamp = String(Date.now())
      if (url.pathname.endsWith('/api/redeem/inspect')) {
        inspectionRequests++
        const body = Buffer.from(JSON.stringify({
          kind: 'super',
          policyName: '黄金策略',
          resources: [
            { id: meta.id, name: meta.name, version: meta.version, resType: meta.resType, size: meta.size },
            { id: 'resource-other', name: 'other resource', version: '2.0', resType: 64, size: 1234 },
          ],
        }))
        const digest = createHash('sha256').update(body).digest('hex')
        return new Response(body, { headers: {
          'x-azvf-json-sha256': digest,
          'x-azvf-json-size': String(body.length),
          'x-azvf-json-timestamp': timestamp,
          'x-azvf-json-signature': responseMac(nonce, 200, url.pathname, digest, body.length, timestamp),
        } })
      }
      if (url.pathname.endsWith('/api/redeem/claim')) {
        const requestBody = JSON.parse(new TextDecoder().decode(init?.body as ArrayBuffer)) as Record<string, unknown>
        expect(requestBody).toEqual({ kind: 'card', code: 'CARD_TEST_1234', resourceId: 'resource-other' })
        const body = Buffer.from(JSON.stringify({ claimToken: pendingClaimToken, expiresInMs: 1_800_000 }))
        const digest = createHash('sha256').update(body).digest('hex')
        return new Response(body, { headers: {
          'x-azvf-json-sha256': digest,
          'x-azvf-json-size': String(body.length),
          'x-azvf-json-timestamp': timestamp,
          'x-azvf-json-signature': responseMac(nonce, 200, url.pathname, digest, body.length, timestamp),
        } })
      }
      if (url.pathname.endsWith('/api/redeem/claim/bind')) {
        if (!orderPayload) throw new Error('order payload is not ready')
        const requestBody = JSON.parse(new TextDecoder().decode(init?.body as ArrayBuffer)) as Record<string, unknown>
        expect(requestBody).toEqual({ claimToken: pendingClaimToken, deviceAddr: 'AA:BB:CC:DD:EE:FF' })
        const body = Buffer.from(JSON.stringify(orderPayload))
        const digest = createHash('sha256').update(body).digest('hex')
        return new Response(body, { headers: {
          'x-azvf-json-sha256': digest,
          'x-azvf-json-size': String(body.length),
          'x-azvf-json-timestamp': timestamp,
          'x-azvf-json-signature': responseMac(nonce, 200, url.pathname, digest, body.length, timestamp),
        } })
      }
      if (url.pathname.endsWith('/internal/device/authorizations')) {
        if (!orderPayload) throw new Error('authorization payload is not ready')
        deviceAuthorizationRequests++
        const requestBody = JSON.parse(new TextDecoder().decode(init?.body as ArrayBuffer)) as Record<string, unknown>
        // 未知/失效的设备会话：Console 一律以 401 应答，安装器据此下达重新核销指令。
        if (requestBody.deviceSessionToken !== deviceSessionToken) {
          return new Response('{"error":"unauthorized"}', { status: 401, headers: { 'content-type': 'application/json' } })
        }
        expect(requestBody).toEqual({ deviceAddr: 'AA:BB:CC:DD:EE:FF', deviceSessionToken })
        const { deviceSessionToken: _opaque, ...safePayload } = orderPayload
        const body = Buffer.from(JSON.stringify(safePayload))
        const digest = createHash('sha256').update(body).digest('hex')
        return new Response(body, { headers: {
          'x-azvf-json-sha256': digest,
          'x-azvf-json-size': String(body.length),
          'x-azvf-json-timestamp': timestamp,
          'x-azvf-json-signature': responseMac(nonce, 200, url.pathname, digest, body.length, timestamp),
        } })
      }
      if (url.pathname.endsWith('/internal/installations/events')) {
        const requestBody = JSON.parse(new TextDecoder().decode(init?.body as ArrayBuffer)) as Record<string, unknown>
        expect(requestBody).not.toHaveProperty('ip')
        telemetryEvents.push(String(requestBody.event))
        const body = Buffer.from('{"ok":true}')
        const digest = createHash('sha256').update(body).digest('hex')
        return new Response(body, { headers: {
          'x-azvf-json-sha256': digest,
          'x-azvf-json-size': String(body.length),
          'x-azvf-json-timestamp': timestamp,
          'x-azvf-json-signature': responseMac(nonce, 200, url.pathname, digest, body.length, timestamp),
        } })
      }
      if (url.pathname.endsWith('/internal/site-content')) {
        expect(url.searchParams.get('page')).toBe('install')
        const body = Buffer.from(JSON.stringify({ page: 'install', sections: [{ id: 'help', title: '帮助', links: [] }] }))
        const digest = createHash('sha256').update(body).digest('hex')
        return new Response(body, { headers: {
          'x-azvf-json-sha256': digest,
          'x-azvf-json-size': String(body.length),
          'x-azvf-json-timestamp': timestamp,
          'x-azvf-json-signature': responseMac(nonce, 200, `${url.pathname}${url.search}`, digest, body.length, timestamp),
        } })
      }
      if (url.pathname.endsWith('/meta')) {
        const digest = createHash('sha256').update(metaBody).digest('hex')
        return new Response(metaBody, { headers: {
          'x-azvf-meta-sha256': digest,
          'x-azvf-meta-size': String(metaBody.length),
          'x-azvf-meta-timestamp': timestamp,
          'x-azvf-meta-signature': responseMac(nonce, 200, url.pathname, digest, metaBody.length, timestamp),
        } })
      }
      if (url.pathname.endsWith('/consume')) {
        consumed++
        const requestBody = JSON.parse(new TextDecoder().decode(init?.body as ArrayBuffer)) as Record<string, unknown>
        expect(requestBody.authorization).toEqual(expect.any(String))
        expect(requestBody.consumptionId).toEqual(expect.any(String))
        expect(requestBody.sessionId).toEqual(expect.any(String))
        expect(['session.create', 'stream.open', 'stream.renew', 'session.heartbeat']).toContain(requestBody.phase)
        expect(requestBody).not.toHaveProperty('sub')
        expect(requestBody).not.toHaveProperty('jti')
        const body = Buffer.from(JSON.stringify({
          ok: true,
          installsUsed: 1,
          idempotent: consumed > 1,
          wireProtocolVersion: WIRE_PROTOCOL_VERSION,
          capability: 'C'.repeat(43),
          capabilityExpiresAt: Date.now() + 60_000,
          signedMeta: meta,
          throttle: { mode: 'enforced', sessionId: requestBody.sessionId,
            ratePerSecond: 100 * 1024, burstBytes: 256 * 1024, sampleWindowMs: 10_000 },
          riskDecision: { action: 'allow', reason: 'allowed' },
        }))
        const digest = createHash('sha256').update(body).digest('hex')
        return new Response(body, { headers: {
          'x-azvf-json-sha256': digest,
          'x-azvf-json-size': String(body.length),
          'x-azvf-json-timestamp': timestamp,
          'x-azvf-json-signature': responseMac(nonce, 200, url.pathname, digest, body.length, timestamp),
        } })
      }
      if (url.pathname.endsWith('/plaintext')) {
        const requestHeaders = new Headers(init?.headers)
        expect(requestHeaders.get('x-azvf-resource-capability')).toBe('C'.repeat(43))
        expect(requestHeaders.get('x-azvf-session-id')).toMatch(/^[A-Za-z0-9_-]{32,64}$/)
        return new Response(plaintext, { headers: {
          'content-length': String(plaintext.length),
          'x-azvf-resource-sha256': meta.sha256,
          'x-azvf-resource-size': String(plaintext.length),
          'x-azvf-response-timestamp': timestamp,
          'x-azvf-response-signature': responseMac(nonce, 200, url.pathname, meta.sha256, plaintext.length, timestamp),
        } })
      }
      throw new Error(`unexpected Console URL ${url}`)
    }) as typeof fetch

    const now = Math.floor(Date.now() / 1_000)
    const authToken = await new SignJWT({
      grant: 'cardkey', sku: 'sku', resourceIds: [meta.id], entitlementId: 'entitlement-integration',
      deviceAddr: 'AA:BB:CC:DD:EE:FF', tier: 'basic', installConcurrency: 1, clientContextVersion: 2,
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: 'integration-key' })
      .setIssuer(TOKEN_ISSUER)
      .setAudience(TOKEN_AUDIENCE)
      .setSubject('user-integration')
      .setJti('integration-jti-value-1234')
      .setIssuedAt(now)
      .setExpirationTime(now + 120)
      .sign(signingKeys.privateKey)
    const secondOrderToken = await new SignJWT({
      grant: 'afdian-order', sku: 'sku-2', resourceIds: ['resource-other'], entitlementId: 'entitlement-other',
      deviceAddr: 'AA:BB:CC:DD:EE:FF', tier: 'premium', installConcurrency: 4, clientContextVersion: 2,
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: 'integration-key' })
      .setIssuer(TOKEN_ISSUER)
      .setAudience(TOKEN_AUDIENCE)
      .setSubject('user-integration')
      .setJti('integration-order-jti-9999')
      .setIssuedAt(now)
      .setExpirationTime(now + 120)
      .sign(signingKeys.privateKey)
    orderPayload = {
      token: authToken,
      tokens: [authToken, secondOrderToken],
      resourceIds: [meta.id, 'resource-other', 'untrusted-extra'],
      resources: [
        { id: meta.id, name: meta.name, version: meta.version, resType: meta.resType, size: meta.size },
        { id: 'resource-other', name: 'other resource', version: '2.0', resType: 64, size: 1234 },
        { id: 'untrusted-extra', name: 'must be dropped', version: '9', resType: 32, size: 9 },
      ],
      deviceSessionToken,
      // 买家在核销页选定的资源随授权回传，安装页据此默认选中。
      selectedResourceId: 'resource-other',
      policies: [{ id: 'internal-policy-id', name: '黄金策略', expiresAt: Date.now() + 31 * 86_400_000,
        resourceIds: [meta.id, 'resource-other'] }],
    }

    const browserKeys = await generateSessionKeypair()
    const clientPublicKey = await exportPublicKey(browserKeys.publicKey)
    const firstAttemptId = 'session_attempt_1234567890abcdefghijklmnop'
    const { buildServer } = await import('./server.js')
    const app = await buildServer()
    try {

      const health = await app.inject({ method: 'GET', url: '/health' })
      expect(health.json()).toEqual({ ok: true })
      const orderNumberOnly = await app.inject({ method: 'POST', url: '/api/redeem/order',
        payload: { outTradeNo: 'ORDER12345', deviceAddr: 'AA:BB:CC:DD:EE:FF' } })
      expect(orderNumberOnly.statusCode).toBe(404)
      const commercialBoundary = await app.inject({
        method: 'POST',
        url: '/api/device/authorizations',
        headers: { cookie: 'azvf_pending_claim=must-not-be-read' },
        payload: { deviceAddr: 'AA:BB:CC:DD:EE:FF' },
      })
      expect(commercialBoundary.statusCode).toBe(404)
      expect(commercialBoundary.headers['set-cookie']).toBeUndefined()

      const missingClientContext = await app.inject({
        method: 'POST',
        url: '/api/session',
        payload: { attemptId: 'missing_context_attempt_1234567890abcdef', authToken, clientPublicKey,
          resourceId: meta.id, deviceAddr: 'aa-bb-cc-dd-ee-ff' },
      })
      expect(missingClientContext.statusCode).toBe(400)
      expect(consumed).toBe(0)

      const init = await app.inject({
        method: 'POST',
        url: '/api/session',
        payload: { attemptId: firstAttemptId, authToken, clientPublicKey, resourceId: meta.id,
          deviceAddr: 'aa-bb-cc-dd-ee-ff', clientAttributes },
      })
      expect(init.statusCode, init.body).toBe(200)
      const session = init.json() as SessionInitResponse
      expect(session.protocolVersion).toBe(WIRE_PROTOCOL_VERSION)
      expect(session.transportTotal).toBe(3)
      expect(session.meta.chunkSha256).toEqual(chunkSha256)
      expect(session.watchfaceTransform?.id).toMatch(/^\d{12}$/)
      expect(session.watchfaceTransform?.id).not.toBe('000000000000')
      expect(session.watchfaceTransform?.idOffset).toBe(WATCHFACE_ID_OFFSET)
      expect(session.watchfaceTransform?.fieldEnd).toBe(WATCHFACE_HEADER_LENGTH)
      const rewritten = patchWatchfaceChunk(plaintext, 0, session.watchfaceTransform!)
      expect(session.watchfaceTransform?.md5).toBe(createHash('md5').update(rewritten).digest('hex'))
      expect(consumed).toBe(1)

      // A reverse proxy or browser may lose the first response after the
      // server has consumed the one-shot JWT. Repeating the exact attempt must
      // recover the same key exchange without consuming again.
      const recoveredInit = await app.inject({
        method: 'POST',
        url: '/api/session',
        payload: { attemptId: firstAttemptId, authToken, clientPublicKey, resourceId: meta.id,
          deviceAddr: 'AA:BB:CC:DD:EE:FF', clientAttributes },
      })
      expect(recoveredInit.statusCode, recoveredInit.body).toBe(200)
      expect(recoveredInit.json()).toEqual(session)
      expect(consumed).toBe(1)

      const conflictingAttempt = await app.inject({
        method: 'POST',
        url: '/api/session',
        payload: { attemptId: firstAttemptId, authToken, clientPublicKey, resourceId: meta.id,
          deviceAddr: 'AA:BB:CC:DD:EE:FF', clientAttributes: { ...clientAttributes, language: 'en-US' } },
      })
      expect(conflictingAttempt.statusCode).toBe(409)
      expect(consumed).toBe(1)

      const siteContent = await app.inject({ method: 'GET', url: '/api/site-content' })
      expect(siteContent.statusCode).toBe(200)
      expect(siteContent.json().sections[0].id).toBe('help')

      const secondToken = await new SignJWT({
        grant: 'cardkey', sku: 'sku', resourceIds: [meta.id], entitlementId: 'entitlement-integration',
        deviceAddr: 'AA:BB:CC:DD:EE:FE', tier: 'basic', installConcurrency: 1, clientContextVersion: 2,
      })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: 'integration-key' })
        .setIssuer(TOKEN_ISSUER)
        .setAudience(TOKEN_AUDIENCE)
        .setSubject('user-integration')
        .setJti('integration-jti-value-5678')
        .setIssuedAt(now)
        .setExpirationTime(now + 120)
        .sign(signingKeys.privateKey)
      const concurrencyRejected = await app.inject({
        method: 'POST',
        url: '/api/session',
        payload: { attemptId: 'concurrency_attempt_1234567890abcdefgh', authToken: secondToken, clientPublicKey,
          resourceId: meta.id, deviceAddr: 'AA:BB:CC:DD:EE:FE', clientAttributes },
      })
      expect(concurrencyRejected.statusCode).toBe(429)
      expect(consumed).toBe(1) // A rejected local lease must never charge a remote install attempt.

      const masterKey = await unwrapSessionKey(browserKeys.privateKey, session.wrappedKey)
      const cryptoKeys = await deriveSessionKeys(masterKey)
      const context: SessionControlContext = {
        sessionId: session.sessionId,
        resourceId: meta.id,
        resourceVersion: meta.version,
        manifestHash,
        deviceId: 'AA:BB:CC:DD:EE:FF',
        serverEpoch: session.serverEpoch,
        transportTotal: session.transportTotal,
        realTotal: session.realTotal,
        padTo: session.padTo,
        watchfaceTransform: session.watchfaceTransform,
      }
      expect(await verifyControlMac(cryptoKeys.controlKey, context, fromBase64(session.controlMac))).toBe(true)

      const missingControl = await app.inject({ method: 'GET', url: session.streamUrl })
      expect(missingControl.statusCode).toBe(410)
      const competingStreams = await Promise.all([
        app.inject({ method: 'GET', url: session.streamUrl, headers: { 'x-session-control': session.controlToken } }),
        app.inject({ method: 'GET', url: session.streamUrl, headers: { 'x-session-control': session.controlToken } }),
      ])
      expect(competingStreams.map((result) => result.statusCode).sort()).toEqual([200, 410])
      const stream = competingStreams.find((result) => result.statusCode === 200)!
      expect(stream.statusCode).toBe(200)
      const wire = new Uint8Array(stream.rawPayload)
      const state = createChunkSequenceState()
      const real: Uint8Array[] = []
      let decoys = 0
      for (let offset = 0; offset < wire.length;) {
        const header = parseChunkHeaderV2(wire, offset)
        const frame = wire.subarray(offset, offset + header.frameLength)
        const decoded = await decryptChunkV2(cryptoKeys, context, frame, state)
        if (decoded.shouldInstall) real.push(decoded.data)
        else decoys++
        offset += header.frameLength
      }
      finalizeChunkSequenceState(state)
      expect(decoys).toBe(1)
      expect(Buffer.concat(real.map((part) => Buffer.from(part))).equals(Buffer.from(plaintext))).toBe(true)

      const replay = await app.inject({
        method: 'GET', url: session.streamUrl, headers: { 'x-session-control': session.controlToken },
      })
      expect(replay.statusCode).toBe(200)
      // Replay keeps the authenticated schedule and plaintext stable while
      // encryption deliberately generates fresh nonces for every response.
      expect(replay.rawPayload.equals(stream.rawPayload)).toBe(false)
      const replayWire = new Uint8Array(replay.rawPayload)
      const replayState = createChunkSequenceState()
      const replayReal: Uint8Array[] = []
      for (let offset = 0; offset < replayWire.length;) {
        const header = parseChunkHeaderV2(replayWire, offset)
        const frame = replayWire.subarray(offset, offset + header.frameLength)
        const decoded = await decryptChunkV2(cryptoKeys, context, frame, replayState)
        if (decoded.shouldInstall) replayReal.push(decoded.data)
        offset += header.frameLength
      }
      finalizeChunkSequenceState(replayState)
      expect(Buffer.concat(replayReal.map((part) => Buffer.from(part))).equals(Buffer.from(plaintext))).toBe(true)
      const complete = await app.inject({
        method: 'POST',
        url: `/api/session/${session.sessionId}/complete`,
        headers: { 'x-session-control': session.controlToken },
        payload: { success: true, attempt: 1, acknowledgedPart: 18 },
      })
      expect(complete.statusCode).toBe(200)

      const replayAfterComplete = await app.inject({
        method: 'GET', url: session.streamUrl, headers: { 'x-session-control': session.controlToken },
      })
      expect(replayAfterComplete.statusCode).toBe(410)

      await vi.waitFor(() => {
        expect(telemetryEvents).toContain('install.started')
        expect(telemetryEvents).toContain('download.started')
        expect(telemetryEvents).toContain('download.completed')
        expect(telemetryEvents).toContain('install.sampled')
        expect(telemetryEvents).toContain('install.completed')
      })

      const tokenReplay = await app.inject({
        method: 'POST',
        url: '/api/session',
        payload: { attemptId: 'token_replay_attempt_1234567890abcdefgh', authToken, clientPublicKey,
          resourceId: meta.id, deviceAddr: 'AA:BB:CC:DD:EE:FF', clientAttributes },
      })
      expect(tokenReplay.statusCode).toBe(409)
      // One initial quota consume plus a capability refresh before each stream.
      // Every refresh reuses the same consumptionId, so Console returns
      // idempotent=true and never counts reconnect as another installation.
      expect(consumed).toBe(3)
    } finally {
      await app.close()
    }
  })
})
