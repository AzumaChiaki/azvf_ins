import { createHash, createHmac } from 'node:crypto'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { WIRE_PROTOCOL_VERSION, type SignedResourceMeta } from '@azvf/contract'
import {
  configureInternalClient,
  consumeEntitlement,
  createSignedRequest,
  EntitlementDecisionError,
  fetchMeta,
  fetchPlaintextChunks,
  reportInstallationEvent,
} from '@azvf/internal-client'
import { config } from './config.js'

const originalFetch = globalThis.fetch
const secret = 'installer-console-test-signing-secret'
process.env.INTERNAL_SIGNING_KEY = secret
configureInternalClient(config)
const capabilityAccess = {
  capability: 'C'.repeat(43),
  sessionId: 'session_1234567890abcdefghijklmnop',
}

afterEach(() => {
  globalThis.fetch = originalFetch
  vi.restoreAllMocks()
})

function signingKey(): Buffer {
  return createHash('sha256').update(secret).digest()
}

describe('Console authenticated streaming client', () => {
  it('creates a canonical timestamp/nonce/method/path/body signature', () => {
    const body = new TextEncoder().encode('{"ok":true}')
    const signed = createSignedRequest('post', new URL('https://console.test/a?b=1'), body, 1234, 'fixed_nonce')
    const bodyHash = createHash('sha256').update(body).digest('hex')
    const expected = createHmac('sha256', signingKey())
      .update(`1234\nfixed_nonce\nPOST\n/a?b=1\n${bodyHash}`)
      .digest('base64url')
    expect(signed.headers['x-azvf-signature']).toBe(expected)
    expect(signed.headers['x-azvf-content-sha256']).toBe(bodyHash)
    expect(signed.headers['x-azvf-client-id']).toBe('installer')
  })

  it('authenticates every byte of the metadata JSON response', async () => {
    const meta = {
      id: 'resource-test', name: 'signed metadata', resType: 16, size: 20_000,
      sha256: '11'.repeat(32), md5: '22'.repeat(16), version: 'v1', chunkSize: 16_384, totalChunks: 2,
    }
    const body = new TextEncoder().encode(JSON.stringify(meta))
    globalThis.fetch = vi.fn(async (input, init) => {
      const url = new URL(String(input))
      const nonce = new Headers(init?.headers).get('x-azvf-nonce')!
      const timestamp = String(Date.now())
      const digest = createHash('sha256').update(body).digest('hex')
      const canonical = `${nonce}\n200\n${url.pathname}${url.search}\n${digest}\n${body.length}\n${timestamp}`
      return new Response(body, {
        headers: {
          'x-azvf-meta-sha256': digest,
          'x-azvf-meta-size': String(body.length),
          'x-azvf-meta-timestamp': timestamp,
          'x-azvf-meta-signature': createHmac('sha256', signingKey()).update(canonical).digest('base64url'),
        },
      })
    }) as typeof fetch
    await expect(fetchMeta(meta.id, capabilityAccess)).resolves.toMatchObject({ name: 'signed metadata', version: 'v1' })
  })

  it('requires an authenticated JSON response when consuming install quota', async () => {
    const responseBody = new TextEncoder().encode(JSON.stringify({
      ok: true,
      wireProtocolVersion: WIRE_PROTOCOL_VERSION,
      capability: capabilityAccess.capability,
      capabilityExpiresAt: Date.now() + 60_000,
      signedMeta: { id: 'resource-1' },
      idempotent: false,
      installsUsed: 1,
      throttle: { mode: 'enforced', sessionId: capabilityAccess.sessionId,
        ratePerSecond: 102400, burstBytes: 262144, sampleWindowMs: 10000 },
      riskDecision: { action: 'allow', reason: 'allowed' },
    }))
    globalThis.fetch = vi.fn(async (input, init) => {
      const url = new URL(String(input))
      const requestHeaders = new Headers(init?.headers)
      const nonce = requestHeaders.get('x-azvf-nonce')!
      const timestamp = String(Date.now())
      const digest = createHash('sha256').update(responseBody).digest('hex')
      const canonical = `${nonce}\n200\n${url.pathname}${url.search}\n${digest}\n${responseBody.length}\n${timestamp}`
      expect(init?.method).toBe('POST')
      expect(requestHeaders.get('x-azvf-content-sha256')).toMatch(/^[a-f0-9]{64}$/)
      return new Response(responseBody, { headers: {
        'x-azvf-json-sha256': digest,
        'x-azvf-json-size': String(responseBody.length),
        'x-azvf-json-timestamp': timestamp,
        'x-azvf-json-signature': createHmac('sha256', signingKey()).update(canonical).digest('base64url'),
      } })
    }) as typeof fetch
    await expect(consumeEntitlement({
      entitlementId: 'entitlement-1',
      authorization: 'signed.jwt.authorization.token.value',
      resourceId: 'resource-1',
      deviceAddress: 'AA:BB:CC:DD:EE:FF',
      consumptionId: 'unique-jti-123456',
      sessionId: capabilityAccess.sessionId,
      expiresAt: Date.now() + 60_000,
      phase: 'session.create',
      clientIp: '127.0.0.1',
    })).resolves.toMatchObject({ capability: capabilityAccess.capability, installsUsed: 1 })
  })

  it('rejects a signed consume response from an incompatible wire protocol', async () => {
    const responseBody = new TextEncoder().encode(JSON.stringify({ ok: true, wireProtocolVersion: 999 }))
    globalThis.fetch = vi.fn(async (input, init) => {
      const url = new URL(String(input))
      const nonce = new Headers(init?.headers).get('x-azvf-nonce')!
      const timestamp = String(Date.now())
      const digest = createHash('sha256').update(responseBody).digest('hex')
      const canonical = `${nonce}\n200\n${url.pathname}${url.search}\n${digest}\n${responseBody.length}\n${timestamp}`
      return new Response(responseBody, { headers: {
        'x-azvf-json-sha256': digest,
        'x-azvf-json-size': String(responseBody.length),
        'x-azvf-json-timestamp': timestamp,
        'x-azvf-json-signature': createHmac('sha256', signingKey()).update(canonical).digest('base64url'),
      } })
    }) as typeof fetch
    await expect(consumeEntitlement({
      entitlementId: 'entitlement-1',
      authorization: 'signed.jwt.authorization.token.value',
      resourceId: 'resource-1',
      deviceAddress: 'AA:BB:CC:DD:EE:FF',
      consumptionId: 'unique-jti-123456',
      sessionId: capabilityAccess.sessionId,
      expiresAt: Date.now() + 60_000,
      phase: 'session.create',
      clientIp: '127.0.0.1',
    })).rejects.toThrow('线协议版本不兼容')
  })

  it('authenticates a reauthorization instruction before exposing it to the installer', async () => {
    const responseBody = new TextEncoder().encode(JSON.stringify({
      error: 'reauth_required',
      riskDecision: { action: 'reauth', reason: 'authorization context changed',
        messageId: 'M'.repeat(22), feedbackDeadlineAt: Date.now() + 30_000 },
    }))
    globalThis.fetch = vi.fn(async (input, init) => {
      const url = new URL(String(input))
      const nonce = new Headers(init?.headers).get('x-azvf-nonce')!
      const timestamp = String(Date.now())
      const digest = createHash('sha256').update(responseBody).digest('hex')
      const canonical = `${nonce}\n409\n${url.pathname}${url.search}\n${digest}\n${responseBody.length}\n${timestamp}`
      return new Response(responseBody, { status: 409, headers: {
        'x-azvf-json-sha256': digest,
        'x-azvf-json-size': String(responseBody.length),
        'x-azvf-json-timestamp': timestamp,
        'x-azvf-json-signature': createHmac('sha256', signingKey()).update(canonical).digest('base64url'),
      } })
    }) as typeof fetch
    const request = consumeEntitlement({
      entitlementId: 'entitlement-1', authorization: 'signed.jwt.authorization.token.value',
      resourceId: 'resource-1', deviceAddress: 'AA:BB:CC:DD:EE:FF',
      consumptionId: 'unique-jti-123456', sessionId: capabilityAccess.sessionId,
      expiresAt: Date.now() + 60_000, phase: 'session.create', clientIp: '127.0.0.1',
    })
    await expect(request).rejects.toMatchObject({
      name: EntitlementDecisionError.name,
      status: 409,
      decision: { action: 'reauth', messageId: 'M'.repeat(22) },
    })
  })

  it('reports only the bounded installation lifecycle fields over the signed channel', async () => {
    const responseBody = new TextEncoder().encode('{"ok":true}')
    globalThis.fetch = vi.fn(async (input, init) => {
      const url = new URL(String(input))
      const requestHeaders = new Headers(init?.headers)
      const requestBody = JSON.parse(new TextDecoder().decode(init?.body as ArrayBuffer)) as Record<string, unknown>
      expect(url.pathname).toBe('/internal/installations/events')
      expect(requestBody).toEqual({
        sessionId: 'session_1234567890abcdefghijklmnop',
        resourceId: 'resource-1',
        deviceAddr: 'SERIAL-123456',
        event: 'install.completed',
        region: 'CN-SH',
      })
      expect(requestBody).not.toHaveProperty('ip')
      const nonce = requestHeaders.get('x-azvf-nonce')!
      const timestamp = String(Date.now())
      const digest = createHash('sha256').update(responseBody).digest('hex')
      const canonical = `${nonce}\n200\n${url.pathname}\n${digest}\n${responseBody.length}\n${timestamp}`
      return new Response(responseBody, { headers: {
        'x-azvf-json-sha256': digest,
        'x-azvf-json-size': String(responseBody.length),
        'x-azvf-json-timestamp': timestamp,
        'x-azvf-json-signature': createHmac('sha256', signingKey()).update(canonical).digest('base64url'),
      } })
    }) as typeof fetch

    await expect(reportInstallationEvent({
      sessionId: 'session_1234567890abcdefghijklmnop',
      resourceId: 'resource-1',
      deviceAddress: 'SERIAL-123456',
      event: 'install.completed',
      region: 'CN-SH',
    })).resolves.toBeUndefined()
  })

  it('verifies the bound response and yields fixed chunks without arrayBuffer', async () => {
    const bytes = new Uint8Array(20_000)
    crypto.getRandomValues(bytes.subarray(0, 20_000))
    const digest = createHash('sha256').update(bytes).digest('hex')
    const chunkSha256 = [
      createHash('sha256').update(bytes.subarray(0, 16_384)).digest('hex'),
      createHash('sha256').update(bytes.subarray(16_384)).digest('hex'),
    ]
    const meta = {
      formatVersion: 2, id: 'resource-test', name: 'test', resType: 16, size: bytes.length,
      sha256: digest, md5: '00'.repeat(16), version: 'v1', chunkSize: 16_384, totalChunks: 2,
      chunkSha256, manifestHash: '00'.repeat(32), manifestSignature: 'A'.repeat(86), manifestKeyId: 'test-key',
    } as SignedResourceMeta

    globalThis.fetch = vi.fn(async (input, init) => {
      const url = new URL(String(input))
      const headers = new Headers(init?.headers)
      const nonce = headers.get('x-azvf-nonce')!
      const timestamp = String(Date.now())
      const canonical = `${nonce}\n200\n${url.pathname}${url.search}\n${digest}\n${bytes.length}\n${timestamp}`
      const signature = createHmac('sha256', signingKey()).update(canonical).digest('base64url')
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes.subarray(0, 137))
          controller.enqueue(bytes.subarray(137, 17_000))
          controller.enqueue(bytes.subarray(17_000))
          controller.close()
        },
      })
      return new Response(body, {
        headers: {
          'x-azvf-resource-sha256': digest,
          'x-azvf-resource-size': String(bytes.length),
          'x-azvf-response-timestamp': timestamp,
          'x-azvf-response-signature': signature,
        },
      })
    }) as typeof fetch

    const chunks: Uint8Array[] = []
    for await (const chunk of fetchPlaintextChunks(meta.id, meta, capabilityAccess)) chunks.push(chunk)
    expect(chunks.map((chunk) => chunk.length)).toEqual([16_384, 3_616])
    const reconstructed = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)))
    expect(reconstructed.equals(Buffer.from(bytes))).toBe(true)
  })
})
