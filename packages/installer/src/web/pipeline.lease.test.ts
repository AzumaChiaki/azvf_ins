import { afterEach, describe, expect, it, vi } from 'vitest'
import { createInstallationSession, hasValidLeaseWindow } from './pipeline.js'

const originalFetch = globalThis.fetch

afterEach(() => {
  globalThis.fetch = originalFetch
  vi.restoreAllMocks()
})

describe('installer lease window validation', () => {
  const serverEpoch = 1_800_000_000

  it('uses the server clock and accepts both millisecond and legacy second expiry values', () => {
    expect(hasValidLeaseWindow(serverEpoch * 1_000 + 300_000, serverEpoch)).toBe(true)
    expect(hasValidLeaseWindow(serverEpoch + 300, serverEpoch)).toBe(true)
  })

  it('rejects expired, malformed, and implausibly long leases', () => {
    expect(hasValidLeaseWindow(serverEpoch * 1_000, serverEpoch)).toBe(false)
    expect(hasValidLeaseWindow(serverEpoch * 1_000 + 3_602_000, serverEpoch)).toBe(false)
    expect(hasValidLeaseWindow('invalid', serverEpoch)).toBe(false)
  })
})

describe('installer session initialization retry', () => {
  it('reuses the exact idempotency request after a transient proxy response', async () => {
    const bodies: string[] = []
    globalThis.fetch = vi.fn(async (_input, init) => {
      bodies.push(String(init?.body))
      return bodies.length === 1
        ? new Response(JSON.stringify({ error: 'bad gateway' }), { status: 502 })
        : new Response(JSON.stringify({ sessionId: 'recovered' }), { status: 200 })
    }) as typeof fetch
    const request = {
      attemptId: 'browser_attempt_1234567890abcdefghijklmnop',
      authToken: 'authorization-token',
      clientPublicKey: 'public-key',
      resourceId: 'resource-1',
      deviceAddr: 'AA:BB:CC:DD:EE:FF',
      deviceName: '我的手环',
      clientAttributes: {
        timeZone: 'Asia/Shanghai', language: 'zh-CN', screen: '1920x1080x24',
        hardwareConcurrency: 8, platform: 'MacIntel', engine: 'Chrome' as const,
      },
    }

    const response = await createInstallationSession(request)
    expect(response.status).toBe(200)
    expect(bodies).toHaveLength(2)
    expect(bodies[1]).toBe(bodies[0])
    expect(JSON.parse(bodies[0]!)).toMatchObject({ deviceAddr: 'AA:BB:CC:DD:EE:FF', deviceName: '我的手环' })
  })
})
