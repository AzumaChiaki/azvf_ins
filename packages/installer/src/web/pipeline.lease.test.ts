import { afterEach, describe, expect, it, vi } from 'vitest'
import { abandonBeaconRequest, createInstallationSession, hasValidLeaseWindow, sendAbandonBeacon } from './pipeline.js'

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

describe('installer lease release on page hide', () => {
  const session = { sessionId: 'session/id needing encoding', controlToken: 'c'.repeat(43) }

  it('addresses /complete with an escaped session id and carries the control token in the body', () => {
    const request = abandonBeaconRequest({ ...session, attempt: 2, acknowledgedPart: 7 })
    expect(request.url).toBe('/api/session/session%2Fid%20needing%20encoding/complete')
    // 令牌只能进 body：query string 会被写进访问日志。
    expect(request.url).not.toContain(session.controlToken)
    expect(JSON.parse(request.body)).toEqual({
      success: false,
      detail: '页面已关闭，安装中止',
      attempt: 2,
      acknowledgedPart: 7,
      control: session.controlToken,
    })
  })

  it('prefers sendBeacon and falls back to a keepalive fetch when the browser refuses it', () => {
    const request = abandonBeaconRequest(session)
    const beacon = vi.fn(() => true)
    vi.stubGlobal('navigator', { sendBeacon: beacon })
    globalThis.fetch = vi.fn(async () => new Response(null, { status: 200 })) as typeof fetch
    expect(sendAbandonBeacon(request)).toBe(true)
    expect(beacon).toHaveBeenCalledOnce()
    expect(globalThis.fetch).not.toHaveBeenCalled()

    beacon.mockReturnValue(false)
    expect(sendAbandonBeacon(request)).toBe(true)
    expect(globalThis.fetch).toHaveBeenCalledOnce()
    const [url, init] = (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit]
    expect(url).toBe(request.url)
    expect(init.keepalive).toBe(true)
    expect(init.body).toBe(request.body)
  })
})
