import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiFetch, onBeforeReauth, onReauthRequired, ReauthRedirect, REAUTH_HEADER, REAUTH_REASON_HEADER } from './apiFetch.js'

const originalFetch = globalThis.fetch
const originalWindow = (globalThis as { window?: unknown }).window

function stubWindow(): { href: string } {
  const location = { href: 'https://example.test/install' }
  ;(globalThis as { window?: unknown }).window = { location }
  return location
}

function respondWith(headers: Record<string, string>): void {
  globalThis.fetch = vi.fn(async () => new Response('{}', { headers })) as typeof fetch
}

describe('安装页请求出口', () => {
  beforeEach(() => { onBeforeReauth(undefined); onReauthRequired(undefined) })

  afterEach(() => {
    globalThis.fetch = originalFetch
    if (originalWindow === undefined) delete (globalThis as { window?: unknown }).window
    else (globalThis as { window?: unknown }).window = originalWindow
    onBeforeReauth(undefined)
    onReauthRequired(undefined)
  })

  it('没有指令时原样返回响应', async () => {
    respondWith({})
    const location = stubWindow()
    const response = await apiFetch('/api/session')
    expect(response.ok).toBe(true)
    expect(location.href).toBe('https://example.test/install')
  })

  it('读到指令时先关闭设备会话再跳转，并让调用方停下', async () => {
    respondWith({ [REAUTH_HEADER]: '/redeem' })
    const location = stubWindow()
    const order: string[] = []
    onBeforeReauth(() => { order.push('teardown') })

    await expect(apiFetch('/api/device/authorizations')).rejects.toBeInstanceOf(ReauthRedirect)
    // 先断开串口再导航：导航时强关串口在部分浏览器上会让标签页崩溃。
    expect(order).toEqual(['teardown'])
    expect(location.href).toBe('/redeem')
  })

  it('清理失败也照常跳转', async () => {
    respondWith({ [REAUTH_HEADER]: '/redeem' })
    const location = stubWindow()
    onBeforeReauth(() => { throw new Error('串口已经没了') })
    await expect(apiFetch('/api/session')).rejects.toBeInstanceOf(ReauthRedirect)
    expect(location.href).toBe('/redeem')
  })

  it.each([
    ['javascript:alert(1)'],
    ['//evil.example/redeem'],
    ['   '],
  ])('忽略不可信的跳转目标 %s', async (target) => {
    respondWith({ [REAUTH_HEADER]: target })
    const location = stubWindow()
    const response = await apiFetch('/api/session')
    expect(response.ok).toBe(true)
    expect(location.href).toBe('https://example.test/install')
  })

  it('接受完整的 http(s) 地址', async () => {
    respondWith({ [REAUTH_HEADER]: 'https://redeem.example.test/' })
    const location = stubWindow()
    await expect(apiFetch('/api/session')).rejects.toBeInstanceOf(ReauthRedirect)
    expect(location.href).toBe('https://redeem.example.test/')
  })

  it('把订单绑定冲突作为专用原因交给页面，而不是通用环境变化', async () => {
    respondWith({ [REAUTH_HEADER]: '/redeem', [REAUTH_REASON_HEADER]: 'order_bound_to_other_device' })
    stubWindow()
    const received: unknown[] = []
    onReauthRequired((target, reason) => { received.push({ target, reason }) })
    await expect(apiFetch('/api/device/authorizations')).rejects.toMatchObject({
      name: ReauthRedirect.name,
      target: '/redeem',
      reason: 'order_bound_to_other_device',
    })
    expect(received).toEqual([{ target: '/redeem', reason: 'order_bound_to_other_device' }])
  })
})
