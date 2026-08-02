import { describe, expect, it } from 'vitest'
import {
  formatPolicyRemaining,
  mergeAuthorizations,
  parseAuthorizationResponse,
  sanitizeDeviceHistory,
  selectAuthorizedResource,
} from './authorization.js'

const tokenA = `aaa.${'b'.repeat(40)}.ccc`
const tokenB = `ddd.${'e'.repeat(40)}.fff`

describe('Installer browser authorization boundary', () => {
  it('accepts multiple verified resource mappings and strips internal policy fields', () => {
    const result = parseAuthorizationResponse({
      resourceTokens: { resource_one: tokenA, resource_two: tokenB },
      resources: [
        { id: 'resource_one', name: '资源一', version: '1.0', resType: 16, size: 1024 },
        { id: 'resource_two', name: '资源二', version: '2.0', resType: 64, size: 2048 },
      ],
      policies: [{ id: 'must-not-reach-ui', name: '黄金策略', expiresAt: Date.now() + 86_400_000,
        resourceIds: ['resource_one', 'resource_two'], internalOwner: 'hidden' }],
    })

    expect(result.resources.map((resource) => resource.id)).toEqual(['resource_one', 'resource_two'])
    expect(result.policies).toEqual([{
      name: '黄金策略',
      expiresAt: expect.any(Number),
      resourceIds: ['resource_one', 'resource_two'],
    }])
    expect(result.policies[0]).not.toHaveProperty('id')
    expect(result.policies[0]).not.toHaveProperty('internalOwner')
  })

  it('keeps a preselected resource only when it has an authenticated token', () => {
    const base = {
      resourceTokens: { resource_one: tokenA, resource_two: tokenB },
      resources: [
        { id: 'resource_one', name: '资源一', version: '1.0', resType: 16, size: 1024 },
        { id: 'resource_two', name: '资源二', version: '2.0', resType: 64, size: 2048 },
      ],
      policies: [],
    }
    expect(parseAuthorizationResponse({ ...base, selectedResourceId: 'resource_two' }).selectedResourceId)
      .toBe('resource_two')
    // 预选项只是默认值：指向没有令牌的资源时静默忽略，不能变成错误或越权。
    expect(parseAuthorizationResponse({ ...base, selectedResourceId: 'resource_three' }).selectedResourceId)
      .toBeUndefined()
    expect(parseAuthorizationResponse(base).selectedResourceId).toBeUndefined()
  })

  it('lets a newer redeem-page selection replace an older still-authorized install-page selection', () => {
    const base = {
      resourceTokens: { resource_one: tokenA, resource_two: tokenB },
      resources: [
        { id: 'resource_one', name: '资源一', version: '1.0', resType: 16, size: 1024 },
        { id: 'resource_two', name: '资源二', version: '2.0', resType: 64, size: 2048 },
      ],
      policies: [],
    }

    const newlySelected = parseAuthorizationResponse({ ...base, selectedResourceId: 'resource_two' })
    expect(selectAuthorizedResource('resource_one', newlySelected)).toBe('resource_two')
    expect(selectAuthorizedResource('resource_two', parseAuthorizationResponse(base))).toBe('resource_two')
  })

  it('rejects a policy resource that has no authenticated token mapping', () => {
    expect(() => parseAuthorizationResponse({
      resourceTokens: { resource_one: tokenA },
      resources: [{ id: 'resource_one', name: '资源一', version: '1', resType: 16, size: 1 }],
      policies: [{ name: '越权策略', expiresAt: null, resourceIds: ['resource_two'] }],
    })).toThrow(/策略资源映射/)
  })

  it('keeps a well-formed 32-hex authkey so the device management UI can auto-fill it', () => {
    const history = sanitizeDeviceHistory([
      { name: 'Watch', addr: 'AA:BB:CC:DD:EE:FF', authkey: 'a1b2c3d4e5f60718293a4b5c6d7e8f90', lastUsed: 123 },
    ])
    expect(history).toEqual([{ name: 'Watch', addr: 'AA:BB:CC:DD:EE:FF', lastUsed: 123, authkey: 'a1b2c3d4e5f60718293a4b5c6d7e8f90' }])
  })

  it('drops a malformed authkey (wrong length/charset) instead of trusting stored data', () => {
    const history = sanitizeDeviceHistory([
      { name: 'Watch', addr: 'AA:BB:CC:DD:EE:FF', authkey: 'not-32-hex-chars', lastUsed: 123 },
    ])
    expect(history).toEqual([{ name: 'Watch', addr: 'AA:BB:CC:DD:EE:FF', lastUsed: 123 }])
    expect(JSON.stringify(history)).not.toContain('not-32-hex-chars')
  })

  it('formats policy lifetime without exposing ids or server timestamps', () => {
    const now = Date.UTC(2026, 6, 15)
    expect(formatPolicyRemaining(null, now)).toBe('长期有效')
    expect(formatPolicyRemaining(now + 26 * 60 * 60 * 1_000, now)).toBe('剩余 1 天 2 小时')
    expect(formatPolicyRemaining(now - 1, now)).toBe('已到期')
  })

  it('lets a later live authorization replace an overlapping redemption token', () => {
    const redeemed = parseAuthorizationResponse({
      resourceTokens: { resource_one: tokenA },
      resources: [{ id: 'resource_one', name: '资源一', version: '1', resType: 16, size: 1 }],
      policies: [{ name: '旧策略', expiresAt: Date.now() + 60_000, resourceIds: ['resource_one'] }],
    })
    const live = parseAuthorizationResponse({
      resourceTokens: { resource_one: tokenB },
      resources: [{ id: 'resource_one', name: '资源一', version: '1', resType: 16, size: 1 }],
      policies: [{ name: '续期策略', expiresAt: null, resourceIds: ['resource_one'] }],
    })
    expect(mergeAuthorizations(redeemed, live).resourceTokens.resource_one).toBe(tokenB)
  })
})
