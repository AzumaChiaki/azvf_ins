import { afterEach, describe, expect, it } from 'vitest'
import { resourceConsumptionId } from './consumption.js'
import { LeaseError, LeaseStore, type AcquireLeaseInput, type LeaseLimits } from './leaseStore.js'

const stores: LeaseStore[] = []
let now = 1_800_000_000_000
const limits: LeaseLimits = {
  global: 10,
  perIp: 10,
  perEntitlement: 1,
  byTier: { basic: 1, standard: 2, premium: 4, internal: 8 },
}

function store(custom: Partial<LeaseLimits> = {}): LeaseStore {
  const value = new LeaseStore(':memory:', { ...limits, ...custom }, () => now)
  stores.push(value)
  return value
}

function lease(id: string, overrides: Partial<AcquireLeaseInput> = {}): AcquireLeaseInput {
  return {
    id,
    tokenJti: `token-jti-value-${id}`,
    tokenExpiresAt: now + 60_000,
    userId: 'user-a',
    entitlementId: `entitlement-${id}`,
    deviceAddress: `AA:BB:CC:DD:EE:${id.padStart(2, '0')}`,
    resourceId: `resource-${id}`,
    ipAddress: '127.0.0.1',
    tier: 'basic',
    tokenConcurrency: 8,
    expiresAt: now + 10_000,
    ...overrides,
  }
}

function expectLeaseCode(operation: () => void, code: LeaseError['code']): void {
  try {
    operation()
  } catch (error) {
    expect(error).toBeInstanceOf(LeaseError)
    expect((error as LeaseError).code).toBe(code)
    return
  }
  throw new Error(`expected LeaseError ${code}`)
}

afterEach(() => {
  for (const value of stores.splice(0)) value.close()
  now = 1_800_000_000_000
})

describe('LeaseStore', () => {
  it('binds a multi-resource JWT replay marker to the selected resource', () => {
    const tokenJti = 'shared-signed-token-jti'
    expect(resourceConsumptionId(tokenJti, 'resource-a')).toBe(resourceConsumptionId(tokenJti, 'resource-a'))
    expect(resourceConsumptionId(tokenJti, 'resource-a')).not.toBe(resourceConsumptionId(tokenJti, 'resource-b'))
  })

  it('revokes a residual device lease so a concurrent install starts immediately', () => {
    const value = store({ perEntitlement: 10 })
    const device = 'AA:BB:CC:DD:EE:AA'
    const resource = 'resource-x'
    const first = lease('01', { deviceAddress: device, resourceId: resource, expiresAt: now + 120_000 })
    expect(value.acquire(first)).toEqual([])

    // 同一设备的并发安装直接吊销旧租约，返回旧会话 id，并签发新租约。
    const revoked = value.acquire(lease('02', { userId: 'user-b', deviceAddress: device, resourceId: resource }))
    expect(revoked).toEqual(['01'])
    expect(value.activeCount()).toBe(1)

    // 旧 token 的 replay marker 保留，重放仍被拒绝。
    expectLeaseCode(
      () => value.acquire(lease('03', { userId: 'user-c', deviceAddress: 'AA:BB:CC:DD:EE:03', tokenJti: first.tokenJti })),
      'TOKEN_REPLAY',
    )
  })

  it('revokes a stuck device lease before USER_LIMIT can block the retry', () => {
    const value = store({ perEntitlement: 10 })
    const device = 'AA:BB:CC:DD:EE:BB'
    const resource = 'resource-basic'
    const userId = 'afdian:buyer-1'
    value.acquire(lease('b1', { userId, deviceAddress: device, resourceId: resource, tier: 'basic', tokenConcurrency: 1 }))

    // 同一设备重试：残留租约被直接吊销，新租约立即签发，不再被 USER_LIMIT 或冷却挡住。
    const revoked = value.acquire(lease('b2', { userId, deviceAddress: device, resourceId: resource, tier: 'basic', tokenConcurrency: 1, expiresAt: now + 900_000 }))
    expect(revoked).toEqual(['b1'])
    expect(value.activeCount()).toBe(1)
  })

  it('revokes the oldest account lease when basic-tier user concurrency is exhausted', () => {
    const value = store({ perEntitlement: 10 })
    const userId = 'user-x'
    value.acquire(lease('u1', { userId, deviceAddress: 'AA:BB:CC:DD:EE:C1', tier: 'basic', tokenConcurrency: 1, expiresAt: now + 42_000 }))

    // 同一账号、不同设备：吊销最旧的 u1，签发新的 u2。
    const revoked = value.acquire(lease('u2', { userId, deviceAddress: 'AA:BB:CC:DD:EE:C2', tier: 'basic', tokenConcurrency: 1 }))
    expect(revoked).toEqual(['u1'])
    expect(value.activeCount()).toBe(1)
  })

  it('revokes the oldest entitlement lease when entitlement concurrency is exhausted', () => {
    const value = store()
    const entitlement = 'shared-entitlement'
    value.acquire(lease('e1', { userId: 'user-a', deviceAddress: 'AA:BB:CC:DD:EE:D1', entitlementId: entitlement }))

    // 不同用户、不同设备，但同一授权：吊销最旧的 e1，签发新的 e2。
    const revoked = value.acquire(lease('e2', { userId: 'user-b', deviceAddress: 'AA:BB:CC:DD:EE:D2', entitlementId: entitlement }))
    expect(revoked).toEqual(['e1'])
    expect(value.activeCount()).toBe(1)
  })

  it('revokes the oldest premium lease when the signed staircase is exhausted', () => {
    const value = store({ perEntitlement: 8 })
    for (let index = 1; index <= 4; index++) {
      value.acquire(lease(`p${index}`, {
        tokenJti: `premium-token-jti-${index}`,
        deviceAddress: `AA:BB:CC:DD:EF:0${index}`,
        entitlementId: 'premium-entitlement',
        tier: 'premium',
        tokenConcurrency: 4,
      }))
    }
    // 第 5 个安装：吊销最旧的 p1，签发新的 p5。
    const revoked = value.acquire(lease('p5', {
      tokenJti: 'premium-token-jti-5',
      deviceAddress: 'AA:BB:CC:DD:EF:05',
      entitlementId: 'premium-entitlement',
      tier: 'premium',
      tokenConcurrency: 4,
    }))
    expect(revoked).toEqual(['p1'])
    expect(value.activeCount()).toBe(4)
  })

  it('revokes the oldest lease when the signed concurrency claim tightens the limit', () => {
    const value = store({ perEntitlement: 8 })
    for (let index = 1; index <= 2; index++) {
      value.acquire(lease(`s${index}`, {
        tokenJti: `signed-limit-jti-${index}`,
        deviceAddress: `AA:BB:CC:DD:F0:0${index}`,
        entitlementId: 'signed-limit-entitlement',
        tier: 'internal',
        tokenConcurrency: 2,
      }))
    }
    const revoked = value.acquire(lease('s3', {
      tokenJti: 'signed-limit-jti-3',
      deviceAddress: 'AA:BB:CC:DD:F0:03',
      entitlementId: 'signed-limit-entitlement',
      tier: 'internal',
      tokenConcurrency: 2,
    }))
    expect(revoked).toEqual(['s1'])
    expect(value.activeCount()).toBe(2)
  })

  it('still enforces the per-IP and global hard limits', () => {
    const value = store({ perIp: 1 })
    value.acquire(lease('01', { ipAddress: '10.0.0.1' }))
    expectLeaseCode(() => value.acquire(lease('02', { userId: 'user-b', ipAddress: '10.0.0.1', deviceAddress: 'AA:BB:CC:DD:EE:02' })), 'IP_LIMIT')

    const tiny = store({ global: 1 })
    tiny.acquire(lease('01', { deviceAddress: 'AA:BB:CC:DD:EE:01' }))
    expectLeaseCode(() => tiny.acquire(lease('02', { userId: 'user-b', deviceAddress: 'AA:BB:CC:DD:EE:02', entitlementId: 'entitlement-02' })), 'GLOBAL_LIMIT')
  })

  it('keeps jti one-shot after release and cleans expired leases', () => {
    const value = store()
    const first = lease('01')
    value.acquire(first)
    expect(value.release(first.id)).toBe(true)
    expectLeaseCode(
      () => value.acquire({ ...first, id: '02', deviceAddress: 'AA:BB:CC:DD:EE:02' }),
      'TOKEN_REPLAY',
    )
    now = first.tokenExpiresAt + 1
    value.cleanup()
    expectLeaseCode(
      () => value.acquire({ ...first, id: '02-exp', deviceAddress: 'AA:BB:CC:DD:EE:12' }),
      'TOKEN_REPLAY',
    )

    value.acquire(lease('03'))
    now += 10_001
    expect(value.activeCount()).toBe(0)
    value.acquire(lease('04'))
    expect(value.activeCount()).toBe(1)
  })

  it('returns a creation token only when cancellation happened before delivery', () => {
    const value = store()
    const first = lease('01')
    value.acquire(first)
    value.cancelCreation(first.id, first.tokenJti)
    expect(() => value.acquire({ ...first, id: '02' })).not.toThrow()
  })

  it('keeps reconnect and failure events after the active lease is released', () => {
    const value = store()
    const active = lease('01')
    value.acquire(active)
    value.recordEvent({
      sessionId: active.id,
      entitlementId: active.entitlementId,
      resourceId: 'resource-a',
      deviceAddress: active.deviceAddress,
      event: 'device.disconnected',
      detail: 'serial disconnected',
      attempt: 1,
      acknowledgedPart: 42,
    })
    value.recordEvent({
      sessionId: active.id,
      entitlementId: active.entitlementId,
      resourceId: 'resource-a',
      deviceAddress: active.deviceAddress,
      event: 'install.failed',
      detail: 'MASS timeout',
      attempt: 2,
      acknowledgedPart: 42,
    })
    expect(value.release(active.id)).toBe(true)
    expect(value.listEvents(active.id)).toEqual([
      { event: 'device.disconnected', detail: 'serial disconnected', attempt: 1, acknowledgedPart: 42 },
      { event: 'install.failed', detail: 'MASS timeout', attempt: 2, acknowledgedPart: 42 },
    ])
  })
})
