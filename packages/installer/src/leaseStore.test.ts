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

  it('reports the remaining device cooldown and waives it after repeated failures', () => {
    const value = store({ perEntitlement: 10 })
    const device = 'AA:BB:CC:DD:EE:AA'
    const resource = 'resource-x'
    value.acquire(lease('01', { deviceAddress: device, resourceId: resource, expiresAt: now + 120_000 }))

    // A second attempt on the same device is blocked with a real countdown.
    let retry = 0
    try {
      value.acquire(lease('02', { userId: 'user-b', deviceAddress: device, resourceId: resource }))
    } catch (error) {
      expect(error).toBeInstanceOf(LeaseError)
      expect((error as LeaseError).code).toBe('DEVICE_LIMIT')
      retry = (error as LeaseError).retryAfterSeconds ?? 0
    }
    expect(retry).toBeGreaterThan(0)
    expect(retry).toBeLessThanOrEqual(120)

    // Two consecutive failures of this device+resource waive the cooldown so
    // the next acquire clears the residual lease and succeeds.
    value.recordInstallFailure(device, resource)
    value.recordInstallFailure(device, resource)
    expect(() => value.acquire(lease('03', { userId: 'user-c', deviceAddress: device, resourceId: resource }))).not.toThrow()
    expect(value.activeCount()).toBe(1)

    // A success resets the streak, so the cooldown applies again afterwards.
    value.resetInstallFailure(device, resource)
    value.recordInstallFailure(device, resource)
    expectLeaseCode(
      () => value.acquire(lease('04', { userId: 'user-d', deviceAddress: device, resourceId: resource })),
      'DEVICE_LIMIT',
    )
  })

  it('enforces signed tier, device, entitlement and global limits atomically', () => {
    const value = store()
    value.acquire(lease('01'))
    expectLeaseCode(() => value.acquire(lease('02')), 'USER_LIMIT')
    expectLeaseCode(
      () => value.acquire(lease('03', { userId: 'user-b', deviceAddress: 'AA:BB:CC:DD:EE:01' })),
      'DEVICE_LIMIT',
    )
    expectLeaseCode(
      () => value.acquire(lease('04', { userId: 'user-b', entitlementId: 'entitlement-01' })),
      'ENTITLEMENT_LIMIT',
    )
  })

  it('allows the configured premium staircase but not a fifth install', () => {
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
    expectLeaseCode(() => value.acquire(lease('p5', {
      tokenJti: 'premium-token-jti-5',
      deviceAddress: 'AA:BB:CC:DD:EF:05',
      entitlementId: 'premium-entitlement',
      tier: 'premium',
      tokenConcurrency: 4,
    })), 'USER_LIMIT')
  })

  it('lets the signed concurrency claim only tighten local tier and entitlement limits', () => {
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
    expectLeaseCode(() => value.acquire(lease('s3', {
      tokenJti: 'signed-limit-jti-3',
      deviceAddress: 'AA:BB:CC:DD:F0:03',
      entitlementId: 'signed-limit-entitlement',
      tier: 'internal',
      tokenConcurrency: 2,
    })), 'USER_LIMIT')
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
