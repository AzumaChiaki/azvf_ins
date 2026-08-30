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

  it('waives a basic-tier user\'s own stuck lease before USER_LIMIT can block the retry', () => {
    // Regression test: basic tier concurrency=1 means USER_LIMIT trips on the very
    // first retry after a crashed/failed install. The device-level failure-streak
    // exemption must run *before* USER_LIMIT is evaluated, or a legitimate retry on
    // the same device is stuck until the stale lease's raw TTL expires (minutes to
    // an hour), even though the exemption mechanism exists specifically to prevent
    // that.
    const value = store({ perEntitlement: 10 })
    const device = 'AA:BB:CC:DD:EE:BB'
    const resource = 'resource-basic'
    const userId = 'afdian:buyer-1'
    value.acquire(lease('b1', { userId, deviceAddress: device, resourceId: resource, tier: 'basic', tokenConcurrency: 1 }))

    // First retry (no failures recorded yet): blocked, but with an honest
    // retryAfterSeconds instead of the generic 30s fallback.
    let firstError: LeaseError | undefined
    try {
      value.acquire(lease('b2', { userId, deviceAddress: device, resourceId: resource, tier: 'basic', tokenConcurrency: 1, expiresAt: now + 900_000 }))
    } catch (error) {
      firstError = error as LeaseError
    }
    expect(firstError?.code).toBe('DEVICE_LIMIT')
    expect(firstError?.retryAfterSeconds).toBeGreaterThan(0)

    // Two consecutive failures on this device+resource waive the cooldown. The
    // very next acquire — same user, same basic tier, concurrency=1 — must
    // succeed immediately, not throw USER_LIMIT.
    value.recordInstallFailure(device, resource)
    value.recordInstallFailure(device, resource)
    expect(() => value.acquire(lease('b3', { userId, deviceAddress: device, resourceId: resource, tier: 'basic', tokenConcurrency: 1 })))
      .not.toThrow()
    expect(value.activeCount()).toBe(1)
  })

  it('counts an abandoned lease as a failure server-side, without any client report', () => {
    // Regression test: 关掉标签页的那次安装既不会 POST /complete，也不会有任何客户端
    // 上报。失败计数以前只在客户端上报时才 +1，于是「连续失败 2 次免 CD」这条逃生
    // 通道在最需要它的场景里永远不会触发——用户只能干等租约自然到期，一次又一次。
    // 租约走到过期即视为一次失败，计数必须由服务端自己记上。
    const value = store({ perEntitlement: 10 })
    const device = 'AA:BB:CC:DD:EE:CC'
    const resource = 'resource-abandoned'

    // 第一次被放弃的安装：租约到期时服务端记一次失败。
    value.acquire(lease('a1', { deviceAddress: device, resourceId: resource, expiresAt: now + 10_000 }))
    now += 11_000
    value.cleanup()
    expect(value.activeCount()).toBe(0)

    // 第二次被放弃：同样由服务端记账，凑满豁免阈值。
    value.acquire(lease('a2', { deviceAddress: device, resourceId: resource, expiresAt: now + 10_000 }))
    now += 11_000
    value.cleanup()

    // 第三次尝试时又撞上一条残留租约（上一把还没到期）——CD 必须已被豁免。
    value.acquire(lease('a3', { deviceAddress: device, resourceId: resource, expiresAt: now + 120_000 }))
    expect(() => value.acquire(lease('a4', { userId: 'user-z', deviceAddress: device, resourceId: resource })))
      .not.toThrow()
    expect(value.activeCount()).toBe(1)
  })

  it('does not count a released lease as a failure', () => {
    // release() 是正常收尾（成功，或客户端明确报了失败并自行记账）走的路径。
    // 只有过期收租约才算「没人报结果」。
    const value = store({ perEntitlement: 10 })
    const device = 'AA:BB:CC:DD:EE:DD'
    const resource = 'resource-released'
    value.acquire(lease('r1', { deviceAddress: device, resourceId: resource, expiresAt: now + 10_000 }))
    expect(value.release('r1')).toBe(true)
    value.acquire(lease('r2', { deviceAddress: device, resourceId: resource, expiresAt: now + 10_000 }))
    expect(value.release('r2')).toBe(true)

    value.acquire(lease('r3', { deviceAddress: device, resourceId: resource, expiresAt: now + 120_000 }))
    expectLeaseCode(
      () => value.acquire(lease('r4', { userId: 'user-y', deviceAddress: device, resourceId: resource })),
      'DEVICE_LIMIT',
    )
  })

  it('gives USER_LIMIT and ENTITLEMENT_LIMIT an accurate retryAfterSeconds instead of a flat fallback', () => {
    const value = store({ perEntitlement: 10 })
    value.acquire(lease('u1', { userId: 'user-x', deviceAddress: 'AA:BB:CC:DD:EE:C1', tier: 'basic', tokenConcurrency: 1, expiresAt: now + 42_000 }))
    let userError: LeaseError | undefined
    try {
      value.acquire(lease('u2', { userId: 'user-x', deviceAddress: 'AA:BB:CC:DD:EE:C2', tier: 'basic', tokenConcurrency: 1 }))
    } catch (error) {
      userError = error as LeaseError
    }
    expect(userError?.code).toBe('USER_LIMIT')
    expect(userError?.retryAfterSeconds).toBeGreaterThan(0)
    expect(userError?.retryAfterSeconds).toBeLessThanOrEqual(42)
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

describe('同设备同授权的重复安装', () => {
  it('让新会话顶掉旧租约,而不是把新会话拒在门外', () => {
    const value = store()
    const device = 'AA:BB:CC:DD:EE:01'
    const entitlement = 'same-order'
    value.acquire(lease('1', { deviceAddress: device, entitlementId: entitlement }))

    // 以前这里会撞上 DEVICE_LIMIT(设备冷却)——旧租约没到期,买家只能干等。
    // 令牌层早就是"后来者胜",租约层必须一致。
    expect(() => value.acquire(lease('2', { deviceAddress: device, entitlementId: entitlement })))
      .not.toThrow()

    // 顶掉而不是并存:同一时刻这台设备就一个安装在跑。
    expect(value.activeCount()).toBe(1)
    // 旧会话确实已经不在了 —— 续期它会失败。
    expect(value.renew('1', now + 60_000)).toBe(false)
    expect(value.renew('2', now + 60_000)).toBe(true)
  })

  it('不放宽跨授权的设备冷却', () => {
    const value = store()
    const device = 'AA:BB:CC:DD:EE:01'
    value.acquire(lease('1', { deviceAddress: device, entitlementId: 'order-a' }))
    // 同一台设备去装另一个订单,仍然受设备冷却约束。
    expect(() => value.acquire(lease('2', { deviceAddress: device, entitlementId: 'order-b' })))
      .toThrow(LeaseError)
  })

  it('不放宽不同设备之间的授权并发上限', () => {
    const value = store({ perEntitlement: 1 })
    value.acquire(lease('1', { deviceAddress: 'AA:BB:CC:DD:EE:01', entitlementId: 'order-a' }))
    // 换一台设备装同一个订单,并发上限照常生效——多并发权限的语义不受影响。
    expect(() => value.acquire(lease('2', { deviceAddress: 'AA:BB:CC:DD:EE:02', entitlementId: 'order-a' })))
      .toThrow(LeaseError)
  })
})
