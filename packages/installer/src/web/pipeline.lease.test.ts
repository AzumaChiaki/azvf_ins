import { describe, expect, it } from 'vitest'
import { hasValidLeaseWindow } from './pipeline.js'

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
