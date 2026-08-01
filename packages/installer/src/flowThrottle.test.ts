import { afterEach, describe, expect, it, vi } from 'vitest'
import { ByteRateGate, splitWireBytes } from './flowThrottle.js'

afterEach(() => vi.useRealTimers())

describe('generic output flow controls', () => {
  it('splits transport bytes without changing order or contents', () => {
    const source = Uint8Array.from({ length: 37 }, (_, index) => index)
    const parts = splitWireBytes(source, 8)
    expect(parts.length).toBeGreaterThanOrEqual(8)
    expect(Buffer.concat(parts.map((part) => Buffer.from(part))).equals(Buffer.from(source))).toBe(true)
  })

  it('waits until enough byte credit is available', async () => {
    vi.useFakeTimers()
    let current = 0
    const gate = new ByteRateGate({ mode: 'enforced', ratePerSecond: 1000, burstBytes: 10 }, () => current)
    const pending = gate.wait(20)
    current = 10
    await vi.advanceTimersByTimeAsync(10)
    await expect(pending).resolves.toBe(10)
  })

  it('does not delay output when disabled', async () => {
    const gate = new ByteRateGate({ mode: 'disabled' })
    await expect(gate.wait(1_000_000)).resolves.toBe(0)
  })
})
