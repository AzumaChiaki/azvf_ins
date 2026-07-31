import { describe, expect, it } from 'vitest'
import { PlaintextQueue } from './plaintextQueue.js'

describe('PlaintextQueue hard-bounded backpressure', () => {
  it('pauses at the high watermark and resumes below the low watermark', async () => {
    const events: boolean[] = []
    const queue = new PlaintextQueue((paused) => events.push(paused), 8, 4, 12)
    queue.push(new Uint8Array(5).fill(1))
    queue.push(new Uint8Array(3).fill(2))
    expect(queue.bufferedBytes).toBe(8)
    expect(events).toEqual([true])

    expect((await queue.pull())?.length).toBe(5)
    expect(queue.bufferedBytes).toBe(3)
    expect(events).toEqual([true, false])
  })

  it('fails closed instead of growing past the hard watermark', async () => {
    const queue = new PlaintextQueue(() => {}, 8, 4, 12)
    queue.push(new Uint8Array(8))
    expect(() => queue.push(new Uint8Array(5))).toThrow(/硬内存上限/)
    await expect(queue.pull()).rejects.toThrow(/硬内存上限/)
  })

  it('delivers directly to a waiting consumer without buffering', async () => {
    const queue = new PlaintextQueue(() => {}, 8, 4, 12)
    const pending = queue.pull()
    queue.push(new Uint8Array([1, 2, 3]))
    expect(await pending).toEqual(new Uint8Array([1, 2, 3]))
    expect(queue.bufferedBytes).toBe(0)
  })

  it('counts a held final chunk and releases it without double-counting', async () => {
    const queue = new PlaintextQueue(() => {}, 8, 4, 12)
    queue.push(new Uint8Array(7))
    queue.reserve(5)
    expect(queue.residentBytes).toBe(12)
    expect(() => queue.push(new Uint8Array(1))).toThrow(/硬内存上限/)

    const safe = new PlaintextQueue(() => {}, 8, 4, 12)
    safe.push(new Uint8Array(7))
    safe.reserve(5)
    safe.pushReserved(new Uint8Array(5))
    expect(safe.residentBytes).toBe(12)
  })
})
