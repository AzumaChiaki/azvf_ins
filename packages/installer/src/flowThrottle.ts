export interface FlowThrottleSettings {
  mode: 'enforced' | 'disabled'
  ratePerSecond?: number
  burstBytes?: number
}

/** Generic byte-rate gate. Policy values are supplied by the authorization service. */
export class ByteRateGate {
  private tokens: number
  private updatedAt: number

  constructor(private settings: FlowThrottleSettings, private readonly clock: () => number = Date.now) {
    this.tokens = settings.mode === 'enforced' ? Number(settings.burstBytes) : Number.POSITIVE_INFINITY
    this.updatedAt = clock()
  }

  update(settings: FlowThrottleSettings): void {
    if (this.settings.mode === 'enforced') {
      this.refill(Number(this.settings.ratePerSecond), Number(this.settings.burstBytes))
    }
    this.settings = settings
    this.tokens = settings.mode === 'enforced'
      ? Math.min(Number(settings.burstBytes), Number.isFinite(this.tokens) ? this.tokens : Number(settings.burstBytes))
      : Number.POSITIVE_INFINITY
    this.updatedAt = this.clock()
  }

  async wait(byteLength: number): Promise<number> {
    if (!Number.isSafeInteger(byteLength) || byteLength < 0) throw new Error('输出字节数无效')
    if (this.settings.mode === 'disabled' || byteLength === 0) return 0
    const rate = Number(this.settings.ratePerSecond)
    const capacity = Number(this.settings.burstBytes)
    if (!Number.isFinite(rate) || rate <= 0 || !Number.isFinite(capacity) || capacity <= 0) {
      throw new Error('输出速率参数无效')
    }
    let remaining = byteLength
    let waited = 0
    while (remaining > 0) {
      this.refill(rate, capacity)
      const take = Math.min(remaining, this.tokens)
      remaining -= take
      this.tokens -= take
      if (remaining <= 0) break
      const delay = Math.max(1, Math.ceil((Math.min(remaining, capacity) - this.tokens) / rate * 1000))
      const startedAt = this.clock()
      await new Promise<void>((resolve) => setTimeout(resolve, delay))
      waited += Math.max(0, this.clock() - startedAt)
    }
    return waited
  }

  private refill(rate: number, capacity: number): void {
    const current = this.clock()
    const elapsed = Math.max(0, current - this.updatedAt)
    this.tokens = Math.min(capacity, this.tokens + elapsed / 1000 * rate)
    this.updatedAt = current
  }
}

/** Splits a frame without changing byte order or contents. */
export function splitWireBytes(bytes: Uint8Array, minimumPieces: number): Uint8Array[] {
  if (bytes.length === 0) return []
  const pieces = Math.max(1, Math.min(bytes.length, Math.trunc(minimumPieces)))
  const size = Math.ceil(bytes.length / pieces)
  const result: Uint8Array[] = []
  for (let offset = 0; offset < bytes.length; offset += size) result.push(bytes.subarray(offset, offset + size))
  return result
}
