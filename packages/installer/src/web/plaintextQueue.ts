import type { PlaintextSource } from './miwear/session.js'

/**
 * 有界明文分片队列 + 背压。解密线程 push，安装(传输)阶段 pull。
 * 队列字节超过高水位时回调 onBackpressure(true)，通知下载线程暂停读取（TCP 背压回传服务端），
 * 消费降到低水位后回调 onBackpressure(false) 恢复。由此保证任意时刻只驻留有限明文，绝不落完整包。
 */
export class PlaintextQueue implements PlaintextSource {
  private readonly chunks: Uint8Array[] = []
  private bytes = 0
  private reservedBytes = 0
  private ended = false
  private error?: Error
  private paused = false
  private waiter?: { resolve: (v: Uint8Array | null) => void; reject: (e: Error) => void }

  constructor(
    private readonly onBackpressure: (paused: boolean) => void,
    private readonly highWater = 4 * 1024 * 1024,
    private readonly lowWater = 1 * 1024 * 1024,
    private readonly hardWater = 6 * 1024 * 1024,
  ) {
    if (!(lowWater >= 0 && lowWater < highWater && highWater < hardWater)) {
      throw new Error('明文队列水位配置无效')
    }
  }

  push(chunk: Uint8Array): void {
    if (this.ended || this.error) return
    if (!(chunk instanceof Uint8Array) || chunk.length === 0) throw new Error('明文队列拒绝空或无效分片')
    if (this.waiter) {
      const w = this.waiter
      this.waiter = undefined
      w.resolve(chunk)
      return
    }
    if (this.bytes + this.reservedBytes + chunk.length > this.hardWater) {
      const error = new Error('明文队列超过硬内存上限，流水线已中止')
      this.fail(error)
      throw error
    }
    this.chunks.push(chunk)
    this.bytes += chunk.length
    this.updateBackpressure()
  }

  /** Count a held plaintext chunk against the hard cap before releasing it. */
  reserve(length: number): void {
    if (!Number.isSafeInteger(length) || length < 1) throw new Error('明文保留长度无效')
    if (this.ended || this.error) return
    if (this.bytes + this.reservedBytes + length > this.hardWater) {
      const error = new Error('明文队列超过硬内存上限，流水线已中止')
      this.fail(error)
      throw error
    }
    this.reservedBytes += length
    this.updateBackpressure()
  }

  /** Move already-reserved bytes into the queue without double-counting. */
  pushReserved(chunk: Uint8Array): void {
    if (this.ended || this.error) return
    if (!(chunk instanceof Uint8Array) || chunk.length === 0 || chunk.length > this.reservedBytes) {
      throw new Error('明文保留分片无效')
    }
    this.reservedBytes -= chunk.length
    if (this.waiter) {
      const waiter = this.waiter
      this.waiter = undefined
      waiter.resolve(chunk)
    } else {
      this.chunks.push(chunk)
      this.bytes += chunk.length
    }
    this.updateBackpressure()
  }

  end(): void {
    this.ended = true
    if (this.waiter) {
      const w = this.waiter
      this.waiter = undefined
      w.resolve(null)
    }
  }

  fail(error: Error): void {
    this.error = error
    if (this.waiter) {
      const w = this.waiter
      this.waiter = undefined
      w.reject(error)
    }
  }

  async pull(): Promise<Uint8Array | null> {
    if (this.error) throw this.error
    if (this.chunks.length > 0) {
      const chunk = this.chunks.shift()!
      this.bytes -= chunk.length
      this.updateBackpressure()
      return chunk
    }
    if (this.ended) return null
    if (this.waiter) throw new Error('明文队列不允许并发 pull')
    return new Promise((resolve, reject) => {
      this.waiter = { resolve, reject }
    })
  }

  get bufferedBytes(): number {
    return this.bytes
  }

  get residentBytes(): number {
    return this.bytes + this.reservedBytes
  }

  private updateBackpressure(): void {
    const resident = this.bytes + this.reservedBytes
    if (!this.paused && resident >= this.highWater) {
      this.paused = true
      this.onBackpressure(true)
    } else if (this.paused && resident <= this.lowWater) {
      this.paused = false
      this.onBackpressure(false)
    }
  }
}
