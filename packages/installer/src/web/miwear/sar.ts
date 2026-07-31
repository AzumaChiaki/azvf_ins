import { concatBytes, crc16Arc, readU16le, u16le } from './bytes'

export enum L1Type {
  Nak = 0,
  Ack = 1,
  Cmd = 2,
  Data = 3
}

export enum L2Channel {
  Pb = 1,
  Mass = 2
}

export enum L2Opcode {
  Write = 1,
  WriteEnc = 2,
  Read = 3
}

export interface L1Frame {
  type: L1Type
  frx: boolean
  seq: number
  payload: Uint8Array
}

export function encodeL1(frame: L1Frame): Uint8Array {
  const typeAndFrx = (frame.type & 0x0f) | (frame.frx ? 0x10 : 0)
  return concatBytes(
    Uint8Array.of(0xa5, 0xa5, typeAndFrx, frame.seq),
    u16le(frame.payload.length),
    u16le(crc16Arc(frame.payload)),
    frame.payload
  )
}

export function decodeL1(data: Uint8Array): L1Frame {
  if (data.length < 8 || data[0] !== 0xa5 || data[1] !== 0xa5) throw new Error('无效的 L1 帧头')
  const length = readU16le(data, 4)
  if (data.length !== length + 8) throw new Error('L1 帧长度不匹配')
  const payload = data.slice(8)
  if (readU16le(data, 6) !== crc16Arc(payload)) throw new Error('L1 CRC16 校验失败')
  return { type: data[2] & 0x0f, frx: (data[2] & 0x10) !== 0, seq: data[3], payload }
}

export function encodeL2(channel: L2Channel, opcode: L2Opcode, payload: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(channel, opcode), payload)
}

export function decodeL2(data: Uint8Array): { channel: number; opcode: number; payload: Uint8Array } {
  if (data.length < 2) throw new Error('L2 数据过短')
  return { channel: data[0], opcode: data[1], payload: data.slice(2) }
}

export class L1StreamDecoder {
  private buffer: Uint8Array = new Uint8Array()

  push(chunk: Uint8Array): L1Frame[] {
    this.buffer = concatBytes(this.buffer, chunk)
    const frames: L1Frame[] = []
    while (this.buffer.length >= 8) {
      let magic = -1
      for (let i = 0; i + 1 < this.buffer.length; i += 1) {
        if (this.buffer[i] === 0xa5 && this.buffer[i + 1] === 0xa5) {
          magic = i
          break
        }
      }
      if (magic < 0) {
        this.buffer = this.buffer.slice(-1)
        break
      }
      if (magic > 0) this.buffer = this.buffer.slice(magic)
      if (this.buffer.length < 8) break
      const total = 8 + readU16le(this.buffer, 4)
      if (this.buffer.length < total) break
      const candidate = this.buffer.slice(0, total)
      this.buffer = this.buffer.slice(total)
      try {
        frames.push(decodeL1(candidate))
      } catch (error) {
        console.warn('[reconstructed] 丢弃无效 L1 帧', error)
      }
    }
    return frames
  }
}

interface PendingFrame {
  frame: L1Frame
  resolve: () => void
  reject: (error: Error) => void
  timer?: ReturnType<typeof setTimeout>
  retries: number
  sent: boolean
}

export interface SarOptions {
  sendTimeoutMs?: number
  txWindow?: number
  maxRetries?: number
}

const DEFAULT_ACK_TIMEOUT_MS = 10_000
// Slow watches (right after「连接新手机」) may negotiate an ACK deadline longer
// than the default. Honor it up to this ceiling instead of clamping to 10s, so
// a device that is still bringing up its SPP link is not abandoned mid-auth.
const MAX_ACK_TIMEOUT_MS = 15_000

export class SarController {
  private nextSeq = 0
  private expectedRxSeq = 0
  private txWindow: number
  private sendTimeoutMs: number
  private readonly maxRetries: number
  private readonly pending: PendingFrame[] = []
  private closed = false
  private pumpRequested = false
  private pumpRunning = false
  // Resolves when the watch echoes the SAR start negotiation (L1 Cmd, type 2).
  // Lets connect() hold the first auth frame until the link is actually ready.
  private negotiated = false
  private negotiationWaiters: Array<() => void> = []

  constructor(
    private readonly write: (data: Uint8Array) => Promise<void>,
    private readonly onData: (payload: Uint8Array) => void | Promise<void>,
    options: SarOptions = {}
  ) {
    this.txWindow = options.txWindow ?? 16
    this.sendTimeoutMs = options.sendTimeoutMs ?? DEFAULT_ACK_TIMEOUT_MS
    this.maxRetries = options.maxRetries ?? 3
  }

  /**
   * Wait until the watch acknowledges the SAR start negotiation, or `timeoutMs`
   * elapses. Never rejects — resolves `true` if the echo arrived, `false` on
   * timeout. Best-effort: some firmwares proceed without echoing, so callers
   * must not treat `false` as fatal.
   */
  awaitNegotiation(timeoutMs: number): Promise<boolean> {
    if (this.negotiated || this.closed) return Promise.resolve(this.negotiated)
    return new Promise((resolve) => {
      let settled = false
      const done = (value: boolean) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        resolve(value)
      }
      const timer = setTimeout(() => done(false), timeoutMs)
      // Resolves with the real negotiation state: `true` once the echo lands,
      // `false` if close() flushes waiters before that.
      this.negotiationWaiters.push(() => done(this.negotiated))
    })
  }

  async start(): Promise<void> {
    const configs = [
      [1, Uint8Array.of(1, 0, 0)],
      [2, u16le(0xffff)],
      [3, u16le(16)],
      [4, u16le(DEFAULT_ACK_TIMEOUT_MS)],
      [5, Uint8Array.of(0)]
    ] as const
    const payload = concatBytes(
      Uint8Array.of(1),
      ...configs.map(([key, value]) => concatBytes(Uint8Array.of(key), u16le(value.length), value))
    )
    await this.write(encodeL1({ type: L1Type.Cmd, frx: false, seq: 0, payload }))
  }

  enqueue(payload: Uint8Array): Promise<void> {
    return this.enqueueBatch([payload])[0]!
  }

  enqueueBatch(payloads: Uint8Array[]): Promise<void>[] {
    if (this.closed) return payloads.map(() => Promise.reject(new Error('SAR 会话已关闭')))
    const promises = payloads.map((payload) => {
      const seq = this.nextSeq
      this.nextSeq = (this.nextSeq + 1) & 0xff
      return new Promise<void>((resolve, reject) => {
        this.pending.push({
          frame: { type: L1Type.Data, frx: false, seq, payload },
          resolve,
          reject,
          retries: 0,
          sent: false
        })
      })
    })
    if (promises.length > 0) this.schedulePump()
    return promises
  }

  async receive(frame: L1Frame): Promise<void> {
    if (this.closed) return
    if (frame.type === L1Type.Ack) {
      this.acknowledge(frame.seq)
      return
    }
    if (frame.type === L1Type.Nak) {
      this.handleNak(frame.seq)
      return
    }
    if (frame.type === L1Type.Cmd) {
      this.applyStartResponse(frame.payload)
      return
    }
    if (frame.type !== L1Type.Data) return
    if (!frame.frx && frame.seq !== this.expectedRxSeq) {
      await this.write(encodeL1({ type: L1Type.Nak, frx: false, seq: this.expectedRxSeq, payload: new Uint8Array() }))
      return
    }
    if (!frame.frx) {
      this.expectedRxSeq = (this.expectedRxSeq + 1) & 0xff
      await this.write(encodeL1({ type: L1Type.Ack, frx: false, seq: frame.seq, payload: new Uint8Array() }))
    }
    await this.onData(frame.payload)
  }

  close(reason = 'SAR 会话已关闭'): void {
    this.closed = true
    for (const item of this.pending.splice(0)) {
      if (item.timer) clearTimeout(item.timer)
      item.reject(new Error(reason))
    }
    // Release anyone parked on the negotiation echo so connect() cannot hang.
    for (const notify of this.negotiationWaiters.splice(0)) notify()
  }

  get windowSize(): number {
    return this.txWindow
  }

  private schedulePump(): void {
    if (this.closed) return
    this.pumpRequested = true
    if (this.pumpRunning) return
    queueMicrotask(() => void this.pump())
  }

  private async pump(): Promise<void> {
    if (this.pumpRunning || this.closed) return
    this.pumpRunning = true
    try {
      while (this.pumpRequested && !this.closed) {
        this.pumpRequested = false
        const inFlight = this.pending.filter(item => item.sent).length
        const ready = this.pending.filter(item => !item.sent).slice(0, Math.max(0, this.txWindow - inFlight))
        if (ready.length === 0) continue
        for (const item of ready) item.sent = true
        try {
          // AstroBox/BandBurg fills one negotiated SAR window and hands the
          // concatenated L1 stream to Web Serial in one operation. This avoids
          // thousands of tiny writer.write() calls on multi-megabyte files.
          await this.write(concatBytes(...ready.map((item) => encodeL1(item.frame))))
          for (const item of ready) {
            if (!this.pending.includes(item) || !item.sent) continue
            item.timer = setTimeout(() => void this.retry(item), this.sendTimeoutMs)
          }
        } catch (error) {
          const failure = error instanceof Error ? error : new Error(String(error))
          for (const item of ready) {
            if (!this.pending.includes(item)) continue
            item.reject(failure)
            this.remove(item)
          }
          this.pumpRequested = true
        }
      }
    } finally {
      this.pumpRunning = false
      if (this.pumpRequested && !this.closed) this.schedulePump()
    }
  }

  private async sendPending(item: PendingFrame): Promise<void> {
    item.sent = true
    try {
      await this.write(encodeL1(item.frame))
    } catch (error) {
      item.reject(error instanceof Error ? error : new Error(String(error)))
      this.remove(item)
      return
    }
    item.timer = setTimeout(() => void this.retry(item), this.sendTimeoutMs)
  }

  private async retry(item: PendingFrame): Promise<void> {
    if (!this.pending.includes(item) || this.closed) return
    if (item.retries >= this.maxRetries) {
      item.reject(new Error(`等待 L1 ACK 超时，seq=${item.frame.seq}`))
      this.remove(item)
      this.schedulePump()
      return
    }
    item.retries += 1
    await this.sendPending(item)
  }

  private acknowledge(seq: number): void {
    const acknowledged = this.pending.filter(item => item.sent && ((seq - item.frame.seq) & 0xff) < 128)
    for (const item of acknowledged) {
      if (item.timer) clearTimeout(item.timer)
      item.resolve()
      this.remove(item)
    }
    this.schedulePump()
  }

  private handleNak(seq: number): void {
    if (seq > 0) this.acknowledge((seq - 1) & 0xff)
    for (const item of this.pending) {
      if (((item.frame.seq - seq) & 0xff) < 128) {
        if (item.timer) clearTimeout(item.timer)
        item.sent = false
      }
    }
    this.schedulePump()
  }

  private applyStartResponse(payload: Uint8Array): void {
    if (payload[0] !== 2) return
    let offset = 1
    while (offset + 3 <= payload.length) {
      const key = payload[offset]
      const length = readU16le(payload, offset + 1)
      offset += 3
      if (offset + length > payload.length) break
      if (key === 3 && length === 2) this.txWindow = Math.max(1, readU16le(payload, offset))
      if (key === 4 && length === 2) {
        // Honor the watch's negotiated ACK deadline, capped so a stale link
        // still hands control to the reconnect/resume path within 15s rather
        // than blocking a single frame for up to a minute.
        this.sendTimeoutMs = Math.min(MAX_ACK_TIMEOUT_MS, Math.max(1_000, readU16le(payload, offset)))
      }
      offset += length
    }
    this.resolveNegotiation()
    this.schedulePump()
  }

  private resolveNegotiation(): void {
    if (this.negotiated) return
    this.negotiated = true
    for (const notify of this.negotiationWaiters.splice(0)) notify()
  }

  private remove(item: PendingFrame): void {
    const index = this.pending.indexOf(item)
    if (index >= 0) this.pending.splice(index, 1)
  }
}
