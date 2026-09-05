/// <reference lib="webworker" />
// Thread 1: fetch authenticated v2 frames and forward them with credit-based
// flow control. At most MAX_INFLIGHT_FRAMES can be queued in the MessagePort.
import { HEADER_LEN, parseChunkHeaderV2 } from '../../crypto/index.js'
interface InitMsg {
  type: 'init'
  streamUrl: string
  controlToken: string
  port: MessagePort
}
type ControlMsg = { type: 'pause' } | { type: 'resume' } | { type: 'abort'; reason?: string }
type PortControl = { type: 'ack'; transportSeq: number } | { type: 'abort'; reason?: string }

// One outstanding frame makes the cross-worker plaintext budget auditable;
// main-thread queue acceptance is the sole source of the next credit.
const MAX_INFLIGHT_FRAMES = 1

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length)
  out.set(a, 0)
  out.set(b, a.length)
  return out
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

type RetryableDownloadFailure = {
  message: string
  code?: string
  retryAfterSeconds?: number
}

async function retryableDownloadFailure(response: Response): Promise<RetryableDownloadFailure | undefined> {
  const body = await response.json().catch(() => undefined) as unknown
  if (!body || typeof body !== 'object') return undefined
  const record = body as Record<string, unknown>
  if (record.retryable !== true) return undefined
  const message = typeof record.error === 'string' && record.error.trim().length > 0 && record.error.length <= 512
    ? record.error.trim()
    : '安装会话暂时不可用，请重新发起安装。'
  const code = typeof record.code === 'string' && /^[a-z][a-z0-9_]{1,80}$/.test(record.code)
    ? record.code
    : undefined
  const retryAfterSeconds = typeof record.retryAfterSeconds === 'number'
    && Number.isFinite(record.retryAfterSeconds)
    && record.retryAfterSeconds > 0
    ? Math.max(1, Math.ceil(record.retryAfterSeconds))
    : undefined
  return { message, ...(code ? { code } : {}), ...(retryAfterSeconds ? { retryAfterSeconds } : {}) }
}

let paused = false
let aborted = false
let started = false
let inflight = 0
let lastAck = -1
let resumeWaiters: Array<() => void> = []
let creditWaiters: Array<() => void> = []
let abortController: AbortController | undefined

function wake(waiters: Array<() => void>): void {
  for (const resolve of waiters.splice(0)) resolve()
}

async function untilReady(): Promise<void> {
  while (paused && !aborted) await new Promise<void>((resolve) => resumeWaiters.push(resolve))
  while (inflight >= MAX_INFLIGHT_FRAMES && !aborted) {
    await new Promise<void>((resolve) => creditWaiters.push(resolve))
  }
  if (aborted) throw new Error('下载流水线已中止')
}

function abort(reason?: string): void {
  if (aborted) return
  aborted = true
  abortController?.abort(reason)
  wake(resumeWaiters)
  wake(creditWaiters)
}

self.onmessage = async (event: MessageEvent<InitMsg | ControlMsg>) => {
  const msg = event.data
  if (msg.type === 'pause') {
    paused = true
    return
  }
  if (msg.type === 'resume') {
    paused = false
    wake(resumeWaiters)
    return
  }
  if (msg.type === 'abort') {
    abort(msg.reason)
    return
  }
  if (started) {
    self.postMessage({ type: 'error', stage: 'download', message: '下载 Worker 不允许重复初始化' })
    return
  }
  started = true

  const { streamUrl, controlToken, port } = msg
  if (!/^[A-Za-z0-9_-]{43}$/.test(controlToken)) {
    self.postMessage({ type: 'error', stage: 'download', message: '会话控制令牌格式无效' })
    return
  }
  abortController = new AbortController()
  port.onmessage = (portEvent: MessageEvent<PortControl>) => {
    const control = portEvent.data
    if (control?.type === 'abort') {
      abort(control.reason)
      return
    }
    if (control?.type !== 'ack' || !Number.isSafeInteger(control.transportSeq)) return
    // MessagePort is ordered; acknowledgements must also be strictly ordered.
    if (control.transportSeq !== lastAck + 1 || inflight <= 0) {
      abort('解密线程返回了无效确认序号')
      return
    }
    lastAck = control.transportSeq
    inflight--
    wake(creditWaiters)
  }
  port.start?.()

  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
  try {
    const response = await fetch(streamUrl, {
      cache: 'no-store',
      credentials: 'same-origin',
      headers: { 'x-session-control': controlToken },
      signal: abortController.signal,
    })
    if (!response.ok || !response.body) {
      const recovery = await retryableDownloadFailure(response)
      self.postMessage({
        type: 'error',
        stage: 'download',
        message: recovery?.message ?? `下载失败: HTTP ${response.status}`,
        ...(recovery ? {
          retryable: true,
          ...(recovery.code ? { code: recovery.code } : {}),
          ...(recovery.retryAfterSeconds ? { retryAfterSeconds: recovery.retryAfterSeconds } : {}),
        } : {}),
      })
      return
    }
    reader = response.body.getReader()

    let buffer = new Uint8Array(0)
    let sent = 0
    for (;;) {
      await untilReady()
      const { done, value } = await reader.read()
      if (done) break
      if (!value?.length) continue
      // Copy into an owned ArrayBuffer; fetch typings may expose ArrayBufferLike.
      buffer = new Uint8Array(concat(buffer, value))
      while (buffer.length >= HEADER_LEN) {
        const header = parseChunkHeaderV2(buffer, 0)
        if (buffer.length < header.frameLength) break
        await untilReady()
        const frame = buffer.slice(0, header.frameLength)
        buffer = buffer.slice(header.frameLength)
        port.postMessage({ type: 'frame', frame }, [frame.buffer])
        inflight++
        sent++
        self.postMessage({ type: 'progress', stage: 'download', sent, total: header.transportTotal })
      }
    }
    if (buffer.length !== 0) throw new Error('下载流以不完整的 v2 分片结尾')
    while (inflight > 0 && !aborted) await new Promise<void>((resolve) => creditWaiters.push(resolve))
    if (aborted) throw new Error('下载流水线已中止')
    port.postMessage({ type: 'end' })
    self.postMessage({ type: 'done', stage: 'download', sent })
  } catch (error) {
    if (!aborted || !(error instanceof DOMException && error.name === 'AbortError')) {
      self.postMessage({ type: 'error', stage: 'download', message: errorMessage(error) })
    }
    port.postMessage({ type: 'abort', reason: errorMessage(error) })
  } finally {
    try { await reader?.cancel() } catch { /* already closed */ }
  }
}
