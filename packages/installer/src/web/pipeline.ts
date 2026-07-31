// Authenticated v2 streaming pipeline:
// download worker (credit limited) -> crypto worker (real/decoy classification)
// -> hard-bounded plaintext queue -> pure TypeScript MiWear streaming transport.
import {
  fromBase64,
  fromHex,
  resourceManifestHashV2,
  normalizeDeviceIdentifier,
  WATCHFACE_ID_OFFSET,
  WATCHFACE_HEADER_LENGTH,
  WIRE_PROTOCOL_VERSION,
  type ResourceMeta,
  type SessionInitRequest,
  type SessionInitResponse,
} from '@azvf/contract'
import {
  deriveSessionKeys,
  exportPublicKey,
  generateSessionKeypair,
  unwrapSessionKey,
  verifyControlMac,
  type SessionControlContext,
} from '../crypto/index.js'
import type { MiWearSession, InstallProgress } from './miwear/session.js'
import { apiFetch } from './apiFetch.js'
import { PlaintextQueue } from './plaintextQueue.js'

interface SecureSessionResponse extends SessionInitResponse {
  controlToken: string
  leaseExpiresAt: number
}

/** Thrown when the server rejects session creation with a cooldown (429). */
export class InstallCooldownError extends Error {
  constructor(message: string, public readonly retryAfterSeconds: number, public readonly code?: string) {
    super(message)
    this.name = 'InstallCooldownError'
  }
}

export interface StreamInstallOptions {
  session: MiWearSession
  authToken: string
  resourceId: string
  deviceAddr?: string
  /** Re-establishes the device transport without creating another server authorization. */
  reconnect?: (attempt: number, error: Error, previous: MiWearSession) => Promise<MiWearSession>
  maxReconnectAttempts?: number
}

export interface StreamProgress {
  downloaded: number
  downloadTotal: number
  decrypted: number
  decoys: number
  device: InstallProgress | null
  total: number
}

export interface StreamCallbacks {
  onProgress?: (progress: StreamProgress) => void
  onLog?: (message: string) => void
}

function normalizeDeviceAddress(value: string | undefined): string {
  if (!value) throw new Error('安装会话必须绑定设备标识')
  try {
    return normalizeDeviceIdentifier(value)
  } catch (error) {
    throw new Error(error instanceof Error ? `设备标识格式无效：${error.message}` : '设备标识格式无效')
  }
}

function leaseExpiryMs(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) return undefined
  // Older installer deployments exposed Unix seconds while current ones use
  // milliseconds. Accept both representations during rolling upgrades.
  return value < 10_000_000_000 ? value * 1_000 : value
}

/**
 * Validate the lease against the server clock carried in the authenticated
 * control context. A browser clock may be minutes ahead or behind, so using
 * Date.now() here can reject a lease that the server created moments ago.
 */
export function hasValidLeaseWindow(leaseExpiresAt: unknown, serverEpoch: unknown): boolean {
  const expiresAt = leaseExpiryMs(leaseExpiresAt)
  if (!expiresAt || typeof serverEpoch !== 'number' || !Number.isSafeInteger(serverEpoch) || serverEpoch <= 0) return false
  const remaining = expiresAt - serverEpoch * 1_000
  // SESSION_TTL is bounded to one hour server-side. The extra second accounts
  // for serverEpoch being rounded down to whole seconds.
  return remaining > 0 && remaining <= 3_601_000
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

async function validateSessionResponse(
  session: SecureSessionResponse,
  requestedResource: string,
  deviceId: string,
): Promise<{ context: SessionControlContext; chunkHashes: string[]; streamUrl: string }> {
  if (session.protocolVersion !== WIRE_PROTOCOL_VERSION) {
    throw new Error(`服务器线协议版本不兼容：期望 ${WIRE_PROTOCOL_VERSION}，实际 ${session.protocolVersion}`)
  }
  if (!/^[A-Za-z0-9_-]{32,64}$/.test(session.sessionId)) throw new Error('会话 ID 格式无效')
  if (!/^[A-Za-z0-9_-]{43}$/.test(session.controlToken)) throw new Error('会话控制令牌格式无效')
  if (!hasValidLeaseWindow(session.leaseExpiresAt, session.serverEpoch)) throw new Error('安装租约无效或已过期')
  if (!session.meta || session.meta.id !== requestedResource) throw new Error('服务器返回了错误的资源')
  if (!Number.isSafeInteger(session.meta.size) || session.meta.size < 1) throw new Error('资源大小无效')
  if (!Number.isSafeInteger(session.padTo) || session.padTo !== session.meta.chunkSize) throw new Error('加密填充大小与资源分片不一致')
  if (!Number.isSafeInteger(session.realTotal) || session.realTotal !== session.meta.totalChunks) throw new Error('真实分片总数与资源不一致')
  if (!Number.isSafeInteger(session.transportTotal) || session.transportTotal <= session.realTotal) {
    throw new Error('传输没有包含有效的诱饵分片计划')
  }
  if (!Number.isSafeInteger(session.serverEpoch) || session.serverEpoch <= 0) {
    throw new Error('服务器会话时间戳无效')
  }
  if (!/^[a-fA-F0-9]{64}$/.test(session.meta.sha256) || !/^[a-fA-F0-9]{32}$/.test(session.meta.md5)) {
    throw new Error('资源摘要格式无效')
  }
  if (!session.meta.version || session.meta.version.length > 128) throw new Error('资源版本无效')
  const watchfaceTransform = session.watchfaceTransform
  if (session.meta.resType === 16) {
    if (!watchfaceTransform
      || !/^\d{12}$/.test(watchfaceTransform.id)
      || !/^[a-f0-9]{32}$/.test(watchfaceTransform.md5)
      || !Number.isSafeInteger(watchfaceTransform.idOffset)
      || watchfaceTransform.idOffset < WATCHFACE_ID_OFFSET
      || watchfaceTransform.idOffset + watchfaceTransform.id.length > WATCHFACE_HEADER_LENGTH
      || watchfaceTransform.fieldEnd !== WATCHFACE_HEADER_LENGTH) {
      throw new Error('表盘会话缺少合法的 ID 改写参数')
    }
  } else if (watchfaceTransform !== undefined) {
    throw new Error('非表盘资源包含非法的 ID 改写参数')
  }
  if (session.meta.formatVersion !== 2
    || !session.meta.manifestHash
    || !/^[a-f0-9]{64}$/.test(session.meta.manifestHash)
    || !session.meta.manifestSignature
    || !/^[A-Za-z0-9_-]{86}$/.test(session.meta.manifestSignature)
    || !session.meta.manifestKeyId) {
    throw new Error('资源缺少已认证的 v2 签名清单')
  }

  const context: SessionControlContext = {
    sessionId: session.sessionId,
    resourceId: session.meta.id,
    resourceVersion: session.meta.version,
    manifestHash: session.meta.manifestHash,
    deviceId,
    serverEpoch: session.serverEpoch,
    transportTotal: session.transportTotal,
    realTotal: session.realTotal,
    padTo: session.padTo,
    watchfaceTransform,
  }
  const absoluteStreamUrl = new URL(session.streamUrl, location.origin)
  if (absoluteStreamUrl.origin !== location.origin
    || absoluteStreamUrl.pathname !== `/api/session/${encodeURIComponent(session.sessionId)}/stream`
    || absoluteStreamUrl.search || absoluteStreamUrl.hash) {
    throw new Error('服务器返回了不受信任的分片流地址')
  }

  const chunkHashes = session.meta.chunkSha256
  if (!chunkHashes || chunkHashes.length !== session.realTotal
    || chunkHashes.some((hash) => !/^[a-f0-9]{64}$/.test(hash))) {
    throw new Error('资源逐片摘要清单无效')
  }
  // The control MAC binds manifestHash, but the browser must also prove that
  // every installation-semantic metadata field and every real chunk digest
  // actually hashes to that signed value. Otherwise altered metadata could be
  // paired with an authentic hash without changing the encrypted transport.
  if (await resourceManifestHashV2(session.meta, chunkHashes) !== session.meta.manifestHash) {
    throw new Error('资源 v2 签名清单与安装元数据不匹配')
  }
  return { context, chunkHashes, streamUrl: absoluteStreamUrl.href }
}

async function sendControl(
  session: SecureSessionResponse,
  action: 'heartbeat' | 'complete' | 'event',
  body?: Record<string, unknown>,
): Promise<Response> {
  return apiFetch(`/api/session/${encodeURIComponent(session.sessionId)}/${action}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-session-control': session.controlToken,
    },
    body: JSON.stringify(body ?? {}),
    signal: AbortSignal.timeout(10_000),
  })
}

const retryDelay = (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds))

function isRecoverableTransportError(error: Error): boolean {
  return /(设备已断开|串口|serial|连接|connect|读取|写入|ACK|超时|timeout|下载线程|network|fetch|设备繁忙|MASS Prepare)/i.test(error.message)
    && !/(摘要|签名|篡改|格式无效|资源大小|存储空间|电量|不支持|授权|租约续期)/.test(error.message)
}

async function waitForReplayReady(session: SecureSessionResponse): Promise<void> {
  const deadline = Date.now() + 12_000
  let lastState = 'unknown'
  while (Date.now() < deadline) {
    const response = await apiFetch(`/api/session/${encodeURIComponent(session.sessionId)}`, {
      headers: { 'x-session-control': session.controlToken },
      signal: AbortSignal.timeout(5_000),
    })
    if (!response.ok) throw new Error(`安装会话恢复失败: HTTP ${response.status}`)
    const status = await response.json() as { state?: unknown }
    lastState = typeof status.state === 'string' ? status.state : 'unknown'
    if (lastState === 'recoverable' || lastState === 'delivered') return
    if (lastState === 'cancelled') throw new Error('安装会话已取消，无法断点续传')
    await retryDelay(250)
  }
  throw new Error(`安装会话未能进入可恢复状态（当前：${lastState}）`)
}

export async function streamInstall(opts: StreamInstallOptions, callbacks: StreamCallbacks = {}): Promise<ResourceMeta> {
  const log = (message: string): void => {
    try { callbacks.onLog?.(message) } catch { /* UI callbacks are not part of the security state machine. */ }
  }
  const reportProgress = (progress: StreamProgress): void => {
    try { callbacks.onProgress?.({ ...progress }) } catch { /* keep transport cleanup deterministic */ }
  }
  const deviceId = normalizeDeviceAddress(opts.deviceAddr ?? opts.session.deviceInfo?.addr)

  // Ephemeral, non-exportable browser RSA key pair protects the per-session HKDF master key.
  const pair = await generateSessionKeypair()
  const clientPublicKey = await exportPublicKey(pair.publicKey)
  const request: SessionInitRequest = {
    authToken: opts.authToken,
    clientPublicKey,
    resourceId: opts.resourceId,
    deviceAddr: deviceId,
  }
  const response = await apiFetch('/api/session', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
    signal: AbortSignal.timeout(30_000),
  })
  if (!response.ok) {
    const body = await response.json().catch(() => ({})) as { error?: string; code?: string; retryAfterSeconds?: number }
    if (response.status === 429) {
      const header = Number(response.headers.get('retry-after'))
      const retryAfter = Number.isFinite(body.retryAfterSeconds) ? Number(body.retryAfterSeconds)
        : Number.isFinite(header) ? header : 30
      throw new InstallCooldownError(body.error ?? '设备安装冷却中，请稍后重试', Math.max(1, Math.ceil(retryAfter)), body.code)
    }
    throw new Error(`建立会话失败: ${body.error ?? response.status}`)
  }
  const session = (await response.json()) as SecureSessionResponse
  let prepared: {
    context: SessionControlContext
    chunkHashes: string[]
    streamUrl: string
    masterKey: CryptoKey
    controlMac: Uint8Array
  }
  try {
    const validated = await validateSessionResponse(session, opts.resourceId, deviceId)
    const masterKey = await unwrapSessionKey(pair.privateKey, session.wrappedKey)
    const keys = await deriveSessionKeys(masterKey)
    const controlMac = fromBase64(session.controlMac)
    if (!(await verifyControlMac(keys.controlKey, validated.context, controlMac))) {
      throw new Error('服务器会话控制信息被篡改')
    }
    prepared = { ...validated, masterKey, controlMac }
  } catch (error) {
    // Session creation already reserved a persistent lease and charged the
    // attempt. If the authenticated response cannot be consumed, release the
    // lease immediately when its capability fields are at least syntactically
    // safe; otherwise it would occupy capacity until TTL expiry.
    if (/^[A-Za-z0-9_-]{32,64}$/.test(session?.sessionId ?? '')
      && /^[A-Za-z0-9_-]{43}$/.test(session?.controlToken ?? '')) {
      await sendControl(session, 'complete', { success: false }).catch(() => undefined)
    }
    throw error
  }
  const { context, chunkHashes, streamUrl, masterKey, controlMac } = prepared
  const { meta } = session
  let heartbeat: ReturnType<typeof setInterval> | undefined
  let completed = false
  let success = false
  let completionDetail: string | undefined
  let heartbeatRunning = false
  let heartbeatFailures = 0
  let activeFail: ((error: Error) => void) | undefined
  let acknowledgedPart = 0
  let totalParts = 0
  let retainedBytes = 0
  let attempt = 0
  let deviceSession = opts.session
  const maxReconnectAttempts = Math.max(0, Math.min(5, Math.trunc(opts.maxReconnectAttempts ?? 2)))

  const reportEvent = async (
    event: 'device.disconnected' | 'device.reconnect' | 'device.resumed',
    detail?: string,
  ): Promise<void> => {
    try {
      await sendControl(session, 'event', { event, detail, attempt, acknowledgedPart })
    } catch (error) {
      log(`⚠️ 安装事件记录失败: ${errorMessage(error)}`)
    }
  }

  const runAttempt = async (target: MiWearSession): Promise<void> => {
    const downloadWorker = new Worker(new URL('./workers/download.worker.ts', import.meta.url), { type: 'module' })
    const decryptWorker = new Worker(new URL('./workers/decrypt.worker.ts', import.meta.url), { type: 'module' })
    const channel = new MessageChannel()
    let queuePaused = false
    const pendingAccepts: number[] = []
    const flushAccepts = (): void => {
      while (!queuePaused && pendingAccepts.length > 0) {
        decryptWorker.postMessage({ type: 'accept', transportSeq: pendingAccepts.shift()! })
      }
    }
    // Anti-extraction: cap resident plaintext at ~1–2 chunks so the full
    // decrypted resource never coexists in browser memory. Download stays at
    // most two chunks ahead of device consumption (backpressure gated), keeping
    // a one-chunk lookahead to avoid pipeline bubbles. Throughput is unaffected:
    // the Bluetooth SPP write is orders of magnitude slower than download and
    // decryption, so a shallow buffer still keeps the device continuously fed.
    const chunkBytes = context.padTo
    const queue = new PlaintextQueue(
      (paused) => {
        queuePaused = paused
        downloadWorker.postMessage({ type: paused ? 'pause' : 'resume' })
        if (!paused) flushAccepts()
      },
      2 * chunkBytes,
      1 * chunkBytes,
      4 * chunkBytes,
    )
    const acceptTransport = (transportSeq: number): void => {
      pendingAccepts.push(transportSeq)
      flushAccepts()
    }
    const progress: StreamProgress = {
      downloaded: 0,
      downloadTotal: context.transportTotal,
      decrypted: 0,
      decoys: 0,
      device: totalParts > 0 ? {
        progress: acknowledgedPart / totalParts,
        total_parts: totalParts,
        current_part_num: acknowledgedPart,
        actual_data_payload_len: 0,
        message: attempt > 0 ? '正在校验数据并恢复传输' : undefined,
      } : null,
      total: context.realTotal,
    }
    let pipelineError: Error | undefined
    let heldFinalChunk: Uint8Array | undefined
    let settleTransport: ((error?: Error) => void) | undefined
    const transportDone = new Promise<void>((resolve, reject) => {
      settleTransport = (error) => error ? reject(error) : resolve()
    })
    void transportDone.catch(() => undefined)

    const fail = (error: Error): void => {
      if (pipelineError) return
      pipelineError = error
      settleTransport?.(error)
      settleTransport = undefined
      queue.fail(error)
      try { downloadWorker.postMessage({ type: 'abort', reason: error.message }) } catch { /* cleanup below */ }
    }
    activeFail = fail
    const workerFailure = (name: string, event: ErrorEvent): void => {
      fail(new Error(`${name}异常: ${event.message || '未知错误'}`))
    }
    downloadWorker.onerror = (event) => workerFailure('下载线程', event)
    decryptWorker.onerror = (event) => workerFailure('解密线程', event)

    downloadWorker.onmessage = (event) => {
      const data = event.data
      if (data.type === 'progress') {
        progress.downloaded = data.sent
        reportProgress(progress)
      } else if (data.type === 'error') {
        fail(new Error(`下载线程错误: ${data.message}`))
      }
    }
    decryptWorker.onmessage = (event) => {
      const data = event.data
      try {
        if (data.type === 'chunk') {
          const payload = data.payload as Uint8Array
          if (data.seq === context.realTotal - 1) {
            if (heldFinalChunk) throw new Error('收到重复的最后真实分片')
            queue.reserve(payload.length)
            heldFinalChunk = payload
          } else {
            queue.push(payload)
          }
          progress.decrypted++
          acceptTransport(data.transportSeq)
        } else if (data.type === 'decoy') {
          progress.decoys = data.processed
          acceptTransport(data.transportSeq)
        } else if (data.type === 'done') {
          progress.decoys = data.decoys
          if (!heldFinalChunk) throw new Error('缺少最后真实分片')
          queue.pushReserved(heldFinalChunk)
          heldFinalChunk = undefined
          queue.end()
          settleTransport?.()
          settleTransport = undefined
        } else if (data.type === 'error') {
          fail(new Error(`解密线程错误: ${data.message}`))
        }
        reportProgress(progress)
      } catch (error) {
        fail(error instanceof Error ? error : new Error(String(error)))
      }
    }

    try {
      decryptWorker.postMessage({
        sessionMasterKey: masterKey,
        context,
        controlMac,
        resourceSize: meta.size,
        expectedChunkHashes: chunkHashes,
        port: channel.port2,
      }, [channel.port2])
      downloadWorker.postMessage(
        { type: 'init', streamUrl, controlToken: session.controlToken, port: channel.port1 },
        [channel.port1],
      )
      await target.installStreaming(
        {
          resType: meta.resType,
          packageName: meta.packageName ?? null,
          md5: fromHex(meta.md5),
          size: meta.size,
          watchfaceTransform: session.watchfaceTransform,
          source: queue,
          onResumeState: (retained, total) => {
            retainedBytes = retained
            acknowledgedPart = 0
            totalParts = 0
            if (retained > 0) log(`设备保留了 ${retained}/${total} 字节，按 BandBurg MASS 语义续传剩余数据`)
          },
          onPartAcknowledged: (part, total) => {
            acknowledgedPart = Math.max(acknowledgedPart, part)
            totalParts = total
          },
        },
        (deviceProgress) => {
          progress.device = deviceProgress
          reportProgress(progress)
        },
      )
      // The device consumes the declared bytes without pulling the queue's null
      // terminator. Keep waiting until all trailing authenticated decoys pass.
      await transportDone
      if (pipelineError) throw pipelineError
    } finally {
      activeFail = undefined
      try { downloadWorker.postMessage({ type: 'abort', reason: 'attempt complete' }) } catch { /* terminate below */ }
      downloadWorker.terminate()
      decryptWorker.terminate()
    }
  }

  try {
    log(`安全会话已认证：${meta.name}，已启用密钥化算法调度与混淆分片`)
    log('v2 流水线已启动：双算法调度 → 诱饵处理 → 信用背压 → 逆向 MiWear 真流式写入')

    heartbeat = setInterval(() => {
      if (heartbeatRunning || completed) return
      heartbeatRunning = true
      void sendControl(session, 'heartbeat').then((result) => {
        if (result.ok) {
          heartbeatFailures = 0
          return
        }
        heartbeatFailures++
        const failure = new Error(`安装租约续期失败: HTTP ${result.status}`)
        if (result.status === 404 || result.status === 410 || heartbeatFailures >= 3) activeFail?.(failure)
        else log(`⚠️ ${failure.message}，将在后台重试（${heartbeatFailures}/3）`)
      }).catch((error) => {
        heartbeatFailures++
        const failure = new Error(`安装租约续期失败: ${errorMessage(error)}`)
        if (heartbeatFailures >= 3) activeFail?.(failure)
        else log(`⚠️ ${failure.message}，将在后台重试（${heartbeatFailures}/3）`)
      }).finally(() => {
        heartbeatRunning = false
      })
    }, 30_000)

    while (true) {
      try {
        await runAttempt(deviceSession)
        break
      } catch (error) {
        const failure = error instanceof Error ? error : new Error(String(error))
        completionDetail = failure.message
        if (!opts.reconnect || attempt >= maxReconnectAttempts || !isRecoverableTransportError(failure)) throw failure
        await reportEvent('device.disconnected', failure.message)
        await deviceSession.disconnect(false).catch(() => undefined)
        await waitForReplayReady(session)
        let reconnectCause = failure
        while (true) {
          if (attempt >= maxReconnectAttempts) throw reconnectCause
          attempt++
          log(`连接中断，准备第 ${attempt}/${maxReconnectAttempts} 次自动恢复；设备上次保留 ${retainedBytes} 字节，已确认 MASS 分片 ${acknowledgedPart}${totalParts ? `/${totalParts}` : ''}`)
          await reportEvent('device.reconnect', reconnectCause.message)
          try {
            deviceSession = await opts.reconnect(attempt, reconnectCause, deviceSession)
            await reportEvent('device.resumed', `等待设备报告已保留字节；上次确认分片 ${acknowledgedPart}`)
            log(`设备已重新认证，将按设备保留的字节断点继续（上次确认分片 ${acknowledgedPart}）`)
            break
          } catch (reconnectError) {
            reconnectCause = reconnectError instanceof Error ? reconnectError : new Error(String(reconnectError))
            completionDetail = reconnectCause.message
            await reportEvent('device.disconnected', reconnectCause.message)
            if (/未选择|取消/.test(reconnectCause.message)) throw reconnectCause
            await retryDelay(Math.min(2_000, 500 * attempt))
          }
        }
      }
    }
    success = true
    completed = true
    log('✅ 认证流式安装完成')
    return meta
  } catch (error) {
    completionDetail = completionDetail ?? errorMessage(error)
    throw error
  } finally {
    completed = true
    if (heartbeat) clearInterval(heartbeat)
    try {
      const completion = await sendControl(session, 'complete', {
        success,
        detail: completionDetail,
        attempt,
        acknowledgedPart,
      })
      if (!completion.ok) log(`⚠️ 安装租约释放返回 HTTP ${completion.status}`)
    } catch (error) {
      log(`⚠️ 安装租约释放失败: ${errorMessage(error)}`)
    }
  }
}
