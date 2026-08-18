import { createHash, createHmac, randomBytes, randomInt } from 'node:crypto'
import { Readable } from 'node:stream'
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify'
import { nanoid } from 'nanoid'
import {
  MAX_CHUNK_PAYLOAD,
  WIRE_PROTOCOL_VERSION,
  canonicalResourceManifestV2,
  toBase64,
  type ResourceMeta,
  type SignedResourceMeta,
  type SessionInitRequest,
  type SessionInitResponse,
  type WatchfaceInstallTransform,
  DEVICE_IDENTIFIER_PATTERN,
} from '@azvf/contract'
import {
  MAX_TRANSPORT_CHUNKS,
  createControlMac,
  deriveSessionKeys,
  encryptChunkV2,
  generateSessionKey,
  importPublicKey,
  wrapSessionKey,
} from './crypto/index.js'
import {
  AuthTokenVerifier,
  AuthorizationVersionError,
  type VerifiedAuthToken,
} from '@azvf/internal-client/auth'
import { config } from './config.js'
import { resourceConsumptionId } from './consumption.js'
import {
  fetchPlaintextChunks,
  fetchSiteContent,
  consumeEntitlement,
  acknowledgeInstallationMessage,
  EntitlementDecisionError,
  reportInstallationEvent,
  reportInstallationSample,
  UpstreamHttpError,
  type InstallationTelemetryEvent,
  type AuthenticatedResourceMeta,
} from '@azvf/internal-client'
import { normalizeDeviceAddress } from './device.js'
import { LeaseError, LeaseStore, type InstallEventType } from './leaseStore.js'
import { RateLimiter } from './rateLimit.js'
import { SessionStore, type InstallSession } from './session.js'
import { DOWNSTREAM_STALL_MARK_MS, streamIdleWindowMs } from './streamWindow.js'
import { createWatchfaceInstallTransform } from './watchfaceTransform.js'
import { ByteRateGate, splitWireBytes } from './flowThrottle.js'

interface SessionResponse extends SessionInitResponse {
  controlToken: string
  leaseExpiresAt: number
}

interface ControlParams { id: string }
interface CompleteBody { success: boolean; detail?: string; attempt?: number; acknowledgedPart?: number
  /** Only for navigator.sendBeacon, which cannot set the x-session-control header. */
  control?: string }
interface EventBody { event: InstallEventType; detail?: string; attempt?: number; acknowledgedPart?: number }

const sessionBodySchema = {
  type: 'object',
  additionalProperties: false,
  required: ['attemptId', 'authToken', 'clientPublicKey', 'resourceId', 'deviceAddr', 'clientAttributes'],
  properties: {
    attemptId: { type: 'string', minLength: 36, maxLength: 64, pattern: '^[A-Za-z0-9_-]+$' },
    authToken: { type: 'string', minLength: 32, maxLength: 16_384 },
    clientPublicKey: { type: 'string', minLength: 128, maxLength: 8_192, pattern: '^[A-Za-z0-9+/]+={0,2}$' },
    resourceId: { type: 'string', minLength: 1, maxLength: 128, pattern: '^[A-Za-z0-9_-]+$' },
    deviceAddr: { type: 'string', minLength: 8, maxLength: 64, pattern: DEVICE_IDENTIFIER_PATTERN },
    deviceName: { type: 'string', minLength: 1, maxLength: 100, pattern: '^[^\\u0000-\\u001f\\u007f]+$' },
    clientAttributes: {
      type: 'object', additionalProperties: false,
      required: ['timeZone', 'language', 'screen', 'hardwareConcurrency', 'platform', 'engine'],
      properties: {
        timeZone: { type: 'string', minLength: 1, maxLength: 64 },
        language: { type: 'string', minLength: 1, maxLength: 32 },
        screen: { type: 'string', minLength: 5, maxLength: 24 },
        hardwareConcurrency: { type: 'integer', minimum: 1, maximum: 1024 },
        platform: { type: 'string', minLength: 1, maxLength: 64 },
        engine: { type: 'string', enum: ['Chrome', 'Firefox', 'Safari', 'Edge', 'Other'] },
      },
    },
  },
} as const

const paramsSchema = {
  type: 'object', additionalProperties: false, required: ['id'],
  properties: { id: { type: 'string', minLength: 32, maxLength: 64, pattern: '^[A-Za-z0-9_-]+$' } },
} as const

function validateMeta(value: ResourceMeta, resourceId: string): ResourceMeta {
  if (!value || typeof value !== 'object' || value.id !== resourceId) throw new Error('资源元数据 ID 不一致')
  if (typeof value.name !== 'string' || value.name.length < 1 || value.name.length > 512) throw new Error('资源名称无效')
  if (![16, 32, 64].includes(value.resType)) throw new Error('资源类型无效')
  if (!Number.isSafeInteger(value.size) || value.size < 1 || value.size > config.maxResourceBytes) throw new Error('资源大小无效')
  if (!Number.isSafeInteger(value.chunkSize) || value.chunkSize < 16_384 || value.chunkSize > MAX_CHUNK_PAYLOAD) throw new Error('资源分片大小无效')
  if (!Number.isSafeInteger(value.totalChunks) || value.totalChunks !== Math.ceil(value.size / value.chunkSize)) {
    throw new Error('资源分片数量无效')
  }
  if (!/^[a-fA-F0-9]{64}$/.test(value.sha256) || !/^[a-fA-F0-9]{32}$/.test(value.md5)) throw new Error('资源摘要无效')
  if (typeof value.version !== 'string' || value.version.length < 1 || value.version.length > 128) throw new Error('资源版本无效')
  if (value.versionCode != null && (!Number.isSafeInteger(value.versionCode) || value.versionCode < 0)) {
    throw new Error('资源 versionCode 无效')
  }
  if (value.packageName != null && (typeof value.packageName !== 'string' || value.packageName.length > 256)) {
    throw new Error('资源包名无效')
  }
  if (value.watchfaceId != null && (typeof value.watchfaceId !== 'string' || value.watchfaceId.length > 128)) {
    throw new Error('表盘 ID 无效')
  }
  return {
    id: value.id,
    name: value.name,
    resType: value.resType,
    packageName: value.packageName ?? null,
    size: value.size,
    sha256: value.sha256.toLowerCase(),
    md5: value.md5.toLowerCase(),
    watchfaceId: value.watchfaceId ?? null,
    version: value.version,
    versionCode: value.versionCode ?? (value.resType === 64 ? 10 : null),
    chunkSize: value.chunkSize,
    totalChunks: value.totalChunks,
  }
}

async function authenticateMeta(
  value: AuthenticatedResourceMeta,
  resourceId: string,
  verifier: AuthTokenVerifier,
): Promise<SignedResourceMeta> {
  const normalized = validateMeta(value, resourceId)
  if (value.formatVersion !== 2
    || !/^[a-f0-9]{64}$/.test(value.manifestHash)
    || !/^[A-Za-z0-9_-]{86}$/.test(value.manifestSignature)
    || typeof value.manifestKeyId !== 'string'
    || value.manifestKeyId.length < 1
    || value.manifestKeyId.length > 128
    || !Array.isArray(value.chunkSha256)
    || value.chunkSha256.length !== normalized.totalChunks
    || value.chunkSha256.some((digest) => typeof digest !== 'string' || !/^[a-f0-9]{64}$/.test(digest))) {
    throw new Error('资源缺少完整的 v2 签名清单')
  }
  const manifest = canonicalResourceManifestV2(normalized, value.chunkSha256)
  const manifestHash = createHash('sha256').update(manifest).digest('hex')
  if (manifestHash !== value.manifestHash) throw new Error('资源 v2 清单摘要不匹配')
  if (!await verifier.verifyResourceManifest(manifestHash, value.manifestSignature, value.manifestKeyId)) {
    throw new Error('资源 v2 清单 Ed25519 签名无效')
  }
  return {
    ...normalized,
    formatVersion: 2,
    chunkSha256: [...value.chunkSha256],
    manifestHash,
    manifestSignature: value.manifestSignature,
    manifestKeyId: value.manifestKeyId,
  }
}

function createFrameSchedule(realTotal: number): Uint8Array {
  const decoys = Math.max(1, Math.round(realTotal * config.decoyRatio))
  const transportTotal = realTotal + decoys
  if (transportTotal > MAX_TRANSPORT_CHUNKS) throw new Error('加入诱饵后资源分片数量超过协议限制')
  const schedule = new Uint8Array(transportTotal)
  schedule.fill(1, 0, realTotal)
  // Fisher-Yates with crypto.randomInt gives every real/decoy interleaving equal probability.
  for (let index = schedule.length - 1; index > 0; index--) {
    const other = randomInt(index + 1)
    const value = schedule[index]!
    schedule[index] = schedule[other]!
    schedule[other] = value
  }
  return schedule
}

function deterministicDecoy(seed: Buffer, transportSeq: number, maxLength: number): Uint8Array {
  const descriptor = createHmac('sha256', seed).update(`length:${transportSeq}`).digest()
  const length = descriptor.readUInt32BE(0) % maxLength + 1
  const bytes = new Uint8Array(length)
  let offset = 0
  let counter = 0
  while (offset < length) {
    const block = createHmac('sha256', seed).update(`data:${transportSeq}:${counter++}`).digest()
    const take = Math.min(block.length, length - offset)
    bytes.set(block.subarray(0, take), offset)
    offset += take
  }
  return bytes
}

function controlHash(value: string | string[] | undefined): Buffer | undefined {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return undefined
  return createHash('sha256').update(value, 'ascii').digest()
}

function boundedExpiry(session: InstallSession, ttlSeconds: number): number {
  return Math.min(Date.now() + ttlSeconds * 1_000, session.absoluteExpiresAt)
}

function checkRate(
  limiter: RateLimiter,
  req: FastifyRequest,
  reply: FastifyReply,
  scope: string,
  capacity: number,
): boolean {
  const result = limiter.consume(`${scope}:${req.ip}`, capacity)
  if (result.allowed) return true
  reply.header('retry-after', String(result.retryAfterSeconds)).code(429).send({ error: '请求过于频繁，请稍后重试' })
  return false
}

function trustedRegion(req: FastifyRequest): string {
  const source = config.trustedRegionSource
  if (!source) return 'UNKNOWN'
  // Deliberately use the raw socket peer. req.ip may already contain a
  // client-controlled forwarded address when Fastify trustProxy is enabled.
  const edgePeer = source.edgePeerHeaderName
    ? req.headers[source.edgePeerHeaderName]
    : undefined
  return source.region(req.raw.socket.remoteAddress, req.headers[source.headerName], edgePeer)
}


function leaseError(reply: FastifyReply, error: LeaseError) {
  const status = error.code === 'TOKEN_REPLAY' ? 409 : 429
  const retryAfter = error.retryAfterSeconds ?? 30
  if (status === 429) reply.header('retry-after', String(retryAfter))
  return reply.code(status).send({ error: error.message, code: error.code, retryAfterSeconds: retryAfter })
}

async function acknowledgeDecision(sessionId: string, error: EntitlementDecisionError): Promise<void> {
  if (!error.decision.messageId) return
  await acknowledgeInstallationMessage({
    sessionId,
    messageId: error.decision.messageId,
    action: error.decision.action === 'reauth' ? 'return-login' : 'acknowledge',
  })
}

function decisionError(reply: FastifyReply, error: EntitlementDecisionError) {
  if (error.decision.action === 'reauth') reply.header('x-azvf-reauth', config.redeemUrl)
  if (error.decision.retryAfterSeconds) reply.header('retry-after', String(error.decision.retryAfterSeconds))
  return reply.code(error.status).send({
    error: error.decision.action === 'reauth' ? '需要重新核销' : error.decision.reason,
    ...(error.decision.retryAfterSeconds ? { retryAfterSeconds: error.decision.retryAfterSeconds } : {}),
  })
}

export async function installerRoutes(app: FastifyInstance) {
  const verifier = new AuthTokenVerifier(config)
  const leases = new LeaseStore(config.leaseDbPath, {
    global: config.globalConcurrency,
    perIp: config.ipConcurrency,
    perEntitlement: config.entitlementConcurrency,
    byTier: config.tierConcurrency,
  })
  const sessions = new SessionStore((session) => leases.release(session.sessionId))
  const limiter = new RateLimiter()

  const sendTelemetry = (
    req: FastifyRequest,
    session: { sessionId: string; resourceId: string; deviceAddress: string },
    event: InstallationTelemetryEvent,
  ) => {
    void reportInstallationEvent({
      sessionId: session.sessionId,
      resourceId: session.resourceId,
      deviceAddress: session.deviceAddress,
      event,
      region: trustedRegion(req),
    }).catch((error) => {
      // Telemetry is never allowed to change the user's install result, but a
      // failed signed delivery must remain visible to operators.
      req.log.warn({ err: error, sessionId: session.sessionId, event }, 'installation telemetry delivery failed')
    })
  }

  app.addHook('onClose', async () => {
    sessions.close()
    leases.close()
  })

  app.get('/api/site-content', async (req, reply) => {
    if (!checkRate(limiter, req, reply, 'site-content', 60)) return
    try {
      const content = await fetchSiteContent('install')
      return reply.header('cache-control', 'public, max-age=300').send(content)
    } catch (error) {
      req.log.warn({ err: error }, 'site content unavailable')
      return reply.code(503).send({ error: 'site_content_unavailable' })
    }
  })

  app.post<{ Body: SessionInitRequest }>('/api/session', { schema: { body: sessionBodySchema } }, async (req, reply) => {
    if (!checkRate(limiter, req, reply, 'session', config.sessionRateLimitPerMinute)) return
    const { attemptId, authToken, clientPublicKey, resourceId } = req.body
    let deviceAddress: string
    try {
      deviceAddress = normalizeDeviceAddress(req.body.deviceAddr)
    } catch (error: any) {
      return reply.code(400).send({ error: error.message })
    }

    const initializationFingerprint = createHash('sha256').update(JSON.stringify([
      authToken,
      clientPublicKey,
      resourceId,
      deviceAddress,
      req.body.deviceName ?? null,
      req.body.clientAttributes,
    ])).digest()
    const previousInitialization = sessions.initialization(attemptId, initializationFingerprint)
    if (previousInitialization === 'conflict') {
      req.log.warn({ attemptId }, 'session initialization attempt was reused with different inputs')
      return reply.code(409).send({ error: '会话创建尝试与原请求不一致' })
    }
    if (previousInitialization) {
      return reply.header('cache-control', 'no-store').send(previousInitialization)
    }

    let auth: VerifiedAuthToken
    try {
      auth = await verifier.verify(authToken)
    } catch (error) {
      if (error instanceof AuthorizationVersionError) {
        req.log.info({ code: error.code }, 'authorization token version rejected')
        if (error.code === 'authorization_client_upgrade_required') {
          return reply.code(426).send({ error: error.code })
        }
        return reply.header('x-azvf-reauth', config.redeemUrl).code(409).send({ error: error.code })
      }
      req.log.warn({ err: error }, 'authorization token rejected')
      return reply.code(401).send({ error: '授权令牌无效或已过期' })
    }
    if (!auth.resourceIds.includes(resourceId)) return reply.code(403).send({ error: '该授权不包含此资源' })
    if (auth.deviceAddr) {
      let boundAddress: string
      try { boundAddress = normalizeDeviceAddress(auth.deviceAddr) } catch { return reply.code(401).send({ error: '授权令牌的设备绑定无效' }) }
      if (boundAddress !== deviceAddress) return reply.code(403).send({ error: '授权绑定的设备不匹配' })
    }

    const sessionId = nanoid(32)
    const consumptionId = resourceConsumptionId(auth.jti, resourceId)
    let acquired = false
    try {
      const now = Date.now()
      const absoluteExpiresAt = now + config.installMaxDurationSeconds * 1_000
      const expiresAt = Math.min(now + config.sessionTtlSeconds * 1_000, absoluteExpiresAt)
      // The concurrency lease (the per-device install "CD") expires on the
      // shorter install-lease TTL; heartbeats renew it every 30s while an
      // install runs, so an abandoned attempt frees the device within ~3min.
      const leaseExpiresAt = Math.min(now + config.installLeaseTtlSeconds * 1_000, absoluteExpiresAt)
      // Reserve concurrency before the extra plaintext pass needed to compute
      // a watchface's rewritten MD5; rejected sessions must not amplify reads.
      leases.acquire({
        id: sessionId,
        tokenJti: consumptionId,
        tokenExpiresAt: auth.exp * 1_000,
        userId: auth.sub,
        entitlementId: auth.entitlementId,
        deviceAddress,
        resourceId,
        ipAddress: req.ip,
        tier: auth.installTier,
        tokenConcurrency: auth.installConcurrency,
        expiresAt: leaseExpiresAt,
      })
      acquired = true
      const consumed = await consumeEntitlement({
        entitlementId: auth.entitlementId,
        authorization: authToken,
        resourceId,
        deviceAddress,
        deviceName: req.body.deviceName,
        consumptionId,
        sessionId,
        expiresAt: Math.min(expiresAt, leaseExpiresAt),
        phase: 'session.create',
        clientIp: req.ip,
        clientAttributes: req.body.clientAttributes,
      })
      const meta = await authenticateMeta(consumed.signedMeta, resourceId, verifier)
      const watchfaceTransform: WatchfaceInstallTransform | undefined = meta.resType === 16
        ? await createWatchfaceInstallTransform(meta, {
          capability: consumed.capability,
          sessionId,
        })
        : undefined
      const clientPub = await importPublicKey(clientPublicKey)
      const sessionKey = await generateSessionKey()
      const wrappedKey = await wrapSessionKey(clientPub, sessionKey)
      const cryptoKeys = await deriveSessionKeys(sessionKey)
      const frameSchedule = createFrameSchedule(meta.totalChunks)
      const serverEpoch = Math.floor(Date.now() / 1_000)
      const controlContext = {
        sessionId,
        resourceId,
        resourceVersion: meta.version,
        manifestHash: meta.manifestHash,
        deviceId: deviceAddress,
        serverEpoch,
        transportTotal: frameSchedule.length,
        realTotal: meta.totalChunks,
        padTo: meta.chunkSize,
        watchfaceTransform,
      } as const
      const controlMac = toBase64(await createControlMac(cryptoKeys.controlKey, controlContext))
      const controlToken = randomBytes(32).toString('base64url')
      const response: SessionResponse = {
        sessionId,
        controlToken,
        leaseExpiresAt,
        protocolVersion: WIRE_PROTOCOL_VERSION,
        wrappedKey,
        serverEpoch,
        transportTotal: controlContext.transportTotal,
        realTotal: controlContext.realTotal,
        padTo: controlContext.padTo,
        controlMac,
        meta,
        watchfaceTransform,
        streamUrl: `/api/session/${sessionId}/stream`,
      }
      sessions.put({
        sessionId,
        attemptId,
        initializationFingerprint,
        initialResponse: response,
        resourceId,
        userId: auth.sub,
        entitlementId: auth.entitlementId,
        consumptionId,
        authorization: authToken,
        resourceCapability: consumed.capability,
        capabilityExpiresAt: consumed.capabilityExpiresAt,
        deviceAddress,
        clientIp: req.ip,
        clientAttributes: req.body.clientAttributes,
        throttle: consumed.throttle,
        lastHeartbeatAt: now,
        cryptoKeys,
        controlContext,
        frameSchedule,
        decoySeed: randomBytes(32),
        controlTokenHash: createHash('sha256').update(controlToken, 'ascii').digest(),
        meta,
        watchfaceTransform,
        createdAt: now,
        expiresAt,
        absoluteExpiresAt,
        state: 'created',
      })
      leases.recordEvent({ sessionId, entitlementId: auth.entitlementId, resourceId, deviceAddress, event: 'session.created' })
      sendTelemetry(req, { sessionId, resourceId, deviceAddress }, 'install.started')
      return reply.header('cache-control', 'no-store').send(response)
    } catch (error) {
      if (acquired) {
        sessions.remove(sessionId)
        leases.cancelCreation(sessionId, consumptionId)
      }
      if (error instanceof LeaseError) return leaseError(reply, error)
      if (error instanceof EntitlementDecisionError) {
        await acknowledgeDecision(sessionId, error).catch((ackError) => req.log.warn({ err: ackError, sessionId }, 'decision acknowledgement failed'))
        return decisionError(reply, error)
      }
      if (error instanceof UpstreamHttpError) return reply.code(error.status).send({ error: error.message })
      req.log.error({ err: error }, 'session creation failed')
      return reply.code(502).send({ error: '无法安全建立安装会话' })
    }
  })

  app.get<{ Params: ControlParams }>('/api/session/:id/stream', { schema: { params: paramsSchema } }, async (req, reply) => {
    const hash = controlHash(req.headers['x-session-control'])
    const initial = hash ? sessions.authorizeControl(req.params.id, hash) : undefined
    if (!initial || !['created', 'recoverable', 'delivered'].includes(initial.state)) {
      return reply.code(410).send({ error: '会话不存在、已过期或正在被其他连接使用' })
    }
    const resuming = initial.state !== 'created'
    const claimed = resuming ? sessions.claimReplay(req.params.id) : sessions.claim(req.params.id)
    if (!claimed) return reply.code(410).send({ error: '会话不存在、已过期或已消费' })
    try {
      const refreshed = await consumeEntitlement({
        entitlementId: claimed.entitlementId,
        authorization: claimed.authorization,
        resourceId: claimed.resourceId,
        deviceAddress: claimed.deviceAddress,
        consumptionId: claimed.consumptionId,
        sessionId: claimed.sessionId,
        expiresAt: boundedExpiry(claimed, config.installLeaseTtlSeconds),
        phase: 'stream.open',
        clientIp: claimed.clientIp,
        clientAttributes: claimed.clientAttributes,
      })
      const refreshedMeta = await authenticateMeta(refreshed.signedMeta, claimed.resourceId, verifier)
      if (refreshedMeta.manifestHash !== claimed.meta.manifestHash) throw new Error('资源版本已在会话期间变化')
      claimed.resourceCapability = refreshed.capability
      claimed.capabilityExpiresAt = refreshed.capabilityExpiresAt
      claimed.throttle = refreshed.throttle
      claimed.lastHeartbeatAt = Date.now()
    } catch (error) {
      req.log.warn({ err: error, sessionId: claimed.sessionId }, 'entitlement live-check rejected stream')
      sessions.remove(claimed.sessionId)
      leases.release(claimed.sessionId)
      if (error instanceof EntitlementDecisionError) {
        await acknowledgeDecision(claimed.sessionId, error).catch((ackError) => req.log.warn({ err: ackError }, 'decision acknowledgement failed'))
        return decisionError(reply, error)
      }
      return reply.code(410).send({ error: '授权已撤销、过期或不再可用' })
    }
    if (claimed.state !== 'authorizing') {
      sessions.remove(claimed.sessionId)
      leases.release(claimed.sessionId)
      return reply.code(410).send({ error: '安装会话已取消' })
    }
    const leaseExpiry = boundedExpiry(claimed, config.installLeaseTtlSeconds)
    const leaseReady = resuming ? leases.renew(claimed.sessionId, leaseExpiry)
      : leases.transition(claimed.sessionId, 'created', 'streaming', leaseExpiry)
    if (!leaseReady
      || !sessions.markStreaming(claimed.sessionId, leaseExpiry)) {
      sessions.remove(req.params.id)
      leases.release(req.params.id)
      return reply.code(410).send({ error: '安装租约已失效' })
    }
    const activeSession = claimed
    leases.recordEvent({ sessionId: claimed.sessionId, entitlementId: claimed.entitlementId, resourceId: claimed.resourceId,
      deviceAddress: claimed.deviceAddress, event: resuming ? 'stream.resumed' : 'stream.started' })
    sendTelemetry(req, claimed, 'download.started')

    async function* frames() {
      let completed = false
      let realSeq = 0
      let lastRenewedAt = Date.now()
      let sampleStartedAt = Date.now()
      let sampleIndex = 0
      let sampleBytes = 0
      let sampleThrottleWaitMs = 0
      let sampleBackpressureMs = 0
      // 最近一次下游(BLE 慢速消费)回压的观测时刻,驱动上游读取的动态空闲窗口。
      let lastDownstreamStallAt = 0
      const throttle = new ByteRateGate(activeSession.throttle)
      let sampleWindowMs = activeSession.throttle.mode === 'enforced'
        ? Number(activeSession.throttle.sampleWindowMs) : 10_000
      const piecesPerFrame = Math.max(1, Math.ceil(8 / activeSession.frameSchedule.length))
      const flushSample = async (force = false) => {
        const current = Date.now()
        if (!force && current - sampleStartedAt < sampleWindowMs) return
        if (sampleBytes === 0 && !force) return
        try {
          const decision = await reportInstallationSample({
            sessionId: activeSession.sessionId,
            resourceId: activeSession.resourceId,
            deviceAddress: activeSession.deviceAddress,
            region: trustedRegion(req),
            sample: {
              windowIndex: sampleIndex++,
              backpressureMs: Math.min(600_000, Math.trunc(sampleBackpressureMs)),
              throttleWaitMs: Math.min(600_000, Math.trunc(sampleThrottleWaitMs)),
              bytesSent: sampleBytes,
              heartbeatGapMs: activeSession.lastHeartbeatAt == null
                ? -1 : Math.min(3_600_000, Math.max(0, current - activeSession.lastHeartbeatAt)),
            },
          })
          if (decision.action !== 'allow') throw new EntitlementDecisionError(410, decision)
        } catch (error) {
          if (error instanceof EntitlementDecisionError) throw error
          req.log.warn({ err: error, sessionId: activeSession.sessionId }, 'flow sample delivery failed')
        } finally {
          sampleStartedAt = current
          sampleBytes = 0
          sampleThrottleWaitMs = 0
          sampleBackpressureMs = 0
        }
      }
      const source = fetchPlaintextChunks(activeSession.resourceId, activeSession.meta, {
        capability: activeSession.resourceCapability,
        sessionId: activeSession.sessionId,
      }, {
        // 下游回压期间按会话剩余租约放宽上游空闲窗口,避免掐断健康慢速安装;
        // 无回压(上游真卡)时保持 internalStreamIdleTimeoutMs 快速失败。
        idleTimeoutWindowMs: () => streamIdleWindowMs({
          now: Date.now(),
          baseMs: config.internalStreamIdleTimeoutMs,
          stallMaxMs: config.installStreamStallMaxMs,
          sessionExpiresAt: activeSession.expiresAt,
          lastDownstreamStallAt,
        }),
      })[Symbol.asyncIterator]()
      type Pull = { result?: IteratorResult<Uint8Array>; error?: unknown }
      const pull = (): Promise<Pull> => source.next().then((result) => ({ result }), (error) => ({ error }))
      let pendingReal = pull()
      try {
        for (let transportSeq = 0; transportSeq < activeSession.frameSchedule.length; transportSeq++) {
          if (activeSession.state === 'cancelled') throw new Error('安装会话已取消')
          const isReal = activeSession.frameSchedule[transportSeq] === 1
          let data: Uint8Array
          if (isReal) {
            const pulled = await pendingReal
            if (pulled.error) throw pulled.error
            if (!pulled.result || pulled.result.done) throw new Error('资源流分片数量不足')
            data = pulled.result.value
            pendingReal = pull()
          } else {
            data = deterministicDecoy(activeSession.decoySeed, transportSeq, activeSession.controlContext.padTo)
          }
          const frame = await encryptChunkV2(activeSession.cryptoKeys, activeSession.controlContext, {
            transportSeq,
            transportTotal: activeSession.controlContext.transportTotal,
            kind: isReal ? 'real' : 'decoy',
            data,
            padTo: activeSession.controlContext.padTo,
            ...(isReal ? { realSeq, realTotal: activeSession.controlContext.realTotal } : {}),
          })
          if (isReal) realSeq++
          if (Date.now() - lastRenewedAt >= 30_000) {
            const refreshed = await consumeEntitlement({
              entitlementId: activeSession.entitlementId,
              authorization: activeSession.authorization,
              resourceId: activeSession.resourceId,
              deviceAddress: activeSession.deviceAddress,
              consumptionId: activeSession.consumptionId,
              sessionId: activeSession.sessionId,
              expiresAt: boundedExpiry(activeSession, config.installLeaseTtlSeconds),
              phase: 'stream.renew',
              clientIp: activeSession.clientIp,
              clientAttributes: activeSession.clientAttributes,
            })
            activeSession.resourceCapability = refreshed.capability
            activeSession.capabilityExpiresAt = refreshed.capabilityExpiresAt
            activeSession.throttle = refreshed.throttle
            throttle.update(refreshed.throttle)
            sampleWindowMs = refreshed.throttle.mode === 'enforced'
              ? Number(refreshed.throttle.sampleWindowMs) : 10_000
            const renewedUntil = boundedExpiry(activeSession, config.installLeaseTtlSeconds)
            if (!leases.renew(activeSession.sessionId, renewedUntil)) throw new Error('安装租约续期失败')
            activeSession.expiresAt = renewedUntil
            lastRenewedAt = Date.now()
          }
          for (const wirePart of splitWireBytes(frame, piecesPerFrame)) {
            sampleThrottleWaitMs += await throttle.wait(wirePart.length)
            sampleBytes += wirePart.length
            const yieldedAt = Date.now()
            yield Buffer.from(wirePart)
            const stalledMs = Math.max(0, Date.now() - yieldedAt)
            sampleBackpressureMs += stalledMs
            if (stalledMs >= DOWNSTREAM_STALL_MARK_MS) lastDownstreamStallAt = Date.now()
            await flushSample()
          }
        }
        const finalPull = await pendingReal
        if (activeSession.state === 'cancelled') throw new Error('安装会话已取消')
        if (finalPull.error) throw finalPull.error
        if (!finalPull.result?.done || realSeq !== activeSession.controlContext.realTotal) {
          throw new Error('资源流真实分片数量不一致')
        }
        await flushSample(true)
        completed = true
      } finally {
        if (!completed) await source.return?.(undefined).catch(() => undefined)
        if (completed) {
          const renewedUntil = boundedExpiry(activeSession, config.installLeaseTtlSeconds)
          activeSession.expiresAt = renewedUntil
          if (!sessions.markDelivered(activeSession.sessionId)
            || !leases.markDelivered(activeSession.sessionId, renewedUntil)) {
            sessions.remove(activeSession.sessionId)
            leases.release(activeSession.sessionId)
          }
          sendTelemetry(req, activeSession, 'download.completed')
        } else {
          const renewedUntil = boundedExpiry(activeSession, config.installLeaseTtlSeconds)
          if (activeSession.state === 'cancelled' || !leases.renew(activeSession.sessionId, renewedUntil)
            || !sessions.markRecoverable(activeSession.sessionId, renewedUntil)) {
            sessions.remove(activeSession.sessionId)
            leases.release(activeSession.sessionId)
          } else {
            leases.recordEvent({ sessionId: activeSession.sessionId, entitlementId: activeSession.entitlementId,
              resourceId: activeSession.resourceId, deviceAddress: activeSession.deviceAddress, event: 'stream.interrupted' })
          }
          sendTelemetry(req, activeSession, 'download.failed')
        }
      }
    }

    reply.header('content-type', 'application/octet-stream')
    reply.header('cache-control', 'no-store, no-transform')
    reply.header('x-content-type-options', 'nosniff')
    reply.header('x-total-chunks', String(activeSession.controlContext.transportTotal))
    return reply.send(Readable.from(frames()))
  })

  app.get<{ Params: ControlParams }>('/api/session/:id', { schema: { params: paramsSchema } }, async (req, reply) => {
    const hash = controlHash(req.headers['x-session-control'])
    const session = hash ? sessions.authorizeControl(req.params.id, hash) : undefined
    if (!session) return reply.code(404).send({ error: 'not found' })
    return reply.header('cache-control', 'no-store').send({
      sessionId: session.sessionId,
      state: session.state,
      leaseExpiresAt: session.expiresAt,
      meta: session.meta,
    })
  })

  app.post<{ Params: ControlParams }>('/api/session/:id/heartbeat', { schema: { params: paramsSchema } }, async (req, reply) => {
    const hash = controlHash(req.headers['x-session-control'])
    const session = hash ? sessions.authorizeControl(req.params.id, hash) : undefined
    if (!session || !['streaming', 'recoverable', 'delivered'].includes(session.state)) return reply.code(404).send({ error: 'not found' })
    try {
      const refreshed = await consumeEntitlement({
        entitlementId: session.entitlementId,
        authorization: session.authorization,
        resourceId: session.resourceId,
        deviceAddress: session.deviceAddress,
        consumptionId: session.consumptionId,
        sessionId: session.sessionId,
        expiresAt: boundedExpiry(session as InstallSession, config.installLeaseTtlSeconds),
        phase: 'session.heartbeat',
        clientIp: (session as InstallSession).clientIp,
        clientAttributes: (session as InstallSession).clientAttributes,
      })
      ;(session as InstallSession).resourceCapability = refreshed.capability
      ;(session as InstallSession).capabilityExpiresAt = refreshed.capabilityExpiresAt
      ;(session as InstallSession).throttle = refreshed.throttle
    } catch (error) {
      req.log.warn({ err: error, sessionId: session.sessionId }, 'entitlement live-check rejected heartbeat')
      sessions.remove(session.sessionId)
      leases.release(session.sessionId)
      if (error instanceof EntitlementDecisionError) {
        await acknowledgeDecision(session.sessionId, error).catch((ackError) => req.log.warn({ err: ackError }, 'decision acknowledgement failed'))
        return decisionError(reply, error)
      }
      return reply.code(410).send({ error: '授权已撤销、过期或不再可用' })
    }
    const expiresAt = boundedExpiry(session as InstallSession, config.installLeaseTtlSeconds)
    if (expiresAt <= Date.now() || !leases.renew(session.sessionId, expiresAt)) {
      sessions.remove(session.sessionId)
      leases.release(session.sessionId)
      return reply.code(410).send({ error: '安装租约已到期' })
    }
    ;(session as InstallSession).expiresAt = expiresAt
    ;(session as InstallSession).lastHeartbeatAt = Date.now()
    return reply.header('cache-control', 'no-store').send({ ok: true, leaseExpiresAt: expiresAt })
  })

  // 关标签页的兜底释放走这里。浏览器在 pagehide 之后不保证还会发普通 fetch，唯一
  // 可靠的出口是 navigator.sendBeacon —— 而 sendBeacon 不能设置请求头，控制令牌只能
  // 放进 body。两处是同一个密钥、同一套 timingSafeEqual 校验；query string 一律不接
  // 受（会进访问日志）。beacon 只允许报失败：success=true 的判定仍要求 delivered 状态。
  app.post<{ Params: ControlParams; Body: CompleteBody }>('/api/session/:id/complete', {
    schema: {
      params: paramsSchema,
      body: {
        type: 'object', additionalProperties: false, required: ['success'],
        properties: { success: { type: 'boolean' }, detail: { type: 'string', maxLength: 500 },
          attempt: { type: 'integer', minimum: 0, maximum: 100 }, acknowledgedPart: { type: 'integer', minimum: 0 },
          control: { type: 'string', minLength: 43, maxLength: 43, pattern: '^[A-Za-z0-9_-]+$' } },
      },
    },
  }, async (req, reply) => {
    const hash = controlHash(req.headers['x-session-control']) ?? controlHash(req.body.control)
    const session = hash ? sessions.authorizeControl(req.params.id, hash) : undefined
    if (!session) return reply.code(404).send({ error: 'not found' })
    if (req.body.success && session.state !== 'delivered') {
      return reply.code(409).send({ error: '传输尚未完成，不能报告安装成功' })
    }
    leases.recordEvent({ sessionId: session.sessionId, entitlementId: session.entitlementId, resourceId: session.resourceId,
      deviceAddress: session.deviceAddress, event: req.body.success ? 'install.completed' : 'install.failed',
      detail: req.body.detail, attempt: req.body.attempt, acknowledgedPart: req.body.acknowledgedPart })
    // Track consecutive failures per device+resource so a stuck cooldown can be
    // waived on retry; a success clears the streak.
    if (req.body.success) leases.resetInstallFailure(session.deviceAddress, session.resourceId)
    else leases.recordInstallFailure(session.deviceAddress, session.resourceId)
    sendTelemetry(req, session, req.body.success ? 'install.completed' : 'install.failed')
    let cancelling = false
    if (session.state === 'created' || session.state === 'recoverable' || session.state === 'delivered') {
      sessions.remove(session.sessionId)
      leases.release(session.sessionId)
    } else if (session.state === 'cancelled') {
      return reply.header('cache-control', 'no-store').send({ ok: true, cancelling: true })
    } else if (!sessions.cancel(session.sessionId)) {
      return reply.code(409).send({ error: '会话无法取消' })
    } else cancelling = true
    req.log.info({ sessionId: session.sessionId, success: req.body.success }, 'installation lease completed')
    return reply.header('cache-control', 'no-store').send({ ok: true, cancelling })
  })

  app.post<{ Params: ControlParams; Body: EventBody }>('/api/session/:id/event', {
    schema: { params: paramsSchema, body: { type: 'object', additionalProperties: false, required: ['event'], properties: {
      event: { type: 'string', enum: ['device.disconnected', 'device.reconnect', 'device.resumed'] },
      detail: { type: 'string', maxLength: 500 }, attempt: { type: 'integer', minimum: 0, maximum: 100 },
      acknowledgedPart: { type: 'integer', minimum: 0 },
    } } },
  }, async (req, reply) => {
    const hash = controlHash(req.headers['x-session-control'])
    const session = hash ? sessions.authorizeControl(req.params.id, hash) : undefined
    if (!session) return reply.code(404).send({ error: 'not found' })
    leases.recordEvent({ sessionId: session.sessionId, entitlementId: session.entitlementId, resourceId: session.resourceId,
      deviceAddress: session.deviceAddress, event: req.body.event, detail: req.body.detail,
      attempt: req.body.attempt, acknowledgedPart: req.body.acknowledgedPart })
    return reply.header('cache-control', 'no-store').send({ ok: true })
  })

  app.get('/health', async () => ({ ok: true }))
}
