// Installer → Console authenticated client. Resource bytes are never assembled in full.
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { MAX_CHUNK_PAYLOAD, WIRE_PROTOCOL_VERSION, type SignedResourceMeta } from '@azvf/contract'

export interface InternalClientConfig {
  consoleUrl: URL
  internalSigningKey: () => Buffer
  internalClientId: string
  internalKeyId: string
  internalClockSkewMs: number
  internalRequestTimeoutMs: number
  internalStreamIdleTimeoutMs: number
  maxMetaBytes: number
  maxResourceBytes: number
}

let configuredClient: InternalClientConfig | undefined

export function configureInternalClient(value: InternalClientConfig): void {
  configuredClient = value
}

const config = new Proxy({} as InternalClientConfig, {
  get(_target, property: keyof InternalClientConfig) {
    if (!configuredClient) throw new Error('内部 Console 客户端尚未配置')
    return configuredClient[property]
  },
})

const EMPTY_SHA256 = createHash('sha256').update('').digest('hex')

export class UpstreamHttpError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message)
    this.name = 'UpstreamHttpError'
  }
}

export type AuthenticatedResourceMeta = SignedResourceMeta

interface SignedRequest {
  headers: Record<string, string>
  nonce: string
  path: string
}

function base64urlMac(canonical: string): string {
  return createHmac('sha256', config.internalSigningKey()).update(canonical).digest('base64url')
}

export function createSignedRequest(
  method: string,
  url: URL,
  body: Uint8Array = new Uint8Array(),
  timestamp = Date.now(),
  nonce = randomBytes(16).toString('base64url'),
): SignedRequest {
  const path = `${url.pathname}${url.search}`
  const bodyHash = body.length === 0 ? EMPTY_SHA256 : createHash('sha256').update(body).digest('hex')
  const canonical = `${timestamp}\n${nonce}\n${method.toUpperCase()}\n${path}\n${bodyHash}`
  return {
    nonce,
    path,
    headers: {
      'x-azvf-timestamp': String(timestamp),
      'x-azvf-nonce': nonce,
      'x-azvf-content-sha256': bodyHash,
      'x-azvf-client-id': config.internalClientId,
      'x-azvf-key-id': config.internalKeyId,
      'x-azvf-signature': base64urlMac(canonical),
    },
  }
}

function internalUrl(path: string): URL {
  return new URL(path.replace(/^\//, ''), config.consoleUrl)
}

async function readBytesLimited(response: Response, maxBytes = 65_536): Promise<Uint8Array> {
  if (!response.body) throw new Error('Console 响应缺少 body')
  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.length
      if (total > maxBytes) throw new Error('Console JSON 响应超过大小限制')
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }
  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.length
  }
  return bytes
}

async function signedFetch(
  method: string,
  url: URL,
  body?: Uint8Array,
  extraHeaders?: Record<string, string>,
  streaming = false,
): Promise<{
  response: Response
  signed: SignedRequest
  abort?: (reason?: unknown) => void
}> {
  const signed = createSignedRequest(method, url, body)
  const fetchBody = body?.length ? new Uint8Array(body).buffer : undefined
  if (!streaming) {
    const response = await fetch(url, {
      method,
      body: fetchBody,
      headers: { ...signed.headers, ...extraHeaders },
      cache: 'no-store',
      redirect: 'error',
      signal: AbortSignal.timeout(config.internalRequestTimeoutMs),
    })
    return { response, signed }
  }

  // For a large stream the ordinary timeout is only a response-header
  // timeout. Keeping one AbortSignal.timeout attached to the body would abort
  // a healthy 256MiB transfer merely because its total duration exceeded 30s.
  const controller = new AbortController()
  const headerTimer = setTimeout(() => controller.abort(new Error('Console 资源流响应头超时')),
    config.internalRequestTimeoutMs)
  try {
    const response = await fetch(url, {
      method,
      body: fetchBody,
      headers: { ...signed.headers, ...extraHeaders },
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal,
    })
    return { response, signed, abort: (reason) => controller.abort(reason) }
  } finally {
    clearTimeout(headerTimer)
  }
}

async function readStreamChunk(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  abort: (reason?: unknown) => void,
): Promise<ReadableStreamReadResult<Uint8Array>> {
  return new Promise((resolve, reject) => {
    let settled = false
    const timer = setTimeout(() => {
      if (settled) return
      settled = true
      const error = new Error('Console 资源流读取空闲超时')
      abort(error)
      reject(error)
    }, config.internalStreamIdleTimeoutMs)
    void reader.read().then((value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(value)
    }, (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      reject(error)
    })
  })
}

function upstreamStatus(status: number): number {
  return [400, 401, 403, 404, 409, 410, 422, 426, 429].includes(status) ? status : 502
}

export interface ResourceCapabilityAccess {
  capability: string
  sessionId: string
}

function capabilityHeaders(access: ResourceCapabilityAccess): Record<string, string> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(access.capability)
    || !/^[A-Za-z0-9_-]{32,64}$/.test(access.sessionId)) {
    throw new Error('资源 capability 访问上下文无效')
  }
  return {
    'x-azvf-resource-capability': access.capability,
    'x-azvf-session-id': access.sessionId,
  }
}

export async function fetchMeta(
  resourceId: string,
  access: ResourceCapabilityAccess,
): Promise<AuthenticatedResourceMeta> {
  const url = internalUrl(`internal/resources/${encodeURIComponent(resourceId)}/meta`)
  const { response, signed } = await signedFetch('GET', url, undefined, capabilityHeaders(access))
  if (!response.ok) throw new UpstreamHttpError(upstreamStatus(response.status), '无法获取资源元数据')
  const body = await readBytesLimited(response, config.maxMetaBytes)
  verifyMetaResponse(response, signed, body)
  const meta = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body)) as AuthenticatedResourceMeta
  if (!meta || typeof meta !== 'object' || typeof meta.sha256 !== 'string' || !Number.isSafeInteger(meta.size)) {
    throw new Error('Console 资源元数据响应无效')
  }
  return meta
}

function verifyMetaResponse(response: Response, signed: SignedRequest, body: Uint8Array): void {
  const digest = response.headers.get('x-azvf-meta-sha256')?.toLowerCase()
  const sizeText = response.headers.get('x-azvf-meta-size')
  const timestampText = response.headers.get('x-azvf-meta-timestamp')
  const signature = response.headers.get('x-azvf-meta-signature')
  if (!digest || !/^[a-f0-9]{64}$/.test(digest) || !sizeText || !timestampText || !signature) {
    throw new Error('Console 元数据响应缺少认证头')
  }
  if (!/^\d{1,8}$/.test(sizeText) || Number(sizeText) !== body.length) throw new Error('Console 元数据响应大小认证失败')
  if (createHash('sha256').update(body).digest('hex') !== digest) throw new Error('Console 元数据响应摘要认证失败')
  if (!/^\d{13}$/.test(timestampText) || Math.abs(Date.now() - Number(timestampText)) > config.internalClockSkewMs) {
    throw new Error('Console 元数据响应时间戳无效')
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(signature)) throw new Error('Console 元数据响应签名格式无效')
  const canonical = `${signed.nonce}\n${response.status}\n${signed.path}\n${digest}\n${sizeText}\n${timestampText}`
  const expectedSignature = Buffer.from(base64urlMac(canonical), 'ascii')
  const receivedSignature = Buffer.from(signature, 'ascii')
  if (expectedSignature.length !== receivedSignature.length || !timingSafeEqual(expectedSignature, receivedSignature)) {
    throw new Error('Console 元数据响应签名无效')
  }
}

function verifyJsonResponse(response: Response, signed: SignedRequest, body: Uint8Array): void {
  const digest = response.headers.get('x-azvf-json-sha256')?.toLowerCase()
  const sizeText = response.headers.get('x-azvf-json-size')
  const timestampText = response.headers.get('x-azvf-json-timestamp')
  const signature = response.headers.get('x-azvf-json-signature')
  if (!digest || !/^[a-f0-9]{64}$/.test(digest) || !sizeText || !timestampText || !signature) {
    throw new Error('Console JSON 响应缺少认证头')
  }
  if (!/^\d{1,8}$/.test(sizeText) || Number(sizeText) !== body.length) throw new Error('Console JSON 响应大小认证失败')
  if (createHash('sha256').update(body).digest('hex') !== digest) throw new Error('Console JSON 响应摘要认证失败')
  if (!/^\d{13}$/.test(timestampText) || Math.abs(Date.now() - Number(timestampText)) > config.internalClockSkewMs) {
    throw new Error('Console JSON 响应时间戳无效')
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(signature)) throw new Error('Console JSON 响应签名格式无效')
  const canonical = `${signed.nonce}\n${response.status}\n${signed.path}\n${digest}\n${sizeText}\n${timestampText}`
  const expectedSignature = Buffer.from(base64urlMac(canonical), 'ascii')
  const receivedSignature = Buffer.from(signature, 'ascii')
  if (expectedSignature.length !== receivedSignature.length || !timingSafeEqual(expectedSignature, receivedSignature)) {
    throw new Error('Console JSON 响应签名无效')
  }
}

function verifyResourceResponse(
  response: Response,
  signed: SignedRequest,
  expectedSha256: string,
  expectedSize: number,
): void {
  const digest = response.headers.get('x-azvf-resource-sha256')?.toLowerCase()
  const sizeText = response.headers.get('x-azvf-resource-size')
  const timestampText = response.headers.get('x-azvf-response-timestamp')
  const signature = response.headers.get('x-azvf-response-signature')
  if (!digest || !/^[a-f0-9]{64}$/.test(digest) || !sizeText || !timestampText || !signature) {
    throw new Error('Console 资源响应缺少认证头')
  }
  if (!/^\d{1,16}$/.test(sizeText) || Number(sizeText) !== expectedSize || digest !== expectedSha256.toLowerCase()) {
    throw new Error('Console 资源响应与签名元数据不匹配')
  }
  if (!/^\d{13}$/.test(timestampText) || Math.abs(Date.now() - Number(timestampText)) > config.internalClockSkewMs) {
    throw new Error('Console 资源响应时间戳无效')
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(signature)) throw new Error('Console 资源响应签名格式无效')
  const canonical = `${signed.nonce}\n${response.status}\n${signed.path}\n${digest}\n${sizeText}\n${timestampText}`
  const expectedSignature = Buffer.from(base64urlMac(canonical), 'ascii')
  const receivedSignature = Buffer.from(signature, 'ascii')
  if (expectedSignature.length !== receivedSignature.length || !timingSafeEqual(expectedSignature, receivedSignature)) {
    throw new Error('Console 资源响应签名无效')
  }
  const contentLength = response.headers.get('content-length')
  if (contentLength && (!/^\d+$/.test(contentLength) || Number(contentLength) !== expectedSize)) {
    throw new Error('Console Content-Length 与资源元数据不匹配')
  }
  const contentEncoding = response.headers.get('content-encoding')
  if (contentEncoding && contentEncoding !== 'identity') throw new Error('资源流禁止内容编码转换')
}

/**
 * Pulls authenticated plaintext into a single fixed-size buffer and yields it immediately.
 * Memory is O(chunkSize); the complete resource is never retained by Installer.
 */
export async function* fetchPlaintextChunks(
  resourceId: string,
  expected: SignedResourceMeta,
  access: ResourceCapabilityAccess,
): AsyncGenerator<Uint8Array> {
  if (!Number.isSafeInteger(expected.size) || expected.size < 1 || expected.size > config.maxResourceBytes) {
    throw new Error('资源大小超出 Installer 限制')
  }
  if (!Number.isSafeInteger(expected.chunkSize) || expected.chunkSize < 16_384 || expected.chunkSize > MAX_CHUNK_PAYLOAD) {
    throw new Error('资源分片大小无效')
  }
  if (expected.totalChunks !== Math.ceil(expected.size / expected.chunkSize)) throw new Error('资源分片元数据不一致')
  if (!/^[a-fA-F0-9]{64}$/.test(expected.sha256)) throw new Error('资源 SHA-256 元数据无效')
  if (expected.formatVersion !== 2 || !expected.chunkSha256 || expected.chunkSha256.length !== expected.totalChunks
    || expected.chunkSha256.some((digest) => !/^[a-f0-9]{64}$/.test(digest))) {
    throw new Error('资源缺少已认证的 v2 逐片摘要')
  }

  const url = internalUrl(`internal/resources/${encodeURIComponent(resourceId)}/plaintext`)
  const { response, signed, abort } = await signedFetch(
    'GET',
    url,
    undefined,
    capabilityHeaders(access),
    true,
  )
  let reader: ReadableStreamDefaultReader<Uint8Array> | undefined
  const hash = createHash('sha256')
  let output = new Uint8Array(expected.chunkSize)
  let outputLength = 0
  let total = 0
  let chunks = 0
  let finished = false
  try {
    if (!response.ok) throw new UpstreamHttpError(upstreamStatus(response.status), '无法获取资源内容')
    verifyResourceResponse(response, signed, expected.sha256, expected.size)
    if (!response.body || !abort) throw new Error('Console 资源响应缺少流')
    reader = response.body.getReader()
    while (true) {
      const { done, value } = await readStreamChunk(reader, abort)
      if (done) break
      if (total + value.length > expected.size) throw new Error('Console 资源流超过声明大小')
      hash.update(value)
      total += value.length
      let sourceOffset = 0
      while (sourceOffset < value.length) {
        const copied = Math.min(output.length - outputLength, value.length - sourceOffset)
        output.set(value.subarray(sourceOffset, sourceOffset + copied), outputLength)
        outputLength += copied
        sourceOffset += copied
        if (outputLength === output.length) {
          if (createHash('sha256').update(output).digest('hex') !== expected.chunkSha256[chunks]) {
            throw new Error(`Console 资源流分片 ${chunks} SHA-256 校验失败`)
          }
          chunks++
          yield output
          output = new Uint8Array(expected.chunkSize)
          outputLength = 0
        }
      }
    }
    if (outputLength > 0) {
      const finalChunk = output.subarray(0, outputLength)
      if (createHash('sha256').update(finalChunk).digest('hex') !== expected.chunkSha256[chunks]) {
        throw new Error(`Console 资源流分片 ${chunks} SHA-256 校验失败`)
      }
      chunks++
      yield finalChunk
    }
    if (total !== expected.size || chunks !== expected.totalChunks) throw new Error('Console 资源流提前结束')
    if (hash.digest('hex') !== expected.sha256.toLowerCase()) throw new Error('Console 资源流 SHA-256 校验失败')
    finished = true
  } finally {
    if (!finished) {
      abort?.(new Error('Console 资源流未完成'))
      await reader?.cancel().catch(() => undefined)
    }
    reader?.releaseLock()
  }
}

export type InstallationTelemetryEvent =
  | 'download.started'
  | 'download.completed'
  | 'download.failed'
  | 'install.started'
  | 'install.completed'
  | 'install.failed'

const INSTALLATION_EVENTS: ReadonlySet<string> = new Set<InstallationTelemetryEvent>([
  'download.started',
  'download.completed',
  'download.failed',
  'install.started',
  'install.completed',
  'install.failed',
])

/** Sends minimal, signed lifecycle telemetry. No client IP or error detail is included. */
export async function reportInstallationEvent(input: {
  sessionId: string
  resourceId: string
  deviceAddress: string
  event: InstallationTelemetryEvent
  region: string
}): Promise<void> {
  if (!/^[A-Za-z0-9_-]{32,64}$/.test(input.sessionId)
    || !/^[A-Za-z0-9_-]{1,128}$/.test(input.resourceId)
    || !/^[A-Za-z0-9+/=_:-]{8,64}$/.test(input.deviceAddress)
    || !INSTALLATION_EVENTS.has(input.event)
    || (input.region !== 'UNKNOWN' && !/^[A-Z0-9][A-Z0-9-]{0,6}[A-Z0-9]$/.test(input.region))) {
    throw new Error('安装遥测字段无效')
  }
  const url = internalUrl('internal/installations/events')
  const body = new TextEncoder().encode(JSON.stringify({
    sessionId: input.sessionId,
    resourceId: input.resourceId,
    deviceAddr: input.deviceAddress,
    event: input.event,
    region: input.region,
  }))
  const { response, signed } = await signedFetch('POST', url, body, { 'content-type': 'application/json' })
  if (!response.ok) throw new UpstreamHttpError(upstreamStatus(response.status), '安装遥测上报失败')
  const responseBody = await readBytesLimited(response, 8_192)
  verifyJsonResponse(response, signed, responseBody)
  const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(responseBody)) as Record<string, unknown>
  if (!parsed || parsed.ok !== true) throw new Error('Console 安装遥测响应无效')
}

export type EntitlementConsumePhase =
  | 'session.create'
  | 'stream.open'
  | 'stream.renew'
  | 'session.heartbeat'

export interface EntitlementConsumption {
  capability: string
  capabilityExpiresAt: number
  signedMeta: AuthenticatedResourceMeta
  idempotent: boolean
  installsUsed: number
  maxInstalls?: number
}

export async function consumeEntitlement(input: {
  entitlementId: string
  authorization: string
  resourceId: string
  deviceAddress: string
  consumptionId: string
  sessionId: string
  expiresAt: number
  phase: EntitlementConsumePhase
}): Promise<EntitlementConsumption> {
  const url = internalUrl(`internal/entitlements/${encodeURIComponent(input.entitlementId)}/consume`)
  const body = new TextEncoder().encode(JSON.stringify({
    authorization: input.authorization,
    resourceId: input.resourceId,
    deviceAddr: input.deviceAddress,
    consumptionId: input.consumptionId,
    sessionId: input.sessionId,
    expiresAt: input.expiresAt,
    phase: input.phase,
  }))
  const { response, signed } = await signedFetch('POST', url, body, { 'content-type': 'application/json' })
  if (!response.ok) throw new UpstreamHttpError(upstreamStatus(response.status), '授权安装额度核销失败')
  const responseBody = await readBytesLimited(response)
  verifyJsonResponse(response, signed, responseBody)
  const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(responseBody)) as Record<string, unknown>
  if (!parsed || parsed.ok !== true) throw new Error('Console 安装额度核销响应无效')
  if (parsed.wireProtocolVersion !== WIRE_PROTOCOL_VERSION) {
    throw new Error(`Console 线协议版本不兼容：期望 ${WIRE_PROTOCOL_VERSION}，实际 ${String(parsed.wireProtocolVersion)}`)
  }
  if (typeof parsed.capability !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(parsed.capability)
    || !Number.isSafeInteger(parsed.capabilityExpiresAt) || Number(parsed.capabilityExpiresAt) <= Date.now()
    || !parsed.signedMeta || typeof parsed.signedMeta !== 'object'
    || typeof (parsed.signedMeta as Record<string, unknown>).id !== 'string'
    || !Number.isSafeInteger(parsed.installsUsed) || Number(parsed.installsUsed) < 0
    || typeof parsed.idempotent !== 'boolean') {
    throw new Error('Console capability 核销响应无效')
  }
  return {
    capability: parsed.capability,
    capabilityExpiresAt: Number(parsed.capabilityExpiresAt),
    signedMeta: parsed.signedMeta as unknown as AuthenticatedResourceMeta,
    idempotent: parsed.idempotent,
    installsUsed: Number(parsed.installsUsed),
    ...(Number.isSafeInteger(parsed.maxInstalls) ? { maxInstalls: Number(parsed.maxInstalls) } : {}),
  }
}
