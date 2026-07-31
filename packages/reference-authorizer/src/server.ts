import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  timingSafeEqual,
} from 'node:crypto'
import { pathToFileURL } from 'node:url'
import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest,
  type preHandlerHookHandler,
} from 'fastify'
import { SignJWT, jwtVerify } from 'jose'
import {
  DEFAULT_CHUNK_SIZE,
  DEFAULT_TOKEN_AUDIENCE,
  DEFAULT_TOKEN_ISSUER,
  SUPPORTED_CLIENT_CONTEXT_VERSION,
  WIRE_PROTOCOL_VERSION,
  canonicalResourceManifestV2,
  normalizeDeviceIdentifier,
  type ResourceMeta,
  type SignedResourceMeta,
} from '@azvf/contract'

const RESOURCE_ID = 'reference-resource'
const ENTITLEMENT_ID = 'reference-entitlement'
const RESOURCE_BYTES = Buffer.from('AZVF reference authorizer resource\n', 'utf8')
const EMPTY_SHA256 = createHash('sha256').digest('hex')
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22}$/
const CAPABILITY_PATTERN = /^[A-Za-z0-9_-]{43}$/
const SESSION_PATTERN = /^[A-Za-z0-9_-]{32,64}$/

function required(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`Missing ${name}`)
  return value
}

function integer(name: string, fallback: number, minimum: number, maximum: number): number {
  const raw = process.env[name]?.trim()
  const value = raw ? Number(raw) : fallback
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer in ${minimum}..${maximum}`)
  }
  return value
}

function key32(name: string): Buffer {
  const value = Buffer.from(required(name), 'base64')
  if (value.length !== 32) throw new Error(`${name} must decode to 32 bytes`)
  return value
}

function privateKey() {
  return createPrivateKey(required('JWT_ED25519_PRIVATE_KEY').replaceAll('\\n', '\n'))
}

function internalKey(): Buffer {
  return key32('INTERNAL_SIGNING_KEY_B64')
}

function capabilityKey(): Buffer {
  return key32('CAPABILITY_HMAC_KEY_B64')
}

const tokenIssuer = () => process.env.TOKEN_ISSUER?.trim() || DEFAULT_TOKEN_ISSUER
const tokenAudience = () => process.env.TOKEN_AUDIENCE?.trim() || DEFAULT_TOKEN_AUDIENCE
const tokenKeyId = () => process.env.JWT_KEY_ID?.trim() || 'reference-v1'
const internalClientId = () => process.env.INTERNAL_CLIENT_ID?.trim() || 'installer'
const internalKeyId = () => process.env.INTERNAL_KEY_ID?.trim() || 'v1'

interface AuthenticatedRequest extends FastifyRequest {
  internalNonce?: string
  internalClientId?: string
}

interface CapabilityBinding {
  clientId: string
  sessionId: string
  resourceId: string
  expiresAt: number
}

function safeEqual(expected: Buffer, supplied: string): boolean {
  try {
    const actual = Buffer.from(supplied, 'base64url')
    return actual.length === expected.length && timingSafeEqual(actual, expected)
  } catch {
    return false
  }
}

function capabilityHash(value: string): string {
  return createHmac('sha256', capabilityKey())
    .update('capability-digest-v1\0', 'utf8')
    .update(value, 'ascii')
    .digest('base64url')
}

function jsonBody(request: FastifyRequest): Buffer {
  return Buffer.from(JSON.stringify(request.body ?? {}))
}

function responseSignature(
  request: AuthenticatedRequest,
  status: number,
  digest: string,
  size: number,
  timestamp: string,
): string {
  const nonce = request.internalNonce
  if (!nonce) throw new Error('Authenticated response is missing its request nonce')
  const path = new URL(request.url, 'http://reference.invalid').pathname
  return createHmac('sha256', internalKey())
    .update(`${nonce}\n${status}\n${path}\n${digest}\n${size}\n${timestamp}`)
    .digest('base64url')
}

function sendSignedJson(
  request: AuthenticatedRequest,
  reply: FastifyReply,
  status: number,
  value: unknown,
) {
  const body = Buffer.from(JSON.stringify(value))
  const digest = createHash('sha256').update(body).digest('hex')
  const timestamp = String(Date.now())
  reply.headers({
    'x-azvf-json-sha256': digest,
    'x-azvf-json-size': String(body.length),
    'x-azvf-json-timestamp': timestamp,
    'x-azvf-json-signature': responseSignature(request, status, digest, body.length, timestamp),
    'content-type': 'application/json; charset=utf-8',
  })
  return reply.code(status).send(body)
}

function signedMeta(): SignedResourceMeta {
  const chunkHash = createHash('sha256').update(RESOURCE_BYTES).digest('hex')
  const base: ResourceMeta = {
    id: RESOURCE_ID,
    name: 'Reference resource',
    resType: 32,
    packageName: 'org.azvf.reference',
    size: RESOURCE_BYTES.length,
    sha256: chunkHash,
    md5: createHash('md5').update(RESOURCE_BYTES).digest('hex'),
    watchfaceId: null,
    version: '1.0.0',
    chunkSize: DEFAULT_CHUNK_SIZE,
    totalChunks: 1,
  }
  const manifestHash = createHash('sha256')
    .update(canonicalResourceManifestV2(base, [chunkHash]))
    .digest('hex')
  return {
    ...base,
    formatVersion: 2,
    chunkSha256: [chunkHash],
    manifestHash,
    manifestSignature: sign(null, Buffer.from(manifestHash, 'hex'), privateKey()).toString('base64url'),
    manifestKeyId: tokenKeyId(),
  }
}

async function issueAuthorization(deviceAddr: string): Promise<string> {
  const now = Math.floor(Date.now() / 1_000)
  return new SignJWT({
    resourceIds: [RESOURCE_ID],
    entitlementId: ENTITLEMENT_ID,
    deviceAddr,
    tier: 'basic',
    installConcurrency: 1,
    clientContextVersion: SUPPORTED_CLIENT_CONTEXT_VERSION,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: tokenKeyId() })
    .setIssuer(tokenIssuer())
    .setAudience(tokenAudience())
    .setSubject(`device:${deviceAddr}`)
    .setJti(randomBytes(18).toString('base64url'))
    .setIssuedAt(now)
    .setExpirationTime(now + 600)
    .sign(privateKey())
}

export async function buildServer(): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL ?? 'info',
      redact: [
        'req.headers.authorization',
        'req.headers.cookie',
        'req.headers.x-azvf-resource-capability',
        'req.body.authorization',
      ],
    },
    bodyLimit: 32_768,
  })
  const nonces = new Map<string, number>()
  const capabilities = new Map<string, CapabilityBinding>()

  const requireInternal: preHandlerHookHandler = async (request, reply) => {
    const timestampText = request.headers['x-azvf-timestamp']
    const nonce = request.headers['x-azvf-nonce']
    const bodyHash = request.headers['x-azvf-content-sha256']
    const clientId = request.headers['x-azvf-client-id']
    const keyId = request.headers['x-azvf-key-id']
    const supplied = request.headers['x-azvf-signature']
    const timestamp = Number(timestampText)
    if (typeof timestampText !== 'string' || !Number.isSafeInteger(timestamp)
      || Math.abs(Date.now() - timestamp) > 30_000
      || typeof nonce !== 'string' || !NONCE_PATTERN.test(nonce)
      || typeof bodyHash !== 'string'
      || clientId !== internalClientId()
      || keyId !== internalKeyId()
      || typeof supplied !== 'string') {
      return reply.code(401).send({ error: 'internal_authentication_failed' })
    }
    const now = Date.now()
    for (const [seen, expiresAt] of nonces) if (expiresAt <= now) nonces.delete(seen)
    if (nonces.has(nonce)) return reply.code(409).send({ error: 'internal_replay_detected' })
    const actualBodyHash = ['GET', 'HEAD'].includes(request.method)
      ? EMPTY_SHA256
      : createHash('sha256').update(jsonBody(request)).digest('hex')
    const path = new URL(request.url, 'http://reference.invalid')
    const canonical = `${timestampText}\n${nonce}\n${request.method}\n${path.pathname}${path.search}\n${actualBodyHash}`
    const expected = createHmac('sha256', internalKey()).update(canonical).digest()
    if (bodyHash !== actualBodyHash || !safeEqual(expected, supplied)) {
      return reply.code(401).send({ error: 'internal_authentication_failed' })
    }
    nonces.set(nonce, now + 30_000)
    const authenticated = request as AuthenticatedRequest
    authenticated.internalNonce = nonce
    authenticated.internalClientId = clientId
  }

  function binding(request: AuthenticatedRequest, resourceId: string): CapabilityBinding | undefined {
    const capability = request.headers['x-azvf-resource-capability']
    const sessionId = request.headers['x-azvf-session-id']
    if (typeof capability !== 'string' || !CAPABILITY_PATTERN.test(capability)
      || typeof sessionId !== 'string' || !SESSION_PATTERN.test(sessionId)) return undefined
    const result = capabilities.get(capabilityHash(capability))
    return result
      && result.clientId === request.internalClientId
      && result.sessionId === sessionId
      && result.resourceId === resourceId
      && result.expiresAt > Date.now()
      ? result
      : undefined
  }

  app.get('/health', async () => ({ ok: true, referenceOnly: true }))

  app.post<{ Body: { deviceAddr: string } }>('/api/device/authorizations', async (request, reply) => {
    let deviceAddr: string
    try {
      deviceAddr = normalizeDeviceIdentifier(request.body?.deviceAddr)
    } catch {
      return reply.code(400).send({ error: 'invalid_device_identifier' })
    }
    const token = await issueAuthorization(deviceAddr)
    return reply.header('cache-control', 'no-store').send({
      resourceTokens: { [RESOURCE_ID]: token },
      resources: [{
        id: RESOURCE_ID,
        name: 'Reference resource',
        version: '1.0.0',
        resType: 32,
        size: RESOURCE_BYTES.length,
      }],
      policies: [{ name: 'Reference policy', expiresAt: null, resourceIds: [RESOURCE_ID] }],
      selectedResourceId: RESOURCE_ID,
    })
  })

  app.post<{ Params: { id: string }; Body: {
    authorization: string
    resourceId: string
    deviceAddr: string
    consumptionId: string
    sessionId: string
    expiresAt: number
  } }>('/internal/entitlements/:id/consume', { preHandler: requireInternal }, async (request, reply) => {
    try {
      const publicKey = createPublicKey(privateKey())
      const { payload } = await jwtVerify(request.body.authorization, publicKey, {
        algorithms: ['EdDSA'],
        issuer: tokenIssuer(),
        audience: tokenAudience(),
        requiredClaims: ['sub', 'jti', 'iat', 'exp'],
        maxTokenAge: 600,
        clockTolerance: 5,
      })
      const deviceAddr = normalizeDeviceIdentifier(request.body.deviceAddr)
      if (request.params.id !== ENTITLEMENT_ID
        || request.body.resourceId !== RESOURCE_ID
        || payload.entitlementId !== ENTITLEMENT_ID
        || payload.deviceAddr !== deviceAddr
        || payload.clientContextVersion !== SUPPORTED_CLIENT_CONTEXT_VERSION
        || !Array.isArray(payload.resourceIds)
        || !payload.resourceIds.includes(RESOURCE_ID)
        || !SESSION_PATTERN.test(request.body.sessionId)) {
        throw new Error('authorization mismatch')
      }
      const expiresAt = Math.min(request.body.expiresAt, Number(payload.exp) * 1_000)
      if (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now()) throw new Error('capability expiry')
      const capability = randomBytes(32).toString('base64url')
      capabilities.set(capabilityHash(capability), {
        clientId: (request as AuthenticatedRequest).internalClientId!,
        sessionId: request.body.sessionId,
        resourceId: RESOURCE_ID,
        expiresAt,
      })
      return sendSignedJson(request as AuthenticatedRequest, reply, 200, {
        ok: true,
        wireProtocolVersion: WIRE_PROTOCOL_VERSION,
        capability,
        capabilityExpiresAt: expiresAt,
        signedMeta: signedMeta(),
        idempotent: false,
        installsUsed: 1,
        maxInstalls: 1,
      })
    } catch {
      return sendSignedJson(request as AuthenticatedRequest, reply, 403, {
        error: 'entitlement_unavailable',
      })
    }
  })

  app.get<{ Params: { id: string } }>('/internal/resources/:id/meta', {
    preHandler: requireInternal,
  }, async (request, reply) => {
    if (request.params.id !== RESOURCE_ID
      || !binding(request as AuthenticatedRequest, request.params.id)) {
      return reply.code(403).send({ error: 'resource_capability_invalid' })
    }
    const body = Buffer.from(JSON.stringify(signedMeta()))
    const digest = createHash('sha256').update(body).digest('hex')
    const timestamp = String(Date.now())
    reply.headers({
      'x-azvf-meta-sha256': digest,
      'x-azvf-meta-size': String(body.length),
      'x-azvf-meta-timestamp': timestamp,
      'x-azvf-meta-signature': responseSignature(
        request as AuthenticatedRequest,
        200,
        digest,
        body.length,
        timestamp,
      ),
      'content-type': 'application/json; charset=utf-8',
    })
    return reply.send(body)
  })

  app.get<{ Params: { id: string } }>('/internal/resources/:id/plaintext', {
    preHandler: requireInternal,
  }, async (request, reply) => {
    if (request.params.id !== RESOURCE_ID
      || !binding(request as AuthenticatedRequest, request.params.id)) {
      return reply.code(403).send({ error: 'resource_capability_invalid' })
    }
    const digest = createHash('sha256').update(RESOURCE_BYTES).digest('hex')
    const timestamp = String(Date.now())
    reply.headers({
      'x-azvf-resource-sha256': digest,
      'x-azvf-resource-size': String(RESOURCE_BYTES.length),
      'x-azvf-response-timestamp': timestamp,
      'x-azvf-response-signature': responseSignature(
        request as AuthenticatedRequest,
        200,
        digest,
        RESOURCE_BYTES.length,
        timestamp,
      ),
      'content-type': 'application/octet-stream',
      'content-length': String(RESOURCE_BYTES.length),
      'cache-control': 'no-store',
    })
    return reply.send(RESOURCE_BYTES)
  })

  app.post('/internal/installations/events', { preHandler: requireInternal }, async (request, reply) => {
    return sendSignedJson(request as AuthenticatedRequest, reply, 200, { ok: true })
  })

  return app
}

async function main(): Promise<void> {
  const app = await buildServer()
  const port = integer('PORT', 4101, 1, 65_535)
  const host = process.env.HOST?.trim() || '127.0.0.1'
  await app.listen({ host, port })
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error)
    process.exitCode = 1
  })
}
