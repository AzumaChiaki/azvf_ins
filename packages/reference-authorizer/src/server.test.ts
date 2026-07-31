import assert from 'node:assert/strict'
import {
  createHash,
  createHmac,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
} from 'node:crypto'
import { after, before, it } from 'node:test'
import { jwtVerify } from 'jose'
import type { FastifyInstance } from 'fastify'
import { WIRE_PROTOCOL_VERSION } from '@azvf/contract'

const internalKey = Buffer.alloc(32, 71)
const capabilityKey = Buffer.alloc(32, 72)
const keys = generateKeyPairSync('ed25519')
let app: FastifyInstance

function signedHeaders(
  method: string,
  path: string,
  payload?: Record<string, unknown>,
  nonce = randomBytes(16).toString('base64url'),
) {
  const timestamp = String(Date.now())
  const bodyHash = payload === undefined
    ? createHash('sha256').digest('hex')
    : createHash('sha256').update(JSON.stringify(payload)).digest('hex')
  const canonical = `${timestamp}\n${nonce}\n${method}\n${path}\n${bodyHash}`
  return {
    nonce,
    headers: {
      'x-azvf-timestamp': timestamp,
      'x-azvf-nonce': nonce,
      'x-azvf-content-sha256': bodyHash,
      'x-azvf-client-id': 'installer',
      'x-azvf-key-id': 'v1',
      'x-azvf-signature': createHmac('sha256', internalKey).update(canonical).digest('base64url'),
    },
  }
}

before(async () => {
  process.env.LOG_LEVEL = 'silent'
  process.env.INTERNAL_SIGNING_KEY_B64 = internalKey.toString('base64')
  process.env.CAPABILITY_HMAC_KEY_B64 = capabilityKey.toString('base64')
  process.env.JWT_KEY_ID = 'reference-test'
  process.env.JWT_ED25519_PRIVATE_KEY = keys.privateKey
    .export({ format: 'pem', type: 'pkcs8' }).toString()
  process.env.TOKEN_ISSUER = 'reference-test'
  process.env.TOKEN_AUDIENCE = 'azvf-installer'
  const { buildServer } = await import('./server.js')
  app = await buildServer()
})

after(async () => {
  await app.close()
})

it('issues a current token and protects capability/meta/plaintext with signed internal requests', async () => {
  const deviceAddr = 'AA:BB:CC:DD:EE:01'
  const browser = await app.inject({
    method: 'POST',
    url: '/api/device/authorizations',
    payload: { deviceAddr },
  })
  assert.equal(browser.statusCode, 200, browser.body)
  const authorization = browser.json() as {
    resourceTokens: Record<string, string>
    resources: Array<{ id: string }>
  }
  const resourceId = authorization.resources[0]!.id
  const token = authorization.resourceTokens[resourceId]!
  const verified = await jwtVerify(token, createPublicKey(keys.privateKey), {
    algorithms: ['EdDSA'],
    issuer: 'reference-test',
    audience: 'azvf-installer',
  })
  assert.equal(verified.payload.clientContextVersion, 1)

  const sessionId = 'session_1234567890abcdefghijklmnop'
  const consumePath = '/internal/entitlements/reference-entitlement/consume'
  const payload = {
    authorization: token,
    resourceId,
    deviceAddr,
    consumptionId: 'reference-consumption-0001',
    sessionId,
    expiresAt: Date.now() + 60_000,
    phase: 'session.create',
  }
  const consumeSigned = signedHeaders('POST', consumePath, payload)
  const consumed = await app.inject({
    method: 'POST',
    url: consumePath,
    headers: consumeSigned.headers,
    payload,
  })
  assert.equal(consumed.statusCode, 200, consumed.body)
  const result = consumed.json() as {
    wireProtocolVersion: number
    capability: string
    signedMeta: { id: string }
  }
  assert.equal(result.wireProtocolVersion, WIRE_PROTOCOL_VERSION)
  assert.equal(result.signedMeta.id, resourceId)
  assert.match(result.capability, /^[A-Za-z0-9_-]{43}$/)

  const metaPath = `/internal/resources/${resourceId}/meta`
  const metaSigned = signedHeaders('GET', metaPath)
  const meta = await app.inject({
    method: 'GET',
    url: metaPath,
    headers: {
      ...metaSigned.headers,
      'x-azvf-resource-capability': result.capability,
      'x-azvf-session-id': sessionId,
    },
  })
  assert.equal(meta.statusCode, 200, meta.body)
  assert.equal(meta.json().id, resourceId)

  const crossSigned = signedHeaders('GET', metaPath)
  const crossSession = await app.inject({
    method: 'GET',
    url: metaPath,
    headers: {
      ...crossSigned.headers,
      'x-azvf-resource-capability': result.capability,
      'x-azvf-session-id': 'different_session_1234567890abcd',
    },
  })
  assert.equal(crossSession.statusCode, 403)

  const plaintextPath = `/internal/resources/${resourceId}/plaintext`
  const plaintextSigned = signedHeaders('GET', plaintextPath)
  const plaintext = await app.inject({
    method: 'GET',
    url: plaintextPath,
    headers: {
      ...plaintextSigned.headers,
      'x-azvf-resource-capability': result.capability,
      'x-azvf-session-id': sessionId,
    },
  })
  assert.equal(plaintext.statusCode, 200, plaintext.body)
  assert.equal(createHash('sha256').update(plaintext.rawPayload).digest('hex'),
    plaintext.headers['x-azvf-resource-sha256'])

  const replay = await app.inject({
    method: 'POST',
    url: consumePath,
    headers: consumeSigned.headers,
    payload,
  })
  assert.equal(replay.statusCode, 409)
})
