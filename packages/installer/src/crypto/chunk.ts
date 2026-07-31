// AZVF authenticated transport frames, protocol v2.
//
// Public frame layout (big endian):
//   magic[4]="AZVF"
//   version[1]=2
//   suite[1]
//   reserved[2]=0
//   serverEpoch[4]
//   transportSeq[4]
//   transportTotal[4]
//   nonce[16]                 // GCM uses the first 12 bytes; the rest must be zero
//   ciphertextLength[4]
//   ciphertext[ciphertextLength]
//   authenticationTag[16|32] // GCM tag or HMAC-SHA-256
//
// The authenticated additional data is the complete public header followed by
// a canonical, length-prefixed session/resource/version/device context. The
// real/decoy marker and real installation sequence are inside the ciphertext.
// There is no plaintext mode in v2.
import { DEFAULT_CHUNK_SIZE, MAX_CHUNK_PAYLOAD } from '@azvf/contract'
import type { SessionCryptoKeys } from './keys.js'

const subtle = globalThis.crypto.subtle
const textEncoder = new TextEncoder()

export const MAGIC = new Uint8Array([0x41, 0x5a, 0x56, 0x46]) // "AZVF"
export const VERSION = 2
export const NONCE_LEN = 16
export const GCM_NONCE_LEN = 12
export const GCM_TAG_LEN = 16
export const HMAC_TAG_LEN = 32
export const HEADER_LEN = 40
export const MAX_TRANSPORT_CHUNKS = 1_000_000

const UINT32_MAX = 0xffff_ffff
const MAX_CONTEXT_FIELD_BYTES = 4096
const INNER_HEADER_LEN = 20
const CONTROL_TAG_LEN = 32
const MIN_CIPHERTEXT_LEN = INNER_HEADER_LEN + CONTROL_TAG_LEN
const MAX_CIPHERTEXT_LEN = INNER_HEADER_LEN + MAX_CHUNK_PAYLOAD + CONTROL_TAG_LEN
const INNER_MAGIC = new Uint8Array([0x41, 0x5a, 0x50, 0x32]) // "AZP2", encrypted
const AAD_PREFIX = textEncoder.encode('AZVF/v2/aad\0')
const SELECTION_PREFIX = textEncoder.encode('AZVF/v2/select\0')
const CONTROL_PREFIX = textEncoder.encode('AZVF/v2/control\0')
const FRAME_MAC_PREFIX = textEncoder.encode('AZVF/v2/frame-mac\0')
const SESSION_CONTROL_PREFIX = textEncoder.encode('AZVF/v2/session-control\0')

export type ChunkCipherSuite = 'AES-256-GCM' | 'AES-256-CTR-HMAC-SHA256'
export type ChunkPayloadKind = 'real' | 'decoy'

const SUITE_TO_ID: Record<ChunkCipherSuite, number> = {
  'AES-256-GCM': 1,
  'AES-256-CTR-HMAC-SHA256': 2,
}

const ID_TO_SUITE: Readonly<Record<number, ChunkCipherSuite>> = {
  1: 'AES-256-GCM',
  2: 'AES-256-CTR-HMAC-SHA256',
}

export interface ChunkCryptoContext {
  sessionId: string
  resourceId: string
  resourceVersion: string
  /** Ed25519-verified v2 resource manifest SHA-256 (lowercase hex). */
  manifestHash: string
  deviceId: string
  /** Unsigned 32-bit server epoch, normally Unix time in seconds. */
  serverEpoch: number
}

/** Authenticated SessionInit context, verified after unwrapping the master key. */
export interface SessionControlContext extends ChunkCryptoContext {
  transportTotal: number
  realTotal: number
  /** Authenticated fixed plaintext area for every real and decoy frame. */
  padTo: number
  /** Optional per-session watchface rewrite, bound by the control HMAC. */
  watchfaceTransform?: import('@azvf/contract').WatchfaceInstallTransform
}

export interface EncryptChunkV2Input {
  transportSeq: number
  transportTotal: number
  kind: ChunkPayloadKind
  data: Uint8Array
  /** Fixed padded data area. Defaults to DEFAULT_CHUNK_SIZE. */
  padTo?: number
  /** Required for real payloads and forbidden for decoys. */
  realSeq?: number
  /** Required for real payloads and forbidden for decoys. */
  realTotal?: number
}

export interface ParsedChunkHeaderV2 {
  suite: ChunkCipherSuite
  serverEpoch: number
  transportSeq: number
  transportTotal: number
  nonce: Uint8Array
  ciphertextLength: number
  authenticationTagLength: number
  frameLength: number
}

export interface DecryptedChunkV2 {
  suite: ChunkCipherSuite
  transportSeq: number
  transportTotal: number
  kind: ChunkPayloadKind
  data: Uint8Array
  realSeq?: number
  realTotal?: number
  /** True only for authenticated real payloads. */
  shouldInstall: boolean
  /** True after this frame closes a complete, strictly ordered stream. */
  streamComplete: boolean
  frameLength: number
}

export interface ChunkSequenceState {
  nextTransportSeq: number
  transportTotal: number | null
  nextRealSeq: number
  realTotal: number | null
  ciphertextLength: number | null
  complete: boolean
}

export function createChunkSequenceState(): ChunkSequenceState {
  return {
    nextTransportSeq: 0,
    transportTotal: null,
    nextRealSeq: 0,
    realTotal: null,
    ciphertextLength: null,
    complete: false,
  }
}

/** Assert that a stream ended with both authenticated sequences complete. */
export function finalizeChunkSequenceState(state: ChunkSequenceState): void {
  if (!state.complete) throw new Error('chunk stream is incomplete')
  if (state.transportTotal === null || state.nextTransportSeq !== state.transportTotal) {
    throw new Error('transport chunk sequence is incomplete')
  }
  if (state.realTotal === null || state.nextRealSeq !== state.realTotal) {
    throw new Error('real chunk sequence is incomplete')
  }
  if (state.ciphertextLength === null) throw new Error('chunk stream has no authenticated frame length')
}

function assertU32(name: string, value: number, allowMax = true): void {
  const max = allowMax ? UINT32_MAX : UINT32_MAX - 1
  if (!Number.isSafeInteger(value) || value < 0 || value > max) {
    throw new Error(`${name} must be an unsigned 32-bit integer`)
  }
}

function assertTransportPosition(seq: number, total: number): void {
  assertU32('transportSeq', seq, false)
  assertU32('transportTotal', total, false)
  if (total < 1 || total > MAX_TRANSPORT_CHUNKS) throw new Error('transportTotal is outside the supported range')
  if (seq >= total) throw new Error('transportSeq must be less than transportTotal')
}

function writeU32BE(target: Uint8Array, offset: number, value: number): void {
  new DataView(target.buffer, target.byteOffset, target.byteLength).setUint32(offset, value, false)
}

function u32be(value: number): Uint8Array {
  const out = new Uint8Array(4)
  writeU32BE(out, 0, value)
  return out
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  let length = 0
  for (const part of parts) {
    length += part.length
    if (!Number.isSafeInteger(length)) throw new Error('byte sequence is too large')
  }
  const out = new Uint8Array(length)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

function encodeContextField(name: string, value: string): Uint8Array {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${name} must not be empty`)
  const encoded = textEncoder.encode(value)
  if (encoded.length > MAX_CONTEXT_FIELD_BYTES) throw new Error(`${name} is too long`)
  return concatBytes([u32be(encoded.length), encoded])
}

function validateContext(context: ChunkCryptoContext): void {
  assertU32('serverEpoch', context.serverEpoch)
  encodeContextField('sessionId', context.sessionId)
  encodeContextField('resourceId', context.resourceId)
  encodeContextField('resourceVersion', context.resourceVersion)
  if (!/^[a-f0-9]{64}$/.test(context.manifestHash)) throw new Error('manifestHash must be lowercase SHA-256 hex')
  encodeContextField('deviceId', context.deviceId)
}

function encodeAad(header: Uint8Array, context: ChunkCryptoContext): Uint8Array {
  if (header.length !== HEADER_LEN) throw new Error('invalid v2 frame header length')
  return concatBytes([
    AAD_PREFIX,
    header,
    encodeContextField('sessionId', context.sessionId),
    encodeContextField('resourceId', context.resourceId),
    encodeContextField('resourceVersion', context.resourceVersion),
    encodeContextField('manifestHash', context.manifestHash),
    encodeContextField('deviceId', context.deviceId),
  ])
}

function selectionInput(context: ChunkCryptoContext, transportSeq: number): Uint8Array {
  return concatBytes([
    SELECTION_PREFIX,
    u32be(context.serverEpoch),
    encodeContextField('sessionId', context.sessionId),
    encodeContextField('resourceId', context.resourceId),
    encodeContextField('resourceVersion', context.resourceVersion),
    encodeContextField('manifestHash', context.manifestHash),
    encodeContextField('deviceId', context.deviceId),
    u32be(transportSeq),
  ])
}

function validateSessionControlContext(context: SessionControlContext): void {
  validateContext(context)
  assertTransportPosition(0, context.transportTotal)
  assertU32('realTotal', context.realTotal, false)
  if (context.realTotal < 1 || context.realTotal > MAX_TRANSPORT_CHUNKS) {
    throw new Error('realTotal is outside the supported range')
  }
  if (context.realTotal > context.transportTotal) throw new Error('realTotal cannot exceed transportTotal')
  assertU32('padTo', context.padTo, false)
  if (context.padTo < 1 || context.padTo > MAX_CHUNK_PAYLOAD) {
    throw new Error('padTo is outside the supported range')
  }
  const transform = context.watchfaceTransform
  if (transform) {
    if (!/^\d{12}$/.test(transform.id)) throw new Error('watchface transform ID must be 12 digits')
    if (!/^[a-f0-9]{32}$/.test(transform.md5)) throw new Error('watchface transform MD5 must be lowercase hex')
    assertU32('watchface idOffset', transform.idOffset, false)
    assertU32('watchface fieldEnd', transform.fieldEnd, false)
    if (transform.fieldEnd <= transform.idOffset || transform.idOffset + transform.id.length > transform.fieldEnd) {
      throw new Error('watchface transform range is invalid')
    }
  }
}

function encodeSessionControlContext(context: SessionControlContext): Uint8Array {
  validateSessionControlContext(context)
  const transform = context.watchfaceTransform
  return concatBytes([
    SESSION_CONTROL_PREFIX,
    encodeContextField('sessionId', context.sessionId),
    encodeContextField('resourceId', context.resourceId),
    encodeContextField('resourceVersion', context.resourceVersion),
    encodeContextField('manifestHash', context.manifestHash),
    encodeContextField('deviceId', context.deviceId),
    u32be(context.serverEpoch),
    u32be(context.transportTotal),
    u32be(context.realTotal),
    u32be(context.padTo),
    ...(transform ? [
      // Optional suffix keeps non-watchface protocol-v2 control MACs
      // byte-compatible with already-open clients during a rolling deploy.
      u32be(1),
      encodeContextField('watchfaceTransform.id', transform.id),
      encodeContextField('watchfaceTransform.md5', transform.md5),
      u32be(transform.idOffset),
      u32be(transform.fieldEnd),
    ] : []),
  ])
}

/** Create a SessionInit HMAC that binds all stream-control metadata. */
export async function createControlMac(controlKey: CryptoKey, context: SessionControlContext): Promise<Uint8Array> {
  const mac = new Uint8Array(
    await subtle.sign('HMAC', controlKey, encodeSessionControlContext(context) as BufferSource),
  )
  if (mac.length !== HMAC_TAG_LEN) throw new Error('unexpected HMAC-SHA-256 output length')
  return mac
}

/** Verify a SessionInit HMAC using WebCrypto's constant-time HMAC verification. */
export async function verifyControlMac(
  controlKey: CryptoKey,
  context: SessionControlContext,
  mac: Uint8Array,
): Promise<boolean> {
  if (!(mac instanceof Uint8Array) || mac.length !== HMAC_TAG_LEN) return false
  return subtle.verify(
    'HMAC',
    controlKey,
    mac as BufferSource,
    encodeSessionControlContext(context) as BufferSource,
  )
}

/**
 * Deterministically choose the frame suite using a secret HMAC schedule. The
 * server emits the selected suite id and the client independently recomputes
 * it before attempting decryption.
 */
export async function selectChunkSuite(
  selectionKey: CryptoKey,
  context: ChunkCryptoContext,
  transportSeq: number,
): Promise<ChunkCipherSuite> {
  validateContext(context)
  assertU32('transportSeq', transportSeq, false)
  const mac = new Uint8Array(
    await subtle.sign('HMAC', selectionKey, selectionInput(context, transportSeq) as BufferSource),
  )
  return (mac[0]! & 1) === 0 ? 'AES-256-GCM' : 'AES-256-CTR-HMAC-SHA256'
}

function suiteTagLength(suite: ChunkCipherSuite): number {
  return suite === 'AES-256-GCM' ? GCM_TAG_LEN : HMAC_TAG_LEN
}

function assertNonce(suite: ChunkCipherSuite, nonce: Uint8Array): void {
  if (nonce.length !== NONCE_LEN) throw new Error('invalid nonce length')
  if (suite === 'AES-256-GCM') {
    let trailing = 0
    for (let i = GCM_NONCE_LEN; i < NONCE_LEN; i++) trailing |= nonce[i]!
    if (trailing !== 0) throw new Error('invalid AES-GCM nonce padding')
  }
}

/** Parse and validate a v2 header. It does not authenticate or decrypt it. */
export function parseChunkHeaderV2(buffer: Uint8Array, offset = 0): ParsedChunkHeaderV2 {
  if (!Number.isSafeInteger(offset) || offset < 0 || offset > buffer.length) throw new Error('invalid frame offset')
  if (buffer.length - offset < HEADER_LEN) throw new Error('incomplete v2 frame header')

  let magicDiff = 0
  for (let i = 0; i < MAGIC.length; i++) magicDiff |= buffer[offset + i]! ^ MAGIC[i]!
  if (magicDiff !== 0) throw new Error('invalid chunk magic')
  if (buffer[offset + 4] !== VERSION) throw new Error(`unsupported chunk version: ${buffer[offset + 4]}`)

  const suite = ID_TO_SUITE[buffer[offset + 5]!]
  if (!suite) throw new Error('unsupported chunk cipher suite')
  if (buffer[offset + 6] !== 0 || buffer[offset + 7] !== 0) throw new Error('non-zero reserved frame bits')

  const view = new DataView(buffer.buffer, buffer.byteOffset + offset, HEADER_LEN)
  const serverEpoch = view.getUint32(8, false)
  const transportSeq = view.getUint32(12, false)
  const transportTotal = view.getUint32(16, false)
  assertTransportPosition(transportSeq, transportTotal)
  const nonce = buffer.subarray(offset + 20, offset + 20 + NONCE_LEN)
  assertNonce(suite, nonce)
  const ciphertextLength = view.getUint32(36, false)
  if (ciphertextLength < MIN_CIPHERTEXT_LEN || ciphertextLength > MAX_CIPHERTEXT_LEN) {
    throw new Error('ciphertext length is outside the supported range')
  }
  const authenticationTagLength = suiteTagLength(suite)
  const frameLength = HEADER_LEN + ciphertextLength + authenticationTagLength
  if (!Number.isSafeInteger(frameLength)) throw new Error('invalid frame length')

  return {
    suite,
    serverEpoch,
    transportSeq,
    transportTotal,
    nonce,
    ciphertextLength,
    authenticationTagLength,
    frameLength,
  }
}

function buildHeader(
  suite: ChunkCipherSuite,
  context: ChunkCryptoContext,
  transportSeq: number,
  transportTotal: number,
  nonce: Uint8Array,
  ciphertextLength: number,
): Uint8Array {
  const header = new Uint8Array(HEADER_LEN)
  header.set(MAGIC, 0)
  header[4] = VERSION
  header[5] = SUITE_TO_ID[suite]
  writeU32BE(header, 8, context.serverEpoch)
  writeU32BE(header, 12, transportSeq)
  writeU32BE(header, 16, transportTotal)
  header.set(nonce, 20)
  writeU32BE(header, 36, ciphertextLength)
  return header
}

function validatePayloadMetadata(input: EncryptChunkV2Input): { realSeq: number; realTotal: number; padTo: number } {
  if (!(input.data instanceof Uint8Array)) throw new Error('chunk data must be a Uint8Array')
  if (input.data.length > MAX_CHUNK_PAYLOAD) throw new Error('chunk payload exceeds the maximum size')
  const padTo = input.padTo ?? DEFAULT_CHUNK_SIZE
  assertU32('padTo', padTo, false)
  if (padTo < 1 || padTo > MAX_CHUNK_PAYLOAD) throw new Error('padTo is outside the supported range')
  if (input.data.length > padTo) throw new Error('chunk data exceeds padTo')

  if (input.kind === 'real') {
    if (input.realSeq === undefined || input.realTotal === undefined) {
      throw new Error('real payload requires realSeq and realTotal')
    }
    assertU32('realSeq', input.realSeq, false)
    assertU32('realTotal', input.realTotal, false)
    if (input.realTotal < 1 || input.realTotal > MAX_TRANSPORT_CHUNKS) {
      throw new Error('realTotal is outside the supported range')
    }
    if (input.realSeq >= input.realTotal) throw new Error('realSeq must be less than realTotal')
    if (input.realTotal > input.transportTotal) throw new Error('realTotal cannot exceed transportTotal')
    return { realSeq: input.realSeq, realTotal: input.realTotal, padTo }
  }

  if (input.kind !== 'decoy') throw new Error('unsupported payload kind')
  if (input.realSeq !== undefined || input.realTotal !== undefined) {
    throw new Error('decoy payload must not include real sequence metadata')
  }
  return { realSeq: UINT32_MAX, realTotal: UINT32_MAX, padTo }
}

function fillRandom(target: Uint8Array): void {
  // WebCrypto limits each getRandomValues call to 65,536 bytes.
  for (let offset = 0; offset < target.length; offset += 65_536) {
    globalThis.crypto.getRandomValues(target.subarray(offset, Math.min(offset + 65_536, target.length)))
  }
}

async function encodeInnerPayload(
  controlKey: CryptoKey,
  aad: Uint8Array,
  input: EncryptChunkV2Input,
): Promise<Uint8Array> {
  const { realSeq, realTotal, padTo } = validatePayloadMetadata(input)
  const header = new Uint8Array(INNER_HEADER_LEN)
  header.set(INNER_MAGIC, 0)
  header[4] = input.kind === 'real' ? 1 : 2
  writeU32BE(header, 8, realSeq)
  writeU32BE(header, 12, realTotal)
  writeU32BE(header, 16, input.data.length)

  const paddedData = new Uint8Array(padTo)
  paddedData.set(input.data)
  fillRandom(paddedData.subarray(input.data.length))
  const authenticated = concatBytes([header, paddedData])
  const controlTag = new Uint8Array(
    await subtle.sign('HMAC', controlKey, concatBytes([CONTROL_PREFIX, aad, authenticated]) as BufferSource),
  )
  if (controlTag.length !== CONTROL_TAG_LEN) throw new Error('unexpected HMAC-SHA-256 output length')
  return concatBytes([authenticated, controlTag])
}

/** Encrypt a real or decoy v2 frame with the HMAC-selected cipher suite. */
export async function encryptChunkV2(
  keys: SessionCryptoKeys,
  context: ChunkCryptoContext,
  input: EncryptChunkV2Input,
): Promise<Uint8Array> {
  validateContext(context)
  assertTransportPosition(input.transportSeq, input.transportTotal)
  // Validate before allocating or selecting a suite.
  const { padTo } = validatePayloadMetadata(input)

  const suite = await selectChunkSuite(keys.selectionKey, context, input.transportSeq)
  const nonce = new Uint8Array(NONCE_LEN)
  const randomNonceLength = suite === 'AES-256-GCM' ? GCM_NONCE_LEN : NONCE_LEN
  globalThis.crypto.getRandomValues(nonce.subarray(0, randomNonceLength))

  const ciphertextLength = INNER_HEADER_LEN + padTo + CONTROL_TAG_LEN
  const header = buildHeader(
    suite,
    context,
    input.transportSeq,
    input.transportTotal,
    nonce,
    ciphertextLength,
  )
  const aad = encodeAad(header, context)
  const plaintext = await encodeInnerPayload(keys.controlKey, aad, input)

  let ciphertext: Uint8Array
  let authenticationTag: Uint8Array
  if (suite === 'AES-256-GCM') {
    const sealed = new Uint8Array(
      await subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: nonce.subarray(0, GCM_NONCE_LEN) as BufferSource,
          additionalData: aad as BufferSource,
          tagLength: GCM_TAG_LEN * 8,
        },
        keys.gcmKey,
        plaintext as BufferSource,
      ),
    )
    ciphertext = sealed.subarray(0, sealed.length - GCM_TAG_LEN)
    authenticationTag = sealed.subarray(sealed.length - GCM_TAG_LEN)
  } else {
    ciphertext = new Uint8Array(
      await subtle.encrypt(
        { name: 'AES-CTR', counter: nonce as BufferSource, length: 64 },
        keys.ctrKey,
        plaintext as BufferSource,
      ),
    )
    authenticationTag = new Uint8Array(
      await subtle.sign(
        'HMAC',
        keys.ctrMacKey,
        concatBytes([FRAME_MAC_PREFIX, aad, ciphertext]) as BufferSource,
      ),
    )
  }

  if (ciphertext.length !== ciphertextLength || authenticationTag.length !== suiteTagLength(suite)) {
    throw new Error('cipher suite produced an invalid output length')
  }
  return concatBytes([header, ciphertext, authenticationTag])
}

async function decryptCiphertext(
  keys: SessionCryptoKeys,
  header: ParsedChunkHeaderV2,
  aad: Uint8Array,
  ciphertext: Uint8Array,
  authenticationTag: Uint8Array,
): Promise<Uint8Array> {
  if (header.suite === 'AES-256-GCM') {
    const sealed = concatBytes([ciphertext, authenticationTag])
    try {
      return new Uint8Array(
        await subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: header.nonce.subarray(0, GCM_NONCE_LEN) as BufferSource,
            additionalData: aad as BufferSource,
            tagLength: GCM_TAG_LEN * 8,
          },
          keys.gcmKey,
          sealed as BufferSource,
        ),
      )
    } catch {
      throw new Error('chunk authentication failed')
    }
  }

  const macInput = concatBytes([FRAME_MAC_PREFIX, aad, ciphertext])
  const valid = await subtle.verify(
    'HMAC',
    keys.ctrMacKey,
    authenticationTag as BufferSource,
    macInput as BufferSource,
  )
  if (!valid) throw new Error('chunk authentication failed')
  return new Uint8Array(
    await subtle.decrypt(
      { name: 'AES-CTR', counter: header.nonce as BufferSource, length: 64 },
      keys.ctrKey,
      ciphertext as BufferSource,
    ),
  )
}

interface DecodedInnerPayload {
  kind: ChunkPayloadKind
  data: Uint8Array
  realSeq?: number
  realTotal?: number
}

async function decodeInnerPayload(
  controlKey: CryptoKey,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<DecodedInnerPayload> {
  if (plaintext.length < MIN_CIPHERTEXT_LEN) throw new Error('decrypted control payload is too short')
  const authenticatedLength = plaintext.length - CONTROL_TAG_LEN
  const authenticated = plaintext.subarray(0, authenticatedLength)
  const controlTag = plaintext.subarray(authenticatedLength)
  const validControlTag = await subtle.verify(
    'HMAC',
    controlKey,
    controlTag as BufferSource,
    concatBytes([CONTROL_PREFIX, aad, authenticated]) as BufferSource,
  )
  if (!validControlTag) throw new Error('control payload authentication failed')

  let magicDiff = 0
  for (let i = 0; i < INNER_MAGIC.length; i++) magicDiff |= authenticated[i]! ^ INNER_MAGIC[i]!
  if (magicDiff !== 0) throw new Error('invalid encrypted control payload')
  if (authenticated[5] !== 0 || authenticated[6] !== 0 || authenticated[7] !== 0) {
    throw new Error('non-zero encrypted control reserved bits')
  }

  const view = new DataView(authenticated.buffer, authenticated.byteOffset, authenticated.byteLength)
  const kindId = authenticated[4]
  const realSeq = view.getUint32(8, false)
  const realTotal = view.getUint32(12, false)
  const payloadLength = view.getUint32(16, false)
  const paddedLength = authenticated.length - INNER_HEADER_LEN
  if (paddedLength < 1 || paddedLength > MAX_CHUNK_PAYLOAD || payloadLength > paddedLength) {
    throw new Error('invalid encrypted payload length')
  }
  const data = authenticated.slice(INNER_HEADER_LEN, INNER_HEADER_LEN + payloadLength)

  if (kindId === 1) {
    if (realTotal < 1 || realTotal > MAX_TRANSPORT_CHUNKS || realSeq >= realTotal) {
      throw new Error('invalid real payload sequence metadata')
    }
    return { kind: 'real', data, realSeq, realTotal }
  }
  if (kindId === 2) {
    if (realSeq !== UINT32_MAX || realTotal !== UINT32_MAX) {
      throw new Error('decoy payload contains real sequence metadata')
    }
    return { kind: 'decoy', data }
  }
  throw new Error('unsupported encrypted payload kind')
}

function assertSequenceState(state: ChunkSequenceState, header: ParsedChunkHeaderV2): void {
  if (state.complete) throw new Error('chunk stream is already complete')
  assertU32('state.nextTransportSeq', state.nextTransportSeq, false)
  assertU32('state.nextRealSeq', state.nextRealSeq, false)
  if (state.transportTotal !== null) {
    assertU32('state.transportTotal', state.transportTotal, false)
    if (state.transportTotal < 1 || state.nextTransportSeq >= state.transportTotal) {
      throw new Error('invalid transport sequence state')
    }
  }
  if (state.realTotal !== null) {
    assertU32('state.realTotal', state.realTotal, false)
    if (state.realTotal < 1 || state.nextRealSeq > state.realTotal) throw new Error('invalid real sequence state')
  }
  if (header.transportSeq !== state.nextTransportSeq) throw new Error('unexpected transport chunk sequence')
  if (state.transportTotal !== null && header.transportTotal !== state.transportTotal) {
    throw new Error('transport chunk total changed within the stream')
  }
  if (state.ciphertextLength !== null && header.ciphertextLength !== state.ciphertextLength) {
    throw new Error('padded chunk length changed within the stream')
  }
}

function advanceSequenceState(
  state: ChunkSequenceState,
  header: ParsedChunkHeaderV2,
  inner: DecodedInnerPayload,
): boolean {
  let nextRealSeq = state.nextRealSeq
  let realTotal = state.realTotal
  if (inner.kind === 'real') {
    if (inner.realSeq !== nextRealSeq) throw new Error('unexpected real chunk sequence')
    if (realTotal !== null && inner.realTotal !== realTotal) throw new Error('real chunk total changed within the stream')
    realTotal = inner.realTotal!
    nextRealSeq++
  }

  const nextTransportSeq = state.nextTransportSeq + 1
  const complete = nextTransportSeq === header.transportTotal
  if (complete && (realTotal === null || nextRealSeq !== realTotal)) {
    throw new Error('transport ended before all real chunks were received')
  }

  // Commit only after every authentication, ordering, and completeness check.
  state.transportTotal = header.transportTotal
  state.nextTransportSeq = nextTransportSeq
  state.nextRealSeq = nextRealSeq
  state.realTotal = realTotal
  state.ciphertextLength = header.ciphertextLength
  state.complete = complete
  return complete
}

/**
 * Authenticate, decrypt, classify, and strictly order one v2 frame. The state
 * object is mandatory so callers cannot accidentally accept reordered,
 * repeated, missing, or prematurely terminated transport/real sequences.
 */
export async function decryptChunkV2(
  keys: SessionCryptoKeys,
  context: SessionControlContext,
  frame: Uint8Array,
  state: ChunkSequenceState,
): Promise<DecryptedChunkV2> {
  validateSessionControlContext(context)
  const header = parseChunkHeaderV2(frame)
  if (frame.length !== header.frameLength) throw new Error('frame length does not match its authenticated header')
  if (header.serverEpoch !== context.serverEpoch) throw new Error('frame server epoch does not match session context')
  if (header.transportTotal !== context.transportTotal) {
    throw new Error('frame transport total does not match authenticated session control')
  }
  const expectedCiphertextLength = INNER_HEADER_LEN + context.padTo + CONTROL_TAG_LEN
  if (header.ciphertextLength !== expectedCiphertextLength) {
    throw new Error('frame padded length does not match authenticated session control')
  }
  assertSequenceState(state, header)

  const expectedSuite = await selectChunkSuite(keys.selectionKey, context, header.transportSeq)
  if (header.suite !== expectedSuite) throw new Error('chunk cipher suite does not match the secret schedule')

  const publicHeader = frame.subarray(0, HEADER_LEN)
  const aad = encodeAad(publicHeader, context)
  const ciphertextStart = HEADER_LEN
  const authenticationTagStart = ciphertextStart + header.ciphertextLength
  const ciphertext = frame.subarray(ciphertextStart, authenticationTagStart)
  const authenticationTag = frame.subarray(authenticationTagStart)
  const plaintext = await decryptCiphertext(keys, header, aad, ciphertext, authenticationTag)
  if (plaintext.length !== header.ciphertextLength) throw new Error('decrypted payload length mismatch')
  const inner = await decodeInnerPayload(keys.controlKey, aad, plaintext)
  if (inner.kind === 'real' && inner.realTotal !== context.realTotal) {
    throw new Error('real chunk total does not match authenticated session control')
  }
  const streamComplete = advanceSequenceState(state, header, inner)

  return {
    suite: header.suite,
    transportSeq: header.transportSeq,
    transportTotal: header.transportTotal,
    kind: inner.kind,
    data: inner.data,
    realSeq: inner.realSeq,
    realTotal: inner.realTotal,
    shouldInstall: inner.kind === 'real',
    streamComplete,
    frameLength: header.frameLength,
  }
}

/** Compatibility name for stream scanners; this always parses protocol v2. */
export const parseHeader = parseChunkHeaderV2
