import { describe, expect, it } from 'vitest'
import {
  deriveSessionKeys,
  exportPublicKey,
  exportSessionKeyRaw,
  generateSessionKey,
  generateSessionKeypair,
  importPublicKey,
  importSessionKeyRaw,
  unwrapSessionKey,
  wrapSessionKey,
  type SessionCryptoKeys,
} from './keys.js'
import { MAX_CHUNK_PAYLOAD } from '@azvf/contract'
import {
  HEADER_LEN,
  createChunkSequenceState,
  createControlMac,
  decryptChunkV2,
  encryptChunkV2,
  finalizeChunkSequenceState,
  parseChunkHeaderV2,
  selectChunkSuite,
  verifyControlMac,
  type ChunkCipherSuite,
  type ChunkCryptoContext,
  type SessionControlContext,
} from './chunk.js'

const encoder = new TextEncoder()

const BASE_CONTEXT: ChunkCryptoContext = {
  sessionId: 'session-test',
  resourceId: 'resource-test',
  resourceVersion: 'version-7',
  manifestHash: 'a5'.repeat(32),
  deviceId: 'device-aa:bb:cc',
  serverEpoch: 1_782_854_400,
}

function bytes(value: string): Uint8Array {
  return encoder.encode(value)
}

function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer
    }
    return true
  }
  return false
}

async function newKeys(): Promise<SessionCryptoKeys> {
  return deriveSessionKeys(await generateSessionKey())
}

async function contextForSuite(keys: SessionCryptoKeys, suite: ChunkCipherSuite): Promise<ChunkCryptoContext> {
  for (let i = 0; i < 512; i++) {
    const context = { ...BASE_CONTEXT, sessionId: `session-suite-${suite}-${i}` }
    if ((await selectChunkSuite(keys.selectionKey, context, 0)) === suite) return context
  }
  throw new Error(`could not find test context for ${suite}`)
}

function controlled(
  context: ChunkCryptoContext,
  transportTotal: number,
  realTotal: number,
  padTo: number,
): SessionControlContext {
  return { ...context, transportTotal, realTotal, padTo }
}

async function singleRealFrame(keys: SessionCryptoKeys, context: ChunkCryptoContext): Promise<Uint8Array> {
  return encryptChunkV2(keys, context, {
    transportSeq: 0,
    transportTotal: 1,
    kind: 'real',
    realSeq: 0,
    realTotal: 1,
    data: bytes('authenticated resource bytes'),
    padTo: 128,
  })
}

describe('session master key envelope and HKDF key separation', () => {
  it('wraps the HKDF master key with RSA-OAEP and derives identical non-exportable client keys', async () => {
    const browserPair = await generateSessionKeypair()
    const serverPublicKey = await importPublicKey(await exportPublicKey(browserPair.publicKey))
    const serverMaster = await generateSessionKey()
    const serverKeys = await deriveSessionKeys(serverMaster)
    const wrapped = await wrapSessionKey(serverPublicKey, serverMaster)
    await expect(exportSessionKeyRaw(serverMaster)).rejects.toThrow(/unavailable|not exportable/)
    await expect(exportSessionKeyRaw(serverMaster)).rejects.toThrow(/unavailable|not exportable/)

    const browserMaster = await unwrapSessionKey(browserPair.privateKey, wrapped)
    const browserKeys = await deriveSessionKeys(browserMaster)
    expect(browserMaster.extractable).toBe(false)
    expect(browserKeys.gcmKey.extractable).toBe(false)
    expect(browserKeys.ctrKey.extractable).toBe(false)
    expect(browserKeys.selectionKey.extractable).toBe(false)

    for (let seq = 0; seq < 12; seq++) {
      expect(await selectChunkSuite(browserKeys.selectionKey, BASE_CONTEXT, seq)).toBe(
        await selectChunkSuite(serverKeys.selectionKey, BASE_CONTEXT, seq),
      )
    }

    const controlContext: SessionControlContext = {
      ...BASE_CONTEXT,
      transportTotal: 5,
      realTotal: 3,
      padTo: 256,
    }
    const controlMac = await createControlMac(serverKeys.controlKey, controlContext)
    expect(await verifyControlMac(browserKeys.controlKey, controlContext, controlMac)).toBe(true)
  })

  it('requires exactly 32 bytes for an imported master key', async () => {
    await expect(importSessionKeyRaw(new Uint8Array(31))).rejects.toThrow(/32 bytes/)
    const master = await importSessionKeyRaw(new Uint8Array(32).fill(0xa5))
    expect(await exportSessionKeyRaw(master)).toEqual(new Uint8Array(32).fill(0xa5))
  })
})

describe('cipher suite schedule and authenticated SessionInit control', () => {
  it('selects both standard suites deterministically', async () => {
    const keys = await newKeys()
    const gcmContext = await contextForSuite(keys, 'AES-256-GCM')
    const ctrContext = await contextForSuite(keys, 'AES-256-CTR-HMAC-SHA256')
    expect(await selectChunkSuite(keys.selectionKey, gcmContext, 0)).toBe('AES-256-GCM')
    expect(await selectChunkSuite(keys.selectionKey, ctrContext, 0)).toBe('AES-256-CTR-HMAC-SHA256')
  })

  it('binds every SessionInit context and stream-control field', async () => {
    const keys = await newKeys()
    const context: SessionControlContext = {
      ...BASE_CONTEXT,
      transportTotal: 8,
      realTotal: 5,
      padTo: 512,
      watchfaceTransform: { id: '123456789012', md5: 'cd'.repeat(16), idOffset: 40, fieldEnd: 58 },
    }
    const mac = await createControlMac(keys.controlKey, context)
    expect(await verifyControlMac(keys.controlKey, context, mac)).toBe(true)

    const mutations: SessionControlContext[] = [
      { ...context, sessionId: `${context.sessionId}-changed` },
      { ...context, resourceId: `${context.resourceId}-changed` },
      { ...context, resourceVersion: `${context.resourceVersion}-changed` },
      { ...context, manifestHash: 'b6'.repeat(32) },
      { ...context, deviceId: `${context.deviceId}-changed` },
      { ...context, serverEpoch: context.serverEpoch + 1 },
      { ...context, transportTotal: context.transportTotal + 1 },
      { ...context, realTotal: context.realTotal + 1 },
      { ...context, padTo: context.padTo + 1 },
      { ...context, watchfaceTransform: undefined },
      { ...context, watchfaceTransform: { ...context.watchfaceTransform!, id: '987654321012' } },
      { ...context, watchfaceTransform: { ...context.watchfaceTransform!, md5: 'ef'.repeat(16) } },
      { ...context, watchfaceTransform: { ...context.watchfaceTransform!, idOffset: 39 } },
      { ...context, watchfaceTransform: { ...context.watchfaceTransform!, fieldEnd: 59 } },
    ]
    for (const mutation of mutations) {
      expect(await verifyControlMac(keys.controlKey, mutation, mac)).toBe(false)
    }
    expect(await verifyControlMac(keys.controlKey, context, mac.subarray(1))).toBe(false)
    expect(await verifyControlMac((await newKeys()).controlKey, context, mac)).toBe(false)
  })
})

describe.each<ChunkCipherSuite>(['AES-256-GCM', 'AES-256-CTR-HMAC-SHA256'])('%s transport', (suite) => {
  it('authenticates and restores a real payload', async () => {
    const keys = await newKeys()
    const context = await contextForSuite(keys, suite)
    const frame = await singleRealFrame(keys, context)
    expect(parseChunkHeaderV2(frame).suite).toBe(suite)

    const state = createChunkSequenceState()
    const decoded = await decryptChunkV2(keys, controlled(context, 1, 1, 128), frame, state)
    expect(decoded.kind).toBe('real')
    expect(decoded.shouldInstall).toBe(true)
    expect(decoded.data).toEqual(bytes('authenticated resource bytes'))
    expect(decoded.realSeq).toBe(0)
    expect(decoded.realTotal).toBe(1)
    expect(decoded.streamComplete).toBe(true)
    expect(() => finalizeChunkSequenceState(state)).not.toThrow()
  })

  it('rejects ciphertext and authentication-tag tampering without advancing state', async () => {
    const keys = await newKeys()
    const context = await contextForSuite(keys, suite)
    const original = await singleRealFrame(keys, context)

    const tamperedCiphertext = original.slice()
    tamperedCiphertext[HEADER_LEN + 7] ^= 0x80
    const state = createChunkSequenceState()
    const control = controlled(context, 1, 1, 128)
    await expect(decryptChunkV2(keys, control, tamperedCiphertext, state)).rejects.toThrow(/authentication/)
    expect(state.nextTransportSeq).toBe(0)

    const tamperedTag = original.slice()
    tamperedTag[tamperedTag.length - 1] ^= 0x01
    await expect(decryptChunkV2(keys, control, tamperedTag, state)).rejects.toThrow(/authentication/)
    expect(state.nextTransportSeq).toBe(0)
  })

  it('rejects an AAD context mismatch', async () => {
    const keys = await newKeys()
    const context = await contextForSuite(keys, suite)
    const frame = await singleRealFrame(keys, context)
    const control = controlled(context, 1, 1, 128)
    await expect(
      decryptChunkV2(keys, { ...control, deviceId: 'different-device' }, frame, createChunkSequenceState()),
    ).rejects.toThrow(/secret schedule|authentication/)
  })
})

describe('hidden decoys, fixed padding, and strict sequencing', () => {
  it('enforces authenticated SessionInit totals and padding on every frame', async () => {
    const keys = await newKeys()
    const context = BASE_CONTEXT
    const frame = await encryptChunkV2(keys, context, {
      transportSeq: 0,
      transportTotal: 2,
      kind: 'real',
      realSeq: 0,
      realTotal: 1,
      data: bytes('bound to session control'),
      padTo: 64,
    })
    const control = controlled(context, 2, 1, 64)

    await expect(
      decryptChunkV2(keys, { ...control, transportTotal: 3 }, frame, createChunkSequenceState()),
    ).rejects.toThrow(/transport total/)
    await expect(
      decryptChunkV2(keys, { ...control, padTo: 65 }, frame, createChunkSequenceState()),
    ).rejects.toThrow(/padded length/)
    await expect(
      decryptChunkV2(keys, { ...control, realTotal: 2 }, frame, createChunkSequenceState()),
    ).rejects.toThrow(/real chunk total/)
    await expect(
      decryptChunkV2(
        keys,
        { ...control, resourceVersion: `${control.resourceVersion}-forged` },
        frame,
        createChunkSequenceState(),
      ),
    ).rejects.toThrow(/secret schedule|authentication/)
    await expect(
      decryptChunkV2(keys, { ...control, manifestHash: 'c7'.repeat(32) }, frame, createChunkSequenceState()),
    ).rejects.toThrow(/secret schedule|authentication/)

    const decoded = await decryptChunkV2(keys, control, frame, createChunkSequenceState())
    expect(decoded.data).toEqual(bytes('bound to session control'))
  })

  it('keeps real/decoy classification encrypted and gives both equal ciphertext lengths', async () => {
    const keys = await newKeys()
    const context = BASE_CONTEXT
    const secretReal = bytes('REAL-PAYLOAD-NOT-IN-PUBLIC-HEADER')
    const secretDecoy = bytes('DECOY-PAYLOAD-NOT-IN-PUBLIC-HEADER')
    const real = await encryptChunkV2(keys, context, {
      transportSeq: 0,
      transportTotal: 2,
      kind: 'real',
      realSeq: 0,
      realTotal: 1,
      data: secretReal,
      padTo: 192,
    })
    const decoy = await encryptChunkV2(keys, context, {
      transportSeq: 1,
      transportTotal: 2,
      kind: 'decoy',
      data: secretDecoy,
      padTo: 192,
    })

    expect(parseChunkHeaderV2(real).ciphertextLength).toBe(parseChunkHeaderV2(decoy).ciphertextLength)
    expect(contains(real, secretReal)).toBe(false)
    expect(contains(decoy, secretDecoy)).toBe(false)

    const state = createChunkSequenceState()
    const control = controlled(context, 2, 1, 192)
    const decodedReal = await decryptChunkV2(keys, control, real, state)
    const decodedDecoy = await decryptChunkV2(keys, control, decoy, state)
    expect(decodedReal.data).toEqual(secretReal)
    expect(decodedReal.shouldInstall).toBe(true)
    expect(decodedDecoy.data).toEqual(secretDecoy)
    expect(decodedDecoy.kind).toBe('decoy')
    expect(decodedDecoy.shouldInstall).toBe(false)
    expect(decodedDecoy.realSeq).toBeUndefined()
    expect(decodedDecoy.streamComplete).toBe(true)
    expect(() => finalizeChunkSequenceState(state)).not.toThrow()
  })

  it('rejects transport reordering, replay, and a forged suite id', async () => {
    const keys = await newKeys()
    const gcmContext = await contextForSuite(keys, 'AES-256-GCM')
    const frame0 = await encryptChunkV2(keys, gcmContext, {
      transportSeq: 0,
      transportTotal: 2,
      kind: 'real',
      realSeq: 0,
      realTotal: 1,
      data: bytes('real'),
      padTo: 64,
    })
    const frame1 = await encryptChunkV2(keys, gcmContext, {
      transportSeq: 1,
      transportTotal: 2,
      kind: 'decoy',
      data: bytes('decoy'),
      padTo: 64,
    })

    const control = controlled(gcmContext, 2, 1, 64)
    await expect(decryptChunkV2(keys, control, frame1, createChunkSequenceState())).rejects.toThrow(/sequence/)
    const state = createChunkSequenceState()
    await decryptChunkV2(keys, control, frame0, state)
    await expect(decryptChunkV2(keys, control, frame0, state)).rejects.toThrow(/sequence/)

    // CTR carries a 32-byte HMAC rather than GCM's 16-byte tag. Extend the
    // forged frame so it passes strict length parsing and reaches schedule validation.
    const forgedSuite = new Uint8Array(frame0.length + 16)
    forgedSuite.set(frame0)
    forgedSuite[5] = 2
    await expect(decryptChunkV2(keys, control, forgedSuite, createChunkSequenceState())).rejects.toThrow(
      /secret schedule/,
    )
  })

  it('rejects a hidden real-sequence gap and refuses to finalize an incomplete stream', async () => {
    const keys = await newKeys()
    const context = BASE_CONTEXT
    const outOfOrderReal = await encryptChunkV2(keys, context, {
      transportSeq: 0,
      transportTotal: 2,
      kind: 'real',
      realSeq: 1,
      realTotal: 2,
      data: bytes('second real chunk'),
      padTo: 64,
    })
    const state = createChunkSequenceState()
    await expect(decryptChunkV2(keys, controlled(context, 2, 2, 64), outOfOrderReal, state)).rejects.toThrow(
      /real chunk sequence/,
    )
    expect(() => finalizeChunkSequenceState(state)).toThrow(/incomplete/)
  })

  it('rejects a final decoy when authenticated real chunks are still missing', async () => {
    const keys = await newKeys()
    const context = BASE_CONTEXT
    const first = await encryptChunkV2(keys, context, {
      transportSeq: 0,
      transportTotal: 2,
      kind: 'real',
      realSeq: 0,
      realTotal: 2,
      data: bytes('first'),
      padTo: 64,
    })
    const last = await encryptChunkV2(keys, context, {
      transportSeq: 1,
      transportTotal: 2,
      kind: 'decoy',
      data: bytes('not the missing real payload'),
      padTo: 64,
    })
    const state = createChunkSequenceState()
    const control = controlled(context, 2, 2, 64)
    await decryptChunkV2(keys, control, first, state)
    await expect(decryptChunkV2(keys, control, last, state)).rejects.toThrow(/ended before/)
    expect(state.nextTransportSeq).toBe(1)
    expect(() => finalizeChunkSequenceState(state)).toThrow(/incomplete/)
  })

  it('enforces exact frame and padded payload bounds', async () => {
    const keys = await newKeys()
    const frame = await singleRealFrame(keys, BASE_CONTEXT)
    const trailing = new Uint8Array(frame.length + 1)
    trailing.set(frame)
    await expect(decryptChunkV2(keys, controlled(BASE_CONTEXT, 1, 1, 128), trailing, createChunkSequenceState())).rejects.toThrow(
      /frame length/,
    )
    expect(() => parseChunkHeaderV2(frame.subarray(0, HEADER_LEN - 1))).toThrow(/incomplete/)

    await expect(
      encryptChunkV2(keys, BASE_CONTEXT, {
        transportSeq: 0,
        transportTotal: 1,
        kind: 'real',
        realSeq: 0,
        realTotal: 1,
        data: new Uint8Array(2),
        padTo: 1,
      }),
    ).rejects.toThrow(/exceeds padTo/)
    await expect(
      encryptChunkV2(keys, BASE_CONTEXT, {
        transportSeq: 0,
        transportTotal: 1,
        kind: 'real',
        realSeq: 0,
        realTotal: 1,
        data: new Uint8Array(),
        padTo: MAX_CHUNK_PAYLOAD + 1,
      }),
    ).rejects.toThrow(/padTo/)
  })
})
