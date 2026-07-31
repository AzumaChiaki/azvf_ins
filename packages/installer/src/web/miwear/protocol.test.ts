import { describe, expect, it } from 'vitest'
import { bytesToHex, crc16Arc, crc32, hexToBytes, md5 } from './bytes.js'
import { aes128CcmEncrypt, deriveSessionKeys } from './crypto.js'
import { buildMassPrepare, decodeFields, fieldBytes, fieldNumber } from './protobuf.js'
import { decodeL1, encodeL1, L1StreamDecoder, L1Type, SarController } from './sar.js'
import { normalizeRetainedBytes, serialWriteSlices, SPP_WRITE_CHUNK_SIZE } from './session.js'

describe('recovered MiWear protocol compatibility vectors', () => {
  it('matches standard checksum and digest vectors', () => {
    const input = new TextEncoder().encode('123456789')
    expect(crc16Arc(input)).toBe(0xbb3d)
    expect(crc32(input)).toBe(0xcbf43926)
    expect(bytesToHex(md5(new TextEncoder().encode('abc')))).toBe('900150983cd24fb0d6963f7d28e17f72')
  })

  it('round-trips an L1 sequence frame', () => {
    const frame = { type: L1Type.Data, frx: false, seq: 42, payload: Uint8Array.of(1, 2, 3, 4) }
    expect(decodeL1(encodeL1(frame))).toEqual(frame)
  })

  it('fills a SAR window and submits it as one serial stream write', async () => {
    const writes: Uint8Array[] = []
    const sar = new SarController(async (data) => { writes.push(data) }, () => undefined, {
      txWindow: 4,
      sendTimeoutMs: 1_000,
      maxRetries: 0,
    })
    const pending = [1, 2, 3, 4].map((value) => sar.enqueue(Uint8Array.of(value)))
    await new Promise<void>((resolve) => setTimeout(resolve, 0))
    expect(writes).toHaveLength(1)
    const frames = new L1StreamDecoder().push(writes[0]!)
    expect(frames.map((frame) => frame.seq)).toEqual([0, 1, 2, 3])
    await sar.receive({ type: L1Type.Ack, frx: false, seq: 3, payload: new Uint8Array() })
    await Promise.all(pending)
    sar.close()
  })

  it('gates the auth handshake on the SAR start negotiation echo', async () => {
    const sar = new SarController(async () => undefined, () => undefined, { txWindow: 4 })
    // Times out (resolves false) when the watch never echoes the negotiation.
    expect(await sar.awaitNegotiation(10)).toBe(false)
    // Resolves true once the device sends its L1 Cmd start response (type 2).
    const waiting = sar.awaitNegotiation(1_000)
    // Minimal start response: leading 0x02 marks it as the device echo; key 4
    // carries a negotiated ACK deadline the controller clamps to its ceiling.
    const startResponse = Uint8Array.of(2, 4, 2, 0, 0x30, 0x75)
    await sar.receive({ type: L1Type.Cmd, frx: false, seq: 0, payload: startResponse })
    expect(await waiting).toBe(true)
    // Already negotiated → resolves immediately.
    expect(await sar.awaitNegotiation(0)).toBe(true)
    sar.close()
  })

  it('releases negotiation waiters when the session closes', async () => {
    const sar = new SarController(async () => undefined, () => undefined)
    const waiting = sar.awaitNegotiation(10_000)
    sar.close()
    expect(await waiting).toBe(false)
  })

  it('normalizes the device-retained MASS byte offset', () => {
    expect(normalizeRetainedBytes(-1, 100)).toBe(0)
    expect(normalizeRetainedBytes(43, 100)).toBe(43)
    expect(normalizeRetainedBytes(101, 100)).toBe(100)
  })

  it('coalesces Web Serial writes into AstroBox-sized SPP chunks', () => {
    const input = new Uint8Array(SPP_WRITE_CHUNK_SIZE * 2 + 17)
    const slices = serialWriteSlices(input)
    expect(slices.map((slice) => slice.length)).toEqual([SPP_WRITE_CHUNK_SIZE, SPP_WRITE_CHUNK_SIZE, 17])
    expect(slices[0]!.buffer).toBe(input.buffer)
  })

  it('uses the recovered MASS protobuf field numbers', () => {
    const digest = hexToBytes('00112233445566778899aabbccddeeff')
    const wear = decodeFields(buildMassPrepare(64, digest, 12_345))
    expect(fieldNumber(wear, 1)).toBe(22)
    expect(fieldNumber(wear, 2)).toBe(0)
    const mass = decodeFields(fieldBytes(wear, 24)!)
    const request = decodeFields(fieldBytes(mass, 1)!)
    expect(fieldNumber(request, 1)).toBe(64)
    expect(fieldBytes(request, 2)).toEqual(digest)
    expect(fieldNumber(request, 3)).toBe(12_345)
  })

  it('matches the recovered directional KDF layout', async () => {
    const keys = await deriveSessionKeys(
      '00112233445566778899aabbccddeeff',
      hexToBytes('000102030405060708090a0b0c0d0e0f'),
      hexToBytes('101112131415161718191a1b1c1d1e1f'),
    )
    expect(bytesToHex(new Uint8Array([
      ...keys.decKey,
      ...keys.encKey,
      ...keys.decNonce,
      ...keys.encNonce,
    ]))).toBe('a2cf6c33c13b444edf33b4d1a3b3a4c1644de586a875a5817a40ba4a92361a464f584e38f35dd40a')
  })

  it('matches an independently calculated AES-128-CCM vector', async () => {
    const result = await aes128CcmEncrypt(
      hexToBytes('00112233445566778899aabbccddeeff'),
      hexToBytes('000102030405060708090a0b'),
      hexToBytes('112233445566778899aabbccddeeff'),
    )
    expect(bytesToHex(result)).toBe('1a3ac428685803baf228fabbc414531e57afce')
  })
})
