import { describe, expect, it } from 'vitest'
import { bytesToHex, concatBytes, crc32, crc32Final, crc32Init, crc32Update, u16le, u32le } from './bytes'
import { consumeResumedPlaintext } from './session.js'
import type { WatchfaceInstallTransform } from '@azvf/contract'
function rand(n: number): Uint8Array {
  const b = new Uint8Array(n)
  for (let o = 0; o < n; o += 65536) crypto.getRandomValues(b.subarray(o, Math.min(o + 65536, n)))
  return b
}

describe('流式 MASS 构造与非流式一致', () => {
  it('consumes the full authenticated stream but emits only the device-missing suffix', async () => {
    const chunks = [Uint8Array.of(0, 1, 2), Uint8Array.of(3, 4, 5, 6, 7), Uint8Array.of(8, 9)]
    let index = 0
    const emitted: Uint8Array[] = []
    await consumeResumedPlaintext(
      { pull: async () => chunks[index++] ?? null },
      4,
      10,
      async (piece) => { emitted.push(piece.slice()) },
    )
    expect(Array.from(concatBytes(...emitted))).toEqual([4, 5, 6, 7, 8, 9])
    expect(index).toBe(3)
  })

  it('applies the authenticated watchface rewrite before slicing a resumed suffix', async () => {
    const data = new Uint8Array(70)
    new TextEncoder().encode('000000000000').forEach((byte, index) => { data[40 + index] = byte })
    const chunks = [data.subarray(0, 43), data.subarray(43, 55), data.subarray(55)]
    const transform: WatchfaceInstallTransform = {
      id: '123456789012', md5: '00'.repeat(16), idOffset: 40, fieldEnd: 58,
    }
    let index = 0
    const emitted: Uint8Array[] = []
    await consumeResumedPlaintext(
      { pull: async () => chunks[index++] ?? null },
      42,
      data.length,
      async (piece) => { emitted.push(piece.slice()) },
      transform,
    )
    const suffix = concatBytes(...emitted)
    expect(new TextDecoder().decode(suffix.subarray(0, 10))).toBe('3456789012')
    expect(Array.from(suffix.subarray(10, 16))).toEqual([0, 0, 0, 0, 0, 0])
  })

  it('滚动 CRC32 等于一次性 CRC32', () => {
    const data = rand(100000)
    let state = crc32Init()
    for (let o = 0; o < data.length; o += 7000) state = crc32Update(state, data.subarray(o, o + 7000))
    expect(crc32Final(state)).toBe(crc32(data))
  })

  // 复刻 sendMassStreaming 的分片器，逐分片喂入，断言产出与非流式 encoded 完全一致
  function streamFragments(prefix: Uint8Array, chunks: Uint8Array[], fragmentSize: number, totalParts: number) {
    const out: Uint8Array[] = []
    let crcState = crc32Init()
    let buffer: Uint8Array = new Uint8Array(0)
    let partNum = 0
    const emit = (fragment: Uint8Array) => {
      partNum += 1
      out.push(concatBytes(u16le(totalParts), u16le(partNum), fragment))
    }
    const feed = (bytes: Uint8Array) => {
      if (bytes.length === 0) return
      buffer = buffer.length === 0 ? bytes : concatBytes(buffer, bytes)
      while (buffer.length >= fragmentSize) {
        emit(buffer.slice(0, fragmentSize))
        buffer = buffer.slice(fragmentSize)
      }
    }
    crcState = crc32Update(crcState, prefix)
    feed(prefix)
    for (const c of chunks) {
      crcState = crc32Update(crcState, c)
      feed(c)
    }
    feed(u32le(crc32Final(crcState)))
    if (buffer.length > 0) emit(buffer)
    return { fragments: out, partNum }
  }

  it('分片流按序拼接后等于 [prefix||data||crc32]，且分片头正确', () => {
    const resType = 16
    const md5 = rand(16)
    const data = rand(53 * 1024 + 17) // 跨多分片、非整除
    const prefix = concatBytes(Uint8Array.of(0, resType), md5, u32le(data.length))

    // 非流式基准
    const massHeader = concatBytes(prefix, data)
    const encoded = concatBytes(massHeader, u32le(crc32(massHeader)))

    const expectedSliceLength = 512
    const fragmentSize = expectedSliceLength - 6
    const totalParts = Math.ceil(encoded.length / fragmentSize)

    // 用不规则的明文分块喂入（模拟解密分片边界与 fragmentSize 不对齐）
    const chunks: Uint8Array[] = []
    for (let o = 0, i = 0; o < data.length; i++) {
      const step = [10000, 3, 40000, 137, 7000][i % 5]
      chunks.push(data.subarray(o, Math.min(o + step, data.length)))
      o += step
    }

    const { fragments, partNum } = streamFragments(prefix, chunks, fragmentSize, totalParts)
    expect(partNum).toBe(totalParts)

    // 去掉每片 4 字节头(totalParts,part)后拼接，应还原 encoded
    const reassembled = concatBytes(...fragments.map((f) => f.subarray(4)))
    expect(bytesToHex(reassembled)).toBe(bytesToHex(encoded))

    // 校验分片头序号
    fragments.forEach((f, idx) => {
      expect(f[0] | (f[1] << 8)).toBe(totalParts)
      expect(f[2] | (f[3] << 8)).toBe(idx + 1)
    })
  })
})
