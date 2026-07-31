import { describe, expect, it } from 'vitest'
import {
  createWatchfacePatch,
  getWatchfaceId,
  patchWatchfaceChunk,
  WATCHFACE_HEADER_LENGTH,
  WATCHFACE_ID_OFFSET,
} from './watchface.js'

/** 头部其余字节填 0xaa,用来验证改写不会溢出 ID 字段。 */
function headerWithId(id = '000000000000'): Uint8Array {
  const data = new Uint8Array(96).fill(0xaa)
  data.fill(0, WATCHFACE_ID_OFFSET, WATCHFACE_HEADER_LENGTH)
  new TextEncoder().encode(id).forEach((byte, index) => { data[WATCHFACE_ID_OFFSET + index] = byte })
  return data
}

describe('watchface ID rewrite at a fixed header offset', () => {
  it('reads the ID at 0x28 and rewrites the same field without touching its neighbours', () => {
    const data = headerWithId()
    expect(getWatchfaceId(data)).toBe('000000000000')
    const patch = createWatchfacePatch(data, '123456789012')
    expect(patch).toEqual({ id: '123456789012', idOffset: 0x28, fieldEnd: 0x28 + 12 })
    const output = patchWatchfaceChunk(data, 0, patch)
    expect(getWatchfaceId(output)).toBe('123456789012')
    // 字段前后的字节保持原值,证明改写严格限制在 [0x28, 0x34)
    expect(Array.from(output.subarray(WATCHFACE_ID_OFFSET - 6, WATCHFACE_ID_OFFSET)))
      .toEqual([0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa])
    expect(Array.from(output.subarray(WATCHFACE_HEADER_LENGTH, WATCHFACE_HEADER_LENGTH + 6)))
      .toEqual([0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa])
    expect(data).not.toBe(output)
    expect(getWatchfaceId(data)).toBe('000000000000')
  })

  it('pads a 9 character ID with NUL and still reads back the shorter form', () => {
    const data = headerWithId()
    const output = patchWatchfaceChunk(data, 0, createWatchfacePatch(data, '123456789'))
    expect(getWatchfaceId(output)).toBe('123456789')
    expect(Array.from(output.subarray(WATCHFACE_ID_OFFSET + 9, WATCHFACE_HEADER_LENGTH)))
      .toEqual([0, 0, 0])
  })

  it('rewrites correctly when the authenticated chunks split the ID field', () => {
    const data = headerWithId('123456789')
    const patch = createWatchfacePatch(data, '987654321012')
    const first = patchWatchfaceChunk(data.subarray(0, 45), 0, patch)
    const second = patchWatchfaceChunk(data.subarray(45), 45, patch)
    const combined = new Uint8Array(data.length)
    combined.set(first)
    combined.set(second, first.length)
    expect(getWatchfaceId(combined)).toBe('987654321012')
  })

  it('never mutates a Node Buffer source while calculating a transformed stream', () => {
    const source = Buffer.from(headerWithId())
    const before = Buffer.from(source)
    const output = patchWatchfaceChunk(source, 0, createWatchfacePatch(source, '246801357924'))
    expect(source).toEqual(before)
    expect(output).not.toBe(source)
    expect(getWatchfaceId(output)).toBe('246801357924')
  })

  it('accepts only 9 or 12 character alphanumeric IDs', () => {
    const data = headerWithId('abc123XYZ')
    expect(getWatchfaceId(data)).toBe('abc123XYZ')
    expect(() => createWatchfacePatch(data, 'too-short')).toThrow(/9 或 12/)
  })

  it('refuses to patch a header whose ID field is not valid', () => {
    const data = headerWithId()
    data.fill(0, WATCHFACE_ID_OFFSET, WATCHFACE_HEADER_LENGTH)
    expect(getWatchfaceId(data)).toBeNull()
    expect(() => createWatchfacePatch(data, '123456789012')).toThrow(/ID 字段无效/)
  })

  it('returns null when the header is shorter than the ID field', () => {
    expect(getWatchfaceId(headerWithId().subarray(0, WATCHFACE_HEADER_LENGTH - 1))).toBeNull()
  })
})
