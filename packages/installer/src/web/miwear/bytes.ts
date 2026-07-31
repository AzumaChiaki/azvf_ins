export function concatBytes(...parts: ArrayLike<number>[]): Uint8Array {
  const length = parts.reduce((total, part) => total + part.length, 0)
  const output = new Uint8Array(length)
  let offset = 0
  for (const part of parts) {
    output.set(part, offset)
    offset += part.length
  }
  return output
}
export function u16le(value: number): Uint8Array {
  return Uint8Array.of(value & 0xff, (value >>> 8) & 0xff)
}

export function u32le(value: number): Uint8Array {
  return Uint8Array.of(
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff
  )
}

export function readU16le(data: Uint8Array, offset = 0): number {
  return data[offset] | (data[offset + 1] << 8)
}

export function readU32le(data: Uint8Array, offset = 0): number {
  return (
    data[offset] |
    (data[offset + 1] << 8) |
    (data[offset + 2] << 16) |
    (data[offset + 3] << 24)
  ) >>> 0
}

export function hexToBytes(value: string): Uint8Array {
  if (!/^[0-9a-f]+$/i.test(value) || value.length % 2 !== 0) {
    throw new Error('十六进制字符串格式无效')
  }
  const output = new Uint8Array(value.length / 2)
  for (let i = 0; i < output.length; i += 1) {
    output[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16)
  }
  return output
}

export function bytesToHex(value: ArrayLike<number>): string {
  return Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('')
}

export function crc16Arc(data: Uint8Array): number {
  let crc = 0
  for (const byte of data) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1) !== 0 ? (crc >>> 1) ^ 0xa001 : crc >>> 1
    }
  }
  return crc & 0xffff
}

export function crc32(data: Uint8Array): number {
  return crc32Final(crc32Update(crc32Init(), data))
}

// 滚动 CRC32：供流式传输时逐分片累计，避免持有完整数据
export function crc32Init(): number {
  return 0xffffffff
}

export function crc32Update(state: number, data: Uint8Array): number {
  let crc = state >>> 0
  for (const byte of data) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 1) !== 0 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1
    }
  }
  return crc >>> 0
}

export function crc32Final(state: number): number {
  return (state ^ 0xffffffff) >>> 0
}

function rotateLeft(value: number, shift: number): number {
  return (value << shift) | (value >>> (32 - shift))
}

// RFC 1321 MD5. MASS uses the raw 16-byte digest as its transfer identifier.
export function md5(input: Uint8Array): Uint8Array {
  const paddedLength = Math.ceil((input.length + 9) / 64) * 64
  const data = new Uint8Array(paddedLength)
  data.set(input)
  data[input.length] = 0x80
  const bitLength = BigInt(input.length) * 8n
  for (let i = 0; i < 8; i += 1) {
    data[paddedLength - 8 + i] = Number((bitLength >> BigInt(i * 8)) & 0xffn)
  }

  const shifts = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ]
  const constants = Array.from({ length: 64 }, (_, i) =>
    Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0
  )

  let a0 = 0x67452301
  let b0 = 0xefcdab89
  let c0 = 0x98badcfe
  let d0 = 0x10325476

  for (let offset = 0; offset < data.length; offset += 64) {
    const words = new Uint32Array(16)
    for (let i = 0; i < 16; i += 1) words[i] = readU32le(data, offset + i * 4)
    let a = a0
    let b = b0
    let c = c0
    let d = d0

    for (let i = 0; i < 64; i += 1) {
      let f: number
      let g: number
      if (i < 16) {
        f = (b & c) | (~b & d)
        g = i
      } else if (i < 32) {
        f = (d & b) | (~d & c)
        g = (5 * i + 1) % 16
      } else if (i < 48) {
        f = b ^ c ^ d
        g = (3 * i + 5) % 16
      } else {
        f = c ^ (b | ~d)
        g = (7 * i) % 16
      }
      const nextD = c
      c = b
      b = (b + rotateLeft((a + f + constants[i] + words[g]) >>> 0, shifts[i])) >>> 0
      a = d
      d = nextD
    }

    a0 = (a0 + a) >>> 0
    b0 = (b0 + b) >>> 0
    c0 = (c0 + c) >>> 0
    d0 = (d0 + d) >>> 0
  }

  return concatBytes(u32le(a0), u32le(b0), u32le(c0), u32le(d0))
}
