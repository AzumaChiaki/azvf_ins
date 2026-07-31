import { concatBytes, hexToBytes } from './bytes'

export interface SessionKeys {
  decKey: Uint8Array
  encKey: Uint8Array
  decNonce: Uint8Array
  encNonce: Uint8Array
}

function subtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) throw new Error('当前环境不支持 Web Crypto')
  return globalThis.crypto.subtle
}

export async function hmacSha256(key: Uint8Array, ...parts: Uint8Array[]): Promise<Uint8Array> {
  const cryptoKey = await subtle().importKey(
    'raw',
    key as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const signature = await subtle().sign('HMAC', cryptoKey, concatBytes(...parts) as BufferSource)
  return new Uint8Array(signature)
}

export async function deriveSessionKeys(
  authKeyHex: string,
  phoneNonce: Uint8Array,
  watchNonce: Uint8Array
): Promise<SessionKeys> {
  const secret = hexToBytes(authKeyHex)
  if (secret.length !== 16 || phoneNonce.length !== 16 || watchNonce.length !== 16) {
    throw new Error('authkey、手机随机数和设备随机数都必须为 16 字节')
  }

  const hmacKey = await hmacSha256(concatBytes(phoneNonce, watchNonce), secret)
  const tag = new TextEncoder().encode('miwear-auth')
  const output = new Uint8Array(64)
  let previous: Uint8Array = new Uint8Array()
  let offset = 0
  for (let counter = 1; offset < output.length; counter += 1) {
    previous = await hmacSha256(hmacKey, previous, tag, Uint8Array.of(counter))
    const length = Math.min(previous.length, output.length - offset)
    output.set(previous.slice(0, length), offset)
    offset += length
  }

  return {
    decKey: output.slice(0, 16),
    encKey: output.slice(16, 32),
    decNonce: output.slice(32, 36),
    encNonce: output.slice(36, 40)
  }
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  let difference = 0
  for (let i = 0; i < left.length; i += 1) difference |= left[i] ^ right[i]
  return difference === 0
}

export async function aes128CtrCrypt(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  if (keyBytes.length !== 16) throw new Error('AES-CTR 密钥必须为 16 字节')
  // Compatibility boundary: the immutable MiWear device protocol defines the
  // CTR initial counter as the 16-byte direction key itself for every PB
  // message. This reuses a keystream and provides no message authentication;
  // changing it unilaterally would make the device reject every command. AZVF
  // v2 never copies this construction: it uses unique counters plus full HMAC.
  const key = await subtle().importKey('raw', keyBytes as BufferSource, 'AES-CTR', false, ['encrypt'])
  const result = await subtle().encrypt(
    { name: 'AES-CTR', counter: keyBytes as BufferSource, length: 128 },
    key,
    data as BufferSource
  )
  return new Uint8Array(result)
}

async function aesBlock(key: CryptoKey, block: Uint8Array): Promise<Uint8Array> {
  const encrypted = await subtle().encrypt(
    { name: 'AES-CBC', iv: new Uint8Array(16) },
    key,
    block as BufferSource
  )
  return new Uint8Array(encrypted).slice(0, 16)
}

function xorBlock(left: Uint8Array, right: Uint8Array): Uint8Array {
  return Uint8Array.from(left, (byte, index) => byte ^ right[index])
}

function paddedBlocks(data: Uint8Array): Uint8Array[] {
  const blocks: Uint8Array[] = []
  for (let offset = 0; offset < data.length; offset += 16) {
    const block = new Uint8Array(16)
    block.set(data.slice(offset, offset + 16))
    blocks.push(block)
  }
  return blocks
}

function counterBlock(nonce: Uint8Array, counter: number): Uint8Array {
  return concatBytes(
    Uint8Array.of(2),
    nonce,
    Uint8Array.of((counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff)
  )
}

// MiWear auth uses AES-CCM with a 12-byte nonce and a 4-byte authentication tag.
export async function aes128CcmEncrypt(
  keyBytes: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad = new Uint8Array()
): Promise<Uint8Array> {
  if (keyBytes.length !== 16 || nonce.length !== 12) throw new Error('AES-CCM 参数长度无效')
  if (plaintext.length >= 0x1000000) throw new Error('AES-CCM 明文过长')
  const key = await subtle().importKey('raw', keyBytes as BufferSource, 'AES-CBC', false, ['encrypt'])
  const flags = (aad.length > 0 ? 0x40 : 0) | 0x08 | 0x02
  const b0 = concatBytes(
    Uint8Array.of(flags),
    nonce,
    Uint8Array.of((plaintext.length >>> 16) & 0xff, (plaintext.length >>> 8) & 0xff, plaintext.length & 0xff)
  )

  const authData = aad.length > 0
    ? concatBytes(Uint8Array.of((aad.length >>> 8) & 0xff, aad.length & 0xff), aad)
    : new Uint8Array()
  let mac: Uint8Array = new Uint8Array(16)
  for (const block of [b0, ...paddedBlocks(authData), ...paddedBlocks(plaintext)]) {
    mac = await aesBlock(key, xorBlock(mac, block))
  }

  const s0 = await aesBlock(key, counterBlock(nonce, 0))
  const ciphertext = new Uint8Array(plaintext.length)
  for (let offset = 0, counter = 1; offset < plaintext.length; offset += 16, counter += 1) {
    const stream = await aesBlock(key, counterBlock(nonce, counter))
    const length = Math.min(16, plaintext.length - offset)
    for (let i = 0; i < length; i += 1) ciphertext[offset + i] = plaintext[offset + i] ^ stream[i]
  }
  const tag = Uint8Array.from(mac.slice(0, 4), (byte, index) => byte ^ s0[index])
  return concatBytes(ciphertext, tag)
}
