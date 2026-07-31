// 同构 SHA-256
import { toHex } from '@azvf/contract'

const subtle = globalThis.crypto.subtle

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', bytes as BufferSource))
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  return toHex(await sha256(bytes))
}
