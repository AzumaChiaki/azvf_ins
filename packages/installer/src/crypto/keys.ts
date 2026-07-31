// Session master key + asymmetric envelope.
//
// A fresh 256-bit HKDF master key is generated for every transport session. It
// is only used to derive purpose-specific keys; it is never used directly for
// encryption. The browser creates an ephemeral RSA-OAEP key pair and the
// server wraps the master key to that public key.
import { fromBase64, toBase64 } from '@azvf/contract'

const subtle = globalThis.crypto.subtle

const MASTER_KEY_BYTES = 32
const HKDF_SALT = new TextEncoder().encode('AZVF transport protocol v2 / HKDF-SHA-256')
const OAEP_LABEL = new TextEncoder().encode('AZVF/v2/session-master-key')
// HKDF CryptoKeys are required by WebCrypto to be non-exportable. Server-side
// keys retain their original random material in a private weak map solely so
// it can be placed into the RSA-OAEP envelope. Client-unwrapped keys are never
// registered here and therefore cannot be exported through this module.
const serverMasterMaterial = new WeakMap<CryptoKey, Uint8Array>()

export interface SessionCryptoKeys {
  /** AES-256-GCM content-encryption key. */
  gcmKey: CryptoKey
  /** AES-256-CTR content-encryption key. */
  ctrKey: CryptoKey
  /** HMAC-SHA-256 Encrypt-then-MAC key for the CTR suite. */
  ctrMacKey: CryptoKey
  /** HMAC-SHA-256 key used to choose the cipher suite for each transport frame. */
  selectionKey: CryptoKey
  /** HMAC-SHA-256 key authenticating the encrypted real/decoy control envelope. */
  controlKey: CryptoKey
}

async function deriveAesKey(
  masterKey: CryptoKey,
  label: string,
  algorithm: 'AES-GCM' | 'AES-CTR',
): Promise<CryptoKey> {
  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: HKDF_SALT as BufferSource,
      info: new TextEncoder().encode(`AZVF/v2/${label}`) as BufferSource,
    },
    masterKey,
    { name: algorithm, length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function deriveHmacKey(masterKey: CryptoKey, label: string): Promise<CryptoKey> {
  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: HKDF_SALT as BufferSource,
      info: new TextEncoder().encode(`AZVF/v2/${label}`) as BufferSource,
    },
    masterKey,
    { name: 'HMAC', hash: 'SHA-256', length: 256 },
    false,
    ['sign', 'verify'],
  )
}

/**
 * Derive independent, non-exportable protocol keys from a session master key.
 * Labels provide domain separation between suites and control functions.
 */
export async function deriveSessionKeys(masterKey: CryptoKey): Promise<SessionCryptoKeys> {
  if (masterKey.algorithm.name !== 'HKDF') throw new Error('session master key must be an HKDF key')
  const [gcmKey, ctrKey, ctrMacKey, selectionKey, controlKey] = await Promise.all([
    deriveAesKey(masterKey, 'suite/aes-256-gcm', 'AES-GCM'),
    deriveAesKey(masterKey, 'suite/aes-256-ctr', 'AES-CTR'),
    deriveHmacKey(masterKey, 'suite/aes-256-ctr/hmac-sha-256'),
    deriveHmacKey(masterKey, 'selection/hmac-sha-256'),
    deriveHmacKey(masterKey, 'control/hmac-sha-256'),
  ])
  return { gcmKey, ctrKey, ctrMacKey, selectionKey, controlKey }
}

/** Generate an exportable 256-bit session master key for server-side wrapping. */
export async function generateSessionKey(): Promise<CryptoKey> {
  const raw = new Uint8Array(MASTER_KEY_BYTES)
  globalThis.crypto.getRandomValues(raw)
  try {
    return await importSessionKeyRaw(raw)
  } finally {
    raw.fill(0)
  }
}

/** Import exactly 32 raw bytes as an HKDF-SHA-256 session master key. */
export async function importSessionKeyRaw(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== MASTER_KEY_BYTES) throw new Error('session master key must be exactly 32 bytes')
  const key = await subtle.importKey('raw', raw as BufferSource, 'HKDF', false, ['deriveKey'])
  serverMasterMaterial.set(key, raw.slice())
  return key
}

export async function exportSessionKeyRaw(key: CryptoKey): Promise<Uint8Array> {
  if (key.algorithm.name !== 'HKDF') throw new Error('session master key must be an HKDF key')
  const raw = serverMasterMaterial.get(key)
  if (!raw) throw new Error('client session master keys are not exportable')
  return raw.slice()
}

// ---- Asymmetric envelope (RSA-OAEP / SHA-256) ----

export interface SessionKeyPair {
  publicKey: CryptoKey
  /** Non-exportable private key, only usable for opening the OAEP envelope. */
  privateKey: CryptoKey
}

export async function generateSessionKeypair(): Promise<SessionKeyPair> {
  const pair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    false,
    ['encrypt', 'decrypt'],
  )
  return { publicKey: pair.publicKey, privateKey: pair.privateKey }
}

/** Export a browser public key as base64(SPKI). */
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  return toBase64(new Uint8Array(await subtle.exportKey('spki', publicKey)))
}

/** Import the browser's RSA-OAEP public key on the server. */
export async function importPublicKey(spkiB64: string): Promise<CryptoKey> {
  const key = await subtle.importKey('spki', fromBase64(spkiB64) as BufferSource, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, [
    'encrypt',
  ])
  const algorithm = key.algorithm as RsaHashedKeyAlgorithm
  const exponent = algorithm.publicExponent
  if (algorithm.modulusLength < 2048 || algorithm.modulusLength > 4096
    || exponent.length !== 3 || exponent[0] !== 1 || exponent[1] !== 0 || exponent[2] !== 1) {
    throw new Error('RSA-OAEP public key must use a 2048..4096-bit modulus and exponent 65537')
  }
  return key
}

/** Wrap an HKDF session master key with RSA-OAEP/SHA-256. */
export async function wrapSessionKey(publicKey: CryptoKey, sessionKey: CryptoKey): Promise<string> {
  if (sessionKey.algorithm.name !== 'HKDF') throw new Error('session master key must be an HKDF key')
  const raw = serverMasterMaterial.get(sessionKey)
  if (!raw) throw new Error('session master key material is unavailable for server-side wrapping')
  try {
    const wrapped = await subtle.encrypt({ name: 'RSA-OAEP', label: OAEP_LABEL as BufferSource }, publicKey, raw as BufferSource)
    return toBase64(new Uint8Array(wrapped))
  } finally {
    // The server keeps only the independently derived suite keys after the
    // one-time envelope is created. Retaining exportable master material for
    // the lifetime of an installation session would unnecessarily widen the
    // impact of a memory disclosure.
    serverMasterMaterial.delete(sessionKey)
    raw.fill(0)
  }
}

/** Unwrap to a non-exportable HKDF key. No content cipher key is exposed. */
export async function unwrapSessionKey(privateKey: CryptoKey, wrappedB64: string): Promise<CryptoKey> {
  const raw = new Uint8Array(
    await subtle.decrypt(
      { name: 'RSA-OAEP', label: OAEP_LABEL as BufferSource },
      privateKey,
      fromBase64(wrappedB64) as BufferSource,
    ),
  )
  if (raw.length !== MASTER_KEY_BYTES) {
    raw.fill(0)
    throw new Error('invalid unwrapped session master key length')
  }
  // Deliberately bypass importSessionKeyRaw: client keys must not be registered
  // in serverMasterMaterial or be exportable through exportSessionKeyRaw.
  try {
    return await subtle.importKey('raw', raw as BufferSource, 'HKDF', false, ['deriveKey'])
  } finally {
    raw.fill(0)
  }
}
