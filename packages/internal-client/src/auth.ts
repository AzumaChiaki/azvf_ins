import { createPublicKey, verify as verifySignature, type KeyObject } from 'node:crypto'
import { decodeProtectedHeader, jwtVerify } from 'jose'
import {
  SUPPORTED_CLIENT_CONTEXT_VERSION,
  normalizeDeviceIdentifier,
  type InstallerAuthorizationClaims,
} from '@azvf/contract'

export type InstallTier = 'basic' | 'standard' | 'premium' | 'internal'

export interface JwtVerifierConfig {
  jwtEd25519PublicKey: () => string | undefined
  jwtEd25519PublicKeyB64: () => string | undefined
  jwtEd25519PublicKeysJson: () => string | undefined
  jwtKeyId: () => string | undefined
  jwtIssuer: () => string
  jwtAudience: () => string
  allowLegacyHs256: boolean
  jwtLegacySecret: () => Uint8Array
  jwtMaxAgeSeconds: number
  jwtClockToleranceSeconds: number
}

export interface VerifiedAuthToken extends InstallerAuthorizationClaims {
  installTier: InstallTier
}

export type AuthorizationVersionErrorCode =
  | 'authorization_version_outdated'
  | 'authorization_client_upgrade_required'

export class AuthorizationVersionError extends Error {
  constructor(
    public readonly code: AuthorizationVersionErrorCode,
    public readonly receivedVersion: number,
    public readonly supportedVersion = SUPPORTED_CLIENT_CONTEXT_VERSION,
  ) {
    super(code === 'authorization_version_outdated'
      ? '授权版本已升级，请重新登录'
      : '授权版本高于当前客户端支持范围，请升级客户端')
    this.name = 'AuthorizationVersionError'
  }
}

export function validateClientContextVersion(value: unknown): number {
  const received = Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : 0
  if (received < SUPPORTED_CLIENT_CONTEXT_VERSION) {
    throw new AuthorizationVersionError('authorization_version_outdated', received)
  }
  if (received > SUPPORTED_CLIENT_CONTEXT_VERSION) {
    throw new AuthorizationVersionError('authorization_client_upgrade_required', received)
  }
  return received
}

function spkiFromBase64(value: string): string {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error('JWT_ED25519_PUBLIC_KEY_B64 不是有效 base64')
  }
  const body = value.match(/.{1,64}/g)?.join('\n') ?? value
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----`
}

function installTier(payload: Record<string, unknown>): InstallTier {
  const value = payload.tier
  if (value === 'basic' || value === 'standard' || value === 'premium' || value === 'internal') return value
  throw new Error('授权令牌包含无效的安装等级')
}

function validatePayload(payload: Record<string, unknown>): asserts payload is Record<string, unknown> & InstallerAuthorizationClaims {
  validateClientContextVersion(payload.clientContextVersion)
  if (typeof payload.sub !== 'string' || payload.sub.length < 1 || payload.sub.length > 256) throw new Error('授权主体无效')
  if (typeof payload.jti !== 'string' || payload.jti.length < 16 || payload.jti.length > 256) throw new Error('授权 jti 无效')
  if (typeof payload.entitlementId !== 'string' || payload.entitlementId.length < 1 || payload.entitlementId.length > 256) {
    throw new Error('授权记录无效')
  }
  if (!Array.isArray(payload.resourceIds) || payload.resourceIds.length < 1 || payload.resourceIds.length > 1_000) {
    throw new Error('授权资源列表无效')
  }
  if (payload.resourceIds.some((id) => typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(id))) {
    throw new Error('授权资源 ID 无效')
  }
  if (new Set(payload.resourceIds).size !== payload.resourceIds.length) throw new Error('授权资源 ID 不允许重复')
  if (payload.deviceAddr !== undefined) {
    if (typeof payload.deviceAddr !== 'string') throw new Error('授权设备绑定无效')
    try { normalizeDeviceIdentifier(payload.deviceAddr) } catch { throw new Error('授权设备绑定无效') }
  }
  // 签发方可以在令牌里附带自己的业务字段（渠道、SKU 等）。安装器不读也不校验
  // 它们——安装决策只用上面这几项。JWT 允许未知字段，多出来的一律忽略。
  if (!Number.isSafeInteger(payload.installConcurrency) || Number(payload.installConcurrency) < 1 || Number(payload.installConcurrency) > 32) {
    throw new Error('授权安装并发无效')
  }
}

export class AuthTokenVerifier {
  private readonly publicKeys = new Map<string, KeyObject>()
  private keySources?: ReadonlyMap<string, string>

  constructor(private readonly config: JwtVerifierConfig) {}

  private sources(): ReadonlyMap<string, string> {
    if (this.keySources) return this.keySources
    const result = new Map<string, string>()
    const json = this.config.jwtEd25519PublicKeysJson()
    if (json) {
      let parsed: unknown
      try { parsed = JSON.parse(json) } catch { throw new Error('JWT_ED25519_PUBLIC_KEYS_JSON 不是有效 JSON') }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('JWT 公钥环必须是对象')
      const entries = Object.entries(parsed as Record<string, unknown>)
      if (entries.length < 1 || entries.length > 32) throw new Error('JWT 公钥环必须包含 1..32 个密钥')
      for (const [kid, source] of entries) {
        if (!/^[A-Za-z0-9._-]{1,128}$/.test(kid) || typeof source !== 'string' || source.length > 16_384) {
          throw new Error('JWT 公钥环条目无效')
        }
        result.set(kid, source.replaceAll('\\n', '\n'))
      }
    } else {
      const kid = this.config.jwtKeyId()
      const source = this.config.jwtEd25519PublicKey() ?? this.config.jwtEd25519PublicKeyB64()
      if (!kid || !source) {
        throw new Error('必须配置 JWT_KEY_ID 与 JWT Ed25519 公钥（或 JWT_ED25519_PUBLIC_KEYS_JSON 公钥环）')
      }
      result.set(kid, source)
    }
    this.keySources = result
    return result
  }

  private publicKey(keyId: string): KeyObject {
    const cached = this.publicKeys.get(keyId)
    if (cached) return cached
    const source = this.sources().get(keyId)
    if (!source) throw new Error('授权令牌 kid 不受信任')
    const pem = source.includes('BEGIN PUBLIC KEY') ? source : spkiFromBase64(source)
    const key = createPublicKey(pem)
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('JWT 公钥必须是 Ed25519')
    this.publicKeys.set(keyId, key)
    return key
  }

  async verify(token: string): Promise<VerifiedAuthToken> {
    if (typeof token !== 'string' || token.length < 32 || token.length > 16_384) throw new Error('授权令牌格式无效')
    const header = decodeProtectedHeader(token)

    let key: Uint8Array | KeyObject
    if (header.alg === 'EdDSA') {
      if (header.typ !== 'JWT') throw new Error('授权令牌 typ 无效')
      if (typeof header.kid !== 'string') throw new Error('授权令牌缺少 kid')
      key = this.publicKey(header.kid)
    } else if (header.alg === 'HS256' && this.config.allowLegacyHs256) {
      if (this.config.jwtKeyId() && header.kid !== this.config.jwtKeyId()) throw new Error('旧版授权令牌 kid 无效')
      key = this.config.jwtLegacySecret()
    } else {
      throw new Error('授权令牌算法不受信任')
    }

    const { payload } = await jwtVerify(token, key, {
      algorithms: [header.alg],
      issuer: this.config.jwtIssuer(),
      audience: this.config.jwtAudience(),
      requiredClaims: ['sub', 'jti', 'iat', 'exp'],
      maxTokenAge: this.config.jwtMaxAgeSeconds,
      clockTolerance: this.config.jwtClockToleranceSeconds,
    })
    validatePayload(payload)
    return { ...(payload as unknown as InstallerAuthorizationClaims), installTier: installTier(payload) }
  }

  async verifyResourceManifest(manifestHash: string, signature: string, keyId: string): Promise<boolean> {
    if (!/^[a-f0-9]{64}$/.test(manifestHash) || !/^[A-Za-z0-9_-]{86}$/.test(signature)) return false
    const decoded = Buffer.from(signature, 'base64url')
    if (decoded.length !== 64) return false
    try {
      return verifySignature(null, Buffer.from(manifestHash, 'hex'), this.publicKey(keyId), decoded)
    } catch {
      return false
    }
  }
}
