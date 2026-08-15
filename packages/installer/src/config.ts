import { createHash } from 'node:crypto'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER } from '@azvf/contract'
import { createTrustedRegionSource } from './trustedRegion.js'

function required(name: string): string {
  const value = process.env[name]?.trim()
  if (!value) throw new Error(`缺少环境变量 ${name}（参考 .env.example）`)
  return value
}

function optional(name: string): string | undefined {
  return process.env[name]?.trim() || undefined
}

function bool(name: string, fallback: boolean): boolean {
  const value = optional(name)
  if (value === undefined) return fallback
  if (value === 'true') return true
  if (value === 'false') return false
  throw new Error(`${name} 必须是 true 或 false`)
}

function integer(name: string, fallback: number, min: number, max: number): number {
  const raw = optional(name)
  const value = raw === undefined ? fallback : Number(raw)
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} 必须是 ${min}..${max} 的整数`)
  }
  return value
}

function number(name: string, fallback: number, min: number, max: number): number {
  const raw = optional(name)
  const value = raw === undefined ? fallback : Number(raw)
  if (!Number.isFinite(value) || value < min || value > max) throw new Error(`${name} 必须是 ${min}..${max} 的数字`)
  return value
}

function origins(): ReadonlySet<string> {
  const defaults = process.env.NODE_ENV === 'production'
    ? []
    : ['http://localhost:5002', 'http://127.0.0.1:5002']
  const values = (optional('CORS_ORIGINS')?.split(',') ?? defaults).map((entry) => entry.trim()).filter(Boolean)
  const normalized = values.map((entry) => {
    if (entry === '*') throw new Error('CORS_ORIGINS 禁止使用通配符')
    const url = new URL(entry)
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
      throw new Error(`CORS_ORIGINS 只允许填写 origin: ${entry}`)
    }
    if (process.env.NODE_ENV === 'production' && url.protocol !== 'https:') {
      throw new Error(`生产 CORS_ORIGINS 必须使用 HTTPS: ${entry}`)
    }
    return url.origin
  })
  return new Set(normalized)
}

function signingKey(): Buffer {
  const encoded = optional('INTERNAL_SIGNING_KEY_B64')
  if (encoded && (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded) || encoded.length % 4 !== 0)) {
    throw new Error('INTERNAL_SIGNING_KEY_B64 不是有效 base64')
  }
  const key = encoded
    ? Buffer.from(encoded, 'base64')
    : createHash('sha256').update(required('INTERNAL_SIGNING_KEY'), 'utf8').digest()
  if (key.length < 32) throw new Error('INTERNAL_SIGNING_KEY 必须至少 32 字节')
  return key
}

/**
 * 安装页被要求回到核销页时的跳转目标（X-AZVF-Reauth）。开源版与生产部署只差
 * 这一项运行时配置，因此不得硬编码站点地址。
 *
 * 只接受同源绝对路径或完整 HTTP(S) URL；`//host` 这类协议相对写法会被浏览器
 * 当成跨站跳转，一律拒绝。
 */
function reauthTarget(): string {
  const raw = (process.env.REDEEM_URL ?? '/').trim()
  if (raw.startsWith('/')) {
    if (raw.startsWith('//')) throw new Error('REDEEM_URL 不允许协议相对地址')
    return raw
  }
  const url = new URL(raw)
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new Error('REDEEM_URL 必须是无凭据的 HTTP(S) URL 或同源绝对路径')
  }
  return url.toString()
}

function consoleUrl(): URL {
  const url = new URL(process.env.CONSOLE_URL ?? 'http://127.0.0.1:4001')
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error('CONSOLE_URL 必须是无凭据、query 和 fragment 的 HTTP(S) URL')
  }
  if (url.pathname !== '/' && !url.pathname.endsWith('/')) url.pathname += '/'
  if (process.env.NODE_ENV === 'production' && url.protocol !== 'https:' && !bool('ALLOW_INSECURE_INTERNAL_HTTP', false)) {
    throw new Error('生产环境 CONSOLE_URL 必须使用 HTTPS（仅隔离网络调试可显式开启 ALLOW_INSECURE_INTERNAL_HTTP）')
  }
  return url
}

export type InstallTier = 'basic' | 'standard' | 'premium' | 'internal'

const dataDir = resolve(process.env.INSTALLER_DATA_DIR ?? './data/installer')
const configuredDbPath = process.env.INSTALLER_DB_PATH ?? `${dataDir}/installer.sqlite`

export const config = {
  env: process.env.NODE_ENV ?? 'development',
  port: integer('PORT', 4002, 1, 65535),
  host: process.env.HOST ?? '127.0.0.1',
  trustProxy: bool('TRUST_PROXY', false),
  requireHttps: bool('REQUIRE_HTTPS', process.env.NODE_ENV === 'production'),
  corsOrigins: origins(),
  consoleUrl: consoleUrl(),
  redeemUrl: reauthTarget(),
  internalSigningKey: signingKey,
  internalClientId: process.env.INTERNAL_CLIENT_ID?.trim() || 'installer',
  internalKeyId: process.env.INTERNAL_KEY_ID ?? 'v1',
  internalClockSkewMs: integer('INTERNAL_CLOCK_SKEW_MS', 30_000, 1_000, 300_000),
  internalRequestTimeoutMs: integer('INTERNAL_REQUEST_TIMEOUT_MS', 30_000, 1_000, 300_000),
  internalStreamIdleTimeoutMs: integer('INTERNAL_STREAM_IDLE_TIMEOUT_MS', 60_000, 5_000, 600_000),
  // 下游 BLE 回压期间上游读取的空闲窗口上限;窗口随会话剩余租约动态伸缩,
  // 无回压时仍以 internalStreamIdleTimeoutMs 快速失败。见 streamWindow.ts。
  installStreamStallMaxMs: integer('INSTALL_STREAM_STALL_MAX_MS', 300_000, 60_000, 900_000),
  // A redeemed installation request always gets at least ten minutes to move
  // from authorization into the encrypted stream, even on older deployments
  // that still carry the former 300-second environment value.
  sessionTtlSeconds: Math.max(600, integer('SESSION_TTL', 600, 30, 3_600)),
  installLeaseTtlSeconds: integer('INSTALL_LEASE_TTL', 180, 60, 7_200),
  installMaxDurationSeconds: integer('INSTALL_MAX_DURATION', 3_600, 300, 28_800),
  maxResourceBytes: integer('MAX_RESOURCE_BYTES', 1_073_741_824, 1_024, 2_147_483_647),
  maxMetaBytes: integer('MAX_META_BYTES', 8_388_608, 65_536, 67_108_864),
  decoyRatio: number('DECOY_RATIO', 0.1, 0.05, 0.5),
  globalConcurrency: integer('INSTALL_GLOBAL_CONCURRENCY', 32, 1, 1_024),
  ipConcurrency: integer('INSTALL_IP_CONCURRENCY', 8, 1, 1_024),
  entitlementConcurrency: integer('INSTALL_ENTITLEMENT_CONCURRENCY', 1, 1, 64),
  tierConcurrency: {
    basic: integer('INSTALL_TIER_BASIC', 1, 1, 64),
    standard: integer('INSTALL_TIER_STANDARD', 2, 1, 64),
    premium: integer('INSTALL_TIER_PREMIUM', 4, 1, 64),
    internal: integer('INSTALL_TIER_INTERNAL', 8, 1, 64),
  } satisfies Record<InstallTier, number>,
  dataDir,
  leaseDbPath: configuredDbPath === ':memory:' ? configuredDbPath : resolve(configuredDbPath),
  serveStatic: bool('SERVE_STATIC', true),
  staticDir: resolve(process.env.INSTALLER_STATIC_DIR ?? fileURLToPath(new URL('../dist-web', import.meta.url))),
  maxBodyBytes: integer('MAX_BODY_BYTES', 32_768, 4_096, 1_048_576),
  apiRateLimitPerMinute: integer('API_RATE_LIMIT_PER_MINUTE', 120, 10, 100_000),
  // Disabled by default. The header is accepted only when the raw TCP peer is
  // in this source's explicit proxy CIDR allowlist.
  trustedRegionSource: createTrustedRegionSource(
    optional('TRUSTED_REGION_HEADER'),
    optional('TRUSTED_REGION_PROXY_CIDRS'),
    optional('TRUSTED_REGION_EDGE_PEER_HEADER'),
    optional('TRUSTED_REGION_EDGE_CIDRS'),
  ),
  sessionRateLimitPerMinute: integer('SESSION_RATE_LIMIT_PER_MINUTE', 10, 1, 10_000),
  jwtEd25519PublicKey: () => optional('JWT_ED25519_PUBLIC_KEY')?.replaceAll('\\n', '\n'),
  jwtEd25519PublicKeyB64: () => optional('JWT_ED25519_PUBLIC_KEY_B64'),
  jwtEd25519PublicKeysJson: () => optional('JWT_ED25519_PUBLIC_KEYS_JSON'),
  jwtKeyId: () => optional('JWT_KEY_ID'),
  jwtIssuer: () => optional('TOKEN_ISSUER') ?? DEFAULT_TOKEN_ISSUER,
  jwtAudience: () => optional('TOKEN_AUDIENCE') ?? DEFAULT_TOKEN_AUDIENCE,
  allowLegacyHs256: bool('JWT_ALLOW_LEGACY_HS256', false),
  jwtLegacySecret: () => new TextEncoder().encode(required('JWT_SECRET')),
  jwtMaxAgeSeconds: integer('JWT_MAX_AGE_SECONDS', 600, 30, 3_600),
  jwtClockToleranceSeconds: integer('JWT_CLOCK_TOLERANCE_SECONDS', 5, 0, 60),
}
