import { generateKeyPairSync, sign } from 'node:crypto'
import { SignJWT } from 'jose'
import { describe, expect, it } from 'vitest'
import { TOKEN_AUDIENCE, TOKEN_ISSUER } from '@azvf/contract'
import { AuthTokenVerifier, AuthorizationVersionError } from '@azvf/internal-client/auth'
import { config } from './config.js'

describe('AuthTokenVerifier', () => {
  it('accepts only a valid EdDSA token and preserves the signed tier', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    process.env.JWT_ED25519_PUBLIC_KEY_B64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
    process.env.JWT_KEY_ID = 'test-key'
    const now = Math.floor(Date.now() / 1_000)
    // grant / sku 是签发方的业务字段，不在安装器契约里。这里刻意保留，验证
    // 安装器对未知 claims 一律放行——签发方可以自由附带，安装器不读也不校验。
    const token = await new SignJWT({
      grant: 'cardkey', sku: 'test', resourceIds: ['resource'], entitlementId: 'entitlement', tier: 'premium',
      installConcurrency: 4, clientContextVersion: 2,
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: 'test-key' })
      .setIssuer(TOKEN_ISSUER)
      .setAudience(TOKEN_AUDIENCE)
      .setSubject('user')
      .setJti('unique-jti-value-1234')
      .setIssuedAt(now)
      .setExpirationTime(now + 60)
      .sign(privateKey)

    const verifier = new AuthTokenVerifier(config)
    const verified = await verifier.verify(token)
    expect(verified.installTier).toBe('premium')
    expect(verified.resourceIds).toEqual(['resource'])

    const manifestHash = 'ab'.repeat(32)
    const manifestSignature = sign(null, Buffer.from(manifestHash, 'hex'), privateKey).toString('base64url')
    await expect(verifier.verifyResourceManifest(manifestHash, manifestSignature, 'test-key')).resolves.toBe(true)
    await expect(verifier.verifyResourceManifest('cd'.repeat(32), manifestSignature, 'test-key')).resolves.toBe(false)
    await expect(verifier.verifyResourceManifest(manifestHash, manifestSignature, 'old-key')).resolves.toBe(false)

    const missingConcurrency = await new SignJWT({
      grant: 'cardkey', sku: 'test', resourceIds: ['resource'], entitlementId: 'entitlement', tier: 'premium',
      clientContextVersion: 2,
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: 'test-key' })
      .setIssuer(TOKEN_ISSUER).setAudience(TOKEN_AUDIENCE).setSubject('user')
      .setJti('missing-concurrency-jti').setIssuedAt(now).setExpirationTime(now + 60).sign(privateKey)
    await expect(verifier.verify(missingConcurrency)).rejects.toThrow('授权安装并发无效')

    const validClaims = {
      resourceIds: ['resource-a'], entitlementId: 'entitlement',
      tier: 'basic', installConcurrency: 1, clientContextVersion: 2,
    }
    const malformed: Array<{ claims: Record<string, unknown>; message: string }> = [
      { claims: { ...validClaims, resourceIds: ['resource-a', 'resource-a'] }, message: '不允许重复' },
      { claims: { ...validClaims, deviceAddr: 1234 }, message: '授权设备绑定无效' },
      { claims: { ...validClaims, deviceAddr: 'AA:BB:CC' }, message: '授权设备绑定无效' },
    ]
    for (let index = 0; index < malformed.length; index++) {
      const candidate = await new SignJWT(malformed[index]!.claims)
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: 'test-key' })
        .setIssuer(TOKEN_ISSUER).setAudience(TOKEN_AUDIENCE).setSubject('user')
        .setJti(`malformed-claim-jti-${index}`).setIssuedAt(now).setExpirationTime(now + 60).sign(privateKey)
      await expect(verifier.verify(candidate)).rejects.toThrow(malformed[index]!.message)
    }
  })

  it('returns typed actions for old and future client-context versions', async () => {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    process.env.JWT_ED25519_PUBLIC_KEY_B64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
    process.env.JWT_KEY_ID = 'version-key'
    const now = Math.floor(Date.now() / 1_000)
    const token = async (clientContextVersion?: number) => new SignJWT({
      resourceIds: ['resource'], entitlementId: 'entitlement', tier: 'basic', installConcurrency: 1,
      ...(clientContextVersion === undefined ? {} : { clientContextVersion }),
    })
      .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: 'version-key' })
      .setIssuer(TOKEN_ISSUER).setAudience(TOKEN_AUDIENCE).setSubject('user')
      .setJti(`version-jti-${clientContextVersion ?? 'missing'}`).setIssuedAt(now).setExpirationTime(now + 60)
      .sign(privateKey)
    const verifier = new AuthTokenVerifier(config)
    for (const [version, code] of [
      [undefined, 'authorization_version_outdated'],
      [0, 'authorization_version_outdated'],
      [1, 'authorization_version_outdated'],
      [3, 'authorization_client_upgrade_required'],
    ] as const) {
      await expect(verifier.verify(await token(version))).rejects.toMatchObject({
        name: AuthorizationVersionError.name,
        code,
      })
    }
  })

  it('uses the deployment-configured issuer and audience', async () => {
    const previousIssuer = process.env.TOKEN_ISSUER
    const previousAudience = process.env.TOKEN_AUDIENCE
    const previousPublicKey = process.env.JWT_ED25519_PUBLIC_KEY_B64
    const previousKeyId = process.env.JWT_KEY_ID
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    process.env.TOKEN_ISSUER = 'custom-console'
    process.env.TOKEN_AUDIENCE = 'custom-installer'
    process.env.JWT_ED25519_PUBLIC_KEY_B64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
    process.env.JWT_KEY_ID = 'custom-key'
    try {
      const now = Math.floor(Date.now() / 1_000)
      const token = await new SignJWT({
        resourceIds: ['resource'], entitlementId: 'entitlement', tier: 'basic', installConcurrency: 1,
        clientContextVersion: 2,
      })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: 'custom-key' })
        .setIssuer('custom-console')
        .setAudience('custom-installer')
        .setSubject('user')
        .setJti('configured-binding-jti')
        .setIssuedAt(now)
        .setExpirationTime(now + 60)
        .sign(privateKey)
      await expect(new AuthTokenVerifier(config).verify(token)).resolves.toMatchObject({ sub: 'user' })

      const wrongAudience = await new SignJWT({
        resourceIds: ['resource'], entitlementId: 'entitlement', tier: 'basic', installConcurrency: 1,
        clientContextVersion: 2,
      })
        .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: 'custom-key' })
        .setIssuer('custom-console')
        .setAudience('azvf-installer')
        .setSubject('user')
        .setJti('wrong-audience-jti')
        .setIssuedAt(now)
        .setExpirationTime(now + 60)
        .sign(privateKey)
      await expect(new AuthTokenVerifier(config).verify(wrongAudience)).rejects.toThrow()
    } finally {
      if (previousIssuer === undefined) delete process.env.TOKEN_ISSUER
      else process.env.TOKEN_ISSUER = previousIssuer
      if (previousAudience === undefined) delete process.env.TOKEN_AUDIENCE
      else process.env.TOKEN_AUDIENCE = previousAudience
      if (previousPublicKey === undefined) delete process.env.JWT_ED25519_PUBLIC_KEY_B64
      else process.env.JWT_ED25519_PUBLIC_KEY_B64 = previousPublicKey
      if (previousKeyId === undefined) delete process.env.JWT_KEY_ID
      else process.env.JWT_KEY_ID = previousKeyId
    }
  })
})
