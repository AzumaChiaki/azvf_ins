import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'
import {
  DEFAULT_CHUNK_SIZE,
  DEFAULT_TOKEN_AUDIENCE,
  DEFAULT_TOKEN_ISSUER,
  MAX_CHUNK_PAYLOAD,
  ResType,
  SUPPORTED_CLIENT_CONTEXT_VERSION,
  WIRE_PROTOCOL_VERSION,
  canonicalResourceManifestV2,
  normalizeDeviceIdentifier,
} from './index.js'

type WireVectors = {
  fixtureVersion: number
  wireProtocolVersion: number
  token: {
    defaultIssuer: string
    defaultAudience: string
    supportedClientContextVersion: number
    clientContextCases: { missing: number; low: number; current: number }
  }
  manifest: {
    resource: Parameters<typeof canonicalResourceManifestV2>[0]
    chunkHashes: string[]
    canonical: string
    sha256: string
  }
  devices: {
    valid: Array<{ input: string; normalized: string }>
    invalid: string[]
  }
  resTypes: { watchface: number; firmware: number; quickApp: number }
  limits: { defaultChunkSize: number; maximumChunkPayload: number; minimumPersistedChunkSize: number }
}

async function vectors(): Promise<WireVectors> {
  const path = new URL('../test/vectors/wire-v3.json', import.meta.url)
  return JSON.parse(await readFile(path, 'utf8')) as WireVectors
}

describe('wire protocol golden vectors', () => {
  it('pins protocol, token defaults, enums and size limits', async () => {
    const fixture = await vectors()
    expect(fixture.fixtureVersion).toBe(1)
    expect(WIRE_PROTOCOL_VERSION).toBe(fixture.wireProtocolVersion)
    expect(DEFAULT_TOKEN_ISSUER).toBe(fixture.token.defaultIssuer)
    expect(DEFAULT_TOKEN_AUDIENCE).toBe(fixture.token.defaultAudience)
    expect(SUPPORTED_CLIENT_CONTEXT_VERSION).toBe(fixture.token.supportedClientContextVersion)
    expect(fixture.token.clientContextCases).toEqual({ missing: 0, low: 0, current: 1 })
    expect(ResType).toMatchObject({
      Watchface: fixture.resTypes.watchface,
      Firmware: fixture.resTypes.firmware,
      QuickApp: fixture.resTypes.quickApp,
    })
    expect(DEFAULT_CHUNK_SIZE).toBe(fixture.limits.defaultChunkSize)
    expect(MAX_CHUNK_PAYLOAD).toBe(fixture.limits.maximumChunkPayload)
    expect(fixture.limits.minimumPersistedChunkSize).toBe(16_384)
  })

  it('pins the fixture file itself for cross-repository comparison', async () => {
    const fixturePath = new URL('../test/vectors/wire-v3.json', import.meta.url)
    const checksumPath = new URL('../test/vectors/wire-vectors.sha256', import.meta.url)
    const fixtureBytes = await readFile(fixturePath)
    const checksum = (await readFile(checksumPath, 'utf8')).trim()
    expect(checksum).toBe(`${createHash('sha256').update(fixtureBytes).digest('hex')}  wire-v3.json`)
  })

  it('reproduces the canonical manifest bytes and digest', async () => {
    const fixture = await vectors()
    const canonical = canonicalResourceManifestV2(fixture.manifest.resource, fixture.manifest.chunkHashes)
    expect(canonical).toBe(fixture.manifest.canonical)
    expect(createHash('sha256').update(canonical).digest('hex')).toBe(fixture.manifest.sha256)
  })

  it('normalizes the same device identifiers and rejects the same invalid cases', async () => {
    const fixture = await vectors()
    for (const item of fixture.devices.valid) expect(normalizeDeviceIdentifier(item.input)).toBe(item.normalized)
    for (const input of fixture.devices.invalid) expect(() => normalizeDeviceIdentifier(input)).toThrow()
  })
})
