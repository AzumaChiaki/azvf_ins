import { describe, expect, it } from 'vitest'
import { ResType } from './types.js'
import { canonicalResourceManifestV2, resourceManifestHashV2 } from './manifest.js'

const resource = {
  id: 'resource-1',
  name: 'demo',
  resType: ResType.Firmware,
  size: 3,
  sha256: 'ab'.repeat(32),
  md5: 'cd'.repeat(16),
  version: '2.0.0',
  chunkSize: 16_384,
  totalChunks: 1,
}
const chunkHashes = ['ef'.repeat(32)]

describe('canonical resource manifest v2', () => {
  it('uses the fixed protocol property names, nulls and insertion order', () => {
    expect(canonicalResourceManifestV2(resource, chunkHashes)).toBe(JSON.stringify({
      formatVersion: 2,
      id: 'resource-1',
      name: 'demo',
      resType: 32,
      packageName: null,
      size: 3,
      sha256: 'ab'.repeat(32),
      md5: 'cd'.repeat(16),
      watchfaceId: null,
      resourceVersion: '2.0.0',
      chunkSize: 16_384,
      totalChunks: 1,
      chunkHashes: ['ef'.repeat(32)],
    }))
  })

  it('changes the browser-verifiable digest when installation semantics change', async () => {
    const original = await resourceManifestHashV2(resource, chunkHashes)
    await expect(resourceManifestHashV2({ ...resource, resType: ResType.QuickApp }, chunkHashes))
      .resolves.not.toBe(original)
    await expect(resourceManifestHashV2(resource, ['00'.repeat(32)])).resolves.not.toBe(original)
  })
})
