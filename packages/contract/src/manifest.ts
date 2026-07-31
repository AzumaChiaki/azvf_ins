import type { ResourceMeta } from './types.js'

export type ResourceManifestV2Fields = Pick<
  ResourceMeta,
  | 'id'
  | 'name'
  | 'resType'
  | 'packageName'
  | 'size'
  | 'sha256'
  | 'md5'
  | 'watchfaceId'
  | 'version'
  | 'chunkSize'
  | 'totalChunks'
>

/**
 * The byte-for-byte canonical manifest covered by the Console Ed25519
 * signature. Keeping this serializer in the shared package prevents either
 * service from silently changing property names or insertion order.
 */
export function canonicalResourceManifestV2(
  resource: ResourceManifestV2Fields,
  chunkHashes: readonly string[],
): string {
  return JSON.stringify({
    formatVersion: 2,
    id: resource.id,
    name: resource.name,
    resType: resource.resType,
    packageName: resource.packageName ?? null,
    size: resource.size,
    sha256: resource.sha256,
    md5: resource.md5,
    watchfaceId: resource.watchfaceId ?? null,
    resourceVersion: resource.version,
    chunkSize: resource.chunkSize,
    totalChunks: resource.totalChunks,
    chunkHashes: [...chunkHashes],
  })
}

/** Browser-safe SHA-256 of the exact canonical manifest bytes. */
export async function resourceManifestHashV2(
  resource: ResourceManifestV2Fields,
  chunkHashes: readonly string[],
): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalResourceManifestV2(resource, chunkHashes))
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes as BufferSource))
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('')
}
