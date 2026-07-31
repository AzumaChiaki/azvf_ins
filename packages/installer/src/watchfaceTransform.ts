import { createHash, randomInt } from 'node:crypto'
import {
  WATCHFACE_HEADER_LENGTH,
  createWatchfacePatch,
  patchWatchfaceChunk,
  type SignedResourceMeta,
  type WatchfaceInstallTransform,
} from '@azvf/contract'
import { fetchPlaintextChunks } from '@azvf/internal-client'
import type { ResourceCapabilityAccess } from '@azvf/internal-client'

export function generateWatchfaceInstallId(): string {
  let id: string
  do id = randomInt(1_000_000_000_000).toString().padStart(12, '0')
  while (id === '000000000000')
  return id
}

/**
 * 设备收到的是改写后的字节,因此 WatchFace Prepare 与 MASS 传输阶段声明的 MD5
 * 必须按改写后的内容计算。此处流式计算,不在内存中保留完整资源。
 */
export async function createWatchfaceInstallTransform(
  meta: SignedResourceMeta,
  access: ResourceCapabilityAccess,
  id = generateWatchfaceInstallId(),
): Promise<WatchfaceInstallTransform> {
  if (meta.resType !== 16) throw new Error('只有表盘资源可以创建 ID 改写参数')
  const source = fetchPlaintextChunks(meta.id, meta, access)
  const md5 = createHash('md5')
  let patch: Omit<WatchfaceInstallTransform, 'md5'> | undefined
  let fileOffset = 0
  try {
    for await (const chunk of source) {
      if (!patch) {
        if (fileOffset !== 0 || chunk.length < WATCHFACE_HEADER_LENGTH) {
          throw new Error('表盘首个认证分片不足以包含 ID 字段')
        }
        patch = createWatchfacePatch(chunk, id)
      }
      md5.update(patchWatchfaceChunk(chunk, fileOffset, patch))
      fileOffset += chunk.length
    }
  } finally {
    await source.return?.(undefined).catch(() => undefined)
  }
  if (!patch || fileOffset !== meta.size) throw new Error('表盘资源流长度不一致')
  return { ...patch, md5: md5.digest('hex') }
}
