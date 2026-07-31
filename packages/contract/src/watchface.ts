/**
 * 小米 `.face` 表盘头部的 ID 字段读写。
 *
 * 字段位置独立取自 AzumaBox 打包器的 `patch_face_id_and_name`:该工具在
 * `.face` 产物的 `0x28` 处写入 ASCII 表盘 ID,在 `0x68` 处写入 64 字节表盘
 * 名称。本模块只处理 ID 字段。
 *
 * 实现按固定偏移直接读写,不扫描候选区间:ID 起始于 `0x28`,最长 12 字节,
 * 短于字段长度时其余字节为 NUL。
 */
import type { WatchfaceInstallTransform } from './types.js'

/** ID 字段起始偏移。 */
export const WATCHFACE_ID_OFFSET = 0x28
/** ID 字段容量;9 位 ID 写入后其余字节补 NUL。 */
export const WATCHFACE_ID_MAX_LENGTH = 12
/** 读取或改写 ID 所需的最小头部长度。 */
export const WATCHFACE_HEADER_LENGTH = WATCHFACE_ID_OFFSET + WATCHFACE_ID_MAX_LENGTH

const VALID_ID_LENGTHS = new Set([9, 12])
const ID_PATTERN = /^[A-Za-z0-9]{9}$|^[A-Za-z0-9]{12}$/

function isIdByte(byte: number): boolean {
  return (byte >= 0x30 && byte <= 0x39)
    || (byte >= 0x41 && byte <= 0x5a)
    || (byte >= 0x61 && byte <= 0x7a)
}

/**
 * 读取固定偏移处的表盘 ID。字段以 NUL 补齐,因此自 `0x28` 起连续取合法字节;
 * 取到的长度不是 9 或 12 时视为没有可用 ID。
 */
export function getWatchfaceId(header: Uint8Array): string | null {
  if (header.length < WATCHFACE_HEADER_LENGTH) return null
  let end = WATCHFACE_ID_OFFSET
  while (end < WATCHFACE_HEADER_LENGTH && isIdByte(header[end]!)) end++
  if (!VALID_ID_LENGTHS.has(end - WATCHFACE_ID_OFFSET)) return null
  return String.fromCharCode(...header.subarray(WATCHFACE_ID_OFFSET, end))
}

/**
 * 构造一次安装的 ID 改写参数。写入位置固定,与原 ID 长度无关。先要求头部本身
 * 带有合法 ID,这样固定偏移假设不成立时会直接失败,而不是静默写坏资源。
 */
export function createWatchfacePatch(
  header: Uint8Array,
  id: string,
): Omit<WatchfaceInstallTransform, 'md5'> {
  if (!ID_PATTERN.test(id)) throw new Error('表盘 ID 必须是 9 或 12 位字母数字')
  if (header.length < WATCHFACE_HEADER_LENGTH) throw new Error('表盘数据不足以包含 ID 字段')
  if (getWatchfaceId(header) === null) throw new Error('表盘头部 ID 字段无效,无法改写')
  return { id, idOffset: WATCHFACE_ID_OFFSET, fieldEnd: WATCHFACE_HEADER_LENGTH }
}

/** Return a copy only when this chunk overlaps the per-session rewrite range. */
export function patchWatchfaceChunk(
  chunk: Uint8Array,
  fileOffset: number,
  patch: Pick<WatchfaceInstallTransform, 'id' | 'idOffset' | 'fieldEnd'>,
): Uint8Array {
  if (!Number.isSafeInteger(fileOffset) || fileOffset < 0) throw new Error('表盘分片偏移非法')
  const chunkEnd = fileOffset + chunk.length
  if (chunkEnd <= patch.idOffset || fileOffset >= patch.fieldEnd) return chunk
  // Buffer overrides slice() with a shared-memory view. Constructing a plain
  // Uint8Array guarantees the signed/authenticated source chunk is untouched.
  const output = new Uint8Array(chunk)
  const id = new TextEncoder().encode(patch.id)
  for (let absolute = Math.max(fileOffset, patch.idOffset); absolute < Math.min(chunkEnd, patch.fieldEnd); absolute++) {
    const idIndex = absolute - patch.idOffset
    output[absolute - fileOffset] = idIndex < id.length ? id[idIndex]! : 0
  }
  return output
}
