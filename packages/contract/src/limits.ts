// 资源分片的尺寸约定。上传入库与安装下发必须使用同一组数值，否则分片边界对
// 不上。

/** 资源入库时的默认分片大小（字节）。 */
export const DEFAULT_CHUNK_SIZE = 256 * 1024

/** 单个分片允许的最大明文长度（字节）。超过即拒绝。 */
export const MAX_CHUNK_PAYLOAD = 1024 * 1024
