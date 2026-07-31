// 同构 base64 编解码（Node 与浏览器均可用）

// 避免直接依赖 Node 的 Buffer 类型（浏览器 tsconfig 下无 node types）
const NodeBuffer: any = (globalThis as any).Buffer

export function toBase64(bytes: Uint8Array): string {
  if (NodeBuffer) {
    return NodeBuffer.from(bytes).toString('base64')
  }
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

export function fromBase64(b64: string): Uint8Array {
  if (NodeBuffer) {
    return new Uint8Array(NodeBuffer.from(b64, 'base64'))
  }
  const binary = atob(b64)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

export function toHex(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0')
  return s
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('十六进制字符串长度必须为偶数')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
