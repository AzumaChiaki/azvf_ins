export interface AuthorizedResource {
  id: string
  name: string
  version?: string
  resType?: number
  size?: number
}

export interface DevicePolicy {
  name: string
  expiresAt: number | null
  resourceIds: string[]
}

export interface BrowserAuthorization {
  resourceTokens: Record<string, string>
  resources: AuthorizedResource[]
  policies: DevicePolicy[]
  notice?: 'authorization_already_bound'
  /** 用户此前选定的资源，用于默认选中。只影响默认值，不限制可选范围。 */
  selectedResourceId?: string
}

export interface DeviceHistoryEntry {
  name: string
  addr: string
  lastUsed: number
  /**
   * Stored locally (browser storage only, never sent to the server except as
   * part of the device's own MiWear pairing handshake) so the user isn't
   * asked to re-type it on every reconnect. Omitted when the user hasn't
   * saved one for this device yet, or when a legacy/malformed value is
   * discarded by sanitizeDeviceHistory below.
   */
  authkey?: string
}

const RESOURCE_ID = /^[A-Za-z0-9_-]{1,128}$/
const TOKEN = /^[A-Za-z0-9._~-]{32,16384}$/
const DEVICE_ID = /^[A-Za-z0-9+/=_:-]{8,64}$/
const AUTHKEY = /^[0-9A-Fa-f]{32}$/

export function emptyAuthorization(): BrowserAuthorization {
  return { resourceTokens: Object.create(null) as Record<string, string>, resources: [], policies: [] }
}

/** Validate the Installer API response again at the browser trust boundary. */
export function parseAuthorizationResponse(raw: unknown): BrowserAuthorization {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('设备授权响应无效')
  const record = raw as Record<string, unknown>
  if (!record.resourceTokens || typeof record.resourceTokens !== 'object' || Array.isArray(record.resourceTokens)) {
    throw new Error('授权令牌映射无效')
  }
  const entries = Object.entries(record.resourceTokens as Record<string, unknown>)
  if (entries.length > 1_000) throw new Error('授权资源数量超出限制')
  const resourceTokens = Object.create(null) as Record<string, string>
  for (const [resourceId, token] of entries) {
    if (!RESOURCE_ID.test(resourceId) || typeof token !== 'string' || !TOKEN.test(token)) {
      throw new Error('授权令牌与资源映射无效')
    }
    resourceTokens[resourceId] = token
  }

  if (!Array.isArray(record.resources) || record.resources.length > 1_000) throw new Error('授权资源摘要无效')
  const summaries = new Map<string, AuthorizedResource>()
  for (const value of record.resources) {
    if (!value || typeof value !== 'object') throw new Error('授权资源摘要无效')
    const resource = value as Record<string, unknown>
    if (typeof resource.id !== 'string' || resourceTokens[resource.id] === undefined) {
      throw new Error('授权资源未通过令牌验证')
    }
    if (summaries.has(resource.id)
      || typeof resource.name !== 'string' || resource.name.length < 1 || resource.name.length > 512
      || typeof resource.version !== 'string' || resource.version.length < 1 || resource.version.length > 128
      || typeof resource.resType !== 'number' || ![16, 32, 64].includes(resource.resType)
      || typeof resource.size !== 'number' || !Number.isSafeInteger(resource.size) || resource.size < 1) {
      throw new Error('授权资源摘要字段无效')
    }
    summaries.set(resource.id, {
      id: resource.id,
      name: resource.name,
      version: resource.version,
      resType: resource.resType,
      size: resource.size,
    })
  }
  const resources = Object.keys(resourceTokens).map((id) => summaries.get(id) ?? { id, name: id })

  if (!Array.isArray(record.policies) || record.policies.length > 256) throw new Error('设备策略响应无效')
  const policies: DevicePolicy[] = record.policies.map((value) => {
    if (!value || typeof value !== 'object') throw new Error('设备策略响应无效')
    const policy = value as Record<string, unknown>
    if (typeof policy.name !== 'string' || policy.name.length < 1 || policy.name.length > 100
      || policy.name !== policy.name.trim() || /[\u0000-\u001f\u007f]/.test(policy.name)) {
      throw new Error('设备策略名称无效')
    }
    if (policy.expiresAt !== null
      && (typeof policy.expiresAt !== 'number' || !Number.isSafeInteger(policy.expiresAt) || policy.expiresAt < 1)) {
      throw new Error('设备策略有效期无效')
    }
    if (!Array.isArray(policy.resourceIds) || policy.resourceIds.length < 1 || policy.resourceIds.length > 1_000) {
      throw new Error('设备策略资源无效')
    }
    const resourceIds: string[] = []
    for (const resourceId of policy.resourceIds) {
      if (typeof resourceId !== 'string' || resourceTokens[resourceId] === undefined || resourceIds.includes(resourceId)) {
        throw new Error('设备策略资源映射无效')
      }
      resourceIds.push(resourceId)
    }
    // Constructing this shape also strips internal policy ids if a compromised
    // or older server accidentally includes them.
    return { name: policy.name, expiresAt: policy.expiresAt as number | null, resourceIds }
  })

  if (record.notice !== undefined && record.notice !== 'authorization_already_bound') throw new Error('设备授权提示无效')
  // 预选项只是默认值：指向一项没有令牌的资源时直接忽略，不当作错误。
  const selected = typeof record.selectedResourceId === 'string' && resourceTokens[record.selectedResourceId] !== undefined
    ? record.selectedResourceId : undefined
  return { resourceTokens, resources, policies,
    ...(record.notice === 'authorization_already_bound' ? { notice: record.notice } : {}),
    ...(selected ? { selectedResourceId: selected } : {}) }
}

export function mergeAuthorizations(...authorizations: BrowserAuthorization[]): BrowserAuthorization {
  const resourceTokens = Object.create(null) as Record<string, string>
  const resources = new Map<string, AuthorizedResource>()
  const policies = new Map<string, DevicePolicy>()
  for (const authorization of authorizations) {
    Object.assign(resourceTokens, authorization.resourceTokens)
    for (const resource of authorization.resources) resources.set(resource.id, resource)
    for (const policy of authorization.policies) {
      const key = `${policy.name}\u0000${policy.expiresAt ?? 'forever'}\u0000${policy.resourceIds.join(',')}`
      policies.set(key, policy)
    }
  }
  return {
    resourceTokens,
    resources: Object.keys(resourceTokens).map((id) => resources.get(id) ?? { id, name: id }),
    policies: [...policies.values()],
    ...(authorizations.some((authorization) => authorization.notice === 'authorization_already_bound')
      ? { notice: 'authorization_already_bound' as const } : {}),
  }
}

/** Re-validates every stored field on each load; drops anything malformed instead of trusting prior writes. */
export function sanitizeDeviceHistory(raw: unknown): DeviceHistoryEntry[] {
  if (!Array.isArray(raw)) return []
  const result: DeviceHistoryEntry[] = []
  for (const value of raw) {
    if (!value || typeof value !== 'object') continue
    const entry = value as Record<string, unknown>
    if (typeof entry.name !== 'string' || entry.name.length > 100
      || typeof entry.addr !== 'string' || !DEVICE_ID.test(entry.addr.trim())) continue
    const addr = entry.addr.trim()
    if (result.some((item) => item.addr === addr)) continue
    result.push({
      name: entry.name.trim(),
      addr,
      lastUsed: typeof entry.lastUsed === 'number' && Number.isSafeInteger(entry.lastUsed) && entry.lastUsed > 0
        ? entry.lastUsed
        : 0,
      ...(typeof entry.authkey === 'string' && AUTHKEY.test(entry.authkey) ? { authkey: entry.authkey } : {}),
    })
    if (result.length === 6) break
  }
  return result
}

export function formatPolicyRemaining(expiresAt: number | null, now = Date.now()): string {
  if (expiresAt === null) return '长期有效'
  const remaining = expiresAt - now
  if (remaining <= 0) return '已到期'
  const minutes = Math.max(1, Math.ceil(remaining / 60_000))
  const days = Math.floor(minutes / (24 * 60))
  const hours = Math.floor((minutes % (24 * 60)) / 60)
  const restMinutes = minutes % 60
  if (days > 0) return hours > 0 ? `剩余 ${days} 天 ${hours} 小时` : `剩余 ${days} 天`
  if (hours > 0) return restMinutes > 0 ? `剩余 ${hours} 小时 ${restMinutes} 分钟` : `剩余 ${hours} 小时`
  return `剩余 ${restMinutes} 分钟`
}
