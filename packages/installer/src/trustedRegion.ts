import { BlockList, isIP } from 'node:net'

export const UNKNOWN_REGION = 'UNKNOWN'

type HeaderValue = string | readonly string[] | undefined
type AddressFamily = 'ipv4' | 'ipv6'

interface NormalizedAddress {
  address: string
  family: AddressFamily
}

/**
 * A region header is authorization-adjacent telemetry: it may only be read
 * from a connection whose raw TCP peer is an explicitly configured proxy.
 */
export class TrustedRegionSource {
  readonly headerName: string
  readonly proxyCidrs: readonly string[]
  readonly edgePeerHeaderName: string | undefined
  readonly edgeCidrs: readonly string[]
  readonly #proxies: BlockList
  readonly #edges: BlockList | undefined

  constructor(
    headerName: string,
    proxyCidrs: readonly string[],
    edgePeerHeaderName?: string,
    edgeCidrs: readonly string[] = [],
  ) {
    this.headerName = validateHeaderName(headerName)
    if (proxyCidrs.length === 0) {
      throw new Error('TRUSTED_REGION_PROXY_CIDRS 必须至少包含一个可信代理 CIDR')
    }

    const proxies = createAllowlist(proxyCidrs, 'TRUSTED_REGION_PROXY_CIDRS')
    this.#proxies = proxies.blockList
    this.proxyCidrs = proxies.cidrs

    if ((edgePeerHeaderName === undefined) !== (edgeCidrs.length === 0)) {
      throw new Error('TRUSTED_REGION_EDGE_PEER_HEADER 与 TRUSTED_REGION_EDGE_CIDRS 必须同时设置')
    }
    if (edgePeerHeaderName !== undefined) {
      this.edgePeerHeaderName = validateHeaderName(edgePeerHeaderName, 'TRUSTED_REGION_EDGE_PEER_HEADER')
      if (this.edgePeerHeaderName === this.headerName) {
        throw new Error('TRUSTED_REGION_EDGE_PEER_HEADER 不能与 TRUSTED_REGION_HEADER 相同')
      }
      const edges = createAllowlist(edgeCidrs, 'TRUSTED_REGION_EDGE_CIDRS')
      this.#edges = edges.blockList
      this.edgeCidrs = edges.cidrs
    } else {
      this.edgePeerHeaderName = undefined
      this.#edges = undefined
      this.edgeCidrs = Object.freeze([])
    }
  }

  region(rawPeerAddress: string | undefined, headerValue: HeaderValue, edgePeerHeaderValue?: HeaderValue): string {
    const peer = normalizePeerAddress(rawPeerAddress)
    if (!peer || !this.#proxies.check(peer.address, peer.family)) return UNKNOWN_REGION
    if (this.#edges) {
      if (typeof edgePeerHeaderValue !== 'string' || edgePeerHeaderValue !== edgePeerHeaderValue.trim()) {
        return UNKNOWN_REGION
      }
      const edgePeer = normalizePeerAddress(edgePeerHeaderValue)
      if (!edgePeer || !this.#edges.check(edgePeer.address, edgePeer.family)) return UNKNOWN_REGION
    }
    if (typeof headerValue !== 'string' || headerValue !== headerValue.trim()) return UNKNOWN_REGION
    return isRegionValue(headerValue) ? headerValue : UNKNOWN_REGION
  }
}

export function createTrustedRegionSource(
  headerName: string | undefined,
  rawProxyCidrs: string | undefined,
  edgePeerHeaderName?: string,
  rawEdgeCidrs?: string,
): TrustedRegionSource | undefined {
  if (!headerName && !rawProxyCidrs && !edgePeerHeaderName && !rawEdgeCidrs) return undefined
  if (!headerName) {
    throw new Error('设置 TRUSTED_REGION_PROXY_CIDRS 时必须同时设置 TRUSTED_REGION_HEADER')
  }
  if (!rawProxyCidrs) {
    throw new Error('设置 TRUSTED_REGION_HEADER 时必须同时设置 TRUSTED_REGION_PROXY_CIDRS')
  }

  const proxyCidrs = rawProxyCidrs.split(',').map((value) => value.trim())
  if (proxyCidrs.some((value) => value.length === 0)) {
    throw new Error('TRUSTED_REGION_PROXY_CIDRS 包含空的 CIDR 项')
  }
  if ((edgePeerHeaderName === undefined) !== (rawEdgeCidrs === undefined)) {
    throw new Error('TRUSTED_REGION_EDGE_PEER_HEADER 与 TRUSTED_REGION_EDGE_CIDRS 必须同时设置')
  }
  const edgeCidrs = rawEdgeCidrs?.split(',').map((value) => value.trim()) ?? []
  if (edgeCidrs.some((value) => value.length === 0)) {
    throw new Error('TRUSTED_REGION_EDGE_CIDRS 包含空的 CIDR 项')
  }
  return new TrustedRegionSource(headerName, proxyCidrs, edgePeerHeaderName, edgeCidrs)
}

function validateHeaderName(value: string, setting = 'TRUSTED_REGION_HEADER'): string {
  if (!/^[a-z][a-z0-9-]{1,62}$/.test(value)) {
    throw new Error(`${setting} 必须是固定的小写 HTTP header 名`)
  }
  return value
}

function createAllowlist(cidrs: readonly string[], setting: string): { blockList: BlockList; cidrs: readonly string[] } {
  const blockList = new BlockList()
  const normalizedCidrs: string[] = []
  for (const cidr of cidrs) {
    const normalized = parseCidr(cidr, setting)
    blockList.addSubnet(normalized.address, normalized.prefix, normalized.family)
    normalizedCidrs.push(`${normalized.address}/${normalized.prefix}`)
  }
  return { blockList, cidrs: Object.freeze(normalizedCidrs) }
}

function parseCidr(value: string, setting: string): NormalizedAddress & { prefix: number } {
  const slash = value.indexOf('/')
  if (slash <= 0 || slash !== value.lastIndexOf('/') || slash === value.length - 1) {
    throw new Error(`${setting} 包含无效 CIDR: ${value}`)
  }
  const address = value.slice(0, slash)
  const rawPrefix = value.slice(slash + 1)
  const ipVersion = isIP(address)
  const maxPrefix = ipVersion === 4 ? 32 : ipVersion === 6 ? 128 : 0
  if (maxPrefix === 0 || !/^(?:0|[1-9][0-9]{0,2})$/.test(rawPrefix)) {
    throw new Error(`${setting} 包含无效 CIDR: ${value}`)
  }
  const prefix = Number(rawPrefix)
  if (prefix > maxPrefix) {
    throw new Error(`${setting} 包含无效 CIDR: ${value}`)
  }
  return { address, prefix, family: ipVersion === 4 ? 'ipv4' : 'ipv6' }
}

function normalizePeerAddress(value: string | undefined): NormalizedAddress | undefined {
  if (!value) return undefined

  // Node commonly exposes an IPv4 peer on a dual-stack listener this way.
  // Match the textual mapped form before isIP(), otherwise it is classified
  // as IPv6 and would not match an intentionally narrow IPv4 allowlist.
  const mappedPrefix = '::ffff:'
  if (value.toLowerCase().startsWith(mappedPrefix)) {
    const mapped = value.slice(mappedPrefix.length)
    if (isIP(mapped) === 4) return { address: mapped, family: 'ipv4' }
  }

  const ipVersion = isIP(value)
  if (ipVersion === 4) return { address: value, family: 'ipv4' }
  if (ipVersion === 6) return { address: value, family: 'ipv6' }
  return undefined
}

function isRegionValue(value: string): boolean {
  // ISO-like country/edge code (CN, US, XX; Cloudflare's T1 is also valid),
  // optionally followed by one compact subdivision token (US-CA). Case
  // conversion is deliberately not performed: the trusted proxy must inject
  // a normalized value.
  return /^(?:(?:[A-Z]{2})(?:-[A-Z0-9]{1,4})?|T1)$/.test(value)
}
