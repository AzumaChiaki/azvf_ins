import { describe, expect, it } from 'vitest'
import { createTrustedRegionSource, TrustedRegionSource } from './trustedRegion.js'

describe('trusted region source', () => {
  it('stays disabled when both settings are empty', () => {
    expect(createTrustedRegionSource(undefined, undefined)).toBeUndefined()
  })

  it('requires the header and CIDR allowlist to be configured together', () => {
    expect(() => createTrustedRegionSource('cf-ipcountry', undefined))
      .toThrow(/TRUSTED_REGION_PROXY_CIDRS/)
    expect(() => createTrustedRegionSource(undefined, '127.0.0.1\/32'))
      .toThrow(/TRUSTED_REGION_HEADER/)
  })

  it('requires both edge settings and the base proxy settings', () => {
    expect(() => createTrustedRegionSource(
      'x-azvf-region', '127.0.0.1/32', 'x-azvf-edge-peer', undefined,
    )).toThrow(/EDGE_PEER_HEADER.*EDGE_CIDRS/)
    expect(() => createTrustedRegionSource(
      'x-azvf-region', '127.0.0.1/32', undefined, '203.0.113.0/24',
    )).toThrow(/EDGE_PEER_HEADER.*EDGE_CIDRS/)
    expect(() => createTrustedRegionSource(
      undefined, undefined, 'x-azvf-edge-peer', '203.0.113.0/24',
    )).toThrow(/TRUSTED_REGION_HEADER/)
  })

  it.each([
    '',
    '127.0.0.1',
    '127.0.0.1/',
    '127.0.0.1/33',
    '127.0.0.1/-1',
    '127.0.0.1/01',
    '2001:db8::/129',
    'not-an-ip/24',
    '127.0.0.1/32/1',
  ])('rejects invalid CIDR %j', (cidr) => {
    expect(() => new TrustedRegionSource('cf-ipcountry', [cidr])).toThrow(/CIDR/)
  })

  it('rejects empty entries and unsafe header names', () => {
    expect(() => createTrustedRegionSource('cf-ipcountry', '127.0.0.1/32,'))
      .toThrow(/空的 CIDR/)
    expect(() => createTrustedRegionSource('CF-IPCountry', '127.0.0.1/32'))
      .toThrow(/小写 HTTP header/)
    expect(() => createTrustedRegionSource(
      'x-azvf-region', '127.0.0.1/32', 'X-Edge-Peer', '203.0.113.0/24',
    )).toThrow(/EDGE_PEER_HEADER.*小写 HTTP header/)
    expect(() => createTrustedRegionSource(
      'x-azvf-region', '127.0.0.1/32', 'x-azvf-edge-peer', '203.0.113.0/24,',
    )).toThrow(/EDGE_CIDRS.*空的 CIDR/)
    expect(() => createTrustedRegionSource(
      'x-azvf-region', '127.0.0.1/32', 'x-azvf-edge-peer', 'not-an-edge/24',
    )).toThrow(/EDGE_CIDRS.*无效 CIDR/)
    expect(() => createTrustedRegionSource(
      'x-azvf-region', '127.0.0.1/32', 'x-azvf-region', '203.0.113.0/24',
    )).toThrow(/不能与 TRUSTED_REGION_HEADER 相同/)
  })

  it('accepts values only from an allowlisted raw IPv4 peer', () => {
    const source = new TrustedRegionSource('cf-ipcountry', ['192.0.2.0/24'])
    expect(source.region('192.0.2.7', 'CN')).toBe('CN')
    expect(source.region('198.51.100.7', 'CN')).toBe('UNKNOWN')
    expect(source.region(undefined, 'CN')).toBe('UNKNOWN')
  })

  it('maps IPv4-mapped IPv6 peers back to the IPv4 allowlist', () => {
    const source = new TrustedRegionSource('x-azvf-region', ['127.0.0.0/8'])
    expect(source.region('::ffff:127.0.0.1', 'US-CA')).toBe('US-CA')
    expect(source.region('::ffff:192.0.2.1', 'US-CA')).toBe('UNKNOWN')
  })

  it('supports explicit IPv6 proxy ranges', () => {
    const source = new TrustedRegionSource('cf-ipcountry', ['2001:db8:abcd::/48'])
    expect(source.region('2001:db8:abcd::42', 'JP')).toBe('JP')
    expect(source.region('2001:db8:abce::42', 'JP')).toBe('UNKNOWN')
  })

  it('requires both the immediate proxy and edge peer to be trusted', () => {
    const source = new TrustedRegionSource(
      'x-azvf-region',
      ['127.0.0.1/32'],
      'x-azvf-edge-peer',
      ['203.0.113.0/24', '2001:db8:feed::/48'],
    )
    expect(source.region('127.0.0.1', 'CN', '203.0.113.8')).toBe('CN')
    expect(source.region('192.0.2.1', 'CN', '203.0.113.8')).toBe('UNKNOWN')
    expect(source.region('127.0.0.1', 'CN', '198.51.100.8')).toBe('UNKNOWN')
    expect(source.region('127.0.0.1', 'CN', undefined)).toBe('UNKNOWN')
  })

  it('rejects spoofed or multi-value edge peer headers', () => {
    const source = new TrustedRegionSource(
      'x-azvf-region', ['127.0.0.1/32'], 'x-azvf-edge-peer', ['203.0.113.0/24'],
    )
    expect(source.region('127.0.0.1', 'US', '203.0.113.8, 198.51.100.1')).toBe('UNKNOWN')
    expect(source.region('127.0.0.1', 'US', ['203.0.113.8'])).toBe('UNKNOWN')
    expect(source.region('127.0.0.1', 'US', ' 203.0.113.8')).toBe('UNKNOWN')
  })

  it('normalizes IPv4-mapped edge peers before checking IPv4 CIDRs', () => {
    const source = new TrustedRegionSource(
      'x-azvf-region', ['127.0.0.1/32'], 'x-azvf-edge-peer', ['203.0.113.0/24'],
    )
    expect(source.region('127.0.0.1', 'DE', '::ffff:203.0.113.9')).toBe('DE')
    expect(source.region('127.0.0.1', 'DE', '::ffff:198.51.100.9')).toBe('UNKNOWN')
  })

  it('accepts a trusted IPv6 edge and rejects an adjacent prefix', () => {
    const source = new TrustedRegionSource(
      'x-azvf-region', ['::1/128'], 'x-azvf-edge-peer', ['2001:db8:feed::/48'],
    )
    expect(source.region('::1', 'FR', '2001:db8:feed::20')).toBe('FR')
    expect(source.region('::1', 'FR', '2001:db8:beef::20')).toBe('UNKNOWN')
  })

  it.each([
    ['CN', 'CN'],
    ['T1', 'T1'],
    ['XX', 'XX'],
    ['US-CA', 'US-CA'],
    ['CN ', 'UNKNOWN'],
    ['cn', 'UNKNOWN'],
    ['USA', 'UNKNOWN'],
    ['1A', 'UNKNOWN'],
    ['US--CA', 'UNKNOWN'],
    ['US-CALIF', 'UNKNOWN'],
    [['CN'], 'UNKNOWN'],
  ] as const)('validates region value %j', (value, expected) => {
    const source = new TrustedRegionSource('cf-ipcountry', ['127.0.0.1/32'])
    expect(source.region('127.0.0.1', value)).toBe(expected)
  })
})
