import { describe, expect, it } from 'vitest'
import { normalizeDeviceAddress } from './device.js'

describe('normalizeDeviceAddress', () => {
  it('normalizes accepted MAC forms to one canonical value', () => {
    expect(normalizeDeviceAddress('aa-bb-cc-dd-ee-ff')).toBe('AA:BB:CC:DD:EE:FF')
    expect(normalizeDeviceAddress('aabbccddeeff')).toBe('AA:BB:CC:DD:EE:FF')
  })

  it('accepts an opaque device handle unchanged (case preserved)', () => {
    expect(normalizeDeviceAddress('U7YHMChB3VNKj5VcYd/gqA==')).toBe('U7YHMChB3VNKj5VcYd/gqA==')
    expect(normalizeDeviceAddress('  aBc-123_xyz  ')).toBe('aBc-123_xyz')
  })

  it('rejects missing and malformed identifiers', () => {
    expect(() => normalizeDeviceAddress(undefined)).toThrow('必须提供')
    expect(() => normalizeDeviceAddress('AA:BB:CC')).toThrow('设备标识格式无效')
    expect(() => normalizeDeviceAddress('GG:BB:CC:DD:EE:FF')).toThrow('设备标识格式无效')
    expect(() => normalizeDeviceAddress('bad id!')).toThrow('设备标识格式无效')
  })
})
