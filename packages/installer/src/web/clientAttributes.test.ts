import { afterEach, describe, expect, it } from 'vitest'
import { collectClientAttributes } from './clientAttributes.js'

const originalNavigator = Object.getOwnPropertyDescriptor(globalThis, 'navigator')
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, 'window')

afterEach(() => {
  if (originalNavigator) Object.defineProperty(globalThis, 'navigator', originalNavigator)
  else delete (globalThis as { navigator?: unknown }).navigator
  if (originalWindow) Object.defineProperty(globalThis, 'window', originalWindow)
  else delete (globalThis as { window?: unknown }).window
})

describe('consented client attributes', () => {
  it('uses the stable browser fields without high-entropy identifiers', () => {
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: {
      userAgent: 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/140.0 Safari/537.36',
      language: 'zh-CN', platform: 'MacIntel', hardwareConcurrency: 8,
    } })
    Object.defineProperty(globalThis, 'window', { configurable: true, value: {
      screen: { width: 1920, height: 1080, colorDepth: 24 },
    } })
    expect(collectClientAttributes()).toMatchObject({
      language: 'zh-CN', platform: 'MacIntel', hardwareConcurrency: 8,
      screen: '1920x1080x24', engine: 'Chrome',
    })
    expect(Object.keys(collectClientAttributes()).sort()).toEqual([
      'engine', 'hardwareConcurrency', 'language', 'platform', 'screen', 'timeZone',
    ])
  })
})
