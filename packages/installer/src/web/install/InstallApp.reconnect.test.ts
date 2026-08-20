import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

const source = readFileSync(new URL('./InstallApp.tsx', import.meta.url), 'utf8')
const reconnectBlock = source.slice(
  source.indexOf('const reconnectDeviceSession'),
  source.indexOf('const renameDeviceHistoryEntry'),
)

describe('Installer automatic reconnect authorization boundary', () => {
  it('keeps the active install token instead of minting a replacement', () => {
    expect(reconnectBlock).not.toContain('refreshDeviceAuthorization(')
    expect(reconnectBlock).not.toContain('setAuthorization(emptyAuthorization())')
  })

  it('still rejects a different device serial after reconnect', () => {
    expect(reconnectBlock).toContain('reconnectedSerial !== serial')
  })
})
