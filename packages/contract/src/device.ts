/**
 * Canonicalize a target device identifier. It is used only for authorization
 * binding and concurrency accounting — never for radio addressing — so it does
 * not have to be a real MAC. The installer now binds to the device serial
 * number read over the authenticated MiWear session; this also accepts a 48-bit
 * MAC (returned as the canonical AA:BB:CC:DD:EE:FF form) or any opaque handle
 * such as a serial number or a Web Bluetooth `device.id` (returned unchanged;
 * base64/serials are case-sensitive, so case must be preserved). Throws on
 * anything outside those shapes.
 *
 * console and installer both call this so a given raw value binds identically
 * on both sides.
 */
export function normalizeDeviceIdentifier(value: unknown): string {
  if (typeof value !== 'string') throw new Error('必须提供目标设备标识')
  const trimmed = value.trim()
  const compact = trimmed.replaceAll(':', '').replaceAll('-', '').toUpperCase()
  if (/^[0-9A-F]{12}$/.test(compact)) return compact.match(/.{2}/g)!.join(':')
  if (DEVICE_IDENTIFIER_REGEX.test(trimmed)) return trimmed
  throw new Error('设备标识格式无效')
}

/** Raw (pre-normalization) identifier charset/length, for JSON-schema `pattern`. */
export const DEVICE_IDENTIFIER_PATTERN = '^[A-Za-z0-9+/=_:-]{8,64}$'
const DEVICE_IDENTIFIER_REGEX = /^[A-Za-z0-9+/=_-]{8,64}$/
