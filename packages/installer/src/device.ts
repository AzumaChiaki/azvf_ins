import { normalizeDeviceIdentifier } from '@azvf/contract'/**
 * Canonical device identifier used by authorization and concurrency checks.
 * Accepts a real MAC or an opaque handle (e.g. a Web Bluetooth device.id); see
 * normalizeDeviceIdentifier. Kept as a thin alias so existing call sites and
 * the "device address" wording elsewhere continue to work.
 */
export function normalizeDeviceAddress(value: unknown): string {
  return normalizeDeviceIdentifier(value)
}
