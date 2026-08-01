import type { SessionInitRequest } from '@azvf/contract'

type Attributes = NonNullable<SessionInitRequest['clientAttributes']>

function browserEngine(userAgent: string): Attributes['engine'] {
  if (/Edg(?:A|iOS)?\//.test(userAgent)) return 'Edge'
  if (/(?:Chrome|CriOS)\//.test(userAgent)) return 'Chrome'
  if (/(?:Firefox|FxiOS)\//.test(userAgent)) return 'Firefox'
  if (/Safari\//.test(userAgent) && !/(?:Chrome|CriOS|Chromium|Edg)\//.test(userAgent)) return 'Safari'
  return 'Other'
}

function browserPlatform(userAgent: string): string {
  if (/Android/i.test(userAgent)) return 'Android'
  if (/iPhone|iPad|iPod/i.test(userAgent)) return 'iOS'
  if (/Windows/i.test(userAgent)) return 'Windows'
  if (/Macintosh|Mac OS X/i.test(userAgent)) return 'macOS'
  if (/Linux/i.test(userAgent)) return 'Linux'
  return 'Other'
}

/** Low-entropy attributes collected only after the redeem flow has recorded consent. */
export function collectClientAttributes(): Attributes {
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  const language = navigator.language || 'und'
  const userAgent = navigator.userAgent || ''
  return {
    timeZone,
    language,
    screen: `${window.screen.width}x${window.screen.height}x${window.screen.colorDepth}`,
    hardwareConcurrency: navigator.hardwareConcurrency || 1,
    platform: navigator.platform || browserPlatform(userAgent),
    engine: browserEngine(userAgent),
  }
}
