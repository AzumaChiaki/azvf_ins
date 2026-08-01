import type { SessionInitRequest } from '@azvf/contract'

type Attributes = NonNullable<SessionInitRequest['clientAttributes']>

function browserEngine(userAgent: string): Attributes['engine'] {
  if (/Edg\//.test(userAgent)) return 'Edge'
  if (/(?:Chrome|CriOS)\//.test(userAgent)) return 'Chrome'
  if (/(?:Firefox|FxiOS)\//.test(userAgent)) return 'Firefox'
  if (/Safari\//.test(userAgent) && !/(?:Chrome|CriOS|Chromium|Edg)\//.test(userAgent)) return 'Safari'
  return 'Other'
}

/** Low-entropy attributes collected only after the redeem flow has recorded consent. */
export function collectClientAttributes(): Attributes {
  const timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
  const language = navigator.language || 'und'
  const width = Math.max(0, Math.round(window.screen?.width ?? 0))
  const height = Math.max(0, Math.round(window.screen?.height ?? 0))
  const depth = Math.max(0, Math.round(window.screen?.colorDepth ?? 0))
  const platform = (navigator.userAgentData?.platform || navigator.platform || 'unknown').slice(0, 64)
  return {
    timeZone,
    language,
    screen: `${width}x${height}x${depth}`,
    hardwareConcurrency: Math.max(1, Math.min(1024, Math.trunc(navigator.hardwareConcurrency || 1))),
    platform,
    engine: browserEngine(navigator.userAgent),
  }
}

declare global {
  interface Navigator {
    userAgentData?: { platform?: string }
  }
}
