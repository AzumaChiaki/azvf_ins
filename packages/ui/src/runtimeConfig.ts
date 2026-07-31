// 页面在运行时读取的部署配置。构建产物不含任何具体站点信息；部署方通过在
// HTML 中定义 window.__AZVF_RUNTIME__ 覆盖默认值。

export interface UpstreamAttribution {
  name: string
  url: string
}

export interface RuntimeConfig {
  /** 品牌名，显示在页眉与页脚。 */
  brand: string
  /** 核销页地址。安装页的返回入口指向这里。 */
  redeemUrl: string
  /** 安装页地址。核销页的前往入口指向这里。 */
  installUrl: string
  /** 本安装器的源码地址。 */
  sourceUrl: string
  /** 上游项目署名。 */
  upstream: UpstreamAttribution[]
  /**
   * 可选：Android 版 Chrome 的自建镜像地址。
   *
   * google.cn/chrome 对 Android UA 只给「去 Google Play」，而本程序存在的意义
   * 之一就是绕开 Play 依赖。部署方若自建了镜像可在此填入；**留空则不显示该入口**，
   * 用户仍可走应用市场或本地 `/browsers/` 回退。构建产物里不含任何站点地址。
   */
  androidChromeMirrorUrl?: string
  /** 镜像入口的显示名，仅在 androidChromeMirrorUrl 存在时使用。 */
  androidChromeMirrorLabel?: string
}

const DEFAULTS: RuntimeConfig = {
  brand: 'AZVF',
  redeemUrl: '/',
  installUrl: '/install',
  sourceUrl: 'https://github.com/AzumaChiaki/azvf_ins',
  upstream: [
    { name: 'AstroBox-NG — AstralSightStudios', url: 'https://github.com/AstralSightStudios/AstroBox-NG' },
    { name: 'AstroBox-NG-Module-Core', url: 'https://github.com/AstralSightStudios/AstroBox-NG-Module-Core' },
  ],
}

/**
 * 允许部署方在运行时覆盖的字段。
 *
 * **`sourceUrl` 与 `upstream` 刻意不在其中。** 许可证要求源码链接与上游署名
 * 「不可移除或模糊」，可运行时覆盖就等于可被移除。这两项固定在构建期，随发布
 * tag 一起确定；后台可编辑的页脚（若有）也不得触及它们。
 */
type MutableRuntimeFields = Pick<RuntimeConfig,
  'brand' | 'redeemUrl' | 'installUrl' | 'androidChromeMirrorUrl' | 'androidChromeMirrorLabel'>

declare global {
  interface Window {
    __AZVF_RUNTIME__?: Partial<MutableRuntimeFields>
  }
}

function readOverrides(): Partial<MutableRuntimeFields> {
  if (typeof window === 'undefined') return {}
  const raw = window.__AZVF_RUNTIME__
  return raw && typeof raw === 'object' ? raw : {}
}

const text = (value: unknown, fallback: string): string =>
  typeof value === 'string' && value ? value : fallback

/** 只接受 http(s)，挡掉 `javascript:` 之类被注入的方案。 */
const httpUrl = (value: unknown): string | undefined => {
  if (typeof value !== 'string' || !value) return undefined
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : undefined
  } catch { return undefined }
}

const overrides = readOverrides()
const mirrorUrl = httpUrl(overrides.androidChromeMirrorUrl)

export const runtimeConfig: RuntimeConfig = {
  brand: text(overrides.brand, DEFAULTS.brand),
  redeemUrl: text(overrides.redeemUrl, DEFAULTS.redeemUrl),
  installUrl: text(overrides.installUrl, DEFAULTS.installUrl),
  // 合规署名：构建期固定，不接受运行时覆盖。
  sourceUrl: DEFAULTS.sourceUrl,
  upstream: DEFAULTS.upstream,
  ...(mirrorUrl ? {
    androidChromeMirrorUrl: mirrorUrl,
    androidChromeMirrorLabel: text(overrides.androidChromeMirrorLabel, '自建下载'),
  } : {}),
}
