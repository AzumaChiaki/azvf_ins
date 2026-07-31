import { useEffect, useState } from 'react'
import { runtimeConfig } from '@azvf/ui/runtime-config'

type Platform = 'windows' | 'macos' | 'android' | 'ios' | 'linux' | 'unknown'

interface BrowserLink {
  label: string
  /** 可选：未配置自建镜像时该条目没有官网链接，只留应用市场与本地回退。 */
  url?: string
  /** Overrides the default "官网下载" label/title next to `url`, for entries where `url` isn't
   * actually the vendor's own site (e.g. the self-hosted Chrome Android mirror below). */
  urlLabel?: string
  urlTitle?: string
  /** Android-only: a market:// intent. Resolves to whichever app store is registered as the
   * handler on that device — Google Play on GMS devices, or the vendor's own store (华为应用市场 /
   * 小米应用商店 / vivo·oppo 应用商店 …) on mainland-market ROMs that ship without Google Play. */
  marketUrl?: string
  fallbackUrl?: string
}

/**
 * Browser download links optimised for mainland China accessibility.
 *
 * Chrome uses google.cn (one of the few Google properties available in China).
 * Edge uses microsoft.com/zh-cn (Microsoft operates normally in China).
 *
 * Neither Chrome nor Edge for Android has an official standalone-APK channel —
 * both ship through Google Play only, which is unusable on most mainland China
 * devices. Google.cn/chrome and microsoft.com's download page both fall back to
 * a "Get it on Google Play" button for an Android UA, so linking to them as the
 * primary action would effectively be a Play Store redirect. `marketUrl` (a
 * `market://` intent) is used instead as the primary Android action: on a real
 * device it resolves to whatever app store is actually registered as the
 * handler, which on mainland-market ROMs is the vendor's own store, not Play.
 *
 * Each entry also carries a server-hosted fallback at `/browsers/...` for when
 * neither the market intent nor the official site works. An admin must place
 * the installers there separately — see deploy/README.md.
 *
 * iOS is intentionally absent — all iOS browsers use WebKit and none support
 * Web Serial, so App Store links would be misleading. iOS users are directed to
 * use Android or a desktop computer instead.
 */

const CHROME_LINKS: Record<string, BrowserLink> = {
  windows: {
    label: 'Chrome（Windows 64 位）',
    url: 'https://www.google.cn/chrome/',
    fallbackUrl: '/browsers/chrome-standalone-setup-x64.exe',
  },
  macos: {
    label: 'Chrome（macOS）',
    url: 'https://www.google.cn/chrome/',
    fallbackUrl: '/browsers/chrome-standalone-universal.pkg',
  },
  android: {
    label: 'Chrome（Android）',
    // google.cn/chrome has no Android download path of its own — it forwards
    // Android UAs to a "Get it on Google Play" button, which is the exact
    // Play Store dependency this whole file exists to avoid.
    //
    // 自建镜像地址来自运行时配置，构建产物里不含任何站点地址；未配置时本条目
    // 不显示，用户仍可走应用市场或下面的本地回退。
    ...(runtimeConfig.androidChromeMirrorUrl ? {
      url: runtimeConfig.androidChromeMirrorUrl,
      urlLabel: runtimeConfig.androidChromeMirrorLabel ?? '自建下载',
      urlTitle: runtimeConfig.androidChromeMirrorLabel ?? '自建镜像下载',
    } : {}),
    marketUrl: 'market://details?id=com.android.chrome',
    fallbackUrl: '/browsers/chrome-android.apk',
  },
  linux: {
    label: 'Chrome（Linux 64 位 .rpm / .deb）',
    url: 'https://www.google.cn/chrome/',
  },
}

const EDGE_LINKS: Record<string, BrowserLink> = {
  windows: {
    label: 'Edge（Windows）',
    url: 'https://www.microsoft.com/zh-cn/edge/download',
    fallbackUrl: '/browsers/edge-setup-x64.exe',
  },
  macos: {
    label: 'Edge（macOS）',
    url: 'https://www.microsoft.com/zh-cn/edge/download',
    fallbackUrl: '/browsers/edge-setup-universal.pkg',
  },
  android: {
    label: 'Edge（Android）',
    url: 'https://www.microsoft.com/zh-cn/edge/download',
    marketUrl: 'market://details?id=com.microsoft.emmx',
    fallbackUrl: '/browsers/edge-android.apk',
  },
  linux: {
    label: 'Edge（Linux .rpm / .deb）',
    url: 'https://www.microsoft.com/zh-cn/edge/download',
  },
}

const PLATFORM_LABELS: Record<Platform, string> = {
  windows: 'Windows',
  macos: 'macOS',
  android: 'Android',
  ios: 'iOS',
  linux: 'Linux',
  unknown: '未知',
}

const PLATFORM_ORDER: Platform[] = ['windows', 'macos', 'android', 'ios', 'linux']

function detectPlatform(): Platform {
  const ua = navigator.userAgent
  // Check iOS first — iPads may report "Macintosh" in modern iPadOS
  if (/iPhone|iPad|iPod/i.test(ua)) return 'ios'
  if (/Android/i.test(ua)) return 'android'
  if (/Windows/i.test(ua)) return 'windows'
  if (/Mac/i.test(ua)) return 'macos'
  if (/Linux/i.test(ua)) return 'linux'
  return 'unknown'
}

function inWeChat(): boolean {
  return /MicroMessenger|QQ\//i.test(navigator.userAgent)
}

function BrowserButton({ link, primary, availableFiles }: { link: BrowserLink; primary?: boolean; availableFiles: Set<string> }) {
  const fallbackFile = link.fallbackUrl?.split('/').pop()
  const fallbackAvailable = Boolean(fallbackFile && availableFiles.has(fallbackFile))
  return (
    <div className="browser-notice-dl">
      <a
        className={`browser-notice-btn${primary ? ' is-primary' : ''}`}
        href={link.marketUrl ?? link.url}
        {...(link.marketUrl ? {} : { target: '_blank', rel: 'noopener noreferrer' })}
      >
        {link.marketUrl ? `${link.label} · 应用商店安装` : link.label}
      </a>
      {link.marketUrl && link.url && (
        <a
          className="browser-notice-fallback"
          href={link.url}
          target="_blank"
          rel="noopener noreferrer"
          title={link.urlTitle ?? '官方网站直接下载（国内网络环境下可能无法访问）'}
        >
          {link.urlLabel ?? '官网下载'}
        </a>
      )}
      {link.fallbackUrl && fallbackAvailable && (
        <a
          className="browser-notice-fallback"
          href={link.fallbackUrl}
          title="服务器备用下载"
        >
          备用下载
        </a>
      )}
    </div>
  )
}

const BYPASS_STORAGE_KEY = 'azvf-browser-bypass'

export function didBypassBrowserCheck(): boolean {
  try {
    return sessionStorage.getItem(BYPASS_STORAGE_KEY) === '1'
  } catch {
    return false
  }
}

export function BrowserNotice({ onBypass }: { onBypass: () => void }) {
  const [platform, setPlatform] = useState<Platform>(() => detectPlatform())
  const [availableFiles, setAvailableFiles] = useState<Set<string>>(() => new Set())
  const detected = detectPlatform()
  const showPicker = platform === 'unknown' || (detected !== 'unknown' && platform !== detected)

  useEffect(() => {
    let cancelled = false
    fetch('/browsers/_manifest')
      .then((response) => (response.ok ? response.json() : { files: [] }))
      .then((data: { files?: string[] }) => { if (!cancelled) setAvailableFiles(new Set(data.files ?? [])) })
      .catch(() => { if (!cancelled) setAvailableFiles(new Set()) })
    return () => { cancelled = true }
  }, [])

  const chrome = CHROME_LINKS[platform]
  const edge = EDGE_LINKS[platform]
  const hasLinks = Boolean(chrome || edge)

  return (
    <div className="browser-notice" role="alert">
      <h1 className="browser-notice-title">当前浏览器无法在线安装</h1>

      <p className="browser-notice-intro">
        安装器需要 <strong>Web Serial</strong> 接口与设备通信，此浏览器未提供该能力。
      </p>

      {/* WeChat / QQ built-in browser hint */}
      {inWeChat() && (
        <div className="browser-notice-wechat">
          <strong>检测到微信 / QQ 内置浏览器</strong>
          <p>
            请点击右上角「···」→<strong>「在浏览器打开」</strong>，并使用电脑版 Chrome 或 Edge 访问本页面。
          </p>
        </div>
      )}

      {/* Platform-specific guidance */}
      {platform === 'ios' && (
        <div className="browser-notice-platform">
          <h2>你正在使用 iOS 设备</h2>
          <p>
            iOS 上的所有浏览器均使用 WebKit 内核，<strong>不支持 Web Serial 接口</strong>。
            请使用 <strong>Android 手机</strong>或<strong>电脑（Windows / macOS）</strong>
            上的 Chrome / Edge 浏览器打开本页面进行安装。
          </p>
        </div>
      )}

      {platform === 'android' && (
        <div className="browser-notice-platform">
          <h2>你正在使用 Android 设备</h2>
          <p>
            Android 设备<strong>支持安装</strong>，但需要支持 Web Serial 的浏览器。
            部分 Android 浏览器（如 Chrome、Edge）可使用本安装器连接设备。
            如果当前浏览器无法使用，请点击下方「应用商店安装」——会跳转到手机自带的应用商店
            （华为应用市场 / 小米应用商店 / vivo·oppo 应用商店等）完成安装，不依赖 Google Play。
          </p>
        </div>
      )}

      {(platform === 'windows' || platform === 'macos' || platform === 'linux') && (
        <div className="browser-notice-platform">
          <h2>
            你正在使用 {PLATFORM_LABELS[platform]}{' '}
            {detected === platform ? '系统' : ''}
          </h2>
          <p>
            请安装最新版 <strong>Chrome</strong> 或 <strong>Microsoft Edge</strong>，
            然后重新打开本页面即可正常使用安装器。
          </p>
        </div>
      )}

      {/* Download buttons — omitted for iOS since browsers won't help */}
      {hasLinks && (
        <div className="browser-notice-actions">
          {chrome && <BrowserButton link={chrome} primary availableFiles={availableFiles} />}
          {edge && <BrowserButton link={edge} availableFiles={availableFiles} />}
        </div>
      )}

      {platform === 'unknown' && (
        <div className="browser-notice-platform">
          <h2>未能识别你的设备类型</h2>
          <p>请手动选择你的平台，我们会展示对应的浏览器下载指引：</p>
        </div>
      )}

      {/* Manual platform picker */}
      <div className="browser-notice-picker">
        <span className="browser-notice-picker-label">
          {showPicker ? '切换平台：' : '未识别到你的设备？手动选择：'}
        </span>
        <div className="browser-notice-picker-btns">
          {PLATFORM_ORDER.map((p) => (
            <button
              key={p}
              type="button"
              className={`browser-notice-chip${platform === p ? ' is-active' : ''}`}
              onClick={() => setPlatform(p)}
            >
              {PLATFORM_LABELS[p]}
            </button>
          ))}
        </div>
      </div>

      <p className="browser-notice-footnote">
        Safari、Firefox 及 iOS 所有浏览器均不支持设备连接安装。
        服务器已备份常用浏览器离线安装包（点击"备用下载"），建议优先从官网下载最新版。
      </p>

      {/* Bypass: let the user force-enter the app even though we know it won't fully work */}
      <div className="browser-notice-bypass">
        <button type="button" className="browser-notice-bypass-btn" onClick={() => {
          try { sessionStorage.setItem(BYPASS_STORAGE_KEY, '1') } catch { /* noop */ }
          onBypass()
        }}>
          我知道不能装，但是我执意要进去试试
        </button>
      </div>
    </div>
  )
}
