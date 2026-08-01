import { useEffect, useMemo, useRef, useState } from 'react'
import { MiWearSession, requestSerialPort } from '../miwear/session.js'
import { streamInstall, InstallCooldownError, type StreamProgress } from '../pipeline.js'
import { AmbientLayer } from '@azvf/ui'
import { InstallFooter } from './InstallFooter.js'
import { runtimeConfig } from '@azvf/ui/runtime-config'
import { apiFetch, onBeforeReauth, onReauthRequired, ReauthRedirect } from '../apiFetch.js'
import {
  emptyAuthorization,
  formatPolicyRemaining,
  parseAuthorizationResponse,
  sanitizeDeviceHistory,
  type BrowserAuthorization,
  type DeviceHistoryEntry,
} from '../authorization.js'

const macFromBytes = (binary: string) =>
  Array.from(binary, (ch) => ch.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase()).join(':')

/**
 * 把 Web Bluetooth 的 device id 还原成 MAC 形式。部分平台以 base64（标准或
 * url-safe，可能省略补位）返回 6 字节 MAC；返回 '' 表示 id 是不可还原的句柄。
 */
function decodeDeviceId(deviceId: string): string {
  if (!deviceId) return ''
  if (/^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(deviceId)) return deviceId.replace(/-/g, ':').toUpperCase()
  let b64 = deviceId.replace(/-/g, '+').replace(/_/g, '/')
  if (b64.length % 4) b64 += '='.repeat(4 - (b64.length % 4))
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) {
    try {
      const binary = atob(b64)
      if (binary.length === 6) return macFromBytes(binary)
    } catch {
      /* not base64 */
    }
  }
  const hex = deviceId.replace(/[^0-9A-Fa-f]/g, '')
  if (hex.length === 12) return (hex.match(/../g) as string[]).join(':').toUpperCase()
  return ''
}

const isValidDeviceId = (value: string) => /^[A-Za-z0-9+/=_:-]{8,64}$/.test(value.trim())

// authkey 是设备配对密钥，只存在浏览器本地；用 localStorage 而不是 cookie，
// 避免它随每个 HTTP 请求一起发送。
const DEVICE_STORAGE_KEY = 'azvf-device-history'
const LEGACY_DEVICE_COOKIE = 'azvf_device_history'

const readDeviceHistory = (): DeviceHistoryEntry[] => {
  try {
    const stored = window.localStorage.getItem(DEVICE_STORAGE_KEY)
    if (stored) return sanitizeDeviceHistory(JSON.parse(stored) as unknown)
  } catch { /* fall through to legacy cookie migration */ }
  try {
    const raw = document.cookie.split('; ').find((item) => item.startsWith(`${LEGACY_DEVICE_COOKIE}=`))?.split('=').slice(1).join('=')
    if (!raw) return []
    const migrated = sanitizeDeviceHistory(JSON.parse(decodeURIComponent(raw)) as unknown)
    document.cookie = `${LEGACY_DEVICE_COOKIE}=; Max-Age=0; Path=/; SameSite=Strict`
    return migrated
  } catch { return [] }
}

const writeDeviceHistory = (history: DeviceHistoryEntry[]) => {
  try {
    window.localStorage.setItem(DEVICE_STORAGE_KEY, JSON.stringify(sanitizeDeviceHistory(history)))
  } catch { /* storage unavailable (private mode / quota) */ }
}

const debug = (message: string) => { try { console.debug('[installer]', message) } catch { /* noop */ } }

/** 通过已认证的设备会话读取序列号。序列号是授权绑定使用的设备标识。 */
async function readDeviceSerial(session: MiWearSession): Promise<string> {
  let info: Record<string, unknown>
  try {
    info = await session.getData('info') as Record<string, unknown>
  } catch (error) {
    throw new Error(`读取设备序列号失败：${error instanceof Error ? error.message : String(error)}`)
  }
  const serial = typeof info?.serialNumber === 'string' ? info.serialNumber.trim() : ''
  if (!isValidDeviceId(serial)) throw new Error('设备未返回可用的序列号，无法完成序列号绑定')
  return serial
}

export function InstallApp() {
  const sessionRef = useRef<MiWearSession | null>(null)
  const authorizationRequestRef = useRef(0)
  const [name, setName] = useState('')
  const [addr, setAddr] = useState('')
  const [authkey, setAuthkey] = useState('')
  const [connected, setConnected] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [showAuthkeyHelp, setShowAuthkeyHelp] = useState(false)
  const [showDeviceManager, setShowDeviceManager] = useState(false)
  const [revealedAuthkeys, setRevealedAuthkeys] = useState<ReadonlySet<string>>(() => new Set())
  const [serial, setSerial] = useState('')

  const [resourceId, setResourceId] = useState('')
  const [authorization, setAuthorization] = useState<BrowserAuthorization>(() => emptyAuthorization())
  const [loadingAuthorization, setLoadingAuthorization] = useState(false)
  const [clock, setClock] = useState(() => Date.now())
  const authorizedResources = authorization.resources
  const resourceTokens = authorization.resourceTokens

  const [prog, setProg] = useState<StreamProgress | null>(null)
  const [installing, setInstalling] = useState(false)
  const [status, setStatus] = useState('')
  const [errorBanner, setErrorBanner] = useState('')
  const [connectionUnstable, setConnectionUnstable] = useState(false)
  const disconnectTimesRef = useRef<number[]>([])
  const [cooldownUntil, setCooldownUntil] = useState(0)
  const [deviceHistory, setDeviceHistory] = useState<DeviceHistoryEntry[]>([])
  const [reauthTarget, setReauthTarget] = useState('')

  useEffect(() => {
    const history = readDeviceHistory()
    setDeviceHistory(history)
    writeDeviceHistory(history)
    const recent = history[0]
    if (recent) {
      setName(recent.name)
      setAddr(recent.addr)
      if (recent.authkey) setAuthkey(recent.authkey)
    }
  }, [])

  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 60_000)
    return () => window.clearInterval(timer)
  }, [])

  // 跳回核销页前先优雅关闭串口：导航时强关在部分浏览器上会让标签页崩溃。
  useEffect(() => {
    onBeforeReauth(async () => { await sessionRef.current?.disconnect(false).catch(() => undefined) })
    onReauthRequired((target) => setReauthTarget(target))
    return () => { onBeforeReauth(undefined); onReauthRequired(undefined) }
  }, [])

  useEffect(() => {
    setResourceId((current) => authorization.resourceTokens[current]
      ? current
      // 核销页选定的资源优先，其次退回第一项。
      : (authorization.selectedResourceId ?? authorization.resources[0]?.id ?? ''))
  }, [authorization])

  useEffect(() => {
    if (!showAuthkeyHelp && !showDeviceManager) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      setShowAuthkeyHelp(false)
      setShowDeviceManager(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [showAuthkeyHelp, showDeviceManager])

  const notify = (m: string) => {
    setStatus(m)
    if (/失败|错误|无效|未通过|拒绝|断开|过期|异常|❌/i.test(m)) setErrorBanner(m)
    debug(m)
  }

  const noteDisconnect = () => {
    const now = Date.now()
    const recent = disconnectTimesRef.current.filter((t) => now - t < 60_000)
    recent.push(now)
    disconnectTimesRef.current = recent
    if (recent.length >= 3) setConnectionUnstable(true)
  }

  const cooldownRemaining = Math.max(0, Math.ceil((cooldownUntil - clock) / 1_000))

  useEffect(() => {
    if (cooldownUntil <= Date.now()) return
    const timer = window.setInterval(() => {
      setClock(Date.now())
      if (Date.now() >= cooldownUntil) window.clearInterval(timer)
    }, 1_000)
    return () => window.clearInterval(timer)
  }, [cooldownUntil])

  /**
   * 提交设备序列号，取回本设备当前可安装的资源与安装令牌。核销页完成的授权
   * 在这一步与设备关联。
   */
  const refreshDeviceAuthorization = async (deviceSerial: string): Promise<void> => {
    const requestId = ++authorizationRequestRef.current
    setLoadingAuthorization(true)
    try {
      const response = await apiFetch('/api/device/authorizations', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ deviceAddr: deviceSerial }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const parsed = parseAuthorizationResponse(await response.json())
      if (authorizationRequestRef.current === requestId) setAuthorization(parsed)
    } catch (error) {
      // 页面正在跳回核销页，不要再覆盖状态或弹错误。
      if (error instanceof ReauthRedirect) return
      if (authorizationRequestRef.current === requestId) {
        setAuthorization(emptyAuthorization())
        notify(`设备授权状态读取失败：${error instanceof Error ? error.message : String(error)}`)
      }
    } finally {
      if (authorizationRequestRef.current === requestId) setLoadingAuthorization(false)
    }
  }

  const openDeviceSession = async (reselectPort: boolean): Promise<MiWearSession> => {
    if (!isValidDeviceId(addr)) throw new Error('请先扫描设备（或手动填写设备标识）')
    // requestPort() 必须在用户手势窗口内同步调用，因此先取得端口再做其余异步工作。
    const portPromise = requestSerialPort()
    await sessionRef.current?.disconnect(false).catch(() => undefined)
    const preacquiredPort = await portPromise
    let nextSession: MiWearSession
    nextSession = new MiWearSession((info) => {
      if (sessionRef.current !== nextSession) return
      notify(`设备已断开：${info.name}`)
      noteDisconnect()
      setConnected(false)
      setSerial('')
      authorizationRequestRef.current++
      setLoadingAuthorization(false)
      setAuthorization(emptyAuthorization())
      sessionRef.current = null
    })
    sessionRef.current = nextSession
    try {
      const info = await nextSession.connect({ name, addr, authkey, sarVersion: 2, connectType: 'SPP', reselectPort, preacquiredPort })
      const deviceSerial = await readDeviceSerial(nextSession)
      setAuthorization(emptyAuthorization())
      setSerial(deviceSerial)
      setConnected(true)
      setDeviceHistory((current) => {
        const next = [{ name: name.trim() || info.name, addr: addr.trim(), lastUsed: Date.now(), authkey: authkey.trim() },
          ...current.filter((item) => item.addr !== addr.trim())]
        writeDeviceHistory(next)
        return next.slice(0, 6)
      })
      await refreshDeviceAuthorization(deviceSerial)
      return nextSession
    } catch (error) {
      await nextSession.disconnect(false).catch(() => undefined)
      if (sessionRef.current === nextSession) sessionRef.current = null
      setConnected(false)
      setSerial('')
      throw error
    }
  }

  const reconnectDeviceSession = async (previous: MiWearSession): Promise<MiWearSession> => {
    sessionRef.current = previous
    try {
      const info = await previous.connect({ name, addr, authkey, sarVersion: 2, connectType: 'SPP', reselectPort: false })
      const reconnectedSerial = await readDeviceSerial(previous)
      if (serial && reconnectedSerial !== serial) {
        throw new Error('重连到的设备序列号与授权绑定不一致，已停止安装')
      }
      setSerial(reconnectedSerial)
      setConnected(true)
      setAuthorization(emptyAuthorization())
      setDeviceHistory((current) => {
        const next = [{ name: name.trim() || info.name, addr: addr.trim(), lastUsed: Date.now(), authkey: authkey.trim() },
          ...current.filter((item) => item.addr !== addr.trim())]
        writeDeviceHistory(next)
        return next.slice(0, 6)
      })
      await refreshDeviceAuthorization(reconnectedSerial)
      return previous
    } catch (error) {
      await previous.disconnect(false).catch(() => undefined)
      if (sessionRef.current === previous) sessionRef.current = null
      setConnected(false)
      setSerial('')
      throw error
    }
  }

  const renameDeviceHistoryEntry = (deviceAddr: string, nextName: string) => {
    setDeviceHistory((current) => {
      const next = current.map((item) => item.addr === deviceAddr ? { ...item, name: nextName.trim() } : item)
      writeDeviceHistory(next)
      return next
    })
  }

  const forgetDeviceHistoryAuthkey = (deviceAddr: string) => {
    setDeviceHistory((current) => {
      const next = current.map((item) => item.addr === deviceAddr ? { name: item.name, addr: item.addr, lastUsed: item.lastUsed } : item)
      writeDeviceHistory(next)
      return next
    })
    setRevealedAuthkeys((current) => { const next = new Set(current); next.delete(deviceAddr); return next })
  }

  const deleteDeviceHistoryEntry = (deviceAddr: string) => {
    setDeviceHistory((current) => {
      const next = current.filter((item) => item.addr !== deviceAddr)
      writeDeviceHistory(next)
      return next
    })
    setRevealedAuthkeys((current) => { const next = new Set(current); next.delete(deviceAddr); return next })
  }

  const clearDeviceHistory = () => {
    setDeviceHistory([])
    writeDeviceHistory([])
    setRevealedAuthkeys(new Set())
  }

  const toggleAuthkeyRevealed = (deviceAddr: string) => {
    setRevealedAuthkeys((current) => {
      const next = new Set(current)
      if (next.has(deviceAddr)) next.delete(deviceAddr); else next.add(deviceAddr)
      return next
    })
  }

  const scan = async () => {
    const bluetooth = (navigator as Navigator & { bluetooth?: { requestDevice(options: object): Promise<{ name?: string; id?: string }> } }).bluetooth
    if (!bluetooth) return notify('当前浏览器不支持蓝牙扫描，请手动填写设备名称与 MAC')
    setScanning(true)
    try {
      notify('正在扫描附近设备…')
      const device = await bluetooth.requestDevice({
        acceptAllDevices: true,
        optionalServices: ['device_information', 'battery_service'],
      })
      const decoded = device.id ? decodeDeviceId(device.id) : ''
      const identifier = decoded || (device.id ?? '')
      if (device.name) setName(device.name)
      if (identifier && isValidDeviceId(identifier)) {
        setAddr(identifier)
        notify(`已识别设备：${device.name || identifier}，填写 authkey 后即可连接`)
      } else {
        notify(`已识别设备：${device.name || '未知'}，但未取得可用设备标识，请重试或手动填写`)
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === 'NotFoundError') notify('已取消设备选择')
      else notify(`扫描失败：${error instanceof Error ? error.message : String(error)}`)
    } finally {
      setScanning(false)
    }
  }

  const connect = async (reselect = false) => {
    try {
      notify('正在连接设备…')
      const session = await openDeviceSession(reselect)
      const info = session.deviceInfo
      notify(`设备 ${(info?.name ?? name) || '未知设备'} 已连接`)
    } catch (error) {
      notify(`连接失败：${error instanceof Error ? error.message : String(error)}`)
    }
  }

  const startInstall = async () => {
    const session = sessionRef.current
    if (!session || !connected) return notify('请先连接设备')
    if (!serial) return notify('尚未读取到设备序列号，请重新连接设备')
    const selectedToken = resourceTokens[resourceId]
    if (!selectedToken || !resourceId) return notify('请先选择资源')
    if (cooldownRemaining > 0) return notify(`设备安装冷却中，还需 ${cooldownRemaining} 秒后可重试`)
    setInstalling(true)
    setProg(null)
    try {
      await streamInstall(
        {
          session,
          authToken: selectedToken,
          resourceId,
          deviceAddr: serial,
          maxReconnectAttempts: 2,
          reconnect: async (attempt, error, previous) => {
            notify(`连接中断，正在自动重连（${attempt}/2）：${error.message}`)
            const replacement = await reconnectDeviceSession(previous)
            notify('设备已重连，正在校验资源并从断点继续')
            return replacement
          },
        },
        { onLog: debug, onProgress: setProg },
      )
      notify('✅ 安装完成')
      setCooldownUntil(0)
    } catch (error) {
      if (error instanceof ReauthRedirect) return
      if (error instanceof InstallCooldownError) {
        setCooldownUntil(Date.now() + error.retryAfterSeconds * 1_000)
        notify(`⏳ ${error.message}`)
      } else {
        notify(`❌ 安装失败：${error instanceof Error ? error.message : String(error)}`)
      }
      if (serial) await refreshDeviceAuthorization(serial).catch(() => undefined)
    } finally {
      setInstalling(false)
    }
  }

  const pct = (n: number, total: number) => (total ? Math.round((n / total) * 100) : 0)
  const devicePct = prog?.device ? Math.round((prog.device.progress ?? 0) * 100) : 0
  // 三个阶段合成一条进度：设备写入占绝大部分实际耗时。
  const overallPct = prog
    ? Math.min(100, Math.round(
        pct(prog.downloaded, prog.downloadTotal) * 0.05
        + pct(prog.decrypted, prog.total) * 0.05
        + devicePct * 0.9,
      ))
    : 0
  const selectedResource = useMemo(
    () => authorizedResources.find((resource) => resource.id === resourceId),
    [authorizedResources, resourceId],
  )

  return (
    <div className="installer-shell">
      <AmbientLayer />
      <div className="ambient-scene" aria-hidden="true">
        <span className="ambient-shape ambient-shape-a" />
        <span className="ambient-shape ambient-shape-b" />
        <span className="ambient-shape ambient-shape-c" />
      </div>
      <header className="site-banner">
        <div className="site-banner-inner">
          <div className="site-banner-heading">
            <p className="eyebrow">{runtimeConfig.brand}</p>
            <h1>资源安装器</h1>
          </div>
          <div className="site-banner-actions">
            <a className="site-banner-link" href={runtimeConfig.redeemUrl}>返回核销页</a>
          </div>
        </div>
      </header>
      <main className="installer-container">
        {errorBanner && <div className="global-error-banner" role="alert"><span>{errorBanner}</span><button type="button" onClick={() => setErrorBanner('')} aria-label="关闭错误提示">关闭</button></div>}
        {connectionUnstable && (
          <div className="global-error-banner" role="alert">
            <span>连接频繁断开。请断开其他应用与该设备的连接：退出小米运动健康 / AstroBox 等正在使用该设备的应用；必要时在系统设置里关闭这些应用的"连接附近设备 / 蓝牙"权限，然后重新连接。</span>
            <button type="button" onClick={() => { setConnectionUnstable(false); disconnectTimesRef.current = [] }} aria-label="关闭连接提示">关闭</button>
          </div>
        )}

      <form className="panel" onSubmit={(event) => { event.preventDefault(); void connect(connected) }}>
        <div className="section-heading"><div><p className="eyebrow">Step 01</p><h2>连接设备</h2><p>扫描并建立设备会话。</p></div></div>
        <div className="form-row">
          <button type="button" onClick={scan} disabled={scanning}>{scanning ? '扫描中…' : '扫描附近设备'}</button>
        </div>
        <div className="form-row">
          <input placeholder="设备名称（扫描后自动填写）" value={name} onChange={(e) => setName(e.target.value)} />
          <input placeholder="设备标识（扫描后自动填写）" value={addr} onChange={(e) => setAddr(e.target.value)} />
        </div>
        {deviceHistory.length > 0 && <div className="history-row"><label>连接历史<select value="" onChange={(event) => {
          const item = deviceHistory.find((entry) => entry.addr === event.target.value)
          if (!item) return
          setName(item.name); setAddr(item.addr); setAuthkey(item.authkey ?? '')
          notify(item.authkey ? `已选择设备：${item.name || item.addr}，已自动填写保存的 authkey` : `已选择设备：${item.name || item.addr}，尚未保存 authkey，请填写`)
        }}><option value="">选择已保存设备</option>{deviceHistory.map((item) => <option key={item.addr} value={item.addr}>{item.name || '未命名设备'} · {item.addr}</option>)}</select></label></div>}
        <div className="form-row">
          <input type="password" autoComplete="off" placeholder="authkey（32 位十六进制，可保存以便自动填写）" value={authkey} onChange={(e) => setAuthkey(e.target.value)} />
          <button type="submit">{connected ? '重新连接（重选设备）' : '连接'}</button>
        </div>
        <div className="form-row">
          <button type="button" className="link-button" onClick={() => setShowAuthkeyHelp(true)}>什么是 authkey，如何获取？</button>
          <button type="button" className="link-button" onClick={() => setShowDeviceManager(true)}>管理已保存的设备</button>
        </div>
        <p className="helper-text">连接前请在手表中开启"连接新手机"，并退出可能占用蓝牙的应用。macOS/Chrome 只支持手表暴露的标准 Bluetooth SPP 串口。</p>
        <div className="status-line"><span className={`status-dot${connected ? ' is-connected' : ''}`} />状态：{connected ? '已连接' : '未连接'}{connected && serial ? ` · 序列号 ${serial}` : ''}</div>
      </form>

      <div className="panel">
        <div className="section-heading"><div><p className="eyebrow">Step 02</p><h2>选择并安装</h2><p>选择资源后仍需明确点击安装。</p></div></div>
        {loadingAuthorization && <p className="authorization-loading" role="status">正在读取此设备可安装的资源…</p>}
        {authorization.policies.length > 0 && (
          <section className="policy-section" aria-label="设备授权策略">
            <div className="policy-section-head"><strong>设备授权策略</strong><span>每次连接均实时校验</span></div>
            <div className="policy-grid">
              {authorization.policies.map((policy, index) => (
                <article className="policy-card" key={`${policy.name}-${policy.expiresAt ?? 'forever'}-${index}`}>
                  <span className="policy-card-label">SUPER ACCESS</span>
                  <strong>{policy.name}</strong>
                  <span>{formatPolicyRemaining(policy.expiresAt, clock)}</span>
                  <small>可访问 {policy.resourceIds.length} 项资源</small>
                </article>
              ))}
            </div>
          </section>
        )}

        {authorizedResources.length > 0 ? (
          <fieldset className="resource-picker">
            <legend>选择本次要安装的一项资源</legend>
            <div className="resource-options">
              {authorizedResources.map((resource) => (
                <label className={`resource-option${resource.id === resourceId ? ' is-selected' : ''}`} key={resource.id}>
                  <input
                    type="radio"
                    name="install-resource"
                    value={resource.id}
                    checked={resource.id === resourceId}
                    disabled={installing}
                    onChange={() => setResourceId(resource.id)}
                  />
                  <span><strong>{resource.name}</strong><small>{resource.version ? `版本 ${resource.version}` : '版本信息暂缺'}</small></span>
                </label>
              ))}
            </div>
          </fieldset>
        ) : (
          <div className="empty-authorization">
            {connected
              ? <>这台设备当前没有可安装的资源。请先在<a href={runtimeConfig.redeemUrl}>核销页</a>完成验证。</>
              : '连接设备后，这里会显示该设备可安装的资源。'}
          </div>
        )}
        <div className="install-action">
          <div><span>本次安装</span><strong>{selectedResource?.name ?? '尚未选择资源'}</strong></div>
          <button type="button" disabled={installing || !selectedResource || cooldownRemaining > 0} onClick={startInstall}>
            {installing ? '安装中…'
              : cooldownRemaining > 0 ? `安装冷却中（${cooldownRemaining}s）`
              : selectedResource ? '安装所选资源' : '请先选择资源'}
          </button>
        </div>
        {cooldownRemaining > 0 && (
          <p className="helper-text" role="status">该设备刚结束一次安装，请稍后重试；还需 {cooldownRemaining} 秒。</p>
        )}
      </div>

      {(prog || installing) && (
        <section className="panel">
          <div className="section-heading"><div><p className="eyebrow">Live status</p><h2>安装进度</h2></div></div>
          <Bar label="整体进度" value={overallPct} />
        </section>
      )}

      {status && <p className="status-message" role="status">{status}</p>}
      </main>
      <InstallFooter />
      {showAuthkeyHelp && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="什么是 authkey，如何获取？" onClick={() => setShowAuthkeyHelp(false)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-head">
              <h3>什么是 authkey，如何获取？</h3>
              <button type="button" onClick={() => setShowAuthkeyHelp(false)} aria-label="关闭">关闭</button>
            </div>
            <p className="modal-intro">authkey 是手表与手机配对后生成的 32 位十六进制密钥，用于与设备建立加密通道。按以下步骤读取：</p>
            <ol className="authkey-steps">
              <li>打开你的"小米运动健康"，点击下方底栏"设备"</li>
              <li>点击下面的"我的"</li>
              <li>向下滑动，点击"关于"</li>
              <li>点击若干次橙色 logo</li>
              <li>看到提示的时候，点击"确认"</li>
              <li>打开表盘自定义工具，选择底栏的"工具"</li>
              <li>选择"AuthKey 读取工具"</li>
              <li>进入后，点击"开始读取"</li>
              <li>点击"复制"</li>
            </ol>
          </div>
        </div>
      )}
      {showDeviceManager && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="管理已保存的设备" onClick={() => setShowDeviceManager(false)}>
          <div className="modal-card" onClick={(event) => event.stopPropagation()}>
            <div className="modal-head">
              <h3>管理已保存的设备</h3>
              <button type="button" onClick={() => setShowDeviceManager(false)} aria-label="关闭">关闭</button>
            </div>
            <p className="modal-intro">仅保存在本浏览器（localStorage），不会上传到服务器。authkey 默认隐藏，点击"显示"查看。</p>
            {deviceHistory.length < 1 ? <p className="helper-text">还没有已保存的设备。</p> : (
              <ul className="device-manager-list">
                {deviceHistory.map((item) => (
                  <li key={item.addr} className="device-manager-item">
                    <div className="device-manager-row">
                      <input
                        aria-label={`设备名称 ${item.addr}`}
                        value={item.name}
                        placeholder="未命名设备"
                        onChange={(event) => renameDeviceHistoryEntry(item.addr, event.target.value)}
                      />
                      <button type="button" className="link-button" onClick={() => deleteDeviceHistoryEntry(item.addr)}>删除</button>
                    </div>
                    <div className="device-manager-row">
                      <code className="device-manager-addr">{item.addr}</code>
                    </div>
                    <div className="device-manager-row">
                      <code className="device-manager-authkey">
                        {item.authkey ? (revealedAuthkeys.has(item.addr) ? item.authkey : '••••••••••••••••••••••••••••••••') : '未保存 authkey'}
                      </code>
                      {item.authkey && <button type="button" className="link-button" onClick={() => toggleAuthkeyRevealed(item.addr)}>{revealedAuthkeys.has(item.addr) ? '隐藏' : '显示'}</button>}
                      {item.authkey && <button type="button" className="link-button" onClick={() => forgetDeviceHistoryAuthkey(item.addr)}>忘记 authkey</button>}
                    </div>
                  </li>
                ))}
              </ul>
            )}
            {deviceHistory.length > 0 && <button type="button" className="link-button" onClick={clearDeviceHistory}>清空全部已保存设备</button>}
          </div>
        </div>
      )}
      {reauthTarget && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-label="需要重新核销">
          <div className="modal-card">
            <div className="modal-head"><h3>需要重新核销</h3></div>
            <p className="modal-intro">当前安装授权已失效或运行环境发生变化。设备连接已安全关闭，请返回核销页重新验证后再继续。</p>
            <div className="form-row">
              <button type="button" onClick={() => { window.location.href = reauthTarget }}>返回核销页</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function Bar({ label, value }: { label: string; value: number }) {
  return (
    <div className="progress-item">
      <div className="progress-label"><span>{label}</span><span>{value}%</span></div>
      <div className="progress-track"><div className="progress-fill" style={{ width: `${value}%` }} /></div>
    </div>
  )
}
