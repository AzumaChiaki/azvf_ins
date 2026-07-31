import { patchWatchfaceChunk, type WatchfaceInstallTransform } from '@azvf/contract'
import { bytesToHex, concatBytes, crc32Final, crc32Init, crc32Update, hexToBytes, u16le, u32le } from './bytes'
import { aes128CcmEncrypt, aes128CtrCrypt, deriveSessionKeys, equalBytes, hmacSha256, SessionKeys } from './crypto'
import {
  buildAppInstall,
  buildAppAction,
  buildAppGetList,
  buildAuthAppConfirm,
  buildAuthAppVerify,
  buildCompanionDevice,
  buildFirmwareInstall,
  buildMassPrepare,
  buildSystemRequest,
  buildWatchfaceAction,
  buildWatchfaceGetList,
  buildWatchfaceInstall,
  IncomingMessage,
  parseWearPacket
} from './protobuf'
import { decodeL2, encodeL2, L1StreamDecoder, L2Channel, L2Opcode, SarController } from './sar'

interface SerialReader {
  read(): Promise<{ done: boolean; value?: Uint8Array }>
  cancel?(): Promise<void>
  releaseLock(): void
}

interface SerialWriter {
  write(data: Uint8Array): Promise<void>
  close?(): Promise<void>
  releaseLock(): void
}

interface SerialPortLike {
  readable: { getReader(): SerialReader } | null
  writable: { getWriter(): SerialWriter } | null
  open(options: { baudRate: number }): Promise<void>
  close(): Promise<void>
  getInfo(): { usbVendorId?: number; usbProductId?: number; serialNumber?: string; bluetoothServiceClassId?: string }
}

interface SerialRequestOptions {
  filters?: Array<{ bluetoothServiceClassId: string }>
  allowedBluetoothServiceClassIds?: string[]
}

interface SerialApi {
  requestPort(options?: SerialRequestOptions): Promise<SerialPortLike>
  getPorts?(): Promise<SerialPortLike[]>
}

export interface ConnectOptions {
  name: string
  addr: string
  authkey: string
  sarVersion: number
  connectType: string
  /** Force the serial picker even when a port was already authorized. */
  reselectPort?: boolean
  /**
   * Port acquired ahead of time via {@link requestSerialPort} so the call to
   * `serial.requestPort()` happens within a user gesture. When set the
   * session opens this port instead of calling `requestPort()` itself.
   */
  preacquiredPort?: SerialPortLike
}

export interface DeviceConnectionInfo {
  name: string
  addr: string
}

export interface InstallProgress {
  progress: number
  total_parts: number
  current_part_num: number
  actual_data_payload_len: number
  message?: string
}

/** 明文分片拉取源（按顺序返回明文，null 表示结束）。用于真流式安装：数据边到边喂给设备，前端不重组完整包 */
export interface PlaintextSource {
  pull(): Promise<Uint8Array | null>
}

export async function consumeResumedPlaintext(
  source: PlaintextSource,
  retainedBytes: number,
  totalBytes: number,
  consume: (piece: Uint8Array) => Promise<void>,
  watchfaceTransform?: WatchfaceInstallTransform,
): Promise<void> {
  let fileOffset = 0
  while (fileOffset < totalBytes) {
    const chunk = await source.pull()
    if (!chunk) throw new Error('明文流在数据发送完成前结束')
    if (chunk.length === 0) continue
    const available = Math.min(chunk.length, totalBytes - fileOffset)
    const start = Math.max(0, retainedBytes - fileOffset)
    const output = watchfaceTransform ? patchWatchfaceChunk(chunk, fileOffset, watchfaceTransform) : chunk
    if (start < available) await consume(output.subarray(start, available))
    fileOffset += available
  }
}

/** 流式安装参数（Prepare 所需的 md5/size/id 由服务端预先算好下发，无需本地持有完整数据） */
export interface StreamingInstallOptions {
  resType: number
  packageName: string | null
  /** 明文 MD5，16 字节 */
  md5: Uint8Array
  /** 明文总字节数 */
  size: number
  /** 表盘每次安装的 ID/MD5/文件头改写参数，由会话 HMAC 认证。 */
  watchfaceTransform?: WatchfaceInstallTransform
  source: PlaintextSource
  /** Device-reported retained byte state after MASS Prepare. */
  onResumeState?: (retainedBytes: number, totalBytes: number) => void
  onPartAcknowledged?: (part: number, total: number) => void
}

type MessageKind = IncomingMessage['kind']

interface Waiter {
  kinds: Set<MessageKind>
  resolve: (message: IncomingMessage) => void
  reject: (error: Error) => void
  timer?: ReturnType<typeof setTimeout>
}

interface ResponseWaitHandle {
  promise: Promise<IncomingMessage>
  startTimeout(timeoutMs: number): void
  cancel(error: Error): void
}

export class DeviceResponseTimeoutError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'DeviceResponseTimeoutError'
  }
}

function massPrepareFailure(status: number): string {
  if (status === 1) return '设备繁忙，可能仍在清理上一次传输状态'
  return `设备拒绝 MASS 传输（状态码 ${status}），请检查可用存储空间、电量及资源数量限制`
}

function installPrepareFailure(status: number): string {
  if (status === 1) return '设备正忙，拒绝安装准备'
  if (status === 2) return '设备已存在相同资源，拒绝重复安装'
  if (status === 3) return '设备存储空间不足，拒绝安装准备'
  if (status === 4) return '设备电量过低，拒绝安装准备'
  if (status === 5) return '设备判定资源 ID 重复或版本降级（状态码 5）'
  if (status === 6) return '设备不支持此安装操作'
  if (status === 7) return '设备资源数量已达上限'
  return `设备拒绝安装准备，状态码 ${status}`
}

const wait = (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds))

export function normalizeRetainedBytes(reported: number, totalBytes: number): number {
  if (!Number.isSafeInteger(reported) || reported < 0) return 0
  return Math.min(reported, totalBytes)
}

const SERIAL_HELLO = Uint8Array.of(0xba, 0xdc, 0xfe, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x10, 0x0e, 0xf0)
const BLUETOOTH_SPP_SERVICE = '00001101-0000-1000-8000-00805f9b34fb'
export const SPP_WRITE_CHUNK_SIZE = 60 * 1024

/**
 * Request a Bluetooth SPP serial port. Must be called within a user gesture
 * (click, keypress, etc.) or Chrome will reject it with "Must be handling a
 * user gesture to show a permission request."
 *
 * Callers should invoke this synchronously in the event handler and await the
 * returned promise later — the transient-activation check happens at call time,
 * not at resolution time.
 */
export async function requestSerialPort(): Promise<SerialPortLike> {
  const serial = (navigator as Navigator & { serial?: SerialApi }).serial
  if (!serial) throw new Error('当前浏览器不支持 Web Serial API')
  try {
    return await serial.requestPort({
      filters: [{ bluetoothServiceClassId: BLUETOOTH_SPP_SERVICE }],
      // Required for Chrome to open a Bluetooth serial port over this service
      // class; without it the watch may appear in the picker yet fail to open.
      allowedBluetoothServiceClassIds: [BLUETOOTH_SPP_SERVICE],
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'NotFoundError') {
      throw new Error('未选择可用的蓝牙 SPP 串口。请先在手表中开启"连接新手机"，并确认 Chrome 的端口列表中出现手表')
    }
    throw error
  }
}

export function serialWriteSlices(data: Uint8Array): Uint8Array[] {
  const slices: Uint8Array[] = []
  for (let offset = 0; offset < data.length; offset += SPP_WRITE_CHUNK_SIZE) {
    slices.push(data.subarray(offset, Math.min(offset + SPP_WRITE_CHUNK_SIZE, data.length)))
  }
  return slices
}

export class MiWearSession {
  private port?: SerialPortLike
  private lastPort?: SerialPortLike
  private reader?: SerialReader
  private writer?: SerialWriter
  private sar?: SarController
  private readLoop?: Promise<void>
  private keys?: SessionKeys
  private writeChain = Promise.resolve()
  private stream = new L1StreamDecoder()
  private readonly waiters: Waiter[] = []
  private info?: DeviceConnectionInfo
  private disconnectNotified = false
  private connectionState: 'idle' | 'connecting' | 'connected' = 'idle'

  constructor(private readonly onDisconnect?: (info: DeviceConnectionInfo) => void) {}

  async connect(options: ConnectOptions): Promise<DeviceConnectionInfo> {
    if (options.sarVersion !== 2) throw new Error('工程还原后端目前只支持 SAR v2')
    if (options.connectType.toUpperCase() !== 'SPP') throw new Error('Web Serial 后端只支持 SPP')
    if (!/^[0-9a-f]{32}$/i.test(options.authkey)) throw new Error('authkey 必须是 32 位十六进制字符串')
    const serial = (navigator as Navigator & { serial?: SerialApi }).serial
    if (!serial) throw new Error('当前浏览器不支持 Web Serial API')

    if (this.connectionState !== 'idle') throw new Error('设备连接正在进行中，请稍候')
    this.connectionState = 'connecting'
    this.disconnectNotified = false
    this.stream = new L1StreamDecoder()
    this.writeChain = Promise.resolve()
    try {
      this.port = await this.acquireOpenPort(serial, options.reselectPort ?? false, options.preacquiredPort)
      this.lastPort = this.port
      if (!this.port.readable || !this.port.writable) throw new Error('串口不可读写')
      this.reader = this.port.readable.getReader()
      this.writer = this.port.writable.getWriter()

      const portInfo = this.port.getInfo()
      const fallbackAddr = portInfo.serialNumber
        ? `serial:${portInfo.serialNumber}`
        : portInfo.usbVendorId !== undefined && portInfo.usbProductId !== undefined
          ? `usb:${portInfo.usbVendorId.toString(16).padStart(4, '0')}:${portInfo.usbProductId.toString(16).padStart(4, '0')}`
          : `serial-port-${Date.now()}`
      this.info = { name: options.name || portInfo.serialNumber || 'Bluetooth Device', addr: options.addr.trim() || fallbackAddr }

      this.sar = new SarController(data => this.writeRaw(data), payload => this.onL2(payload))
      this.readLoop = this.runReadLoop()
      await this.writeRaw(SERIAL_HELLO)
      await this.sar.start()
      // Hold the first auth frame until the watch echoes the SAR negotiation.
      // A device still bringing up its SPP link right after「连接新手机」often
      // drops data sent before it has answered the config handshake, which is a
      // frequent cause of connect failures. Best-effort: proceed after 2s if
      // the firmware never echoes (AstroBox does not hard-require the echo).
      await this.sar.awaitNegotiation(2000)
      await this.authenticate(options.authkey)
      this.connectionState = 'connected'
      return this.info
    } catch (error) {
      await this.disconnect(false)
      throw error
    }
  }

  private async acquireOpenPort(serial: SerialApi, reselect: boolean, preacquiredPort?: SerialPortLike): Promise<SerialPortLike> {
    const openOnce = async (p: SerialPortLike) => {
      try {
        await p.open({ baudRate: 115200 })
      } catch {
        // A port left open by a previous attempt (or the same page) rejects
        // re-open; reset it once and retry before giving up on this candidate.
        try { await p.close() } catch { /* ignore */ }
        await p.open({ baudRate: 115200 })
      }
    }
    // Port acquired ahead of time by the caller (inside a user gesture). Open
    // it directly — no need to call requestPort() again.
    if (preacquiredPort) {
      await openOnce(preacquiredPort)
      return preacquiredPort
    }
    // Automatic reconnect (no user gesture available): try to reuse a
    // previously authorized port so the system picker never appears.
    if (!reselect) {
      if (this.lastPort) {
        try { await openOnce(this.lastPort); return this.lastPort } catch { /* inspect granted ports next */ }
      }
      // When there is no lastPort we are on the first-connect path, which
      // should have been served by the caller via preacquiredPort.  Fall
      // through to requestPort() only as a last resort; the user gesture
      // may have expired by now, but getPorts() adds another async gap, so
      // skip it and go straight to the picker.
    }
    let picked: SerialPortLike
    try {
      picked = await serial.requestPort({
        filters: [{ bluetoothServiceClassId: BLUETOOTH_SPP_SERVICE }],
        allowedBluetoothServiceClassIds: [BLUETOOTH_SPP_SERVICE],
      })
    } catch (error) {
      if (error instanceof DOMException && error.name === 'NotFoundError') {
        throw new Error('未选择可用的蓝牙 SPP 串口。请先在手表中开启”连接新手机”，并确认 Chrome 的端口列表中出现手表')
      }
      throw error
    }
    try {
      await openOnce(picked)
    } catch {
      const isMac = /Macintosh|Mac OS X/i.test(navigator.userAgent)
      if (isMac) {
        throw new Error('macOS 已找到端口但无法建立 SPP 通信。请在手表中开启”连接新手机”，退出小米运动健康和 AstroBox 后重试；若端口列表没有手表，则当前固件未暴露标准 SPP，Chrome 无法绕过 Serial blocklist')
      }
      throw new Error('无法打开蓝牙 SPP 串口：请关闭可能占用设备的程序，并在手表中开启”连接新手机”后重试')
    }
    return picked
  }

  async disconnect(notify = true): Promise<void> {
    const info = this.info
    this.connectionState = 'idle'
    if (!notify) this.disconnectNotified = true
    this.sar?.close()
    this.rejectWaiters(new Error('设备已断开'))
    const readLoop = this.readLoop
    try {
      await this.reader?.cancel?.()
    } catch {}
    if (readLoop) await readLoop.catch(() => undefined)
    try {
      this.reader?.releaseLock()
    } catch {}
    try {
      await this.writer?.close?.()
    } catch {}
    try {
      this.writer?.releaseLock()
    } catch {}
    try {
      await this.port?.close()
    } catch {}
    this.reader = undefined
    this.writer = undefined
    this.port = undefined
    this.sar = undefined
    this.readLoop = undefined
    this.keys = undefined
    if (notify && info) this.notifyDisconnect()
  }

  get deviceInfo(): DeviceConnectionInfo | undefined {
    return this.info
  }

  /**
   * 真流式安装：明文分片从 `source` 边到边喂入 MASS 分片器，任意时刻只驻留一个滚动缓冲，
   * 前端不重组完整包。Prepare/MASS 头所需的 md5/size/watchfaceId 由服务端预先计算下发。
   */
  async installStreaming(opts: StreamingInstallOptions, progress?: (value: InstallProgress) => void): Promise<void> {
    if (!this.sar || !this.keys) throw new Error('设备尚未完成认证')
    if (opts.md5.length !== 16) throw new Error('md5 必须为 16 字节')

    let preparePacket: Uint8Array
    let prepareKind: MessageKind
    let resultKinds: MessageKind[]
    let massMd5 = opts.md5
    if (opts.resType === 16) {
      if (!opts.watchfaceTransform) throw new Error('流式安装表盘缺少已认证的 ID 改写参数')
      preparePacket = buildWatchfaceInstall(opts.watchfaceTransform.id, opts.size)
      massMd5 = hexToBytes(opts.watchfaceTransform.md5)
      prepareKind = 'watchface-prepare'
      resultKinds = ['watchface-result']
    } else if (opts.resType === 32) {
      preparePacket = buildFirmwareInstall(bytesToHex(opts.md5), opts.size)
      prepareKind = 'firmware-prepare'
      resultKinds = ['firmware-prepare']
    } else if (opts.resType === 64) {
      if (!opts.packageName) throw new Error('安装快应用必须提供 package_name')
      preparePacket = buildAppInstall(opts.packageName, opts.size)
      prepareKind = 'app-prepare'
      resultKinds = ['app-result']
    } else {
      throw new Error(`不支持的安装资源类型: ${opts.resType}`)
    }

    const prepare = await this.requestPb(preparePacket, [prepareKind], 30000)
    if ('status' in prepare && prepare.status !== 0) throw new Error(installPrepareFailure(prepare.status))

    // Register before MASS so an early result cannot be missed, but do not
    // start the final-result deadline until all MASS bytes have been ACKed.
    const resultWaiter = this.waitFor(resultKinds)
    // Observe immediately: a MASS send failure cancels this waiter before the
    // normal await below, and must not create an unhandled rejection.
    void resultWaiter.promise.catch(() => undefined)
    try {
      await this.sendMassStreaming(opts, massMd5, progress)
    } catch (error) {
      const failure = error instanceof Error ? error : new Error(String(error))
      resultWaiter.cancel(failure)
      throw failure
    }
    resultWaiter.startTimeout(opts.resType === 32 ? 15_000 : 120_000)

    let result: IncomingMessage
    try {
      result = await resultWaiter.promise
    } catch (error) {
      if (opts.resType === 32 && error instanceof DeviceResponseTimeoutError) {
        throw new Error('固件数据已传输，但设备未返回可验证的最终结果')
      }
      throw error
    }
    if (result.kind === 'firmware-prepare' && result.status !== 0) {
      throw new Error(`固件安装失败，状态码 ${result.status}`)
    }
    if (result.kind === 'app-result' && result.code !== 0) throw new Error(`快应用安装失败，状态码 ${result.code}`)
    if (result.kind === 'watchface-result' && result.code !== 2 && result.code !== 3) {
      throw new Error(`表盘安装失败，状态码 ${result.code}`)
    }
  }

  private async sendMassStreaming(
    opts: StreamingInstallOptions,
    massMd5: Uint8Array,
    progress?: (value: InstallProgress) => void
  ): Promise<void> {
    let response: IncomingMessage | undefined
    for (let attempt = 0; attempt < 3; attempt++) {
      response = await this.requestPb(buildMassPrepare(opts.resType, massMd5, opts.size), ['mass-prepare'], 30000)
      if (response.kind !== 'mass-prepare') throw new Error('MASS Prepare 返回了错误的响应类型')
      if (response.status === 0) break
      if (response.status !== 1 || attempt === 2) throw new Error(massPrepareFailure(response.status))
      await wait(700 * (attempt + 1))
    }
    if (!response || response.kind !== 'mass-prepare' || response.status !== 0) {
      throw new Error('设备持续繁忙，自动重试后仍无法开始 MASS 传输')
    }
    // L1 encodes payload length as u16. L2 adds two bytes around the MASS
    // slice, so values above 65535 would wrap the frame and an attacker could
    // otherwise force the rolling buffer to retain an entire resource.
    if (!Number.isSafeInteger(response.expectedSliceLength)
      || response.expectedSliceLength <= 6
      || response.expectedSliceLength > 65_535) {
      throw new Error(`设备返回的切片长度无效: ${response.expectedSliceLength}`)
    }

    // BandBurg's AstroBox core treats remainedDataLength as the number of file
    // bytes retained by the watch. A resumed MASS payload gets a fresh header,
    // remaining length and CRC over only the unsent suffix.
    const retainedLen = normalizeRetainedBytes(response.remainedDataLength, opts.size)
    const remainingLen = opts.size - retainedLen
    opts.onResumeState?.(retainedLen, opts.size)
    // massHeader 前缀 = [0,resType] || md5(16) || u32le(remainingLen)（共 22 字节），随后是数据，末尾附 crc32(前缀||数据)
    const prefix = concatBytes(Uint8Array.of(0, opts.resType), massMd5, u32le(remainingLen))
    const encodedLen = prefix.length + remainingLen + 4
    const fragmentSize = response.expectedSliceLength - 6
    const totalParts = Math.ceil(encodedLen / fragmentSize)
    if (!Number.isSafeInteger(totalParts) || totalParts < 1 || totalParts > 0xffff) {
      throw new Error(`MASS 分片总数超出设备协议上限: ${totalParts}`)
    }
    const windowSize = Math.min(this.sar?.windowSize ?? 8, 32)

    let crcState = crc32Init()
    let buffer: Uint8Array = new Uint8Array(0)
    let partNum = 0
    const inflight = new Set<Promise<void>>()
    const fragmentBatch: Array<{ part: number; fragment: Uint8Array }> = []
    // Keep at most one SAR window's worth of MASS fragments outstanding. The
    // window is the real SPP flow-control depth; extra backlog only parks more
    // plaintext file bytes (MASS is an unencrypted L2 write) in memory without
    // improving throughput, since refilling a freed window slot costs only a
    // microtask against a ~115200-baud link. One window keeps the wire full
    // while minimizing resident plaintext for the anti-extraction threat model.
    const backlogLimit = windowSize

    const drainBacklog = async () => {
      while (inflight.size >= backlogLimit) await Promise.race(inflight)
    }
    const flushBatch = async () => {
      if (fragmentBatch.length === 0) return
      const entries = fragmentBatch.splice(0)
      const payloads = entries.map(({ part, fragment }) => encodeL2(
        L2Channel.Mass,
        L2Opcode.Write,
        concatBytes(u16le(totalParts), u16le(part), fragment),
      ))
      const acknowledgements = this.sar!.enqueueBatch(payloads)
      entries.forEach(({ part }, index) => {
        let tracked: Promise<void>
        tracked = acknowledgements[index]!
          .then(() => { opts.onPartAcknowledged?.(part, totalParts) })
          .finally(() => inflight.delete(tracked))
        void tracked.catch(() => undefined)
        inflight.add(tracked)
      })
      await drainBacklog()
    }
    const emit = async (fragment: Uint8Array) => {
      partNum += 1
      fragmentBatch.push({ part: partNum, fragment })
      const segmentProgress = partNum / totalParts
      const overallProgress = opts.size === 0
        ? 1
        : retainedLen / opts.size + (remainingLen / opts.size) * segmentProgress
      progress?.({
        progress: overallProgress,
        total_parts: totalParts,
        current_part_num: partNum,
        actual_data_payload_len: fragment.length + 4,
        message: retainedLen > 0
          ? `已恢复 ${retainedLen} 字节，继续传输 ${partNum}/${totalParts}`
          : `正在传输 ${partNum}/${totalParts}`
      })
      if (fragmentBatch.length >= windowSize) await flushBatch()
    }
    const feed = async (bytes: Uint8Array) => {
      if (bytes.length === 0) return
      let offset = 0
      if (buffer.length > 0) {
        const needed = fragmentSize - buffer.length
        if (bytes.length < needed) {
          buffer = concatBytes(buffer, bytes)
          return
        }
        const fragment = new Uint8Array(fragmentSize)
        fragment.set(buffer)
        fragment.set(bytes.subarray(0, needed), buffer.length)
        buffer = new Uint8Array(0)
        offset = needed
        await emit(fragment)
      }
      while (offset + fragmentSize <= bytes.length) {
        await emit(bytes.subarray(offset, offset + fragmentSize))
        offset += fragmentSize
      }
      if (offset < bytes.length) buffer = bytes.slice(offset)
    }

    // 1) 前缀（计入 CRC）
    crcState = crc32Update(crcState, prefix)
    await feed(prefix)

    // 2) 数据。服务端重放仍从文件开头开始，以便浏览器重新验证完整
    // manifest；先消费设备已保留的前缀，再只编码剩余后缀。
    let consumed = 0
    await consumeResumedPlaintext(opts.source, retainedLen, opts.size, async (piece) => {
      crcState = crc32Update(crcState, piece)
      consumed += piece.length
      await feed(piece)
    }, opts.watchfaceTransform)
    if (consumed !== remainingLen) throw new Error('断点续传的剩余明文长度不一致')

    // 3) 末尾 CRC（不计入 CRC 自身）
    await feed(u32le(crc32Final(crcState)))

    // 4) 冲刷最后一个不足整片的分片，并等待全部 ACK
    if (buffer.length > 0) await emit(buffer)
    await flushBatch()
    if (inflight.size > 0) await Promise.all(inflight)
  }

  async getData(dataType: string): Promise<any> {
    const normalized = dataType.toLowerCase()
    const request = normalized === 'info'
      ? { id: 2, kind: 'device-info' as const }
      : normalized === 'status'
        ? { id: 1, kind: 'device-status' as const }
        : normalized === 'storage'
          ? { id: 62, kind: 'storage-info' as const }
          : undefined
    if (!request) throw new Error(`不支持的设备数据类型: ${dataType}`)
    const response = await this.requestPb(buildSystemRequest(request.id), [request.kind], 30000)
    if (response.kind !== request.kind) throw new Error('设备数据响应类型错误')
    return response.data
  }

  async getWatchfaces(): Promise<Array<Record<string, any>>> {
    const response = await this.requestPb(buildWatchfaceGetList(), ['watchface-list'], 30000)
    if (response.kind !== 'watchface-list') throw new Error('表盘列表响应类型错误')
    return response.data
  }

  async setCurrentWatchface(id: string): Promise<void> {
    await this.sendPb(buildWatchfaceAction(1, id))
  }

  async uninstallWatchface(id: string): Promise<void> {
    await this.sendPb(buildWatchfaceAction(2, id))
  }

  async getApps(): Promise<Array<Record<string, any>>> {
    const response = await this.requestPb(buildAppGetList(), ['app-list'], 30000)
    if (response.kind !== 'app-list') throw new Error('快应用列表响应类型错误')
    return response.data
  }

  async launchApp(packageName: string, page: string): Promise<void> {
    const app = await this.findApp(packageName)
    await this.sendPb(buildAppAction(4, packageName, app.fingerprint, page))
  }

  async uninstallApp(packageName: string): Promise<void> {
    const app = await this.findApp(packageName)
    await this.sendPb(buildAppAction(3, packageName, app.fingerprint))
  }

  async sendAppMessage(packageName: string, data: string): Promise<void> {
    const app = await this.findApp(packageName)
    await this.sendPb(buildAppAction(8, packageName, app.fingerprint, undefined, new TextEncoder().encode(data)))
  }

  private async authenticate(authkey: string): Promise<void> {
    const phoneNonce = crypto.getRandomValues(new Uint8Array(16))
    const verify = await this.requestPb(buildAuthAppVerify(phoneNonce), ['auth-device-verify'], 30000, false)
    if (verify.kind !== 'auth-device-verify') throw new Error('认证响应类型错误')
    if (verify.deviceRandom.length !== 16 || verify.deviceSign.length !== 32) throw new Error('设备认证随机数或签名长度错误')

    const keys = await deriveSessionKeys(authkey, phoneNonce, verify.deviceRandom)
    const expected = await hmacSha256(keys.decKey, verify.deviceRandom, phoneNonce)
    if (!equalBytes(expected, verify.deviceSign)) throw new Error('Auth HMAC 不匹配，请检查 authkey')
    const appSign = await hmacSha256(keys.encKey, phoneNonce, verify.deviceRandom)
    const nonce = concatBytes(keys.encNonce, new Uint8Array(8))
    const encryptedDevice = await aes128CcmEncrypt(keys.encKey, nonce, buildCompanionDevice(0))
    this.keys = keys

    const confirm = await this.requestPb(buildAuthAppConfirm(appSign, encryptedDevice), ['auth-device-confirm'], 30000, false)
    if (confirm.kind !== 'auth-device-confirm' || !confirm.confirmed) throw new Error('设备未确认认证')
  }

  private async requestPb(
    packet: Uint8Array,
    responseKinds: MessageKind[],
    timeoutMs: number,
    encrypted = true
  ): Promise<IncomingMessage> {
    const response = this.waitFor(responseKinds, timeoutMs)
    void response.promise.catch(() => undefined)
    try {
      await this.sendPb(packet, encrypted)
    } catch (error) {
      const failure = error instanceof Error ? error : new Error(String(error))
      response.cancel(failure)
      throw failure
    }
    return response.promise
  }

  private async sendPb(packet: Uint8Array, encrypted = true): Promise<void> {
    if (!this.sar) throw new Error('SAR 尚未初始化')
    if (encrypted) {
      if (!this.keys) throw new Error('加密会话尚未建立')
      const ciphertext = await aes128CtrCrypt(this.keys.encKey, packet)
      return this.sar.enqueue(encodeL2(L2Channel.Pb, L2Opcode.WriteEnc, ciphertext))
    }
    return this.sar.enqueue(encodeL2(L2Channel.Pb, L2Opcode.Write, packet))
  }

  private async findApp(packageName: string): Promise<{ fingerprint: Uint8Array }> {
    const apps = await this.getApps()
    const app = apps.find(item => item.packageName === packageName)
    if (!app) throw new Error(`设备中未找到快应用: ${packageName}`)
    return { fingerprint: Uint8Array.from(app.fingerprint ?? []) }
  }

  private async onL2(data: Uint8Array): Promise<void> {
    const l2 = decodeL2(data)
    if (l2.channel !== L2Channel.Pb) return
    let payload = l2.payload
    if (l2.opcode === L2Opcode.WriteEnc) {
      if (!this.keys) throw new Error('收到加密 PB 包时会话密钥尚未建立')
      payload = await aes128CtrCrypt(this.keys.decKey, payload)
    }
    const message = parseWearPacket(payload)
    if (message.kind === 'unknown') return
    const index = this.waiters.findIndex(waiter => waiter.kinds.has(message.kind))
    if (index >= 0) {
      const [waiter] = this.waiters.splice(index, 1)
      if (waiter.timer) clearTimeout(waiter.timer)
      waiter.resolve(message)
    }
  }

  private waitFor(kinds: MessageKind[], timeoutMs?: number): ResponseWaitHandle {
    let waiter: Waiter
    const promise = new Promise<IncomingMessage>((resolve, reject) => {
      waiter = {
        kinds: new Set(kinds),
        resolve,
        reject,
      }
      this.waiters.push(waiter)
    })
    const startTimeout = (durationMs: number): void => {
      if (this.waiters.indexOf(waiter) < 0 || waiter.timer) return
      if (!Number.isSafeInteger(durationMs) || durationMs < 1) throw new Error('设备响应超时参数无效')
      waiter.timer = setTimeout(() => {
        const index = this.waiters.indexOf(waiter)
        if (index >= 0) this.waiters.splice(index, 1)
        waiter.reject(new DeviceResponseTimeoutError(`等待设备响应超时: ${kinds.join(', ')}`))
      }, durationMs)
    }
    if (timeoutMs !== undefined) startTimeout(timeoutMs)
    return {
      promise,
      startTimeout,
      cancel: (error) => {
        const index = this.waiters.indexOf(waiter)
        if (index < 0) return
        this.waiters.splice(index, 1)
        if (waiter.timer) clearTimeout(waiter.timer)
        waiter.reject(error)
      }
    }
  }

  private async runReadLoop(): Promise<void> {
    let terminalError = new Error('串口读取已结束')
    try {
      while (this.reader) {
        const { done, value } = await this.reader.read()
        if (done) {
          terminalError = new Error('串口数据流已由系统结束')
          break
        }
        if (!value) continue
        for (const frame of this.stream.push(new Uint8Array(value))) await this.sar?.receive(frame)
      }
    } catch (error) {
      terminalError = new Error(`串口读取失败：${error instanceof Error ? error.message : String(error)}`)
      console.warn('[reconstructed] 串口读取结束', error)
    } finally {
      this.sar?.close(terminalError.message)
      this.rejectWaiters(terminalError)
      if (this.connectionState !== 'idle') {
        this.connectionState = 'idle'
        this.notifyDisconnect()
      }
      try { this.reader?.releaseLock() } catch {}
      try { this.writer?.releaseLock() } catch {}
      void this.port?.close().catch(() => undefined)
      this.reader = undefined
      this.writer = undefined
      this.port = undefined
      this.sar = undefined
      this.readLoop = undefined
      this.keys = undefined
    }
  }

  private writeRaw(data: Uint8Array): Promise<void> {
    const operation = this.writeChain.then(async () => {
      if (!this.writer) throw new Error('串口写入器不可用')
      // Match AstroBox/BandBurg's SPP coalescing cap. A 977-byte write size
      // creates thousands of JS→Web Serial promises for large resources and
      // keeps macOS Bluetooth SPP active long enough to be torn down midway.
      for (const slice of serialWriteSlices(data)) await this.writer.write(slice)
    })
    this.writeChain = operation.catch(() => undefined)
    return operation
  }

  private rejectWaiters(error: Error): void {
    for (const waiter of this.waiters.splice(0)) {
      if (waiter.timer) clearTimeout(waiter.timer)
      waiter.reject(error)
    }
  }

  private notifyDisconnect(): void {
    if (!this.disconnectNotified && this.info) {
      this.disconnectNotified = true
      this.onDisconnect?.(this.info)
    }
  }
}
