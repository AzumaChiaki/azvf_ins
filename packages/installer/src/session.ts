import { timingSafeEqual } from 'node:crypto'
import type { SessionInitResponse, SignedResourceMeta, WatchfaceInstallTransform } from '@azvf/contract'
import type { SessionControlContext, SessionCryptoKeys } from './crypto/index.js'
export type InstallSessionState = 'created' | 'authorizing' | 'streaming' | 'recoverable' | 'delivered' | 'cancelled'

export interface InstallSession {
  sessionId: string
  attemptId: string
  initializationFingerprint: Buffer
  initialResponse: SessionInitResponse
  resourceId: string
  userId: string
  entitlementId: string
  /** Resource-bound one-shot/idempotency key derived from JWT jti. */
  consumptionId: string
  /** Original signed JWT retained only in process memory for Console re-verification. */
  authorization: string
  /** Opaque Console bearer bound to this session/resource/internal client. */
  resourceCapability: string
  capabilityExpiresAt: number
  deviceAddress: string
  clientIp: string
  clientAttributes: NonNullable<import('@azvf/contract').SessionInitRequest['clientAttributes']>
  throttle: {
    mode: 'enforced' | 'disabled'
    sessionId: string
    ratePerSecond?: number
    burstBytes?: number
    sampleWindowMs?: number
  }
  lastHeartbeatAt?: number
  /** HKDF 派生的用途隔离密钥，全部不可导出。 */
  cryptoKeys: SessionCryptoKeys
  controlContext: SessionControlContext
  /** 1=真实，0=诱饵；真假标记只会出现在认证密文内部。 */
  frameSchedule: Uint8Array
  /** Makes decoy plaintext byte-identical when an authenticated stream is replayed for resume. */
  decoySeed: Buffer
  controlTokenHash: Buffer
  meta: SignedResourceMeta
  watchfaceTransform?: WatchfaceInstallTransform
  createdAt: number
  expiresAt: number
  absoluteExpiresAt: number
  state: InstallSessionState
  /**
   * 本会话到目前为止开过的流的代数,每次进入 streaming 递增。
   * 正在跑的生成器捕获自己那一代:一旦被同一会话的新连接接管,代数就变了,
   * 旧生成器据此静默收手,绝不再去改已经归新连接所有的会话/租约状态。
   * 老客户端不感知这个字段,行为不受影响。
   */
  streamEpoch: number
}

export class SessionStore {
  private readonly sessions = new Map<string, InstallSession>()
  private readonly attempts = new Map<string, string>()
  private readonly timer: NodeJS.Timeout

  constructor(
    private readonly onExpired: (session: InstallSession) => void,
    private readonly now: () => number = Date.now,
  ) {
    this.timer = setInterval(() => this.cleanup(), 30_000)
    this.timer.unref?.()
  }

  put(session: InstallSession): void {
    if (this.sessions.has(session.sessionId)) throw new Error('会话 ID 冲突')
    if (this.attempts.has(session.attemptId)) throw new Error('会话创建尝试 ID 冲突')
    this.sessions.set(session.sessionId, session)
    this.attempts.set(session.attemptId, session.sessionId)
  }

  initialization(attemptId: string, fingerprint: Buffer): SessionInitResponse | 'conflict' | undefined {
    const sessionId = this.attempts.get(attemptId)
    if (!sessionId) return undefined
    const session = this.live(sessionId)
    if (!session) {
      this.attempts.delete(attemptId)
      return undefined
    }
    if (session.initializationFingerprint.length !== fingerprint.length
      || !timingSafeEqual(session.initializationFingerprint, fingerprint)) return 'conflict'
    return session.initialResponse
  }

  private drop(id: string): InstallSession | undefined {
    const session = this.sessions.get(id)
    if (!session) return undefined
    this.sessions.delete(id)
    if (this.attempts.get(session.attemptId) === id) this.attempts.delete(session.attemptId)
    return session
  }

  private live(id: string): InstallSession | undefined {
    const session = this.sessions.get(id)
    if (!session) return undefined
    if (this.now() >= session.expiresAt) {
      this.drop(id)
      this.onExpired(session)
      return undefined
    }
    return session
  }

  get(id: string): Readonly<InstallSession> | undefined {
    return this.live(id)
  }

  /** Claim before any async live-check so concurrent stream requests cannot race. */
  claim(id: string): InstallSession | undefined {
    const session = this.live(id)
    if (!session || session.state !== 'created') return undefined
    session.state = 'authorizing'
    return session
  }

  /** Replays use the same authenticated session and do not consume a new JWT. */
  claimReplay(id: string): InstallSession | undefined {
    const session = this.live(id)
    if (!session || !['recoverable', 'delivered'].includes(session.state)) return undefined
    session.state = 'authorizing'
    return session
  }

  markStreaming(id: string, expiresAt: number): InstallSession | undefined {
    const session = this.live(id)
    if (!session || session.state !== 'authorizing') return undefined
    session.state = 'streaming'
    session.expiresAt = expiresAt
    session.streamEpoch += 1
    return session
  }

  /**
   * 同一会话的新连接接管正在进行的流。把会话退回 recoverable,后续按既有的
   * claimReplay 断点续传路径走 —— 与"等服务端自己察觉断开"落到的是同一个状态,
   * 只是不必再等。控制令牌已在调用方校验过,所以只有会话本人能接管。
   */
  supersedeStream(id: string, expiresAt: number): InstallSession | undefined {
    const session = this.live(id)
    // 只接管 streaming:那说明已经有一条流在跑,可以靠 streamEpoch 让它干净退出。
    // authorizing 是另一个请求正在建流的中间态(还在等 Console 的核销往返),
    // 这时插进去会和它的 markStreaming 抢状态,而那条失败路径会 sessions.remove()
    // 把会话直接销毁 —— 真正并发的重复请求仍按原样拒掉第二个。
    if (!session || session.state !== 'streaming') return undefined
    session.state = 'recoverable'
    session.expiresAt = expiresAt
    return session
  }

  markDelivered(id: string): boolean {
    const session = this.live(id)
    if (!session || session.state !== 'streaming') return false
    session.state = 'delivered'
    return true
  }

  markRecoverable(id: string, expiresAt: number): InstallSession | undefined {
    const session = this.live(id)
    if (!session || !['authorizing', 'streaming'].includes(session.state)) return undefined
    session.state = 'recoverable'
    session.expiresAt = expiresAt
    return session
  }

  cancel(id: string): InstallSession | undefined {
    const session = this.live(id)
    if (!session || !['authorizing', 'streaming'].includes(session.state)) return undefined
    session.state = 'cancelled'
    return session
  }

  authorizeControl(id: string, presentedHash: Buffer): InstallSession | undefined {
    const session = this.live(id)
    if (!session || session.controlTokenHash.length !== presentedHash.length) return undefined
    return timingSafeEqual(session.controlTokenHash, presentedHash) ? session : undefined
  }

  remove(id: string): InstallSession | undefined {
    return this.drop(id)
  }

  cleanup(): void {
    const now = this.now()
    for (const [id, session] of this.sessions) {
      if (now >= session.expiresAt) {
        this.drop(id)
        this.onExpired(session)
      }
    }
  }

  close(): void {
    clearInterval(this.timer)
    for (const session of this.sessions.values()) this.onExpired(session)
    this.sessions.clear()
    this.attempts.clear()
  }
}
