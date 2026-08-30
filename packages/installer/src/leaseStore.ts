import { chmodSync, lstatSync, mkdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname } from 'node:path'
import type { DatabaseSync as DatabaseSyncType } from 'node:sqlite'
import type { InstallTier } from './config.js'

// Vite 5's builtin-module table predates node:sqlite. createRequire keeps this
// runtime builtin external while retaining compile-time Node 22 types.
const { DatabaseSync } = createRequire(import.meta.url)('node:sqlite') as typeof import('node:sqlite')

export type LeaseErrorCode = 'TOKEN_REPLAY' | 'GLOBAL_LIMIT' | 'USER_LIMIT' | 'ENTITLEMENT_LIMIT' | 'DEVICE_LIMIT' | 'IP_LIMIT'

export class LeaseError extends Error {
  constructor(
    public readonly code: LeaseErrorCode,
    message: string,
    /** Seconds until the blocking condition clears, surfaced as Retry-After. */
    public readonly retryAfterSeconds?: number,
  ) {
    super(message)
    this.name = 'LeaseError'
  }
}

export interface LeaseLimits {
  global: number
  perIp: number
  perEntitlement: number
  byTier: Readonly<Record<InstallTier, number>>
}

export interface AcquireLeaseInput {
  id: string
  tokenJti: string
  tokenExpiresAt: number
  userId: string
  entitlementId: string
  deviceAddress: string
  resourceId: string
  ipAddress: string
  tier: InstallTier
  tokenConcurrency: number
  expiresAt: number
}

interface CountRow { count: number }
const CONSUMED_TOKEN_RETENTION_MS = 24 * 60 * 60 * 1_000
const EVENT_RETENTION_MS = 30 * 24 * 60 * 60 * 1_000
// After this many consecutive failed installs of the same resource on the same
// device, the next acquire clears that device's residual lease so a user stuck
// behind a crashed attempt can retry immediately (the "CD 豁免").
const FAILURE_EXEMPT_THRESHOLD = 2
// A failure streak older than this is treated as stale and no longer grants the
// exemption, so the per-device cooldown is only waived for active retry loops.
const FAILURE_STREAK_TTL_MS = 30 * 60 * 1_000

export type InstallEventType = 'session.created' | 'stream.started' | 'stream.resumed' | 'stream.interrupted'
  | 'device.disconnected' | 'device.reconnect' | 'device.resumed' | 'install.failed' | 'install.completed'

export class LeaseStore {
  private readonly db: DatabaseSyncType

  constructor(
    path: string,
    private readonly limits: LeaseLimits,
    private readonly now: () => number = Date.now,
  ) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    try {
      if (lstatSync(path).isSymbolicLink()) throw new Error('Installer SQLite 数据库不能是符号链接')
    } catch (error: any) {
      if (error?.code !== 'ENOENT') throw error
    }
    this.db = new DatabaseSync(path)
    try { chmodSync(path, 0o600) } catch { /* 某些平台不支持 POSIX 权限 */ }
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = FULL;
      PRAGMA foreign_keys = ON;
      PRAGMA busy_timeout = 5000;
      CREATE TABLE IF NOT EXISTS consumed_tokens (
        jti TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL
      ) STRICT;
      CREATE TABLE IF NOT EXISTS install_leases (
        id TEXT PRIMARY KEY,
        token_jti TEXT NOT NULL UNIQUE REFERENCES consumed_tokens(jti) ON DELETE CASCADE,
        user_id TEXT NOT NULL,
        entitlement_id TEXT NOT NULL,
        device_address TEXT NOT NULL,
        resource_id TEXT NOT NULL DEFAULT '',
        ip_address TEXT NOT NULL,
        tier TEXT NOT NULL CHECK (tier IN ('basic','standard','premium','internal')),
        token_concurrency INTEGER NOT NULL CHECK (token_concurrency BETWEEN 1 AND 32),
        state TEXT NOT NULL CHECK (state IN ('created','streaming','delivered')),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      ) STRICT;
      CREATE UNIQUE INDEX IF NOT EXISTS one_active_install_per_device ON install_leases(device_address);
      CREATE INDEX IF NOT EXISTS install_leases_user ON install_leases(user_id);
      CREATE INDEX IF NOT EXISTS install_leases_entitlement ON install_leases(entitlement_id);
      CREATE INDEX IF NOT EXISTS install_leases_ip ON install_leases(ip_address);
      CREATE INDEX IF NOT EXISTS install_leases_expiry ON install_leases(expires_at);
      CREATE INDEX IF NOT EXISTS consumed_tokens_expiry ON consumed_tokens(expires_at);
      CREATE TABLE IF NOT EXISTS install_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        entitlement_id TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        device_address TEXT NOT NULL,
        event_type TEXT NOT NULL,
        detail TEXT,
        attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 100),
        acknowledged_part INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged_part >= 0),
        created_at INTEGER NOT NULL
      ) STRICT;
      CREATE INDEX IF NOT EXISTS install_events_session ON install_events(session_id, created_at);
      CREATE INDEX IF NOT EXISTS install_events_created ON install_events(created_at);
      CREATE TABLE IF NOT EXISTS install_failure_streaks (
        device_address TEXT NOT NULL,
        resource_id TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0 CHECK (count >= 0),
        updated_at INTEGER NOT NULL,
        PRIMARY KEY (device_address, resource_id)
      ) STRICT;
      CREATE INDEX IF NOT EXISTS install_failure_streaks_updated ON install_failure_streaks(updated_at);
    `)
    const columns = this.db.prepare('PRAGMA table_info(install_leases)').all() as Array<Record<string, unknown>>
    if (!columns.some((column) => column.name === 'token_concurrency')) {
      this.db.exec('ALTER TABLE install_leases ADD COLUMN token_concurrency INTEGER NOT NULL DEFAULT 1 CHECK (token_concurrency BETWEEN 1 AND 32)')
    }
    // 服务端记失败计数需要知道这条租约装的是哪个资源。老库里的租约没有这一列，
    // 补列后留空字符串：它们过期时无法归属到 (设备, 资源)，只能不计数。
    if (!columns.some((column) => column.name === 'resource_id')) {
      this.db.exec("ALTER TABLE install_leases ADD COLUMN resource_id TEXT NOT NULL DEFAULT ''")
    }
    this.cleanup()
  }

  private transaction<T>(operation: () => T): T {
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const result = operation()
      this.db.exec('COMMIT')
      return result
    } catch (error) {
      try { this.db.exec('ROLLBACK') } catch { /* preserve the original failure */ }
      throw error
    }
  }

  private count(sql: string, value?: string): number {
    const statement = this.db.prepare(sql)
    const row = (value === undefined ? statement.get() : statement.get(value)) as unknown as CountRow
    return Number(row.count)
  }

  /** Seconds until the longest-lived lease matching `whereSql` naturally expires, for a Retry-After hint. */
  private retryAfterFor(whereSql: string, value: string, now: number): number {
    const row = this.db.prepare(`SELECT expires_at FROM install_leases WHERE ${whereSql} ORDER BY expires_at DESC LIMIT 1`)
      .get(value) as { expires_at?: number } | undefined
    return Math.max(1, Math.ceil(((row?.expires_at ?? now) - now) / 1_000))
  }

  private cleanupWithinTransaction(now: number): void {
    // 租约走到自然过期 = 这次安装既没报成功也没报失败（标签页被关掉、浏览器被杀、
    // 断网）。失败计数以前只在客户端 POST /complete 时才 +1，于是最需要 CD 豁免的
    // 那条路径永远记不上数——「连续失败 2 次免 CD」形同虚设。改为在服务端收租约时
    // 记：客户端上报与否都算得准。
    for (const row of this.db.prepare('SELECT device_address, resource_id FROM install_leases WHERE expires_at <= ?')
      .all(now) as Array<Record<string, unknown>>) {
      const resourceId = String(row.resource_id ?? '')
      if (resourceId) this.recordInstallFailureWithinTransaction(String(row.device_address), resourceId, now)
    }
    this.db.prepare('DELETE FROM install_leases WHERE expires_at <= ?').run(now)
    this.db.prepare('DELETE FROM consumed_tokens WHERE expires_at <= ? AND NOT EXISTS (SELECT 1 FROM install_leases WHERE token_jti = consumed_tokens.jti)').run(now)
    this.db.prepare('DELETE FROM install_events WHERE created_at <= ?').run(now - EVENT_RETENTION_MS)
    this.db.prepare('DELETE FROM install_failure_streaks WHERE updated_at <= ?').run(now - FAILURE_STREAK_TTL_MS)
  }

  cleanup(): void {
    this.transaction(() => this.cleanupWithinTransaction(this.now()))
  }

  acquire(input: AcquireLeaseInput): void {
    this.transaction(() => {
      const now = this.now()
      this.cleanupWithinTransaction(now)
      if (this.count('SELECT COUNT(*) AS count FROM consumed_tokens WHERE jti = ?', input.tokenJti) !== 0) {
        throw new LeaseError('TOKEN_REPLAY', '该安装令牌已使用，请获取新令牌')
      }
      if (this.count('SELECT COUNT(*) AS count FROM install_leases') >= this.limits.global) {
        throw new LeaseError('GLOBAL_LIMIT', '安装服务当前繁忙，请稍后重试')
      }

      // 同一设备就同一授权再次发起安装,是重试/换个页面重来,不是第二个并发安装
      // ——一台设备同一时刻只可能跑一个真实安装。以前这种请求要么撞上下面的设备
      // 冷却、要么撞上授权并发上限,新会话被直接拒绝,用户只能干等旧租约自然到期
      // (最长 INSTALL_LEASE_TTL/MAX_DURATION)。而令牌层(Console 的
      // supersedeInstallTokens)早就是"后来者胜":新令牌一签发就撤销旧令牌。两层
      // 语义对不上,于是旧会话被判死、新会话又进不来,买家两头落空。
      // 这里让租约层与令牌层一致:同设备同授权的旧租约直接让位给新会话。
      // 作用域刻意收窄到"同授权":跨授权在同一设备上连开安装仍受设备冷却约束,
      // 不同设备之间的并发仍按账号/授权上限计数,多并发权限的语义不受影响。
      this.db.prepare('DELETE FROM install_leases WHERE device_address = ? AND entitlement_id = ?')
        .run(input.deviceAddress, input.entitlementId)

      // 设备级残留租约 + CD 豁免必须先于账号/授权并发检查处理:一台设备同一时刻只可能
      // 有一个真实安装在跑,残留租约几乎总是崩溃/断连的上一次尝试。basic 档并发=1 时,
      // 若先判 USER_LIMIT,残留租约会在这里的豁免逻辑执行前就已经把请求挡死——豁免机制
      // 形同虚设,用户只能干等原始租约自然到期(可长达 INSTALL_LEASE_TTL/MAX_DURATION)。
      // 所以本设备的残留租约必须先在此清掉(或按未豁免情形直接以 DEVICE_LIMIT 拒绝并
      // 给出 retryAfter),再进入下面按账号/授权计数的检查。
      if (this.count('SELECT COUNT(*) AS count FROM install_leases WHERE device_address = ?', input.deviceAddress) !== 0) {
        if (this.failureStreak(input.deviceAddress, input.resourceId, now) >= FAILURE_EXEMPT_THRESHOLD) {
          this.db.prepare('DELETE FROM install_leases WHERE device_address = ?').run(input.deviceAddress)
        } else {
          const retryAfter = this.retryAfterFor('device_address = ?', input.deviceAddress, now)
          throw new LeaseError('DEVICE_LIMIT', `该设备正在安装冷却中，请等待 ${retryAfter} 秒后重试`, retryAfter)
        }
      }

      const userLimit = Math.min(this.limits.byTier[input.tier], input.tokenConcurrency)
      if (this.count('SELECT COUNT(*) AS count FROM install_leases WHERE user_id = ?', input.userId) >= userLimit) {
        const retryAfter = this.retryAfterFor('user_id = ?', input.userId, now)
        throw new LeaseError('USER_LIMIT', `当前账号的 ${input.tier} 等级安装并发已达上限，请等待 ${retryAfter} 秒后重试`, retryAfter)
      }
      const entitlementLimit = Math.min(this.limits.perEntitlement, input.tokenConcurrency)
      if (this.count('SELECT COUNT(*) AS count FROM install_leases WHERE entitlement_id = ?', input.entitlementId) >= entitlementLimit) {
        const retryAfter = this.retryAfterFor('entitlement_id = ?', input.entitlementId, now)
        throw new LeaseError('ENTITLEMENT_LIMIT', `该授权的安装并发已达上限，请等待 ${retryAfter} 秒后重试`, retryAfter)
      }
      if (this.count('SELECT COUNT(*) AS count FROM install_leases WHERE ip_address = ?', input.ipAddress) >= this.limits.perIp) {
        throw new LeaseError('IP_LIMIT', '当前网络来源的安装并发已达上限')
      }

      // JWT verification accepts a small post-exp clock-tolerance window, and
      // an installation can outlive the short JWT itself. Retaining replay
      // markers for at least 24h closes both windows and matches Console's
      // idempotency retention without unbounded SQLite growth.
      const replayRetainUntil = Math.max(input.tokenExpiresAt, input.expiresAt, now + CONSUMED_TOKEN_RETENTION_MS)
      this.db.prepare('INSERT INTO consumed_tokens (jti, expires_at) VALUES (?, ?)').run(input.tokenJti, replayRetainUntil)
      this.db.prepare(`
        INSERT INTO install_leases
          (id, token_jti, user_id, entitlement_id, device_address, resource_id, ip_address, tier, token_concurrency, state, created_at, updated_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'created', ?, ?, ?)
      `).run(
        input.id,
        input.tokenJti,
        input.userId,
        input.entitlementId,
        input.deviceAddress,
        input.resourceId,
        input.ipAddress,
        input.tier,
        input.tokenConcurrency,
        now,
        now,
        input.expiresAt,
      )
    })
  }

  private failureStreak(deviceAddress: string, resourceId: string, now: number): number {
    const row = this.db.prepare('SELECT count, updated_at FROM install_failure_streaks WHERE device_address = ? AND resource_id = ?')
      .get(deviceAddress, resourceId) as { count?: number; updated_at?: number } | undefined
    if (!row || Number(row.updated_at) <= now - FAILURE_STREAK_TTL_MS) return 0
    return Number(row.count)
  }

  private recordInstallFailureWithinTransaction(deviceAddress: string, resourceId: string, now: number): void {
    const current = this.failureStreak(deviceAddress, resourceId, now)
    this.db.prepare(`INSERT INTO install_failure_streaks (device_address, resource_id, count, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(device_address, resource_id) DO UPDATE SET count = ?, updated_at = ?`)
      .run(deviceAddress, resourceId, current + 1, now, current + 1, now)
  }

  /** Increment the consecutive-failure counter for a device+resource. */
  recordInstallFailure(deviceAddress: string, resourceId: string): void {
    this.transaction(() => this.recordInstallFailureWithinTransaction(deviceAddress, resourceId, this.now()))
  }

  /** Clear the failure streak once an install of this device+resource succeeds. */
  resetInstallFailure(deviceAddress: string, resourceId: string): void {
    this.db.prepare('DELETE FROM install_failure_streaks WHERE device_address = ? AND resource_id = ?')
      .run(deviceAddress, resourceId)
  }

  recordEvent(input: {
    sessionId: string
    entitlementId: string
    resourceId: string
    deviceAddress: string
    event: InstallEventType
    detail?: string
    attempt?: number
    acknowledgedPart?: number
  }): void {
    const detail = input.detail?.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 500) || null
    const attempt = Math.max(0, Math.min(100, Math.trunc(input.attempt ?? 0)))
    const acknowledgedPart = Math.max(0, Math.trunc(input.acknowledgedPart ?? 0))
    this.db.prepare(`INSERT INTO install_events
      (session_id,entitlement_id,resource_id,device_address,event_type,detail,attempt,acknowledged_part,created_at)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(input.sessionId, input.entitlementId, input.resourceId, input.deviceAddress,
        input.event, detail, attempt, acknowledgedPart, this.now())
  }

  listEvents(sessionId: string): Array<{ event: string; detail?: string; attempt: number; acknowledgedPart: number }> {
    const rows = this.db.prepare(`SELECT event_type,detail,attempt,acknowledged_part FROM install_events
      WHERE session_id=? ORDER BY id`).all(sessionId) as Array<Record<string, unknown>>
    return rows.map((row) => ({ event: String(row.event_type), detail: row.detail == null ? undefined : String(row.detail),
      attempt: Number(row.attempt), acknowledgedPart: Number(row.acknowledged_part) }))
  }

  /** Only use when session creation failed before a response reached the client. */
  cancelCreation(id: string, tokenJti: string): void {
    this.transaction(() => {
      this.db.prepare('DELETE FROM install_leases WHERE id = ? AND token_jti = ? AND state = ?').run(id, tokenJti, 'created')
      this.db.prepare('DELETE FROM consumed_tokens WHERE jti = ? AND NOT EXISTS (SELECT 1 FROM install_leases WHERE token_jti = ?)').run(tokenJti, tokenJti)
    })
  }

  transition(id: string, from: 'created' | 'streaming', to: 'streaming' | 'delivered', expiresAt: number): boolean {
    const result = this.db.prepare(
      'UPDATE install_leases SET state = ?, updated_at = ?, expires_at = ? WHERE id = ? AND state = ? AND expires_at > ?',
    ).run(to, this.now(), expiresAt, id, from, this.now())
    return Number(result.changes) === 1
  }

  markDelivered(id: string, expiresAt: number): boolean {
    const result = this.db.prepare(`UPDATE install_leases SET state='delivered', updated_at=?, expires_at=?
      WHERE id=? AND state IN ('streaming','delivered') AND expires_at>?`)
      .run(this.now(), expiresAt, id, this.now())
    return Number(result.changes) === 1
  }

  renew(id: string, expiresAt: number): boolean {
    const result = this.db.prepare(
      'UPDATE install_leases SET updated_at = ?, expires_at = ? WHERE id = ? AND expires_at > ?',
    ).run(this.now(), expiresAt, id, this.now())
    return Number(result.changes) === 1
  }

  release(id: string): boolean {
    const result = this.db.prepare('DELETE FROM install_leases WHERE id = ?').run(id)
    return Number(result.changes) === 1
  }

  activeCount(): number {
    this.cleanup()
    return this.count('SELECT COUNT(*) AS count FROM install_leases')
  }

  close(): void {
    this.db.close()
  }
}
