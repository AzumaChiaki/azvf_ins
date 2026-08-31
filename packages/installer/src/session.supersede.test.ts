import { describe, expect, it } from 'vitest'
import { SessionStore, type InstallSession } from './session.js'

function seed(store: SessionStore, id: string): void {
  // 只填状态机用得到的字段;其余是流内容,与接管语义无关。
  store.put({
    sessionId: id, state: 'created', streamEpoch: 0,
    createdAt: Date.now(), expiresAt: Date.now() + 600_000, absoluteExpiresAt: Date.now() + 600_000,
  } as unknown as InstallSession)
}

function drive(store: SessionStore, id: string): void {
  store.claim(id)
  store.markStreaming(id, Date.now() + 600_000)
}

describe('同一会话的新连接接管正在跑的流', () => {
  const store = () => new SessionStore(() => undefined)

  it('streaming 会话被接管后退回 recoverable,可继续走 claimReplay 续传', () => {
    const s = store()
    seed(s, 'a'.repeat(32)); drive(s, 'a'.repeat(32))
    expect(s.get('a'.repeat(32))?.state).toBe('streaming')

    expect(s.supersedeStream('a'.repeat(32), Date.now() + 600_000)).toBeDefined()
    expect(s.get('a'.repeat(32))?.state).toBe('recoverable')
    // 续传路径照旧可用 —— 客户端不需要任何改动。
    expect(s.claimReplay('a'.repeat(32))).toBeDefined()
  })

  it('markStreaming 递增代数,旧生成器据此察觉自己已被接管', () => {
    const s = store()
    seed(s, 'b'.repeat(32)); drive(s, 'b'.repeat(32))
    const firstEpoch = s.get('b'.repeat(32))!.streamEpoch

    s.supersedeStream('b'.repeat(32), Date.now() + 600_000)
    s.claimReplay('b'.repeat(32))
    s.markStreaming('b'.repeat(32), Date.now() + 600_000)

    expect(s.get('b'.repeat(32))!.streamEpoch).toBeGreaterThan(firstEpoch)
  })

  it('不接管 authorizing:那是另一个请求正在建流,插进去会把会话抢没', () => {
    const s = store()
    seed(s, 'c'.repeat(32))
    s.claim('c'.repeat(32))
    expect(s.get('c'.repeat(32))?.state).toBe('authorizing')
    expect(s.supersedeStream('c'.repeat(32), Date.now() + 600_000)).toBeUndefined()
    expect(s.get('c'.repeat(32))?.state).toBe('authorizing')
  })

  it('不接管 created / delivered / 不存在的会话', () => {
    const s = store()
    seed(s, 'd'.repeat(32))
    expect(s.supersedeStream('d'.repeat(32), Date.now() + 600_000)).toBeUndefined()
    drive(s, 'd'.repeat(32))
    s.markDelivered('d'.repeat(32))
    expect(s.supersedeStream('d'.repeat(32), Date.now() + 600_000)).toBeUndefined()
    expect(s.supersedeStream('e'.repeat(32), Date.now() + 600_000)).toBeUndefined()
  })
})
