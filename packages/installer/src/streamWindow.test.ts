import { describe, expect, it } from 'vitest'
import { DOWNSTREAM_STALL_GRACE_MS, DOWNSTREAM_STALL_MARK_MS, streamIdleWindowMs } from './streamWindow.js'

const BASE = 60_000
const STALL_MAX = 300_000

describe('streamIdleWindowMs', () => {
  it('从未观测到回压时使用基准窗口快速失败', () => {
    const now = 1_000_000
    expect(streamIdleWindowMs({
      now, baseMs: BASE, stallMaxMs: STALL_MAX,
      sessionExpiresAt: now + 900_000, lastDownstreamStallAt: 0,
    })).toBe(BASE)
  })

  it('回压观测超过有效期后回到基准窗口', () => {
    const now = 1_000_000
    expect(streamIdleWindowMs({
      now, baseMs: BASE, stallMaxMs: STALL_MAX,
      sessionExpiresAt: now + 900_000,
      lastDownstreamStallAt: now - DOWNSTREAM_STALL_GRACE_MS - 1,
    })).toBe(BASE)
  })

  it('回压期间窗口跟随剩余租约,不超过封顶', () => {
    const now = 1_000_000
    // 剩余租约 900s > 封顶 300s → 封顶
    expect(streamIdleWindowMs({
      now, baseMs: BASE, stallMaxMs: STALL_MAX,
      sessionExpiresAt: now + 900_000, lastDownstreamStallAt: now - 1_000,
    })).toBe(STALL_MAX)
    // 剩余租约 120s < 封顶 → 跟随租约
    expect(streamIdleWindowMs({
      now, baseMs: BASE, stallMaxMs: STALL_MAX,
      sessionExpiresAt: now + 120_000, lastDownstreamStallAt: now - 1_000,
    })).toBe(120_000)
  })

  it('剩余租约不足基准窗口时不低于基准窗口', () => {
    const now = 1_000_000
    expect(streamIdleWindowMs({
      now, baseMs: BASE, stallMaxMs: STALL_MAX,
      sessionExpiresAt: now + 30_000, lastDownstreamStallAt: now - 1_000,
    })).toBe(BASE)
    // 租约已过期(负数)同样塌缩回基准窗口
    expect(streamIdleWindowMs({
      now, baseMs: BASE, stallMaxMs: STALL_MAX,
      sessionExpiresAt: now - 5_000, lastDownstreamStallAt: now - 1_000,
    })).toBe(BASE)
  })

  it('回压观测恰在有效期边界内仍视为回压', () => {
    const now = 1_000_000
    expect(streamIdleWindowMs({
      now, baseMs: BASE, stallMaxMs: STALL_MAX,
      sessionExpiresAt: now + 900_000,
      lastDownstreamStallAt: now - DOWNSTREAM_STALL_GRACE_MS,
    })).toBe(STALL_MAX)
  })

  it('打点阈值常量为正且远小于基准窗口', () => {
    expect(DOWNSTREAM_STALL_MARK_MS).toBeGreaterThan(0)
    expect(DOWNSTREAM_STALL_MARK_MS).toBeLessThan(BASE)
  })
})
