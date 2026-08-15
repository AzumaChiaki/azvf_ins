/**
 * 流式安装上游(console→installer)读取的空闲窗口计算。
 *
 * 背景:下游(手机/浏览器经 BLE 喂手环)是 stop-and-wait 慢速消费,客户端回压
 * 会让 installer 暂停拉取 console 明文流数十秒——这是健康现象。固定的 60s 空闲
 * 中止会把这类安装拦腰掐断(客户端表现为"后端响应超时"/流被重置)。
 *
 * 动态窗口:
 * - 近期观测到下游回压(慢但健康):窗口跟随会话剩余租约拉长,封顶 stallMaxMs。
 *   租约由 30s 续期推进;会话死亡/租约耗尽后窗口自然塌缩回 baseMs。
 * - 无近期回压(下游在等字节、上游 console 真卡):保持 baseMs 快速失败。
 */

/** 单次 yield 挂起超过该时长即视为 BLE 级回压(BLE 常态每片数百毫秒)。 */
export const DOWNSTREAM_STALL_MARK_MS = 250

/** 最后一次回压观测的有效期:连续回压期间每个慢速 yield 都会重新打点。 */
export const DOWNSTREAM_STALL_GRACE_MS = 120_000

export interface StreamIdleWindowInput {
  now: number
  /** 上游真卡死时的快速失败窗口(config.internalStreamIdleTimeoutMs)。 */
  baseMs: number
  /** 回压期间的窗口封顶(config.installStreamStallMaxMs)。 */
  stallMaxMs: number
  /** 会话租约到期时刻(随 30s 续期推进)。 */
  sessionExpiresAt: number
  /** 最近一次下游回压观测时刻;0 表示从未观测到。 */
  lastDownstreamStallAt: number
}

export function streamIdleWindowMs(input: StreamIdleWindowInput): number {
  const { now, baseMs, stallMaxMs, sessionExpiresAt, lastDownstreamStallAt } = input
  const backpressured =
    lastDownstreamStallAt > 0 && now - lastDownstreamStallAt <= DOWNSTREAM_STALL_GRACE_MS
  if (!backpressured) return baseMs
  const remainingLeaseMs = sessionExpiresAt - now
  return Math.max(baseMs, Math.min(stallMaxMs, remainingLeaseMs))
}
