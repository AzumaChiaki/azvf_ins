interface Bucket {
  tokens: number
  updatedAt: number
  lastSeenAt: number
}
/** In-process token bucket. Concurrency leases remain authoritative across processes. */
export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>()

  constructor(private readonly now: () => number = Date.now) {}

  consume(key: string, capacity: number, intervalMs = 60_000): { allowed: boolean; retryAfterSeconds: number } {
    const now = this.now()
    const existing = this.buckets.get(key) ?? { tokens: capacity, updatedAt: now, lastSeenAt: now }
    const elapsed = Math.max(0, now - existing.updatedAt)
    existing.tokens = Math.min(capacity, existing.tokens + elapsed * (capacity / intervalMs))
    existing.updatedAt = now
    existing.lastSeenAt = now
    const allowed = existing.tokens >= 1
    if (allowed) existing.tokens -= 1
    this.buckets.set(key, existing)
    if (this.buckets.size > 10_000) this.cleanup(intervalMs * 2)
    const missing = Math.max(0, 1 - existing.tokens)
    return { allowed, retryAfterSeconds: Math.max(1, Math.ceil(missing / (capacity / intervalMs) / 1_000)) }
  }

  cleanup(maxIdleMs = 120_000): void {
    const cutoff = this.now() - maxIdleMs
    for (const [key, bucket] of this.buckets) if (bucket.lastSeenAt < cutoff) this.buckets.delete(key)
  }

  checkFailureLimit(key: string, maxFailures: number, windowMs: number, _cooldownMs: number): { allowed: boolean; retryAfterSeconds: number } {
    const entry = this.#failures.get(key)
    if (!entry || this.now() - entry.since > windowMs) return { allowed: true, retryAfterSeconds: 0 }
    if (entry.count >= maxFailures) {
      const remaining = Math.ceil((entry.cooldownUntil! - this.now()) / 1_000)
      return { allowed: false, retryAfterSeconds: Math.max(1, remaining) }
    }
    return { allowed: true, retryAfterSeconds: 0 }
  }

  recordFailure(key: string, maxFailures: number, windowMs: number, cooldownMs: number): void {
    const now = this.now()
    let entry = this.#failures.get(key)
    if (!entry || now - entry.since > windowMs) {
      entry = { count: 0, since: now, firstFailureAt: now }
    }
    entry.count++
    if (entry.count >= maxFailures) entry.cooldownUntil = now + cooldownMs
    this.#failures.set(key, entry)
  }

  clearFailures(key: string): void { this.#failures.delete(key) }

  #failures = new Map<string, { count: number; since: number; firstFailureAt: number; cooldownUntil?: number }>()
}
