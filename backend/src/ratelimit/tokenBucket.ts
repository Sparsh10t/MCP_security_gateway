/**
 * Token bucket rate limiter, keyed by (userId, toolName).
 *
 * Think of it like a bucket of tokens:
 *   - Each request uses 1 token
 *   - Tokens refill slowly over time (e.g. 60/min = 1 per second)
 *   - If the bucket is empty → request is rejected
 *
 * In-memory only, so limits reset on server restart.
 */

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  retryAfterSeconds: number; // 0 if allowed
}

interface BucketState {
  tokens: number;
  lastRefillMs: number;
}

export class InMemoryRateLimiter {
  // key = "userId:toolName"
  private readonly buckets = new Map<string, BucketState>();

  constructor(private readonly defaultPerMinute = 60) { }

  consume(
    userId: string,
    toolName: string,
    limitPerMinute?: number
  ): RateLimitResult {
    const limit = limitPerMinute ?? this.defaultPerMinute;
    const key = `${userId}:${toolName}`;
    const now = Date.now();
    const refillRatePerMs = limit / 60_000; // tokens added per millisecond

    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { tokens: limit, lastRefillMs: now };
      this.buckets.set(key, bucket);
    } else {
      // Refill based on time elapsed since last request
      const elapsed = Math.max(0, now - bucket.lastRefillMs);
      bucket.tokens = Math.min(limit, bucket.tokens + elapsed * refillRatePerMs);
      bucket.lastRefillMs = now;
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true, remaining: Math.floor(bucket.tokens), limit, retryAfterSeconds: 0 };
    }

    // Not enough tokens — tell the caller how long to wait
    const deficit = 1 - bucket.tokens;
    const retryAfterSeconds = Math.max(1, Math.ceil(deficit / refillRatePerMs / 1000));
    return { allowed: false, remaining: 0, limit, retryAfterSeconds };
  }

  reset(): void {
    this.buckets.clear();
  }
}
