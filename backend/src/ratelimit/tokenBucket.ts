export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  retryAfterSeconds: number;
}

interface BucketState {
  tokens: number;
  lastRefillMs: number;
}

/**
 * In-memory token bucket rate limiter keyed by (userId, toolName).
 * Refills continuously at `limitPerMinute / 60_000` tokens per millisecond.
 */
export class InMemoryRateLimiter {
  private readonly buckets = new Map<string, BucketState>();

  constructor(private readonly defaultPerMinute = 60) {}

  consume(
    userId: string,
    toolName: string,
    limitPerMinute?: number
  ): RateLimitResult {
    const limit = limitPerMinute ?? this.defaultPerMinute;
    const key = `${userId}:${toolName}`;
    const now = Date.now();
    const refillRatePerMs = limit / 60_000;

    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = { tokens: limit, lastRefillMs: now };
      this.buckets.set(key, bucket);
    } else {
      const elapsed = Math.max(0, now - bucket.lastRefillMs);
      bucket.tokens = Math.min(limit, bucket.tokens + elapsed * refillRatePerMs);
      bucket.lastRefillMs = now;
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return {
        allowed: true,
        remaining: Math.floor(bucket.tokens),
        limit,
        retryAfterSeconds: 0,
      };
    }

    const deficit = 1 - bucket.tokens;
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil(deficit / refillRatePerMs / 1000)
    );
    return {
      allowed: false,
      remaining: 0,
      limit,
      retryAfterSeconds,
    };
  }

  reset(): void {
    this.buckets.clear();
  }
}
