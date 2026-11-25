import { Redis } from "ioredis";
import { env } from "../config/env.js";

let client: Redis | null = null;
let connected = false;

export function getRedisClient(): Redis {
  if (!client) {
    client = new Redis(env.REDIS_URL, {
      lazyConnect: true,
      connectTimeout: 2000,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      retryStrategy: () => null,
    });
    client.on("error", (err) => {
      connected = false;
      if (env.REQUIRE_INFRA) {
        console.error("[redis] error:", err.message);
      }
    });
    client.on("ready", () => {
      connected = true;
    });
  }
  return client;
}

export async function initRedis(): Promise<boolean> {
  const redis = getRedisClient();
  try {
    if (redis.status === "wait") {
      await redis.connect();
    }
    const pong = await redis.ping();
    connected = pong === "PONG";
    return connected;
  } catch (err) {
    connected = false;
    if (env.REQUIRE_INFRA) {
      throw err;
    }
    console.warn(
      "[redis] unavailable (continuing because REQUIRE_INFRA=false):",
      err instanceof Error ? err.message : String(err)
    );
    return false;
  }
}

export async function cacheToolCatalog(
  tools: unknown[],
  ttlSeconds = 60
): Promise<void> {
  if (!connected || !client) return;
  try {
    await client.set(
      "gateway:tools:catalog",
      JSON.stringify(tools),
      "EX",
      ttlSeconds
    );
  } catch {
    // Non-fatal cache write
  }
}

export async function pingRedis(): Promise<boolean> {
  if (!client) return false;
  try {
    const pong = await client.ping();
    connected = pong === "PONG";
    return connected;
  } catch {
    connected = false;
    return false;
  }
}

export async function closeRedis(): Promise<void> {
  if (client) {
    const ref = client;
    client = null;
    connected = false;
    if (ref.status === "ready" || ref.status === "connecting") {
      await ref.quit().catch(() => ref.disconnect());
    } else {
      ref.disconnect();
    }
  }
}
