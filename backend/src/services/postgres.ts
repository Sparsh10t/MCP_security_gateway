import { Pool } from "pg";
import { env } from "../config/env.js";
import type { UpstreamServerConfig } from "../config/upstreams.js";

let pool: Pool | null = null;
let connected = false;

export function getPostgresPool(): Pool {
  if (!pool) {
    pool = new Pool({
      connectionString: env.DATABASE_URL,
      connectionTimeoutMillis: 2000,
      max: 10,
    });
    pool.on("error", (err) => {
      connected = false;
      console.error("[postgres] pool error:", err.message);
    });
  }
  return pool;
}

const BOOTSTRAP_SQL = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS upstream_servers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  transport TEXT NOT NULL CHECK (transport IN ('stdio', 'http')),
  endpoint TEXT NOT NULL,
  risk_tier TEXT NOT NULL DEFAULT 'medium' CHECK (risk_tier IN ('low', 'medium', 'high', 'critical')),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policy_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  version TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT 'local',
  activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_events (
  seq BIGSERIAL UNIQUE,
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  trace_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  roles TEXT[] NOT NULL DEFAULT '{}',
  tool TEXT NOT NULL,
  args_redacted JSONB NOT NULL DEFAULT '{}'::jsonb,
  args_hash TEXT NOT NULL,
  decision TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  findings JSONB NOT NULL DEFAULT '[]'::jsonb,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);

ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS seq BIGSERIAL;
CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_user_tool ON audit_events (user_id, tool);
`;

export async function initPostgres(): Promise<boolean> {
  const pgPool = getPostgresPool();
  try {
    await pgPool.query("SELECT 1");
    await pgPool.query(BOOTSTRAP_SQL);
    connected = true;
    return true;
  } catch (err) {
    connected = false;
    if (env.REQUIRE_INFRA) {
      throw err;
    }
    console.warn(
      "[postgres] unavailable (continuing because REQUIRE_INFRA=false):",
      err instanceof Error ? err.message : String(err)
    );
    return false;
  }
}

export async function syncUpstreamServers(
  configs: UpstreamServerConfig[]
): Promise<void> {
  if (!connected) return;
  const pgPool = getPostgresPool();
  for (const cfg of configs) {
    const endpoint =
      cfg.transport === "stdio"
        ? `${cfg.command} ${cfg.args.join(" ")}`.trim()
        : cfg.url;
    await pgPool.query(
      `INSERT INTO upstream_servers (name, transport, endpoint, risk_tier, enabled)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (name) DO UPDATE SET
         transport = EXCLUDED.transport,
         endpoint = EXCLUDED.endpoint,
         risk_tier = EXCLUDED.risk_tier,
         enabled = EXCLUDED.enabled,
         updated_at = NOW()`,
      [cfg.name, cfg.transport, endpoint, cfg.riskTier, cfg.enabled]
    );
  }
}

export async function recordPolicyVersion(
  version: string,
  sha256: string,
  source = "local"
): Promise<void> {
  if (!connected) return;
  const pgPool = getPostgresPool();
  const latest = await pgPool.query<{ sha256: string }>(
    `SELECT sha256 FROM policy_versions ORDER BY activated_at DESC LIMIT 1`
  );
  if (latest.rows[0]?.sha256 === sha256) {
    return;
  }
  await pgPool.query(
    `INSERT INTO policy_versions (version, sha256, source) VALUES ($1, $2, $3)`,
    [version, sha256, source]
  );
}

export async function pingPostgres(): Promise<boolean> {
  try {
    await getPostgresPool().query("SELECT 1");
    connected = true;
    return true;
  } catch {
    connected = false;
    return false;
  }
}

export async function closePostgres(): Promise<void> {
  if (pool) {
    await pool.end();
    pool = null;
    connected = false;
  }
}
