-- Core schema aligned with Design Report Section 9.1
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

CREATE INDEX IF NOT EXISTS idx_audit_events_ts ON audit_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_user_tool ON audit_events (user_id, tool);
