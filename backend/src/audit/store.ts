/**
 * Two audit stores — same interface, different backends:
 *   PostgresAuditStore → saves to DB (used when Docker is running)
 *   FileAuditStore     → saves to a .log file (fallback if DB not available)
 *
 * server.ts picks whichever one works at startup.
 */

import fs from "node:fs/promises";
import path from "node:path";
import type { Pool } from "pg";
import { GENESIS_HASH } from "./hashChain.js";
import type {
  AuditDecision,
  AuditEventRecord,
  AuditFinding,
  AuditQueryFilter,
} from "./types.js";

export interface AuditStore {
  getLatestHash(): Promise<string>;
  append(record: AuditEventRecord): Promise<void>;
  query(filter: AuditQueryFilter): Promise<{ events: AuditEventRecord[]; total: number }>;
  getAllChronological(): Promise<AuditEventRecord[]>;
}

// Postgres returns snake_case columns; our code uses camelCase — this maps between them
interface PgAuditRow {
  seq: string | number;
  id: string;
  ts: Date | string;
  trace_id: string;
  user_id: string;
  roles: string[];
  tool: string;
  args_redacted: Record<string, unknown>;
  args_hash: string;
  decision: AuditDecision;
  reason_code: string;
  findings: AuditFinding[];
  latency_ms: number;
  prev_hash: string;
  hash: string;
}

function mapPgRow(row: PgAuditRow): AuditEventRecord {
  return {
    seq: Number(row.seq),
    id: row.id,
    ts: row.ts instanceof Date ? row.ts.toISOString() : new Date(row.ts).toISOString(),
    traceId: row.trace_id,
    userId: row.user_id,
    roles: row.roles ?? [],
    tool: row.tool,
    argsRedacted: row.args_redacted ?? {},
    argsHash: row.args_hash,
    decision: row.decision,
    reasonCode: row.reason_code,
    findings: row.findings ?? [],
    latencyMs: row.latency_ms,
    prevHash: row.prev_hash,
    hash: row.hash,
  };
}

// --- Store 1: PostgreSQL ---

export class PostgresAuditStore implements AuditStore {
  constructor(private readonly pool: Pool) { }

  async getLatestHash(): Promise<string> {
    const res = await this.pool.query<{ hash: string }>(
      `SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`
    );
    return res.rows[0]?.hash ?? GENESIS_HASH;
  }

  async append(record: AuditEventRecord): Promise<void> {
    // $1, $2, ... are parameterized placeholders — prevents SQL injection
    await this.pool.query(
      `INSERT INTO audit_events (
        id, ts, trace_id, user_id, roles, tool, args_redacted, args_hash,
        decision, reason_code, findings, latency_ms, prev_hash, hash
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7::jsonb, $8,
        $9, $10, $11::jsonb, $12, $13, $14
      )`,
      [
        record.id,
        record.ts,
        record.traceId,
        record.userId,
        record.roles,
        record.tool,
        JSON.stringify(record.argsRedacted),
        record.argsHash,
        record.decision,
        record.reasonCode,
        JSON.stringify(record.findings),
        record.latencyMs,
        record.prevHash,
        record.hash,
      ]
    );
  }

  async query(
    filter: AuditQueryFilter
  ): Promise<{ events: AuditEventRecord[]; total: number }> {
    // Build the WHERE clause dynamically based on which filters are provided
    const conditions: string[] = [];
    const params: unknown[] = [];

    if (filter.userId) {
      params.push(filter.userId);
      conditions.push(`user_id = $${params.length}`);
    }
    if (filter.tool) {
      params.push(filter.tool);
      conditions.push(`tool = $${params.length}`);
    }
    if (filter.decision) {
      params.push(filter.decision);
      conditions.push(`decision = $${params.length}`);
    }
    if (filter.reasonCode) {
      params.push(filter.reasonCode);
      conditions.push(`reason_code = $${params.length}`);
    }

    const whereClause =
      conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    const countRes = await this.pool.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM audit_events ${whereClause}`,
      params
    );
    const total = Number(countRes.rows[0]?.count ?? 0);

    const limit = Math.min(Math.max(filter.limit ?? 50, 1), 500);
    const offset = Math.max(filter.offset ?? 0, 0);

    const rowsRes = await this.pool.query<PgAuditRow>(
      `SELECT seq, id, ts, trace_id, user_id, roles, tool, args_redacted, args_hash,
              decision, reason_code, findings, latency_ms, prev_hash, hash
       FROM audit_events
       ${whereClause}
       ORDER BY seq DESC
       LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
      [...params, limit, offset]
    );

    return {
      events: rowsRes.rows.map(mapPgRow),
      total,
    };
  }

  async getAllChronological(): Promise<AuditEventRecord[]> {
    const res = await this.pool.query<PgAuditRow>(
      `SELECT seq, id, ts, trace_id, user_id, roles, tool, args_redacted, args_hash,
              decision, reason_code, findings, latency_ms, prev_hash, hash
       FROM audit_events
       ORDER BY seq ASC`
    );
    return res.rows.map(mapPgRow);
  }
}

// --- Store 2: Plain log file (one JSON object per line) ---

export class FileAuditStore implements AuditStore {
  private readonly filePath: string;

  constructor(filePath: string) {
    this.filePath = path.resolve(process.cwd(), filePath);
  }

  private async readAllLines(): Promise<AuditEventRecord[]> {
    try {
      const content = await fs.readFile(this.filePath, "utf-8");
      const records: AuditEventRecord[] = [];
      for (const line of content.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        records.push(JSON.parse(trimmed) as AuditEventRecord);
      }
      return records;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return []; // file not created yet
      throw err;
    }
  }

  async getLatestHash(): Promise<string> {
    const all = await this.readAllLines();
    return all[all.length - 1]?.hash ?? GENESIS_HASH;
  }

  async append(record: AuditEventRecord): Promise<void> {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    await fs.appendFile(this.filePath, `${JSON.stringify(record)}\n`, "utf-8");
  }

  async query(
    filter: AuditQueryFilter
  ): Promise<{ events: AuditEventRecord[]; total: number }> {
    const all = await this.readAllLines();
    // Filter in memory (like SQL WHERE, but in JS)
    const filtered = all
      .filter((ev) => !filter.userId || ev.userId === filter.userId)
      .filter((ev) => !filter.tool || ev.tool === filter.tool)
      .filter((ev) => !filter.decision || ev.decision === filter.decision)
      .filter((ev) => !filter.reasonCode || ev.reasonCode === filter.reasonCode)
      .reverse(); // newest first

    const limit = Math.min(Math.max(filter.limit ?? 50, 1), 500);
    const offset = Math.max(filter.offset ?? 0, 0);

    return {
      events: filtered.slice(offset, offset + limit),
      total: filtered.length,
    };
  }

  async getAllChronological(): Promise<AuditEventRecord[]> {
    return this.readAllLines();
  }
}
