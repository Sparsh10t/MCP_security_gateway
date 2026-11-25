import crypto from "node:crypto";
import { computeEventHash, verifyAuditChain } from "./hashChain.js";
import { redactAndHashArgs } from "./redactor.js";
import type { AuditStore } from "./store.js";
import type {
  AuditEventInput,
  AuditEventPayload,
  AuditEventRecord,
  AuditQueryFilter,
  ChainVerificationResult,
} from "./types.js";

/**
 * Serialized, tamper-evident audit logger.
 * Every record is chained to the previous record's SHA-256 hash.
 */
export class AuditLogger {
  private writeQueue: Promise<unknown> = Promise.resolve();

  constructor(private readonly store: AuditStore) {}

  async log(input: AuditEventInput): Promise<AuditEventRecord> {
    const task = this.writeQueue.then(async () => {
      const prevHash = await this.store.getLatestHash();
      const { argsRedacted, argsHash } = redactAndHashArgs(input.args);

      const payload: AuditEventPayload = {
        id: crypto.randomUUID(),
        ts: new Date().toISOString(),
        traceId: input.traceId,
        userId: input.userId,
        roles: input.roles,
        tool: input.tool,
        argsRedacted,
        argsHash,
        decision: input.decision,
        reasonCode: input.reasonCode,
        findings: input.findings ?? [],
        latencyMs: Math.max(0, Math.round(input.latencyMs)),
      };

      const hash = computeEventHash(prevHash, payload);
      const record: AuditEventRecord = {
        ...payload,
        prevHash,
        hash,
      };

      await this.store.append(record);
      return record;
    });

    // Keep the queue alive even if one write fails
    this.writeQueue = task.catch(() => {});
    return task;
  }

  async query(
    filter: AuditQueryFilter
  ): Promise<{ events: AuditEventRecord[]; total: number }> {
    return this.store.query(filter);
  }

  async verifyChain(): Promise<ChainVerificationResult> {
    const events = await this.store.getAllChronological();
    return verifyAuditChain(events);
  }

  formatCsv(events: AuditEventRecord[]): string {
    const headers = [
      "id",
      "ts",
      "traceId",
      "userId",
      "roles",
      "tool",
      "decision",
      "reasonCode",
      "latencyMs",
      "argsHash",
      "prevHash",
      "hash",
    ];
    const escape = (val: unknown): string => {
      const str = String(val ?? "");
      if (str.includes(",") || str.includes('"') || str.includes("\n")) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };

    const lines = [headers.join(",")];
    for (const ev of events) {
      lines.push(
        [
          ev.id,
          ev.ts,
          ev.traceId,
          ev.userId,
          ev.roles.join("|"),
          ev.tool,
          ev.decision,
          ev.reasonCode,
          ev.latencyMs,
          ev.argsHash,
          ev.prevHash,
          ev.hash,
        ]
          .map(escape)
          .join(",")
      );
    }
    return lines.join("\n");
  }
}
