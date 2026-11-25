import crypto from "node:crypto";
import type { AuditEventPayload, AuditEventRecord, ChainVerificationResult } from "./types.js";

export const GENESIS_HASH = "0".repeat(64);

/**
 * Deterministic JSON serialization with recursively sorted object keys
 * so hash computation is invariant across PostgreSQL JSONB and JS objects.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj)
    .filter((k) => obj[k] !== undefined)
    .sort();
  const entries = keys.map(
    (k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`
  );
  return `{${entries.join(",")}}`;
}

export function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input, "utf-8").digest("hex");
}

export function toCanonicalPayload(event: AuditEventPayload): AuditEventPayload {
  return {
    id: event.id,
    ts: event.ts,
    traceId: event.traceId,
    userId: event.userId,
    roles: event.roles,
    tool: event.tool,
    argsRedacted: event.argsRedacted,
    argsHash: event.argsHash,
    decision: event.decision,
    reasonCode: event.reasonCode,
    findings: event.findings,
    latencyMs: event.latencyMs,
  };
}

export function computeEventHash(
  prevHash: string,
  event: AuditEventPayload
): string {
  const payloadJson = canonicalJson(toCanonicalPayload(event));
  return sha256Hex(`${prevHash}${payloadJson}`);
}

export function verifyAuditChain(
  events: AuditEventRecord[]
): ChainVerificationResult {
  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    if (!event) continue;

    if (event.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        totalEvents: events.length,
        headHash: expectedPrevHash,
        firstInvalid: {
          index: i,
          id: event.id,
          reason: "prev_hash mismatch (broken chain link or deleted/reordered row)",
          expectedHash: expectedPrevHash,
          actualHash: event.prevHash,
        },
      };
    }

    const expectedHash = computeEventHash(expectedPrevHash, event);
    if (event.hash !== expectedHash) {
      return {
        valid: false,
        totalEvents: events.length,
        headHash: expectedPrevHash,
        firstInvalid: {
          index: i,
          id: event.id,
          reason: "hash mismatch (event payload was tampered with)",
          expectedHash,
          actualHash: event.hash,
        },
      };
    }

    expectedPrevHash = event.hash;
  }

  return {
    valid: true,
    totalEvents: events.length,
    headHash: expectedPrevHash,
  };
}
