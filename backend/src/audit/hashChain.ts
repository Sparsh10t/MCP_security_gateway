/**
 * Hash chain for tamper-evident audit logs.
 * Like blockchain — each event stores the hash of the previous one,
 * so if someone edits a row, all hashes after it break.
 */

import crypto from "node:crypto";
import type { AuditEventPayload, AuditEventRecord, ChainVerificationResult } from "./types.js";

// Starting point: first event has no "previous", so we use 64 zeros
export const GENESIS_HASH = "0".repeat(64);

/**
 * Sorts object keys before stringifying so { b:1, a:2 } and { a:2, b:1 }
 * always produce the same string → same hash.
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
    .sort(); // alphabetical order = deterministic
  const entries = keys.map(
    (k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`
  );
  return `{${entries.join(",")}}`;
}

// SHA-256 of a string → 64-char hex fingerprint
export function sha256Hex(input: string): string {
  return crypto.createHash("sha256").update(input, "utf-8").digest("hex");
}

// Pick only the fields that go into the hash (excludes DB-internal stuff like `seq`)
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

// Hash = SHA-256(prevHash + canonicalJSON(event))
// Including prevHash links each event to the one before it
export function computeEventHash(
  prevHash: string,
  event: AuditEventPayload
): string {
  const payloadJson = canonicalJson(toCanonicalPayload(event));
  return sha256Hex(`${prevHash}${payloadJson}`);
}

/**
 * Walk through all events in order and verify the chain is unbroken.
 * Returns { valid: false, firstInvalid: {...} } if any event was tampered with.
 */
export function verifyAuditChain(
  events: AuditEventRecord[]
): ChainVerificationResult {
  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < events.length; i++) {
    const event = events[i];
    if (!event) continue;

    // Check 1: prevHash must match what we computed from the last event
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

    // Check 2: recompute the hash and confirm it matches what's stored
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
