/**
 * Scrubs sensitive data from tool arguments before storing them in the audit log.
 *
 * Two strategies:
 *   1. Key-based: if the key looks sensitive (e.g. "password", "api_key") → redact the value
 *   2. Pattern-based: if the value itself looks like a secret (AWS key, Bearer token) → redact it
 *
 * We also hash the ORIGINAL args (before redaction) so we can prove they weren't altered.
 */

import { canonicalJson, sha256Hex } from "./hashChain.js";

// Keys whose values should always be redacted
const SENSITIVE_KEY_PATTERN =
  /password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key|credential|ssn|aadhaar/i;

// Patterns that look like real secrets inside string values
const INLINE_SECRET_PATTERNS: RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g,           // AWS Access Key
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, // GitHub token
  /\bsk-[A-Za-z0-9]{20,}\b/g,         // OpenAI/similar key
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, // Bearer token
];

function redactValue(value: unknown, keyHint?: string): unknown {
  // Redact by key name (e.g. { password: "hunter2" } → { password: "[REDACTED]" })
  if (keyHint && SENSITIVE_KEY_PATTERN.test(keyHint)) {
    return "[REDACTED]";
  }

  if (typeof value === "string") {
    let sanitized = value;
    for (const pattern of INLINE_SECRET_PATTERNS) {
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }
    // Don't store massive strings in audit logs
    if (sanitized.length > 2000) {
      return `${sanitized.slice(0, 2000)}...[TRUNCATED]`;
    }
    return sanitized;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item));
  }

  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactValue(v, k);
    }
    return out;
  }

  return value;
}

/**
 * Returns:
 *   argsHash     — SHA-256 of original args (proves they weren't changed)
 *   argsRedacted — args with secrets scrubbed (safe to store in DB)
 */
export function redactAndHashArgs(args?: Record<string, unknown>): {
  argsRedacted: Record<string, unknown>;
  argsHash: string;
} {
  const normalized = args ?? {};
  const argsHash = sha256Hex(canonicalJson(normalized)); // hash BEFORE redacting
  const argsRedacted = redactValue(normalized) as Record<string, unknown>;
  return { argsRedacted, argsHash };
}
