import { canonicalJson, sha256Hex } from "./hashChain.js";

const SENSITIVE_KEY_PATTERN =
  /password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key|credential|ssn|aadhaar/i;

const INLINE_SECRET_PATTERNS: RegExp[] = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bsk-[A-Za-z0-9]{20,}\b/g,
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
];

function redactValue(value: unknown, keyHint?: string): unknown {
  if (keyHint && SENSITIVE_KEY_PATTERN.test(keyHint)) {
    return "[REDACTED]";
  }
  if (typeof value === "string") {
    let sanitized = value;
    for (const pattern of INLINE_SECRET_PATTERNS) {
      sanitized = sanitized.replace(pattern, "[REDACTED]");
    }
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

export function redactAndHashArgs(args?: Record<string, unknown>): {
  argsRedacted: Record<string, unknown>;
  argsHash: string;
} {
  const normalized = args ?? {};
  const argsHash = sha256Hex(canonicalJson(normalized));
  const argsRedacted = redactValue(normalized) as Record<string, unknown>;
  return { argsRedacted, argsHash };
}
