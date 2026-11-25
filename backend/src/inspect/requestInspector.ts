import { detectSecrets } from "../filters/secrets.js";

export interface RequestInspectionResult {
  passed: boolean;
  reason?: string;
  findings: Array<{ arg: string; rule: string; severity: string }>;
}

function scanValue(
  value: unknown,
  argPath: string,
  findings: Array<{ arg: string; rule: string; severity: string }>
): void {
  if (typeof value === "string") {
    for (const f of detectSecrets(value)) {
      findings.push({ arg: argPath, rule: f.rule, severity: f.severity });
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, idx) => scanValue(item, `${argPath}[${idx}]`, findings));
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      scanValue(v, `${argPath}.${k}`, findings);
    }
  }
}

/**
 * Scans outbound tool call arguments for embedded secrets to prevent
 * credential exfiltration through tool parameters.
 */
export function inspectToolArguments(
  args?: Record<string, unknown>
): RequestInspectionResult {
  if (!args) {
    return { passed: true, findings: [] };
  }

  const findings: Array<{ arg: string; rule: string; severity: string }> = [];
  for (const [key, value] of Object.entries(args)) {
    scanValue(value, key, findings);
  }

  if (findings.length > 0) {
    const summary = findings.map((f) => `${f.arg} (${f.rule})`).join(", ");
    return {
      passed: false,
      reason: `Secret detected in tool arguments: ${summary}`,
      findings,
    };
  }

  return { passed: true, findings: [] };
}
