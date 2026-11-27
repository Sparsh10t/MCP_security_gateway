import type { AuditFinding } from "../audit/types.js";
import {
  analyzePromptInjectionWithGemini,
  type AnalyzeOptions,
} from "../filters/geminiAnalyzer.js";
import { detectPromptInjection } from "../filters/injection.js";
import { detectSecrets } from "../filters/secrets.js";

export interface RequestInspectionResult {
  passed: boolean;
  reasonCode?: "SECRET_IN_ARGUMENTS" | "PROMPT_INJECTION_IN_ARGUMENTS";
  reason?: string;
  findings: AuditFinding[];
}

function collectStrings(
  value: unknown,
  argPath: string,
  out: Array<{ arg: string; text: string }>
): void {
  if (typeof value === "string") {
    out.push({ arg: argPath, text: value });
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, idx) => collectStrings(item, `${argPath}[${idx}]`, out));
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      collectStrings(v, `${argPath}.${k}`, out);
    }
  }
}

/**
 * Synchronous scan of outbound tool call arguments for embedded secrets.
 */
export function inspectToolArguments(
  args?: Record<string, unknown>
): RequestInspectionResult {
  if (!args) {
    return { passed: true, findings: [] };
  }

  const strings: Array<{ arg: string; text: string }> = [];
  for (const [key, value] of Object.entries(args)) {
    collectStrings(value, key, strings);
  }

  const findings: AuditFinding[] = [];
  const hitSummary: string[] = [];
  for (const item of strings) {
    for (const f of detectSecrets(item.text)) {
      hitSummary.push(`${item.arg} (${f.rule})`);
      findings.push({
        detector: "secrets.v1",
        category: "secret_in_arg",
        severity: "critical",
        action: "deny",
        detail: `${item.arg}:${f.rule}`,
      });
    }
  }

  if (findings.length > 0) {
    return {
      passed: false,
      reasonCode: "SECRET_IN_ARGUMENTS",
      reason: `Secret detected in tool arguments: ${hitSummary.join(", ")}`,
      findings,
    };
  }

  return { passed: true, findings: [] };
}

/**
 * Inspects incoming tool arguments for both embedded secrets AND prompt injection
 * (deterministic regex + Gemini LLM analysis).
 */
export async function inspectToolArgumentsWithGemini(
  toolName: string,
  args?: Record<string, unknown>,
  geminiOptions?: Omit<AnalyzeOptions, "toolName">
): Promise<RequestInspectionResult> {
  const secretCheck = inspectToolArguments(args);
  if (!secretCheck.passed) {
    return secretCheck;
  }

  if (!args) {
    return { passed: true, findings: [] };
  }

  const strings: Array<{ arg: string; text: string }> = [];
  for (const [key, value] of Object.entries(args)) {
    collectStrings(value, key, strings);
  }

  const combinedText = strings.map((s) => `${s.arg}: ${s.text}`).join("\n");
  if (combinedText.trim().length < 12) {
    return { passed: true, findings: [] };
  }

  const findings: AuditFinding[] = [];
  const regexScan = detectPromptInjection(combinedText);
  for (const m of regexScan.matches) {
    findings.push({
      detector: "injection.v1",
      category: "prompt_injection",
      severity: "high",
      action: "deny",
      detail: `${m.pattern}:${m.score}`,
    });
  }

  const geminiOutcome = await analyzePromptInjectionWithGemini(combinedText, {
    toolName: `${toolName}:args`,
    ...geminiOptions,
  });

  if (geminiOutcome.status === "completed" && geminiOutcome.analysis) {
    const a = geminiOutcome.analysis;
    findings.push({
      detector: "gemini",
      analyzer: "gemini",
      category: "prompt_injection",
      severity: a.riskLevel,
      action: a.isInjection ? "deny" : "allow",
      detail: `${a.riskLevel}:${a.confidence.toFixed(2)}`,
      analysisStatus: geminiOutcome.status,
      injectionDetected: a.isInjection,
      riskLevel: a.riskLevel,
      confidence: a.confidence,
      reason: a.reason,
      evidence: a.evidence,
      recommendedAction: a.recommendedAction,
    });

    if (a.isInjection) {
      return {
        passed: false,
        reasonCode: "PROMPT_INJECTION_IN_ARGUMENTS",
        reason: `Prompt injection detected in tool arguments by Gemini: ${a.reason}`,
        findings,
      };
    }
  } else {
    findings.push({
      detector: "gemini",
      analyzer: "gemini",
      category: "prompt_injection",
      severity: "medium",
      action: "fallback_deterministic",
      detail: geminiOutcome.status,
      analysisStatus: geminiOutcome.status,
      injectionDetected: null,
      ...(geminiOutcome.errorMessage !== undefined
        ? { reason: geminiOutcome.errorMessage }
        : {}),
    });
  }

  if (regexScan.detected) {
    return {
      passed: false,
      reasonCode: "PROMPT_INJECTION_IN_ARGUMENTS",
      reason: `Prompt injection detected in tool arguments (${regexScan.matches.map((m) => m.pattern).join(", ")})`,
      findings,
    };
  }

  return { passed: true, findings };
}
