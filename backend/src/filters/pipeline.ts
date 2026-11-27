import type { CallToolResult } from "@modelcontextprotocol/client";
import type { AuditFinding } from "../audit/types.js";
import type { ResponseFilterRule } from "../policy/types.js";
import { detectPromptInjection, redactPromptInjection } from "./injection.js";
import {
  analyzePromptInjectionWithGemini,
  type AnalyzeOptions,
} from "./geminiAnalyzer.js";
import { detectPii, maskPii } from "./pii.js";
import { detectSecrets, redactSecrets } from "./secrets.js";

export interface FilterPipelineResult {
  blocked: boolean;
  blockReason?: string;
  redacted: boolean;
  result: CallToolResult;
  findings: AuditFinding[];
}

const DEFAULT_FILTER_RULE: Required<ResponseFilterRule> = {
  pii: "mask",
  secrets: "redact",
  injection: "flag",
};

export function resolveResponseFilterRule(
  toolName: string,
  responseFilters?: Record<string, ResponseFilterRule>
): Required<ResponseFilterRule> {
  if (!responseFilters) {
    return { ...DEFAULT_FILTER_RULE };
  }

  const base = responseFilters["default"] ?? {};
  const prefix = toolName.includes(".") ? `${toolName.split(".")[0]}.*` : "";
  const wildcardMatch = prefix ? responseFilters[prefix] ?? {} : {};
  const exactMatch = responseFilters[toolName] ?? {};

  return {
    pii: exactMatch.pii ?? wildcardMatch.pii ?? base.pii ?? DEFAULT_FILTER_RULE.pii,
    secrets:
      exactMatch.secrets ??
      wildcardMatch.secrets ??
      base.secrets ??
      DEFAULT_FILTER_RULE.secrets,
    injection:
      exactMatch.injection ??
      wildcardMatch.injection ??
      base.injection ??
      DEFAULT_FILTER_RULE.injection,
  };
}

export function applyResponseFilters(
  toolName: string,
  result: CallToolResult,
  responseFilters?: Record<string, ResponseFilterRule>
): FilterPipelineResult {
  const rule = resolveResponseFilterRule(toolName, responseFilters);
  const findings: AuditFinding[] = [];
  let redacted = false;
  let blocked = false;
  let blockReason: string | undefined;

  const updatedContent = result.content.map((block) => {
    if (block.type !== "text") {
      return block;
    }

    let text = block.text;

    // 1. Secrets
    if (rule.secrets !== "off") {
      if (rule.secrets === "block") {
        const secretHits = detectSecrets(text);
        if (secretHits.length > 0) {
          blocked = true;
          blockReason = `Response blocked: secret detected (${secretHits.map((s) => s.rule).join(", ")})`;
          for (const s of secretHits) {
            findings.push({
              detector: "secrets.v1",
              category: "secret",
              severity: s.severity,
              action: "block",
              detail: s.rule,
            });
          }
        }
      } else if (rule.secrets === "redact") {
        const res = redactSecrets(text);
        if (res.findings.length > 0) {
          redacted = true;
          text = res.text;
          for (const s of res.findings) {
            findings.push({
              detector: "secrets.v1",
              category: "secret",
              severity: s.severity,
              action: "redact",
              detail: s.rule,
            });
          }
        }
      } else {
        const secretHits = detectSecrets(text);
        for (const s of secretHits) {
          findings.push({
            detector: "secrets.v1",
            category: "secret",
            severity: s.severity,
            action: "flag",
            detail: s.rule,
          });
        }
      }
    }

    // 2. PII
    if (!blocked && rule.pii !== "off") {
      if (rule.pii === "mask") {
        const res = maskPii(text);
        if (res.findings.length > 0) {
          redacted = true;
          text = res.text;
          for (const p of res.findings) {
            findings.push({
              detector: "pii.v1",
              category: "pii",
              severity: "medium",
              action: "mask",
              detail: `${p.kind} (${p.count})`,
            });
          }
        }
      } else {
        const piiHits = detectPii(text);
        for (const p of piiHits) {
          findings.push({
            detector: "pii.v1",
            category: "pii",
            severity: "medium",
            action: "flag",
            detail: `${p.kind} (${p.count})`,
          });
        }
      }
    }

    // 3. Prompt injection heuristics
    if (!blocked && rule.injection !== "off") {
      if (rule.injection === "block") {
        const scan = detectPromptInjection(text);
        if (scan.detected) {
          blocked = true;
          blockReason = `Response blocked: suspected prompt injection (${scan.matches.map((m) => m.pattern).join(", ")})`;
          for (const m of scan.matches) {
            findings.push({
              detector: "injection.v1",
              category: "prompt_injection",
              severity: "high",
              action: "block",
              detail: `${m.pattern}:${m.score}`,
            });
          }
        }
      } else if (rule.injection === "redact") {
        const res = redactPromptInjection(text);
        if (res.scan.detected) {
          redacted = true;
          text = res.text;
          for (const m of res.scan.matches) {
            findings.push({
              detector: "injection.v1",
              category: "prompt_injection",
              severity: "high",
              action: "redact",
              detail: `${m.pattern}:${m.score}`,
            });
          }
        }
      } else {
        const scan = detectPromptInjection(text);
        for (const m of scan.matches) {
          findings.push({
            detector: "injection.v1",
            category: "prompt_injection",
            severity: "high",
            action: "flag",
            detail: `${m.pattern}:${m.score}`,
          });
        }
      }
    }

    return { ...block, text };
  });

  if (blocked) {
    return {
      blocked: true,
      ...(blockReason !== undefined ? { blockReason } : {}),
      redacted: false,
      result: {
        isError: true,
        content: [
          {
            type: "text",
            text: blockReason ?? "Response blocked by gateway security policy.",
          },
        ],
      },
      findings,
    };
  }

  return {
    blocked: false,
    redacted,
    result: {
      ...result,
      content: updatedContent,
    },
    findings,
  };
}

/**
 * Redacts secrets and PII before sending tool output to Gemini. Gemini and the
 * deterministic injection detector then inspect that same text, so heuristic
 * redaction cannot hide injection evidence from Gemini.
 */
export async function applyResponseFiltersWithGemini(
  toolName: string,
  result: CallToolResult,
  responseFilters?: Record<string, ResponseFilterRule>,
  geminiOptions?: Omit<AnalyzeOptions, "toolName">
): Promise<FilterPipelineResult> {
  const rule = resolveResponseFilterRule(toolName, responseFilters);

  if (rule.injection === "off") {
    return applyResponseFilters(toolName, result, responseFilters);
  }

  // First sanitize secrets and PII, but leave injection text intact for Gemini.
  const sanitized = applyResponseFilters(toolName, result, {
    [toolName]: { ...rule, injection: "off" },
  });

  if (sanitized.blocked) return sanitized;

  const textBlocks = sanitized.result.content
    .filter((b): b is { type: "text"; text: string } => b.type === "text")
    .map((b) => b.text);

  if (textBlocks.length === 0) {
    return sanitized;
  }

  // Keep the regex detector as a fallback and as an independent safety layer.
  const deterministic = applyResponseFilters(toolName, sanitized.result, {
    [toolName]: { pii: "off", secrets: "off", injection: rule.injection },
  });
  const findings = [...sanitized.findings, ...deterministic.findings];
  const base: FilterPipelineResult = {
    ...deterministic,
    redacted: sanitized.redacted || deterministic.redacted,
    findings,
  };

  const combinedText = textBlocks.join("\n\n");
  const outcome = await analyzePromptInjectionWithGemini(combinedText, {
    toolName,
    ...geminiOptions,
  });

  if (outcome.status !== "completed" || !outcome.analysis) {
    base.findings.push({
      detector: "gemini",
      analyzer: "gemini",
      category: "prompt_injection",
      severity: "medium",
      action: "fallback_deterministic",
      detail: outcome.status,
      analysisStatus: outcome.status,
      injectionDetected: null,
      ...(outcome.errorMessage !== undefined
        ? { reason: outcome.errorMessage }
        : {}),
    });
    return base;
  }

  const analysis = outcome.analysis;
  const effectiveAction = analysis.isInjection ? rule.injection : "allow";

  const geminiFinding: AuditFinding = {
    detector: "gemini",
    analyzer: "gemini",
    category: "prompt_injection",
    severity: analysis.riskLevel,
    action: effectiveAction,
    detail: `${analysis.riskLevel}:${analysis.confidence.toFixed(2)}`,
    analysisStatus: outcome.status,
    injectionDetected: analysis.isInjection,
    riskLevel: analysis.riskLevel,
    confidence: analysis.confidence,
    reason: analysis.reason,
    evidence: analysis.evidence,
    recommendedAction: analysis.recommendedAction,
  };
  base.findings.push(geminiFinding);

  if (!analysis.isInjection && !base.blocked) {
    return base;
  }

  if (base.blocked) {
    return base;
  }

  // The deterministic detector may already have applied the configured action.
  if (deterministic.blocked || deterministic.redacted || rule.injection === "flag") {
    return base;
  }

  if (rule.injection === "block") {
    const blockReason = `Response blocked by Gemini analysis: ${analysis.reason}`;
    return {
      blocked: true,
      blockReason,
      redacted: false,
      result: {
        isError: true,
        content: [{ type: "text", text: blockReason }],
      },
      findings: base.findings,
    };
  }

  if (rule.injection === "redact") {
    let anyRedacted = base.redacted;
    const updatedContent = base.result.content.map((block) => {
      if (block.type !== "text") return block;
      let updatedText = block.text;
      for (const snippet of analysis.evidence) {
        if (snippet && updatedText.includes(snippet)) {
          updatedText = updatedText.replaceAll(
            snippet,
            "[REDACTED: suspected injection]"
          );
          anyRedacted = true;
        }
      }
      if (!anyRedacted) {
        updatedText = `[REDACTED: suspected injection by Gemini] ${updatedText}`;
        anyRedacted = true;
      }
      return { ...block, text: updatedText };
    });

    return {
      blocked: false,
      redacted: anyRedacted,
      result: {
        ...base.result,
        content: updatedContent,
      },
      findings: base.findings,
    };
  }

  return base;
}
