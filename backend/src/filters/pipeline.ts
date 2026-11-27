/**
 * Response filter pipeline — scans tool output before returning it to the AI agent.
 *
 * Checks in order:
 *   1. Secrets  — API keys, tokens, passwords
 *   2. PII      — emails, phone numbers, Aadhaar numbers
 *   3. Injection — hidden instructions trying to hijack the AI
 *
 * Each check has an action: "off" | "flag" | "redact"/"mask" | "block"
 * Actions come from the policy file (response_filters section).
 *
 * Two exported functions:
 *   applyResponseFilters()           — sync, regex only
 *   applyResponseFiltersWithGemini() — async, regex + Gemini LLM
 */

import type { CallToolResult } from "@modelcontextprotocol/client";
import type { AuditFinding } from "../audit/types.js";
import type { ResponseFilterRule } from "../policy/types.js";
import { detectPromptInjection, redactPromptInjection } from "./injection.js";
import { analyzePromptInjectionWithGemini, type AnalyzeOptions } from "./geminiAnalyzer.js";
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

/**
 * Resolves which filter rule applies to a tool.
 * More specific rules override less specific ones:
 *   exact tool name > namespace wildcard (e.g. "demo.*") > "default"
 */
export function resolveResponseFilterRule(
  toolName: string,
  responseFilters?: Record<string, ResponseFilterRule>
): Required<ResponseFilterRule> {
  if (!responseFilters) return { ...DEFAULT_FILTER_RULE };

  const base = responseFilters["default"] ?? {};
  const prefix = toolName.includes(".") ? `${toolName.split(".")[0]}.*` : "";
  const wildcardMatch = prefix ? responseFilters[prefix] ?? {} : {};
  const exactMatch = responseFilters[toolName] ?? {};

  return {
    pii: exactMatch.pii ?? wildcardMatch.pii ?? base.pii ?? DEFAULT_FILTER_RULE.pii,
    secrets: exactMatch.secrets ?? wildcardMatch.secrets ?? base.secrets ?? DEFAULT_FILTER_RULE.secrets,
    injection: exactMatch.injection ?? wildcardMatch.injection ?? base.injection ?? DEFAULT_FILTER_RULE.injection,
  };
}

// Synchronous filter — regex only, no Gemini
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
    if (block.type !== "text") return block;

    let text = block.text;

    // --- Check 1: Secrets ---
    if (rule.secrets !== "off") {
      if (rule.secrets === "block") {
        const secretHits = detectSecrets(text);
        if (secretHits.length > 0) {
          blocked = true;
          blockReason = `Response blocked: secret detected (${secretHits.map((s) => s.rule).join(", ")})`;
          for (const s of secretHits) {
            findings.push({ detector: "secrets.v1", category: "secret", severity: s.severity, action: "block", detail: s.rule });
          }
        }
      } else if (rule.secrets === "redact") {
        const res = redactSecrets(text);
        if (res.findings.length > 0) {
          redacted = true;
          text = res.text;
          for (const s of res.findings) {
            findings.push({ detector: "secrets.v1", category: "secret", severity: s.severity, action: "redact", detail: s.rule });
          }
        }
      } else {
        for (const s of detectSecrets(text)) {
          findings.push({ detector: "secrets.v1", category: "secret", severity: s.severity, action: "flag", detail: s.rule });
        }
      }
    }

    // --- Check 2: PII ---
    if (!blocked && rule.pii !== "off") {
      if (rule.pii === "mask") {
        const res = maskPii(text);
        if (res.findings.length > 0) {
          redacted = true;
          text = res.text;
          for (const p of res.findings) {
            findings.push({ detector: "pii.v1", category: "pii", severity: "medium", action: "mask", detail: `${p.kind} (${p.count})` });
          }
        }
      } else {
        for (const p of detectPii(text)) {
          findings.push({ detector: "pii.v1", category: "pii", severity: "medium", action: "flag", detail: `${p.kind} (${p.count})` });
        }
      }
    }

    // --- Check 3: Prompt injection (regex heuristics) ---
    if (!blocked && rule.injection !== "off") {
      if (rule.injection === "block") {
        const scan = detectPromptInjection(text);
        if (scan.detected) {
          blocked = true;
          blockReason = `Response blocked: suspected prompt injection (${scan.matches.map((m) => m.pattern).join(", ")})`;
          for (const m of scan.matches) {
            findings.push({ detector: "injection.v1", category: "prompt_injection", severity: "high", action: "block", detail: `${m.pattern}:${m.score}` });
          }
        }
      } else if (rule.injection === "redact") {
        const res = redactPromptInjection(text);
        if (res.scan.detected) {
          redacted = true;
          text = res.text;
          for (const m of res.scan.matches) {
            findings.push({ detector: "injection.v1", category: "prompt_injection", severity: "high", action: "redact", detail: `${m.pattern}:${m.score}` });
          }
        }
      } else {
        for (const m of detectPromptInjection(text).matches) {
          findings.push({ detector: "injection.v1", category: "prompt_injection", severity: "high", action: "flag", detail: `${m.pattern}:${m.score}` });
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
        content: [{ type: "text", text: blockReason ?? "Response blocked by gateway security policy." }],
      },
      findings,
    };
  }

  return { blocked: false, redacted, result: { ...result, content: updatedContent }, findings };
}

/**
 * Async filter pipeline — same as above but also uses Gemini for injection detection.
 *
 * Strategy:
 *   1. Run secrets + PII filters first (without injection) — sanitizes the text
 *   2. Run regex injection detector as an independent fallback
 *   3. Send the sanitized text to Gemini (we don't send raw secrets to Gemini's API)
 *   4. Combine all findings and apply the configured action
 *
 * Redacts secrets/PII before Gemini so we don't send real credentials to a cloud API.
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

  // Step 1: secrets + PII only (injection="off" here, handled separately below)
  const sanitized = applyResponseFilters(toolName, result, {
    [toolName]: { ...rule, injection: "off" },
  });
  if (sanitized.blocked) return sanitized;

  const textBlocks = sanitized.result.content
    .filter((b): b is { type: "text"; text: string } => b.type === "text")
    .map((b) => b.text);

  if (textBlocks.length === 0) return sanitized;

  // Step 2: regex injection detector as fallback
  const deterministic = applyResponseFilters(toolName, sanitized.result, {
    [toolName]: { pii: "off", secrets: "off", injection: rule.injection },
  });

  const findings = [...sanitized.findings, ...deterministic.findings];
  const base: FilterPipelineResult = {
    ...deterministic,
    redacted: sanitized.redacted || deterministic.redacted,
    findings,
  };

  // Step 3: Gemini LLM injection analysis
  const combinedText = textBlocks.join("\n\n");
  const outcome = await analyzePromptInjectionWithGemini(combinedText, { toolName, ...geminiOptions });

  if (outcome.status !== "completed" || !outcome.analysis) {
    // Gemini unavailable — record it and use regex result
    base.findings.push({
      detector: "gemini",
      analyzer: "gemini",
      category: "prompt_injection",
      severity: "medium",
      action: "fallback_deterministic",
      detail: outcome.status,
      analysisStatus: outcome.status,
      injectionDetected: null,
      ...(outcome.errorMessage !== undefined ? { reason: outcome.errorMessage } : {}),
    });
    return base;
  }

  const analysis = outcome.analysis;

  base.findings.push({
    detector: "gemini",
    analyzer: "gemini",
    category: "prompt_injection",
    severity: analysis.riskLevel,
    action: analysis.isInjection ? rule.injection : "allow",
    detail: `${analysis.riskLevel}:${analysis.confidence.toFixed(2)}`,
    analysisStatus: outcome.status,
    injectionDetected: analysis.isInjection,
    riskLevel: analysis.riskLevel,
    confidence: analysis.confidence,
    reason: analysis.reason,
    evidence: analysis.evidence,
    recommendedAction: analysis.recommendedAction,
  });

  if (!analysis.isInjection && !base.blocked) return base;
  if (base.blocked) return base;
  if (deterministic.blocked || deterministic.redacted || rule.injection === "flag") return base;

  // Step 4: apply Gemini's decision
  if (rule.injection === "block") {
    const blockReason = `Response blocked by Gemini analysis: ${analysis.reason}`;
    return {
      blocked: true,
      blockReason,
      redacted: false,
      result: { isError: true, content: [{ type: "text", text: blockReason }] },
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
          updatedText = updatedText.replaceAll(snippet, "[REDACTED: suspected injection]");
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
      result: { ...base.result, content: updatedContent },
      findings: base.findings,
    };
  }

  return base;
}
