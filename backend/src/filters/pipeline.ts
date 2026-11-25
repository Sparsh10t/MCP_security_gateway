import type { CallToolResult } from "@modelcontextprotocol/client";
import type { AuditFinding } from "../audit/types.js";
import type { ResponseFilterRule } from "../policy/types.js";
import { detectPromptInjection, redactPromptInjection } from "./injection.js";
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
