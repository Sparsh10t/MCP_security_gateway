export interface InjectionMatch {
  pattern: string;
  score: number;
  snippet: string;
}

export interface InjectionScanResult {
  detected: boolean;
  maxScore: number;
  matches: InjectionMatch[];
}

const INJECTION_RULES: Array<{
  pattern: string;
  score: number;
  regex: RegExp;
}> = [
  {
    pattern: "instruction_override",
    score: 0.91,
    regex: /ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?/gi,
  },
  {
    pattern: "tool_hijack",
    score: 0.88,
    regex: /(?:and\s+call|execute|run|invoke)\s+[a-z0-9_-]+\.[a-z0-9_-]+/gi,
  },
  {
    pattern: "system_prompt_leak",
    score: 0.85,
    regex: /(?:reveal|print|output|show)\s+(?:your\s+)?(?:system\s+prompt|hidden\s+instructions)/gi,
  },
  {
    pattern: "role_override",
    score: 0.78,
    regex: /\byou\s+are\s+now\s+(?:a|an|in)\s+(?:developer|admin|unrestricted|jailbreak)\b/gi,
  },
  {
    pattern: "exfiltrate_secrets",
    score: 0.92,
    regex: /(?:send|exfiltrate|post|leak)\s+(?:the\s+)?(?:repo\s+)?(?:secrets?|tokens?|credentials?|keys?)\s+to\b/gi,
  },
];

export function detectPromptInjection(text: string): InjectionScanResult {
  const matches: InjectionMatch[] = [];
  let maxScore = 0;

  for (const rule of INJECTION_RULES) {
    rule.regex.lastIndex = 0;
    const match = rule.regex.exec(text);
    if (match) {
      maxScore = Math.max(maxScore, rule.score);
      matches.push({
        pattern: rule.pattern,
        score: rule.score,
        snippet: match[0],
      });
    }
  }

  return {
    detected: matches.length > 0,
    maxScore,
    matches,
  };
}

export function redactPromptInjection(text: string): {
  text: string;
  scan: InjectionScanResult;
} {
  const scan = detectPromptInjection(text);
  let output = text;
  for (const rule of INJECTION_RULES) {
    rule.regex.lastIndex = 0;
    output = output.replace(rule.regex, "[REDACTED: suspected injection]");
  }
  return { text: output, scan };
}
