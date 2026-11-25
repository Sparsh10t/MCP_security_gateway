export interface SecretFinding {
  rule: string;
  severity: "high" | "critical";
  matchPreview: string;
}

const SECRET_PATTERNS: Array<{
  rule: string;
  severity: "high" | "critical";
  regex: RegExp;
}> = [
  {
    rule: "aws_access_key",
    severity: "critical",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    rule: "github_token",
    severity: "critical",
    regex: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  },
  {
    rule: "openai_or_api_sk_key",
    severity: "critical",
    regex: /\bsk-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    rule: "private_key_pem",
    severity: "critical",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
  },
  {
    rule: "bearer_token",
    severity: "high",
    regex: /\bBearer\s+[A-Za-z0-9\-._~+/]{16,}=*/gi,
  },
];

export function detectSecrets(text: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  for (const { rule, severity, regex } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    const match = regex.exec(text);
    if (match) {
      const raw = match[0];
      const preview =
        raw.length > 8 ? `${raw.slice(0, 4)}...${raw.slice(-4)}` : "***";
      findings.push({ rule, severity, matchPreview: preview });
    }
  }
  return findings;
}

export function redactSecrets(text: string): {
  text: string;
  findings: SecretFinding[];
} {
  const findings = detectSecrets(text);
  let output = text;
  for (const { rule, regex } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    output = output.replace(regex, `[REDACTED:${rule}]`);
  }
  return { text: output, findings };
}
