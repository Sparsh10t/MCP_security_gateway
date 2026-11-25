export interface PiiFinding {
  kind: string;
  count: number;
}

const PII_PATTERNS: Array<{
  kind: string;
  regex: RegExp;
  mask: (match: string) => string;
}> = [
  {
    kind: "email",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    mask: (m) => {
      const parts = m.split("@");
      const local = parts[0] ?? "";
      const domain = parts[1] ?? "";
      return `${local.slice(0, 2)}***@${domain}`;
    },
  },
  {
    kind: "ssn",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    mask: () => "***-**-****",
  },
  {
    kind: "aadhaar",
    regex: /\b\d{4}\s\d{4}\s\d{4}\b/g,
    mask: (m) => `XXXX XXXX ${m.slice(-4)}`,
  },
  {
    kind: "credit_card",
    regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    mask: (m) => `****-****-****-${m.replace(/\D/g, "").slice(-4)}`,
  },
  {
    kind: "phone",
    regex: /\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g,
    mask: (m) => `***-***-${m.replace(/\D/g, "").slice(-4)}`,
  },
];

export function detectPii(text: string): PiiFinding[] {
  const findings: PiiFinding[] = [];
  for (const { kind, regex } of PII_PATTERNS) {
    regex.lastIndex = 0;
    const matches = text.match(regex);
    if (matches && matches.length > 0) {
      findings.push({ kind, count: matches.length });
    }
  }
  return findings;
}

export function maskPii(text: string): {
  text: string;
  findings: PiiFinding[];
} {
  const findings = detectPii(text);
  let output = text;
  for (const { regex, mask } of PII_PATTERNS) {
    regex.lastIndex = 0;
    output = output.replace(regex, mask);
  }
  return { text: output, findings };
}
