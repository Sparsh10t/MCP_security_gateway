export type AuditDecision =
  | "allow"
  | "allow_redacted"
  | "blocked"
  | "deny"
  | "rate_limited"
  | "require_approval"
  | "auth_failed"
  | "upstream_error";

export interface AuditFinding {
  detector: string;
  analyzer?: string;
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  action: string;
  detail?: string;
  analysisStatus?: string;
  injectionDetected?: boolean | null;
  riskLevel?: string;
  confidence?: number;
  reason?: string;
  evidence?: string[];
  recommendedAction?: string;
}

export interface AuditEventPayload {
  id: string;
  ts: string;
  traceId: string;
  userId: string;
  roles: string[];
  tool: string;
  argsRedacted: Record<string, unknown>;
  argsHash: string;
  decision: AuditDecision;
  reasonCode: string;
  findings: AuditFinding[];
  latencyMs: number;
}

export interface AuditEventRecord extends AuditEventPayload {
  seq?: number;
  prevHash: string;
  hash: string;
}

export interface AuditEventInput {
  traceId: string;
  userId: string;
  roles: string[];
  tool: string;
  args?: Record<string, unknown>;
  decision: AuditDecision;
  reasonCode: string;
  findings?: AuditFinding[];
  latencyMs: number;
}

export interface AuditQueryFilter {
  userId?: string;
  tool?: string;
  decision?: string;
  reasonCode?: string;
  limit?: number;
  offset?: number;
}

export interface ChainVerificationResult {
  valid: boolean;
  totalEvents: number;
  headHash: string;
  firstInvalid?: {
    index: number;
    id: string;
    reason: string;
    expectedHash?: string;
    actualHash?: string;
  };
}
