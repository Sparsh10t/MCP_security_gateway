export type PrimitiveValue = string | number | boolean;

export interface ArgumentConstraint {
  in?: PrimitiveValue[];
  not_in?: PrimitiveValue[];
  equals?: PrimitiveValue;
  matches?: string;
  min?: number;
  max?: number;
  min_length?: number;
  max_length?: number;
  optional?: boolean;
}

export interface RateLimitRule {
  per_minute?: number;
}

export interface AllowRule {
  tool: string;
  constraints?: Record<string, ArgumentConstraint>;
  rate?: RateLimitRule;
}

export interface RoleDefinition {
  inherits?: string[];
  allow?: AllowRule[];
  require_approval?: Array<{ tool: string }>;
}

export interface ResponseFilterRule {
  pii?: "off" | "flag" | "mask";
  secrets?: "off" | "flag" | "redact" | "block";
  injection?: "off" | "flag" | "redact" | "block";
}

export interface PolicyDocument {
  version: number | string;
  defaults: {
    effect: "deny" | "allow";
  };
  roles: Record<string, RoleDefinition>;
  response_filters?: Record<string, ResponseFilterRule>;
}

export interface ResolvedRole {
  name: string;
  allow: AllowRule[];
  requireApproval: string[];
}

export interface LoadedPolicy {
  document: PolicyDocument;
  resolvedRoles: Map<string, ResolvedRole>;
  sha256: string;
  source: string;
}

export type PolicyReasonCode =
  | "ALLOWED"
  | "ACCESS_DENIED"
  | "ARG_CONSTRAINT_VIOLATION"
  | "APPROVAL_REQUIRED"
  | "POLICY_ENGINE_ERROR";

export interface PolicyDecision {
  allowed: boolean;
  effect: "allow" | "deny" | "require_approval";
  reasonCode: PolicyReasonCode;
  reason: string;
  matchedRole?: string;
  matchedPattern?: string;
  rateLimitPerMinute?: number;
}
