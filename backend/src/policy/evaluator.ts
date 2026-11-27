/**
 * RBAC policy engine — answers two questions:
 *   1. Can this user SEE this tool? (tools/list)
 *   2. Can this user CALL this tool with these args? (tools/call)
 *
 * Default is deny-everything. A user needs an explicit allow rule in their role.
 *
 * Tool patterns:
 *   "*"        → matches all tools
 *   "demo.*"   → all tools under the "demo" namespace
 *   "demo.greet" → exact match only
 */

import type { Tool } from "@modelcontextprotocol/client";
import type { Identity } from "../auth/identity.js";
import { evaluateArgumentConstraints } from "./constraints.js";
import type { LoadedPolicy, PolicyDecision } from "./types.js";

export function matchToolPattern(pattern: string, toolName: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith(".*")) {
    const prefix = pattern.slice(0, -1); // "demo.*" → "demo."
    return toolName.startsWith(prefix);
  }
  return pattern === toolName;
}

export class PolicyEngine {
  private policy: LoadedPolicy;

  constructor(policy: LoadedPolicy) {
    this.policy = policy;
  }

  getPolicyMetadata() {
    return {
      version: String(this.policy.document.version),
      sha256: this.policy.sha256,
      source: this.policy.source,
      defaults: this.policy.document.defaults,
      roles: Array.from(this.policy.resolvedRoles.keys()),
    };
  }

  getFullPolicySummary() {
    return {
      ...this.getPolicyMetadata(),
      roleDetails: Array.from(this.policy.resolvedRoles.values()),
      responseFilters: this.policy.document.response_filters ?? {},
    };
  }

  getResponseFilters() {
    return this.policy.document.response_filters;
  }

  reload(newPolicy: LoadedPolicy): void {
    this.policy = newPolicy;
  }

  canDiscoverTool(identity: Identity, toolName: string): boolean {
    try {
      for (const roleName of identity.roles) {
        const role = this.policy.resolvedRoles.get(roleName);
        if (!role) continue;
        if (role.allow.some((rule) => matchToolPattern(rule.tool, toolName))) {
          return true;
        }
      }
      return this.policy.document.defaults.effect === "allow";
    } catch {
      return false; // fail closed
    }
  }

  filterVisibleTools(identity: Identity, tools: Tool[]): Tool[] {
    return tools.filter((tool) => this.canDiscoverTool(identity, tool.name));
  }

  evaluateToolCall(
    identity: Identity,
    toolName: string,
    args?: Record<string, unknown>
  ): PolicyDecision {
    try {
      // Step 1: check require_approval before anything else
      for (const roleName of identity.roles) {
        const role = this.policy.resolvedRoles.get(roleName);
        if (!role) continue;

        const approvalPattern = role.requireApproval.find((pattern) =>
          matchToolPattern(pattern, toolName)
        );
        if (approvalPattern) {
          return {
            allowed: false,
            effect: "require_approval",
            reasonCode: "APPROVAL_REQUIRED",
            reason: `Tool "${toolName}" requires human approval for role "${roleName}"`,
            matchedRole: roleName,
            matchedPattern: approvalPattern,
          };
        }
      }

      // Step 2: collect all allow rules that match this tool
      const matchingRules: Array<{
        roleName: string;
        pattern: string;
        constraints?: Record<string, import("./types.js").ArgumentConstraint>;
        ratePerMinute?: number;
      }> = [];

      for (const roleName of identity.roles) {
        const role = this.policy.resolvedRoles.get(roleName);
        if (!role) continue;

        for (const rule of role.allow) {
          if (matchToolPattern(rule.tool, toolName)) {
            matchingRules.push({
              roleName,
              pattern: rule.tool,
              ...(rule.constraints !== undefined ? { constraints: rule.constraints } : {}),
              ...(rule.rate?.per_minute !== undefined ? { ratePerMinute: rule.rate.per_minute } : {}),
            });
          }
        }
      }

      if (matchingRules.length === 0) {
        if (this.policy.document.defaults.effect === "allow") {
          return { allowed: true, effect: "allow", reasonCode: "ALLOWED", reason: "Allowed by default policy" };
        }
        return {
          allowed: false,
          effect: "deny",
          reasonCode: "ACCESS_DENIED",
          reason: `Roles [${identity.roles.join(", ")}] are not permitted to call "${toolName}"`,
        };
      }

      // Step 3: check argument constraints for each matching rule
      const constraintFailures: string[] = [];

      for (const candidate of matchingRules) {
        const check = evaluateArgumentConstraints(candidate.constraints, args);
        if (check.passed) {
          return {
            allowed: true,
            effect: "allow",
            reasonCode: "ALLOWED",
            reason: `Allowed by role "${candidate.roleName}" (${candidate.pattern})`,
            matchedRole: candidate.roleName,
            matchedPattern: candidate.pattern,
            ...(candidate.ratePerMinute !== undefined ? { rateLimitPerMinute: candidate.ratePerMinute } : {}),
          };
        }
        if (check.reason) constraintFailures.push(`${candidate.roleName}: ${check.reason}`);
      }

      return {
        allowed: false,
        effect: "deny",
        reasonCode: "ARG_CONSTRAINT_VIOLATION",
        reason: constraintFailures.join("; ") || `Arguments violated policy constraints for "${toolName}"`,
      };

    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        allowed: false,
        effect: "deny",
        reasonCode: "POLICY_ENGINE_ERROR",
        reason: `Policy evaluation error (fail-closed): ${msg}`,
      };
    }
  }
}
