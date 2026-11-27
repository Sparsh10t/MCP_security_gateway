/**
 * Core security pipeline — every tool call passes through these checks:
 *
 *   1. JWT auth     — valid token? who are you?
 *   2. RBAC         — does your role allow this tool?
 *   3. Rate limiter — are you calling too fast?
 *   4. Request scan — do your arguments contain secrets or injection?
 *   5. Upstream     — forward the call to the real MCP server
 *   6. Response scan — does the response contain secrets/PII/injection?
 *   7. Audit log    — record everything
 *
 * Fail closed: any error → deny, never accidentally allow.
 */

import crypto from "node:crypto";
import {
  ProtocolError,
  ProtocolErrorCode,
  Server,
  type McpServerFactory,
} from "@modelcontextprotocol/server";
import type { AuditLogger } from "../audit/logger.js";
import type { AuditEventInput } from "../audit/types.js";
import { identityFromAuthInfo } from "../auth/identity.js";
import { env } from "../config/env.js";
import { applyResponseFiltersWithGemini } from "../filters/pipeline.js";
import { inspectToolArgumentsWithGemini } from "../inspect/requestInspector.js";
import type { PolicyEngine } from "../policy/evaluator.js";
import type { InMemoryRateLimiter } from "../ratelimit/tokenBucket.js";
import {
  UnknownToolError,
  UpstreamUnavailableError,
  type UpstreamManager,
} from "./upstreamManager.js";

const POLICY_DENIED_RPC_CODE = -32003;
const RATE_LIMITED_RPC_CODE = -32029;

async function persistAudit(auditLogger: AuditLogger, input: AuditEventInput): Promise<void> {
  try {
    await auditLogger.log(input);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[audit] write failed:", msg);
    if (env.AUDIT_FAIL_CLOSED) {
      throw new ProtocolError(ProtocolErrorCode.InternalError, "AUDIT_FAILURE: unable to persist audit record");
    }
  }
}

export function createGatewayServerFactory(
  upstreamManager: UpstreamManager,
  policyEngine: PolicyEngine,
  auditLogger: AuditLogger,
  rateLimiter: InMemoryRateLimiter
): McpServerFactory {
  return (ctx) => {
    const identity = identityFromAuthInfo(ctx.authInfo);

    const server = new Server(
      { name: "mcp-security-gateway", version: "1.0.0" },
      { capabilities: { tools: {} } }
    );

    // tools/list — return only the tools this user's role can see
    server.setRequestHandler("tools/list", async () => {
      if (!identity) {
        throw new ProtocolError(ProtocolErrorCode.InvalidRequest, "AUTH_REQUIRED: missing authenticated identity");
      }
      const allTools = upstreamManager.listTools();
      const visibleTools = policyEngine.filterVisibleTools(identity, allTools);
      console.log(`[gateway] tools/list user=${identity.userId} roles=[${identity.roles.join(",")}] visible=${visibleTools.length}/${allTools.length}`);
      return { tools: visibleTools };
    });

    // tools/call — the full 7-step security pipeline
    server.setRequestHandler("tools/call", async (request) => {
      if (!identity) {
        throw new ProtocolError(ProtocolErrorCode.InvalidRequest, "AUTH_REQUIRED: missing authenticated identity");
      }

      const traceId = crypto.randomUUID();
      const { name, arguments: args } = request.params;
      const startedAt = Date.now();

      // --- Step 1 & 2: RBAC policy check ---
      const decision = policyEngine.evaluateToolCall(identity, name, args);
      if (!decision.allowed) {
        const latencyMs = Date.now() - startedAt;
        await persistAudit(auditLogger, {
          traceId, userId: identity.userId, roles: identity.roles, tool: name,
          ...(args !== undefined ? { args } : {}),
          decision: decision.effect === "require_approval" ? "require_approval" : "deny",
          reasonCode: decision.reasonCode, latencyMs,
        });
        console.warn(`[gateway] tools/call DENIED user=${identity.userId} tool=${name} code=${decision.reasonCode} (${latencyMs}ms)`);
        throw new ProtocolError(POLICY_DENIED_RPC_CODE, `${decision.reasonCode}: ${decision.reason}`, {
          traceId, reasonCode: decision.reasonCode, effect: decision.effect, tool: name,
          userId: identity.userId, roles: identity.roles,
        });
      }

      // --- Step 3: Rate limiter ---
      const rate = rateLimiter.consume(identity.userId, name, decision.rateLimitPerMinute);
      if (!rate.allowed) {
        const latencyMs = Date.now() - startedAt;
        await persistAudit(auditLogger, {
          traceId, userId: identity.userId, roles: identity.roles, tool: name,
          ...(args !== undefined ? { args } : {}),
          decision: "rate_limited", reasonCode: "RATE_LIMITED", latencyMs,
        });
        console.warn(`[gateway] tools/call RATE_LIMITED user=${identity.userId} tool=${name} retryAfter=${rate.retryAfterSeconds}s`);
        throw new ProtocolError(
          RATE_LIMITED_RPC_CODE,
          `RATE_LIMITED: Rate limit exceeded for "${name}". Retry after ${rate.retryAfterSeconds}s.`,
          { traceId, reasonCode: "RATE_LIMITED", retryAfterSeconds: rate.retryAfterSeconds, limit: rate.limit }
        );
      }

      // --- Step 4: Scan arguments for secrets & prompt injection ---
      const inspection = await inspectToolArgumentsWithGemini(name, args);
      if (!inspection.passed) {
        const latencyMs = Date.now() - startedAt;
        const reasonCode = inspection.reasonCode ?? "SECRET_IN_ARGUMENTS";
        await persistAudit(auditLogger, {
          traceId, userId: identity.userId, roles: identity.roles, tool: name,
          ...(args !== undefined ? { args } : {}),
          decision: "deny", reasonCode, findings: inspection.findings, latencyMs,
        });
        console.warn(`[gateway] tools/call ${reasonCode} user=${identity.userId} tool=${name} (${latencyMs}ms)`);
        throw new ProtocolError(POLICY_DENIED_RPC_CODE, `${reasonCode}: ${inspection.reason}`, {
          traceId, reasonCode, findings: inspection.findings,
        });
      }

      // --- Steps 5 & 6: Call upstream + filter the response ---
      try {
        const { result, entry } = await upstreamManager.callTool(name, args);
        const filtered = await applyResponseFiltersWithGemini(name, result, policyEngine.getResponseFilters());
        const latencyMs = Date.now() - startedAt;

        if (filtered.blocked) {
          await persistAudit(auditLogger, {
            traceId, userId: identity.userId, roles: identity.roles, tool: name,
            ...(args !== undefined ? { args } : {}),
            decision: "blocked", reasonCode: "RESPONSE_BLOCKED", findings: filtered.findings, latencyMs,
          });
          console.warn(`[gateway] tools/call RESPONSE_BLOCKED user=${identity.userId} tool=${name} (${latencyMs}ms)`);
          throw new ProtocolError(POLICY_DENIED_RPC_CODE, filtered.blockReason ?? "RESPONSE_BLOCKED", {
            traceId, reasonCode: "RESPONSE_BLOCKED", findings: filtered.findings,
          });
        }

        const hasActionableFinding = filtered.findings.some(
          (f) => f.action !== "allow" && f.action !== "fallback_deterministic"
        );

        await persistAudit(auditLogger, {
          traceId, userId: identity.userId, roles: identity.roles, tool: name,
          ...(args !== undefined ? { args } : {}),
          decision: filtered.redacted ? "allow_redacted" : "allow",
          reasonCode: result.isError ? "UPSTREAM_TOOL_ERROR" : hasActionableFinding ? "ALLOWED_WITH_FINDINGS" : "ALLOWED",
          findings: filtered.findings, latencyMs,
        });

        console.log(`[gateway] tools/call ${filtered.redacted ? "ALLOW_REDACTED" : "ALLOW"} user=${identity.userId} role=${decision.matchedRole ?? "-"} ${name} findings=${filtered.findings.length} (${latencyMs}ms)`);
        return server.projectCallToolResult(filtered.result, entry.tool.outputSchema);

      } catch (err) {
        if (err instanceof ProtocolError) throw err;

        const latencyMs = Date.now() - startedAt;

        if (err instanceof UnknownToolError) {
          await persistAudit(auditLogger, {
            traceId, userId: identity.userId, roles: identity.roles, tool: name,
            ...(args !== undefined ? { args } : {}),
            decision: "upstream_error", reasonCode: "UNKNOWN_TOOL", latencyMs,
          });
          console.warn(`[gateway] tools/call ${name} -> unknown (${latencyMs}ms)`);
          throw new ProtocolError(ProtocolErrorCode.InvalidParams, err.message);
        }

        if (err instanceof UpstreamUnavailableError) {
          await persistAudit(auditLogger, {
            traceId, userId: identity.userId, roles: identity.roles, tool: name,
            ...(args !== undefined ? { args } : {}),
            decision: "upstream_error", reasonCode: "UPSTREAM_UNAVAILABLE", latencyMs,
          });
          console.error(`[gateway] tools/call ${name} -> unavailable (${latencyMs}ms)`);
          throw new ProtocolError(ProtocolErrorCode.InternalError, err.message);
        }

        const message = err instanceof Error ? err.message : String(err);
        await persistAudit(auditLogger, {
          traceId, userId: identity.userId, roles: identity.roles, tool: name,
          ...(args !== undefined ? { args } : {}),
          decision: "upstream_error", reasonCode: "UPSTREAM_EXECUTION_ERROR", latencyMs,
        });
        console.error(`[gateway] tools/call ${name} failed (${latencyMs}ms):`, message);
        throw new ProtocolError(ProtocolErrorCode.InternalError, `Upstream tool execution failed: ${message}`);
      }
    });

    return server;
  };
}
