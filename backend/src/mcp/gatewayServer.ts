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

async function persistAudit(
  auditLogger: AuditLogger,
  input: AuditEventInput
): Promise<void> {
  try {
    await auditLogger.log(input);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[audit] write failed:", msg);
    if (env.AUDIT_FAIL_CLOSED) {
      throw new ProtocolError(
        ProtocolErrorCode.InternalError,
        "AUDIT_FAILURE: unable to persist audit record"
      );
    }
  }
}

/**
 * Builds a per-request MCP Server factory enforcing AuthN, RBAC, rate limiting,
 * argument secret inspection, response PII/secret/injection filtering, and hash-chained auditing.
 */
export function createGatewayServerFactory(
  upstreamManager: UpstreamManager,
  policyEngine: PolicyEngine,
  auditLogger: AuditLogger,
  rateLimiter: InMemoryRateLimiter
): McpServerFactory {
  return (ctx) => {
    const identity = identityFromAuthInfo(ctx.authInfo);

    const server = new Server(
      {
        name: "mcp-security-gateway",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    server.setRequestHandler("tools/list", async () => {
      if (!identity) {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidRequest,
          "AUTH_REQUIRED: missing authenticated identity"
        );
      }

      const allTools = upstreamManager.listTools();
      const visibleTools = policyEngine.filterVisibleTools(identity, allTools);
      console.log(
        `[gateway] tools/list user=${identity.userId} roles=[${identity.roles.join(",")}] visible=${visibleTools.length}/${allTools.length}`
      );
      return {
        tools: visibleTools,
      };
    });

    server.setRequestHandler("tools/call", async (request) => {
      if (!identity) {
        throw new ProtocolError(
          ProtocolErrorCode.InvalidRequest,
          "AUTH_REQUIRED: missing authenticated identity"
        );
      }

      const traceId = crypto.randomUUID();
      const { name, arguments: args } = request.params;
      const startedAt = Date.now();

      // 1. RBAC Policy Evaluation
      const decision = policyEngine.evaluateToolCall(identity, name, args);
      if (!decision.allowed) {
        const latencyMs = Date.now() - startedAt;
        await persistAudit(auditLogger, {
          traceId,
          userId: identity.userId,
          roles: identity.roles,
          tool: name,
          ...(args !== undefined ? { args } : {}),
          decision:
            decision.effect === "require_approval"
              ? "require_approval"
              : "deny",
          reasonCode: decision.reasonCode,
          latencyMs,
        });

        console.warn(
          `[gateway] tools/call DENIED user=${identity.userId} roles=[${identity.roles.join(",")}] tool=${name} code=${decision.reasonCode} (${latencyMs}ms)`
        );
        throw new ProtocolError(
          POLICY_DENIED_RPC_CODE,
          `${decision.reasonCode}: ${decision.reason}`,
          {
            traceId,
            reasonCode: decision.reasonCode,
            effect: decision.effect,
            tool: name,
            userId: identity.userId,
            roles: identity.roles,
          }
        );
      }

      // 2. Per-identity / per-tool Rate Limiter
      const rate = rateLimiter.consume(
        identity.userId,
        name,
        decision.rateLimitPerMinute
      );
      if (!rate.allowed) {
        const latencyMs = Date.now() - startedAt;
        await persistAudit(auditLogger, {
          traceId,
          userId: identity.userId,
          roles: identity.roles,
          tool: name,
          ...(args !== undefined ? { args } : {}),
          decision: "rate_limited",
          reasonCode: "RATE_LIMITED",
          latencyMs,
        });
        console.warn(
          `[gateway] tools/call RATE_LIMITED user=${identity.userId} tool=${name} retryAfter=${rate.retryAfterSeconds}s`
        );
        throw new ProtocolError(
          RATE_LIMITED_RPC_CODE,
          `RATE_LIMITED: Rate limit exceeded for "${name}". Retry after ${rate.retryAfterSeconds}s.`,
          {
            traceId,
            reasonCode: "RATE_LIMITED",
            retryAfterSeconds: rate.retryAfterSeconds,
            limit: rate.limit,
          }
        );
      }

      // 3. Request Inspector (scan arguments for embedded secrets & prompt injection)
      const inspection = await inspectToolArgumentsWithGemini(name, args);
      if (!inspection.passed) {
        const latencyMs = Date.now() - startedAt;
        const reasonCode = inspection.reasonCode ?? "SECRET_IN_ARGUMENTS";
        await persistAudit(auditLogger, {
          traceId,
          userId: identity.userId,
          roles: identity.roles,
          tool: name,
          ...(args !== undefined ? { args } : {}),
          decision: "deny",
          reasonCode,
          findings: inspection.findings,
          latencyMs,
        });
        console.warn(
          `[gateway] tools/call ${reasonCode} user=${identity.userId} tool=${name} (${latencyMs}ms)`
        );
        throw new ProtocolError(
          POLICY_DENIED_RPC_CODE,
          `${reasonCode}: ${inspection.reason}`,
          { traceId, reasonCode, findings: inspection.findings }
        );
      }

      // 4. Forward to Upstream + Apply Response Filters
      try {
        const { result, entry } = await upstreamManager.callTool(name, args);
        const filtered = await applyResponseFiltersWithGemini(
          name,
          result,
          policyEngine.getResponseFilters()
        );
        const latencyMs = Date.now() - startedAt;

        if (filtered.blocked) {
          await persistAudit(auditLogger, {
            traceId,
            userId: identity.userId,
            roles: identity.roles,
            tool: name,
            ...(args !== undefined ? { args } : {}),
            decision: "blocked",
            reasonCode: "RESPONSE_BLOCKED",
            findings: filtered.findings,
            latencyMs,
          });
          console.warn(
            `[gateway] tools/call RESPONSE_BLOCKED user=${identity.userId} tool=${name} (${latencyMs}ms)`
          );
          throw new ProtocolError(
            POLICY_DENIED_RPC_CODE,
            filtered.blockReason ?? "RESPONSE_BLOCKED",
            { traceId, reasonCode: "RESPONSE_BLOCKED", findings: filtered.findings }
          );
        }

        const hasActionableFinding = filtered.findings.some(
          (f) => f.action !== "allow" && f.action !== "fallback_deterministic"
        );

        await persistAudit(auditLogger, {
          traceId,
          userId: identity.userId,
          roles: identity.roles,
          tool: name,
          ...(args !== undefined ? { args } : {}),
          decision: filtered.redacted ? "allow_redacted" : "allow",
          reasonCode: result.isError
            ? "UPSTREAM_TOOL_ERROR"
            : hasActionableFinding
              ? "ALLOWED_WITH_FINDINGS"
              : "ALLOWED",
          findings: filtered.findings,
          latencyMs,
        });

        console.log(
          `[gateway] tools/call ${filtered.redacted ? "ALLOW_REDACTED" : "ALLOW"} user=${identity.userId} role=${decision.matchedRole ?? "-"} ${name} findings=${filtered.findings.length} (${latencyMs}ms)`
        );
        return server.projectCallToolResult(
          filtered.result,
          entry.tool.outputSchema
        );
      } catch (err) {
        if (err instanceof ProtocolError) {
          throw err;
        }
        const latencyMs = Date.now() - startedAt;
        if (err instanceof UnknownToolError) {
          await persistAudit(auditLogger, {
            traceId,
            userId: identity.userId,
            roles: identity.roles,
            tool: name,
            ...(args !== undefined ? { args } : {}),
            decision: "upstream_error",
            reasonCode: "UNKNOWN_TOOL",
            latencyMs,
          });
          console.warn(`[gateway] tools/call ${name} -> unknown (${latencyMs}ms)`);
          throw new ProtocolError(ProtocolErrorCode.InvalidParams, err.message);
        }
        if (err instanceof UpstreamUnavailableError) {
          await persistAudit(auditLogger, {
            traceId,
            userId: identity.userId,
            roles: identity.roles,
            tool: name,
            ...(args !== undefined ? { args } : {}),
            decision: "upstream_error",
            reasonCode: "UPSTREAM_UNAVAILABLE",
            latencyMs,
          });
          console.error(`[gateway] tools/call ${name} -> unavailable (${latencyMs}ms)`);
          throw new ProtocolError(ProtocolErrorCode.InternalError, err.message);
        }

        const message = err instanceof Error ? err.message : String(err);
        await persistAudit(auditLogger, {
          traceId,
          userId: identity.userId,
          roles: identity.roles,
          tool: name,
          ...(args !== undefined ? { args } : {}),
          decision: "upstream_error",
          reasonCode: "UPSTREAM_EXECUTION_ERROR",
          latencyMs,
        });
        console.error(`[gateway] tools/call ${name} failed (${latencyMs}ms):`, message);
        throw new ProtocolError(
          ProtocolErrorCode.InternalError,
          `Upstream tool execution failed: ${message}`
        );
      }
    });

    return server;
  };
}
