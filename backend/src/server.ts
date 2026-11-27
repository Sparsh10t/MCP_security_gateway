/**
 * server.ts — Entry point. Starts the MCP Security Gateway.
 *
 * Startup order:
 *   1. Express + CORS
 *   2. Postgres (falls back to file log if unavailable)
 *   3. Load RBAC policy
 *   4. Connect to upstream MCP servers
 *   5. Create MCP handler (the security pipeline)
 *   6. Mount JWT auth + MCP endpoint
 *   7. Mount REST API routes
 *   8. Start listening
 */

import cors from "cors";
import express from "express";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { AuditLogger } from "./audit/logger.js";
import { FileAuditStore, PostgresAuditStore } from "./audit/store.js";
import { env } from "./config/env.js";
import { loadUpstreamConfigs } from "./config/upstreams.js";
import { createGatewayServerFactory } from "./mcp/gatewayServer.js";
import { expressMcpHandler } from "./mcp/httpAdapter.js";
import { UpstreamManager } from "./mcp/upstreamManager.js";
import { createAuthMiddleware } from "./middleware/authMiddleware.js";
import { PolicyEngine } from "./policy/evaluator.js";
import { loadPolicyFile } from "./policy/loader.js";
import { InMemoryRateLimiter } from "./ratelimit/tokenBucket.js";
import { createAuditRouter } from "./routes/audit.js";
import { createHealthRouter } from "./routes/health.js";
import { createPolicyRouter } from "./routes/policy.js";
import {
  closePostgres,
  getPostgresPool,
  initPostgres,
  recordPolicyVersion,
  syncUpstreamServers,
} from "./services/postgres.js";

async function bootstrap() {
  const app = express();
  app.use(cors()); // allows the React dashboard (port 5173) to call this API (port 5000)

  // Try postgres first, fall back to a plain log file
  const pgConnected = await initPostgres();
  const auditStore = pgConnected
    ? new PostgresAuditStore(getPostgresPool())
    : new FileAuditStore(env.AUDIT_LOG_PATH);
  const auditLogger = new AuditLogger(auditStore);
  console.log(`[audit] initialized (${pgConnected ? "postgres:audit_events" : `file:${env.AUDIT_LOG_PATH}`})`);

  // Load the RBAC policy YAML file
  const loadedPolicy = await loadPolicyFile(env.POLICY_PATH);
  const policyEngine = new PolicyEngine(loadedPolicy);
  await recordPolicyVersion(String(loadedPolicy.document.version), loadedPolicy.sha256, loadedPolicy.source);
  console.log(`[policy] loaded v${loadedPolicy.document.version} (${loadedPolicy.resolvedRoles.size} roles, sha256=${loadedPolicy.sha256.slice(0, 12)})`);

  // Connect to upstream MCP servers
  const upstreamConfigs = await loadUpstreamConfigs(env.UPSTREAM_CONFIG_PATH);
  await syncUpstreamServers(upstreamConfigs);
  const upstreamManager = new UpstreamManager();
  await upstreamManager.initialize(upstreamConfigs);

  // Default 60 req/min; individual tools can override this in policy
  const rateLimiter = new InMemoryRateLimiter(60);

  const mcpHandler = createMcpHandler(
    createGatewayServerFactory(upstreamManager, policyEngine, auditLogger, rateLimiter),
    { onerror: (err) => console.error("[mcp-handler] error:", err) }
  );

  const requireMcpAuth = createAuthMiddleware(auditLogger);

  // Mount MCP endpoint BEFORE express.json() — the SDK reads the raw body itself
  app.all("/mcp", requireMcpAuth, expressMcpHandler(mcpHandler));
  app.use(express.json());

  app.get("/", (_req, res) => {
    res.json({
      message: "Welcome to MCP Sentinel!",
      status: "Gateway is running",
      mcpEndpoint: "/mcp",
      authRequired: true,
      policyVersion: String(loadedPolicy.document.version),
      toolsLoaded: upstreamManager.listTools().length,
    });
  });

  app.use(createHealthRouter(upstreamManager));
  app.use(createPolicyRouter(policyEngine, upstreamManager));
  app.use(createAuditRouter(auditLogger));

  const httpServer = app.listen(env.PORT, () => {
    console.log(`MCP Security Gateway listening on http://localhost:${env.PORT} (MCP endpoint: /mcp, AuthN+RBAC+Audit: enabled)`);
  });

  // Graceful shutdown on Ctrl+C or kill signal
  const shutdown = async (signal: string) => {
    console.log(`\n[gateway] received ${signal}, shutting down...`);
    httpServer.close();
    await mcpHandler.close();
    await upstreamManager.closeAll();
    await closePostgres();
    process.exit(0);
  };

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

bootstrap().catch((err) => {
  console.error("[gateway] fatal startup error:", err);
  process.exit(1);
});
