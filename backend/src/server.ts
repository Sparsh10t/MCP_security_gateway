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
import { closeRedis, initRedis } from "./services/redis.js";

async function bootstrap() {
  const app = express();
  app.use(cors());

  const pgConnected = await initPostgres();
  await initRedis();

  const auditStore = pgConnected
    ? new PostgresAuditStore(getPostgresPool())
    : new FileAuditStore(env.AUDIT_LOG_PATH);
  const auditLogger = new AuditLogger(auditStore);
  console.log(
    `[audit] initialized (${pgConnected ? "postgres:audit_events" : `file:${env.AUDIT_LOG_PATH}`})`
  );

  const loadedPolicy = await loadPolicyFile(env.POLICY_PATH);
  const policyEngine = new PolicyEngine(loadedPolicy);
  await recordPolicyVersion(
    String(loadedPolicy.document.version),
    loadedPolicy.sha256,
    loadedPolicy.source
  );
  console.log(
    `[policy] loaded v${loadedPolicy.document.version} (${loadedPolicy.resolvedRoles.size} roles, sha256=${loadedPolicy.sha256.slice(0, 12)})`
  );

  const upstreamConfigs = await loadUpstreamConfigs(env.UPSTREAM_CONFIG_PATH);
  await syncUpstreamServers(upstreamConfigs);

  const upstreamManager = new UpstreamManager();
  await upstreamManager.initialize(upstreamConfigs);

  const rateLimiter = new InMemoryRateLimiter(60);

  const mcpHandler = createMcpHandler(
    createGatewayServerFactory(
      upstreamManager,
      policyEngine,
      auditLogger,
      rateLimiter
    ),
    {
      onerror: (err) => {
        console.error("[mcp-handler] error:", err);
      },
    }
  );

  const requireMcpAuth = createAuthMiddleware(auditLogger);

  // Enforce JWT AuthN and mount Streamable HTTP MCP endpoint before express.json()
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
    console.log(
      `MCP Security Gateway listening on http://localhost:${env.PORT} (MCP endpoint: /mcp, AuthN+RBAC+Audit: enabled)`
    );
  });

  const shutdown = async (signal: string) => {
    console.log(`\n[gateway] received ${signal}, shutting down...`);
    httpServer.close();
    await mcpHandler.close();
    await upstreamManager.closeAll();
    await closeRedis();
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
