import { Router } from "express";
import type { UpstreamManager } from "../mcp/upstreamManager.js";
import { pingPostgres } from "../services/postgres.js";

export function createHealthRouter(upstreamManager: UpstreamManager): Router {
  const router = Router();

  router.get("/health", async (_req, res) => {
    const postgresOk = await pingPostgres();
    const upstreams = upstreamManager.getStatuses();
    const connectedUpstreams = upstreams.filter((u) => u.connected).length;

    res.json({
      status: "ok",
      service: "mcp-security-gateway",
      infra: {
        postgres: postgresOk ? "connected" : "unavailable",
      },
      upstreams: {
        total: upstreams.length,
        connected: connectedUpstreams,
        tools: upstreamManager.listTools().length,
      },
    });
  });

  router.get("/api/upstreams", (_req, res) => {
    res.json({
      upstreams: upstreamManager.getStatuses(),
      totalTools: upstreamManager.listTools().length,
    });
  });

  return router;
}
