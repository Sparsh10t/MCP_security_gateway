import { Router } from "express";
import type { AuditLogger } from "../audit/logger.js";
import type { AuditQueryFilter } from "../audit/types.js";
import { requireJwtAuth } from "../middleware/authMiddleware.js";

function parseFilter(query: Record<string, unknown>): AuditQueryFilter {
  const userId = typeof query["userId"] === "string" ? query["userId"] : undefined;
  const tool = typeof query["tool"] === "string" ? query["tool"] : undefined;
  const decision =
    typeof query["decision"] === "string" ? query["decision"] : undefined;
  const reasonCode =
    typeof query["reasonCode"] === "string" ? query["reasonCode"] : undefined;
  const limitRaw =
    typeof query["limit"] === "string" ? Number(query["limit"]) : undefined;
  const offsetRaw =
    typeof query["offset"] === "string" ? Number(query["offset"]) : undefined;

  return {
    ...(userId ? { userId } : {}),
    ...(tool ? { tool } : {}),
    ...(decision ? { decision } : {}),
    ...(reasonCode ? { reasonCode } : {}),
    ...(limitRaw !== undefined && Number.isFinite(limitRaw)
      ? { limit: limitRaw }
      : {}),
    ...(offsetRaw !== undefined && Number.isFinite(offsetRaw)
      ? { offset: offsetRaw }
      : {}),
  };
}

export function createAuditRouter(auditLogger: AuditLogger): Router {
  const router = Router();

  router.get("/api/audit", requireJwtAuth, async (req, res, next) => {
    try {
      const filter = parseFilter(req.query as Record<string, unknown>);
      const result = await auditLogger.query(filter);
      res.json(result);
    } catch (err) {
      next(err);
    }
  });

  router.get("/api/audit/verify", requireJwtAuth, async (_req, res, next) => {
    try {
      const verification = await auditLogger.verifyChain();
      res.status(verification.valid ? 200 : 409).json(verification);
    } catch (err) {
      next(err);
    }
  });

  router.get("/api/audit/stats", requireJwtAuth, async (_req, res, next) => {
    try {
      const { events, total } = await auditLogger.query({ limit: 500 });
      const byDecision: Record<string, number> = {};
      const byTool: Record<string, number> = {};
      let totalFindings = 0;

      for (const ev of events) {
        byDecision[ev.decision] = (byDecision[ev.decision] ?? 0) + 1;
        byTool[ev.tool] = (byTool[ev.tool] ?? 0) + 1;
        totalFindings += ev.findings.filter(
          (f) => f.action !== "allow" && f.action !== "fallback_deterministic"
        ).length;
      }

      res.json({
        totalEvents: total,
        sampledEvents: events.length,
        totalFindings,
        byDecision,
        byTool,
      });
    } catch (err) {
      next(err);
    }
  });

  router.get("/api/audit/export", requireJwtAuth, async (req, res, next) => {
    try {
      const filter = parseFilter(req.query as Record<string, unknown>);
      const { events } = await auditLogger.query({
        ...filter,
        limit: filter.limit ?? 500,
      });

      const format = req.query["format"] === "csv" ? "csv" : "json";
      if (format === "csv") {
        res.setHeader("Content-Type", "text/csv; charset=utf-8");
        res.setHeader(
          "Content-Disposition",
          'attachment; filename="audit-events.csv"'
        );
        res.send(auditLogger.formatCsv(events));
        return;
      }

      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader(
        "Content-Disposition",
        'attachment; filename="audit-events.json"'
      );
      res.send(JSON.stringify(events, null, 2));
    } catch (err) {
      next(err);
    }
  });

  return router;
}
