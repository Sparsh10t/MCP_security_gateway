import { Router } from "express";
import type { UpstreamManager } from "../mcp/upstreamManager.js";
import {
  requireJwtAuth,
  type AuthenticatedRequest,
} from "../middleware/authMiddleware.js";
import type { PolicyEngine } from "../policy/evaluator.js";

export function createPolicyRouter(
  policyEngine: PolicyEngine,
  upstreamManager: UpstreamManager
): Router {
  const router = Router();

  router.get(
    "/api/whoami",
    requireJwtAuth,
    (req: AuthenticatedRequest, res) => {
      const identity = req.identity;
      if (!identity) {
        res.status(401).json({ error: "unauthorized" });
        return;
      }

      const visibleTools = policyEngine
        .filterVisibleTools(identity, upstreamManager.listTools())
        .map((t) => t.name);

      res.json({
        identity,
        visibleTools,
      });
    }
  );

  router.get(
    "/api/policy",
    requireJwtAuth,
    (_req: AuthenticatedRequest, res) => {
      res.json(policyEngine.getFullPolicySummary());
    }
  );

  return router;
}
