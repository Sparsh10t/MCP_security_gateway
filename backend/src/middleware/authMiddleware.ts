import crypto from "node:crypto";
import type { AuthInfo } from "@modelcontextprotocol/server";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { AuditLogger } from "../audit/logger.js";
import { toAuthInfo, type Identity } from "../auth/identity.js";
import { AuthError, verifyJwtToken } from "../auth/jwtVerifier.js";

export interface AuthenticatedRequest extends Request {
  identity?: Identity;
  authInfo?: AuthInfo;
}

function sendUnauthorized(
  res: Response,
  code: string,
  message: string
): void {
  const escapedDesc = message.replace(/"/g, '\\"');
  res.setHeader(
    "WWW-Authenticate",
    `Bearer realm="mcp-security-gateway", error="invalid_token", error_description="${escapedDesc}"`
  );
  res.status(401).json({
    error: "unauthorized",
    code,
    message,
  });
}

export function createAuthMiddleware(auditLogger?: AuditLogger): RequestHandler {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const startedAt = Date.now();
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      if (auditLogger) {
        void auditLogger
          .log({
            traceId: crypto.randomUUID(),
            userId: "anonymous",
            roles: [],
            tool: "mcp.auth",
            decision: "auth_failed",
            reasonCode: "missing_token",
            latencyMs: Date.now() - startedAt,
          })
          .catch(() => { });
      }
      sendUnauthorized(
        res,
        "missing_token",
        "Authorization header with Bearer JWT is required"
      );
      return;
    }

    const token = authHeader.slice("Bearer ".length).trim();
    verifyJwtToken(token)
      .then((identity) => {
        req.identity = identity;
        req.authInfo = toAuthInfo(token, identity);
        next();
      })
      .catch((err) => {
        const code = err instanceof AuthError ? err.code : "invalid_token";
        const message =
          err instanceof AuthError ? err.message : "Authentication failed";
        if (auditLogger) {
          void auditLogger
            .log({
              traceId: crypto.randomUUID(),
              userId: "anonymous",
              roles: [],
              tool: "mcp.auth",
              decision: "auth_failed",
              reasonCode: code,
              latencyMs: Date.now() - startedAt,
            })
            .catch(() => { });
        }
        sendUnauthorized(res, code, message);
      });
  };
}

export const requireJwtAuth = createAuthMiddleware();
