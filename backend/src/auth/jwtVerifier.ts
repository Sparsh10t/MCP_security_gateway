import jwt, { type JwtPayload } from "jsonwebtoken";
import { env } from "../config/env.js";
import type { Identity } from "./identity.js";

export type AuthErrorCode = "missing_token" | "invalid_token" | "expired_token";

export class AuthError extends Error {
  readonly code: AuthErrorCode;

  constructor(code: AuthErrorCode, message: string) {
    super(message);
    this.name = "AuthError";
    this.code = code;
  }
}

function extractRoles(claims: JwtPayload): string[] {
  const roles = new Set<string>();
  const rawRoles = claims["roles"];
  if (Array.isArray(rawRoles)) {
    for (const r of rawRoles) {
      if (typeof r === "string" && r.trim()) roles.add(r.trim());
    }
  }
  const singleRole = claims["role"];
  if (typeof singleRole === "string" && singleRole.trim()) {
    roles.add(singleRole.trim());
  }
  return Array.from(roles);
}

function extractScopes(claims: JwtPayload): string[] {
  const scopes = new Set<string>();
  if (typeof claims["scope"] === "string") {
    for (const s of claims["scope"].split(/\s+/)) {
      if (s) scopes.add(s);
    }
  }
  if (Array.isArray(claims["scp"])) {
    for (const s of claims["scp"]) {
      if (typeof s === "string" && s) scopes.add(s);
    }
  }
  return Array.from(scopes);
}

export async function verifyJwtToken(token: string): Promise<Identity> {
  if (!token || !token.trim()) {
    throw new AuthError("missing_token", "Missing bearer token");
  }

  let claims: JwtPayload;
  try {
    const verified = jwt.verify(token, env.JWT_SECRET, {
      algorithms: ["HS256", "HS384", "HS512"],
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
    });
    if (typeof verified === "string") {
      throw new AuthError("invalid_token", "JWT payload must be a JSON object");
    }
    claims = verified;
  } catch (err) {
    if (err instanceof AuthError) throw err;
    if (err instanceof jwt.TokenExpiredError) {
      throw new AuthError("expired_token", "JWT has expired");
    }
    const message = err instanceof Error ? err.message : "JWT verification failed";
    throw new AuthError("invalid_token", message);
  }

  if (typeof claims.sub !== "string" || !claims.sub.trim()) {
    throw new AuthError("invalid_token", "JWT missing required 'sub' claim");
  }
  if (typeof claims.exp !== "number") {
    throw new AuthError("invalid_token", "JWT missing required 'exp' claim");
  }

  return {
    userId: claims.sub,
    roles: extractRoles(claims),
    tenant: typeof claims["tenant"] === "string" ? claims["tenant"] : "default",
    scopes: extractScopes(claims),
    clientId: claims.sub,
    expiresAt: claims.exp,
    ...(typeof claims.jti === "string" ? { tokenId: claims.jti } : {}),
  };
}
