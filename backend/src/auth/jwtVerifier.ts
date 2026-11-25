import crypto from "node:crypto";
import jwt, { type JwtHeader, type JwtPayload } from "jsonwebtoken";
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

interface JwkCacheEntry {
  keysByKid: Map<string, crypto.KeyObject>;
  fetchedAtMs: number;
}

const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;
let jwksCache: JwkCacheEntry | null = null;

async function fetchJwksKey(kid?: string): Promise<crypto.KeyObject> {
  if (!env.JWT_JWKS_URI) {
    throw new AuthError("invalid_token", "JWKS URI is not configured");
  }

  const now = Date.now();
  if (!jwksCache || now - jwksCache.fetchedAtMs > JWKS_CACHE_TTL_MS) {
    const response = await fetch(env.JWT_JWKS_URI);
    if (!response.ok) {
      throw new AuthError(
        "invalid_token",
        `Failed to fetch JWKS (${response.status})`
      );
    }
    const body = (await response.json()) as {
      keys?: Array<crypto.webcrypto.JsonWebKey & { kid?: string }>;
    };
    const keysByKid = new Map<string, crypto.KeyObject>();
    for (const jwk of body.keys ?? []) {
      if (jwk.kid) {
        keysByKid.set(
          jwk.kid,
          crypto.createPublicKey({ key: jwk, format: "jwk" })
        );
      }
    }
    jwksCache = { keysByKid, fetchedAtMs: now };
  }

  if (kid) {
    const matched = jwksCache.keysByKid.get(kid);
    if (matched) return matched;
  }

  if (!kid && jwksCache.keysByKid.size === 1) {
    const first = jwksCache.keysByKid.values().next().value;
    if (first) return first;
  }

  throw new AuthError("invalid_token", "Signing key not found in JWKS");
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
  const realmAccess = claims["realm_access"] as
    | { roles?: unknown }
    | undefined;
  if (realmAccess && Array.isArray(realmAccess.roles)) {
    for (const r of realmAccess.roles) {
      if (typeof r === "string" && r.trim()) roles.add(r.trim());
    }
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

  const decodedComplete = jwt.decode(token, { complete: true });
  if (!decodedComplete || typeof decodedComplete === "string") {
    throw new AuthError("invalid_token", "Malformed JWT");
  }

  const header = decodedComplete.header as JwtHeader;
  let verifyKey: string | crypto.KeyObject = env.JWT_SECRET;
  let algorithms: jwt.Algorithm[] = ["HS256", "HS384", "HS512"];

  if (env.JWT_JWKS_URI && header.alg && !header.alg.startsWith("HS")) {
    verifyKey = await fetchJwksKey(header.kid);
    algorithms = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"];
  }

  let claims: JwtPayload;
  try {
    const verified = jwt.verify(token, verifyKey, {
      algorithms,
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

  const tenant =
    typeof claims["tenant"] === "string"
      ? claims["tenant"]
      : typeof claims["org_id"] === "string"
        ? claims["org_id"]
        : "default";

  const clientId =
    typeof claims["azp"] === "string"
      ? claims["azp"]
      : typeof claims["client_id"] === "string"
        ? claims["client_id"]
        : claims.sub;

  return {
    userId: claims.sub,
    roles: extractRoles(claims),
    tenant,
    scopes: extractScopes(claims),
    clientId,
    expiresAt: claims.exp,
    ...(typeof claims.jti === "string" ? { tokenId: claims.jti } : {}),
  };
}
