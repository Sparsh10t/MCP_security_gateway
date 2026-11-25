import type { AuthInfo } from "@modelcontextprotocol/server";

export interface Identity {
  userId: string;
  roles: string[];
  tenant: string;
  scopes: string[];
  clientId: string;
  expiresAt: number;
  tokenId?: string;
}

export function toAuthInfo(token: string, identity: Identity): AuthInfo {
  return {
    token,
    clientId: identity.clientId,
    scopes: identity.scopes,
    expiresAt: identity.expiresAt,
    extra: {
      identity,
    },
  };
}

export function identityFromAuthInfo(authInfo?: AuthInfo): Identity | null {
  const candidate = authInfo?.extra?.["identity"];
  if (!candidate || typeof candidate !== "object") {
    return null;
  }
  const id = candidate as Partial<Identity>;
  if (typeof id.userId !== "string" || !Array.isArray(id.roles)) {
    return null;
  }
  return {
    userId: id.userId,
    roles: id.roles.filter((r): r is string => typeof r === "string"),
    tenant: typeof id.tenant === "string" ? id.tenant : "default",
    scopes: Array.isArray(id.scopes)
      ? id.scopes.filter((s): s is string => typeof s === "string")
      : [],
    clientId: typeof id.clientId === "string" ? id.clientId : id.userId,
    expiresAt: typeof id.expiresAt === "number" ? id.expiresAt : 0,
    ...(typeof id.tokenId === "string" ? { tokenId: id.tokenId } : {}),
  };
}
