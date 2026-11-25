import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import jwt, { type SignOptions } from "jsonwebtoken";
import { env } from "../config/env.js";

export interface DevTokenOptions {
  userId: string;
  roles: string[];
  tenant?: string;
  scopes?: string[];
  expiresIn?: SignOptions["expiresIn"];
}

export function signDevToken(options: DevTokenOptions): string {
  const payload = {
    roles: options.roles,
    tenant: options.tenant ?? "default",
    scope: (options.scopes ?? ["mcp:tools"]).join(" "),
  };

  return jwt.sign(payload, env.JWT_SECRET, {
    algorithm: "HS256",
    subject: options.userId,
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE,
    jwtid: crypto.randomUUID(),
    expiresIn: options.expiresIn ?? "1h",
  });
}

function parseCliArgs(argv: string[]): DevTokenOptions {
  let userId = "alice";
  const roles: string[] = [];
  let tenant = "default";
  let expiresIn: SignOptions["expiresIn"] = "1h";

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];
    if ((arg === "--user" || arg === "-u") && next) {
      userId = next;
      i++;
    } else if ((arg === "--role" || arg === "-r") && next) {
      for (const r of next.split(",")) {
        if (r.trim()) roles.push(r.trim());
      }
      i++;
    } else if ((arg === "--tenant" || arg === "-t") && next) {
      tenant = next;
      i++;
    } else if ((arg === "--expires-in" || arg === "-e") && next) {
      expiresIn = next as NonNullable<SignOptions["expiresIn"]>;
      i++;
    }
  }

  return {
    userId,
    roles: roles.length > 0 ? roles : ["support-agent"],
    tenant,
    expiresIn,
  };
}

const isEntrypoint =
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isEntrypoint) {
  const opts = parseCliArgs(process.argv.slice(2));
  const token = signDevToken(opts);
  console.log(token);
}
