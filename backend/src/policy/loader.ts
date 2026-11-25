import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { load as loadYaml } from "js-yaml";
import * as z from "zod/v4";
import type {
  AllowRule,
  LoadedPolicy,
  PolicyDocument,
  ResolvedRole,
} from "./types.js";

const primitiveSchema = z.union([z.string(), z.number(), z.boolean()]);

const argumentConstraintSchema = z.object({
  in: z.array(primitiveSchema).optional(),
  not_in: z.array(primitiveSchema).optional(),
  equals: primitiveSchema.optional(),
  matches: z
    .string()
    .refine((pattern) => {
      try {
        new RegExp(pattern);
        return true;
      } catch {
        return false;
      }
    }, "Invalid regex pattern in constraint")
    .optional(),
  min: z.number().optional(),
  max: z.number().optional(),
  min_length: z.number().int().nonnegative().optional(),
  max_length: z.number().int().nonnegative().optional(),
  optional: z.boolean().optional(),
});

const allowRuleSchema = z.object({
  tool: z.string().min(1),
  constraints: z.record(z.string(), argumentConstraintSchema).optional(),
  rate: z
    .object({
      per_minute: z.number().int().positive().optional(),
    })
    .optional(),
});

const roleDefinitionSchema = z.object({
  inherits: z.array(z.string().min(1)).optional(),
  allow: z.array(allowRuleSchema).optional(),
  require_approval: z
    .array(
      z.union([
        z.object({ tool: z.string().min(1) }),
        z.string().min(1).transform((tool) => ({ tool })),
      ])
    )
    .optional(),
});

const responseFilterRuleSchema = z.object({
  pii: z.enum(["off", "flag", "mask"]).optional(),
  secrets: z.enum(["off", "flag", "redact", "block"]).optional(),
  injection: z.enum(["off", "flag", "redact", "block"]).optional(),
});

const policyDocumentSchema = z.object({
  version: z.union([z.number(), z.string()]),
  defaults: z
    .object({
      effect: z.enum(["deny", "allow"]).default("deny"),
    })
    .default({ effect: "deny" }),
  roles: z.record(z.string(), roleDefinitionSchema),
  response_filters: z.record(z.string(), responseFilterRuleSchema).optional(),
});

function resolveRole(
  roleName: string,
  roles: PolicyDocument["roles"],
  visiting: Set<string>,
  resolvedCache: Map<string, ResolvedRole>
): ResolvedRole {
  const cached = resolvedCache.get(roleName);
  if (cached) return cached;

  if (visiting.has(roleName)) {
    throw new Error(`Circular role inheritance detected involving "${roleName}"`);
  }

  const def = roles[roleName];
  if (!def) {
    throw new Error(`Referenced role "${roleName}" does not exist in policy`);
  }

  visiting.add(roleName);

  const allow: AllowRule[] = [];
  const requireApproval: string[] = [];

  for (const parentName of def.inherits ?? []) {
    const parentResolved = resolveRole(
      parentName,
      roles,
      visiting,
      resolvedCache
    );
    allow.push(...parentResolved.allow);
    requireApproval.push(...parentResolved.requireApproval);
  }

  for (const rule of def.allow ?? []) {
    allow.push(rule);
  }

  for (const item of def.require_approval ?? []) {
    requireApproval.push(item.tool);
  }

  visiting.delete(roleName);

  const resolved: ResolvedRole = {
    name: roleName,
    allow,
    requireApproval: Array.from(new Set(requireApproval)),
  };
  resolvedCache.set(roleName, resolved);
  return resolved;
}

export function parsePolicyYaml(
  yamlContent: string,
  source = "inline"
): LoadedPolicy {
  const raw = loadYaml(yamlContent);
  const document = policyDocumentSchema.parse(raw) as PolicyDocument;
  const sha256 = crypto
    .createHash("sha256")
    .update(yamlContent, "utf-8")
    .digest("hex");

  const resolvedRoles = new Map<string, ResolvedRole>();
  const visiting = new Set<string>();

  for (const roleName of Object.keys(document.roles)) {
    resolveRole(roleName, document.roles, visiting, resolvedRoles);
  }

  return {
    document,
    resolvedRoles,
    sha256,
    source,
  };
}

export async function loadPolicyFile(
  policyPath: string
): Promise<LoadedPolicy> {
  const resolvedPath = path.resolve(process.cwd(), policyPath);
  const content = await fs.readFile(resolvedPath, "utf-8");
  return parsePolicyYaml(content, resolvedPath);
}
