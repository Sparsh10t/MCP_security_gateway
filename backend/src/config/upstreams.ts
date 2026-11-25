import fs from "node:fs/promises";
import path from "node:path";
import { load as loadYaml } from "js-yaml";
import * as z from "zod/v4";

const serverNameSchema = z
  .string()
  .regex(/^[a-z0-9_-]+$/, "Upstream name must match ^[a-z0-9_-]+$");

const riskTierSchema = z
  .enum(["low", "medium", "high", "critical"])
  .default("medium");

const stdioUpstreamSchema = z.object({
  name: serverNameSchema,
  transport: z.literal("stdio"),
  command: z.string().min(1),
  args: z.array(z.string()).default([]),
  cwd: z.string().optional(),
  env: z.record(z.string(), z.string()).optional(),
  riskTier: riskTierSchema,
  enabled: z.boolean().default(true),
});

const httpUpstreamSchema = z.object({
  name: serverNameSchema,
  transport: z.literal("http"),
  url: z.url(),
  headers: z.record(z.string(), z.string()).optional(),
  riskTier: riskTierSchema,
  enabled: z.boolean().default(true),
});

const upstreamConfigSchema = z.object({
  upstreams: z.array(z.discriminatedUnion("transport", [stdioUpstreamSchema, httpUpstreamSchema])),
});

export type UpstreamServerConfig = z.infer<
  typeof upstreamConfigSchema
>["upstreams"][number];

/**
 * Loads and validates upstream MCP server registrations from YAML.
 * Rejects duplicate server names to prevent tool namespace collisions.
 */
export async function loadUpstreamConfigs(
  configPath: string
): Promise<UpstreamServerConfig[]> {
  const resolvedPath = path.resolve(process.cwd(), configPath);
  const raw = await fs.readFile(resolvedPath, "utf-8");
  const parsed = upstreamConfigSchema.parse(loadYaml(raw));

  const seenNames = new Set<string>();
  for (const upstream of parsed.upstreams) {
    if (seenNames.has(upstream.name)) {
      throw new Error(
        `Duplicate upstream server name "${upstream.name}" in ${resolvedPath}`
      );
    }
    seenNames.add(upstream.name);
  }

  return parsed.upstreams;
}
