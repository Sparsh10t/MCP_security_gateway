import "dotenv/config";
import * as z from "zod/v4";

const envSchema = z.object({
  PORT: z.coerce.number().int().positive().default(5000),
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  UPSTREAM_CONFIG_PATH: z.string().default("./config/upstreams.yaml"),
  UPSTREAM_CALL_TIMEOUT_MS: z.coerce.number().int().positive().default(15000),
  POLICY_PATH: z.string().default("./policies/policy.yaml"),
  GEMINI_API_KEY: z.string().optional(),
  GEMINI_MODEL: z.string().default("gemini-3.6-flash"),
  GEMINI_TIMEOUT_MS: z.coerce.number().int().min(10000).default(15000),
  AUDIT_LOG_PATH: z.string().default("./data/audit-events.jsonl"),
  AUDIT_FAIL_CLOSED: z
    .string()
    .optional()
    .transform((v) => v !== "false"),
  JWT_SECRET: z
    .string()
    .min(16)
    .default("dev-only-mcp-sentinel-secret-change-me"),
  JWT_ISSUER: z.string().default("mcp-sentinel-dev"),
  JWT_AUDIENCE: z.string().default("mcp-security-gateway"),
  DATABASE_URL: z
    .string()
    .default("postgresql://mcp:mcp_secret@localhost:5432/mcp_gateway"),
  REQUIRE_INFRA: z
    .string()
    .optional()
    .transform((v) => v === "true"),
});

export const env = envSchema.parse(process.env);
