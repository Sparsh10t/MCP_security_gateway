# Threat Model (STRIDE) — MCP Security Gateway

This document captures the STRIDE threat model for **MCP Sentinel** (Enterprise RBAC MCP Gateway & Audit Server).

## Scope & Trust Boundaries
- **Untrusted / Semi-trusted**: AI clients (Claude Desktop, IDE agents, custom agents) and external/internal tool outputs (e.g., Jira ticket descriptions).
- **Trusted Control Plane**: MCP Security Gateway (`backend/`), YAML policy file, PostgreSQL audit ledger.
- **Private Upstream Zone**: Upstream MCP servers (`demo`, `jira`, etc.) reachable only through the gateway.

## STRIDE Analysis

| Threat | Category | Mitigation in Design |
| --- | --- | --- |
| Stolen or forged JWT | Spoofing | Signature verification (`HS256` / `RS256`), required `exp`, `iss`, `aud`, and `sub` checks; `401` with `WWW-Authenticate` challenge; `auth_failed` logged to audit trail. |
| Client bypasses gateway to call upstream directly | Elevation of Privilege | Upstream stdio/HTTP servers run behind the gateway on a private network; clients only receive the `/mcp` gateway URL. |
| Tool name confusion / namespace collision | Spoofing | Mandatory `<upstream>.<tool>` namespacing; duplicate upstream names and duplicate tool names are rejected at startup. |
| Prompt injection via tool responses | Tampering | Pattern-based injection heuristics (`injection.v1`) with per-tool `flag`, `redact`, or `block` actions; strict role scoping limits blast radius. |
| Argument-based secret exfiltration | Information Disclosure | `inspectToolArguments` scans outbound arguments for AWS keys, GitHub tokens, `sk-` keys, private keys, and Bearer tokens before forwarding. |
| PII or secret leakage in tool responses | Information Disclosure | `pii.v1` masks emails, phones, SSN/Aadhaar, and card numbers; `secrets.v1` redacts or blocks API keys and private keys before returning to the LLM. |
| Audit log tampering or deletion | Repudiation / Tampering | Append-only audit events chained via `hash = SHA-256(prev_hash \|\| canonical_json(event))`; verified via `npm run audit:verify` and `GET /api/audit/verify`. |
| Runaway / looping agent | Denial of Service | In-memory per-`(userId, tool)` token bucket rate limiter (`RATE_LIMITED` with retry-after hint) and upstream call timeout (`UPSTREAM_CALL_TIMEOUT_MS`). |
| Policy misconfiguration | Elevation of Privilege | `defaults.effect: deny`, Zod schema validation on startup, circular inheritance detection, and fail-closed evaluation on policy errors. |
| PII/secrets stored in audit logs | Information Disclosure | `redactAndHashArgs` stores redacted arguments alongside the SHA-256 hash of original arguments. |

## Honest Limitations
- Pattern-based prompt-injection, PII, and secret detection are **bypassable** by obfuscation or novel phrasing.
- The primary security guarantee is **defense in depth**: deny-by-default RBAC, strict argument constraints, rate limiting, and a tamper-evident audit trail.
