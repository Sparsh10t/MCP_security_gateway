# MCP Sentinel — Enterprise RBAC MCP Gateway & Audit Server

A reverse-proxy security gateway for Model Context Protocol (MCP) tool traffic built with **TypeScript, Express 5, `@modelcontextprotocol/server`, PostgreSQL, and React + Tailwind**.

## Implemented Capabilities
- **Streamable HTTP MCP Proxy (`/mcp`)**: Connects to multiple upstream MCP servers (`stdio` or `http`), namespaces tools (`<server>.<tool>`), and proxies `tools/list` and `tools/call`.
- **JWT Authentication**: Validates Bearer JWTs (`exp`, `iss`, `aud`, `sub`) and maps user identity & roles.
- **Deny-by-Default RBAC Policy Engine (`backend/policies/policy.yaml`)**: Role inheritance, least-privilege `tools/list` filtering, and argument constraints (`in`, `not_in`, `equals`, `matches`, `min`, `max`, `min_length`, `max_length`).
- **Request & Response Protection**:
  - Argument secret scanning (`inspectToolArguments`)
  - Regex PII masking (email, phone, SSN, Aadhaar, credit cards)
  - Regex secret redaction/blocking (AWS keys, GitHub tokens, `sk-` keys, PEM private keys, Bearer tokens)
  - Pattern-based prompt-injection heuristics (`flag`, `redact`, `block` per tool)
- **In-Memory Rate Limiting**: Per-identity and per-tool token bucket limits.
- **Tamper-Evident Audit Logging**: SHA-256 hash-chained audit events (`PostgresAuditStore` with `FileAuditStore` fallback), search/export API (`/api/audit`, `/api/audit/verify`, `/api/audit/export`), and CLI verifier (`npm run audit:verify`).
- **Admin Dashboard (`dashboard/`)**: Live decision feed, filters, hash-chain verification, policy viewer, and upstream status.

> **Security Note**: Pattern-based prompt-injection, PII, and secret detection are risk-reduction controls and can be bypassed. Primary enforcement relies on defense in depth: deny-by-default RBAC, argument constraints, rate limits, and tamper-evident audit logging.

## Quick Start

### 1. Start PostgreSQL & Redis (optional — gateway falls back to local JSONL audit if offline)
```powershell
docker compose up -d postgres redis
```

### 2. Start the Backend Gateway
```powershell
cd backend
npm install
npm run dev
```

### 3. Run the Attack & Governance Demo
In another terminal:
```powershell
cd backend
npm run demo:attack
```

### 4. Start the Admin Dashboard
```powershell
cd dashboard
npm install
npm run dev
```
Mint a dev JWT to sign in to the dashboard:
```powershell
cd backend
npm run auth:token -- --user carol --role admin-agent
```

## Testing & Verification
```powershell
cd backend
npm run typecheck
npm test
npm run audit:verify
```

## Documentation
- [Architecture](docs/architecture.md)
- [STRIDE Threat Model](docs/threat-model.md)
- [Operations Runbook](docs/runbook.md)
