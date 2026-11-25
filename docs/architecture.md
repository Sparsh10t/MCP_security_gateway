# Architecture — MCP Security Gateway

## Request Lifecycle (`tools/call`)
1. **AuthN (`requireJwtAuth`)**: Validates Bearer JWT (`exp`, `iss`, `aud`, `sub`) and extracts `Identity` (`userId`, `roles`, `scopes`). Failures return HTTP `401` and log `auth_failed`.
2. **RBAC Policy Engine (`PolicyEngine`)**: Evaluates `defaults.effect: deny`, role inheritance, and argument constraints (`in`, `not_in`, `equals`, `matches`, `min`, `max`, `min_length`, `max_length`).
3. **Rate Limiter (`InMemoryRateLimiter`)**: Token bucket per `(userId, tool)` using rule-level `rate.per_minute` or the default limit.
4. **Request Inspector (`inspectToolArguments`)**: Scans outbound arguments for embedded secrets before calling upstream.
5. **Upstream Router (`UpstreamManager`)**: Routes `<upstream>.<tool>` to the target stdio or Streamable HTTP MCP server with `UPSTREAM_CALL_TIMEOUT_MS`.
6. **Response Filter Pipeline (`applyResponseFilters`)**: Runs `secrets.v1`, `pii.v1`, and `injection.v1` per `response_filters` policy (`off`, `flag`, `mask`, `redact`, `block`).
7. **Audit Logger (`AuditLogger`)**: Serializes every decision into a SHA-256 hash chain (`PostgresAuditStore` or `FileAuditStore` fallback).

## Excluded / Out-of-Scope Features (v1)
- Advanced / AI/ML-based prompt injection, PII, or secret detection
- Human-in-the-loop approval workflows, SIEM export, policy hot-reload
- Redis-based distributed rate limiting, HA/load balancing, Kubernetes deployment
- Multi-tenancy, SSO/OAuth/OIDC provider flows, Prometheus/Grafana
- Non-tool MCP capabilities (sampling, elicitation, resources, prompts)
