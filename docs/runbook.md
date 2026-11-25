# Operations Runbook — MCP Security Gateway

## 1. Starting Dependencies & Services
- **Local dev (recommended)**:
  ```powershell
  docker compose up -d postgres redis
  cd backend && npm run dev
  ```
- **Dashboard**:
  ```powershell
  cd dashboard && npm run dev
  ```

## 2. Verifying Audit Log Integrity
Run the CLI verifier (checks PostgreSQL `audit_events` if connected, otherwise `backend/data/audit-events.jsonl`):
```powershell
cd backend
npm run audit:verify
```
Or verify via HTTP API:
```powershell
$token = npm run auth:token -- --user carol --role admin-agent
Invoke-RestMethod http://localhost:5000/api/audit/verify -Headers @{ Authorization = "Bearer $token" }
```

## 3. Rotating `JWT_SECRET`
1. Update `JWT_SECRET` in `backend/.env` (or container environment).
2. Restart the gateway service.
3. Re-issue client tokens with `npm run auth:token`.

## 4. Policy Rollback
1. Revert `backend/policies/policy.yaml` via Git (`git checkout <commit> -- backend/policies/policy.yaml`).
2. Restart the gateway so the reverted policy is loaded and recorded in `policy_versions`.

## 5. Upstream Outage Handling
- Check `/health` and `/api/upstreams` to see which upstream server is disconnected.
- Calls to an unavailable upstream return JSON-RPC `-32603` (`UPSTREAM_UNAVAILABLE`) and are recorded in the audit log.
