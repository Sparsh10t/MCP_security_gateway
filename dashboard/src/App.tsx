import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Download,
  FileCode2,
  KeyRound,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

interface AuditFinding {
  detector: string;
  analyzer?: string;
  category: string;
  severity: string;
  action: string;
  detail?: string;
  analysisStatus?: string;
  injectionDetected?: boolean | null;
  riskLevel?: string;
  confidence?: number;
  reason?: string;
  evidence?: string[];
  recommendedAction?: string;
}

interface AuditEvent {
  id: string;
  ts: string;
  traceId: string;
  userId: string;
  roles: string[];
  tool: string;
  argsRedacted: Record<string, unknown>;
  argsHash: string;
  decision: string;
  reasonCode: string;
  findings: AuditFinding[];
  latencyMs: number;
  prevHash: string;
  hash: string;
}

interface AuditStats {
  totalEvents: number;
  totalFindings: number;
  byDecision: Record<string, number>;
  byTool: Record<string, number>;
}

interface HealthResponse {
  status: string;
  infra: { postgres: string };
  upstreams: { total: number; connected: number; tools: number };
}

interface UpstreamInfo {
  name: string;
  transport: string;
  riskTier: string;
  enabled: boolean;
  connected: boolean;
  toolCount: number;
  tools: string[];
  error?: string;
}

interface PolicySummary {
  version: string;
  sha256: string;
  defaults: { effect: string };
  roles: string[];
  roleDetails?: Array<{
    name: string;
    allow: Array<{ tool: string; constraints?: Record<string, unknown>; rate?: { per_minute?: number } }>;
    requireApproval: string[];
  }>;
  responseFilters?: Record<string, Record<string, string>>;
}

interface VerifyResponse {
  valid: boolean;
  totalEvents: number;
  headHash: string;
  firstInvalid?: { index: number; id: string; reason: string };
}

type TabKey = "audit" | "policy" | "upstreams";

const DECISION_BADGE: Record<string, string> = {
  allow: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  allow_redacted: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  deny: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  blocked: "bg-rose-600/20 text-rose-200 border-rose-500/40",
  rate_limited: "bg-orange-500/15 text-orange-300 border-orange-500/30",
  auth_failed: "bg-red-500/15 text-red-300 border-red-500/30",
  require_approval: "bg-purple-500/15 text-purple-300 border-purple-500/30",
  upstream_error: "bg-slate-500/20 text-slate-300 border-slate-500/30",
};

export default function App() {
  const [token, setToken] = useState<string>(
    () => localStorage.getItem("mcp_gateway_jwt") ?? ""
  );
  const [tokenInput, setTokenInput] = useState(token);
  const [tab, setTab] = useState<TabKey>("audit");
  const [autoRefresh, setAutoRefresh] = useState(true);

  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [policy, setPolicy] = useState<PolicySummary | null>(null);
  const [upstreams, setUpstreams] = useState<UpstreamInfo[]>([]);
  const [verification, setVerification] = useState<VerifyResponse | null>(null);
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);

  const [decisionFilter, setDecisionFilter] = useState("");
  const [toolFilter, setToolFilter] = useState("");
  const [userFilter, setUserFilter] = useState("");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const authHeaders = useMemo<Record<string, string>>(() => {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    return headers;
  }, [token]);

  const fetchPublic = useCallback(async () => {
    try {
      const [hRes, uRes] = await Promise.all([
        fetch("/health"),
        fetch("/api/upstreams"),
      ]);
      if (hRes.ok) setHealth((await hRes.json()) as HealthResponse);
      if (uRes.ok) {
        const uData = (await uRes.json()) as { upstreams: UpstreamInfo[] };
        setUpstreams(uData.upstreams);
      }
    } catch {
      // Gateway might be starting
    }
  }, []);

  const fetchProtected = useCallback(async () => {
    if (!token) return;
    setErrorMsg(null);
    const params = new URLSearchParams({ limit: "100" });
    if (decisionFilter) params.set("decision", decisionFilter);
    if (toolFilter) params.set("tool", toolFilter);
    if (userFilter) params.set("userId", userFilter);

    try {
      const [auditRes, statsRes, policyRes] = await Promise.all([
        fetch(`/api/audit?${params.toString()}`, { headers: authHeaders }),
        fetch("/api/audit/stats", { headers: authHeaders }),
        fetch("/api/policy", { headers: authHeaders }),
      ]);

      if (auditRes.status === 401) {
        setErrorMsg("JWT rejected (401). Generate a valid token with `npm run auth:token`.");
        return;
      }

      if (auditRes.ok) {
        const data = (await auditRes.json()) as { events: AuditEvent[] };
        setEvents(data.events);
      }
      if (statsRes.ok) setStats((await statsRes.json()) as AuditStats);
      if (policyRes.ok) setPolicy((await policyRes.json()) as PolicySummary);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to reach gateway");
    }
  }, [token, authHeaders, decisionFilter, toolFilter, userFilter]);

  useEffect(() => {
    void fetchPublic();
    void fetchProtected();
  }, [fetchPublic, fetchProtected]);

  useEffect(() => {
    if (!autoRefresh || !token) return;
    const id = setInterval(() => {
      void fetchPublic();
      void fetchProtected();
    }, 5000);
    return () => clearInterval(id);
  }, [autoRefresh, token, fetchPublic, fetchProtected]);

  const handleSaveToken = () => {
    const trimmed = tokenInput.trim();
    localStorage.setItem("mcp_gateway_jwt", trimmed);
    setToken(trimmed);
  };

  const handleVerifyChain = async () => {
    if (!token) return;
    const res = await fetch("/api/audit/verify", { headers: authHeaders });
    const data = (await res.json()) as VerifyResponse;
    setVerification(data);
  };

  const handleExport = async (format: "csv" | "json") => {
    if (!token) return;
    const res = await fetch(`/api/audit/export?format=${format}`, {
      headers: authHeaders,
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `audit-events.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const blockedCount =
    (stats?.byDecision["deny"] ?? 0) +
    (stats?.byDecision["blocked"] ?? 0) +
    (stats?.byDecision["rate_limited"] ?? 0) +
    (stats?.byDecision["auth_failed"] ?? 0);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-900/70 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/15 text-emerald-400">
              <Shield className="h-6 w-6" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight">MCP Sentinel</h1>
              <p className="text-xs text-slate-400">
                Enterprise RBAC MCP Gateway & Audit Console
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 text-xs">
            <span className="rounded-full border border-slate-700 bg-slate-800 px-3 py-1">
              Upstreams: {health?.upstreams.connected ?? 0}/{health?.upstreams.total ?? 0}
            </span>
            <span className="rounded-full border border-slate-700 bg-slate-800 px-3 py-1">
              Tools: {health?.upstreams.tools ?? 0}
            </span>
            <span
              className={`rounded-full border px-3 py-1 ${health?.infra.postgres === "connected"
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
                : "border-amber-500/40 bg-amber-500/10 text-amber-300"
                }`}
            >
              Postgres: {health?.infra.postgres ?? "unknown"}
            </span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        {/* Auth Bar */}
        <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex flex-wrap items-center gap-3">
            <KeyRound className="h-4 w-4 text-slate-400" />
            <input
              type="password"
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              placeholder="Paste Bearer JWT (run: npm run auth:token -- --user carol --role admin-agent)"
              className="min-w-[280px] flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-emerald-500 focus:outline-none"
            />
            <button
              onClick={handleSaveToken}
              className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500"
            >
              Connect
            </button>
            <button
              onClick={() => void fetchProtected()}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm hover:bg-slate-700"
            >
              <RefreshCw className="h-4 w-4" /> Refresh
            </button>
            <label className="flex items-center gap-2 text-xs text-slate-400">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="accent-emerald-500"
              />
              Auto-refresh (5s)
            </label>
          </div>
          {errorMsg && (
            <p className="mt-2 text-xs text-rose-400">{errorMsg}</p>
          )}
        </section>

        {/* KPI Cards */}
        <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Total Audit Events</span>
              <Activity className="h-4 w-4 text-sky-400" />
            </div>
            <p className="mt-2 text-2xl font-bold">{stats?.totalEvents ?? 0}</p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Allowed Calls</span>
              <CheckCircle2 className="h-4 w-4 text-emerald-400" />
            </div>
            <p className="mt-2 text-2xl font-bold text-emerald-400">
              {(stats?.byDecision["allow"] ?? 0) +
                (stats?.byDecision["allow_redacted"] ?? 0)}
            </p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Blocked / Denied</span>
              <ShieldAlert className="h-4 w-4 text-rose-400" />
            </div>
            <p className="mt-2 text-2xl font-bold text-rose-400">{blockedCount}</p>
          </div>
          <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Security Findings</span>
              <AlertTriangle className="h-4 w-4 text-amber-400" />
            </div>
            <p className="mt-2 text-2xl font-bold text-amber-400">
              {stats?.totalFindings ?? 0}
            </p>
          </div>
        </section>

        {/* Navigation Tabs */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex gap-2">
            {(
              [
                ["audit", "Live Decision Feed"],
                ["policy", "Policy Viewer"],
                ["upstreams", "Upstreams & Tools"],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                onClick={() => setTab(key)}
                className={`rounded-lg px-4 py-2 text-sm font-medium transition ${tab === key
                  ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                  : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                  }`}
              >
                {label}
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => void handleVerifyChain()}
              disabled={!token}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium hover:bg-slate-700 disabled:opacity-40"
            >
              <ShieldCheck className="h-4 w-4 text-emerald-400" /> Verify Hash Chain
            </button>
            <button
              onClick={() => void handleExport("csv")}
              disabled={!token}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium hover:bg-slate-700 disabled:opacity-40"
            >
              <Download className="h-4 w-4" /> CSV
            </button>
            <button
              onClick={() => void handleExport("json")}
              disabled={!token}
              className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium hover:bg-slate-700 disabled:opacity-40"
            >
              <Download className="h-4 w-4" /> JSON
            </button>
          </div>
        </div>

        {verification && (
          <div
            className={`rounded-xl border p-4 text-sm ${verification.valid
              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
              : "border-rose-500/40 bg-rose-500/10 text-rose-200"
              }`}
          >
            {verification.valid ? (
              <span>
                Hash chain <strong>VALID</strong> ({verification.totalEvents} events,
                headHash: <code className="text-xs">{verification.headHash}</code>)
              </span>
            ) : (
              <span>
                <strong>TAMPER DETECTED</strong> at index{" "}
                {verification.firstInvalid?.index}: {verification.firstInvalid?.reason}
              </span>
            )}
          </div>
        )}

        {/* Tab 1: Audit Feed */}
        {tab === "audit" && (
          <section className="space-y-4">
            <div className="flex flex-wrap gap-3">
              <input
                value={userFilter}
                onChange={(e) => setUserFilter(e.target.value)}
                placeholder="Filter userId..."
                className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm"
              />
              <input
                value={toolFilter}
                onChange={(e) => setToolFilter(e.target.value)}
                placeholder="Filter tool (e.g. jira.get_issue)..."
                className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm"
              />
              <select
                value={decisionFilter}
                onChange={(e) => setDecisionFilter(e.target.value)}
                className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm"
              >
                <option value="">All decisions</option>
                <option value="allow">allow</option>
                <option value="allow_redacted">allow_redacted</option>
                <option value="deny">deny</option>
                <option value="blocked">blocked</option>
                <option value="rate_limited">rate_limited</option>
                <option value="auth_failed">auth_failed</option>
              </select>
            </div>

            <div className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900/50">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-slate-800 bg-slate-900 text-xs uppercase text-slate-400">
                  <tr>
                    <th className="px-4 py-3">Time</th>
                    <th className="px-4 py-3">User / Roles</th>
                    <th className="px-4 py-3">Tool</th>
                    <th className="px-4 py-3">Decision</th>
                    <th className="px-4 py-3">Reason</th>
                    <th className="px-4 py-3">Findings</th>
                    <th className="px-4 py-3">Latency</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {events.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                        {token
                          ? "No audit events match your filter."
                          : "Connect with a JWT above to view audit events."}
                      </td>
                    </tr>
                  ) : (
                    events.map((ev) => {
                      const isExpanded = expandedEventId === ev.id;
                      return (
                        <Fragment key={ev.id}>
                          <tr
                            onClick={() =>
                              setExpandedEventId((prev) =>
                                prev === ev.id ? null : ev.id
                              )
                            }
                            className={`cursor-pointer transition ${isExpanded
                              ? "bg-slate-800/70"
                              : "hover:bg-slate-800/50"
                              }`}
                          >
                            <td className="whitespace-nowrap px-4 py-2.5 text-xs text-slate-400">
                              <span className="mr-2 inline-block text-[10px] text-slate-500">
                                {isExpanded ? "▼" : "▶"}
                              </span>
                              {new Date(ev.ts).toLocaleTimeString()}
                            </td>
                            <td className="px-4 py-2.5">
                              <span className="font-medium">{ev.userId}</span>
                              <span className="ml-2 text-xs text-slate-400">
                                {ev.roles.join(", ")}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 font-mono text-xs text-sky-300">
                              {ev.tool}
                            </td>
                            <td className="px-4 py-2.5">
                              <span
                                className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${DECISION_BADGE[ev.decision] ??
                                  "bg-slate-700 text-slate-200 border-slate-600"
                                  }`}
                              >
                                {ev.decision}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-xs text-slate-300">
                              {ev.reasonCode}
                            </td>
                            <td className="px-4 py-2.5 text-xs text-amber-300">
                              <div className="flex items-center gap-1.5">
                                <span>
                                  {ev.findings.length > 0 ? ev.findings.length : "-"}
                                </span>
                                {ev.findings.some((f) => f.analyzer === "gemini") && (
                                  <span className="rounded bg-indigo-500/20 px-1.5 py-0.5 text-[10px] text-indigo-300 border border-indigo-500/30">
                                    Gemini
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="px-4 py-2.5 text-xs text-slate-400">
                              {ev.latencyMs}ms
                            </td>
                          </tr>
                          {isExpanded && (
                            <tr className="bg-slate-900/90">
                              <td colSpan={7} className="px-4 py-4 text-xs">
                                <div className="rounded-xl border border-slate-700 bg-slate-900 p-4">
                                  <div className="mb-2 flex items-center justify-between">
                                    <strong className="text-sm">
                                      Event Detail ({ev.id})
                                    </strong>
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        setExpandedEventId(null);
                                      }}
                                      className="rounded border border-slate-700 px-2 py-0.5 text-slate-400 hover:bg-slate-800 hover:text-white"
                                    >
                                      Hide
                                    </button>
                                  </div>
                                  {ev.findings.length > 0 && (
                                    <div className="mb-3 space-y-2">
                                      <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                                        Findings &amp; Gemini Analysis
                                      </div>
                                      {ev.findings.map((f, idx) => (
                                        <div
                                          key={`${f.detector}-${idx}`}
                                          className="space-y-1 rounded-lg border border-slate-800 bg-slate-950 p-3"
                                        >
                                          <div className="flex flex-wrap items-center gap-2">
                                            <span className="font-mono font-semibold text-indigo-300">
                                              {f.analyzer ?? f.detector}
                                            </span>
                                            <span className="rounded bg-slate-800 px-2 py-0.5 text-[11px] text-slate-300">
                                              action: {f.action}
                                            </span>
                                            {f.analysisStatus && (
                                              <span className="rounded bg-slate-800 px-2 py-0.5 text-[11px] text-sky-300">
                                                status: {f.analysisStatus}
                                              </span>
                                            )}
                                            {f.riskLevel && (
                                              <span className="rounded bg-amber-500/15 px-2 py-0.5 text-[11px] text-amber-300">
                                                risk: {f.riskLevel}
                                              </span>
                                            )}
                                            {typeof f.confidence === "number" && (
                                              <span className="text-[11px] text-slate-400">
                                                confidence: {(f.confidence * 100).toFixed(0)}%
                                              </span>
                                            )}
                                            {f.recommendedAction && (
                                              <span className="text-[11px] text-emerald-300">
                                                recommended: {f.recommendedAction}
                                              </span>
                                            )}
                                          </div>
                                          {f.reason && (
                                            <p className="text-slate-300">
                                              Reason: {f.reason}
                                            </p>
                                          )}
                                          {f.evidence && f.evidence.length > 0 && (
                                            <p className="text-rose-300">
                                              Evidence: {f.evidence.join(" | ")}
                                            </p>
                                          )}
                                        </div>
                                      ))}
                                    </div>
                                  )}
                                  <pre className="overflow-x-auto rounded bg-slate-950 p-3 text-slate-300">
                                    {JSON.stringify(ev, null, 2)}
                                  </pre>
                                </div>
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* Tab 2: Policy Viewer */}
        {tab === "policy" && (
          <section className="space-y-4">
            {!policy ? (
              <p className="text-sm text-slate-400">
                Connect with a JWT to inspect the active RBAC policy.
              </p>
            ) : (
              <>
                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 text-sm">
                  <div className="flex flex-wrap gap-6">
                    <div>
                      <span className="text-slate-400">Version:</span>{" "}
                      <strong>v{policy.version}</strong>
                    </div>
                    <div>
                      <span className="text-slate-400">Default Effect:</span>{" "}
                      <strong className="text-rose-400">{policy.defaults.effect}</strong>
                    </div>
                    <div>
                      <span className="text-slate-400">SHA-256:</span>{" "}
                      <code className="text-xs text-emerald-300">{policy.sha256}</code>
                    </div>
                  </div>
                </div>

                <div className="grid gap-4 md:grid-cols-2">
                  {policy.roleDetails?.map((role) => (
                    <div
                      key={role.name}
                      className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"
                    >
                      <div className="mb-3 flex items-center gap-2">
                        <FileCode2 className="h-4 w-4 text-emerald-400" />
                        <h3 className="font-semibold">{role.name}</h3>
                      </div>
                      <ul className="space-y-2 text-xs">
                        {role.allow.map((rule, i) => (
                          <li
                            key={`${role.name}-${rule.tool}-${i}`}
                            className="rounded-lg border border-slate-800 bg-slate-950 p-2.5"
                          >
                            <div className="font-mono text-sky-300">{rule.tool}</div>
                            {rule.constraints && (
                              <div className="mt-1 text-slate-400">
                                constraints: {JSON.stringify(rule.constraints)}
                              </div>
                            )}
                            {rule.rate?.per_minute && (
                              <div className="mt-1 text-amber-300">
                                rate: {rule.rate.per_minute}/min
                              </div>
                            )}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </>
            )}
          </section>
        )}

        {/* Tab 3: Upstreams */}
        {tab === "upstreams" && (
          <section className="grid gap-4 md:grid-cols-2">
            {upstreams.map((u) => (
              <div
                key={u.name}
                className="rounded-xl border border-slate-800 bg-slate-900/60 p-4"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Server className="h-4 w-4 text-sky-400" />
                    <h3 className="font-semibold">{u.name}</h3>
                  </div>
                  <span
                    className={`rounded-full px-2.5 py-0.5 text-xs ${u.connected
                      ? "bg-emerald-500/15 text-emerald-300"
                      : "bg-rose-500/15 text-rose-300"
                      }`}
                  >
                    {u.connected ? "connected" : "disconnected"}
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-400">
                  transport: {u.transport} | risk tier: {u.riskTier}
                </p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {u.tools.map((t) => (
                    <span
                      key={t}
                      className="rounded border border-slate-700 bg-slate-950 px-2 py-0.5 font-mono text-xs text-slate-300"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </section>
        )}
      </main>
    </div>
  );
}
