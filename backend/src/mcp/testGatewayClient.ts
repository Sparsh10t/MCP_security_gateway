import assert from "node:assert/strict";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { signDevToken } from "../auth/devToken.js";

const GATEWAY_URL = process.env.GATEWAY_URL ?? "http://localhost:5000/mcp";

async function connectAs(token: string): Promise<Client> {
  const client = new Client({
    name: "mcp-gateway-phase2-client",
    version: "1.0.0",
  });
  const transport = new StreamableHTTPClientTransport(new URL(GATEWAY_URL), {
    requestInit: {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    },
  });
  await client.connect(transport);
  return client;
}

async function main() {
  // 1. Unauthenticated request must return 401
  const unauthRes = await fetch(GATEWAY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(unauthRes.status, 401, "Expected 401 for missing JWT");
  console.log("1. Unauthenticated request rejected with HTTP 401");

  // 2. Tampered / invalid JWT must return 401
  const badRes = await fetch(GATEWAY_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer invalid.jwt.token",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(badRes.status, 401, "Expected 401 for malformed JWT");
  console.log("2. Invalid JWT rejected with HTTP 401");

  // 3. support-agent: least-privilege discovery + constraints
  const supportToken = signDevToken({
    userId: "alice",
    roles: ["support-agent"],
  });
  const supportClient = await connectAs(supportToken);
  const supportTools = (await supportClient.listTools()).tools.map((t) => t.name);
  console.log("3. support-agent visible tools:", supportTools);
  assert.deepEqual(supportTools.sort(), [
    "demo.greet",
    "jira.get_issue",
    "jira.list_issues",
  ]);

  const supIssue = await supportClient.callTool({
    name: "jira.get_issue",
    arguments: { issueId: "SUP-142" },
  });
  assert.match(supIssue.content.find((c) => c.type === "text")?.text ?? "", /SUP-142/);

  await assert.rejects(
    () =>
      supportClient.callTool({
        name: "jira.get_issue",
        arguments: { issueId: "PAY-101" },
      }),
    /ARG_CONSTRAINT_VIOLATION/
  );
  console.log("   support-agent blocked from PAY-101 (ARG_CONSTRAINT_VIOLATION)");

  await assert.rejects(
    () =>
      supportClient.callTool({
        name: "jira.add_comment",
        arguments: { issueId: "SUP-142", body: "Hello" },
      }),
    /ACCESS_DENIED/
  );
  console.log("   support-agent blocked from jira.add_comment (ACCESS_DENIED)");
  await supportClient.close();

  // 4. dev-agent: inherited tools + write access + length constraint
  const devToken = signDevToken({
    userId: "bob",
    roles: ["dev-agent"],
  });
  const devClient = await connectAs(devToken);
  const devTools = (await devClient.listTools()).tools.map((t) => t.name);
  console.log("4. dev-agent visible tools:", devTools);
  assert.deepEqual(devTools.sort(), [
    "demo.greet",
    "jira.add_comment",
    "jira.get_issue",
    "jira.list_issues",
  ]);

  const commentRes = await devClient.callTool({
    name: "jira.add_comment",
    arguments: { issueId: "PAY-101", body: "Verified webhook retry cap." },
  });
  assert.match(
    commentRes.content.find((c) => c.type === "text")?.text ?? "",
    /PAY-101/
  );

  await assert.rejects(
    () =>
      devClient.callTool({
        name: "jira.add_comment",
        arguments: { issueId: "PAY-101", body: "x".repeat(501) },
      }),
    /ARG_CONSTRAINT_VIOLATION/
  );
  console.log("   dev-agent oversized comment rejected (ARG_CONSTRAINT_VIOLATION)");
  await devClient.close();

  // 5. admin-agent: require_approval check
  const adminToken = signDevToken({
    userId: "carol",
    roles: ["admin-agent"],
  });
  const adminClient = await connectAs(adminToken);
  await assert.rejects(
    () =>
      adminClient.callTool({
        name: "jira.delete_issue",
        arguments: { issueId: "SUP-142" },
      }),
    /APPROVAL_REQUIRED/
  );
  console.log("5. admin-agent high-risk tool gated (APPROVAL_REQUIRED)");
  await adminClient.close();

  // 6. Verify audit trail and hash chain via API
  const baseUrl = GATEWAY_URL.replace(/\/mcp$/, "");
  const auditRes = await fetch(`${baseUrl}/api/audit?limit=10`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert.equal(auditRes.status, 200);
  const auditData = (await auditRes.json()) as { total: number; events: unknown[] };
  assert.ok(auditData.total >= 6, `Expected >= 6 audit events, got ${auditData.total}`);

  const verifyRes = await fetch(`${baseUrl}/api/audit/verify`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert.equal(verifyRes.status, 200);
  const verifyData = (await verifyRes.json()) as { valid: boolean; totalEvents: number };
  assert.equal(verifyData.valid, true, "Expected audit hash chain to be valid");
  console.log(`6. Audit log & hash chain verified (${verifyData.totalEvents} events)`);

  console.log("\nGateway Phase 2+3 (AuthN + RBAC + Audit) integration check PASSED!");
}

main().catch((err) => {
  console.error("Gateway Phase 2 integration test failed:", err);
  process.exit(1);
});
