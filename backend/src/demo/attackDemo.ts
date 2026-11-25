import assert from "node:assert/strict";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { signDevToken } from "../auth/devToken.js";

const GATEWAY_URL = process.env.GATEWAY_URL ?? "http://localhost:5000/mcp";
const BASE_URL = GATEWAY_URL.replace(/\/mcp$/, "");

async function connectAs(token: string): Promise<Client> {
  const client = new Client({
    name: "mcp-sentinel-attack-demo",
    version: "1.0.0",
  });
  const transport = new StreamableHTTPClientTransport(new URL(GATEWAY_URL), {
    requestInit: {
      headers: { Authorization: `Bearer ${token}` },
    },
  });
  await client.connect(transport);
  return client;
}

async function main() {
  console.log("=== MCP Security Gateway — Headline Attack & Governance Demo ===\n");

  const supportToken = signDevToken({
    userId: "alice",
    roles: ["support-agent"],
  });
  const client = await connectAs(supportToken);

  // Scenario 1: Benign call
  console.log("1. [ALLOW] support-agent calls jira.get_issue(SUP-142)...");
  const benign = await client.callTool({
    name: "jira.get_issue",
    arguments: { issueId: "SUP-142" },
  });
  console.log("   Result:", benign.content.find((c) => c.type === "text")?.text?.slice(0, 120), "...\n");

  // Scenario 2: RBAC denial
  console.log("2. [DENY] support-agent attempts jira.add_comment...");
  try {
    await client.callTool({
      name: "jira.add_comment",
      arguments: { issueId: "SUP-142", body: "Unauthorized write" },
    });
  } catch (err) {
    console.log("   Blocked:", err instanceof Error ? err.message : String(err), "\n");
  }

  // Scenario 3: Secret exfiltration via tool arguments
  console.log("3. [DENY] support-agent attempts secret exfiltration in demo.greet args...");
  try {
    await client.callTool({
      name: "demo.greet",
      arguments: { name: "AKIAIOSFODNN7EXAMPLE" },
    });
  } catch (err) {
    console.log("   Blocked:", err instanceof Error ? err.message : String(err), "\n");
  }

  // Scenario 4: Section 7.1 Poisoned Jira ticket (injection + PII + secret)
  console.log("4. [REDACT] support-agent fetches poisoned ticket SUP-666...");
  const poisoned = await client.callTool({
    name: "jira.get_issue",
    arguments: { issueId: "SUP-666" },
  });
  const poisonedText = poisoned.content.find((c) => c.type === "text")?.text ?? "";
  console.log("   Sanitised response:\n" + poisonedText + "\n");
  assert.doesNotMatch(poisonedText, /IGNORE ALL PREVIOUS INSTRUCTIONS/);
  assert.doesNotMatch(poisonedText, /AKIAIOSFODNN7EXAMPLE/);
  assert.doesNotMatch(poisonedText, /alice\.smith@acme\.com/);
  assert.match(poisonedText, /\[REDACTED: suspected injection\]/);
  assert.match(poisonedText, /\[REDACTED:aws_access_key\]/);
  assert.match(poisonedText, /al\*\*\*@acme\.com/);

  await client.close();

  // Scenario 5: Verify hash chain
  console.log("5. [AUDIT] Verifying tamper-evident hash chain...");
  const verifyRes = await fetch(`${BASE_URL}/api/audit/verify`, {
    headers: { Authorization: `Bearer ${supportToken}` },
  });
  const verify = (await verifyRes.json()) as { valid: boolean; totalEvents: number; headHash: string };
  assert.equal(verify.valid, true);
  console.log(`   Verified ${verify.totalEvents} events (headHash=${verify.headHash.slice(0, 16)}...)\n`);

  console.log("=== Demo Complete ===");
}

main().catch((err) => {
  console.error("Attack demo failed:", err);
  process.exit(1);
});
