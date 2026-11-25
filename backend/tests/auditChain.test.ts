import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { canonicalJson } from "../src/audit/hashChain.js";
import { AuditLogger } from "../src/audit/logger.js";
import { redactAndHashArgs } from "../src/audit/redactor.js";
import { FileAuditStore } from "../src/audit/store.js";

describe("Audit Redactor & Canonical JSON", () => {
  it("produces identical canonical JSON regardless of key order", () => {
    const a = { b: 2, a: { y: true, x: "hi" } };
    const b = { a: { x: "hi", y: true }, b: 2 };
    assert.equal(canonicalJson(a), canonicalJson(b));
  });

  it("redacts sensitive argument keys and inline secrets while hashing original", () => {
    const { argsRedacted, argsHash } = redactAndHashArgs({
      issueId: "SUP-142",
      apiKey: "super-secret-key",
      note: "token ghp_1234567890abcdefghij123456 leaked",
    });
    assert.equal(argsRedacted["issueId"], "SUP-142");
    assert.equal(argsRedacted["apiKey"], "[REDACTED]");
    assert.match(String(argsRedacted["note"]), /\[REDACTED\]/);
    assert.equal(argsHash.length, 64);
  });
});

describe("AuditLogger & Tamper Detection", () => {
  it("writes a valid hash chain and detects tampering when a row is edited", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "mcp-audit-test-"));
    const logPath = path.join(tmpDir, "audit.jsonl");

    try {
      const store = new FileAuditStore(logPath);
      const logger = new AuditLogger(store);

      await logger.log({
        traceId: "trace-1",
        userId: "alice",
        roles: ["support-agent"],
        tool: "jira.get_issue",
        args: { issueId: "SUP-142" },
        decision: "allow",
        reasonCode: "ALLOWED",
        latencyMs: 12,
      });

      await logger.log({
        traceId: "trace-2",
        userId: "alice",
        roles: ["support-agent"],
        tool: "jira.add_comment",
        args: { issueId: "SUP-142", body: "hi" },
        decision: "deny",
        reasonCode: "ACCESS_DENIED",
        latencyMs: 2,
      });

      await logger.log({
        traceId: "trace-3",
        userId: "carol",
        roles: ["admin-agent"],
        tool: "jira.delete_issue",
        args: { issueId: "SUP-142" },
        decision: "require_approval",
        reasonCode: "APPROVAL_REQUIRED",
        latencyMs: 1,
      });

      const okResult = await logger.verifyChain();
      assert.equal(okResult.valid, true);
      assert.equal(okResult.totalEvents, 3);

      // Tamper with row index 1 (change decision from "deny" to "allow")
      const raw = await fs.readFile(logPath, "utf-8");
      const lines = raw.trim().split("\n");
      const row1 = JSON.parse(lines[1]!) as Record<string, unknown>;
      row1["decision"] = "allow";
      lines[1] = JSON.stringify(row1);
      await fs.writeFile(logPath, `${lines.join("\n")}\n`, "utf-8");

      const tamperedResult = await logger.verifyChain();
      assert.equal(tamperedResult.valid, false);
      assert.equal(tamperedResult.firstInvalid?.index, 1);
      assert.match(tamperedResult.firstInvalid?.reason ?? "", /hash mismatch/);
    } finally {
      await fs.rm(tmpDir, { recursive: true, force: true });
    }
  });
});
