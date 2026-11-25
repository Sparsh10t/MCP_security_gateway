import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { Tool } from "@modelcontextprotocol/client";
import type { Identity } from "../src/auth/identity.js";
import { PolicyEngine } from "../src/policy/evaluator.js";
import { parsePolicyYaml } from "../src/policy/loader.js";

const SAMPLE_POLICY = `
version: 1
defaults:
  effect: deny
roles:
  support-agent:
    allow:
      - tool: demo.greet
      - tool: jira.get_issue
        constraints:
          issueId:
            matches: "^SUP-[0-9]+$"
      - tool: jira.list_issues
        constraints:
          project:
            in: ["SUP"]
  dev-agent:
    inherits: [support-agent]
    allow:
      - tool: jira.get_issue
        constraints:
          issueId:
            matches: "^(SUP|PAY)-[0-9]+$"
      - tool: jira.add_comment
        constraints:
          body:
            min_length: 3
            max_length: 100
          priority:
            optional: true
            min: 1
            max: 5
  admin-agent:
    allow:
      - tool: "*"
    require_approval:
      - tool: github.delete_repo
`;

const ALL_TOOLS: Tool[] = [
  { name: "demo.greet", inputSchema: { type: "object" } },
  { name: "jira.get_issue", inputSchema: { type: "object" } },
  { name: "jira.list_issues", inputSchema: { type: "object" } },
  { name: "jira.add_comment", inputSchema: { type: "object" } },
  { name: "github.delete_repo", inputSchema: { type: "object" } },
];

function makeIdentity(roles: string[]): Identity {
  return {
    userId: "tester",
    roles,
    tenant: "acme",
    scopes: ["mcp:tools"],
    clientId: "tester",
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
  };
}

describe("PolicyLoader", () => {
  it("detects circular role inheritance", () => {
    const cyclic = `
version: 1
defaults: { effect: deny }
roles:
  a:
    inherits: [b]
  b:
    inherits: [a]
`;
    assert.throws(() => parsePolicyYaml(cyclic), /Circular role inheritance/);
  });

  it("rejects unknown inherited roles", () => {
    const broken = `
version: 1
defaults: { effect: deny }
roles:
  a:
    inherits: [missing]
`;
    assert.throws(() => parsePolicyYaml(broken), /does not exist/);
  });
});

describe("PolicyEngine", () => {
  const engine = new PolicyEngine(parsePolicyYaml(SAMPLE_POLICY));

  it("denies everything by default for unknown or empty roles", () => {
    const anon = makeIdentity([]);
    assert.deepEqual(engine.filterVisibleTools(anon, ALL_TOOLS), []);
    const decision = engine.evaluateToolCall(anon, "demo.greet", { name: "x" });
    assert.equal(decision.allowed, false);
    assert.equal(decision.reasonCode, "ACCESS_DENIED");
  });

  it("filters tools/list by role and inheritance", () => {
    const supportTools = engine
      .filterVisibleTools(makeIdentity(["support-agent"]), ALL_TOOLS)
      .map((t) => t.name);
    assert.deepEqual(supportTools, [
      "demo.greet",
      "jira.get_issue",
      "jira.list_issues",
    ]);

    const devTools = engine
      .filterVisibleTools(makeIdentity(["dev-agent"]), ALL_TOOLS)
      .map((t) => t.name);
    assert.deepEqual(devTools, [
      "demo.greet",
      "jira.get_issue",
      "jira.list_issues",
      "jira.add_comment",
    ]);
  });

  it("enforces regex, in, min/max, and length constraints", () => {
    const support = makeIdentity(["support-agent"]);
    assert.equal(
      engine.evaluateToolCall(support, "jira.get_issue", { issueId: "SUP-142" })
        .allowed,
      true
    );

    const deniedIssue = engine.evaluateToolCall(support, "jira.get_issue", {
      issueId: "PAY-101",
    });
    assert.equal(deniedIssue.allowed, false);
    assert.equal(deniedIssue.reasonCode, "ARG_CONSTRAINT_VIOLATION");

    // Omitting constrained argument must not bypass constraint
    const missingProject = engine.evaluateToolCall(
      support,
      "jira.list_issues",
      {}
    );
    assert.equal(missingProject.allowed, false);
    assert.equal(missingProject.reasonCode, "ARG_CONSTRAINT_VIOLATION");

    const dev = makeIdentity(["dev-agent"]);
    assert.equal(
      engine.evaluateToolCall(dev, "jira.get_issue", { issueId: "PAY-101" })
        .allowed,
      true
    );
    assert.equal(
      engine.evaluateToolCall(dev, "jira.add_comment", { body: "Looks good" })
        .allowed,
      true
    );
    assert.equal(
      engine.evaluateToolCall(dev, "jira.add_comment", {
        body: "Looks good",
        priority: 10,
      }).reasonCode,
      "ARG_CONSTRAINT_VIOLATION"
    );
    assert.equal(
      engine.evaluateToolCall(dev, "jira.add_comment", { body: "ok" })
        .reasonCode,
      "ARG_CONSTRAINT_VIOLATION"
    );
  });

  it("flags require_approval tools even when wildcard allow exists", () => {
    const admin = makeIdentity(["admin-agent"]);
    assert.equal(
      engine.evaluateToolCall(admin, "demo.greet", { name: "x" }).allowed,
      true
    );
    const deleteDecision = engine.evaluateToolCall(
      admin,
      "github.delete_repo",
      { name: "payments-core" }
    );
    assert.equal(deleteDecision.allowed, false);
    assert.equal(deleteDecision.effect, "require_approval");
    assert.equal(deleteDecision.reasonCode, "APPROVAL_REQUIRED");
  });
});
