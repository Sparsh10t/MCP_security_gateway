/**
 * Manages connections to upstream MCP servers and routes tool calls to the right one.
 *
 * Gateway sits between the AI agent and the real MCP servers:
 *   AI Agent → [MCP Gateway] → Demo Server  (tools: greet, echo)
 *                            → Jira Server   (tools: search, createIssue)
 *
 * Tools get namespaced to avoid collisions:
 *   "greet" on Demo server → registered as "demo.greet"
 *   "search" on Jira server → registered as "jira.search"
 */

import {
  Client,
  StreamableHTTPClientTransport,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { env } from "../config/env.js";
import type { UpstreamServerConfig } from "../config/upstreams.js";

export interface RegisteredToolEntry {
  namespacedName: string; // e.g. "demo.greet"
  upstreamName: string;   // e.g. "demo"
  originalName: string;   // e.g. "greet" (what the upstream expects)
  tool: Tool;
}

export interface UpstreamStatus {
  name: string;
  transport: "stdio" | "http";
  riskTier: UpstreamServerConfig["riskTier"];
  enabled: boolean;
  connected: boolean;
  toolCount: number;
  tools: string[];
  error?: string;
}

interface UpstreamConnection {
  config: UpstreamServerConfig;
  client: Client | null;
  connected: boolean;
  tools: Tool[];
  error?: string;
}

export class UpstreamManager {
  private readonly connections = new Map<string, UpstreamConnection>();
  private readonly toolRegistry = new Map<string, RegisteredToolEntry>();

  async initialize(configs: UpstreamServerConfig[]): Promise<void> {
    await this.closeAll();

    for (const config of configs) {
      if (!config.enabled) {
        this.connections.set(config.name, { config, client: null, connected: false, tools: [] });
        continue;
      }
      await this.connectUpstream(config);
    }

    await this.rebuildToolRegistry();
  }

  private async connectUpstream(config: UpstreamServerConfig): Promise<void> {
    const client = new Client({ name: `mcp-gateway-upstream-${config.name}`, version: "1.0.0" });

    try {
      const transport = this.createTransport(config);
      await client.connect(transport);
      const result = await client.listTools();

      this.connections.set(config.name, { config, client, connected: true, tools: result.tools });
      console.log(`[upstream:${config.name}] connected (${config.transport}) - ${result.tools.length} tools`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.connections.set(config.name, { config, client: null, connected: false, tools: [], error: message });
      await client.close().catch(() => { });
      console.error(`[upstream:${config.name}] connection failed:`, message);
    }
  }

  private createTransport(config: UpstreamServerConfig) {
    if (config.transport === "stdio") {
      // stdio: gateway launches the upstream as a child process
      return new StdioClientTransport({
        command: config.command,
        args: config.args,
        ...(config.cwd !== undefined ? { cwd: config.cwd } : {}),
        ...(config.env !== undefined ? { env: { ...process.env, ...config.env } as Record<string, string> } : {}),
      });
    }
    // http: connect to a remote URL
    return new StreamableHTTPClientTransport(new URL(config.url), {
      ...(config.headers !== undefined ? { requestInit: { headers: config.headers } } : {}),
    });
  }

  private async rebuildToolRegistry(): Promise<void> {
    this.toolRegistry.clear();

    for (const [upstreamName, conn] of this.connections.entries()) {
      if (!conn.connected) continue;

      for (const tool of conn.tools) {
        const namespacedName = `${upstreamName}.${tool.name}`;

        if (this.toolRegistry.has(namespacedName)) {
          throw new Error(`Tool namespace collision detected for "${namespacedName}"`);
        }

        this.toolRegistry.set(namespacedName, {
          namespacedName,
          upstreamName,
          originalName: tool.name,
          tool: {
            ...tool,
            name: namespacedName,
            description: tool.description
              ? `[${upstreamName}] ${tool.description}`
              : `[${upstreamName}] ${tool.name}`,
          },
        });
      }
    }
  }

  listTools(): Tool[] {
    return Array.from(this.toolRegistry.values()).map((e) => e.tool);
  }

  getToolEntry(namespacedName: string): RegisteredToolEntry | undefined {
    return this.toolRegistry.get(namespacedName);
  }

  async callTool(
    namespacedName: string,
    args?: Record<string, unknown>
  ): Promise<{ result: CallToolResult; entry: RegisteredToolEntry }> {
    const entry = this.toolRegistry.get(namespacedName);
    if (!entry) throw new UnknownToolError(namespacedName);

    const conn = this.connections.get(entry.upstreamName);
    if (!conn || !conn.connected || !conn.client) throw new UpstreamUnavailableError(entry.upstreamName);

    // Call with the original (un-namespaced) tool name
    const result = await conn.client.callTool(
      { name: entry.originalName, ...(args !== undefined ? { arguments: args } : {}) },
      { timeout: env.UPSTREAM_CALL_TIMEOUT_MS }
    );

    return { result, entry };
  }

  getStatuses(): UpstreamStatus[] {
    return Array.from(this.connections.values()).map((conn) => ({
      name: conn.config.name,
      transport: conn.config.transport,
      riskTier: conn.config.riskTier,
      enabled: conn.config.enabled,
      connected: conn.connected,
      toolCount: conn.tools.length,
      tools: conn.tools.map((t) => `${conn.config.name}.${t.name}`),
      ...(conn.error !== undefined ? { error: conn.error } : {}),
    }));
  }

  async closeAll(): Promise<void> {
    for (const conn of this.connections.values()) {
      if (conn.client) await conn.client.close().catch(() => { });
    }
    this.connections.clear();
    this.toolRegistry.clear();
  }
}

export class UnknownToolError extends Error {
  constructor(toolName: string) {
    super(`Unknown tool: ${toolName}`);
    this.name = "UnknownToolError";
  }
}

export class UpstreamUnavailableError extends Error {
  constructor(upstreamName: string) {
    super(`Upstream server "${upstreamName}" is unavailable`);
    this.name = "UpstreamUnavailableError";
  }
}
