import { McpServer } from "@modelcontextprotocol/server";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

// Create MCP server
const server = new McpServer({
    name: "demo-upstream-server",
    version: "1.0.0",
});

// Register our first tool
server.registerTool(
    "greet",
    {
        description: "Greets a person by their name",
        inputSchema: z.object({
            name: z.string()
        })
    },
    async ({ name }) => {
        return {
            content: [
                {
                    type: "text",
                    text: `Hello ${name}! Welcome to MCP Sentinel.`
                }
            ]
        };
    }
);

// Start MCP server
async function main() {
    const transport = new StdioServerTransport();

    await server.connect(transport);
}

main().catch(console.error);