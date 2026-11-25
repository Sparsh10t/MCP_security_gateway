import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

async function main() {

    // 1. Create MCP client
    const client = new Client({
        name: "mcp-sentinel-client",
        version: "1.0.0"
    });

    // 2. Connect to demo MCP server
    const transport = new StdioClientTransport({
        command: "npx",
        args: ["tsx", "src/mcp/demoServer.ts"]
    });

    await client.connect(transport);

    console.log("Connected to MCP Server!");

    // 3. Discover available tools
    const result = await client.listTools();

    console.log("\nAvailable Tools:");

    for (const tool of result.tools) {
        console.log("-", tool.name);
    }

    // 4. Call greet tool
    const response = await client.callTool({
        name: "greet",
        arguments: {
            name: "Sparsh"
        }
    });

    console.log("\nTool Response:");
    console.log(response);

    // 5. Close connection
    await client.close();
}

main().catch(console.error);