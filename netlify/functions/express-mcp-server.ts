import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { Config } from "@netlify/functions";
import { setupMCPServer } from "../mcp-server/index.ts";

const methodNotAllowed = () =>
  Response.json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null }, { status: 405 });

export default async (req: Request) => {
  if (req.method !== "POST") return methodNotAllowed();
  // Stateless mode: a fresh server and transport per request avoids request ID collisions.
  try {
    const server = setupMCPServer();
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await server.connect(transport);
    return await transport.handleRequest(req);
  } catch (error) {
    console.error("Error handling MCP request:", error);
    return Response.json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null }, { status: 500 });
  }
};

export const config: Config = { path: "/mcp" };
