import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { AuthError, authenticate } from "@/lib/auth";
import { errorResponse } from "@/lib/http";
import { buildMcpServer } from "@/lib/mcp/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * Stateless MCP over Streamable HTTP. Every request is authenticated with an Entra bearer token
 * (workload identity for agents) and gets a server bound to that principal.
 */
async function handle(req: Request) {
  let me;
  try {
    me = await authenticate(req, { bearerOnly: true });
  } catch (err) {
    if (err instanceof AuthError && err.status === 401) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 401,
        headers: {
          "content-type": "application/json",
          "www-authenticate": `Bearer resource_metadata="${new URL("/.well-known/oauth-protected-resource", req.url)}"`,
        },
      });
    }
    return errorResponse(err);
  }
  const server = buildMcpServer(me);
  const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  await server.connect(transport);
  try {
    return await transport.handleRequest(req);
  } finally {
    // Stateless: tear down once the response is produced.
    queueMicrotask(() => void server.close());
  }
}

export { handle as GET, handle as POST, handle as DELETE };
