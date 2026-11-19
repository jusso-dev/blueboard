import { config } from "@/lib/config";

export const dynamic = "force-dynamic";

/** RFC 9728 metadata so MCP clients can discover the Entra authorisation server and resource. */
export function GET(req: Request) {
  const cfg = config();
  return Response.json({
    resource: new URL("/api/mcp", req.url).toString(),
    authorization_servers: cfg.AZURE_TENANT_ID ? [`https://login.microsoftonline.com/${cfg.AZURE_TENANT_ID}/v2.0`] : [],
    scopes_supported: cfg.BOARD_API_AUDIENCE ? [`${cfg.BOARD_API_AUDIENCE}/.default`] : [],
    bearer_methods_supported: ["header"],
  });
}
