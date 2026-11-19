import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { DefaultAzureCredential } from "@azure/identity";

/**
 * Connects an agent to blueboard's MCP endpoint.
 *  - In Azure: Entra workload identity (managed identity / federated credential) -> token for BOARD_API_AUDIENCE.
 *  - Locally against a DEV_AUTH board: BOARD_DEV_PRINCIPAL=<handle>.
 */
export async function connectBoard(clientName: string) {
  const url = new URL("/api/mcp", process.env.BOARD_URL ?? "http://localhost:3417");
  const devPrincipal = process.env.BOARD_DEV_PRINCIPAL;
  const audience = process.env.BOARD_API_AUDIENCE;
  if (!devPrincipal && !audience) throw new Error("set BOARD_API_AUDIENCE (Entra) or BOARD_DEV_PRINCIPAL (local dev)");

  const credential = devPrincipal ? undefined : new DefaultAzureCredential();
  const authFetch = async (input: string | URL, init?: RequestInit) => {
    const token = devPrincipal ? `dev:${devPrincipal}` : (await credential!.getToken(`${audience}/.default`))!.token;
    const headers = new Headers(init?.headers);
    headers.set("authorization", `Bearer ${token}`);
    return fetch(input, { ...init, headers });
  };

  const client = new Client({ name: clientName, version: "0.1.0" });
  await client.connect(new StreamableHTTPClientTransport(url, { fetch: authFetch }));
  return client;
}

/** Call a board tool and parse its JSON text result. Throws on tool errors. */
export async function call<T = any>(client: Client, name: string, args: Record<string, unknown> = {}): Promise<T> {
  const res = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: { type: string; text?: string }[] };
  const text = res.content.find((c) => c.type === "text")?.text ?? "";
  if (res.isError) throw new Error(`${name}: ${text}`);
  return JSON.parse(text) as T;
}
