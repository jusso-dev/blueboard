import { DefaultAzureCredential, type TokenCredential } from "@azure/identity";

/**
 * Thin authenticated fetch for Microsoft Graph and the Defender (MDE) API, using the board's own
 * identity (managed identity in Azure, or developer credentials locally). Agents never get these tokens.
 */
export const GRAPH = "https://graph.microsoft.com";
export const DEFENDER = "https://api.security.microsoft.com";

const SCOPES: Record<string, string> = {
  [GRAPH]: "https://graph.microsoft.com/.default",
  [DEFENDER]: "https://api.securitycenter.microsoft.com/.default",
};

let credential: TokenCredential | undefined;
function cred() {
  credential ??= new DefaultAzureCredential();
  return credential;
}

export class GraphError extends Error {
  constructor(
    message: string,
    public status: number,
    public body: unknown,
  ) {
    super(message);
  }
}

export async function msFetch<T = unknown>(
  base: typeof GRAPH | typeof DEFENDER,
  path: string,
  init: { method?: string; body?: unknown; headers?: Record<string, string> } = {},
): Promise<T> {
  const token = await cred().getToken(SCOPES[base]!);
  if (!token) throw new Error(`could not get token for ${base}`);
  const url = path.startsWith("https://") ? path : `${base}${path}`;
  if (!url.startsWith(base)) throw new Error(`refusing to send token to ${url}`);
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url, {
      method: init.method ?? "GET",
      headers: {
        authorization: `Bearer ${token.token}`,
        "content-type": "application/json",
        ...init.headers,
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    if ((res.status === 429 || res.status >= 500) && attempt < 3) {
      const retry = Number(res.headers.get("retry-after") ?? 2 ** attempt);
      await new Promise((r) => setTimeout(r, Math.min(retry, 30) * 1000));
      continue;
    }
    const text = await res.text();
    const body = text ? safeJson(text) : undefined;
    if (!res.ok) {
      const msg = (body as { error?: { message?: string } } | undefined)?.error?.message ?? res.statusText;
      throw new GraphError(`${init.method ?? "GET"} ${path}: ${res.status} ${msg}`, res.status, body);
    }
    return body as T;
  }
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
