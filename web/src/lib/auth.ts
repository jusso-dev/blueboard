import type { AccountInfo, IPublicClientApplication } from "@azure/msal-browser";

/**
 * Microsoft Entra sign-in for the browser (MSAL, authorisation code flow with PKCE).
 *
 * The web host serves /config.json with the tenant, client id, API URL and scope, so one build runs in every
 * environment. Tokens live in sessionStorage (cleared when the tab closes) and are sent as a bearer token to
 * the Function App. Local development skips all of this: the API runs with DEV_AUTH and /dev-login picks an identity.
 */
export type PublicConfig = { mode?: "entra"; tenant_id: string; client_id: string; authority: string; api_base_url: string; scope: string };
/** Served only by a local demo host (BLUEBOARD_DEV_AUTH, refused in Azure). */
export type DevConfig = { mode: "dev"; api_base_url: string };

type Auth = { mode: "dev"; apiBase: string } | { mode: "entra"; apiBase: string; pca: IPublicClientApplication; config: PublicConfig };

let auth: Auth | undefined;

/**
 * The host decides the sign-in mode. "dev" (the local demo) is honoured only when the API agrees: its /api/me
 * accepts a dev identity, which it does only with DEV_AUTH, which the API refuses in Azure. A host that claims
 * "dev" in front of a real API therefore gets an error instead of a sign-in bypass.
 */
export async function devApiConfirms(apiBase: string, fetcher: typeof fetch = fetch): Promise<boolean> {
  try {
    const res = await fetcher(`${apiBase}/me`, { headers: { "x-dev-principal": "analyst" }, credentials: "omit" });
    return res.ok;
  } catch {
    return false;
  }
}

export async function initAuth(): Promise<Auth> {
  if (auth) return auth;
  if (import.meta.env.DEV) return (auth = { mode: "dev", apiBase: "/api" });
  const res = await fetch("/config.json", { cache: "no-store" });
  if (!res.ok) throw new Error("web host configuration missing (/config.json)");
  const raw = (await res.json()) as PublicConfig | DevConfig;
  if (raw.mode === "dev") {
    if (!(await devApiConfirms(raw.api_base_url))) throw new Error("the web host is in dev mode but the API does not accept dev sign-in");
    return (auth = { mode: "dev", apiBase: raw.api_base_url });
  }
  const config = raw;
  // Loaded only in deployed builds, as its own chunk: local development never pulls MSAL in.
  const { createStandardPublicClientApplication } = await import("@azure/msal-browser");
  const pca = await createStandardPublicClientApplication({
    auth: {
      clientId: config.client_id,
      authority: config.authority,
      redirectUri: `${location.origin}/redirect`,
      postLogoutRedirectUri: `${location.origin}/`,
    },
    cache: { cacheLocation: "sessionStorage" },
  });
  const result = await pca.handleRedirectPromise();
  const account = result?.account ?? pca.getActiveAccount() ?? pca.getAllAccounts()[0] ?? null;
  if (account) pca.setActiveAccount(account);
  return (auth = { mode: "entra", apiBase: config.api_base_url, pca, config });
}

export function current(): Auth {
  if (!auth) throw new Error("initAuth() first");
  return auth;
}

export function account(): AccountInfo | null {
  const a = current();
  return a.mode === "entra" ? a.pca.getActiveAccount() : null;
}

export async function signIn() {
  const a = current();
  if (a.mode === "entra") await a.pca.loginRedirect({ scopes: [a.config.scope], redirectStartPage: location.href });
}

export async function signOut() {
  const a = current();
  if (a.mode === "entra") await a.pca.logoutRedirect({ account: a.pca.getActiveAccount() });
  else {
    sessionStorage.removeItem("bb_dev_principal");
    location.assign("/dev-login");
  }
}

/** Authorization header for an API call, or null when the user must sign in. */
export async function authHeaders(): Promise<Record<string, string> | null> {
  const a = current();
  if (a.mode === "dev") {
    const dev = sessionStorage.getItem("bb_dev_principal");
    return dev ? { "x-dev-principal": dev } : {};
  }
  const acc = a.pca.getActiveAccount();
  if (!acc) return null;
  try {
    const t = await a.pca.acquireTokenSilent({ scopes: [a.config.scope], account: acc });
    return { authorization: `Bearer ${t.accessToken}` };
  } catch (e) {
    // InteractionRequiredAuthError (consent, MFA, expired session): send the user through sign-in again.
    if ((e as { name?: string }).name === "InteractionRequiredAuthError") return null;
    throw e;
  }
}
