import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { config } from "../config";
import { sql } from "../db";
import type { Principal, Role } from "../types";

/**
 * Who is calling. Roles come from Entra app roles on every request, so Entra stays the
 * source of truth for who may join, post, request actions or approve.
 *
 *   Board.Post            read and post messages, claim requests
 *   Board.Hunt            run read-only enrichment (advanced hunting, entity lookups) via the board
 *   Board.RequestActions  file brokered containment/eradication action requests
 *   Board.Approve         approve or deny brokered actions (humans only, enforced)
 *   Board.Admin           manage principals
 */
const APP_ROLE_MAP: Record<string, Role> = {
  "Board.Post": "poster",
  "Board.Hunt": "hunter",
  "Board.RequestActions": "requester",
  "Board.Approve": "approver",
  "Board.Admin": "admin",
};

export class AuthError extends Error {
  constructor(
    message: string,
    public status: 401 | 403 = 401,
  ) {
    super(message);
  }
}

type Identity = {
  oid: string;
  appId?: string;
  kind: "agent" | "human";
  name: string;
  username?: string;
  roles: Role[];
};

let jwks: ReturnType<typeof createRemoteJWKSet> | undefined;
function getJwks(tenant: string) {
  jwks ??= createRemoteJWKSet(new URL(`https://login.microsoftonline.com/${tenant}/discovery/v2.0/keys`));
  return jwks;
}

function mapRoles(raw: unknown, kind: Identity["kind"]): Role[] {
  const list = Array.isArray(raw) ? raw.filter((r): r is string => typeof r === "string") : [];
  const roles = new Set<Role>();
  for (const r of list) {
    const mapped = APP_ROLE_MAP[r];
    if (mapped) roles.add(mapped);
  }
  // Destructive actions always need a human decision: agents can never approve.
  if (kind === "agent") roles.delete("approver");
  return [...roles];
}

export async function verifyEntraToken(token: string): Promise<Identity> {
  const cfg = config();
  if (!cfg.AZURE_TENANT_ID || !cfg.BOARD_API_AUDIENCE) {
    throw new AuthError("Entra auth is not configured (AZURE_TENANT_ID, BOARD_API_AUDIENCE)");
  }
  const tenant = cfg.AZURE_TENANT_ID;
  let payload: JWTPayload & Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(token, getJwks(tenant), {
      issuer: [`https://login.microsoftonline.com/${tenant}/v2.0`, `https://sts.windows.net/${tenant}/`],
      audience: [cfg.BOARD_API_AUDIENCE, `api://${cfg.BOARD_API_AUDIENCE}`],
      clockTolerance: 60,
    }));
  } catch {
    throw new AuthError("invalid token");
  }
  if (payload.tid !== tenant) throw new AuthError("wrong tenant");
  const oid = typeof payload.oid === "string" ? payload.oid : undefined;
  if (!oid) throw new AuthError("token has no oid");

  // App-only (workload identity) tokens have idtyp=app and no scp; delegated user tokens have scp.
  const isApp = payload.idtyp === "app" || (payload.scp === undefined && payload.preferred_username === undefined);
  const kind: Identity["kind"] = isApp ? "agent" : "human";
  const appId = (payload.azp ?? payload.appid) as string | undefined;
  return {
    oid,
    appId,
    kind,
    name: String(payload.name ?? payload.app_displayname ?? appId ?? oid),
    username: typeof payload.preferred_username === "string" ? payload.preferred_username : undefined,
    roles: mapRoles(payload.roles, kind),
  };
}

/** Azure Container Apps / App Service built-in auth ("Easy Auth"). The platform strips client-sent copies. */
function fromEasyAuth(headers: Headers): Identity | undefined {
  if (process.env.EASY_AUTH !== "true") return undefined;
  const raw = headers.get("x-ms-client-principal");
  if (!raw) return undefined;
  const decoded = JSON.parse(Buffer.from(raw, "base64").toString("utf8")) as {
    claims?: { typ: string; val: string }[];
  };
  const claims = decoded.claims ?? [];
  const get = (...types: string[]) => claims.find((c) => types.includes(c.typ))?.val;
  const oid = get("http://schemas.microsoft.com/identity/claims/objectidentifier", "oid");
  if (!oid) throw new AuthError("easy auth principal has no oid");
  const roles = claims.filter((c) => c.typ === "roles" || c.typ.endsWith("/role")).map((c) => c.val);
  return {
    oid,
    kind: "human",
    name: get("name") ?? get("preferred_username") ?? oid,
    username: get("preferred_username"),
    roles: mapRoles(roles, "human"),
  };
}

function handleFor(identity: Identity): string {
  const base = (identity.username?.split("@")[0] ?? identity.name)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 32);
  return base || `${identity.kind}-${identity.oid.slice(0, 8)}`;
}

/** Upsert the principal for a verified identity. Disabled principals are refused. */
async function upsertPrincipal(identity: Identity): Promise<Principal> {
  const [existing] = await sql<(Principal & { enabled: boolean })[]>`
    select id, handle, display_name, kind, roles, enabled from principals where entra_oid = ${identity.oid}`;
  if (existing) {
    if (!existing.enabled) throw new AuthError("principal disabled", 403);
    const [row] = await sql<Principal[]>`
      update principals set roles = ${identity.roles}, last_seen_at = now()
      where id = ${existing.id}
      returning id, handle, display_name, kind, roles`;
    return row!;
  }
  let handle = handleFor(identity);
  const [clash] = await sql`select 1 from principals where handle = ${handle}`;
  if (clash) handle = `${handle}-${identity.oid.slice(0, 6)}`;
  const [row] = await sql<Principal[]>`
    insert into principals (handle, display_name, kind, entra_oid, entra_app_id, roles, last_seen_at)
    values (${handle}, ${identity.name}, ${identity.kind}, ${identity.oid}, ${identity.appId ?? null}, ${identity.roles}, now())
    returning id, handle, display_name, kind, roles`;
  await audit(row!.id, "principal.joined", row!.handle, { kind: identity.kind, appId: identity.appId });
  return row!;
}

async function devPrincipal(handle: string): Promise<Principal> {
  const [row] = await sql<(Principal & { enabled: boolean })[]>`
    select id, handle, display_name, kind, roles, enabled from principals where handle = ${handle}`;
  if (!row || !row.enabled) throw new AuthError(`unknown dev principal ${handle}`);
  return row;
}

/**
 * Resolve the caller of an HTTP request, or throw AuthError.
 * `bearerOnly` is for paths excluded from Easy Auth (/api/mcp): there the platform may not strip a
 * client-forged x-ms-client-principal header, so only a verified Entra token is accepted.
 */
export async function authenticate(req: Request, opts: { bearerOnly?: boolean } = {}): Promise<Principal> {
  const cfg = config();
  const auth = req.headers.get("authorization");
  if (auth?.toLowerCase().startsWith("bearer ")) {
    if (cfg.DEV_AUTH && auth.slice(7).startsWith("dev:")) return devPrincipal(auth.slice(11));
    return upsertPrincipal(await verifyEntraToken(auth.slice(7).trim()));
  }
  if (opts.bearerOnly && !cfg.DEV_AUTH) throw new AuthError("bearer token required");
  const easy = opts.bearerOnly ? undefined : fromEasyAuth(req.headers);
  if (easy) return upsertPrincipal(easy);
  if (cfg.DEV_AUTH) {
    const dev = req.headers.get("x-dev-principal") ?? cookie(req, "bb_dev_principal");
    if (dev) return devPrincipal(dev);
  }
  throw new AuthError("authentication required");
}

function cookie(req: Request, name: string): string | undefined {
  const header = req.headers.get("cookie");
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return undefined;
}

export function requireRole(p: Principal, role: Role) {
  if (!p.roles.includes(role)) throw new AuthError(`missing role ${role}`, 403);
}

export async function audit(actorId: string | null, event: string, subject: string | null, detail?: unknown) {
  await sql`insert into audit_log (actor_id, event, subject, detail)
            values (${actorId}, ${event}, ${subject}, ${detail === undefined ? null : sql.json(detail as never)})`;
}
