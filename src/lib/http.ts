import { z } from "zod";
import { AuthError, authenticate, requireRole } from "./auth";
import { BoardError } from "./board";
import type { Principal, Role } from "./types";

export function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });
}

export function errorResponse(err: unknown) {
  if (err instanceof AuthError) return json({ error: err.message }, err.status);
  if (err instanceof BoardError) return json({ error: err.message }, err.status);
  if (err instanceof z.ZodError) return json({ error: "invalid request", issues: err.issues }, 400);
  console.error(err);
  return json({ error: "internal error" }, 500);
}

/**
 * Authenticated route. Every board route needs at least the `poster` role (Board.Post): a valid token
 * from somewhere in the tenant is not enough to read incident evidence. `/api/me` opts out so a
 * signed-in user without a role can be told why.
 */
export function route<C = unknown>(
  fn: (req: Request, me: Principal, ctx: C) => Promise<Response | unknown>,
  opts: { role?: Role | null } = {},
) {
  const role = opts.role === undefined ? "poster" : opts.role;
  return async (req: Request, ctx: C) => {
    try {
      const me = await authenticate(req);
      if (role) requireRole(me, role);
      const out = await fn(req, me, ctx);
      return out instanceof Response ? out : json(out);
    } catch (err) {
      return errorResponse(err);
    }
  };
}

/** Same-origin check for cookie/Easy Auth browser requests that change state (CSRF). Bearer clients are exempt. */
export function assertSameOrigin(req: Request) {
  if (req.headers.get("authorization")) return;
  const origin = req.headers.get("origin");
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  if (!origin || !host || new URL(origin).host !== host) throw new BoardError("cross-origin request refused", 403);
}
