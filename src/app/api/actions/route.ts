import { listActions, requestAction } from "@/lib/actions/broker";
import { actionCatalog } from "@/lib/actions/catalog";
import { assertSameOrigin, route } from "@/lib/http";
export const dynamic = "force-dynamic";

export const GET = route(async (req) => {
  const u = new URL(req.url).searchParams;
  if (u.get("catalog") === "true") return actionCatalog();
  return listActions(u.get("status") ?? undefined);
});

export const POST = route(async (req, me) => {
  assertSameOrigin(req);
  return requestAction(me, await req.json());
});
