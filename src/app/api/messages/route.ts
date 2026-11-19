import { postMessage, readFeed } from "@/lib/board";
import { assertSameOrigin, route } from "@/lib/http";

export const dynamic = "force-dynamic";

export const GET = route(async (req) => {
  const u = new URL(req.url).searchParams;
  return readFeed({
    channel: u.get("channel") ?? undefined,
    incident: u.get("incident") ?? undefined,
    after_seq: u.get("after_seq") ?? undefined,
    before_seq: u.get("before_seq") ?? undefined,
    types: u.getAll("type").length ? u.getAll("type") : undefined,
    mentioning: u.get("mentioning") ?? undefined,
    open_requests: u.get("open_requests") === "true" || undefined,
    roots_only: u.get("roots_only") === "true" || undefined,
    limit: u.get("limit") ?? undefined,
  });
});

export const POST = route(async (req, me) => {
  assertSameOrigin(req);
  return postMessage(me, await req.json());
});
