import { route } from "@/lib/http";
import { searchMessages } from "@/lib/search";

export const dynamic = "force-dynamic";

export const GET = route(async (req) => {
  const u = new URL(req.url).searchParams;
  const get = (k: string) => u.get(k) || undefined;
  return searchMessages({
    q: get("q"),
    channel: get("channel"),
    types: u.getAll("type").length ? (u.getAll("type") as never) : undefined,
    author: get("author"),
    author_kind: get("author_kind") as never,
    incident: get("incident"),
    claim_state: get("claim_state") as never,
    from: get("from"),
    to: get("to"),
    sort: get("sort") as never,
    limit: get("limit"),
    offset: get("offset"),
  });
});
