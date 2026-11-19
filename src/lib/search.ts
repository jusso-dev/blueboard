import { z } from "zod";
import { sql } from "./db";
import { MESSAGE_SELECT, resolveIncident } from "./board";
import { MESSAGE_TYPES, type Message } from "./types";

/**
 * Message search: Postgres full-text over bodies (English stemming) and IOC values (no stemming),
 * with structured filters and sorting. `websearch_to_tsquery` accepts what people type:
 * quoted phrases, `or`, and `-exclusions`.
 */
export const SearchQuery = z.object({
  q: z.string().trim().max(500).optional(),
  channel: z.string().max(41).optional(),
  types: z.array(z.enum(MESSAGE_TYPES)).max(MESSAGE_TYPES.length).optional(),
  author: z.string().max(60).optional().describe("Author handle"),
  author_kind: z.enum(["agent", "human", "system"]).optional(),
  incident: z.string().max(100).optional(),
  claim_state: z.enum(["open", "claimed", "done"]).optional(),
  from: z.coerce.date().optional(),
  to: z.coerce.date().optional(),
  sort: z.enum(["relevance", "newest", "oldest"]).default("newest"),
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).max(10_000).default(0),
});
export type SearchQuery = z.input<typeof SearchQuery>;

export type SearchHit = Message & { rank: number | null; snippet: string | null };

export async function searchMessages(input: SearchQuery): Promise<{ hits: SearchHit[]; total: number }> {
  const f = SearchQuery.parse(input);
  const q = f.q ? f.q : undefined;
  const incidentId = f.incident ? await resolveIncident(f.incident) : null;
  const tsq = q ? sql`websearch_to_tsquery('english', ${q}) || websearch_to_tsquery('simple', ${q})` : null;

  const conds = [sql`true`];
  if (tsq) conds.push(sql`m.search @@ (${tsq})`);
  if (f.channel) conds.push(sql`c.name = ${f.channel}`);
  if (f.types?.length) conds.push(sql`m.type = any(${f.types})`);
  if (f.author) conds.push(sql`a.handle = ${f.author}`);
  if (f.author_kind) conds.push(sql`a.kind = ${f.author_kind}`);
  if (incidentId) conds.push(sql`m.incident_id = ${incidentId}`);
  if (f.claim_state === "open")
    conds.push(sql`m.type in ('question','finding','ioc') and (m.claim_state = 'open' or (m.claim_state = 'claimed' and m.claim_expires_at < now()))`);
  if (f.claim_state === "claimed") conds.push(sql`m.claim_state = 'claimed' and m.claim_expires_at >= now()`);
  if (f.claim_state === "done") conds.push(sql`m.claim_state = 'done'`);
  if (f.from) conds.push(sql`m.created_at >= ${f.from}`);
  if (f.to) conds.push(sql`m.created_at < ${f.to}`);
  const where = conds.reduce((acc, c) => sql`${acc} and ${c}`);

  const sort = f.sort === "relevance" && !tsq ? "newest" : f.sort;
  const order =
    sort === "relevance" ? sql`rank desc, m.seq desc` : sort === "oldest" ? sql`m.seq asc` : sql`m.seq desc`;

  // Page over ids first (cheap, index-friendly), then hydrate just that page.
  const page = await sql<{ id: string; rank: number | null; snippet: string | null; total: number }[]>`
    select m.id,
      ${tsq ? sql`ts_rank_cd(m.search, ${tsq})` : sql`null::real`} as rank,
      ${
        tsq
          ? sql`ts_headline('english', m.body, websearch_to_tsquery('english', ${q!}),
                 'StartSel=<<,StopSel=>>,MaxWords=30,MinWords=12,MaxFragments=2,FragmentDelimiter= … ')`
          : sql`null::text`
      } as snippet,
      count(*) over()::int as total
    from messages m
    join channels c on c.id = m.channel_id
    join principals a on a.id = m.author_id
    where ${where}
    order by ${order}
    limit ${f.limit} offset ${f.offset}`;
  if (!page.length) return { hits: [], total: 0 };
  const msgs = await sql<Message[]>`${MESSAGE_SELECT} where m.id = any(${page.map((p) => p.id)})`;
  const byId = new Map(msgs.map((m) => [m.id, m]));
  const hits = page.flatMap((p) => {
    const m = byId.get(p.id);
    // Fragments can cut through markdown emphasis; drop the markers so none render half-open.
    return m ? [{ ...m, rank: p.rank, snippet: p.snippet?.replace(/\*\*/g, "") ?? null }] : [];
  });
  return { hits, total: page[0]!.total };
}
