import { z } from "zod";
import { config } from "./config";
import { sql } from "./db";
import { audit } from "./auth";
import { PayloadSchemas, type Message, type MessageType, type Principal } from "./types";

export class BoardError extends Error {
  constructor(
    message: string,
    public status: 400 | 403 | 404 | 409 = 400,
  ) {
    super(message);
  }
}

export const NOTIFY_CHANNEL = "blueboard_events";

export type BoardEvent =
  | { kind: "message"; id: string; seq: string; channel: string; incident_id: string | null }
  | { kind: "claim"; id: string; claim_state: string; claimed_by: string | null }
  | { kind: "action"; id: string; status: string };

export async function emit(event: BoardEvent) {
  await sql`select pg_notify(${NOTIFY_CHANNEL}, ${JSON.stringify(event)})`;
}

const MENTION_RE = /(?:^|[^\w@])@([a-z0-9][a-z0-9-]{1,40})/g;
export function parseMentions(body: string): string[] {
  return [...new Set([...body.matchAll(MENTION_RE)].map((m) => m[1]!))];
}

export const MESSAGE_SELECT = sql`
  select m.id, m.seq::text as seq, c.name as channel,
         json_build_object('handle', a.handle, 'display_name', a.display_name, 'kind', a.kind) as author,
         m.parent_id, m.incident_id, i.graph_id as incident_graph_id,
         m.type, m.body, m.payload, m.mentions,
         case when m.claim_state = 'claimed' and m.claim_expires_at < now() then 'open' else m.claim_state end as claim_state,
         case when m.claim_state = 'claimed' and m.claim_expires_at < now() then null else cp.handle end as claimed_by,
         m.claim_expires_at, m.created_at,
         (select count(*)::int from messages r where r.parent_id = m.id) as reply_count
  from messages m
  join channels c on c.id = m.channel_id
  join principals a on a.id = m.author_id
  left join principals cp on cp.id = m.claimed_by
  left join incidents i on i.id = m.incident_id`;

export async function listChannels() {
  return sql<{ name: string; topic: string; last_seq: string | null }[]>`
    select c.name, c.topic, (select max(seq)::text from messages m where m.channel_id = c.id) as last_seq
    from channels c order by c.name`;
}

async function channelId(name: string): Promise<string> {
  const [row] = await sql<{ id: string }[]>`select id from channels where name = ${name}`;
  if (!row) throw new BoardError(`unknown channel #${name}`, 404);
  return row.id;
}

export async function resolveIncident(ref: string | undefined | null): Promise<string | null> {
  if (!ref) return null;
  const isUuid = /^[0-9a-f-]{36}$/i.test(ref);
  const [row] = isUuid
    ? await sql<{ id: string }[]>`select id from incidents where id = ${ref} or graph_id = ${ref}`
    : await sql<{ id: string }[]>`select id from incidents where graph_id = ${ref}`;
  if (!row) throw new BoardError(`unknown incident ${ref}`, 404);
  return row.id;
}

export const PostInput = z.object({
  channel: z.string().min(1).max(41),
  type: z.enum(["chat", "finding", "question", "ioc", "verdict", "status"]).default("chat"),
  body: z.string().min(1).max(20000),
  payload: z.record(z.string(), z.unknown()).optional(),
  parent_id: z.string().uuid().optional(),
  incident: z.string().max(100).optional().describe("Board incident UUID or Defender/Sentinel incident id"),
});
export type PostInput = z.input<typeof PostInput>;

/** Post a message. `system` lets the board itself post board-only types (incident, action_request, action_result). */
export async function postMessage(
  author: Principal,
  input: Omit<PostInput, "type"> & { type?: MessageType },
  opts: { system?: boolean } = {},
): Promise<Message> {
  const type = input.type ?? "chat";
  const parsed = opts.system
    ? { ...input, type }
    : PostInput.parse({ ...input, type });
  if (!opts.system && !author.roles.includes("poster")) throw new BoardError("missing role poster", 403);

  if (parsed.payload !== undefined && type in PayloadSchemas) {
    const schema = PayloadSchemas[type as keyof typeof PayloadSchemas];
    const result = schema.safeParse(parsed.payload);
    if (!result.success) throw new BoardError(`invalid ${type} payload: ${result.error.message}`);
    parsed.payload = result.data as Record<string, unknown>;
  }

  const chId = await channelId(parsed.channel);
  let incidentId = await resolveIncident(parsed.incident);
  if (parsed.parent_id) {
    const [parent] = await sql<{ channel_id: string; incident_id: string | null; parent_id: string | null }[]>`
      select channel_id, incident_id, parent_id from messages where id = ${parsed.parent_id}`;
    if (!parent) throw new BoardError("parent message not found", 404);
    if (parent.parent_id) throw new BoardError("reply to the thread root, not to a reply");
    if (parent.channel_id !== chId) throw new BoardError("reply must be in the parent's channel");
    incidentId ??= parent.incident_id;
  }

  const mentions = parseMentions(parsed.body);
  const [row] = await sql<{ id: string; seq: string }[]>`
    insert into messages (channel_id, author_id, parent_id, incident_id, type, body, payload, mentions)
    values (${chId}, ${author.id}, ${parsed.parent_id ?? null}, ${incidentId}, ${type}, ${parsed.body},
            ${parsed.payload === undefined ? null : sql.json(parsed.payload as never)}, ${mentions})
    returning id, seq::text as seq`;
  await emit({ kind: "message", id: row!.id, seq: row!.seq, channel: parsed.channel, incident_id: incidentId });
  return (await getMessage(row!.id))!;
}

export async function getMessage(id: string): Promise<Message | undefined> {
  const [row] = await sql<Message[]>`${MESSAGE_SELECT} where m.id = ${id}`;
  return row;
}

export const FeedQuery = z.object({
  channel: z.string().optional(),
  incident: z.string().optional(),
  after_seq: z.coerce.bigint().optional().describe("Return messages with seq greater than this cursor"),
  before_seq: z.coerce.bigint().optional(),
  types: z.array(z.string()).optional(),
  mentioning: z.string().optional().describe("Only messages that @mention this handle"),
  open_requests: z.boolean().optional().describe("Only unclaimed question/action messages"),
  roots_only: z.boolean().optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
});
export type FeedQuery = z.input<typeof FeedQuery>;

export async function readFeed(q: FeedQuery): Promise<{ messages: Message[]; cursor: string | null }> {
  const f = FeedQuery.parse(q);
  const incidentId = f.incident ? await resolveIncident(f.incident) : null;
  const conds = [sql`true`];
  if (f.channel) conds.push(sql`c.name = ${f.channel}`);
  if (incidentId) conds.push(sql`m.incident_id = ${incidentId}`);
  if (f.after_seq !== undefined) conds.push(sql`m.seq > ${f.after_seq.toString()}`);
  if (f.before_seq !== undefined) conds.push(sql`m.seq < ${f.before_seq.toString()}`);
  if (f.types?.length) conds.push(sql`m.type = any(${f.types})`);
  if (f.mentioning) conds.push(sql`${f.mentioning} = any(m.mentions)`);
  if (f.roots_only) conds.push(sql`m.parent_id is null`);
  if (f.open_requests) {
    conds.push(sql`m.type in ('question', 'finding', 'ioc')`);
    conds.push(sql`(m.claim_state = 'open' or (m.claim_state = 'claimed' and m.claim_expires_at < now()))`);
  }
  const where = conds.reduce((acc, c) => sql`${acc} and ${c}`);
  // Forward paging (after_seq) reads oldest-first so agents can process in order; otherwise newest page.
  const forward = f.after_seq !== undefined;
  const rows = forward
    ? await sql<Message[]>`${MESSAGE_SELECT} where ${where} order by m.seq asc limit ${f.limit}`
    : await sql<Message[]>`select * from (${MESSAGE_SELECT} where ${where} order by m.seq desc limit ${f.limit}) t order by seq::bigint asc`;
  const cursor = rows.length ? rows[rows.length - 1]!.seq : f.after_seq?.toString() ?? null;
  return { messages: rows, cursor };
}

export async function getThread(rootId: string): Promise<{ root: Message; replies: Message[] }> {
  const root = await getMessage(rootId);
  if (!root) throw new BoardError("message not found", 404);
  const replies = await sql<Message[]>`${MESSAGE_SELECT} where m.parent_id = ${rootId} order by m.seq asc`;
  return { root, replies };
}

/**
 * Claim a specific message (a question, request for enrichment, etc.) so other agents know someone
 * is on it. Atomic: only succeeds if the message is open or its previous lease has expired.
 */
export async function claimMessage(p: Principal, id: string, leaseSeconds?: number): Promise<Message> {
  if (!p.roles.includes("poster")) throw new BoardError("missing role poster", 403);
  const lease = Math.min(Math.max(leaseSeconds ?? config().CLAIM_LEASE_SECONDS, 30), 3600);
  const rows = await sql<{ id: string }[]>`
    update messages
    set claim_state = 'claimed', claimed_by = ${p.id}, claimed_at = now(),
        claim_expires_at = now() + make_interval(secs => ${lease})
    where id = ${id}
      and type in ('question', 'finding', 'ioc')
      and (claim_state = 'open'
           or (claim_state = 'claimed' and (claim_expires_at < now() or claimed_by = ${p.id})))
    returning id`;
  if (!rows.length) {
    const existing = await getMessage(id);
    if (!existing) throw new BoardError("message not found", 404);
    if (!["question", "finding", "ioc"].includes(existing.type))
      throw new BoardError(`${existing.type} messages are not claimable`);
    throw new BoardError(`already ${existing.claim_state} by @${existing.claimed_by}`, 409);
  }
  await audit(p.id, "message.claimed", id, { lease });
  const msg = (await getMessage(id))!;
  await emit({ kind: "claim", id, claim_state: msg.claim_state, claimed_by: msg.claimed_by });
  return msg;
}

/** Release (back to open) or complete (done) a claim you hold. */
export async function settleClaim(p: Principal, id: string, outcome: "release" | "done"): Promise<Message> {
  const state = outcome === "done" ? "done" : "open";
  const rows = await sql`
    update messages
    set claim_state = ${state},
        claimed_by = case when ${state} = 'done' then claimed_by else null end,
        claim_expires_at = null
    where id = ${id} and claim_state = 'claimed' and claimed_by = ${p.id}
    returning id`;
  if (!rows.length) throw new BoardError("you do not hold a claim on this message", 409);
  await audit(p.id, `message.claim_${outcome}`, id);
  const msg = (await getMessage(id))!;
  await emit({ kind: "claim", id, claim_state: msg.claim_state, claimed_by: msg.claimed_by });
  return msg;
}

export async function listParticipants() {
  return sql<{ handle: string; display_name: string; kind: string; roles: string[]; description: string | null; last_seen_at: string | null }[]>`
    select handle, display_name, kind, roles, description, last_seen_at
    from principals where enabled order by kind, handle`;
}
