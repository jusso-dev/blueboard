import { z } from "zod";
import { config } from "../config";
import { sql } from "../db";
import { audit } from "../auth";
import { BoardError, emit, getMessage, postMessage, resolveIncident } from "../board";
import { boardPrincipal } from "../graph/ingest";
import type { Principal } from "../types";
import { ACTIONS, ACTION_KINDS, type ActionKind } from "./catalog";
import { evaluate } from "./policy";

export const RequestActionInput = z.object({
  kind: z.enum(ACTION_KINDS),
  params: z.record(z.string(), z.unknown()),
  justification: z.string().min(20).max(4000).describe("Why this action, citing evidence on the board"),
  incident: z.string().max(100).optional(),
  parent_id: z.string().uuid().optional().describe("Board message this request responds to"),
});
export type RequestActionInput = z.input<typeof RequestActionInput>;

export type ActionRow = {
  id: string;
  kind: ActionKind;
  params: Record<string, unknown>;
  incident_id: string | null;
  incident_graph_id: string | null;
  request_message_id: string | null;
  requested_by: string;
  justification: string;
  status: string;
  requires_approval: boolean;
  policy_notes: string[];
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  result: unknown;
  error: string | null;
  created_at: string;
};

const ACTION_SELECT = sql`
  select a.id, a.kind, a.params, a.incident_id, i.graph_id as incident_graph_id, a.request_message_id,
         rp.handle as requested_by, a.justification, a.status, a.requires_approval, a.policy_notes,
         dp.handle as decided_by, a.decided_at, a.decision_note, a.result, a.error, a.created_at
  from actions a
  join principals rp on rp.id = a.requested_by
  left join principals dp on dp.id = a.decided_by
  left join incidents i on i.id = a.incident_id`;

export async function getAction(id: string): Promise<ActionRow | undefined> {
  const [row] = await sql<ActionRow[]>`${ACTION_SELECT} where a.id = ${id}`;
  return row;
}

export async function listActions(status?: string) {
  return status
    ? sql<ActionRow[]>`${ACTION_SELECT} where a.status = ${status} order by a.created_at desc limit 100`
    : sql<ActionRow[]>`${ACTION_SELECT} order by a.created_at desc limit 100`;
}

/** File an action request. Never runs a destructive action directly: it lands as pending_approval. */
export async function requestAction(p: Principal, input: RequestActionInput) {
  if (!p.roles.includes("requester")) throw new BoardError("missing role requester", 403);
  const req = RequestActionInput.parse(input);
  const def = ACTIONS[req.kind];
  const parsed = def.schema.safeParse(req.params);
  if (!parsed.success) throw new BoardError(`invalid params for ${req.kind}: ${parsed.error.message}`);
  const params = parsed.data as Record<string, unknown>;

  let incidentId = await resolveIncident(req.incident);
  if (!incidentId && req.parent_id) incidentId = (await getMessage(req.parent_id))?.incident_id ?? null;
  const [incident] = incidentId
    ? await sql<{ graph_id: string; data: unknown }[]>`select graph_id, data from incidents where id = ${incidentId}`
    : [];

  const decision = evaluate(def as never, params, incident ?? null);
  const status = decision.outcome === "reject" ? "rejected" : decision.outcome === "auto" ? "approved" : "pending_approval";

  const [row] = await sql<{ id: string }[]>`
    insert into actions (kind, params, incident_id, requested_by, justification, status, requires_approval, policy_notes)
    values (${req.kind}, ${sql.json(params as never)}, ${incidentId}, ${p.id}, ${req.justification}, ${status},
            ${decision.outcome === "needs_approval"}, ${decision.notes})
    returning id`;
  const actionId = row!.id;
  await audit(p.id, "action.requested", actionId, { kind: req.kind, params, decision });

  const board = await boardPrincipal();
  const label =
    status === "rejected" ? "REJECTED by policy" : status === "approved" ? "auto-approved (non-destructive)" : "awaiting human approval";
  const msg = await postMessage(
    board,
    {
      channel: "containment",
      type: "action_request",
      incident: incidentId ?? undefined,
      body:
        `@${p.handle} requests **${def.title}**: ${def.describe(params as never)}\n\n` +
        `> ${req.justification.replace(/\n/g, "\n> ")}\n\n` +
        `Status: **${label}**` +
        (decision.notes.length ? `\n\nPolicy notes:\n${decision.notes.map((n) => `- ${n}`).join("\n")}` : ""),
      payload: { action_id: actionId, kind: req.kind, params, status, policy_notes: decision.notes },
    },
    { system: true },
  );
  await sql`update actions set request_message_id = ${msg.id} where id = ${actionId}`;
  await emit({ kind: "action", id: actionId, status });

  if (status === "approved") await execute(actionId);
  return (await getAction(actionId))!;
}

/** Human decision. Only principals with the approver role (never agents), and never the requester. */
export async function decideAction(p: Principal, id: string, decision: "approve" | "deny", note?: string) {
  if (p.kind !== "human" || !p.roles.includes("approver")) throw new BoardError("only human approvers can decide actions", 403);
  const status = decision === "approve" ? "approved" : "denied";
  const rows = await sql<{ id: string }[]>`
    update actions set status = ${status}, decided_by = ${p.id}, decided_at = now(), decision_note = ${note ?? null}, updated_at = now()
    where id = ${id} and status = 'pending_approval' and requested_by <> ${p.id}
    returning id`;
  if (!rows.length) {
    const a = await getAction(id);
    if (!a) throw new BoardError("action not found", 404);
    if (a.requested_by === p.handle) throw new BoardError("you cannot approve your own request", 403);
    throw new BoardError(`action is ${a.status}`, 409);
  }
  await audit(p.id, `action.${status}`, id, { note });
  const a = (await getAction(id))!;
  const board = await boardPrincipal();
  await postMessage(
    board,
    {
      channel: "containment",
      type: "status",
      parent_id: a.request_message_id ?? undefined,
      incident: a.incident_id ?? undefined,
      body: `@${p.handle} **${status}** ${ACTIONS[a.kind].title}${note ? `: ${note}` : ""} (requested by @${a.requested_by})`,
      payload: { state: `action_${status}`, action_id: id },
    },
    { system: true },
  );
  await emit({ kind: "action", id, status });
  if (status === "approved") await execute(id);
  return (await getAction(id))!;
}

/** Run an approved action exactly once (claim via status transition), then post the result. */
export async function execute(id: string) {
  const [claimed] = await sql<{ id: string }[]>`
    update actions set status = 'running', started_at = now(), updated_at = now() where id = ${id} and status = 'approved' returning id`;
  if (!claimed) return;
  const a = (await getAction(id))!;
  const def = ACTIONS[a.kind];
  const ctx = {
    comment: `blueboard action ${id} for incident ${a.incident_graph_id ?? "n/a"}, requested by ${a.requested_by}${
      a.decided_by ? `, approved by ${a.decided_by}` : " (auto-approved)"
    }: ${a.justification}`,
  };
  let status: "succeeded" | "failed";
  let result: unknown = null;
  let error: string | null = null;
  try {
    // Re-validate stored params: never run a write against Defender from unchecked JSON.
    const params = def.schema.parse(a.params);
    result = config().BROKER_EXECUTE ? await def.run(params as never, ctx) : { dry_run: true, would: def.describe(params as never) };
    status = "succeeded";
  } catch (err) {
    status = "failed";
    error = err instanceof Error ? err.message : String(err);
  }
  await sql`update actions set status = ${status}, result = ${result === null ? null : sql.json(result as never)},
            error = ${error}, finished_at = now(), updated_at = now() where id = ${id}`;
  await audit(null, `action.${status}`, id, { error });
  const board = await boardPrincipal();
  await postMessage(
    board,
    {
      channel: "containment",
      type: "action_result",
      parent_id: a.request_message_id ?? undefined,
      incident: a.incident_id ?? undefined,
      body:
        status === "succeeded"
          ? `**${def.title}** ${config().BROKER_EXECUTE ? "completed" : "completed (dry run: BROKER_EXECUTE is off)"}: ${def.describe(def.schema.parse(a.params) as never)}`
          : `**${def.title}** failed: ${error}`,
      payload: { action_id: id, status, result: summariseResult(result), error },
    },
    { system: true },
  );
  await emit({ kind: "action", id, status });
}

function summariseResult(result: unknown) {
  if (!result || typeof result !== "object") return result;
  const r = result as Record<string, unknown>;
  const keep = ["id", "type", "status", "requestor", "creationDateTimeUtc", "dry_run", "would", "reset"];
  return Object.fromEntries(Object.entries(r).filter(([k]) => keep.includes(k)));
}

/**
 * Recovery for actions a crash or a failed follow-up step left behind. Runs on the ingest loop's leader.
 *  - `approved` for over a minute: never started, so it is safe to run now.
 *  - `running` for over 10 minutes: may or may not have reached Defender. Never re-run it blindly:
 *    mark it failed and post so a person can check the device or account and re-request if needed.
 */
export async function recoverActions() {
  const stuck = await sql<{ id: string }[]>`
    select id from actions where status = 'approved' and updated_at < now() - interval '1 minute' order by created_at limit 20`;
  for (const a of stuck) await execute(a.id);

  const stale = await sql<{ id: string }[]>`
    update actions set status = 'failed', finished_at = now(), updated_at = now(),
      error = 'interrupted while running: outcome unknown, check Defender before re-requesting'
    where status = 'running' and coalesce(started_at, updated_at) < now() - interval '10 minutes'
    returning id`;
  if (!stale.length) return { resumed: stuck.length, interrupted: 0 };
  const board = await boardPrincipal();
  for (const { id } of stale) {
    const a = (await getAction(id))!;
    await audit(null, "action.interrupted", id);
    await postMessage(
      board,
      {
        channel: "containment",
        type: "action_result",
        parent_id: a.request_message_id ?? undefined,
        incident: a.incident_id ?? undefined,
        body: `**${ACTIONS[a.kind].title}** was interrupted while running. Its outcome is unknown: check Defender before requesting it again.`,
        payload: { action_id: id, status: "failed", error: a.error },
      },
      { system: true },
    );
    await emit({ kind: "action", id, status: "failed" });
  }
  return { resumed: stuck.length, interrupted: stale.length };
}
