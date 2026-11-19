import { z } from "zod";
import { decideAction, getAction } from "@/lib/actions/broker";
import { BoardError } from "@/lib/board";
import { assertSameOrigin, route } from "@/lib/http";
export const dynamic = "force-dynamic";

type Ctx = { params: Promise<{ id: string }> };

export const GET = route<Ctx>(async (_req, _me, { params }) => {
  const a = await getAction((await params).id);
  if (!a) throw new BoardError("action not found", 404);
  return a;
});

const Decision = z.object({ decision: z.enum(["approve", "deny"]), note: z.string().max(2000).optional() });

export const POST = route<Ctx>(async (req, me, { params }) => {
  assertSameOrigin(req);
  const { decision, note } = Decision.parse(await req.json());
  return decideAction(me, (await params).id, decision, note);
});
