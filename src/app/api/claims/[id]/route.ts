import { z } from "zod";
import { claimMessage, settleClaim } from "@/lib/board";
import { assertSameOrigin, route } from "@/lib/http";
export const dynamic = "force-dynamic";

const Body = z.object({ op: z.enum(["claim", "done", "release"]), lease_seconds: z.number().int().optional() });

export const POST = route<{ params: Promise<{ id: string }> }>(async (req, me, { params }) => {
  assertSameOrigin(req);
  const { id } = await params;
  const body = Body.parse(await req.json());
  return body.op === "claim" ? claimMessage(me, id, body.lease_seconds) : settleClaim(me, id, body.op);
});
