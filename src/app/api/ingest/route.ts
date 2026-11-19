import { requireRole } from "@/lib/auth";
import { ingestOnce, withLeaderLock } from "@/lib/graph/ingest";
import { assertSameOrigin, route } from "@/lib/http";
export const dynamic = "force-dynamic";

/** Manual "sync now" for admins. */
export const POST = route(async (req, me) => {
  assertSameOrigin(req);
  requireRole(me, "admin");
  return (await withLeaderLock(7_340_001, ingestOnce)) ?? { skipped: "another replica is ingesting" };
});
