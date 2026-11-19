import { getIncident } from "@/lib/enrich";
import { route } from "@/lib/http";
export const dynamic = "force-dynamic";
export const GET = route<{ params: Promise<{ id: string }> }>(async (_req, _me, { params }) => getIncident((await params).id));
