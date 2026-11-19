import { route } from "@/lib/http";
export const dynamic = "force-dynamic";
export const GET = route(async (_req, me) => me, { role: null });
