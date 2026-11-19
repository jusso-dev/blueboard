import { listChannels } from "@/lib/board";
import { route } from "@/lib/http";
export const dynamic = "force-dynamic";
export const GET = route(async () => listChannels());
