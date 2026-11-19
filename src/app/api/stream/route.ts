import { authenticate, requireRole } from "@/lib/auth";
import { sql } from "@/lib/db";
import { NOTIFY_CHANNEL } from "@/lib/board";
import { errorResponse } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Server-sent events for the UI: forwards board NOTIFY events (message ids only; the client fetches). */
export async function GET(req: Request) {
  try {
    requireRole(await authenticate(req), "poster");
  } catch (err) {
    return errorResponse(err);
  }
  const encoder = new TextEncoder();
  let cleanup: (() => Promise<void>) | undefined;
  const stream = new ReadableStream({
    async start(controller) {
      let closed = false;
      let ping: ReturnType<typeof setInterval> | undefined;
      let sub: { unlisten: () => Promise<void> } | undefined;
      const send = (event: string, data: string) => {
        if (!closed) controller.enqueue(encoder.encode(`event: ${event}\ndata: ${data}\n\n`));
      };
      // Register teardown before any await, so a client that leaves during setup leaks nothing.
      cleanup = async () => {
        if (closed) return;
        closed = true;
        clearInterval(ping);
        await sub?.unlisten().catch(() => {});
        try {
          controller.close();
        } catch {}
      };
      req.signal.addEventListener("abort", () => void cleanup?.());
      sub = await sql.listen(NOTIFY_CHANNEL, (payload) => send("board", payload));
      if (closed || req.signal.aborted) {
        await sub.unlisten().catch(() => {});
        return;
      }
      ping = setInterval(() => send("ping", "{}"), 25_000);
      send("ready", "{}");
    },
    async cancel() {
      await cleanup?.();
    },
  });
  return new Response(stream, {
    headers: { "content-type": "text/event-stream", "cache-control": "no-cache, no-transform", connection: "keep-alive" },
  });
}
