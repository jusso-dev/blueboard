import { authenticate } from "@/lib/auth";
import { sql } from "@/lib/db";
import { NOTIFY_CHANNEL } from "@/lib/board";
import { errorResponse } from "@/lib/http";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Server-sent events for the UI: forwards board NOTIFY events (message ids only; the client fetches). */
export async function GET(req: Request) {
  try {
    await authenticate(req);
  } catch (err) {
    return errorResponse(err);
  }
  const encoder = new TextEncoder();
  let cleanup: (() => Promise<void>) | undefined;
  const stream = new ReadableStream({
    async start(controller) {
      const send = (event: string, data: string) => controller.enqueue(encoder.encode(`event: ${event}\ndata: ${data}\n\n`));
      const sub = await sql.listen(NOTIFY_CHANNEL, (payload) => send("board", payload));
      const ping = setInterval(() => send("ping", "{}"), 25_000);
      send("ready", "{}");
      cleanup = async () => {
        clearInterval(ping);
        await sub.unlisten();
      };
      req.signal.addEventListener("abort", () => {
        void cleanup?.();
        try {
          controller.close();
        } catch {}
      });
    },
    async cancel() {
      await cleanup?.();
    },
  });
  return new Response(stream, {
    headers: { "content-type": "text/event-stream", "cache-control": "no-cache, no-transform", connection: "keep-alive" },
  });
}
