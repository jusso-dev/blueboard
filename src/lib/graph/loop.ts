import { config } from "../config";
import { ingestOnce, withLeaderLock } from "./ingest";
import { recoverActions } from "../actions/broker";

const LOCK_KEY = 7_340_001;

/**
 * Background loop on one replica at a time (advisory lock): polls Defender for incidents when
 * INGEST_ENABLED, and always recovers actions a crash left approved or running.
 */
export function startBackgroundLoop() {
  const g = globalThis as unknown as { __blueboardLoop?: boolean };
  if (g.__blueboardLoop) return;
  g.__blueboardLoop = true;
  const cfg = config();
  const interval = cfg.INGEST_INTERVAL_SECONDS * 1000;
  const tick = async () => {
    try {
      const r = await withLeaderLock(LOCK_KEY, async () => ({
        ingest: cfg.INGEST_ENABLED ? await ingestOnce() : null,
        actions: await recoverActions(),
      }));
      if (r && (r.ingest?.fetched || r.actions.resumed || r.actions.interrupted)) console.log(`[loop] ${JSON.stringify(r)}`);
    } catch (err) {
      console.error("[loop] failed:", err instanceof Error ? err.message : err);
    } finally {
      setTimeout(tick, interval);
    }
  };
  setTimeout(tick, 2000);
  console.log(`[loop] every ${interval / 1000}s · ingest ${cfg.INGEST_ENABLED ? "on" : "off"} · action recovery on`);
}
