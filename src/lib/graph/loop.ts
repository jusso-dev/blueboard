import { config } from "../config";
import { ingestOnce, withLeaderLock } from "./ingest";

const LOCK_KEY = 7_340_001;

export function startIngestLoop() {
  const g = globalThis as unknown as { __blueboardIngest?: boolean };
  if (g.__blueboardIngest) return;
  g.__blueboardIngest = true;
  const interval = config().INGEST_INTERVAL_SECONDS * 1000;
  const tick = async () => {
    try {
      const r = await withLeaderLock(LOCK_KEY, ingestOnce);
      if (r && r.fetched) console.log(`[ingest] ${JSON.stringify(r)}`);
    } catch (err) {
      console.error("[ingest] failed:", err instanceof Error ? err.message : err);
    } finally {
      setTimeout(tick, interval);
    }
  };
  setTimeout(tick, 2000);
  console.log(`[ingest] polling Graph security incidents every ${interval / 1000}s`);
}
