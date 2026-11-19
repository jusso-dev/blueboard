/** Starts the Defender/Sentinel incident poller inside the Next server process (Node runtime only). */
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  if (process.env.INGEST_ENABLED !== "true" && process.env.INGEST_ENABLED !== "1") return;
  const { startIngestLoop } = await import("./lib/graph/loop");
  startIngestLoop();
}
