/** Starts the background loop (Defender incident poller + action recovery) in the Next server process. */
export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  if (!process.env.DATABASE_URL && !process.env.PGHOST) return; // e.g. during `next build`
  const { startBackgroundLoop } = await import("./lib/graph/loop");
  startBackgroundLoop();
}
