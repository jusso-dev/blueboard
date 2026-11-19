import { describe, expect, it } from "vitest";
import { LiveCache } from "../lib/live";

/** A fetcher that counts requests per path and resolves when told to. */
function counter() {
  const calls = new Map<string, number>();
  return {
    calls,
    fetch: async (path: string) => {
      calls.set(path, (calls.get(path) ?? 0) + 1);
      await Promise.resolve();
      return { path, n: calls.get(path) };
    },
  };
}

describe("LiveCache (PERF-01: one request per path per tick)", () => {
  it("10 subscribers to one path cause one fetch per tick", async () => {
    const c = counter();
    const cache = new LiveCache(c.fetch);
    const seen: number[] = [];
    // Ten "tabs" or components asking for the same path.
    const unsubs = Array.from({ length: 10 }, () => cache.subscribe("/actions?status=pending_approval", () => seen.push(1)));
    await cache.refreshAll(); // the initial load is shared with this tick
    expect(c.calls.get("/actions?status=pending_approval")).toBe(1);

    await cache.refreshAll();
    await cache.refreshAll();
    expect(c.calls.get("/actions?status=pending_approval")).toBe(3);
    // Every subscriber sees the same data.
    expect(cache.get<{ n: number }>("/actions?status=pending_approval").data?.n).toBe(3);
    unsubs.forEach((u) => u());
  });

  it("only paths someone is watching are fetched, once each", async () => {
    const c = counter();
    const cache = new LiveCache(c.fetch);
    const a = cache.subscribe("/channels", () => {});
    cache.subscribe("/channels", () => {});
    cache.subscribe("/incidents", () => {});
    await cache.refreshAll();
    expect(Object.fromEntries(c.calls)).toEqual({ "/channels": 1, "/incidents": 1 });
    a();
    await cache.refreshAll();
    expect(c.calls.get("/channels")).toBe(2); // one subscriber left
  });

  it("drops a path when the last subscriber leaves", async () => {
    const c = counter();
    const cache = new LiveCache(c.fetch);
    const u = cache.subscribe("/me", () => {});
    await cache.refreshAll();
    u();
    expect(cache.paths).toEqual([]);
    await cache.refreshAll();
    expect(c.calls.get("/me")).toBe(1);
  });

  it("keeps the last good data when a refresh fails", async () => {
    let fail = false;
    const cache = new LiveCache(async () => {
      if (fail) throw new Error("down");
      return { ok: true };
    });
    cache.subscribe("/me", () => {});
    await cache.refreshAll();
    fail = true;
    await cache.refreshAll();
    const s = cache.get<{ ok: boolean }>("/me");
    expect(s.data).toEqual({ ok: true });
    expect((s.error as Error).message).toBe("down");
  });
});
