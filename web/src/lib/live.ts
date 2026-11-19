/**
 * Shared live-query cache (PERF-01). One entry per API path: however many components ask for the same path,
 * the board gets one request per poll tick and every subscriber gets the same result. Entries with no
 * subscribers are dropped, and a fetch already in flight is never started twice.
 *
 * Kept free of React and auth so it can be unit-tested with a fake fetcher.
 */
export type Snapshot<T> = { data: T | undefined; error: unknown; loading: boolean };

type Entry = {
  snap: Snapshot<unknown>;
  subscribers: Set<() => void>;
  inflight: Promise<void> | null;
};

export class LiveCache {
  private entries = new Map<string, Entry>();

  constructor(private fetcher: (path: string) => Promise<unknown>) {}

  /** Snapshot for a path (stable object until it changes, as useSyncExternalStore needs). */
  get<T>(path: string): Snapshot<T> {
    return (this.entries.get(path)?.snap ?? EMPTY) as Snapshot<T>;
  }

  /** Start receiving updates for a path; fetches it if this is the first subscriber. Returns the unsubscribe. */
  subscribe(path: string, onChange: () => void): () => void {
    let e = this.entries.get(path);
    const first = !e;
    if (!e) {
      e = { snap: EMPTY, subscribers: new Set(), inflight: null };
      this.entries.set(path, e);
    }
    e.subscribers.add(onChange);
    if (first) void this.load(path);
    return () => {
      const cur = this.entries.get(path);
      if (!cur) return;
      cur.subscribers.delete(onChange);
      if (cur.subscribers.size === 0) this.entries.delete(path);
    };
  }

  /** Refetch one path now (shared with any fetch already running for it). */
  load(path: string): Promise<void> {
    const e = this.entries.get(path);
    if (!e) return Promise.resolve();
    if (e.inflight) return e.inflight;
    this.set(e, { ...e.snap, loading: true });
    e.inflight = this.fetcher(path).then(
      (data) => this.set(e, { data, error: null, loading: false }),
      (error: unknown) => this.set(e, { data: e.snap.data, error, loading: false }),
    ).finally(() => {
      e.inflight = null;
    });
    return e.inflight;
  }

  /** One poll tick: one request per subscribed path. */
  refreshAll(): Promise<void> {
    return Promise.all([...this.entries.keys()].map((p) => this.load(p))).then(() => undefined);
  }

  get paths(): string[] {
    return [...this.entries.keys()];
  }

  private set(e: Entry, snap: Snapshot<unknown>) {
    e.snap = snap;
    e.subscribers.forEach((s) => s());
  }
}

const EMPTY: Snapshot<never> = Object.freeze({ data: undefined, error: null, loading: false });
