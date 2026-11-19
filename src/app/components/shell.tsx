"use client";

import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { createContext, useContext, useEffect, useRef, type ReactNode } from "react";
import { cx, Kbd, Severity } from "./ui";
import { useLive, useLiveQuery, type Action, type Channel, type Incident, type Me } from "./data";

const MeContext = createContext<Me | null>(null);
export const useMe = () => useContext(MeContext);

/** Side rail (N3) + main column. Every app page renders inside this. */
export function Shell({ children }: { children: ReactNode }) {
  const { data: me, error } = useLiveQuery<Me>("/api/me");
  if (error && !me) return <SignedOut reason={error} />;
  if (me && !me.roles.includes("poster")) return <NoRole me={me} />;
  return (
    <MeContext.Provider value={me ?? null}>
      <div className="grid h-dvh grid-cols-[232px_minmax(0,1fr)] max-md:grid-cols-1 max-md:grid-rows-[auto_minmax(0,1fr)]">
        <Rail me={me ?? null} />
        <MobileBar />
        <div className="flex min-h-0 min-w-0 flex-col">{children}</div>
      </div>
    </MeContext.Provider>
  );
}

/** Below md the rail collapses to a single row of the destinations people switch between most. */
function MobileBar() {
  const path = usePathname();
  const { data: pending } = useLiveQuery<Action[]>("/api/actions?status=pending_approval");
  const items = [
    { href: "/", label: "Board", active: path === "/" || path.startsWith("/incidents") },
    { href: "/search", label: "Search", active: path === "/search" },
    { href: "/approvals", label: pending?.length ? `Approvals · ${pending.length}` : "Approvals", active: path === "/approvals" },
  ];
  return (
    <nav aria-label="Board" className="flex h-11 items-center gap-1 overflow-x-auto border-b border-rule px-3 md:hidden">
      <span className="mr-2 font-semibold tracking-tight">blueboard</span>
      {items.map((i) => (
        <Link
          key={i.href}
          href={i.href}
          aria-current={i.active ? "page" : undefined}
          className={cx(
            "whitespace-nowrap rounded-[var(--radius-control)] px-2.5 py-1.5 text-[13px] transition-colors duration-150",
            i.active ? "bg-paper-3 text-ink" : "text-muted hover:text-ink",
          )}
        >
          {i.label}
        </Link>
      ))}
    </nav>
  );
}

function NoRole({ me }: { me: Me }) {
  return (
    <div className="flex h-dvh items-center justify-center px-6">
      <div className="max-w-sm">
        <p className="text-lg font-semibold tracking-tight">blueboard</p>
        <p className="mt-2 text-sm text-ink-2">You're signed in as {me.display_name}, but you don't have access to the board yet.</p>
        <p className="mt-1 text-[13px] text-muted">Ask a board admin to assign you the Board.Post role in Entra ID, then reload.</p>
      </div>
    </div>
  );
}

function SignedOut({ reason }: { reason: string }) {
  return (
    <div className="flex h-dvh items-center justify-center px-6">
      <div className="max-w-sm">
        <p className="text-lg font-semibold tracking-tight">blueboard</p>
        <p className="mt-2 text-sm text-ink-2">You're not signed in.</p>
        <p className="mt-1 text-[13px] text-muted">
          In Azure, Entra ID sign-in sits in front of this app. Locally, run with <code className="font-mono">DEV_AUTH=true</code> and{" "}
          <a className="text-accent underline-offset-4 hover:underline" href="/dev-login">
            pick a dev identity
          </a>
          .
        </p>
        <p className="label mt-4">{reason}</p>
      </div>
    </div>
  );
}

function RailLink({ href, active, children, count }: { href: string; active: boolean; children: ReactNode; count?: number }) {
  return (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      className={cx(
        "group flex h-7 items-center gap-2 rounded-[var(--radius-control)] px-2 text-[13px] transition-colors duration-150",
        active ? "bg-paper-3 text-ink" : "text-muted hover:bg-paper-2 hover:text-ink",
      )}
    >
      <span className="min-w-0 flex-1 truncate">{children}</span>
      {count ? (
        <span className="tnum min-w-4 rounded-[4px] bg-accent px-1 text-center font-mono text-[10.5px] font-semibold leading-4 text-accent-ink" aria-label={`${count} waiting`}>
          {count}
        </span>
      ) : null}
    </Link>
  );
}

function Rail({ me }: { me: Me | null }) {
  const path = usePathname();
  const params = useSearchParams();
  const live = useLive();
  const router = useRouter();
  const { data: channels } = useLiveQuery<Channel[]>("/api/channels");
  const { data: incidents } = useLiveQuery<Incident[]>("/api/incidents");
  const { data: pending } = useLiveQuery<Action[]>("/api/actions?status=pending_approval");
  const searchRef = useRef<HTMLInputElement>(null);

  // "/" focuses search from anywhere (except while typing).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (e.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName)) {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const channel = path === "/" ? params.get("channel") ?? "incidents" : null;
  const incident = path.startsWith("/incidents/") ? path.split("/")[2] : null;
  const isAdmin = me?.roles.includes("admin");

  return (
    <aside className="flex min-h-0 flex-col border-r border-rule bg-paper max-md:hidden">
      <div className="flex h-12 items-center gap-2 px-4">
        <span className="font-semibold tracking-tight">blueboard</span>
        <span
          className={cx("size-1.5 rounded-full", live ? "bg-good" : "bg-faint")}
          role="status"
          aria-label={live ? "Live updates connected" : "Live updates disconnected"}
          title={live ? "Live" : "Reconnecting"}
        />
      </div>

      <form
        className="px-3 pb-3"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          const q = searchRef.current?.value.trim();
          router.push(q ? `/search?q=${encodeURIComponent(q)}` : "/search");
        }}
      >
        <label className="relative block">
          <span className="sr-only">Search messages</span>
          <input
            ref={searchRef}
            key={path === "/search" ? params.get("q") ?? "" : "rail"}
            defaultValue={path === "/search" ? params.get("q") ?? "" : ""}
            placeholder="Search"
            className="h-8 w-full rounded-[var(--radius-control)] border border-control bg-paper-2 pl-2.5 pr-7 text-[13px] text-ink placeholder:text-faint transition-colors duration-150 hover:border-ink-2 focus-visible:border-accent focus-visible:outline-none"
          />
          <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2">
            <Kbd>/</Kbd>
          </span>
        </label>
      </form>

      <nav aria-label="Board" className="min-h-0 flex-1 space-y-5 overflow-y-auto px-3 pb-4">
        <div className="space-y-px">
          <RailLink href="/approvals" active={path === "/approvals"} count={pending?.length}>
            Approvals
          </RailLink>
          {isAdmin && (
            <RailLink href="/reports" active={path === "/reports"}>
              Reports
            </RailLink>
          )}
        </div>

        <div>
          <p className="label px-2 pb-1">Channels</p>
          <div className="space-y-px">
            {channels?.map((c) => (
              <RailLink key={c.name} href={`/?channel=${c.name}`} active={channel === c.name}>
                <span className="text-faint">#</span> {c.name}
              </RailLink>
            ))}
          </div>
        </div>

        <div>
          <p className="label px-2 pb-1">Incidents</p>
          <div className="space-y-px">
            {incidents?.length === 0 && <p className="px-2 text-xs text-faint">None yet. The poller posts them here.</p>}
            {incidents?.map((i) => (
              <Link
                key={i.id}
                href={`/incidents/${i.id}`}
                aria-current={incident === i.id ? "page" : undefined}
                className={cx(
                  "block rounded-[var(--radius-control)] px-2 py-1.5 transition-colors duration-150",
                  incident === i.id ? "bg-paper-3" : "hover:bg-paper-2",
                )}
              >
                <span className="flex items-center gap-1.5">
                  <Severity value={i.severity} />
                  <span className="label tnum text-ink-2">{i.graph_id}</span>
                </span>
                <span className="mt-0.5 block truncate text-xs text-muted">{i.display_name}</span>
              </Link>
            ))}
          </div>
        </div>
      </nav>

      {me && (
        <div className="border-t border-rule px-4 py-3">
          <p className="truncate text-[13px] text-ink-2">{me.display_name}</p>
          <p className="label truncate">@{me.handle}</p>
        </div>
      )}
    </aside>
  );
}

/** Page header: one title, optional subtitle, right-side controls. */
export function PageHeader({ title, sub, children }: { title: ReactNode; sub?: ReactNode; children?: ReactNode }) {
  return (
    <header className="flex min-h-12 shrink-0 flex-wrap items-center gap-x-3 gap-y-2 border-b border-rule px-5 py-2">
      <div className="min-w-[min(100%,16rem)] flex-1">
        <h1 className="truncate text-sm font-semibold tracking-tight">{title}</h1>
        {sub && <div className="truncate text-xs text-muted">{sub}</div>}
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </header>
  );
}
