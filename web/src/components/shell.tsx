import { Link, Outlet, useLocation, useNavigate, useSearchParams } from "react-router";
import { createContext, useContext, type ReactNode } from "react";
import { cx, Kbd, Select, Severity } from "./ui";
import { ShortcutsProvider, useSearchShortcut, useShortcutDialogs } from "./shortcuts";
import { IconBell } from "./icons";
import { signIn, signOut } from "../lib/auth";
import { IdleSignOut } from "./idle";
import { useLive, useLiveQuery, type Action, type BoardStatus, type Channel, type Incident, type Me } from "../lib/api";

const MeContext = createContext<Me | null>(null);
export const useMe = () => useContext(MeContext);

/** Side rail (N3) + main column. Every app page renders inside this. */
export function Shell() {
  const { data: me, error } = useLiveQuery<Me>("/me");
  if (error?.status === 401) return <SignedOut />;
  if (error && !me) return <Unavailable reason={error.message} />;
  if (me && !me.roles.includes("poster")) return <NoRole me={me} />;
  return (
    <MeContext.Provider value={me ?? null}>
      <ShortcutsProvider me={me ?? null}>
      <div className="grid h-dvh grid-cols-[248px_minmax(0,1fr)] max-md:grid-cols-1 max-md:grid-rows-[auto_minmax(0,1fr)]">
        <Rail me={me ?? null} />
        <MobileBar />
        <main className="flex min-h-0 min-w-0 flex-col">
          <SessionIdle />
          <StatusBanner admin={!!me?.roles.includes("admin")} />
          <Outlet />
        </main>
      </div>
      </ShortcutsProvider>
    </MeContext.Provider>
  );
}

/** Idle sign-out at the limit the API reports (SESSION_IDLE_MINUTES). */
function SessionIdle() {
  const { data: s } = useLiveQuery<BoardStatus>("/status");
  return <IdleSignOut minutes={s?.session_idle_minutes ?? 0} />;
}

/**
 * Persistent banner while the broker is paused, in dry run, or the policy is the default. Words first: the colour only
 * repeats what the text says (design.md). Paused is critical; dry run and default policy are warnings.
 */
function StatusBanner({ admin }: { admin: boolean }) {
  const { data: s } = useLiveQuery<BoardStatus>("/status");
  if (!s) return null;
  const lines: { tone: "critical" | "warning"; label: string; text: string }[] = [];
  if (s.broker === "paused")
    lines.push({
      tone: "critical",
      label: "Broker paused",
      text: `by @${s.paused_by}. Nothing runs in the tenant; approvals are recorded and held${s.held ? ` (${s.held} held)` : ""}.`,
    });
  else if (s.broker === "dry_run") lines.push({ tone: "warning", label: "Dry run", text: "Approved actions are recorded but never sent to Defender or Entra (BROKER_EXECUTE is off)." });
  if (s.broker !== "paused" && s.held > 0) lines.push({ tone: "warning", label: "Held actions", text: `${s.held} action(s) approved during a pause are waiting for Run now on Approvals.` });
  if (s.policy !== "loaded")
    lines.push({
      tone: s.policy === "missing" ? "critical" : "warning",
      label: s.policy === "missing" ? "Policy file missing" : "Default policy",
      text: "No protected users, devices or indicators are configured.",
    });
  if (lines.length === 0) return null;
  return (
    <div role="status" className="shrink-0 border-b border-rule">
      {lines.map((l) => (
        <p
          key={l.label}
          className={cx(
            "flex flex-wrap items-baseline gap-x-2 px-6 py-1.5 max-sm:px-4 text-xs",
            l.tone === "critical" ? "bg-critical-soft/50 text-ink" : "bg-warning-soft/40 text-ink",
          )}
        >
          <span className={cx("font-semibold", l.tone === "critical" ? "text-critical" : "text-warning")}>{l.label}:</span>
          <span className="text-ink-2">{l.text}</span>
          {admin && (
            <Link to={l.label === "Broker paused" ? "/admin/participants" : "/setup"} className="text-accent underline-offset-4 hover:underline">
              {l.label === "Broker paused" ? "Broker controls" : "Setup"}
            </Link>
          )}
        </p>
      ))}
    </div>
  );
}

/** All destinations stay reachable below md without a horizontally scrolling navigation bar. */
function MobileBar() {
  const path = useLocation().pathname;
  const navigate = useNavigate();
  const me = useMe();
  const { data: channels } = useLiveQuery<Channel[]>("/channels");
  const { data: pending } = useLiveQuery<Action[]>("/actions?status=open");
  const groups = [
    { label: "Board", items: [
      { href: "/", label: "Queue" },
      { href: "/search", label: "Search" },
      { href: "/approvals", label: pending?.length ? `Approvals · ${pending.length}` : "Approvals" },
      { href: "/policy", label: "Policy" },
      { href: "/intel", label: "Threat intel" },
      { href: "/exposure", label: "Exposure" },
      { href: "/memory", label: "Shared memory" },
      { href: "/settings/notifications", label: "Notifications" },
    ] },
    { label: "Channels", items: (channels ?? []).map((c) => ({ href: `/channels/${encodeURIComponent(c.name)}`, label: `# ${c.name}` })) },
    ...(me?.roles.includes("admin") ? [{ label: "Administration", items: [
      { href: "/admin", label: "Admin centre" },
      { href: "/admin/posture", label: "Posture" },
      { href: "/admin/participants", label: "Access review" },
      { href: "/admin/audit", label: "Audit log" },
      { href: "/setup", label: "Setup" },
      { href: "/reports", label: "Reports" },
    ] }] : []),
  ];
  const known = groups.some((g) => g.items.some((i) => i.href === path));
  return (
    <nav aria-label="Board" className="flex min-h-14 min-w-0 items-center gap-3 border-b border-rule px-4 md:hidden">
      <Link to="/" className="shrink-0 font-semibold tracking-tight">blueboard</Link>
      <Select aria-label="Navigate board" value={path} onChange={(e) => navigate(e.target.value)} className="min-w-0 flex-1">
        {!known && <option value={path}>{path.startsWith("/incidents/") ? "Incident" : "Current page"}</option>}
        {groups.map((g) => (
          <optgroup key={g.label} label={g.label}>
            {g.items.map((i) => <option key={i.href} value={i.href}>{i.label}</option>)}
          </optgroup>
        ))}
      </Select>
      <Link
        to="/settings/notifications"
        aria-label="Notification settings"
        aria-current={path === "/settings/notifications" ? "page" : undefined}
        className="inline-flex size-9 shrink-0 items-center justify-center rounded-[var(--radius-control)] text-muted hover:bg-paper-3 hover:text-ink"
      >
        <IconBell />
      </Link>
    </nav>
  );
}

function NoRole({ me }: { me: Me }) {
  return (
    <div className="flex h-dvh items-center justify-center px-6">
      <div className="max-w-sm">
        <p className="text-lg font-semibold tracking-tight">blueboard</p>
        <p className="mt-2 text-sm text-ink-2">You're signed in as {me.display_name}, but you don't have access to the board yet.</p>
        <p className="mt-1 text-ui text-muted">Ask a board admin to assign you the Board.Post role in Entra ID, then reload.</p>
      </div>
    </div>
  );
}

function Unavailable({ reason }: { reason: string }) {
  return (
    <div className="flex h-dvh items-center justify-center px-6">
      <div className="max-w-sm">
        <p className="text-lg font-semibold tracking-tight">blueboard</p>
        <p className="mt-2 text-sm text-ink-2">The board API isn't responding.</p>
        <p className="label mt-4">{reason}</p>
      </div>
    </div>
  );
}

function SignedOut() {
  return (
    <div className="flex h-dvh items-center justify-center px-6">
      <div className="max-w-sm">
        <p className="text-lg font-semibold tracking-tight">blueboard</p>
        <p className="mt-2 text-sm text-ink-2">Sign in with your work account to open the board.</p>
        <button
          type="button"
          onClick={() => void signIn()}
          className="mt-4 inline-flex h-9 items-center rounded-[var(--radius-control)] bg-accent px-3 text-ui font-medium text-accent-ink transition-colors duration-150 hover:bg-focus"
        >
          Sign in with Microsoft
        </button>
        {import.meta.env.DEV && (
          <p className="mt-4 text-ui text-muted">
            Local development:{" "}
            <Link className="text-accent underline-offset-4 hover:underline" to="/dev-login">
              pick a dev identity
            </Link>
            .
          </p>
        )}
      </div>
    </div>
  );
}

function RailLink({ href, active, children, count }: { href: string; active: boolean; children: ReactNode; count?: number }) {
  return (
    <Link
      to={href}
      aria-current={active ? "page" : undefined}
      className={cx(
        "group flex h-9 items-center gap-2 rounded-[var(--radius-control)] px-2 text-ui transition-colors duration-150",
        active ? "bg-accent-soft/40 font-medium text-ink" : "text-muted hover:bg-paper-2 hover:text-ink",
      )}
    >
      <span className="min-w-0 flex-1 truncate">{children}</span>
      {count ? (
        <span className="tnum min-w-4 rounded-[4px] bg-accent px-1 text-center text-meta font-semibold leading-4 text-accent-ink" aria-label={`${count} waiting`}>
          {count}
        </span>
      ) : null}
    </Link>
  );
}

function Rail({ me }: { me: Me | null }) {
  const path = useLocation().pathname;
  const [params] = useSearchParams();
  const live = useLive();
  const navigate = useNavigate();
  const { data: channels } = useLiveQuery<Channel[]>("/channels");
  const { data: incidents } = useLiveQuery<Incident[]>("/incidents?limit=5");
  const { data: pending } = useLiveQuery<Action[]>("/actions?status=open");
  const searchRef = useSearchShortcut(); // "/" focuses it (components/shortcuts.tsx)
  const { openHelp } = useShortcutDialogs();

  const channel = path.startsWith("/channels/") ? decodeURIComponent(path.split("/")[2] ?? "") : null;
  const incident = path.startsWith("/incidents/") ? path.split("/")[2] : null;
  const isAdmin = me?.roles.includes("admin");

  return (
    <aside className="flex min-h-0 flex-col border-r border-rule bg-paper max-md:hidden">
      <div className="flex h-14 shrink-0 items-center gap-2 px-5">
        <span className="font-semibold tracking-tight">blueboard</span>
        <span
          className={cx("size-1.5 rounded-full", live ? "bg-good" : "bg-faint")}
          role="status"
          aria-label={live ? "Board API reachable" : "Board API unreachable"}
          title={live ? "Live (updates every few seconds)" : "Reconnecting"}
        />
      </div>

      <form
        className="px-3 pb-3"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          const q = searchRef?.current?.value.trim();
          navigate(q ? `/search?q=${encodeURIComponent(q)}` : "/search");
        }}
      >
        <label className="relative block">
          <span className="sr-only">Search messages</span>
          <input
            ref={searchRef}
            key={path === "/search" ? params.get("q") ?? "" : "rail"}
            defaultValue={path === "/search" ? params.get("q") ?? "" : ""}
            placeholder="Search"
            className="h-9 w-full rounded-[var(--radius-control)] border border-control bg-paper-2 pl-2.5 pr-7 text-ui text-ink placeholder:text-faint transition-colors duration-150 hover:border-ink-2 focus-visible:border-accent"
          />
          <span className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2">
            <Kbd>/</Kbd>
          </span>
        </label>
      </form>

      <nav aria-label="Board" className="min-h-0 flex-1 space-y-5 overflow-y-auto px-3 pb-4">
        <div className="space-y-px">
          <RailLink href="/" active={path === "/"}>
            Queue
          </RailLink>
          <RailLink href="/approvals" active={path === "/approvals"} count={pending?.length}>
            Approvals
          </RailLink>
          <RailLink href="/search" active={path === "/search"}>
            Search
          </RailLink>
          <RailLink href="/policy" active={path === "/policy"}>
            Policy
          </RailLink>
          <RailLink href="/intel" active={path.startsWith("/intel")}>
            Threat intel
          </RailLink>
          <RailLink href="/exposure" active={path === "/exposure"}>
            Exposure
          </RailLink>
          <RailLink href="/memory" active={path === "/memory"}>
            Shared memory
          </RailLink>
          <RailLink href="/settings/notifications" active={path === "/settings/notifications"}>
            Notifications
          </RailLink>
        </div>

        <div>
          <p className="label px-2 pb-1">Channels</p>
          <div className="space-y-px">
            {channels?.map((c) => (
              <RailLink key={c.name} href={`/channels/${encodeURIComponent(c.name)}`} active={channel === c.name}>
                <span className="text-faint">#</span> {c.name}
              </RailLink>
            ))}
          </div>
        </div>

        {isAdmin && (
          <details open={path.startsWith("/admin") || path === "/setup" || path === "/reports"}>
            <summary className="cursor-pointer rounded-[var(--radius-control)] px-2 py-2 text-meta font-medium text-muted hover:text-ink">Administration</summary>
            <div className="mt-1 space-y-px">
              <RailLink href="/admin" active={path === "/admin"}>
                Admin centre
              </RailLink>
              <RailLink href="/admin/posture" active={path === "/admin/posture"}>
                Posture
              </RailLink>
              <RailLink href="/admin/participants" active={path === "/admin/participants"}>
                Access review
              </RailLink>
              <RailLink href="/admin/audit" active={path === "/admin/audit"}>
                Audit log
              </RailLink>
              <RailLink href="/setup" active={path === "/setup"}>
                Setup
              </RailLink>
              <RailLink href="/reports" active={path === "/reports"}>
                Reports
              </RailLink>
            </div>
          </details>
        )}

        <div>
          <p className="label px-2 pb-1">Recent incidents</p>
          <div className="space-y-px">
            {incidents?.length === 0 && <p className="px-2 text-xs text-faint">None yet. The poller posts them to the queue.</p>}
            {incidents?.map((i) => (
              <Link
                key={i.id}
                to={`/incidents/${i.id}`}
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

      <button type="button" onClick={openHelp} className="label mx-3 mb-2 flex items-center gap-1.5 rounded-[var(--radius-control)] px-2 py-1 text-left hover:text-ink">
        <Kbd>?</Kbd> Keyboard shortcuts
      </button>

      {me && (
        <div className="flex items-end gap-2 border-t border-rule px-4 py-3">
          <div className="min-w-0 flex-1">
            <p className="truncate text-ui text-ink-2">{me.display_name}</p>
            <p className="label truncate">@{me.handle}</p>
          </div>
          <button type="button" onClick={() => void signOut()} className="label hover:text-accent">
            Sign out
          </button>
        </div>
      )}
    </aside>
  );
}

/** Page header: one title, optional subtitle, right-side controls. */
export function PageHeader({ title, sub, children }: { title: ReactNode; sub?: ReactNode; children?: ReactNode }) {
  return (
    <header className="flex min-h-14 shrink-0 flex-wrap items-center gap-x-4 gap-y-3 border-b border-rule px-6 py-3 max-sm:px-4">
      <div className="min-w-[min(100%,16rem)] flex-1">
        <h1 className="text-title font-semibold tracking-tight">{title}</h1>
        {sub && <div className="mt-0.5 text-ui text-muted [overflow-wrap:anywhere]">{sub}</div>}
      </div>
      {children && <div className="flex min-w-0 max-w-full flex-wrap items-center gap-2">{children}</div>}
    </header>
  );
}
