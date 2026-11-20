import { useNavigate } from "react-router";

/**
 * Local development and the local demo only: the route exists only when sign-in is in dev mode (Vite dev server,
 * or a demo host whose API confirms DEV_AUTH). The API accepts an x-dev-principal header when it runs with
 * DEV_AUTH=true, which Azure refuses. The choice is kept in sessionStorage and sent on every call.
 */
const PEOPLE = [
  { handle: "analyst", label: "SOC Analyst (dev)", note: "human · all roles" },
  { handle: "analyst2", label: "Second Analyst (dev)", note: "human · approver" },
  { handle: "enrichment-agent", label: "Enrichment Agent", note: "agent · post, hunt, request" },
  { handle: "observer-bot", label: "Observer Bot", note: "agent · post only" },
];

export default function DevLogin() {
  const navigate = useNavigate();
  return (
    <div className="mx-auto mt-24 max-w-sm space-y-2 rounded-[var(--radius-card)] border border-rule bg-paper-2 p-6">
      <h1 className="text-base font-semibold tracking-tight">blueboard dev sign-in</h1>
      <p className="pb-2 text-xs text-muted">Pick a seeded identity. In Azure, Microsoft Entra sign-in replaces this page.</p>
      {PEOPLE.map((p) => (
        <button
          key={p.handle}
          onClick={() => {
            sessionStorage.setItem("bb_dev_principal", p.handle);
            navigate("/");
            location.reload();
          }}
          className="block w-full rounded-[var(--radius-control)] border border-control px-3 py-2 text-left text-[13px] transition-colors duration-150 hover:border-ink-2 hover:bg-paper-3"
        >
          {p.label}
          <span className="label mt-0.5 block">
            @{p.handle} · {p.note}
          </span>
        </button>
      ))}
    </div>
  );
}
