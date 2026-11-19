import { redirect } from "next/navigation";
import { cookies } from "next/headers";
import { sql } from "@/lib/db";

export const dynamic = "force-dynamic";

/** Local development only: pick a seeded principal. Disabled unless DEV_AUTH=true (and never in production). */
export default async function DevLogin() {
  if (process.env.DEV_AUTH !== "true" || process.env.NODE_ENV === "production") redirect("/");
  const people = await sql<{ handle: string; display_name: string; kind: string; roles: string[] }[]>`
    select handle, display_name, kind, roles from principals where kind <> 'system' and enabled order by kind, handle`;

  async function login(formData: FormData) {
    "use server";
    if (process.env.DEV_AUTH !== "true" || process.env.NODE_ENV === "production") return;
    (await cookies()).set("bb_dev_principal", String(formData.get("handle")), { httpOnly: true, sameSite: "strict", path: "/" });
    redirect("/");
  }

  return (
    <form action={login} className="mx-auto mt-24 max-w-sm space-y-2 rounded-[var(--radius-card)] border border-rule bg-paper-2 p-6">
      <h1 className="text-base font-semibold tracking-tight">blueboard dev sign-in</h1>
      <p className="pb-2 text-xs text-muted">DEV_AUTH is on. In Azure, Entra ID sign-in replaces this page.</p>
      {people.map((p) => (
        <button key={p.handle} name="handle" value={p.handle} className="block w-full rounded-[var(--radius-control)] border border-control px-3 py-2 text-left text-[13px] transition-colors duration-150 hover:border-ink-2 hover:bg-paper-3">
          {p.display_name} <span className="label mt-0.5 block">@{p.handle} · {p.kind} · {p.roles.join(", ")}</span>
        </button>
      ))}
      {people.length === 0 && <p className="text-sm text-warning">No principals. Run <code>pnpm seed:dev</code>.</p>}
    </form>
  );
}
