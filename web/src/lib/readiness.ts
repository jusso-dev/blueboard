/**
 * Go-live stages for the Setup page, the same four as docs/QUICKSTART-AZURE.md § Staged go-live. Each stage is a
 * set of setup check ids; a stage is reached when none of them is failing and the ones it needs OK are OK. Purely a
 * reading of GET /api/setup: no extra calls, nothing stored.
 */
export type CheckStatus = "ok" | "warning" | "failed";
export type SetupCheck = { id: string; name: string; status: CheckStatus };

export type Stage = {
  key: "deployed" | "connected" | "governed" | "live";
  title: string;
  summary: string;
  /** Check ids that must be OK. Checks missing from the report (a profile that doesn't run them) are skipped. */
  needs: string[];
};

export const STAGES: Stage[] = [
  { key: "deployed", title: "Deployed", summary: "Database, single sign-on and read permissions work. Nothing can change your tenant.", needs: ["database", "auth", "reads"] },
  { key: "connected", title: "Connected", summary: "Incidents arrive from Defender and Sentinel, and an agent is checking in.", needs: ["ingest", "agents"] },
  { key: "governed", title: "Governed", summary: "Your policy, two or more approvers, notifications and (production) audit export to Sentinel.", needs: ["policy", "access", "notify", "audit_export"] },
  { key: "live", title: "Live actions", summary: "Write permissions for the actions you broker, and the broker out of dry run.", needs: ["writes", "broker"] },
];

export type StageState = { stage: Stage; state: "done" | "current" | "todo"; blocking: SetupCheck[] };

/** The stages in order: done until the first one with a blocking check, which is current; the rest are to do. */
export function stageStates(checks: SetupCheck[]): StageState[] {
  const byId = new Map(checks.map((c) => [c.id, c]));
  let reachedCurrent = false;
  return STAGES.map((stage) => {
    const blocking = stage.needs.map((id) => byId.get(id)).filter((c): c is SetupCheck => !!c && c.status !== "ok");
    if (reachedCurrent) return { stage, state: "todo", blocking };
    if (blocking.length === 0) return { stage, state: "done", blocking };
    reachedCurrent = true;
    return { stage, state: "current", blocking };
  });
}
