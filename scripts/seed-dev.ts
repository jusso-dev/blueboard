/**
 * Local development seed: principals with roles, plus (optionally) one realistic sample incident so the
 * board and agents can be exercised without a tenant. Never run against production.
 */
import { sql } from "../src/lib/db";
import { upsertIncident, boardPrincipal, type GraphIncident } from "../src/lib/graph/ingest";

const principals = [
  { handle: "analyst", display_name: "SOC Analyst (dev)", kind: "human", roles: ["poster", "hunter", "requester", "approver", "admin"] },
  { handle: "analyst2", display_name: "Second Analyst (dev)", kind: "human", roles: ["poster", "hunter", "requester", "approver"] },
  { handle: "enrichment-agent", display_name: "Enrichment Agent", kind: "agent", roles: ["poster", "hunter", "requester"], description: "Reference Claude agent: enriches incidents, answers questions, proposes containment" },
  { handle: "observer-bot", display_name: "Observer Bot", kind: "agent", roles: ["poster"], description: "Posts only" },
];

const sample: GraphIncident = {
  id: "90210",
  displayName: "Multi-stage incident involving Initial access & Credential access on one endpoint",
  severity: "high",
  status: "active",
  incidentWebUrl: "https://security.microsoft.com/incidents/90210",
  createdDateTime: new Date(Date.now() - 3600_000).toISOString(),
  lastUpdateDateTime: new Date().toISOString(),
  alerts: [
    {
      id: "da637f-sample-1",
      title: "Suspicious PowerShell download cradle",
      severity: "high",
      serviceSource: "microsoftDefenderForEndpoint",
      mitreTechniques: ["T1059.001", "T1105"],
      evidence: [
        { "@odata.type": "#microsoft.graph.security.deviceEvidence", mdeDeviceId: "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d", deviceDnsName: "fin-lt-0423.contoso.local" },
        { "@odata.type": "#microsoft.graph.security.userEvidence", userAccount: { userPrincipalName: "j.doe@contoso.com", azureAdUserId: "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f", displayName: "Jane Doe" } },
        { "@odata.type": "#microsoft.graph.security.ipEvidence", ipAddress: "203.0.113.45" },
        { "@odata.type": "#microsoft.graph.security.urlEvidence", url: "https://cdn-update-check.example.net/payload.ps1" },
        { "@odata.type": "#microsoft.graph.security.fileEvidence", fileDetails: { fileName: "update.exe", sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", sha1: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" } },
      ],
    },
    {
      id: "da637f-sample-2",
      title: "Possible credential theft via LSASS access",
      severity: "high",
      serviceSource: "microsoftDefenderForEndpoint",
      mitreTechniques: ["T1003.001"],
      evidence: [{ "@odata.type": "#microsoft.graph.security.deviceEvidence", mdeDeviceId: "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d", deviceDnsName: "fin-lt-0423.contoso.local" }],
    },
  ],
};

async function main() {
  if (process.env.NODE_ENV === "production") throw new Error("refusing to seed in production");
  for (const p of principals) {
    await sql`insert into principals (handle, display_name, kind, roles, description)
              values (${p.handle}, ${p.display_name}, ${p.kind}, ${p.roles}, ${p.description ?? null})
              on conflict (handle) do update set roles = excluded.roles, display_name = excluded.display_name, description = excluded.description`;
  }
  if (process.argv.includes("--sample-incident")) {
    console.log(`sample incident: ${await upsertIncident(sample, await boardPrincipal())}`);
  }
  console.log("seeded");
  await sql.end();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
