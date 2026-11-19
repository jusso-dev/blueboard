import { randomBytes } from "node:crypto";
import { z } from "zod";
import { DEFENDER, GRAPH, msFetch } from "../graph/client";

/**
 * Every write the board can make in Defender / Entra / Sentinel. Agents only ever *request* these;
 * the broker runs them with the board's own identity after policy and (usually) human approval.
 *
 * `targets` returns the identifiers that must belong to the linked incident (scope guard) and that
 * are checked against the protected-asset lists.
 */
export type ActionDef<S extends z.ZodTypeAny = z.ZodTypeAny> = {
  kind: string;
  title: string;
  stage: "contain" | "eradicate" | "recover" | "record";
  destructive: boolean;
  schema: S;
  targets: (p: z.infer<S>) => { users?: string[]; devices?: string[]; other?: string[] };
  describe: (p: z.infer<S>) => string;
  run: (p: z.infer<S>, ctx: { comment: string }) => Promise<unknown>;
};

const deviceId = z.string().regex(/^[0-9a-f]{40}$/i, "MDE machine id (40 hex chars)");
const userRef = z.string().min(3).max(200).describe("Entra user object id or UPN");
const comment = (ctx: { comment: string }) => ctx.comment.slice(0, 900);

function def<S extends z.ZodTypeAny>(d: ActionDef<S>): ActionDef<S> {
  return d;
}

const INDICATOR_TYPES = {
  sha256: "FileSha256",
  sha1: "FileSha1",
  md5: "FileMd5",
  ip: "IpAddress",
  domain: "DomainName",
  url: "Url",
} as const;

export const ACTIONS = {
  isolate_device: def({
    kind: "isolate_device",
    title: "Isolate device (MDE)",
    stage: "contain",
    destructive: true,
    schema: z.object({ machine_id: deviceId, isolation_type: z.enum(["Full", "Selective"]).default("Full") }),
    targets: (p) => ({ devices: [p.machine_id] }),
    describe: (p) => `${p.isolation_type} network isolation of MDE device ${p.machine_id}`,
    run: (p, ctx) =>
      msFetch(DEFENDER, `/api/machines/${p.machine_id}/isolate`, {
        method: "POST",
        body: { Comment: comment(ctx), IsolationType: p.isolation_type },
      }),
  }),
  release_device: def({
    kind: "release_device",
    title: "Release device from isolation (MDE)",
    stage: "recover",
    destructive: true,
    schema: z.object({ machine_id: deviceId }),
    targets: (p) => ({ devices: [p.machine_id] }),
    describe: (p) => `Release MDE device ${p.machine_id} from isolation`,
    run: (p, ctx) =>
      msFetch(DEFENDER, `/api/machines/${p.machine_id}/unisolate`, { method: "POST", body: { Comment: comment(ctx) } }),
  }),
  run_av_scan: def({
    kind: "run_av_scan",
    title: "Run antivirus scan (MDE)",
    stage: "eradicate",
    destructive: false,
    schema: z.object({ machine_id: deviceId, scan_type: z.enum(["Quick", "Full"]).default("Quick") }),
    targets: (p) => ({ devices: [p.machine_id] }),
    describe: (p) => `${p.scan_type} Defender AV scan on ${p.machine_id}`,
    run: (p, ctx) =>
      msFetch(DEFENDER, `/api/machines/${p.machine_id}/runAntiVirusScan`, {
        method: "POST",
        body: { Comment: comment(ctx), ScanType: p.scan_type },
      }),
  }),
  collect_investigation_package: def({
    kind: "collect_investigation_package",
    title: "Collect investigation package (MDE)",
    stage: "contain",
    destructive: false,
    schema: z.object({ machine_id: deviceId }),
    targets: (p) => ({ devices: [p.machine_id] }),
    describe: (p) => `Collect forensic investigation package from ${p.machine_id}`,
    run: (p, ctx) =>
      msFetch(DEFENDER, `/api/machines/${p.machine_id}/collectInvestigationPackage`, {
        method: "POST",
        body: { Comment: comment(ctx) },
      }),
  }),
  disable_user: def({
    kind: "disable_user",
    title: "Disable user account (Entra ID)",
    stage: "contain",
    destructive: true,
    schema: z.object({ user: userRef }),
    targets: (p) => ({ users: [p.user] }),
    describe: (p) => `Disable Entra ID account ${p.user}`,
    run: (p) =>
      msFetch(GRAPH, `/v1.0/users/${encodeURIComponent(p.user)}`, { method: "PATCH", body: { accountEnabled: false } }),
  }),
  revoke_sessions: def({
    kind: "revoke_sessions",
    title: "Revoke sign-in sessions (Entra ID)",
    stage: "contain",
    destructive: true,
    schema: z.object({ user: userRef }),
    targets: (p) => ({ users: [p.user] }),
    describe: (p) => `Revoke all refresh tokens and sessions for ${p.user}`,
    run: (p) => msFetch(GRAPH, `/v1.0/users/${encodeURIComponent(p.user)}/revokeSignInSessions`, { method: "POST" }),
  }),
  reset_password: def({
    kind: "reset_password",
    title: "Force password reset (Entra ID)",
    stage: "eradicate",
    destructive: true,
    schema: z.object({ user: userRef }),
    targets: (p) => ({ users: [p.user] }),
    describe: (p) =>
      `Set a random password on ${p.user} and require a change at next sign-in (the user recovers through SSPR or the helpdesk; the password is never stored or shown)`,
    run: async (p) => {
      // Random, discarded password: the point is to invalidate the known-compromised one.
      const password = `${randomBytes(18).toString("base64url")}!a1`;
      await msFetch(GRAPH, `/v1.0/users/${encodeURIComponent(p.user)}`, {
        method: "PATCH",
        body: { passwordProfile: { forceChangePasswordNextSignIn: true, password } },
      });
      return { reset: true, forceChangePasswordNextSignIn: true };
    },
  }),
  block_indicator: def({
    kind: "block_indicator",
    title: "Block indicator (Defender custom IOC)",
    stage: "contain",
    destructive: true,
    schema: z.object({
      indicator_type: z.enum(["sha256", "sha1", "md5", "ip", "domain", "url"]),
      value: z.string().min(3).max(2048),
      title: z.string().min(3).max(200),
      severity: z.enum(["Informational", "Low", "Medium", "High"]).default("High"),
      expires_in_days: z.number().int().min(1).max(365).default(30),
    }),
    targets: (p) => ({ other: [p.value] }),
    describe: (p) => `Block ${p.indicator_type} ${p.value} tenant-wide for ${p.expires_in_days} days`,
    run: (p, ctx) => {
      const isFile = ["sha256", "sha1", "md5"].includes(p.indicator_type);
      return msFetch(DEFENDER, "/api/indicators", {
        method: "POST",
        body: {
          indicatorValue: p.value,
          indicatorType: INDICATOR_TYPES[p.indicator_type],
          action: isFile ? "BlockAndRemediate" : "Block",
          title: p.title,
          description: comment(ctx),
          severity: p.severity,
          generateAlert: true,
          expirationTime: new Date(Date.now() + p.expires_in_days * 86400_000).toISOString(),
        },
      });
    },
  }),
  purge_email: def({
    kind: "purge_email",
    title: "Purge email (Defender for Office 365)",
    stage: "eradicate",
    destructive: true,
    schema: z.object({
      messages: z
        .array(z.object({ network_message_id: z.string().min(8), recipient: z.string().email() }))
        .min(1)
        .max(100),
      action: z.enum(["softDelete", "hardDelete", "moveToJunk", "moveToDeletedItems"]).default("softDelete"),
    }),
    targets: (p) => ({ users: p.messages.map((m) => m.recipient), other: p.messages.map((m) => m.network_message_id) }),
    describe: (p) => `${p.action} ${p.messages.length} message(s) from recipient mailboxes`,
    run: (p, ctx) =>
      msFetch(GRAPH, "/beta/security/collaboration/analyzedEmails/remediate", {
        method: "POST",
        body: {
          displayName: `blueboard: ${ctx.comment.slice(0, 80)}`,
          description: comment(ctx),
          severity: "high",
          action: p.action,
          remediateSendersCopy: false,
          analyzedEmails: p.messages.map((m) => ({ networkMessageId: m.network_message_id, recipientEmailAddress: m.recipient })),
        },
      }),
  }),
  update_incident: def({
    kind: "update_incident",
    title: "Update / close incident (Defender XDR / Sentinel)",
    stage: "record",
    destructive: true,
    schema: z
      .object({
        incident_id: z.string().min(1).max(50).describe("Defender XDR incident id"),
        status: z.enum(["active", "inProgress", "resolved", "redirected"]).optional(),
        classification: z.enum(["truePositive", "falsePositive", "informationalExpectedActivity", "unknown"]).optional(),
        determination: z.string().max(100).optional(),
        assigned_to: z.string().max(200).optional(),
        custom_tags: z.array(z.string().max(50)).max(20).optional(),
      })
      .refine((p) => p.status || p.classification || p.determination || p.assigned_to || p.custom_tags, "nothing to update"),
    targets: () => ({}),
    describe: (p) =>
      `Update incident ${p.incident_id}: ${[
        p.status && `status=${p.status}`,
        p.classification && `classification=${p.classification}`,
        p.determination && `determination=${p.determination}`,
        p.assigned_to && `assignedTo=${p.assigned_to}`,
      ]
        .filter(Boolean)
        .join(", ")}`,
    run: (p) =>
      msFetch(GRAPH, `/v1.0/security/incidents/${encodeURIComponent(p.incident_id)}`, {
        method: "PATCH",
        body: Object.fromEntries(
          Object.entries({
            status: p.status,
            classification: p.classification,
            determination: p.determination,
            assignedTo: p.assigned_to,
            customTags: p.custom_tags,
          }).filter(([, v]) => v !== undefined),
        ),
      }),
  }),
  add_incident_comment: def({
    kind: "add_incident_comment",
    title: "Comment on incident (Defender XDR / Sentinel)",
    stage: "record",
    destructive: false,
    schema: z.object({ incident_id: z.string().min(1).max(50), comment: z.string().min(1).max(30000) }),
    targets: () => ({}),
    describe: (p) => `Add a comment to incident ${p.incident_id}`,
    run: (p) =>
      msFetch(GRAPH, `/v1.0/security/incidents/${encodeURIComponent(p.incident_id)}/comments`, {
        method: "POST",
        body: { "@odata.type": "microsoft.graph.security.alertComment", comment: p.comment },
      }),
  }),
} satisfies Record<string, ActionDef<any>>;

export type ActionKind = keyof typeof ACTIONS;
export const ACTION_KINDS = Object.keys(ACTIONS) as [ActionKind, ...ActionKind[]];

export function actionCatalog() {
  return Object.values(ACTIONS).map((a) => ({
    kind: a.kind,
    title: a.title,
    stage: a.stage,
    destructive: a.destructive,
    params: z.toJSONSchema(a.schema, { io: "input" }),
  }));
}
