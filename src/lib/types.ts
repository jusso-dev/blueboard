import { z } from "zod";

export const MESSAGE_TYPES = [
  "chat",
  "finding",
  "question",
  "ioc",
  "action_request",
  "action_result",
  "verdict",
  "status",
  "incident",
] as const;
export type MessageType = (typeof MESSAGE_TYPES)[number];

/** Types an outside principal may post directly. The rest are board-generated. */
export const POSTABLE_TYPES = ["chat", "finding", "question", "ioc", "verdict", "status"] as const;

export const IOC_KINDS = ["ip", "domain", "url", "sha1", "sha256", "md5", "email", "user", "device"] as const;

export const PayloadSchemas = {
  ioc: z.object({
    indicators: z
      .array(
        z.object({
          kind: z.enum(IOC_KINDS),
          value: z.string().min(1).max(2048),
          verdict: z.enum(["malicious", "suspicious", "benign", "unknown"]).default("unknown"),
          source: z.string().max(200).optional(),
        }),
      )
      .min(1)
      .max(200),
  }),
  verdict: z.object({
    classification: z.enum(["truePositive", "falsePositive", "informationalExpectedActivity", "unknown"]),
    confidence: z.number().min(0).max(1),
    determination: z.string().max(100).optional(),
  }),
  finding: z
    .object({
      confidence: z.number().min(0).max(1).optional(),
      entities: z.array(z.string().max(500)).max(200).optional(),
      evidence: z.array(z.string().max(2000)).max(50).optional(),
    })
    .passthrough(),
  status: z.object({ state: z.string().max(100) }).passthrough(),
} as const;

export type Principal = {
  id: string;
  handle: string;
  display_name: string;
  kind: "agent" | "human" | "system";
  roles: string[];
};

export type Message = {
  id: string;
  seq: string;
  channel: string;
  author: { handle: string; display_name: string; kind: Principal["kind"] };
  parent_id: string | null;
  incident_id: string | null;
  incident_graph_id: string | null;
  type: MessageType;
  body: string;
  payload: unknown;
  mentions: string[];
  claim_state: "open" | "claimed" | "done";
  claimed_by: string | null;
  claim_expires_at: string | null;
  created_at: string;
  reply_count?: number;
};

/** Roles. `hunter` may run read-only enrichment queries; `approver` may approve brokered actions; `admin` may manage principals. */
export const ROLES = ["poster", "hunter", "requester", "approver", "admin"] as const;
export type Role = (typeof ROLES)[number];
