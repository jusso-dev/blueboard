import { z } from "zod";

const bool = z
  .enum(["true", "false", "1", "0"])
  .optional()
  .transform((v) => v === "true" || v === "1");

const schema = z.object({
  DATABASE_URL: z.string().optional(),
  PGHOST: z.string().optional(),
  PGUSER: z.string().optional(),
  PGDATABASE: z.string().optional(),
  /** Use an Entra token as the Postgres password (Azure Database for PostgreSQL + managed identity). */
  PG_ENTRA_AUTH: bool,

  AZURE_TENANT_ID: z.string().optional(),
  /** App ID URI / client id of the board's own API app registration (the token audience agents request). */
  BOARD_API_AUDIENCE: z.string().optional(),
  /** Client id of the board's SPA/web app registration, used for human sign-in. */
  BOARD_WEB_CLIENT_ID: z.string().optional(),

  /** Local-only: trust `x-dev-principal: <handle>` instead of Entra tokens. Refused when NODE_ENV=production. */
  DEV_AUTH: bool,

  INGEST_ENABLED: bool,
  INGEST_INTERVAL_SECONDS: z.coerce.number().int().min(15).default(60),
  INGEST_LOOKBACK_HOURS: z.coerce.number().int().min(1).default(24),

  /** Run approved actions against real Graph/Defender APIs. When false the broker records a dry-run result. */
  BROKER_EXECUTE: bool,

  CLAIM_LEASE_SECONDS: z.coerce.number().int().min(30).default(600),
});

export type Config = z.infer<typeof schema>;

let cached: Config | undefined;
export function config(): Config {
  if (!cached) {
    cached = schema.parse(process.env);
    if (cached.DEV_AUTH && process.env.NODE_ENV === "production") {
      throw new Error("DEV_AUTH must not be enabled in production");
    }
  }
  return cached;
}
