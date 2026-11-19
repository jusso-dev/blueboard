import postgres from "postgres";
import { DefaultAzureCredential } from "@azure/identity";

const PG_SCOPE = "https://ossrdbms-aad.database.windows.net/.default";

function create() {
  const entra = process.env.PG_ENTRA_AUTH === "true" || process.env.PG_ENTRA_AUTH === "1";
  const opts: postgres.Options<{}> = {
    max: Number(process.env.PG_POOL_MAX ?? 10),
    idle_timeout: 30,
    onnotice: () => {},
    transform: { undefined: null },
  };
  if (entra) {
    const credential = new DefaultAzureCredential();
    opts.ssl = "require";
    opts.password = async () => (await credential.getToken(PG_SCOPE)).token;
  }
  const url = process.env.DATABASE_URL;
  return url ? postgres(url, opts) : postgres(opts);
}

const globalForDb = globalThis as unknown as { __blueboardSql?: ReturnType<typeof create> };
export const sql = globalForDb.__blueboardSql ?? (globalForDb.__blueboardSql = create());
export type Sql = typeof sql;
