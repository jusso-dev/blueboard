import { sql } from "@/lib/db";
import { route } from "@/lib/http";
export const dynamic = "force-dynamic";
export const GET = route(async () =>
  sql`select id, graph_id, display_name, severity, status, classification, alert_count, web_url, updated_at_src, last_synced_at,
             (select count(*)::int from messages m where m.incident_id = incidents.id) as message_count
      from incidents order by coalesce(updated_at_src, first_seen_at) desc limit 100`,
);
