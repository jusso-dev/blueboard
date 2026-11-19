import { requireRole } from "@/lib/auth";
import { BoardError } from "@/lib/board";
import { route } from "@/lib/http";
import { buildReport, reportCsv } from "@/lib/reporting";

export const dynamic = "force-dynamic";

/** Admin-only response metrics. `?format=csv` downloads the per-incident table. */
export const GET = route(async (req, me) => {
  requireRole(me, "admin");
  const u = new URL(req.url).searchParams;
  let report;
  try {
    report = await buildReport({ from: u.get("from") || undefined, to: u.get("to") || undefined, severity: u.get("severity") || undefined });
  } catch (err) {
    throw new BoardError((err as Error).message);
  }
  if (u.get("format") === "csv") {
    return new Response(reportCsv(report), {
      headers: {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition": `attachment; filename="blueboard-response-${report.range.from.slice(0, 10)}-${report.range.to.slice(0, 10)}.csv"`,
      },
    });
  }
  return report;
});
