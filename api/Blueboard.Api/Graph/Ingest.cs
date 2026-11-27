using Blueboard.Contracts;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Graph;

public enum UpsertOutcome { Created, Updated, Unchanged }
public sealed record IngestResult(string Since, int Fetched, int Created, int Updated, int Unchanged);

/// <summary>
/// Polls Graph /security/incidents (Defender XDR + Sentinel) and announces new or changed incidents in
/// #incidents. New incidents get a root `incident` message (and the first matching playbook); meaningful changes get a `status` reply.
/// </summary>
public sealed class Ingest(Db db, BoardService board, MsClient ms, SystemPrincipal system, Settings settings, PlaybookRunner? playbooks = null, Agents.AgentFeedback? feedback = null)
{
    private const string CursorKey = KvState.IngestCursor;

    /// <summary>
    /// Fetch a single incident directly from Microsoft Graph using the board's own managed identity and upsert it.
    /// Lets Sentinel Automation Rules / Logic Apps and analysts push immediate wake-ups without trusting caller data.
    /// </summary>
    public async Task<(UpsertOutcome Outcome, string GraphId)> SyncOneAsync(string graphId, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(graphId) || graphId.Length > 20 || !graphId.All(char.IsAsciiDigit))
            throw new BoardException("incident must be a numeric Defender XDR / Sentinel incident id");
        var inc = await ms.SendAsync(MsApi.Graph, $"/v1.0/security/incidents/{Uri.EscapeDataString(graphId)}?$expand=alerts", ct: ct)
                  ?? throw BoardException.NotFound($"incident {graphId}");
        var outcome = await UpsertAsync(inc, ct);
        return (outcome, graphId);
    }

    public async Task<IngestResult> RunOnceAsync(CancellationToken ct = default)
    {
        var since = await GetCursorAsync(ct);
        var incidents = new List<JsonElement>();
        var filter = Uri.EscapeDataString($"lastUpdateDateTime gt {since}");
        string? next = $"/v1.0/security/incidents?$filter={filter}&$expand=alerts&$top=50&$orderby=lastUpdateDateTime asc";
        while (next is not null && incidents.Count < 500)
        {
            var page = await ms.SendAsync(MsApi.Graph, next, ct: ct);
            if (page is not { } pg) break;
            incidents.AddRange(pg.GetProperty("value").EnumerateArray().Select(e => e.Clone()));
            next = pg.TryGetProperty("@odata.nextLink", out var nl) ? nl.GetString() : null;
        }
        int created = 0, updated = 0, unchanged = 0;
        var max = since;
        foreach (var inc in incidents)
        {
            switch (await UpsertAsync(inc, ct))
            {
                case UpsertOutcome.Created: created++; break;
                case UpsertOutcome.Updated: updated++; break;
                default: unchanged++; break;
            }
            if (Str(inc, "lastUpdateDateTime") is { } u && string.CompareOrdinal(u, max) > 0) max = u;
        }
        if (max != since) await SetCursorAsync(max, ct);
        return new IngestResult(since, incidents.Count, created, updated, unchanged);
    }

    public async Task<UpsertOutcome> UpsertAsync(JsonElement inc, CancellationToken ct = default)
    {
        var graphId = Str(inc, "id") ?? throw new BoardException("incident without id");
        var severity = Str(inc, "severity") ?? "unknown";
        var status = Str(inc, "status") ?? "unknown";
        var classification = Str(inc, "classification");
        var alertCount = inc.TryGetProperty("alerts", out var al) && al.ValueKind == JsonValueKind.Array ? al.GetArrayLength() : 0;

        (string Severity, string Status, int AlertCount, string? Classification)? prev = null;
        await using (var pc = db.Command("select severity, status, alert_count, classification from incidents where graph_id = @g").With("g", graphId))
        await using (var r = await pc.ExecuteReaderAsync(ct))
            if (await r.ReadAsync(ct)) prev = (r.GetString(0), r.GetString(1), r.GetInt32(2), r.Get<string>("classification"));

        var safeWebUrl = Intel.J.SafeUrl(Str(inc, "incidentWebUrl"));
        Guid incidentId;
        await using (var up = db.Command("""
            insert into incidents (graph_id, display_name, severity, status, classification, determination, assigned_to,
                                   alert_count, web_url, created_at_src, updated_at_src, data, last_synced_at)
            values (@g, @n, @sev, @st, @cl, @det, @as, @ac, @url, @cr, @upd, @data, now())
            on conflict (graph_id) do update set
              display_name = excluded.display_name, severity = excluded.severity, status = excluded.status,
              classification = excluded.classification, determination = excluded.determination,
              assigned_to = excluded.assigned_to, alert_count = excluded.alert_count, web_url = excluded.web_url,
              updated_at_src = excluded.updated_at_src, data = excluded.data, last_synced_at = now()
            returning id
            """).With("g", graphId).With("n", Str(inc, "displayName") ?? graphId).With("sev", severity).With("st", status)
                .With("cl", classification).With("det", Str(inc, "determination")).With("as", Str(inc, "assignedTo"))
                .With("ac", alertCount).With("url", safeWebUrl)
                .With("cr", Time(inc, "createdDateTime")).With("upd", Time(inc, "lastUpdateDateTime")).WithJson("data", inc))
            incidentId = (Guid)(await up.ExecuteScalarAsync(ct))!;

        var entities = Entities.Extract(inc);
        var boardPrincipal = await system.GetAsync(ct);
        if (prev is null)
        {
            var alerts = al.ValueKind == JsonValueKind.Array
                ? string.Join("\n", al.EnumerateArray().Take(10).Select(a => $"- [{Str(a, "severity") ?? "?"}] {Str(a, "title") ?? Str(a, "id")} ({Str(a, "serviceSource") ?? "unknown source"})"))
                : "";
            var announced = await board.PostAsync(boardPrincipal, new PostInput("incidents",
                $"**{severity.ToUpperInvariant()}** incident {graphId}: {Str(inc, "displayName")}\n\n{Summary(entities)}\n\n{alerts}"
                + (safeWebUrl is not null ? $"\n\n[Open in Defender]({safeWebUrl})" : ""),
                "incident", Json.Element(new { graph_id = graphId, severity, status, alert_count = alertCount, entities }), null, incidentId.ToString()), system: true, ct);
            // First sight: attach the first matching playbook; its steps become claimable questions in this thread.
            if (playbooks is not null) await playbooks.AttachAsync(incidentId, inc, announced.Id, ct);
            return UpsertOutcome.Created;
        }

        // Overturn tracking: a resolved classification from Defender / Sentinel is compared with the latest agent verdict (once each).
        if (feedback is not null && status == "resolved" && classification is not null)
            await feedback.RecordResolutionAsync(incidentId, classification, "sync", ct);

        var changes = new List<string>();
        var p = prev.Value;
        if (p.Severity != severity) changes.Add($"severity {p.Severity} → {severity}");
        if (p.Status != status) changes.Add($"status {p.Status} → {status}");
        if (p.AlertCount != alertCount) changes.Add($"alerts {p.AlertCount} → {alertCount}");
        if (p.Classification != classification) changes.Add($"classification {p.Classification ?? "none"} → {classification ?? "none"}");
        if (changes.Count == 0) return UpsertOutcome.Unchanged;

        Guid? root = null;
        await using (var rc = db.Command("""
            select m.id from messages m join channels c on c.id = m.channel_id
            where m.incident_id = @i and m.type = 'incident' and m.parent_id is null and c.name = 'incidents'
            order by m.seq asc limit 1
            """).With("i", incidentId))
            root = await rc.ExecuteScalarAsync(ct) as Guid?;
        await board.PostAsync(boardPrincipal, new PostInput("incidents", $"Incident {graphId} updated in Defender: {string.Join("; ", changes)}",
            "status", Json.Element(new { state = "source_updated", changes, entities }), root, incidentId.ToString()), system: true, ct);
        return UpsertOutcome.Updated;
    }

    internal static string Summary(IncidentEntities e)
    {
        var parts = new List<string>();
        if (e.Devices.Count > 0) parts.Add($"{e.Devices.Count} device(s): {string.Join(", ", e.Devices.Take(5).Select(d => d.Name ?? d.MdeDeviceId))}");
        if (e.Users.Count > 0) parts.Add($"{e.Users.Count} user(s): {string.Join(", ", e.Users.Take(5).Select(u => u.Upn ?? u.Name))}");
        if (e.Ips.Count > 0) parts.Add($"{e.Ips.Count} IP(s)");
        if (e.Files.Count > 0) parts.Add($"{e.Files.Count} file(s)");
        if (e.Emails.Count > 0) parts.Add($"{e.Emails.Count} email(s)");
        if (e.CloudApps.Count > 0) parts.Add($"{e.CloudApps.Count} app(s): {string.Join(", ", e.CloudApps.Take(3).Select(a => a.DisplayName ?? a.AppId ?? a.ObjectId))}");
        if (e.AzureResources.Count > 0) parts.Add($"{e.AzureResources.Count} Azure resource(s)");
        if (e.Mitre.Count > 0) parts.Add($"MITRE {string.Join(", ", e.Mitre.Take(6))}");
        return parts.Count > 0 ? string.Join(" · ", parts) : "No entities extracted.";
    }

    private async Task<string> GetCursorAsync(CancellationToken ct)
    {
        await using var cmd = db.Command("select value #>> '{}' from kv_state where key = @k").With("k", CursorKey);
        return await cmd.ExecuteScalarAsync(ct) as string
               ?? DateTimeOffset.UtcNow.AddHours(-settings.IngestLookbackHours).ToString("yyyy-MM-ddTHH:mm:ssZ");
    }

    private async Task SetCursorAsync(string value, CancellationToken ct)
    {
        await using var cmd = db.Command("insert into kv_state (key, value) values (@k, @v) on conflict (key) do update set value = excluded.value, updated_at = now()")
            .With("k", CursorKey).WithJson("v", value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static string? Str(JsonElement e, string k) => e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static DateTimeOffset? Time(JsonElement e, string k) => Str(e, k) is { } s && DateTimeOffset.TryParse(s, out var t) ? t : null;
}
