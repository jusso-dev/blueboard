using System.Globalization;
using System.Text;
using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;

namespace Blueboard.Api.Ops;

public sealed record AuditRow(long Id, DateTimeOffset At, string? Actor, string? ActorKind, string Event, string? Subject, JsonElement? Detail);

public sealed record AuditPage(IReadOnlyList<AuditRow> Rows, long? Next, IReadOnlyList<string> Events);

/// <summary>
/// Admin → Audit log: read-only view of audit_log (append-only for every role, db/migrations/009) with filters and a
/// CSV export. Reading is admin-only; every export is itself written to the audit log (audit.exported) with the filter
/// and row count, so taking the trail out of the board is on the trail.
/// </summary>
public sealed class AuditLog(Db db, Audit audit)
{
    public const int MaxExportRows = 50_000;

    public async Task<AuditPage> QueryAsync(Principal me, AuditQuery q, CancellationToken ct = default)
    {
        me.Require(Roles.Admin);
        var rows = await ReadAsync(q, Math.Clamp(q.Limit ?? 100, 1, 500), ct);
        var events = new List<string>();
        await using (var e = db.Command("select distinct event from audit_log order by event limit 200"))
        await using (var r = await e.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) events.Add(r.GetString(0));
        var limit = Math.Clamp(q.Limit ?? 100, 1, 500);
        return new AuditPage(rows, rows.Count == limit ? rows[^1].Id : null, events);
    }

    public async Task<string> ExportCsvAsync(Principal me, AuditQuery q, CancellationToken ct = default)
    {
        me.Require(Roles.Admin);
        if (!me.IsHuman) throw BoardException.Forbidden("only people can export the audit log");
        var rows = await ReadAsync(q with { Before = null }, MaxExportRows, ct);
        await audit.WriteAsync(me.Id, "audit.exported", me.Handle,
            new { rows = rows.Count, from = q.From, to = q.To, @event = q.Event, actor = q.Actor, subject = q.Subject }, ct);
        return Csv(rows);
    }

    private async Task<List<AuditRow>> ReadAsync(AuditQuery q, int limit, CancellationToken ct)
    {
        var where = new List<string>();
        var cmd = db.Command("");
        if (q.From is { } from) { where.Add("l.at >= @from"); cmd.With("from", from); }
        if (q.To is { } to) { where.Add("l.at < @to"); cmd.With("to", to); }
        if (q.Event is { Length: > 0 } ev)
        {
            // "action." or "action" matches the family; anything else is exact.
            if (ev.EndsWith('.')) { where.Add("starts_with(l.event, @ev)"); cmd.With("ev", ev); }
            else { where.Add("(l.event = @ev or starts_with(l.event, @evp))"); cmd.With("ev", ev).With("evp", ev + "."); }
        }
        if (q.Actor is { Length: > 0 } actor) { where.Add("p.handle = @actor"); cmd.With("actor", actor.TrimStart('@')); }
        if (q.Subject is { Length: > 0 } subject) { where.Add("strpos(lower(l.subject), lower(@subject)) > 0"); cmd.With("subject", subject); }
        if (q.Before is { } before) { where.Add("l.id < @before"); cmd.With("before", before); }
        cmd.CommandText = $"""
            select l.id, l.at, p.handle, p.kind, l.event, l.subject, l.detail::text
            from audit_log l left join principals p on p.id = l.actor_id
            {(where.Count > 0 ? "where " + string.Join(" and ", where) : "")}
            order by l.id desc limit @limit
            """;
        cmd.With("limit", limit);
        var list = new List<AuditRow>();
        await using (cmd)
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
            {
                var detail = r.IsDBNull(6) ? (JsonElement?)null : JsonDocument.Parse(r.GetString(6)).RootElement.Clone();
                list.Add(new AuditRow(r.GetInt64(0), r.GetFieldValue<DateTimeOffset>(1), r.Get<string>("handle"), r.Get<string>("kind"),
                    r.GetString(4), r.Get<string>("subject"), detail));
            }
        return list;
    }

    /// <summary>RFC 4180 with the same formula-injection guard as the reports export.</summary>
    public static string Csv(IEnumerable<AuditRow> rows)
    {
        static string Esc(string? s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var t = s.TrimStart();
            if ("=+-@\t\r\n".Contains(s[0]) || (t.Length > 0 && "=+-@".Contains(t[0]))) s = "'" + s;
            return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
        }
        var sb = new StringBuilder("id,at_utc,actor,actor_kind,event,subject,detail\n");
        foreach (var x in rows)
            sb.AppendJoin(',', new[]
            {
                x.Id.ToString(CultureInfo.InvariantCulture), x.At.UtcDateTime.ToString("O"), x.Actor, x.ActorKind, x.Event, x.Subject,
                x.Detail?.GetRawText(),
            }.Select(Esc)).Append('\n');
        return sb.ToString();
    }
}
