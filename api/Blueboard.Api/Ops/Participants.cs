using Blueboard.Api.Actions;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Ops;

/// <summary>
/// One row on Admin → Participants. Roles are as last seen in an Entra token (Entra stays the source of truth: the
/// board can't grant roles). RateLimit is a slot for the per-principal limits another change adds; null until then.
/// </summary>
public sealed record ParticipantRow(
    Guid Id, string Handle, string DisplayName, string Kind, string[] Roles, DateTimeOffset? LastSeenAt,
    int Posts24h, int Actions24h, bool Enabled, string? DisabledReason, string? DisabledBy, DateTimeOffset? DisabledAt, object? RateLimit = null);

/// <summary>Admin view of every principal, and enable/disable with a required reason (issue #10).</summary>
public sealed class Participants(Db db, Audit audit, BoardService board, SystemPrincipal system)
{
    public async Task<IReadOnlyList<ParticipantRow>> ListAsync(Principal me, CancellationToken ct = default)
    {
        me.Require(Roles.Admin);
        await using var cmd = db.Command("""
            select p.id, p.handle, p.display_name, p.kind, p.roles, p.last_seen_at,
                   (select count(*)::int from messages m where m.author_id = p.id and m.created_at > now() - interval '24 hours'),
                   (select count(*)::int from actions a where a.requested_by = p.id and a.created_at > now() - interval '24 hours'),
                   p.enabled, p.disabled_reason, d.handle as disabled_by, p.disabled_at
            from principals p left join principals d on d.id = p.disabled_by
            where p.kind <> 'system'
            order by p.enabled desc, p.kind, p.last_seen_at desc nulls last, p.handle
            limit 500
            """);
        var list = new List<ParticipantRow>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new ParticipantRow(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetFieldValue<string[]>(4),
                r.Get<DateTimeOffset?>("last_seen_at"), r.GetInt32(6), r.GetInt32(7), r.GetBoolean(8), r.Get<string>("disabled_reason"),
                r.Get<string>("disabled_by"), r.Get<DateTimeOffset?>("disabled_at")));
        return list;
    }

    /// <summary>Disable or re-enable a principal. Audited and announced in #general. Takes effect on its next request.</summary>
    public async Task<ParticipantRow> SetEnabledAsync(Principal me, string handle, bool enabled, string? reason, CancellationToken ct = default)
    {
        me.Require(Roles.Admin);
        if (!me.IsHuman) throw BoardException.Forbidden("only people can enable or disable principals");
        reason = reason?.Trim();
        if (reason is not { Length: >= 5 and <= 500 }) throw new BoardException("reason must be 5–500 characters");
        if (!enabled && handle == me.Handle) throw new BoardException("you can't disable yourself");

        await using (var cmd = db.Command("""
            update principals set enabled = @e,
                   disabled_reason = case when @e then null else @r end,
                   disabled_by = case when @e then null else @by end,
                   disabled_at = case when @e then null else now() end
            where handle = @h and kind <> 'system' and enabled <> @e
            returning id
            """).With("e", enabled).With("r", reason).With("by", me.Id).With("h", handle))
        {
            if (await cmd.ExecuteScalarAsync(ct) is null)
            {
                await using var ex = db.Command("select 1 from principals where handle = @h and kind <> 'system'").With("h", handle);
                throw await ex.ExecuteScalarAsync(ct) is not null
                    ? BoardException.Conflict($"@{handle} is already {(enabled ? "enabled" : "disabled")}")
                    : BoardException.NotFound("principal");
            }
            await audit.WriteAsync(me.Id, enabled ? "principal.enabled" : "principal.disabled", handle, new { reason }, ct);
        }
        await board.PostAsync(await system.GetAsync(ct), new PostInput("general",
            enabled ? $"@{me.Handle} **re-enabled** @{handle}. Reason: {reason}"
                    : $"@{me.Handle} **disabled** @{handle}: its requests are refused from now on. Reason: {reason}",
            "status", Json.Element(new { state = enabled ? "principal_enabled" : "principal_disabled", handle })), system: true, ct);
        return (await ListAsync(me, ct)).First(p => p.Handle == handle);
    }
}
