using Blueboard.Contracts;
using Blueboard.Api.Actions;
using Blueboard.Api.Auth;
using Blueboard.Api.Board;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Npgsql;

namespace Blueboard.Api.Ops;

/// <summary>
/// One row on Admin → Participants. Roles are as last seen in an Entra token (Entra stays the source of truth: the
/// board can't grant roles). RateLimit is a slot for the per-principal limits another change adds; null until then.
/// </summary>
public sealed record ParticipantRow(
    Guid Id, string Handle, string DisplayName, string Kind, string[] Roles, DateTimeOffset? LastSeenAt,
    int Posts24h, int Actions24h, bool Enabled, string? DisabledReason, string? DisabledBy, DateTimeOffset? DisabledAt, object? RateLimit = null, string? Description = null);

/// <summary>Admin view of every principal, enable/disable with a required reason (issue #10), and agent names.</summary>
public sealed class Participants(Db db, Audit audit, BoardService board, SystemPrincipal system)
{
    public async Task<IReadOnlyList<ParticipantRow>> ListAsync(Principal me, CancellationToken ct = default)
    {
        me.Require(Roles.Admin);
        await using var cmd = db.Command("""
            select p.id, p.handle, p.display_name, p.kind, p.roles, p.last_seen_at,
                   (select count(*)::int from messages m where m.author_id = p.id and m.created_at > now() - interval '24 hours'),
                   (select count(*)::int from actions a where a.requested_by = p.id and a.created_at > now() - interval '24 hours'),
                   p.enabled, p.disabled_reason, d.handle as disabled_by, p.disabled_at, p.description
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
                r.Get<string>("disabled_by"), r.Get<DateTimeOffset?>("disabled_at"), Description: r.Get<string>("description")));
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
            if (await cmd.ExecuteScalarAsync(ct) is not Guid pid)
            {
                await using var ex = db.Command("select 1 from principals where handle = @h and kind <> 'system'").With("h", handle);
                throw await ex.ExecuteScalarAsync(ct) is not null
                    ? BoardException.Conflict($"@{handle} is already {(enabled ? "enabled" : "disabled")}")
                    : BoardException.NotFound("principal");
            }
            if (!enabled)
            {
                await using var release = db.Command("""
                    update messages set claim_state = 'open', claimed_by = null, claim_expires_at = null
                    where claimed_by = @pid and claim_state = 'claimed';
                    update agent_subscriptions set enabled = false, disabled_reason = 'principal disabled by admin'
                    where principal_id = @pid and enabled;
                    """).With("pid", pid);
                await release.ExecuteNonQueryAsync(ct);
            }
            await audit.WriteAsync(me.Id, enabled ? "principal.enabled" : "principal.disabled", handle, new { reason }, ct);
        }
        await board.PostAsync(await system.GetAsync(ct), new PostInput("general",
            enabled ? $"@{me.Handle} **re-enabled** @{handle}. Reason: {reason}"
                    : $"@{me.Handle} **disabled** @{handle}: its requests are refused from now on. Reason: {reason}",
            "status", Json.Element(new { state = enabled ? "principal_enabled" : "principal_disabled", handle })), system: true, ct);
        return (await ListAsync(me, ct)).First(p => p.Handle == handle);
    }

    /// <summary>
    /// Inactive principals (INACTIVE_DISABLE_DAYS, off by default): people and agents not seen for that many days are
    /// disabled by the board, with a reason, an audit row (principal.disabled, by "board") and a #general notice, the same
    /// as an admin disabling them (claims released, webhooks off). Never seen principals count from when they were
    /// created. The board's own principal and principals already disabled are left alone. An admin re-enables them.
    /// </summary>
    public async Task<IReadOnlyList<string>> DisableInactiveAsync(int days, CancellationToken ct = default)
    {
        if (days < 30) throw new BoardException("INACTIVE_DISABLE_DAYS needs at least 30 days");
        var sys = await system.GetAsync(ct);
        var reason = $"inactive for more than {days} days (INACTIVE_DISABLE_DAYS)";
        var handles = new List<(Guid Id, string Handle)>();
        await using (var cmd = db.Command("""
            with disabled as (
              update principals set enabled = false, disabled_reason = @r, disabled_by = @by, disabled_at = now()
              where enabled and kind not in ('system', 'integration') and id <> @by
                and coalesce(last_seen_at, created_at) < now() - make_interval(days => @d)
              returning id, handle
            ), released as (
              update messages set claim_state = 'open', claimed_by = null, claim_expires_at = null
              where claimed_by in (select id from disabled) and claim_state = 'claimed'
            ), unsubscribed as (
              update agent_subscriptions set enabled = false, disabled_reason = 'principal disabled: inactive'
              where principal_id in (select id from disabled) and enabled
            ), logged as (
              insert into audit_log (actor_id, event, subject, detail)
              select @by, 'principal.disabled', handle,
                jsonb_build_object('reason', @r::text, 'automatic', true, 'days', @d::int) from disabled
            )
            select id, handle from disabled
            """).With("r", reason).With("by", sys.Id).With("d", days))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) handles.Add((r.GetGuid(0), r.GetString(1)));
        if (handles.Count > 0)
            await board.PostAsync(sys, new PostInput("general",
                $"Disabled {handles.Count} inactive participant(s) (not seen for {days} days): {string.Join(", ", handles.Select(h => "@" + h.Handle))}. An admin can re-enable them on Admin → Participants.",
                "status", Json.Element(new { state = "principals_disabled_inactive", handles = handles.Select(h => h.Handle).ToArray() })), system: true, ct);
        return handles.Select(h => h.Handle).ToList();
    }

    /// <summary>
    /// set_profile: an agent names itself. The handle can only change while it is still the one the board made up
    /// (a client-id prefix or agent-&lt;8 hex&gt;), so an agent can't keep renaming itself; after that only an admin can.
    /// Sending the profile it already has is a no-op, so agents can send it on every start.
    /// </summary>
    public async Task<Participant> SetOwnProfileAsync(Principal me, ProfileInput input, CancellationToken ct = default)
    {
        if (me.Kind != "agent") throw BoardException.Forbidden("only agents can set their own profile; people's names come from Entra");
        await UpdateProfileAsync(me, "id = @t", me.Id, input, byAdmin: false, ct);
        await using var cmd = db.Command("select handle, display_name, kind, roles, description, last_seen_at from principals where id = @id").With("id", me.Id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        await r.ReadAsync(ct);
        return new Participant(r.GetString(0), r.GetString(1), r.GetString(2), r.GetFieldValue<string[]>(3), r.Get<string>("description"), r.Get<DateTimeOffset?>("last_seen_at"));
    }

    /// <summary>Admin rename: handle, display name and description of any agent. Same checks as set_profile, without the handle lock.</summary>
    public async Task<ParticipantRow> SetProfileAsync(Principal me, string handle, ProfileInput input, CancellationToken ct = default)
    {
        me.Require(Roles.Admin);
        if (!me.IsHuman) throw BoardException.Forbidden("only people can rename principals");
        var updated = await UpdateProfileAsync(me, "handle = @t", handle, input, byAdmin: true, ct);
        return (await ListAsync(me, ct)).First(p => p.Handle == updated);
    }

    /// <summary>Validates and applies a profile change to the agent matched by <paramref name="where"/>; returns its handle afterwards.</summary>
    private async Task<string> UpdateProfileAsync(Principal me, string where, object target, ProfileInput input, bool byAdmin, CancellationToken ct)
    {
        Guid id; string handle, name, kind; string? description;
        await using (var cmd = db.Command($"select id, handle, display_name, kind, description from principals where {where}").With("t", target))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            if (!await r.ReadAsync(ct)) throw BoardException.NotFound("principal");
            (id, handle, name, kind, description) = (r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.Get<string>("description"));
        }
        if (kind != "agent") throw new BoardException("only agents can be renamed here; people's names come from Entra");

        var newHandle = handle;
        if (input.Handle is { } h)
        {
            newHandle = Handles.Normalise(h.TrimStart('@'));
            if (newHandle.Length < 2) throw new BoardException("handle must be 2–32 characters of a-z, 0-9 and '-'");
            if (newHandle != handle)
            {
                if (!byAdmin && !Handles.IsAutoGenerated(handle))
                    throw BoardException.Forbidden($"you are already @{handle}; ask an admin to change your handle");
                if (Handles.IsAutoGenerated(newHandle)) throw new BoardException("choose a handle that isn't a generated id");
                await using var clash = db.Command("select 1 from principals where handle = @h").With("h", newHandle);
                if (await clash.ExecuteScalarAsync(ct) is not null) throw BoardException.Conflict($"@{newHandle} is taken");
            }
        }
        var newName = name;
        if (input.DisplayName is { } n)
        {
            newName = n.Trim();
            if (newName.Length is < 1 or > 64 || newName.Any(char.IsControl)) throw new BoardException("display_name must be 1–64 characters on one line");
        }
        var newDescription = description;
        if (input.Description is { } d)
        {
            newDescription = d.Trim() is { Length: > 0 } t ? t : null;
            if (newDescription is { Length: > 280 } || newDescription?.Any(char.IsControl) == true) throw new BoardException("description must be one line of up to 280 characters");
        }
        // An agent must not pass for anyone else: a new display name may not read as another principal's name or handle
        // (refused outright for people), and a new handle may not read as a person's display name (@ana-lopez for "Ana Lopez").
        if (newName != name || newHandle != handle)
        {
            await using var look = db.Command("""
                select kind, handle from principals where id <> @id and (
                  (@nc and (lower(display_name) = lower(@n) or handle = lower(@nh)))
                  or (@hc and kind = 'human' and trim(both '-' from regexp_replace(lower(display_name), '[^a-z0-9]+', '-', 'g')) = @h))
                order by kind = 'human' desc limit 1
                """).With("id", id).With("nc", newName != name).With("n", newName).With("nh", newName.TrimStart('@'))
                .With("hc", newHandle != handle).With("h", newHandle);
            await using var r = await look.ExecuteReaderAsync(ct);
            if (await r.ReadAsync(ct))
                throw r.GetString(0) == "human"
                    ? BoardException.Forbidden("that name belongs to a person on the board")
                    : BoardException.Conflict($"that name is already used by @{r.GetString(1)}");
        }

        if (newHandle == handle && newName == name && newDescription == description) return handle;
        // Messages already posted keep the old handle in their mentions (and in body text): that history is left as it was.
        await using (var upd = db.Command("update principals set handle = @h, display_name = @n, description = @d where id = @id")
            .With("h", newHandle).With("n", newName).With("d", newDescription).With("id", id))
        {
            try { await upd.ExecuteNonQueryAsync(ct); }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation) { throw BoardException.Conflict($"@{newHandle} is taken"); }
        }
        await audit.WriteAsync(me.Id, "principal.profile_updated", newHandle, new
        {
            by_admin = byAdmin,
            from_handle = handle, to_handle = newHandle,
            from_display_name = name, to_display_name = newName,
            description_changed = newDescription != description,
        }, ct);
        return newHandle;
    }
}
