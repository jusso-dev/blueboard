using System.Text;
using System.Text.RegularExpressions;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Npgsql;

namespace Blueboard.Api.Auth;

/// <summary>
/// Resolves the caller of a request to a board principal.
///  1. Bearer token: a validated Microsoft Entra access token for the board API. Browsers get one with
///     MSAL (delegated, scope Board.Access); agents use their workload identity (app-only).
///  2. Local development only: Bearer dev:&lt;handle&gt; / x-dev-principal (DEV_AUTH, refused in Azure).
/// There is no cookie or platform header path, so nothing a client sets can stand in for a token.
/// Roles come from Entra on every request; a disabled principal is refused.
/// </summary>
public sealed class Authenticator(Settings settings, TokenValidator tokens, Db db, Audit audit)
{
    public async Task<Principal> AuthenticateAsync(IReadOnlyDictionary<string, string> headers, CancellationToken ct = default)
    {
        var auth = headers.GetValueOrDefault("authorization");
        if (auth is not null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = auth[7..].Trim();
            if (settings.DevAuth && token.StartsWith("dev:", StringComparison.Ordinal)) return await DevPrincipalAsync(token[4..], ct);
            return await UpsertAsync(await tokens.ValidateAsync(token, ct), ct);
        }
        if (settings.DevAuth && headers.GetValueOrDefault("x-dev-principal") is { } dev)
            return await DevPrincipalAsync(dev, ct);
        throw BoardException.Unauthorized();
    }

    private async Task<Principal> DevPrincipalAsync(string handle, CancellationToken ct)
    {
        // Local development: one statement reads the principal and records activity like the Entra path does (at most
        // once a minute, PERF-01), so last-seen works on the admin pages. One statement keeps the pooled connection simple.
        await using var cmd = db.Command("""
            with p as (select id from principals where handle = @h),
            touched as (
              update principals t set last_seen_at = now() from p
              where t.id = p.id and t.enabled and (t.last_seen_at is null or t.last_seen_at < now() - interval '1 minute')
              returning t.id)
            select id, handle, display_name, kind, roles, enabled from principals where handle = @h
            """).With("h", handle);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) throw BoardException.Unauthorized($"unknown dev principal {handle}");
        if (!r.GetBoolean(5)) throw BoardException.Forbidden("principal disabled");
        return new Principal(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetFieldValue<string[]>(4));
    }

    /// <summary>
    /// last_seen_at is written at most once a minute per principal (PERF-01): the update below only touches the row
    /// when roles changed or the last write is older than a minute, so steady polling doesn't write on every request.
    /// </summary>
    internal const string TouchSql = """
        with p as (select id, handle, display_name, kind, roles, enabled, last_seen_at from principals where {0} for update)
        update principals t set roles = @r, last_seen_at = now(), username = coalesce(@u, t.username)
        from p where t.id = p.id and p.enabled and (p.roles is distinct from @r::text[] or p.last_seen_at is null or p.last_seen_at < now() - interval '1 minute')
        returning t.id, t.handle, p.roles as old_roles
        """;

    /// <summary>
    /// Board roles come from Entra on every token; the board can't grant them. When a principal's roles differ from what
    /// the board last saw, that is recorded once (principal.roles_changed, old and new), so a grant or removal made in
    /// Entra (group membership, PIM activation, app role assignment) shows in the audit trail at its first use.
    /// </summary>
    internal static (string[] Added, string[] Removed) RoleDelta(string[] before, string[] after) =>
        (after.Except(before, StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray(),
         before.Except(after, StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray());

    /// <summary>A person's sign-in name (preferred_username, usually the UPN) for notification routing. Never stored for agents.</summary>
    internal static string? HumanUsername(CallerIdentity id) =>
        id.Kind == "human" && id.Username is { Length: > 0 and <= 254 } u && !u.Any(char.IsControl) ? u : null;

    internal async Task<Principal> UpsertAsync(CallerIdentity id, CancellationToken ct)
    {
        {
            // Updating the cached roles and recording the change must commit together. Lock the old row so concurrent
            // requests cannot both report the same change, or lose the old roles while waiting for another update.
            await using var conn = await db.OpenAsync(ct);
            await using var tx = await conn.BeginTransactionAsync(ct);
            (Guid Id, string Handle, string[] Before)? changed = null;
            await using (var touch = new NpgsqlCommand(string.Format(TouchSql, "entra_oid = @o"), conn, tx).With("r", id.Roles).With("o", id.Oid).With("u", HumanUsername(id)))
            await using (var tr = await touch.ExecuteReaderAsync(ct))
            {
                if (await tr.ReadAsync(ct))
                {
                    var before = tr.GetFieldValue<string[]>(2);
                    if (!before.ToHashSet(StringComparer.Ordinal).SetEquals(id.Roles)) changed = (tr.GetGuid(0), tr.GetString(1), before);
                }
            }
            if (changed is { } c)
            {
                var (added, removed) = RoleDelta(c.Before, id.Roles);
                await using var log = new NpgsqlCommand("insert into audit_log (actor_id, event, subject, detail) values (@a, 'principal.roles_changed', @s, @d)", conn, tx)
                    .With("a", c.Id).With("s", c.Handle).WithJson("d", new { added, removed, roles = id.Roles, source = "entra_token" });
                await log.ExecuteNonQueryAsync(ct);
            }
            await tx.CommitAsync(ct);
        }
        await using (var cmd = db.Command("select id, handle, display_name, kind, roles, enabled from principals where entra_oid = @o").With("o", id.Oid))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            if (await r.ReadAsync(ct))
            {
                if (!r.GetBoolean(5)) throw BoardException.Forbidden("principal disabled");
                return new Principal(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), id.Roles);
            }
        }
        var (handle, name) = Handles.Default(id);
        await using (var clash = db.Command("select 1 from principals where handle = @h").With("h", handle))
            if (await clash.ExecuteScalarAsync(ct) is not null) handle = $"{handle}-{id.Oid[..6]}";

        await using var ins = db.Command("""
            insert into principals (handle, display_name, kind, entra_oid, entra_app_id, roles, last_seen_at, username)
            values (@h, @n, @k, @o, @a, @r, now(), @u)
            on conflict (entra_oid) do update set roles = excluded.roles, last_seen_at = now(), username = coalesce(excluded.username, principals.username)
            returning id, handle, display_name, kind, roles
            """).With("h", handle).With("n", name).With("k", id.Kind).With("o", id.Oid).With("a", id.AppId).With("r", id.Roles).With("u", HumanUsername(id));
        Principal p;
        await using (var rd = await ins.ExecuteReaderAsync(ct))
        {
            await rd.ReadAsync(ct);
            p = new Principal(rd.GetGuid(0), rd.GetString(1), rd.GetString(2), rd.GetString(3), rd.GetFieldValue<string[]>(4));
        }
        await audit.WriteAsync(p.Id, "principal.joined", p.Handle, new { kind = id.Kind, app_id = id.AppId }, ct);
        return p;
    }
}

internal static partial class Handles
{
    /// <summary>Handles the board makes up when a token carries no usable name: a client-id prefix, or agent-&lt;8 hex&gt; (with a clash suffix).</summary>
    [GeneratedRegex("^[0-9a-f]{8}(-[0-9a-f]+)+$|^agent-[0-9a-f]{8}(-[0-9a-f]{6})?$")]
    private static partial Regex AutoGenerated();

    public static string For(CallerIdentity id)
    {
        var h = Normalise(id.Username?.Split('@')[0] ?? id.Name);
        return h.Length > 0 ? h : $"{id.Kind}-{id.Oid[..8]}";
    }

    /// <summary>Lowercase a-z and 0-9; any run of other characters becomes one '-'; trimmed to at most 32 characters.</summary>
    public static string Normalise(string src)
    {
        var sb = new StringBuilder();
        foreach (var ch in src.ToLowerInvariant()) sb.Append(char.IsAsciiLetterOrDigit(ch) ? ch : '-');
        var h = Regex.Replace(sb.ToString(), "-+", "-").Trim('-');
        return h.Length > 32 ? h[..32].TrimEnd('-') : h;
    }

    public static bool IsAutoGenerated(string handle) => AutoGenerated().IsMatch(handle);

    /// <summary>
    /// Handle and display name for a first sign-in. Entra v2 app-only tokens carry no name or app_displayname, so the
    /// name would be the client id: those agents get agent-&lt;first 8 of the app id&gt; / "Agent &lt;first 8&gt;" until they
    /// send a profile (set_profile) or an admin renames them.
    /// </summary>
    public static (string Handle, string Name) Default(CallerIdentity id)
    {
        if (id.Kind != "agent" || !Guid.TryParse(id.Name, out _)) return (For(id), id.Name);
        var app = Normalise(id.AppId ?? id.Oid).Replace("-", "");
        var prefix = app[..Math.Min(8, app.Length)];
        return ($"agent-{prefix}", $"Agent {prefix}");
    }
}
