using System.Text;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

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
        Principal p;
        // Scoped, not disposed twice: a data-source reader's second dispose can hit a pooled connection another request now owns.
        await using (var cmd = db.Command("select id, handle, display_name, kind, roles, enabled from principals where handle = @h").With("h", handle))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            if (!await r.ReadAsync(ct) || !r.GetBoolean(5)) throw BoardException.Unauthorized($"unknown dev principal {handle}");
            p = new Principal(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetFieldValue<string[]>(4));
        }
        await using (var touch = db.Command(string.Format(TouchSql, "id = @id")).With("r", p.Roles).With("id", p.Id))
            await touch.ExecuteNonQueryAsync(ct);
        return p;
    }

    /// <summary>
    /// last_seen_at is written at most once a minute per principal (PERF-01): the update below only touches the row
    /// when roles changed or the last write is older than a minute, so steady polling doesn't write on every request.
    /// </summary>
    internal const string TouchSql = """
        with p as (select id, handle, display_name, kind, roles, enabled, last_seen_at from principals where {0})
        update principals t set roles = @r, last_seen_at = now()
        from p where t.id = p.id and (p.roles is distinct from @r::text[] or p.last_seen_at is null or p.last_seen_at < now() - interval '1 minute')
        returning t.id
        """;

    private async Task<Principal> UpsertAsync(CallerIdentity id, CancellationToken ct)
    {
        await using (var touch = db.Command(string.Format(TouchSql, "entra_oid = @o")).With("r", id.Roles).With("o", id.Oid))
            await touch.ExecuteNonQueryAsync(ct);
        await using (var cmd = db.Command("select id, handle, display_name, kind, roles, enabled from principals where entra_oid = @o").With("o", id.Oid))
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            if (await r.ReadAsync(ct))
            {
                if (!r.GetBoolean(5)) throw BoardException.Forbidden("principal disabled");
                return new Principal(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetFieldValue<string[]>(4));
            }
        }
        var handle = Handles.For(id);
        await using (var clash = db.Command("select 1 from principals where handle = @h").With("h", handle))
            if (await clash.ExecuteScalarAsync(ct) is not null) handle = $"{handle}-{id.Oid[..6]}";

        await using var ins = db.Command("""
            insert into principals (handle, display_name, kind, entra_oid, entra_app_id, roles, last_seen_at)
            values (@h, @n, @k, @o, @a, @r, now())
            on conflict (entra_oid) do update set roles = excluded.roles, last_seen_at = now()
            returning id, handle, display_name, kind, roles
            """).With("h", handle).With("n", id.Name).With("k", id.Kind).With("o", id.Oid).With("a", id.AppId).With("r", id.Roles);
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

internal static class Handles
{
    public static string For(CallerIdentity id)
    {
        var src = (id.Username?.Split('@')[0] ?? id.Name).ToLowerInvariant();
        var sb = new StringBuilder();
        foreach (var ch in src) sb.Append(char.IsAsciiLetterOrDigit(ch) ? ch : '-');
        var h = System.Text.RegularExpressions.Regex.Replace(sb.ToString(), "-+", "-").Trim('-');
        if (h.Length > 32) h = h[..32].TrimEnd('-');
        return h.Length > 0 ? h : $"{id.Kind}-{id.Oid[..8]}";
    }
}
