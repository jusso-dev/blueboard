using System.Text;
using System.Text.Json;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Auth;

/// <summary>
/// Resolves the caller of a request to a board principal.
///  1. Bearer token (agents, and any client calling the Function App directly): validated Entra JWT.
///  2. x-ms-client-principal (browsers via the linked Static Web App): only when TRUST_SWA_PRINCIPAL,
///     which is set only when the Function App accepts traffic solely from its linked SWA.
///  3. Local development: Bearer dev:&lt;handle&gt; / x-dev-principal (DEV_AUTH, refused in Azure).
/// Roles come from Entra on every request; a disabled principal is refused.
/// </summary>
public sealed class Authenticator(Settings settings, TokenValidator tokens, Db db, Audit audit)
{
    public async Task<Principal> AuthenticateAsync(IReadOnlyDictionary<string, string> headers, bool bearerOnly = false, CancellationToken ct = default)
    {
        var auth = headers.GetValueOrDefault("authorization");
        if (auth is not null && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = auth[7..].Trim();
            if (settings.DevAuth && token.StartsWith("dev:", StringComparison.Ordinal)) return await DevPrincipalAsync(token[4..], ct);
            return await UpsertAsync(await tokens.ValidateAsync(token, ct), ct);
        }
        if (!bearerOnly && settings.TrustSwaPrincipal && headers.GetValueOrDefault("x-ms-client-principal") is { } swa)
            return await UpsertAsync(FromSwaPrincipal(swa), ct);
        if (settings.DevAuth && headers.GetValueOrDefault("x-dev-principal") is { } dev)
            return await DevPrincipalAsync(dev, ct);
        throw BoardException.Unauthorized();
    }

    /// <summary>
    /// Parses x-ms-client-principal. Two shapes reach the Function App, depending on which layer wrote it:
    ///  - Static Web Apps: { identityProvider, userId, userDetails, userRoles[], claims[{typ,val}] }
    ///  - App Service built-in auth: { auth_typ, claims[{typ,val}], name_typ, role_typ }
    /// The header is only trusted when TRUST_SWA_PRINCIPAL is set, which deploy.sh sets only together with
    /// built-in auth on the Function App (App Service strips client-sent x-ms-* headers).
    /// Roles come from Entra "roles" claims and from SWA userRoles (filled by /api/swa-roles at sign-in).
    /// </summary>
    internal static CallerIdentity FromSwaPrincipal(string header)
    {
        using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(header)));
        var root = doc.RootElement;
        var idp = root.TryGetProperty("identityProvider", out var i) ? i.GetString()
                  : root.TryGetProperty("auth_typ", out var a) ? a.GetString() : null;
        if (idp is not ("aad" or "azureactivedirectory"))
            throw BoardException.Unauthorized("only Microsoft Entra sign-in is accepted");

        var claims = new List<(string Typ, string Val)>();
        if (root.TryGetProperty("claims", out var cl) && cl.ValueKind == JsonValueKind.Array)
            foreach (var c in cl.EnumerateArray())
                if (c.TryGetProperty("typ", out var t) && c.TryGetProperty("val", out var v) && t.GetString() is { } ts && v.GetString() is { } vs)
                    claims.Add((ts, vs));
        string? Claim(params string[] types) => claims.FirstOrDefault(c => types.Contains(c.Typ)).Val;

        var roleTyp = root.TryGetProperty("role_typ", out var rt) ? rt.GetString() : null;
        var roles = claims.Where(c => c.Typ is "roles" or "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" || c.Typ == roleTyp)
            .Select(c => c.Val).ToList();
        if (root.TryGetProperty("userRoles", out var ur) && ur.ValueKind == JsonValueKind.Array)
            roles.AddRange(ur.EnumerateArray().Select(r => r.GetString()).OfType<string>());

        var oid = Claim("http://schemas.microsoft.com/identity/claims/objectidentifier", "oid")
                  ?? throw BoardException.Unauthorized("principal has no oid");
        var username = Claim("preferred_username", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")
                       ?? (root.TryGetProperty("userDetails", out var ud) ? ud.GetString() : null);
        return new CallerIdentity(oid, null, "human", Claim("name") ?? username ?? oid, username, TokenValidator.MapRoles(roles, "human"));
    }

    private async Task<Principal> DevPrincipalAsync(string handle, CancellationToken ct)
    {
        await using var cmd = db.Command("select id, handle, display_name, kind, roles, enabled from principals where handle = @h").With("h", handle);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct) || !r.GetBoolean(5)) throw BoardException.Unauthorized($"unknown dev principal {handle}");
        return new Principal(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetFieldValue<string[]>(4));
    }

    private async Task<Principal> UpsertAsync(CallerIdentity id, CancellationToken ct)
    {
        await using (var cmd = db.Command("update principals set roles = @r, last_seen_at = now() where entra_oid = @o returning id, handle, display_name, kind, roles, enabled")
                         .With("r", id.Roles).With("o", id.Oid))
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
        await using var rd = await ins.ExecuteReaderAsync(ct);
        await rd.ReadAsync(ct);
        var p = new Principal(rd.GetGuid(0), rd.GetString(1), rd.GetString(2), rd.GetString(3), rd.GetFieldValue<string[]>(4));
        await rd.DisposeAsync();
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
