using System.Text.Json;
using Blueboard.Api.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Blueboard.Api.Http;

/// <summary>
/// Static Web Apps "rolesSource": called by SWA (not by browsers) after each Entra sign-in with the
/// user's ID-token claims. Returns the user's Entra app roles (Board.*) as SWA roles, so they reach the
/// API in x-ms-client-principal.userRoles. It only echoes roles already in the signed token: it grants nothing.
/// </summary>
public sealed class SwaRoles
{
    [Function("swa-roles")]
    public static async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "swa-roles")] HttpRequest req)
    {
        using var doc = await JsonDocument.ParseAsync(req.Body);
        var roles = new List<string>();
        if (doc.RootElement.TryGetProperty("claims", out var claims) && claims.ValueKind == JsonValueKind.Array)
            foreach (var c in claims.EnumerateArray())
                if (c.TryGetProperty("typ", out var t) && t.GetString() is "roles" or "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
                    && c.TryGetProperty("val", out var v) && v.GetString() is { } role && Roles.FromAppRole.ContainsKey(role))
                    roles.Add(role);
        return new ContentResult { Content = Json.Serialize(new { roles = roles.Distinct() }), ContentType = "application/json", StatusCode = 200 };
    }
}
