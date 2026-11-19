using System.Text.Json;
using Blueboard.Api.Auth;
using Blueboard.Api.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Blueboard.Api.Http;

/// <summary>Shared plumbing for HTTP functions: authenticate, require a role, map errors, write snake_case JSON.</summary>
public sealed class Endpoint(Authenticator auth, ILogger<Endpoint> log)
{
    public async Task<IActionResult> RunAsync(HttpRequest req, Func<Principal, Task<object?>> handler, string? role = Roles.Poster, bool mutates = false)
    {
        try
        {
            var headers = req.Headers.ToDictionary(h => h.Key.ToLowerInvariant(), h => h.Value.ToString());
            var me = await auth.AuthenticateAsync(headers, ct: req.HttpContext.RequestAborted);
            if (role is not null) me.Require(role);
            if (mutates) AssertSameOrigin(req);
            var result = await handler(me);
            return result switch
            {
                IActionResult r => r,
                null => new NoContentResult(),
                _ => new ContentResult { Content = Json.Serialize(result), ContentType = "application/json", StatusCode = 200 },
            };
        }
        catch (BoardException ex)
        {
            return Error(ex.Status, ex.Message);
        }
        catch (JsonException)
        {
            return Error(400, "invalid JSON body");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogError(ex, "unhandled error in {Path}", req.Path);
            return Error(500, "internal error");
        }
    }

    /// <summary>
    /// Browser writes arrive through the Static Web App with its auth cookie; refuse cross-site requests
    /// (CSRF). Bearer-token callers (agents, scripts) are exempt.
    /// </summary>
    internal static void AssertSameOrigin(HttpRequest req)
    {
        if (req.Headers.Authorization.Count > 0) return;
        var origin = req.Headers.Origin.ToString();
        var host = req.Headers["x-forwarded-host"].ToString() is { Length: > 0 } fh ? fh : req.Host.Value;
        if (string.IsNullOrEmpty(origin) || !Uri.TryCreate(origin, UriKind.Absolute, out var o) || !string.Equals(o.Authority, host, StringComparison.OrdinalIgnoreCase))
            throw BoardException.Forbidden("cross-origin request refused");
    }

    public static async Task<T> BodyAsync<T>(HttpRequest req)
    {
        if (req.ContentLength is > 1_000_000) throw new BoardException("body too large", 413);
        return await JsonSerializer.DeserializeAsync<T>(req.Body, Json.Options, req.HttpContext.RequestAborted)
               ?? throw new BoardException("body required");
    }

    private static ContentResult Error(int status, string message) =>
        new() { Content = Json.Serialize(new { error = message }), ContentType = "application/json", StatusCode = status };
}
