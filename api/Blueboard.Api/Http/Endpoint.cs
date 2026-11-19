using System.Text.Json;
using Blueboard.Api.Auth;
using Blueboard.Api.Core;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Blueboard.Api.Http;

/// <summary>
/// Shared plumbing for HTTP functions: authenticate, require a role, map errors, write snake_case JSON.
/// Every caller sends an Entra bearer token (MSAL in the browser, workload identity for agents). There are no
/// cookies, so cross-site request forgery has nothing to ride on.
/// </summary>
public sealed class Endpoint(Authenticator auth, ILogger<Endpoint> log)
{
    public async Task<IActionResult> RunAsync(HttpRequest req, Func<Principal, Task<object?>> handler, string? role = Roles.Poster)
    {
        try
        {
            var headers = req.Headers.ToDictionary(h => h.Key.ToLowerInvariant(), h => h.Value.ToString());
            var me = await auth.AuthenticateAsync(headers, req.HttpContext.RequestAborted);
            if (role is not null) me.Require(role);
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

    public static async Task<T> BodyAsync<T>(HttpRequest req)
    {
        if (req.ContentLength is > 1_000_000) throw new BoardException("body too large", 413);
        return await JsonSerializer.DeserializeAsync<T>(req.Body, Json.Options, req.HttpContext.RequestAborted)
               ?? throw new BoardException("body required");
    }

    private static ContentResult Error(int status, string message) =>
        new() { Content = Json.Serialize(new { error = message }), ContentType = "application/json", StatusCode = status };
}
