using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Auth;
using Blueboard.Api.Core;
using Blueboard.Contracts;
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
            if (ex.RetryAfterSeconds is { } retry) req.HttpContext.Response.Headers.RetryAfter = retry.ToString(System.Globalization.CultureInfo.InvariantCulture);
            return Error(ex.Status, ex.Message);
        }
        catch (ContractException ex)
        {
            return Error(400, ex.Message);
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

    /// <summary>Reads a JSON body with a hard streaming byte cap (enforced even under chunked transfer encoding).</summary>
    public static async Task<JsonElement> ReadJsonAsync(HttpRequest req, int maxBytes = 1_000_000)
    {
        if (req.ContentLength is > 0 && req.ContentLength > maxBytes) throw new BoardException("body too large", 413);
        using var ms = new MemoryStream();
        var buf = new byte[Math.Min(16_384, maxBytes + 1)];
        int n;
        while ((n = await req.Body.ReadAsync(buf.AsMemory(0, buf.Length), req.HttpContext.RequestAborted)) > 0)
        {
            if (ms.Length + n > maxBytes) throw new BoardException("body too large", 413);
            ms.Write(buf, 0, n);
        }
        if (ms.Length == 0) throw new BoardException("body required");
        ms.Position = 0;
        using var doc = await JsonDocument.ParseAsync(ms, default, req.HttpContext.RequestAborted);
        return doc.RootElement.Clone();
    }

    /// <summary>Reads and validates a JSON body against its contract record.</summary>
    public static async Task<T> BodyAsync<T>(HttpRequest req) where T : class =>
        Contract.Read<T>(await ReadJsonAsync(req, 1_000_000));

    /// <summary>
    /// Reads and validates the query string against a contract record: booleans become true/false, list fields take
    /// every repeated value, and everything else is a string the contract parses (numbers, ids, dates).
    /// </summary>
    public static T Query<T>(HttpRequest req, IReadOnlyDictionary<string, string>? aliases = null) where T : class =>
        Contract.Read<T>(QueryJson<T>(req.Query.ToDictionary(q => q.Key, q => q.Value.OfType<string>().ToArray()), aliases));

    internal static JsonElement QueryJson<T>(IReadOnlyDictionary<string, string[]> query, IReadOnlyDictionary<string, string>? aliases = null)
    {
        var o = new JsonObject();
        var ctor = typeof(T).GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
        foreach (var p in ctor.GetParameters())
        {
            var name = JsonNamingPolicy.SnakeCaseLower.ConvertName(p.Name!);
            var key = query.ContainsKey(name) ? name : aliases?.FirstOrDefault(a => a.Value == name).Key;
            if (key is null || !query.TryGetValue(key, out var values)) continue;
            var nonEmpty = values.Where(v => v.Length > 0).ToArray();
            if (nonEmpty.Length == 0) continue;
            var t = Nullable.GetUnderlyingType(p.ParameterType) ?? p.ParameterType;
            o[name] = t == typeof(string[]) ? new JsonArray(nonEmpty.Select(v => (JsonNode)v).ToArray())
                : t == typeof(bool) ? nonEmpty[0] == "true"
                : nonEmpty[0];
        }
        return JsonSerializer.SerializeToElement(o);
    }

    private static ContentResult Error(int status, string message) =>
        new() { Content = Json.Serialize(new { error = message }), ContentType = "application/json", StatusCode = status };
}

/// <summary>Marks the contract a REST function reads, for the OpenAPI document. One attribute per route.</summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class RouteDocAttribute(string summary) : Attribute
{
    public string Summary { get; } = summary;
    /// <summary>Request record read from the query string.</summary>
    public Type? Query { get; init; }
    /// <summary>Request record read from the JSON body.</summary>
    public Type? Body { get; init; }
    /// <summary>Response type (an array is shown as a list).</summary>
    public Type? Response { get; init; }
    /// <summary>Board role needed (null: authenticated only, "public": no auth).</summary>
    public string? Role { get; init; } = Roles.Poster;
}

internal static class RouteInfo
{
    public static IEnumerable<(MethodInfo Method, RouteDocAttribute Doc)> All(Type type) =>
        type.GetMethods().Select(m => (m, m.GetCustomAttribute<RouteDocAttribute>())).Where(x => x.Item2 is not null)!;
}
