using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Auth;
using Blueboard.Api.Core;
using Blueboard.Api.Mcp;
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
/// <remarks>
/// Agents may call REST with their workload token as well as MCP, so an agent's REST call passes the same observability
/// hook as an MCP tool (<see cref="McpObserver"/>): the hard budget cap before the handler, then metering, the
/// tool-call trace and risk inputs, labelled "rest:METHOD /api/route". People are never budgeted or traced here.
/// </remarks>
public sealed class Endpoint(Authenticator auth, ILogger<Endpoint> log, McpObserver? observer = null)
{
    public async Task<IActionResult> RunAsync(HttpRequest req, Func<Principal, Task<object?>> handler, string? role = Roles.Poster)
    {
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        Principal? me = null;
        string? label = null;
        JsonElement? args = null;
        object? result = null;
        IActionResult response;
        var status = "ok";
        string? error = null;
        try
        {
            var headers = req.Headers.ToDictionary(h => h.Key.ToLowerInvariant(), h => h.Value.ToString());
            me = await auth.AuthenticateAsync(headers, req.HttpContext.RequestAborted);
            if (observer is not null && !me.IsHuman)
            {
                label = RouteLabel(req.Method, req.Path);
                args = await PeekArgumentsAsync(req);
            }
            if (role is not null) me.Require(role);
            if (label is not null)
                await observer!.BeforeRestAsync(me, label, label == McpObserver.RestClaim && args is { } a && a.TryGetProperty("body", out var b) ? McpObserver.ClaimOp(b) : null,
                    req.HttpContext.RequestAborted);
            result = await handler(me);
            response = result switch
            {
                IActionResult r => r,
                null => new NoContentResult(),
                _ => new ContentResult { Content = Json.Serialize(result), ContentType = "application/json", StatusCode = 200 },
            };
        }
        catch (BoardException ex)
        {
            if (ex.RetryAfterSeconds is { } retry) req.HttpContext.Response.Headers.RetryAfter = retry.ToString(System.Globalization.CultureInfo.InvariantCulture);
            (status, error) = (McpObserver.StatusOf(ex), ex.Message);
            response = Error(ex.Status, ex.Message);
        }
        catch (ContractException ex)
        {
            (status, error) = ("invalid", ex.Message);
            response = Error(400, ex.Message);
        }
        catch (JsonException)
        {
            (status, error) = ("invalid", "invalid JSON body");
            response = Error(400, "invalid JSON body");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogError(ex, "unhandled error in {Path}", req.Path);
            (status, error) = ("error", "internal error");
            response = Error(500, "internal error");
        }
        if (label is not null && me is not null)
            await observer!.AfterAsync(new Agents.TraceEntry(me, label, status, args, error,
                (int)System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds,
                response is ContentResult { Content: { } c } ? System.Text.Encoding.UTF8.GetByteCount(c) : 0, McpObserver.MessageIdOf(result)));
        return response;
    }

    /// <summary>
    /// "rest:METHOD /api/route" for an agent's REST call: ids (GUIDs, digits, Okta-style ids) become {id}, so the label
    /// names the route, not the record. Public for tests.
    /// </summary>
    public static string RouteLabel(string method, PathString path)
    {
        var segments = (path.Value ?? "").Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Select(s => Guid.TryParse(s, out _) || s.All(char.IsAsciiDigit) ? "{id}" : s.Length > 40 ? "{id}" : s);
        return $"rest:{method.ToUpperInvariant()} /{string.Join('/', segments)}";
    }

    /// <summary>
    /// The agent call's query and JSON body as trace arguments ({"query": {...}, "body": {...}}), read from a buffered
    /// copy so the handler still reads the body. Never throws: a body that isn't JSON is simply not summarised.
    /// </summary>
    private static async Task<JsonElement?> PeekArgumentsAsync(HttpRequest req)
    {
        var o = new JsonObject();
        if (req.Query.Count > 0)
            o["query"] = new JsonObject(req.Query.Take(30).Select(q => KeyValuePair.Create(q.Key, (JsonNode?)q.Value.ToString())));
        if (req.ContentLength is > 0 and <= 1_000_000 || (req.ContentLength is null && req.Method is "POST" or "PUT" or "PATCH"))
        {
            req.EnableBuffering();
            try { o["body"] = JsonNode.Parse((await ReadJsonAsync(req)).GetRawText()); }
            catch (Exception ex) when (ex is BoardException or JsonException) { }
            finally { req.Body.Position = 0; }
        }
        return o.Count == 0 ? null : JsonSerializer.SerializeToElement(o);
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
