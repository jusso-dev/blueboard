using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Board;

namespace Blueboard.Api.Agents;

/// <summary>
/// Turns MCP tool arguments into a small, redacted summary for the trace. Never stores secrets or result payloads:
/// any string the board's secret-leak detector flags is replaced, keys that name credentials are dropped, strings are
/// cut to a short excerpt, lists and depth are capped, and the whole summary is capped at <see cref="MaxBytes"/>.
/// KQL for hunting tools is kept in full (up to 10,000 characters) unless it carries a secret.
/// </summary>
public static class TraceRedactor
{
    public const int MaxBytes = 4096;
    public const int MaxString = 160;
    public const int MaxItems = 10;
    public const int MaxDepth = 3;
    public const string Redacted = "[redacted: secret]";

    /// <summary>Tools whose "query" argument is KQL worth showing in the trace.</summary>
    public static readonly HashSet<string> KqlTools = ["run_hunting_query", "run_sentinel_query"];

    private static readonly string[] SensitiveKeyParts = ["secret", "password", "passwd", "token", "authorization", "credential", "api_key", "apikey", "private_key", "signing", "cookie", "session_key"];

    public static bool IsSensitiveKey(string key)
    {
        var k = key.ToLowerInvariant();
        return SensitiveKeyParts.Any(k.Contains);
    }

    /// <summary>The redacted argument summary (null for no arguments).</summary>
    public static JsonObject? Summarise(JsonElement? args)
    {
        if (args is not { ValueKind: JsonValueKind.Object } a) return null;
        var o = (JsonObject)Node(a, 0)!;
        if (o.Count == 0) return null;
        // Cap the total: drop the largest fields until it fits, then say so.
        while (o.ToJsonString().Length > MaxBytes && o.Count > 0)
        {
            var biggest = o.OrderByDescending(kv => kv.Value?.ToJsonString().Length ?? 0).First().Key;
            o.Remove(biggest);
            o["_truncated"] = true;
        }
        return o;
    }

    /// <summary>The KQL text of a hunting call, or null (other tools, or the query carries a secret).</summary>
    public static string? Kql(string tool, JsonElement? args)
    {
        if (!KqlTools.Contains(tool) || args is not { ValueKind: JsonValueKind.Object } a) return null;
        if (!a.TryGetProperty("query", out var q) || q.ValueKind != JsonValueKind.String) return null;
        var text = q.GetString()!;
        if (BoardService.DetectSecretLeak(text) is not null) return null;
        return text.Length > 10_000 ? text[..10_000] : text;
    }

    private static JsonNode? Node(JsonElement e, int depth)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Object:
                if (depth >= MaxDepth) return $"{{object, {e.EnumerateObject().Count()} keys}}";
                var o = new JsonObject();
                foreach (var p in e.EnumerateObject().Take(30))
                    o[p.Name] = IsSensitiveKey(p.Name) ? "[redacted]" : Node(p.Value, depth + 1);
                return o;
            case JsonValueKind.Array:
                if (depth >= MaxDepth) return $"[list, {e.GetArrayLength()} items]";
                var arr = new JsonArray();
                foreach (var x in e.EnumerateArray().Take(MaxItems)) arr.Add(Node(x, depth + 1));
                if (e.GetArrayLength() > MaxItems) arr.Add($"… {e.GetArrayLength() - MaxItems} more");
                return arr;
            case JsonValueKind.String:
                return Text(e.GetString()!);
            case JsonValueKind.Number:
                return JsonNode.Parse(e.GetRawText());
            case JsonValueKind.True:
            case JsonValueKind.False:
                return e.GetBoolean();
            default:
                return null;
        }
    }

    /// <summary>A short, single-line, secret-free excerpt of a string argument.</summary>
    public static string Text(string s)
    {
        if (BoardService.DetectSecretLeak(s) is not null) return Redacted;
        var one = new string(s.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
        return one.Length <= MaxString ? one : $"{one[..MaxString]}… ({s.Length} chars)";
    }
}
