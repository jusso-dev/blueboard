using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Core;

namespace Blueboard.Api.Board;

/// <summary>Validates and normalises typed message payloads (ioc, verdict, finding, status).</summary>
public static class Payloads
{
    private static readonly string[] IocKinds = ["ip", "domain", "url", "sha1", "sha256", "md5", "email", "user", "device", "cve"];
    private static readonly string[] IocVerdicts = ["malicious", "suspicious", "benign", "unknown"];
    private static readonly string[] Classifications = ["truePositive", "falsePositive", "informationalExpectedActivity", "unknown"];

    public const int MaxPayloadBytes = 65_536;

    public static JsonElement Validate(string type, JsonElement payload, bool system = false)
    {
        if (payload.ValueKind != JsonValueKind.Object) throw new BoardException($"invalid {type} payload: must be an object");
        if (payload.GetRawText().Length > MaxPayloadBytes) throw new BoardException("payload must be at most 64 KB");
        var validated = type switch
        {
            "ioc" => Ioc(payload),
            "verdict" => Verdict(payload),
            "finding" => Finding(payload),
            "status" => Status(payload, system),
            _ => payload,
        };
        if (payload.TryGetProperty("gif", out var gifEl) && gifEl.ValueKind != JsonValueKind.Null)
        {
            var cleanGif = Gifs.ValidatePayload(gifEl);
            var node = JsonNode.Parse(validated.GetRawText())!.AsObject();
            node["gif"] = cleanGif;
            return JsonSerializer.SerializeToElement(node);
        }
        return validated;
    }

    private static JsonElement Ioc(JsonElement p)
    {
        if (!p.TryGetProperty("indicators", out var list) || list.ValueKind != JsonValueKind.Array)
            throw new BoardException("invalid ioc payload: indicators[] required");
        var n = list.GetArrayLength();
        if (n is < 1 or > 200) throw new BoardException("invalid ioc payload: 1–200 indicators");
        var output = new JsonArray();
        foreach (var i in list.EnumerateArray())
        {
            var kind = Str(i, "kind");
            var value = Str(i, "value");
            if (kind is null || !IocKinds.Contains(kind)) throw new BoardException($"invalid ioc kind '{kind}'");
            if (value is null || value.Length is < 1 or > 2048) throw new BoardException("invalid ioc value");
            // CVE ids are stored upper case so search and /intel match them exactly, like hashes.
            if (kind == "cve") value = Intel.Indicators.NormaliseCve(value) ?? throw new BoardException("invalid ioc value: cve must look like CVE-2024-12345");
            var verdict = Str(i, "verdict") ?? "unknown";
            if (!IocVerdicts.Contains(verdict)) throw new BoardException($"invalid ioc verdict '{verdict}'");
            var o = new JsonObject { ["kind"] = kind, ["value"] = value, ["verdict"] = verdict };
            if (Str(i, "source") is { Length: <= 200 } src) o["source"] = src;
            output.Add(o);
        }
        var result = new JsonObject { ["indicators"] = output };
        if (TimelineEvents(p, "ioc") is { } events) result["events"] = events;
        return JsonSerializer.SerializeToElement(result);
    }

    public const int MaxTimelineEvents = 200;

    /// <summary>
    /// Optional attack-timeline events on a finding or ioc payload: [{ts, entity, action, source?, ref?}]. Returns the
    /// normalised array (unknown keys dropped), null when absent, or throws. These are a participant's claims: the
    /// timeline shows them as reported, never as Defender evidence.
    /// </summary>
    internal static JsonArray? TimelineEvents(JsonElement p, string type, DateTimeOffset? now = null)
    {
        if (!p.TryGetProperty("events", out var list) || list.ValueKind == JsonValueKind.Null) return null;
        if (list.ValueKind != JsonValueKind.Array) throw new BoardException($"invalid {type} payload: events must be an array");
        var n = list.GetArrayLength();
        if (n is < 1 or > MaxTimelineEvents) throw new BoardException($"invalid {type} payload: 1–{MaxTimelineEvents} events");
        var latest = (now ?? DateTimeOffset.UtcNow).AddMinutes(5);
        var output = new JsonArray();
        var i = 0;
        foreach (var e in list.EnumerateArray())
        {
            i++;
            if (e.ValueKind != JsonValueKind.Object) throw new BoardException($"invalid {type} payload: events[{i - 1}] must be an object");
            var tsText = Str(e, "ts");
            if (tsText is null || !DateTimeOffset.TryParse(tsText, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeUniversal, out var ts))
                throw new BoardException($"invalid {type} payload: events[{i - 1}].ts must be an ISO-8601 time");
            if (ts > latest) throw new BoardException($"invalid {type} payload: events[{i - 1}].ts is in the future");
            if (ts.Year < 2000) throw new BoardException($"invalid {type} payload: events[{i - 1}].ts is before 2000");
            var entity = Clean(Str(e, "entity"));
            var action = Clean(Str(e, "action"));
            if (entity is not { Length: >= 1 and <= 512 }) throw new BoardException($"invalid {type} payload: events[{i - 1}].entity must be 1–512 characters");
            if (action is not { Length: >= 1 and <= 300 }) throw new BoardException($"invalid {type} payload: events[{i - 1}].action must be 1–300 characters");
            var o = new JsonObject { ["ts"] = ts.ToUniversalTime().ToString("O"), ["entity"] = entity, ["action"] = action };
            if (Clean(Str(e, "source")) is { Length: > 0 } src)
                o["source"] = src.Length <= 200 ? src : throw new BoardException($"invalid {type} payload: events[{i - 1}].source must be at most 200 characters");
            if (Clean(Str(e, "ref")) is { Length: > 0 } r)
                o["ref"] = r.Length <= 500 ? r : throw new BoardException($"invalid {type} payload: events[{i - 1}].ref must be at most 500 characters");
            output.Add(o);
        }
        return output;
    }

    /// <summary>One line, trimmed, no control characters (timeline text is shown in tables and Markdown).</summary>
    private static string? Clean(string? s) =>
        s is null ? null : new string(s.Select(c => char.IsControl(c) ? ' ' : c).ToArray()).Trim();

    private static JsonElement Verdict(JsonElement p)
    {
        var c = Str(p, "classification");
        if (c is null || !Classifications.Contains(c)) throw new BoardException("invalid verdict payload: classification");
        if (!p.TryGetProperty("confidence", out var conf) || conf.ValueKind != JsonValueKind.Number || conf.GetDouble() is < 0 or > 1)
            throw new BoardException("invalid verdict payload: confidence must be 0–1");
        var o = new JsonObject { ["classification"] = c, ["confidence"] = conf.GetDouble() };
        if (Str(p, "determination") is { Length: <= 100 } d) o["determination"] = d;
        return JsonSerializer.SerializeToElement(o);
    }

    private static JsonElement Finding(JsonElement p)
    {
        if (p.TryGetProperty("confidence", out var conf) && (conf.ValueKind != JsonValueKind.Number || conf.GetDouble() is < 0 or > 1))
            throw new BoardException("invalid finding payload: confidence must be 0–1");
        if (TimelineEvents(p, "finding") is not { } events) return p;
        var node = JsonNode.Parse(p.GetRawText())!.AsObject();
        node["events"] = events;
        return JsonSerializer.SerializeToElement(node);
    }

    private static JsonElement Status(JsonElement p, bool system)
    {
        if (Str(p, "state") is not { Length: > 0 and <= 100 } state) throw new BoardException("invalid status payload: state required");
        if (!system && IsReservedStatusState(state))
            throw new BoardException($"status state '{state}' is reserved for the board");
        return p;
    }

    internal static bool IsReservedStatusState(string state) =>
        state.StartsWith("action_", StringComparison.OrdinalIgnoreCase)
        || state.StartsWith("broker_", StringComparison.OrdinalIgnoreCase)
        || state.StartsWith("principal_", StringComparison.OrdinalIgnoreCase)
        || state.Equals("source_updated", StringComparison.OrdinalIgnoreCase)
        || state.Equals("followup", StringComparison.OrdinalIgnoreCase);

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
