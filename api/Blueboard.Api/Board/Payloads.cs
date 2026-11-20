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

    public static JsonElement Validate(string type, JsonElement payload)
    {
        if (payload.ValueKind != JsonValueKind.Object) throw new BoardException($"invalid {type} payload: must be an object");
        return type switch
        {
            "ioc" => Ioc(payload),
            "verdict" => Verdict(payload),
            "finding" => Finding(payload),
            "status" => Status(payload),
            _ => payload,
        };
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
        return JsonSerializer.SerializeToElement(new JsonObject { ["indicators"] = output });
    }

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
        return p;
    }

    private static JsonElement Status(JsonElement p)
    {
        if (Str(p, "state") is not { Length: > 0 and <= 100 }) throw new BoardException("invalid status payload: state required");
        return p;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
