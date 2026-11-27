using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Blueboard.Api.Core;
using Blueboard.Api.Intel;

namespace Blueboard.Api.Actions;

/// <summary>What the broker knows about one action when it runs (for actions whose request depends on more than params).</summary>
public sealed record ActionContext(
    Guid ActionId, string? IncidentGraphId, Guid? IncidentId, string RequestedBy, string? DecidedBy, string Justification, TiSettings Ti, DateTimeOffset Now,
    // Data the kind's resolver looked up at execution time (Resolvers.cs), e.g. the Intune managed device id.
    JsonObject? Facts = null);

/// <summary>
/// STIX 2.1 indicators for the Microsoft Sentinel upload API (issue #20). Values are validated for their kind first,
/// then written as escaped STIX string literals, so a value can't break out of the pattern.
/// </summary>
public static class Stix
{
    public const string SourceSystem = "blueboard";
    public const string ApiVersion = "2024-02-01-preview";
    /// <summary>A fixed identity for the board (UUIDv5 of the repo URL), so every published indicator has the same creator.</summary>
    public const string IdentityId = "identity--605ed233-e247-54ed-bafe-b5c4614f0960";

    public static readonly string[] Kinds = ["ip", "domain", "url", "sha256", "sha1", "md5", "email"];

    /// <summary>TLP 1.0 marking definitions defined by STIX 2.1 (section 7.2.1.4).</summary>
    public static readonly IReadOnlyDictionary<string, string> Tlp = new Dictionary<string, string>
    {
        ["white"] = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
        ["green"] = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
        ["amber"] = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
        ["red"] = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
    };

    /// <summary>A STIX pattern string literal: single-quoted, with backslash and quote escaped.</summary>
    public static string Literal(string value)
    {
        if (value.Any(char.IsControl)) throw new BoardException("refusing control characters in a STIX value");
        return "'" + value.Replace("\\", "\\\\").Replace("'", "\\'") + "'";
    }

    /// <summary>[ipv4-addr:value = '203.0.113.5'], [file:hashes.'SHA-256' = '…'] and so on. Refuses values that don't fit the kind.</summary>
    public static string Pattern(string kind, string value)
    {
        if (!Kinds.Contains(kind)) throw new BoardException($"kind must be one of {string.Join(", ", Kinds)}");
        var v = Indicators.Normalise(kind, value) ?? throw new BoardException($"value is not a valid {kind}");
        var path = kind switch
        {
            "ip" => v.Contains(':') ? "ipv6-addr:value" : "ipv4-addr:value",
            "domain" => "domain-name:value",
            "url" => "url:value",
            "sha256" => "file:hashes.'SHA-256'",
            "sha1" => "file:hashes.'SHA-1'",
            "md5" => "file:hashes.MD5",
            _ => "email-addr:value",
        };
        return $"[{path} = {Literal(v)}]";
    }

    /// <summary>A stable indicator id per action, so a retry of the same action never creates a second indicator.</summary>
    public static string IndicatorId(Guid actionId)
    {
        var b = SHA256.HashData(Encoding.UTF8.GetBytes($"blueboard-stix:{actionId}"))[..16];
        b[6] = (byte)((b[6] & 0x0f) | 0x40); // version 4 layout
        b[8] = (byte)((b[8] & 0x3f) | 0x80); // RFC 4122 variant
        var hex = Convert.ToHexStringLower(b);
        return $"indicator--{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
    }

    private static string Ts(DateTimeOffset t) => t.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

    /// <summary>The exact upload request: workspace and body. Shown in full by the dry run.</summary>
    public static JsonObject UploadRequest(JsonObject p, ActionContext ctx)
    {
        var ws = ctx.Ti.SentinelWorkspaceId;
        if (ws is null || !Guid.TryParse(ws, out var wsId)) throw new BoardException("SENTINEL_WORKSPACE_ID is not set to the Log Analytics workspace id (a GUID)");
        var kind = p["kind"]!.GetValue<string>();
        var value = p["value"]!.GetValue<string>();
        var now = ctx.Now;
        var refs = new JsonArray();
        var reference = new JsonObject
        {
            ["source_name"] = SourceSystem,
            ["description"] = $"blueboard action {ctx.ActionId}" + (ctx.IncidentGraphId is null ? "" : $" for Defender incident {ctx.IncidentGraphId}"),
            ["external_id"] = ctx.IncidentGraphId ?? ctx.ActionId.ToString(),
        };
        if (ctx.Ti.BoardWebUrl is { } web && Uri.TryCreate(web, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps && ctx.IncidentId is { } iid)
            reference["url"] = $"{u.GetLeftPart(UriPartial.Authority)}/incidents/{iid}";
        refs.Add(reference);

        var labels = new JsonArray("blueboard");
        if (ctx.IncidentGraphId is { } g) labels.Add($"incident-{g}");
        var indicator = new JsonObject
        {
            ["type"] = "indicator",
            ["spec_version"] = "2.1",
            ["id"] = IndicatorId(ctx.ActionId),
            ["created"] = Ts(now),
            ["modified"] = Ts(now),
            ["created_by_ref"] = IdentityId,
            ["name"] = $"{kind} {value}".Length <= 200 ? $"{kind} {value}" : $"{kind} {value}"[..200],
            ["description"] = p["description"]!.GetValue<string>()
                              + $"\n\nConfirmed on blueboard: requested by {ctx.RequestedBy}, approved by {ctx.DecidedBy ?? "nobody (dry run)"}.",
            ["indicator_types"] = new JsonArray("malicious-activity"),
            ["pattern"] = Pattern(kind, value),
            ["pattern_type"] = "stix",
            ["pattern_version"] = "2.1",
            ["valid_from"] = Ts(now),
            ["valid_until"] = Ts(now.AddDays(p["valid_days"]!.GetValue<int>())),
            ["confidence"] = p["confidence"]!.GetValue<int>(),
            ["labels"] = labels,
            ["external_references"] = refs,
            ["object_marking_refs"] = new JsonArray(Tlp[p["tlp"]!.GetValue<string>()]),
        };
        var identity = new JsonObject
        {
            ["type"] = "identity",
            ["spec_version"] = "2.1",
            ["id"] = IdentityId,
            ["created"] = "2026-11-19T00:00:00.000Z",
            ["modified"] = "2026-11-19T00:00:00.000Z",
            ["name"] = "blueboard",
            ["identity_class"] = "system",
        };
        return new JsonObject
        {
            ["method"] = "POST",
            ["url"] = $"https://api.ti.sentinel.azure.com/workspaces/{wsId}/threat-intelligence-stix-objects:upload?api-version={ApiVersion}",
            ["workspace_id"] = wsId.ToString(),
            ["body"] = new JsonObject { ["sourcesystem"] = SourceSystem, ["stixobjects"] = new JsonArray(identity, indicator) },
        };
    }
}
