using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;

namespace Blueboard.Api.Actions;

/// <summary>Identifiers an action targets: checked against protected lists and the incident's evidence.</summary>
public sealed record Targets(string[] Users, string[] Devices, string[] Other)
{
    public static readonly Targets None = new([], [], []);
    public IEnumerable<string> All => Users.Concat(Devices).Concat(Other);
}

/// <summary>One brokered write. Params arrive as JSON and are validated into a normalised object before anything runs.</summary>
public sealed record ActionDef(
    string Kind,
    string Title,
    string Stage,
    bool Destructive,
    JsonObject ParamsSchema,
    Func<JsonElement, JsonObject> Validate,
    Func<JsonObject, Targets> TargetsOf,
    Func<JsonObject, string> Describe,
    Func<MsClient, JsonObject, string, CancellationToken, Task<object?>> Run);

/// <summary>
/// Every write the board can make in Defender, Entra and Sentinel. Agents only request these; the broker
/// runs them with the Function App's identity after policy and (usually) human approval.
/// </summary>
public static partial class Catalog
{
    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.IgnoreCase)] private static partial Regex MdeId();
    [GeneratedRegex(@"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[^\s/\\?#@]+@[^\s/\\?#@]+\.[^\s/\\?#@]+)$", RegexOptions.IgnoreCase)] private static partial Regex UserRef();
    [GeneratedRegex(@"^\d{1,20}$")] private static partial Regex IncidentId();
    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$")] private static partial Regex Email();

    // ── param helpers ──────────────────────────────────────────────────────────────────────────
    private static string Req(JsonElement p, string name, Regex? pattern = null, string? hint = null, int max = 2048)
    {
        if (p.ValueKind != JsonValueKind.Object || !p.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.String || v.GetString() is not { Length: > 0 } s)
            throw new BoardException($"{name} is required");
        if (s.Length > max || (pattern is not null && !pattern.IsMatch(s))) throw new BoardException($"invalid {name}{(hint is null ? "" : $": {hint}")}");
        return s;
    }

    private static string Enum(JsonElement p, string name, string[] allowed, string fallback)
    {
        if (p.ValueKind != JsonValueKind.Object || !p.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) return fallback;
        var s = v.GetString();
        return s is not null && allowed.Contains(s) ? s : throw new BoardException($"{name} must be one of {string.Join(", ", allowed)}");
    }

    private static string? Opt(JsonElement p, string name, int max)
    {
        if (p.ValueKind != JsonValueKind.Object || !p.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) return null;
        var s = v.ValueKind == JsonValueKind.String ? v.GetString() : throw new BoardException($"{name} must be a string");
        return s!.Length <= max ? s : throw new BoardException($"{name} too long");
    }

    private static JsonObject Schema(object properties, string[] required) =>
        JsonSerializer.SerializeToNode(new { type = "object", properties, required, additionalProperties = false })!.AsObject();

    private static string S(JsonObject o, string k) => o[k]!.GetValue<string>();
    private static string Comment(string c) => c.Length <= 900 ? c : c[..900];
    private static string Enc(string s) => Uri.EscapeDataString(s);

    private static readonly object MachineIdProp = new { type = "string", description = "MDE machine id (40 hex chars)", pattern = "^[0-9a-fA-F]{40}$" };
    private static readonly object UserProp = new { type = "string", description = "Entra user object id or UPN" };
    private static readonly object IncidentProp = new { type = "string", description = "Defender XDR incident id (digits)", pattern = "^[0-9]{1,20}$" };

    private static readonly Dictionary<string, string> IndicatorTypes = new()
    {
        ["sha256"] = "FileSha256", ["sha1"] = "FileSha1", ["md5"] = "FileMd5", ["ip"] = "IpAddress", ["domain"] = "DomainName", ["url"] = "Url",
    };

    public static readonly IReadOnlyDictionary<string, ActionDef> All = new ActionDef[]
    {
        new("isolate_device", "Isolate device (MDE)", "contain", true,
            Schema(new { machine_id = MachineIdProp, isolation_type = new { type = "string", @enum = new[] { "Full", "Selective" }, @default = "Full" } }, ["machine_id"]),
            p => new JsonObject { ["machine_id"] = Req(p, "machine_id", MdeId(), "MDE machine id (40 hex chars)"), ["isolation_type"] = Enum(p, "isolation_type", ["Full", "Selective"], "Full") },
            p => new Targets([], [S(p, "machine_id")], []),
            p => $"{S(p, "isolation_type")} network isolation of MDE device {S(p, "machine_id")}",
            (ms, p, c, ct) => Send(ms, MsApi.Defender, $"/api/machines/{S(p, "machine_id")}/isolate", HttpMethod.Post, new { Comment = Comment(c), IsolationType = S(p, "isolation_type") }, ct)),

        new("release_device", "Release device from isolation (MDE)", "recover", true,
            Schema(new { machine_id = MachineIdProp }, ["machine_id"]),
            p => new JsonObject { ["machine_id"] = Req(p, "machine_id", MdeId(), "MDE machine id (40 hex chars)") },
            p => new Targets([], [S(p, "machine_id")], []),
            p => $"Release MDE device {S(p, "machine_id")} from isolation",
            (ms, p, c, ct) => Send(ms, MsApi.Defender, $"/api/machines/{S(p, "machine_id")}/unisolate", HttpMethod.Post, new { Comment = Comment(c) }, ct)),

        new("run_av_scan", "Run antivirus scan (MDE)", "eradicate", false,
            Schema(new { machine_id = MachineIdProp, scan_type = new { type = "string", @enum = new[] { "Quick", "Full" }, @default = "Quick" } }, ["machine_id"]),
            p => new JsonObject { ["machine_id"] = Req(p, "machine_id", MdeId(), "MDE machine id (40 hex chars)"), ["scan_type"] = Enum(p, "scan_type", ["Quick", "Full"], "Quick") },
            p => new Targets([], [S(p, "machine_id")], []),
            p => $"{S(p, "scan_type")} Defender AV scan on {S(p, "machine_id")}",
            (ms, p, c, ct) => Send(ms, MsApi.Defender, $"/api/machines/{S(p, "machine_id")}/runAntiVirusScan", HttpMethod.Post, new { Comment = Comment(c), ScanType = S(p, "scan_type") }, ct)),

        new("collect_investigation_package", "Collect investigation package (MDE)", "contain", false,
            Schema(new { machine_id = MachineIdProp }, ["machine_id"]),
            p => new JsonObject { ["machine_id"] = Req(p, "machine_id", MdeId(), "MDE machine id (40 hex chars)") },
            p => new Targets([], [S(p, "machine_id")], []),
            p => $"Collect forensic investigation package from {S(p, "machine_id")}",
            (ms, p, c, ct) => Send(ms, MsApi.Defender, $"/api/machines/{S(p, "machine_id")}/collectInvestigationPackage", HttpMethod.Post, new { Comment = Comment(c) }, ct)),

        new("disable_user", "Disable user account (Entra ID)", "contain", true,
            Schema(new { user = UserProp }, ["user"]),
            p => new JsonObject { ["user"] = Req(p, "user", UserRef(), "Entra user object id or UPN", 200) },
            p => new Targets([S(p, "user")], [], []),
            p => $"Disable Entra ID account {S(p, "user")}",
            (ms, p, _, ct) => Send(ms, MsApi.Graph, $"/v1.0/users/{Enc(S(p, "user"))}", HttpMethod.Patch, new { accountEnabled = false }, ct)),

        new("revoke_sessions", "Revoke sign-in sessions (Entra ID)", "contain", true,
            Schema(new { user = UserProp }, ["user"]),
            p => new JsonObject { ["user"] = Req(p, "user", UserRef(), "Entra user object id or UPN", 200) },
            p => new Targets([S(p, "user")], [], []),
            p => $"Revoke all refresh tokens and sessions for {S(p, "user")}",
            (ms, p, _, ct) => Send(ms, MsApi.Graph, $"/v1.0/users/{Enc(S(p, "user"))}/revokeSignInSessions", HttpMethod.Post, null, ct)),

        new("reset_password", "Force password reset (Entra ID)", "eradicate", true,
            Schema(new { user = UserProp }, ["user"]),
            p => new JsonObject { ["user"] = Req(p, "user", UserRef(), "Entra user object id or UPN", 200) },
            p => new Targets([S(p, "user")], [], []),
            p => $"Set a random password on {S(p, "user")} and require a change at next sign-in (the password is never stored or shown)",
            async (ms, p, _, ct) =>
            {
                // Random, discarded: the point is to invalidate the known-compromised password.
                var password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', '-').Replace('/', '_') + "!a1";
                await ms.SendAsync(MsApi.Graph, $"/v1.0/users/{Enc(S(p, "user"))}", HttpMethod.Patch,
                    new { passwordProfile = new { forceChangePasswordNextSignIn = true, password } }, ct);
                return new { reset = true, forceChangePasswordNextSignIn = true };
            }),

        new("block_indicator", "Block indicator (Defender custom IOC)", "contain", true,
            Schema(new
            {
                indicator_type = new { type = "string", @enum = IndicatorTypes.Keys.ToArray() },
                value = new { type = "string", maxLength = 2048 },
                title = new { type = "string", minLength = 3, maxLength = 200 },
                severity = new { type = "string", @enum = new[] { "Informational", "Low", "Medium", "High" }, @default = "High" },
                expires_in_days = new { type = "integer", minimum = 1, maximum = 365, @default = 30 },
            }, ["indicator_type", "value", "title"]),
            p =>
            {
                var days = p.TryGetProperty("expires_in_days", out var d) && d.ValueKind == JsonValueKind.Number ? d.GetInt32() : 30;
                if (days is < 1 or > 365) throw new BoardException("expires_in_days must be 1–365");
                var title = Req(p, "title", max: 200);
                if (title.Length < 3) throw new BoardException("title must be at least 3 characters");
                return new JsonObject
                {
                    ["indicator_type"] = Enum(p, "indicator_type", IndicatorTypes.Keys.ToArray(), ""),
                    ["value"] = Req(p, "value"),
                    ["title"] = title,
                    ["severity"] = Enum(p, "severity", ["Informational", "Low", "Medium", "High"], "High"),
                    ["expires_in_days"] = days,
                };
            },
            p => new Targets([], [], [S(p, "value")]),
            p => $"Block {S(p, "indicator_type")} {S(p, "value")} tenant-wide for {p["expires_in_days"]} days",
            (ms, p, c, ct) =>
            {
                var t = S(p, "indicator_type");
                var isFile = t is "sha256" or "sha1" or "md5";
                return Send(ms, MsApi.Defender, "/api/indicators", HttpMethod.Post, new
                {
                    indicatorValue = S(p, "value"),
                    indicatorType = IndicatorTypes[t],
                    action = isFile ? "BlockAndRemediate" : "Block",
                    title = S(p, "title"),
                    description = Comment(c),
                    severity = S(p, "severity"),
                    generateAlert = true,
                    expirationTime = DateTimeOffset.UtcNow.AddDays(p["expires_in_days"]!.GetValue<int>()).ToString("O"),
                }, ct);
            }),

        new("purge_email", "Purge email (Defender for Office 365)", "eradicate", true,
            Schema(new
            {
                messages = new { type = "array", minItems = 1, maxItems = 100, items = new { type = "object", properties = new { network_message_id = new { type = "string" }, recipient = new { type = "string" } }, required = new[] { "network_message_id", "recipient" } } },
                action = new { type = "string", @enum = new[] { "softDelete", "hardDelete", "moveToJunk", "moveToDeletedItems" }, @default = "softDelete" },
            }, ["messages"]),
            p =>
            {
                if (!p.TryGetProperty("messages", out var list) || list.ValueKind != JsonValueKind.Array || list.GetArrayLength() is < 1 or > 100)
                    throw new BoardException("messages must have 1–100 entries");
                var arr = new JsonArray();
                foreach (var m in list.EnumerateArray())
                {
                    var id = Req(m, "network_message_id", max: 200);
                    if (id.Length < 8) throw new BoardException("invalid network_message_id");
                    arr.Add(new JsonObject { ["network_message_id"] = id, ["recipient"] = Req(m, "recipient", Email(), "email address", 320) });
                }
                return new JsonObject { ["messages"] = arr, ["action"] = Enum(p, "action", ["softDelete", "hardDelete", "moveToJunk", "moveToDeletedItems"], "softDelete") };
            },
            p =>
            {
                var msgs = p["messages"]!.AsArray();
                return new Targets(msgs.Select(m => m!["recipient"]!.GetValue<string>()).ToArray(), [], msgs.Select(m => m!["network_message_id"]!.GetValue<string>()).ToArray());
            },
            p => $"{S(p, "action")} {p["messages"]!.AsArray().Count} message(s) from recipient mailboxes",
            (ms, p, c, ct) => Send(ms, MsApi.Graph, "/beta/security/collaboration/analyzedEmails/remediate", HttpMethod.Post, new
            {
                displayName = $"blueboard: {(c.Length > 80 ? c[..80] : c)}",
                description = Comment(c),
                severity = "high",
                action = S(p, "action"),
                remediateSendersCopy = false,
                analyzedEmails = p["messages"]!.AsArray().Select(m => new { networkMessageId = m!["network_message_id"]!.GetValue<string>(), recipientEmailAddress = m["recipient"]!.GetValue<string>() }),
            }, ct)),

        new("update_incident", "Update / close incident (Defender XDR / Sentinel)", "record", true,
            Schema(new
            {
                incident_id = IncidentProp,
                status = new { type = "string", @enum = new[] { "active", "inProgress", "resolved", "redirected" } },
                classification = new { type = "string", @enum = new[] { "truePositive", "falsePositive", "informationalExpectedActivity", "unknown" } },
                determination = new { type = "string", maxLength = 100 },
                assigned_to = new { type = "string", maxLength = 200 },
            }, ["incident_id"]),
            p =>
            {
                var o = new JsonObject { ["incident_id"] = Req(p, "incident_id", IncidentId(), "Defender XDR incident id (digits)") };
                if (p.TryGetProperty("status", out _)) o["status"] = Enum(p, "status", ["active", "inProgress", "resolved", "redirected"], "");
                if (p.TryGetProperty("classification", out _)) o["classification"] = Enum(p, "classification", ["truePositive", "falsePositive", "informationalExpectedActivity", "unknown"], "");
                if (Opt(p, "determination", 100) is { } det) o["determination"] = det;
                if (Opt(p, "assigned_to", 200) is { } at) o["assigned_to"] = at;
                if (o.Count == 1) throw new BoardException("nothing to update");
                return o;
            },
            _ => Targets.None,
            p => $"Update incident {S(p, "incident_id")}: {string.Join(", ", p.Where(kv => kv.Key != "incident_id").Select(kv => $"{kv.Key}={kv.Value}"))}",
            (ms, p, _, ct) =>
            {
                var body = new Dictionary<string, string>();
                if (p["status"] is { } s) body["status"] = s.GetValue<string>();
                if (p["classification"] is { } cl) body["classification"] = cl.GetValue<string>();
                if (p["determination"] is { } d) body["determination"] = d.GetValue<string>();
                if (p["assigned_to"] is { } a) body["assignedTo"] = a.GetValue<string>();
                return Send(ms, MsApi.Graph, $"/v1.0/security/incidents/{Enc(S(p, "incident_id"))}", HttpMethod.Patch, body, ct);
            }),

        new("add_incident_comment", "Comment on incident (Defender XDR / Sentinel)", "record", false,
            Schema(new { incident_id = IncidentProp, comment = new { type = "string", minLength = 1, maxLength = 30000 } }, ["incident_id", "comment"]),
            p => new JsonObject { ["incident_id"] = Req(p, "incident_id", IncidentId(), "Defender XDR incident id (digits)"), ["comment"] = Req(p, "comment", max: 30000) },
            _ => Targets.None,
            p => $"Add a comment to incident {S(p, "incident_id")}",
            (ms, p, _, ct) => Send(ms, MsApi.Graph, $"/v1.0/security/incidents/{Enc(S(p, "incident_id"))}/comments", HttpMethod.Post,
                new Dictionary<string, string> { ["@odata.type"] = "microsoft.graph.security.alertComment", ["comment"] = S(p, "comment") }, ct)),
    }.ToDictionary(a => a.Kind);

    /// <summary>Incident-scoped kinds must be linked to, and aimed at, that same incident.</summary>
    public static readonly HashSet<string> IncidentScoped = ["update_incident", "add_incident_comment"];

    /// <summary>What a kind acts on: device, user, indicator, email or incident. The UI filters its action picker by this.</summary>
    public static string TargetType(string kind) => kind switch
    {
        "isolate_device" or "release_device" or "run_av_scan" or "collect_investigation_package" => "device",
        "disable_user" or "revoke_sessions" or "reset_password" => "user",
        "block_indicator" => "indicator",
        "purge_email" => "email",
        _ => "incident",
    };

    private static async Task<object?> Send(MsClient ms, MsApi api, string path, HttpMethod method, object? body, CancellationToken ct) =>
        await ms.SendAsync(api, path, method, body, ct);

    public static ActionDef Get(string kind) =>
        All.TryGetValue(kind, out var def) ? def : throw new BoardException($"unknown action kind {kind}");
}
