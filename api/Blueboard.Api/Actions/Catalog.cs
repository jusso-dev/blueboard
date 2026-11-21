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
    Func<MsClient, JsonObject, string, CancellationToken, Task<object?>> Run,
    // Builds the exact outbound request from params plus broker context. When set, the dry run shows it in full and
    // Run receives it instead of the params (publish_ti_indicator).
    Func<JsonObject, ActionContext, JsonObject>? Prepare = null);

/// <summary>
/// Every write the board can make in Defender, Entra and Sentinel. Agents only request these; the broker
/// runs them with the Function App's identity after policy and (usually) human approval.
/// </summary>
public static partial class Catalog
{
    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.IgnoreCase)] private static partial Regex MdeId();
    [GeneratedRegex(@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase)] private static partial Regex GuidId();
    [GeneratedRegex(@"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[^\s/\\?#@]+@[^\s/\\?#@]+\.[^\s/\\?#@]+)$", RegexOptions.IgnoreCase)] private static partial Regex UserRef();
    [GeneratedRegex(@"^\d{1,20}$")] private static partial Regex IncidentId();
    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$")] private static partial Regex Email();
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._ -]{0,199}$")] private static partial Regex DeviceTag();

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

    private static int Int(JsonElement p, string name, int? fallback, int min, int max)
    {
        if (p.ValueKind != JsonValueKind.Object || !p.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null)
            return fallback ?? throw new BoardException($"{name} is required");
        if (v.ValueKind != JsonValueKind.Number || !v.TryGetInt32(out var n) || n < min || n > max) throw new BoardException($"{name} must be a whole number {min}–{max}");
        return n;
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

        new("restrict_app_execution", "Restrict app execution to Microsoft-signed binaries (MDE)", "contain", true,
            Schema(new { machine_id = MachineIdProp }, ["machine_id"]),
            p => new JsonObject { ["machine_id"] = Req(p, "machine_id", MdeId(), "MDE machine id (40 hex chars)") },
            p => new Targets([], [S(p, "machine_id")], []),
            p => $"Restrict code execution to Microsoft-signed binaries on MDE device {S(p, "machine_id")}",
            (ms, p, c, ct) => Send(ms, MsApi.Defender, $"/api/machines/{S(p, "machine_id")}/restrictCodeExecution", HttpMethod.Post, new { Comment = Comment(c) }, ct)),

        new("unrestrict_app_execution", "Remove app execution restriction (MDE)", "recover", true,
            Schema(new { machine_id = MachineIdProp }, ["machine_id"]),
            p => new JsonObject { ["machine_id"] = Req(p, "machine_id", MdeId(), "MDE machine id (40 hex chars)") },
            p => new Targets([], [S(p, "machine_id")], []),
            p => $"Remove code execution restriction on MDE device {S(p, "machine_id")}",
            (ms, p, c, ct) => Send(ms, MsApi.Defender, $"/api/machines/{S(p, "machine_id")}/unrestrictCodeExecution", HttpMethod.Post, new { Comment = Comment(c) }, ct)),

        new("stop_and_quarantine_file", "Stop process and quarantine file (MDE)", "eradicate", true,
            Schema(new
            {
                machine_id = MachineIdProp,
                sha1 = new { type = "string", description = "File SHA-1 hash (40 hex chars)", pattern = "^[0-9a-fA-F]{40}$" },
            }, ["machine_id", "sha1"]),
            p => new JsonObject
            {
                ["machine_id"] = Req(p, "machine_id", MdeId(), "MDE machine id (40 hex chars)"),
                ["sha1"] = Req(p, "sha1", MdeId(), "SHA-1 hash (40 hex chars)").ToLowerInvariant(),
            },
            p => new Targets([], [S(p, "machine_id")], [S(p, "sha1")]),
            p => $"Stop and quarantine SHA-1 {S(p, "sha1")} on MDE device {S(p, "machine_id")}",
            (ms, p, c, ct) => Send(ms, MsApi.Defender, $"/api/machines/{S(p, "machine_id")}/StopAndQuarantineFile", HttpMethod.Post, new { Comment = Comment(c), Sha1 = S(p, "sha1") }, ct)),

        new("tag_device", "Add or remove device tag (MDE)", "contain", false,
            Schema(new
            {
                machine_id = MachineIdProp,
                tag = new { type = "string", minLength = 1, maxLength = 200, description = "Device tag (e.g. UnderInvestigation, Compromised)" },
                action = new { type = "string", @enum = new[] { "Add", "Remove" }, @default = "Add" },
            }, ["machine_id", "tag"]),
            p => new JsonObject
            {
                ["machine_id"] = Req(p, "machine_id", MdeId(), "MDE machine id (40 hex chars)"),
                ["tag"] = Req(p, "tag", DeviceTag(), "letters, digits, spaces, '.', '_' or '-'", 200),
                ["action"] = Enum(p, "action", ["Add", "Remove"], "Add"),
            },
            p => new Targets([], [S(p, "machine_id")], []),
            p => $"{S(p, "action")} tag '{S(p, "tag")}' on MDE device {S(p, "machine_id")}",
            (ms, p, _, ct) => Send(ms, MsApi.Defender, $"/api/machines/{S(p, "machine_id")}/tags", HttpMethod.Post, new { Value = S(p, "tag"), Action = S(p, "action") }, ct)),

        new("disable_user", "Disable user account (Entra ID)", "contain", true,
            Schema(new { user = UserProp }, ["user"]),
            p => new JsonObject { ["user"] = Req(p, "user", UserRef(), "Entra user object id or UPN", 200) },
            p => new Targets([S(p, "user")], [], []),
            p => $"Disable Entra ID account {S(p, "user")}",
            (ms, p, _, ct) => Send(ms, MsApi.Graph, $"/v1.0/users/{Enc(S(p, "user"))}", HttpMethod.Patch, new { accountEnabled = false }, ct)),

        new("enable_user", "Re-enable user account (Entra ID)", "recover", true,
            Schema(new { user = UserProp }, ["user"]),
            p => new JsonObject { ["user"] = Req(p, "user", UserRef(), "Entra user object id or UPN", 200) },
            p => new Targets([S(p, "user")], [], []),
            p => $"Re-enable Entra ID account {S(p, "user")}",
            (ms, p, _, ct) => Send(ms, MsApi.Graph, $"/v1.0/users/{Enc(S(p, "user"))}", HttpMethod.Patch, new { accountEnabled = true }, ct)),

        new("confirm_user_compromised", "Confirm user compromised (Entra ID Protection)", "contain", true,
            Schema(new { user_id = new { type = "string", description = "Entra user object id (GUID)" } }, ["user_id"]),
            p => new JsonObject { ["user_id"] = Req(p, "user_id", GuidId(), "Entra user object id (GUID)", 64).ToLowerInvariant() },
            p => new Targets([S(p, "user_id")], [], []),
            p => $"Mark Entra user {S(p, "user_id")} as High risk (compromised) in Entra ID Protection",
            (ms, p, _, ct) => Send(ms, MsApi.Graph, "/v1.0/identityProtection/riskyUsers/confirmCompromised", HttpMethod.Post, new { userIds = new[] { S(p, "user_id") } }, ct)),

        new("dismiss_user_risk", "Dismiss user risk (Entra ID Protection)", "recover", true,
            Schema(new { user_id = new { type = "string", description = "Entra user object id (GUID)" } }, ["user_id"]),
            p => new JsonObject { ["user_id"] = Req(p, "user_id", GuidId(), "Entra user object id (GUID)", 64).ToLowerInvariant() },
            p => new Targets([S(p, "user_id")], [], []),
            p => $"Dismiss Entra ID Protection risk for user {S(p, "user_id")}",
            (ms, p, _, ct) => Send(ms, MsApi.Graph, "/v1.0/identityProtection/riskyUsers/dismiss", HttpMethod.Post, new { userIds = new[] { S(p, "user_id") } }, ct)),

        new("disable_service_principal", "Disable service principal / OAuth app (Entra ID)", "contain", true,
            Schema(new { service_principal_id = new { type = "string", description = "Entra service principal object id (GUID)" } }, ["service_principal_id"]),
            p => new JsonObject { ["service_principal_id"] = Req(p, "service_principal_id", GuidId(), "Entra service principal object id (GUID)", 64).ToLowerInvariant() },
            p => new Targets([], [], [S(p, "service_principal_id")]),
            p => $"Disable Entra service principal {S(p, "service_principal_id")} (stops sign-ins and token issuance)",
            (ms, p, _, ct) => Send(ms, MsApi.Graph, $"/v1.0/servicePrincipals/{Enc(S(p, "service_principal_id"))}", HttpMethod.Patch, new { accountEnabled = false }, ct)),

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
                var kind = Enum(p, "indicator_type", IndicatorTypes.Keys.ToArray(), "");
                var value = Intel.Indicators.Normalise(kind, Req(p, "value")) ?? throw new BoardException($"value is not a valid {kind}");
                var days = Int(p, "expires_in_days", 30, 1, 365);
                var title = Req(p, "title", max: 200);
                if (title.Length < 3) throw new BoardException("title must be at least 3 characters");
                return new JsonObject
                {
                    ["indicator_type"] = kind,
                    ["value"] = value,
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

        new("unblock_indicator", "Remove custom indicator block (MDE)", "recover", true,
            Schema(new { indicator_id = new { type = "string", description = "Defender custom indicator id (digits)", pattern = "^[0-9]{1,20}$" } }, ["indicator_id"]),
            p => new JsonObject { ["indicator_id"] = Req(p, "indicator_id", IncidentId(), "Defender indicator id (digits)") },
            _ => Targets.None,
            p => $"Remove Defender custom indicator {S(p, "indicator_id")}",
            (ms, p, _, ct) => Send(ms, MsApi.Defender, $"/api/indicators/{Enc(S(p, "indicator_id"))}", HttpMethod.Delete, null, ct)),

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
                if (p.TryGetProperty("status", out var sv) && sv.ValueKind != JsonValueKind.Null) o["status"] = Enum(p, "status", ["active", "inProgress", "resolved", "redirected"], "");
                if (p.TryGetProperty("classification", out var cv) && cv.ValueKind != JsonValueKind.Null) o["classification"] = Enum(p, "classification", ["truePositive", "falsePositive", "informationalExpectedActivity", "unknown"], "");
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

        new("publish_ti_indicator", "Publish indicator to Sentinel threat intelligence (preview API)", "contain", true,
            Schema(new
            {
                kind = new { type = "string", @enum = Stix.Kinds },
                value = new { type = "string", maxLength = 2048 },
                confidence = new { type = "integer", minimum = 0, maximum = 100 },
                valid_days = new { type = "integer", minimum = 1, maximum = 90, @default = 30 },
                tlp = new { type = "string", @enum = Stix.Tlp.Keys.ToArray(), @default = "amber" },
                description = new { type = "string", minLength = 10, maxLength = 2000 },
            }, ["kind", "value", "confidence", "description"]),
            p =>
            {
                var kind = Enum(p, "kind", Stix.Kinds, "");
                var value = Intel.Indicators.Normalise(kind, Req(p, "value")) ?? throw new BoardException($"value is not a valid {kind}");
                var confidence = Int(p, "confidence", null, 0, 100);
                var days = Int(p, "valid_days", 30, 1, 90);
                var description = Req(p, "description", max: 2000);
                if (description.Length < 10) throw new BoardException("description must be at least 10 characters");
                return new JsonObject
                {
                    ["kind"] = kind, ["value"] = value, ["confidence"] = confidence, ["valid_days"] = days,
                    ["tlp"] = Enum(p, "tlp", Stix.Tlp.Keys.ToArray(), "amber"), ["description"] = description,
                };
            },
            p => new Targets([], [], [S(p, "value")]),
            p => $"Publish {S(p, "kind")} {S(p, "value")} to Microsoft Sentinel threat intelligence (confidence {p["confidence"]}, valid {p["valid_days"]} days, TLP:{S(p, "tlp").ToUpperInvariant()})",
            async (ms, req, _, ct) =>
            {
                var ws = S(req, "workspace_id");
                var body = req["body"]!.AsObject();
                var id = body["stixobjects"]!.AsArray().Last()!["id"]!.GetValue<string>();
                JsonElement? res;
                try
                {
                    res = await ms.SendAsync(MsApi.SentinelTi, $"/workspaces/{Enc(ws)}/threat-intelligence-stix-objects:upload?api-version={Stix.ApiVersion}", HttpMethod.Post, body, ct);
                }
                catch (BoardException ex) when (ex.UpstreamStatus is 401 or 403)
                {
                    throw new BoardException($"Microsoft Sentinel Contributor not assigned on workspace {ws}", 502) { UpstreamStatus = ex.UpstreamStatus };
                }
                // The upload API answers 200 even when objects fail validation, listing them under errors[].
                if (res is { } r && r.TryGetProperty("errors", out var errs) && errs.ValueKind == JsonValueKind.Array && errs.GetArrayLength() > 0)
                {
                    var text = errs.GetRawText();
                    throw new BoardException($"Sentinel rejected the indicator: {(text.Length > 500 ? text[..500] : text)}", 502);
                }
                return new
                {
                    stix_id = id,
                    workspace_id = ws,
                    find_in_sentinel = $"ThreatIntelIndicators | where SourceSystem == \"{Stix.SourceSystem}\" and Id has \"{id["indicator--".Length..]}\"",
                    note = "Indicators can take a few minutes to appear in Threat intelligence (Defender portal) and in ThreatIntelIndicators.",
                };
            },
            Prepare: Stix.UploadRequest),

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
        "isolate_device" or "release_device" or "run_av_scan" or "collect_investigation_package"
            or "restrict_app_execution" or "unrestrict_app_execution" or "stop_and_quarantine_file" or "tag_device" => "device",
        "disable_user" or "enable_user" or "revoke_sessions" or "reset_password"
            or "confirm_user_compromised" or "dismiss_user_risk" or "disable_service_principal" => "user",
        "block_indicator" or "unblock_indicator" or "publish_ti_indicator" => "indicator",
        "purge_email" => "email",
        _ => "incident",
    };

    /// <summary>Kinds whose value must already be confirmed malicious by an ioc message on the linked incident.</summary>
    public static readonly HashSet<string> NeedsMaliciousIoc = ["publish_ti_indicator"];

    private static async Task<object?> Send(MsClient ms, MsApi api, string path, HttpMethod method, object? body, CancellationToken ct) =>
        await ms.SendAsync(api, path, method, body, ct);

    public static ActionDef Get(string kind) =>
        All.TryGetValue(kind, out var def) ? def : throw new BoardException($"unknown action kind {kind}");
}
