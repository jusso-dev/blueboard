using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;
using Blueboard.Api.Intel;

namespace Blueboard.Api.Actions;

/// <summary>
/// Detection engineering (create / disable a custom detection) and Intune patching kinds. Each one builds the exact
/// outbound request in Prepare (shown in full in a dry run) and runs it with <see cref="RunPrepared"/>.
/// API versions, checked against Microsoft Learn on 27-11-2026:
///  - Defender XDR custom detections: Graph v1.0 /security/rules/detectionRules (CustomDetection.ReadWrite.All).
///  - Sentinel scheduled analytics rules: ARM Microsoft.SecurityInsights/alertRules api-version 2025-09-01 (Microsoft Sentinel Contributor).
///  - Intune syncDevice / windowsDefenderUpdateSignatures: Graph v1.0 (DeviceManagementManagedDevices.PrivilegedOperations.All).
///  - Windows Autopatch expedited quality updates: Graph **beta** /admin/windows/updates (WindowsUpdates.ReadWrite.All); beta only.
/// </summary>
public static partial class Catalog
{
    public const string SentinelRulesApiVersion = "2025-09-01";
    public const string RuleTag = "[blueboard]";

    [GeneratedRegex(@"^/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/[A-Za-z0-9._()-]{1,90}/providers/Microsoft\.OperationalInsights/workspaces/[A-Za-z0-9][A-Za-z0-9-]{2,62}$")]
    public static partial Regex WorkspaceResourceId();
    [GeneratedRegex(@"^T\d{4}(\.\d{3})?$")] private static partial Regex Technique();
    [GeneratedRegex(@"^[A-Za-z0-9-]{8,128}$")] private static partial Regex CatalogEntryId();
    [GeneratedRegex(@"^[^\p{C}]{3,200}$")] private static partial Regex RuleName();

    /// <summary>
    /// Schema constants for these kinds. A nested class, so they are initialised before <see cref="All"/> reads them
    /// (static field order across partial-class files is not defined).
    /// </summary>
    public static class Rules
    {
        public static readonly string[] Frequencies = ["PT1H", "PT3H", "PT12H", "P1D"];
        public static readonly string[] Lookbacks = ["PT1H", "PT3H", "PT12H", "P1D", "P2D", "P7D", "P14D"];
        public static readonly string[] Severities = ["informational", "low", "medium", "high"];
        public static readonly string[] Tactics =
        [
            "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence", "PrivilegeEscalation", "DefenseEvasion",
            "CredentialAccess", "Discovery", "LateralMovement", "Collection", "Exfiltration", "CommandAndControl", "Impact",
        ];

        /// <summary>
        /// (entity, field) → Graph entityMappingConfiguration collection + column property, and Sentinel (entityType, identifier).
        /// Sentinel is null where it has no matching identifier (an MDE device id; a file hash needs two columns).
        /// </summary>
        public static readonly IReadOnlyDictionary<string, (string GraphSet, string GraphProp, string? SentinelType, string? SentinelId)> EntityFields =
            new Dictionary<string, (string, string, string?, string?)>
            {
                ["host.device_id"] = ("hosts", "deviceIdColumn", null, null),
                ["host.name"] = ("hosts", "nameColumn", "Host", "FullName"),
                ["account.upn"] = ("accounts", "upnColumn", "Account", "FullName"),
                ["account.name"] = ("accounts", "nameColumn", "Account", "Name"),
                ["account.aad_user_id"] = ("accounts", "aadUserIdColumn", "Account", "AadUserId"),
                ["ip.address"] = ("ips", "addressColumn", "IP", "Address"),
                ["url.address"] = ("urls", "addressColumn", "URL", "Url"),
                ["file.name"] = ("files", "nameColumn", "File", "Name"),
                ["file.sha1"] = ("files", "sha1Column", null, null),
                ["file.sha256"] = ("files", "sha256Column", null, null),
            };

        public static readonly object DeviceProps = new
        {
            machine_id = new { type = "string", description = "MDE machine id (40 hex chars). Give this or managed_device_id", pattern = "^[0-9a-fA-F]{40}$" },
            managed_device_id = new { type = "string", description = "Intune managed device id (GUID). Give this or machine_id", pattern = "^[0-9a-fA-F-]{36}$" },
        };
    }

    private static IEnumerable<ActionDef> DetectionAndPatchKinds() =>
    [
        new("create_detection_rule", "Create custom detection rule (Defender XDR / Sentinel)", "record", false,
            Schema(new
            {
                target = new { type = "string", @enum = new[] { "defender", "sentinel" }, description = "defender: Defender XDR custom detection (Graph). sentinel: scheduled analytics rule in the configured workspace (ARM)" },
                name = new { type = "string", minLength = 3, maxLength = 200 },
                description = new { type = "string", maxLength = 1000 },
                query = new { type = "string", minLength = 5, maxLength = 10000, description = "The exact KQL that was back-tested (same text, so the same SHA-256)" },
                frequency = new { type = "string", @enum = Rules.Frequencies, @default = "PT1H" },
                lookback = new { type = "string", @enum = Rules.Lookbacks, description = "Sentinel queryPeriod (at least frequency). Defender derives the lookback from frequency" },
                severity = new { type = "string", @enum = Rules.Severities, @default = "medium" },
                mitre = new
                {
                    type = "array", maxItems = 5,
                    items = new { type = "object", properties = new { tactic = new { type = "string", @enum = Rules.Tactics }, techniques = new { type = "array", maxItems = 10, items = new { type = "string", pattern = @"^T\d{4}(\.\d{3})?$" } } }, required = new[] { "tactic" } },
                },
                entity_mappings = new
                {
                    type = "array", maxItems = 10,
                    items = new { type = "object", properties = new { entity = new { type = "string", @enum = Rules.EntityFields.Keys.ToArray() }, column = new { type = "string", pattern = "^[A-Za-z_][A-Za-z0-9_]{0,99}$" } }, required = new[] { "entity", "column" } },
                },
                enabled = new { type = "boolean", @default = true },
                backtest_id = new { type = "string", description = "backtest_id from backtest_detection for this exact query and target, at least 7 days, from the 24 hours before this request", pattern = "^[0-9a-fA-F-]{36}$" },
            }, ["target", "name", "query", "backtest_id"]),
            ValidateCreateRule,
            _ => Targets.None,
            p => $"Create {S(p, "target")} detection rule '{S(p, "name")}' ({S(p, "severity")}, every {S(p, "frequency")}"
                 + (S(p, "target") == "sentinel" ? $", looking back {S(p, "lookback")}" : "") + $", {(p["enabled"]!.GetValue<bool>() ? "enabled" : "created disabled")}) "
                 + $"from back-test {S(p, "backtest_id")}, query sha256 {DetectionService.QueryHash(S(p, "query"))[..12]}…",
            RunPrepared,
            Prepare: PrepareCreateRule,
            Resolve: Resolvers.BacktestBinding),

        new("disable_detection_rule", "Disable a board-created detection rule (Defender XDR / Sentinel)", "recover", true,
            Schema(new
            {
                rule_action_id = new { type = "string", description = "Action id of the succeeded create_detection_rule that created the rule (the board only disables rules it created)", pattern = "^[0-9a-fA-F-]{36}$" },
            }, ["rule_action_id"]),
            p => new JsonObject { ["rule_action_id"] = Req(p, "rule_action_id", GuidId(), "action id (GUID)", 64).ToLowerInvariant() },
            _ => Targets.None,
            p => $"Disable the detection rule created by action {S(p, "rule_action_id")} (stops it raising alerts; the rule is kept)",
            RunPrepared,
            Prepare: PrepareDisableRule,
            Resolve: Resolvers.CreatedRule),

        new("intune_sync_device", "Sync device with Intune", "eradicate", false,
            Schema(Rules.DeviceProps, []),
            ValidateDevice,
            p => new Targets([], [DeviceTarget(p)], []),
            p => $"Ask Intune device {DeviceTarget(p)} to check in now (applies pending policies, updates and apps)",
            RunPrepared,
            Prepare: (_, c) => Requests(Step("Graph", "POST", $"/v1.0/deviceManagement/managedDevices/{Enc(ManagedId(c))}/syncDevice")),
            Resolve: Resolvers.ManagedDevice),

        new("intune_update_defender_signatures", "Update Defender Antivirus signatures (Intune)", "eradicate", false,
            Schema(Rules.DeviceProps, []),
            ValidateDevice,
            p => new Targets([], [DeviceTarget(p)], []),
            p => $"Update Microsoft Defender Antivirus security intelligence on Intune device {DeviceTarget(p)}",
            RunPrepared,
            Prepare: (_, c) => Requests(Step("Graph", "POST", $"/v1.0/deviceManagement/managedDevices/{Enc(ManagedId(c))}/windowsDefenderUpdateSignatures")),
            Resolve: Resolvers.ManagedDevice),

        new("intune_expedite_quality_update", "Expedite Windows quality update (Windows Autopatch, beta API)", "eradicate", true,
            Schema(new
            {
                machine_id = new { type = "string", description = "MDE machine id (40 hex chars). Give this or managed_device_id", pattern = "^[0-9a-fA-F]{40}$" },
                managed_device_id = new { type = "string", description = "Intune managed device id (GUID). Give this or machine_id", pattern = "^[0-9a-fA-F-]{36}$" },
                quality_update_id = new { type = "string", description = "Windows Autopatch catalog entry id of the quality update. Omit for the latest expeditable security update", pattern = "^[A-Za-z0-9-]{8,128}$" },
                days_until_forced_reboot = new { type = "integer", minimum = 0, maximum = 2, @default = 2 },
            }, []),
            p =>
            {
                var o = ValidateDevice(p);
                if (Opt(p, "quality_update_id", 128) is { } q)
                    o["quality_update_id"] = CatalogEntryId().IsMatch(q) ? q : throw new BoardException("invalid quality_update_id");
                o["days_until_forced_reboot"] = Int(p, "days_until_forced_reboot", 2, 0, 2);
                return o;
            },
            p => new Targets([], [DeviceTarget(p)], []),
            p => $"Expedite the {(p["quality_update_id"] is { } q ? $"Windows quality update {q}" : "latest expeditable Windows security update")} to Intune device {DeviceTarget(p)}, "
                 + $"forcing a restart after {p["days_until_forced_reboot"]} day(s) if the user hasn't restarted",
            RunPrepared,
            Prepare: PrepareExpedite,
            Resolve: Resolvers.ManagedDeviceAndUpdate),
    ];

    /// <summary>Intune kinds: exactly one of machine_id (MDE) or managed_device_id (Intune); the other ids are resolved by the board.</summary>
    internal static JsonObject ValidateDevice(JsonElement p)
    {
        var mde = Opt(p, "machine_id", 64);
        var managed = Opt(p, "managed_device_id", 64);
        if ((mde is null) == (managed is null)) throw new BoardException("give exactly one of machine_id (MDE) or managed_device_id (Intune)");
        return mde is not null
            ? new JsonObject { ["machine_id"] = MdeId().IsMatch(mde) ? mde.ToLowerInvariant() : throw new BoardException("invalid machine_id: MDE machine id (40 hex chars)") }
            : new JsonObject { ["managed_device_id"] = GuidId().IsMatch(managed!) ? managed!.ToLowerInvariant() : throw new BoardException("invalid managed_device_id: Intune managed device id (GUID)") };
    }

    /// <summary>The device id the request names (MDE or Intune), as policy and the approver see it.</summary>
    public static string DeviceTarget(JsonObject p) => (p["machine_id"] ?? p["managed_device_id"])!.GetValue<string>();

    private static string ManagedId(ActionContext c) =>
        c.Facts?["managed_device_id"]?.GetValue<string>() ?? throw new BoardException("the device could not be matched to an Intune managed device");

    internal static JsonObject ValidateCreateRule(JsonElement p)
    {
        var target = Enum(p, "target", ["defender", "sentinel"], "");
        if (target.Length == 0) throw new BoardException("target is required");
        var name = Req(p, "name", RuleName(), "3-200 characters, no control characters", 200).Trim();
        var query = Req(p, "query", max: 10000);
        // The rule's KQL goes through the same lexical guards as hunting: no management commands, no outbound plugins.
        Enrichment.ValidateKql(query, "P1D");
        var frequency = Enum(p, "frequency", Rules.Frequencies, "PT1H");
        var lookback = Enum(p, "lookback", Rules.Lookbacks, frequency);
        if (Array.IndexOf(Rules.Lookbacks, lookback) < Array.IndexOf(Rules.Lookbacks, frequency)) throw new BoardException("lookback must be at least frequency");
        var o = new JsonObject
        {
            ["target"] = target, ["name"] = name, ["query"] = query, ["frequency"] = frequency, ["lookback"] = lookback,
            ["severity"] = Enum(p, "severity", Rules.Severities, "medium"),
            ["enabled"] = Bool(p, "enabled", true),
            ["backtest_id"] = Req(p, "backtest_id", GuidId(), "backtest_id (GUID) from backtest_detection", 64).ToLowerInvariant(),
        };
        if (Opt(p, "description", 1000) is { Length: > 0 } d) o["description"] = d;

        var mitre = new JsonArray();
        foreach (var m in Arr(p, "mitre", 5))
        {
            var tactic = Enum(m, "tactic", Rules.Tactics, "");
            if (tactic.Length == 0) throw new BoardException("mitre[].tactic is required");
            var techniques = new JsonArray();
            foreach (var t in Arr(m, "techniques", 10))
            {
                var s = t.ValueKind == JsonValueKind.String ? t.GetString()! : throw new BoardException("mitre[].techniques must be strings");
                techniques.Add(Technique().IsMatch(s) ? s : throw new BoardException($"invalid MITRE technique '{(s.Length > 20 ? s[..20] : s)}': use T1234 or T1234.001"));
            }
            mitre.Add(new JsonObject { ["tactic"] = tactic, ["techniques"] = techniques });
        }
        o["mitre"] = mitre;

        var maps = new JsonArray();
        foreach (var m in Arr(p, "entity_mappings", 10))
        {
            var entity = Enum(m, "entity", Rules.EntityFields.Keys.ToArray(), "");
            if (entity.Length == 0) throw new BoardException("entity_mappings[].entity is required");
            var column = Req(m, "column", DetectionService.Column(), "a result column name (letters, digits, '_')", 100);
            if (target == "sentinel" && Rules.EntityFields[entity].SentinelType is null)
                throw new BoardException($"entity mapping {entity} isn't supported for Sentinel rules; use one of {string.Join(", ", Rules.EntityFields.Where(kv => kv.Value.SentinelType is not null).Select(kv => kv.Key))}");
            maps.Add(new JsonObject { ["entity"] = entity, ["column"] = column });
        }
        if (maps.Select(x => x!["entity"]!.GetValue<string>()).Distinct().Count() != maps.Count) throw new BoardException("each entity field may be mapped once");
        o["entity_mappings"] = maps;
        return o;
    }

    private static bool Bool(JsonElement p, string name, bool fallback)
    {
        if (p.ValueKind != JsonValueKind.Object || !p.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) return fallback;
        return v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => throw new BoardException($"{name} must be true or false") };
    }

    private static IEnumerable<JsonElement> Arr(JsonElement p, string name, int max)
    {
        if (p.ValueKind != JsonValueKind.Object || !p.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) return [];
        if (v.ValueKind != JsonValueKind.Array) throw new BoardException($"{name} must be a list");
        if (v.GetArrayLength() > max) throw new BoardException($"{name} takes at most {max} entries");
        return v.EnumerateArray().ToList();
    }

    // ── outbound requests ────────────────────────────────────────────────────────────────────────

    private static JsonObject Step(string api, string method, string path, JsonNode? body = null, string op = "send") =>
        new() { ["op"] = op, ["api"] = api, ["method"] = method, ["path"] = path, ["body"] = body };

    private static JsonObject Requests(params JsonObject[] steps) => new() { ["requests"] = new JsonArray(steps) };

    private static string Provenance(ActionContext c) =>
        $"Created by blueboard action {c.ActionId}" + (c.IncidentGraphId is null ? "" : $" for incident {c.IncidentGraphId}")
        + $", requested by {c.RequestedBy}" + (c.DecidedBy is null ? "" : $", approved by {c.DecidedBy}") + ".";

    /// <summary>The rule id the board gives a rule, derived from the creating action so disable can find it again.</summary>
    public static string RuleId(string target, Guid actionId) => target == "defender" ? $"blueboard-{actionId:N}" : actionId.ToString();

    internal static JsonObject PrepareCreateRule(JsonObject p, ActionContext c)
    {
        var target = S(p, "target");
        var name = S(p, "name");
        var description = $"{(p["description"]?.GetValue<string>() is { Length: > 0 } d ? d + "\n\n" : "")}{Provenance(c)} Back-test {S(p, "backtest_id")}.";
        var maps = p["entity_mappings"]!.AsArray().Select(m => (Entity: m!["entity"]!.GetValue<string>(), Column: m["column"]!.GetValue<string>())).ToList();
        var mitre = p["mitre"]!.AsArray().Select(m => (Tactic: m!["tactic"]!.GetValue<string>(), Techniques: m["techniques"]!.AsArray().Select(t => t!.GetValue<string>()).ToList())).ToList();
        if (target == "defender")
        {
            var mappings = new JsonObject();
            foreach (var g in maps.GroupBy(m => Rules.EntityFields[m.Entity].GraphSet))
            {
                var o = new JsonObject();
                foreach (var m in g) o[Rules.EntityFields[m.Entity].GraphProp] = m.Column;
                mappings[g.Key] = new JsonArray(o);
            }
            var template = new JsonObject
            {
                ["title"] = name,
                ["description"] = description,
                ["severity"] = S(p, "severity"),
                ["recommendedActions"] = "Review the blueboard incident thread and the back-test before acting.",
            };
            if (mappings.Count > 0) template["entityMappings"] = mappings;
            if (mitre.Count > 0)
                template["tactics"] = new JsonArray(mitre.Select(m => (JsonNode)new JsonObject
                {
                    ["tactic"] = m.Tactic, ["techniques"] = new JsonArray(m.Techniques.Select(t => (JsonNode)new JsonObject { ["technique"] = t }).ToArray()),
                }).ToArray());
            return Requests(Step("Graph", "POST", "/v1.0/security/rules/detectionRules", new JsonObject
            {
                ["@odata.type"] = "#microsoft.graph.security.detectionRule",
                ["id"] = RuleId("defender", c.ActionId),
                ["displayName"] = $"{RuleTag} {name}",
                ["description"] = description,
                ["status"] = p["enabled"]!.GetValue<bool>() ? "enabled" : "disabled",
                ["queryCondition"] = new JsonObject { ["queryText"] = S(p, "query") },
                ["schedule"] = new JsonObject { ["frequency"] = S(p, "frequency") },
                ["detectionAction"] = new JsonObject { ["alertTemplate"] = template },
            }));
        }

        var ws = WorkspacePath(c.Ti);
        var entityMappings = new JsonArray(maps.GroupBy(m => Rules.EntityFields[m.Entity].SentinelType!).Select(g => (JsonNode)new JsonObject
        {
            ["entityType"] = g.Key,
            ["fieldMappings"] = new JsonArray(g.Select(m => (JsonNode)new JsonObject { ["identifier"] = Rules.EntityFields[m.Entity].SentinelId, ["columnName"] = m.Column }).ToArray()),
        }).ToArray());
        var severity = S(p, "severity");
        var props = new JsonObject
        {
            ["displayName"] = $"{RuleTag} {name}",
            ["description"] = description,
            ["severity"] = char.ToUpperInvariant(severity[0]) + severity[1..],
            ["enabled"] = p["enabled"]!.GetValue<bool>(),
            ["query"] = S(p, "query"),
            ["queryFrequency"] = S(p, "frequency"),
            ["queryPeriod"] = S(p, "lookback"),
            ["triggerOperator"] = "GreaterThan",
            ["triggerThreshold"] = 0,
            ["suppressionDuration"] = "PT1H",
            ["suppressionEnabled"] = false,
            ["tactics"] = new JsonArray(mitre.Select(m => (JsonNode)m.Tactic).Distinct().ToArray()),
            // This API version takes base techniques (T1059); sub-techniques are reduced to their parent.
            ["techniques"] = new JsonArray(mitre.SelectMany(m => m.Techniques).Select(t => t.Split('.')[0]).Distinct().Select(t => (JsonNode)t).ToArray()),
            ["eventGroupingSettings"] = new JsonObject { ["aggregationKind"] = "AlertPerResult" },
            ["incidentConfiguration"] = new JsonObject { ["createIncident"] = true },
        };
        if (entityMappings.Count > 0) props["entityMappings"] = entityMappings;
        return Requests(Step("Arm", "PUT", $"{ws}/providers/Microsoft.SecurityInsights/alertRules/{RuleId("sentinel", c.ActionId)}?api-version={SentinelRulesApiVersion}",
            new JsonObject { ["kind"] = "Scheduled", ["properties"] = props }));
    }

    internal static JsonObject PrepareDisableRule(JsonObject p, ActionContext c)
    {
        var facts = c.Facts ?? throw new BoardException("the rule to disable could not be resolved");
        var target = facts["target"]!.GetValue<string>();
        var ruleId = facts["rule_id"]!.GetValue<string>();
        return target == "defender"
            ? Requests(Step("Graph", "PATCH", $"/v1.0/security/rules/detectionRules/{Enc(ruleId)}", new JsonObject { ["status"] = "disabled" }))
            // ARM alert rules have no PATCH: read the rule as it is now and write it back with enabled = false.
            : Requests(Step("Arm", "PUT", $"{WorkspacePath(c.Ti)}/providers/Microsoft.SecurityInsights/alertRules/{Enc(ruleId)}?api-version={SentinelRulesApiVersion}",
                new JsonObject { ["properties"] = new JsonObject { ["enabled"] = false } }, op: "get_then_put_disabled"));
    }

    internal static JsonObject PrepareExpedite(JsonObject p, ActionContext c)
    {
        var aad = c.Facts?["aad_device_id"]?.GetValue<string>() ?? throw new BoardException("the device's Entra device id could not be resolved from Intune; the update can't be targeted");
        var update = p["quality_update_id"]?.GetValue<string>() ?? c.Facts?["quality_update_id"]?.GetValue<string>()
                     ?? throw new BoardException("no expeditable Windows security update was found in the Windows Autopatch catalog");
        return Requests(
            Step("Graph", "POST", "/beta/admin/windows/updates/deployments", new JsonObject
            {
                ["@odata.type"] = "#microsoft.graph.windowsUpdates.deployment",
                ["content"] = new JsonObject
                {
                    ["@odata.type"] = "#microsoft.graph.windowsUpdates.catalogContent",
                    ["catalogEntry"] = new JsonObject { ["@odata.type"] = "#microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry", ["id"] = update },
                },
                ["settings"] = new JsonObject
                {
                    ["@odata.type"] = "microsoft.graph.windowsUpdates.deploymentSettings",
                    ["expedite"] = new JsonObject { ["isExpedited"] = true, ["isReadinessTest"] = false },
                    ["userExperience"] = new JsonObject { ["daysUntilForcedReboot"] = p["days_until_forced_reboot"]!.GetValue<int>() },
                },
            }),
            Step("Graph", "POST", "/beta/admin/windows/updates/deployments/{deployment_id}/audience/updateAudience", new JsonObject
            {
                ["addMembers"] = new JsonArray(new JsonObject { ["@odata.type"] = "#microsoft.graph.windowsUpdates.azureADDevice", ["id"] = aad }),
            }));
    }

    private static string WorkspacePath(TiSettings ti) =>
        ti.SentinelWorkspaceResourceId is { } rid && WorkspaceResourceId().IsMatch(rid)
            ? rid
            : throw new BoardException("SENTINEL_WORKSPACE_RESOURCE_ID is not set to the Sentinel workspace's ARM resource id (/subscriptions/…/workspaces/…)");

    /// <summary>
    /// Runs a prepared request list in order. Only APIs these kinds use are allowed; {deployment_id} is the id the
    /// previous step returned. MsClient still pins every call to the exact Microsoft origin.
    /// </summary>
    internal static async Task<object?> RunPrepared(MsClient ms, JsonObject prepared, string _, CancellationToken ct)
    {
        var results = new JsonArray();
        string? previousId = null;
        foreach (var node in prepared["requests"]!.AsArray())
        {
            var step = node!.AsObject();
            var api = step["api"]!.GetValue<string>() switch { "Graph" => MsApi.Graph, "Arm" => MsApi.Arm, var a => throw new BoardException($"api {a} is not allowed here") };
            var path = step["path"]!.GetValue<string>();
            if (path.Contains("{deployment_id}"))
                path = path.Replace("{deployment_id}", Enc(previousId ?? throw new BoardException("the previous step returned no id")));
            var method = new HttpMethod(step["method"]!.GetValue<string>());
            JsonElement? res;
            if (step["op"]?.GetValue<string>() == "get_then_put_disabled")
            {
                var current = await ms.SendAsync(api, path, HttpMethod.Get, null, ct) ?? throw new BoardException("the rule was not found");
                var rule = JsonNode.Parse(current.GetRawText())!.AsObject();
                rule["properties"]!["enabled"] = false;
                foreach (var k in new[] { "id", "name", "type", "systemData" }) rule.Remove(k);
                res = await ms.SendAsync(api, path, HttpMethod.Put, rule, ct);
            }
            else
            {
                res = await ms.SendAsync(api, path, method, step["body"], ct);
            }
            previousId = res is { } r && r.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String ? id.GetString() : null;
            results.Add(new JsonObject { ["method"] = method.Method, ["path"] = path.Split('?')[0], ["id"] = previousId });
        }
        return new { requests = results };
    }
}
