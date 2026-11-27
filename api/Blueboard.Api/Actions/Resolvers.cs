using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Api.Intel;

namespace Blueboard.Api.Actions;

/// <summary>What a resolver can read. RequestedAt is when the action was requested (now, for a new request or a preview).</summary>
public sealed record ResolveContext(Db Db, MsClient Ms, Settings Settings, DateTimeOffset RequestedAt);

/// <summary>
/// Facts the board looked up for one request, before policy runs: names a device target is also known by (so protected
/// lists and the evidence check see them), targets it couldn't resolve, notes and a hard refusal for policy, and data
/// Prepare needs to build the outbound request. Re-resolved at every check (request, approval, Run now, execution).
/// </summary>
public sealed record ActionFacts(
    IReadOnlyDictionary<string, string[]>? DeviceAliases = null,
    IReadOnlyList<string>? UnresolvedDevices = null,
    IReadOnlyList<string>? Notes = null,
    string? Reject = null,
    JsonObject? Data = null);

/// <summary>The lookups behind create_detection_rule, disable_detection_rule and the Intune kinds.</summary>
public static class Resolvers
{
    /// <summary>
    /// create_detection_rule: the cited back-test must exist, be for the same target, cover at least 7 days, have been
    /// run within 24 hours before the request, hash to exactly the submitted query, and not estimate an alert flood.
    /// </summary>
    public static async Task<ActionFacts> BacktestBinding(ResolveContext c, JsonObject p, CancellationToken ct)
    {
        var id = Guid.Parse(p["backtest_id"]!.GetValue<string>());
        var b = await DetectionService.LoadAsync(c.Db, id, ct);
        return BacktestFacts(b, p["target"]!.GetValue<string>(), DetectionService.QueryHash(p["query"]!.GetValue<string>()), c.RequestedAt);
    }

    /// <summary>The back-test gate as a pure function (unit tested).</summary>
    public static ActionFacts BacktestFacts(BacktestRecord? b, string target, string queryHash, DateTimeOffset requestedAt)
    {
        if (b is null) return new(Reject: "backtest_id was not found: run backtest_detection on this exact query first");
        if (b.Target != target) return new(Reject: $"back-test {b.Id} ran against {b.Target}, but the rule targets {target}");
        if (!string.Equals(b.QuerySha256, queryHash, StringComparison.Ordinal))
            return new(Reject: $"the rule's query (sha256 {queryHash[..12]}…) is not the query back-tested in {b.Id} (sha256 {b.QuerySha256[..12]}…)");
        if (b.LookbackDays < DetectionService.MinBindLookbackDays)
            return new(Reject: $"back-test {b.Id} covers {b.LookbackDays} day(s); at least {DetectionService.MinBindLookbackDays} are needed");
        var age = requestedAt - b.CreatedAt;
        if (age > DetectionService.BindWindow || age < TimeSpan.FromMinutes(-5))
            return new(Reject: $"back-test {b.Id} is from {b.CreatedAt:u}; it must be from the 24 hours before the request, so run it again");
        if (b.EstAlertsPerDay > DetectionService.MaxAlertsPerDay)
            return new(Reject: $"back-test {b.Id} estimates {b.EstAlertsPerDay:0.#} alerts a day, above the ceiling of {DetectionService.MaxAlertsPerDay:0} (alert flood): tune the query");
        var notes = new List<string>
        {
            $"back-test {b.Id} ({b.Target}, {b.LookbackDays} days, {b.CreatedAt:u}): {b.TotalHits} hits, about {b.EstAlertsPerDay:0.##} alerts a day, peak {b.PeakHitsPerDay} in a day",
        };
        if (b.TotalHits == 0) notes.Add("the back-test found no hits: check the rule detects what it should before approving");
        return new(Notes: notes);
    }

    /// <summary>disable_detection_rule: only a rule this board created (a succeeded create_detection_rule) can be disabled.</summary>
    public static async Task<ActionFacts> CreatedRule(ResolveContext c, JsonObject p, CancellationToken ct)
    {
        var actionId = Guid.Parse(p["rule_action_id"]!.GetValue<string>());
        await using var cmd = c.Db.Command("select status, params->>'target', params->>'name' from actions where id = @id and kind = 'create_detection_rule'").With("id", actionId);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (!await r.ReadAsync(ct)) return new(Reject: $"action {actionId} is not a create_detection_rule request on this board");
        if (r.GetString(0) != "succeeded") return new(Reject: $"create_detection_rule {actionId} is {r.GetString(0)}, so there is no rule to disable");
        var target = r.GetString(1);
        return new(Notes: [$"disables {target} rule '{r.GetString(2)}' (rule id {Catalog.RuleId(target, actionId)})"],
            Data: new JsonObject { ["target"] = target, ["rule_id"] = Catalog.RuleId(target, actionId) });
    }

    public static Task<ActionFacts> ManagedDevice(ResolveContext c, JsonObject p, CancellationToken ct) => DeviceFacts(c, p, update: false, ct);
    public static Task<ActionFacts> ManagedDeviceAndUpdate(ResolveContext c, JsonObject p, CancellationToken ct) => DeviceFacts(c, p, update: true, ct);

    /// <summary>
    /// Intune kinds take an MDE machine id or an Intune managed device id. Both are resolved to the device's other ids
    /// (managed device id ↔ Entra device id ↔ MDE id ↔ DNS name ↔ host name) so protected_devices and the evidence
    /// check match whichever name the policy uses. A device that can't be resolved is reported, never guessed.
    /// </summary>
    private static async Task<ActionFacts> DeviceFacts(ResolveContext c, JsonObject p, bool update, CancellationToken ct)
    {
        var target = Catalog.DeviceTarget(p);
        var machineId = p["machine_id"]?.GetValue<string>();
        var managedId = p["managed_device_id"]?.GetValue<string>();
        string? aad = null, name = null, mdeName = null;
        var notes = new List<string>();
        // Fail closed: a device is fully resolved only when both sides (Intune and MDE) answered and agreed on the Entra
        // device id. Anything less (a lookup that threw, or found nothing on one side) leaves names unknown, so the device
        // is reported unresolved: the protected list is checked by id only, the approver is told, and it never auto-runs.
        var partial = false;
        try
        {
            if (machineId is not null)
            {
                var m = await Get(c.Ms, MsApi.Defender, $"/api/machines/{machineId}", ct);
                aad = Str(m, "aadDeviceId");
                mdeName = Str(m, "computerDnsName");
                if (aad is not null && Guid.TryParse(aad, out var aadId))
                {
                    var list = await Get(c.Ms, MsApi.Graph, $"/v1.0/deviceManagement/managedDevices?$filter={Uri.EscapeDataString($"azureADDeviceId eq '{aadId}'")}&$select=id,deviceName,azureADDeviceId,operatingSystem", ct);
                    if (First(list) is { } md) { managedId = Str(md, "id"); name = Str(md, "deviceName"); }
                }
                else partial = true;
            }
            else if (managedId is not null)
            {
                var md = await Get(c.Ms, MsApi.Graph, $"/v1.0/deviceManagement/managedDevices/{managedId}?$select=id,deviceName,azureADDeviceId,operatingSystem", ct);
                if (md is null) managedId = null;
                name = Str(md, "deviceName");
                aad = Str(md, "azureADDeviceId");
                if (aad is not null && Guid.TryParse(aad, out var aadId))
                {
                    var list = await Get(c.Ms, MsApi.Defender, $"/api/machines?$filter={Uri.EscapeDataString($"aadDeviceId eq {aadId}")}", ct);
                    if (First(list) is { } m) { machineId = Str(m, "id"); mdeName = Str(m, "computerDnsName"); }
                    else partial = true;
                }
                else partial = true;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            notes.Add($"device lookup failed ({(ex is BoardException ? ex.Message : ex.GetType().Name)})");
            partial = true;
        }

        if (managedId is null || !Guid.TryParse(managedId, out _))
            return new(UnresolvedDevices: [target], Notes: [.. notes, $"{target} could not be matched to an Intune managed device, so Intune can't act on it and its other names are unknown"]);
        if (partial)
            notes.Add($"{target} was only partly resolved (the Intune or Defender side of the lookup failed or found nothing), so some of its names are unknown");

        var aliases = new[] { managedId, aad, machineId, name, name?.Split('.')[0], mdeName, mdeName?.Split('.')[0] }
            .OfType<string>().Where(x => x.Length > 0).Select(x => x.ToLowerInvariant()).Distinct().ToArray();
        var data = new JsonObject { ["managed_device_id"] = managedId.ToLowerInvariant(), ["aad_device_id"] = aad, ["device_name"] = name ?? mdeName };
        if (update && p["quality_update_id"] is null)
        {
            try
            {
                var entries = await Get(c.Ms, MsApi.Graph,
                    "/beta/admin/windows/updates/catalog/entries?$top=10&$orderby=releaseDateTime%20desc&$filter="
                    + Uri.EscapeDataString("isof('microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry') and microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/isExpeditable eq true"), ct);
                if (entries is { } e && e.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Array
                    && v.EnumerateArray().FirstOrDefault(x => Str(x, "qualityUpdateClassification") == "security") is { ValueKind: JsonValueKind.Object } latest)
                {
                    data["quality_update_id"] = Str(latest, "id");
                    notes.Add($"latest expeditable security update: {Str(latest, "displayName") ?? Str(latest, "id")}");
                }
            }
            catch (BoardException ex)
            {
                notes.Add($"Windows Autopatch catalog lookup failed ({ex.Message})");
            }
        }
        if (aad is null && update) notes.Add($"{target} has no Entra device id in Intune, so an expedited update can't target it");
        return new(DeviceAliases: new Dictionary<string, string[]> { [target.ToLowerInvariant()] = aliases },
            UnresolvedDevices: partial ? [target] : null, Notes: notes, Data: data);
    }

    private static async Task<JsonElement?> Get(MsClient ms, MsApi api, string path, CancellationToken ct)
    {
        try { return await ms.SendAsync(api, path, HttpMethod.Get, null, ct); }
        catch (BoardException ex) when (ex.UpstreamStatus == 404) { return null; }
    }

    private static JsonElement? First(JsonElement? list) =>
        list is { } l && l.TryGetProperty("value", out var v) && v.ValueKind == JsonValueKind.Array && v.GetArrayLength() > 0 ? v[0] : null;

    private static string? Str(JsonElement? e, string k) =>
        e is { ValueKind: JsonValueKind.Object } o && o.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
