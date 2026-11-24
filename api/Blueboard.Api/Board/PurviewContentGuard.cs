using System.Text.Json;
using Blueboard.Api.Auth;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Graph;
using Blueboard.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Blueboard.Api.Board;

/// <summary>
/// Optional Microsoft Purview data-security check on non-system board posts via Microsoft Graph
/// (<c>POST /v1.0/security/dataSecurityAndGovernance/processContent</c>). Off by default; controlled by
/// <c>PURVIEW_CONTENT_GUARD=off|audit|block</c>. Runs outside database transactions so pooled connections are never
/// held waiting on Microsoft Graph.
/// </summary>
public sealed class PurviewContentGuard(MsClient ms, Audit audit, Settings settings, ILogger<PurviewContentGuard>? log = null)
{
    private readonly ILogger _log = log ?? NullLogger<PurviewContentGuard>.Instance;

    public bool Enabled => settings.PurviewGuardMode is "audit" or "block";

    public async Task InspectPostAsync(Principal author, PostInput input, CancellationToken ct = default)
    {
        if (!Enabled) return;
        var mode = settings.PurviewGuardMode;
        var correlationId = Guid.NewGuid();
        var body = BuildProcessContentBody(author, input, correlationId);
        JsonElement? res;
        try
        {
            const string path = "/v1.0/security/dataSecurityAndGovernance/processContent";
            res = await ms.SendAsync(MsApi.Graph, path, HttpMethod.Post, body, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning("Purview processContent call failed in {Mode} mode: {Error}", mode, ex.Message);
            await audit.WriteAsync(author.Id, "purview.guard_error", input.Channel, new { mode, error = ex.Message }, ct);
            if (mode == "block") throw new BoardException("Microsoft Purview content guard could not verify this post", 502);
            return;
        }

        var actions = ExtractPolicyActions(res);
        if (actions.Count == 0) return;

        await audit.WriteAsync(author.Id, "purview.content_flagged", input.Channel, new { mode, actions, type = input.Type ?? "chat" }, ct);
        if (mode == "block" && actions.Any(a => a is "restrictAccess" or "blockAccess"))
            throw BoardException.Forbidden($"blocked by Microsoft Purview data security policy ({string.Join(", ", actions)})");
    }

    internal static Dictionary<string, object?> BuildProcessContentBody(Principal author, PostInput input, Guid correlationId)
    {
        var now = DateTimeOffset.UtcNow.ToString("O");
        var text = input.Body;
        if (input.Payload is { ValueKind: not JsonValueKind.Null and not JsonValueKind.Undefined } p)
            text = $"{text}\n\n{p.GetRawText()}";

        return new Dictionary<string, object?>
        {
            ["contentToProcess"] = new Dictionary<string, object?>
            {
                ["contentEntries"] = new[]
                {
                    new Dictionary<string, object?>
                    {
                        ["@odata.type"] = "microsoft.graph.processConversationMetadata",
                        ["identifier"] = correlationId.ToString(),
                        ["content"] = new Dictionary<string, object?>
                        {
                            ["@odata.type"] = "microsoft.graph.textContent",
                            ["data"] = text,
                        },
                        ["name"] = $"blueboard #{input.Channel} ({input.Type ?? "chat"}) by @{author.Handle}",
                        ["isTruncated"] = false,
                        ["createdDateTime"] = now,
                        ["modifiedDateTime"] = now,
                        ["correlationId"] = correlationId.ToString(),
                        ["sequenceNumber"] = 0,
                        ["parentMessageId"] = input.ParentId?.ToString() ?? correlationId.ToString(),
                    },
                },
                ["activityMetadata"] = new Dictionary<string, object?> { ["activity"] = "uploadText" },
                ["protectedAppMetadata"] = new Dictionary<string, object?>
                {
                    ["name"] = "blueboard",
                    ["version"] = "2.1",
                    ["applicationLocation"] = new Dictionary<string, object?>
                    {
                        ["@odata.type"] = "microsoft.graph.policyLocationApplication",
                        ["value"] = "blueboard",
                    },
                },
                ["integratedAppMetadata"] = new Dictionary<string, object?>
                {
                    ["name"] = "blueboard",
                    ["version"] = "2.1",
                },
            },
        };
    }

    internal static IReadOnlyList<string> ExtractPolicyActions(JsonElement? res)
    {
        if (res is not { ValueKind: JsonValueKind.Object } root) return [];
        if (!root.TryGetProperty("policyActions", out var list) || list.ValueKind != JsonValueKind.Array) return [];
        var actions = new List<string>();
        foreach (var item in list.EnumerateArray())
        {
            if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty("action", out var act) && act.ValueKind == JsonValueKind.String)
            {
                if (act.GetString() is { Length: > 0 } s) actions.Add(s);
            }
            else if (item.ValueKind == JsonValueKind.Object && item.TryGetProperty("@odata.type", out var otype) && otype.ValueKind == JsonValueKind.String)
            {
                var name = otype.GetString()!.Split('.').Last();
                if (name.Length > 0) actions.Add(name);
            }
        }
        return actions;
    }
}
