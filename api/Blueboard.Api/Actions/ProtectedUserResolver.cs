using System.Collections.Concurrent;
using System.Text.Json;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;

namespace Blueboard.Api.Actions;

/// <summary>
/// protected_users may list Entra object ids. Policy matches a target by every name it has, but an Okta user (or a
/// target outside the evidence) only carries a login or email, so an object id alone can't protect it. This resolves
/// each object id on the list to its UPN through Graph (GET /v1.0/users/{id}), cached for <see cref="Ttl"/> (a failure
/// for <see cref="FailureTtl"/>, so an outage doesn't hammer Graph). Failures are tolerated: the id is reported
/// unresolved, and policy adds a note that blocks automation and tells the approver.
/// </summary>
public sealed class ProtectedUserResolver(MsClient ms, Func<DateTimeOffset>? clock = null)
{
    public static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan FailureTtl = TimeSpan.FromMinutes(1);

    private readonly Func<DateTimeOffset> _now = clock ?? (() => DateTimeOffset.UtcNow);
    private readonly ConcurrentDictionary<string, (string? Upn, DateTimeOffset Until)> _cache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Object ids on the list mapped to their UPN (lower case), and the ids that couldn't be resolved now.</summary>
    public async Task<(IReadOnlyDictionary<string, string> Resolved, IReadOnlyList<string> Unresolved)> ResolveAsync(IEnumerable<string> protectedUsers, CancellationToken ct = default)
    {
        var resolved = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var unresolved = new List<string>();
        foreach (var id in protectedUsers.Where(u => Guid.TryParse(u, out _)).Select(u => u.Trim().ToLowerInvariant()).Distinct())
        {
            if (!_cache.TryGetValue(id, out var hit) || hit.Until <= _now())
            {
                string? upn = null;
                try
                {
                    var user = await ms.SendAsync(MsApi.Graph, $"/v1.0/users/{Uri.EscapeDataString(id)}?$select=id,userPrincipalName", ct: ct);
                    upn = user is { ValueKind: JsonValueKind.Object } u && u.TryGetProperty("userPrincipalName", out var v) && v.ValueKind == JsonValueKind.String
                        ? v.GetString()?.Trim().ToLowerInvariant() : null;
                }
                catch (Exception ex) when (ex is not OperationCanceledException) { upn = null; }
                hit = (upn, _now() + (upn is null ? FailureTtl : Ttl));
                _cache[id] = hit;
            }
            if (hit.Upn is { Length: > 0 } name) resolved[id] = name;
            else unresolved.Add(id);
        }
        return (resolved, unresolved);
    }

    /// <summary>The policy with its object-id entries resolved (unchanged when it lists none).</summary>
    public async Task<Policy> ApplyAsync(Policy policy, CancellationToken ct = default)
    {
        if (!policy.ProtectedUsers.Any(u => Guid.TryParse(u, out _))) return policy;
        var (resolved, unresolved) = await ResolveAsync(policy.ProtectedUsers, ct);
        return policy with { ResolvedProtectedUsers = resolved, UnresolvedProtectedUsers = unresolved };
    }
}
