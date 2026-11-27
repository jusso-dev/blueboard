using System.Text.Json.Nodes;
using Blueboard.Api.Connectors;
using Blueboard.Api.Core;

namespace Blueboard.Api.Actions;

/// <summary>
/// Okta brokered writes (docs/INTEGRATIONS.md § Okta). Same rules as every other kind: agents request, PolicyEngine checks
/// protected users through Okta id ↔ login ↔ email ↔ Entra UPN ↔ object id aliases, a human approves, the broker runs
/// it once with the connector's credential (dry run unless BROKER_EXECUTE=true). The Okta user must be named by its Okta
/// id or its login/email; nothing else reaches the URL path.
/// </summary>
public static partial class Catalog
{
    public static readonly HashSet<string> OktaKinds = ["okta_suspend_user", "okta_unsuspend_user", "okta_clear_user_sessions", "okta_reset_factors"];

    /// <summary>
    /// The kind that undoes another, for WS1's auto-revert map (docs/INTEGRATIONS.md § Reverse pairs). Only true inverses
    /// are listed: clearing sessions and resetting factors can't be undone, so they have no entry.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> ConnectorReverseKinds = new Dictionary<string, string>
    {
        ["okta_suspend_user"] = "okta_unsuspend_user",
        ["okta_unsuspend_user"] = "okta_suspend_user",
    };

    private static readonly object OktaUserProp = new
    {
        type = "string",
        description = "Okta user id (00u…) or Okta login / primary email. Protected-user checks resolve it to every name the user has in Okta and Entra.",
        maxLength = 320,
    };

    private static readonly object OktaPinnedIdProp = new
    {
        type = "string",
        description = "Set by the board: the Okta user id resolved when the request was filed. Any value you send is replaced.",
        maxLength = 40,
    };

    private static string OktaUser(System.Text.Json.JsonElement p)
    {
        var s = Req(p, "user", null, "Okta user id (00u…) or login / email", 320).Trim();
        if (!OktaClient.IsUserRef(s)) throw new BoardException("invalid user: Okta user id (00u…) or login / email");
        return OktaClient.OktaId().IsMatch(s) ? s : s.ToLowerInvariant();
    }

    /// <summary>{ user, okta_user_id? }: okta_user_id is the board's own pin (ConnectorHub.PrepareTargetAsync) and must be an Okta id.</summary>
    private static JsonObject OktaParams(System.Text.Json.JsonElement p)
    {
        var o = new JsonObject { ["user"] = OktaUser(p) };
        if (Opt(p, "okta_user_id", 40) is { } pinned)
            o["okta_user_id"] = OktaClient.OktaId().IsMatch(pinned) ? pinned : throw new BoardException("invalid okta_user_id: an Okta user id (00u…)");
        return o;
    }

    private static string? Pinned(JsonObject p) => p["okta_user_id"]?.GetValue<string>();

    private static IEnumerable<ActionDef> OktaActions() =>
    [
        new("okta_suspend_user", "Suspend user (Okta)", "contain", true,
            Schema(new { user = OktaUserProp, okta_user_id = OktaPinnedIdProp }, ["user"]),
            OktaParams,
            p => new Targets([S(p, "user")], [], []),
            p => $"Suspend Okta user {S(p, "user")} (blocks Okta sign-in; groups and app assignments are kept)",
            (_, _, _, _) => throw new InvalidOperationException("Okta kinds run through RunConnector"),
            RunConnector: (hub, p, _, ct) => hub.OktaWriteAsync(S(p, "user"), Pinned(p), "suspend", ct)),

        new("okta_unsuspend_user", "Unsuspend user (Okta)", "recover", true,
            Schema(new { user = OktaUserProp, okta_user_id = OktaPinnedIdProp }, ["user"]),
            OktaParams,
            p => new Targets([S(p, "user")], [], []),
            p => $"Unsuspend Okta user {S(p, "user")} (returns a SUSPENDED user to ACTIVE)",
            (_, _, _, _) => throw new InvalidOperationException("Okta kinds run through RunConnector"),
            RunConnector: (hub, p, _, ct) => hub.OktaWriteAsync(S(p, "user"), Pinned(p), "unsuspend", ct)),

        new("okta_clear_user_sessions", "Clear sessions and revoke tokens (Okta)", "contain", true,
            Schema(new { user = OktaUserProp, okta_user_id = OktaPinnedIdProp }, ["user"]),
            OktaParams,
            p => new Targets([S(p, "user")], [], []),
            p => $"End every Okta session of {S(p, "user")} and revoke the OAuth/OIDC tokens Okta issued to them",
            (_, _, _, _) => throw new InvalidOperationException("Okta kinds run through RunConnector"),
            RunConnector: (hub, p, _, ct) => hub.OktaWriteAsync(S(p, "user"), Pinned(p), "clear_sessions", ct)),

        new("okta_reset_factors", "Reset MFA factors (Okta)", "eradicate", true,
            Schema(new { user = OktaUserProp, okta_user_id = OktaPinnedIdProp }, ["user"]),
            OktaParams,
            p => new Targets([S(p, "user")], [], []),
            p => $"Reset every enrolled Okta MFA factor of {S(p, "user")} (they must enrol again at next sign-in; cannot be undone)",
            (_, _, _, _) => throw new InvalidOperationException("Okta kinds run through RunConnector"),
            RunConnector: (hub, p, _, ct) => hub.OktaWriteAsync(S(p, "user"), Pinned(p), "reset_factors", ct)),
    ];
}
