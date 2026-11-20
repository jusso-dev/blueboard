using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Graph;
using Xunit;

namespace Blueboard.Api.Tests;

public class PolicyTests
{
    private const string Device = "4b1d7e2c9f0a3b6d8e5c1a7f2e9d0c3b6a8f1e4d";

    private static readonly IncidentContext Incident = new("42", JsonDocument.Parse($$"""
        { "alerts": [ { "mitreTechniques": ["T1003.001"], "evidence": [
          { "@odata.type": "#microsoft.graph.security.deviceEvidence", "mdeDeviceId": "{{Device}}", "deviceDnsName": "fin-lt-1.contoso.local" },
          { "@odata.type": "#microsoft.graph.security.userEvidence", "userAccount": { "userPrincipalName": "J.Doe@contoso.com", "azureAdUserId": "u-1" } },
          { "@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "203.0.113.45" },
          { "@odata.type": "#microsoft.graph.security.urlEvidence", "url": "https://evil.example.net/a.ps1" }
        ] } ] }
        """).RootElement);

    private static PolicyDecision Eval(string kind, object prms, IncidentContext? inc = null, Policy? policy = null, bool noIncident = false)
    {
        var def = Catalog.Get(kind);
        var p = def.Validate(JsonSerializer.SerializeToElement(prms));
        return PolicyEngine.Evaluate(def, p, noIncident ? null : inc ?? Incident, policy ?? new Policy());
    }

    [Fact]
    public void Entities_are_normalised()
    {
        var e = Entities.Extract(Incident.Data);
        Assert.Equal(Device, e.Devices[0].MdeDeviceId);
        Assert.Equal("J.Doe@contoso.com", e.Users[0].Upn);
        Assert.Equal(["evil.example.net"], e.Domains);
        Assert.Equal(["T1003.001"], e.Mitre);
    }

    [Fact]
    public void Destructive_actions_always_need_approval() =>
        Assert.Equal(Outcome.NeedsApproval, Eval("isolate_device", new { machine_id = Device }).Outcome);

    [Fact]
    public void Listed_non_destructive_actions_auto_run_when_in_scope() =>
        Assert.Equal(Outcome.Auto, Eval("run_av_scan", new { machine_id = Device }).Outcome);

    [Fact]
    public void Out_of_scope_target_is_flagged_and_not_auto_approved()
    {
        var d = Eval("run_av_scan", new { machine_id = new string('0', 40) });
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Contains("not in incident 42 evidence", d.Notes[0]);
    }

    [Fact]
    public void Unlinked_requests_are_not_auto_approved() =>
        Assert.Equal(Outcome.NeedsApproval, Eval("run_av_scan", new { machine_id = Device }, noIncident: true).Outcome);

    [Fact]
    public void Protected_user_is_rejected_case_insensitively() =>
        Assert.Equal(Outcome.Reject, Eval("disable_user", new { user = "j.doe@contoso.com" }, policy: new Policy { ProtectedUsers = ["J.DOE@contoso.com"] }).Outcome);

    [Fact]
    public void Protected_user_listed_by_upn_is_rejected_when_request_uses_object_id() =>
        Assert.Equal(Outcome.Reject, Eval("disable_user", new { user = "6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f" },
            new IncidentContext("42", JsonDocument.Parse("""{"alerts":[{"evidence":[{"@odata.type":"#microsoft.graph.security.userEvidence","userAccount":{"userPrincipalName":"j.doe@contoso.com","azureAdUserId":"6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f"}}]}]}""").RootElement),
            new Policy { ProtectedUsers = ["j.doe@contoso.com"] }).Outcome);

    [Theory]
    [InlineData("fin-lt-1.contoso.local")]
    [InlineData("FIN-LT-1")]
    [InlineData(Device)]
    public void Protected_device_matches_any_alias(string listed) =>
        Assert.Equal(Outcome.Reject, Eval("isolate_device", new { machine_id = Device }, policy: new Policy { ProtectedDevices = [listed] }).Outcome);

    [Fact]
    public void Unresolvable_device_is_flagged_when_a_protected_list_exists()
    {
        var d = Eval("run_av_scan", new { machine_id = new string('1', 40) }, policy: new Policy { ProtectedDevices = ["dc01"] });
        Assert.Equal(Outcome.NeedsApproval, d.Outcome);
        Assert.Contains(d.Notes, n => n.Contains("checked by id only"));
    }

    [Theory]
    [InlineData("domain", "contoso.com", Outcome.Reject)]
    [InlineData("domain", "login.contoso.com", Outcome.Reject)]
    [InlineData("url", "https://contoso.com/x", Outcome.Reject)]
    [InlineData("url", "https://login.contoso.com/oauth2", Outcome.Reject)]
    [InlineData("url", "HTTPS://Login.Contoso.Com:443/", Outcome.Reject)]
    [InlineData("domain", "contoso.com.", Outcome.Reject)]
    [InlineData("domain", "login.contoso.com.", Outcome.Reject)]
    [InlineData("url", "https://contoso.com.evil.example/x", Outcome.NeedsApproval)]
    [InlineData("domain", "notcontoso.com", Outcome.NeedsApproval)]
    [InlineData("domain", "evil.example.net", Outcome.NeedsApproval)]
    public void Protected_indicators_and_subdomains_are_rejected(string type, string value, Outcome expected) =>
        Assert.Equal(expected, Eval("block_indicator", new { indicator_type = type, value, title = "test block" },
            policy: new Policy { ProtectedIndicators = ["contoso.com"] }).Outcome);

    [Fact]
    public void Disabled_kinds_are_rejected() =>
        Assert.Equal(Outcome.Reject, Eval("reset_password", new { user = "j.doe@contoso.com" }, policy: new Policy { Disabled = ["reset_password"] }).Outcome);

    [Fact]
    public void Incident_writes_must_target_their_linked_incident() =>
        Assert.Equal(Outcome.Reject, Eval("update_incident", new { incident_id = "999", status = "resolved" }).Outcome);

    [Fact]
    public void Incident_comment_without_linked_incident_is_rejected() =>
        Assert.Equal(Outcome.Reject, Eval("add_incident_comment", new { incident_id = "42", comment = "hi" }, noIncident: true).Outcome);

    [Fact]
    public void Incident_comment_on_its_own_incident_auto_runs() =>
        Assert.Equal(Outcome.Auto, Eval("add_incident_comment", new { incident_id = "42", comment = "hi" }).Outcome);

    [Theory]
    [InlineData("isolate_device", """{"machine_id":"not-an-id"}""")]
    [InlineData("update_incident", """{"incident_id":"..","status":"resolved"}""")]
    [InlineData("update_incident", """{"incident_id":"1"}""")]
    [InlineData("disable_user", """{"user":"../me"}""")]
    [InlineData("block_indicator", """{"indicator_type":"sha256","value":"x","title":"ab"}""")]
    [InlineData("block_indicator", """{"indicator_type":"sha256","value":"x","title":"abc","expires_in_days":400}""")]
    public void Invalid_params_are_rejected(string kind, string json) =>
        Assert.Throws<BoardException>(() => Catalog.Get(kind).Validate(JsonDocument.Parse(json).RootElement));

    [Theory]
    [InlineData("j.doe@contoso.com")]
    [InlineData("6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f")]
    public void Valid_user_refs_are_accepted(string user) =>
        Assert.Equal(user, Catalog.Get("disable_user").Validate(JsonSerializer.SerializeToElement(new { user }))["user"]!.GetValue<string>());
}
