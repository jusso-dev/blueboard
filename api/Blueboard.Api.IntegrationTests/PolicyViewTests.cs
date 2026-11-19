using System.Text.Json;
using Blueboard.Api.Actions;
using Blueboard.Api.Data;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>Issues #11 and #8: GET /api/policy, the simulator, the request preview and the catalogue, over the real REST handlers.</summary>
public sealed class PolicyViewTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly Policy Strict = new()
    {
        ProtectedUsers = ["breakglass@contoso.com"], ProtectedDevices = ["dc01.contoso.com"], ProtectedIndicators = ["contoso.com"],
        Disabled = ["purge_email"], RequireTwoApprovers = ["disable_user"],
    };

    private async Task ClearQueue()
    {
        await using var c = t.Db.Command("update actions set status = 'denied' where status = any(@s)").With("s", ActionStatus.Open);
        await c.ExecuteNonQueryAsync(Ct);
    }

    [DbFact]
    public async Task Policy_view_shows_counts_to_everyone_and_values_only_to_admins()
    {
        var app = A1.Build(t, Strict);
        var (s1, reader) = A1.Read(await app.Api.GetPolicy(A1.Request("reader")));
        Assert.Equal(200, s1);
        Assert.Equal(1, reader.GetProperty("protected").GetProperty("devices").GetInt32());
        Assert.Equal(JsonValueKind.Null, reader.GetProperty("lists").ValueKind);
        Assert.DoesNotContain("dc01", reader.GetRawText());
        Assert.DoesNotContain("breakglass", reader.GetRawText());

        var (_, admin) = A1.Read(await app.Api.GetPolicy(A1.Request("analyst")));
        Assert.Equal("dc01.contoso.com", admin.GetProperty("lists").GetProperty("devices")[0].GetString());
        var modes = admin.GetProperty("actions").EnumerateArray().ToDictionary(a => a.GetProperty("kind").GetString()!, a => a.GetProperty("mode").GetString());
        Assert.Equal("disabled", modes["purge_email"]);
        Assert.Equal("two_approvers", modes["disable_user"]);
    }

    public static TheoryData<string, string> Cases => new()
    {
        { "isolate_device", $$"""{"machine_id":"{{TestBoard.Device}}"}""" },
        { "run_av_scan", $$"""{"machine_id":"{{TestBoard.Device}}"}""" },
        { "run_av_scan", $$"""{"machine_id":"{{new string('0', 40)}}"}""" },
        { "disable_user", """{"user":"ana@contoso.com"}""" },
        { "disable_user", """{"user":"breakglass@contoso.com"}""" },
        { "block_indicator", """{"indicator_type":"domain","value":"login.contoso.com","title":"test block"}""" },
        { "block_indicator", """{"indicator_type":"domain","value":"bad.example","title":"test block"}""" },
        { "purge_email", """{"messages":[{"network_message_id":"abcdefgh12","recipient":"ana@contoso.com"}]}""" },
        { "add_incident_comment", """{"incident_id":"90210","comment":"noted"}""" },
        { "update_incident", """{"incident_id":"1","status":"resolved"}""" },
    };

    /// <summary>The simulator, the preview and a real request agree on outcome, status and notes for every fixture.</summary>
    [DbTheory]
    [MemberData(nameof(Cases))]
    public async Task Simulator_preview_and_request_agree(string kind, string prms)
    {
        await ClearQueue();
        var app = A1.Build(t, Strict);
        var body = new { kind, @params = JsonDocument.Parse(prms).RootElement, incident = TestBoard.IncidentGraphId };
        var before = await t.ScalarAsync("select count(*) from actions");
        var (s1, sim) = A1.Read(await app.Api.SimulatePolicy(A1.Request("reader", "POST", body)));
        var (s2, pre) = A1.Read(await app.Api.PreviewAction(A1.Request("analyst", "POST", body)));
        Assert.Equal(200, s1);
        Assert.Equal(200, s2);
        Assert.Equal(sim.GetRawText(), pre.GetRawText());
        Assert.Equal(before, await t.ScalarAsync("select count(*) from actions")); // preview and simulate write nothing

        var row = await app.Broker.RequestAsync(await t.As("analyst2"), new ActionRequest(kind, JsonDocument.Parse(prms).RootElement,
            "Simulator agreement check: same input as the preview above.", TestBoard.IncidentGraphId), Ct);
        var expected = sim.GetProperty("status").GetString();
        // Auto-approved actions run at once (dry run), so the stored status has moved on to succeeded.
        Assert.Equal(expected == "approved" ? "succeeded" : expected, row.Status);
        Assert.Equal(sim.GetProperty("notes").EnumerateArray().Select(n => n.GetString()).ToArray(), row.PolicyNotes);
        if (expected == "pending_approval") Assert.Equal(sim.GetProperty("approvals_required").GetInt32(), row.ApprovalsRequired);
    }

    [DbFact]
    public async Task Preview_needs_the_request_role_and_writes_nothing()
    {
        var app = A1.Build(t, Strict);
        var body = new { kind = "isolate_device", @params = new { machine_id = TestBoard.Device }, incident = TestBoard.IncidentGraphId };
        var before = await t.ScalarAsync("select count(*) from actions");
        Assert.Equal(403, A1.Read(await app.Api.PreviewAction(A1.Request("reader", "POST", body))).Status);
        Assert.Equal(403, A1.Read(await app.Api.RequestAction(A1.Request("reader", "POST", new
        {
            kind = "isolate_device", @params = new { machine_id = TestBoard.Device }, justification = "Reader trying to request an action directly.", incident = TestBoard.IncidentGraphId,
        }))).Status);
        var (ok, pre) = A1.Read(await app.Api.PreviewAction(A1.Request("agent", "POST", body)));
        Assert.Equal(200, ok);
        Assert.Equal("Needs approval", pre.GetProperty("summary").GetString());
        Assert.Equal(before, await t.ScalarAsync("select count(*) from actions"));
    }

    [DbFact]
    public async Task Simulator_explains_a_protected_target_without_an_incident()
    {
        var app = A1.Build(t, Strict);
        var (_, sim) = A1.Read(await app.Api.SimulatePolicy(A1.Request("reader", "POST", new { kind = "disable_user", @params = new { user = "BreakGlass@contoso.com" } })));
        Assert.Equal("reject", sim.GetProperty("outcome").GetString());
        Assert.Equal("Will be rejected: BreakGlass@contoso.com is a protected user", sim.GetProperty("summary").GetString());
        var (bad, err) = A1.Read(await app.Api.SimulatePolicy(A1.Request("reader", "POST", new { kind = "isolate_device", @params = new { machine_id = "nope" } })));
        Assert.Equal(400, bad);
        Assert.Contains("machine_id", err.GetProperty("error").GetString());
    }

    [DbFact]
    public async Task Catalogue_carries_target_type_and_policy_mode()
    {
        var app = A1.Build(t, Strict);
        var (_, cat) = A1.Read(await app.Api.Actions(A1.Request("reader", query: "?catalog=true")));
        var purge = cat.EnumerateArray().Single(a => a.GetProperty("kind").GetString() == "purge_email");
        Assert.Equal("email", purge.GetProperty("target").GetString());
        Assert.Equal("disabled", purge.GetProperty("mode").GetString());
        Assert.Equal("device", cat.EnumerateArray().Single(a => a.GetProperty("kind").GetString() == "isolate_device").GetProperty("target").GetString());
    }

    [DbFact]
    public async Task Open_filter_lists_pending_and_one_of_two()
    {
        await ClearQueue();
        var app = A1.Build(t, Strict);
        var a = await app.Broker.RequestAsync(await t.As("agent"), A1.Disable(), Ct);
        var b = await app.Broker.RequestAsync(await t.As("agent"), A1.Isolate(), Ct);
        await app.Broker.DecideAsync(await t.As("analyst"), a.Id, "approve", null, Ct);
        var (_, open) = A1.Read(await app.Api.Actions(A1.Request("reader", query: "?status=open")));
        var states = open.EnumerateArray().ToDictionary(x => x.GetProperty("id").GetGuid(), x => x.GetProperty("status").GetString());
        Assert.Equal("approved_once", states[a.Id]);
        Assert.Equal("pending_approval", states[b.Id]);
    }
}

/// <summary>Theory variant of DbFact: skips when no test database is configured.</summary>
public sealed class DbTheoryAttribute : TheoryAttribute
{
    public DbTheoryAttribute(
        [System.Runtime.CompilerServices.CallerFilePath] string? sourceFilePath = null,
        [System.Runtime.CompilerServices.CallerLineNumber] int sourceLineNumber = -1)
        : base(sourceFilePath, sourceLineNumber)
    {
        if (TestBoard.ServerUrl is null) Skip = TestBoard.SkipReason;
    }
}
