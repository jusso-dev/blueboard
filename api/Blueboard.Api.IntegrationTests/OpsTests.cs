using Blueboard.Contracts;
using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Blueboard.Api.Actions;
using Blueboard.Api.Auth;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Api.Ops;
using Xunit;

namespace Blueboard.Api.IntegrationTests;

/// <summary>Answers 200 and records each request body (stands in for Teams, a webhook receiver, Azure Monitor).</summary>
internal sealed class Receiver : HttpMessageHandler
{
    public ConcurrentQueue<(Uri Uri, string Body, string? Signature, string? Auth)> Got { get; } = new();
    public HttpStatusCode Status { get; set; } = HttpStatusCode.OK;

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
    {
        Got.Enqueue((r.RequestUri!, await r.Content!.ReadAsStringAsync(ct),
            r.Headers.TryGetValues("X-Blueboard-Signature", out var s) ? s.First() : null, r.Headers.Authorization?.Parameter));
        return new HttpResponseMessage(Status);
    }
}

internal sealed class StaticToken : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext c, CancellationToken ct) => new("test-token", DateTimeOffset.UtcNow.AddHours(1));
    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext c, CancellationToken ct) => ValueTask.FromResult(GetToken(c, ct));
}

public sealed class OpsTests(TestBoard t) : IClassFixture<TestBoard>
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly string Secret = new('s', 40);

    private async Task<ActionRow> RequestIsolationAsync(string by = "agent") =>
        await t.Broker.RequestAsync(await t.As(by), new ActionRequest("isolate_device",
            JsonSerializer.SerializeToElement(new { machine_id = TestBoard.Device }),
            "Device shows a PowerShell download cradle and LSASS access in the incident evidence.", TestBoard.IncidentGraphId), Ct);

    private async Task ResumeAsync()
    {
        var pause = await t.Broker.GetPauseAsync(Ct);
        if (pause.Paused) await t.Broker.SetPauseAsync(await t.As("analyst"), false, "test cleanup", Ct);
    }

    // ── #10 participants ───────────────────────────────────────────────────────────────────────────
    [DbFact]
    public async Task Disabled_agent_is_refused_on_its_next_call_and_the_board_says_so()
    {
        var admin = await t.As("analyst");
        var auth = new Authenticator(t.Settings, new TokenValidator(t.Settings), t.Db, t.Audit);
        var headers = new Dictionary<string, string> { ["authorization"] = "Bearer dev:agent2" };
        Assert.Equal("agent2", (await auth.AuthenticateAsync(headers, Ct)).Handle);

        var parts = new Participants(t.Db, t.Audit, t.Board, t.System);
        await Assert.ThrowsAsync<BoardException>(() => parts.SetEnabledAsync(admin, "agent2", false, "", Ct)); // reason required
        await Assert.ThrowsAsync<BoardException>(async () => await parts.SetEnabledAsync(await t.As("analyst2"), "agent2", false, "not an admin", Ct));
        var row = await parts.SetEnabledAsync(admin, "agent2", false, "suspected stolen credential", Ct);
        Assert.False(row.Enabled);
        Assert.Equal("analyst", row.DisabledBy);

        var ex = await Assert.ThrowsAsync<BoardException>(() => auth.AuthenticateAsync(headers, Ct));
        Assert.Equal(403, ex.Status);
        Assert.Equal("principal disabled", ex.Message);
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'principal.disabled' and subject = 'agent2'"));
        Assert.Equal(1, await t.ScalarAsync("""
            select count(*) from messages m join channels c on c.id = m.channel_id
            where c.name = 'general' and m.body like '%disabled** @agent2%'
            """));

        await parts.SetEnabledAsync(admin, "agent2", true, "credential rotated", Ct);
        Assert.Equal("agent2", (await auth.AuthenticateAsync(headers, Ct)).Handle);
    }

    [DbFact]
    public async Task Participants_list_needs_admin_and_counts_activity()
    {
        var parts = new Participants(t.Db, t.Audit, t.Board, t.System);
        await Assert.ThrowsAsync<BoardException>(async () => await parts.ListAsync(await t.As("reader"), Ct));
        var list = await parts.ListAsync(await t.As("analyst"), Ct);
        Assert.DoesNotContain(list, p => p.Kind == "system");
        Assert.Contains(list, p => p.Handle == "agent" && p.Kind == "agent");
    }

    // ── agent names (set_profile, admin rename) ────────────────────────────────────────────────────
    private async Task<Principal> NewAgentAsync(string handle, string name = "Agent")
    {
        await using (var c = t.Db.Command("insert into principals (handle, display_name, kind, roles) values (@h, @n, 'agent', '{poster}')").With("h", handle).With("n", name))
            await c.ExecuteNonQueryAsync(Ct);
        return await t.As(handle);
    }

    private static async Task<int> StatusOf(Func<Task> call) => (await Assert.ThrowsAsync<BoardException>(call)).Status;

    [DbFact]
    public async Task Agent_replaces_its_generated_handle_once()
    {
        var parts = new Participants(t.Db, t.Audit, t.Board, t.System);
        var me = await NewAgentAsync("0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b", "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2bc0de");
        var p = await parts.SetOwnProfileAsync(me, new ProfileInput("Triage Agent", "Triage agent", "Triages new incidents"), Ct);
        Assert.Equal(("triage-agent", "Triage agent", "Triages new incidents"), (p.Handle, p.DisplayName, p.Description));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'principal.profile_updated' and subject = 'triage-agent' and detail->>'from_handle' = '0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b'"));

        // Now named: sending the same profile again (every restart) is fine, a new handle is not.
        me = await t.As("triage-agent");
        await parts.SetOwnProfileAsync(me, new ProfileInput("triage-agent", "Triage agent", "Triages new incidents"), Ct);
        Assert.Equal(403, await StatusOf(() => parts.SetOwnProfileAsync(me, new ProfileInput("analyst-helper"), Ct)));
        // The description stays the agent's to edit.
        Assert.Equal("Triages and enriches", (await parts.SetOwnProfileAsync(me, new ProfileInput(Description: "Triages and enriches"), Ct)).Description);
    }

    [DbFact]
    public async Task Profile_handle_clash_is_409_and_people_cannot_be_impersonated()
    {
        var parts = new Participants(t.Db, t.Audit, t.Board, t.System);
        var me = await NewAgentAsync("agent-0badc0de");
        Assert.Equal(409, await StatusOf(() => parts.SetOwnProfileAsync(me, new ProfileInput("agent2"), Ct)));
        Assert.Equal(403, await StatusOf(() => parts.SetOwnProfileAsync(me, new ProfileInput(DisplayName: "second ANALYST"), Ct))); // a person's display name
        Assert.Equal(403, await StatusOf(() => parts.SetOwnProfileAsync(me, new ProfileInput(DisplayName: "@analyst"), Ct)));      // a person's handle
        Assert.Equal(403, await StatusOf(() => parts.SetOwnProfileAsync(me, new ProfileInput("Second Analyst"), Ct)));         // @second-analyst reads as a person
        Assert.Equal(409, await StatusOf(() => parts.SetOwnProfileAsync(me, new ProfileInput("reader"), Ct)));                     // a person's handle: taken
        Assert.Equal(400, await StatusOf(() => parts.SetOwnProfileAsync(me, new ProfileInput(DisplayName: "two\nlines"), Ct)));
        Assert.Equal(400, await StatusOf(() => parts.SetOwnProfileAsync(me, new ProfileInput("agent-12345678"), Ct)));           // can't pick a generated-looking handle
        Assert.Equal("agent-0badc0de", (await t.As("agent-0badc0de")).Handle); // nothing changed
        // People's names come from Entra.
        Assert.Equal(403, await StatusOf(async () => await parts.SetOwnProfileAsync(await t.As("reader"), new ProfileInput(DisplayName: "Reader Bot"), Ct)));
    }

    [DbFact]
    public async Task Only_admins_rename_other_agents()
    {
        var parts = new Participants(t.Db, t.Audit, t.Board, t.System);
        await NewAgentAsync("hunter-bot", "Hunter bot");
        Assert.Equal(403, await StatusOf(async () => await parts.SetProfileAsync(await t.As("analyst2"), "hunter-bot", new ProfileInput("hunter"), Ct)));
        Assert.Equal(403, await StatusOf(async () => await parts.SetProfileAsync(await t.As("agent"), "hunter-bot", new ProfileInput("hunter"), Ct)));

        var admin = await t.As("analyst");
        var row = await parts.SetProfileAsync(admin, "hunter-bot", new ProfileInput("threat-hunter", "Threat hunter", "Hunts across Defender tables"), Ct);
        Assert.Equal(("threat-hunter", "Threat hunter", "Hunts across Defender tables"), (row.Handle, row.DisplayName, row.Description));
        Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'principal.profile_updated' and subject = 'threat-hunter' and (detail->>'by_admin')::boolean"));
        // Admins can rename an agent that already has a real handle, but the same checks apply.
        Assert.Equal(409, await StatusOf(() => parts.SetProfileAsync(admin, "threat-hunter", new ProfileInput("agent2"), Ct)));
        Assert.Equal(403, await StatusOf(() => parts.SetProfileAsync(admin, "threat-hunter", new ProfileInput(DisplayName: "Analyst"), Ct)));
        Assert.Equal(400, await StatusOf(() => parts.SetProfileAsync(admin, "analyst2", new ProfileInput(DisplayName: "Someone"), Ct))); // people aren't renamed here
        Assert.Equal(404, await StatusOf(() => parts.SetProfileAsync(admin, "nobody", new ProfileInput(DisplayName: "x"), Ct)));
    }

    [DbFact]
    public async Task First_sign_in_of_a_nameless_app_token_gets_an_agent_handle()
    {
        var auth = new Authenticator(t.Settings, new TokenValidator(t.Settings), t.Db, t.Audit);
        var appId = Guid.NewGuid().ToString();
        var upsert = typeof(Authenticator).GetMethod("UpsertAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!;
        var id = new CallerIdentity(Guid.NewGuid().ToString(), appId, "agent", appId, null, ["poster"]);
        var p = await (Task<Principal>)upsert.Invoke(auth, [id, Ct])!;
        Assert.Equal($"agent-{appId[..8]}", p.Handle);
        Assert.Equal($"Agent {appId[..8]}", p.DisplayName);
    }

    // ── #10 broker pause ───────────────────────────────────────────────────────────────────────────
    [DbFact]
    public async Task Pause_holds_approved_actions_until_an_approver_runs_them()
    {
        var admin = await t.As("analyst");
        try
        {
            await Assert.ThrowsAsync<BoardException>(async () => await t.Broker.SetPauseAsync(await t.As("analyst2"), true, "not an admin", Ct));
            await t.Broker.SetPauseAsync(admin, true, "investigating an agent", Ct);

            var a = await RequestIsolationAsync();
            // A second Broker instance stands in for another Function App instance: it reads the pause from the database.
            var other = t.Broker;
            var decided = await other.DecideAsync(admin, a.Id, "approve", "contain", Ct);
            Assert.Equal("approved", decided.Status);
            Assert.NotNull(decided.HeldAt);

            // Recovery sweep never runs a held action, even after unpausing.
            await t.Db.Command("update actions set updated_at = now() - interval '5 minutes' where id = @id").With("id", a.Id).ExecuteNonQueryAsync(Ct);
            await other.RecoverAsync(Ct);
            Assert.Equal("approved", (await t.Broker.GetAsync(a.Id, Ct))!.Status);

            var paused = await Assert.ThrowsAsync<BoardException>(async () => await t.Broker.RunNowAsync(await t.As("analyst2"), a.Id, Ct));
            Assert.Equal("broker paused by @analyst", paused.Message);

            await t.Broker.SetPauseAsync(admin, false, "agent cleared", Ct);
            await other.RecoverAsync(Ct);
            Assert.Equal("approved", (await t.Broker.GetAsync(a.Id, Ct))!.Status); // not run automatically

            await Assert.ThrowsAsync<BoardException>(async () => await t.Broker.RunNowAsync(await t.As("agent"), a.Id, Ct)); // agents can't
            var ran = await t.Broker.RunNowAsync(await t.As("analyst2"), a.Id, Ct);
            Assert.Equal("succeeded", ran.Status); // dry run
            Assert.Null(ran.HeldAt);
            Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'action.held' and subject = @s", ("s", a.Id.ToString())));
            Assert.Equal(1, await t.ScalarAsync("select count(*) from audit_log where event = 'action.released' and subject = @s", ("s", a.Id.ToString())));
        }
        finally { await ResumeAsync(); }
    }

    [DbFact]
    public async Task Pause_set_after_approval_stops_execution_at_claim_time()
    {
        var admin = await t.As("analyst");
        try
        {
            var a = await RequestIsolationAsync();
            // Simulate: approved on one instance, paused on another before the executor claims it.
            await t.Db.Command("update actions set status = 'approved' where id = @id").With("id", a.Id).ExecuteNonQueryAsync(Ct);
            await t.Broker.SetPauseAsync(admin, true, "stop everything", Ct);
            await t.Broker.ExecuteAsync(a.Id, Ct);
            var row = (await t.Broker.GetAsync(a.Id, Ct))!;
            Assert.Equal("approved", row.Status);
            Assert.NotNull(row.HeldAt);
            Assert.Contains(await t.Broker.ListAsync("held", Ct), x => x.Id == a.Id);
        }
        finally { await ResumeAsync(); }
    }

    // ── #3 notifications ───────────────────────────────────────────────────────────────────────────
    private Notifier NewNotifier(Receiver rx) => new(new HttpClient(rx), t.Db, t.Audit, t.Ms, t.Settings with
    {
        NotifyTeamsWebhookUrl = "https://teams.example.com/workflows/abc",
        NotifyWebhookUrl = "https://hooks.example.com/blueboard",
        NotifyWebhookSecret = Secret,
        NotifyAllowedHosts = ["teams.example.com", "hooks.example.com"],
        WebBaseUrl = "https://board.example.com",
        NotifyRemindMinutes = 15,
    });

    [DbFact]
    public async Task Each_event_goes_to_each_sink_once_across_instances()
    {
        await t.Db.Command("update actions set status = 'denied' where status = 'pending_approval'").ExecuteNonQueryAsync(Ct);
        await t.Db.Command("""update incidents set display_name = '[x](https://evil.example) <b>hi</b>' where graph_id = '90210'""").ExecuteNonQueryAsync(Ct);
        var a = await RequestIsolationAsync();
        var rx = new Receiver();
        // Two "instances" sweeping at once.
        var sent = await Task.WhenAll(NewNotifier(rx).RunOnceAsync(Ct), NewNotifier(rx).RunOnceAsync(Ct));
        Assert.Equal(2, sent.Sum());
        Assert.Equal(0, await NewNotifier(rx).RunOnceAsync(Ct)); // nothing new
        var mine = rx.Got.Where(g => g.Body.Contains(a.Id.ToString())).ToList();
        Assert.Equal(2, mine.Count);

        var hook = mine.Single(g => g.Uri.Host == "hooks.example.com");
        Assert.Equal(Notifier.Sign(hook.Body, Secret), hook.Signature);
        Assert.Contains("\"event\":\"action.pending_approval\"", hook.Body);
        Assert.Contains($"https://board.example.com/approvals#{a.Id}", hook.Body);
        Assert.DoesNotContain("PowerShell download cradle", hook.Body); // justification never leaves the board

        var teams = mine.Single(g => g.Uri.Host == "teams.example.com");
        Assert.Null(teams.Signature);
        Assert.Contains(@"\\[x\\]\\(https://evil\\.example\\)", teams.Body);
        Assert.DoesNotContain("PowerShell download cradle", teams.Body);

        // A reminder after the interval; deciding stops further reminders.
        await t.Db.Command("update actions set created_at = now() - interval '16 minutes' where id = @id").With("id", a.Id).ExecuteNonQueryAsync(Ct);
        Assert.Equal(2, await NewNotifier(rx).RunOnceAsync(Ct));
        Assert.Contains(rx.Got, g => g.Body.Contains("action.reminder") && g.Body.Contains(a.Id.ToString()));
        await t.Broker.DecideAsync(await t.As("analyst"), a.Id, "deny", null, Ct);
        await t.Db.Command("update actions set created_at = now() - interval '31 minutes' where id = @id").With("id", a.Id).ExecuteNonQueryAsync(Ct);
        Assert.Equal(0, await NewNotifier(rx).RunOnceAsync(Ct));
    }

    [DbFact]
    public async Task Failing_sink_is_audited_and_never_blocks()
    {
        await t.Db.Command("update actions set status = 'denied' where status = 'pending_approval'").ExecuteNonQueryAsync(Ct);
        var a = await RequestIsolationAsync();
        var rx = new Receiver { Status = HttpStatusCode.InternalServerError };
        Assert.Equal(0, await NewNotifier(rx).RunOnceAsync(Ct));
        Assert.Equal(2, await t.ScalarAsync("select count(*) from audit_log where event = 'notify.failed' and subject = @s", ("s", a.Id.ToString())));
        Assert.Equal(2, await t.ScalarAsync("select count(*) from notifications where action_id = @a and status = 'failed'", ("a", a.Id)));
        Assert.Equal("pending_approval", (await t.Broker.GetAsync(a.Id, Ct))!.Status);
        Assert.Equal(0, await t.ScalarAsync("select count(*) from audit_log where event = 'notify.failed' and detail::text like '%example.com%'"));
    }

    // ── #26 audit export ───────────────────────────────────────────────────────────────────────────
    [DbFact]
    public async Task Audit_rows_are_exported_once_in_order()
    {
        var rx = new Receiver();
        var settings = t.Settings with { AuditDceEndpoint = "https://bb-dce.australiaeast-1.ingest.monitor.azure.com", AuditDcrId = "dcr-0123456789abcdef0123456789abcdef" };
        var exporter = new AuditExporter(new HttpClient(rx), t.Db, settings, new StaticToken());
        // Don't depend on test order: make sure there is at least one row to export.
        await t.Audit.WriteAsync(null, "test.event", "seed", null, Ct);
        var first = await exporter.RunOnceAsync(Ct);
        Assert.True(first > 0);
        Assert.Equal(0, await exporter.RunOnceAsync(Ct));
        await t.Audit.WriteAsync(null, "test.event", "x", new { n = 1 }, Ct);
        Assert.Equal(1, await exporter.RunOnceAsync(Ct));

        var ids = rx.Got.SelectMany(g => JsonDocument.Parse(g.Body).RootElement.EnumerateArray().Select(r => r.GetProperty("AuditId").GetInt64())).ToList();
        Assert.Equal(ids.Distinct().Count(), ids.Count);
        Assert.Equal(await t.ScalarAsync("select count(*) from audit_log"), ids.Count);
        Assert.All(rx.Got, g => Assert.Equal("bb-dce.australiaeast-1.ingest.monitor.azure.com", g.Uri.Host));
        Assert.All(rx.Got, g => Assert.Equal("test-token", g.Auth));

        // A rejected batch doesn't move the mark: the same rows go next time.
        await t.Audit.WriteAsync(null, "test.event", "y", null, Ct);
        rx.Status = HttpStatusCode.Forbidden;
        await Assert.ThrowsAsync<HttpRequestException>(() => exporter.RunOnceAsync(Ct));
        rx.Status = HttpStatusCode.OK;
        Assert.Equal(1, await exporter.RunOnceAsync(Ct));
    }
}
