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
