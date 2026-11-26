using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Ops;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Blueboard.Api.Http;

/// <summary>Operations routes: setup checklist, shell status banner, participants admin, broker pause, run held actions.</summary>
public sealed class OpsApi(Endpoint ep, Setup setup, Notifier notifier, Participants participants, Broker broker, AuditLog auditLog, Posture posture)
{
    private static Guid Id(string s) => Guid.TryParse(s, out var g) ? g : throw new BoardException("invalid id");

    /// <summary>Cheap state for the banner on every page (Board.Post): broker mode, pause, policy loaded or default.</summary>
    [Function("status")]
    [RouteDoc("Board status banner state: broker mode, pause, policy, held actions")]
    public Task<IActionResult> Status([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "status")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await setup.StatusAsync(req.HttpContext.RequestAborted));

    /// <summary>The setup checklist (Board.Admin), cached for 60 seconds. ?fresh=true re-runs it.</summary>
    [Function("setup")]
    [RouteDoc("Setup checklist and health probes (admin)", Role = Roles.Admin)]
    public Task<IActionResult> SetupChecks([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "setup")] HttpRequest req) =>
        ep.RunAsync(req, async _ =>
        {
            if (req.Query["fresh"] == "true") setup.Invalidate();
            return await setup.GetAsync(req.HttpContext.RequestAborted);
        }, Roles.Admin);

    [Function("setup-test-notification")]
    [RouteDoc("Send a test notification to configured approver sinks (admin)", Role = Roles.Admin)]
    public Task<IActionResult> TestNotification([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "setup/test-notification")] HttpRequest req) =>
        ep.RunAsync(req, async me => await notifier.SendTestAsync(me, req.HttpContext.RequestAborted), Roles.Admin);

    // ── notification settings ──────────────────────────────────────────────────────────────────────
    /// <summary>A PUT body as raw JSON (a merge patch, or null to reset everything). Validated strictly by the notifier.</summary>
    private static async Task<System.Text.Json.JsonElement> PatchAsync(HttpRequest req)
    {
        if (req.ContentLength is > 64_000) throw new BoardException("body too large", 413);
        if (req.ContentLength is 0) throw new BoardException("body required: a JSON object of settings to change");
        using var doc = await System.Text.Json.JsonDocument.ParseAsync(req.Body, default, req.HttpContext.RequestAborted);
        return doc.RootElement.Clone();
    }

    [Function("notifications-settings")]
    [RouteDoc("Notification settings: board defaults, your overrides, the effective result and sink status (people)", Response = typeof(Blueboard.Contracts.NotificationSettingsView), Role = null)]
    public Task<IActionResult> GetNotificationSettings([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "notifications/settings")] HttpRequest req) =>
        ep.RunAsync(req, async me => await notifier.GetSettingsAsync(me, req.HttpContext.RequestAborted), role: null);

    [Function("notifications-settings-mine")]
    [RouteDoc("Change your own notification settings (merge patch; null resets a field to the board default)", Body = typeof(Blueboard.Contracts.NotificationSettingsPatch), Response = typeof(Blueboard.Contracts.NotificationSettingsView), Role = null)]
    public Task<IActionResult> PutMyNotificationSettings([HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "notifications/settings/mine")] HttpRequest req) =>
        ep.RunAsync(req, async me => await notifier.PutMineAsync(me, await PatchAsync(req), req.HttpContext.RequestAborted), role: null);

    [Function("notifications-settings-defaults")]
    [RouteDoc("Change the board's default notification settings (admin; merge patch, null resets a field)", Body = typeof(Blueboard.Contracts.NotificationSettingsPatch), Response = typeof(Blueboard.Contracts.NotificationSettingsView), Role = Roles.Admin)]
    public Task<IActionResult> PutDefaultNotificationSettings([HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "notifications/settings/defaults")] HttpRequest req) =>
        ep.RunAsync(req, async me => await notifier.PutDefaultsAsync(me, await PatchAsync(req), req.HttpContext.RequestAborted), Roles.Admin);

    [Function("notifications-test")]
    [RouteDoc("Send yourself a sample notice of one event through the sinks your settings have on", Body = typeof(Blueboard.Contracts.NotificationTestInput), Response = typeof(Notifier.TestResult[]), Role = null)]
    public Task<IActionResult> TestNotifications([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "notifications/test")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            var body = req.ContentLength is null or 0 ? new Blueboard.Contracts.NotificationTestInput() : await Endpoint.BodyAsync<Blueboard.Contracts.NotificationTestInput>(req);
            return await notifier.SendSampleAsync(me, body.Event, req.HttpContext.RequestAborted);
        }, role: null);

    [Function("notifications-recent")]
    [RouteDoc("Recent notification deliveries, newest first (admin)", Query = typeof(Blueboard.Contracts.NotificationRecentQuery), Response = typeof(Blueboard.Contracts.NotificationDelivery[]), Role = Roles.Admin)]
    public Task<IActionResult> RecentNotifications([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "notifications/recent")] HttpRequest req) =>
        ep.RunAsync(req, async me => await notifier.RecentAsync(me, Endpoint.Query<Blueboard.Contracts.NotificationRecentQuery>(req).Limit, req.HttpContext.RequestAborted), Roles.Admin);

    [Function("admin-posture")]
    [RouteDoc("Enterprise posture: which controls this deployment enforces, scored, with fixes (admin)", Response = typeof(PostureReport), Role = Roles.Admin)]
    public Task<IActionResult> GetPosture([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/posture")] HttpRequest req) =>
        ep.RunAsync(req, async me => await posture.BuildAsync(me, req.HttpContext.RequestAborted), Roles.Admin);

    // ── audit log ──────────────────────────────────────────────────────────────────────────────────
    [Function("admin-audit")]
    [RouteDoc("Audit log, newest first, with filters (admin); format=csv to export (people only; the export is itself audited)", Query = typeof(Blueboard.Contracts.AuditQuery), Response = typeof(AuditPage), Role = Roles.Admin)]
    public Task<IActionResult> Audit([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/audit")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            var q = Endpoint.Query<Blueboard.Contracts.AuditQuery>(req);
            if (q.Format != "csv") return (object)await auditLog.QueryAsync(me, q, req.HttpContext.RequestAborted);
            var csv = await auditLog.ExportCsvAsync(me, q, req.HttpContext.RequestAborted);
            req.HttpContext.Response.Headers.ContentDisposition = $"attachment; filename=\"blueboard-audit-{DateTime.UtcNow:yyyy-MM-dd}.csv\"";
            return new ContentResult { Content = csv, ContentType = "text/csv; charset=utf-8", StatusCode = 200 };
        }, Roles.Admin);

    [Function("admin-participants")]
    [RouteDoc("List all participants with activity and enabled state (admin)", Role = Roles.Admin)]
    public Task<IActionResult> ListParticipants([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/participants")] HttpRequest req) =>
        ep.RunAsync(req, async me => await participants.ListAsync(me, req.HttpContext.RequestAborted), Roles.Admin);

    public sealed record EnabledBody(bool Enabled, string? Reason);

    [Function("admin-participant-set")]
    [RouteDoc("Enable or disable a participant (admin)", Body = typeof(EnabledBody), Role = Roles.Admin)]
    public Task<IActionResult> SetParticipant([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "manage/participants/{handle}")] HttpRequest req, string handle) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<EnabledBody>(req);
            return await participants.SetEnabledAsync(me, handle, b.Enabled, b.Reason, req.HttpContext.RequestAborted);
        }, Roles.Admin);

    /// <summary>Rename an agent: handle, display name, description (omitted fields are kept). Old messages keep the old handle.</summary>
    [Function("admin-participant-profile")]
    [RouteDoc("Set an agent's handle, display name or description (admin)", Body = typeof(Blueboard.Contracts.ProfileInput), Role = Roles.Admin)]
    public Task<IActionResult> SetParticipantProfile([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "manage/participants/{handle}/profile")] HttpRequest req, string handle) =>
        ep.RunAsync(req, async me =>
            await participants.SetProfileAsync(me, handle, await Endpoint.BodyAsync<Blueboard.Contracts.ProfileInput>(req), req.HttpContext.RequestAborted), Roles.Admin);

    [Function("admin-broker")]
    [RouteDoc("Read broker pause state (admin)", Role = Roles.Admin)]
    public Task<IActionResult> GetBroker([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/broker")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await broker.GetPauseAsync(req.HttpContext.RequestAborted), Roles.Admin);

    public sealed record PauseBody(bool Paused, string? Reason);

    [Function("admin-broker-set")]
    [RouteDoc("Pause or resume the action broker (admin)", Body = typeof(PauseBody), Role = Roles.Admin)]
    public Task<IActionResult> SetBroker([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "manage/broker")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            var b = await Endpoint.BodyAsync<PauseBody>(req);
            var state = await broker.SetPauseAsync(me, b.Paused, b.Reason, req.HttpContext.RequestAborted);
            setup.Invalidate();
            return state;
        }, Roles.Admin);

    /// <summary>Run an action that was approved while the broker was paused (human approver, not the requester).</summary>
    [Function("action-run")]
    [RouteDoc("Run an approved action that was held while the broker was paused", Body = typeof(Blueboard.Contracts.RunActionInput), Role = Roles.Approver)]
    public Task<IActionResult> RunNow([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "actions/{id:guid}/run")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var body = req.ContentLength is null or 0 ? new Blueboard.Contracts.RunActionInput() : await Endpoint.BodyAsync<Blueboard.Contracts.RunActionInput>(req);
            return await broker.RunNowAsync(me, Id(id), req.HttpContext.RequestAborted, body.Confirm);
        }, Roles.Approver);
}
