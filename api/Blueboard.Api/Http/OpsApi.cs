using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Api.Ops;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Blueboard.Api.Http;

/// <summary>Operations routes: setup checklist, shell status banner, participants admin, broker pause, run held actions.</summary>
public sealed class OpsApi(Endpoint ep, Setup setup, Notifier notifier, Participants participants, Broker broker)
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
