using Blueboard.Api.Actions;
using Blueboard.Api.Core;
using Blueboard.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Blueboard.Api.Http;

/// <summary>
/// Policy administration (db/migrations/015): per-kind overrides within the policy.json ceiling, playbook triggers,
/// the automation kill switch, the second-admin queue, and Keep / Revert now on actions. REST only, never MCP: the
/// writes need a human Board.Admin (app-only tokens never carry it), and Keep / Revert now a human Board.Approve.
/// </summary>
public sealed class PolicyApi(Endpoint ep, PolicyStore store, Broker broker)
{
    private static Guid Id(string s) => Guid.TryParse(s, out var g) ? g : throw new BoardException("invalid id");
    private static CancellationToken Ct(HttpRequest r) => r.HttpContext.RequestAborted;

    [Function("policy-automation")]
    [RouteDoc("Automation: ceiling, overrides (file vs effective), playbook triggers, kill switch, pending and past changes")]
    public Task<IActionResult> View([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "policy/automation")] HttpRequest req) =>
        ep.RunAsync(req, async me => await store.ViewAsync(me, Ct(req)));

    [Function("policy-kind-set")]
    [RouteDoc("Change one action kind's override (human admin). Tightening applies now; loosening waits for a second admin", Body = typeof(KindOverrideInput), Response = typeof(PolicyChange), Role = Roles.Admin)]
    public Task<IActionResult> SetKind([HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "policy/kinds/{kind}")] HttpRequest req, string kind) =>
        ep.RunAsync(req, async me => await store.ChangeKindAsync(me, kind, await Endpoint.BodyAsync<KindOverrideInput>(req), Ct(req)), Roles.Admin);

    [Function("policy-trigger-set")]
    [RouteDoc("Add, edit, disable or remove a playbook trigger (human admin). Disabling/removing applies now; anything else waits for a second admin", Body = typeof(TriggerInput), Response = typeof(PolicyChange), Role = Roles.Admin)]
    public Task<IActionResult> SetTrigger([HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "policy/triggers/{id}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me => await store.ChangeTriggerAsync(me, id, await Endpoint.BodyAsync<TriggerInput>(req), Ct(req)), Roles.Admin);

    [Function("policy-automation-pause")]
    [RouteDoc("Automation kill switch (human admin): pause applies now; resume waits for a second admin", Body = typeof(AutomationPauseInput), Role = Roles.Admin)]
    public Task<IActionResult> Pause([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "policy/automation/pause")] HttpRequest req) =>
        ep.RunAsync(req, async me => await store.SetPauseAsync(me, await Endpoint.BodyAsync<AutomationPauseInput>(req), Ct(req)), Roles.Admin);

    [Function("policy-change-decide")]
    [RouteDoc("Approve or deny a pending loosening (a different human admin from the requester)", Body = typeof(PolicyChangeDecisionInput), Response = typeof(PolicyChange), Role = Roles.Admin)]
    public Task<IActionResult> Decide([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "policy/changes/{id:guid}")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me => await store.DecideAsync(me, Id(id), await Endpoint.BodyAsync<PolicyChangeDecisionInput>(req), Ct(req)), Roles.Admin);

    [Function("action-revert")]
    [RouteDoc("Keep (cancel the scheduled automatic revert) or Revert now (human approvers)", Body = typeof(RevertOpInput), Response = typeof(ActionRow), Role = Roles.Approver)]
    public Task<IActionResult> Revert([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "actions/{id:guid}/revert")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me => await broker.RevertOpAsync(me, Id(id), await Endpoint.BodyAsync<RevertOpInput>(req), Ct(req)), Roles.Approver);
}
