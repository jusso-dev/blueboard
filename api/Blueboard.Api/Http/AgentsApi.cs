using Blueboard.Api.Agents;
using Blueboard.Api.Core;
using Blueboard.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Blueboard.Api.Http;

/// <summary>
/// Agent observability routes for the web app. Feedback and traces need Board.Post (feedback: people only); budgets,
/// top-ups, settings, the cost dashboard and risk scores need Board.Admin and are refused to agents. None of the
/// admin routes have an MCP tool: agents can't change their own budget or thresholds.
/// </summary>
public sealed class AgentsApi(Endpoint ep, AgentBudgets budgets, AgentFeedback feedback, AgentTrace trace, AgentRisk risk, AgentReports reports, ObservabilitySettingsStore settings)
{
    private static Guid Id(string s) => Guid.TryParse(s, out var g) ? g : throw new BoardException("invalid id");
    private static CancellationToken Ct(HttpRequest r) => r.HttpContext.RequestAborted;

    private static void HumanAdmin(Principal me)
    {
        me.Require(Roles.Admin);
        if (!me.IsHuman) throw BoardException.Forbidden("people only");
    }

    // ── feedback (people) ──────────────────────────────────────────────────────────────────────────
    [Function("message-feedback-get")]
    [RouteDoc("Feedback on an agent's verdict, finding or ioc message")]
    public Task<IActionResult> GetFeedback([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "messages/{id:guid}/feedback")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me => await feedback.ForMessageAsync(me, Id(id), Ct(req)));

    [Function("message-feedback-set")]
    [RouteDoc("Mark an agent's verdict, finding or ioc correct or incorrect (people only)", Body = typeof(FeedbackInput))]
    public Task<IActionResult> SetFeedback([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "messages/{id:guid}/feedback")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me => await feedback.GiveAsync(me, Id(id), await Endpoint.BodyAsync<FeedbackInput>(req), Ct(req)));

    [Function("message-feedback-delete")]
    [RouteDoc("Take back your feedback on a message (people only)")]
    public Task<IActionResult> DeleteFeedback([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "messages/{id:guid}/feedback")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me => await feedback.RemoveAsync(me, Id(id), Ct(req)));

    // ── traces ─────────────────────────────────────────────────────────────────────────────────────
    [Function("message-trace")]
    [RouteDoc("Agent trace: the MCP calls that led to this agent message (redacted arguments, KQL, status, timing)", Response = typeof(TraceCall[]))]
    public Task<IActionResult> MessageTrace([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "messages/{id:guid}/trace")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ => await trace.ForMessageAsync(Id(id), Ct(req)));

    [Function("incident-trace")]
    [RouteDoc("Agent trace for an incident: every agent MCP call linked to it", Response = typeof(TraceCall[]))]
    public Task<IActionResult> IncidentTrace([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents/{id:guid}/trace")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ => await trace.ForIncidentAsync(Id(id), Ct(req)));

    [Function("agent-trace")]
    [RouteDoc("One agent's latest MCP calls (admin)", Response = typeof(TraceCall[]), Role = Roles.Admin)]
    public Task<IActionResult> AgentTraceRoute([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/agents/{handle}/trace")] HttpRequest req, string handle) =>
        ep.RunAsync(req, async _ => await trace.ForAgentAsync(handle, int.TryParse(req.Query["limit"], out var n) ? n : 100, Ct(req)), Roles.Admin);

    // ── dashboard, budgets, risk, settings (Board.Admin people) ───────────────────────────────────
    [Function("agents-report")]
    [RouteDoc("Agent cost and accuracy dashboard (admin)", Query = typeof(AgentReportQuery), Response = typeof(AgentCostReport), Role = Roles.Admin)]
    public Task<IActionResult> Report([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/agents/report")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            var q = Endpoint.Query<AgentReportQuery>(req);
            return await reports.BuildAsync(me, q.From, q.To, Ct(req));
        }, Roles.Admin);

    [Function("agents-budgets")]
    [RouteDoc("Every agent's budget, spend today and this month, and reporting health (admin)", Response = typeof(AgentBudgetRow[]), Role = Roles.Admin)]
    public Task<IActionResult> Budgets([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/agents/budgets")] HttpRequest req) =>
        ep.RunAsync(req, async me => await budgets.ListAsync(me, Ct(req)), Roles.Admin);

    [Function("agents-budget-set")]
    [RouteDoc("Set an agent's hard budget (admin, people only)", Body = typeof(BudgetInput), Response = typeof(AgentBudgetRow), Role = Roles.Admin)]
    public Task<IActionResult> SetBudget([HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "manage/agents/{handle}/budget")] HttpRequest req, string handle) =>
        ep.RunAsync(req, async me =>
        {
            HumanAdmin(me);
            return await budgets.SetBudgetAsync(me, handle, await Endpoint.BodyAsync<BudgetInput>(req), Ct(req));
        }, Roles.Admin);

    [Function("agents-budget-delete")]
    [RouteDoc("Remove an agent's budget (admin, people only; ?reason=)", Response = typeof(AgentBudgetRow), Role = Roles.Admin)]
    public Task<IActionResult> DeleteBudget([HttpTrigger(AuthorizationLevel.Anonymous, "delete", Route = "manage/agents/{handle}/budget")] HttpRequest req, string handle) =>
        ep.RunAsync(req, async me =>
        {
            HumanAdmin(me);
            return await budgets.RemoveBudgetAsync(me, handle, req.Query["reason"].FirstOrDefault(), Ct(req));
        }, Roles.Admin);

    [Function("agents-budget-topup")]
    [RouteDoc("Grant an agent a temporary budget top-up (admin, people only)", Body = typeof(TopupInput), Response = typeof(AgentBudgetRow), Role = Roles.Admin)]
    public Task<IActionResult> TopUp([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "manage/agents/{handle}/topup")] HttpRequest req, string handle) =>
        ep.RunAsync(req, async me =>
        {
            HumanAdmin(me);
            return await budgets.TopUpAsync(me, handle, await Endpoint.BodyAsync<TopupInput>(req), Ct(req));
        }, Roles.Admin);

    [Function("agents-risk")]
    [RouteDoc("Agent risk scores with contributing factors (admin)", Response = typeof(AgentRiskScore[]), Role = Roles.Admin)]
    public Task<IActionResult> Risk([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/agents/risk")] HttpRequest req) =>
        ep.RunAsync(req, async me => await risk.ListAsync(me, Ct(req)), Roles.Admin);

    [Function("agents-settings")]
    [RouteDoc("Agent observability settings: trace retention, risk alert and quarantine thresholds (admin)", Response = typeof(ObservabilitySettings), Role = Roles.Admin)]
    public Task<IActionResult> GetSettings([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/agents/settings")] HttpRequest req) =>
        ep.RunAsync(req, async _ => await settings.GetAsync(Ct(req)), Roles.Admin);

    [Function("agents-settings-set")]
    [RouteDoc("Change agent observability settings (admin, people only)", Body = typeof(ObservabilitySettingsInput), Response = typeof(ObservabilitySettings), Role = Roles.Admin)]
    public Task<IActionResult> SetSettings([HttpTrigger(AuthorizationLevel.Anonymous, "put", Route = "manage/agents/settings")] HttpRequest req) =>
        ep.RunAsync(req, async me => await settings.SetAsync(me, await Endpoint.BodyAsync<ObservabilitySettingsInput>(req), Ct(req)), Roles.Admin);
}
