using System.Text;
using Blueboard.Api.Connectors;
using Blueboard.Api.Core;
using Blueboard.Api.Ops;
using Blueboard.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace Blueboard.Api.Http;

/// <summary>
/// Connector routes (docs/INTEGRATIONS.md): admin status and test, the incident page's Okta and ticket context, opening a
/// ticket by hand, and the signed inbound endpoint for ServiceNow / Jira. The inbound route has no Entra token (the ticketing
/// system can't get one): it authenticates with the per-system HMAC secret and a single-use nonce instead, and it can only
/// post an untrusted comment or attach a playbook.
/// </summary>
public sealed class ConnectorsApi(Endpoint ep, ConnectorHub hub, Setup setup, ILogger<ConnectorsApi> log)
{
    public const int MaxInboundBytes = 64 * 1024;

    [Function("admin-connectors")]
    [RouteDoc("Connector status: Okta, ServiceNow, Jira health, last sync and errors (admin; never credentials)", Response = typeof(ConnectorHub.ConnectorsView), Role = Roles.Admin)]
    public Task<IActionResult> Status([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "manage/connectors")] HttpRequest req) =>
        ep.RunAsync(req, async me => await hub.StatusAsync(me, req.HttpContext.RequestAborted), Roles.Admin);

    [Function("admin-connectors-test")]
    [RouteDoc("Test a connector with one harmless read (admin, people only; audited)", Body = typeof(ConnectorTestInput), Role = Roles.Admin)]
    public Task<IActionResult> Test([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "manage/connectors/test")] HttpRequest req) =>
        ep.RunAsync(req, async me =>
        {
            var body = await Endpoint.BodyAsync<ConnectorTestInput>(req);
            var result = await hub.TestAsync(me, body.Connector, req.HttpContext.RequestAborted);
            setup.Invalidate();
            return result;
        }, Roles.Admin);

    [Function("incident-connectors")]
    [RouteDoc("Okta context and ticket links for an incident (database only)", Response = typeof(ConnectorHub.IncidentConnectors))]
    public Task<IActionResult> Incident([HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "incidents/{id}/connectors")] HttpRequest req, string id) =>
        ep.RunAsync(req, async _ =>
        {
            var incidentId = await hub.ResolveIncidentAsync(id, req.HttpContext.RequestAborted);
            return await hub.IncidentAsync(incidentId, req.HttpContext.RequestAborted);
        });

    [Function("incident-ticket")]
    [RouteDoc("Open a ServiceNow or Jira ticket for an incident by hand (people with Board.RequestActions)", Body = typeof(TicketCreateInput), Role = Roles.Requester)]
    public Task<IActionResult> CreateTicket([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "incidents/{id}/ticket")] HttpRequest req, string id) =>
        ep.RunAsync(req, async me =>
        {
            var body = await Endpoint.BodyAsync<TicketCreateInput>(req);
            return await hub.CreateTicketAsync(me, id, body.System, req.HttpContext.RequestAborted);
        }, Roles.Requester);

    /// <summary>
    /// Signed ticket updates. Headers: X-Blueboard-Timestamp (unix seconds), X-Blueboard-Nonce (16-128 of [A-Za-z0-9_-]) and
    /// X-Blueboard-Signature ("sha256=" + hex HMAC-SHA256(secret, "{timestamp}.{nonce}.{body}")). Unknown systems and
    /// systems without a secret answer 404, so the route doesn't reveal which connectors exist.
    /// </summary>
    [Function("connector-inbound")]
    [RouteDoc("Signed inbound ServiceNow / Jira update: post an untrusted comment or attach a playbook (HMAC + nonce; cannot approve actions)", Body = typeof(TicketInbound), Role = "public")]
    public async Task<IActionResult> Inbound([HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "connectors/{system}/inbound")] HttpRequest req, string system)
    {
        try
        {
            if (system is not ("servicenow" or "jira")) return Json(404, new { error = "not found" });
            if (req.ContentLength is > MaxInboundBytes) return Json(413, new { error = "body too large" });
            using var ms = new MemoryStream();
            var buf = new byte[8192];
            int n;
            while ((n = await req.Body.ReadAsync(buf, req.HttpContext.RequestAborted)) > 0)
            {
                if (ms.Length + n > MaxInboundBytes) return Json(413, new { error = "body too large" });
                ms.Write(buf, 0, n);
            }
            var body = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
            var headers = req.Headers.ToDictionary(h => h.Key.ToLowerInvariant(), h => h.Value.ToString());
            var r = await hub.InboundAsync(system, headers, body, req.HttpContext.RequestAborted);
            return Json(r.Status, r.Body);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogError(ex, "connector inbound failed");
            return Json(500, new { error = "internal error" });
        }
    }

    private static ContentResult Json(int status, object body) =>
        new() { Content = Core.Json.Serialize(body), ContentType = "application/json", StatusCode = status };
}
