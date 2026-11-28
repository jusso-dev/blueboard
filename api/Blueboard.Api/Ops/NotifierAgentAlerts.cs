using Blueboard.Contracts;
using Microsoft.Extensions.Logging;

namespace Blueboard.Api.Ops;

/// <summary>
/// Agent observability alerts (WS3): an agent hit its hard budget, crossed its soft budget alert, or its risk score
/// crossed the admin threshold. Sent straight to approvers on every ready sink (they decide budgets and quarantine),
/// best effort: a failed sink is logged and audited like any other notice, never thrown to the caller.
/// The board message in #general is the durable record; this is the nudge.
/// </summary>
public sealed partial class Notifier
{
    /// <summary>Sends one agent alert to approvers who have approval notices on. Returns notices sent.</summary>
    public async Task<int> AlertApproversAsync(string evt, string headline, string agentHandle, string detail, string path, CancellationToken ct = default)
    {
        var sinks = ReadySinks().ToArray();
        if (sinks.Length == 0) return 0;
        var defaults = await DefaultsAsync(ct);
        var people = await PeopleAsync(defaults, ct);
        var sent = 0;
        foreach (var sink in sinks)
        {
            var to = people.Where(p => p.IsApprover && p.Settings is { Enabled: true, Events.Approvals: true } && NotificationRules.SinkOn(p.Settings, sink)).ToList();
            if (to.Count == 0) continue;
            var notice = new Notice(evt, null, headline, detail, agentHandle, null, null, null, 0,
                Base() is { } b ? $"{b}{path}" : null, "alert", to.Select(p => p.Recipient).ToList());
            try
            {
                await SendAsync(sink, Render(notice), ct);
                sent++;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                var error = SafeError(ex);
                _log.LogWarning(ex, "agent alert to {Sink} failed: {Error}", sink, error);
                await audit.WriteAsync(null, "notify.failed", agentHandle, new { sink, @event = evt, error }, CancellationToken.None);
            }
        }
        return sent;
    }
}
