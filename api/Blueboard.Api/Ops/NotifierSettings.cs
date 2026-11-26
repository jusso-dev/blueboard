using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Api.Core;
using Blueboard.Api.Data;
using Blueboard.Contracts;
using Microsoft.Extensions.Logging;

namespace Blueboard.Api.Ops;

/// <summary>Notification settings storage and the settings page: board defaults, each person's overrides, test sends, recent deliveries.</summary>
public sealed partial class Notifier
{
    // ── storage ──────────────────────────────────────────────────────────────────────────────────
    private async Task<JsonObject?> StoredAsync(Guid? principalId, CancellationToken ct)
    {
        await using var cmd = db.Command("select settings::text from notification_settings where coalesce(principal_id, '00000000-0000-0000-0000-000000000000'::uuid) = @p")
            .With("p", principalId ?? Guid.Empty);
        return await cmd.ExecuteScalarAsync(ct) is string json ? Sanitise(json) : null;
    }

    /// <summary>A stored document that no longer validates (an older version, a hand edit) is ignored rather than breaking every notice.</summary>
    private JsonObject? Sanitise(string json)
    {
        try { return NotificationRules.ValidatePatch(JsonDocument.Parse(json).RootElement, allowNull: false); }
        catch (BoardException ex)
        {
            _log.LogWarning("ignoring stored notification settings: {Reason}", ex.Message);
            return null;
        }
    }

    /// <summary>The board defaults: built-in values with the admin's stored changes laid over them.</summary>
    public async Task<NotificationSettings> DefaultsAsync(CancellationToken ct = default) =>
        NotificationRules.Overlay(NotificationRules.BuiltIn, await StoredAsync(null, ct));

    /// <summary>Every enabled person, with effective settings and their sign-in name (when the board has seen one).</summary>
    internal async Task<IReadOnlyList<Person>> PeopleAsync(NotificationSettings defaults, CancellationToken ct = default)
    {
        var list = new List<Person>();
        await using var cmd = db.Command("""
            select p.handle, p.display_name, p.username, p.roles, s.settings::text
            from principals p left join notification_settings s on s.principal_id = p.id
            where p.kind = 'human' and p.enabled
            order by p.handle
            """);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            var mine = r.Get<string>("settings") is { } json ? Sanitise(json) : null;
            var email = r.Get<string>("username") is { } u && u.Contains('@') ? u : null;
            list.Add(new Person(r.GetString(0), r.GetString(1), email, r.GetFieldValue<string[]>(3), NotificationRules.Effective(defaults, mine)));
        }
        return list;
    }

    private async Task SaveAsync(Guid? principalId, JsonObject doc, Principal by, CancellationToken ct)
    {
        if (doc.Count == 0)
        {
            await using var del = db.Command("delete from notification_settings where coalesce(principal_id, '00000000-0000-0000-0000-000000000000'::uuid) = @p")
                .With("p", principalId ?? Guid.Empty);
            await del.ExecuteNonQueryAsync(ct);
            return;
        }
        await using var cmd = db.Command("""
            insert into notification_settings (principal_id, settings, updated_at, updated_by) values (@p, @s::jsonb, now(), @by)
            on conflict (coalesce(principal_id, '00000000-0000-0000-0000-000000000000'::uuid))
            do update set settings = excluded.settings, updated_at = now(), updated_by = excluded.updated_by
            """).With("p", principalId).With("s", doc.ToJsonString()).With("by", by.Id);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    // ── the settings page ────────────────────────────────────────────────────────────────────────
    private static void RequireHuman(Principal p)
    {
        if (!p.IsHuman) throw BoardException.Forbidden("notification settings are for people");
    }

    public IReadOnlyList<NotificationSinkStatus> SinkStatus()
    {
        var states = Sinks().ToDictionary(s => s.Sink);
        return NotificationRules.SinkKeys.Select(k => states.TryGetValue(k, out var s)
            ? new NotificationSinkStatus(k, true, s.Problem is null, s.Problem)
            : new NotificationSinkStatus(k, false, false, null)).ToList();
    }

    /// <summary>GET /api/notifications/settings: defaults, the caller's overrides, the merged result, sinks (never URLs).</summary>
    public async Task<NotificationSettingsView> GetSettingsAsync(Principal p, CancellationToken ct = default)
    {
        RequireHuman(p);
        var defaults = await DefaultsAsync(ct);
        var mine = await StoredAsync(p.Id, ct);
        return new NotificationSettingsView(defaults, mine is { Count: > 0 } ? JsonSerializer.SerializeToElement(mine) : null,
            NotificationRules.Effective(defaults, mine), SinkStatus(), p.Has(Roles.Admin));
    }

    /// <summary>PUT mine: a merge patch over the caller's overrides; null resets a field to the board default.</summary>
    public async Task<NotificationSettingsView> PutMineAsync(Principal p, JsonElement patch, CancellationToken ct = default)
    {
        RequireHuman(p);
        var (doc, changed) = Patched(await StoredAsync(p.Id, ct), patch);
        await SaveAsync(p.Id, doc, p, ct);
        await audit.WriteAsync(p.Id, "notify.settings_changed", p.Handle, new { scope = "mine", changed }, ct);
        return await GetSettingsAsync(p, ct);
    }

    /// <summary>PUT defaults (admin): a merge patch over the board defaults; null resets a field to the built-in default.</summary>
    public async Task<NotificationSettingsView> PutDefaultsAsync(Principal p, JsonElement patch, CancellationToken ct = default)
    {
        RequireHuman(p);
        p.Require(Roles.Admin);
        var (doc, changed) = Patched(await StoredAsync(null, ct), patch);
        await SaveAsync(null, doc, p, ct);
        await audit.WriteAsync(p.Id, "notify.settings_changed", "defaults", new { scope = "defaults", changed }, ct);
        return await GetSettingsAsync(p, ct);
    }

    /// <summary>A JSON null body resets everything; otherwise the patch is validated strictly and applied.</summary>
    private static (JsonObject Doc, IReadOnlyList<string> Changed) Patched(JsonObject? stored, JsonElement patch)
    {
        if (patch.ValueKind == JsonValueKind.Null) return (new JsonObject(), ["*"]);
        var p = NotificationRules.ValidatePatch(patch);
        var doc = NotificationRules.ApplyPatch(stored, p);
        if (JsonSerializer.Serialize(doc).Length > 8_192) throw new BoardException("notification settings too large");
        return (doc, NotificationRules.Paths(p));
    }

    /// <summary>
    /// POST /api/notifications/test: a sample of one event (or the generic test notice) addressed to the caller,
    /// through the ready sinks their settings have on. Marked test: true. At most one every 10 seconds per person. Audited.
    /// </summary>
    public async Task<IReadOnlyList<TestResult>> SendSampleAsync(Principal p, string? evt, CancellationToken ct = default)
    {
        RequireHuman(p);
        if (evt is not null && !NotificationRules.EventKeys.Contains(evt)) throw new BoardException($"event must be one of {string.Join(", ", NotificationRules.EventKeys)}");
        await using (var recent = db.Command("select count(*) from audit_log where actor_id = @p and event = 'notify.test' and at > now() - interval '10 seconds'").With("p", p.Id))
            if (Convert.ToInt64(await recent.ExecuteScalarAsync(ct)) > 0) throw BoardException.RateLimited("notify.test", 10);

        var defaults = await DefaultsAsync(ct);
        var me = (await PeopleAsync(defaults, ct)).FirstOrDefault(x => x.Handle == p.Handle)
                 ?? new Person(p.Handle, p.DisplayName, null, p.Roles, NotificationRules.Effective(defaults, await StoredAsync(p.Id, ct)));
        var to = new[] { me.Recipient };
        var rendered = evt switch
        {
            null => Render(new Notice("test", null, "Test notification", "No action: this checks the notification path", p.Handle, null, null, null, 0, Base(), "test", to)),
            "approvals" => Render(new Notice("action.pending_approval", Guid.Empty, "Isolate device (MDE)", "Sample: no action exists", "enrichment-agent",
                "0", "Sample incident", "high", 0, Base() is { } b ? $"{b}/approvals" : null, "pending_approval", to, Test: true)),
            _ => Render(SampleMessage(evt, to)),
        };
        var sinks = Sinks().Where(s => NotificationRules.SinkOn(me.Settings, s.Sink));
        var results = await SendToAsync(sinks, rendered, ct);
        await audit.WriteAsync(p.Id, "notify.test", evt, new { results = results.Select(r => new { r.Sink, r.Ok }) }, ct);
        return results;
    }

    private MessageNotice SampleMessage(string evt, IReadOnlyList<NotificationRecipient> to)
    {
        var author = evt is "incident" or "action_result" ? new Author("board", "Blueboard", "system") : new Author("enrichment-agent", "Enrichment agent", "agent");
        var (type, summary) = evt switch
        {
            "question" => ("question", "Sample: can you confirm whether ws-042 is a jump host before I propose isolation?"),
            "mention" => ("chat", "Sample: you were mentioned in a message on the board."),
            "reply" => ("chat", "Sample: a reply in a thread you started."),
            "verdict" => ("verdict", "Sample: credential theft confirmed on ws-042."),
            "finding" => ("finding", "Sample: the download cradle reached bad.example from ws-042."),
            "incident" => ("incident", "Sample: HIGH incident 0: Sample incident"),
            _ => ("action_result", "Sample: Update incident completed."),
        };
        return new MessageNotice(evt, Guid.Empty, evt is "incident" ? "incidents" : "triage", author, type, summary,
            "0", "Sample incident", "high", evt == "verdict" ? "truePositive" : null, evt == "verdict" ? 0.9 : null,
            evt == "action_result" ? new NoticeAction(Guid.Empty, "Update incident", "succeeded") : null,
            to, Base() is { } b ? $"{b}/channels/triage" : null, Test: true);
    }

    /// <summary>GET /api/notifications/recent (admin): the latest notices, newest first. Skipped claims aren't listed.</summary>
    public async Task<IReadOnlyList<NotificationDelivery>> RecentAsync(Principal p, int limit, CancellationToken ct = default)
    {
        p.Require(Roles.Admin);
        var list = new List<NotificationDelivery>();
        await using var cmd = db.Command("""
            select event, sink, status, error, recipient, created_at, message_id, action_id from notifications
            where status <> 'skipped' order by created_at desc, id desc limit @n
            """).With("n", Math.Clamp(limit, 1, 200));
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new NotificationDelivery(r.GetString(0), r.GetString(1), r.GetString(2), r.Get<string>("error"), r.Get<string>("recipient"),
                r.GetFieldValue<DateTimeOffset>(5), r.Get<Guid?>("message_id"), r.Get<Guid?>("action_id")));
        return list;
    }
}
