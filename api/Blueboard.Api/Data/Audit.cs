using Blueboard.Api.Core;

namespace Blueboard.Api.Data;

public class Audit(Db db)
{
    public virtual async Task WriteAsync(Guid? actorId, string evt, string? subject, object? detail = null, CancellationToken ct = default)
    {
        await using var cmd = db.Command("insert into audit_log (actor_id, event, subject, detail) values (@a, @e, @s, @d)")
            .With("a", actorId).With("e", evt).With("s", subject).WithJson("d", detail);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
