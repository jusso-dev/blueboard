using Blueboard.Contracts;
using Blueboard.Api.Core;
using Blueboard.Api.Data;

namespace Blueboard.Api.Board;

public sealed record SearchResult(IReadOnlyList<Message> Hits, int Total);

/// <summary>
/// Full-text search over message bodies (English stemming) and IOC values (exact, 'simple' config),
/// via the generated tsvector column + GIN index from migration 002. websearch_to_tsquery accepts what
/// people type: "phrases", or, -exclusions.
/// </summary>
public sealed class Search(Db db, BoardService board)
{
    public async Task<SearchResult> RunAsync(SearchQuery q, CancellationToken ct = default)
    {
        var text = string.IsNullOrWhiteSpace(q.Q) ? null : q.Q.Trim();
        if (text is { Length: > 500 }) throw new BoardException("query too long");
        if (q.Types?.Except(MessageTypes.All).FirstOrDefault() is { } badType) throw new BoardException($"unknown type {badType}");
        if (q.AuthorKind is not (null or "agent" or "human" or "system")) throw new BoardException("author_kind must be agent, human or system");
        if (q.ClaimState is not (null or "open" or "claimed" or "done")) throw new BoardException("claim_state must be open, claimed or done");
        if (q.Sort is not ("relevance" or "newest" or "oldest")) throw new BoardException("sort must be relevance, newest or oldest");
        var limit = Math.Clamp(q.Limit, 1, 100);
        var offset = Math.Clamp(q.Offset, 0, 10_000);
        var incidentId = await board.ResolveIncidentAsync(q.Incident, ct);

        await using var cmd = db.Command("");
        var where = new List<string> { "true" };
        const string tsq = "(websearch_to_tsquery('english', @q) || websearch_to_tsquery('simple', @q))";
        if (text is not null) { where.Add($"m.search @@ {tsq}"); cmd.With("q", text); }
        if (q.Channel is { } ch) { where.Add("c.name = @ch"); cmd.With("ch", ch); }
        if (q.Types is { Length: > 0 } t) { where.Add("m.type = any(@types)"); cmd.With("types", t); }
        if (q.Author is { } au) { where.Add("a.handle = @au"); cmd.With("au", au); }
        if (q.AuthorKind is { } ak) { where.Add("a.kind = @ak"); cmd.With("ak", ak); }
        if (incidentId is { } inc) { where.Add("m.incident_id = @inc"); cmd.With("inc", inc); }
        switch (q.ClaimState)
        {
            case "open": where.Add("m.type in ('question','finding','ioc') and (m.claim_state = 'open' or (m.claim_state = 'claimed' and m.claim_expires_at < now()))"); break;
            case "claimed": where.Add("m.claim_state = 'claimed' and m.claim_expires_at >= now()"); break;
            case "done": where.Add("m.claim_state = 'done'"); break;
        }
        if (q.From is { } from) { where.Add("m.created_at >= @from"); cmd.With("from", from); }
        if (q.To is { } to) { where.Add("m.created_at < @to"); cmd.With("to", to); }
        cmd.With("limit", limit).With("offset", offset);

        var sort = q.Sort == "relevance" && text is null ? "newest" : q.Sort;
        var order = sort switch { "relevance" => "rank desc, m.seq desc", "oldest" => "m.seq asc", _ => "m.seq desc" };
        var rank = text is null ? "null::real" : $"ts_rank_cd(m.search, {tsq})";
        var snippet = text is null ? "null::text"
            : "ts_headline('english', m.body, websearch_to_tsquery('english', @q), 'StartSel=<<,StopSel=>>,MaxWords=30,MinWords=12,MaxFragments=2,FragmentDelimiter= … ')";

        // Page over ids first (index-friendly), then hydrate just that page.
        cmd.CommandText = $"""
            select m.id, {rank} as rank, {snippet} as snippet, count(*) over()::int as total
            from messages m
            join channels c on c.id = m.channel_id
            join principals a on a.id = m.author_id
            where {string.Join(" and ", where)}
            order by {order}
            limit @limit offset @offset
            """;
        var page = new List<(Guid Id, string? Snippet)>();
        var total = 0;
        await using (var r = await cmd.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct))
            {
                page.Add((r.GetGuid(0), r.IsDBNull(2) ? null : r.GetString(2).Replace("**", "")));
                total = r.GetInt32(3);
            }
        var byId = (await board.GetManyAsync(page.Select(x => x.Id).ToList(), ct)).ToDictionary(m => m.Id);
        var hits = page.Where(x => byId.ContainsKey(x.Id)).Select(x => byId[x.Id] with { Snippet = x.Snippet }).ToList();
        return new SearchResult(hits, total);
    }
}
