using System.Text.Json;

namespace Blueboard.Agent;

/// <summary>
/// What an agent has done, saved to a JSON file so a restart picks up exactly where it stopped: the feed cursor
/// and the ids it already handled. The file is written to a temp name and moved into place, so a crash mid-write
/// never leaves a half-written state.
/// </summary>
public sealed class AgentState
{
    public string? Cursor { get; set; }
    public List<string> Done { get; set; } = [];
    /// <summary>Thread roots this agent posted in (root or reply), newest last. Human replies in them reach the agent without an @mention.</summary>
    public List<string> Threads { get; set; } = [];
    /// <summary>Incidents this agent posted on, with when it last did (unix seconds). Newest last.</summary>
    public Dictionary<string, long> Incidents { get; set; } = [];

    public const int MaxConversations = 500;

    private HashSet<string>? _done;
    private HashSet<string> DoneSet => _done ??= [.. Done];

    public bool IsDone(Guid id) => DoneSet.Contains(id.ToString());

    public void MarkDone(Guid id)
    {
        if (!DoneSet.Add(id.ToString())) return;
        Done.Add(id.ToString());
        if (Done.Count > 5000)
        {
            Done.RemoveRange(0, Done.Count - 5000);
            _done = [.. Done];
        }
    }

    public bool InThread(Guid rootId) => Threads.Contains(rootId.ToString());

    /// <summary>Remember that this agent posted in a thread (and on its incident, if linked). Keeps the newest 500 of each.</summary>
    public void MarkPosted(Guid rootId, Guid? incidentId, DateTimeOffset at)
    {
        var root = rootId.ToString();
        Threads.Remove(root);
        Threads.Add(root);
        if (Threads.Count > MaxConversations) Threads.RemoveRange(0, Threads.Count - MaxConversations);
        if (incidentId is not { } inc) return;
        Incidents[inc.ToString()] = Math.Max(Incidents.GetValueOrDefault(inc.ToString()), at.ToUnixTimeSeconds());
        if (Incidents.Count > MaxConversations)
            foreach (var old in Incidents.OrderBy(kv => kv.Value).Take(Incidents.Count - MaxConversations).Select(kv => kv.Key).ToList())
                Incidents.Remove(old);
    }

    /// <summary>True when this agent posted on the incident within <paramref name="window"/> of <paramref name="at"/>.</summary>
    public bool PostedOnIncident(Guid incidentId, DateTimeOffset at, TimeSpan window) =>
        Incidents.TryGetValue(incidentId.ToString(), out var last) && at.ToUnixTimeSeconds() - last <= window.TotalSeconds;

    public static async Task<AgentState> LoadAsync(string path, CancellationToken ct = default) =>
        File.Exists(path) ? JsonSerializer.Deserialize<AgentState>(await File.ReadAllTextAsync(path, ct)) ?? new() : new();

    public async Task SaveAsync(string path, CancellationToken ct = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var tmp = path + ".tmp";
        await File.WriteAllTextAsync(tmp, JsonSerializer.Serialize(this), ct);
        File.Move(tmp, path, overwrite: true);
    }
}
