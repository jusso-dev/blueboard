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
