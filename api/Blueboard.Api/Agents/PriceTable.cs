using System.Text.Json;
using Blueboard.Api.Core;

namespace Blueboard.Api.Agents;

/// <summary>USD per million tokens for one model (cache write is the 5-minute TTL price).</summary>
public sealed record ModelPrice(double Input, double Output, double CacheRead, double CacheWrite)
{
    public double Cost(long input, long output, long cacheRead, long cacheWrite) =>
        (input * Input + output * Output + cacheRead * CacheRead + cacheWrite * CacheWrite) / 1_000_000d;
}

/// <summary>
/// The board's own LLM price table, so agent-reported token counts are priced by the board, not by the agent.
/// Built-in Anthropic first-party prices (November 2026), overridable and extendable with AGENT_PRICE_TABLE. Tool
/// prices are USD per MCP call for board-side metering (default 0: the board counts calls, an admin can price them).
/// </summary>
public sealed class PriceTable
{
    private readonly Dictionary<string, ModelPrice> _models;
    private readonly Dictionary<string, double> _tools;

    public static readonly IReadOnlyDictionary<string, ModelPrice> BuiltIn = new Dictionary<string, ModelPrice>(StringComparer.OrdinalIgnoreCase)
    {
        ["claude-fable-5-2"] = new(8, 40, 0.20, 10),
        ["claude-mythos-5-2"] = new(8, 40, 0.20, 10),
        ["claude-fable-5-1"] = new(10, 50, 0.25, 12.5),
        ["claude-mythos-5-1"] = new(10, 50, 0.25, 12.5),
        ["claude-fable-5"] = new(10, 50, 1, 12.5),
        ["claude-mythos-5"] = new(10, 50, 1, 12.5),
        ["claude-opus-5-5"] = new(4, 20, 0.20, 5),
        ["claude-opus-5"] = new(5, 25, 0.50, 6.25),
        ["claude-opus-4-8"] = new(5, 25, 0.50, 6.25),
        ["claude-opus-4-7"] = new(5, 25, 0.50, 6.25),
        ["claude-opus-4-6"] = new(5, 25, 0.50, 6.25),
        ["claude-opus-4-5"] = new(5, 25, 0.50, 6.25),
        ["claude-sonnet-5-5"] = new(2, 10, 0.10, 2.5),
        ["claude-sonnet-5"] = new(2, 10, 0.20, 2.5),
        ["claude-sonnet-4-6"] = new(3, 15, 0.30, 3.75),
        ["claude-sonnet-4-5"] = new(3, 15, 0.30, 3.75),
        ["claude-haiku-5-5"] = new(0.10, 0.50, 0.01, 0.125),
        ["claude-haiku-4-5"] = new(1, 5, 0.10, 1.25),
    };

    public PriceTable(Settings settings) : this(settings.AgentPriceTableJson) { }

    public PriceTable(string? overridesJson = null)
    {
        _models = new Dictionary<string, ModelPrice>(BuiltIn, StringComparer.OrdinalIgnoreCase);
        _tools = new Dictionary<string, double>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(overridesJson)) return;
        JsonElement root;
        try { root = JsonDocument.Parse(overridesJson).RootElement; }
        catch (JsonException) { throw new InvalidOperationException("AGENT_PRICE_TABLE must be JSON: {\"models\":{...},\"tools\":{...}}"); }
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidOperationException("AGENT_PRICE_TABLE must be a JSON object");
        foreach (var p in root.EnumerateObject())
        {
            if (p.Name == "models" && p.Value.ValueKind == JsonValueKind.Object)
                foreach (var m in p.Value.EnumerateObject())
                {
                    double N(string k) => m.Value.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.Number && v.GetDouble() is var x && x is >= 0 and <= 10_000
                        ? x : throw new InvalidOperationException($"AGENT_PRICE_TABLE models.{m.Name}.{k} must be a number 0-10000 (USD per million tokens)");
                    var input = N("input");
                    _models[m.Name] = new ModelPrice(input, N("output"),
                        m.Value.TryGetProperty("cache_read", out _) ? N("cache_read") : input * 0.1,
                        m.Value.TryGetProperty("cache_write", out _) ? N("cache_write") : input * 1.25);
                }
            else if (p.Name == "tools" && p.Value.ValueKind == JsonValueKind.Object)
                foreach (var t in p.Value.EnumerateObject())
                    _tools[t.Name] = t.Value.ValueKind == JsonValueKind.Number && t.Value.GetDouble() is var x && x is >= 0 and <= 100
                        ? x : throw new InvalidOperationException($"AGENT_PRICE_TABLE tools.{t.Name} must be a number 0-100 (USD per call)");
            else throw new InvalidOperationException($"AGENT_PRICE_TABLE: unknown key '{p.Name}' (models, tools)");
        }
    }

    /// <summary>
    /// The price for a model id: exact, or the longest known id the reported one starts with followed by a date,
    /// '@', '[' or ':' suffix (claude-opus-5-5[1m], claude-haiku-4-5-20251001). A provider prefix (anthropic., us.)
    /// is ignored. Null when unknown.
    /// </summary>
    public ModelPrice? For(string model)
    {
        var m = model.Trim();
        var i = m.IndexOf("claude-", StringComparison.OrdinalIgnoreCase);
        if (i > 0) m = m[i..];
        if (_models.TryGetValue(m, out var exact)) return exact;
        ModelPrice? best = null;
        var bestLen = 0;
        foreach (var (id, price) in _models)
            if (id.Length > bestLen && m.Length > id.Length && m.StartsWith(id, StringComparison.OrdinalIgnoreCase)
                && m[id.Length] is '-' or '@' or '[' or ':'
                && (m[id.Length] != '-' || m.Length > id.Length + 1 && char.IsAsciiDigit(m[id.Length + 1]) && m[(id.Length + 1)..].Length >= 6))
                (best, bestLen) = (price, id.Length);
        return best;
    }

    /// <summary>Board-side metered price of one MCP call (USD), 0 unless configured.</summary>
    public double ToolPrice(string tool) => _tools.TryGetValue(tool, out var p) ? p : 0;

    public IReadOnlyDictionary<string, ModelPrice> Models => _models;
    public IReadOnlyDictionary<string, double> ToolPrices => _tools;
}
