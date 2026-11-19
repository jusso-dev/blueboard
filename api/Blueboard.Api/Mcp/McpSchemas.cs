using System.Text.Json;
using System.Text.Json.Nodes;
using Blueboard.Contracts;
using Microsoft.Azure.Functions.Worker.Builder;

namespace Blueboard.Api.Mcp;

/// <summary>MCP tool input schemas, built from the request records in Blueboard.Contracts.</summary>
public static class McpSchemas
{
    /// <summary>The inputSchema for each tool. Program.cs registers exactly these; tests compare them with OpenAPI.</summary>
    public static IReadOnlyDictionary<string, JsonObject> All() =>
        Tools.All.ToDictionary(t => t.Name, t => Contract.SchemaFor(t.Input));

    public static void Register(FunctionsApplicationBuilder builder)
    {
        foreach (var (name, schema) in All()) builder.ConfigureMcpTool(name).WithInputSchema(schema);
    }

    /// <summary>
    /// MCP tool arguments (strings, numbers, dictionaries and lists from the extension) as one JSON object.
    /// Older agents sent payload_json / params_json strings; those still work and become payload / params.
    /// </summary>
    public static JsonElement Arguments(IReadOnlyDictionary<string, object>? args)
    {
        var o = new JsonObject();
        foreach (var (k, v) in args ?? new Dictionary<string, object>())
        {
            var node = JsonSerializer.SerializeToNode(v);
            if (k is "payload_json" or "params_json" && node is JsonValue s && s.TryGetValue<string>(out var text))
            {
                if (string.IsNullOrWhiteSpace(text)) continue;
                try { node = JsonNode.Parse(text); }
                catch (JsonException) { throw new ContractException($"{k} must be a JSON object string"); }
                o[k[..^5]] = node;
                continue;
            }
            o[k] = node;
        }
        return JsonSerializer.SerializeToElement(o);
    }
}
