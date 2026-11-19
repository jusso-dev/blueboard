using System.Collections.Concurrent;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Schema;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace Blueboard.Contracts;

/// <summary>A request that failed its contract (missing field, wrong type, out of range). Safe to show the caller.</summary>
public sealed class ContractException(string message) : Exception(message);

/// <summary>
/// One schema source. A request record's constructor parameters, with [Description] and the DataAnnotations
/// constraints on them, produce its JSON Schema (MCP inputSchema and OpenAPI) and its validation, so the two
/// cannot drift: add or remove a parameter and every surface changes together.
/// </summary>
public static class Contract
{
    private static readonly JsonSerializerOptions SchemaOptions = new(BoardJson.Options)
    {
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
        NumberHandling = JsonNumberHandling.Strict,
        TypeInfoResolver = new DefaultJsonTypeInfoResolver(),
    };

    private static readonly ConcurrentDictionary<Type, JsonObject> Cache = new();

    /// <summary>JSON Schema (draft 2020-12, as used by OpenAPI 3.1 and MCP) for a request or response record.</summary>
    public static JsonObject SchemaFor(Type type) => (JsonObject)Cache.GetOrAdd(type, Build).DeepClone();

    public static JsonObject SchemaFor<T>() => SchemaFor(typeof(T));

    private static JsonObject Build(Type type)
    {
        var root = SchemaOptions.GetJsonSchemaAsNode(type, new JsonSchemaExporterOptions { TreatNullObliviousAsNonNullable = true }) as JsonObject
                   ?? new JsonObject { ["type"] = "object" };
        if (root["properties"] is not JsonObject props) root["properties"] = props = new JsonObject();
        foreach (var p in PrimaryConstructor(type).GetParameters())
        {
            var name = JsonNamingPolicy.SnakeCaseLower.ConvertName(p.Name!);
            if (!props.ContainsKey(name)) continue;
            // JsonElement fields export as the boolean schema `true` (anything): give them an object schema to describe.
            if (props[name] is not JsonObject prop) props[name] = prop = new JsonObject();
            Describe(prop, p);
        }
        Inline(root, root);
        return root;
    }

    /// <summary>
    /// The exporter writes a repeated type once and points later uses at it with a document-relative $ref
    /// (e.g. #/properties/root/properties/author). Those break once the schema is embedded elsewhere (OpenAPI
    /// components, MCP), so replace each with a copy of what it points at.
    /// </summary>
    private static void Inline(JsonNode node, JsonObject root)
    {
        switch (node)
        {
            case JsonObject o:
                foreach (var key in o.Select(kv => kv.Key).ToList())
                {
                    if (o[key] is JsonObject child && child["$ref"] is JsonValue r && r.GetValue<string>() is var path && path.StartsWith("#/", StringComparison.Ordinal))
                        o[key] = Resolve(root, path).DeepClone();
                    if (o[key] is { } next) Inline(next, root);
                }
                break;
            case JsonArray a:
                for (var i = 0; i < a.Count; i++)
                {
                    if (a[i] is JsonObject child && child["$ref"] is JsonValue r && r.GetValue<string>() is var path && path.StartsWith("#/", StringComparison.Ordinal))
                        a[i] = Resolve(root, path).DeepClone();
                    if (a[i] is { } next) Inline(next, root);
                }
                break;
        }
    }

    private static JsonNode Resolve(JsonObject root, string pointer)
    {
        JsonNode? n = root;
        foreach (var seg in pointer[2..].Split('/')) n = n is JsonObject o ? o[seg.Replace("~1", "/").Replace("~0", "~")] : n is JsonArray a ? a[int.Parse(seg)] : null;
        return n ?? throw new InvalidOperationException($"unresolved schema ref {pointer}");
    }

    /// <summary>Applies a parameter's [Description] and constraints to its property schema.</summary>
    private static void Describe(JsonObject o, ParameterInfo p)
    {
        var t = Nullable.GetUnderlyingType(p.ParameterType) ?? p.ParameterType;
        if (t == typeof(JsonElement)) { o.Clear(); o["type"] = "object"; }
        if (o.ContainsKey("default") && o["default"] is null) o.Remove("default");
        // Optional fields are simply left out: "or null" only adds noise for agents.
        if (p.HasDefaultValue && o["type"] is JsonArray types)
        {
            var kept = types.Select(x => x!.GetValue<string>()).Where(x => x != "null").ToArray();
            o["type"] = kept.Length == 1 ? kept[0] : new JsonArray(kept.Select(k => (JsonNode)k).ToArray());
        }
        foreach (var a in p.GetCustomAttributes(true))
        {
            switch (a)
            {
                case DescriptionAttribute d: o["description"] = d.Description; break;
                case RangeAttribute r: o["minimum"] = Convert.ToInt64(r.Minimum); o["maximum"] = Convert.ToInt64(r.Maximum); break;
                case StringLengthAttribute s:
                    if (s.MinimumLength > 0) o["minLength"] = s.MinimumLength;
                    o["maxLength"] = s.MaximumLength;
                    break;
                case AllowedValuesAttribute v: o["enum"] = new JsonArray(v.Values.Select(x => (JsonNode?)JsonValue.Create(x?.ToString())).ToArray()); break;
                case RegularExpressionAttribute re: o["pattern"] = re.Pattern; break;
            }
        }
    }

    private static ConstructorInfo PrimaryConstructor(Type t) =>
        t.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();

    /// <summary>Reads and validates a request from JSON (REST body, query string or MCP tool arguments).</summary>
    public static T Read<T>(JsonElement json) where T : class
    {
        if (json.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) json = JsonDocument.Parse("{}").RootElement;
        if (json.ValueKind != JsonValueKind.Object) throw new ContractException("expected a JSON object");
        T value;
        try
        {
            value = json.Deserialize<T>(BoardJson.Input) ?? throw new ContractException("body required");
        }
        catch (JsonException ex)
        {
            throw new ContractException(Explain(ex));
        }
        Validate(value);
        return value;
    }

    /// <summary>Checks a record against the DataAnnotations on its constructor parameters.</summary>
    public static void Validate<T>(T value) where T : class
    {
        foreach (var p in PrimaryConstructor(typeof(T)).GetParameters())
        {
            var prop = typeof(T).GetProperty(p.Name!, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
            var v = prop?.GetValue(value);
            var name = JsonNamingPolicy.SnakeCaseLower.ConvertName(p.Name!);
            if (v is null) continue;
            foreach (var a in p.GetCustomAttributes<ValidationAttribute>())
            {
                if (a.IsValid(v)) continue;
                throw new ContractException(a switch
                {
                    RangeAttribute r => $"{name} must be {r.Minimum}–{r.Maximum}",
                    StringLengthAttribute s => $"{name} must be {s.MinimumLength}–{s.MaximumLength} characters",
                    AllowedValuesAttribute av => $"{name} must be one of {string.Join(", ", av.Values)}",
                    RegularExpressionAttribute => $"invalid {name}",
                    _ => $"invalid {name}",
                });
            }
        }
    }

    private static string Explain(JsonException ex)
    {
        var path = ex.Path is { Length: > 2 } p ? p.TrimStart('$', '.') : null;
        if (ex.Message.Contains("missing required properties", StringComparison.Ordinal) ||
            ex.Message.Contains("required", StringComparison.OrdinalIgnoreCase))
        {
            var start = ex.Message.IndexOf("including: ", StringComparison.Ordinal);
            if (start >= 0) return $"missing required field {ex.Message[(start + 11)..].TrimEnd('.').Trim('\'')}";
            if (path is not null) return $"{path} is required";
        }
        return path is null ? "invalid request" : $"invalid {path}";
    }
}
