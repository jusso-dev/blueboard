using System.Text.Json;
using System.Text.Json.Serialization;

namespace Blueboard.Contracts;

/// <summary>JSON settings shared by the API and the agent SDK: snake_case on the wire, matching the database.</summary>
public static class BoardJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = null,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower) },
    };

    /// <summary>
    /// For reading requests (REST bodies, query strings, MCP tool arguments): required fields must be present and
    /// non-null, numbers may arrive as strings, and string lists may be a JSON array or one comma-separated string.
    /// </summary>
    public static readonly JsonSerializerOptions Input = new(Options)
    {
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
        Converters = { new StringListConverter() },
    };

    /// <summary>Accepts ["a","b"] or "a,b" for a string[] field.</summary>
    private sealed class StringListConverter : JsonConverter<string[]>
    {
        public override string[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType == JsonTokenType.String)
                return reader.GetString()!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (reader.TokenType != JsonTokenType.StartArray) throw new JsonException("expected a list of strings");
            var list = new List<string>();
            while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                list.Add(reader.TokenType == JsonTokenType.String ? reader.GetString()! : throw new JsonException("expected a list of strings"));
            return list.ToArray();
        }

        public override void Write(Utf8JsonWriter writer, string[] value, JsonSerializerOptions options) =>
            JsonSerializer.Serialize(writer, value, typeof(string[]));
    }
}
