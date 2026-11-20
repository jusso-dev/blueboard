using System.Text.Json;
using Blueboard.Contracts;

namespace Blueboard.Api.Core;

public static class Json
{
    /// <summary>snake_case on the wire, matching the database and the agents' tool schemas (shared with the agent SDK).</summary>
    public static JsonSerializerOptions Options => BoardJson.Options;

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);
    public static JsonElement Element<T>(T value) => JsonSerializer.SerializeToElement(value, Options);
}
