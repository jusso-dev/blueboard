namespace Blueboard.Api.Core;

/// <summary>An error that is safe to show to the caller, with an HTTP status.</summary>
public sealed class BoardException(string message, int status = 400) : Exception(message)
{
    public int Status { get; } = status;
    /// <summary>HTTP status from Microsoft when this wraps a failed Graph / Defender / Sentinel call.</summary>
    public int? UpstreamStatus { get; init; }
    public static BoardException NotFound(string what) => new($"{what} not found", 404);
    public static BoardException Forbidden(string why) => new(why, 403);
    public static BoardException Conflict(string why) => new(why, 409);
    public static BoardException Unauthorized(string why = "authentication required") => new(why, 401);
}
