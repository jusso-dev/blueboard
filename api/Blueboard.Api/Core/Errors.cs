namespace Blueboard.Api.Core;

/// <summary>An error that is safe to show to the caller, with an HTTP status.</summary>
public sealed class BoardException(string message, int status = 400) : Exception(message)
{
    public int Status { get; } = status;
    /// <summary>Seconds until the caller may retry (429 only): sent as Retry-After.</summary>
    public int? RetryAfterSeconds { get; init; }
    /// <summary>The rate limit bucket that refused the call (429 only).</summary>
    public string? Bucket { get; init; }

    public static BoardException NotFound(string what) => new($"{what} not found", 404);
    public static BoardException Forbidden(string why) => new(why, 403);
    public static BoardException Conflict(string why) => new(why, 409);
    public static BoardException Unauthorized(string why = "authentication required") => new(why, 401);
    public static BoardException RateLimited(string bucket, int retryAfterSeconds) =>
        new($"rate limited: {bucket}, retry in {retryAfterSeconds}s", 429) { RetryAfterSeconds = retryAfterSeconds, Bucket = bucket };
}
