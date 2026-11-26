using Blueboard.Api.Data;
using Npgsql;
using Xunit;

namespace Blueboard.Api.Tests;

/// <summary>PG_SSL_MODE: Azure PostgreSQL connections verify the server certificate unless explicitly relaxed.</summary>
public sealed class DbTlsTests
{
    [Theory]
    [InlineData(null, SslMode.VerifyFull)]
    [InlineData("", SslMode.VerifyFull)]
    [InlineData("VerifyFull", SslMode.VerifyFull)]
    [InlineData("verify-full", SslMode.VerifyFull)]
    [InlineData("VerifyCA", SslMode.VerifyCA)]
    [InlineData("Require", SslMode.Require)]
    public void Ssl_mode_defaults_to_verify_full(string? value, SslMode expected) =>
        Assert.Equal(expected, Db.SslModeFrom(value));

    [Theory]
    [InlineData("disable")]
    [InlineData("prefer")]
    [InlineData("allow")]
    [InlineData("nonsense")]
    public void Ssl_modes_without_encryption_are_refused(string value) =>
        Assert.Throws<InvalidOperationException>(() => Db.SslModeFrom(value));

    [Fact]
    public void Local_database_url_keeps_prefer() =>
        Assert.Equal(SslMode.Prefer, Db.FromUrl("postgres://u:p@localhost:5432/blueboard").SslMode);
}
