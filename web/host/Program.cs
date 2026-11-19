// blueboard web host: serves the React build with security headers. See Blueboard.Web.csproj.
using Blueboard.Web;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;

// wwwroot sits next to the binary (publish output), whatever the working directory is.
var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
    WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot"),
});
builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);
var app = builder.Build();

var config = WebConfig.FromEnvironment(app.Environment.IsDevelopment());
var headers = SecurityHeaders.For(config);
var root = app.Environment.WebRootFileProvider;

app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() =>
    {
        var path = ctx.Request.Path.Value ?? "/";
        foreach (var (k, v) in headers.ForPath(path)) ctx.Response.Headers[k] = v;
        return Task.CompletedTask;
    });
    await next();
});

app.MapGet("/healthz", () => Results.Text("ok"));
// Public, non-secret settings the SPA needs to sign in. Never cached, so a redeploy takes effect at once.
app.MapGet("/config.json", (HttpContext ctx) =>
{
    ctx.Response.Headers.CacheControl = "no-store";
    return Results.Json(config.Public, WebJson.Default.PublicConfig);
});
// MSAL redirect bridge (msal-browser v5): receives the auth code, so no-store and same-origin only.
app.MapGet("/redirect", (HttpContext ctx) => SpaFile(ctx, root, "redirect.html"));

app.UseStaticFiles(new StaticFileOptions
{
    ContentTypeProvider = new FileExtensionContentTypeProvider(),
    OnPrepareResponse = f =>
    {
        // Vite fingerprints everything under /assets: cache for a year. Everything else: revalidate.
        f.Context.Response.Headers.CacheControl = f.Context.Request.Path.StartsWithSegments("/assets")
            ? "public, max-age=31536000, immutable"
            : "no-cache";
    },
});

// Client-side routes (/incidents/…, /search, …) get index.html. Unknown files under /assets are a real 404.
app.MapFallback((HttpContext ctx) =>
    ctx.Request.Path.StartsWithSegments("/assets") || !HttpMethods.IsGet(ctx.Request.Method)
        ? Results.NotFound()
        : SpaFile(ctx, root, "index.html"));

app.Run();

static IResult SpaFile(HttpContext ctx, IFileProvider root, string name)
{
    var file = root.GetFileInfo(name);
    if (!file.Exists) return Results.Problem("web build missing: run pnpm build in web/", statusCode: 503);
    ctx.Response.Headers.CacheControl = "no-store";
    return Results.Stream(file.CreateReadStream(), "text/html; charset=utf-8");
}
