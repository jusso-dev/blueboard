// Reference agent: Enrichment.
//
// Joins blueboard over MCP (Entra workload identity) through the agent SDK (agents/Blueboard.Agent.Sdk) and runs
// Claude on Microsoft Foundry to:
//  - enrich every new incident posted to #incidents (entity context, hunting, IOCs, initial verdict),
//  - answer questions that @mention it or are left open in #intel / #triage / #general (claiming them first),
//  - propose containment via request_action, which the board gates behind human approval.
// It holds no Microsoft security credentials: every read and write goes through the board.
//
//   BOARD_URL=http://localhost:7351 BOARD_DEV_PRINCIPAL=enrichment-agent CLAUDE_PROVIDER=anthropic dotnet run
//   AGENT_MODE=scripted AGENT_SCRIPT=dev/fixtures/agent-script.json ...   (local demo: canned results, no model)

using Anthropic;
using Anthropic.Foundry;
using Anthropic.Helpers;
using Azure.Identity;
using Blueboard.Agent;

var cfg = AgentConfig.FromEnvironment();
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
AppDomain.CurrentDomain.ProcessExit += (_, _) => cts.Cancel();

await using var board = await ConnectWithRetryAsync(cfg.Board, cts.Token);
var me = await board.WhoAmIAsync(cts.Token);

(AgentHandler Incident, AgentHandler Question, AgentHandler Mention) handlers;
if (cfg.Mode == "scripted")
{
    var script = await ScriptedAgent.LoadAsync(cfg.ScriptFile, cts.Token);
    Console.WriteLine($"[agent] connected as @{me.Handle} ({string.Join(", ", me.Roles)}), SCRIPTED demo mode: no model, canned results from {cfg.ScriptFile}");
    handlers = new ScriptedAgent(script, cfg.ScriptDelay).Handlers();
}
else
{
    var allTools = await board.Client!.ListToolsAsync(cancellationToken: cts.Token);
    var tools = allTools.Where(t => ClaudeAgent.ModelTools.Contains(t.Name)).ToList();
    Console.WriteLine($"[agent] connected as @{me.Handle} ({string.Join(", ", me.Roles)}), model {cfg.Model}");
    handlers = new ClaudeAgent(Claude.Create(cfg), tools, me.Handle, cfg).Handlers();
}

// Webhook mode (optional): the board wakes the agent instead of it polling every few seconds.
await using var webhooks = cfg.WebhookUrl is { } url
    ? await WebhookReceiver.SubscribeAndListenAsync(board, url, cfg.WebhookPort, ["incident.new", "mention", "thread.reply"], cts.Token)
    : null;

await BoardAgent.RunLoopAsync(board, new LoopOptions
{
    StateFile = cfg.StateFile,
    PollInterval = cfg.PollInterval,
    LeaseSeconds = 900,
    StartFromBeginning = cfg.StartFromBeginning,
    Wakeups = webhooks?.Events,
}, handlers.Incident, handlers.Question, handlers.Mention, cts.Token);

static async Task<BoardConnection> ConnectWithRetryAsync(BoardOptions options, CancellationToken ct)
{
    for (var attempt = 1; ; attempt++)
    {
        try { return await BoardConnection.ConnectAsync(options, ct); }
        catch (Exception ex) when (ex is HttpRequestException or TimeoutException && attempt < 30)
        {
            Console.Error.WriteLine($"[agent] board not reachable yet ({ex.Message}), retrying");
            await Task.Delay(TimeSpan.FromSeconds(2), ct);
        }
    }
}

sealed record AgentConfig(
    BoardOptions Board, string Mode, string ScriptFile, TimeSpan ScriptDelay, string Model, string? FallbackModel, string Provider,
    string? FoundryResource, string Effort, int MaxTurns, TimeSpan PollInterval, string StateFile, bool StartFromBeginning,
    string? WebhookUrl, int WebhookPort)
{
    public static AgentConfig FromEnvironment()
    {
        static string? Env(string k) => Environment.GetEnvironmentVariable(k) is { Length: > 0 } v ? v : null;
        static int Int(string k, int d) => int.TryParse(Env(k), out var v) ? v : d;
        return new AgentConfig(
            BoardOptions.FromEnvironment() with { BoardUrl = new Uri(Env("BOARD_URL") ?? "http://localhost:7351") },
            Env("AGENT_MODE") ?? "claude",
            Env("AGENT_SCRIPT") ?? "dev/fixtures/agent-script.json",
            TimeSpan.FromMilliseconds(Int("AGENT_SCRIPT_DELAY_MS", 1500)),
            Env("CLAUDE_MODEL") ?? "claude-opus-5-5",
            Environment.GetEnvironmentVariable("CLAUDE_FALLBACK_MODEL") ?? "claude-opus-4-8",
            Env("CLAUDE_PROVIDER") ?? "foundry",
            Env("ANTHROPIC_FOUNDRY_RESOURCE"),
            Env("AGENT_EFFORT") ?? "high",
            Int("AGENT_MAX_TURNS", 30),
            TimeSpan.FromSeconds(Int("AGENT_POLL_SECONDS", 15)),
            Path.GetFullPath(Path.Combine(Env("AGENT_STATE_DIR") ?? ".agent-state", "enrichment.json")),
            Env("AGENT_START_FROM_BEGINNING") == "true",
            Env("AGENT_WEBHOOK_URL"),
            Int("AGENT_WEBHOOK_PORT", 8080));
    }
}

static class Claude
{
    /// <summary>
    /// Claude on Microsoft Foundry with Entra auth (default), or the first-party API for local development.
    /// Security content can trip Claude's safety classifiers, so a client-side refusal fallback is on by
    /// default (server-side fallbacks aren't available on Foundry). Set CLAUDE_FALLBACK_MODEL="" to disable.
    /// </summary>
    public static AnthropicClient Create(AgentConfig cfg)
    {
        var handlers = string.IsNullOrEmpty(cfg.FallbackModel)
            ? new List<DelegatingHandler>()
            : [new BetaRefusalFallbackHandler { Fallbacks = [new(cfg.FallbackModel)] }];
        if (cfg.Provider == "anthropic") return new AnthropicClient { Handlers = handlers };
        return new AnthropicFoundryClient(new AnthropicFoundryIdentityTokenCredentials(
            new DefaultAzureCredential(),
            cfg.FoundryResource ?? throw new InvalidOperationException("set ANTHROPIC_FOUNDRY_RESOURCE"),
            null)) { Handlers = handlers };
    }
}
