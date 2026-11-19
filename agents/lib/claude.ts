import Anthropic, { betaRefusalFallbackMiddleware } from "@anthropic-ai/sdk";
import { AnthropicFoundry } from "@anthropic-ai/foundry-sdk";
import { DefaultAzureCredential, getBearerTokenProvider } from "@azure/identity";

/**
 * Claude via Microsoft Foundry (default). Entra auth unless ANTHROPIC_FOUNDRY_API_KEY is set.
 *
 * Security work can trip Claude's safety classifiers, so a client-side refusal fallback is enabled by
 * default (server-side `fallbacks` isn't available on Foundry). The fallback model must also be
 * deployed in your Foundry resource. Set CLAUDE_FALLBACK_MODEL="" to turn it off.
 *
 * CLAUDE_PROVIDER=anthropic uses the first-party API instead (ANTHROPIC_API_KEY), for local development.
 */
export const MODEL = process.env.CLAUDE_MODEL ?? "claude-opus-5-5";
const FALLBACK = process.env.CLAUDE_FALLBACK_MODEL ?? "claude-opus-4-8";

export function claudeClient(): Anthropic {
  const middleware = FALLBACK ? [betaRefusalFallbackMiddleware([{ model: FALLBACK }])] : [];
  if (process.env.CLAUDE_PROVIDER === "anthropic") return new Anthropic({ middleware });
  const apiKey = process.env.ANTHROPIC_FOUNDRY_API_KEY;
  return new AnthropicFoundry({
    middleware,
    ...(apiKey
      ? { apiKey }
      : { azureADTokenProvider: getBearerTokenProvider(new DefaultAzureCredential(), "https://ai.azure.com/.default") }),
    // resource / baseURL come from ANTHROPIC_FOUNDRY_RESOURCE / ANTHROPIC_FOUNDRY_BASE_URL
  }) as unknown as Anthropic;
}
