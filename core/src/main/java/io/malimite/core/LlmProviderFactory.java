package io.malimite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Creates an {@link LlmProvider} from a config map (env vars).
 *
 * <pre>
 * LLM_PROVIDER          = openai | claude | claude-oauth | deepseek | ollama | bedrock | glm | none (default: none)
 * OPENAI_API_KEY        = sk-...
 * ANTHROPIC_API_KEY     = sk-ant-...            (required for provider=claude)
 * DEEPSEEK_API_KEY      = sk-...
 * DEEPSEEK_BASE_URL     = https://api.deepseek.com   (optional override)
 * OLLAMA_BASE_URL       = http://localhost:11434
 * AWS_ACCESS_KEY_ID     = AKIA...                (required for provider=bedrock)
 * AWS_SECRET_ACCESS_KEY = ...                    (required for provider=bedrock)
 * AWS_REGION            = us-east-1              (optional override; default us-east-1)
 * BEDROCK_MODEL_ID      = anthropic.claude-...   (optional override; falls back to LLM_MODEL)
 * GLM_API_KEY           = ...                    (required for provider=glm)
 * GLM_BASE_URL          = https://open.bigmodel.cn/api/paas/v4  (optional override)
 * LLM_MODEL             = override default model id
 * LLM_MAX_TOKENS        = 4096   (default; raise if FIND_VULNS responses truncate)
 * </pre>
 *
 * These env vars are sourced by web/app/scanner.py's llm_env() — which itself resolves them
 * from the Config tab's stored credentials (web/app/agent/llm_config.py) before falling back
 * to the server's own *_API_KEY/.env bootstrap — and passed to this CLI's subprocess
 * environment, so a key saved once in the Config tab reaches both the Python chat agent and
 * this Java-side scan enrichment without being entered twice.
 */
public final class LlmProviderFactory {

    private static final Logger log = LoggerFactory.getLogger(LlmProviderFactory.class);

    private LlmProviderFactory() {}

    /**
     * Reads {@code LLM_PROVIDER} from {@code cfg} and constructs the matching provider.
     * Returns {@code null} when {@code LLM_PROVIDER} is absent or {@code none}.
     */
    public static LlmProvider create(Map<String, String> cfg) {
        String provider  = cfg.getOrDefault("LLM_PROVIDER", "none").toLowerCase();
        String model     = cfg.getOrDefault("LLM_MODEL", "");
        int    maxTokens = Integer.parseInt(cfg.getOrDefault("LLM_MAX_TOKENS", "4096"));

        return switch (provider) {
            case "openai" -> {
                String key = cfg.get("OPENAI_API_KEY");
                if (key == null || key.isBlank()) throw new IllegalStateException("OPENAI_API_KEY missing");
                log.info("LLM provider: OpenAI model={}", model.isBlank() ? "gpt-4o-mini" : model);
                yield new OpenAiProvider(key, model, maxTokens);
            }
            case "claude" -> {
                String key = cfg.get("ANTHROPIC_API_KEY");
                if (key == null || key.isBlank()) throw new IllegalStateException("ANTHROPIC_API_KEY missing");
                log.info("LLM provider: Claude model={}", model.isBlank() ? "claude-sonnet-5" : model);
                yield new ClaudeProvider(key, model, maxTokens);
            }
            // Uses a Claude Pro/Max OAuth session (see AnthropicOAuthLogin) instead of
            // a pay-per-token API key. Requires 'malimite claude-login' to have run once.
            case "claude-oauth" -> {
                log.info("LLM provider: Claude (OAuth) model={}", model.isBlank() ? "claude-sonnet-5" : model);
                yield new ClaudeOAuthProvider(model, maxTokens);
            }
            case "deepseek" -> {
                String key = cfg.get("DEEPSEEK_API_KEY");
                if (key == null || key.isBlank()) throw new IllegalStateException("DEEPSEEK_API_KEY missing");
                String base = cfg.getOrDefault("DEEPSEEK_BASE_URL", "https://api.deepseek.com");
                String resolved = DeepSeekModels.resolve(model);
                log.info("LLM provider: DeepSeek model={} base={}", resolved, base);
                yield new DeepSeekProvider(key, resolved, maxTokens, base);
            }
            case "ollama" -> {
                String url = cfg.getOrDefault("OLLAMA_BASE_URL", "http://localhost:11434");
                log.info("LLM provider: Ollama url={} model={}", url, model.isBlank() ? "llama3" : model);
                yield new OllamaProvider(url, model, maxTokens);
            }
            case "bedrock" -> {
                String accessKeyId = cfg.get("AWS_ACCESS_KEY_ID");
                String secretAccessKey = cfg.get("AWS_SECRET_ACCESS_KEY");
                if (accessKeyId == null || accessKeyId.isBlank() || secretAccessKey == null || secretAccessKey.isBlank())
                    throw new IllegalStateException("AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY missing");
                String region = cfg.getOrDefault("AWS_REGION", "us-east-1");
                // BEDROCK_MODEL_ID (Config tab's bedrock-specific model override) wins over the
                // generic LLM_MODEL, which may be left over from a different provider's default.
                String bedrockModel = cfg.getOrDefault("BEDROCK_MODEL_ID", model);
                log.info("LLM provider: Bedrock region={} model={}", region,
                        bedrockModel.isBlank() ? "anthropic.claude-sonnet-5-20260101-v1:0" : bedrockModel);
                yield new BedrockProvider(accessKeyId, secretAccessKey, region, bedrockModel, maxTokens);
            }
            case "glm" -> {
                String key = cfg.get("GLM_API_KEY");
                if (key == null || key.isBlank()) throw new IllegalStateException("GLM_API_KEY missing");
                String base = cfg.getOrDefault("GLM_BASE_URL", "https://open.bigmodel.cn/api/paas/v4");
                log.info("LLM provider: GLM model={} base={}", model.isBlank() ? "glm-4.6" : model, base);
                yield new GlmProvider(key, model, maxTokens, base);
            }
            default -> null; // "none" or unknown
        };
    }
}
