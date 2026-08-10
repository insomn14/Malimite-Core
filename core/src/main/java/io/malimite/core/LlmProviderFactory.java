package io.malimite.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Creates an {@link LlmProvider} from a config map (env vars).
 *
 * <pre>
 * LLM_PROVIDER      = openai | claude | deepseek | ollama | none   (default: none)
 * OPENAI_API_KEY    = sk-...
 * ANTHROPIC_API_KEY = sk-ant-...
 * DEEPSEEK_API_KEY  = sk-...
 * DEEPSEEK_BASE_URL = https://api.deepseek.com   (optional override)
 * OLLAMA_BASE_URL   = http://localhost:11434
 * LLM_MODEL         = override default model id
 * LLM_MAX_TOKENS    = 4096   (default; raise if FIND_VULNS responses truncate)
 * </pre>
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
                log.info("LLM provider: Claude model={}", model.isBlank() ? "claude-sonnet-4-6" : model);
                yield new ClaudeProvider(key, model, maxTokens);
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
            default -> null; // "none" or unknown
        };
    }
}
