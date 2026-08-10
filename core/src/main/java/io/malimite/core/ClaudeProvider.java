package io.malimite.core;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Anthropic Claude provider using the Messages API.
 * Uses prompt caching on the system prompt to reduce costs on repeated enrichment calls.
 */
public class ClaudeProvider implements LlmProvider {

    private static final Logger log = LoggerFactory.getLogger(ClaudeProvider.class);
    private static final String API_URL         = "https://api.anthropic.com/v1/messages";
    private static final String API_VERSION     = "2023-06-01";
    private static final String CACHE_BETA      = "prompt-caching-2024-07-31";

    private final String     apiKey;
    private final String     model;
    private final int        maxTokens;
    private final HttpClient http;

    public ClaudeProvider(String apiKey, String model, int maxTokens) {
        this.apiKey    = apiKey;
        this.model     = model.isBlank() ? "claude-sonnet-4-6" : model;
        this.maxTokens = maxTokens;
        this.http      = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();
    }

    @Override
    public String complete(String systemPrompt, String userMessage) throws LlmException {
        // System prompt with cache_control — Anthropic caches this across calls
        JSONArray systemArray = new JSONArray().put(new JSONObject()
                .put("type", "text")
                .put("text", systemPrompt)
                .put("cache_control", new JSONObject().put("type", "ephemeral")));

        JSONObject body = new JSONObject()
                .put("model", model)
                .put("max_tokens", maxTokens)
                .put("system", systemArray)
                .put("messages", new JSONArray()
                        .put(new JSONObject()
                                .put("role", "user")
                                .put("content", userMessage)));
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(API_URL))
                    .header("x-api-key", apiKey)
                    .header("anthropic-version", API_VERSION)
                    .header("anthropic-beta", CACHE_BETA)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                    .build();
            String raw = http.send(req, HttpResponse.BodyHandlers.ofString()).body();
            JSONObject resp = new JSONObject(raw);
            if (resp.has("error"))
                throw new LlmException("Claude error: " + resp.getJSONObject("error").optString("message"));
            return resp.getJSONArray("content")
                       .getJSONObject(0)
                       .getString("text");
        } catch (LlmException e) {
            throw e;
        } catch (Exception e) {
            throw new LlmException("Claude request failed", e);
        }
    }
}
