package io.mailmite.core;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * DeepSeek chat provider — OpenAI-compatible {@code /v1/chat/completions} API.
 *
 * @see <a href="https://api-docs.deepseek.com/">DeepSeek API docs</a>
 */
public class DeepSeekProvider implements LlmProvider {

    private static final String DEFAULT_BASE = "https://api.deepseek.com";

    private final String     apiKey;
    private final String     model;
    private final int        maxTokens;
    private final String     completionsUrl;
    private final HttpClient http;

    public DeepSeekProvider(String apiKey, String model, int maxTokens) {
        this(apiKey, model, maxTokens, DEFAULT_BASE);
    }

    DeepSeekProvider(String apiKey, String model, int maxTokens, String baseUrl) {
        this.apiKey    = apiKey;
        this.model     = DeepSeekModels.resolve(model);
        this.maxTokens = maxTokens;
        String base    = baseUrl.replaceAll("/+$", "");
        this.completionsUrl = base + "/v1/chat/completions";
        this.http      = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();
    }

    public String model() { return model; }

    @Override
    public String complete(String systemPrompt, String userMessage) throws LlmException {
        JSONObject body = new JSONObject()
                .put("model", model)
                .put("max_tokens", maxTokens)
                .put("messages", new JSONArray()
                        .put(new JSONObject().put("role", "system").put("content", systemPrompt))
                        .put(new JSONObject().put("role", "user").put("content", userMessage)));
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(completionsUrl))
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                    .timeout(Duration.ofMinutes(DeepSeekModels.isReasoningModel(model) ? 10 : 3))
                    .build();
            String raw = http.send(req, HttpResponse.BodyHandlers.ofString()).body();
            JSONObject resp = new JSONObject(raw);
            if (resp.has("error"))
                throw new LlmException("DeepSeek error: " + resp.getJSONObject("error").optString("message"));
            JSONObject message = resp.getJSONArray("choices")
                    .getJSONObject(0)
                    .getJSONObject("message");
            return extractContent(message);
        } catch (LlmException e) {
            throw e;
        } catch (Exception e) {
            throw new LlmException("DeepSeek request failed", e);
        }
    }

    /** Reasoning models may return {@code content} and/or {@code reasoning_content}. */
    static String extractContent(JSONObject message) {
        String content = message.optString("content", "").trim();
        if (!content.isBlank()) return content;
        String reasoning = message.optString("reasoning_content", "").trim();
        if (!reasoning.isBlank()) return reasoning;
        throw new LlmException("DeepSeek returned empty content");
    }
}
