package io.malimite.core;

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
        // Retry transient failures (network, 429/5xx, timeout) with backoff; the
        // caller (LlmEnricher) runs calls concurrently, so the provider must stay
        // stateless + thread-safe (it is: a single java.net.http.HttpClient).
        int attempts = 3;
        long backoffMs = 500;
        LlmException last = null;
        for (int i = 0; i < attempts; i++) {
            if (i > 0) sleep(backoffMs << (i - 1));
            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(completionsUrl))
                        .header("Authorization", "Bearer " + apiKey)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                        .timeout(Duration.ofMinutes(DeepSeekModels.isReasoningModel(model) ? 10 : 3))
                        .build();
                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
                int status = resp.statusCode();
                String raw = resp.body();
                if (status >= 500 || status == 429) {
                    // retryable
                    last = new LlmException("DeepSeek HTTP " + status + ": " + abbreviate(raw));
                    continue;
                }
                if (status >= 400) {
                    throw new LlmException("DeepSeek error " + status + ": " + abbreviate(raw));
                }
                JSONObject parsed = new JSONObject(raw);
                if (parsed.has("error")) {
                    String msg = parsed.getJSONObject("error").optString("message");
                    // 429/'insufficient_quota' are retryable; others are not.
                    boolean retryable = parsed.getJSONObject("error").optString("code", "")
                            .contains("rate") || status == 429;
                    last = new LlmException("DeepSeek error: " + msg);
                    if (!retryable) throw last;
                    continue;
                }
                JSONObject message = parsed.getJSONArray("choices")
                        .getJSONObject(0)
                        .getJSONObject("message");
                return extractContent(message);
            } catch (java.io.IOException e) {
                last = new LlmException("DeepSeek request failed", e);
            } catch (LlmException e) {
                throw e;
            } catch (Exception e) {
                last = new LlmException("DeepSeek request failed", e);
            }
        }
        throw last != null ? last : new LlmException("DeepSeek request failed after retries");
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private static String abbreviate(String s) {
        if (s == null) return "";
        return s.length() > 300 ? s.substring(0, 300) : s;
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
