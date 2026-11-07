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
 * Zai (Zhipu) GLM provider — OpenAI-compatible {@code /chat/completions} API.
 * Same request/response shape as {@link OpenAiProvider} / {@link DeepSeekProvider}, just a
 * different default base URL and model id.
 *
 * @see <a href="https://docs.z.ai/">Zai API docs</a>
 */
public class GlmProvider implements LlmProvider {

    private static final String DEFAULT_BASE = "https://open.bigmodel.cn/api/paas/v4";
    private static final String DEFAULT_MODEL = "glm-4.6";

    private final String apiKey;
    private final String model;
    private final int maxTokens;
    private final String completionsUrl;
    private final HttpClient http;

    public GlmProvider(String apiKey, String model, int maxTokens) {
        this(apiKey, model, maxTokens, DEFAULT_BASE);
    }

    GlmProvider(String apiKey, String model, int maxTokens, String baseUrl) {
        this.apiKey = apiKey;
        this.model = model == null || model.isBlank() ? DEFAULT_MODEL : model;
        this.maxTokens = maxTokens;
        String base = (baseUrl == null || baseUrl.isBlank() ? DEFAULT_BASE : baseUrl).replaceAll("/+$", "");
        this.completionsUrl = base + "/chat/completions";
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();
    }

    public String model() { return model; }
    String completionsUrl() { return completionsUrl; }

    @Override
    public String complete(String systemPrompt, String userMessage) throws LlmException {
        JSONObject body = new JSONObject()
                .put("model", model)
                .put("max_tokens", maxTokens)
                .put("messages", new JSONArray()
                        .put(new JSONObject().put("role", "system").put("content", systemPrompt))
                        .put(new JSONObject().put("role", "user").put("content", userMessage)));
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
                        .timeout(Duration.ofMinutes(3))
                        .build();
                HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
                int status = resp.statusCode();
                String raw = resp.body();
                if (status >= 500 || status == 429) {
                    last = new LlmException("GLM HTTP " + status + ": " + abbreviate(raw));
                    continue;
                }
                if (status >= 400) {
                    throw new LlmException("GLM error " + status + ": " + abbreviate(raw));
                }
                JSONObject parsed = new JSONObject(raw);
                if (parsed.has("error")) {
                    Object err = parsed.get("error");
                    String msg = err instanceof JSONObject ? ((JSONObject) err).optString("message") : String.valueOf(err);
                    throw new LlmException("GLM error: " + msg);
                }
                JSONObject message = parsed.getJSONArray("choices")
                        .getJSONObject(0)
                        .getJSONObject("message");
                String content = message.optString("content", "").trim();
                if (content.isBlank()) throw new LlmException("GLM returned empty content");
                return content;
            } catch (java.io.IOException e) {
                last = new LlmException("GLM request failed", e);
            } catch (LlmException e) {
                throw e;
            } catch (Exception e) {
                last = new LlmException("GLM request failed", e);
            }
        }
        throw last != null ? last : new LlmException("GLM request failed after retries");
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private static String abbreviate(String s) {
        if (s == null) return "";
        return s.length() > 300 ? s.substring(0, 300) : s;
    }
}
