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

/** OpenAI Chat Completions provider (GPT-4o / GPT-4o-mini). */
public class OpenAiProvider implements LlmProvider {

    private static final Logger log = LoggerFactory.getLogger(OpenAiProvider.class);
    private static final String API_URL = "https://api.openai.com/v1/chat/completions";

    private final String     apiKey;
    private final String     model;
    private final int        maxTokens;
    private final HttpClient http;

    public OpenAiProvider(String apiKey, String model, int maxTokens) {
        this.apiKey    = apiKey;
        this.model     = model.isBlank() ? "gpt-4o-mini" : model;
        this.maxTokens = maxTokens;
        this.http      = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();
    }

    @Override
    public String complete(String systemPrompt, String userMessage) throws LlmException {
        JSONObject body = new JSONObject()
                .put("model", model)
                .put("max_tokens", maxTokens)
                .put("messages", new JSONArray()
                        .put(new JSONObject().put("role", "system").put("content", systemPrompt))
                        .put(new JSONObject().put("role", "user").put("content", userMessage)));
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(API_URL))
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                    .build();
            String raw = http.send(req, HttpResponse.BodyHandlers.ofString()).body();
            JSONObject resp = new JSONObject(raw);
            if (resp.has("error"))
                throw new LlmException("OpenAI error: " + resp.getJSONObject("error").optString("message"));
            return resp.getJSONArray("choices")
                       .getJSONObject(0)
                       .getJSONObject("message")
                       .getString("content");
        } catch (LlmException e) {
            throw e;
        } catch (Exception e) {
            throw new LlmException("OpenAI request failed", e);
        }
    }
}
