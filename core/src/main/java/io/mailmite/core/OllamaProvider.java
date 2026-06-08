package io.mailmite.core;

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

/** Ollama local model provider (OpenAI-compatible /api/chat endpoint). */
public class OllamaProvider implements LlmProvider {

    private static final Logger log = LoggerFactory.getLogger(OllamaProvider.class);

    private final String     baseUrl;
    private final String     model;
    private final int        maxTokens;
    private final HttpClient http;

    public OllamaProvider(String baseUrl, String model, int maxTokens) {
        this.baseUrl   = baseUrl.replaceAll("/+$", "");
        this.model     = model.isBlank() ? "llama3" : model;
        this.maxTokens = maxTokens;
        this.http      = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(60)).build();
    }

    @Override
    public String complete(String systemPrompt, String userMessage) throws LlmException {
        JSONObject body = new JSONObject()
                .put("model", model)
                .put("stream", false)
                .put("options", new JSONObject().put("num_predict", maxTokens))
                .put("messages", new JSONArray()
                        .put(new JSONObject().put("role", "system").put("content", systemPrompt))
                        .put(new JSONObject().put("role", "user").put("content", userMessage)));
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(baseUrl + "/api/chat"))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                    .timeout(Duration.ofMinutes(5))
                    .build();
            String raw = http.send(req, HttpResponse.BodyHandlers.ofString()).body();
            JSONObject resp = new JSONObject(raw);
            if (resp.has("error"))
                throw new LlmException("Ollama error: " + resp.getString("error"));
            return resp.getJSONObject("message").getString("content");
        } catch (LlmException e) {
            throw e;
        } catch (Exception e) {
            throw new LlmException("Ollama request failed", e);
        }
    }
}
