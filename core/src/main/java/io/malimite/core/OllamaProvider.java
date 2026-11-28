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
 * Ollama local model provider (native /api/chat endpoint).
 *
 * <p>Request parameters come from the optional {@code OLLAMA_OPTIONS} JSON (written by the web
 * Config tab — see web/app/agent/llm_config.py). Unset keys fall back to the same defaults the web
 * side uses: Ollama's own 4096-token context is too small for enrichment prompts, and thinking
 * models would otherwise spend the output budget on hidden reasoning.
 */
public class OllamaProvider implements LlmProvider {

    private static final Logger log = LoggerFactory.getLogger(OllamaProvider.class);

    private final String     baseUrl;
    private final String     model;
    private final int        maxTokens;
    private final JSONObject params;
    private final HttpClient http;

    /** Keys that live inside the request's {@code options} object; think/keep_alive are top-level. */
    private static final String[] OPTION_KEYS = {"num_ctx", "num_predict", "temperature", "top_p", "top_k",
            "min_p", "repeat_penalty", "num_thread", "num_batch"};

    public OllamaProvider(String baseUrl, String model, int maxTokens) {
        this(baseUrl, model, maxTokens, null);
    }

    public OllamaProvider(String baseUrl, String model, int maxTokens, String optionsJson) {
        this.baseUrl   = baseUrl.replaceAll("/+$", "");
        this.model     = model.isBlank() ? "llama3" : model;
        this.maxTokens = maxTokens;
        this.params    = parseOptions(optionsJson);
        this.http      = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(60)).build();
    }

    private static JSONObject parseOptions(String json) {
        JSONObject o = new JSONObject().put("num_ctx", 16384).put("think", false).put("keep_alive", "30m");
        if (json == null || json.isBlank()) return o;
        try {
            JSONObject given = new JSONObject(json);
            for (String k : given.keySet()) o.put(k, given.get(k));
        } catch (Exception e) {
            log.warn("Ignoring malformed OLLAMA_OPTIONS: {}", e.getMessage());
        }
        return o;
    }

    /** Request body for one completion; package-private so tests can check it without a server. */
    JSONObject buildBody(String systemPrompt, String userMessage) {
        JSONObject options = new JSONObject();
        for (String k : OPTION_KEYS) if (params.has(k)) options.put(k, params.get(k));
        if (!options.has("num_predict")) options.put("num_predict", maxTokens);   // LLM_MAX_TOKENS unless overridden
        return new JSONObject()
                .put("model", model)
                .put("stream", false)
                .put("think", params.optBoolean("think", false))
                .put("keep_alive", params.optString("keep_alive", "30m"))
                .put("options", options)
                .put("messages", new JSONArray()
                        .put(new JSONObject().put("role", "system").put("content", systemPrompt))
                        .put(new JSONObject().put("role", "user").put("content", userMessage)));
    }

    @Override
    public String complete(String systemPrompt, String userMessage) throws LlmException {
        JSONObject body = buildBody(systemPrompt, userMessage);
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
