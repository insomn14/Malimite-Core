package io.malimite.core;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Anthropic Claude models hosted on AWS Bedrock, invoked via the (non-streaming)
 * {@code bedrock-runtime InvokeModel} API, SigV4-signed with a static access key/secret pair
 * (see AwsSigV4Signer — no AWS SDK dependency).
 *
 * Wire format is the Messages API body (system/messages, same shape {@link ClaudeProvider}
 * builds) minus {@code model} — the model id is part of the URL path instead of a JSON field;
 * {@code anthropic_version} replaces Claude's {@code anthropic-version} HTTP header (Bedrock
 * wants it IN the body instead).
 *
 * @see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/model-parameters-anthropic-claude-messages.html">
 *      Anthropic Claude Messages API on Bedrock</a>
 */
public class BedrockProvider implements LlmProvider {

    private static final String DEFAULT_MODEL = "anthropic.claude-sonnet-5-20260101-v1:0";
    private static final String ANTHROPIC_VERSION = "bedrock-2023-05-31";

    private final String accessKeyId;
    private final String secretAccessKey;
    private final String region;
    private final String model;
    private final int maxTokens;
    private final HttpClient http;

    public BedrockProvider(String accessKeyId, String secretAccessKey, String region, String model, int maxTokens) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.region = region == null || region.isBlank() ? "us-east-1" : region;
        this.model = model == null || model.isBlank() ? DEFAULT_MODEL : model;
        this.maxTokens = maxTokens;
        this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();
    }

    public String model() { return model; }
    public String region() { return region; }

    @Override
    public String complete(String systemPrompt, String userMessage) throws LlmException {
        JSONObject body = new JSONObject()
                .put("anthropic_version", ANTHROPIC_VERSION)
                .put("max_tokens", maxTokens)
                .put("system", systemPrompt)
                .put("messages", new JSONArray()
                        .put(new JSONObject().put("role", "user").put("content", userMessage)));
        byte[] bodyBytes = body.toString().getBytes(StandardCharsets.UTF_8);

        String host = "bedrock-runtime." + region + ".amazonaws.com";
        String urlPath = "/model/" + model + "/invoke";
        String url = "https://" + host + urlPath;

        Map<String, String> extraHeaders = new LinkedHashMap<>();
        extraHeaders.put("content-type", "application/json");
        extraHeaders.put("accept", "application/json");

        int attempts = 3;
        long backoffMs = 500;
        LlmException last = null;
        for (int i = 0; i < attempts; i++) {
            if (i > 0) sleep(backoffMs << (i - 1));
            Map<String, String> headers = AwsSigV4Signer.sign(
                    "POST", urlPath, region, "bedrock", accessKeyId, secretAccessKey, host, bodyBytes, extraHeaders);
            try {
                HttpRequest.Builder reqBuilder = HttpRequest.newBuilder(URI.create(url))
                        .POST(HttpRequest.BodyPublishers.ofByteArray(bodyBytes))
                        .timeout(Duration.ofMinutes(3));
                for (Map.Entry<String, String> e : headers.entrySet()) {
                    if ("Host".equalsIgnoreCase(e.getKey())) continue; // HttpClient sets this itself; rejects explicit override
                    reqBuilder.header(e.getKey(), e.getValue());
                }
                HttpResponse<String> resp = http.send(reqBuilder.build(), HttpResponse.BodyHandlers.ofString());
                int status = resp.statusCode();
                String raw = resp.body();
                if (status >= 500 || status == 429) {
                    last = new LlmException("Bedrock HTTP " + status + ": " + abbreviate(raw));
                    continue;
                }
                if (status >= 400) {
                    throw new LlmException("Bedrock error " + status + ": " + abbreviate(raw));
                }
                JSONObject parsed = new JSONObject(raw);
                return ClaudeOAuthProvider.extractText(parsed.getJSONArray("content"), parsed.optString("stop_reason", ""));
            } catch (java.io.IOException e) {
                last = new LlmException("Bedrock request failed", e);
            } catch (LlmException e) {
                throw e;
            } catch (Exception e) {
                last = new LlmException("Bedrock request failed", e);
            }
        }
        throw last != null ? last : new LlmException("Bedrock request failed after retries");
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    private static String abbreviate(String s) {
        if (s == null) return "";
        return s.length() > 300 ? s.substring(0, 300) : s;
    }
}
