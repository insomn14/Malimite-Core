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
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.Set;

/**
 * Anthropic Claude provider authorized with a Claude Pro/Max OAuth session
 * instead of a pay-per-token {@code ANTHROPIC_API_KEY}.
 *
 * <p>Requests are billed against the subscription's own usage because the
 * Messages API treats this exactly like a Claude Code CLI request: the
 * token travels as {@code Authorization: Bearer <access_token>} (not
 * {@code x-api-key}), the {@code anthropic-beta: oauth-2025-04-20} +
 * {@code claude-code-20250219} capabilities are declared, and the system
 * prompt opens with Anthropic's own Claude Code identity string before this
 * class's own system prompt is appended. Dropping any of those three makes
 * the API reject the OAuth token outright — this is Anthropic's documented
 * behavior for this credential type, not an implementation choice made
 * here.</p>
 *
 * <p>Credentials are obtained once via {@link AnthropicOAuthLogin#login},
 * persisted by {@link AnthropicOAuthCredentials}, and transparently
 * refreshed by this class whenever they are within Anthropic's expiry
 * margin — callers never see a token-refresh step.</p>
 */
public class ClaudeOAuthProvider implements LlmProvider {

    private static final Logger log = LoggerFactory.getLogger(ClaudeOAuthProvider.class);

    private static final String API_URL     = "https://api.anthropic.com/v1/messages";
    private static final String API_VERSION = "2023-06-01";

    // HttpClient.connectTimeout (below) only bounds opening the TCP connection —
    // it does NOT bound how long we wait for a response once connected. Without
    // an explicit per-request timeout, a request that connects fine but then
    // hangs (observed directly: Cloudflare in front of Anthropic returning one
    // 502 and then never completing the next attempt at all) blocks its worker
    // thread FOREVER — confirmed via a real production jstack showing a worker
    // thread parked inside HttpClient.send() for 34+ minutes on a single call,
    // silently stalling that whole scan's enrichment with no further log output
    // and no exception ever thrown. REQUEST_TIMEOUT bounds the whole
    // request-to-response round trip per attempt, so a hang like this surfaces
    // as a normal retryable transport failure instead of hanging indefinitely.
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(120);

    // Required for the API to accept an OAuth bearer token at all.
    private static final String BETA_HEADER_VALUE = "claude-code-20250219,oauth-2025-04-20";
    private static final String CLAUDE_CODE_IDENTITY =
            "You are Claude Code, Anthropic's official CLI for Claude.";

    // Claude Pro/Max OAuth sessions hit a much tighter, burstier rate limit than a
    // paid API key (observed directly: identical back-to-back requests alternate
    // between 200 and 429 within seconds; see also
    // https://github.com/earendil-works/pi/issues/4621 and
    // https://dev.to/alexey-pelykh/claude-code-retries-rate-limit-errors-for-api-keys-not-for-your-max-plan-4p31).
    // Mirrors pi-ai's utils/provider-retry.js: honor Retry-After[-ms] verbatim, else
    // exponential min(0.5*2^n, 8)s with jitter, same 5-attempt budget as
    // web/app/agent/llm.py's Python-side retry for the AI Assistant chat path.
    private static final Set<Integer> RETRYABLE_STATUS = Set.of(408, 409, 429, 500, 502, 503, 504, 524, 529);
    private static final int MAX_RETRIES = 5;
    private static final double BACKOFF_BASE_S = 0.5;
    private static final double BACKOFF_CAP_S = 8.0;
    private static final double BACKOFF_JITTER_RATIO = 0.25;

    private final String     model;
    private final int        maxTokens;
    private final HttpClient http;

    /** Guards the load-refresh-save sequence so concurrent callers don't race a double refresh. */
    private final Object refreshLock = new Object();
    private volatile AnthropicOAuthCredentials cached;

    public ClaudeOAuthProvider(String model, int maxTokens) {
        this.model     = (model == null || model.isBlank()) ? "claude-sonnet-4-6" : model;
        this.maxTokens = maxTokens;
        this.http      = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();

        this.cached = AnthropicOAuthCredentials.load();
        if (this.cached == null) {
            throw new LlmException(
                    "No Anthropic OAuth session found. Run 'malimite claude-login' first " +
                    "(stores credentials at " + AnthropicOAuthCredentials.storePath() + ").");
        }
    }

    @Override
    public String complete(String systemPrompt, String userMessage) throws LlmException {
        JSONArray systemArray = new JSONArray()
                .put(new JSONObject().put("type", "text").put("text", CLAUDE_CODE_IDENTITY))
                .put(new JSONObject().put("type", "text").put("text", systemPrompt));

        JSONObject body = new JSONObject()
                .put("model", model)
                .put("max_tokens", maxTokens)
                .put("system", systemArray)
                .put("messages", new JSONArray()
                        .put(new JSONObject()
                                .put("role", "user")
                                .put("content", userMessage)));

        Exception lastFailure = null;
        for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
            if (attempt > 0) {
                log.info("Retrying Claude OAuth request (attempt {}/{}) after: {}",
                        attempt, MAX_RETRIES, lastFailure != null ? lastFailure.getMessage() : "unknown");
            }
            String accessToken = currentAccessToken(); // re-resolved per attempt: may have just been refreshed
            HttpRequest req = HttpRequest.newBuilder(URI.create(API_URL))
                    .header("Authorization", "Bearer " + accessToken)
                    .header("anthropic-version", API_VERSION)
                    .header("anthropic-beta", BETA_HEADER_VALUE)
                    .header("anthropic-dangerous-direct-browser-access", "true")
                    .header("Content-Type", "application/json")
                    .timeout(REQUEST_TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                    .build();

            HttpResponse<String> httpResp;
            try {
                httpResp = http.send(req, HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                // Transport-level failure (connect/timeout/IO): same retry budget as an HTTP error status.
                lastFailure = e;
                if (attempt < MAX_RETRIES) {
                    sleepBackoff(attempt, null);
                    continue;
                }
                throw new LlmException("Claude OAuth request failed (transport): " + e.getMessage(), e);
            }

            int status = httpResp.statusCode();
            if (status == 401) {
                throw new LlmException("Claude OAuth request unauthorized (401). " +
                        "Token may have been revoked — run 'malimite claude-login' again. Body: " + httpResp.body());
            }
            if (RETRYABLE_STATUS.contains(status) && attempt < MAX_RETRIES) {
                lastFailure = new LlmException("HTTP " + status + ": " + truncate(httpResp.body(), 200));
                sleepBackoff(attempt, httpResp);
                continue;
            }
            if (status != 200) {
                if (status == 429) {
                    // Exhausted MAX_RETRIES retries against a rate limit — on Pro/Max OAuth this is a real,
                    // observed throttle (see the class-level javadoc links), not a config problem. Say so
                    // plainly instead of a bare HTTP 429 that LlmEnricher logs as "Claude OAuth request failed".
                    // LlmEnricher already defaults to a much lower concurrency for this provider than for a
                    // pay-per-token API key (see LlmEnricher.resolveConcurrency()) — LLM_ENRICH_CONCURRENCY
                    // lowers it further if this still happens, or raises it back up if the account's actual
                    // limits are more generous than the conservative default assumes.
                    throw new LlmException("Claude (OAuth) is rate-limited by Anthropic after " + MAX_RETRIES +
                            " retries — this happens on Pro/Max subscription usage during bursts of requests " +
                            "(including other scans or AI Assistant chats sharing the same subscription), " +
                            "independent of any ANTHROPIC_API_KEY quota. Try again shortly, or set " +
                            "LLM_ENRICH_CONCURRENCY=1 to reduce parallel LLM calls.");
                }
                throw new LlmException("Claude OAuth request failed: HTTP " + status + ": " +
                        truncate(httpResp.body(), 200));
            }

            // status == 200: parse only now that we know the body is a real Messages API response,
            // not whatever a proxy/edge returns for a non-200 (often not JSON at all).
            try {
                JSONObject resp = new JSONObject(httpResp.body());
                if (resp.has("error")) {
                    throw new LlmException("Claude error: " + resp.getJSONObject("error").optString("message"));
                }
                return resp.getJSONArray("content")
                           .getJSONObject(0)
                           .getString("text");
            } catch (LlmException e) {
                throw e;
            } catch (Exception e) {
                // HTTP 200 but an unexpected body shape (e.g. empty content array) — not retryable,
                // the request already succeeded from Anthropic's point of view.
                throw new LlmException("Claude OAuth response could not be parsed: " + e.getMessage() +
                        "; body=" + truncate(httpResp.body(), 300), e);
            }
        }
        // Unreachable: the loop above always returns or throws before exhausting MAX_RETRIES+1 iterations.
        throw new LlmException("Claude OAuth request failed after " + MAX_RETRIES + " retries",
                lastFailure instanceof LlmException ? lastFailure.getCause() : lastFailure);
    }

    /** Sleeps the delay for one retry, honoring the provider's Retry-After[-ms] header when present. */
    private void sleepBackoff(int attempt, HttpResponse<String> failedResponse) {
        double delaySeconds = retryDelaySeconds(attempt, failedResponse);
        try {
            Thread.sleep((long) (delaySeconds * 1000));
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    private static double retryDelaySeconds(int attempt, HttpResponse<String> resp) {
        if (resp != null) {
            String retryAfterMs = resp.headers().firstValue("retry-after-ms").orElse(null);
            if (retryAfterMs != null) {
                try {
                    return Math.max(0, Double.parseDouble(retryAfterMs) / 1000.0);
                } catch (NumberFormatException ignored) { /* fall through */ }
            }
            String retryAfter = resp.headers().firstValue("retry-after").orElse(null);
            if (retryAfter != null) {
                try {
                    return Math.max(0, Double.parseDouble(retryAfter));
                } catch (NumberFormatException notASeconds) {
                    try {
                        ZonedDateTime target = ZonedDateTime.parse(retryAfter,
                                java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME);
                        return Math.max(0, (target.toInstant().toEpochMilli() - System.currentTimeMillis()) / 1000.0);
                    } catch (DateTimeParseException alsoNotADate) { /* fall through */ }
                }
            }
        }
        double base = Math.min(BACKOFF_BASE_S * Math.pow(2, attempt), BACKOFF_CAP_S);
        return base * (1 - Math.random() * BACKOFF_JITTER_RATIO);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    /** Returns a non-expired access token, refreshing and persisting it first if needed. */
    private String currentAccessToken() {
        AnthropicOAuthCredentials snapshot = cached;
        if (!snapshot.isExpired()) {
            return snapshot.accessToken;
        }
        synchronized (refreshLock) {
            // Re-check: another thread may have refreshed while we waited for the lock.
            if (cached.isExpired()) {
                try {
                    log.info("Anthropic OAuth access token expired, refreshing...");
                    cached = AnthropicOAuthLogin.refresh(cached);
                } catch (Exception e) {
                    throw new LlmException(
                            "Failed to refresh Anthropic OAuth token. Run 'malimite claude-login' again.", e);
                }
            }
            return cached.accessToken;
        }
    }
}
