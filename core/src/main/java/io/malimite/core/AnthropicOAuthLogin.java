package io.malimite.core;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.Desktop;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Implements the same OAuth 2.0 Authorization Code + PKCE flow Claude Code
 * itself uses to sign in a Claude Pro/Max/subscription session, so requests
 * can be authorized without a separately-billed {@code ANTHROPIC_API_KEY}.
 *
 * <h2>What this is</h2>
 * <p>{@code client_id} below is the <b>public</b> OAuth client id Anthropic
 * registered for its own Claude Code CLI. It is not a secret — every
 * open-source tool that reimplements "Sign in with Claude" (pi-ai, OpenCode,
 * etc.) uses the same value, because Anthropic's authorization server
 * identifies requests by this id rather than by a confidential secret (this
 * is a public, native-app OAuth client per RFC 8252 — there is no
 * {@code client_secret} to leak).</p>
 *
 * <h2>Why requests must claim to be Claude Code</h2>
 * <p>The Messages API only honors an OAuth bearer token when the request also
 * carries the {@code anthropic-beta: oauth-2025-04-20} capability and a
 * system prompt that opens with Anthropic's own Claude Code identity string
 * (see {@link ClaudeOAuthProvider}). Requests authorized this way are
 * metered against the signed-in subscription's usage, not pay-per-token API
 * billing — which is exactly how Claude Code, and this file, make it work.</p>
 *
 * <h2>Terms of Service</h2>
 * <p>This reproduces a publicly documented flow used by several existing
 * open-source tools, but routing a third-party application's traffic through
 * a consumer subscription this way may fall outside Anthropic's Terms of
 * Service for that subscription tier. Review Anthropic's current ToS and
 * acceptable-use policy before relying on this in anything beyond personal,
 * single-user tooling.</p>
 */
public final class AnthropicOAuthLogin {

    private static final Logger log = LoggerFactory.getLogger(AnthropicOAuthLogin.class);

    // Public native-app client id for "Claude Code" (base64 of the UUID, matching
    // how Anthropic's own CLI and third-party reimplementations carry it).
    private static final String CLIENT_ID =
            new String(Base64.getDecoder().decode("OWQxYzI1MGEtZTYxYi00NGQ5LTg4ZWQtNTk0NGQxOTYyZjVl"),
                    StandardCharsets.UTF_8);

    private static final String AUTHORIZE_URL = "https://claude.ai/oauth/authorize";
    private static final String TOKEN_URL     = "https://platform.claude.com/v1/oauth/token";
    private static final String SCOPES        =
            "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload";

    private static final int    CALLBACK_PORT = 53692;
    private static final String CALLBACK_HOST = "127.0.0.1";
    private static final String CALLBACK_PATH = "/callback";
    private static final String REDIRECT_URI  = "http://localhost:" + CALLBACK_PORT + CALLBACK_PATH;

    private static final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .build();

    private AnthropicOAuthLogin() {}

    /**
     * Runs the full interactive login: opens the system browser (falling
     * back to printing the URL), waits for the local callback, exchanges the
     * code for tokens, and persists them via {@link AnthropicOAuthCredentials#save()}.
     *
     * @param waitMinutes how long to wait for the human to finish the browser flow
     * @return the newly stored credentials
     */
    public static AnthropicOAuthCredentials login(int waitMinutes) throws Exception {
        String verifier  = randomUrlSafe(32);
        String challenge  = base64UrlSha256(verifier);
        // pi-ai/Claude Code reuse the verifier itself as the OAuth "state" value;
        // kept here only for parity with that flow, not as a secrecy requirement.
        String state = verifier;

        CompletableFuture<Map<String, String>> callbackResult = new CompletableFuture<>();
        HttpServer server = startCallbackServer(state, callbackResult);
        try {
            String authorizeUrl = AUTHORIZE_URL + "?" + buildQuery(Map.of(
                    "code", "true",
                    "client_id", CLIENT_ID,
                    "response_type", "code",
                    "redirect_uri", REDIRECT_URI,
                    "scope", SCOPES,
                    "code_challenge", challenge,
                    "code_challenge_method", "S256",
                    "state", state));

            System.out.println();
            System.out.println("Open this URL to sign in with your Claude account:");
            System.out.println();
            System.out.println("  " + authorizeUrl);
            System.out.println();
            tryOpenBrowser(authorizeUrl);
            System.out.println("Waiting for the browser redirect"
                    + " (or paste the redirect URL / code#state here and press Enter)...");

            Map<String, String> result = waitForCallbackOrManualInput(callbackResult, state, waitMinutes);

            String code = result.get("code");
            if (code == null || code.isBlank()) {
                throw new IllegalStateException("No authorization code received");
            }

            System.out.println("Exchanging authorization code for tokens...");
            AnthropicOAuthCredentials creds = exchangeCode(code, state, verifier);
            creds.save();
            System.out.println("Signed in. Credentials stored at " + AnthropicOAuthCredentials.storePath());
            return creds;
        } finally {
            server.stop(0);
        }
    }

    /**
     * Refreshes an expiring credential and persists the result.
     *
     * <p>Takes a cross-process file lock first (see
     * {@link AnthropicOAuthCredentials#withRefreshLock}) because Anthropic's
     * refresh_token is single-use: if another process (e.g. the Python web
     * service refreshing concurrently) wins a simultaneous refresh race, this
     * call's {@code refresh_token} is already spent and the API 400s. After
     * acquiring the lock this re-reads the credential from disk — if the other
     * process already refreshed while we waited, we reuse ITS result instead of
     * attempting a second refresh with our now-stale refresh_token.</p>
     */
    public static AnthropicOAuthCredentials refresh(AnthropicOAuthCredentials current) throws Exception {
        return AnthropicOAuthCredentials.withRefreshLock(() -> {
            try {
                AnthropicOAuthCredentials onDisk = AnthropicOAuthCredentials.load();
                if (onDisk != null && !onDisk.isExpired() && !onDisk.refreshToken.equals(current.refreshToken)) {
                    // Someone else refreshed while we were waiting for the lock — the
                    // refresh_token changed and the new credential isn't expired.
                    // Reuse it instead of burning our (now stale) refresh_token.
                    return onDisk;
                }
                String body = new JSONObject()
                        .put("grant_type", "refresh_token")
                        .put("client_id", CLIENT_ID)
                        .put("refresh_token", current.refreshToken)
                        .toString();
                JSONObject tokenData = postJson(body);
                AnthropicOAuthCredentials refreshed = toCredentials(tokenData);
                refreshed.save();
                return refreshed;
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    // ---------------------------------------------------------------- helpers

    private static AnthropicOAuthCredentials exchangeCode(String code, String state, String verifier) throws IOException, InterruptedException {
        String body = new JSONObject()
                .put("grant_type", "authorization_code")
                .put("client_id", CLIENT_ID)
                .put("code", code)
                .put("state", state)
                .put("redirect_uri", REDIRECT_URI)
                .put("code_verifier", verifier)
                .toString();

        return toCredentials(postJson(body));
    }

    private static JSONObject postJson(String body) throws IOException, InterruptedException {
        HttpRequest req = HttpRequest.newBuilder(URI.create(TOKEN_URL))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() / 100 != 2) {
            throw new IOException("Anthropic token endpoint returned HTTP " + resp.statusCode() + ": " + resp.body());
        }
        return new JSONObject(resp.body());
    }

    private static AnthropicOAuthCredentials toCredentials(JSONObject tokenData) {
        long expiresInMs   = tokenData.getLong("expires_in") * 1000L;
        long fiveMinutesMs = 5 * 60 * 1000L;
        long expiresAt     = System.currentTimeMillis() + expiresInMs - fiveMinutesMs; // same safety margin pi-ai uses
        return new AnthropicOAuthCredentials(
                tokenData.getString("access_token"),
                tokenData.getString("refresh_token"),
                expiresAt);
    }

    /** Minimal loopback HTTP server that only understands {@code CALLBACK_PATH}. */
    private static HttpServer startCallbackServer(String expectedState, CompletableFuture<Map<String, String>> result) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(CALLBACK_HOST, CALLBACK_PORT), 0);
        server.createContext(CALLBACK_PATH, (HttpExchange exchange) -> {
            try {
                Map<String, String> params = parseQuery(exchange.getRequestURI().getRawQuery());
                String code  = params.get("code");
                String state = params.get("state");
                String error = params.get("error");

                String html;
                int status;
                if (error != null) {
                    status = 400;
                    html = errorPage("Anthropic authentication did not complete.", "Error: " + error);
                } else if (code == null || state == null) {
                    status = 400;
                    html = errorPage("Missing code or state parameter.", null);
                } else if (!state.equals(expectedState)) {
                    status = 400;
                    html = errorPage("State mismatch.", null);
                } else {
                    status = 200;
                    html = successPage();
                    result.complete(Map.of("code", code, "state", state));
                }
                byte[] bytes = html.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
                exchange.sendResponseHeaders(status, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            } finally {
                exchange.close();
            }
        });
        server.start();
        return server;
    }

    /**
     * Waits for either the loopback callback to fire or the human to paste
     * the redirect URL / bare code manually (useful when the browser runs on
     * a different machine than this process).
     */
    private static Map<String, String> waitForCallbackOrManualInput(
            CompletableFuture<Map<String, String>> callbackResult, String expectedState, int waitMinutes) throws Exception {

        CompletableFuture<Map<String, String>> manualResult = new CompletableFuture<>();
        Thread stdinReader = new Thread(() -> {
            try (Scanner scanner = new Scanner(System.in, StandardCharsets.UTF_8)) {
                if (scanner.hasNextLine()) {
                    String line = scanner.nextLine().trim();
                    if (!line.isEmpty()) {
                        manualResult.complete(parseManualInput(line, expectedState));
                    }
                }
            } catch (Exception e) {
                manualResult.completeExceptionally(e);
            }
        }, "anthropic-oauth-manual-input");
        stdinReader.setDaemon(true);
        stdinReader.start();

        CompletableFuture<Map<String, String>> either = callbackResult.applyToEither(manualResult, r -> r);
        try {
            return either.get(waitMinutes, TimeUnit.MINUTES);
        } catch (TimeoutException e) {
            throw new IllegalStateException("Timed out waiting for Anthropic login after " + waitMinutes + " minute(s)");
        }
    }

    private static Map<String, String> parseManualInput(String input, String expectedState) {
        String code;
        String state;
        try {
            URI uri = URI.create(input);
            Map<String, String> q = parseQuery(uri.getRawQuery());
            code  = q.get("code");
            state = q.get("state");
        } catch (Exception notAUrl) {
            if (input.contains("#")) {
                String[] parts = input.split("#", 2);
                code  = parts[0];
                state = parts[1];
            } else if (input.contains("code=")) {
                Map<String, String> q = parseQuery(input);
                code  = q.get("code");
                state = q.get("state");
            } else {
                code  = input;
                state = null;
            }
        }
        if (state != null && !state.equals(expectedState)) {
            throw new IllegalStateException("OAuth state mismatch in pasted input");
        }
        return Map.of("code", code == null ? "" : code, "state", state == null ? expectedState : state);
    }

    private static Map<String, String> parseQuery(String rawQuery) {
        if (rawQuery == null || rawQuery.isBlank()) return Map.of();
        Map<String, String> out = new java.util.HashMap<>();
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) continue;
            String k = java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
            String v = java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            out.put(k, v);
        }
        return out;
    }

    private static String buildQuery(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (var e : params.entrySet()) {
            if (sb.length() > 0) sb.append('&');
            sb.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
              .append('=')
              .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
        }
        return sb.toString();
    }

    private static void tryOpenBrowser(String url) {
        try {
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(URI.create(url));
                return;
            }
        } catch (Exception e) {
            log.debug("Desktop.browse failed, falling back to printed URL: {}", e.toString());
        }
        // Headless/server environment: the URL printed by the caller is the whole UX.
    }

    private static String randomUrlSafe(int numBytes) {
        byte[] bytes = new byte[numBytes];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String base64UrlSha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e); // SHA-256 is mandatory on every JDK
        }
    }

    private static String successPage() {
        return "<!doctype html><meta charset=utf-8><title>Signed in</title>"
                + "<body style=font-family:system-ui;padding:2rem>"
                + "<h2>Anthropic authentication completed.</h2>"
                + "<p>You can close this window and return to Malimite.</p></body>";
    }

    private static String errorPage(String message, String detail) {
        return "<!doctype html><meta charset=utf-8><title>Sign-in failed</title>"
                + "<body style=font-family:system-ui;padding:2rem>"
                + "<h2>" + message + "</h2>"
                + (detail != null ? "<p>" + detail + "</p>" : "")
                + "</body>";
    }
}
