package io.malimite.bot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.WebSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.*;

/**
 * Slack bot using Socket Mode (WebSocket) — no public HTTPS endpoint required.
 *
 * Env:
 *   SLACK_APP_TOKEN   — xapp-... (Socket Mode app-level token)
 *   SLACK_BOT_TOKEN   — xoxb-... (bot OAuth token for REST API / file downloads)
 *   MALIMITE_API_URL
 *   MALIMITE_API_KEY  (optional)
 *
 * Required OAuth Bot Scopes: files:read, chat:write, channels:history, im:history
 * Required Event Subscriptions (Socket Mode): message.channels, message.im
 */
public class SlackBot implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(SlackBot.class);
    private static final String SLACK_API = "https://slack.com/api";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final String     appToken; // xapp-...
    private final String     botToken; // xoxb-...
    private final String     apiUrl;
    private final String     apiKey;
    private final HttpClient http;

    public SlackBot(String appToken, String botToken, String apiUrl, String apiKey) {
        this.appToken = appToken;
        this.botToken = botToken;
        this.apiUrl   = apiUrl;
        this.apiKey   = apiKey;
        this.http     = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15)).build();
    }

    @Override
    public void run() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                String wsUrl = openSocketMode();
                connectAndWait(wsUrl);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("Slack connection error", e);
            }
            log.info("Slack disconnected — reconnecting in 5s");
            try { Thread.sleep(5_000); } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    // ── connection ────────────────────────────────────────────────────────────

    private String openSocketMode() throws Exception {
        HttpResponse<String> r = http.send(
                HttpRequest.newBuilder(URI.create(SLACK_API + "/apps.connections.open"))
                        .header("Authorization", "Bearer " + appToken)
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        JsonNode resp = JSON.readTree(r.body());
        if (!resp.path("ok").asBoolean(false))
            throw new IllegalStateException("apps.connections.open failed: " + resp.path("error").asText());
        return resp.path("url").asText();
    }

    private void connectAndWait(String wsUrl) throws Exception {
        CountDownLatch done = new CountDownLatch(1);

        WebSocket ws = http.newWebSocketBuilder()
                .buildAsync(URI.create(wsUrl), new SocketModeListener(done))
                .get(30, TimeUnit.SECONDS);
        ws.request(1);
        done.await();
    }

    // ── WebSocket listener ────────────────────────────────────────────────────

    private final class SocketModeListener implements WebSocket.Listener {
        private final CountDownLatch done;
        private final StringBuilder  buf = new StringBuilder();

        SocketModeListener(CountDownLatch done) { this.done = done; }

        @Override
        public CompletionStage<?> onText(WebSocket ws, CharSequence data, boolean last) {
            buf.append(data);
            if (last) {
                dispatch(ws, buf.toString());
                buf.setLength(0);
            }
            ws.request(1);
            return null;
        }

        @Override
        public CompletionStage<?> onClose(WebSocket ws, int code, String reason) {
            log.warn("Slack WS closed {}: {}", code, reason);
            done.countDown();
            return null;
        }

        @Override
        public void onError(WebSocket ws, Throwable t) {
            log.error("Slack WS error", t);
            done.countDown();
        }
    }

    // ── message dispatch ──────────────────────────────────────────────────────

    private void dispatch(WebSocket ws, String raw) {
        try {
            JsonNode n    = JSON.readTree(raw);
            String   type = n.path("type").asText();

            switch (type) {
                case "hello" -> log.info("Slack Socket Mode connected, num_connections={}",
                                         n.path("num_connections").asInt());

                case "events_api" -> {
                    // ACK first — Slack requires response within 3 seconds
                    ws.sendText("{\"envelope_id\":\"" + n.path("envelope_id").asText() + "\"}", true);
                    handleEvent(n.path("payload").path("event"));
                }

                case "disconnect" -> {
                    log.warn("Slack requested disconnect: {}", n.path("reason").asText());
                    ws.sendClose(WebSocket.NORMAL_CLOSURE, "server-requested").exceptionally(e -> null);
                }

                default -> log.debug("Slack msg type={}", type);
            }
        } catch (Exception e) {
            log.error("dispatch error", e);
        }
    }

    private void handleEvent(JsonNode event) {
        if (!"message".equals(event.path("type").asText())) return;
        if (!event.path("bot_id").isMissingNode()) return; // skip bot messages

        // Accept file_share subtype or plain messages that carry files
        String subtype = event.path("subtype").asText("");
        if (!subtype.isEmpty() && !"file_share".equals(subtype)) return;

        JsonNode files     = event.path("files");
        String   channelId = event.path("channel").asText();
        String   threadTs  = event.path("ts").asText();

        if (!files.isArray()) return;

        for (JsonNode file : files) {
            String filename    = file.path("name").asText("");
            String downloadUrl = file.path("url_private_download").asText("");
            String lower = filename.toLowerCase();
            if ((!lower.endsWith(".ipa") && !lower.endsWith(".apk")) || downloadUrl.isBlank()) continue;

            CompletableFuture.runAsync(() -> {
                try {
                    Path   ipa    = downloadSlackFile(downloadUrl, filename);
                    String scanId = uploadToMalimite(ipa, filename);
                    postMessage(channelId, threadTs,
                            "✅ Queued. `scan_id=" + scanId + "`\nCheck: " + apiUrl + "/api/v1/scans/" + scanId);
                } catch (Exception ex) {
                    log.error("Slack handle fail", ex);
                    postMessage(channelId, threadTs, "❌ Error: " + ex.getMessage());
                }
            });
        }
    }

    // ── REST helpers ──────────────────────────────────────────────────────────

    private Path downloadSlackFile(String url, String filename) throws Exception {
        String suffix = filename != null && filename.toLowerCase().endsWith(".apk") ? ".apk" : ".ipa";
        Path tmp = Files.createTempFile("slack-", suffix);
        http.send(
                HttpRequest.newBuilder(URI.create(url))
                        .header("Authorization", "Bearer " + botToken).build(),
                HttpResponse.BodyHandlers.ofFile(tmp));
        return tmp;
    }

    private void postMessage(String channelId, String threadTs, String text) {
        try {
            String body = JSON.writeValueAsString(Map.of(
                    "channel",   channelId,
                    "thread_ts", threadTs,
                    "text",      text));
            http.send(
                    HttpRequest.newBuilder(URI.create(SLACK_API + "/chat.postMessage"))
                            .header("Authorization", "Bearer " + botToken)
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                    HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            log.error("postMessage fail", e);
        }
    }

    private String uploadToMalimite(Path ipa, String name) throws Exception {
        String boundary = "----malimite" + System.nanoTime();
        byte[] body = MultipartUtil.build(boundary, "file", name, Files.readAllBytes(ipa));
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(apiUrl + "/api/v1/scans"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        if (apiKey != null) b.header("X-Api-Key", apiKey);
        return JSON.readTree(
                http.send(b.build(), HttpResponse.BodyHandlers.ofString()).body()
        ).path("scan_id").asText();
    }
}
