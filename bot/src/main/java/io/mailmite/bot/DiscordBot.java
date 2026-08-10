package io.mailmite.bot;

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
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Discord bot using the Gateway WebSocket API (v10).
 *
 * Env:
 *   DISCORD_BOT_TOKEN   — bot token from Discord Developer Portal
 *   MAILMITE_API_URL
 *   MAILMITE_API_KEY    (optional)
 *
 * Required privileged Gateway intent: MESSAGE_CONTENT
 * Enable it at: https://discord.com/developers/applications → Bot → Privileged Gateway Intents
 *
 * Intents used: GUILDS(1) | GUILD_MESSAGES(512) | DIRECT_MESSAGES(4096) | MESSAGE_CONTENT(32768)
 */
public class DiscordBot implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(DiscordBot.class);

    private static final String GATEWAY  = "wss://gateway.discord.gg/?v=10&encoding=json";
    private static final String REST_BASE = "https://discord.com/api/v10";
    private static final int    INTENTS   = 1 | 512 | 4096 | 32768;

    private static final ObjectMapper JSON = new ObjectMapper();

    private final String     token;
    private final String     apiUrl;
    private final String     apiKey;
    private final HttpClient http;

    private final AtomicLong              lastSeq   = new AtomicLong(-1);
    private final AtomicReference<WebSocket> wsRef  = new AtomicReference<>();
    private volatile ScheduledExecutorService heartbeatExec;

    public DiscordBot(String token, String apiUrl, String apiKey) {
        this.token  = token;
        this.apiUrl = apiUrl;
        this.apiKey = apiKey;
        this.http   = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15)).build();
    }

    @Override
    public void run() {
        while (!Thread.currentThread().isInterrupted()) {
            try {
                connectAndWait();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("Discord connection error", e);
            }
            log.info("Discord disconnected — reconnecting in 5s");
            try { Thread.sleep(5_000); } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    // ── connection ────────────────────────────────────────────────────────────

    private void connectAndWait() throws Exception {
        CountDownLatch done = new CountDownLatch(1);

        WebSocket ws = http.newWebSocketBuilder()
                .buildAsync(URI.create(GATEWAY), new GatewayListener(done))
                .get(30, TimeUnit.SECONDS);

        wsRef.set(ws);
        ws.request(1); // start receiving
        done.await();
        wsRef.set(null);
        stopHeartbeat();
    }

    // ── WebSocket listener ────────────────────────────────────────────────────

    private final class GatewayListener implements WebSocket.Listener {
        private final CountDownLatch done;
        private final StringBuilder  buf = new StringBuilder();

        GatewayListener(CountDownLatch done) { this.done = done; }

        @Override
        public CompletionStage<?> onText(WebSocket ws, CharSequence data, boolean last) {
            buf.append(data);
            if (last) {
                dispatch(buf.toString());
                buf.setLength(0);
            }
            ws.request(1);
            return null;
        }

        @Override
        public CompletionStage<?> onClose(WebSocket ws, int code, String reason) {
            log.warn("Discord WS closed {}: {}", code, reason);
            stopHeartbeat();
            done.countDown();
            return null;
        }

        @Override
        public void onError(WebSocket ws, Throwable t) {
            log.error("Discord WS error", t);
            stopHeartbeat();
            done.countDown();
        }
    }

    // ── Gateway message handling ──────────────────────────────────────────────

    private void dispatch(String raw) {
        try {
            JsonNode n  = JSON.readTree(raw);
            int      op = n.path("op").asInt(-1);
            JsonNode d  = n.path("d");
            JsonNode s  = n.path("s");
            if (s.isNumber()) lastSeq.set(s.asLong());

            switch (op) {
                case 10 -> onHello(d);
                case 11 -> log.debug("Discord heartbeat ACK");
                case  9 -> onInvalidSession();
                case  0 -> onEvent(n.path("t").asText(""), d);
                default -> {}
            }
        } catch (Exception e) {
            log.error("dispatch error", e);
        }
    }

    private void onHello(JsonNode d) {
        long interval = d.path("heartbeat_interval").asLong(45_000);
        startHeartbeat(interval);
        // Identify
        String identify = """
                {"op":2,"d":{"token":"%s","intents":%d,"properties":{"os":"linux","browser":"mailmite","device":"mailmite"}}}
                """.formatted(token, INTENTS).strip();
        sendGateway(identify);
    }

    private void onEvent(String type, JsonNode d) {
        if ("MESSAGE_CREATE".equals(type)) handleMessageCreate(d);
    }

    private void onInvalidSession() {
        log.warn("Discord Invalid Session — closing for fresh reconnect");
        stopHeartbeat();
        WebSocket w = wsRef.get();
        if (w != null) w.sendClose(WebSocket.NORMAL_CLOSURE, "invalid session").exceptionally(e -> null);
    }

    private void handleMessageCreate(JsonNode msg) {
        JsonNode attachments = msg.path("attachments");
        if (!attachments.isArray() || attachments.isEmpty()) return;
        String channelId = msg.path("channel_id").asText();

        for (JsonNode att : attachments) {
            String filename = att.path("filename").asText("");
            String lower = filename.toLowerCase();
            if (!lower.endsWith(".ipa") && !lower.endsWith(".apk")) continue;
            String downloadUrl = att.path("url").asText();

            CompletableFuture.runAsync(() -> {
                try {
                    Path   ipa    = downloadFile(downloadUrl, filename);
                    String scanId = uploadToMailmite(ipa, filename);
                    sendChannelMessage(channelId,
                            "✅ Queued. `scan_id=" + scanId + "`\nCheck: " + apiUrl + "/api/v1/scans/" + scanId);
                } catch (Exception ex) {
                    log.error("Discord handle fail", ex);
                    sendChannelMessage(channelId, "❌ Error: " + ex.getMessage());
                }
            });
        }
    }

    // ── heartbeat ─────────────────────────────────────────────────────────────

    private void startHeartbeat(long intervalMs) {
        stopHeartbeat();
        ScheduledExecutorService exec = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "discord-heartbeat");
            t.setDaemon(true);
            return t;
        });
        heartbeatExec = exec;
        exec.scheduleAtFixedRate(() -> {
            long s = lastSeq.get();
            sendGateway(s < 0 ? "{\"op\":1,\"d\":null}" : "{\"op\":1,\"d\":" + s + "}");
        }, 0, intervalMs, TimeUnit.MILLISECONDS);
    }

    private void stopHeartbeat() {
        ScheduledExecutorService h = heartbeatExec;
        if (h != null) { h.shutdownNow(); heartbeatExec = null; }
    }

    private void sendGateway(String text) {
        WebSocket w = wsRef.get();
        if (w != null) w.sendText(text, true);
    }

    // ── REST helpers ──────────────────────────────────────────────────────────

    private void sendChannelMessage(String channelId, String content) {
        try {
            String body = JSON.writeValueAsString(java.util.Map.of("content", content));
            http.send(
                    HttpRequest.newBuilder(URI.create(REST_BASE + "/channels/" + channelId + "/messages"))
                            .header("Authorization", "Bot " + token)
                            .header("Content-Type", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                    HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            log.error("sendChannelMessage fail", e);
        }
    }

    private Path downloadFile(String url, String filename) throws Exception {
        String suffix = filename != null && filename.toLowerCase().endsWith(".apk") ? ".apk" : ".ipa";
        Path tmp = Files.createTempFile("discord-", suffix);
        http.send(
                HttpRequest.newBuilder(URI.create(url))
                        .header("Authorization", "Bot " + token).build(),
                HttpResponse.BodyHandlers.ofFile(tmp));
        return tmp;
    }

    private String uploadToMailmite(Path ipa, String name) throws Exception {
        String boundary = "----mailmite" + System.nanoTime();
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
