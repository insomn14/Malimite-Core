package io.mailmite.bot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

/**
 * Minimal Telegram bot: long-poll /getUpdates, on document with .ipa MIME
 * fetch the file via getFile + file_path, POST it to Mailmite API
 * (MAILMITE_API_URL), reply with scan_id.
 *
 * Env:
 *   TELEGRAM_BOT_TOKEN
 *   MAILMITE_API_URL    e.g. http://api:8080
 *   MAILMITE_API_KEY    (optional)
 */
public class TelegramBot {

    private static final Logger log = LoggerFactory.getLogger(TelegramBot.class);
    private static final ObjectMapper M = new ObjectMapper();
    private static final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10)).build();

    public static void main(String[] args) throws Exception {
        run(require("TELEGRAM_BOT_TOKEN"), require("MAILMITE_API_URL"), System.getenv("MAILMITE_API_KEY"));
    }

    static void run(String token, String api, String apiKey) throws Exception {
        log.info("Telegram bot starting");
        long offset = 0;

        while (!Thread.currentThread().isInterrupted()) {
            String url = "https://api.telegram.org/bot" + token +
                         "/getUpdates?timeout=30&offset=" + offset;
            HttpResponse<String> resp = http.send(
                    HttpRequest.newBuilder(URI.create(url)).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            JsonNode root = M.readTree(resp.body());
            for (JsonNode upd : root.path("result")) {
                offset = upd.path("update_id").asLong() + 1;
                JsonNode msg = upd.path("message");
                JsonNode doc = msg.path("document");
                if (doc.isMissingNode()) continue;
                String name = doc.path("file_name").asText("");
                String lowerName = name.toLowerCase();
                if (!lowerName.endsWith(".ipa") && !lowerName.endsWith(".apk")) continue;

                long chatId = msg.path("chat").path("id").asLong();
                try {
                    Path ipa = downloadFile(token, doc.path("file_id").asText(), name);
                    String scanId = uploadToApi(api, apiKey, ipa, name);
                    sendMessage(token, chatId,
                        "✅ Queued. scan_id=" + scanId + "\nCheck " + api + "/api/v1/scans/" + scanId);
                } catch (Exception ex) {
                    log.error("handle fail", ex);
                    sendMessage(token, chatId, "❌ " + ex.getMessage());
                }
            }
        }
    }

    private static Path downloadFile(String token, String fileId, String filename) throws Exception {
        String meta = http.send(HttpRequest.newBuilder(URI.create(
                "https://api.telegram.org/bot" + token + "/getFile?file_id=" + fileId)).build(),
                HttpResponse.BodyHandlers.ofString()).body();
        String path = M.readTree(meta).path("result").path("file_path").asText();
        String suffix = filename != null && filename.toLowerCase().endsWith(".apk") ? ".apk" : ".ipa";
        Path out = Files.createTempFile("tg-", suffix);
        try (var in = URI.create("https://api.telegram.org/file/bot" + token + "/" + path)
                .toURL().openStream()) {
            Files.copy(in, out, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        return out;
    }

    private static String uploadToApi(String api, String apiKey, Path ipa, String name)
            throws IOException, InterruptedException {
        // minimal multipart — for production swap with a proper builder
        String boundary = "----mailmite" + System.nanoTime();
        byte[] body = MultipartUtil.build(boundary, "file", name, Files.readAllBytes(ipa));
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(api + "/api/v1/scans"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
        if (apiKey != null) b.header("X-Api-Key", apiKey);
        HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        return M.readTree(r.body()).path("scan_id").asText();
    }

    private static void sendMessage(String token, long chatId, String text) throws Exception {
        String body = M.writeValueAsString(java.util.Map.of("chat_id", chatId, "text", text));
        http.send(HttpRequest.newBuilder(URI.create(
                "https://api.telegram.org/bot" + token + "/sendMessage"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.discarding());
    }

    static String require(String k) {
        String v = System.getenv(k);
        if (v == null || v.isBlank()) throw new IllegalStateException("env " + k + " required");
        return v;
    }
}
