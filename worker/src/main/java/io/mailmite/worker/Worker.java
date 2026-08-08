package io.mailmite.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mailmite.core.*;
import io.minio.DownloadObjectArgs;
import io.minio.MinioClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import redis.clients.jedis.JedisPooled;
import redis.clients.jedis.StreamEntryID;
import redis.clients.jedis.params.XReadGroupParams;
import redis.clients.jedis.resps.StreamEntry;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Polls Redis Stream, downloads IPA from MinIO, runs MailmiteAnalyzer. */
public class Worker {

    private static final Logger       log    = LoggerFactory.getLogger(Worker.class);
    private static final ObjectMapper JSON   = new ObjectMapper();
    private static final String       STREAM = "mailmite:scans";
    private static final String       GROUP  = "workers";

    public static void main(String[] args) throws Exception {
        JedisPooled redis = new JedisPooled(env("REDIS_URL", "redis://localhost:6379"));
        MinioClient minio = MinioClient.builder()
                .endpoint(env("MINIO_ENDPOINT", "http://localhost:9000"))
                .credentials(env("MINIO_ACCESS", "minioadmin"), env("MINIO_SECRET", "minioadmin"))
                .build();
        String bucket   = env("MINIO_BUCKET", "mailmite-ipa");
        Path ghidraHome = Path.of(env("GHIDRA_HOME", "/opt/ghidra"));
        Path outBase    = Path.of(env("REPORT_DIR", "/var/mailmite/reports"));
        Files.createDirectories(outBase);

        // LLM config from env
        boolean llmEnabled = Boolean.parseBoolean(env("LLM_ENABLED", "false"));
        LlmMode llmMode    = LlmMode.fromString(env("LLM_MODE", "summarize"));
        Map<String, String> llmCfg = Map.of(
                "LLM_PROVIDER",      env("LLM_PROVIDER", "none"),
                "OPENAI_API_KEY",    env("OPENAI_API_KEY", ""),
                "ANTHROPIC_API_KEY", env("ANTHROPIC_API_KEY", ""),
                "DEEPSEEK_API_KEY",  env("DEEPSEEK_API_KEY", ""),
                "DEEPSEEK_BASE_URL", env("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
                "OLLAMA_BASE_URL",   env("OLLAMA_BASE_URL", "http://localhost:11434"),
                "LLM_MODEL",         env("LLM_MODEL", ""),
                "LLM_MAX_TOKENS",    env("LLM_MAX_TOKENS", "2000"));

        String webhookUrl = System.getenv("WEBHOOK_URL"); // Phase 5.7

        try { redis.xgroupCreate(STREAM, GROUP, new StreamEntryID("0"), true); }
        catch (Exception ignored) {}

        String consumer = "worker-" + java.util.UUID.randomUUID();
        log.info("worker {} ready (llm={} mode={})", consumer, llmEnabled, llmMode);

        // LLM cache backed by Redis
        LlmCache llmCache = new RedisLlmCache(redis);
        MailmiteAnalyzer analyzer = new MailmiteAnalyzer();

        while (true) {
            var resp = redis.xreadGroup(GROUP, consumer,
                    XReadGroupParams.xReadGroupParams().count(1).block(5000),
                    Map.of(STREAM, StreamEntryID.UNRECEIVED_ENTRY));
            if (resp == null) continue;

            for (var entry : resp) {
                List<StreamEntry> msgs = entry.getValue();
                for (StreamEntry m : msgs) {
                    Map<String, String> f = m.getFields();
                    String scanId = f.get("scan_id");
                    String key    = f.get("object_key");
                    try {
                        redis.hset("mailmite:status:" + scanId, Map.of(
                                "state", "running",
                                "started_at", java.time.Instant.now().toString()));
                        Path local = Files.createTempFile("mailmite-", ".ipa");
                        minio.downloadObject(DownloadObjectArgs.builder()
                                .bucket(bucket).object(key)
                                .filename(local.toString()).overwrite(true).build());

                        AnalysisResult r = analyzer.analyze(AnalyzeOptions.builder()
                                .ipaPath(local)
                                .ghidraHome(ghidraHome)
                                .outputDir(outBase.resolve(scanId))
                                .llmEnabled(llmEnabled)
                                .llmMode(llmMode)
                                .llmConfig(llmCfg)
                                .build());

                        // Phase 4: Redis-cached LLM enrichment if not yet run inside analyzer
                        // (LlmCache.NOOP was used in analyze(); re-run with Redis cache if needed)
                        if (llmEnabled) {
                            LlmProvider provider = LlmProviderFactory.create(llmCfg);
                            if (provider != null) {
                                try (SqliteStore store = new SqliteStore(r.dbPath().toString())) {
                                    new LlmEnricher(provider, llmMode, llmCache, false)
                                            .enrich(store, extractExecName(r));
                                }
                            }
                        }

                        AnalysisReport report = ReportBuilder.buildFromDir(r.reportDir(), r.durationMs());
                        String reportJson = JSON.writeValueAsString(report);

                        redis.set("mailmite:result:" + scanId, reportJson);
                        redis.hset("mailmite:status:" + scanId,
                                Map.of("state", "done",
                                       "report_dir", r.reportDir().toString(),
                                       "finished_at", java.time.Instant.now().toString()));

                        // Phase 5.7: webhook notification
                        if (webhookUrl != null && !webhookUrl.isBlank())
                            postWebhook(webhookUrl, reportJson);

                    } catch (Exception ex) {
                        log.error("scan {} failed", scanId, ex);
                        redis.hset("mailmite:status:" + scanId,
                                Map.of("state", "error",
                                       "message", String.valueOf(ex.getMessage()),
                                       "finished_at", java.time.Instant.now().toString()));
                    } finally {
                        redis.xack(STREAM, GROUP, m.getID());
                    }
                }
            }
        }
    }

    // ── Redis-backed LLM cache ────────────────────────────────────────────────

    private static final class RedisLlmCache implements LlmCache {
        private static final String KEY = "mailmite:llm:cache";
        private final JedisPooled redis;
        RedisLlmCache(JedisPooled redis) { this.redis = redis; }

        @Override
        public Optional<String> get(String hash) {
            String v = redis.hget(KEY, hash);
            return Optional.ofNullable(v);
        }
        @Override
        public void put(String hash, String result) { redis.hset(KEY, hash, result); }
    }

    // ── webhook ───────────────────────────────────────────────────────────────

    private static void postWebhook(String url, String json) {
        try {
            HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                    .timeout(Duration.ofSeconds(15))
                    .build();
            int status = http.send(req, HttpResponse.BodyHandlers.discarding()).statusCode();
            log.info("Webhook POST {} → {}", url, status);
        } catch (Exception e) {
            log.warn("Webhook POST failed: {}", e.getMessage());
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private static String extractExecName(AnalysisResult r) {
        try {
            com.fasterxml.jackson.databind.JsonNode meta =
                    JSON.readTree(r.reportDir().resolve("scan.json").toFile());
            return meta.path("bundleExecutable").asText();
        } catch (Exception e) {
            return "";
        }
    }

    private static String env(String k, String def) {
        String v = System.getenv(k);
        return v == null ? def : v;
    }
}
