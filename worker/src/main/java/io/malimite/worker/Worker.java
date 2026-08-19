package io.malimite.worker;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.malimite.core.*;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Polls Redis Stream, downloads IPA from MinIO, runs MalimiteAnalyzer. */
public class Worker {

    private static final Logger       log    = LoggerFactory.getLogger(Worker.class);
    private static final ObjectMapper JSON   = new ObjectMapper();
    private static final String       STREAM = "malimite:scans";
    private static final String       GROUP  = "workers";

    public static void main(String[] args) throws Exception {
        JedisPooled redis = new JedisPooled(env("REDIS_URL", "redis://localhost:6379"));
        MinioClient minio = MinioClient.builder()
                .endpoint(env("MINIO_ENDPOINT", "http://localhost:9000"))
                .credentials(env("MINIO_ACCESS", "minioadmin"), env("MINIO_SECRET", "minioadmin"))
                .build();
        String bucket   = env("MINIO_BUCKET", "malimite-ipa");
        Path ghidraHome = Path.of(env("GHIDRA_HOME", "/opt/ghidra"));
        String jadxEnv  = System.getenv("JADX_HOME");
        Path jadxHome   = (jadxEnv == null || jadxEnv.isBlank()) ? null : Path.of(jadxEnv);
        Path outBase    = Path.of(env("REPORT_DIR", "/var/malimite/reports"));
        Files.createDirectories(outBase);

        // LLM / scan-scope config from env (LLM_MODE selects Fast/Full even when LLM is off)
        boolean llmEnabled = Boolean.parseBoolean(env("LLM_ENABLED", "false"));
        LlmMode llmMode    = LlmMode.fromString(env("LLM_MODE", "summarize"));
        if (llmMode == LlmMode.OFFENSIVE && !llmEnabled) {
            log.error("LLM_MODE=offensive requires LLM_ENABLED=true");
            System.exit(2);
        }
        List<String> extraPrefixes = parseIncludePackages(env("INCLUDE_PACKAGE", ""));
        Map<String, String> llmCfg = Map.of(
                "LLM_PROVIDER",      env("LLM_PROVIDER", "none"),
                "OPENAI_API_KEY",    env("OPENAI_API_KEY", ""),
                "ANTHROPIC_API_KEY", env("ANTHROPIC_API_KEY", ""),
                "DEEPSEEK_API_KEY",  env("DEEPSEEK_API_KEY", ""),
                "DEEPSEEK_BASE_URL", env("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
                "OLLAMA_BASE_URL",   env("OLLAMA_BASE_URL", "http://localhost:11434"),
                "LLM_MODEL",         env("LLM_MODEL", ""),
                "LLM_MAX_TOKENS",    env("LLM_MAX_TOKENS", "4096"));

        String webhookUrl = System.getenv("WEBHOOK_URL"); // Phase 5.7

        try { redis.xgroupCreate(STREAM, GROUP, new StreamEntryID("0"), true); }
        catch (Exception ignored) {}

        String consumer = "worker-" + java.util.UUID.randomUUID();
        log.info("worker {} ready (llm={} mode={} scope={} extraPackages={})",
                consumer, llmEnabled, llmMode, llmMode.scanScope(), extraPrefixes);

        // LLM cache backed by Redis
        LlmCache llmCache = new RedisLlmCache(redis);
        MalimiteAnalyzer analyzer = new MalimiteAnalyzer();

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
                        redis.hset("malimite:status:" + scanId, Map.of(
                                "state", "running",
                                "started_at", java.time.Instant.now().toString()));
                        String suffix = (key != null && key.toLowerCase().endsWith(".apk")) ? ".apk" : ".ipa";
                        Path local = Files.createTempFile("malimite-", suffix);
                        minio.downloadObject(DownloadObjectArgs.builder()
                                .bucket(bucket).object(key)
                                .filename(local.toString()).overwrite(true).build());

                        AnalysisResult r = analyzer.analyze(AnalyzeOptions.builder()
                                .packagePath(local)
                                .ghidraHome(ghidraHome)
                                .jadxHome(jadxHome)
                                .outputDir(outBase.resolve(scanId))
                                .llmEnabled(llmEnabled)
                                .llmMode(llmMode)
                                .llmConfig(llmCfg)
                                .extraPackagePrefixes(extraPrefixes)
                                .build());

                        // Phase 4: Redis-cached LLM enrichment if not yet run inside analyzer
                        // (LlmCache.NOOP was used in analyze(); re-run with Redis cache if needed)
                        if (llmEnabled) {
                            LlmProvider provider = LlmProviderFactory.create(llmCfg);
                            if (provider != null) {
                                try (SqliteStore store = new SqliteStore(r.dbPath().toString())) {
                                    PackagePlatform plat = PackagePlatform.IOS;
                                    try {
                                        plat = PackagePlatform.detect(local);
                                    } catch (Exception ignored) {}
                                    boolean isSwift = plat == PackagePlatform.IOS && readIsSwift(r);
                                    String appId = extractApplicationId(r);
                                    ScanScopeFilter scope = ScanScopeFilter.from(
                                            llmMode, appId, plat, extraPrefixes);
                                    new LlmEnricher(provider, llmMode, llmCache, isSwift, plat)
                                            .enrich(store, extractExecName(r), scope);
                                }
                            }
                        }

                        AnalysisReport report = ReportBuilder.buildFromDir(r.reportDir(), r.durationMs());
                        String reportJson = JSON.writeValueAsString(report);

                        redis.set("malimite:result:" + scanId, reportJson);
                        redis.hset("malimite:status:" + scanId,
                                Map.of("state", "done",
                                       "report_dir", r.reportDir().toString(),
                                       "finished_at", java.time.Instant.now().toString()));

                        // Phase 5.7: webhook notification
                        if (webhookUrl != null && !webhookUrl.isBlank())
                            postWebhook(webhookUrl, reportJson);

                    } catch (Exception ex) {
                        log.error("scan {} failed", scanId, ex);
                        redis.hset("malimite:status:" + scanId,
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
        private static final String KEY = "malimite:llm:cache";
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
            String exec = meta.path("bundleExecutable").asText();
            if (exec == null || exec.isBlank())
                exec = meta.path("applicationId").asText();
            return exec == null ? "" : exec;
        } catch (Exception e) {
            return "";
        }
    }

    private static String extractApplicationId(AnalysisResult r) {
        try {
            com.fasterxml.jackson.databind.JsonNode meta =
                    JSON.readTree(r.reportDir().resolve("scan.json").toFile());
            String id = meta.path("bundleIdentifier").asText();
            if (id == null || id.isBlank())
                id = meta.path("applicationId").asText();
            return id == null ? "" : id;
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean readIsSwift(AnalysisResult r) {
        try {
            com.fasterxml.jackson.databind.JsonNode meta =
                    JSON.readTree(r.reportDir().resolve("scan.json").toFile());
            return meta.path("isSwift").asBoolean(false);
        } catch (Exception e) {
            return false;
        }
    }

    private static List<String> parseIncludePackages(String raw) {
        if (raw == null || raw.isBlank()) return List.of();
        List<String> out = new ArrayList<>();
        for (String part : raw.split("[,;\\s]+")) {
            String n = ScanScopeFilter.sanitizePackagePrefix(part);
            if (n != null) out.add(n);
            else if (!part.isBlank())
                log.warn("Ignoring invalid INCLUDE_PACKAGE value: {}", part);
        }
        return List.copyOf(out);
    }

    private static String env(String k, String def) {
        String v = System.getenv(k);
        return v == null ? def : v;
    }
}
